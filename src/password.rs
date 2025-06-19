#![allow(dead_code)] // TODO: remove this

use crate::generators::{ generate_letter, generate_number, generate_special };
use crate::encryption::{ serialize_salt, deserialize_salt, generate_secret_b64, derive_key, decrypt_json_data, encrypt_json_data };
use crate::errors::{ VaultError, VaultInitError, VaultPersistError };

use std::fs::{ File, OpenOptions };
use std::io::{ BufReader, Seek, SeekFrom };
use std::convert::TryFrom;

use argon2::{ password_hash::{
    rand_core::OsRng,
    SaltString,
}};

use base64::{engine::general_purpose, Engine as _};

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

use serde::{ Deserialize, Serialize };

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    proto: String,
    version: u8,
    name: String,
    #[serde(serialize_with="serialize_salt", deserialize_with="deserialize_salt")]
    salt: SaltString,
    nonce: String,
    master_password_hash_b64: String,
    data: String,

}

impl TryFrom<Vault> for VaultData {
    type Error = VaultPersistError;


    fn try_from(vault: Vault) -> Result<Self, Self::Error> {
        let passwords = &vault.password_manager.passwords;

        let passwords_json = serde_json::to_string(&passwords)
            .map_err(|e| VaultPersistError::new(format!("{}", e)))?;

        let master_password_hash = vault.get_password_hash_u8()
            .map_err(|e| VaultPersistError::new(format!("{}", e)))?;

        let nonce = vault.get_nonce_u8()
            .map_err(|e| VaultPersistError::new(format!("{}", e)))?;

        let passwords_json_cipher = encrypt_json_data(&master_password_hash, &passwords_json.into_bytes(), &nonce);

        let passwords_json_cipher_b64 = general_purpose::STANDARD.encode(passwords_json_cipher);

        Ok(Self {
            proto: vault.proto,
            version: vault.version,
            name: vault.name,
            salt: vault.salt,
            nonce: vault.nonce,
            master_password_hash_b64: vault.master_password_hash_b64,
            data: passwords_json_cipher_b64,
        })
    }
}

pub struct Vault {
    proto: String,
    version: u8,
    name: String,
    password_manager: Manager,
    vault_file: File,
    salt: SaltString,
    nonce: String,
    master_password_hash_b64: String,
    data: String,
    locked: bool,
}

impl Vault {
    const DEFAULT_FILE_PATH: &str = "~/.oktopass";

    pub fn new(name: &str, password: &str) -> Result<Self, VaultInitError> {
        let salt = SaltString::generate(&mut OsRng);
        let nonce = generate_secret_b64::<12>();
        let master_password_hash = derive_key(password, &salt)
            .map_err(|e| VaultInitError::new(format!("Vault initialization failed: {}", e)))?;

        let master_password_hash_b64 = general_purpose::STANDARD.encode(master_password_hash);

        let vault_file = Self::get_vault_file(name)?;

        Ok(Self {
            proto: String::from("OKTP"),
            version: 1,
            name: name.to_string(),
            password_manager: Manager::default(),
            vault_file,
            salt,
            nonce: general_purpose::STANDARD.encode(nonce),
            master_password_hash_b64,
            data: String::from(""),
            locked: false,
        })
    }

    pub fn load_from_file(name: String) -> Result<Self, VaultInitError> {
        let vault_file = OpenOptions::new()
            .read(true)
            .open(&Self::get_vault_file_path(name.as_str()))?;

        let vault_data: VaultData = {
            let reader = BufReader::new(&vault_file);
            serde_json::from_reader(reader)
                .map_err(|e| VaultInitError::new(format!("Could not load vault from file: {}", e)))?
        };

        let vault = Vault::try_from(vault_data)?;

        Ok(vault)
    }

    pub fn unlock(&mut self, master_password: String) -> Result<(), VaultError> {
        let password_hash = derive_key(master_password.as_str(), &self.salt)
            .map_err(|e| VaultError::new(format!("{}", e)))?;

        let master_password_hash = general_purpose::STANDARD.decode(&self.master_password_hash_b64)
            .map_err(|e| VaultError::new(format!("{}", e)))?;

        if master_password_hash == password_hash {
            self.locked = false;

            if self.data.len() != 0 {
                let cipher_data: &[u8] = &general_purpose::STANDARD.decode(&self.data)
                    .map_err(|e| VaultError::new(format!("{}", e)))?;

                let nonce = self.get_nonce_u8()?;

                let decrypted_data = decrypt_json_data(&password_hash, cipher_data, &nonce);

                let passwords: Vec<Password> = serde_json::from_str(&decrypted_data)
                    .map_err(|_| VaultError::new("Could not deserialize password data".to_string()))?;

                self.password_manager.passwords = passwords;
            }
        }

        Ok(())
    }

    pub fn save() -> Result<(), VaultPersistError> {
        todo!("Implement this")
    }

    pub fn add_password(&mut self, name: String, password: String) {
        let new_password = Password {
            name,
            password,
        };
        self.password_manager.add_password(new_password);
    }

    pub fn generate_password(&mut self, password_request: PasswordRequest) -> Result<(), std::io::Error> {
        self.password_manager.generate_password(password_request)?;

        Ok(())
    }

    fn get_password_hash_u8(&self) -> Result<[u8; 32], VaultError> {
        let password_hash_vec = general_purpose::STANDARD.decode(&self.master_password_hash_b64)
            .map_err(|e| VaultError::new(format!("{}", e)))?;

        let password_hash: [u8; 32] = password_hash_vec
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::new("Password hash must be exactly 32 bytes!".to_string()))?;

        Ok(password_hash)
    }

    fn get_nonce_u8(&self) -> Result<[u8; 12], VaultError> {
        let nonce_vec = general_purpose::STANDARD.decode(&self.nonce)
            .map_err(|e| VaultError::new(format!("{}", e)))?;

        let nonce: [u8; 12] = nonce_vec
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::new("Nonce must be exactly 12 bytes!".to_string()))?;

        Ok(nonce)
    }

    fn get_vault_file(name: &str) -> Result<File, VaultInitError> {
        let vault_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&Self::get_vault_file_path(name))?;

        Ok(vault_file)
    }

    fn get_vault_file_path(name: &str) -> String {
        format!("{}/{}.okv", Self::DEFAULT_FILE_PATH, name)
    }
}

impl TryFrom<VaultData> for Vault {
    type Error = VaultInitError;

    fn try_from(vd: VaultData) -> Result<Self, Self::Error> {

        let vault_file = Self::get_vault_file(vd.name.as_str())?;

        Ok(Vault {
            proto: vd.proto,
            version: vd.version,
            name: vd.name,
            salt: vd.salt,
            nonce: vd.nonce,
            master_password_hash_b64: vd.master_password_hash_b64,
            data: vd.data,
            vault_file,
            password_manager: Manager::default(),
            locked: true,
        })
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Manager {
    pub passwords: Vec<Password>,
}

impl Manager {
    fn new() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }

    fn default() -> Self {
        Self {
            passwords: vec![]
        }
    }

    fn add_password(&mut self, password: Password) {
        self.passwords.push(password);
    }

    fn generate_password(&mut self, request: PasswordRequest) -> Result<(), std::io::Error> {
        let mut rng = rand::rng();

        let mut chars: Vec<char> = Vec::new();
        let mut pools: Vec<Box<dyn Fn() -> char>> = Vec::new();

        if request.lowercase {
            pools.push(Box::new(|| generate_letter(false)));
        }

        if request.uppercase {
            pools.push(Box::new(|| generate_letter(true)));
        }

        if request.numbers {
            pools.push(Box::new(|| generate_number()));
        }

        if request.specials {
            pools.push(Box::new(|| generate_special()));
        }

        if pools.is_empty() {
            panic!("No options selected for password generation.");
        }

        while chars.len() < request.length {
            let generator = pools.choose(&mut rng).unwrap();
            chars.push(generator());
        }

        chars.shuffle(&mut rng);

        let password_string = chars.iter().collect();

        let password = Password {
            password: password_string,
            name: request.name,
        };

        self.passwords.push(password);

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Password {
    pub password: String,
    pub name: String,
}

pub struct PasswordRequest {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub specials: bool,
    pub length: usize,
    pub name: String,
}
