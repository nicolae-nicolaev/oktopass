#![allow(dead_code)] // TODO: remove this

use crate::encryption::{
    decrypt_json_data, derive_key, deserialize_salt, encrypt_json_data, generate_secret_b64,
    serialize_salt,
};
use crate::errors::{VaultError, VaultInitError, VaultPersistError};
use crate::generators::{generate_letter, generate_number, generate_special};

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Seek, SeekFrom, Write};

use argon2::password_hash::{SaltString, rand_core::OsRng};

use base64::{Engine as _, engine::general_purpose};

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    proto: String,
    version: u8,
    name: String,
    #[serde(
        serialize_with = "serialize_salt",
        deserialize_with = "deserialize_salt"
    )]
    salt: SaltString,
    nonce: String,
    master_password_hash_b64: String,
    data: String,
}

impl TryFrom<&Vault> for VaultData {
    type Error = VaultPersistError;

    fn try_from(vault: &Vault) -> Result<Self, Self::Error> {
        let passwords = &vault.password_manager.passwords;

        let passwords_json = serde_json::to_string(&passwords)
            .map_err(|e| VaultPersistError::new(format!("{e}")))?;

        let master_password_hash = vault
            .get_password_hash_u8()
            .map_err(|e| VaultPersistError::new(format!("{e}")))?;

        let nonce = vault
            .get_nonce_u8()
            .map_err(|e| VaultPersistError::new(format!("{e}")))?;

        let passwords_json_cipher =
            encrypt_json_data(&master_password_hash, &passwords_json.into_bytes(), &nonce);

        let passwords_json_cipher_b64 = general_purpose::STANDARD.encode(passwords_json_cipher);

        Ok(Self {
            proto: vault.proto.clone(),
            version: vault.version,
            name: vault.name.clone(),
            salt: vault.salt.clone(),
            nonce: vault.nonce.clone(),
            master_password_hash_b64: vault.master_password_hash_b64.clone(),
            data: passwords_json_cipher_b64,
        })
    }
}

pub struct Vault {
    proto: String,
    version: u8,
    pub name: String,
    password_manager: Manager,
    vault_file: File,
    pub salt: SaltString,
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
            .map_err(|e| VaultInitError::new(format!("Vault initialization failed: {e}")))?;

        let master_password_hash_b64 = general_purpose::STANDARD.encode(master_password_hash);

        let vault_file = Self::get_vault_file(name)
            .map_err(|_| VaultInitError::new(format!("Could not load {name} vault file")))?;

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

    pub fn load(name: &str) -> Result<Self, VaultInitError> {
        let vault_file = OpenOptions::new()
            .read(true)
            .open(Self::get_vault_file_path(name))?;

        let vault_data: VaultData = {
            let reader = BufReader::new(&vault_file);
            serde_json::from_reader(reader)
                .map_err(|e| VaultInitError::new(format!("Could not load vault from file: {e}")))?
        };

        let vault = Vault::try_from(vault_data)?;

        Ok(vault)
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<(), VaultError> {
        let password_hash =
            derive_key(master_password, &self.salt).map_err(|e| VaultError::new(format!("{e}")))?;

        let master_password_hash = general_purpose::STANDARD
            .decode(&self.master_password_hash_b64)
            .map_err(|e| VaultError::new(format!("{e}")))?;

        if master_password_hash == password_hash {
            self.locked = false;

            if !self.data.is_empty() {
                let cipher_data: &[u8] = &general_purpose::STANDARD
                    .decode(&self.data)
                    .map_err(|e| VaultError::new(format!("{e}")))?;

                let nonce = self.get_nonce_u8()?;

                let decrypted_data = decrypt_json_data(&password_hash, cipher_data, &nonce);

                let passwords: Vec<Password> =
                    serde_json::from_str(&decrypted_data).map_err(|_| {
                        VaultError::new("Could not deserialize password data".to_string())
                    })?;

                self.password_manager.passwords = passwords;
            }
        }

        Ok(())
    }

    pub fn add_password(&mut self, name: &str, password: &str) -> Result<(), VaultError> {
        if self.locked {
            Err(VaultError::new(
                "Cannot add password to vault. Vault is locked.".to_string(),
            ))
        } else {
            let new_password = Password {
                name: name.to_string(),
                password: password.to_string(),
            };

            self.password_manager.add_password(new_password);

            Ok(())
        }
    }

    pub fn save(&self) -> Result<(), VaultPersistError> {
        let vault_data = VaultData::try_from(self)?;

        let vault_json = serde_json::to_string_pretty(&vault_data)
            .map_err(|_| VaultPersistError::new("Could not serialize vault".to_string()))?;

        let mut vault_file = Self::get_vault_file(&self.name).map_err(|_| {
            VaultPersistError::new(format!("Could not get {} vault file", &self.name))
        })?;

        vault_file.set_len(0)?;
        vault_file.seek(SeekFrom::Start(0))?;

        vault_file.write_all(vault_json.as_bytes())?;

        Ok(())
    }

    pub fn get_passwords(&self) -> Result<&[Password], VaultError> {
        if self.locked {
            Err(VaultError::new(
                "Vault is locked. Unlock it first.".to_string(),
            ))
        } else {
            Ok(&self.password_manager.passwords)
        }
    }

    pub fn get_password(&self, name: &str) -> Option<Password> {
        self.get_passwords()
            .ok()
            .and_then(|passwords| passwords.iter().find(|p| p.name == name).cloned())
    }

    pub fn get_passwords_service_names(&self) -> Result<Vec<String>, VaultError> {
        let mut passwords = vec![];

        match self.get_passwords() {
            Ok(result) => {
                for password in result {
                    passwords.push(password.name.clone());
                }

                Ok(passwords)
            }
            Err(err) => Err(VaultError::new(err.message)),
        }
    }

    pub fn generate_password(
        &mut self,
        password_request: PasswordRequest,
    ) -> Result<String, VaultError> {
        if self.locked {
            Err(VaultError::new(
                "Cannot generate a password. Vault is locked.".to_string(),
            ))
        } else {
            Ok(self
                .password_manager
                .generate_password(password_request)
                .map_err(|e| VaultError::new(format!("Could not generate password: {e}")))?)
        }
    }

    fn get_password_hash_u8(&self) -> Result<[u8; 32], VaultError> {
        let password_hash_vec = general_purpose::STANDARD
            .decode(&self.master_password_hash_b64)
            .map_err(|e| VaultError::new(format!("{e}")))?;

        let password_hash: [u8; 32] = password_hash_vec
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::new("Password hash must be exactly 32 bytes!".to_string()))?;

        Ok(password_hash)
    }

    fn get_nonce_u8(&self) -> Result<[u8; 12], VaultError> {
        let nonce_vec = general_purpose::STANDARD
            .decode(&self.nonce)
            .map_err(|e| VaultError::new(format!("{e}")))?;

        let nonce: [u8; 12] = nonce_vec
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::new("Nonce must be exactly 12 bytes!".to_string()))?;

        Ok(nonce)
    }

    fn get_vault_file(name: &str) -> Result<File, VaultError> {
        let path = Self::get_vault_file_path(name);

        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let vault_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(Self::get_vault_file_path(name))?;

        Ok(vault_file)
    }

    fn get_vault_file_path(name: &str) -> String {
        let home_dir = dirs::home_dir().expect("Could not determine home directory.");
        format!("{}/.oktopass/{}.okv", home_dir.display(), name)
    }
}

impl TryFrom<VaultData> for Vault {
    type Error = VaultInitError;

    fn try_from(vd: VaultData) -> Result<Self, Self::Error> {
        let vault_file = Self::get_vault_file(vd.name.as_str())
            .map_err(|_| VaultInitError::new(format!("Could not load {} vault file", &vd.name)))?;

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
        Self { passwords: vec![] }
    }

    fn add_password(&mut self, password: Password) {
        self.passwords.push(password);
    }

    fn generate_password(&mut self, request: PasswordRequest) -> Result<String, std::io::Error> {
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
            pools.push(Box::new(generate_number));
        }

        if request.specials {
            pools.push(Box::new(generate_special));
        }

        if pools.is_empty() {
            panic!("No options selected for password generation.");
        }

        while chars.len() < request.length {
            let generator = pools.choose(&mut rng).unwrap();
            chars.push(generator());
        }

        chars.shuffle(&mut rng);

        let password_string: String = chars.iter().collect();

        let password = Password {
            password: password_string.clone(),
            name: request.name,
        };

        self.passwords.push(password);

        Ok(password_string)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Password {
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
