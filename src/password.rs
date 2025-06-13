use crate::generators::{ generate_letter, generate_number, generate_special };
use crate::encryption::{ serialize_salt, deserialize_salt, generate_secret_b64, derive_key };
use crate::errors::{ VaultInitError };

use std::fs::{ File, OpenOptions };
use std::io::{ BufReader, Seek, SeekFrom };
use std::convert::TryFrom;

use argon2::{ password_hash::{
    rand_core::OsRng,
    SaltString,
}};

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

use serde::{ Deserialize, Serialize, Deserializer };

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    proto: String,
    version: u8,
    name: String,
    #[serde(serialize_with="serialize_salt", deserialize_with="deserialize_salt")]
    salt: SaltString,
    nonce: String,
    master_password_hash: String,
    data: String,

}

pub struct Vault {
    proto: String,
    version: u8,
    name: String,
    password_manager: Manager,
    vault_file: File,
    salt: SaltString,
    nonce: String,
    master_password_hash: String,
    data: String,
}

impl Vault {
    const DEFAULT_FILE_PATH: &str = "~/.oktopass";

    pub fn new(name: &str, password: &str) -> Result<Self, VaultInitError> {
        let salt = SaltString::generate(&mut OsRng);
        let nonce = generate_secret_b64::<12>();
        let master_password_hash = derive_key(password, &salt)
            .map_err(|e| VaultInitError::new(format!("Vault initialization failed: {}", e)))?;

        let vault_file = Self::get_vault_file(name)?;

        Ok(Self {
            proto: String::from("OKTP"),
            version: 1,
            name: name.to_string(),
            password_manager: Manager::default(),
            vault_file,
            salt,
            nonce,
            master_password_hash,
            data: String::from(""),
        })
    }

    pub fn load_from_vault_file(name: &str) -> Result<Self, VaultInitError> {
        let vault_file = OpenOptions::new()
            .read(true)
            .open(&Self::get_vault_file_path(name))?;

        let vault_data: VaultData = {
            let reader = BufReader::new(&vault_file);
            serde_json::from_reader(reader)
                .map_err(|e| VaultInitError::new(format!("Could not load vault from file: {}", e)))?
        };

        let vault = Vault::try_from(vault_data)?;

        Ok(vault)
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
            master_password_hash: vd.master_password_hash,
            data: vd.data,
            vault_file,
            password_manager: Manager::default(),
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
        // TODO: return Result<>
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
