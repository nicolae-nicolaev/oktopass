use crate::generators::{ generate_letter, generate_number, generate_special };
use crate::encryption::{ serialize_salt, deserialize_salt, generate_secret_b64, derive_key };
use crate::errors::{ VaultInitError };

use std::fs::{ File, OpenOptions };
use std::io::{ BufReader, Seek, SeekFrom };
use std::io::prelude::*;

use argon2::{ password_hash::{
    rand_core::OsRng,
    SaltString,
    Error
}};

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

use serde::{ Deserialize, Serialize, Deserializer };

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    proto: String,
    version: u8,
    name: String,
    #[serde(serialize_with = "serialize_salt", deserialize_with= "deserialize_salt")]
    salt: SaltString,
    nonce: String,
    master_password_hash: String,
    data: String,

}

#[derive(Serialize)]
pub struct Vault {
    proto: String,
    version: u8,
    name: String,
    password_manager: Manager,
    #[serde(skip_serializing)]
    vault_file: File,
    #[serde(serialize_with = "serialize_salt", deserialize_with= "deserialize_salt")]
    salt: SaltString,
    nonce: String,
    master_password_hash: String,
    data: String,
}

impl Vault {
    pub fn new(name: &str, password: &str) -> Result<Self, VaultInitError> {
        let salt = SaltString::generate(&mut OsRng);
        let nonce = generate_secret_b64::<12>();
        let master_password_hash = derive_key(password, &salt)
            .map_err(|e| VaultInitError::new(format!("Vault initialization failed: {}", e)))?;

        let filename = format!("{}.okv", name);
        let vault_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&filename)?;

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

    pub fn add_password(&mut self, name: String, password: String) {
        // TODO: return Result<>
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

//    pub fn persist(&mut self) -> Result<()> {
//    }
}

impl<'de> Deserialize<'de> for Vault {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de>, {
        let data = VaultData::deserialize(deserializer)?;

        let filename = format!("{}.okv", data.name);

        let vault_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&filename)
            .map_err(serde::de::Error::custom)?;

        Ok(Vault {
            proto: data.proto,
            version: data.version,
            name: data.name,
            salt: data.salt,
            nonce: data.nonce,
            master_password_hash: data.master_password_hash,
            data: data.data,
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


