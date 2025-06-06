use crate::generators::{generate_letter, generate_number, generate_special};

use std::fs::{ File, OpenOptions };
use std::io::{ Result, BufReader, Seek, SeekFrom };
use std::io::prelude::*;

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    pub password: String,
    pub name: String,
}

pub struct Manager {
    pub passwords: Vec<Password>,
    pub passwords_file: File,
}

pub struct PasswordRequest {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub specials: bool,
    pub length: usize,
    pub name: String,
}

impl Manager {
    pub fn new(file_path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_path)?;

        Ok(Self {
            passwords: Vec::new(),
            passwords_file: file,
        })
    }

    pub fn read_passwords_file(&mut self) -> Result<()> {
        let passwords: Vec<Password> = {
            let metadata = self.passwords_file.metadata()?;
            if metadata.len() == 0 {
                vec![]
            } else {
                let reader = BufReader::new(&self.passwords_file);
                serde_json::from_reader(reader)?
            }
        };

        self.passwords = passwords;

        Ok(())
    }

    pub fn write_passwords_file(&mut self) -> Result<()> {
        self.passwords_file.set_len(0)?;
        self.passwords_file.seek(SeekFrom::Start(0))?;

        let serialized = serde_json::to_string_pretty(&self.passwords).unwrap();
        self.passwords_file.write_all(serialized.as_bytes())?;

        Ok(())
    }

    pub fn generate(&mut self, request: PasswordRequest) -> Result<()> {
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
