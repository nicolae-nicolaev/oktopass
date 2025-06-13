use argon2::{Argon2, PasswordHasher, password_hash::{
    SaltString,
    Error
}};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize};

pub fn derive_key(master_password: &str, salt: &SaltString) -> Result<String, Error> {
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(master_password.as_bytes(), salt)?
        .to_string();

    Ok(password_hash)
}

pub fn generate_secret_b64<const N: usize>() -> String {
    let mut salt = [0u8; N];
    rand::fill(&mut salt);

    general_purpose::STANDARD.encode(salt)
}

pub fn serialize_salt<S>(salt: &SaltString, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer, {
        serializer.serialize_str(salt.as_str())
}

pub fn deserialize_salt<'de, D>(deserializer: D) -> Result<SaltString, D::Error>
    where D: serde::Deserializer<'de>, {
        let salt = String::deserialize(deserializer)?;
        SaltString::new(&salt).map_err(serde::de::Error::custom)
}
