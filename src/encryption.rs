use argon2::{Argon2, PasswordHasher, password_hash::{
    rand_core::OsRng,
    SaltString,
    Error
}};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Vault {
    proto: String,
    version: u8,
    name: String,
    #[serde(serialize_with = "serialize_salt", deserialize_with= "deserialize_salt")]
    salt: SaltString,
    nonce: String,
    master_password_hash: String,
    data: String,
}

impl Vault {
    pub fn new(name: &str, password: &str) -> Result<Self, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let nonce = generate_secret_b64::<12>();
        let master_password_hash = derive_key(password, &salt)?;
        Ok(Self {
            proto: String::from("OKTP"),
            version: 1,
            name: name.to_string(),
            salt,
            nonce,
            master_password_hash,
            data: String::from(""),
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_creation() {
        let vault_name = "Default";
        let password = "R@nd0MP@sSw0Rd";
        let vault = Vault::new(vault_name, password).unwrap();
        let expected_password_hash = derive_key(password, &vault.salt).unwrap();

        assert_eq!(vault.proto, "OKTP");
        assert_eq!(vault.version, 1);
        assert_eq!(vault.name, vault_name);
        assert_eq!(vault.password_hash, expected_password_hash);
    }
}
