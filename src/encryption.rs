#![allow(dead_code)] // TODO: remove this

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, password_hash::{
    SaltString,
    Error,
}};
use serde::{Deserialize};

pub fn derive_key(master_password: &str, salt: &SaltString) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];

    let argon2 = Argon2::default();
    let _password_hash = argon2
        .hash_password_into(
            master_password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key,
        )?;

    Ok(key)
}

pub fn generate_secret_b64<const N: usize>() -> [u8; N] {
    let mut secret = [0u8; N];
    rand::fill(&mut secret);

    secret
}

pub fn serialize_salt<S>(salt: &SaltString, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer, {
        serializer.serialize_str(salt.as_str())
}

pub fn deserialize_salt<'de, D>(deserializer: D) -> Result<SaltString, D::Error>
    where D: serde::Deserializer<'de>, {
        let salt = String::deserialize(deserializer)?;
        SaltString::from_b64(&salt).map_err(serde::de::Error::custom)
}

pub fn encrypt_json_data(key: &[u8; 32], plaintext: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

pub fn decrypt_json_data(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> String {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let decrypted_bytes = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).unwrap();
    String::from_utf8(decrypted_bytes).unwrap()
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::str::Bytes;
    use std::string::ToString;

    use argon2::password_hash::rand_core::OsRng;

    use super::*;

    #[test]
    fn encrypt_json_test() {
        let password = "R@nD0mP@sSw0rD";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = derive_key(password, &salt).unwrap();
        let nonce = generate_secret_b64::<12>();

        let plaintext_json = "[{name: google, password: \"An0tH3rP@sSw0rD\"},{name: apple, password: \"Y3tAn0Th3Rp@sSw0Rd\"}]";
        let encrypted_json = encrypt_json_data(&password_hash, plaintext_json.as_bytes(), &nonce);
        let decrypted_json = decrypt_json_data(&password_hash, &encrypted_json, &nonce);

        assert_eq!(decrypted_json, plaintext_json);
    }
}
