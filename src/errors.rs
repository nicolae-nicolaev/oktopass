use std::fmt;

#[derive(Debug, Clone)]
pub struct VaultInitError {
    message: String
}

impl VaultInitError {
    pub fn new(message: String) -> Self {
        Self {
            message: format!("VaultInitError: {}", message),
        }
    }
}

impl From<std::io::Error> for VaultInitError {
    fn from(e: std::io::Error) -> Self {
        VaultInitError {
            message: format!("I/O error: {}", e),
        }
    }
}

impl fmt::Display for VaultInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VaultInitError: {}", self.message)
    }
}

pub struct VaultPersistError {
    message: String
}

impl VaultPersistError {
    pub fn new(message: String) -> Self {
        Self {
            message: format!("VaultPersistError: {}", message),
        }
    }
}

impl From<std::io::Error> for VaultPersistError {
    fn from(e: std::io::Error) -> Self {
        VaultPersistError {
            message: format!("I/O error: {}", e),
        }
    }
}

pub struct VaultError {
    message: String,
}

impl VaultError {
    pub fn new(message: String) -> Self {
        Self { 
            message: format!("VaultError: {}", message),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError {
            message: format!("I/O error: {}", e),
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VaultError: {}", self.message)
    }
}
