use std::fmt;

#[derive(Debug, Clone)]
pub struct VaultInitError {
    message: String
}

impl VaultInitError {
    pub fn new(message: String) -> Self {
        Self { message }
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
        write!(f, "Could not initialize vault")
    }
}
