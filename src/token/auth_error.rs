use std::{fmt, error::Error};

#[derive(Debug)]
pub enum PermLibError {
    FailToCreateToken,
    InvalidTokenFormat,
    InvalidPermissions,
    // Otros errores relacionados con autenticación
}

impl fmt::Display for PermLibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermLibError::FailToCreateToken => write!(f, "Failed to create token"),
            PermLibError::InvalidTokenFormat => write!(f, "Token format is invalid"),
            PermLibError::InvalidPermissions => write!(f, "Invalid permissions for the token"),
        }
    }
}

impl Error for PermLibError {}
