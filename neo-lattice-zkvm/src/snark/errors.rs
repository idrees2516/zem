// SNARK Error Types

use std::fmt;

/// Errors that can occur during SNARK operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SNARKError {
    /// Setup failed
    SetupFailed(String),
    
    /// Invalid witness
    InvalidWitness(String),
    
    /// Invalid statement
    InvalidStatement(String),
    
    /// Proving failed
    ProvingFailed(String),
    
    /// Verification failed
    VerificationFailed(String),
    
    /// Extraction failed
    ExtractionFailed(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
}

impl fmt::Display for SNARKError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupFailed(msg) => write!(f, "SNARK setup failed: {}", msg),
            Self::InvalidWitness(msg) => write!(f, "Invalid witness: {}", msg),
            Self::InvalidStatement(msg) => write!(f, "Invalid statement: {}", msg),
            Self::ProvingFailed(msg) => write!(f, "Proving failed: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Self::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for SNARKError {}

impl ToString for SNARKError {
    fn to_string(&self) -> String {
        format!("{}", self)
    }
}
