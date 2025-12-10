// Error types for Relativized SNARK module

use std::fmt;

/// Errors that can occur in relativized SNARK operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelSNARKError {
    /// Setup failed
    SetupFailed(String),
    
    /// Indexing failed
    IndexingFailed(String),
    
    /// Proving failed
    ProvingFailed(String),
    
    /// Verification failed
    VerificationFailed,
    
    /// Extraction failed
    ExtractionFailed(String),
    
    /// Circuit not satisfied
    CircuitNotSatisfied,
    
    /// Invalid witness
    InvalidWitness(String),
    
    /// Invalid statement
    InvalidStatement(String),
    
    /// Oracle error
    OracleError(String),
    
    /// AGM error
    AGMError(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
    
    /// Invalid parameters
    InvalidParameters(String),
}

impl fmt::Display for RelSNARKError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelSNARKError::SetupFailed(msg) => {
                write!(f, "Setup failed: {}", msg)
            }
            RelSNARKError::IndexingFailed(msg) => {
                write!(f, "Indexing failed: {}", msg)
            }
            RelSNARKError::ProvingFailed(msg) => {
                write!(f, "Proving failed: {}", msg)
            }
            RelSNARKError::VerificationFailed => {
                write!(f, "Verification failed")
            }
            RelSNARKError::ExtractionFailed(msg) => {
                write!(f, "Extraction failed: {}", msg)
            }
            RelSNARKError::CircuitNotSatisfied => {
                write!(f, "Circuit not satisfied")
            }
            RelSNARKError::InvalidWitness(msg) => {
                write!(f, "Invalid witness: {}", msg)
            }
            RelSNARKError::InvalidStatement(msg) => {
                write!(f, "Invalid statement: {}", msg)
            }
            RelSNARKError::OracleError(msg) => {
                write!(f, "Oracle error: {}", msg)
            }
            RelSNARKError::AGMError(msg) => {
                write!(f, "AGM error: {}", msg)
            }
            RelSNARKError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            RelSNARKError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
            RelSNARKError::InvalidParameters(msg) => {
                write!(f, "Invalid parameters: {}", msg)
            }
        }
    }
}

impl std::error::Error for RelSNARKError {}

/// Result type for relativized SNARK operations
pub type RelSNARKResult<T> = Result<T, RelSNARKError>;
