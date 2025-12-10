// Error types for Oracle module

use std::fmt;

/// Errors that can occur in oracle operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// Oracle query failed
    QueryFailed(String),
    
    /// Oracle transcript is inconsistent
    InconsistentTranscript,
    
    /// Oracle response mismatch
    ResponseMismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    
    /// Oracle not initialized
    NotInitialized,
    
    /// Invalid oracle state
    InvalidState(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
    
    /// Emulation error
    EmulationError(String),
    
    /// Signing oracle error
    SigningError(String),
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::QueryFailed(msg) => {
                write!(f, "Oracle query failed: {}", msg)
            }
            OracleError::InconsistentTranscript => {
                write!(f, "Oracle transcript is inconsistent")
            }
            OracleError::ResponseMismatch { expected, actual } => {
                write!(f, "Oracle response mismatch: expected {:?}, got {:?}", expected, actual)
            }
            OracleError::NotInitialized => {
                write!(f, "Oracle not initialized")
            }
            OracleError::InvalidState(msg) => {
                write!(f, "Invalid oracle state: {}", msg)
            }
            OracleError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            OracleError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
            OracleError::EmulationError(msg) => {
                write!(f, "Emulation error: {}", msg)
            }
            OracleError::SigningError(msg) => {
                write!(f, "Signing error: {}", msg)
            }
        }
    }
}

impl std::error::Error for OracleError {}

/// Result type for oracle operations
pub type OracleResult<T> = Result<T, OracleError>;
