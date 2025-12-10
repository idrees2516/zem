// Error types for aggregate signatures

use std::fmt;

/// Errors that can occur during aggregate signature operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateSignatureError {
    /// Setup failed
    SetupFailed(String),
    
    /// Invalid number of signatures
    InvalidSignatureCount {
        expected: usize,
        got: usize,
    },
    
    /// Signature verification failed for a specific index
    SignatureVerificationFailed {
        index: usize,
        reason: String,
    },
    
    /// Oracle forcing failed
    OracleForcingFailed(String),
    
    /// Group element extraction failed
    GroupElementExtractionFailed(String),
    
    /// SNARK proof generation failed
    ProofGenerationFailed(String),
    
    /// SNARK proof verification failed
    ProofVerificationFailed(String),
    
    /// Invalid statement
    InvalidStatement(String),
    
    /// Invalid witness
    InvalidWitness(String),
    
    /// Oracle response mismatch
    OracleResponseMismatch {
        expected: Vec<u8>,
        got: Vec<u8>,
    },
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
}

impl fmt::Display for AggregateSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupFailed(msg) => write!(f, "Aggregate signature setup failed: {}", msg),
            Self::InvalidSignatureCount { expected, got } => {
                write!(f, "Invalid signature count: expected {}, got {}", expected, got)
            }
            Self::SignatureVerificationFailed { index, reason } => {
                write!(f, "Signature verification failed at index {}: {}", index, reason)
            }
            Self::OracleForcingFailed(msg) => write!(f, "Oracle forcing failed: {}", msg),
            Self::GroupElementExtractionFailed(msg) => {
                write!(f, "Group element extraction failed: {}", msg)
            }
            Self::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            Self::ProofVerificationFailed(msg) => write!(f, "Proof verification failed: {}", msg),
            Self::InvalidStatement(msg) => write!(f, "Invalid statement: {}", msg),
            Self::InvalidWitness(msg) => write!(f, "Invalid witness: {}", msg),
            Self::OracleResponseMismatch { expected, got } => {
                write!(f, "Oracle response mismatch: expected {:?}, got {:?}", expected, got)
            }
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for AggregateSignatureError {}

/// Result type for aggregate signature operations
pub type AggregateSignatureResult<T> = Result<T, AggregateSignatureError>;
