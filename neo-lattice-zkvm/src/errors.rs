// Error types for Neo Lattice zkVM
//
// Comprehensive error handling for all protocol components

use std::fmt;
use std::error::Error;

/// Main error type for zkVM operations
#[derive(Debug, Clone)]
pub enum ZKVMError {
    /// Invalid parameter provided
    InvalidParameter(String),
    
    /// Invalid proof structure or content
    InvalidProof(String),
    
    /// Invalid commitment
    InvalidCommitment(String),
    
    /// Proof generation failed
    ProofGenerationError(String),
    
    /// Proof generation failed  
    ProofGenerationFailed(String),
    
    /// Verification failed
    VerificationError(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
    
    /// Polynomial operation error
    PolynomialError(String),
    
    /// Lattice operation error
    LatticeError(String),
    
    /// Commitment scheme error
    CommitmentError(String),
    
    /// Transcript error
    TranscriptError(String),
    
    /// Configuration error
    ConfigError(String),
    
    /// I/O error
    IoError(String),
    
    /// Out of bounds access
    OutOfBounds(String),
    
    /// Unsupported operation
    UnsupportedOperation(String),
    
    /// Internal error
    InternalError(String),
}

impl fmt::Display for ZKVMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZKVMError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            ZKVMError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            ZKVMError::InvalidCommitment(msg) => write!(f, "Invalid commitment: {}", msg),
            ZKVMError::ProofGenerationError(msg) => write!(f, "Proof generation error: {}", msg),
            ZKVMError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            ZKVMError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            ZKVMError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ZKVMError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            ZKVMError::PolynomialError(msg) => write!(f, "Polynomial error: {}", msg),
            ZKVMError::LatticeError(msg) => write!(f, "Lattice error: {}", msg),
            ZKVMError::CommitmentError(msg) => write!(f, "Commitment error: {}", msg),
            ZKVMError::TranscriptError(msg) => write!(f, "Transcript error: {}", msg),
            ZKVMError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            ZKVMError::IoError(msg) => write!(f, "I/O error: {}", msg),
            ZKVMError::OutOfBounds(msg) => write!(f, "Out of bounds: {}", msg),
            ZKVMError::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),
            ZKVMError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for ZKVMError {}

impl From<std::io::Error> for ZKVMError {
    fn from(err: std::io::Error) -> Self {
        ZKVMError::IoError(err.to_string())
    }
}

impl From<bincode::Error> for ZKVMError {
    fn from(err: bincode::Error) -> Self {
        ZKVMError::SerializationError(err.to_string())
    }
}

/// Result type alias for zkVM operations
pub type ZKVMResult<T> = Result<T, ZKVMError>;
