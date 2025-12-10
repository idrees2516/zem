// AHP Error Types

use std::fmt;

#[derive(Debug, Clone)]
pub enum AHPError {
    /// Invalid proof structure
    InvalidProof(String),
    
    /// Polynomial evaluation failed
    EvaluationFailed(String),
    
    /// Degree bound exceeded
    DegreeBoundExceeded { expected: usize, actual: usize },
    
    /// Invalid round number
    InvalidRound(usize),
    
    /// Compilation failed
    CompilationFailed(String),
    
    /// PCS error
    PCSError(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Invalid parameters
    InvalidParameters(String),
}

impl fmt::Display for AHPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AHPError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            AHPError::EvaluationFailed(msg) => write!(f, "Evaluation failed: {}", msg),
            AHPError::DegreeBoundExceeded { expected, actual } => {
                write!(f, "Degree bound exceeded: expected {}, got {}", expected, actual)
            }
            AHPError::InvalidRound(round) => write!(f, "Invalid round: {}", round),
            AHPError::CompilationFailed(msg) => write!(f, "Compilation failed: {}", msg),
            AHPError::PCSError(msg) => write!(f, "PCS error: {}", msg),
            AHPError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            AHPError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
        }
    }
}

impl std::error::Error for AHPError {}

pub type AHPResult<T> = Result<T, AHPError>;
