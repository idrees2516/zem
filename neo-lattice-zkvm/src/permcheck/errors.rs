// Error types for permutation check protocols

use std::fmt;

/// Errors that can occur during permutation check operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermCheckError {
    /// Invalid permutation (not a bijection)
    InvalidPermutation { reason: String },
    
    /// Permutation size mismatch
    PermutationSizeMismatch { expected: usize, got: usize },
    
    /// Invalid dimension
    InvalidDimension { expected: usize, got: usize },
    
    /// Invalid field size for security parameter
    InvalidFieldSize { field_bits: usize, required_bits: usize },
    
    /// Invalid group parameter
    InvalidGroupParameter { ell: usize, num_vars: usize },
    
    /// Lookup table size mismatch
    LookupTableSizeMismatch,
    
    /// Invalid lookup map
    InvalidLookupMap { reason: String },
    
    /// Polynomial degree mismatch
    DegreeMismatch { expected: usize, got: usize },
}

impl fmt::Display for PermCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermCheckError::InvalidPermutation { reason } => {
                write!(f, "Invalid permutation: {}", reason)
            }
            PermCheckError::PermutationSizeMismatch { expected, got } => {
                write!(f, "Permutation size mismatch: expected {}, got {}", expected, got)
            }
            PermCheckError::InvalidDimension { expected, got } => {
                write!(f, "Invalid dimension: expected {}, got {}", expected, got)
            }
            PermCheckError::InvalidFieldSize { field_bits, required_bits } => {
                write!(f, "Invalid field size: {} bits, need at least {} bits", 
                       field_bits, required_bits)
            }
            PermCheckError::InvalidGroupParameter { ell, num_vars } => {
                write!(f, "Invalid group parameter ℓ={} for μ={} variables", ell, num_vars)
            }
            PermCheckError::LookupTableSizeMismatch => {
                write!(f, "Lookup table size mismatch")
            }
            PermCheckError::InvalidLookupMap { reason } => {
                write!(f, "Invalid lookup map: {}", reason)
            }
            PermCheckError::DegreeMismatch { expected, got } => {
                write!(f, "Polynomial degree mismatch: expected {}, got {}", expected, got)
            }
        }
    }
}

impl std::error::Error for PermCheckError {}

/// Errors that can occur during verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Sumcheck round check failed
    SumcheckRoundCheckFailed {
        round: usize,
        expected: String,
        got: String,
    },
    
    /// Sumcheck final check failed
    SumcheckFinalCheckFailed {
        expected: String,
        got: String,
    },
    
    /// PCS commitment verification failed
    CommitmentVerificationFailed,
    
    /// PCS opening verification failed
    OpeningVerificationFailed { point: String },
    
    /// Invalid proof format
    InvalidProofFormat { reason: String },
    
    /// Proof deserialization failed
    DeserializationFailed { reason: String },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::SumcheckRoundCheckFailed { round, expected, got } => {
                write!(f, "Sumcheck round {} check failed: expected {}, got {}", 
                       round, expected, got)
            }
            VerificationError::SumcheckFinalCheckFailed { expected, got } => {
                write!(f, "Sumcheck final check failed: expected {}, got {}", expected, got)
            }
            VerificationError::CommitmentVerificationFailed => {
                write!(f, "PCS commitment verification failed")
            }
            VerificationError::OpeningVerificationFailed { point } => {
                write!(f, "PCS opening verification failed at point {}", point)
            }
            VerificationError::InvalidProofFormat { reason } => {
                write!(f, "Invalid proof format: {}", reason)
            }
            VerificationError::DeserializationFailed { reason } => {
                write!(f, "Proof deserialization failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for VerificationError {}
