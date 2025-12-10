// Error types for AGM module

use std::fmt;

/// Errors that can occur in AGM operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AGMError {
    /// Group representation is missing for an output element
    MissingRepresentation,
    
    /// Group representation verification failed (y ≠ Γ^T x)
    InvalidRepresentation,
    
    /// Basis element not found in representation
    BasisElementNotFound,
    
    /// Coefficient matrix dimensions mismatch
    DimensionMismatch {
        expected: usize,
        actual: usize,
    },
    
    /// Adversary output is not algebraic (missing representations)
    NonAlgebraicOutput,
    
    /// Group element serialization failed
    SerializationError(String),
    
    /// Group element deserialization failed
    DeserializationError(String),
    
    /// Invalid basis (empty or contains identity)
    InvalidBasis(String),
}

impl fmt::Display for AGMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AGMError::MissingRepresentation => {
                write!(f, "Group representation missing for output element")
            }
            AGMError::InvalidRepresentation => {
                write!(f, "Group representation verification failed: y ≠ Γ^T x")
            }
            AGMError::BasisElementNotFound => {
                write!(f, "Basis element not found in representation")
            }
            AGMError::DimensionMismatch { expected, actual } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, actual)
            }
            AGMError::NonAlgebraicOutput => {
                write!(f, "Adversary output is not algebraic (missing representations)")
            }
            AGMError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            AGMError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
            AGMError::InvalidBasis(msg) => {
                write!(f, "Invalid basis: {}", msg)
            }
        }
    }
}

impl std::error::Error for AGMError {}

/// Result type for AGM operations
pub type AGMResult<T> = Result<T, AGMError>;
