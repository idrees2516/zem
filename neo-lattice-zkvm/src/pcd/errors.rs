// Error types for PCD

use std::fmt;

/// Errors that can occur during PCD operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PCDError {
    /// Invalid DAG structure
    InvalidDAG(String),
    
    /// Vertex not found
    VertexNotFound(usize),
    
    /// Edge not found
    EdgeNotFound { source: usize, target: usize },
    
    /// Cycle detected in DAG
    CycleDetected,
    
    /// Invalid compliance predicate
    InvalidCompliance(String),
    
    /// Compliance check failed
    ComplianceCheckFailed {
        vertex_id: usize,
        reason: String,
    },
    
    /// Extraction failed
    ExtractionFailed(String),
    
    /// Invalid proof
    InvalidProof(String),
    
    /// Verification failed
    VerificationFailed(String),
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
}

impl fmt::Display for PCDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDAG(msg) => write!(f, "Invalid DAG structure: {}", msg),
            Self::VertexNotFound(id) => write!(f, "Vertex not found: {}", id),
            Self::EdgeNotFound { source, target } => {
                write!(f, "Edge not found: {} -> {}", source, target)
            }
            Self::CycleDetected => write!(f, "Cycle detected in DAG"),
            Self::InvalidCompliance(msg) => write!(f, "Invalid compliance predicate: {}", msg),
            Self::ComplianceCheckFailed { vertex_id, reason } => {
                write!(f, "Compliance check failed at vertex {}: {}", vertex_id, reason)
            }
            Self::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
            Self::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for PCDError {}

/// Result type for PCD operations
pub type PCDResult<T> = Result<T, PCDError>;
