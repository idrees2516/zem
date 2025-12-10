// Core types for Oracle module

use serde::{Serialize, Deserialize};

/// Oracle distribution O_λ
///
/// Samples oracle θ: X → Y for specified domain X and codomain Y
pub trait OracleDistribution {
    /// Domain type
    type Domain;
    
    /// Codomain type
    type Codomain;
    
    /// Sample an oracle from the distribution
    fn sample(&self, security_parameter: usize) -> Box<dyn Oracle<Self::Domain, Self::Codomain>>;
}

/// Oracle response type
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OracleResponse {
    /// Response data
    pub data: Vec<u8>,
    
    /// Timestamp (for ordering)
    pub timestamp: u64,
}

impl OracleResponse {
    /// Create a new oracle response
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }
    
    /// Get the response data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Trait for oracle implementations
///
/// This is re-exported from transcript module for convenience
pub use super::transcript::Oracle;
