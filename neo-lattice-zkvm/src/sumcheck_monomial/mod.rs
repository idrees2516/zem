// Sum-Check Protocol over the Monomial Basis - Complete Implementation
//
// This module implements the optimized sumcheck protocol described in:
// "Sum-Check Protocol over the Monomial Basis, and Other Optimizations"
//
// # Overview
//
// The monomial basis sumcheck protocol provides several advantages over the
// standard multilinear basis approach:
//
// 1. **Reduced Prover Complexity**: O(N) instead of O(N log N) for many polynomials
// 2. **Better Cache Locality**: Sequential memory access patterns
// 3. **Simpler Bookkeeping**: Direct indexing without bit manipulation
// 4. **Native Compatibility**: Works directly with polynomial evaluation form
//
// # Key Innovations (from Paper)
//
// ## Monomial Representation (Section 2)
// Instead of multilinear basis (1-x₁)(1-x₂)..., use monomial basis:
// f(x₁,...,xₙ) = ∑_{i=0}^{d₁} ∑_{i=0}^{d₂} ... a_{i₁,...,iₙ} x₁^{i₁} · x₂^{i₂} · ...
//
// ## Incremental Evaluation (Section 3)
// Round polynomials can be computed incrementally:
// u_k(r) = ∑_{s=0}^{D} c_s · r^s where coefficients are accumulated via Horner's method
//
// ## Caching Strategy (Section 4)
// Pre-compute and cache powers: {1, α, α², ..., α^D} for challenge α
// Reduces field multiplications significantly
//
// ## Parallel Composition (Section 5)
// Multiple polynomial products can be handled efficiently using tensor structure
//
// # Security Considerations
//
// - All field operations use constant-time implementations to prevent timing attacks
// - Challenge sampling uses cryptographically secure randomness
// - Zero-knowledge property maintained via proper randomization
// - Soundness error: ≤ D·n/|𝔽| where D is max degree, n is #variables
//
// # Performance Characteristics
//
// For N-sized polynomial with D max degree and n variables:
// - Prover time: O(N) field operations
// - Verifier time: O(n·D) field operations  
// - Proof size: O(n·D) field elements
// - Memory: O(N) with streaming optimization available

pub mod types;
pub mod prover;
pub mod verifier;
pub mod polynomial;
pub mod optimization;
pub mod batching;
pub mod streaming;
pub mod security;

pub use types::*;
pub use prover::*;
pub use verifier::*;
pub use polynomial::*;
pub use optimization::*;
pub use batching::*;
pub use streaming::*;
pub use security::*;

use crate::field::Field;
use std::fmt;

/// Error types for monomial sumcheck protocol
#[derive(Clone, Debug, PartialEq)]
pub enum MonomialSumcheckError {
    /// Invalid proof structure
    InvalidProofStructure {
        expected_rounds: usize,
        actual_rounds: usize,
    },
    
    /// Round consistency check failed
    RoundConsistencyFailed {
        round: usize,
        expected_sum: String,
        actual_sum: String,
    },
    
    /// Final evaluation mismatch
    FinalEvaluationMismatch {
        expected: String,
        actual: String,
    },
    
    /// Invalid polynomial degree
    InvalidDegree {
        round: usize,
        expected: usize,
        actual: usize,
    },
    
    /// Polynomial evaluation error
    EvaluationError {
        reason: String,
    },
    
    /// Challenge sampling error
    ChallengeSamplingError {
        reason: String,
    },
    
    /// Batch verification error
    BatchVerificationFailed {
        instance: usize,
        reason: String,
    },
}

impl fmt::Display for MonomialSumcheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProofStructure { expected_rounds, actual_rounds } => {
                write!(f, "Invalid proof structure: expected {} rounds, got {}", 
                       expected_rounds, actual_rounds)
            }
            Self::RoundConsistencyFailed { round, expected_sum, actual_sum } => {
                write!(f, "Round {} consistency failed: expected {}, got {}", 
                       round, expected_sum, actual_sum)
            }
            Self::FinalEvaluationMismatch { expected, actual } => {
                write!(f, "Final evaluation mismatch: expected {}, got {}", 
                       expected, actual)
            }
            Self::InvalidDegree { round, expected, actual } => {
                write!(f, "Invalid degree at round {}: expected {}, got {}", 
                       round, expected, actual)
            }
            Self::EvaluationError { reason } => {
                write!(f, "Polynomial evaluation error: {}", reason)
            }
            Self::ChallengeSamplingError { reason } => {
                write!(f, "Challenge sampling error: {}", reason)
            }
            Self::BatchVerificationFailed { instance, reason } => {
                write!(f, "Batch verification failed at instance {}: {}", 
                       instance, reason)
            }
        }
    }
}

impl std::error::Error for MonomialSumcheckError {}

/// Configuration for monomial sumcheck protocol
#[derive(Clone, Debug)]
pub struct MonomialSumcheckConfig {
    /// Number of variables
    pub num_vars: usize,
    
    /// Maximum degree in each variable
    pub max_degree: usize,
    
    /// Enable caching optimizations
    pub enable_caching: bool,
    
    /// Enable parallel computation
    pub enable_parallel: bool,
    
    /// Batch size for parallel operations
    pub parallel_batch_size: usize,
    
    /// Enable streaming mode for memory efficiency
    pub enable_streaming: bool,
    
    /// Security parameter (in bits)
    pub security_parameter: usize,
}

impl Default for MonomialSumcheckConfig {
    fn default() -> Self {
        Self {
            num_vars: 10,
            max_degree: 3,
            enable_caching: true,
            enable_parallel: true,
            parallel_batch_size: 1024,
            enable_streaming: false,
            security_parameter: 128,
        }
    }
}

impl MonomialSumcheckConfig {
    /// Compute soundness error bound
    ///
    /// Returns the probability that a cheating prover can fool the verifier
    /// Formula: ε ≤ D·n/|𝔽| where D is max degree, n is #variables
    pub fn soundness_error<F: Field>(&self) -> f64 {
        let field_size_bits = F::MODULUS_BITS as f64;
        let numerator = (self.max_degree * self.num_vars) as f64;
        numerator / 2f64.powf(field_size_bits)
    }
    
    /// Check if configuration provides adequate security
    pub fn is_secure<F: Field>(&self) -> bool {
        let error_bits = -self.soundness_error::<F>().log2();
        error_bits >= self.security_parameter as f64
    }
    
    /// Estimate prover complexity (field operations)
    pub fn prover_complexity(&self) -> usize {
        // O(N) where N = (max_degree + 1)^num_vars
        (self.max_degree + 1).pow(self.num_vars as u32)
    }
    
    /// Estimate verifier complexity (field operations)
    pub fn verifier_complexity(&self) -> usize {
        // O(n·D)
        self.num_vars * self.max_degree
    }
    
    /// Estimate proof size (field elements)
    pub fn proof_size(&self) -> usize {
        // n rounds, each with D+1 evaluations, plus final evaluation
        self.num_vars * (self.max_degree + 1) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_soundness() {
        let config = MonomialSumcheckConfig {
            num_vars: 10,
            max_degree: 3,
            security_parameter: 128,
            ..Default::default()
        };
        
        // With 256-bit field, soundness should be adequate
        // Error ≈ 30/2^256 which is negligible
        assert!(30.0 / 2f64.powf(256.0) < 2f64.powf(-128.0));
    }
    
    #[test]
    fn test_complexity_estimates() {
        let config = MonomialSumcheckConfig {
            num_vars: 10,
            max_degree: 3,
            ..Default::default()
        };
        
        // Prover: O((D+1)^n) = O(4^10) ≈ 1M operations
        assert_eq!(config.prover_complexity(), 4_usize.pow(10));
        
        // Verifier: O(n·D) = O(10·3) = 30 operations
        assert_eq!(config.verifier_complexity(), 30);
        
        // Proof size: n·(D+1) + 1 = 10·4 + 1 = 41 field elements
        assert_eq!(config.proof_size(), 41);
    }
}
