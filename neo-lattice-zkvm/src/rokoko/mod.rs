// RoKoko: Lattice-based Succinct Arguments with Committed Refinement
// Complete production-ready implementation of the RoKoko protocol
// 
// This module implements the full RoKoko protocol as described in the paper,
// including:
// - Lattice-based polynomial commitment scheme with committed refinement
// - Multilinear polynomial evaluation proofs
// - Sumcheck protocol with batching optimizations
// - Refinement protocol for succinctness
// - Recursive composition for arbitrary computation
// - Security-hardened implementation with constant-time operations

pub mod commitment;
pub mod polynomial;
pub mod sumcheck;
pub mod refinement;
pub mod prover;
pub mod verifier;
pub mod transcript;
pub mod protocol;
pub mod batching;
pub mod optimization;
pub mod lattice;
pub mod ring_switching;
pub mod composition;
pub mod security;

pub use commitment::{RokokoCommitment, CommitmentScheme, CommitmentKey, Opening};
pub use polynomial::{MultilinearPolynomial, UnivariatePolynomial, PolynomialOps};
pub use sumcheck::{SumcheckProof, SumcheckProver, SumcheckVerifier, SumcheckRound};
pub use refinement::{RefinementProof, RefinementProtocol, RefinementLayer};
pub use prover::{RokokoProver, ProverState};
pub use verifier::{RokokoVerifier, VerifierState};
pub use transcript::{RokokoTranscript, TranscriptProtocol};
pub use protocol::{RokokoProtocol, RokokoProof, RokokoParams, PublicParams};
pub use lattice::{LatticeParams, LatticeElement, ModulusSwitching};
pub use ring_switching::{RingSwitchingProof, RingSwitchingProtocol};

use crate::errors::ZKVMError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Security parameter in bits (128-bit post-quantum security)
pub const SECURITY_PARAMETER: usize = 128;

/// Maximum degree for univariate polynomials in sumcheck
pub const MAX_DEGREE: usize = 8192;

/// Field element size in bytes (256-bit prime field)
pub const FIELD_ELEMENT_SIZE: usize = 32;

/// Lattice ring dimension for commitment scheme
pub const LATTICE_DIMENSION: usize = 2048;

/// Modulus for lattice operations (60-bit primes)
pub const LATTICE_MODULUS: u64 = (1u64 << 60) - 93;

/// Number of refinement rounds for succinctness
pub const REFINEMENT_ROUNDS: usize = 10;

/// Batch size for proof aggregation
pub const BATCH_SIZE: usize = 64;

/// Configuration for the RoKoko protocol with security-critical parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RokokoConfig {
    /// Security level in bits (must be >= 128 for post-quantum security)
    pub security_level: usize,
    
    /// Commitment size in lattice dimension
    pub commitment_size: usize,
    
    /// Number of refinement rounds (controls proof size vs verification time)
    pub refinement_depth: usize,
    
    /// Enable batching for multiple proofs
    pub use_batching: bool,
    
    /// Enable parallel proving (thread-safe)
    pub parallel_mode: bool,
    
    /// Enable ring switching optimization
    pub use_ring_switching: bool,
    
    /// Maximum circuit size supported
    pub max_circuit_size: usize,
    
    /// Enable constant-time operations for side-channel resistance
    pub constant_time: bool,
}

impl Default for RokokoConfig {
    fn default() -> Self {
        Self {
            security_level: SECURITY_PARAMETER,
            commitment_size: LATTICE_DIMENSION,
            refinement_depth: REFINEMENT_ROUNDS,
            use_batching: true,
            parallel_mode: true,
            use_ring_switching: true,
            max_circuit_size: 1 << 20, // 1M gates
            constant_time: true,
        }
    }
}

impl RokokoConfig {
    /// Validates configuration parameters for security
    pub fn validate(&self) -> Result<(), ZKVMError> {
        if self.security_level < 128 {
            return Err(ZKVMError::InvalidParameter(
                "Security level must be at least 128 bits".to_string()
            ));
        }
        
        if self.commitment_size < 1024 {
            return Err(ZKVMError::InvalidParameter(
                "Commitment size too small for security".to_string()
            ));
        }
        
        if self.refinement_depth < 3 {
            return Err(ZKVMError::InvalidParameter(
                "Refinement depth must be at least 3".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Returns recommended configuration for given security level
    pub fn for_security_level(bits: usize) -> Self {
        let mut config = Self::default();
        config.security_level = bits;
        
        // Scale parameters based on security level
        if bits >= 256 {
            config.commitment_size = 4096;
            config.refinement_depth = 15;
        } else if bits >= 192 {
            config.commitment_size = 3072;
            config.refinement_depth = 12;
        }
        
        config
    }
}

impl Zeroize for RokokoConfig {
    fn zeroize(&mut self) {
        self.security_level.zeroize();
        self.commitment_size.zeroize();
        self.refinement_depth.zeroize();
    }
}

impl Drop for RokokoConfig {
    fn drop(&mut self) {
        self.zeroize();
    }
}
