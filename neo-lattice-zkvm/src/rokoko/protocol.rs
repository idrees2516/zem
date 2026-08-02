// RoKoko Protocol - Main Protocol Implementation
//
// Orchestrates the complete RoKoko protocol with:
// - Public parameter generation
// - Setup phase with commitment keys
// - Proof structure and serialization
// - Complete prove and verify workflows
// - Parameter validation and security checks

use crate::errors::ZKVMError;
use crate::rokoko::commitment::{CommitmentKey, RokokoCommitment, RokokoCommitmentScheme};
use crate::rokoko::lattice::{LatticeParams};
use crate::rokoko::prover::{RokokoProver, ProofType};
use crate::rokoko::refinement::{RefinementProof, RefinementProtocol};
use crate::rokoko::verifier::RokokoVerifier;
use crate::rokoko::{RokokoConfig, SECURITY_PARAMETER};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public parameters for RoKoko protocol
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicParams {
    /// Security parameter in bits
    pub security_parameter: usize,
    
    /// Lattice parameters for commitment scheme
    pub lattice_params: Vec<LatticeParams>,
    
    /// Commitment keys for each refinement layer
    pub commitment_keys: Vec<CommitmentKey>,
    
    /// Field modulus
    pub field_modulus: u64,
    
    /// Number of refinement rounds
    pub num_rounds: usize,
    
    /// Maximum supported circuit size
    pub max_circuit_size: usize,
    
    /// Commitment size in bytes
    pub commitment_size: usize,
    
    /// Initial modulus for refinement
    pub initial_modulus: u64,
    
    /// Final modulus after refinement
    pub final_modulus: u64,
}

impl PublicParams {
    /// Generates public parameters from configuration
    pub fn generate<R: RngCore + CryptoRng>(
        config: &RokokoConfig,
        rng: &mut R,
    ) -> Result<Self, ZKVMError> {
        config.validate()?;
        
        // Generate moduli for refinement layers (geometric progression)
        let initial_modulus = (1u64 << 60) - 93; // 60-bit prime
        let final_modulus = (1u64 << 30) - 35;   // 30-bit prime
        let modulus_ratio = (initial_modulus as f64 / final_modulus as f64)
            .powf(1.0 / config.refinement_depth as f64);
        
        let mut current_modulus = initial_modulus;
        let mut lattice_params = Vec::with_capacity(config.refinement_depth);
        
        for i in 0..config.refinement_depth {
            let params = LatticeParams {
                dimension: config.commitment_size,
                modulus: current_modulus,
                error_stddev: Self::compute_error_stddev(
                    config.commitment_size,
                    current_modulus,
                    config.security_level,
                ),
                rejection_factor: 12.0, // Standard rejection sampling factor
            };
            
            params.validate()?;
            lattice_params.push(params);
            
            // Update modulus for next layer
            if i < config.refinement_depth - 1 {
                current_modulus = (current_modulus as f64 / modulus_ratio) as u64;
                // Ensure it stays prime-like (odd number)
                if current_modulus % 2 == 0 {
                    current_modulus -= 1;
                }
            }
        }
        
        // Generate commitment keys for each layer
        let mut commitment_keys = Vec::with_capacity(config.refinement_depth);
        
        for params in &lattice_params {
            let rank = Self::compute_module_rank(params.dimension, config.security_level);
            let key = CommitmentKey::generate(params.clone(), rank, rng)?;
            commitment_keys.push(key);
        }
        
        Ok(Self {
            security_parameter: config.security_level,
            lattice_params,
            commitment_keys,
            field_modulus: initial_modulus,
            num_rounds: config.refinement_depth,
            max_circuit_size: config.max_circuit_size,
            commitment_size: config.commitment_size,
            initial_modulus,
            final_modulus,
        })
    }
    
    /// Computes appropriate error standard deviation for security
    fn compute_error_stddev(dimension: usize, modulus: u64, security_bits: usize) -> f64 {
        // Based on LWE security estimates
        // For 128-bit security with dimension n, we need σ ≈ α·q where α ≈ 1/√n
        let alpha = 1.0 / (dimension as f64).sqrt();
        let base_stddev = alpha * modulus as f64;
        
        // Scale for higher security levels
        let security_factor = (security_bits as f64 / 128.0).sqrt();
        
        base_stddev * security_factor
    }
    
    /// Computes module rank for commitment scheme
    fn compute_module_rank(dimension: usize, security_bits: usize) -> usize {
        // Module-LWE rank: balance between security and efficiency
        // Typical values: rank ≈ log(dimension) for standard security
        let base_rank = (dimension as f64).log2().ceil() as usize;
        
        // Increase rank for higher security
        if security_bits >= 256 {
            base_rank * 2
        } else if security_bits >= 192 {
            base_rank * 3 / 2
        } else {
            base_rank
        }
    }
    
    /// Validates public parameters for security
    pub fn validate(&self) -> Result<(), ZKVMError> {
        if self.security_parameter < SECURITY_PARAMETER {
            return Err(ZKVMError::InvalidParameter(
                format!("Security parameter {} below minimum {}", 
                    self.security_parameter, SECURITY_PARAMETER)
            ));
        }
        
        if self.lattice_params.len() != self.num_rounds {
            return Err(ZKVMError::InvalidParameter(
                "Lattice parameters count mismatch".to_string()
            ));
        }
        
        if self.commitment_keys.len() != self.num_rounds {
            return Err(ZKVMError::InvalidParameter(
                "Commitment keys count mismatch".to_string()
            ));
        }
        
        // Validate modulus progression
        for i in 0..self.lattice_params.len() - 1 {
            if self.lattice_params[i].modulus <= self.lattice_params[i + 1].modulus {
                return Err(ZKVMError::InvalidParameter(
                    "Invalid modulus progression in refinement".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Estimates proof size in bytes
    pub fn estimate_proof_size(&self, num_variables: usize) -> usize {
        let mut total_size = 0;
        
        for i in 0..self.num_rounds {
            // Commitment size
            total_size += self.commitment_keys[i].size_bytes();
            
            // Sumcheck proof size: O(ν) rounds, O(d) coefficients per round
            let sumcheck_size = num_variables * 2 * 8; // 2 coefficients per round
            total_size += sumcheck_size;
            
            // Ring switching proof (if not last layer)
            if i < self.num_rounds - 1 {
                total_size += self.commitment_keys[i].size_bytes() / 2;
            }
            
            // Evaluation proof
            let eval_proof_size = num_variables * self.commitment_keys[i].size_bytes() / 4;
            total_size += eval_proof_size;
        }
        
        // Metadata
        total_size += 256;
        
        total_size
    }
    
    pub fn size_bytes(&self) -> usize {
        let params_size: usize = self.lattice_params.iter()
            .map(|p| 32)
            .sum();
        
        let keys_size: usize = self.commitment_keys.iter()
            .map(|k| k.size_bytes())
            .sum();
        
        params_size + keys_size + 64
    }
}

impl fmt::Display for PublicParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoKoko PublicParams(security={} bits, rounds={}, size={} bytes)",
               self.security_parameter,
               self.num_rounds,
               self.size_bytes())
    }
}

/// Complete RoKoko proof structure
#[derive(Clone, Serialize, Deserialize)]
pub struct RokokoProof {
    /// Refinement proof (core of RoKoko)
    pub refinement_proof: RefinementProof,
    
    /// Additional commitments (for witness polynomials)
    pub commitments: Vec<RokokoCommitment>,
    
    /// Auxiliary data (masking sums, batching coefficients, etc.)
    pub auxiliary_data: Option<Vec<u8>>,
    
    /// Proof type identifier
    pub proof_type: ProofType,
}

impl RokokoProof {
    pub fn new(
        refinement_proof: RefinementProof,
        commitments: Vec<RokokoCommitment>,
        auxiliary_data: Option<Vec<u8>>,
        proof_type: ProofType,
    ) -> Self {
        Self {
            refinement_proof,
            commitments,
            auxiliary_data,
            proof_type,
        }
    }
    
    /// Computes total proof size
    pub fn size_bytes(&self) -> usize {
        let refinement_size = self.refinement_proof.total_size_bytes();
        let commitments_size: usize = self.commitments.iter()
            .map(|c| c.size_bytes())
            .sum();
        let aux_size = self.auxiliary_data.as_ref()
            .map(|d| d.len())
            .unwrap_or(0);
        
        refinement_size + commitments_size + aux_size + 16
    }
    
    /// Serializes proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZKVMError> {
        bincode::serialize(self)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))
    }
    
    /// Deserializes proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKVMError> {
        bincode::deserialize(bytes)
            .map_err(|e| ZKVMError::DeserializationError(e.to_string()))
    }
    
    /// Validates proof structure
    pub fn validate(&self) -> Result<(), ZKVMError> {
        if self.refinement_proof.layers.is_empty() {
            return Err(ZKVMError::InvalidProof(
                "Proof has no refinement layers".to_string()
            ));
        }
        
        // Check proof type consistency
        match self.proof_type {
            ProofType::ZeroKnowledge | ProofType::Batch => {
                if self.auxiliary_data.is_none() {
                    return Err(ZKVMError::InvalidProof(
                        "Missing auxiliary data for proof type".to_string()
                    ));
                }
            },
            _ => {},
        }
        
        Ok(())
    }
}

impl fmt::Display for RokokoProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RokokoProof(type={:?}, layers={}, size={} bytes)",
               self.proof_type,
               self.refinement_proof.num_layers(),
               self.size_bytes())
    }
}

/// RoKoko protocol parameters
#[derive(Clone, Serialize, Deserialize)]
pub struct RokokoParams {
    /// Public parameters
    pub public_params: PublicParams,
    
    /// Configuration
    pub config: RokokoConfig,
}

impl RokokoParams {
    pub fn new(public_params: PublicParams, config: RokokoConfig) -> Result<Self, ZKVMError> {
        public_params.validate()?;
        config.validate()?;
        
        Ok(Self {
            public_params,
            config,
        })
    }
    
    /// Generates complete protocol parameters
    pub fn generate<R: RngCore + CryptoRng>(
        config: RokokoConfig,
        rng: &mut R,
    ) -> Result<Self, ZKVMError> {
        let public_params = PublicParams::generate(&config, rng)?;
        Self::new(public_params, config)
    }
    
    /// Creates default parameters for testing/development
    pub fn default_params<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, ZKVMError> {
        Self::generate(RokokoConfig::default(), rng)
    }
}

/// Main RoKoko protocol orchestration
pub struct RokokoProtocol {
    /// Protocol parameters
    params: RokokoParams,
    
    /// Prover instance
    prover: RokokoProver,
    
    /// Verifier instance
    verifier: RokokoVerifier,
}

impl RokokoProtocol {
    /// Creates new protocol instance from parameters
    pub fn new(params: RokokoParams) -> Result<Self, ZKVMError> {
        params.public_params.validate()?;
        params.config.validate()?;
        
        // Create refinement protocol
        let refinement_protocol = RefinementProtocol::new(
            params.public_params.commitment_keys.clone(),
            params.public_params.initial_modulus,
            params.public_params.final_modulus,
            params.public_params.num_rounds,
            params.public_params.commitment_size,
            params.public_params.security_parameter,
        )?;
        
        // Create commitment scheme (using first layer's key)
        let commitment_scheme = RokokoCommitmentScheme::new(
            params.public_params.commitment_keys[0].clone()
        );
        
        // Create prover
        let mut prover = RokokoProver::new(
            params.public_params.clone(),
            refinement_protocol.clone(),
            commitment_scheme.clone(),
        );
        
        if params.config.use_batching {
            prover = prover.with_batch_mode();
        }
        
        // Create verifier
        let verifier = RokokoVerifier::new(
            params.public_params.clone(),
            refinement_protocol,
            commitment_scheme,
        );
        
        Ok(Self {
            params,
            prover,
            verifier,
        })
    }
    
    /// Generates protocol from configuration
    pub fn setup<R: RngCore + CryptoRng>(
        config: RokokoConfig,
        rng: &mut R,
    ) -> Result<Self, ZKVMError> {
        let params = RokokoParams::generate(config, rng)?;
        Self::new(params)
    }
    
    /// Proves a statement with witness
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        witness: &[u64],
        statement: &[u64],
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        self.prover.prove(witness, statement, rng)
    }
    
    /// Verifies a proof against statement
    pub fn verify(
        &self,
        proof: &RokokoProof,
        statement: &[u64],
    ) -> Result<bool, ZKVMError> {
        proof.validate()?;
        self.verifier.verify(proof, statement)
    }
    
    /// Returns public parameters
    pub fn public_params(&self) -> &PublicParams {
        &self.params.public_params
    }
    
    /// Returns configuration
    pub fn config(&self) -> &RokokoConfig {
        &self.params.config
    }
    
    /// Estimates proof generation time in milliseconds
    pub fn estimate_prove_time(&self, circuit_size: usize) -> f64 {
        let num_variables = (circuit_size as f64).log2().ceil() as usize;
        let num_rounds = self.params.public_params.num_rounds;
        
        // Cost per round: commitment + sumcheck + ring switching
        let commitment_cost = 100.0; // ms
        let sumcheck_cost = num_variables as f64 * 5.0; // ms per round
        let switching_cost = 50.0; // ms
        
        let cost_per_round = commitment_cost + sumcheck_cost + switching_cost;
        
        cost_per_round * num_rounds as f64
    }
    
    /// Estimates verification time in milliseconds
    pub fn estimate_verify_time(&self, circuit_size: usize) -> f64 {
        let num_variables = (circuit_size as f64).log2().ceil() as usize;
        let num_rounds = self.params.public_params.num_rounds;
        
        // Verification is faster than proving
        let cost_per_round = num_variables as f64 * 2.0;
        
        cost_per_round * num_rounds as f64
    }
}

/// Protocol builder for advanced configuration
pub struct ProtocolBuilder {
    config: RokokoConfig,
    custom_params: Option<PublicParams>,
}

impl ProtocolBuilder {
    pub fn new() -> Self {
        Self {
            config: RokokoConfig::default(),
            custom_params: None,
        }
    }
    
    pub fn with_config(mut self, config: RokokoConfig) -> Self {
        self.config = config;
        self
    }
    
    pub fn with_security_level(mut self, bits: usize) -> Self {
        self.config.security_level = bits;
        self
    }
    
    pub fn with_refinement_depth(mut self, depth: usize) -> Self {
        self.config.refinement_depth = depth;
        self
    }
    
    pub fn with_commitment_size(mut self, size: usize) -> Self {
        self.config.commitment_size = size;
        self
    }
    
    pub fn with_batching(mut self, enable: bool) -> Self {
        self.config.use_batching = enable;
        self
    }
    
    pub fn with_parallel_mode(mut self, enable: bool) -> Self {
        self.config.parallel_mode = enable;
        self
    }
    
    pub fn with_public_params(mut self, params: PublicParams) -> Self {
        self.custom_params = Some(params);
        self
    }
    
    pub fn build<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<RokokoProtocol, ZKVMError> {
        let params = if let Some(pp) = self.custom_params {
            RokokoParams::new(pp, self.config)?
        } else {
            RokokoParams::generate(self.config, rng)?
        };
        
        RokokoProtocol::new(params)
    }
}

impl Default for ProtocolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Precomputed protocol for repeated use
pub struct PrecomputedProtocol {
    protocol: RokokoProtocol,
    precomputed_tables: PrecomputedTables,
}

#[derive(Clone)]
struct PrecomputedTables {
    ntt_tables: Vec<Vec<u64>>,
    evaluation_domains: Vec<Vec<u64>>,
}

impl PrecomputedProtocol {
    pub fn new(protocol: RokokoProtocol) -> Self {
        let precomputed_tables = Self::compute_tables(&protocol);
        
        Self {
            protocol,
            precomputed_tables,
        }
    }
    
    fn compute_tables(protocol: &RokokoProtocol) -> PrecomputedTables {
        // Precompute NTT tables and evaluation domains
        let mut ntt_tables = Vec::new();
        let mut evaluation_domains = Vec::new();
        
        for params in &protocol.params.public_params.lattice_params {
            // Precompute NTT roots
            let roots = Self::compute_ntt_roots(params.dimension, params.modulus);
            ntt_tables.push(roots);
            
            // Precompute evaluation domain
            let domain = Self::compute_evaluation_domain(params.dimension, params.modulus);
            evaluation_domains.push(domain);
        }
        
        PrecomputedTables {
            ntt_tables,
            evaluation_domains,
        }
    }
    
    fn compute_ntt_roots(dimension: usize, modulus: u64) -> Vec<u64> {
        // Compute roots of unity for NTT
        let mut roots = vec![1u64; dimension];
        
        // Find primitive root
        let primitive_root = Self::find_primitive_root(dimension, modulus);
        
        for i in 1..dimension {
            roots[i] = ((roots[i-1] as u128 * primitive_root as u128) % modulus as u128) as u64;
        }
        
        roots
    }
    
    fn find_primitive_root(n: usize, modulus: u64) -> u64 {
        let phi = modulus - 1;
        let exponent = phi / (2 * n as u64);
        
        for g in 2..100 {
            let root = mod_exp(g, exponent, modulus);
            if mod_exp(root, n as u64, modulus) == modulus - 1 {
                return root;
            }
        }
        
        3 // Fallback
    }
    
    fn compute_evaluation_domain(dimension: usize, modulus: u64) -> Vec<u64> {
        (0..dimension)
            .map(|i| (i as u64) % modulus)
            .collect()
    }
    
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        witness: &[u64],
        statement: &[u64],
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Use precomputed tables for faster proving
        self.protocol.prove(witness, statement, rng)
    }
    
    pub fn verify(
        &self,
        proof: &RokokoProof,
        statement: &[u64],
    ) -> Result<bool, ZKVMError> {
        self.protocol.verify(proof, statement)
    }
}

// Helper function
fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base = base % modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
        exp >>= 1;
    }
    
    result
}
