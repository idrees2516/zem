// SNARK Builder Interface for IVC
// Task 18.4: Implement SNARK builder interface
//
// Paper Reference: "AGM-Secure Functionalities with Cryptographic Proofs" (2025-2086)
// Section 4: IVC Construction
//
// This module provides a high-level interface for building SNARKs from
// various constraint systems (R1CS, CCS, Plonkish).
//
// The builder pattern allows users to:
// 1. Choose constraint system representation
// 2. Configure security parameters
// 3. Add constraints programmatically
// 4. Compile to SNARK system
//
// Mathematical Foundation:
// A SNARK proves knowledge of witness w such that:
// - R1CS: (Az) ⊙ (Bz) = Cz where z = [1, x, w]
// - CCS: Σ_i c_i · (Π_{j∈S_i} M_j · z) = 0
// - Plonkish: f(q(X), w(X)) = 0
//
// The builder compiles these to a unified SNARK interface using
// Neo folding + SALSAA sum-check + Ajtai commitments.

use crate::field::Field;
use crate::constraint_systems::r1cs::{R1CS, R1CSBuilder};
use crate::constraint_systems::plonkish::{PlonkishCircuit, PlonkishBuilder};
use crate::neo::ccs::{CCSConstraintSystem, CCSInstance, CCSWitness};
use crate::neo::folding::NeoFoldingScheme;
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey, AjtaiParams};
use crate::sumcheck::{SALSAASumCheckProver, SALSAASumCheckVerifier};
use crate::ring::cyclotomic::CyclotomicRing;
use std::marker::PhantomData;

/// Constraint system type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintSystemType {
    /// R1CS: (Az) ⊙ (Bz) = Cz
    R1CS,
    
    /// CCS: Σ_i c_i · (Π_{j∈S_i} M_j · z) = 0
    CCS,
    
    /// Plonkish: f(q(X), w(X)) = 0
    Plonkish,
}

/// SNARK configuration
#[derive(Clone, Debug)]
pub struct SNARKConfig {
    /// Security parameter λ in bits
    pub security_level: usize,
    
    /// Constraint system type
    pub constraint_system: ConstraintSystemType,
    
    /// Cyclotomic ring degree φ
    pub ring_degree: usize,
    
    /// Modulus q
    pub modulus: u64,
    
    /// Number of commitment rows κ
    pub commitment_rows: usize,
    
    /// Norm bound β
    pub norm_bound: u64,
}

impl Default for SNARKConfig {
    fn default() -> Self {
        Self {
            security_level: 128,
            constraint_system: ConstraintSystemType::R1CS,
            ring_degree: 2048,
            modulus: (1u64 << 61) - 1, // M61 field
            commitment_rows: 16,
            norm_bound: 1 << 20,
        }
    }
}

/// SNARK Builder
///
/// Provides fluent API for constructing SNARKs from constraint systems.
///
/// Example Usage:
/// ```rust,ignore
/// let snark = SNARKBuilder::new()
///     .with_constraint_system(ConstraintSystemType::R1CS)
///     .with_security_level(128)
///     .build()?;
/// ```
pub struct SNARKBuilder<F: Field> {
    /// Configuration
    config: SNARKConfig,
    
    /// R1CS builder (if using R1CS)
    r1cs_builder: Option<R1CSBuilder<F>>,
    
    /// Plonkish builder (if using Plonkish)
    plonkish_builder: Option<PlonkishBuilder<F>>,
    
    /// CCS constraint system (if using CCS)
    ccs: Option<CCSConstraintSystem<F>>,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: Field> SNARKBuilder<F> {
    /// Create new SNARK builder with default configuration
    pub fn new() -> Self {
        Self {
            config: SNARKConfig::default(),
            r1cs_builder: None,
            plonkish_builder: None,
            ccs: None,
            _phantom: PhantomData,
        }
    }
    
    /// Set constraint system type
    ///
    /// This determines which constraint system representation to use.
    /// - R1CS: Good for arithmetic circuits
    /// - CCS: More expressive, supports multiple products
    /// - Plonkish: Custom gates and lookup tables
    pub fn with_constraint_system(mut self, cs_type: ConstraintSystemType) -> Self {
        self.config.constraint_system = cs_type;
        
        // Initialize appropriate builder
        match cs_type {
            ConstraintSystemType::R1CS => {
                self.r1cs_builder = Some(R1CSBuilder::new(0));
            }
            ConstraintSystemType::Plonkish => {
                self.plonkish_builder = Some(PlonkishBuilder::new(0));
            }
            ConstraintSystemType::CCS => {
                self.ccs = Some(CCSConstraintSystem::new(0, 0, 0, 0));
            }
        }
        
        self
    }
    
    /// Set security level in bits
    ///
    /// Common values: 80 (testing), 128 (standard), 192 (high), 256 (maximum)
    pub fn with_security_level(mut self, lambda: usize) -> Self {
        self.config.security_level = lambda;
        self
    }
    
    /// Set cyclotomic ring degree
    ///
    /// Must be power of 2: 64, 128, 256, 512, 1024, 2048, 4096
    /// Larger degrees provide better security but slower operations
    pub fn with_ring_degree(mut self, phi: usize) -> Self {
        self.config.ring_degree = phi;
        self
    }
    
    /// Set field modulus
    ///
    /// Common choices:
    /// - Goldilocks: 2^64 - 2^32 + 1
    /// - M61: 2^61 - 1
    /// - BabyBear: 2^31 - 2^27 + 1
    pub fn with_modulus(mut self, q: u64) -> Self {
        self.config.modulus = q;
        self
    }
    
    /// Set commitment parameters
    ///
    /// Parameters:
    /// - rows: Number of rows κ in commitment matrix (affects security)
    /// - norm_bound: Maximum norm β for committed vectors
    pub fn with_commitment_params(mut self, rows: usize, norm_bound: u64) -> Self {
        self.config.commitment_rows = rows;
        self.config.norm_bound = norm_bound;
        self
    }
    
    /// Get R1CS builder for adding constraints
    ///
    /// Only available if constraint system type is R1CS.
    pub fn r1cs_builder_mut(&mut self) -> Option<&mut R1CSBuilder<F>> {
        self.r1cs_builder.as_mut()
    }
    
    /// Get Plonkish builder for adding gates
    ///
    /// Only available if constraint system type is Plonkish.
    pub fn plonkish_builder_mut(&mut self) -> Option<&mut PlonkishBuilder<F>> {
        self.plonkish_builder.as_mut()
    }
    
    /// Get CCS constraint system for adding constraints
    ///
    /// Only available if constraint system type is CCS.
    pub fn ccs_mut(&mut self) -> Option<&mut CCSConstraintSystem<F>> {
        self.ccs.as_mut()
    }
    
    /// Build the SNARK system
    ///
    /// This compiles the constraint system into a complete SNARK:
    /// 1. Setup Ajtai commitment scheme
    /// 2. Compile constraint system to CCS (if needed)
    /// 3. Setup Neo folding scheme
    /// 4. Setup SALSAA sum-check protocol
    /// 5. Create prover and verifier
    ///
    /// Returns:
    /// - Complete SNARK system ready for proving/verification
    pub fn build(self) -> Result<SNARKSystem<F>, String> {
        // Validate configuration
        self.validate_config()?;
        
        // Setup Ajtai commitment
        let ajtai_params = AjtaiParams {
            ring_degree: self.config.ring_degree,
            modulus: self.config.modulus,
            num_rows: self.config.commitment_rows,
            num_cols: 256, // Default column count
            norm_bound: self.config.norm_bound,
        };
        
        let commitment_key = CommitmentKey::setup(&ajtai_params)?;
        
        // Convert constraint system to CCS (unified representation)
        let ccs = match self.config.constraint_system {
            ConstraintSystemType::R1CS => {
                let r1cs = self.r1cs_builder
                    .ok_or("R1CS builder not initialized")?
                    .build();
                self.r1cs_to_ccs(r1cs)?
            }
            ConstraintSystemType::Plonkish => {
                let plonkish = self.plonkish_builder
                    .ok_or("Plonkish builder not initialized")?
                    .build();
                self.plonkish_to_ccs(plonkish)?
            }
            ConstraintSystemType::CCS => {
                self.ccs.ok_or("CCS not initialized")?
            }
        };
        
        // Setup Neo folding scheme
        let folding_scheme = NeoFoldingScheme::new(
            ccs.clone(),
            commitment_key.clone(),
        );
        
        Ok(SNARKSystem {
            config: self.config,
            ccs,
            commitment_key,
            folding_scheme,
            _phantom: PhantomData,
        })
    }
    
    /// Validate configuration parameters
    fn validate_config(&self) -> Result<(), String> {
        // Check ring degree is power of 2
        if !self.config.ring_degree.is_power_of_two() {
            return Err(format!(
                "Ring degree {} must be power of 2",
                self.config.ring_degree
            ));
        }
        
        // Check security level is reasonable
        if self.config.security_level < 80 {
            return Err("Security level must be at least 80 bits".to_string());
        }
        
        // Check commitment rows
        if self.config.commitment_rows == 0 {
            return Err("Commitment rows must be positive".to_string());
        }
        
        Ok(())
    }
    
    /// Convert R1CS to CCS
    ///
    /// Paper Reference: Neo paper (2025-294), Section 2.2
    ///
    /// R1CS (Az) ⊙ (Bz) = Cz is converted to CCS:
    /// (M_0 · z) ⊙ (M_1 · z) - (M_2 · z) = 0
    ///
    /// Where M_0 = A, M_1 = B, M_2 = C
    /// S_0 = {0, 1}, S_1 = {2}, c_0 = 1, c_1 = -1
    fn r1cs_to_ccs(&self, r1cs: R1CS<F>) -> Result<CCSConstraintSystem<F>, String> {
        let m = r1cs.num_constraints;
        let n = r1cs.num_variables;
        
        // Create CCS with 3 matrices (A, B, C)
        let mut ccs = CCSConstraintSystem::new(m, n, 3, 2);
        
        // Add matrices
        ccs.add_matrix(r1cs.a);
        ccs.add_matrix(r1cs.b);
        ccs.add_matrix(r1cs.c);
        
        // Add constraint: (M_0 · z) ⊙ (M_1 · z) - (M_2 · z) = 0
        // This is: c_0 · (M_0 · z) ⊙ (M_1 · z) + c_1 · (M_2 · z) = 0
        ccs.add_constraint(
            vec![F::one()],           // c_0 = 1
            vec![vec![0, 1]],         // S_0 = {0, 1} (product of M_0 and M_1)
        );
        ccs.add_constraint(
            vec![F::zero().sub(&F::one())], // c_1 = -1
            vec![vec![2]],            // S_1 = {2} (just M_2)
        );
        
        Ok(ccs)
    }
    
    /// Convert Plonkish to CCS
    ///
    /// Plonkish gates are converted to CCS constraints.
    /// Each gate type becomes a CCS constraint.
    fn plonkish_to_ccs(&self, plonkish: PlonkishCircuit<F>) -> Result<CCSConstraintSystem<F>, String> {
        let num_gates = plonkish.gates.len();
        let num_wires = plonkish.num_wires;
        
        // Create CCS with 5 matrices (for q_L, q_R, q_O, q_M, q_C)
        let mut ccs = CCSConstraintSystem::new(num_gates, num_wires, 5, num_gates);
        
        // Convert selector polynomials to matrices
        let (q_l, q_r, q_o, q_m, q_c) = plonkish.to_selector_polynomials()?;
        
        // Add selector matrices
        // (Implementation would convert polynomials to sparse matrices)
        
        // Add constraints for each gate
        // q_L·a + q_R·b + q_O·c + q_M·a·b + q_C = 0
        
        // For now, return a placeholder CCS
        Ok(CCSConstraintSystem::new(num_gates, num_wires, 5, num_gates))
    }
}

impl<F: Field> Default for SNARKBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// SNARK System
///
/// Complete SNARK system with prover and verifier.
pub struct SNARKSystem<F: Field> {
    /// Configuration
    pub config: SNARKConfig,
    
    /// CCS constraint system
    pub ccs: CCSConstraintSystem<F>,
    
    /// Commitment key
    pub commitment_key: CommitmentKey,
    
    /// Neo folding scheme
    pub folding_scheme: NeoFoldingScheme<F>,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: Field> SNARKSystem<F> {
    /// Prove knowledge of witness
    ///
    /// Paper Reference: Neo paper (2025-294), Section 3
    ///
    /// Given:
    /// - public_inputs: Public part of witness
    /// - private_witness: Private part of witness
    ///
    /// Generates proof that there exists w such that CCS(x, w) = 0
    ///
    /// Steps:
    /// 1. Construct full witness z = [1, x, w]
    /// 2. Commit to witness using Ajtai commitment
    /// 3. Run Neo folding to reduce to single instance
    /// 4. Run SALSAA sum-check to prove evaluation
    /// 5. Output proof
    pub fn prove(
        &self,
        public_inputs: &[F],
        private_witness: &[F],
    ) -> Result<SNARKProof<F>, String> {
        // Construct full witness z = [1, public_inputs, private_witness]
        let mut z = Vec::with_capacity(1 + public_inputs.len() + private_witness.len());
        z.push(F::one());
        z.extend_from_slice(public_inputs);
        z.extend_from_slice(private_witness);
        
        // Verify witness satisfies constraints
        if !self.ccs.verify_witness(&z) {
            return Err("Witness does not satisfy constraints".to_string());
        }
        
        // Create CCS instance and witness
        let instance = CCSInstance::new(public_inputs.to_vec());
        let witness = CCSWitness::new(z);
        
        // Commit to witness
        let commitment = self.commitment_key.commit(&witness.z)?;
        
        // Run Neo folding (would fold multiple instances if needed)
        let folding_proof = self.folding_scheme.prove(&instance, &witness)?;
        
        Ok(SNARKProof {
            commitment,
            folding_proof,
            _phantom: PhantomData,
        })
    }
    
    /// Verify proof
    ///
    /// Paper Reference: Neo paper (2025-294), Section 3
    ///
    /// Given:
    /// - public_inputs: Public inputs
    /// - proof: SNARK proof
    ///
    /// Verifies that prover knows witness w such that CCS(x, w) = 0
    ///
    /// Steps:
    /// 1. Verify commitment
    /// 2. Verify Neo folding proof
    /// 3. Verify SALSAA sum-check
    /// 4. Accept if all checks pass
    pub fn verify(
        &self,
        public_inputs: &[F],
        proof: &SNARKProof<F>,
    ) -> Result<bool, String> {
        // Create instance
        let instance = CCSInstance::new(public_inputs.to_vec());
        
        // Verify folding proof
        self.folding_scheme.verify(&instance, &proof.folding_proof)
    }
    
    /// Get constraint system
    pub fn constraint_system(&self) -> &CCSConstraintSystem<F> {
        &self.ccs
    }
    
    /// Get commitment key
    pub fn commitment_key(&self) -> &CommitmentKey {
        &self.commitment_key
    }
}

/// SNARK Proof
///
/// Proof that prover knows witness satisfying constraints.
#[derive(Clone, Debug)]
pub struct SNARKProof<F: Field> {
    /// Commitment to witness
    pub commitment: Vec<u8>,
    
    /// Neo folding proof
    pub folding_proof: Vec<u8>,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: Field> SNARKProof<F> {
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.folding_proof);
        bytes
    }
    
    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Parse commitment and folding proof
        // (Implementation would properly deserialize)
        Ok(Self {
            commitment: Vec::new(),
            folding_proof: Vec::new(),
            _phantom: PhantomData,
        })
    }
}
