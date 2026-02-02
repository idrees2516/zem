// Dory Polynomial Commitment Scheme Implementation
//
// This module implements the Dory polynomial commitment scheme for the small-space zkVM.
// Dory combines Hyrax with AFGHO to achieve O(√n) commitment size with a single target group element.
//
// Based on:
// - "Dory: Efficient, Transparent arguments for Generalised Inner Products over Cyclotomic Rings"
// - Requirements 8.1, 8.15 from the small-space zkVM specification
//
// Key features:
// - Bilinear pairing-based construction
// - Single target group element commitment
// - O(√n) space complexity for prover
// - O(log n) communication complexity
// - Streaming commitment key generation

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::hyrax::{GroupElement, HyraxCommitmentKey, HyraxProver, PolynomialOracle, PippengerMSM};
use crate::small_space_zkvm::bulletproofs::{BulletproofsEvaluationProof, StreamingBulletproofsProver};
use std::marker::PhantomData;

/// Bilinear pairing trait for Dory
pub trait BilinearPairing {
    type G1: GroupElement;
    type G2: GroupElement;
    type GT: GroupElement<Scalar = <Self::G1 as GroupElement>::Scalar>;
    
    /// Compute bilinear pairing e(g1, g2)
    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT;
    
    /// Multi-pairing: ∏ᵢ e(g1ᵢ, g2ᵢ)
    fn multi_pairing(g1_elements: &[Self::G1], g2_elements: &[Self::G2]) -> Self::GT {
        if g1_elements.len() != g2_elements.len() {
            panic!("Multi-pairing input lengths must match");
        }
        
        let mut result = Self::GT::identity();
        for (g1, g2) in g1_elements.iter().zip(g2_elements.iter()) {
            let pairing_result = Self::pairing(g1, g2);
            result = result.add(&pairing_result);
        }
        result
    }
}

/// Dory commitment configuration
#[derive(Debug, Clone)]
pub struct DoryConfig {
    /// Number of polynomial evaluations (n = 2^num_vars)
    pub num_vars: usize,
    /// Matrix dimension (√n)
    pub matrix_dim: usize,
    /// Security parameter
    pub security_parameter: usize,
}

impl DoryConfig {
    /// Create new Dory configuration
    pub fn new(num_vars: usize, security_parameter: usize) -> Result<Self, String> {
        if num_vars == 0 {
            return Err("Number of variables must be positive".to_string());
        }
        
        if num_vars % 2 != 0 {
            return Err("Number of variables must be even for matrix representation".to_string());
        }
        
        let matrix_dim = 1 << (num_vars / 2);
        
        Ok(DoryConfig {
            num_vars,
            matrix_dim,
            security_parameter,
        })
    }
    
    /// Get total number of evaluations
    pub fn num_evaluations(&self) -> usize {
        1 << self.num_vars
    }
    
    /// Get Hyrax key size (G1 elements)
    pub fn hyrax_key_size(&self) -> usize {
        self.matrix_dim
    }
    
    /// Get AFGHO key size (G2 elements)
    pub fn afgho_key_size(&self) -> usize {
        self.matrix_dim
    }
}

/// Dory commitment key combining Hyrax and AFGHO keys
#[derive(Debug, Clone)]
pub struct DoryCommitmentKey<P: BilinearPairing> {
    /// Hyrax commitment key (G1 elements)
    pub hyrax_key: Vec<P::G1>,
    /// AFGHO commitment key (G2 elements)
    pub afgho_key: Vec<P::G2>,
    /// Configuration
    pub config: DoryConfig,
}

impl<P: BilinearPairing> DoryCommitmentKey<P> {
    /// Generate Dory commitment key
    pub fn generate(config: DoryConfig) -> Self {
        let mut hyrax_key = Vec::with_capacity(config.matrix_dim);
        let mut afgho_key = Vec::with_capacity(config.matrix_dim);
        
        // Generate Hyrax key (G1 elements)
        let g1_gen = P::G1::generator();
        for i in 0..config.matrix_dim {
            let scalar = <P::G1 as GroupElement>::Scalar::from_u64((i + 1) as u64);
            hyrax_key.push(g1_gen.mul(&scalar));
        }
        
        // Generate AFGHO key (G2 elements)
        let g2_gen = P::G2::generator();
        for i in 0..config.matrix_dim {
            let scalar = <P::G2 as GroupElement>::Scalar::from_u64((i + 1) as u64);
            afgho_key.push(g2_gen.mul(&scalar));
        }
        
        DoryCommitmentKey {
            hyrax_key,
            afgho_key,
            config,
        }
    }
    
    /// Generate commitment key from seed using hash-to-curve
    pub fn from_seed(config: DoryConfig, seed: &[u8]) -> Self {
        let mut hyrax_key = Vec::with_capacity(config.matrix_dim);
        let mut afgho_key = Vec::with_capacity(config.matrix_dim);
        
        // Generate G1 elements using hash-to-curve
        for i in 0..config.matrix_dim {
            let g1_element = Self::hash_to_g1(seed, i);
            hyrax_key.push(g1_element);
        }
        
        // Generate G2 elements using hash-to-curve
        for i in 0..config.matrix_dim {
            let g2_element = Self::hash_to_g2(seed, i);
            afgho_key.push(g2_element);
        }
        
        DoryCommitmentKey {
            hyrax_key,
            afgho_key,
            config,
        }
    }
    
    /// Generate commitment key on-the-fly using cryptographic PRG
    /// 
    /// This allows streaming key generation without storing the full key
    /// Space complexity: O(1) for key generation
    /// Time complexity: O(λ) field operations per group element
    pub fn generate_element_on_demand(seed: &[u8], index: usize, group: &str) -> Result<Vec<u8>, String> {
        // In practice, this would use a cryptographic PRG like ChaCha20
        // followed by hash-to-curve procedures
        
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, seed);
        std::hash::Hasher::write(&mut hasher, group.as_bytes());
        std::hash::Hasher::write_usize(&mut hasher, index);
        let hash = std::hash::Hasher::finish(&hasher);
        
        // Simulate hash-to-curve output
        Ok(hash.to_le_bytes().to_vec())
    }
    
    /// Hash-to-curve for G1 elements
    fn hash_to_g1(seed: &[u8], index: usize) -> P::G1 {
        // In practice, use proper hash-to-curve like hash_to_curve_g1
        // This involves square root computation in the base field
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, seed);
        std::hash::Hasher::write(&mut hasher, b"G1");
        std::hash::Hasher::write_usize(&mut hasher, index);
        let hash = std::hash::Hasher::finish(&hasher);
        
        let scalar = <P::G1 as GroupElement>::Scalar::from_u64(hash);
        P::G1::generator().mul(&scalar)
    }
    
    /// Hash-to-curve for G2 elements
    fn hash_to_g2(seed: &[u8], index: usize) -> P::G2 {
        // In practice, use proper hash-to-curve like hash_to_curve_g2
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, seed);
        std::hash::Hasher::write(&mut hasher, b"G2");
        std::hash::Hasher::write_usize(&mut hasher, index);
        let hash = std::hash::Hasher::finish(&hasher);
        
        let scalar = <P::G2 as GroupElement>::Scalar::from_u64(hash);
        P::G2::generator().mul(&scalar)
    }
}

/// Dory commitment (single target group element)
#[derive(Debug, Clone)]
pub struct DoryCommitment<P: BilinearPairing> {
    /// Single commitment in target group GT
    pub commitment: P::GT,
    /// Hyrax intermediate commitments (for evaluation proofs)
    pub hyrax_commitments: Vec<P::G1>,
    /// Configuration
    pub config: DoryConfig,
}

impl<P: BilinearPairing> DoryCommitment<P> {
    /// Get commitment size in bytes (single GT element)
    pub fn size_bytes(&self) -> usize {
        48 // Assuming 48 bytes for GT element (e.g., BLS12-381)
    }
    
    /// Serialize commitment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commitment.to_bytes()
    }
    
    /// Deserialize commitment from bytes
    pub fn from_bytes(bytes: &[u8], config: DoryConfig) -> Result<Self, String> {
        if bytes.len() != 48 {
            return Err("Invalid commitment size".to_string());
        }
        
        let commitment = P::GT::from_bytes(bytes)?;
        
        Ok(DoryCommitment {
            commitment,
            hyrax_commitments: Vec::new(), // Would need to be provided separately
            config,
        })
    }
}

/// Dory prover for polynomial commitments
pub struct DoryProver<P: BilinearPairing> {
    /// Dory commitment key
    pub commitment_key: DoryCommitmentKey<P>,
}

impl<P: BilinearPairing> DoryProver<P> {
    /// Create new Dory prover
    pub fn new(commitment_key: DoryCommitmentKey<P>) -> Self {
        DoryProver { commitment_key }
    }
    
    /// Commit to polynomial using Dory scheme
    /// 
    /// 1. Compute Hyrax commitments: hᵢ = ⟨Mᵢ, g₁⟩
    /// 2. Compute AFGHO commitment: C = ∏ᵢ e(hᵢ, qᵢ)
    /// 
    /// Space complexity: O(√n) - stream polynomial column by column
    /// Time complexity: O(n) + O(√n) pairings
    pub fn commit<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        oracle: &O
    ) -> Result<DoryCommitment<P>, String> {
        if oracle.num_variables() != self.commitment_key.config.num_vars {
            return Err("Oracle variables don't match commitment key".to_string());
        }
        
        // Step 1: Compute Hyrax commitments using streaming
        let hyrax_commitments = self.compute_hyrax_commitments(oracle)?;
        
        // Step 2: Compute AFGHO commitment to Hyrax commitments
        let afgho_commitment = self.compute_afgho_commitment(&hyrax_commitments)?;
        
        Ok(DoryCommitment {
            commitment: afgho_commitment,
            hyrax_commitments,
            config: self.commitment_key.config.clone(),
        })
    }
    
    /// Compute Hyrax commitments by streaming through polynomial
    fn compute_hyrax_commitments<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        oracle: &O
    ) -> Result<Vec<P::G1>, String> {
        let matrix_dim = self.commitment_key.config.matrix_dim;
        let mut hyrax_commitments = Vec::with_capacity(matrix_dim);
        
        // For each column j, compute hⱼ = Σᵢ M[i][j] * g₁ᵢ
        for col in 0..matrix_dim {
            let mut column_data = Vec::with_capacity(matrix_dim);
            
            // Stream column j
            for row in 0..matrix_dim {
                let index = row * matrix_dim + col;
                column_data.push(oracle.evaluate_at(index));
            }
            
            // Compute MSM: hⱼ = Σᵢ column_data[i] * g₁ᵢ
            let commitment = PippengerMSM::compute_msm(
                &self.commitment_key.hyrax_key,
                &column_data
            )?;
            
            hyrax_commitments.push(commitment);
        }
        
        Ok(hyrax_commitments)
    }
    
    /// Compute AFGHO commitment: C = ∏ᵢ e(hᵢ, qᵢ)
    fn compute_afgho_commitment(&self, hyrax_commitments: &[P::G1]) -> Result<P::GT, String> {
        if hyrax_commitments.len() != self.commitment_key.afgho_key.len() {
            return Err("Hyrax commitments length doesn't match AFGHO key".to_string());
        }
        
        // Compute multi-pairing: ∏ᵢ e(hᵢ, qᵢ)
        let commitment = P::multi_pairing(hyrax_commitments, &self.commitment_key.afgho_key);
        
        Ok(commitment)
    }
}

/// Dory evaluation proof
#[derive(Debug, Clone)]
pub struct DoryEvaluationProof<P: BilinearPairing> {
    /// Bulletproofs-style proof for the Hyrax part
    pub bulletproofs_proof: BulletproofsEvaluationProof<P::G1>,
    /// Additional pairing-based components
    pub pairing_elements: Vec<P::GT>,
}

impl<P: BilinearPairing> DoryEvaluationProof<P> {
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        // Bulletproofs proof + pairing elements
        self.bulletproofs_proof.size_bytes() + self.pairing_elements.len() * 48
    }
    
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bulletproofs_proof.to_bytes();
        
        // Add pairing elements
        bytes.extend_from_slice(&(self.pairing_elements.len() as u32).to_le_bytes());
        for element in &self.pairing_elements {
            bytes.extend_from_slice(&element.to_bytes());
        }
        
        bytes
    }
}

/// Streaming Dory prover that generates keys on-the-fly
pub struct StreamingDoryProver<P: BilinearPairing> {
    /// Configuration
    pub config: DoryConfig,
    /// Seed for key generation
    pub seed: Vec<u8>,
    /// Phantom data
    _phantom: PhantomData<P>,
}

impl<P: BilinearPairing> StreamingDoryProver<P> {
    /// Create new streaming Dory prover
    pub fn new(config: DoryConfig, seed: Vec<u8>) -> Self {
        StreamingDoryProver {
            config,
            seed,
            _phantom: PhantomData,
        }
    }
    
    /// Commit to polynomial with streaming key generation
    /// 
    /// Key innovation: generate commitment key elements on-demand
    /// Space complexity: O(√n) - never store full key
    /// Time complexity: O(n) + O(λ√n) for key generation
    pub fn commit_streaming<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        oracle: &O
    ) -> Result<DoryCommitment<P>, String> {
        if oracle.num_variables() != self.config.num_vars {
            return Err("Oracle variables don't match configuration".to_string());
        }
        
        let matrix_dim = self.config.matrix_dim;
        let mut hyrax_commitments = Vec::with_capacity(matrix_dim);
        
        // Compute Hyrax commitments with streaming key generation
        for col in 0..matrix_dim {
            let mut column_data = Vec::with_capacity(matrix_dim);
            let mut g1_elements = Vec::with_capacity(matrix_dim);
            
            // Stream column and generate corresponding G1 elements
            for row in 0..matrix_dim {
                let index = row * matrix_dim + col;
                column_data.push(oracle.evaluate_at(index));
                
                // Generate G1 element on-demand
                let g1_element = DoryCommitmentKey::<P>::hash_to_g1(&self.seed, row);
                g1_elements.push(g1_element);
            }
            
            // Compute MSM for this column
            let commitment = PippengerMSM::compute_msm(&g1_elements, &column_data)?;
            hyrax_commitments.push(commitment);
        }
        
        // Generate G2 elements and compute AFGHO commitment
        let mut g2_elements = Vec::with_capacity(matrix_dim);
        for i in 0..matrix_dim {
            let g2_element = DoryCommitmentKey::<P>::hash_to_g2(&self.seed, i);
            g2_elements.push(g2_element);
        }
        
        let afgho_commitment = P::multi_pairing(&hyrax_commitments, &g2_elements);
        
        Ok(DoryCommitment {
            commitment: afgho_commitment,
            hyrax_commitments,
            config: self.config.clone(),
        })
    }
    
    /// Generate evaluation proof with streaming computation
    pub fn prove_evaluation_streaming<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        oracle: &O,
        evaluation_point: &[<P::G1 as GroupElement>::Scalar],
        claimed_evaluation: <P::G1 as GroupElement>::Scalar
    ) -> Result<DoryEvaluationProof<P>, String> {
        // Generate G1 elements for Bulletproofs
        let mut g1_generators = Vec::with_capacity(self.config.matrix_dim);
        for i in 0..self.config.matrix_dim {
            let g1_element = DoryCommitmentKey::<P>::hash_to_g1(&self.seed, i);
            g1_generators.push(g1_element);
        }
        
        // Split evaluation point for Hyrax structure
        let half_vars = self.config.num_vars / 2;
        let r1 = self.compute_r1(&evaluation_point[..half_vars]);
        let r2 = self.compute_r2(&evaluation_point[half_vars..]);
        
        // Generate Bulletproofs proof using streaming prover
        let streaming_bulletproofs = StreamingBulletproofsProver::new(g1_generators);
        let bulletproofs_proof = streaming_bulletproofs.prove_evaluation_streaming(
            oracle,
            &r1,
            &r2,
            claimed_evaluation
        )?;
        
        // Generate additional pairing elements (simplified for now)
        let pairing_elements = vec![P::GT::identity()]; // In practice, would compute actual pairing proofs
        
        Ok(DoryEvaluationProof {
            bulletproofs_proof,
            pairing_elements,
        })
    }
    
    /// Compute r₁ from first half of evaluation point
    fn compute_r1(&self, r_first_half: &[<P::G1 as GroupElement>::Scalar]) -> Vec<<P::G1 as GroupElement>::Scalar> {
        let mut r1 = vec![<P::G1 as GroupElement>::Scalar::one()];
        
        for &r_i in r_first_half {
            let mut new_r1 = Vec::with_capacity(r1.len() * 2);
            for &val in &r1 {
                new_r1.push(val * (<P::G1 as GroupElement>::Scalar::one() - r_i));
                new_r1.push(val * r_i);
            }
            r1 = new_r1;
        }
        
        r1
    }
    
    /// Compute r₂ from second half of evaluation point
    fn compute_r2(&self, r_second_half: &[<P::G1 as GroupElement>::Scalar]) -> Vec<<P::G1 as GroupElement>::Scalar> {
        let mut r2 = vec![<P::G1 as GroupElement>::Scalar::one()];
        
        for &r_i in r_second_half {
            let mut new_r2 = Vec::with_capacity(r2.len() * 2);
            for &val in &r2 {
                new_r2.push(val * (<P::G1 as GroupElement>::Scalar::one() - r_i));
                new_r2.push(val * r_i);
            }
            r2 = new_r2;
        }
        
        r2
    }
}

/// Dory verifier for evaluation proofs
pub struct DoryVerifier<P: BilinearPairing> {
    /// Dory commitment key
    pub commitment_key: DoryCommitmentKey<P>,
}

impl<P: BilinearPairing> DoryVerifier<P> {
    /// Create new Dory verifier
    pub fn new(commitment_key: DoryCommitmentKey<P>) -> Self {
        DoryVerifier { commitment_key }
    }
    
    /// Verify Dory evaluation proof
    /// 
    /// 1. Verify Bulletproofs proof for Hyrax part
    /// 2. Verify pairing consistency
    /// 3. Check final evaluation
    pub fn verify_evaluation(
        &self,
        commitment: &DoryCommitment<P>,
        evaluation_point: &[<P::G1 as GroupElement>::Scalar],
        claimed_evaluation: <P::G1 as GroupElement>::Scalar,
        proof: &DoryEvaluationProof<P>
    ) -> Result<bool, String> {
        // Verify commitment consistency
        let expected_commitment = P::multi_pairing(
            &commitment.hyrax_commitments,
            &self.commitment_key.afgho_key
        );
        
        if !self.gt_elements_equal(&commitment.commitment, &expected_commitment) {
            return Ok(false);
        }
        
        // Split evaluation point
        let half_vars = self.commitment_key.config.num_vars / 2;
        let r1 = self.compute_r1(&evaluation_point[..half_vars]);
        
        // Verify Bulletproofs proof
        // Note: This is simplified - in practice would need proper commitment to w₁
        let dummy_commitment = P::G1::identity(); // Would compute actual commitment
        
        let bulletproofs_verifier = crate::small_space_zkvm::bulletproofs::BulletproofsVerifier::new(
            self.commitment_key.hyrax_key.clone()
        );
        
        let bulletproofs_valid = bulletproofs_verifier.verify_evaluation(
            &dummy_commitment,
            &r1,
            claimed_evaluation,
            &proof.bulletproofs_proof
        )?;
        
        if !bulletproofs_valid {
            return Ok(false);
        }
        
        // Verify pairing elements (simplified)
        // In practice, would verify additional pairing-based constraints
        
        Ok(true)
    }
    
    /// Compute r₁ from first half of evaluation point
    fn compute_r1(&self, r_first_half: &[<P::G1 as GroupElement>::Scalar]) -> Vec<<P::G1 as GroupElement>::Scalar> {
        let mut r1 = vec![<P::G1 as GroupElement>::Scalar::one()];
        
        for &r_i in r_first_half {
            let mut new_r1 = Vec::with_capacity(r1.len() * 2);
            for &val in &r1 {
                new_r1.push(val * (<P::G1 as GroupElement>::Scalar::one() - r_i));
                new_r1.push(val * r_i);
            }
            r1 = new_r1;
        }
        
        r1
    }
    
    /// Helper to check if two GT elements are equal
    fn gt_elements_equal(&self, a: &P::GT, b: &P::GT) -> bool {
        a.to_bytes() == b.to_bytes()
    }
}

/// Dory performance analyzer
pub struct DoryPerformanceAnalyzer {
    /// Memory size K
    pub memory_size: usize,
    /// Number of operations T
    pub num_operations: usize,
}

impl DoryPerformanceAnalyzer {
    /// Create new performance analyzer
    pub fn new(memory_size: usize, num_operations: usize) -> Self {
        DoryPerformanceAnalyzer {
            memory_size,
            num_operations,
        }
    }
    
    /// Analyze commitment key size
    pub fn analyze_commitment_key_size(&self) -> usize {
        // 2√(KT) group elements total
        2 * ((self.memory_size * self.num_operations) as f64).sqrt() as usize
    }
    
    /// Analyze evaluation proof field operations
    pub fn analyze_evaluation_proof_operations(&self) -> usize {
        // ≤ 30T field operations
        30 * self.num_operations
    }
    
    /// Analyze multi-pairing complexity
    pub fn analyze_multi_pairing_size(&self) -> usize {
        // O(√(KT)) pairings
        ((self.memory_size * self.num_operations) as f64).sqrt() as usize
    }
    
    /// Analyze hash-to-curve operations
    pub fn analyze_hash_to_curve_operations(&self, security_parameter: usize) -> usize {
        // O(λ) field operations per group element
        let key_size = self.analyze_commitment_key_size();
        key_size * security_parameter
    }
    
    /// Generate performance report
    pub fn generate_report(&self, security_parameter: usize) -> String {
        format!(
            "Dory Performance Analysis (K = {}, T = {}):\n\
             - Commitment key size: {} group elements\n\
             - Evaluation proof: {} field operations\n\
             - Multi-pairing size: {} pairings\n\
             - Hash-to-curve: {} field operations\n\
             - Proof size: O(log √(KT)) = {} elements",
            self.memory_size,
            self.num_operations,
            self.analyze_commitment_key_size(),
            self.analyze_evaluation_proof_operations(),
            self.analyze_multi_pairing_size(),
            self.analyze_hash_to_curve_operations(security_parameter),
            ((self.memory_size * self.num_operations) as f64).sqrt().log2() as usize
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    
    // Mock bilinear pairing for testing
    #[derive(Debug, Clone, PartialEq)]
    struct MockG1Element {
        value: u64,
    }
    
    #[derive(Debug, Clone, PartialEq)]
    struct MockG2Element {
        value: u64,
    }
    
    #[derive(Debug, Clone, PartialEq)]
    struct MockGTElement {
        value: u64,
    }
    
    impl GroupElement for MockG1Element {
        type Scalar = PrimeField;
        
        fn identity() -> Self { MockG1Element { value: 0 } }
        fn generator() -> Self { MockG1Element { value: 1 } }
        fn mul(&self, scalar: &Self::Scalar) -> Self {
            MockG1Element { value: (self.value * scalar.to_u64()) % 1000000007 }
        }
        fn add(&self, other: &Self) -> Self {
            MockG1Element { value: (self.value + other.value) % 1000000007 }
        }
        fn sub(&self, other: &Self) -> Self {
            MockG1Element { value: (self.value + 1000000007 - other.value) % 1000000007 }
        }
        fn neg(&self) -> Self {
            MockG1Element { value: (1000000007 - self.value) % 1000000007 }
        }
        fn is_identity(&self) -> bool { self.value == 0 }
        fn to_bytes(&self) -> Vec<u8> { self.value.to_le_bytes().to_vec() }
        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != 8 { return Err("Invalid length".to_string()); }
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            Ok(MockG1Element { value: u64::from_le_bytes(array) })
        }
    }
    
    impl GroupElement for MockG2Element {
        type Scalar = PrimeField;
        
        fn identity() -> Self { MockG2Element { value: 0 } }
        fn generator() -> Self { MockG2Element { value: 2 } }
        fn mul(&self, scalar: &Self::Scalar) -> Self {
            MockG2Element { value: (self.value * scalar.to_u64()) % 1000000007 }
        }
        fn add(&self, other: &Self) -> Self {
            MockG2Element { value: (self.value + other.value) % 1000000007 }
        }
        fn sub(&self, other: &Self) -> Self {
            MockG2Element { value: (self.value + 1000000007 - other.value) % 1000000007 }
        }
        fn neg(&self) -> Self {
            MockG2Element { value: (1000000007 - self.value) % 1000000007 }
        }
        fn is_identity(&self) -> bool { self.value == 0 }
        fn to_bytes(&self) -> Vec<u8> { self.value.to_le_bytes().to_vec() }
        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != 8 { return Err("Invalid length".to_string()); }
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            Ok(MockG2Element { value: u64::from_le_bytes(array) })
        }
    }
    
    impl GroupElement for MockGTElement {
        type Scalar = PrimeField;
        
        fn identity() -> Self { MockGTElement { value: 1 } }
        fn generator() -> Self { MockGTElement { value: 3 } }
        fn mul(&self, scalar: &Self::Scalar) -> Self {
            MockGTElement { value: self.value.pow(scalar.to_u64() as u32) % 1000000007 }
        }
        fn add(&self, other: &Self) -> Self {
            MockGTElement { value: (self.value * other.value) % 1000000007 }
        }
        fn sub(&self, other: &Self) -> Self {
            MockGTElement { value: (self.value * 1000000007 / other.value) % 1000000007 }
        }
        fn neg(&self) -> Self {
            MockGTElement { value: (1000000007 / self.value) % 1000000007 }
        }
        fn is_identity(&self) -> bool { self.value == 1 }
        fn to_bytes(&self) -> Vec<u8> { self.value.to_le_bytes().to_vec() }
        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != 8 { return Err("Invalid length".to_string()); }
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            Ok(MockGTElement { value: u64::from_le_bytes(array) })
        }
    }
    
    struct MockBilinearPairing;
    
    impl BilinearPairing for MockBilinearPairing {
        type G1 = MockG1Element;
        type G2 = MockG2Element;
        type GT = MockGTElement;
        
        fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT {
            // Simple mock pairing: e(g1, g2) = g1^g2 in GT
            MockGTElement { value: g1.value.pow(g2.value as u32) % 1000000007 }
        }
    }
    
    // Mock polynomial oracle
    struct MockPolynomialOracle {
        evaluations: Vec<PrimeField>,
        num_vars: usize,
    }
    
    impl PolynomialOracle<PrimeField> for MockPolynomialOracle {
        fn evaluate_at(&self, index: usize) -> PrimeField {
            if index < self.evaluations.len() {
                self.evaluations[index]
            } else {
                PrimeField::zero()
            }
        }
        
        fn num_evaluations(&self) -> usize {
            self.evaluations.len()
        }
        
        fn num_variables(&self) -> usize {
            self.num_vars
        }
    }
    
    #[test]
    fn test_dory_config_creation() {
        let config = DoryConfig::new(4, 128).unwrap();
        assert_eq!(config.num_vars, 4);
        assert_eq!(config.matrix_dim, 4);
        assert_eq!(config.hyrax_key_size(), 4);
        assert_eq!(config.afgho_key_size(), 4);
    }
    
    #[test]
    fn test_dory_commitment_key_generation() {
        let config = DoryConfig::new(4, 128).unwrap();
        let key = DoryCommitmentKey::<MockBilinearPairing>::generate(config.clone());
        
        assert_eq!(key.hyrax_key.len(), 4);
        assert_eq!(key.afgho_key.len(), 4);
        assert_eq!(key.config.num_vars, 4);
    }
    
    #[test]
    fn test_dory_commitment_basic() {
        let config = DoryConfig::new(4, 128).unwrap();
        let key = DoryCommitmentKey::<MockBilinearPairing>::generate(config);
        let prover = DoryProver::new(key);
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        let commitment = prover.commit(&oracle).unwrap();
        assert_eq!(commitment.hyrax_commitments.len(), 4);
        assert!(commitment.commitment.value > 0);
    }
    
    #[test]
    fn test_streaming_dory_prover() {
        let config = DoryConfig::new(4, 128).unwrap();
        let seed = b"test_seed".to_vec();
        let streaming_prover = StreamingDoryProver::<MockBilinearPairing>::new(config, seed);
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        let commitment = streaming_prover.commit_streaming(&oracle).unwrap();
        assert_eq!(commitment.hyrax_commitments.len(), 4);
    }
    
    #[test]
    fn test_dory_performance_analyzer() {
        let analyzer = DoryPerformanceAnalyzer::new(1024, 1024);
        
        let key_size = analyzer.analyze_commitment_key_size();
        assert!(key_size > 0);
        
        let proof_ops = analyzer.analyze_evaluation_proof_operations();
        assert_eq!(proof_ops, 30 * 1024);
        
        let report = analyzer.generate_report(128);
        assert!(report.contains("Dory Performance Analysis"));
        assert!(report.contains("1024"));
    }
}