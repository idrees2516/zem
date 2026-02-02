// Hyrax Polynomial Commitment Scheme Implementation
//
// This module implements the Hyrax polynomial commitment scheme for the small-space zkVM.
// Hyrax achieves O(√n) commitment size and evaluation proof size with streaming computation.
//
// Based on:
// - "Doubly-efficient zkSNARKs without trusted setup" by Wahby et al.
// - "Proving CPU Executions in Small Space" requirements 8.1-8.15
//
// Key features:
// - Matrix representation: arrange polynomial evaluations in √n × √n matrix
// - Streaming commitment: compute column commitments in O(√n) space
// - Bulletproofs evaluation proofs: O(log √n) rounds with O(√n) space
// - Pippenger's algorithm for multi-scalar multiplication (MSM)

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Group element trait for elliptic curve operations
pub trait GroupElement: Clone + std::fmt::Debug + Send + Sync {
    type Scalar: FieldElement;
    
    /// Identity element (point at infinity)
    fn identity() -> Self;
    
    /// Generator element
    fn generator() -> Self;
    
    /// Scalar multiplication: self * scalar
    fn mul(&self, scalar: &Self::Scalar) -> Self;
    
    /// Group addition: self + other
    fn add(&self, other: &Self) -> Self;
    
    /// Group subtraction: self - other
    fn sub(&self, other: &Self) -> Self;
    
    /// Negation: -self
    fn neg(&self) -> Self;
    
    /// Check if this is the identity element
    fn is_identity(&self) -> bool;
    
    /// Serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>;
}

/// Multi-scalar multiplication (MSM) using Pippenger's algorithm
pub struct PippengerMSM<G: GroupElement> {
    _phantom: PhantomData<G>,
}

impl<G: GroupElement> PippengerMSM<G> {
    /// Compute MSM: Σᵢ scalars[i] * bases[i] using Pippenger's algorithm
    /// 
    /// This is the core operation for Hyrax commitments.
    /// Time complexity: O(n / log n) group operations for n terms
    /// Space complexity: O(√n) for bucket storage
    pub fn compute_msm(bases: &[G], scalars: &[G::Scalar]) -> Result<G, String> {
        if bases.len() != scalars.len() {
            return Err("Bases and scalars must have same length".to_string());
        }
        
        if bases.is_empty() {
            return Ok(G::identity());
        }
        
        let n = bases.len();
        
        // For small inputs, use naive algorithm
        if n <= 32 {
            return Self::naive_msm(bases, scalars);
        }
        
        // Pippenger's algorithm parameters
        let window_size = Self::optimal_window_size(n);
        let num_windows = (256 + window_size - 1) / window_size; // Assuming 256-bit scalars
        
        let mut result = G::identity();
        
        // Process each window from most significant to least significant
        for window_idx in (0..num_windows).rev() {
            // Double the result window_size times (except for the first window)
            if window_idx < num_windows - 1 {
                for _ in 0..window_size {
                    result = result.add(&result);
                }
            }
            
            // Process this window using bucket method
            let window_result = Self::process_window(bases, scalars, window_idx, window_size)?;
            result = result.add(&window_result);
        }
        
        Ok(result)
    }
    
    /// Compute optimal window size for Pippenger's algorithm
    fn optimal_window_size(n: usize) -> usize {
        if n <= 32 { return 1; }
        if n <= 256 { return 3; }
        if n <= 2048 { return 4; }
        if n <= 16384 { return 5; }
        if n <= 131072 { return 6; }
        7 // For very large n
    }
    
    /// Process a single window using bucket method
    fn process_window(
        bases: &[G], 
        scalars: &[G::Scalar], 
        window_idx: usize, 
        window_size: usize
    ) -> Result<G, String> {
        let num_buckets = 1 << window_size;
        let mut buckets = vec![G::identity(); num_buckets];
        
        // Extract window bits and accumulate into buckets
        for (base, scalar) in bases.iter().zip(scalars.iter()) {
            let window_bits = Self::extract_window_bits(scalar, window_idx, window_size);
            if window_bits > 0 {
                buckets[window_bits] = buckets[window_bits].add(base);
            }
        }
        
        // Compute bucket sum using running sum technique
        let mut running_sum = G::identity();
        let mut result = G::identity();
        
        for bucket in buckets.iter().rev().skip(1) { // Skip bucket 0
            running_sum = running_sum.add(bucket);
            result = result.add(&running_sum);
        }
        
        Ok(result)
    }
    
    /// Extract window bits from scalar
    fn extract_window_bits(scalar: &G::Scalar, window_idx: usize, window_size: usize) -> usize {
        // Convert scalar to bytes and extract the relevant bits
        let bytes = scalar.to_bytes();
        let start_bit = window_idx * window_size;
        let mut result = 0usize;
        
        for i in 0..window_size {
            let bit_idx = start_bit + i;
            if bit_idx >= 256 { break; } // Assuming 256-bit scalars
            
            let byte_idx = bit_idx / 8;
            let bit_offset = bit_idx % 8;
            
            if byte_idx < bytes.len() {
                let bit = (bytes[byte_idx] >> bit_offset) & 1;
                result |= (bit as usize) << i;
            }
        }
        
        result
    }
    
    /// Naive MSM for small inputs
    fn naive_msm(bases: &[G], scalars: &[G::Scalar]) -> Result<G, String> {
        let mut result = G::identity();
        for (base, scalar) in bases.iter().zip(scalars.iter()) {
            result = result.add(&base.mul(scalar));
        }
        Ok(result)
    }
}

/// Hyrax commitment configuration
#[derive(Debug, Clone)]
pub struct HyraxConfig {
    /// Number of polynomial evaluations (n = 2^num_vars)
    pub num_vars: usize,
    /// Matrix dimension (√n)
    pub matrix_dim: usize,
    /// Security parameter (typically 128, 192, or 256)
    pub security_parameter: usize,
}

impl HyraxConfig {
    /// Create new Hyrax configuration
    pub fn new(num_vars: usize, security_parameter: usize) -> Result<Self, String> {
        if num_vars == 0 {
            return Err("Number of variables must be positive".to_string());
        }
        
        if num_vars % 2 != 0 {
            return Err("Number of variables must be even for matrix representation".to_string());
        }
        
        let matrix_dim = 1 << (num_vars / 2);
        
        Ok(HyraxConfig {
            num_vars,
            matrix_dim,
            security_parameter,
        })
    }
    
    /// Get total number of evaluations
    pub fn num_evaluations(&self) -> usize {
        1 << self.num_vars
    }
    
    /// Get commitment key size (number of group elements)
    pub fn commitment_key_size(&self) -> usize {
        self.matrix_dim
    }
    
    /// Get evaluation proof size (number of group elements)
    pub fn evaluation_proof_size(&self) -> usize {
        // Bulletproofs: 2 * log(matrix_dim) + 2 elements
        2 * (self.num_vars / 2) + 2
    }
}

/// Hyrax commitment key
#[derive(Debug, Clone)]
pub struct HyraxCommitmentKey<G: GroupElement> {
    /// Generator elements: g₁, g₂, ..., g_{√n}
    pub generators: Vec<G>,
    /// Configuration
    pub config: HyraxConfig,
}

impl<G: GroupElement> HyraxCommitmentKey<G> {
    /// Generate commitment key with random generators
    pub fn generate(config: HyraxConfig) -> Self {
        let mut generators = Vec::with_capacity(config.matrix_dim);
        
        // In practice, these would be generated using a cryptographic hash function
        // For now, we use the generator and its multiples (not secure, just for structure)
        let base_gen = G::generator();
        for i in 0..config.matrix_dim {
            let scalar = G::Scalar::from_u64((i + 1) as u64);
            generators.push(base_gen.mul(&scalar));
        }
        
        HyraxCommitmentKey {
            generators,
            config,
        }
    }
    
    /// Generate commitment key from seed (deterministic)
    pub fn from_seed(config: HyraxConfig, seed: &[u8]) -> Self {
        // In practice, use hash-to-curve with the seed
        // For now, use a simple deterministic generation
        let mut generators = Vec::with_capacity(config.matrix_dim);
        let base_gen = G::generator();
        
        for i in 0..config.matrix_dim {
            // Simple deterministic scalar from seed and index
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hasher::write(&mut hasher, seed);
            std::hash::Hasher::write_usize(&mut hasher, i);
            let hash = std::hash::Hasher::finish(&hasher);
            let scalar = G::Scalar::from_u64(hash);
            generators.push(base_gen.mul(&scalar));
        }
        
        HyraxCommitmentKey {
            generators,
            config,
        }
    }
}

/// Polynomial oracle trait for streaming evaluation access
pub trait PolynomialOracle<F: FieldElement> {
    /// Get polynomial evaluation at index i
    fn evaluate_at(&self, index: usize) -> F;
    
    /// Get number of evaluations
    fn num_evaluations(&self) -> usize;
    
    /// Get number of variables
    fn num_variables(&self) -> usize;
}

/// Matrix representation of polynomial evaluations
/// 
/// Arranges polynomial evaluations f(0), f(1), ..., f(2^n - 1) in a √n × √n matrix M
/// where M[i][j] = f(i * √n + j) for column-major ordering
#[derive(Debug)]
pub struct PolynomialMatrix<F: FieldElement> {
    /// Matrix dimension (√n)
    pub dim: usize,
    /// Number of variables
    pub num_vars: usize,
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> PolynomialMatrix<F> {
    /// Create new polynomial matrix
    pub fn new(num_vars: usize) -> Result<Self, String> {
        if num_vars % 2 != 0 {
            return Err("Number of variables must be even".to_string());
        }
        
        let dim = 1 << (num_vars / 2);
        
        Ok(PolynomialMatrix {
            dim,
            num_vars,
            _phantom: PhantomData,
        })
    }
    
    /// Convert linear index to matrix coordinates (row, col)
    pub fn index_to_coords(&self, index: usize) -> (usize, usize) {
        let row = index / self.dim;
        let col = index % self.dim;
        (row, col)
    }
    
    /// Convert matrix coordinates to linear index
    pub fn coords_to_index(&self, row: usize, col: usize) -> usize {
        row * self.dim + col
    }
    
    /// Stream column j from polynomial oracle
    pub fn stream_column<P: PolynomialOracle<F>>(
        &self, 
        oracle: &P, 
        col: usize
    ) -> Result<Vec<F>, String> {
        if col >= self.dim {
            return Err("Column index out of bounds".to_string());
        }
        
        let mut column = Vec::with_capacity(self.dim);
        
        for row in 0..self.dim {
            let index = self.coords_to_index(row, col);
            column.push(oracle.evaluate_at(index));
        }
        
        Ok(column)
    }
    
    /// Stream row i from polynomial oracle
    pub fn stream_row<P: PolynomialOracle<F>>(
        &self, 
        oracle: &P, 
        row: usize
    ) -> Result<Vec<F>, String> {
        if row >= self.dim {
            return Err("Row index out of bounds".to_string());
        }
        
        let mut row_data = Vec::with_capacity(self.dim);
        
        for col in 0..self.dim {
            let index = self.coords_to_index(row, col);
            row_data.push(oracle.evaluate_at(index));
        }
        
        Ok(row_data)
    }
    
    /// Compute matrix-vector product M * r₂ in streaming fashion
    pub fn matrix_vector_product<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        r2: &[F]
    ) -> Result<Vec<F>, String> {
        if r2.len() != self.dim {
            return Err("Vector r2 must have dimension √n".to_string());
        }
        
        let mut result = vec![F::zero(); self.dim];
        
        // For each row i, compute result[i] = Σⱼ M[i][j] * r2[j]
        for row in 0..self.dim {
            let mut sum = F::zero();
            
            for col in 0..self.dim {
                let index = self.coords_to_index(row, col);
                let m_val = oracle.evaluate_at(index);
                sum = sum + m_val * r2[col];
            }
            
            result[row] = sum;
        }
        
        Ok(result)
    }
}

/// Hyrax commitment (vector of group elements)
#[derive(Debug, Clone)]
pub struct HyraxCommitment<G: GroupElement> {
    /// Column commitments: h₁, h₂, ..., h_{√n}
    pub column_commitments: Vec<G>,
    /// Configuration
    pub config: HyraxConfig,
}

impl<G: GroupElement> HyraxCommitment<G> {
    /// Get commitment size in bytes
    pub fn size_bytes(&self) -> usize {
        self.column_commitments.len() * 32 // Assuming 32 bytes per group element
    }
    
    /// Serialize commitment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for commitment in &self.column_commitments {
            bytes.extend_from_slice(&commitment.to_bytes());
        }
        bytes
    }
    
    /// Deserialize commitment from bytes
    pub fn from_bytes(bytes: &[u8], config: HyraxConfig) -> Result<Self, String> {
        let element_size = 32; // Assuming 32 bytes per group element
        let expected_size = config.matrix_dim * element_size;
        
        if bytes.len() != expected_size {
            return Err(format!("Invalid commitment size: expected {}, got {}", expected_size, bytes.len()));
        }
        
        let mut column_commitments = Vec::with_capacity(config.matrix_dim);
        
        for i in 0..config.matrix_dim {
            let start = i * element_size;
            let end = start + element_size;
            let element_bytes = &bytes[start..end];
            let element = G::from_bytes(element_bytes)?;
            column_commitments.push(element);
        }
        
        Ok(HyraxCommitment {
            column_commitments,
            config,
        })
    }
}

/// Hyrax prover for polynomial commitments
pub struct HyraxProver<G: GroupElement> {
    /// Commitment key
    pub commitment_key: HyraxCommitmentKey<G>,
}

impl<G: GroupElement> HyraxProver<G> {
    /// Create new Hyrax prover
    pub fn new(commitment_key: HyraxCommitmentKey<G>) -> Self {
        HyraxProver { commitment_key }
    }
    
    /// Commit to polynomial using streaming computation
    /// 
    /// For each column j: hⱼ = ⟨Mⱼ, g⟩ = Σᵢ M[i][j] * gᵢ
    /// 
    /// Space complexity: O(√n) - only store one column at a time
    /// Time complexity: O(n) - single pass through polynomial evaluations
    pub fn commit<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P
    ) -> Result<HyraxCommitment<G>, String> {
        if oracle.num_variables() != self.commitment_key.config.num_vars {
            return Err("Oracle variables don't match commitment key".to_string());
        }
        
        let matrix = PolynomialMatrix::new(oracle.num_variables())?;
        let mut column_commitments = Vec::with_capacity(matrix.dim);
        
        // Commit to each column using streaming
        for col in 0..matrix.dim {
            let column_data = matrix.stream_column(oracle, col)?;
            
            // Compute MSM: hⱼ = Σᵢ column_data[i] * generators[i]
            let commitment = PippengerMSM::compute_msm(
                &self.commitment_key.generators,
                &column_data
            )?;
            
            column_commitments.push(commitment);
        }
        
        Ok(HyraxCommitment {
            column_commitments,
            config: self.commitment_key.config.clone(),
        })
    }
    
    /// Split evaluation point r into two halves
    /// 
    /// r₁ = ⊗_{i=1}^{log n/2} (1-rᵢ, rᵢ) ∈ F^{√n}
    /// r₂ = ⊗_{i=log n/2+1}^{log n} (1-rᵢ, rᵢ) ∈ F^{√n}
    pub fn split_evaluation_point(&self, r: &[G::Scalar]) -> Result<(Vec<G::Scalar>, Vec<G::Scalar>), String> {
        if r.len() != self.commitment_key.config.num_vars {
            return Err("Evaluation point must have num_vars elements".to_string());
        }
        
        let half_vars = self.commitment_key.config.num_vars / 2;
        
        // Compute r₁ = ⊗_{i=1}^{half_vars} (1-rᵢ, rᵢ)
        let mut r1 = vec![G::Scalar::one()];
        for i in 0..half_vars {
            let mut new_r1 = Vec::with_capacity(r1.len() * 2);
            for &val in &r1 {
                new_r1.push(val * (G::Scalar::one() - r[i])); // val * (1 - rᵢ)
                new_r1.push(val * r[i]);                      // val * rᵢ
            }
            r1 = new_r1;
        }
        
        // Compute r₂ = ⊗_{i=half_vars+1}^{num_vars} (1-rᵢ, rᵢ)
        let mut r2 = vec![G::Scalar::one()];
        for i in half_vars..self.commitment_key.config.num_vars {
            let mut new_r2 = Vec::with_capacity(r2.len() * 2);
            for &val in &r2 {
                new_r2.push(val * (G::Scalar::one() - r[i])); // val * (1 - rᵢ)
                new_r2.push(val * r[i]);                      // val * rᵢ
            }
            r2 = new_r2;
        }
        
        Ok((r1, r2))
    }
    
    /// Compute matrix-vector product k = M·r₂ in streaming fashion
    pub fn compute_matrix_vector_product<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r2: &[G::Scalar]
    ) -> Result<Vec<G::Scalar>, String> {
        let matrix = PolynomialMatrix::new(oracle.num_variables())?;
        matrix.matrix_vector_product(oracle, r2)
    }
}

/// Simple evaluation proof (non-zero-knowledge version)
#[derive(Debug, Clone)]
pub struct SimpleEvaluationProof<G: GroupElement> {
    /// Vector k = M·r₂ ∈ F^{√n}
    pub k_vector: Vec<G::Scalar>,
}

impl<G: GroupElement> SimpleEvaluationProof<G> {
    /// Create simple evaluation proof
    pub fn new(k_vector: Vec<G::Scalar>) -> Self {
        SimpleEvaluationProof { k_vector }
    }
    
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        self.k_vector.len() * 32 // Assuming 32 bytes per field element
    }
}

/// Hyrax verifier for simple evaluation proofs
pub struct SimpleHyraxVerifier<G: GroupElement> {
    /// Commitment key (for verification)
    pub commitment_key: HyraxCommitmentKey<G>,
}

impl<G: GroupElement> SimpleHyraxVerifier<G> {
    /// Create new simple Hyrax verifier
    pub fn new(commitment_key: HyraxCommitmentKey<G>) -> Self {
        SimpleHyraxVerifier { commitment_key }
    }
    
    /// Verify simple evaluation proof
    /// 
    /// 1. Compute c* = ⟨r₂, h⟩ = Σⱼ r₂[j] * hⱼ
    /// 2. Check ⟨k, g⟩ = c*
    /// 3. Check p(r) = ⟨r₁, k⟩
    pub fn verify_evaluation(
        &self,
        commitment: &HyraxCommitment<G>,
        evaluation_point: &[G::Scalar],
        claimed_evaluation: G::Scalar,
        proof: &SimpleEvaluationProof<G>
    ) -> Result<bool, String> {
        // Split evaluation point
        let prover = HyraxProver::new(self.commitment_key.clone());
        let (r1, r2) = prover.split_evaluation_point(evaluation_point)?;
        
        if r2.len() != commitment.column_commitments.len() {
            return Err("r2 dimension doesn't match commitment".to_string());
        }
        
        if proof.k_vector.len() != self.commitment_key.generators.len() {
            return Err("k vector dimension doesn't match generators".to_string());
        }
        
        // 1. Compute c* = ⟨r₂, h⟩ = Σⱼ r₂[j] * hⱼ
        let mut c_star = G::identity();
        for (r2_j, h_j) in r2.iter().zip(&commitment.column_commitments) {
            c_star = c_star.add(&h_j.mul(r2_j));
        }
        
        // 2. Check ⟨k, g⟩ = c*
        let k_commitment = PippengerMSM::compute_msm(
            &self.commitment_key.generators,
            &proof.k_vector
        )?;
        
        if !self.group_elements_equal(&k_commitment, &c_star) {
            return Ok(false);
        }
        
        // 3. Check p(r) = ⟨r₁, k⟩
        let mut computed_evaluation = G::Scalar::zero();
        for (r1_i, k_i) in r1.iter().zip(&proof.k_vector) {
            computed_evaluation = computed_evaluation + (*r1_i) * (*k_i);
        }
        
        Ok(computed_evaluation == claimed_evaluation)
    }
    
    /// Helper to check if two group elements are equal
    fn group_elements_equal(&self, a: &G, b: &G) -> bool {
        // In practice, this would use proper group element comparison
        // For now, compare serialized forms
        a.to_bytes() == b.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    
    // Mock group element for testing
    #[derive(Debug, Clone, PartialEq)]
    struct MockGroupElement {
        value: u64,
    }
    
    impl GroupElement for MockGroupElement {
        type Scalar = PrimeField;
        
        fn identity() -> Self {
            MockGroupElement { value: 0 }
        }
        
        fn generator() -> Self {
            MockGroupElement { value: 1 }
        }
        
        fn mul(&self, scalar: &Self::Scalar) -> Self {
            MockGroupElement { 
                value: (self.value * scalar.to_u64()) % 1000000007 
            }
        }
        
        fn add(&self, other: &Self) -> Self {
            MockGroupElement { 
                value: (self.value + other.value) % 1000000007 
            }
        }
        
        fn sub(&self, other: &Self) -> Self {
            MockGroupElement { 
                value: (self.value + 1000000007 - other.value) % 1000000007 
            }
        }
        
        fn neg(&self) -> Self {
            MockGroupElement { 
                value: (1000000007 - self.value) % 1000000007 
            }
        }
        
        fn is_identity(&self) -> bool {
            self.value == 0
        }
        
        fn to_bytes(&self) -> Vec<u8> {
            self.value.to_le_bytes().to_vec()
        }
        
        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != 8 {
                return Err("Invalid byte length".to_string());
            }
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            Ok(MockGroupElement { value: u64::from_le_bytes(array) })
        }
    }
    
    // Mock polynomial oracle for testing
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
    fn test_hyrax_config_creation() {
        let config = HyraxConfig::new(4, 128).unwrap();
        assert_eq!(config.num_vars, 4);
        assert_eq!(config.matrix_dim, 4); // 2^(4/2) = 4
        assert_eq!(config.num_evaluations(), 16); // 2^4 = 16
        assert_eq!(config.commitment_key_size(), 4);
    }
    
    #[test]
    fn test_polynomial_matrix() {
        let matrix = PolynomialMatrix::<PrimeField>::new(4).unwrap();
        assert_eq!(matrix.dim, 4);
        
        // Test coordinate conversion
        assert_eq!(matrix.index_to_coords(0), (0, 0));
        assert_eq!(matrix.index_to_coords(5), (1, 1));
        assert_eq!(matrix.index_to_coords(15), (3, 3));
        
        assert_eq!(matrix.coords_to_index(0, 0), 0);
        assert_eq!(matrix.coords_to_index(1, 1), 5);
        assert_eq!(matrix.coords_to_index(3, 3), 15);
    }
    
    #[test]
    fn test_hyrax_commitment_basic() {
        let config = HyraxConfig::new(4, 128).unwrap();
        let key = HyraxCommitmentKey::<MockGroupElement>::generate(config);
        let prover = HyraxProver::new(key);
        
        // Create mock polynomial: f(x) = x
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        let commitment = prover.commit(&oracle).unwrap();
        assert_eq!(commitment.column_commitments.len(), 4);
    }
    
    #[test]
    fn test_evaluation_point_splitting() {
        let config = HyraxConfig::new(4, 128).unwrap();
        let key = HyraxCommitmentKey::<MockGroupElement>::generate(config);
        let prover = HyraxProver::new(key);
        
        let r = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(2),
            PrimeField::from_u64(3),
            PrimeField::from_u64(4),
        ];
        
        let (r1, r2) = prover.split_evaluation_point(&r).unwrap();
        assert_eq!(r1.len(), 4); // 2^(4/2) = 4
        assert_eq!(r2.len(), 4); // 2^(4/2) = 4
    }
    
    #[test]
    fn test_simple_evaluation_proof() {
        let config = HyraxConfig::new(4, 128).unwrap();
        let key = HyraxCommitmentKey::<MockGroupElement>::generate(config.clone());
        let prover = HyraxProver::new(key.clone());
        let verifier = SimpleHyraxVerifier::new(key);
        
        // Create mock polynomial: f(x) = x
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations: evaluations.clone(),
            num_vars: 4,
        };
        
        // Commit to polynomial
        let commitment = prover.commit(&oracle).unwrap();
        
        // Evaluation point
        let r = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(0),
            PrimeField::from_u64(1),
            PrimeField::from_u64(0),
        ];
        
        // Compute evaluation: f(1,0,1,0) = f(10) = 10
        let claimed_evaluation = PrimeField::from_u64(10);
        
        // Generate proof
        let (_, r2) = prover.split_evaluation_point(&r).unwrap();
        let k_vector = prover.compute_matrix_vector_product(&oracle, &r2).unwrap();
        let proof = SimpleEvaluationProof::new(k_vector);
        
        // Verify proof
        let is_valid = verifier.verify_evaluation(
            &commitment,
            &r,
            claimed_evaluation,
            &proof
        ).unwrap();
        
        assert!(is_valid);
    }
}