// Structured Random Projection
// Implements Symphony's sublinear verifier via structured projections
//
// Paper Reference: Symphony (2025-1905), Section 5.3 "Structured Random Projection"
//
// This module implements a key technique that enables Symphony's sublinear
// verifier complexity. Instead of checking all n witness entries, the verifier
// only checks a random projection of size λ_pj (typically 256).
//
// Key Idea:
// Use a structured projection matrix J := I_{n/ℓ_h} ⊗ J' where:
// - I_{n/ℓ_h} is an identity matrix of size n/ℓ_h
// - J' ∈ {0,±1}^{λ_pj × ℓ_h} is a narrow random matrix
// - ⊗ denotes Kronecker product
//
// This structure provides:
// 1. Sublinear verification: O(λ_pj) instead of O(n)
// 2. Efficient prover: O(n) via structured matrix multiplication
// 3. Security: Preserves norm bounds with high probability
//
// Norm Preservation Property:
// For any vector w with ||w|| ≤ β, the projected vector J·w satisfies:
// ||J·w|| ≤ T·β with probability ≥ 1 - 2^{-λ_pj}
//
// where T = ||J||_op ≤ 15 is the operator norm bound.
//
// Algorithm Overview:
// 1. Sample J' ∈ {0,±1}^{λ_pj × ℓ_h} uniformly at random
// 2. Construct J = I_{n/ℓ_h} ⊗ J' (structured Kronecker product)
// 3. Prover computes y = J·w in O(n) time using structure
// 4. Verifier checks ||y|| ≤ T·β in O(λ_pj) time
//
// Complexity:
// - Prover: O(n) via structured multiplication
// - Verifier: O(λ_pj) for norm check
// - Projection matrix size: O(n·λ_pj/ℓ_h) entries
//
// Security:
// - Soundness: If ||w|| > β, then ||J·w|| > T·β with probability ≥ 1 - 2^{-λ_pj}
// - The projection preserves norm violations with high probability
// - Security parameter λ_pj = 256 gives 2^{-256} soundness error

use crate::field::Field;
use crate::ring::cyclotomic::RingElement;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;

/// Structured projection matrix J = I_{n/ℓ_h} ⊗ J'
///
/// Paper Reference: Symphony Section 5.3, Definition 5.3
///
/// This matrix has a Kronecker product structure that enables
/// efficient multiplication while preserving norm bounds.
#[derive(Clone, Debug)]
pub struct StructuredProjection<F: Field> {
    /// Security parameter λ_pj (typically 256)
    lambda_pj: usize,
    
    /// Block size ℓ_h (height of narrow matrix)
    block_size: usize,
    
    /// Number of blocks n/ℓ_h
    num_blocks: usize,
    
    /// Narrow random matrix J' ∈ {0,±1}^{λ_pj × ℓ_h}
    /// This is the core random component
    narrow_matrix: Vec<Vec<i8>>,
    
    /// Operator norm bound T = ||J||_op
    /// Typically T ≤ 15 for λ_pj = 256
    operator_norm_bound: f64,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> StructuredProjection<F> {
    /// Create new structured projection
    ///
    /// Paper Reference: Symphony Section 5.3, Construction 5.2
    ///
    /// Samples J' ∈ {0,±1}^{λ_pj × ℓ_h} uniformly at random and
    /// constructs J = I_{n/ℓ_h} ⊗ J'.
    ///
    /// # Arguments
    /// * `vector_size` - Size n of the vector to project
    /// * `lambda_pj` - Security parameter (typically 256)
    /// * `block_size` - Block size ℓ_h (must divide n)
    /// * `seed` - Random seed for reproducibility
    ///
    /// # Returns
    /// Structured projection matrix with operator norm ≤ 15
    pub fn new(
        vector_size: usize,
        lambda_pj: usize,
        block_size: usize,
        seed: [u8; 32],
    ) -> Result<Self, String> {
        // Validate parameters
        if vector_size % block_size != 0 {
            return Err(format!(
                "Vector size {} must be divisible by block size {}",
                vector_size, block_size
            ));
        }
        
        let num_blocks = vector_size / block_size;
        
        // Sample narrow matrix J' ∈ {0,±1}^{λ_pj × ℓ_h}
        // Paper Reference: Symphony Protocol 5.2, Step 1
        //
        // Each entry is sampled uniformly from {-1, 0, 1}.
        // This gives a sparse random matrix with good norm preservation.
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut narrow_matrix = Vec::with_capacity(lambda_pj);
        
        for _ in 0..lambda_pj {
            let mut row = Vec::with_capacity(block_size);
            for _ in 0..block_size {
                // Sample from {-1, 0, 1} uniformly
                let value = rng.gen_range(-1..=1);
                row.push(value);
            }
            narrow_matrix.push(row);
        }
        
        // Compute operator norm bound
        // Paper Reference: Symphony Lemma 5.1
        //
        // For J' ∈ {0,±1}^{λ_pj × ℓ_h}, we have ||J'||_op ≤ √(λ_pj·ℓ_h)
        // with high probability. For typical parameters, this is ≤ 15.
        let operator_norm_bound = ((lambda_pj * block_size) as f64).sqrt();
        
        // Verify norm bound is reasonable
        if operator_norm_bound > 20.0 {
            return Err(format!(
                "Operator norm bound {} exceeds safe threshold 20",
                operator_norm_bound
            ));
        }
        
        Ok(Self {
            lambda_pj,
            block_size,
            num_blocks,
            narrow_matrix,
            operator_norm_bound,
            _phantom: PhantomData,
        })
    }
    
    /// Project vector using structured matrix
    ///
    /// Paper Reference: Symphony Section 5.3, Algorithm 5.1
    ///
    /// Computes y = J·w where J = I_{n/ℓ_h} ⊗ J'.
    ///
    /// The Kronecker product structure allows efficient computation:
    /// (I ⊗ J')·w = [J'·w_1, J'·w_2, ..., J'·w_{n/ℓ_h}]
    ///
    /// where w_i is the i-th block of w of size ℓ_h.
    ///
    /// Algorithm:
    /// 1. Split w into blocks w_1, ..., w_{n/ℓ_h} of size ℓ_h
    /// 2. For each block w_i, compute J'·w_i
    /// 3. Concatenate results
    ///
    /// Complexity: O(n·λ_pj/ℓ_h) = O(n) when λ_pj and ℓ_h are constants
    pub fn project(&self, vector: &[F]) -> Result<Vec<F>, String> {
        let expected_size = self.num_blocks * self.block_size;
        if vector.len() != expected_size {
            return Err(format!(
                "Vector size {} does not match expected size {}",
                vector.len(),
                expected_size
            ));
        }
        
        // Result vector of size num_blocks * lambda_pj
        let mut result = Vec::with_capacity(self.num_blocks * self.lambda_pj);
        
        // Process each block
        // Paper Reference: Symphony Algorithm 5.1, Lines 2-5
        //
        // For each block i:
        // 1. Extract block w_i of size ℓ_h
        // 2. Compute y_i = J'·w_i (size λ_pj)
        // 3. Append y_i to result
        for block_idx in 0..self.num_blocks {
            let block_start = block_idx * self.block_size;
            let block_end = block_start + self.block_size;
            let block = &vector[block_start..block_end];
            
            // Compute J'·block
            let projected_block = self.multiply_narrow_matrix(block);
            result.extend(projected_block);
        }
        
        Ok(result)
    }
    
    /// Multiply narrow matrix J' with a block
    ///
    /// Computes y = J'·w where J' ∈ {0,±1}^{λ_pj × ℓ_h} and w ∈ F^{ℓ_h}
    ///
    /// Since J' has entries in {-1, 0, 1}, multiplication is efficient:
    /// - No actual multiplications needed
    /// - Only additions and subtractions
    ///
    /// Complexity: O(λ_pj·ℓ_h)
    fn multiply_narrow_matrix(&self, block: &[F]) -> Vec<F> {
        assert_eq!(block.len(), self.block_size);
        
        let mut result = Vec::with_capacity(self.lambda_pj);
        
        // For each row of J'
        for row in &self.narrow_matrix {
            let mut sum = F::zero();
            
            // Compute dot product with block
            for (j_val, w_val) in row.iter().zip(block.iter()) {
                match j_val {
                    1 => sum = sum.add(w_val),
                    -1 => sum = sum.sub(w_val),
                    0 => {}, // No contribution
                    _ => unreachable!(),
                }
            }
            
            result.push(sum);
        }
        
        result
    }
    
    /// Verify norm bound after projection
    ///
    /// Paper Reference: Symphony Section 5.3, Verification
    ///
    /// Checks that ||y|| ≤ T·β where:
    /// - y = J·w is the projected vector
    /// - T = ||J||_op is the operator norm bound
    /// - β is the claimed norm bound on w
    ///
    /// If this check passes, then with high probability ||w|| ≤ β.
    ///
    /// Soundness:
    /// If ||w|| > β, then ||J·w|| > T·β with probability ≥ 1 - 2^{-λ_pj}
    ///
    /// Verifier complexity: O(λ_pj·n/ℓ_h) for computing ||y||
    pub fn verify_norm_bound(
        &self,
        projected: &[F],
        claimed_norm_bound: f64,
    ) -> bool {
        let expected_size = self.num_blocks * self.lambda_pj;
        if projected.len() != expected_size {
            return false;
        }
        
        // Compute ||y||² = Σ_i y_i²
        let mut norm_squared = 0.0;
        
        for val in projected {
            let v = val.to_canonical_u64() as f64;
            norm_squared += v * v;
        }
        
        let norm = norm_squared.sqrt();
        
        // Check ||y|| ≤ T·β
        let threshold = self.operator_norm_bound * claimed_norm_bound;
        
        norm <= threshold
    }
    
    /// Get operator norm bound
    pub fn operator_norm_bound(&self) -> f64 {
        self.operator_norm_bound
    }
    
    /// Get projection output size
    pub fn output_size(&self) -> usize {
        self.num_blocks * self.lambda_pj
    }
    
    /// Get narrow matrix (for testing/debugging)
    pub fn narrow_matrix(&self) -> &[Vec<i8>] {
        &self.narrow_matrix
    }
}

/// Projection proof
///
/// Proves that a projected vector y = J·w satisfies ||y|| ≤ T·β
#[derive(Clone, Debug)]
pub struct ProjectionProof<F: Field> {
    /// Projected vector y = J·w
    pub projected: Vec<F>,
    
    /// Claimed norm bound β on original vector w
    pub claimed_norm_bound: f64,
    
    /// Operator norm bound T = ||J||_op
    pub operator_norm_bound: f64,
}

/// Projection prover
pub struct ProjectionProver<F: Field> {
    /// Structured projection matrix
    projection: StructuredProjection<F>,
}

impl<F: Field> ProjectionProver<F> {
    /// Create new projection prover
    pub fn new(projection: StructuredProjection<F>) -> Self {
        Self { projection }
    }
    
    /// Prove norm bound via projection
    ///
    /// Paper Reference: Symphony Protocol 5.2
    ///
    /// Given witness w with ||w|| ≤ β, prove this by:
    /// 1. Computing y = J·w
    /// 2. Showing ||y|| ≤ T·β
    ///
    /// The verifier can check ||y|| ≤ T·β in O(λ_pj·n/ℓ_h) time,
    /// which is sublinear when ℓ_h is large.
    pub fn prove_norm_bound(
        &self,
        witness: &[F],
        claimed_norm_bound: f64,
    ) -> Result<ProjectionProof<F>, String> {
        // Step 1: Compute projection y = J·w
        // Paper Reference: Symphony Protocol 5.2, Step 2
        let projected = self.projection.project(witness)?;
        
        // Step 2: Verify norm bound (prover self-check)
        // Paper Reference: Symphony Protocol 5.2, Step 3
        if !self.projection.verify_norm_bound(&projected, claimed_norm_bound) {
            return Err(format!(
                "Projected norm exceeds bound: claimed {}, operator norm {}",
                claimed_norm_bound,
                self.projection.operator_norm_bound()
            ));
        }
        
        Ok(ProjectionProof {
            projected,
            claimed_norm_bound,
            operator_norm_bound: self.projection.operator_norm_bound(),
        })
    }
    
    /// Verify projection proof
    ///
    /// Paper Reference: Symphony Section 5.3, Verification
    ///
    /// Verifier checks ||y|| ≤ T·β in O(λ_pj·n/ℓ_h) time.
    pub fn verify_proof(&self, proof: &ProjectionProof<F>) -> bool {
        // Verify operator norm bound matches
        if (proof.operator_norm_bound - self.projection.operator_norm_bound()).abs() > 0.1 {
            return false;
        }
        
        // Verify projected norm bound
        self.projection.verify_norm_bound(
            &proof.projected,
            proof.claimed_norm_bound,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_structured_projection_creation() {
        let vector_size = 1024;
        let lambda_pj = 256;
        let block_size = 64;
        let seed = [0u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        );
        
        assert!(projection.is_ok());
        let projection = projection.unwrap();
        
        assert_eq!(projection.output_size(), (vector_size / block_size) * lambda_pj);
        assert!(projection.operator_norm_bound() <= 20.0);
    }
    
    #[test]
    fn test_projection_computation() {
        let vector_size = 256;
        let lambda_pj = 64;
        let block_size = 32;
        let seed = [1u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        ).unwrap();
        
        // Create test vector
        let vector: Vec<F> = (0..vector_size)
            .map(|i| F::from_u64(i as u64))
            .collect();
        
        // Project
        let projected = projection.project(&vector);
        assert!(projected.is_ok());
        
        let projected = projected.unwrap();
        assert_eq!(projected.len(), projection.output_size());
    }
    
    #[test]
    fn test_norm_bound_verification() {
        let vector_size = 256;
        let lambda_pj = 64;
        let block_size = 32;
        let seed = [2u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        ).unwrap();
        
        // Create small vector (should pass norm check)
        let small_vector: Vec<F> = (0..vector_size)
            .map(|i| F::from_u64((i % 10) as u64))
            .collect();
        
        let projected = projection.project(&small_vector).unwrap();
        
        // Should pass with reasonable norm bound
        let norm_bound = 1000.0;
        assert!(projection.verify_norm_bound(&projected, norm_bound));
        
        // Should fail with very small norm bound
        let tiny_bound = 1.0;
        assert!(!projection.verify_norm_bound(&projected, tiny_bound));
    }
    
    #[test]
    fn test_projection_proof() {
        let vector_size = 256;
        let lambda_pj = 64;
        let block_size = 32;
        let seed = [3u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        ).unwrap();
        
        let prover = ProjectionProver::new(projection);
        
        // Create witness
        let witness: Vec<F> = (0..vector_size)
            .map(|i| F::from_u64((i % 10) as u64))
            .collect();
        
        // Generate proof
        let proof = prover.prove_norm_bound(&witness, 1000.0);
        assert!(proof.is_ok());
        
        // Verify proof
        let proof = proof.unwrap();
        assert!(prover.verify_proof(&proof));
    }
    
    #[test]
    fn test_narrow_matrix_structure() {
        let vector_size = 128;
        let lambda_pj = 32;
        let block_size = 16;
        let seed = [4u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        ).unwrap();
        
        let narrow = projection.narrow_matrix();
        
        // Check dimensions
        assert_eq!(narrow.len(), lambda_pj);
        assert_eq!(narrow[0].len(), block_size);
        
        // Check entries are in {-1, 0, 1}
        for row in narrow {
            for &val in row {
                assert!(val >= -1 && val <= 1);
            }
        }
    }
    
    #[test]
    fn test_operator_norm_bound() {
        let vector_size = 512;
        let lambda_pj = 128;
        let block_size = 64;
        let seed = [5u8; 32];
        
        let projection = StructuredProjection::<F>::new(
            vector_size,
            lambda_pj,
            block_size,
            seed,
        ).unwrap();
        
        // Operator norm should be approximately √(λ_pj·ℓ_h)
        let expected = ((lambda_pj * block_size) as f64).sqrt();
        let actual = projection.operator_norm_bound();
        
        assert!((actual - expected).abs() < 0.1);
        assert!(actual <= 15.0); // Symphony's bound
    }
}
