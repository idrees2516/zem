// Π^batch and Π^batch*: Batching Reduction Protocols
//
// Mathematical Background:
// Combines multiple linear relations into single relation using random linear combination.
// Reduces verification cost from checking k relations to checking 1 relation.
//
// Standard Batching (Π^batch, from [KLNO25]):
// Input: k relations H_i F_i W_i = Y_i for i ∈ [k]
// 1. Verifier samples challenge ρ ∈ F_{q^e}^×
// 2. Prover computes batched matrices:
//    H' = Σ_i ρ^i H_i
//    Y' = Σ_i ρ^i Y_i
// 3. Output single relation: H'FW = Y'
//
// Enhanced Batching (Π^batch*, via sumcheck):
// Instead of batching H matrices, express F̄W = ȳ as sumcheck claims
// and batch using random linear combination in extension field.
// This eliminates the compression matrix H entirely.
//
// Properties:
// - Standard: Communication 0 bits (challenge from transcript)
// - Enhanced: Uses sumcheck, communication (2d-1)µe log q bits
// - Soundness: Schwartz-Zippel lemma, ε ≈ k/q^e
// - Verification: O(1) relations instead of O(k)
//
// Reference: SALSAA paper Section 6.2, [KLNO25], Requirements 12.1, 12.2

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::ExtFieldElement;
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Standard batching reduction protocol
pub struct BatchingReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Number of relations to batch
    pub num_relations: usize,
}

impl<F: Field> BatchingReduction<F> {
    /// Create new batching reduction
    pub fn new(ring: Arc<CyclotomicRing<F>>, num_relations: usize) -> Self {
        assert!(num_relations > 0, "Must batch at least one relation");
        
        Self {
            ring,
            num_relations,
        }
    }
    
    /// Prover batching: Combine k relations into one
    ///
    /// Algorithm:
    /// 1. Receive batching challenge ρ from verifier
    /// 2. Compute H' = Σ_i ρ^i H_i
    /// 3. Compute Y' = Σ_i ρ^i Y_i
    /// 4. F and W remain unchanged (assuming same structure)
    ///
    /// Complexity: O(k·n·m) ring operations where n, m are matrix dimensions
    pub fn prover_batch(
        &self,
        statements: &[LinearStatement<F>],
        witness: &LinearWitness<F>,
        transcript: &mut Transcript,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        assert_eq!(statements.len(), self.num_relations,
            "Expected {} statements, got {}", self.num_relations, statements.len());
        
        // All statements should have same F matrix and witness
        // (in practice, might have different F matrices that need combining)
        
        // Step 1: Sample batching challenge
        let rho = self.sample_batching_challenge(transcript);
        
        // Step 2: Batch H matrices
        let h_batched = self.batch_matrices(
            &statements.iter().map(|s| &s.h_matrix).collect::<Vec<_>>(),
            &rho,
        );
        
        // Step 3: Batch Y matrices
        let y_batched = self.batch_matrices(
            &statements.iter().map(|s| &s.y_matrix).collect::<Vec<_>>(),
            &rho,
        );
        
        // Step 4: Use F from first statement (or batch if different)
        let f_batched = if self.all_f_equal(statements) {
            statements[0].f_matrix.clone()
        } else {
            self.batch_matrices(
                &statements.iter().map(|s| &s.f_matrix).collect::<Vec<_>>(),
                &rho,
            )
        };
        
        let batched_statement = LinearStatement {
            h_matrix: h_batched,
            f_matrix: f_batched,
            y_matrix: y_batched,
        };
        
        (batched_statement, witness.clone())
    }
    
    /// Verifier batching: Compute batched statement
    ///
    /// Verifier performs same computation as prover
    pub fn verifier_batch(
        &self,
        statements: &[LinearStatement<F>],
        transcript: &mut Transcript,
    ) -> LinearStatement<F> {
        assert_eq!(statements.len(), self.num_relations);
        
        // Sample same challenge as prover
        let rho = self.sample_batching_challenge(transcript);
        
        // Batch matrices
        let h_batched = self.batch_matrices(
            &statements.iter().map(|s| &s.h_matrix).collect::<Vec<_>>(),
            &rho,
        );
        
        let y_batched = self.batch_matrices(
            &statements.iter().map(|s| &s.y_matrix).collect::<Vec<_>>(),
            &rho,
        );
        
        let f_batched = if self.all_f_equal(statements) {
            statements[0].f_matrix.clone()
        } else {
            self.batch_matrices(
                &statements.iter().map(|s| &s.f_matrix).collect::<Vec<_>>(),
                &rho,
            )
        };
        
        LinearStatement {
            h_matrix: h_batched,
            f_matrix: f_batched,
            y_matrix: y_batched,
        }
    }
    
    /// Sample batching challenge from transcript
    fn sample_batching_challenge(&self, transcript: &mut Transcript) -> RingElement<F> {
        transcript.challenge_ring(b"batching-challenge", &self.ring)
    }
    
    /// Batch matrices using powers of challenge
    ///
    /// M' = Σ_i ρ^i M_i
    fn batch_matrices(
        &self,
        matrices: &[&Matrix<F>],
        rho: &RingElement<F>,
    ) -> Matrix<F> {
        if matrices.is_empty() {
            panic!("Cannot batch empty list of matrices");
        }
        
        // Verify all matrices have same dimensions
        let rows = matrices[0].rows;
        let cols = matrices[0].cols;
        
        for matrix in matrices {
            assert_eq!(matrix.rows, rows, "All matrices must have same number of rows");
            assert_eq!(matrix.cols, cols, "All matrices must have same number of columns");
        }
        
        // Initialize result with zeros
        let mut result = Matrix::zero(rows, cols, self.ring.degree);
        let mut rho_power = self.ring.one();
        
        // Accumulate: result += ρ^i · M_i
        for matrix in matrices {
            let scaled = matrix.scalar_mul(&rho_power, &self.ring);
            result = result.add(&scaled, &self.ring);
            rho_power = self.ring.mul(&rho_power, rho);
        }
        
        result
    }
    
    /// Check if all F matrices are equal
    fn all_f_equal(&self, statements: &[LinearStatement<F>]) -> bool {
        if statements.len() <= 1 {
            return true;
        }
        
        let first_f = &statements[0].f_matrix;
        
        for statement in &statements[1..] {
            if !self.matrices_equal(first_f, &statement.f_matrix) {
                return false;
            }
        }
        
        true
    }
    
    /// Check matrix equality
    fn matrices_equal(&self, a: &Matrix<F>, b: &Matrix<F>) -> bool {
        if a.rows != b.rows || a.cols != b.cols {
            return false;
        }
        
        for i in 0..a.data.len() {
            if !self.ring.equal(&a.data[i], &b.data[i]) {
                return false;
            }
        }
        
        true
    }
    
    /// Verify batching correctness
    ///
    /// Checks that if all original relations hold, batched relation holds
    pub fn verify_batching(
        &self,
        original_statements: &[LinearStatement<F>],
        original_witness: &LinearWitness<F>,
        batched_statement: &LinearStatement<F>,
        batched_witness: &LinearWitness<F>,
        rho: &RingElement<F>,
    ) -> bool {
        // Check all original relations
        for statement in original_statements {
            let fw = statement.f_matrix.mul_mat(&original_witness.w_matrix, &self.ring);
            let hfw = statement.h_matrix.mul_mat(&fw, &self.ring);
            
            if !self.matrices_equal(&hfw, &statement.y_matrix) {
                return false;
            }
        }
        
        // Check batched relation
        let fw_batch = batched_statement.f_matrix.mul_mat(&batched_witness.w_matrix, &self.ring);
        let hfw_batch = batched_statement.h_matrix.mul_mat(&fw_batch, &self.ring);
        
        self.matrices_equal(&hfw_batch, &batched_statement.y_matrix)
    }
    
    /// Estimate communication cost
    ///
    /// Standard batching has zero communication (challenge from transcript)
    pub fn communication_bits(&self) -> usize {
        0
    }
    
    /// Compute soundness error
    ///
    /// Based on Schwartz-Zippel: ε ≈ k/|R_q|
    /// where k is number of relations being batched
    pub fn soundness_error(&self) -> f64 {
        let q = F::characteristic();
        let phi = self.ring.degree;
        let ring_size = q.pow(phi as u32) as f64;
        
        self.num_relations as f64 / ring_size
    }
}

/// Enhanced batching via sumcheck
///
/// Instead of batching H matrices, expresses constraints as sumcheck
/// and batches in extension field. This eliminates H entirely.
pub struct EnhancedBatchingReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Number of relations to batch
    pub num_relations: usize,
    
    /// Extension field degree
    pub ext_degree: usize,
}

impl<F: Field> EnhancedBatchingReduction<F> {
    /// Create new enhanced batching reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        num_relations: usize,
        ext_degree: usize,
    ) -> Self {
        Self {
            ring,
            num_relations,
            ext_degree,
        }
    }
    
    /// Prover enhanced batching
    ///
    /// Expresses F̄W = ȳ as evaluation claims and batches with random
    /// linear combination in F_{q^e}
    ///
    /// This is more complex and typically composed with sumcheck protocol
    pub fn prover_batch_enhanced(
        &self,
        statements: &[LinearStatement<F>],
        witness: &LinearWitness<F>,
        transcript: &mut Transcript,
    ) -> (Vec<ExtFieldElement<F>>, Vec<RingElement<F>>) {
        // Sample batching coefficients in extension field
        let batching_coeffs = transcript.challenge_ext_field_vector(
            b"enhanced-batching",
            self.num_relations,
            self.ext_degree,
            crate::ring::crt::ModulusType::PowerOfTwoCyclotomic,
        );
        
        // Convert statements to evaluation claims
        // This would typically involve LDE and sumcheck
        // For now, return placeholder structure
        
        let evaluations = vec![self.ring.zero(); self.num_relations];
        
        (batching_coeffs, evaluations)
    }
    
    /// Estimate communication cost
    ///
    /// Enhanced batching uses sumcheck: (2d-1)µe log q bits
    pub fn communication_bits(&self, d: usize, mu: usize, e: usize, log_q: usize) -> usize {
        (2 * d - 1) * mu * e * log_q
    }
}
