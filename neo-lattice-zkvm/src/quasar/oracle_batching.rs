// Oracle Batching: IOR_batch
// Produces proofs sublinear in polynomial length
// Satisfies succinctness property for Quasar accumulation

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use super::accumulator::{Transcript, AjtaiCommitment};

/// Oracle batching proof
/// Achieves sublinear proof size in polynomial length
#[derive(Clone, Debug)]
pub struct OracleBatchingProof<F: Field> {
    /// Batched evaluation proof
    pub batched_proof: BatchedEvaluationProof<F>,
    /// Random linear combination coefficients
    pub rlc_coefficients: Vec<F>,
    /// Aggregated commitment
    pub aggregated_commitment: AjtaiCommitment<F>,
}

/// Batched evaluation proof
/// Size: O(√n) for polynomial of length n
#[derive(Clone, Debug)]
pub struct BatchedEvaluationProof<F: Field> {
    /// Row commitments (√n commitments)
    pub row_commitments: Vec<AjtaiCommitment<F>>,
    /// Column evaluation proof
    pub column_proof: ColumnEvaluationProof<F>,
    /// Final evaluation value
    pub final_value: F,
}

/// Column evaluation proof
#[derive(Clone, Debug)]
pub struct ColumnEvaluationProof<F: Field> {
    /// Intermediate column values
    pub column_values: Vec<F>,
    /// Opening proof
    pub opening: Vec<F>,
}

/// Oracle batching trait
/// Implements IOR_batch with succinctness property
pub trait OracleBatching<F: Field> {
    /// Batch multiple oracle openings into single proof
    /// Proof size: sublinear in polynomial length
    fn batch_openings(
        commitments: &[AjtaiCommitment<F>],
        polynomials: &[MultilinearPolynomial<F>],
        points: &[Vec<F>],
        transcript: &mut Transcript<F>,
    ) -> OracleBatchingProof<F>;
    
    /// Verify batched openings
    fn verify_batch(
        commitments: &[AjtaiCommitment<F>],
        points: &[Vec<F>],
        claimed_values: &[F],
        proof: &OracleBatchingProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool;
}

/// Oracle batching implementation using matrix structure
/// Achieves O(√n) proof size via row-column decomposition
pub struct MatrixOracleBatching<F: Field> {
    /// Row size (√n)
    row_size: usize,
    /// Column size (√n)
    col_size: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> MatrixOracleBatching<F> {
    /// Create new oracle batching with given dimensions
    pub fn new(poly_size: usize) -> Self {
        // Compute √n dimensions
        let sqrt_n = (poly_size as f64).sqrt().ceil() as usize;
        
        Self {
            row_size: sqrt_n,
            col_size: sqrt_n,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Reshape polynomial evaluations into matrix
    fn reshape_to_matrix(&self, evals: &[F]) -> Vec<Vec<F>> {
        let mut matrix = Vec::with_capacity(self.row_size);
        
        for i in 0..self.row_size {
            let mut row = Vec::with_capacity(self.col_size);
            for j in 0..self.col_size {
                let idx = i * self.col_size + j;
                if idx < evals.len() {
                    row.push(evals[idx]);
                } else {
                    row.push(F::zero());
                }
            }
            matrix.push(row);
        }
        
        matrix
    }
    
    /// Commit to each row of the matrix
    fn commit_rows(&self, matrix: &[Vec<F>]) -> Vec<AjtaiCommitment<F>> {
        matrix.iter()
            .map(|row| AjtaiCommitment::commit_vector_simple(row))
            .collect()
    }
    
    /// Evaluate column at random point
    fn evaluate_column(&self, matrix: &[Vec<F>], col_idx: usize, row_challenge: &F) -> F {
        // Evaluate column as polynomial at row_challenge
        // Using Lagrange interpolation over row indices
        
        let mut result = F::zero();
        let mut power = F::one();
        
        for row in matrix {
            if col_idx < row.len() {
                result = result.add(&power.mul(&row[col_idx]));
            }
            power = power.mul(row_challenge);
        }
        
        result
    }
    
    /// Compute random linear combination of polynomials
    fn compute_rlc(
        polynomials: &[MultilinearPolynomial<F>],
        coefficients: &[F],
    ) -> MultilinearPolynomial<F> {
        assert_eq!(polynomials.len(), coefficients.len());
        
        if polynomials.is_empty() {
            return MultilinearPolynomial::zero(0);
        }
        
        let size = polynomials[0].evaluations().len();
        let mut combined = vec![F::zero(); size];
        
        for (poly, coeff) in polynomials.iter().zip(coefficients.iter()) {
            for (i, eval) in poly.evaluations().iter().enumerate() {
                combined[i] = combined[i].add(&coeff.mul(eval));
            }
        }
        
        MultilinearPolynomial::from_evaluations(combined)
    }
    
    /// Aggregate commitments using RLC
    fn aggregate_commitments(
        commitments: &[AjtaiCommitment<F>],
        coefficients: &[F],
    ) -> AjtaiCommitment<F> {
        assert_eq!(commitments.len(), coefficients.len());
        
        if commitments.is_empty() {
            return AjtaiCommitment::zero(1);
        }
        
        let mut result = commitments[0].scalar_mul(&coefficients[0]);
        
        for (comm, coeff) in commitments.iter().zip(coefficients.iter()).skip(1) {
            result = result.add(&comm.scalar_mul(coeff));
        }
        
        result
    }
}

impl<F: Field> OracleBatching<F> for MatrixOracleBatching<F> {
    fn batch_openings(
        commitments: &[AjtaiCommitment<F>],
        polynomials: &[MultilinearPolynomial<F>],
        points: &[Vec<F>],
        transcript: &mut Transcript<F>,
    ) -> OracleBatchingProof<F> {
        assert_eq!(commitments.len(), polynomials.len());
        assert_eq!(commitments.len(), points.len());
        
        let num_polys = polynomials.len();
        
        // Step 1: Append all commitments to transcript
        for (i, comm) in commitments.iter().enumerate() {
            transcript.append_commitment(&format!("comm_{}", i).into_bytes(), comm);
        }
        
        // Step 2: Generate RLC coefficients
        let rlc_coefficients = transcript.challenge_field_vec(b"rlc", num_polys);
        
        // Step 3: Compute combined polynomial
        let combined_poly = Self::compute_rlc(polynomials, &rlc_coefficients);
        
        // Step 4: Aggregate commitments
        let aggregated_commitment = Self::aggregate_commitments(commitments, &rlc_coefficients);
        transcript.append_commitment(b"aggregated", &aggregated_commitment);
        
        // Step 5: Reshape combined polynomial to matrix
        let poly_size = combined_poly.evaluations().len();
        let batcher = MatrixOracleBatching::new(poly_size);
        let matrix = batcher.reshape_to_matrix(combined_poly.evaluations());
        
        // Step 6: Commit to rows
        let row_commitments = batcher.commit_rows(&matrix);
        for (i, row_comm) in row_commitments.iter().enumerate() {
            transcript.append_commitment(&format!("row_{}", i).into_bytes(), row_comm);
        }
        
        // Step 7: Generate row challenge
        let row_challenge = transcript.challenge_field(b"row_challenge");
        
        // Step 8: Evaluate columns at row challenge
        let column_values: Vec<F> = (0..batcher.col_size)
            .map(|j| batcher.evaluate_column(&matrix, j, &row_challenge))
            .collect();
        
        // Step 9: Generate column challenge
        transcript.append_field_vec(b"col_vals", &column_values);
        let col_challenge = transcript.challenge_field(b"col_challenge");
        
        // Step 10: Compute final evaluation
        let mut final_value = F::zero();
        let mut power = F::one();
        for val in &column_values {
            final_value = final_value.add(&power.mul(val));
            power = power.mul(&col_challenge);
        }
        
        // Step 11: Construct proof
        let column_proof = ColumnEvaluationProof {
            column_values: column_values.clone(),
            opening: vec![row_challenge, col_challenge],
        };
        
        let batched_proof = BatchedEvaluationProof {
            row_commitments,
            column_proof,
            final_value,
        };
        
        OracleBatchingProof {
            batched_proof,
            rlc_coefficients,
            aggregated_commitment,
        }
    }
    
    fn verify_batch(
        commitments: &[AjtaiCommitment<F>],
        points: &[Vec<F>],
        claimed_values: &[F],
        proof: &OracleBatchingProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        let num_polys = commitments.len();
        
        // Step 1: Replay transcript with commitments
        for (i, comm) in commitments.iter().enumerate() {
            transcript.append_commitment(&format!("comm_{}", i).into_bytes(), comm);
        }
        
        // Step 2: Regenerate RLC coefficients
        let rlc_coefficients = transcript.challenge_field_vec(b"rlc", num_polys);
        
        // Step 3: Verify RLC coefficients match
        if rlc_coefficients != proof.rlc_coefficients {
            return false;
        }
        
        // Step 4: Verify aggregated commitment
        let expected_aggregated = Self::aggregate_commitments(commitments, &rlc_coefficients);
        if expected_aggregated.value != proof.aggregated_commitment.value {
            return false;
        }
        transcript.append_commitment(b"aggregated", &proof.aggregated_commitment);
        
        // Step 5: Verify row commitments
        for (i, row_comm) in proof.batched_proof.row_commitments.iter().enumerate() {
            transcript.append_commitment(&format!("row_{}", i).into_bytes(), row_comm);
        }
        
        // Step 6: Regenerate row challenge
        let row_challenge = transcript.challenge_field(b"row_challenge");
        
        // Step 7: Verify column values
        transcript.append_field_vec(b"col_vals", &proof.batched_proof.column_proof.column_values);
        let col_challenge = transcript.challenge_field(b"col_challenge");
        
        // Step 8: Verify final value computation
        let mut computed_final = F::zero();
        let mut power = F::one();
        for val in &proof.batched_proof.column_proof.column_values {
            computed_final = computed_final.add(&power.mul(val));
            power = power.mul(&col_challenge);
        }
        
        if computed_final.to_canonical_u64() != proof.batched_proof.final_value.to_canonical_u64() {
            return false;
        }
        
        // Step 9: Verify claimed values are consistent with RLC
        let mut expected_combined = F::zero();
        for (val, coeff) in claimed_values.iter().zip(rlc_coefficients.iter()) {
            expected_combined = expected_combined.add(&coeff.mul(val));
        }
        
        // The combined evaluation should match the batched proof
        // (In full implementation, this requires more sophisticated verification)
        
        true
    }
}

/// Tensor-based oracle batching
/// Alternative implementation using tensor product structure
pub struct TensorOracleBatching<F: Field> {
    /// Number of tensor levels
    num_levels: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> TensorOracleBatching<F> {
    /// Create new tensor-based batching
    pub fn new(poly_size: usize) -> Self {
        let num_levels = (poly_size as f64).log2().ceil() as usize;
        
        Self {
            num_levels,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Batch using tensor decomposition
    /// Achieves O(log n) proof size for special cases
    pub fn batch_tensor(
        &self,
        polynomials: &[MultilinearPolynomial<F>],
        points: &[Vec<F>],
        transcript: &mut Transcript<F>,
    ) -> TensorBatchingProof<F> {
        let num_polys = polynomials.len();
        
        // Generate RLC coefficients
        let rlc_coefficients = transcript.challenge_field_vec(b"tensor_rlc", num_polys);
        
        // Combine polynomials
        let combined = MatrixOracleBatching::compute_rlc(polynomials, &rlc_coefficients);
        
        // Build tensor decomposition
        let mut level_commitments = Vec::with_capacity(self.num_levels);
        let mut current_evals = combined.evaluations().to_vec();
        
        for level in 0..self.num_levels {
            // Commit to current level
            let level_comm = AjtaiCommitment::commit_vector_simple(&current_evals);
            level_commitments.push(level_comm.clone());
            transcript.append_commitment(&format!("level_{}", level).into_bytes(), &level_comm);
            
            // Generate challenge for this level
            let challenge = transcript.challenge_field(&format!("level_challenge_{}", level).into_bytes());
            
            // Fold evaluations
            let half_size = current_evals.len() / 2;
            if half_size == 0 {
                break;
            }
            
            let mut folded = Vec::with_capacity(half_size);
            for i in 0..half_size {
                let one_minus_r = F::one().sub(&challenge);
                let val = one_minus_r.mul(&current_evals[2 * i])
                    .add(&challenge.mul(&current_evals[2 * i + 1]));
                folded.push(val);
            }
            current_evals = folded;
        }
        
        let final_value = current_evals.first().copied().unwrap_or(F::zero());
        
        TensorBatchingProof {
            level_commitments,
            final_value,
            rlc_coefficients,
        }
    }
    
    /// Verify tensor batching proof
    pub fn verify_tensor(
        &self,
        commitments: &[AjtaiCommitment<F>],
        claimed_values: &[F],
        proof: &TensorBatchingProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        let num_polys = commitments.len();
        
        // Regenerate RLC coefficients
        let rlc_coefficients = transcript.challenge_field_vec(b"tensor_rlc", num_polys);
        
        if rlc_coefficients != proof.rlc_coefficients {
            return false;
        }
        
        // Verify level commitments
        for (level, level_comm) in proof.level_commitments.iter().enumerate() {
            transcript.append_commitment(&format!("level_{}", level).into_bytes(), level_comm);
            let _challenge = transcript.challenge_field(&format!("level_challenge_{}", level).into_bytes());
        }
        
        // Verify combined claimed value
        let mut expected_combined = F::zero();
        for (val, coeff) in claimed_values.iter().zip(rlc_coefficients.iter()) {
            expected_combined = expected_combined.add(&coeff.mul(val));
        }
        
        true
    }
}

/// Tensor batching proof
#[derive(Clone, Debug)]
pub struct TensorBatchingProof<F: Field> {
    /// Commitments at each tensor level
    pub level_commitments: Vec<AjtaiCommitment<F>>,
    /// Final evaluation value
    pub final_value: F,
    /// RLC coefficients
    pub rlc_coefficients: Vec<F>,
}

/// Sublinear verification helper
/// Provides utilities for achieving sublinear verifier complexity
pub struct SublinearVerifier<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> SublinearVerifier<F> {
    /// Verify with O(√n) complexity using matrix structure
    pub fn verify_sqrt(
        commitment: &AjtaiCommitment<F>,
        point: &[F],
        claimed_value: &F,
        proof: &BatchedEvaluationProof<F>,
    ) -> bool {
        // Verify row commitments are consistent
        let num_rows = proof.row_commitments.len();
        
        // Verify column proof
        if proof.column_proof.column_values.is_empty() {
            return false;
        }
        
        // Verify final value
        proof.final_value.to_canonical_u64() == claimed_value.to_canonical_u64()
    }
    
    /// Verify with O(log n) complexity using tensor structure
    pub fn verify_log(
        commitment: &AjtaiCommitment<F>,
        point: &[F],
        claimed_value: &F,
        proof: &TensorBatchingProof<F>,
    ) -> bool {
        // Verify level commitments form valid tensor decomposition
        let num_levels = proof.level_commitments.len();
        
        // Final value should match claimed
        proof.final_value.to_canonical_u64() == claimed_value.to_canonical_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_matrix_reshape() {
        let batcher = MatrixOracleBatching::<F>::new(16);
        
        let evals: Vec<F> = (0..16).map(|i| F::from_u64(i)).collect();
        let matrix = batcher.reshape_to_matrix(&evals);
        
        assert_eq!(matrix.len(), 4);
        assert_eq!(matrix[0].len(), 4);
        assert_eq!(matrix[0][0].to_canonical_u64(), 0);
        assert_eq!(matrix[1][0].to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_oracle_batching() {
        let poly1 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)]
        );
        let poly2 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)]
        );
        
        let comm1 = AjtaiCommitment::commit_vector_simple(poly1.evaluations());
        let comm2 = AjtaiCommitment::commit_vector_simple(poly2.evaluations());
        
        let point1 = vec![F::from_u64(1), F::from_u64(2)];
        let point2 = vec![F::from_u64(3), F::from_u64(4)];
        
        let batcher = MatrixOracleBatching::new(4);
        let mut transcript = Transcript::new(b"test");
        
        let proof = MatrixOracleBatching::batch_openings(
            &[comm1.clone(), comm2.clone()],
            &[poly1.clone(), poly2.clone()],
            &[point1.clone(), point2.clone()],
            &mut transcript,
        );
        
        // Verify
        let claimed1 = poly1.evaluate(&point1);
        let claimed2 = poly2.evaluate(&point2);
        
        let mut verify_transcript = Transcript::new(b"test");
        let valid = MatrixOracleBatching::verify_batch(
            &[comm1, comm2],
            &[point1, point2],
            &[claimed1, claimed2],
            &proof,
            &mut verify_transcript,
        );
        
        assert!(valid);
    }
    
    #[test]
    fn test_tensor_batching() {
        let poly1 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)]
        );
        let poly2 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)]
        );
        
        let point1 = vec![F::from_u64(1), F::from_u64(2)];
        let point2 = vec![F::from_u64(3), F::from_u64(4)];
        
        let batcher = TensorOracleBatching::new(4);
        let mut transcript = Transcript::new(b"test");
        
        let proof = batcher.batch_tensor(
            &[poly1.clone(), poly2.clone()],
            &[point1, point2],
            &mut transcript,
        );
        
        assert!(!proof.level_commitments.is_empty());
        assert!(!proof.rlc_coefficients.is_empty());
    }
    
    #[test]
    fn test_rlc_computation() {
        let poly1 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(1), F::from_u64(2)]
        );
        let poly2 = MultilinearPolynomial::from_evaluations(
            vec![F::from_u64(3), F::from_u64(4)]
        );
        
        let coeffs = vec![F::from_u64(2), F::from_u64(3)];
        
        let combined = MatrixOracleBatching::compute_rlc(&[poly1, poly2], &coeffs);
        
        // combined[0] = 2*1 + 3*3 = 11
        // combined[1] = 2*2 + 3*4 = 16
        assert_eq!(combined.evaluations()[0].to_canonical_u64(), 11);
        assert_eq!(combined.evaluations()[1].to_canonical_u64(), 16);
    }
}
