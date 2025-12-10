// Π^split: Split Reduction Protocol
//
// Mathematical Background:
// Splits witness vertically and combines with random challenge.
// Reduces witness from W = [W_top; W_bot] to W' = W_top + α·W_bot.
//
// Protocol (from [KLNO24]):
// Input: Linear relation HFW = Y with W = [W_top; W_bot]
// 1. Prover commits to top part: y_top = F_top·W_top
// 2. Verifier samples challenge α ∈ R_q
// 3. Prover computes combined witness: W' = W_top + α·W_bot
// 4. Update F matrix: F' = F_top + α·F_bot
// 5. Update Y: Y' = y_top + α·(Y - y_top)
//
// Properties:
// - Reduces witness height by half (or other split ratio)
// - Communication: |y_top| = size of commitment
// - Soundness: Schwartz-Zippel lemma over R_q
// - Preserves norm bounds (with appropriate scaling)
//
// Use Cases:
// - Iterative witness reduction in SNARK
// - Combining multiple witness blocks
// - Amortizing commitment costs
//
// Reference: SALSAA paper Section 6.2, [KLNO24], Requirement 9.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Split reduction protocol
pub struct SplitReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Split point (number of rows in top part)
    pub split_point: usize,
}

/// Split proof
#[derive(Clone, Debug)]
pub struct SplitProof<F: Field> {
    /// Commitment to top part: y_top = F_top·W_top
    pub y_top: Matrix<F>,
    
    /// Challenge used for combination
    pub alpha: RingElement<F>,
}

impl<F: Field> SplitReduction<F> {
    /// Create new split reduction
    ///
    /// split_point: Number of rows in W_top (remaining rows go to W_bot)
    pub fn new(ring: Arc<CyclotomicRing<F>>, split_point: usize) -> Self {
        assert!(split_point > 0, "Split point must be positive");
        
        Self {
            ring,
            split_point,
        }
    }
    
    /// Prover split: Reduce witness height
    ///
    /// Algorithm:
    /// 1. Split W = [W_top; W_bot] at split_point
    /// 2. Split F = [F_top; F_bot] correspondingly
    /// 3. Compute y_top = F_top·W_top
    /// 4. Send y_top to verifier (via transcript)
    /// 5. Receive challenge α
    /// 6. Compute W' = W_top + α·W_bot
    /// 7. Compute F' = F_top + α·F_bot
    /// 8. Compute Y' = y_top + α·(Y - y_top)
    ///
    /// Complexity: O(m·r) ring operations where m is witness height
    pub fn prover_split(
        &self,
        statement: &LinearStatement<F>,
        witness: &LinearWitness<F>,
        transcript: &mut Transcript,
    ) -> (LinearStatement<F>, LinearWitness<F>, SplitProof<F>) {
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        
        // Verify split point is valid
        if self.split_point >= m {
            panic!("Split point {} must be less than witness height {}", 
                self.split_point, m);
        }
        
        // Step 1: Split witness W = [W_top; W_bot]
        let (w_top, w_bot) = witness.w_matrix.split_top_bottom(self.split_point);
        
        // Step 2: Split F matrix F = [F_top; F_bot]
        // F has shape (n, m·r), we need to split columns corresponding to witness rows
        let (f_top, f_bot) = self.split_f_matrix(&statement.f_matrix, r);
        
        // Step 3: Compute commitment to top part
        let y_top = f_top.mul_mat(&w_top, &self.ring);
        
        // Step 4: Send y_top to transcript
        transcript.append_matrix(b"split-y-top", &y_top);
        
        // Step 5: Receive challenge α
        let alpha = transcript.challenge_ring(b"split-challenge", &self.ring);
        
        // Step 6: Compute combined witness W' = W_top + α·W_bot
        let alpha_w_bot = w_bot.scalar_mul(&alpha, &self.ring);
        let w_prime = w_top.add(&alpha_w_bot, &self.ring);
        
        // Step 7: Compute combined F matrix F' = F_top + α·F_bot
        let alpha_f_bot = f_bot.scalar_mul(&alpha, &self.ring);
        let f_prime = f_top.add(&alpha_f_bot, &self.ring);
        
        // Step 8: Compute Y' = y_top + α·(Y - y_top)
        let y_minus_y_top = statement.y_matrix.sub(&y_top, &self.ring);
        let alpha_diff = y_minus_y_top.scalar_mul(&alpha, &self.ring);
        let y_prime = y_top.add(&alpha_diff, &self.ring);
        
        let split_statement = LinearStatement {
            h_matrix: statement.h_matrix.clone(),
            f_matrix: f_prime,
            y_matrix: y_prime,
        };
        
        let split_witness = LinearWitness {
            w_matrix: w_prime,
        };
        
        let proof = SplitProof {
            y_top,
            alpha,
        };
        
        (split_statement, split_witness, proof)
    }
    
    /// Verifier split: Update statement with challenge
    ///
    /// Verifier performs same computation as prover but without witness
    ///
    /// Algorithm:
    /// 1. Receive y_top from prover
    /// 2. Sample challenge α
    /// 3. Compute F' = F_top + α·F_bot
    /// 4. Compute Y' = y_top + α·(Y - y_top)
    pub fn verifier_split(
        &self,
        statement: &LinearStatement<F>,
        y_top: &Matrix<F>,
        transcript: &mut Transcript,
    ) -> LinearStatement<F> {
        let r = statement.y_matrix.cols;
        
        // Add y_top to transcript
        transcript.append_matrix(b"split-y-top", y_top);
        
        // Sample challenge
        let alpha = transcript.challenge_ring(b"split-challenge", &self.ring);
        
        // Split F matrix
        let (f_top, f_bot) = self.split_f_matrix(&statement.f_matrix, r);
        
        // Compute F' = F_top + α·F_bot
        let alpha_f_bot = f_bot.scalar_mul(&alpha, &self.ring);
        let f_prime = f_top.add(&alpha_f_bot, &self.ring);
        
        // Compute Y' = y_top + α·(Y - y_top)
        let y_minus_y_top = statement.y_matrix.sub(y_top, &self.ring);
        let alpha_diff = y_minus_y_top.scalar_mul(&alpha, &self.ring);
        let y_prime = y_top.add(&alpha_diff, &self.ring);
        
        LinearStatement {
            h_matrix: statement.h_matrix.clone(),
            f_matrix: f_prime,
            y_matrix: y_prime,
        }
    }
    
    /// Split F matrix into top and bottom parts
    ///
    /// F has shape (n, m·r) where m is witness height, r is number of columns
    /// We split it into F_top (n, split_point·r) and F_bot (n, (m-split_point)·r)
    fn split_f_matrix(&self, f: &Matrix<F>, r: usize) -> (Matrix<F>, Matrix<F>) {
        let n = f.rows;
        let total_cols = f.cols;
        
        // Determine split point in columns
        let split_col = self.split_point * r;
        
        if split_col >= total_cols {
            // Cannot split, return original and zero matrix
            let zero_bot = Matrix::zero(n, 0, self.ring.degree);
            return (f.clone(), zero_bot);
        }
        
        // Extract top and bottom column blocks
        let mut f_top_data = Vec::with_capacity(n * split_col);
        let mut f_bot_data = Vec::with_capacity(n * (total_cols - split_col));
        
        for row_idx in 0..n {
            let row = f.get_row(row_idx);
            
            // Top part: first split_col columns
            for col_idx in 0..split_col {
                if col_idx < row.len() {
                    f_top_data.push(row[col_idx].clone());
                } else {
                    f_top_data.push(self.ring.zero());
                }
            }
            
            // Bottom part: remaining columns
            for col_idx in split_col..total_cols {
                if col_idx < row.len() {
                    f_bot_data.push(row[col_idx].clone());
                } else {
                    f_bot_data.push(self.ring.zero());
                }
            }
        }
        
        let f_top = Matrix::from_data(n, split_col, f_top_data);
        let f_bot = Matrix::from_data(n, total_cols - split_col, f_bot_data);
        
        (f_top, f_bot)
    }
    
    /// Verify split correctness
    ///
    /// Checks that:
    /// 1. Original relation holds: HFW = Y
    /// 2. Split relation holds: HF'W' = Y'
    /// 3. Commitment is correct: y_top = F_top·W_top
    pub fn verify_split(
        &self,
        original_statement: &LinearStatement<F>,
        original_witness: &LinearWitness<F>,
        split_statement: &LinearStatement<F>,
        split_witness: &LinearWitness<F>,
        proof: &SplitProof<F>,
    ) -> bool {
        // Check original relation
        let fw_orig = original_statement.f_matrix.mul_mat(&original_witness.w_matrix, &self.ring);
        let hfw_orig = original_statement.h_matrix.mul_mat(&fw_orig, &self.ring);
        
        if !self.matrices_equal(&hfw_orig, &original_statement.y_matrix) {
            return false;
        }
        
        // Check split relation
        let fw_split = split_statement.f_matrix.mul_mat(&split_witness.w_matrix, &self.ring);
        let hfw_split = split_statement.h_matrix.mul_mat(&fw_split, &self.ring);
        
        if !self.matrices_equal(&hfw_split, &split_statement.y_matrix) {
            return false;
        }
        
        // Check commitment correctness
        let (w_top, _) = original_witness.w_matrix.split_top_bottom(self.split_point);
        let r = original_witness.w_matrix.cols;
        let (f_top, _) = self.split_f_matrix(&original_statement.f_matrix, r);
        let computed_y_top = f_top.mul_mat(&w_top, &self.ring);
        
        self.matrices_equal(&computed_y_top, &proof.y_top)
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
    
    /// Estimate communication cost in bits
    ///
    /// Communication: |y_top| = t·r·log|R_q| bits
    /// where t is number of rows in H, r is number of columns
    pub fn communication_bits(&self, t: usize, r: usize, log_ring_size: usize) -> usize {
        t * r * log_ring_size
    }
    
    /// Compute soundness error
    ///
    /// Based on Schwartz-Zippel lemma: ε ≈ d/|R_q|
    /// where d is degree of the polynomial being tested
    pub fn soundness_error(&self, degree: usize) -> f64 {
        let q = F::characteristic();
        let phi = self.ring.degree;
        let ring_size = q.pow(phi as u32) as f64;
        
        degree as f64 / ring_size
    }
}
