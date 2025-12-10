// Π^fold: Folding Reduction Protocol
//
// Mathematical Background:
// Reduces witness height by folding with random challenge.
// Splits witness into d blocks and combines them linearly.
//
// Protocol (from [KLNO25]):
// Input: Linear relation HFW = Y with W ∈ R_q^{m×r}, F with tensor structure
// 1. Split W into d blocks: W = [W_0; W_1; ...; W_{d-1}] where W_i ∈ R_q^{m/d×r}
// 2. Verifier samples challenge γ ∈ Challenge set (Subtractive or Large)
// 3. Prover computes folded witness: W' = Σ_{i∈[d]} γ^i W_i ∈ R_q^{m/d×r}
// 4. Update F matrix using tensor structure: F' = F_0 + γF_1 + ... + γ^{d-1}F_{d-1}
// 5. Update Y accordingly: Y' = HF'W'
//
// Challenge Sets:
// - Subtractive: γ ∈ {d, d+1, ..., 2d-1} ⊂ Z_q
// - Large: γ ∈ R_q with ∥γ∥ ≤ B for large B
//
// Properties:
// - Witness height reduced by factor d
// - Norm bound: ∥W'∥ ≤ d · max_i ∥W_i∥
// - Preserves relation: HF'W' = Y
// - Communication: 0 bits (challenge from transcript)
//
// Reference: SALSAA paper Section 6.2, [KLNO25], Requirements 8.1, 8.2

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::salsaa::matrix::{Matrix, TensorStructure};
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Challenge set type for folding
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeSet {
    /// Subtractive set: {d, d+1, ..., 2d-1}
    Subtractive,
    
    /// Large set: R_q with bounded norm
    Large { norm_bound: u64 },
}

/// Folding reduction protocol
pub struct FoldingReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Challenge set type
    pub challenge_set: ChallengeSet,
    
    /// Folding factor (typically d from LDE degree)
    pub folding_factor: usize,
}

impl<F: Field> FoldingReduction<F> {
    /// Create new folding reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        challenge_set: ChallengeSet,
        folding_factor: usize,
    ) -> Self {
        assert!(folding_factor > 0, "Folding factor must be positive");
        
        Self {
            ring,
            challenge_set,
            folding_factor,
        }
    }
    
    /// Prover folding: Reduce witness height by factor d
    ///
    /// Algorithm:
    /// 1. Split W into d blocks
    /// 2. Sample challenge γ from transcript
    /// 3. Compute W' = Σ_i γ^i W_i
    /// 4. Update F using tensor structure
    /// 5. Compute Y' = HF'W'
    ///
    /// Complexity: O(m · r) ring operations
    pub fn prover_fold(
        &self,
        statement: &LinearStatement<F>,
        witness: &LinearWitness<F>,
        transcript: &mut Transcript,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        let d = self.folding_factor;
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        
        // Verify witness can be split into d blocks
        if m % d != 0 {
            panic!("Witness height {} must be divisible by folding factor {}", m, d);
        }
        
        let block_height = m / d;
        
        // Step 1: Split witness into d blocks
        let mut blocks = Vec::with_capacity(d);
        for i in 0..d {
            let start_row = i * block_height;
            let end_row = (i + 1) * block_height;
            
            let block_data = witness.w_matrix.data[start_row * r..end_row * r].to_vec();
            let block = Matrix::from_data(block_height, r, block_data);
            blocks.push(block);
        }
        
        // Step 2: Sample folding challenge
        let gamma = self.sample_challenge(transcript);
        
        // Step 3: Compute folded witness W' = Σ_i γ^i W_i
        let mut w_folded = Matrix::zero(block_height, r, self.ring.degree);
        let mut gamma_power = self.ring.one();
        
        for block in &blocks {
            let scaled_block = block.scalar_mul(&gamma_power, &self.ring);
            w_folded = w_folded.add(&scaled_block, &self.ring);
            gamma_power = self.ring.mul(&gamma_power, &gamma);
        }
        
        // Step 4: Update F matrix using tensor structure
        let f_folded = if let Some(tensor_struct) = statement.f_matrix.get_tensor_structure() {
            // Use tensor structure for efficient folding
            let folded_tensor = tensor_struct.fold_with_challenge(&gamma, &self.ring);
            folded_tensor.compute_full_matrix(&self.ring)
        } else {
            // Manual folding if no tensor structure
            self.fold_matrix_manual(&statement.f_matrix, &gamma, d)
        };
        
        // Step 5: Compute Y' = HF'W'
        let fw_folded = f_folded.mul_mat(&w_folded, &self.ring);
        let y_folded = statement.h_matrix.mul_mat(&fw_folded, &self.ring);
        
        let folded_statement = LinearStatement {
            h_matrix: statement.h_matrix.clone(),
            f_matrix: f_folded,
            y_matrix: y_folded,
        };
        
        let folded_witness = LinearWitness {
            w_matrix: w_folded,
        };
        
        (folded_statement, folded_witness)
    }
    
    /// Verifier folding: Update statement with challenge
    ///
    /// Verifier performs same computation as prover but without witness
    pub fn verifier_fold(
        &self,
        statement: &LinearStatement<F>,
        transcript: &mut Transcript,
    ) -> LinearStatement<F> {
        let d = self.folding_factor;
        
        // Sample same challenge as prover
        let gamma = self.sample_challenge(transcript);
        
        // Update F matrix
        let f_folded = if let Some(tensor_struct) = statement.f_matrix.get_tensor_structure() {
            let folded_tensor = tensor_struct.fold_with_challenge(&gamma, &self.ring);
            folded_tensor.compute_full_matrix(&self.ring)
        } else {
            self.fold_matrix_manual(&statement.f_matrix, &gamma, d)
        };
        
        // Note: Y will be provided by prover or computed from commitment
        // For now, keep original Y (will be updated in full protocol)
        LinearStatement {
            h_matrix: statement.h_matrix.clone(),
            f_matrix: f_folded,
            y_matrix: statement.y_matrix.clone(),
        }
    }
    
    /// Sample folding challenge from transcript
    fn sample_challenge(&self, transcript: &mut Transcript) -> RingElement<F> {
        match &self.challenge_set {
            ChallengeSet::Subtractive => {
                // Sample from {d, d+1, ..., 2d-1}
                let d = self.folding_factor;
                
                // Use transcript to generate index in range [0, d)
                let mut challenge_bytes = [0u8; 8];
                let state = transcript.state();
                challenge_bytes.copy_from_slice(&state[..8]);
                let index = u64::from_le_bytes(challenge_bytes) % (d as u64);
                
                // Map to {d, d+1, ..., 2d-1}
                let value = d as u64 + index;
                
                // Update transcript
                transcript.append_message(b"folding-challenge", &value.to_le_bytes());
                
                self.ring.from_u64(value)
            }
            
            ChallengeSet::Large { norm_bound } => {
                // Sample random ring element with bounded norm
                // Keep sampling until we get one within the bound
                loop {
                    let challenge = transcript.challenge_ring(b"folding-challenge", &self.ring);
                    
                    // Compute canonical norm squared
                    let conjugate = self.ring.conjugate(&challenge);
                    let inner_prod = self.ring.mul(&challenge, &conjugate);
                    let trace = self.ring.trace(&inner_prod);
                    let norm_squared = trace.to_canonical_u64();
                    
                    // Check if within bound
                    if norm_squared <= norm_bound * norm_bound {
                        return challenge;
                    }
                    
                    // Update transcript to get different challenge on next iteration
                    transcript.append_message(b"folding-retry", &norm_squared.to_le_bytes());
                }
            }
        }
    }
    
    /// Manual matrix folding without tensor structure
    ///
    /// Folds matrix by splitting rows into d blocks and combining with powers of γ
    fn fold_matrix_manual(
        &self,
        matrix: &Matrix<F>,
        gamma: &RingElement<F>,
        d: usize,
    ) -> Matrix<F> {
        let n = matrix.rows;
        let m = matrix.cols;
        
        if n % d != 0 {
            // Cannot fold evenly, return original
            return matrix.clone();
        }
        
        let block_height = n / d;
        let mut folded = Matrix::zero(block_height, m, self.ring.degree);
        let mut gamma_power = self.ring.one();
        
        for i in 0..d {
            let start_row = i * block_height;
            let end_row = (i + 1) * block_height;
            
            let block_data = matrix.data[start_row * m..end_row * m].to_vec();
            let block = Matrix::from_data(block_height, m, block_data);
            
            let scaled_block = block.scalar_mul(&gamma_power, &self.ring);
            folded = folded.add(&scaled_block, &self.ring);
            
            gamma_power = self.ring.mul(&gamma_power, gamma);
        }
        
        folded
    }
    
    /// Verify folding preserves relation
    ///
    /// Checks that HF'W' = Y' where F', W', Y' are folded versions
    pub fn verify_folding(
        &self,
        original_statement: &LinearStatement<F>,
        original_witness: &LinearWitness<F>,
        folded_statement: &LinearStatement<F>,
        folded_witness: &LinearWitness<F>,
    ) -> bool {
        // Check original relation
        let fw_orig = original_statement.f_matrix.mul_mat(&original_witness.w_matrix, &self.ring);
        let hfw_orig = original_statement.h_matrix.mul_mat(&fw_orig, &self.ring);
        
        if !self.matrices_equal(&hfw_orig, &original_statement.y_matrix) {
            return false;
        }
        
        // Check folded relation
        let fw_fold = folded_statement.f_matrix.mul_mat(&folded_witness.w_matrix, &self.ring);
        let hfw_fold = folded_statement.h_matrix.mul_mat(&fw_fold, &self.ring);
        
        self.matrices_equal(&hfw_fold, &folded_statement.y_matrix)
    }
    
    /// Compute norm bound after folding
    ///
    /// ∥W'∥ ≤ d · max_i ∥W_i∥
    ///
    /// This is a loose bound; actual norm may be smaller due to cancellation
    pub fn folded_norm_bound(&self, original_norm: u64) -> u64 {
        self.folding_factor as u64 * original_norm
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
    
    /// Estimate communication cost
    ///
    /// Folding has zero communication (challenge from transcript)
    pub fn communication_bits(&self) -> usize {
        0
    }
    
    /// Compute soundness error
    ///
    /// For subtractive set: ε = 1/d
    /// For large set: ε ≈ 1/B where B is norm bound
    pub fn soundness_error(&self) -> f64 {
        match &self.challenge_set {
            ChallengeSet::Subtractive => {
                1.0 / (self.folding_factor as f64)
            }
            ChallengeSet::Large { norm_bound } => {
                1.0 / (*norm_bound as f64)
            }
        }
    }
}
