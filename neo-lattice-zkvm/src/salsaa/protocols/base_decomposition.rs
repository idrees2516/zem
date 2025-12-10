// Π^b-decomp: Base Decomposition Protocol
//
// Mathematical Background:
// Decomposes witness into base-b representation to reduce norm.
// Each witness element w_i is written as w_i = Σ_{j∈[ℓ]} b^j · w_{i,j}
// where w_{i,j} ∈ {0, 1, ..., b-1}.
//
// Protocol (from [KLNO24]):
// Input: Linear relation HFW = Y with W ∈ R_q^{m×r}
// 1. Prover decomposes each w_i into ℓ base-b digits: w_i = Σ_j b^j · w_{i,j}
// 2. Create expanded witness W' ∈ R_q^{ℓm×r} by stacking all digits
// 3. Update F matrix: F' = F · diag(1, b, b², ..., b^{ℓ-1})
// 4. Relation preserved: HF'W' = Y
//
// Properties:
// - Witness height increases by factor ℓ
// - Norm reduced: ∥W'∥ ≤ b · √ℓ (each digit bounded by b)
// - Original norm: ∥W∥ ≤ b^ℓ (before decomposition)
// - Net reduction: ∥W'∥/∥W∥ ≈ √ℓ / b^{ℓ-1}
// - Communication: 0 bits (deterministic transformation)
//
// Use Cases:
// - Norm reduction in SNARK
// - Preparing witness for final verification
// - Converting between different norm bounds
//
// Reference: SALSAA paper Section 6.2, [KLNO24], Requirement 11.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use std::sync::Arc;

/// Base decomposition protocol
pub struct BaseDecomposition<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Decomposition base b
    pub base: u64,
    
    /// Number of digits ℓ
    pub num_digits: usize,
}

impl<F: Field> BaseDecomposition<F> {
    /// Create new base decomposition
    ///
    /// base: Decomposition base b (typically 2, 4, or small power of 2)
    /// num_digits: Number of digits ℓ in decomposition
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        base: u64,
        num_digits: usize,
    ) -> Self {
        assert!(base >= 2, "Base must be at least 2");
        assert!(num_digits > 0, "Number of digits must be positive");
        
        // Verify base^num_digits doesn't overflow
        assert!(
            base.checked_pow(num_digits as u32).is_some(),
            "Base {} to power {} overflows",
            base, num_digits
        );
        
        Self {
            ring,
            base,
            num_digits,
        }
    }
    
    /// Prover decomposition: Reduce witness norm
    ///
    /// Algorithm:
    /// 1. For each element w_i, compute base-b decomposition
    /// 2. Stack all digits to create W' ∈ R_q^{ℓm×r}
    /// 3. Update F matrix with diagonal scaling
    /// 4. Verify relation: HF'W' = Y
    ///
    /// Complexity: O(ℓ·m·r·φ) field operations
    pub fn prover_decompose(
        &self,
        statement: &LinearStatement<F>,
        witness: &LinearWitness<F>,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        let ell = self.num_digits;
        
        // Step 1: Decompose witness
        let w_decomposed = self.decompose_matrix(&witness.w_matrix);
        
        // Step 2: Update F matrix
        let f_decomposed = self.update_f_matrix(&statement.f_matrix, m, r);
        
        // Verify dimensions
        assert_eq!(w_decomposed.rows, ell * m);
        assert_eq!(w_decomposed.cols, r);
        
        let decomposed_statement = LinearStatement {
            h_matrix: statement.h_matrix.clone(),
            f_matrix: f_decomposed,
            y_matrix: statement.y_matrix.clone(),
        };
        
        let decomposed_witness = LinearWitness {
            w_matrix: w_decomposed,
        };
        
        (decomposed_statement, decomposed_witness)
    }
    
    /// Decompose matrix into base-b representation
    ///
    /// For each element w, computes w = Σ_{j∈[ℓ]} b^j · w_j
    /// Returns matrix with ℓ times more rows, stacking all digit matrices
    fn decompose_matrix(&self, matrix: &Matrix<F>) -> Matrix<F> {
        let m = matrix.rows;
        let r = matrix.cols;
        let ell = self.num_digits;
        
        // Result has ℓ·m rows (ℓ digit matrices stacked)
        let mut decomposed_data = Vec::with_capacity(ell * m * r);
        
        // For each digit position j ∈ [ℓ]
        for digit_idx in 0..ell {
            // For each element in original matrix
            for row_idx in 0..m {
                for col_idx in 0..r {
                    let elem = matrix.get(row_idx, col_idx);
                    let digit = self.extract_digit(elem, digit_idx);
                    decomposed_data.push(digit);
                }
            }
        }
        
        Matrix::from_data(ell * m, r, decomposed_data)
    }
    
    /// Extract j-th digit in base-b decomposition
    ///
    /// For ring element w, computes w_j such that w = Σ_j b^j · w_j
    /// Returns w_j ∈ {0, 1, ..., b-1}
    fn extract_digit(&self, elem: &RingElement<F>, digit_idx: usize) -> RingElement<F> {
        // Decompose each coefficient independently
        let mut digit_coeffs = Vec::with_capacity(elem.coeffs.len());
        
        for coeff in &elem.coeffs {
            let value = coeff.to_canonical_u64();
            
            // Extract digit: (value / b^digit_idx) mod b
            let divisor = self.base.pow(digit_idx as u32);
            let digit_value = (value / divisor) % self.base;
            
            digit_coeffs.push(F::from_u64(digit_value));
        }
        
        RingElement::from_coeffs(digit_coeffs)
    }
    
    /// Update F matrix for decomposed witness
    ///
    /// F' = F · diag(1, b, b², ..., b^{ℓ-1})
    ///
    /// The diagonal matrix accounts for the place values in base-b representation
    fn update_f_matrix(&self, f: &Matrix<F>, m: usize, r: usize) -> Matrix<F> {
        let n = f.rows;
        let ell = self.num_digits;
        
        // F has shape (n, m·r), F' will have shape (n, ℓ·m·r)
        let mut f_prime_data = Vec::with_capacity(n * ell * m * r);
        
        // For each row of F
        for row_idx in 0..n {
            let row = f.get_row(row_idx);
            
            // For each digit position
            for digit_idx in 0..ell {
                // Compute scaling factor b^digit_idx
                let scale_value = self.base.pow(digit_idx as u32);
                let scale = self.ring.from_u64(scale_value);
                
                // Scale the corresponding block of the row
                for col_idx in 0..(m * r) {
                    let elem = if col_idx < row.len() {
                        &row[col_idx]
                    } else {
                        &self.ring.zero()
                    };
                    
                    let scaled = self.ring.mul(elem, &scale);
                    f_prime_data.push(scaled);
                }
            }
        }
        
        Matrix::from_data(n, ell * m * r, f_prime_data)
    }
    
    /// Verify decomposition correctness
    ///
    /// Checks:
    /// 1. Original relation: HFW = Y
    /// 2. Decomposed relation: HF'W' = Y
    /// 3. Reconstruction: W = Σ_j b^j · W'_j
    pub fn verify_decomposition(
        &self,
        original_statement: &LinearStatement<F>,
        original_witness: &LinearWitness<F>,
        decomposed_statement: &LinearStatement<F>,
        decomposed_witness: &LinearWitness<F>,
    ) -> bool {
        // Check original relation
        let fw_orig = original_statement.f_matrix.mul_mat(&original_witness.w_matrix, &self.ring);
        let hfw_orig = original_statement.h_matrix.mul_mat(&fw_orig, &self.ring);
        
        if !self.matrices_equal(&hfw_orig, &original_statement.y_matrix) {
            return false;
        }
        
        // Check decomposed relation
        let fw_decomp = decomposed_statement.f_matrix.mul_mat(&decomposed_witness.w_matrix, &self.ring);
        let hfw_decomp = decomposed_statement.h_matrix.mul_mat(&fw_decomp, &self.ring);
        
        if !self.matrices_equal(&hfw_decomp, &decomposed_statement.y_matrix) {
            return false;
        }
        
        // Check reconstruction
        let reconstructed = self.reconstruct_matrix(&decomposed_witness.w_matrix);
        self.matrices_equal(&reconstructed, &original_witness.w_matrix)
    }
    
    /// Reconstruct original matrix from decomposed form
    ///
    /// W = Σ_{j∈[ℓ]} b^j · W'_j
    fn reconstruct_matrix(&self, decomposed: &Matrix<F>) -> Matrix<F> {
        let ell = self.num_digits;
        let total_rows = decomposed.rows;
        let r = decomposed.cols;
        
        if total_rows % ell != 0 {
            panic!("Decomposed matrix rows {} not divisible by num_digits {}", 
                total_rows, ell);
        }
        
        let m = total_rows / ell;
        let mut reconstructed_data = Vec::with_capacity(m * r);
        
        // For each position in original matrix
        for row_idx in 0..m {
            for col_idx in 0..r {
                let mut sum = self.ring.zero();
                let mut power = self.ring.one();
                
                // Sum over all digits
                for digit_idx in 0..ell {
                    let decomp_row = digit_idx * m + row_idx;
                    let digit = decomposed.get(decomp_row, col_idx);
                    
                    let term = self.ring.mul(digit, &power);
                    sum = self.ring.add(&sum, &term);
                    
                    // Update power: power *= b
                    let b_elem = self.ring.from_u64(self.base);
                    power = self.ring.mul(&power, &b_elem);
                }
                
                reconstructed_data.push(sum);
            }
        }
        
        Matrix::from_data(m, r, reconstructed_data)
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
    
    /// Compute norm bound after decomposition
    ///
    /// Each digit is bounded by b, so:
    /// ∥W'∥ ≤ b · √ℓ (assuming independent digits)
    pub fn decomposed_norm_bound(&self) -> u64 {
        let sqrt_ell = (self.num_digits as f64).sqrt();
        (self.base as f64 * sqrt_ell).ceil() as u64
    }
    
    /// Compute original norm bound before decomposition
    ///
    /// If W = Σ_j b^j · W'_j and ∥W'_j∥ ≤ b, then:
    /// ∥W∥ ≤ Σ_j b^j · b = b · (b^ℓ - 1)/(b - 1) ≈ b^ℓ
    pub fn original_norm_bound(&self) -> u64 {
        self.base.pow(self.num_digits as u32)
    }
    
    /// Compute norm reduction factor
    ///
    /// Ratio of decomposed norm to original norm:
    /// ∥W'∥/∥W∥ ≈ (b·√ℓ) / b^ℓ = √ℓ / b^{ℓ-1}
    pub fn norm_reduction_factor(&self) -> f64 {
        let sqrt_ell = (self.num_digits as f64).sqrt();
        let b_power = self.base.pow((self.num_digits - 1) as u32) as f64;
        sqrt_ell / b_power
    }
    
    /// Estimate communication cost
    ///
    /// Base decomposition has zero communication (deterministic)
    pub fn communication_bits(&self) -> usize {
        0
    }
}
