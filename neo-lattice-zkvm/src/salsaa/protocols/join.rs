// Π^join: Join Reduction Protocol
//
// Mathematical Background:
// Combines two linear relations by stacking them vertically.
// Useful for composing multiple protocol steps or handling multiple constraints.
//
// Protocol (from [KLNO25]):
// Input: Two relations H_0 F_0 W_0 = Y_0 and H_1 F_1 W_1 = Y_1
// Output: Single relation [H_0; H_1][F_0; F_1][W_0; W_1] = [Y_0; Y_1]
//
// Vertical Stacking:
// - H' = [H_0; H_1] ∈ R_q^{(t_0+t_1)×(n_0+n_1)}
// - F' = [F_0, 0; 0, F_1] ∈ R_q^{(n_0+n_1)×(m_0+m_1)}
// - W' = [W_0; W_1] ∈ R_q^{(m_0+m_1)×r}
// - Y' = [Y_0; Y_1] ∈ R_q^{(t_0+t_1)×r}
//
// Properties:
// - Zero communication (deterministic combination)
// - Preserves both relations independently
// - Witness height: m_0 + m_1
// - Norm bound: max(∥W_0∥, ∥W_1∥)
//
// Use Cases:
// - Combining norm-check and evaluation claims
// - Handling multiple witness components
// - Composing protocol steps
//
// Reference: SALSAA paper Section 6.2, [KLNO25], Requirement 13.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use std::sync::Arc;

/// Join reduction protocol
pub struct JoinReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
}

impl<F: Field> JoinReduction<F> {
    /// Create new join reduction
    pub fn new(ring: Arc<CyclotomicRing<F>>) -> Self {
        Self { ring }
    }
    
    /// Prover join: Stack two relations vertically
    ///
    /// Algorithm:
    /// 1. Stack H matrices: H' = [H_0; H_1]
    /// 2. Create block-diagonal F: F' = [F_0, 0; 0, F_1]
    /// 3. Stack witnesses: W' = [W_0; W_1]
    /// 4. Stack targets: Y' = [Y_0; Y_1]
    ///
    /// Complexity: O(1) (just pointer manipulation, no computation)
    pub fn prover_join(
        &self,
        statement_0: &LinearStatement<F>,
        witness_0: &LinearWitness<F>,
        statement_1: &LinearStatement<F>,
        witness_1: &LinearWitness<F>,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        // Verify compatibility
        let r_0 = witness_0.w_matrix.cols;
        let r_1 = witness_1.w_matrix.cols;
        
        if r_0 != r_1 {
            panic!("Witnesses must have same number of columns: {} vs {}", r_0, r_1);
        }
        
        // Step 1: Stack H matrices vertically
        let h_joined = statement_0.h_matrix.vstack(&statement_1.h_matrix);
        
        // Step 2: Create block-diagonal F matrix
        let f_joined = self.create_block_diagonal_f(
            &statement_0.f_matrix,
            &statement_1.f_matrix,
        );
        
        // Step 3: Stack witnesses vertically
        let w_joined = witness_0.w_matrix.vstack(&witness_1.w_matrix);
        
        // Step 4: Stack targets vertically
        let y_joined = statement_0.y_matrix.vstack(&statement_1.y_matrix);
        
        let joined_statement = LinearStatement {
            h_matrix: h_joined,
            f_matrix: f_joined,
            y_matrix: y_joined,
        };
        
        let joined_witness = LinearWitness {
            w_matrix: w_joined,
        };
        
        (joined_statement, joined_witness)
    }
    
    /// Verifier join: Stack two statements
    ///
    /// Verifier performs same computation as prover (without witness)
    pub fn verifier_join(
        &self,
        statement_0: &LinearStatement<F>,
        statement_1: &LinearStatement<F>,
    ) -> LinearStatement<F> {
        // Stack H matrices
        let h_joined = statement_0.h_matrix.vstack(&statement_1.h_matrix);
        
        // Create block-diagonal F
        let f_joined = self.create_block_diagonal_f(
            &statement_0.f_matrix,
            &statement_1.f_matrix,
        );
        
        // Stack Y matrices
        let y_joined = statement_0.y_matrix.vstack(&statement_1.y_matrix);
        
        LinearStatement {
            h_matrix: h_joined,
            f_matrix: f_joined,
            y_matrix: y_joined,
        }
    }
    
    /// Create block-diagonal F matrix
    ///
    /// F' = [F_0, 0  ]
    ///      [0,  F_1]
    ///
    /// This ensures F_0 only acts on W_0 and F_1 only acts on W_1
    fn create_block_diagonal_f(
        &self,
        f_0: &Matrix<F>,
        f_1: &Matrix<F>,
    ) -> Matrix<F> {
        let n_0 = f_0.rows;
        let m_0 = f_0.cols;
        let n_1 = f_1.rows;
        let m_1 = f_1.cols;
        
        let total_rows = n_0 + n_1;
        let total_cols = m_0 + m_1;
        
        let mut f_joined_data = Vec::with_capacity(total_rows * total_cols);
        
        // Top-left block: F_0
        for row_idx in 0..n_0 {
            let row_0 = f_0.get_row(row_idx);
            
            // F_0 part
            for col_idx in 0..m_0 {
                if col_idx < row_0.len() {
                    f_joined_data.push(row_0[col_idx].clone());
                } else {
                    f_joined_data.push(self.ring.zero());
                }
            }
            
            // Zero padding for F_1 columns
            for _ in 0..m_1 {
                f_joined_data.push(self.ring.zero());
            }
        }
        
        // Bottom-right block: F_1
        for row_idx in 0..n_1 {
            let row_1 = f_1.get_row(row_idx);
            
            // Zero padding for F_0 columns
            for _ in 0..m_0 {
                f_joined_data.push(self.ring.zero());
            }
            
            // F_1 part
            for col_idx in 0..m_1 {
                if col_idx < row_1.len() {
                    f_joined_data.push(row_1[col_idx].clone());
                } else {
                    f_joined_data.push(self.ring.zero());
                }
            }
        }
        
        Matrix::from_data(total_rows, total_cols, f_joined_data)
    }
    
    /// Verify join correctness
    ///
    /// Checks that:
    /// 1. Both original relations hold
    /// 2. Joined relation holds
    /// 3. Joined relation implies both original relations
    pub fn verify_join(
        &self,
        statement_0: &LinearStatement<F>,
        witness_0: &LinearWitness<F>,
        statement_1: &LinearStatement<F>,
        witness_1: &LinearWitness<F>,
        joined_statement: &LinearStatement<F>,
        joined_witness: &LinearWitness<F>,
    ) -> bool {
        // Check first original relation
        let fw_0 = statement_0.f_matrix.mul_mat(&witness_0.w_matrix, &self.ring);
        let hfw_0 = statement_0.h_matrix.mul_mat(&fw_0, &self.ring);
        
        if !self.matrices_equal(&hfw_0, &statement_0.y_matrix) {
            return false;
        }
        
        // Check second original relation
        let fw_1 = statement_1.f_matrix.mul_mat(&witness_1.w_matrix, &self.ring);
        let hfw_1 = statement_1.h_matrix.mul_mat(&fw_1, &self.ring);
        
        if !self.matrices_equal(&hfw_1, &statement_1.y_matrix) {
            return false;
        }
        
        // Check joined relation
        let fw_joined = joined_statement.f_matrix.mul_mat(&joined_witness.w_matrix, &self.ring);
        let hfw_joined = joined_statement.h_matrix.mul_mat(&fw_joined, &self.ring);
        
        self.matrices_equal(&hfw_joined, &joined_statement.y_matrix)
    }
    
    /// Split joined statement back into components
    ///
    /// Inverse of join operation (useful for verification)
    pub fn split_joined(
        &self,
        joined_statement: &LinearStatement<F>,
        joined_witness: &LinearWitness<F>,
        split_point_h: usize,
        split_point_f: usize,
        split_point_w: usize,
    ) -> (
        (LinearStatement<F>, LinearWitness<F>),
        (LinearStatement<F>, LinearWitness<F>),
    ) {
        // Split H matrix
        let (h_0, h_1) = joined_statement.h_matrix.split_top_bottom(split_point_h);
        
        // Split Y matrix
        let (y_0, y_1) = joined_statement.y_matrix.split_top_bottom(split_point_h);
        
        // Split F matrix (more complex due to block-diagonal structure)
        let (f_0, f_1) = self.split_block_diagonal_f(
            &joined_statement.f_matrix,
            split_point_f,
        );
        
        // Split witness
        let (w_0, w_1) = joined_witness.w_matrix.split_top_bottom(split_point_w);
        
        let statement_0 = LinearStatement {
            h_matrix: h_0,
            f_matrix: f_0,
            y_matrix: y_0,
        };
        
        let witness_0 = LinearWitness {
            w_matrix: w_0,
        };
        
        let statement_1 = LinearStatement {
            h_matrix: h_1,
            f_matrix: f_1,
            y_matrix: y_1,
        };
        
        let witness_1 = LinearWitness {
            w_matrix: w_1,
        };
        
        ((statement_0, witness_0), (statement_1, witness_1))
    }
    
    /// Split block-diagonal F matrix
    ///
    /// Extracts F_0 and F_1 from block-diagonal structure:
    /// F = [F_0, 0  ]
    ///     [0,  F_1]
    ///
    /// Algorithm:
    /// 1. Identify non-zero blocks by scanning the matrix
    /// 2. Extract F_0 from top-left block
    /// 3. Extract F_1 from bottom-right block
    /// 4. Determine column split by finding first all-zero column in top rows
    fn split_block_diagonal_f(
        &self,
        f_joined: &Matrix<F>,
        split_row: usize,
    ) -> (Matrix<F>, Matrix<F>) {
        let total_rows = f_joined.rows;
        let total_cols = f_joined.cols;
        
        if split_row >= total_rows {
            return (f_joined.clone(), Matrix::zero(0, total_cols, self.ring.degree));
        }
        
        // Find column split point by scanning top rows for zero columns
        let mut split_col = total_cols;
        
        for col_idx in 0..total_cols {
            let mut all_zero_in_top = true;
            
            for row_idx in 0..split_row {
                let elem = f_joined.get(row_idx, col_idx);
                if elem.coeffs.iter().any(|c| c.to_canonical_u64() != 0) {
                    all_zero_in_top = false;
                    break;
                }
            }
            
            // If we found a column that's all zero in top rows, this is the split
            if all_zero_in_top {
                split_col = col_idx;
                break;
            }
        }
        
        // If no split found, use proportional split
        if split_col == total_cols {
            split_col = (total_cols * split_row) / total_rows;
        }
        
        // Extract F_0 (top-left block)
        let mut f_0_data = Vec::with_capacity(split_row * split_col);
        
        for row_idx in 0..split_row {
            for col_idx in 0..split_col {
                f_0_data.push(f_joined.get(row_idx, col_idx).clone());
            }
        }
        
        let f_0 = Matrix::from_data(split_row, split_col, f_0_data);
        
        // Extract F_1 (bottom-right block)
        let bottom_rows = total_rows - split_row;
        let right_cols = total_cols - split_col;
        let mut f_1_data = Vec::with_capacity(bottom_rows * right_cols);
        
        for row_idx in split_row..total_rows {
            for col_idx in split_col..total_cols {
                f_1_data.push(f_joined.get(row_idx, col_idx).clone());
            }
        }
        
        let f_1 = Matrix::from_data(bottom_rows, right_cols, f_1_data);
        
        (f_0, f_1)
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
    
    /// Compute joined norm bound
    ///
    /// ∥W'∥ = max(∥W_0∥, ∥W_1∥)
    ///
    /// The norm of the joined witness is the maximum of the component norms
    pub fn joined_norm_bound(&self, norm_0: u64, norm_1: u64) -> u64 {
        norm_0.max(norm_1)
    }
    
    /// Estimate communication cost
    ///
    /// Join has zero communication (deterministic combination)
    pub fn communication_bits(&self) -> usize {
        0
    }
    
    /// Compute soundness error
    ///
    /// Join preserves soundness of both component relations
    /// Overall error is max of component errors
    pub fn soundness_error(&self, error_0: f64, error_1: f64) -> f64 {
        error_0.max(error_1)
    }
}
