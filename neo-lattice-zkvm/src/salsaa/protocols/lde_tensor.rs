// Π^lde-⊗: LDE Tensor Reduction Protocol
//
// Mathematical Background:
// Reduces LDE evaluation claims to linear relations without communication.
// This is a deterministic reduction that the verifier can compute locally.
//
// Input: Ξ^lde-⊗ statement with evaluation claims LDE[W](r_i) = s_i
// Output: Ξ^lin statement with HFW = Y
//
// Construction (Lemma 2):
// For each evaluation claim LDE[W](r_i) = s_i:
// 1. Compute Lagrange basis r̃_i = ⊗_{j∈[µ]} L_j(r_{i,j})
// 2. Express as linear equation: (r̃_i^T ⊗ I_r) W = s_i^T
// 3. Stack all equations: [r̃_0^T ⊗ I_r; r̃_1^T ⊗ I_r; ...] W = [s_0^T; s_1^T; ...]
//
// The resulting linear relation can be combined with existing HFW = Y:
// H' = [H; I_t], F' = [F; (M_i r̃_i^T)], Y' = [Y; (s_i^T)]
//
// Properties:
// - Zero communication cost (deterministic reduction)
// - Preserves witness W
// - Adds t new rows to the linear system (t = number of evaluation claims)
//
// Reference: SALSAA paper Lemma 2, Requirement 5.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::{CRTContext, ExtFieldElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::lde::LDEContext;
use crate::salsaa::relations::{
    LDEStatement, LDEWitness, LinearStatement, LinearWitness,
};
use std::sync::Arc;

/// LDE tensor reduction protocol
///
/// Reduces Ξ^lde-⊗ → Ξ^lin deterministically without communication
pub struct LDETensorReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// LDE context for Lagrange basis computation
    pub lde_context: Arc<LDEContext<F>>,
    
    /// CRT context for challenge lifting
    pub crt_context: Arc<CRTContext<F>>,
}

impl<F: Field> LDETensorReduction<F> {
    /// Create new LDE tensor reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        lde_context: Arc<LDEContext<F>>,
        crt_context: Arc<CRTContext<F>>,
    ) -> Self {
        Self {
            ring,
            lde_context,
            crt_context,
        }
    }
    
    /// Prover reduction: Ξ^lde-⊗ → Ξ^lin
    ///
    /// Takes LDE statement and witness, produces linear statement and witness.
    /// This is deterministic - no randomness or communication needed.
    ///
    /// Algorithm:
    /// 1. For each evaluation claim (r_i, s_i):
    ///    a. Lift r_i from F_{q^e}^µ to R_q^µ via CRT
    ///    b. Compute Lagrange basis r̃_i ∈ R_q^{d^µ}
    ///    c. Create matrix row M_i = r̃_i^T ⊗ I_r
    /// 2. Stack with existing linear relation:
    ///    H' = [H; I_t], F' = [F; M], Y' = [Y; S]
    ///
    /// Complexity: O(t · d^µ · r) where t is number of evaluation claims
    pub fn prover_reduce(
        &self,
        lde_statement: &LDEStatement<F>,
        lde_witness: &LDEWitness<F>,
        existing_h: Option<&Matrix<F>>,
        existing_f: Option<&Matrix<F>>,
        existing_y: Option<&Matrix<F>>,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        let num_claims = lde_statement.eval_points.len();
        let num_cols = lde_witness.w_matrix.cols;
        let witness_size = lde_witness.w_matrix.rows;
        
        // Compute Lagrange basis vectors for each evaluation point
        let mut lagrange_rows = Vec::with_capacity(num_claims);
        
        for eval_point in &lde_statement.eval_points {
            // Lift evaluation point from F_{q^e}^µ to R_q^µ
            let lifted_point = self.lift_evaluation_point(eval_point);
            
            // Compute Lagrange basis r̃_i ∈ R_q^{d^µ}
            let lagrange_basis = self.lde_context.lagrange_basis(&lifted_point);
            
            lagrange_rows.push(lagrange_basis);
        }
        
        // Build new F matrix rows: M_i = r̃_i^T ⊗ I_r
        // Each row of M_i corresponds to one evaluation claim
        // M_i has shape (r, d^µ · r) where we replicate r̃_i for each column
        let mut new_f_rows = Vec::with_capacity(num_claims * num_cols);
        
        for lagrange_basis in &lagrange_rows {
            // For each column in the witness, create a row in F
            // Row structure: [0...0, r̃_i, 0...0] where r̃_i is in the i-th block
            for col_idx in 0..num_cols {
                let mut row_data = vec![self.ring.zero(); witness_size * num_cols];
                
                // Place lagrange_basis in the appropriate block
                for (j, &ref lag_elem) in lagrange_basis.iter().enumerate() {
                    let target_idx = j * num_cols + col_idx;
                    if target_idx < row_data.len() {
                        row_data[target_idx] = lag_elem.clone();
                    }
                }
                
                new_f_rows.push(row_data);
            }
        }
        
        // Build new Y matrix: stack claimed values
        let mut new_y_data = Vec::with_capacity(num_claims * num_cols);
        
        for claimed_values in &lde_statement.claimed_values {
            for value in claimed_values {
                new_y_data.push(value.clone());
            }
        }
        
        // Combine with existing matrices if provided
        let (h_matrix, f_matrix, y_matrix) = if let (Some(h), Some(f), Some(y)) = 
            (existing_h, existing_f, existing_y) {
            // Stack existing and new matrices
            let new_f_matrix = Matrix::from_data(
                num_claims * num_cols,
                witness_size * num_cols,
                new_f_rows.into_iter().flatten().collect(),
            );
            
            let new_y_matrix = Matrix::from_data(
                num_claims * num_cols,
                1,
                new_y_data,
            );
            
            // Create identity matrix for new H rows
            let identity_new = Matrix::identity(num_claims * num_cols, self.ring.degree);
            
            // Stack matrices vertically
            let h_stacked = h.vstack(&identity_new);
            let f_stacked = f.vstack(&new_f_matrix);
            let y_stacked = y.vstack(&new_y_matrix);
            
            (h_stacked, f_stacked, y_stacked)
        } else {
            // No existing matrices, create new ones
            let h_matrix = Matrix::identity(num_claims * num_cols, self.ring.degree);
            
            let f_matrix = Matrix::from_data(
                num_claims * num_cols,
                witness_size * num_cols,
                new_f_rows.into_iter().flatten().collect(),
            );
            
            let y_matrix = Matrix::from_data(
                num_claims * num_cols,
                1,
                new_y_data,
            );
            
            (h_matrix, f_matrix, y_matrix)
        };
        
        let linear_statement = LinearStatement {
            h_matrix,
            f_matrix,
            y_matrix,
        };
        
        let linear_witness = LinearWitness {
            w_matrix: lde_witness.w_matrix.clone(),
        };
        
        (linear_statement, linear_witness)
    }
    
    /// Verifier reduction: Ξ^lde-⊗ → Ξ^lin
    ///
    /// Verifier performs the same deterministic reduction as prover.
    /// This allows verifier to compute the linear statement locally.
    ///
    /// Note: Verifier doesn't have the witness, so only computes the statement.
    pub fn verifier_reduce(
        &self,
        lde_statement: &LDEStatement<F>,
        existing_h: Option<&Matrix<F>>,
        existing_f: Option<&Matrix<F>>,
        existing_y: Option<&Matrix<F>>,
    ) -> LinearStatement<F> {
        let num_claims = lde_statement.eval_points.len();
        let num_cols = lde_statement.claimed_values[0].len();
        
        // Determine witness size from tensor matrices or use default
        let witness_size = if !lde_statement.tensor_matrices.is_empty() {
            lde_statement.tensor_matrices[0].cols
        } else {
            self.lde_context.witness_size
        };
        
        // Compute Lagrange basis vectors for each evaluation point
        let mut lagrange_rows = Vec::with_capacity(num_claims);
        
        for eval_point in &lde_statement.eval_points {
            let lifted_point = self.lift_evaluation_point(eval_point);
            let lagrange_basis = self.lde_context.lagrange_basis(&lifted_point);
            lagrange_rows.push(lagrange_basis);
        }
        
        // Build new F matrix rows
        let mut new_f_rows = Vec::with_capacity(num_claims * num_cols);
        
        for lagrange_basis in &lagrange_rows {
            for col_idx in 0..num_cols {
                let mut row_data = vec![self.ring.zero(); witness_size * num_cols];
                
                for (j, &ref lag_elem) in lagrange_basis.iter().enumerate() {
                    let target_idx = j * num_cols + col_idx;
                    if target_idx < row_data.len() {
                        row_data[target_idx] = lag_elem.clone();
                    }
                }
                
                new_f_rows.push(row_data);
            }
        }
        
        // Build new Y matrix
        let mut new_y_data = Vec::with_capacity(num_claims * num_cols);
        
        for claimed_values in &lde_statement.claimed_values {
            for value in claimed_values {
                new_y_data.push(value.clone());
            }
        }
        
        // Combine with existing matrices
        let (h_matrix, f_matrix, y_matrix) = if let (Some(h), Some(f), Some(y)) = 
            (existing_h, existing_f, existing_y) {
            let new_f_matrix = Matrix::from_data(
                num_claims * num_cols,
                witness_size * num_cols,
                new_f_rows.into_iter().flatten().collect(),
            );
            
            let new_y_matrix = Matrix::from_data(
                num_claims * num_cols,
                1,
                new_y_data,
            );
            
            let identity_new = Matrix::identity(num_claims * num_cols, self.ring.degree);
            
            let h_stacked = h.vstack(&identity_new);
            let f_stacked = f.vstack(&new_f_matrix);
            let y_stacked = y.vstack(&new_y_matrix);
            
            (h_stacked, f_stacked, y_stacked)
        } else {
            let h_matrix = Matrix::identity(num_claims * num_cols, self.ring.degree);
            
            let f_matrix = Matrix::from_data(
                num_claims * num_cols,
                witness_size * num_cols,
                new_f_rows.into_iter().flatten().collect(),
            );
            
            let y_matrix = Matrix::from_data(
                num_claims * num_cols,
                1,
                new_y_data,
            );
            
            (h_matrix, f_matrix, y_matrix)
        };
        
        LinearStatement {
            h_matrix,
            f_matrix,
            y_matrix,
        }
    }
    
    /// Lift evaluation point from F_{q^e}^µ to R_q^µ
    ///
    /// For each coordinate r_j ∈ F_{q^e}, computes CRT^{-1}(1_{φ/e} · r_j) ∈ R_q
    /// This creates a ring element that equals r_j in all CRT slots.
    ///
    /// Mathematical: The lifted point r̃ ∈ R_q^µ satisfies:
    /// CRT(r̃_j) = (r_j, r_j, ..., r_j) for each coordinate j
    fn lift_evaluation_point(
        &self,
        point: &[ExtFieldElement<F>],
    ) -> Vec<RingElement<F>> {
        point.iter()
            .map(|coord| self.crt_context.lift_challenge(coord))
            .collect()
    }
    
    /// Compute tensor product of Lagrange bases
    ///
    /// For univariate bases b_0, b_1, ..., b_{µ-1}, computes:
    /// b_0 ⊗ b_1 ⊗ ... ⊗ b_{µ-1}
    ///
    /// This is used internally for Lagrange basis computation.
    fn tensor_product_bases(
        &self,
        bases: &[Vec<RingElement<F>>],
    ) -> Vec<RingElement<F>> {
        if bases.is_empty() {
            return vec![self.ring.one()];
        }
        
        let mut result = vec![self.ring.one()];
        
        for basis in bases {
            let mut new_result = Vec::with_capacity(result.len() * basis.len());
            
            for existing_elem in &result {
                for basis_elem in basis {
                    let prod = self.ring.mul(existing_elem, basis_elem);
                    new_result.push(prod);
                }
            }
            
            result = new_result;
        }
        
        result
    }
    
    /// Verify that reduction preserves the relation
    ///
    /// Checks that if LDE[W](r_i) = s_i for all i, then HFW = Y
    /// This is a sanity check for the reduction correctness.
    pub fn verify_reduction(
        &self,
        lde_statement: &LDEStatement<F>,
        lde_witness: &LDEWitness<F>,
        linear_statement: &LinearStatement<F>,
        linear_witness: &LinearWitness<F>,
    ) -> bool {
        // Check that witness is preserved
        if lde_witness.w_matrix.rows != linear_witness.w_matrix.rows ||
           lde_witness.w_matrix.cols != linear_witness.w_matrix.cols {
            return false;
        }
        
        // Check that all LDE evaluations match claimed values
        for (i, (eval_point, claimed_values)) in lde_statement.eval_points.iter()
            .zip(lde_statement.claimed_values.iter()).enumerate() {
            
            let lifted_point = self.lift_evaluation_point(eval_point);
            
            // Evaluate LDE at this point for each column
            for (col_idx, claimed_value) in claimed_values.iter().enumerate() {
                let column = lde_witness.w_matrix.get_col(col_idx);
                let lde_value = self.lde_context.evaluate_lde(&column, &lifted_point);
                
                if !self.ring.equal(&lde_value, claimed_value) {
                    return false;
                }
            }
        }
        
        // Check that linear relation holds
        let fw = linear_statement.f_matrix.mul_mat(&linear_witness.w_matrix, &self.ring);
        let hfw = linear_statement.h_matrix.mul_mat(&fw, &self.ring);
        
        // Verify HFW = Y
        if hfw.rows != linear_statement.y_matrix.rows ||
           hfw.cols != linear_statement.y_matrix.cols {
            return false;
        }
        
        for i in 0..hfw.data.len() {
            if !self.ring.equal(&hfw.data[i], &linear_statement.y_matrix.data[i]) {
                return false;
            }
        }
        
        true
    }
}
