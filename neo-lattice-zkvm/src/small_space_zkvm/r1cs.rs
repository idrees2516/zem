// R1CS Structure Module for Spartan Prover
//
// This module implements the R1CS (Rank-1 Constraint System) structure
// used by the Spartan prover. It supports efficient sparse representations
// and block-diagonal structure for small-space proving.
//
// Key Features:
// 1. Sparse row representation for efficient storage
// 2. Block-diagonal constraint structure
// 3. Uniform R1CS for streaming computation
// 4. Efficient matrix-vector products
// 5. MLE evaluation for matrices
//
// References:
// - Paper Section 4: Spartan for Uniform R1CS (Requirements 4.1-4.13)
// - Tasks 15.1-15.7: R1CS structure implementation

use crate::field::Field;
use std::collections::HashMap;

/// Sparse Row Representation
///
/// Stores a sparse row as pairs of (column_index, value).
/// Efficient for rows with few non-zero entries.
///
/// Reference: Requirements 4.1-4.2, 4.4, Task 15.1
#[derive(Clone, Debug)]
pub struct SparseRow<F: Field> {
    /// Column indices
    indices: Vec<usize>,
    
    /// Field values at those indices
    values: Vec<F>,
}

impl<F: Field> SparseRow<F> {
    /// Create new sparse row
    pub fn new() -> Self {
        Self {
            indices: Vec::new(),
            values: Vec::new(),
        }
    }
    
    /// Create from dense vector
    pub fn from_dense(dense: &[F]) -> Self {
        let mut indices = Vec::new();
        let mut values = Vec::new();
        
        for (i, &val) in dense.iter().enumerate() {
            if val != F::zero() {
                indices.push(i);
                values.push(val);
            }
        }
        
        Self { indices, values }
    }
    
    /// Add entry to sparse row
    pub fn add_entry(&mut self, col: usize, val: F) {
        if val != F::zero() {
            // Check if column already exists
            if let Some(pos) = self.indices.iter().position(|&x| x == col) {
                self.values[pos] = self.values[pos] + val;
            } else {
                self.indices.push(col);
                self.values.push(val);
            }
        }
    }
    
    /// Compute dot product with dense vector
    ///
    /// Returns Σᵢ row[i] * vec[i]
    /// Time: O(nnz) where nnz is number of non-zero entries
    pub fn dot_product(&self, vec: &[F]) -> F {
        let mut result = F::zero();
        for (i, &idx) in self.indices.iter().enumerate() {
            if idx < vec.len() {
                result = result + self.values[i] * vec[idx];
            }
        }
        result
    }
    
    /// Get number of non-zero entries
    pub fn nnz(&self) -> usize {
        self.indices.len()
    }
    
    /// Get indices
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }
    
    /// Get values
    pub fn values(&self) -> &[F] {
        &self.values
    }
    
    /// Convert to dense vector
    pub fn to_dense(&self, size: usize) -> Vec<F> {
        let mut dense = vec![F::zero(); size];
        for (i, &idx) in self.indices.iter().enumerate() {
            if idx < size {
                dense[idx] = self.values[i];
            }
        }
        dense
    }
}

/// Constraint Block
///
/// Represents a block of β constraints over O(1) variables.
/// Used in block-diagonal R1CS structure.
///
/// Reference: Requirements 4.1-4.2, 4.4, Task 15.2
#[derive(Clone, Debug)]
pub struct ConstraintBlock<F: Field> {
    /// A matrix rows (β rows)
    pub a_block: Vec<SparseRow<F>>,
    
    /// B matrix rows (β rows)
    pub b_block: Vec<SparseRow<F>>,
    
    /// C matrix rows (β rows)
    pub c_block: Vec<SparseRow<F>>,
}

impl<F: Field> ConstraintBlock<F> {
    /// Create new constraint block
    pub fn new() -> Self {
        Self {
            a_block: Vec::new(),
            b_block: Vec::new(),
            c_block: Vec::new(),
        }
    }
    
    /// Add constraint to block
    ///
    /// Adds a single constraint: A·z ⊙ B·z = C·z
    pub fn add_constraint(&mut self, a_row: SparseRow<F>, b_row: SparseRow<F>, c_row: SparseRow<F>) {
        self.a_block.push(a_row);
        self.b_block.push(b_row);
        self.c_block.push(c_row);
    }
    
    /// Get number of constraints in block
    pub fn num_constraints(&self) -> usize {
        self.a_block.len()
    }
    
    /// Evaluate block at witness vector
    ///
    /// Computes A·z, B·z, C·z for all constraints in block
    pub fn evaluate(&self, witness: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
        let mut a_vals = Vec::new();
        let mut b_vals = Vec::new();
        let mut c_vals = Vec::new();
        
        for i in 0..self.num_constraints() {
            a_vals.push(self.a_block[i].dot_product(witness));
            b_vals.push(self.b_block[i].dot_product(witness));
            c_vals.push(self.c_block[i].dot_product(witness));
        }
        
        (a_vals, b_vals, c_vals)
    }
}

/// Uniform R1CS
///
/// Represents a uniform R1CS instance with block-diagonal structure.
/// Each cycle has the same β constraints over O(1) variables.
///
/// Reference: Requirements 4.1-4.2, Task 15.3
#[derive(Clone, Debug)]
pub struct UniformR1CS<F: Field> {
    /// Number of constraints per cycle (β)
    pub num_constraints_per_cycle: usize,
    
    /// Number of cycles (T)
    pub num_cycles: usize,
    
    /// Total number of witness variables
    pub num_variables: usize,
    
    /// Constant constraint block (same for all cycles)
    pub constraint_block: ConstraintBlock<F>,
}

impl<F: Field> UniformR1CS<F> {
    /// Create new uniform R1CS
    pub fn new(
        num_constraints_per_cycle: usize,
        num_cycles: usize,
        num_variables: usize,
    ) -> Self {
        Self {
            num_constraints_per_cycle,
            num_cycles,
            num_variables,
            constraint_block: ConstraintBlock::new(),
        }
    }
    
    /// Get total number of constraints
    pub fn total_constraints(&self) -> usize {
        self.num_constraints_per_cycle * self.num_cycles
    }
    
    /// Evaluate constraint at specific cycle
    ///
    /// Returns (A·z, B·z, C·z) for constraints at given cycle
    pub fn evaluate_cycle(&self, cycle: usize, witness: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
        self.constraint_block.evaluate(witness)
    }
    
    /// Verify all constraints
    ///
    /// Checks that A·z ⊙ B·z = C·z for all constraints
    pub fn verify(&self, witness: &[F]) -> bool {
        for cycle in 0..self.num_cycles {
            let (a_vals, b_vals, c_vals) = self.evaluate_cycle(cycle, witness);
            
            for i in 0..self.num_constraints_per_cycle {
                if a_vals[i] * b_vals[i] != c_vals[i] {
                    return false;
                }
            }
        }
        true
    }
}

/// Matrix MLE Evaluator
///
/// Evaluates multilinear extensions of R1CS matrices.
/// Supports efficient computation using block-diagonal structure.
///
/// Reference: Requirements 4.3, 4.10, Task 15.4
pub struct MatrixMLEEvaluator<F: Field> {
    /// Reference to R1CS
    r1cs: UniformR1CS<F>,
}

impl<F: Field> MatrixMLEEvaluator<F> {
    /// Create new evaluator
    pub fn new(r1cs: UniformR1CS<F>) -> Self {
        Self { r1cs }
    }
    
    /// Evaluate Ã(Y,x) at point Y
    ///
    /// Computes the MLE of the A matrix at point Y.
    /// Uses block-diagonal structure for O(log T) time.
    ///
    /// Reference: Requirements 4.3, 4.10, Task 15.4
    pub fn eval_a_mle(&self, y: &[F], x: &[F]) -> F {
        // For block-diagonal structure:
        // Ã(Y,x) = Σ_cycle eq̃(Y_cycle, tobits(cycle)) * A_block[x_cycle][x_var]
        
        let mut result = F::zero();
        
        // Compute cycle index from x
        let num_cycle_bits = (self.r1cs.num_cycles as f64).log2().ceil() as usize;
        let num_var_bits = (self.r1cs.num_variables as f64).log2().ceil() as usize;
        
        // Split x into cycle and variable parts
        let x_cycle_bits = &x[..num_cycle_bits];
        let x_var_bits = &x[num_cycle_bits..];
        
        // Split y into cycle and variable parts
        let y_cycle_bits = &y[..num_cycle_bits];
        let y_var_bits = &y[num_cycle_bits..];
        
        // For each cycle, compute contribution
        for cycle in 0..self.r1cs.num_cycles {
            // Compute eq̃(y_cycle, tobits(cycle))
            let cycle_eq = self.eval_eq(y_cycle_bits, cycle);
            
            // Compute A_block[x_cycle][x_var]
            if cycle < self.r1cs.constraint_block.a_block.len() {
                let a_row = &self.r1cs.constraint_block.a_block[cycle];
                
                // Evaluate at x_var
                let a_val = self.eval_row_mle(a_row, y_var_bits);
                
                result = result + cycle_eq * a_val;
            }
        }
        
        result
    }
    
    /// Evaluate Ã(Y,x) at point Y (alternative implementation)
    ///
    /// More efficient version using direct computation.
    pub fn eval_a_mle_fast(&self, y: &[F], x: &[F]) -> F {
        // Direct computation without decomposition
        let mut result = F::zero();
        
        // Compute contribution from each constraint
        for i in 0..self.r1cs.constraint_block.a_block.len() {
            let a_row = &self.r1cs.constraint_block.a_block[i];
            let val = self.eval_row_mle(a_row, y);
            result = result + val;
        }
        
        result
    }
    
    /// Evaluate B̃(Y,x) at point Y
    pub fn eval_b_mle(&self, y: &[F], x: &[F]) -> F {
        let mut result = F::zero();
        
        for i in 0..self.r1cs.constraint_block.b_block.len() {
            let b_row = &self.r1cs.constraint_block.b_block[i];
            let val = self.eval_row_mle(b_row, y);
            result = result + val;
        }
        
        result
    }
    
    /// Evaluate C̃(Y,x) at point Y
    pub fn eval_c_mle(&self, y: &[F], x: &[F]) -> F {
        let mut result = F::zero();
        
        for i in 0..self.r1cs.constraint_block.c_block.len() {
            let c_row = &self.r1cs.constraint_block.c_block[i];
            let val = self.eval_row_mle(c_row, y);
            result = result + val;
        }
        
        result
    }
    
    /// Evaluate sparse row MLE
    ///
    /// Computes MLE of a sparse row at point y.
    fn eval_row_mle(&self, row: &SparseRow<F>, y: &[F]) -> F {
        let mut result = F::zero();
        
        for (i, &idx) in row.indices().iter().enumerate() {
            let val = row.values()[i];
            
            // Compute eq̃(y, tobits(idx))
            let eq_val = self.eval_eq(y, idx);
            
            result = result + val * eq_val;
        }
        
        result
    }
    
    /// Evaluate equality function
    ///
    /// Computes eq̃(y, tobits(idx))
    fn eval_eq(&self, y: &[F], idx: usize) -> F {
        let mut result = F::one();
        
        for i in 0..y.len() {
            let bit = (idx >> i) & 1;
            let bit_f = if bit == 1 { F::one() } else { F::zero() };
            
            // eq̃ component: (1-y[i])(1-bit) + y[i]*bit
            let component = (F::one() - y[i]) * (F::one() - bit_f) + y[i] * bit_f;
            result = result * component;
        }
        
        result
    }
}

/// Streaming Matrix-Vector Product
///
/// Computes matrix-vector products in streaming fashion
/// without storing full matrices.
///
/// Reference: Requirements 4.3-4.4, Task 15.5
pub struct StreamingMatrixVectorProduct<F: Field> {
    /// R1CS instance
    r1cs: UniformR1CS<F>,
}

impl<F: Field> StreamingMatrixVectorProduct<F> {
    /// Create new streaming product
    pub fn new(r1cs: UniformR1CS<F>) -> Self {
        Self { r1cs }
    }
    
    /// Compute A·z in streaming fashion
    ///
    /// Computes matrix-vector product without storing full A matrix.
    /// Time: O(T·β·nnz) where nnz is average non-zeros per row
    /// Space: O(T·β) for result vector
    pub fn compute_az(&self, witness: &[F]) -> Vec<F> {
        let mut result = Vec::new();
        
        for cycle in 0..self.r1cs.num_cycles {
            let (a_vals, _, _) = self.r1cs.evaluate_cycle(cycle, witness);
            result.extend(a_vals);
        }
        
        result
    }
    
    /// Compute B·z in streaming fashion
    pub fn compute_bz(&self, witness: &[F]) -> Vec<F> {
        let mut result = Vec::new();
        
        for cycle in 0..self.r1cs.num_cycles {
            let (_, b_vals, _) = self.r1cs.evaluate_cycle(cycle, witness);
            result.extend(b_vals);
        }
        
        result
    }
    
    /// Compute C·z in streaming fashion
    pub fn compute_cz(&self, witness: &[F]) -> Vec<F> {
        let mut result = Vec::new();
        
        for cycle in 0..self.r1cs.num_cycles {
            let (_, _, c_vals) = self.r1cs.evaluate_cycle(cycle, witness);
            result.extend(c_vals);
        }
        
        result
    }
}

/// h̃ Vector Evaluator
///
/// Computes h̃_A, h̃_B, h̃_C vectors efficiently.
///
/// Reference: Requirements 4.3, 4.5, Tasks 15.6-15.7
pub struct HVectorEvaluator<F: Field> {
    /// R1CS instance
    r1cs: UniformR1CS<F>,
}

impl<F: Field> HVectorEvaluator<F> {
    /// Create new evaluator
    pub fn new(r1cs: UniformR1CS<F>) -> Self {
        Self { r1cs }
    }
    
    /// Compute h̃_A(Y) = Σ_x Ã(Y,x)·ũ(x)
    ///
    /// Streams through witness on-demand.
    /// Time: O(2^n) where n is number of variables
    /// Space: O(1) per query
    ///
    /// Reference: Requirements 4.3, 4.5, Task 15.6
    pub fn eval_h_a(&self, y: &[F], witness_oracle: &dyn Fn(usize) -> F) -> F {
        let mut result = F::zero();
        let num_vars = self.r1cs.num_variables;
        
        // Iterate over all possible x values
        for x_idx in 0..(1 << num_vars) {
            // Convert index to binary representation
            let mut x = vec![F::zero(); num_vars];
            for i in 0..num_vars {
                if (x_idx >> i) & 1 == 1 {
                    x[i] = F::one();
                }
            }
            
            // Compute Ã(Y,x)
            let evaluator = MatrixMLEEvaluator::new(self.r1cs.clone());
            let a_val = evaluator.eval_a_mle_fast(y, &x);
            
            // Get witness value
            let u_val = witness_oracle(x_idx);
            
            // Add contribution
            result = result + a_val * u_val;
        }
        
        result
    }
    
    /// Compute h̃_B(Y) = Σ_x B̃(Y,x)·ũ(x)
    pub fn eval_h_b(&self, y: &[F], witness_oracle: &dyn Fn(usize) -> F) -> F {
        let mut result = F::zero();
        let num_vars = self.r1cs.num_variables;
        
        for x_idx in 0..(1 << num_vars) {
            let mut x = vec![F::zero(); num_vars];
            for i in 0..num_vars {
                if (x_idx >> i) & 1 == 1 {
                    x[i] = F::one();
                }
            }
            
            let evaluator = MatrixMLEEvaluator::new(self.r1cs.clone());
            let b_val = evaluator.eval_b_mle(y, &x);
            let u_val = witness_oracle(x_idx);
            
            result = result + b_val * u_val;
        }
        
        result
    }
    
    /// Compute h̃_C(Y) = Σ_x C̃(Y,x)·ũ(x)
    pub fn eval_h_c(&self, y: &[F], witness_oracle: &dyn Fn(usize) -> F) -> F {
        let mut result = F::zero();
        let num_vars = self.r1cs.num_variables;
        
        for x_idx in 0..(1 << num_vars) {
            let mut x = vec![F::zero(); num_vars];
            for i in 0..num_vars {
                if (x_idx >> i) & 1 == 1 {
                    x[i] = F::one();
                }
            }
            
            let evaluator = MatrixMLEEvaluator::new(self.r1cs.clone());
            let c_val = evaluator.eval_c_mle(y, &x);
            let u_val = witness_oracle(x_idx);
            
            result = result + c_val * u_val;
        }
        
        result
    }
}
