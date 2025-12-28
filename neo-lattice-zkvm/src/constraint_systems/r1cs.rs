// R1CS Constraint System
// Implements Az ⊙ Bz = Cz for sparse matrices A, B, C
//
// Paper Reference: Multiple papers use R1CS as standard constraint system
// - "Sum-check Is All You Need" (2025-2041), Section 5.1
// - SALSAA (2025-2124), Section 3.3
//
// This module implements the Rank-1 Constraint System (R1CS), which is
// one of the most widely used constraint systems in zkSNARKs.
//
// Mathematical Background:
// R1CS represents computations as a system of quadratic constraints:
// (Az) ⊙ (Bz) = Cz
//
// where:
// - A, B, C are m×n matrices (typically sparse)
// - z ∈ F^n is the witness vector
// - ⊙ denotes element-wise (Hadamard) product
// - m is the number of constraints
// - n is the witness size
//
// Witness Structure:
// z = [1, x_1, ..., x_ℓ, w_1, ..., w_k]
// where:
// - 1 is a constant (for handling constants in constraints)
// - x_1, ..., x_ℓ are public inputs
// - w_1, ..., w_k are private witness values
//
// Example: Multiplication Gate
// To prove c = a · b:
// - A has single row [0, 1, 0, ...] (selects a)
// - B has single row [0, 0, 1, ...] (selects b)
// - C has single row [0, 0, 0, 1, ...] (selects c)
// - Constraint: a · b = c
//
// Sparse Representation:
// Since A, B, C are typically sparse (most entries are 0), we store
// them in compressed format:
// - For each row, store list of (column_index, value) pairs
// - This reduces space from O(m·n) to O(nnz) where nnz is number of non-zeros
//
// Sum-check Integration:
// R1CS constraints can be verified using sum-check protocol:
// 1. Extend A, B, C to multilinear polynomials ã, b̃, c̃
// 2. Extend z to multilinear polynomial z̃
// 3. Prove: Σ_x [ã(x)·z̃(x)] · [b̃(x)·z̃(x)] = Σ_x [c̃(x)·z̃(x)]
//
// This reduces R1CS verification to polynomial evaluation checks.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Sparse matrix entry
///
/// Represents a single non-zero entry in a sparse matrix.
#[derive(Clone, Debug)]
pub struct SparseEntry<F: Field> {
    /// Row index
    pub row: usize,
    
    /// Column index
    pub column: usize,
    
    /// Value at (row, column)
    pub value: F,
}

impl<F: Field> SparseEntry<F> {
    /// Create new sparse entry
    pub fn new(row: usize, column: usize, value: F) -> Self {
        Self { row, column, value }
    }
}

/// Sparse matrix in compressed row format
///
/// Paper Reference: Standard sparse matrix representation
///
/// Stores matrix as list of non-zero entries per row.
/// This is efficient for matrices where most entries are zero.
#[derive(Clone, Debug)]
pub struct SparseMatrix<F: Field> {
    /// Number of rows
    pub num_rows: usize,
    
    /// Number of columns
    pub num_columns: usize,
    
    /// Non-zero entries, grouped by row
    /// rows[i] contains all non-zero entries in row i
    pub rows: Vec<Vec<(usize, F)>>,
}

impl<F: Field> SparseMatrix<F> {
    /// Create new sparse matrix
    ///
    /// # Arguments
    /// * `num_rows` - Number of rows
    /// * `num_columns` - Number of columns
    ///
    /// # Returns
    /// Empty sparse matrix
    pub fn new(num_rows: usize, num_columns: usize) -> Self {
        Self {
            num_rows,
            num_columns,
            rows: vec![Vec::new(); num_rows],
        }
    }
    
    /// Create from list of entries
    ///
    /// # Arguments
    /// * `num_rows` - Number of rows
    /// * `num_columns` - Number of columns
    /// * `entries` - List of non-zero entries
    ///
    /// # Returns
    /// Sparse matrix with given entries
    pub fn from_entries(
        num_rows: usize,
        num_columns: usize,
        entries: Vec<SparseEntry<F>>,
    ) -> Result<Self, String> {
        let mut matrix = Self::new(num_rows, num_columns);
        
        for entry in entries {
            if entry.row >= num_rows {
                return Err(format!("Row index {} out of bounds", entry.row));
            }
            if entry.column >= num_columns {
                return Err(format!("Column index {} out of bounds", entry.column));
            }
            
            matrix.rows[entry.row].push((entry.column, entry.value));
        }
        
        // Sort each row by column index for efficient lookup
        for row in &mut matrix.rows {
            row.sort_by_key(|(col, _)| *col);
        }
        
        Ok(matrix)
    }
    
    /// Set entry at (row, column)
    pub fn set(&mut self, row: usize, column: usize, value: F) -> Result<(), String> {
        if row >= self.num_rows {
            return Err(format!("Row index {} out of bounds", row));
        }
        if column >= self.num_columns {
            return Err(format!("Column index {} out of bounds", column));
        }
        
        // Check if entry already exists
        if let Some(pos) = self.rows[row].iter().position(|(col, _)| *col == column) {
            self.rows[row][pos].1 = value;
        } else {
            self.rows[row].push((column, value));
            self.rows[row].sort_by_key(|(col, _)| *col);
        }
        
        Ok(())
    }
    
    /// Get entry at (row, column)
    pub fn get(&self, row: usize, column: usize) -> F {
        if row >= self.num_rows || column >= self.num_columns {
            return F::zero();
        }
        
        for (col, val) in &self.rows[row] {
            if *col == column {
                return *val;
            }
        }
        
        F::zero()
    }
    
    /// Multiply matrix by vector: result = M · v
    ///
    /// Paper Reference: Standard matrix-vector multiplication
    ///
    /// Computes result[i] = Σ_j M[i,j] · v[j] for each row i.
    ///
    /// For sparse matrices, this is efficient:
    /// - Only process non-zero entries
    /// - Complexity: O(nnz) where nnz is number of non-zeros
    pub fn multiply_vector(&self, vector: &[F]) -> Result<Vec<F>, String> {
        if vector.len() != self.num_columns {
            return Err(format!(
                "Vector length {} doesn't match matrix columns {}",
                vector.len(), self.num_columns
            ));
        }
        
        let mut result = vec![F::zero(); self.num_rows];
        
        for (i, row) in self.rows.iter().enumerate() {
            for (col, val) in row {
                result[i] = result[i].add(&val.mul(&vector[*col]));
            }
        }
        
        Ok(result)
    }
    
    /// Get number of non-zero entries
    pub fn num_nonzeros(&self) -> usize {
        self.rows.iter().map(|row| row.len()).sum()
    }
    
    /// Get sparsity (fraction of zero entries)
    pub fn sparsity(&self) -> f64 {
        let total_entries = self.num_rows * self.num_columns;
        let nonzeros = self.num_nonzeros();
        1.0 - (nonzeros as f64 / total_entries as f64)
    }
}

/// R1CS constraint system
///
/// Paper Reference: Section 5.1, "R1CS Constraints"
///
/// Represents computation as (Az) ⊙ (Bz) = Cz where:
/// - A, B, C are sparse matrices
/// - z is the witness vector
/// - ⊙ is element-wise product
#[derive(Clone, Debug)]
pub struct R1CS<F: Field> {
    /// Matrix A
    pub a_matrix: SparseMatrix<F>,
    
    /// Matrix B
    pub b_matrix: SparseMatrix<F>,
    
    /// Matrix C
    pub c_matrix: SparseMatrix<F>,
    
    /// Number of constraints (rows in matrices)
    pub num_constraints: usize,
    
    /// Witness size (columns in matrices)
    pub witness_size: usize,
    
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl<F: Field> R1CS<F> {
    /// Create new R1CS instance
    ///
    /// # Arguments
    /// * `a_matrix` - Matrix A
    /// * `b_matrix` - Matrix B
    /// * `c_matrix` - Matrix C
    /// * `num_public_inputs` - Number of public inputs
    ///
    /// # Returns
    /// R1CS constraint system
    pub fn new(
        a_matrix: SparseMatrix<F>,
        b_matrix: SparseMatrix<F>,
        c_matrix: SparseMatrix<F>,
        num_public_inputs: usize,
    ) -> Result<Self, String> {
        // Verify dimensions match
        if a_matrix.num_rows != b_matrix.num_rows || b_matrix.num_rows != c_matrix.num_rows {
            return Err("Matrices must have same number of rows".to_string());
        }
        
        if a_matrix.num_columns != b_matrix.num_columns || b_matrix.num_columns != c_matrix.num_columns {
            return Err("Matrices must have same number of columns".to_string());
        }
        
        let num_constraints = a_matrix.num_rows;
        let witness_size = a_matrix.num_columns;
        
        if num_public_inputs >= witness_size {
            return Err("Public inputs must be less than witness size".to_string());
        }
        
        Ok(Self {
            a_matrix,
            b_matrix,
            c_matrix,
            num_constraints,
            witness_size,
            num_public_inputs,
        })
    }
    
    /// Verify R1CS constraints
    ///
    /// Paper Reference: Section 5.1, "R1CS Verification"
    ///
    /// Checks that (Az) ⊙ (Bz) = Cz for given witness z.
    ///
    /// Algorithm:
    /// 1. Compute Az, Bz, Cz using sparse matrix-vector multiplication
    /// 2. Compute (Az) ⊙ (Bz) element-wise
    /// 3. Check if result equals Cz
    ///
    /// Complexity: O(nnz) where nnz is total number of non-zeros
    pub fn verify(&self, witness: &[F]) -> Result<bool, String> {
        if witness.len() != self.witness_size {
            return Err(format!(
                "Witness size {} doesn't match expected {}",
                witness.len(), self.witness_size
            ));
        }
        
        // Compute Az, Bz, Cz
        let az = self.a_matrix.multiply_vector(witness)?;
        let bz = self.b_matrix.multiply_vector(witness)?;
        let cz = self.c_matrix.multiply_vector(witness)?;
        
        // Check (Az) ⊙ (Bz) = Cz
        for i in 0..self.num_constraints {
            let lhs = az[i].mul(&bz[i]);
            if lhs.to_canonical_u64() != cz[i].to_canonical_u64() {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Convert to multilinear polynomials for sum-check
    ///
    /// Paper Reference: Section 5.1, "Polynomial Encoding"
    ///
    /// Converts R1CS matrices to multilinear polynomials:
    /// - ã: multilinear extension of A
    /// - b̃: multilinear extension of B
    /// - c̃: multilinear extension of C
    /// - z̃: multilinear extension of z
    ///
    /// This allows using sum-check protocol to verify R1CS.
    ///
    /// Algorithm:
    /// 1. Flatten matrix to vector (row-major order)
    /// 2. Pad to power of 2
    /// 3. Compute multilinear extension
    ///
    /// Complexity: O(m·n) where m is constraints, n is witness size
    pub fn to_multilinear_polynomials(
        &self,
        witness: &[F],
    ) -> Result<(MultilinearPolynomial<F>, MultilinearPolynomial<F>, MultilinearPolynomial<F>, MultilinearPolynomial<F>), String> {
        // Flatten matrices to vectors
        let mut a_vec = Vec::new();
        let mut b_vec = Vec::new();
        let mut c_vec = Vec::new();
        
        for i in 0..self.num_constraints {
            for j in 0..self.witness_size {
                a_vec.push(self.a_matrix.get(i, j));
                b_vec.push(self.b_matrix.get(i, j));
                c_vec.push(self.c_matrix.get(i, j));
            }
        }
        
        // Pad to power of 2
        let total_size = self.num_constraints * self.witness_size;
        let padded_size = total_size.next_power_of_two();
        
        a_vec.resize(padded_size, F::zero());
        b_vec.resize(padded_size, F::zero());
        c_vec.resize(padded_size, F::zero());
        
        // Create multilinear polynomials
        let a_poly = MultilinearPolynomial::from_evaluations(a_vec)?;
        let b_poly = MultilinearPolynomial::from_evaluations(b_vec)?;
        let c_poly = MultilinearPolynomial::from_evaluations(c_vec)?;
        
        // Pad witness
        let mut z_vec = witness.to_vec();
        z_vec.resize(padded_size, F::zero());
        let z_poly = MultilinearPolynomial::from_evaluations(z_vec)?;
        
        Ok((a_poly, b_poly, c_poly, z_poly))
    }
    
    /// Get public inputs from witness
    ///
    /// Public inputs are the first num_public_inputs elements of witness
    /// (after the constant 1).
    pub fn extract_public_inputs(&self, witness: &[F]) -> Vec<F> {
        if witness.len() <= 1 {
            return vec![];
        }
        
        let end = (self.num_public_inputs + 1).min(witness.len());
        witness[1..end].to_vec()
    }
    
    /// Get private witness from full witness
    ///
    /// Private witness is everything after public inputs.
    pub fn extract_private_witness(&self, witness: &[F]) -> Vec<F> {
        let start = (self.num_public_inputs + 1).min(witness.len());
        witness[start..].to_vec()
    }
}

/// R1CS builder for constructing constraint systems
pub struct R1CSBuilder<F: Field> {
    /// A matrix entries
    a_entries: Vec<SparseEntry<F>>,
    
    /// B matrix entries
    b_entries: Vec<SparseEntry<F>>,
    
    /// C matrix entries
    c_entries: Vec<SparseEntry<F>>,
    
    /// Number of constraints added
    num_constraints: usize,
    
    /// Witness size
    witness_size: usize,
    
    /// Number of public inputs
    num_public_inputs: usize,
}

impl<F: Field> R1CSBuilder<F> {
    /// Create new R1CS builder
    ///
    /// # Arguments
    /// * `witness_size` - Size of witness vector
    /// * `num_public_inputs` - Number of public inputs
    pub fn new(witness_size: usize, num_public_inputs: usize) -> Self {
        Self {
            a_entries: Vec::new(),
            b_entries: Vec::new(),
            c_entries: Vec::new(),
            num_constraints: 0,
            witness_size,
            num_public_inputs,
        }
    }
    
    /// Add constraint: (a·z) · (b·z) = (c·z)
    ///
    /// # Arguments
    /// * `a_coeffs` - Coefficients for A row
    /// * `b_coeffs` - Coefficients for B row
    /// * `c_coeffs` - Coefficients for C row
    ///
    /// Each coefficient list is (column_index, value) pairs.
    pub fn add_constraint(
        &mut self,
        a_coeffs: Vec<(usize, F)>,
        b_coeffs: Vec<(usize, F)>,
        c_coeffs: Vec<(usize, F)>,
    ) -> Result<(), String> {
        let row = self.num_constraints;
        
        // Add A entries
        for (col, val) in a_coeffs {
            if col >= self.witness_size {
                return Err(format!("Column index {} out of bounds", col));
            }
            self.a_entries.push(SparseEntry::new(row, col, val));
        }
        
        // Add B entries
        for (col, val) in b_coeffs {
            if col >= self.witness_size {
                return Err(format!("Column index {} out of bounds", col));
            }
            self.b_entries.push(SparseEntry::new(row, col, val));
        }
        
        // Add C entries
        for (col, val) in c_coeffs {
            if col >= self.witness_size {
                return Err(format!("Column index {} out of bounds", col));
            }
            self.c_entries.push(SparseEntry::new(row, col, val));
        }
        
        self.num_constraints += 1;
        Ok(())
    }
    
    /// Add multiplication gate: c = a · b
    ///
    /// Witness layout: z = [1, ..., a, b, c, ...]
    ///
    /// # Arguments
    /// * `a_index` - Index of a in witness
    /// * `b_index` - Index of b in witness
    /// * `c_index` - Index of c in witness
    pub fn add_multiplication_gate(
        &mut self,
        a_index: usize,
        b_index: usize,
        c_index: usize,
    ) -> Result<(), String> {
        self.add_constraint(
            vec![(a_index, F::one())],
            vec![(b_index, F::one())],
            vec![(c_index, F::one())],
        )
    }
    
    /// Add addition gate: c = a + b
    ///
    /// Encoded as: (a + b) · 1 = c
    pub fn add_addition_gate(
        &mut self,
        a_index: usize,
        b_index: usize,
        c_index: usize,
    ) -> Result<(), String> {
        self.add_constraint(
            vec![(a_index, F::one()), (b_index, F::one())],
            vec![(0, F::one())], // Multiply by constant 1
            vec![(c_index, F::one())],
        )
    }
    
    /// Build R1CS instance
    pub fn build(self) -> Result<R1CS<F>, String> {
        let a_matrix = SparseMatrix::from_entries(
            self.num_constraints,
            self.witness_size,
            self.a_entries,
        )?;
        
        let b_matrix = SparseMatrix::from_entries(
            self.num_constraints,
            self.witness_size,
            self.b_entries,
        )?;
        
        let c_matrix = SparseMatrix::from_entries(
            self.num_constraints,
            self.witness_size,
            self.c_entries,
        )?;
        
        R1CS::new(a_matrix, b_matrix, c_matrix, self.num_public_inputs)
    }
}
