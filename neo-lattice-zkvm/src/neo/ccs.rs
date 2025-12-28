// CCS (Customizable Constraint System) Implementation
// Task 7.1: Implement CCS constraint system representation
//
// **Paper Reference**: Neo Section 2.1 "CCS Constraint System", Requirement 16.2
//
// **CCS Definition**:
// A CCS instance consists of:
// - Matrices M_1, ..., M_t ∈ F^{m×n} (sparse constraint matrices)
// - Selector sets S_1, ..., S_q ⊆ [t] (which matrices to multiply)
// - Coefficients c_1, ..., c_q ∈ F (linear combination weights)
// - Public input x ∈ F^ℓ
//
// **Constraint**:
// Σ_{i∈[q]} c_i · (Π_{j∈S_i} M_j · z) = 0
// where z = (x, w) ∈ F^n is the full witness (public + private)
//
// **Why CCS?**:
// CCS generalizes R1CS and Plonkish constraints, allowing:
// - Higher-degree constraints (products of multiple matrices)
// - More efficient representation of complex circuits
// - Better compatibility with folding schemes

use crate::field::Field;
use std::collections::HashMap;

/// Sparse matrix representation for efficient storage and computation
/// 
/// **Paper Reference**: Neo Section 2.1
/// 
/// **Sparsity Optimization**:
/// Most constraint matrices in zkVM circuits are extremely sparse
/// (< 1% non-zero entries). We store only non-zero entries as (row, col, value)
/// triples, reducing memory from O(m·n) to O(nnz) where nnz << m·n.
#[derive(Clone, Debug)]
pub struct SparseMatrix<F: Field> {
    /// Non-zero entries: (row, col) → value
    pub entries: HashMap<(usize, usize), F>,
    /// Number of rows
    pub rows: usize,
    /// Number of columns
    pub cols: usize,
    /// Number of non-zero entries (for cost tracking)
    pub nnz: usize,
}

impl<F: Field> SparseMatrix<F> {
    /// Create new sparse matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            entries: HashMap::new(),
            rows,
            cols,
            nnz: 0,
        }
    }
    
    /// Set entry at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.rows && col < self.cols, "Index out of bounds");
        
        if value.to_canonical_u64() != 0 {
            if self.entries.insert((row, col), value).is_none() {
                self.nnz += 1;
            }
        } else {
            if self.entries.remove(&(row, col)).is_some() {
                self.nnz -= 1;
            }
        }
    }
    
    /// Get entry at (row, col)
    pub fn get(&self, row: usize, col: usize) -> F {
        self.entries.get(&(row, col)).copied().unwrap_or(F::zero())
    }
    
    /// Matrix-vector multiplication: M·v
    /// 
    /// **Complexity**: O(nnz) where nnz is number of non-zero entries
    /// 
    /// For sparse matrices with nnz << m·n, this is much faster than
    /// dense multiplication which would be O(m·n).
    pub fn mul_vector(&self, v: &[F]) -> Vec<F> {
        assert_eq!(v.len(), self.cols, "Vector dimension mismatch");
        
        let mut result = vec![F::zero(); self.rows];
        
        for (&(row, col), &value) in &self.entries {
            result[row] = result[row].add(&value.mul(&v[col]));
        }
        
        result
    }
    
    /// Hadamard (element-wise) product: u ⊙ v
    /// 
    /// **Paper Reference**: Neo Section 2.1
    /// 
    /// Used in CCS constraints: (Π_{j∈S_i} M_j · z) is computed as
    /// a sequence of matrix-vector multiplications followed by Hadamard products.
    pub fn hadamard_product(u: &[F], v: &[F]) -> Vec<F> {
        assert_eq!(u.len(), v.len(), "Vector dimension mismatch");
        
        u.iter()
            .zip(v.iter())
            .map(|(a, b)| a.mul(b))
            .collect()
    }
    
    /// Get sparsity ratio: nnz / (rows * cols)
    pub fn sparsity(&self) -> f64 {
        self.nnz as f64 / (self.rows * self.cols) as f64
    }
    
    /// Create identity matrix
    pub fn identity(size: usize) -> Self {
        let mut matrix = Self::new(size, size);
        for i in 0..size {
            matrix.set(i, i, F::one());
        }
        matrix
    }
    
    /// Create zero matrix
    pub fn zero(rows: usize, cols: usize) -> Self {
        Self::new(rows, cols)
    }
}

/// Selector set S_i ⊆ [t]
/// 
/// **Paper Reference**: Neo Section 2.1
/// 
/// Each selector set specifies which matrices to multiply together.
/// For example, S_i = {1, 3, 5} means compute M_1·z ⊙ M_3·z ⊙ M_5·z.
#[derive(Clone, Debug)]
pub struct SelectorSet {
    /// Indices of matrices to multiply
    pub indices: Vec<usize>,
}

impl SelectorSet {
    /// Create new selector set
    pub fn new(indices: Vec<usize>) -> Self {
        Self { indices }
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
    
    /// Get degree (number of matrices to multiply)
    pub fn degree(&self) -> usize {
        self.indices.len()
    }
}

/// CCS Instance: Public parameters and constraints
/// 
/// **Paper Reference**: Neo Section 2.1, Requirement 16.2
/// 
/// **Structure**:
/// - m: number of constraints
/// - n: total witness size (public + private)
/// - ℓ: public input size
/// - t: number of matrices
/// - q: number of selector sets
/// - M_1, ..., M_t: constraint matrices
/// - S_1, ..., S_q: selector sets
/// - c_1, ..., c_q: coefficients
/// - x: public input
/// 
/// **Constraint**:
/// Σ_{i∈[q]} c_i · (Π_{j∈S_i} M_j · z) = 0 mod F
/// where z = (x, w) is the full witness
#[derive(Clone, Debug)]
pub struct CCSInstance<F: Field> {
    /// Number of constraints
    pub m: usize,
    /// Total witness size (public + private)
    pub n: usize,
    /// Public input size
    pub ell: usize,
    /// Number of matrices
    pub t: usize,
    /// Number of selector sets
    pub q: usize,
    /// Constraint matrices M_1, ..., M_t
    pub matrices: Vec<SparseMatrix<F>>,
    /// Selector sets S_1, ..., S_q
    pub selectors: Vec<SelectorSet>,
    /// Coefficients c_1, ..., c_q
    pub coefficients: Vec<F>,
    /// Public input x ∈ F^ℓ
    pub public_input: Vec<F>,
}

impl<F: Field> CCSInstance<F> {
    /// Create new CCS instance
    pub fn new(
        m: usize,
        n: usize,
        ell: usize,
        matrices: Vec<SparseMatrix<F>>,
        selectors: Vec<SelectorSet>,
        coefficients: Vec<F>,
        public_input: Vec<F>,
    ) -> Result<Self, String> {
        let t = matrices.len();
        let q = selectors.len();
        
        // Validation
        if coefficients.len() != q {
            return Err("Number of coefficients must match number of selectors".to_string());
        }
        
        if public_input.len() != ell {
            return Err("Public input size mismatch".to_string());
        }
        
        for matrix in &matrices {
            if matrix.rows != m || matrix.cols != n {
                return Err("Matrix dimensions must be m×n".to_string());
            }
        }
        
        for selector in &selectors {
            for &idx in &selector.indices {
                if idx >= t {
                    return Err("Selector index out of bounds".to_string());
                }
            }
        }
        
        Ok(Self {
            m,
            n,
            ell,
            t,
            q,
            matrices,
            selectors,
            coefficients,
            public_input,
        })
    }
    
    /// Verify CCS constraint: Σ_{i∈[q]} c_i · (Π_{j∈S_i} M_j · z) = 0
    /// 
    /// **Paper Reference**: Neo Section 2.1
    /// 
    /// **Algorithm**:
    /// 1. For each selector set S_i:
    ///    a. Compute M_j·z for each j ∈ S_i
    ///    b. Compute Hadamard product: v_i = ⊙_{j∈S_i} (M_j·z)
    /// 2. Compute linear combination: Σ_i c_i·v_i
    /// 3. Check if result is zero vector
    /// 
    /// **Complexity**: O(q·d·nnz) where d is max selector degree
    pub fn verify(&self, witness: &CCSWitness<F>) -> bool {
        // Construct full witness z = (x, w)
        let z = self.construct_full_witness(witness);
        
        if z.len() != self.n {
            return false;
        }
        
        // Accumulator for linear combination
        let mut result = vec![F::zero(); self.m];
        
        // For each selector set
        for i in 0..self.q {
            let selector = &self.selectors[i];
            let coeff = &self.coefficients[i];
            
            if selector.is_empty() {
                continue;
            }
            
            // Compute product term: Π_{j∈S_i} M_j·z
            let mut product = vec![F::one(); self.m];
            
            for &j in &selector.indices {
                let mj_z = self.matrices[j].mul_vector(&z);
                product = SparseMatrix::hadamard_product(&product, &mj_z);
            }
            
            // Add c_i · product to result
            for k in 0..self.m {
                result[k] = result[k].add(&coeff.mul(&product[k]));
            }
        }
        
        // Check if result is zero
        result.iter().all(|&v| v.to_canonical_u64() == 0)
    }
    
    /// Construct full witness z = (x, w) from public input and private witness
    fn construct_full_witness(&self, witness: &CCSWitness<F>) -> Vec<F> {
        let mut z = Vec::with_capacity(self.n);
        z.extend_from_slice(&self.public_input);
        z.extend_from_slice(&witness.witness);
        z
    }
    
    /// Check if instance is satisfiable (for testing)
    pub fn is_satisfiable(&self, witness: &CCSWitness<F>) -> bool {
        self.verify(witness)
    }
}

/// CCS Witness: Private witness vector
/// 
/// **Paper Reference**: Neo Section 2.1
/// 
/// The witness w ∈ F^{n-ℓ} is the private part of the full witness z = (x, w).
/// Combined with public input x, it should satisfy the CCS constraints.
#[derive(Clone, Debug)]
pub struct CCSWitness<F: Field> {
    /// Private witness vector w ∈ F^{n-ℓ}
    pub witness: Vec<F>,
}

impl<F: Field> CCSWitness<F> {
    /// Create new CCS witness
    pub fn new(witness: Vec<F>) -> Self {
        Self { witness }
    }
    
    /// Get witness size
    pub fn size(&self) -> usize {
        self.witness.len()
    }
}

/// Complete CCS constraint system with instance and witness
/// 
/// **Paper Reference**: Neo Section 2.1
/// 
/// This bundles the CCS instance (public) with its witness (private)
/// for convenience in proving operations.
#[derive(Clone, Debug)]
pub struct CCSConstraintSystem<F: Field> {
    /// CCS instance (public)
    pub instance: CCSInstance<F>,
    /// CCS witness (private)
    pub witness: CCSWitness<F>,
}

impl<F: Field> CCSConstraintSystem<F> {
    /// Create new CCS constraint system
    pub fn new(instance: CCSInstance<F>, witness: CCSWitness<F>) -> Result<Self, String> {
        // Verify dimensions
        if instance.n != instance.ell + witness.size() {
            return Err("Witness size mismatch: n ≠ ℓ + |w|".to_string());
        }
        
        Ok(Self { instance, witness })
    }
    
    /// Verify constraint satisfaction
    pub fn verify(&self) -> bool {
        self.instance.verify(&self.witness)
    }
    
    /// Convert R1CS to CCS
    /// 
    /// **Paper Reference**: Neo Section 2.1
    /// 
    /// **R1CS**: Az ⊙ Bz = Cz
    /// **CCS Encoding**:
    /// - t = 3 matrices: M_1 = A, M_2 = B, M_3 = C
    /// - q = 2 selector sets: S_1 = {1, 2}, S_2 = {3}
    /// - Coefficients: c_1 = 1, c_2 = -1
    /// - Constraint: (M_1·z) ⊙ (M_2·z) - M_3·z = 0
    pub fn from_r1cs(
        a: SparseMatrix<F>,
        b: SparseMatrix<F>,
        c: SparseMatrix<F>,
        public_input: Vec<F>,
        witness: Vec<F>,
    ) -> Result<Self, String> {
        let m = a.rows;
        let n = a.cols;
        let ell = public_input.len();
        
        // Verify dimensions
        if b.rows != m || b.cols != n || c.rows != m || c.cols != n {
            return Err("R1CS matrix dimensions must match".to_string());
        }
        
        // Create CCS instance
        let matrices = vec![a, b, c];
        let selectors = vec![
            SelectorSet::new(vec![0, 1]), // S_1 = {A, B}
            SelectorSet::new(vec![2]),     // S_2 = {C}
        ];
        let coefficients = vec![F::one(), F::one().neg()]; // [1, -1]
        
        let instance = CCSInstance::new(
            m,
            n,
            ell,
            matrices,
            selectors,
            coefficients,
            public_input,
        )?;
        
        let witness = CCSWitness::new(witness);
        
        Self::new(instance, witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_sparse_matrix_creation() {
        let mut matrix = SparseMatrix::<F>::new(3, 3);
        matrix.set(0, 0, F::from_u64(1));
        matrix.set(1, 1, F::from_u64(2));
        matrix.set(2, 2, F::from_u64(3));
        
        assert_eq!(matrix.nnz, 3);
        assert_eq!(matrix.get(0, 0).to_canonical_u64(), 1);
        assert_eq!(matrix.get(1, 1).to_canonical_u64(), 2);
        assert_eq!(matrix.get(2, 2).to_canonical_u64(), 3);
    }
    
    #[test]
    fn test_sparse_matrix_mul_vector() {
        let mut matrix = SparseMatrix::<F>::new(2, 2);
        matrix.set(0, 0, F::from_u64(2));
        matrix.set(0, 1, F::from_u64(3));
        matrix.set(1, 0, F::from_u64(4));
        matrix.set(1, 1, F::from_u64(5));
        
        let v = vec![F::from_u64(1), F::from_u64(2)];
        let result = matrix.mul_vector(&v);
        
        // [2 3] [1]   [2*1 + 3*2]   [8]
        // [4 5] [2] = [4*1 + 5*2] = [14]
        assert_eq!(result[0].to_canonical_u64(), 8);
        assert_eq!(result[1].to_canonical_u64(), 14);
    }
    
    #[test]
    fn test_hadamard_product() {
        let u = vec![F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let v = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7)];
        
        let result = SparseMatrix::<F>::hadamard_product(&u, &v);
        
        assert_eq!(result[0].to_canonical_u64(), 10); // 2*5
        assert_eq!(result[1].to_canonical_u64(), 18); // 3*6
        assert_eq!(result[2].to_canonical_u64(), 28); // 4*7
    }
    
    #[test]
    fn test_ccs_instance_creation() {
        let m = 2;
        let n = 3;
        let ell = 1;
        
        let mut matrix = SparseMatrix::new(m, n);
        matrix.set(0, 0, F::one());
        matrix.set(1, 1, F::one());
        
        let matrices = vec![matrix];
        let selectors = vec![SelectorSet::new(vec![0])];
        let coefficients = vec![F::one()];
        let public_input = vec![F::from_u64(5)];
        
        let instance = CCSInstance::new(
            m,
            n,
            ell,
            matrices,
            selectors,
            coefficients,
            public_input,
        );
        
        assert!(instance.is_ok());
        let inst = instance.unwrap();
        assert_eq!(inst.m, 2);
        assert_eq!(inst.n, 3);
        assert_eq!(inst.t, 1);
        assert_eq!(inst.q, 1);
    }
    
    #[test]
    fn test_r1cs_to_ccs_conversion() {
        // Simple R1CS: x * w = y
        // A = [1 0], B = [0 1], C = [0 0]
        //     [0 0]      [0 0]      [1 0]
        // z = [x, w, y]
        
        let mut a = SparseMatrix::new(2, 3);
        a.set(0, 0, F::one());
        
        let mut b = SparseMatrix::new(2, 3);
        b.set(0, 1, F::one());
        
        let mut c = SparseMatrix::new(2, 3);
        c.set(1, 0, F::one());
        
        let public_input = vec![F::from_u64(3)]; // x = 3
        let witness = vec![F::from_u64(4), F::from_u64(12)]; // w = 4, y = 12
        
        let ccs = CCSConstraintSystem::from_r1cs(
            a,
            b,
            c,
            public_input,
            witness,
        );
        
        assert!(ccs.is_ok());
    }
}
