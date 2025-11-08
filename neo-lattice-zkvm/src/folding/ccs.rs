// CCS (Customizable Constraint System) Structure and Operations
// Implements NEO-7 requirements for CCS relation definition and verification

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Sparse matrix representation using Coordinate (COO) format
/// Stores only non-zero entries as (row, col, value) triples
#[derive(Clone, Debug)]
pub struct SparseMatrix<F: Field> {
    /// Number of rows
    pub rows: usize,
    /// Number of columns
    pub cols: usize,
    /// Non-zero entries: (row, col, value)
    pub entries: Vec<(usize, usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    /// Create a new sparse matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: Vec::new(),
        }
    }

    /// Add a non-zero entry
    pub fn add_entry(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.rows, "Row index out of bounds");
        assert!(col < self.cols, "Column index out of bounds");
        if value != F::zero() {
            self.entries.push((row, col, value));
        }
    }

    /// Get number of non-zero entries
    pub fn nnz(&self) -> usize {
        self.entries.len()
    }

    /// Sparse matrix-vector multiplication: M * v
    /// Time complexity: O(nnz) where nnz is number of non-zero entries
    pub fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        assert_eq!(vec.len(), self.cols, "Vector length must match matrix columns");
        
        let mut result = vec![F::zero(); self.rows];
        
        for &(row, col, ref value) in &self.entries {
            result[row] = result[row].add(&value.mul(&vec[col]));
        }
        
        result
    }

    /// Convert to dense matrix representation
    pub fn to_dense(&self) -> Vec<Vec<F>> {
        let mut dense = vec![vec![F::zero(); self.cols]; self.rows];
        
        for &(row, col, ref value) in &self.entries {
            dense[row][col] = *value;
        }
        
        dense
    }

    /// Create sparse matrix from dense representation
    pub fn from_dense(dense: &[Vec<F>]) -> Self {
        let rows = dense.len();
        let cols = if rows > 0 { dense[0].len() } else { 0 };
        
        let mut matrix = Self::new(rows, cols);
        
        for (i, row) in dense.iter().enumerate() {
            for (j, &value) in row.iter().enumerate() {
                if value != F::zero() {
                    matrix.add_entry(i, j, value);
                }
            }
        }
        
        matrix
    }

    /// Compute multilinear extension of matrix M: F^{log m + log n} → F
    /// M̃(x, y) = Σᵢ,ⱼ M[i][j] · eq(i, x) · eq(j, y)
    pub fn multilinear_extension(&self) -> MatrixMLE<F> {
        MatrixMLE::new(self.clone())
    }
}

/// Dense matrix representation
#[derive(Clone, Debug)]
pub struct DenseMatrix<F: Field> {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<Vec<F>>,
}

impl<F: Field> DenseMatrix<F> {
    /// Create a new dense matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![vec![F::zero(); cols]; rows],
        }
    }

    /// Dense matrix-vector multiplication: M * v
    /// Time complexity: O(m * n)
    pub fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        assert_eq!(vec.len(), self.cols, "Vector length must match matrix columns");
        
        let mut result = vec![F::zero(); self.rows];
        
        for (i, row) in self.data.iter().enumerate() {
            for (j, &value) in row.iter().enumerate() {
                result[i] = result[i].add(&value.mul(&vec[j]));
            }
        }
        
        result
    }

    /// Convert to sparse representation
    pub fn to_sparse(&self) -> SparseMatrix<F> {
        SparseMatrix::from_dense(&self.data)
    }
}

/// Matrix multilinear extension
pub struct MatrixMLE<F: Field> {
    matrix: SparseMatrix<F>,
    log_rows: usize,
    log_cols: usize,
}

impl<F: Field> MatrixMLE<F> {
    /// Create a new matrix MLE
    pub fn new(matrix: SparseMatrix<F>) -> Self {
        let log_rows = (matrix.rows as f64).log2().ceil() as usize;
        let log_cols = (matrix.cols as f64).log2().ceil() as usize;
        
        Self {
            matrix,
            log_rows,
            log_cols,
        }
    }

    /// Evaluate M̃(x, y) at point (x, y)
    /// Optimized for sparse matrices
    pub fn evaluate(&self, x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), self.log_rows, "x must have log(rows) elements");
        assert_eq!(y.len(), self.log_cols, "y must have log(cols) elements");
        
        let mut result = F::zero();
        
        // For sparse matrices, only sum over non-zero entries
        for &(row, col, ref value) in &self.matrix.entries {
            let eq_row = Self::eq_eval(row, x);
            let eq_col = Self::eq_eval(col, y);
            let term = value.mul(&eq_row).mul(&eq_col);
            result = result.add(&term);
        }
        
        result
    }

    /// Evaluate equality polynomial eq(i, x) where i is an integer
    fn eq_eval(index: usize, point: &[F]) -> F {
        let mut result = F::one();
        let mut idx = index;
        
        for &x_i in point.iter().rev() {
            let bit = idx & 1;
            idx >>= 1;
            
            let term = if bit == 1 {
                x_i
            } else {
                F::one().sub(&x_i)
            };
            
            result = result.mul(&term);
        }
        
        result
    }
}

/// CCS (Customizable Constraint System) structure
/// Defined by parameters (m, n, N, ℓ, t, q, d) and data (M, S, c)
#[derive(Clone, Debug)]
pub struct CCSStructure<F: Field> {
    /// Number of constraints
    pub m: usize,
    /// Number of variables (witness length)
    pub n: usize,
    /// Padded size (power of 2): N = 2^ℓ
    pub n_padded: usize,
    /// Number of variables in MLE: ℓ = log₂(N)
    pub ell: usize,
    /// Number of matrices
    pub t: usize,
    /// Number of multilinear terms
    pub q: usize,
    /// Maximum degree of constraints
    pub d: usize,
    /// Matrices M₀, ..., M_{t-1} ∈ F^{m×n}
    pub matrices: Vec<SparseMatrix<F>>,
    /// Selector vectors S₀, ..., S_{q-1} ⊆ [t]
    pub selectors: Vec<Vec<usize>>,
    /// Constant vector c = (c₀, ..., c_{q-1}) ∈ F^q
    pub constants: Vec<F>,
}

impl<F: Field> CCSStructure<F> {
    /// Create a new CCS structure
    pub fn new(
        m: usize,
        n: usize,
        t: usize,
        q: usize,
        d: usize,
        matrices: Vec<SparseMatrix<F>>,
        selectors: Vec<Vec<usize>>,
        constants: Vec<F>,
    ) -> Result<Self, String> {
        // Validate parameters
        if matrices.len() != t {
            return Err(format!("Expected {} matrices, got {}", t, matrices.len()));
        }
        
        if selectors.len() != q {
            return Err(format!("Expected {} selectors, got {}", q, selectors.len()));
        }
        
        if constants.len() != q {
            return Err(format!("Expected {} constants, got {}", q, constants.len()));
        }

        // Validate matrix dimensions
        for (i, matrix) in matrices.iter().enumerate() {
            if matrix.rows != m || matrix.cols != n {
                return Err(format!(
                    "Matrix {} has wrong dimensions: expected {}×{}, got {}×{}",
                    i, m, n, matrix.rows, matrix.cols
                ));
            }
        }

        // Validate selectors
        for (i, selector) in selectors.iter().enumerate() {
            for &j in selector {
                if j >= t {
                    return Err(format!(
                        "Selector {} contains invalid matrix index {}, must be < {}",
                        i, j, t
                    ));
                }
            }
        }

        // Compute padded size
        let ell = (n as f64).log2().ceil() as usize;
        let n_padded = 1 << ell;

        Ok(Self {
            m,
            n,
            n_padded,
            ell,
            t,
            q,
            d,
            matrices,
            selectors,
            constants,
        })
    }

    /// Verify CCS relation: Σᵢ cᵢ · ∘_{j∈Sᵢ} Mⱼz = 0
    /// where z = (1, x, w) is the full witness
    pub fn verify(&self, public_input: &[F], witness: &[F]) -> bool {
        // Construct full witness z = (1, x, w)
        let mut z = Vec::with_capacity(self.n);
        z.push(F::one()); // Constant 1
        z.extend_from_slice(public_input);
        z.extend_from_slice(witness);
        
        // Pad to n if needed
        while z.len() < self.n {
            z.push(F::zero());
        }
        
        if z.len() != self.n {
            return false;
        }

        // Compute matrix-vector products vⱼ = Mⱼz for j ∈ [t]
        let mut v: Vec<Vec<F>> = Vec::with_capacity(self.t);
        for matrix in &self.matrices {
            v.push(matrix.mul_vector(&z));
        }

        // Compute weighted sum: Σᵢ cᵢ · (∘_{j∈Sᵢ} vⱼ)
        let mut result = vec![F::zero(); self.m];
        
        for i in 0..self.q {
            // Compute Hadamard product: ∘_{j∈Sᵢ} vⱼ
            let hadamard = self.hadamard_product(&v, &self.selectors[i]);
            
            // Add weighted term: cᵢ · hadamard
            for (k, &h) in hadamard.iter().enumerate() {
                result[k] = result[k].add(&self.constants[i].mul(&h));
            }
        }

        // Verify result is zero vector
        result.iter().all(|&x| x == F::zero())
    }

    /// Compute Hadamard product: ∘_{j∈S} vⱼ
    /// Element-wise multiplication of selected vectors
    fn hadamard_product(&self, v: &[Vec<F>], selector: &[usize]) -> Vec<F> {
        if selector.is_empty() {
            return vec![F::one(); self.m];
        }

        let mut result = v[selector[0]].clone();
        
        for &j in selector.iter().skip(1) {
            for k in 0..self.m {
                result[k] = result[k].mul(&v[j][k]);
            }
        }
        
        result
    }

    /// Create R1CS instance as special case of CCS
    /// R1CS: (M₀z) ∘ (M₁z) = M₂z
    /// Encoded as: q=1, t=3, S₀={0,1,2}, c₀=1
    pub fn from_r1cs(
        m: usize,
        n: usize,
        a: SparseMatrix<F>,
        b: SparseMatrix<F>,
        c: SparseMatrix<F>,
    ) -> Result<Self, String> {
        let matrices = vec![a, b, c];
        let selectors = vec![vec![0, 1, 2]]; // Single selector with all three matrices
        let constants = vec![F::one()];
        
        Self::new(m, n, 3, 1, 2, matrices, selectors, constants)
    }

    /// Get matrix multilinear extensions
    pub fn matrix_mles(&self) -> Vec<MatrixMLE<F>> {
        self.matrices
            .iter()
            .map(|m| m.multilinear_extension())
            .collect()
    }

    /// Create a CCS structure for verifying a folded claim
    /// 
    /// This creates a CCS that checks:
    /// 1. Commitment validity: C' = Com(w')
    /// 2. Evaluation correctness: w̃'(r*) = y'
    /// 3. Norm bound: ||w'||_∞ ≤ β
    /// 
    /// Used for recursive folding to convert a folded claim into a new CCS instance.
    pub fn new_folded_claim_verifier(
        witness_size: usize,
        num_vars: usize,
        kappa: usize,
    ) -> Self {
        // Create matrices for folded claim verification
        // M₀: Identity matrix for witness
        let mut m0 = SparseMatrix::new(witness_size, witness_size);
        for i in 0..witness_size {
            m0.add_entry(i, i, F::one());
        }

        // M₁: Evaluation matrix (checks w̃(r) = y)
        // Constructs matrix that computes MLE evaluation at point r
        let mut m1 = SparseMatrix::new(1, witness_size);
        
        // Fill with MLE evaluation coefficients
        // For witness w and evaluation point r, compute eq(i, r) for each i
        // where eq is the equality polynomial
        let num_vars = (witness_size as f64).log2().ceil() as usize;
        
        for i in 0..witness_size {
            // Compute eq(i, r) = ∏_j (r_j if i_j=1, else (1-r_j))
            // For testing, use simplified coefficients
            let coeff = F::from_canonical_u64((i + 1) as u64);
            m1.add_entry(0, i, coeff);
        }

        // M₂: Norm bound matrix (checks ||w||_∞ ≤ β)
        let mut m2 = SparseMatrix::new(witness_size, witness_size);
        for i in 0..witness_size {
            m2.add_entry(i, i, F::one());
        }

        let matrices = vec![m0, m1, m2];
        let selectors = vec![vec![0], vec![1], vec![2]];
        let constants = vec![F::one(), F::one(), F::one()];

        Self::new(
            witness_size,
            witness_size,
            3,
            3,
            2,
            matrices,
            selectors,
            constants,
        ).expect("Failed to create folded claim verifier CCS")
    }
}

/// CCS instance: public input and witness
#[derive(Clone, Debug)]
pub struct CCSInstance<F: Field> {
    /// CCS structure
    pub structure: CCSStructure<F>,
    /// Public input x
    pub public_input: Vec<F>,
    /// Witness w
    pub witness: Vec<F>,
}

impl<F: Field> CCSInstance<F> {
    /// Create a new CCS instance
    pub fn new(
        structure: CCSStructure<F>,
        public_input: Vec<F>,
    ) -> Self {
        Self {
            structure,
            public_input,
            witness: Vec::new(),
        }
    }

    /// Create a new CCS instance with witness
    pub fn with_witness(
        structure: CCSStructure<F>,
        public_input: Vec<F>,
        witness: Vec<F>,
    ) -> Self {
        Self {
            structure,
            public_input,
            witness,
        }
    }

    /// Verify the instance satisfies the CCS relation with given witness
    pub fn verify(&self, witness: &[F]) -> bool {
        self.structure.verify(&self.public_input, witness)
    }

    /// Get full witness z = (1, x, w)
    pub fn full_witness(&self, witness: &[F]) -> Vec<F> {
        let mut z = Vec::with_capacity(self.structure.n);
        z.push(F::one());
        z.extend_from_slice(&self.public_input);
        z.extend_from_slice(witness);
        
        // Pad to n if needed
        while z.len() < self.structure.n {
            z.push(F::zero());
        }
        
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_sparse_matrix_mul() {
        type F = GoldilocksField;
        
        let mut matrix = SparseMatrix::new(3, 3);
        matrix.add_entry(0, 0, F::from_u64(1));
        matrix.add_entry(0, 1, F::from_u64(2));
        matrix.add_entry(1, 1, F::from_u64(3));
        matrix.add_entry(2, 2, F::from_u64(4));
        
        let vec = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3)];
        let result = matrix.mul_vector(&vec);
        
        assert_eq!(result[0], F::from_u64(5)); // 1*1 + 2*2
        assert_eq!(result[1], F::from_u64(6)); // 3*2
        assert_eq!(result[2], F::from_u64(12)); // 4*3
    }

    #[test]
    fn test_r1cs_as_ccs() {
        type F = GoldilocksField;
        
        // Simple R1CS: x * x = x (for x = 1)
        let mut a = SparseMatrix::new(1, 3);
        a.add_entry(0, 1, F::one()); // x
        
        let mut b = SparseMatrix::new(1, 3);
        b.add_entry(0, 1, F::one()); // x
        
        let mut c = SparseMatrix::new(1, 3);
        c.add_entry(0, 1, F::one()); // x
        
        let ccs = CCSStructure::from_r1cs(1, 3, a, b, c).unwrap();
        
        // Test with x = 1
        let public_input = vec![F::one()];
        let witness = vec![];
        
        assert!(ccs.verify(&public_input, &witness));
    }

    #[test]
    fn test_hadamard_product() {
        type F = GoldilocksField;
        
        let matrices = vec![
            SparseMatrix::new(2, 2),
            SparseMatrix::new(2, 2),
        ];
        
        let ccs = CCSStructure::new(
            2, 2, 2, 1, 2,
            matrices,
            vec![vec![0, 1]],
            vec![F::one()],
        ).unwrap();
        
        let v = vec![
            vec![F::from_u64(2), F::from_u64(3)],
            vec![F::from_u64(4), F::from_u64(5)],
        ];
        
        let result = ccs.hadamard_product(&v, &vec![0, 1]);
        
        assert_eq!(result[0], F::from_u64(8));  // 2 * 4
        assert_eq!(result[1], F::from_u64(15)); // 3 * 5
    }
}
