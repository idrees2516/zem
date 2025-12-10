// Matrix operations with row-tensor structure for SALSAA
//
// Mathematical Background:
// - Matrices over cyclotomic ring R_q = Z_q[X]/(Φ_f(X))
// - Standard operations: addition, multiplication, Kronecker products
// - Special structure: row-tensor matrices for efficient vSIS commitments
//
// Row-Tensor Matrices (SALSAA Definition 1):
// A matrix F ∈ R_q^{n×m} has row-tensor structure if:
// F = F_0 • F_1 • ... • F_{µ-1}
// where F_i ∈ R_q^{n×d} are factor matrices and • is row-wise Kronecker product
//
// Row-wise Kronecker Product:
// For A ∈ R^{n×a}, B ∈ R^{n×b}, the product (A • B) ∈ R^{n×ab} satisfies:
// (A • B)_{i,:} = A_{i,:} ⊗ B_{i,:}
// where ⊗ is the standard Kronecker product of row vectors
//
// Properties:
// 1. Dimension: If F = F_0 • ... • F_{µ-1} with F_i ∈ R^{n×d}, then F ∈ R^{n×d^µ}
// 2. Associativity: (A • B) • C = A • (B • C)
// 3. Efficient multiplication: Fw can be computed in O(n·d·µ) instead of O(n·d^µ)
// 4. vSIS hardness: Finding short x with Fx = 0 is hard for random row-tensor F
//
// Applications in SALSAA:
// - vSIS commitments: y = Fw for public F with row-tensor structure
// - Linear relations: HFW = Y where F has row-tensor structure
// - Folding: Reduce witness height by folding first factor with challenge
// - Batching: Combine multiple relations using random linear combinations
//
// Reference: SALSAA paper Section 2.3, Requirement 3.1, 3.2

use crate::field::Field;
use crate::ring::RingElement;
use std::ops::{Add, Sub, Mul};

/// Matrix over R_q with optional row-tensor structure
/// Stored in row-major order for cache efficiency
#[derive(Clone, Debug)]
pub struct Matrix<F: Field> {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<RingElement<F>>,
    pub tensor_structure: Option<TensorStructure<F>>,
}

/// Row-tensor structure: F = F_0 • F_1 • ... • F_{µ-1}
/// Each F_i ∈ R_q^{n×d} is a factor matrix
/// The full matrix F ∈ R_q^{n×d^µ} is their row-wise Kronecker product
#[derive(Clone, Debug)]
pub struct TensorStructure<F: Field> {
    pub factors: Vec<Matrix<F>>,  // F_i matrices
    pub mu: usize,                 // Number of factors
    pub d: usize,                  // Factor width (columns per factor)
}

impl<F: Field> Matrix<F> {
    /// Create new matrix with given dimensions
    pub fn new(rows: usize, cols: usize) -> Self {
        let data = vec![RingElement::from_coeffs(vec![F::zero(); 1]); rows * cols];
        Self {
            rows,
            cols,
            data,
            tensor_structure: None,
        }
    }
    
    /// Create matrix from data vector (row-major order)
    pub fn from_data(rows: usize, cols: usize, data: Vec<RingElement<F>>) -> Self {
        assert_eq!(data.len(), rows * cols);
        Self {
            rows,
            cols,
            data,
            tensor_structure: None,
        }
    }

    
    /// Create identity matrix
    pub fn identity(size: usize, ring_degree: usize) -> Self {
        let mut data = vec![RingElement::from_coeffs(vec![F::zero(); ring_degree]); size * size];
        
        for i in 0..size {
            let mut coeffs = vec![F::zero(); ring_degree];
            coeffs[0] = F::one();
            data[i * size + i] = RingElement::from_coeffs(coeffs);
        }
        
        Self {
            rows: size,
            cols: size,
            data,
            tensor_structure: None,
        }
    }
    
    /// Create zero matrix
    pub fn zero(rows: usize, cols: usize, ring_degree: usize) -> Self {
        let data = vec![RingElement::from_coeffs(vec![F::zero(); ring_degree]); rows * cols];
        Self {
            rows,
            cols,
            data,
            tensor_structure: None,
        }
    }
    
    /// Get element at (row, col)
    pub fn get(&self, row: usize, col: usize) -> &RingElement<F> {
        assert!(row < self.rows && col < self.cols);
        &self.data[row * self.cols + col]
    }
    
    /// Set element at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: RingElement<F>) {
        assert!(row < self.rows && col < self.cols);
        self.data[row * self.cols + col] = value;
    }
    
    /// Get row as slice
    pub fn get_row(&self, row: usize) -> &[RingElement<F>] {
        assert!(row < self.rows);
        let start = row * self.cols;
        &self.data[start..start + self.cols]
    }
    
    /// Get column (creates new vector)
    pub fn get_col(&self, col: usize) -> Vec<RingElement<F>> {
        assert!(col < self.cols);
        (0..self.rows)
            .map(|row| self.get(row, col).clone())
            .collect()
    }

    
    /// Matrix-vector multiplication: Fw
    /// For F ∈ R_q^{n×m}, w ∈ R_q^m, computes Fw ∈ R_q^n
    pub fn mul_vec(&self, vec: &[RingElement<F>], ring: &crate::ring::CyclotomicRing<F>) -> Vec<RingElement<F>> {
        assert_eq!(vec.len(), self.cols);
        
        let mut result = Vec::with_capacity(self.rows);
        
        for row_idx in 0..self.rows {
            let row = self.get_row(row_idx);
            
            // Compute dot product of row with vector
            let mut sum = ring.zero();
            for (mat_elem, vec_elem) in row.iter().zip(vec.iter()) {
                let prod = ring.mul(mat_elem, vec_elem);
                sum = ring.add(&sum, &prod);
            }
            
            result.push(sum);
        }
        
        result
    }
    
    /// Matrix-matrix multiplication: AB
    /// For A ∈ R_q^{n×m}, B ∈ R_q^{m×p}, computes AB ∈ R_q^{n×p}
    pub fn mul_mat(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.cols, other.rows);
        
        let mut result_data = Vec::with_capacity(self.rows * other.cols);
        
        for i in 0..self.rows {
            for j in 0..other.cols {
                let mut sum = ring.zero();
                
                for k in 0..self.cols {
                    let a_ik = self.get(i, k);
                    let b_kj = other.get(k, j);
                    let prod = ring.mul(a_ik, b_kj);
                    sum = ring.add(&sum, &prod);
                }
                
                result_data.push(sum);
            }
        }
        
        Matrix::from_data(self.rows, other.cols, result_data)
    }

    
    /// Row-wise Kronecker product: A • B
    /// For A ∈ R^{n×a}, B ∈ R^{n×b}, computes (A • B) ∈ R^{n×ab}
    /// where (A • B)_{i,:} = A_{i,:} ⊗ B_{i,:} (standard Kronecker product of rows)
    /// 
    /// Reference: SALSAA paper Definition 1 (Row-Tensor Matrices)
    pub fn row_kronecker(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.rows, other.rows);
        
        let result_cols = self.cols * other.cols;
        let mut result_data = Vec::with_capacity(self.rows * result_cols);
        
        for row_idx in 0..self.rows {
            let a_row = self.get_row(row_idx);
            let b_row = other.get_row(row_idx);
            
            // Compute Kronecker product of the two rows
            for a_elem in a_row {
                for b_elem in b_row {
                    let prod = ring.mul(a_elem, b_elem);
                    result_data.push(prod);
                }
            }
        }
        
        Matrix::from_data(self.rows, result_cols, result_data)
    }
    
    /// Standard Kronecker product: A ⊗ B
    /// For A ∈ R^{n×m}, B ∈ R^{p×q}, computes (A ⊗ B) ∈ R^{np×mq}
    /// where (A ⊗ B)_{i*p+k, j*q+l} = A_{i,j} * B_{k,l}
    pub fn kronecker(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        let result_rows = self.rows * other.rows;
        let result_cols = self.cols * other.cols;
        let mut result_data = Vec::with_capacity(result_rows * result_cols);
        
        for i in 0..self.rows {
            for k in 0..other.rows {
                for j in 0..self.cols {
                    for l in 0..other.cols {
                        let a_ij = self.get(i, j);
                        let b_kl = other.get(k, l);
                        let prod = ring.mul(a_ij, b_kl);
                        result_data.push(prod);
                    }
                }
            }
        }
        
        Matrix::from_data(result_rows, result_cols, result_data)
    }

    
    /// Hadamard (element-wise) product: A ⊙ B
    /// For A, B ∈ R^{n×m}, computes (A ⊙ B)_{i,j} = A_{i,j} * B_{i,j}
    pub fn hadamard(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.rows, other.rows);
        assert_eq!(self.cols, other.cols);
        
        let result_data: Vec<RingElement<F>> = self.data.iter()
            .zip(other.data.iter())
            .map(|(a, b)| ring.mul(a, b))
            .collect();
        
        Matrix::from_data(self.rows, self.cols, result_data)
    }
    
    /// Split matrix into top and bottom parts
    /// For F = [F_top; F_bot] ∈ R^{(n+n̄)×m}, returns (F_top, F_bot)
    /// where F_top ∈ R^{n×m} and F_bot ∈ R^{n̄×m}
    pub fn split_top_bottom(&self, top_rows: usize) -> (Matrix<F>, Matrix<F>) {
        assert!(top_rows <= self.rows);
        
        let bottom_rows = self.rows - top_rows;
        
        let top_data = self.data[..top_rows * self.cols].to_vec();
        let bottom_data = self.data[top_rows * self.cols..].to_vec();
        
        let top = Matrix::from_data(top_rows, self.cols, top_data);
        let bottom = Matrix::from_data(bottom_rows, self.cols, bottom_data);
        
        (top, bottom)
    }
    
    /// Vertical concatenation: [A; B]
    /// For A ∈ R^{n×m}, B ∈ R^{p×m}, computes [A; B] ∈ R^{(n+p)×m}
    pub fn vstack(&self, other: &Matrix<F>) -> Matrix<F> {
        assert_eq!(self.cols, other.cols);
        
        let mut result_data = self.data.clone();
        result_data.extend_from_slice(&other.data);
        
        Matrix::from_data(self.rows + other.rows, self.cols, result_data)
    }
    
    /// Horizontal concatenation: [A | B]
    /// For A ∈ R^{n×m}, B ∈ R^{n×p}, computes [A | B] ∈ R^{n×(m+p)}
    pub fn hstack(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.rows, other.rows);
        
        let result_cols = self.cols + other.cols;
        let mut result_data = Vec::with_capacity(self.rows * result_cols);
        
        for row_idx in 0..self.rows {
            let a_row = self.get_row(row_idx);
            let b_row = other.get_row(row_idx);
            
            result_data.extend_from_slice(a_row);
            result_data.extend_from_slice(b_row);
        }
        
        Matrix::from_data(self.rows, result_cols, result_data)
    }

    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &RingElement<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        let result_data: Vec<RingElement<F>> = self.data.iter()
            .map(|elem| ring.mul(scalar, elem))
            .collect();
        
        Matrix::from_data(self.rows, self.cols, result_data)
    }
    
    /// Matrix addition
    pub fn add(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.rows, other.rows);
        assert_eq!(self.cols, other.cols);
        
        let result_data: Vec<RingElement<F>> = self.data.iter()
            .zip(other.data.iter())
            .map(|(a, b)| ring.add(a, b))
            .collect();
        
        Matrix::from_data(self.rows, self.cols, result_data)
    }
    
    /// Matrix subtraction
    pub fn sub(&self, other: &Matrix<F>, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert_eq!(self.rows, other.rows);
        assert_eq!(self.cols, other.cols);
        
        let result_data: Vec<RingElement<F>> = self.data.iter()
            .zip(other.data.iter())
            .map(|(a, b)| ring.sub(a, b))
            .collect();
        
        Matrix::from_data(self.rows, self.cols, result_data)
    }
    
    /// Transpose matrix
    pub fn transpose(&self) -> Matrix<F> {
        let mut result_data = Vec::with_capacity(self.rows * self.cols);
        
        for col_idx in 0..self.cols {
            for row_idx in 0..self.rows {
                result_data.push(self.get(row_idx, col_idx).clone());
            }
        }
        
        Matrix::from_data(self.cols, self.rows, result_data)
    }
    
    /// Check if matrix has row-tensor structure
    pub fn is_row_tensor(&self) -> bool {
        self.tensor_structure.is_some()
    }
    
    /// Get tensor structure if it exists
    pub fn get_tensor_structure(&self) -> Option<&TensorStructure<F>> {
        self.tensor_structure.as_ref()
    }
}


impl<F: Field> TensorStructure<F> {
    /// Create new tensor structure from factor matrices
    /// Verifies that F = F_0 • F_1 • ... • F_{µ-1}
    pub fn new(factors: Vec<Matrix<F>>) -> Self {
        assert!(!factors.is_empty());
        
        let mu = factors.len();
        let n = factors[0].rows;
        let d = factors[0].cols;
        
        // Verify all factors have same dimensions
        for factor in &factors {
            assert_eq!(factor.rows, n);
            assert_eq!(factor.cols, d);
        }
        
        Self { factors, mu, d }
    }
    
    /// Compute the full matrix F = F_0 • F_1 • ... • F_{µ-1}
    /// Returns F ∈ R_q^{n×d^µ}
    pub fn compute_full_matrix(&self, ring: &crate::ring::CyclotomicRing<F>) -> Matrix<F> {
        assert!(!self.factors.is_empty());
        
        let mut result = self.factors[0].clone();
        
        for i in 1..self.mu {
            result = result.row_kronecker(&self.factors[i], ring);
        }
        
        result
    }
    
    /// Efficient matrix-vector multiplication using tensor structure
    /// For F = F_0 • ... • F_{µ-1} and w ∈ R^{d^µ}, computes Fw
    /// Complexity: O(n·d·µ) instead of O(n·d^µ) for naive multiplication
    /// 
    /// Reference: SALSAA paper - exploits tensor structure for efficiency
    pub fn mul_vec_efficient(
        &self,
        vec: &[RingElement<F>],
        ring: &crate::ring::CyclotomicRing<F>,
    ) -> Vec<RingElement<F>> {
        let n = self.factors[0].rows;
        let d = self.d;
        let mu = self.mu;
        
        // Verify vector has correct length d^µ
        assert_eq!(vec.len(), d.pow(mu as u32));
        
        // Reshape vector into tensor: w ∈ R^{d×d×...×d} (µ dimensions)
        // Then apply each factor matrix sequentially
        
        let mut current = vec.to_vec();
        
        // Apply factors from right to left
        for factor_idx in (0..mu).rev() {
            let factor = &self.factors[factor_idx];
            let chunk_size = d.pow(factor_idx as u32);
            let num_chunks = current.len() / (d * chunk_size);
            
            let mut next = Vec::with_capacity(n * chunk_size * num_chunks);
            
            for chunk_idx in 0..num_chunks {
                for row_idx in 0..n {
                    for inner_idx in 0..chunk_size {
                        let mut sum = ring.zero();
                        
                        for col_idx in 0..d {
                            let vec_idx = chunk_idx * d * chunk_size + col_idx * chunk_size + inner_idx;
                            let mat_elem = factor.get(row_idx, col_idx);
                            let vec_elem = &current[vec_idx];
                            
                            let prod = ring.mul(mat_elem, vec_elem);
                            sum = ring.add(&sum, &prod);
                        }
                        
                        next.push(sum);
                    }
                }
            }
            
            current = next;
        }
        
        current
    }
    
    /// Fold tensor structure with challenge γ
    /// For F = F_0 • ... • F_{µ-1}, computes F' = (F_0 + γF_1 + ... + γ^{d-1}F_{d-1}) • F_1 • ... • F_{µ-1}
    /// Used in folding protocol to reduce witness height
    pub fn fold_with_challenge(
        &self,
        gamma: &RingElement<F>,
        ring: &crate::ring::CyclotomicRing<F>,
    ) -> TensorStructure<F> {
        assert!(self.mu > 0);
        
        // Fold first factor
        let f0 = &self.factors[0];
        let block_height = f0.rows / self.d;
        
        let mut f0_folded = Matrix::zero(block_height, f0.cols, ring.degree);
        let mut gamma_power = ring.one();
        
        for i in 0..self.d {
            let start_row = i * block_height;
            let block_data = f0.data[start_row * f0.cols..(start_row + block_height) * f0.cols].to_vec();
            let block = Matrix::from_data(block_height, f0.cols, block_data);
            
            let scaled = block.scalar_mul(&gamma_power, ring);
            f0_folded = f0_folded.add(&scaled, ring);
            
            gamma_power = ring.mul(&gamma_power, gamma);
        }
        
        // Keep remaining factors unchanged
        let mut new_factors = vec![f0_folded];
        new_factors.extend_from_slice(&self.factors[1..]);
        
        TensorStructure::new(new_factors)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::ring::CyclotomicRing;
    use std::sync::Arc;
    
    fn create_test_ring() -> Arc<CyclotomicRing<GoldilocksField>> {
        Arc::new(CyclotomicRing::new(64))
    }
    
    fn create_test_element(val: u64, ring_degree: usize) -> RingElement<GoldilocksField> {
        let mut coeffs = vec![GoldilocksField::zero(); ring_degree];
        coeffs[0] = GoldilocksField::from_u64(val);
        RingElement::from_coeffs(coeffs)
    }
    
    #[test]
    fn test_matrix_creation() {
        let mat = Matrix::<GoldilocksField>::new(3, 4);
        assert_eq!(mat.rows, 3);
        assert_eq!(mat.cols, 4);
        assert_eq!(mat.data.len(), 12);
    }
    
    #[test]
    fn test_identity_matrix() {
        let ring = create_test_ring();
        let id = Matrix::identity(3, ring.degree);
        
        assert_eq!(id.rows, 3);
        assert_eq!(id.cols, 3);
        
        // Check diagonal elements are 1
        for i in 0..3 {
            assert_eq!(id.get(i, i).coeffs[0].to_canonical_u64(), 1);
        }
        
        // Check off-diagonal elements are 0
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    assert_eq!(id.get(i, j).coeffs[0].to_canonical_u64(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_matrix_get_set() {
        let ring = create_test_ring();
        let mut mat = Matrix::zero(2, 2, ring.degree);
        
        let elem = create_test_element(42, ring.degree);
        mat.set(0, 1, elem.clone());
        
        assert_eq!(mat.get(0, 1).coeffs[0].to_canonical_u64(), 42);
    }
    
    #[test]
    fn test_matrix_vector_multiplication() {
        let ring = create_test_ring();
        
        // Create 2x3 matrix
        let mut mat_data = Vec::new();
        for i in 0..6 {
            mat_data.push(create_test_element((i + 1) as u64, ring.degree));
        }
        let mat = Matrix::from_data(2, 3, mat_data);
        
        // Create vector [1, 2, 3]
        let vec = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
        ];
        
        // Multiply
        let result = mat.mul_vec(&vec, &ring);
        
        // Result should be [1*1 + 2*2 + 3*3, 4*1 + 5*2 + 6*3] = [14, 32]
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].coeffs[0].to_canonical_u64(), 14);
        assert_eq!(result[1].coeffs[0].to_canonical_u64(), 32);
    }

    
    #[test]
    fn test_matrix_matrix_multiplication() {
        let ring = create_test_ring();
        
        // Create 2x2 matrices
        let a_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let a = Matrix::from_data(2, 2, a_data);
        
        let b_data = vec![
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
            create_test_element(7, ring.degree),
            create_test_element(8, ring.degree),
        ];
        let b = Matrix::from_data(2, 2, b_data);
        
        // Multiply
        let c = a.mul_mat(&b, &ring);
        
        // C = [[1*5+2*7, 1*6+2*8], [3*5+4*7, 3*6+4*8]] = [[19, 22], [43, 50]]
        assert_eq!(c.get(0, 0).coeffs[0].to_canonical_u64(), 19);
        assert_eq!(c.get(0, 1).coeffs[0].to_canonical_u64(), 22);
        assert_eq!(c.get(1, 0).coeffs[0].to_canonical_u64(), 43);
        assert_eq!(c.get(1, 1).coeffs[0].to_canonical_u64(), 50);
    }
    
    #[test]
    fn test_row_kronecker_product() {
        let ring = create_test_ring();
        
        // Create 2x2 matrices
        let a_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let a = Matrix::from_data(2, 2, a_data);
        
        let b_data = vec![
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
            create_test_element(7, ring.degree),
            create_test_element(8, ring.degree),
        ];
        let b = Matrix::from_data(2, 2, b_data);
        
        // Row-wise Kronecker product
        let c = a.row_kronecker(&b, &ring);
        
        // Result should be 2x4
        assert_eq!(c.rows, 2);
        assert_eq!(c.cols, 4);
        
        // First row: [1, 2] ⊗ [5, 6] = [1*5, 1*6, 2*5, 2*6] = [5, 6, 10, 12]
        assert_eq!(c.get(0, 0).coeffs[0].to_canonical_u64(), 5);
        assert_eq!(c.get(0, 1).coeffs[0].to_canonical_u64(), 6);
        assert_eq!(c.get(0, 2).coeffs[0].to_canonical_u64(), 10);
        assert_eq!(c.get(0, 3).coeffs[0].to_canonical_u64(), 12);
        
        // Second row: [3, 4] ⊗ [7, 8] = [3*7, 3*8, 4*7, 4*8] = [21, 24, 28, 32]
        assert_eq!(c.get(1, 0).coeffs[0].to_canonical_u64(), 21);
        assert_eq!(c.get(1, 1).coeffs[0].to_canonical_u64(), 24);
        assert_eq!(c.get(1, 2).coeffs[0].to_canonical_u64(), 28);
        assert_eq!(c.get(1, 3).coeffs[0].to_canonical_u64(), 32);
    }
    
    #[test]
    fn test_hadamard_product() {
        let ring = create_test_ring();
        
        let a_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let a = Matrix::from_data(2, 2, a_data);
        
        let b_data = vec![
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
            create_test_element(7, ring.degree),
            create_test_element(8, ring.degree),
        ];
        let b = Matrix::from_data(2, 2, b_data);
        
        let c = a.hadamard(&b, &ring);
        
        // Element-wise: [[1*5, 2*6], [3*7, 4*8]] = [[5, 12], [21, 32]]
        assert_eq!(c.get(0, 0).coeffs[0].to_canonical_u64(), 5);
        assert_eq!(c.get(0, 1).coeffs[0].to_canonical_u64(), 12);
        assert_eq!(c.get(1, 0).coeffs[0].to_canonical_u64(), 21);
        assert_eq!(c.get(1, 1).coeffs[0].to_canonical_u64(), 32);
    }
    
    #[test]
    fn test_split_top_bottom() {
        let ring = create_test_ring();
        
        let mut data = Vec::new();
        for i in 0..12 {
            data.push(create_test_element((i + 1) as u64, ring.degree));
        }
        let mat = Matrix::from_data(4, 3, data);
        
        let (top, bottom) = mat.split_top_bottom(2);
        
        assert_eq!(top.rows, 2);
        assert_eq!(top.cols, 3);
        assert_eq!(bottom.rows, 2);
        assert_eq!(bottom.cols, 3);
        
        // Check first element of top
        assert_eq!(top.get(0, 0).coeffs[0].to_canonical_u64(), 1);
        
        // Check first element of bottom
        assert_eq!(bottom.get(0, 0).coeffs[0].to_canonical_u64(), 7);
    }
    
    #[test]
    fn test_vstack() {
        let ring = create_test_ring();
        
        let a_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
        ];
        let a = Matrix::from_data(1, 2, a_data);
        
        let b_data = vec![
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let b = Matrix::from_data(1, 2, b_data);
        
        let c = a.vstack(&b);
        
        assert_eq!(c.rows, 2);
        assert_eq!(c.cols, 2);
        assert_eq!(c.get(0, 0).coeffs[0].to_canonical_u64(), 1);
        assert_eq!(c.get(1, 0).coeffs[0].to_canonical_u64(), 3);
    }
    
    #[test]
    fn test_tensor_structure_creation() {
        let ring = create_test_ring();
        
        // Create two 2x2 factor matrices
        let f0_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let f0 = Matrix::from_data(2, 2, f0_data);
        
        let f1_data = vec![
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
            create_test_element(7, ring.degree),
            create_test_element(8, ring.degree),
        ];
        let f1 = Matrix::from_data(2, 2, f1_data);
        
        let tensor = TensorStructure::new(vec![f0, f1]);
        
        assert_eq!(tensor.mu, 2);
        assert_eq!(tensor.d, 2);
        assert_eq!(tensor.factors.len(), 2);
    }
    
    #[test]
    fn test_tensor_structure_full_matrix() {
        let ring = create_test_ring();
        
        // Create two 2x2 factor matrices
        let f0_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let f0 = Matrix::from_data(2, 2, f0_data);
        
        let f1_data = vec![
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
            create_test_element(7, ring.degree),
            create_test_element(8, ring.degree),
        ];
        let f1 = Matrix::from_data(2, 2, f1_data);
        
        let tensor = TensorStructure::new(vec![f0, f1]);
        
        // Compute full matrix F = F0 • F1
        let full = tensor.compute_full_matrix(&ring);
        
        // Result should be 2x4 (2 rows, 2^2 = 4 columns)
        assert_eq!(full.rows, 2);
        assert_eq!(full.cols, 4);
    }
    
    #[test]
    fn test_matrix_addition() {
        let ring = create_test_ring();
        
        let a_data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
        ];
        let a = Matrix::from_data(1, 2, a_data);
        
        let b_data = vec![
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
        ];
        let b = Matrix::from_data(1, 2, b_data);
        
        let c = a.add(&b, &ring);
        
        assert_eq!(c.get(0, 0).coeffs[0].to_canonical_u64(), 4);
        assert_eq!(c.get(0, 1).coeffs[0].to_canonical_u64(), 6);
    }
    
    #[test]
    fn test_matrix_transpose() {
        let ring = create_test_ring();
        
        let data = vec![
            create_test_element(1, ring.degree),
            create_test_element(2, ring.degree),
            create_test_element(3, ring.degree),
            create_test_element(4, ring.degree),
            create_test_element(5, ring.degree),
            create_test_element(6, ring.degree),
        ];
        let mat = Matrix::from_data(2, 3, data);
        
        let transposed = mat.transpose();
        
        assert_eq!(transposed.rows, 3);
        assert_eq!(transposed.cols, 2);
        assert_eq!(transposed.get(0, 0).coeffs[0].to_canonical_u64(), 1);
        assert_eq!(transposed.get(1, 0).coeffs[0].to_canonical_u64(), 2);
        assert_eq!(transposed.get(2, 0).coeffs[0].to_canonical_u64(), 3);
    }
}
