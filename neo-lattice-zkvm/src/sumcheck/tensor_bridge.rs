// Tensor-of-Rings Bridge for Sum-Check and Folding
// Implements E = K ⊗_Fq Rq bidirectional conversion

use crate::field::extension_framework::ExtensionFieldElement;
use crate::field::Field;
use crate::ring::cyclotomic::CyclotomicRing;
use std::fmt::Debug;

/// Tensor-of-Rings structure bridging extension fields and cyclotomic rings
/// E = K ⊗_Fq Rq where K = F_q^t and Rq = Zq[X]/(X^d + 1)
#[derive(Clone, Debug)]
pub struct TensorOfRings<K: ExtensionFieldElement, R: CyclotomicRing> {
    /// Matrix representation over Zq^{t×d}
    /// matrix[i][j] represents coefficient of α^i · X^j
    /// where α generates K/Fq and X generates Rq
    pub matrix: Vec<Vec<K::BaseField>>,
    /// Extension field degree t
    pub extension_degree: usize,
    /// Ring dimension d
    pub ring_dimension: usize,
    _phantom_k: std::marker::PhantomData<K>,
    _phantom_r: std::marker::PhantomData<R>,
}

impl<K, R> TensorOfRings<K, R>
where
    K: ExtensionFieldElement,
    R: CyclotomicRing<BaseField = K::BaseField>,
{
    /// Create new tensor element from matrix
    pub fn new(matrix: Vec<Vec<K::BaseField>>) -> Result<Self, String> {
        if matrix.is_empty() {
            return Err("Matrix cannot be empty".to_string());
        }
        
        let extension_degree = matrix.len();
        let ring_dimension = matrix[0].len();
        
        // Verify all rows have same length
        for row in &matrix {
            if row.len() != ring_dimension {
                return Err("All matrix rows must have same length".to_string());
            }
        }
        
        Ok(Self {
            matrix,
            extension_degree,
            ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        })
    }
    
    /// Create zero tensor
    pub fn zero(extension_degree: usize, ring_dimension: usize) -> Self {
        let matrix = vec![vec![K::BaseField::zero(); ring_dimension]; extension_degree];
        Self {
            matrix,
            extension_degree,
            ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        }
    }
    
    /// Interpret as K-vector space element for sum-check operations
    /// Returns [e_1, ..., e_d] ∈ K^d
    /// Algorithm: For each column j, compute k_elem = Σ_i matrix[i][j]·α^i
    pub fn as_k_vector(&self) -> Vec<K> {
        let mut result = Vec::with_capacity(self.ring_dimension);
        
        for col in 0..self.ring_dimension {
            // Collect coefficients for this column
            let mut coeffs = Vec::with_capacity(self.extension_degree);
            for row in 0..self.extension_degree {
                coeffs.push(self.matrix[row][col]);
            }
            
            // Create extension field element from coefficients
            let k_elem = K::from_base_field_coefficients(&coeffs);
            result.push(k_elem);
        }
        
        result
    }
    
    /// Interpret as Rq-module element for folding operations
    /// Returns (e'_1, ..., e'_t) ∈ Rq^t
    /// Algorithm: For each row i, create ring element from coefficients matrix[i][:]
    pub fn as_rq_module(&self) -> Vec<R> {
        let mut result = Vec::with_capacity(self.extension_degree);
        
        for row in 0..self.extension_degree {
            // Create ring element from row coefficients
            let ring_elem = R::from_coefficients(&self.matrix[row]);
            result.push(ring_elem);
        }
        
        result
    }
    
    /// K-scalar multiplication for sum-check operations
    /// Algorithm: Multiply by scalar coefficients with wraparound modulo extension degree
    pub fn k_scalar_mul(&self, scalar: K) -> Self {
        let scalar_coeffs = scalar.to_base_field_coefficients();
        let mut new_matrix = vec![vec![K::BaseField::zero(); self.ring_dimension]; self.extension_degree];
        
        // Perform multiplication in extension field
        // (Σ_i s_i α^i) · (Σ_j m_j α^j) = Σ_{i,j} s_i m_j α^{i+j}
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                for k in 0..scalar_coeffs.len().min(self.extension_degree) {
                    // Multiply and accumulate with wraparound
                    let idx = (i + k) % self.extension_degree;
                    let term = scalar_coeffs[k].mul(&self.matrix[i][j]);
                    new_matrix[idx][j] = new_matrix[idx][j].add(&term);
                }
            }
        }
        
        Self {
            matrix: new_matrix,
            extension_degree: self.extension_degree,
            ring_dimension: self.ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        }
    }
    
    /// Rq-scalar multiplication for folding operations
    /// Algorithm: Multiply by ring coefficients with wraparound modulo ring dimension
    pub fn rq_scalar_mul(&self, scalar: R) -> Self {
        let scalar_coeffs = scalar.coefficients();
        let mut new_matrix = vec![vec![K::BaseField::zero(); self.ring_dimension]; self.extension_degree];
        
        // Perform multiplication in cyclotomic ring
        // (Σ_i s_i X^i) · (Σ_j m_j X^j) = Σ_{i,j} s_i m_j X^{i+j}
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                for k in 0..scalar_coeffs.len().min(self.ring_dimension) {
                    // Multiply and accumulate with wraparound
                    let idx = (j + k) % self.ring_dimension;
                    let term = scalar_coeffs[k].mul(&self.matrix[i][j]);
                    new_matrix[i][idx] = new_matrix[i][idx].add(&term);
                }
            }
        }
        
        Self {
            matrix: new_matrix,
            extension_degree: self.extension_degree,
            ring_dimension: self.ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        }
    }
    
    /// Add two tensor elements
    pub fn add(&self, other: &Self) -> Result<Self, String> {
        if self.extension_degree != other.extension_degree || 
           self.ring_dimension != other.ring_dimension {
            return Err("Tensor dimensions must match".to_string());
        }
        
        let mut result_matrix = vec![vec![K::BaseField::zero(); self.ring_dimension]; self.extension_degree];
        
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                result_matrix[i][j] = self.matrix[i][j].add(&other.matrix[i][j]);
            }
        }
        
        Ok(Self {
            matrix: result_matrix,
            extension_degree: self.extension_degree,
            ring_dimension: self.ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        })
    }
    
    /// Create tensor from K-vector
    pub fn from_k_vector(vec: &[K], ring_dimension: usize) -> Self {
        let extension_degree = K::degree();
        let mut matrix = vec![vec![K::BaseField::zero(); ring_dimension]; extension_degree];
        
        for (col, &k_elem) in vec.iter().enumerate().take(ring_dimension) {
            let coeffs = k_elem.to_base_field_coefficients();
            for (row, &coeff) in coeffs.iter().enumerate().take(extension_degree) {
                matrix[row][col] = coeff;
            }
        }
        
        Self {
            matrix,
            extension_degree,
            ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        }
    }
    
    /// Create tensor from Rq-module
    pub fn from_rq_module(module: &[R]) -> Self {
        if module.is_empty() {
            return Self::zero(1, 1);
        }
        
        let extension_degree = module.len();
        let ring_dimension = module[0].dimension();
        let mut matrix = vec![vec![K::BaseField::zero(); ring_dimension]; extension_degree];
        
        for (row, ring_elem) in module.iter().enumerate() {
            let coeffs = ring_elem.coefficients();
            for (col, &coeff) in coeffs.iter().enumerate().take(ring_dimension) {
                matrix[row][col] = coeff;
            }
        }
        
        Self {
            matrix,
            extension_degree,
            ring_dimension,
            _phantom_k: std::marker::PhantomData,
            _phantom_r: std::marker::PhantomData,
        }
    }
    
    /// Verify bidirectional conversion: as_k_vector().to_tensor() == original
    pub fn verify_conversion_consistency(&self) -> bool {
        // Convert to K-vector and back
        let k_vec = self.as_k_vector();
        let reconstructed = Self::from_k_vector(&k_vec, self.ring_dimension);
        
        // Check if matrices match
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                if self.matrix[i][j] != reconstructed.matrix[i][j] {
                    return false;
                }
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M61Field, Field};
    use crate::field::extension_framework::M61ExtensionField2;
    use crate::ring::cyclotomic::CyclotomicRingElement;
    
    type K = M61ExtensionField2;
    type R = CyclotomicRingElement<M61Field, 4>;
    
    #[test]
    fn test_create_tensor() {
        let matrix = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2)],
            vec![M61Field::from_u64(3), M61Field::from_u64(4)],
        ];
        
        let tensor = TensorOfRings::<K, R>::new(matrix).unwrap();
        assert_eq!(tensor.extension_degree, 2);
        assert_eq!(tensor.ring_dimension, 2);
    }
    
    #[test]
    fn test_as_k_vector() {
        let matrix = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2)],
            vec![M61Field::from_u64(3), M61Field::from_u64(4)],
        ];
        
        let tensor = TensorOfRings::<K, R>::new(matrix).unwrap();
        let k_vec = tensor.as_k_vector();
        
        assert_eq!(k_vec.len(), 2);
        
        // First element should be [1, 3] in extension field
        let coeffs0 = k_vec[0].to_base_field_coefficients();
        assert_eq!(coeffs0[0].to_canonical_u64(), 1);
        assert_eq!(coeffs0[1].to_canonical_u64(), 3);
        
        // Second element should be [2, 4] in extension field
        let coeffs1 = k_vec[1].to_base_field_coefficients();
        assert_eq!(coeffs1[0].to_canonical_u64(), 2);
        assert_eq!(coeffs1[1].to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_as_rq_module() {
        let matrix = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2), M61Field::from_u64(3), M61Field::from_u64(4)],
            vec![M61Field::from_u64(5), M61Field::from_u64(6), M61Field::from_u64(7), M61Field::from_u64(8)],
        ];
        
        let tensor = TensorOfRings::<K, R>::new(matrix).unwrap();
        let rq_module = tensor.as_rq_module();
        
        assert_eq!(rq_module.len(), 2);
        
        // First ring element should have coefficients [1, 2, 3, 4]
        let coeffs0 = rq_module[0].coefficients();
        assert_eq!(coeffs0[0].to_canonical_u64(), 1);
        assert_eq!(coeffs0[1].to_canonical_u64(), 2);
        assert_eq!(coeffs0[2].to_canonical_u64(), 3);
        assert_eq!(coeffs0[3].to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_k_scalar_mul() {
        let matrix = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2)],
            vec![M61Field::from_u64(3), M61Field::from_u64(4)],
        ];
        
        let tensor = TensorOfRings::<K, R>::new(matrix).unwrap();
        
        // Scalar in extension field: 2 + 3α
        let scalar = K::from_base_field_coefficients(&[
            M61Field::from_u64(2),
            M61Field::from_u64(3),
        ]);
        
        let result = tensor.k_scalar_mul(scalar);
        
        // Verify dimensions preserved
        assert_eq!(result.extension_degree, 2);
        assert_eq!(result.ring_dimension, 2);
    }
    
    #[test]
    fn test_add_tensors() {
        let matrix1 = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2)],
            vec![M61Field::from_u64(3), M61Field::from_u64(4)],
        ];
        
        let matrix2 = vec![
            vec![M61Field::from_u64(5), M61Field::from_u64(6)],
            vec![M61Field::from_u64(7), M61Field::from_u64(8)],
        ];
        
        let tensor1 = TensorOfRings::<K, R>::new(matrix1).unwrap();
        let tensor2 = TensorOfRings::<K, R>::new(matrix2).unwrap();
        
        let sum = tensor1.add(&tensor2).unwrap();
        
        assert_eq!(sum.matrix[0][0].to_canonical_u64(), 6);
        assert_eq!(sum.matrix[0][1].to_canonical_u64(), 8);
        assert_eq!(sum.matrix[1][0].to_canonical_u64(), 10);
        assert_eq!(sum.matrix[1][1].to_canonical_u64(), 12);
    }
    
    #[test]
    fn test_bidirectional_conversion() {
        let matrix = vec![
            vec![M61Field::from_u64(1), M61Field::from_u64(2)],
            vec![M61Field::from_u64(3), M61Field::from_u64(4)],
        ];
        
        let tensor = TensorOfRings::<K, R>::new(matrix).unwrap();
        
        // Test K-vector conversion
        assert!(tensor.verify_conversion_consistency());
    }
    
    #[test]
    fn test_from_k_vector() {
        let k_vec = vec![
            K::from_base_field_coefficients(&[M61Field::from_u64(1), M61Field::from_u64(2)]),
            K::from_base_field_coefficients(&[M61Field::from_u64(3), M61Field::from_u64(4)]),
        ];
        
        let tensor = TensorOfRings::<K, R>::from_k_vector(&k_vec, 2);
        
        assert_eq!(tensor.extension_degree, 2);
        assert_eq!(tensor.ring_dimension, 2);
        assert_eq!(tensor.matrix[0][0].to_canonical_u64(), 1);
        assert_eq!(tensor.matrix[1][0].to_canonical_u64(), 2);
        assert_eq!(tensor.matrix[0][1].to_canonical_u64(), 3);
        assert_eq!(tensor.matrix[1][1].to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_zero_tensor() {
        let tensor = TensorOfRings::<K, R>::zero(2, 3);
        
        assert_eq!(tensor.extension_degree, 2);
        assert_eq!(tensor.ring_dimension, 3);
        
        for i in 0..2 {
            for j in 0..3 {
                assert_eq!(tensor.matrix[i][j], M61Field::zero());
            }
        }
    }
}
