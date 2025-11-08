// Tensor-of-rings framework E := K ⊗_{F_q} Rq
// Represents elements as t×d matrix over Z_q
// Supports both K-vector space and Rq-module interpretations
// Critical for Symphony's high-arity folding efficiency

use crate::field::{Field, ExtensionField};
use super::{RingElement, CyclotomicRing};

/// Tensor element E := K ⊗_{F_q} Rq represented as t×d matrix over Z_q
/// where K = F_{q^t} is extension field and Rq = Z_q[X]/⟨X^d + 1⟩
#[derive(Clone, Debug)]
pub struct TensorElement<F: Field> {
    /// Matrix representation: t × d matrix over Z_q
    pub matrix: Vec<Vec<F>>,
    /// Extension field degree t
    pub t: usize,
    /// Ring degree d
    pub d: usize,
}

impl<F: Field> TensorElement<F> {
    /// Create new tensor element from matrix
    pub fn new(matrix: Vec<Vec<F>>) -> Self {
        let t = matrix.len();
        let d = if t > 0 { matrix[0].len() } else { 0 };
        
        // Verify all rows have same length
        for row in &matrix {
            assert_eq!(row.len(), d, "All rows must have same length");
        }
        
        Self { matrix, t, d }
    }
    
    /// Create zero tensor element
    pub fn zero(t: usize, d: usize) -> Self {
        let matrix = vec![vec![F::zero(); d]; t];
        Self { matrix, t, d }
    }
    
    /// Create tensor element from K-vector interpretation
    /// Input: [e_1, ..., e_d] ∈ K^{1×d}
    /// Each e_i ∈ K is represented as [c_0, c_1] for K = F_{q^2}
    pub fn from_k_vector(elements: &[ExtensionField<F>]) -> Self {
        let d = elements.len();
        let t = 2; // For K = F_{q^2}
        
        let mut matrix = vec![vec![F::zero(); d]; t];
        for (j, elem) in elements.iter().enumerate() {
            matrix[0][j] = elem.coeffs[0];
            matrix[1][j] = elem.coeffs[1];
        }
        
        Self { matrix, t, d }
    }
    
    /// Convert to K-vector space interpretation
    /// Output: [e_1, ..., e_d] ∈ K^{1×d}
    pub fn to_k_vector(&self) -> Vec<ExtensionField<F>> {
        assert_eq!(self.t, 2, "Only supports t=2 for K = F_{q^2}");
        
        (0..self.d)
            .map(|j| ExtensionField::new(self.matrix[0][j], self.matrix[1][j]))
            .collect()
    }
    
    /// Create tensor element from Rq-module interpretation
    /// Input: (e'_1, ..., e'_t) ∈ Rq^t
    pub fn from_rq_module(elements: &[RingElement<F>]) -> Self {
        let t = elements.len();
        let d = if t > 0 { elements[0].coeffs.len() } else { 0 };
        
        let mut matrix = vec![vec![F::zero(); d]; t];
        for (i, elem) in elements.iter().enumerate() {
            matrix[i] = elem.coeffs.clone();
        }
        
        Self { matrix, t, d }
    }
    
    /// Convert to Rq-module interpretation
    /// Output: (e'_1, ..., e'_t) ∈ Rq^t
    pub fn to_rq_module(&self) -> Vec<RingElement<F>> {
        self.matrix.iter()
            .map(|row| RingElement::from_coeffs(row.clone()))
            .collect()
    }
    
    /// K-scalar multiplication: a·[e_1, ..., e_d] = [a·e_1, ..., a·e_d]
    /// Multiplies each column by scalar a ∈ K
    pub fn k_scalar_mul(&self, scalar: &ExtensionField<F>) -> Self {
        let k_vec = self.to_k_vector();
        let result: Vec<ExtensionField<F>> = k_vec.iter()
            .map(|e| scalar.mul(e))
            .collect();
        Self::from_k_vector(&result)
    }
    
    /// Rq-scalar multiplication: (e'_1, ..., e'_t)·b = (b·e'_1, ..., b·e'_t)
    /// Multiplies each row by scalar b ∈ Rq
    pub fn rq_scalar_mul(&self, scalar: &RingElement<F>, ring: &CyclotomicRing<F>) -> Self {
        let rq_module = self.to_rq_module();
        let result: Vec<RingElement<F>> = rq_module.iter()
            .map(|e| ring.mul(scalar, e))
            .collect();
        Self::from_rq_module(&result)
    }
    
    /// Mixed multiplication: a·b ∈ E for a ∈ K, b ∈ Rq
    /// Computed as cf(a) ⊗ cf(b)^⊤ ∈ Z_q^{t×d}
    pub fn k_times_rq(k_elem: &ExtensionField<F>, rq_elem: &RingElement<F>) -> Self {
        let t = 2; // For K = F_{q^2}
        let d = rq_elem.coeffs.len();
        
        // cf(a) = [a_0, a_1]^T (column vector)
        let k_coeffs = [k_elem.coeffs[0], k_elem.coeffs[1]];
        
        // cf(b) = [b_0, ..., b_{d-1}] (row vector)
        let rq_coeffs = &rq_elem.coeffs;
        
        // Outer product: cf(a) ⊗ cf(b)^⊤
        let mut matrix = vec![vec![F::zero(); d]; t];
        for i in 0..t {
            for j in 0..d {
                matrix[i][j] = k_coeffs[i].mul(&rq_coeffs[j]);
            }
        }
        
        Self { matrix, t, d }
    }
    
    /// Lift b ∈ Rq to e_b := [b, 0, ..., 0]^⊤ ∈ E
    /// For K-scalar multiplication interpretation
    pub fn lift_from_rq(rq_elem: &RingElement<F>, t: usize) -> Self {
        let d = rq_elem.coeffs.len();
        let mut matrix = vec![vec![F::zero(); d]; t];
        matrix[0] = rq_elem.coeffs.clone();
        Self { matrix, t, d }
    }
    
    /// Lift a ∈ K to e_a := [a, 0, ..., 0] ∈ E
    /// For Rq-scalar multiplication interpretation
    pub fn lift_from_k(k_elem: &ExtensionField<F>, d: usize) -> Self {
        let t = 2; // For K = F_{q^2}
        let mut matrix = vec![vec![F::zero(); d]; t];
        matrix[0][0] = k_elem.coeffs[0];
        matrix[1][0] = k_elem.coeffs[1];
        Self { matrix, t, d }
    }
    
    /// Addition of tensor elements
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.t, other.t);
        assert_eq!(self.d, other.d);
        
        let matrix = self.matrix.iter()
            .zip(other.matrix.iter())
            .map(|(row1, row2)| {
                row1.iter()
                    .zip(row2.iter())
                    .map(|(a, b)| a.add(b))
                    .collect()
            })
            .collect();
        
        Self { matrix, t: self.t, d: self.d }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_tensor_creation() {
        let matrix = vec![
            vec![GoldilocksField::from_u64(1), GoldilocksField::from_u64(2)],
            vec![GoldilocksField::from_u64(3), GoldilocksField::from_u64(4)],
        ];
        let tensor = TensorElement::new(matrix);
        assert_eq!(tensor.t, 2);
        assert_eq!(tensor.d, 2);
    }
    
    #[test]
    fn test_k_vector_conversion() {
        let k_vec = vec![
            ExtensionField::new(GoldilocksField::from_u64(1), GoldilocksField::from_u64(2)),
            ExtensionField::new(GoldilocksField::from_u64(3), GoldilocksField::from_u64(4)),
        ];
        
        let tensor = TensorElement::from_k_vector(&k_vec);
        let recovered = tensor.to_k_vector();
        
        assert_eq!(k_vec.len(), recovered.len());
        for (orig, rec) in k_vec.iter().zip(recovered.iter()) {
            assert_eq!(orig, rec);
        }
    }
    
    #[test]
    fn test_rq_module_conversion() {
        let rq_module = vec![
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1), GoldilocksField::from_u64(2)]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(3), GoldilocksField::from_u64(4)]),
        ];
        
        let tensor = TensorElement::from_rq_module(&rq_module);
        let recovered = tensor.to_rq_module();
        
        assert_eq!(rq_module.len(), recovered.len());
        for (orig, rec) in rq_module.iter().zip(recovered.iter()) {
            assert_eq!(orig.coeffs, rec.coeffs);
        }
    }
    
    #[test]
    fn test_k_scalar_multiplication() {
        let k_vec = vec![
            ExtensionField::new(GoldilocksField::from_u64(2), GoldilocksField::from_u64(3)),
            ExtensionField::new(GoldilocksField::from_u64(4), GoldilocksField::from_u64(5)),
        ];
        let tensor = TensorElement::from_k_vector(&k_vec);
        
        let scalar = ExtensionField::new(GoldilocksField::from_u64(2), GoldilocksField::zero());
        let result = tensor.k_scalar_mul(&scalar);
        
        // Verify result is not zero
        assert!(result.matrix.iter().any(|row| row.iter().any(|&x| x.to_canonical_u64() != 0)));
    }
    
    #[test]
    fn test_rq_scalar_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let rq_module = vec![
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
        ];
        let tensor = TensorElement::from_rq_module(&rq_module);
        
        let mut scalar_coeffs = vec![GoldilocksField::zero(); 64];
        scalar_coeffs[0] = GoldilocksField::from_u64(3);
        let scalar = RingElement::from_coeffs(scalar_coeffs);
        
        let result = tensor.rq_scalar_mul(&scalar, &ring);
        
        // Verify result is not zero
        assert!(result.matrix.iter().any(|row| row.iter().any(|&x| x.to_canonical_u64() != 0)));
    }
    
    #[test]
    fn test_mixed_multiplication() {
        let k_elem = ExtensionField::new(
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3)
        );
        
        let mut rq_coeffs = vec![GoldilocksField::zero(); 64];
        rq_coeffs[0] = GoldilocksField::from_u64(5);
        rq_coeffs[1] = GoldilocksField::from_u64(7);
        let rq_elem = RingElement::from_coeffs(rq_coeffs);
        
        let tensor = TensorElement::k_times_rq(&k_elem, &rq_elem);
        
        assert_eq!(tensor.t, 2);
        assert_eq!(tensor.d, 64);
        
        // Verify outer product structure
        // matrix[0][0] should be 2*5 = 10
        assert_eq!(tensor.matrix[0][0].to_canonical_u64(), 10);
        // matrix[1][0] should be 3*5 = 15
        assert_eq!(tensor.matrix[1][0].to_canonical_u64(), 15);
    }
    
    #[test]
    fn test_both_interpretations_consistent() {
        // Create tensor from K-vector
        let k_vec = vec![
            ExtensionField::new(GoldilocksField::from_u64(1), GoldilocksField::from_u64(2)),
            ExtensionField::new(GoldilocksField::from_u64(3), GoldilocksField::from_u64(4)),
        ];
        let tensor1 = TensorElement::from_k_vector(&k_vec);
        
        // Create same tensor from Rq-module
        let rq_module = vec![
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1), GoldilocksField::from_u64(3)]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(2), GoldilocksField::from_u64(4)]),
        ];
        let tensor2 = TensorElement::from_rq_module(&rq_module);
        
        // Both should produce same matrix
        assert_eq!(tensor1.matrix, tensor2.matrix);
    }
}
