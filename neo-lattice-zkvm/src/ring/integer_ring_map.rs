// Integer-to-Ring Mapping (MR) for HyperWolf PCS
// Maps coefficient vectors from Z_q^{nd} to R_q^n
// Groups d consecutive coefficients into each ring element
// Per HyperWolf paper Requirement 21

use crate::field::Field;
use super::RingElement;

/// Integer-to-Ring mapping: MR: Z_q^{nd} → R_q^n
/// 
/// For coefficient vector f⃗ = (f_0, f_1, ..., f_{nd-1}) ∈ Z_q^{nd},
/// produces ring vector (r_0, r_1, ..., r_{n-1}) ∈ R_q^n where:
/// 
/// r_i = Σ_{j=0}^{d-1} f_{id+j} X^j
/// 
/// This groups d consecutive coefficients into each ring element.
#[derive(Clone, Debug)]
pub struct IntegerRingMap {
    /// Ring degree d (must be power of 2)
    pub ring_degree: usize,
}

impl IntegerRingMap {
    /// Create new integer-to-ring mapping
    /// 
    /// # Arguments
    /// * `ring_degree` - Ring degree d (must be power of 2)
    pub fn new(ring_degree: usize) -> Result<Self, String> {
        if !ring_degree.is_power_of_two() {
            return Err(format!(
                "Ring degree must be power of 2, got {}",
                ring_degree
            ));
        }
        
        if ring_degree < 64 {
            return Err(format!(
                "Ring degree must be at least 64 for security, got {}",
                ring_degree
            ));
        }
        
        Ok(Self { ring_degree })
    }
    
    /// Map coefficient vector to ring vector
    /// 
    /// # Arguments
    /// * `coefficients` - Coefficient vector f⃗ ∈ Z_q^{nd}
    /// 
    /// # Returns
    /// Ring vector (r_0, ..., r_{n-1}) ∈ R_q^n where n = len(coefficients) / d
    /// 
    /// # Example
    /// For d=4 and coefficients [1,2,3,4, 5,6,7,8]:
    /// - r_0 = 1 + 2X + 3X² + 4X³
    /// - r_1 = 5 + 6X + 7X² + 8X³
    pub fn map<F: Field>(&self, coefficients: Vec<F>) -> Result<Vec<RingElement<F>>, String> {
        let total_len = coefficients.len();
        
        if total_len % self.ring_degree != 0 {
            return Err(format!(
                "Coefficient vector length {} is not divisible by ring degree {}",
                total_len, self.ring_degree
            ));
        }
        
        let n = total_len / self.ring_degree;
        let mut ring_vector = Vec::with_capacity(n);
        
        // Group d consecutive coefficients into each ring element
        for i in 0..n {
            let start = i * self.ring_degree;
            let end = start + self.ring_degree;
            let ring_coeffs = coefficients[start..end].to_vec();
            
            ring_vector.push(RingElement::from_coeffs(ring_coeffs));
        }
        
        Ok(ring_vector)
    }
    
    /// Inverse mapping: R_q^n → Z_q^{nd}
    /// 
    /// # Arguments
    /// * `ring_vector` - Ring vector (r_0, ..., r_{n-1}) ∈ R_q^n
    /// 
    /// # Returns
    /// Coefficient vector f⃗ ∈ Z_q^{nd}
    pub fn inverse_map<F: Field>(&self, ring_vector: Vec<RingElement<F>>) -> Vec<F> {
        let mut coefficients = Vec::with_capacity(ring_vector.len() * self.ring_degree);
        
        for ring_elem in ring_vector {
            if ring_elem.coeffs.len() != self.ring_degree {
                panic!(
                    "Ring element has {} coefficients, expected {}",
                    ring_elem.coeffs.len(),
                    self.ring_degree
                );
            }
            coefficients.extend(ring_elem.coeffs);
        }
        
        coefficients
    }
    
    /// Map polynomial coefficients to ring vector
    /// Handles both univariate and multilinear polynomials
    /// 
    /// # Arguments
    /// * `poly_coeffs` - Polynomial coefficients
    /// * `is_multilinear` - Whether polynomial is multilinear
    /// 
    /// # Returns
    /// Ring vector representation
    pub fn map_polynomial<F: Field>(
        &self,
        poly_coeffs: Vec<F>,
        is_multilinear: bool,
    ) -> Result<Vec<RingElement<F>>, String> {
        // For both univariate and multilinear, the mapping is the same:
        // group d consecutive coefficients into each ring element
        self.map(poly_coeffs)
    }
    
    /// Compute auxiliary vectors for univariate evaluation
    /// 
    /// For univariate polynomial f(X) evaluated at point u:
    /// - a⃗_i = (1, u^{2^i d}) for i ∈ [1, k-1]
    /// - a⃗_0 = (1, u, u², ..., u^{2d-1})
    /// 
    /// # Arguments
    /// * `eval_point` - Evaluation point u
    /// * `num_rounds` - Number of rounds k
    /// 
    /// # Returns
    /// Auxiliary vectors (a⃗_0, a⃗_1, ..., a⃗_{k-1})
    pub fn univariate_auxiliary_vectors<F: Field>(
        &self,
        eval_point: F,
        num_rounds: usize,
    ) -> Vec<Vec<F>> {
        let mut aux_vectors = Vec::with_capacity(num_rounds);
        
        // a⃗_0 = (1, u, u², ..., u^{2d-1})
        let mut a0 = Vec::with_capacity(2 * self.ring_degree);
        let mut power = F::one();
        for _ in 0..(2 * self.ring_degree) {
            a0.push(power);
            power = power.mul(&eval_point);
        }
        aux_vectors.push(a0);
        
        // a⃗_i = (1, u^{2^i d}) for i ∈ [1, k-1]
        for i in 1..num_rounds {
            let exponent = (1 << i) * self.ring_degree; // 2^i * d
            let u_power = Self::power(eval_point, exponent);
            aux_vectors.push(vec![F::one(), u_power]);
        }
        
        aux_vectors
    }
    
    /// Compute auxiliary vectors for multilinear evaluation
    /// 
    /// For multilinear polynomial f(X_0, ..., X_{ℓ-1}) evaluated at point (u_0, ..., u_{ℓ-1}):
    /// - a⃗_i = (1, u_{log d + i}) for i ∈ [1, k-1]
    /// - a⃗_0 = ⊗_{j=0}^{log d} (1, u_j)
    /// 
    /// # Arguments
    /// * `eval_point` - Evaluation point (u_0, ..., u_{ℓ-1})
    /// * `num_rounds` - Number of rounds k
    /// 
    /// # Returns
    /// Auxiliary vectors (a⃗_0, a⃗_1, ..., a⃗_{k-1})
    pub fn multilinear_auxiliary_vectors<F: Field>(
        &self,
        eval_point: &[F],
        num_rounds: usize,
    ) -> Result<Vec<Vec<F>>, String> {
        let log_d = (self.ring_degree as f64).log2() as usize;
        
        if eval_point.len() < log_d {
            return Err(format!(
                "Evaluation point has {} coordinates, need at least {} (log d)",
                eval_point.len(), log_d
            ));
        }
        
        let mut aux_vectors = Vec::with_capacity(num_rounds);
        
        // a⃗_0 = ⊗_{j=0}^{log d} (1, u_j)
        // Start with (1, u_0)
        let mut a0 = vec![F::one(), eval_point[0]];
        
        // Tensor product with (1, u_j) for j = 1, ..., log d - 1
        for j in 1..log_d {
            a0 = Self::tensor_product(&a0, &[F::one(), eval_point[j]]);
        }
        
        aux_vectors.push(a0);
        
        // a⃗_i = (1, u_{log d + i}) for i ∈ [1, k-1]
        for i in 1..num_rounds {
            let idx = log_d + i - 1;
            if idx >= eval_point.len() {
                return Err(format!(
                    "Evaluation point has {} coordinates, need at least {}",
                    eval_point.len(), idx + 1
                ));
            }
            aux_vectors.push(vec![F::one(), eval_point[idx]]);
        }
        
        Ok(aux_vectors)
    }
    
    /// Compute power: base^exponent
    fn power<F: Field>(base: F, exponent: usize) -> F {
        let mut result = F::one();
        let mut b = base;
        let mut e = exponent;
        
        while e > 0 {
            if e % 2 == 1 {
                result = result.mul(&b);
            }
            b = b.mul(&b);
            e /= 2;
        }
        
        result
    }
    
    /// Tensor product of two vectors
    /// For a⃗ ∈ F^m and b⃗ ∈ F^n, computes a⃗ ⊗ b⃗ ∈ F^{mn}
    fn tensor_product<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
        let mut result = Vec::with_capacity(a.len() * b.len());
        
        for a_elem in a {
            for b_elem in b {
                result.push(a_elem.mul(b_elem));
            }
        }
        
        result
    }
    
    /// Check if mapping is injective (one-to-one)
    /// This is always true for the MR mapping
    pub fn is_injective(&self) -> bool {
        true
    }
    
    /// Get expected output dimension for given input length
    pub fn output_dimension(&self, input_length: usize) -> usize {
        input_length / self.ring_degree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_map_creation() {
        let map = IntegerRingMap::new(64).unwrap();
        assert_eq!(map.ring_degree, 64);
    }
    
    #[test]
    fn test_invalid_ring_degree() {
        // Not power of 2
        assert!(IntegerRingMap::new(63).is_err());
        
        // Too small
        assert!(IntegerRingMap::new(32).is_err());
    }
    
    #[test]
    fn test_basic_mapping() {
        let map = IntegerRingMap::new(64).unwrap();
        
        // Create coefficient vector of length 128 (2 ring elements)
        let coeffs: Vec<GoldilocksField> = (0..128)
            .map(|i| GoldilocksField::from_u64(i as u64))
            .collect();
        
        let ring_vector = map.map(coeffs.clone()).unwrap();
        
        assert_eq!(ring_vector.len(), 2);
        
        // First ring element should have coefficients 0..63
        for (i, coeff) in ring_vector[0].coeffs.iter().enumerate() {
            assert_eq!(coeff.to_canonical_u64(), i as u64);
        }
        
        // Second ring element should have coefficients 64..127
        for (i, coeff) in ring_vector[1].coeffs.iter().enumerate() {
            assert_eq!(coeff.to_canonical_u64(), (64 + i) as u64);
        }
    }
    
    #[test]
    fn test_inverse_mapping() {
        let map = IntegerRingMap::new(64).unwrap();
        
        // Create coefficient vector
        let original_coeffs: Vec<GoldilocksField> = (0..128)
            .map(|i| GoldilocksField::from_u64(i as u64))
            .collect();
        
        // Map to ring vector and back
        let ring_vector = map.map(original_coeffs.clone()).unwrap();
        let recovered_coeffs = map.inverse_map(ring_vector);
        
        // Should recover original coefficients
        assert_eq!(original_coeffs.len(), recovered_coeffs.len());
        for (orig, rec) in original_coeffs.iter().zip(recovered_coeffs.iter()) {
            assert_eq!(orig.to_canonical_u64(), rec.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_invalid_length() {
        let map = IntegerRingMap::new(64).unwrap();
        
        // Length not divisible by ring degree
        let coeffs: Vec<GoldilocksField> = (0..100)
            .map(|i| GoldilocksField::from_u64(i as u64))
            .collect();
        
        assert!(map.map(coeffs).is_err());
    }
    
    #[test]
    fn test_univariate_auxiliary_vectors() {
        let map = IntegerRingMap::new(64).unwrap();
        let eval_point = GoldilocksField::from_u64(5);
        let num_rounds = 3;
        
        let aux_vectors = map.univariate_auxiliary_vectors(eval_point, num_rounds);
        
        assert_eq!(aux_vectors.len(), 3);
        
        // a⃗_0 should have length 2d = 128
        assert_eq!(aux_vectors[0].len(), 128);
        
        // a⃗_0[0] should be 1
        assert_eq!(aux_vectors[0][0].to_canonical_u64(), 1);
        
        // a⃗_0[1] should be u = 5
        assert_eq!(aux_vectors[0][1].to_canonical_u64(), 5);
        
        // a⃗_0[2] should be u² = 25
        assert_eq!(aux_vectors[0][2].to_canonical_u64(), 25);
        
        // a⃗_1 should be (1, u^{2d}) = (1, u^{128})
        assert_eq!(aux_vectors[1].len(), 2);
        assert_eq!(aux_vectors[1][0].to_canonical_u64(), 1);
        
        // a⃗_2 should be (1, u^{4d}) = (1, u^{256})
        assert_eq!(aux_vectors[2].len(), 2);
        assert_eq!(aux_vectors[2][0].to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_multilinear_auxiliary_vectors() {
        let map = IntegerRingMap::new(64).unwrap();
        
        // For d=64, log d = 6
        // Need at least 6 + (k-1) coordinates
        let eval_point: Vec<GoldilocksField> = (0..10)
            .map(|i| GoldilocksField::from_u64(i as u64 + 1))
            .collect();
        
        let num_rounds = 3;
        let aux_vectors = map.multilinear_auxiliary_vectors(&eval_point, num_rounds).unwrap();
        
        assert_eq!(aux_vectors.len(), 3);
        
        // a⃗_0 = ⊗_{j=0}^{5} (1, u_j)
        // Should have length 2^6 = 64
        assert_eq!(aux_vectors[0].len(), 64);
        
        // a⃗_1 = (1, u_6)
        assert_eq!(aux_vectors[1].len(), 2);
        assert_eq!(aux_vectors[1][0].to_canonical_u64(), 1);
        assert_eq!(aux_vectors[1][1].to_canonical_u64(), 7); // u_6 = 7
        
        // a⃗_2 = (1, u_7)
        assert_eq!(aux_vectors[2].len(), 2);
        assert_eq!(aux_vectors[2][0].to_canonical_u64(), 1);
        assert_eq!(aux_vectors[2][1].to_canonical_u64(), 8); // u_7 = 8
    }
    
    #[test]
    fn test_tensor_product() {
        let a = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        let b = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let result = IntegerRingMap::tensor_product(&a, &b);
        
        // a ⊗ b = (1·3, 1·4, 2·3, 2·4) = (3, 4, 6, 8)
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].to_canonical_u64(), 3);
        assert_eq!(result[1].to_canonical_u64(), 4);
        assert_eq!(result[2].to_canonical_u64(), 6);
        assert_eq!(result[3].to_canonical_u64(), 8);
    }
    
    #[test]
    fn test_power() {
        let base = GoldilocksField::from_u64(2);
        
        assert_eq!(IntegerRingMap::power(base, 0).to_canonical_u64(), 1);
        assert_eq!(IntegerRingMap::power(base, 1).to_canonical_u64(), 2);
        assert_eq!(IntegerRingMap::power(base, 2).to_canonical_u64(), 4);
        assert_eq!(IntegerRingMap::power(base, 3).to_canonical_u64(), 8);
        assert_eq!(IntegerRingMap::power(base, 10).to_canonical_u64(), 1024);
    }
    
    #[test]
    fn test_output_dimension() {
        let map = IntegerRingMap::new(64).unwrap();
        
        assert_eq!(map.output_dimension(64), 1);
        assert_eq!(map.output_dimension(128), 2);
        assert_eq!(map.output_dimension(640), 10);
    }
    
    #[test]
    fn test_is_injective() {
        let map = IntegerRingMap::new(64).unwrap();
        assert!(map.is_injective());
    }
    
    #[test]
    fn test_map_polynomial() {
        let map = IntegerRingMap::new(64).unwrap();
        
        // Create polynomial coefficients
        let poly_coeffs: Vec<GoldilocksField> = (0..128)
            .map(|i| GoldilocksField::from_u64(i as u64))
            .collect();
        
        // Map as univariate
        let ring_vec_uni = map.map_polynomial(poly_coeffs.clone(), false).unwrap();
        assert_eq!(ring_vec_uni.len(), 2);
        
        // Map as multilinear
        let ring_vec_multi = map.map_polynomial(poly_coeffs.clone(), true).unwrap();
        assert_eq!(ring_vec_multi.len(), 2);
        
        // Both should produce same result
        for (uni, multi) in ring_vec_uni.iter().zip(ring_vec_multi.iter()) {
            assert_eq!(uni.coeffs, multi.coeffs);
        }
    }
}
