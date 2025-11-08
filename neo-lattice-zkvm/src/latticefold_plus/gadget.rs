// Gadget matrix decomposition for LatticeFold+
// G^(-1)_{b,k}: R^(n×m) → R^(n×mk) for norm reduction

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};

/// Gadget vector g_{b,k} = (1, b, ..., b^(k-1))
#[derive(Clone, Debug)]
pub struct GadgetVector {
    pub base: i64,
    pub length: usize,
    pub vector: Vec<i64>,
}

impl GadgetVector {
    /// Create gadget vector g_{b,k} = (1, b, ..., b^(k-1))
    pub fn new(base: i64, length: usize) -> Self {
        assert!(base > 1, "Base must be greater than 1");
        assert!(length > 0, "Length must be positive");
        
        let mut vector = Vec::with_capacity(length);
        let mut power = 1i64;
        
        for _ in 0..length {
            vector.push(power);
            power = power.saturating_mul(base);
        }
        
        Self {
            base,
            length,
            vector,
        }
    }
    
    /// Get bound: b^k
    pub fn bound(&self) -> i64 {
        self.vector[self.length - 1] * self.base
    }
}

/// Gadget matrix G_{b,k} = I_m ⊗ g_{b,k}
/// Tensor product of identity matrix with gadget vector
#[derive(Clone, Debug)]
pub struct GadgetMatrix {
    pub base: i64,
    pub length: usize,
    pub dimension: usize,
    pub gadget_vector: GadgetVector,
}

impl GadgetMatrix {
    /// Create gadget matrix G_{b,k} = I_m ⊗ g_{b,k}
    pub fn new(base: i64, length: usize, dimension: usize) -> Self {
        let gadget_vector = GadgetVector::new(base, length);
        
        Self {
            base,
            length,
            dimension,
            gadget_vector,
        }
    }
    
    /// Get matrix dimensions: (m*k) × m
    pub fn rows(&self) -> usize {
        self.dimension * self.length
    }
    
    pub fn cols(&self) -> usize {
        self.dimension
    }
    
    /// Multiply gadget matrix by vector: G_{b,k} · v
    /// Input: v ∈ R^(mk), Output: result ∈ R^m
    pub fn multiply_vector<F: Field>(
        &self,
        v: &[RingElement<F>],
        ring: &CyclotomicRing<F>
    ) -> Vec<RingElement<F>> {
        assert_eq!(v.len(), self.rows());
        
        let mut result = vec![ring.zero(); self.cols()];
        
        for i in 0..self.dimension {
            for j in 0..self.length {
                let idx = i * self.length + j;
                let power = self.gadget_vector.vector[j];
                
                // Scale by power of base
                let scaled = if power == 1 {
                    v[idx].clone()
                } else {
                    let power_field = F::from_u64(power.abs() as u64);
                    ring.scalar_mul(&power_field, &v[idx])
                };
                
                result[i] = ring.add(&result[i], &scaled);
            }
        }
        
        result
    }
}

/// Gadget decomposition G^(-1)_{b,k}
/// Decomposes high-norm elements into low-norm elements
pub struct GadgetDecomposition {
    pub base: i64,
    pub length: usize,
    pub gadget_vector: GadgetVector,
}

impl GadgetDecomposition {
    /// Create gadget decomposition with base b and length k
    /// Decomposes elements with norm < b^k into elements with norm < b
    pub fn new(base: i64, length: usize) -> Self {
        let gadget_vector = GadgetVector::new(base, length);
        
        Self {
            base,
            length,
            gadget_vector,
        }
    }
    
    /// Create decomposition for specific norm bound
    /// Automatically computes k = ⌈log_b(bound)⌉
    pub fn for_bound(base: i64, bound: i64) -> Self {
        assert!(base > 1);
        assert!(bound > 0);
        
        let length = ((bound as f64).log(base as f64)).ceil() as usize;
        Self::new(base, length)
    }
    
    /// Decompose scalar x into base-b representation
    /// Returns (x_0, ..., x_{k-1}) where x = Σ_i x_i · b^i and |x_i| < b
    pub fn decompose_scalar(&self, x: i64) -> Vec<i64> {
        let mut result = vec![0i64; self.length];
        let mut abs_x = x.abs();
        let sign = x.signum();
        
        for i in 0..self.length {
            let digit = (abs_x % self.base) as i64;
            result[i] = sign * digit;
            abs_x /= self.base;
        }
        
        // Verify decomposition
        debug_assert_eq!(self.reconstruct_scalar(&result), x);
        
        result
    }
    
    /// Reconstruct scalar from decomposition
    /// x = Σ_i x_i · b^i
    fn reconstruct_scalar(&self, decomp: &[i64]) -> i64 {
        assert_eq!(decomp.len(), self.length);
        
        let mut result = 0i64;
        for (i, &digit) in decomp.iter().enumerate() {
            result += digit * self.gadget_vector.vector[i];
        }
        result
    }
    
    /// Decompose ring element coefficient-wise
    /// Each coefficient is decomposed independently
    pub fn decompose_ring_element<F: Field>(
        &self,
        elem: &RingElement<F>,
        ring: &CyclotomicRing<F>
    ) -> Vec<RingElement<F>> {
        let d = ring.degree;
        let mut result = vec![vec![F::zero(); d]; self.length];
        
        // Decompose each coefficient
        for (coeff_idx, coeff) in elem.coeffs.iter().enumerate() {
            let val = self.field_to_signed(*coeff);
            let decomp = self.decompose_scalar(val);
            
            for (k, &digit) in decomp.iter().enumerate() {
                result[k][coeff_idx] = self.signed_to_field(digit);
            }
        }
        
        // Convert to ring elements
        result.into_iter()
            .map(|coeffs| RingElement::from_coeffs(coeffs))
            .collect()
    }
    
    /// Decompose matrix G^(-1)(M) where M ∈ R^(n×m)
    /// Returns M' ∈ R^(n×mk) such that M = M' · G_{b,k}
    pub fn decompose_matrix<F: Field>(
        &self,
        matrix: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>
    ) -> Vec<Vec<RingElement<F>>> {
        let n = matrix.len();
        if n == 0 {
            return vec![];
        }
        let m = matrix[0].len();
        
        let mut result = vec![vec![ring.zero(); m * self.length]; n];
        
        for i in 0..n {
            for j in 0..m {
                let decomposed = self.decompose_ring_element(&matrix[i][j], ring);
                
                for (k, elem) in decomposed.into_iter().enumerate() {
                    result[i][j * self.length + k] = elem;
                }
            }
        }
        
        result
    }
    
    /// Verify decomposition: M = M' · G_{b,k}
    pub fn verify_decomposition<F: Field>(
        &self,
        original: &[Vec<RingElement<F>>],
        decomposed: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>
    ) -> bool {
        let n = original.len();
        if n == 0 {
            return decomposed.is_empty();
        }
        let m = original[0].len();
        
        // Reconstruct and compare
        for i in 0..n {
            for j in 0..m {
                let mut reconstructed = ring.zero();
                
                for k in 0..self.length {
                    let idx = j * self.length + k;
                    let power = self.gadget_vector.vector[k];
                    let power_field = F::from_u64(power as u64);
                    
                    let scaled = ring.scalar_mul(&power_field, &decomposed[i][idx]);
                    reconstructed = ring.add(&reconstructed, &scaled);
                }
                
                if reconstructed != original[i][j] {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Verify norm reduction: ||M'||∞ < b when ||M||∞ < b^k
    pub fn verify_norm_reduction<F: Field>(
        &self,
        decomposed: &[Vec<RingElement<F>>]
    ) -> bool {
        for row in decomposed {
            for elem in row {
                if elem.norm_infinity() >= self.base as u64 {
                    return false;
                }
            }
        }
        true
    }
    
    /// Convert field element to signed integer (balanced representation)
    fn field_to_signed<F: Field>(&self, f: F) -> i64 {
        let val = f.to_canonical_u64();
        let modulus = F::MODULUS;
        
        // Map to [-q/2, q/2]
        if val <= modulus / 2 {
            val as i64
        } else {
            (val as i64) - (modulus as i64)
        }
    }
    
    /// Convert signed integer to field element
    fn signed_to_field<F: Field>(&self, x: i64) -> F {
        if x >= 0 {
            F::from_u64(x as u64)
        } else {
            F::from_u64((-x) as u64).neg()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_gadget_vector() {
        let gv = GadgetVector::new(2, 8);
        assert_eq!(gv.vector, vec![1, 2, 4, 8, 16, 32, 64, 128]);
        assert_eq!(gv.bound(), 256);
    }
    
    #[test]
    fn test_gadget_matrix() {
        let gm = GadgetMatrix::new(2, 4, 3);
        assert_eq!(gm.rows(), 12); // 3 * 4
        assert_eq!(gm.cols(), 3);
    }
    
    #[test]
    fn test_scalar_decomposition() {
        let gd = GadgetDecomposition::new(10, 3);
        
        // Test positive number
        let x = 456i64;
        let decomp = gd.decompose_scalar(x);
        assert_eq!(decomp, vec![6, 5, 4]); // 456 = 6 + 5*10 + 4*100
        
        // Test negative number
        let y = -123i64;
        let decomp_y = gd.decompose_scalar(y);
        assert_eq!(decomp_y, vec![-3, -2, -1]); // -123 = -3 + -2*10 + -1*100
    }
    
    #[test]
    fn test_scalar_reconstruction() {
        let gd = GadgetDecomposition::new(10, 4);
        
        for x in -1000..1000 {
            let decomp = gd.decompose_scalar(x);
            let reconstructed = gd.reconstruct_scalar(&decomp);
            assert_eq!(reconstructed, x);
        }
    }
    
    #[test]
    fn test_ring_element_decomposition() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let gd = GadgetDecomposition::new(32, 2); // base 32, length 2
        
        // Create ring element with small coefficients
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(100);
        coeffs[1] = GoldilocksField::from_u64(200);
        let elem = RingElement::from_coeffs(coeffs);
        
        // Decompose
        let decomposed = gd.decompose_ring_element(&elem, &ring);
        assert_eq!(decomposed.len(), 2);
        
        // Verify each decomposed element has small norm
        for d_elem in &decomposed {
            assert!(d_elem.norm_infinity() < 32);
        }
    }
    
    #[test]
    fn test_matrix_decomposition() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let gd = GadgetDecomposition::new(16, 3);
        
        // Create 2×2 matrix
        let mut matrix = vec![vec![ring.zero(); 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64((i * 10 + j * 5) as u64);
                matrix[i][j] = RingElement::from_coeffs(coeffs);
            }
        }
        
        // Decompose
        let decomposed = gd.decompose_matrix(&matrix, &ring);
        
        // Verify dimensions: 2×(2*3) = 2×6
        assert_eq!(decomposed.len(), 2);
        assert_eq!(decomposed[0].len(), 6);
        
        // Verify decomposition correctness
        assert!(gd.verify_decomposition(&matrix, &decomposed, &ring));
        
        // Verify norm reduction
        assert!(gd.verify_norm_reduction(&decomposed));
    }
    
    #[test]
    fn test_for_bound() {
        let gd = GadgetDecomposition::for_bound(2, 256);
        assert_eq!(gd.length, 8); // 2^8 = 256
        
        let gd2 = GadgetDecomposition::for_bound(10, 1000);
        assert_eq!(gd2.length, 3); // 10^3 = 1000
    }
}
