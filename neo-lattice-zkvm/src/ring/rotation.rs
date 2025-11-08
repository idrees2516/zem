// Rotation matrix implementation for ring elements

use crate::field::Field;
use super::RingElement;

/// Rotation matrix for efficient matrix-vector operations
/// rot(a) · cf(b) = cf(a·b)
pub struct RotationMatrix<F: Field> {
    degree: usize,
    matrix: Vec<Vec<F>>,
}

impl<F: Field> RotationMatrix<F> {
    /// Construct rotation matrix for ring element a
    /// For X^d + 1, the rotation matrix has special structure
    pub fn new(element: &RingElement<F>, degree: usize) -> Self {
        let mut matrix = vec![vec![F::zero(); degree]; degree];
        
        // Column i is X^i · a reduced modulo X^d + 1
        // For X^d + 1: X^d = -1
        
        for col in 0..degree {
            for row in 0..degree {
                let coeff_idx = if row >= col {
                    row - col
                } else {
                    degree + row - col
                };
                
                let coeff = element.coeffs[coeff_idx];
                
                // If we wrapped around (row < col), negate due to X^d = -1
                if row < col {
                    matrix[row][col] = coeff.neg();
                } else {
                    matrix[row][col] = coeff;
                }
            }
        }
        
        Self { degree, matrix }
    }
    
    /// Matrix-vector multiplication
    pub fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        assert_eq!(vec.len(), self.degree);
        
        let mut result = vec![F::zero(); self.degree];
        
        for i in 0..self.degree {
            for j in 0..self.degree {
                let prod = self.matrix[i][j].mul(&vec[j]);
                result[i] = result[i].add(&prod);
            }
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::ring::CyclotomicRing;
    
    #[test]
    fn test_rotation_matrix() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        a_coeffs[1] = GoldilocksField::from_u64(3);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(4);
        b_coeffs[1] = GoldilocksField::from_u64(5);
        let b = RingElement::from_coeffs(b_coeffs.clone());
        
        // Compute a*b using ring multiplication
        let ab_ring = ring.mul(&a, &b);
        
        // Compute using rotation matrix
        let rot = RotationMatrix::new(&a, 64);
        let ab_rot = rot.mul_vector(&b_coeffs);
        
        // Should be equal
        for (ring_val, rot_val) in ab_ring.coeffs.iter().zip(ab_rot.iter()) {
            assert_eq!(ring_val, rot_val);
        }
    }
}
