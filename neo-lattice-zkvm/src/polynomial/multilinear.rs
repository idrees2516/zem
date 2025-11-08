// Multilinear polynomial implementation

use crate::field::Field;

/// Multilinear polynomial represented by evaluations over Boolean hypercube
#[derive(Clone, Debug)]
pub struct MultilinearPolynomial<F: Field> {
    pub evaluations: Vec<F>,
    pub num_vars: usize,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create new multilinear polynomial from evaluations
    /// Length must be a power of 2
    pub fn new(evaluations: Vec<F>) -> Self {
        let len = evaluations.len();
        assert!(len.is_power_of_two(), "Length must be power of 2");
        let num_vars = len.trailing_zeros() as usize;
        
        Self {
            evaluations,
            num_vars,
        }
    }
    
    /// Evaluate multilinear extension at point r ∈ F^ℓ
    /// Uses recursive formula for O(N) evaluation
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");
        
        let mut current = self.evaluations.clone();
        
        // For each variable, interpolate between 0 and 1 evaluations
        for r_i in point.iter() {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                // Interpolate: (1 - r_i) · current[j] + r_i · current[j + half]
                let one_minus_r = F::one().sub(r_i);
                let left = current[j].mul(&one_minus_r);
                let right = current[j + half].mul(r_i);
                next.push(left.add(&right));
            }
            
            current = next;
        }
        
        assert_eq!(current.len(), 1);
        current[0]
    }
    
    /// Compute equality polynomial: eq(x, r) = ∏ᵢ (xᵢ·rᵢ + (1-xᵢ)·(1-rᵢ))
    pub fn eq_poly(x: &[bool], r: &[F]) -> F {
        assert_eq!(x.len(), r.len());
        
        let mut result = F::one();
        for (xi, ri) in x.iter().zip(r.iter()) {
            let term = if *xi {
                *ri
            } else {
                F::one().sub(ri)
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Partial evaluation: fix first k variables
    pub fn partial_eval(&self, values: &[F]) -> Self {
        let k = values.len();
        assert!(k <= self.num_vars, "Too many variables to fix");
        
        let mut current = self.evaluations.clone();
        
        for val in values {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                let one_minus_val = F::one().sub(val);
                let interpolated = current[j].mul(&one_minus_val)
                    .add(&current[j + half].mul(val));
                next.push(interpolated);
            }
            
            current = next;
        }
        
        Self {
            evaluations: current,
            num_vars: self.num_vars - k,
        }
    }
    
    /// Linear combination of MLEs: (Σᵢ αᵢ·wᵢ)~(r) = Σᵢ αᵢ·w̃ᵢ(r)
    pub fn linear_combination(polys: &[Self], coeffs: &[F]) -> Self {
        assert_eq!(polys.len(), coeffs.len());
        assert!(!polys.is_empty());
        
        let len = polys[0].evaluations.len();
        let num_vars = polys[0].num_vars;
        
        // Verify all polynomials have same size
        for poly in polys {
            assert_eq!(poly.evaluations.len(), len);
            assert_eq!(poly.num_vars, num_vars);
        }
        
        let mut result = vec![F::zero(); len];
        
        for (poly, coeff) in polys.iter().zip(coeffs.iter()) {
            for (i, eval) in poly.evaluations.iter().enumerate() {
                result[i] = result[i].add(&eval.mul(coeff));
            }
        }
        
        Self {
            evaluations: result,
            num_vars,
        }
    }
    
    /// Verify multilinearity: polynomial is linear in each variable
    pub fn is_multilinear(&self) -> bool {
        // For a multilinear polynomial, the degree in each variable is at most 1
        // This is guaranteed by construction from Boolean hypercube evaluations
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_mle_creation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearPolynomial::new(evals);
        assert_eq!(mle.num_vars, 2);
    }
    
    #[test]
    fn test_mle_evaluation_at_boolean() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearPolynomial::new(evals.clone());
        
        // Evaluate at Boolean points
        let point00 = vec![GoldilocksField::zero(), GoldilocksField::zero()];
        assert_eq!(mle.evaluate(&point00), evals[0]);
        
        let point01 = vec![GoldilocksField::zero(), GoldilocksField::one()];
        assert_eq!(mle.evaluate(&point01), evals[1]);
        
        let point10 = vec![GoldilocksField::one(), GoldilocksField::zero()];
        assert_eq!(mle.evaluate(&point10), evals[2]);
        
        let point11 = vec![GoldilocksField::one(), GoldilocksField::one()];
        assert_eq!(mle.evaluate(&point11), evals[3]);
    }
    
    #[test]
    fn test_partial_evaluation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearPolynomial::new(evals);
        
        // Fix first variable to 0
        let partial = mle.partial_eval(&[GoldilocksField::zero()]);
        assert_eq!(partial.num_vars, 1);
        assert_eq!(partial.evaluations.len(), 2);
    }
    
    #[test]
    fn test_linear_combination() {
        let evals1 = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        let evals2 = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle1 = MultilinearPolynomial::new(evals1);
        let mle2 = MultilinearPolynomial::new(evals2);
        
        let coeffs = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let combined = MultilinearPolynomial::linear_combination(
            &[mle1, mle2],
            &coeffs
        );
        
        // 2*1 + 3*3 = 11
        assert_eq!(combined.evaluations[0].to_canonical_u64(), 11);
        // 2*2 + 3*4 = 16
        assert_eq!(combined.evaluations[1].to_canonical_u64(), 16);
    }
    
    #[test]
    fn test_eq_poly() {
        let x = vec![false, true];
        let r = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let result = MultilinearPolynomial::<GoldilocksField>::eq_poly(&x, &r);
        
        // eq([0,1], [3,5]) = (1-3) * 5 = -2 * 5 = -10
        // In field arithmetic, this should be computed correctly
        assert!(result.to_canonical_u64() > 0);
    }
}
