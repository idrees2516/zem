// Univariate Polynomial Implementation for Sum-Check Protocol

use crate::field::extension_framework::ExtensionFieldElement;
use std::fmt::Debug;

/// Univariate polynomial over extension field K
/// Represented in evaluation form for efficiency
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnivariatePolynomial<K: ExtensionFieldElement> {
    /// Evaluations at points 0, 1, 2, ..., degree
    pub evaluations: Vec<K>,
}

impl<K: ExtensionFieldElement> UnivariatePolynomial<K> {
    /// Create from evaluations at 0, 1, 2, ..., degree
    pub fn from_evaluations(evals: &[K]) -> Self {
        Self {
            evaluations: evals.to_vec(),
        }
    }
    
    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        if self.evaluations.is_empty() {
            0
        } else {
            self.evaluations.len() - 1
        }
    }
    
    /// Evaluate at arbitrary point using Lagrange interpolation
    pub fn evaluate(&self, x: K) -> K {
        if self.evaluations.is_empty() {
            return K::zero();
        }
        
        let n = self.evaluations.len();
        let mut result = K::zero();
        
        // Lagrange interpolation: p(x) = Σ_i y_i · L_i(x)
        // where L_i(x) = Π_{j≠i} (x - j) / (i - j)
        for i in 0..n {
            let mut term = self.evaluations[i];
            
            // Compute Lagrange basis polynomial L_i(x)
            for j in 0..n {
                if i != j {
                    // (x - j)
                    let j_field = K::from_base_field_element(
                        K::BaseField::from_u64(j as u64),
                        0
                    );
                    let numerator = x.sub(&j_field);
                    
                    // (i - j)
                    let i_val = K::BaseField::from_u64(i as u64);
                    let j_val = K::BaseField::from_u64(j as u64);
                    let denominator = K::from_base_field_element(
                        i_val.sub(&j_val),
                        0
                    );
                    
                    if let Some(denom_inv) = denominator.inverse() {
                        term = term.mul(&numerator).mul(&denom_inv);
                    }
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
    
    /// Evaluate at integer point (optimized)
    pub fn evaluate_at_int(&self, x: usize) -> K {
        if x < self.evaluations.len() {
            self.evaluations[x]
        } else {
            let x_field = K::from_base_field_element(
                K::BaseField::from_u64(x as u64),
                0
            );
            self.evaluate(x_field)
        }
    }
    
    /// Convert to coefficient form
    pub fn to_coefficients(&self) -> Vec<K> {
        if self.evaluations.is_empty() {
            return vec![];
        }
        
        let n = self.evaluations.len();
        let mut coeffs = vec![K::zero(); n];
        
        // Use Lagrange interpolation to find coefficients
        for i in 0..n {
            let mut basis_coeffs = vec![K::zero(); n];
            basis_coeffs[0] = K::one();
            
            // Build (x - 0)(x - 1)...(x - i-1)(x - i+1)...(x - n-1)
            for j in 0..n {
                if i != j {
                    let j_field = K::from_base_field_element(
                        K::BaseField::from_u64(j as u64),
                        0
                    );
                    
                    // Multiply by (x - j)
                    let mut new_coeffs = vec![K::zero(); n];
                    for k in 0..n {
                        if k > 0 {
                            new_coeffs[k] = new_coeffs[k].add(&basis_coeffs[k - 1]);
                        }
                        new_coeffs[k] = new_coeffs[k].sub(&basis_coeffs[k].mul(&j_field));
                    }
                    basis_coeffs = new_coeffs;
                }
            }
            
            // Divide by denominator (i - 0)(i - 1)...(i - i-1)(i - i+1)...(i - n-1)
            let mut denom = K::one();
            for j in 0..n {
                if i != j {
                    let i_val = K::BaseField::from_u64(i as u64);
                    let j_val = K::BaseField::from_u64(j as u64);
                    let diff = K::from_base_field_element(i_val.sub(&j_val), 0);
                    denom = denom.mul(&diff);
                }
            }
            
            if let Some(denom_inv) = denom.inverse() {
                for k in 0..n {
                    let term = basis_coeffs[k].mul(&denom_inv).mul(&self.evaluations[i]);
                    coeffs[k] = coeffs[k].add(&term);
                }
            }
        }
        
        coeffs
    }
    
    /// Add two univariate polynomials
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.evaluations.len().max(other.evaluations.len());
        let mut result = vec![K::zero(); max_len];
        
        for i in 0..max_len {
            if i < self.evaluations.len() {
                result[i] = result[i].add(&self.evaluations[i]);
            }
            if i < other.evaluations.len() {
                result[i] = result[i].add(&other.evaluations[i]);
            }
        }
        
        Self { evaluations: result }
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: K) -> Self {
        let evals: Vec<K> = self.evaluations.iter()
            .map(|&e| e.mul(&scalar))
            .collect();
        Self { evaluations: evals }
    }
    
    /// Create zero polynomial
    pub fn zero() -> Self {
        Self {
            evaluations: vec![K::zero()],
        }
    }
    
    /// Create constant polynomial
    pub fn constant(value: K) -> Self {
        Self {
            evaluations: vec![value],
        }
    }
    
    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.evaluations.iter().all(|&e| e == K::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M61Field, Field};
    use crate::field::extension_framework::M61ExtensionField2;
    
    type K = M61ExtensionField2;
    
    #[test]
    fn test_from_evaluations() {
        let evals = vec![
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(2), 0),
            K::from_base_field_element(M61Field::from_u64(3), 0),
        ];
        
        let poly = UnivariatePolynomial::from_evaluations(&evals);
        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.evaluations.len(), 3);
    }
    
    #[test]
    fn test_evaluate_at_int() {
        let evals = vec![
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(4), 0),
            K::from_base_field_element(M61Field::from_u64(9), 0),
        ];
        
        let poly = UnivariatePolynomial::from_evaluations(&evals);
        
        // Should return stored evaluations
        assert_eq!(poly.evaluate_at_int(0), evals[0]);
        assert_eq!(poly.evaluate_at_int(1), evals[1]);
        assert_eq!(poly.evaluate_at_int(2), evals[2]);
    }
    
    #[test]
    fn test_lagrange_interpolation() {
        // Polynomial p(x) = x^2: p(0)=0, p(1)=1, p(2)=4
        let evals = vec![
            K::from_base_field_element(M61Field::from_u64(0), 0),
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(4), 0),
        ];
        
        let poly = UnivariatePolynomial::from_evaluations(&evals);
        
        // Evaluate at x=3, should get 9
        let x = K::from_base_field_element(M61Field::from_u64(3), 0);
        let result = poly.evaluate(x);
        let expected = K::from_base_field_element(M61Field::from_u64(9), 0);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_constant_polynomial() {
        let value = K::from_base_field_element(M61Field::from_u64(42), 0);
        let poly = UnivariatePolynomial::constant(value);
        
        assert_eq!(poly.degree(), 0);
        assert_eq!(poly.evaluate_at_int(0), value);
        
        // Should be constant everywhere
        let x = K::from_base_field_element(M61Field::from_u64(100), 0);
        assert_eq!(poly.evaluate(x), value);
    }
    
    #[test]
    fn test_add_polynomials() {
        let poly1 = UnivariatePolynomial::from_evaluations(&[
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(2), 0),
            K::from_base_field_element(M61Field::from_u64(3), 0),
        ]);
        
        let poly2 = UnivariatePolynomial::from_evaluations(&[
            K::from_base_field_element(M61Field::from_u64(4), 0),
            K::from_base_field_element(M61Field::from_u64(5), 0),
            K::from_base_field_element(M61Field::from_u64(6), 0),
        ]);
        
        let sum = poly1.add(&poly2);
        
        assert_eq!(sum.evaluate_at_int(0), 
            K::from_base_field_element(M61Field::from_u64(5), 0));
        assert_eq!(sum.evaluate_at_int(1), 
            K::from_base_field_element(M61Field::from_u64(7), 0));
        assert_eq!(sum.evaluate_at_int(2), 
            K::from_base_field_element(M61Field::from_u64(9), 0));
    }
    
    #[test]
    fn test_scalar_mul() {
        let poly = UnivariatePolynomial::from_evaluations(&[
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(2), 0),
            K::from_base_field_element(M61Field::from_u64(3), 0),
        ]);
        
        let scalar = K::from_base_field_element(M61Field::from_u64(2), 0);
        let result = poly.scalar_mul(scalar);
        
        assert_eq!(result.evaluate_at_int(0), 
            K::from_base_field_element(M61Field::from_u64(2), 0));
        assert_eq!(result.evaluate_at_int(1), 
            K::from_base_field_element(M61Field::from_u64(4), 0));
        assert_eq!(result.evaluate_at_int(2), 
            K::from_base_field_element(M61Field::from_u64(6), 0));
    }
    
    #[test]
    fn test_zero_polynomial() {
        let poly = UnivariatePolynomial::<K>::zero();
        
        assert!(poly.is_zero());
        assert_eq!(poly.evaluate_at_int(0), K::zero());
        
        let x = K::from_base_field_element(M61Field::from_u64(42), 0);
        assert_eq!(poly.evaluate(x), K::zero());
    }
    
    #[test]
    fn test_degree() {
        let poly0 = UnivariatePolynomial::from_evaluations(&[
            K::from_base_field_element(M61Field::from_u64(5), 0),
        ]);
        assert_eq!(poly0.degree(), 0);
        
        let poly2 = UnivariatePolynomial::from_evaluations(&[
            K::from_base_field_element(M61Field::from_u64(1), 0),
            K::from_base_field_element(M61Field::from_u64(2), 0),
            K::from_base_field_element(M61Field::from_u64(3), 0),
        ]);
        assert_eq!(poly2.degree(), 2);
    }
}
