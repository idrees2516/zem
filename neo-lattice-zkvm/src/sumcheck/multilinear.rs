// Multilinear Polynomial Implementation for Sum-Check Protocol
// Implements MLE over extension fields with full evaluation and manipulation

use crate::field::extension_framework::ExtensionFieldElement;
use std::fmt::Debug;

/// Multilinear polynomial over extension field K
/// Represents unique multilinear extension of function f: {0,1}^n → K
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilinearPolynomial<K: ExtensionFieldElement> {
    /// Evaluations over Boolean hypercube {0,1}^n
    /// evaluations[i] = f(binary representation of i)
    pub evaluations: Vec<K>,
    /// Number of variables n
    pub num_vars: usize,
}

impl<K: ExtensionFieldElement> MultilinearPolynomial<K> {
    /// Create MLE from evaluations over {0,1}^n
    /// Validates that length is a power of 2
    pub fn from_evaluations(evals: Vec<K>) -> Result<Self, String> {
        if evals.is_empty() {
            return Err("Evaluations cannot be empty".to_string());
        }
        
        if !evals.len().is_power_of_two() {
            return Err(format!(
                "Evaluations length {} must be a power of 2",
                evals.len()
            ));
        }
        
        let num_vars = evals.len().trailing_zeros() as usize;
        
        Ok(Self {
            evaluations: evals,
            num_vars,
        })
    }
    
    /// Evaluate at point r ∈ K^n using Lagrange interpolation
    /// ã(r) = Σ_{x∈{0,1}^n} a(x) · eq̃(r,x)
    pub fn evaluate(&self, point: &[K]) -> Result<K, String> {
        if point.len() != self.num_vars {
            return Err(format!(
                "Point dimension {} does not match polynomial variables {}",
                point.len(),
                self.num_vars
            ));
        }
        
        let mut result = K::zero();
        
        for (idx, &eval) in self.evaluations.iter().enumerate() {
            let x = Self::index_to_bits(idx, self.num_vars);
            let eq_val = Self::eq_polynomial(point, &x);
            result = result.add(&eval.mul(&eq_val));
        }
        
        Ok(result)
    }
    
    /// Equality polynomial: eq̃(r,x) = Π_{i=1}^n ((1-r_i)(1-x_i) + r_i·x_i)
    /// This equals 1 when r = x (on Boolean hypercube) and is multilinear
    pub fn eq_polynomial(r: &[K], x: &[bool]) -> K {
        assert_eq!(r.len(), x.len(), "Dimensions must match");
        
        let mut result = K::one();
        
        for (r_i, &x_i) in r.iter().zip(x.iter()) {
            let term = if x_i {
                // When x_i = 1: contribution is r_i
                *r_i
            } else {
                // When x_i = 0: contribution is (1 - r_i)
                K::one().sub(r_i)
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Partial evaluation: fix first variable to value r_0
    /// Returns (n-1)-variate MLE
    /// Formula: p̃(r_0,x') = (1-r_0)·p̃(0,x') + r_0·p̃(1,x')
    pub fn partial_eval(&self, r_0: K) -> Result<Self, String> {
        if self.num_vars == 0 {
            return Err("Cannot partially evaluate 0-variate polynomial".to_string());
        }
        
        let half = self.evaluations.len() / 2;
        let mut new_evals = Vec::with_capacity(half);
        
        let one_minus_r0 = K::one().sub(&r_0);
        
        for i in 0..half {
            // p̃(r_0, x_2,...,x_n) = (1-r_0)·p̃(0,x_2,...,x_n) + r_0·p̃(1,x_2,...,x_n)
            let eval_0 = self.evaluations[i];
            let eval_1 = self.evaluations[i + half];
            
            let term0 = one_minus_r0.mul(&eval_0);
            let term1 = r_0.mul(&eval_1);
            new_evals.push(term0.add(&term1));
        }
        
        Ok(Self {
            evaluations: new_evals,
            num_vars: self.num_vars - 1,
        })
    }
    
    /// Convert index to Boolean vector
    /// index_to_bits(5, 4) = [true, false, true, false] (binary: 0101)
    pub fn index_to_bits(idx: usize, n: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(n);
        for i in 0..n {
            bits.push((idx >> i) & 1 == 1);
        }
        bits
    }
    
    /// Convert Boolean vector to index
    pub fn bits_to_index(bits: &[bool]) -> usize {
        let mut idx = 0;
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                idx |= 1 << i;
            }
        }
        idx
    }
    
    /// Get evaluation at Boolean point
    pub fn eval_at_boolean(&self, point: &[bool]) -> Result<K, String> {
        if point.len() != self.num_vars {
            return Err(format!(
                "Point dimension {} does not match polynomial variables {}",
                point.len(),
                self.num_vars
            ));
        }
        
        let idx = Self::bits_to_index(point);
        Ok(self.evaluations[idx])
    }
    
    /// Add two multilinear polynomials
    pub fn add(&self, other: &Self) -> Result<Self, String> {
        if self.num_vars != other.num_vars {
            return Err("Polynomials must have same number of variables".to_string());
        }
        
        let evals: Vec<K> = self.evaluations.iter()
            .zip(other.evaluations.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        
        Ok(Self {
            evaluations: evals,
            num_vars: self.num_vars,
        })
    }
    
    /// Multiply two multilinear polynomials (pointwise)
    pub fn mul(&self, other: &Self) -> Result<Self, String> {
        if self.num_vars != other.num_vars {
            return Err("Polynomials must have same number of variables".to_string());
        }
        
        let evals: Vec<K> = self.evaluations.iter()
            .zip(other.evaluations.iter())
            .map(|(a, b)| a.mul(b))
            .collect();
        
        Ok(Self {
            evaluations: evals,
            num_vars: self.num_vars,
        })
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: K) -> Self {
        let evals: Vec<K> = self.evaluations.iter()
            .map(|a| a.mul(&scalar))
            .collect();
        
        Self {
            evaluations: evals,
            num_vars: self.num_vars,
        }
    }
    
    /// Create zero polynomial
    pub fn zero(num_vars: usize) -> Self {
        let size = 1 << num_vars;
        Self {
            evaluations: vec![K::zero(); size],
            num_vars,
        }
    }
    
    /// Create constant polynomial
    pub fn constant(value: K, num_vars: usize) -> Self {
        let size = 1 << num_vars;
        Self {
            evaluations: vec![value; size],
            num_vars,
        }
    }
    
    /// Check if two MLEs are equal
    /// Two MLEs are equal iff their evaluations match on {0,1}^n
    pub fn equals(&self, other: &Self) -> bool {
        if self.num_vars != other.num_vars {
            return false;
        }
        
        self.evaluations == other.evaluations
    }
    
    /// Verify MLE uniqueness property
    /// If two multilinear polynomials agree on {0,1}^n, they are identical
    pub fn verify_uniqueness(&self, other: &Self) -> bool {
        // Check if evaluations on Boolean hypercube match
        if self.num_vars != other.num_vars {
            return false;
        }
        
        for i in 0..self.evaluations.len() {
            if self.evaluations[i] != other.evaluations[i] {
                return false;
            }
        }
        
        true
    }
    
    /// Relabel variables (permute dimensions)
    pub fn relabel(&self, permutation: &[usize]) -> Result<Self, String> {
        if permutation.len() != self.num_vars {
            return Err("Permutation size must match number of variables".to_string());
        }
        
        let mut new_evals = vec![K::zero(); self.evaluations.len()];
        
        for old_idx in 0..self.evaluations.len() {
            let old_bits = Self::index_to_bits(old_idx, self.num_vars);
            let mut new_bits = vec![false; self.num_vars];
            
            for (new_pos, &old_pos) in permutation.iter().enumerate() {
                new_bits[new_pos] = old_bits[old_pos];
            }
            
            let new_idx = Self::bits_to_index(&new_bits);
            new_evals[new_idx] = self.evaluations[old_idx];
        }
        
        Ok(Self {
            evaluations: new_evals,
            num_vars: self.num_vars,
        })
    }
    
    /// Bind multiple variables at once
    pub fn bind_variables(&self, values: &[(usize, K)]) -> Result<Self, String> {
        let mut result = self.clone();
        
        // Sort by variable index in descending order to maintain correct indexing
        let mut sorted_values = values.to_vec();
        sorted_values.sort_by(|a, b| b.0.cmp(&a.0));
        
        for (var_idx, value) in sorted_values {
            if var_idx >= result.num_vars {
                return Err(format!("Variable index {} out of bounds", var_idx));
            }
            
            // Relabel to bring variable to front, then partial eval
            let mut perm: Vec<usize> = (0..result.num_vars).collect();
            perm.swap(0, var_idx);
            
            result = result.relabel(&perm)?;
            result = result.partial_eval(value)?;
            
            // Relabel back (if needed for remaining variables)
            if result.num_vars > 0 {
                let mut inv_perm: Vec<usize> = (0..result.num_vars).collect();
                if var_idx < result.num_vars {
                    inv_perm.insert(var_idx, 0);
                    inv_perm.remove(0);
                }
            }
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M61Field, Field};
    use crate::field::extension_framework::M61ExtensionField2;
    
    type K = M61ExtensionField2;
    
    fn make_test_poly(n: usize) -> MultilinearPolynomial<K> {
        let size = 1 << n;
        let evals: Vec<K> = (0..size)
            .map(|i| {
                K::from_base_field_element(M61Field::from_u64(i as u64), 0)
            })
            .collect();
        MultilinearPolynomial::from_evaluations(evals).unwrap()
    }
    
    #[test]
    fn test_from_evaluations_power_of_two() {
        let evals = vec![K::zero(); 16];
        let poly = MultilinearPolynomial::from_evaluations(evals);
        assert!(poly.is_ok());
        assert_eq!(poly.unwrap().num_vars, 4);
    }
    
    #[test]
    fn test_from_evaluations_not_power_of_two() {
        let evals = vec![K::zero(); 15];
        let poly = MultilinearPolynomial::from_evaluations(evals);
        assert!(poly.is_err());
    }
    
    #[test]
    fn test_index_to_bits() {
        let bits = MultilinearPolynomial::<K>::index_to_bits(5, 4);
        assert_eq!(bits, vec![true, false, true, false]); // 0101 in binary
        
        let bits = MultilinearPolynomial::<K>::index_to_bits(10, 4);
        assert_eq!(bits, vec![false, true, false, true]); // 1010 in binary
    }
    
    #[test]
    fn test_bits_to_index() {
        let idx = MultilinearPolynomial::<K>::bits_to_index(&[true, false, true, false]);
        assert_eq!(idx, 5);
        
        let idx = MultilinearPolynomial::<K>::bits_to_index(&[false, true, false, true]);
        assert_eq!(idx, 10);
    }
    
    #[test]
    fn test_eq_polynomial() {
        let r = vec![
            K::from_base_field_element(M61Field::from_u64(3), 0),
            K::from_base_field_element(M61Field::from_u64(5), 0),
        ];
        let x = vec![true, false];
        
        let eq_val = MultilinearPolynomial::<K>::eq_polynomial(&r, &x);
        
        // eq(r, x) = r[0] * (1 - r[1])
        let expected = r[0].mul(&K::one().sub(&r[1]));
        assert_eq!(eq_val, expected);
    }
    
    #[test]
    fn test_eq_polynomial_identity() {
        // eq(x, x) = 1 for x ∈ {0,1}^n
        let x_bits = vec![true, false, true];
        let x_field: Vec<K> = x_bits.iter()
            .map(|&b| if b { K::one() } else { K::zero() })
            .collect();
        
        let eq_val = MultilinearPolynomial::<K>::eq_polynomial(&x_field, &x_bits);
        assert_eq!(eq_val, K::one());
    }
    
    #[test]
    fn test_partial_eval() {
        let poly = make_test_poly(3);
        let r_0 = K::from_base_field_element(M61Field::from_u64(7), 0);
        
        let partial = poly.partial_eval(r_0).unwrap();
        assert_eq!(partial.num_vars, 2);
        assert_eq!(partial.evaluations.len(), 4);
    }
    
    #[test]
    fn test_evaluate_at_boolean() {
        let poly = make_test_poly(3);
        
        let point = vec![true, false, true];
        let eval = poly.eval_at_boolean(&point).unwrap();
        
        // Should equal evaluations[5] (binary 101 = 5)
        assert_eq!(eval, poly.evaluations[5]);
    }
    
    #[test]
    fn test_evaluate_lagrange() {
        let poly = make_test_poly(2);
        
        // Evaluate at a Boolean point
        let point = vec![K::one(), K::zero()];
        let eval = poly.evaluate(&point).unwrap();
        
        // Should equal evaluation at (1, 0) which is index 1
        assert_eq!(eval, poly.evaluations[1]);
    }
    
    #[test]
    fn test_mle_uniqueness() {
        let poly1 = make_test_poly(3);
        let poly2 = make_test_poly(3);
        
        assert!(poly1.verify_uniqueness(&poly2));
        
        // Create different polynomial
        let mut evals = poly1.evaluations.clone();
        evals[0] = evals[0].add(&K::one());
        let poly3 = MultilinearPolynomial::from_evaluations(evals).unwrap();
        
        assert!(!poly1.verify_uniqueness(&poly3));
    }
    
    #[test]
    fn test_add_polynomials() {
        let poly1 = make_test_poly(2);
        let poly2 = make_test_poly(2);
        
        let sum = poly1.add(&poly2).unwrap();
        
        for i in 0..sum.evaluations.len() {
            let expected = poly1.evaluations[i].add(&poly2.evaluations[i]);
            assert_eq!(sum.evaluations[i], expected);
        }
    }
    
    #[test]
    fn test_mul_polynomials() {
        let poly1 = make_test_poly(2);
        let poly2 = make_test_poly(2);
        
        let product = poly1.mul(&poly2).unwrap();
        
        for i in 0..product.evaluations.len() {
            let expected = poly1.evaluations[i].mul(&poly2.evaluations[i]);
            assert_eq!(product.evaluations[i], expected);
        }
    }
    
    #[test]
    fn test_scalar_mul() {
        let poly = make_test_poly(2);
        let scalar = K::from_base_field_element(M61Field::from_u64(3), 0);
        
        let result = poly.scalar_mul(scalar);
        
        for i in 0..result.evaluations.len() {
            let expected = poly.evaluations[i].mul(&scalar);
            assert_eq!(result.evaluations[i], expected);
        }
    }
    
    #[test]
    fn test_zero_polynomial() {
        let poly = MultilinearPolynomial::<K>::zero(3);
        
        assert_eq!(poly.num_vars, 3);
        assert_eq!(poly.evaluations.len(), 8);
        assert!(poly.evaluations.iter().all(|&x| x == K::zero()));
    }
    
    #[test]
    fn test_constant_polynomial() {
        let value = K::from_base_field_element(M61Field::from_u64(42), 0);
        let poly = MultilinearPolynomial::<K>::constant(value, 3);
        
        assert_eq!(poly.num_vars, 3);
        assert!(poly.evaluations.iter().all(|&x| x == value));
    }
    
    #[test]
    fn test_partial_eval_consistency() {
        let poly = make_test_poly(4);
        let r = vec![
            K::from_base_field_element(M61Field::from_u64(3), 0),
            K::from_base_field_element(M61Field::from_u64(5), 0),
            K::from_base_field_element(M61Field::from_u64(7), 0),
            K::from_base_field_element(M61Field::from_u64(11), 0),
        ];
        
        // Evaluate directly
        let direct_eval = poly.evaluate(&r).unwrap();
        
        // Evaluate via partial evaluations
        let mut partial = poly.clone();
        for &r_i in &r {
            partial = partial.partial_eval(r_i).unwrap();
        }
        
        // After all partial evals, should have 0 variables and 1 evaluation
        assert_eq!(partial.num_vars, 0);
        assert_eq!(partial.evaluations.len(), 1);
        assert_eq!(partial.evaluations[0], direct_eval);
    }
}
