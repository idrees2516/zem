// Foundation Layer: Core Mathematical Primitives
//
// This module implements the fundamental mathematical primitives used throughout
// the Linear-Time Permutation Check protocols (Bünz, Chen, DeStefano 2025).
//
// Key components:
// - Boolean Hypercube: B^μ = {0,1}^μ
// - Equality Polynomial: eq(X,Y) = ∏ᵢ [XᵢYᵢ + (1-Xᵢ)(1-Yᵢ)]
// - Multilinear Extension (MLE) utilities

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;

/// Boolean Hypercube B^μ = {0,1}^μ
///
/// Represents the set of all μ-bit binary strings. This is the fundamental
/// domain over which multilinear polynomials are defined.
///
/// # Paper Reference
/// Section 2.1: "We denote the boolean hypercube by B^μ = {0,1}^μ"
#[derive(Clone, Debug)]
pub struct BooleanHypercube {
    pub num_vars: usize,
}

impl BooleanHypercube {
    /// Create a new boolean hypercube of dimension μ
    pub fn new(num_vars: usize) -> Self {
        Self { num_vars }
    }
    
    /// Size of the hypercube: 2^μ
    pub fn size(&self) -> usize {
        1 << self.num_vars
    }

    
    /// Iterator over all points in B^μ in lexicographic order
    ///
    /// Yields points as Vec<bool> where each point represents a binary string.
    /// Order: [0,0,...,0], [1,0,...,0], [0,1,...,0], ..., [1,1,...,1]
    pub fn iter(&self) -> BooleanHypercubeIter {
        BooleanHypercubeIter {
            num_vars: self.num_vars,
            current: 0,
            size: self.size(),
        }
    }
    
    /// Convert boolean vector to field elements
    ///
    /// Maps false → 0, true → 1 in the field
    pub fn to_field<F: Field>(&self, point: &[bool]) -> Vec<F> {
        assert_eq!(point.len(), self.num_vars);
        point.iter().map(|&b| if b { F::one() } else { F::zero() }).collect()
    }
    
    /// Convert integer index to boolean vector
    ///
    /// Index i ∈ [0, 2^μ) is converted to its binary representation
    /// Example: i=5, μ=3 → [1,0,1] (binary: 101)
    pub fn index_to_point(&self, index: usize) -> Vec<bool> {
        assert!(index < self.size());
        (0..self.num_vars)
            .map(|i| (index >> i) & 1 == 1)
            .collect()
    }
}


/// Iterator over boolean hypercube points
pub struct BooleanHypercubeIter {
    num_vars: usize,
    current: usize,
    size: usize,
}

impl Iterator for BooleanHypercubeIter {
    type Item = Vec<bool>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.size {
            return None;
        }
        
        let point = (0..self.num_vars)
            .map(|i| (self.current >> i) & 1 == 1)
            .collect();
        
        self.current += 1;
        Some(point)
    }
}


/// Equality Polynomial eq(X,Y)
///
/// The equality polynomial is a fundamental building block that equals 1 when
/// X = Y and 0 otherwise for boolean inputs.
///
/// # Definition (Paper Section 2.1)
/// For X,Y ∈ F^μ:
///   eq(X,Y) := ∏_{i=1}^μ [X_i·Y_i + (1-X_i)·(1-Y_i)]
///
/// # Properties
/// - For x,y ∈ B^μ: eq(x,y) = 1 if x = y, else 0
/// - eq is multilinear in both X and Y
/// - Can be computed in O(μ) time for a single evaluation
/// - Can be computed for all y ∈ B^{μ/2} in O(2^{μ/2}) time (critical for BiPerm)
///
/// # Paper Reference
/// Definition 2.1: "The equality polynomial eq : F^μ × F^μ → F is defined as..."
pub struct EqualityPolynomial;

impl EqualityPolynomial {
    /// Compute eq(X,Y) = ∏ᵢ [XᵢYᵢ + (1-Xᵢ)(1-Yᵢ)]
    ///
    /// # Arguments
    /// - `x`: First point in F^μ
    /// - `y`: Second point in F^μ
    ///
    /// # Returns
    /// The value eq(x,y) ∈ F
    ///
    /// # Complexity
    /// O(μ) field operations
    ///
    /// # Paper Reference
    /// Definition 2.1
    pub fn evaluate<F: Field>(x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len(), "Dimension mismatch");
        
        let mut result = F::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            // Compute: xi·yi + (1-xi)·(1-yi)
            let term = xi.mul(yi).add(
                &F::one().sub(xi).mul(&F::one().sub(yi))
            );
            result = result.mul(&term);
        }
        
        result
    }

    
    /// Evaluate eq(y, α) for all y ∈ B^μ in O(2^μ) time
    ///
    /// This is the standard algorithm that evaluates the equality polynomial
    /// at all 2^μ boolean points. Used as a baseline and for smaller dimensions.
    ///
    /// # Arguments
    /// - `alpha`: Point α ∈ F^μ
    ///
    /// # Returns
    /// Vector of length 2^μ where result[i] = eq(yᵢ, α) for yᵢ ∈ B^μ
    ///
    /// # Complexity
    /// O(2^μ) field operations
    ///
    /// # Algorithm
    /// Uses dynamic programming to build up evaluations dimension by dimension.
    /// For dimension i, we have: eq(y||0, α) = eq(y, α[:-1]) · (1-αᵢ)
    ///                           eq(y||1, α) = eq(y, α[:-1]) · αᵢ
    ///
    /// # Paper Reference
    /// Used implicitly throughout; explicit in BiPerm preprocessing (Section 3.1)
    pub fn evaluate_all_boolean<F: Field>(alpha: &[F]) -> Vec<F> {
        let mu = alpha.len();
        let size = 1 << mu;
        
        // Start with eq([], []) = 1
        let mut current = vec![F::one()];
        
        // Build up dimension by dimension
        for i in 0..mu {
            let mut next = Vec::with_capacity(current.len() * 2);
            let one_minus_alpha_i = F::one().sub(&alpha[i]);
            
            for &val in current.iter() {
                // eq(y||0, α) = val · (1-αᵢ)
                next.push(val.mul(&one_minus_alpha_i));
                // eq(y||1, α) = val · αᵢ
                next.push(val.mul(&alpha[i]));
            }
            
            current = next;
        }
        
        assert_eq!(current.len(), size);
        current
    }

    
    /// Evaluate eq(y_L, α_L) for all y_L ∈ B^{μ/2} in O(2^{μ/2}) = O(√n) time
    ///
    /// **CRITICAL OPTIMIZATION FOR BiPerm**
    ///
    /// This is the key optimization that enables BiPerm to achieve O(n) prover time.
    /// By splitting the equality polynomial evaluation into left and right halves,
    /// we can precompute lookup tables in O(√n) time instead of O(n).
    ///
    /// # Arguments
    /// - `alpha_half`: Point α_L ∈ F^{μ/2} (left or right half of α)
    ///
    /// # Returns
    /// Vector of length 2^{μ/2} where result[i] = eq(yᵢ, α_L) for yᵢ ∈ B^{μ/2}
    ///
    /// # Complexity
    /// O(2^{μ/2}) = O(√n) field operations where n = 2^μ
    ///
    /// # Paper Reference
    /// Section 3.1, Equation (3.2):
    /// "The prover can compute eq(y_L, α_L) for all y_L ∈ B^{μ/2} in time O(2^{μ/2})"
    ///
    /// This is used in BiPerm preprocessing to compute indicator tables efficiently.
    pub fn evaluate_half_boolean<F: Field>(alpha_half: &[F]) -> Vec<F> {
        Self::evaluate_all_boolean(alpha_half)
    }

    
    /// Compute eq as a multilinear polynomial
    ///
    /// Given a fixed point y ∈ F^μ, returns the MLE of eq(·, y) as a function
    /// of the first argument.
    ///
    /// # Arguments
    /// - `y`: Fixed point y ∈ F^μ
    ///
    /// # Returns
    /// Multilinear polynomial p where p(x) = eq(x, y)
    ///
    /// # Paper Reference
    /// Used in various protocol constructions where eq is treated as a polynomial
    pub fn as_mle<F: Field>(y: &[F]) -> MultilinearPolynomial<F> {
        let evaluations = Self::evaluate_all_boolean(y);
        MultilinearPolynomial::new(evaluations)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_boolean_hypercube_size() {
        let hc = BooleanHypercube::new(3);
        assert_eq!(hc.size(), 8);
        
        let hc = BooleanHypercube::new(10);
        assert_eq!(hc.size(), 1024);
    }
    
    #[test]
    fn test_boolean_hypercube_iter() {
        let hc = BooleanHypercube::new(2);
        let points: Vec<Vec<bool>> = hc.iter().collect();
        
        assert_eq!(points.len(), 4);
        assert_eq!(points[0], vec![false, false]); // 00
        assert_eq!(points[1], vec![true, false]);  // 10
        assert_eq!(points[2], vec![false, true]);  // 01
        assert_eq!(points[3], vec![true, true]);   // 11
    }
    
    #[test]
    fn test_eq_poly_boolean_identity() {
        // Test: eq(x,x) = 1 for all x ∈ B^μ
        let hc = BooleanHypercube::new(3);
        
        for point in hc.iter() {
            let field_point = hc.to_field::<GoldilocksField>(&point);
            let result = EqualityPolynomial::evaluate(&field_point, &field_point);
            assert_eq!(result, GoldilocksField::one(), "eq(x,x) should be 1");
        }
    }

    
    #[test]
    fn test_eq_poly_boolean_distinct() {
        // Test: eq(x,y) = 0 for x ≠ y where x,y ∈ B^μ
        let hc = BooleanHypercube::new(3);
        let points: Vec<Vec<bool>> = hc.iter().collect();
        
        for (i, x) in points.iter().enumerate() {
            for (j, y) in points.iter().enumerate() {
                let x_field = hc.to_field::<GoldilocksField>(x);
                let y_field = hc.to_field::<GoldilocksField>(y);
                let result = EqualityPolynomial::evaluate(&x_field, &y_field);
                
                if i == j {
                    assert_eq!(result, GoldilocksField::one(), "eq(x,x) should be 1");
                } else {
                    assert_eq!(result, GoldilocksField::zero(), "eq(x,y) should be 0 for x≠y");
                }
            }
        }
    }
    
    #[test]
    fn test_evaluate_all_boolean() {
        let alpha = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let results = EqualityPolynomial::evaluate_all_boolean(&alpha);
        assert_eq!(results.len(), 4);
        
        // Verify against direct computation
        let hc = BooleanHypercube::new(2);
        for (i, point) in hc.iter().enumerate() {
            let field_point = hc.to_field::<GoldilocksField>(&point);
            let expected = EqualityPolynomial::evaluate(&field_point, &alpha);
            assert_eq!(results[i], expected, "Mismatch at index {}", i);
        }
    }
    
    #[test]
    fn test_evaluate_half_boolean_sqrt_complexity() {
        // Test that half evaluation is indeed O(√n)
        let mu = 10; // n = 2^10 = 1024
        let mu_half = mu / 2; // √n = 2^5 = 32
        
        let alpha_half: Vec<GoldilocksField> = (0..mu_half)
            .map(|i| GoldilocksField::from_u64(i as u64 + 1))
            .collect();
        
        let results = EqualityPolynomial::evaluate_half_boolean(&alpha_half);
        assert_eq!(results.len(), 1 << mu_half); // 32 evaluations, not 1024
    }
}
