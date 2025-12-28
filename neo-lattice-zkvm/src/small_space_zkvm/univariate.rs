// Univariate Polynomial Module for Small-Space zkVM
//
// This module implements univariate polynomials used in sum-check protocols.
// In sum-check, the prover sends univariate polynomials of degree ℓ (typically ≤ 3)
// in each round.
//
// Key Features:
// 1. Lagrange interpolation from evaluation points
// 2. Efficient interpolation for small degree (closed-form formulas)
// 3. Horner's method for evaluation
// 4. Polynomial arithmetic (addition, multiplication, scalar multiplication)
// 5. Degree computation
//
// References:
// - Paper Section 3.1: Sum-Check Protocol (Requirements 1.2, 1.14)
// - Tasks 4.1-4.6: Univariate polynomial operations

use crate::field::Field;

/// Univariate Polynomial
///
/// Represents a polynomial p(X) = a₀ + a₁X + a₂X² + ... + aₙXⁿ
/// by its coefficients [a₀, a₁, ..., aₙ].
///
/// In sum-check protocols, these polynomials typically have degree ℓ ≤ 3,
/// where ℓ is the number of multilinear polynomials being multiplied.
///
/// Reference: Requirements 1.2, 1.14, Task 4.1
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnivariatePolynomial<F: Field> {
    /// Coefficients [a₀, a₁, ..., aₙ] where aₙ ≠ 0 (unless zero polynomial)
    pub coefficients: Vec<F>,
}

impl<F: Field> UnivariatePolynomial<F> {
    /// Create polynomial from coefficients
    ///
    /// Coefficients are in ascending order: [a₀, a₁, ..., aₙ]
    pub fn new(coefficients: Vec<F>) -> Self {
        let mut poly = Self { coefficients };
        poly.trim_leading_zeros();
        poly
    }
    
    /// Create zero polynomial
    pub fn zero() -> Self {
        Self {
            coefficients: vec![F::zero()],
        }
    }
    
    /// Create constant polynomial
    pub fn constant(c: F) -> Self {
        Self {
            coefficients: vec![c],
        }
    }
    
    /// Create monomial: cX^degree
    pub fn monomial(c: F, degree: usize) -> Self {
        let mut coeffs = vec![F::zero(); degree + 1];
        coeffs[degree] = c;
        Self { coefficients: coeffs }
    }
    
    /// Lagrange interpolation
    ///
    /// Given points (x₀,y₀), (x₁,y₁), ..., (xₙ,yₙ), finds the unique polynomial
    /// of degree ≤ n that passes through all points.
    ///
    /// Uses Lagrange basis polynomials:
    ///   Lᵢ(x) = ∏_{j≠i} (x - xⱼ) / (xᵢ - xⱼ)
    ///   p(x) = Σᵢ yᵢ · Lᵢ(x)
    ///
    /// Time: O(n³) for general case
    /// Space: O(n²)
    ///
    /// Reference: Requirements 1.2, 1.14, Task 4.2
    pub fn interpolate(points: &[F], values: &[F]) -> Self {
        assert_eq!(points.len(), values.len(), "Points and values length mismatch");
        assert!(!points.is_empty(), "Cannot interpolate with no points");
        
        let n = points.len();
        
        if n == 1 {
            return Self::constant(values[0]);
        }
        
        // For small degree, use optimized formulas
        if n <= 3 {
            return Self::interpolate_small_degree(points, values);
        }
        
        // General Lagrange interpolation
        let mut result = Self::zero();
        
        for i in 0..n {
            // Compute Lagrange basis polynomial Lᵢ(x)
            let mut basis = Self::constant(F::one());
            let mut denominator = F::one();
            
            for j in 0..n {
                if i != j {
                    // Multiply by (X - xⱼ)
                    let linear = Self::new(vec![points[j].neg(), F::one()]);
                    basis = basis.mul(&linear);
                    
                    // Compute denominator: (xᵢ - xⱼ)
                    denominator = denominator.mul(&points[i].sub(&points[j]));
                }
            }
            
            // Scale by yᵢ / denominator
            let scale = values[i].mul(&denominator.inverse());
            basis = basis.scalar_mul(scale);
            
            result = result.add(&basis);
        }
        
        result
    }
    
    /// Efficient interpolation for small degree
    ///
    /// For degree 2 (sum-check with 3 evaluation points), uses closed-form formulas
    /// to avoid the overhead of general Lagrange interpolation.
    ///
    /// This is a significant optimization since sum-check typically uses degree 2 or 3.
    ///
    /// Reference: Requirements 1.2, 1.14, Task 4.3
    pub fn interpolate_small_degree(points: &[F], values: &[F]) -> Self {
        let n = points.len();
        
        match n {
            1 => Self::constant(values[0]),
            
            2 => {
                // Linear interpolation: p(x) = y₀ + (y₁-y₀)/(x₁-x₀) · (x-x₀)
                let x0 = points[0];
                let x1 = points[1];
                let y0 = values[0];
                let y1 = values[1];
                
                let slope = y1.sub(&y0).mul(&x1.sub(&x0).inverse());
                
                // p(x) = y₀ - slope·x₀ + slope·x
                let a0 = y0.sub(&slope.mul(&x0));
                let a1 = slope;
                
                Self::new(vec![a0, a1])
            }
            
            3 => {
                // Quadratic interpolation using closed-form formula
                // This is the most common case in sum-check (degree 2)
                let x0 = points[0];
                let x1 = points[1];
                let x2 = points[2];
                let y0 = values[0];
                let y1 = values[1];
                let y2 = values[2];
                
                // Compute denominators
                let d0 = (x0.sub(&x1)).mul(&x0.sub(&x2));
                let d1 = (x1.sub(&x0)).mul(&x1.sub(&x2));
                let d2 = (x2.sub(&x0)).mul(&x2.sub(&x1));
                
                // Compute coefficients using Lagrange formula
                // a₀ = Σᵢ yᵢ · ∏_{j≠i} xⱼ / dᵢ
                let a0 = y0.mul(&x1.mul(&x2)).mul(&d0.inverse())
                    .add(&y1.mul(&x0.mul(&x2)).mul(&d1.inverse()))
                    .add(&y2.mul(&x0.mul(&x1)).mul(&d2.inverse()));
                
                // a₁ = -Σᵢ yᵢ · (xⱼ + xₖ) / dᵢ  (j,k ≠ i)
                let a1 = y0.mul(&x1.add(&x2).neg()).mul(&d0.inverse())
                    .add(&y1.mul(&x0.add(&x2).neg()).mul(&d1.inverse()))
                    .add(&y2.mul(&x0.add(&x1).neg()).mul(&d2.inverse()));
                
                // a₂ = Σᵢ yᵢ / dᵢ
                let a2 = y0.mul(&d0.inverse())
                    .add(&y1.mul(&d1.inverse()))
                    .add(&y2.mul(&d2.inverse()));
                
                Self::new(vec![a0, a1, a2])
            }
            
            _ => {
                // Fall back to general Lagrange for degree > 2
                Self::interpolate(points, values)
            }
        }
    }
    
    /// Evaluate polynomial at point using Horner's method
    ///
    /// Evaluates p(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ
    /// using Horner's rule: p(x) = a₀ + x(a₁ + x(a₂ + ... + x·aₙ))
    ///
    /// This is more efficient than computing powers of x separately.
    ///
    /// Time: O(n) field operations
    /// Space: O(1)
    ///
    /// Reference: Requirements 1.2, 1.14, Task 4.4
    pub fn evaluate(&self, x: &F) -> F {
        if self.coefficients.is_empty() {
            return F::zero();
        }
        
        // Horner's method: start from highest degree
        let mut result = *self.coefficients.last().unwrap();
        
        for i in (0..self.coefficients.len() - 1).rev() {
            result = result.mul(x).add(&self.coefficients[i]);
        }
        
        result
    }
    
    /// Get degree of polynomial
    ///
    /// Returns the degree (highest non-zero coefficient).
    /// Zero polynomial has degree 0 by convention.
    ///
    /// Reference: Requirement 1.2, Task 4.5
    pub fn degree(&self) -> usize {
        if self.coefficients.is_empty() || self.is_zero() {
            return 0;
        }
        self.coefficients.len() - 1
    }
    
    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coefficients.is_empty() || 
        self.coefficients.iter().all(|c| c.is_zero())
    }
    
    /// Addition
    ///
    /// Computes p(x) + q(x) by adding coefficients.
    ///
    /// Reference: Requirement 1.2, Task 4.6
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut result = vec![F::zero(); max_len];
        
        for (i, c) in self.coefficients.iter().enumerate() {
            result[i] = result[i].add(c);
        }
        
        for (i, c) in other.coefficients.iter().enumerate() {
            result[i] = result[i].add(c);
        }
        
        Self::new(result)
    }
    
    /// Subtraction
    ///
    /// Computes p(x) - q(x) by subtracting coefficients.
    ///
    /// Reference: Requirement 1.2, Task 4.6
    pub fn sub(&self, other: &Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut result = vec![F::zero(); max_len];
        
        for (i, c) in self.coefficients.iter().enumerate() {
            result[i] = result[i].add(c);
        }
        
        for (i, c) in other.coefficients.iter().enumerate() {
            result[i] = result[i].sub(c);
        }
        
        Self::new(result)
    }
    
    /// Multiplication
    ///
    /// Computes p(x) · q(x) using convolution of coefficients.
    ///
    /// Time: O(n·m) where n, m are degrees
    ///
    /// Reference: Requirement 1.2, Task 4.6
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        
        let n = self.coefficients.len();
        let m = other.coefficients.len();
        let mut result = vec![F::zero(); n + m - 1];
        
        for i in 0..n {
            for j in 0..m {
                result[i + j] = result[i + j].add(&self.coefficients[i].mul(&other.coefficients[j]));
            }
        }
        
        Self::new(result)
    }
    
    /// Scalar multiplication
    ///
    /// Computes c · p(x) by multiplying all coefficients by c.
    ///
    /// Reference: Requirement 1.2, Task 4.6
    pub fn scalar_mul(&self, scalar: F) -> Self {
        let coeffs: Vec<F> = self.coefficients.iter()
            .map(|c| c.mul(&scalar))
            .collect();
        Self::new(coeffs)
    }
    
    /// Negation
    pub fn neg(&self) -> Self {
        self.scalar_mul(F::one().neg())
    }
    
    /// Trim leading zero coefficients
    fn trim_leading_zeros(&mut self) {
        while self.coefficients.len() > 1 && 
              self.coefficients.last().unwrap().is_zero() {
            self.coefficients.pop();
        }
        
        if self.coefficients.is_empty() {
            self.coefficients.push(F::zero());
        }
    }
    
    /// Batch evaluation at multiple points
    ///
    /// Evaluates p(x) at multiple points efficiently.
    pub fn batch_evaluate(&self, points: &[F]) -> Vec<F> {
        points.iter().map(|x| self.evaluate(x)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_constant_polynomial() {
        let p = UnivariatePolynomial::<GoldilocksField>::constant(
            GoldilocksField::from_u64(5)
        );
        
        assert_eq!(p.degree(), 0);
        assert_eq!(p.evaluate(&GoldilocksField::from_u64(10)).to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_linear_interpolation() {
        // Interpolate through (0, 1) and (1, 3)
        // Should get p(x) = 1 + 2x
        let points = vec![
            GoldilocksField::zero(),
            GoldilocksField::one(),
        ];
        let values = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(3),
        ];
        
        let p = UnivariatePolynomial::interpolate(&points, &values);
        
        assert_eq!(p.degree(), 1);
        assert_eq!(p.evaluate(&GoldilocksField::zero()).to_canonical_u64(), 1);
        assert_eq!(p.evaluate(&GoldilocksField::one()).to_canonical_u64(), 3);
        
        // Check p(2) = 1 + 2*2 = 5
        assert_eq!(p.evaluate(&GoldilocksField::from_u64(2)).to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_quadratic_interpolation() {
        // Interpolate through (0, 1), (1, 2), (2, 5)
        // Should get p(x) = 1 + 0·x + 1·x² = 1 + x²
        let points = vec![
            GoldilocksField::zero(),
            GoldilocksField::one(),
            GoldilocksField::from_u64(2),
        ];
        let values = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(5),
        ];
        
        let p = UnivariatePolynomial::interpolate(&points, &values);
        
        assert_eq!(p.degree(), 2);
        
        // Verify interpolation points
        for (point, value) in points.iter().zip(values.iter()) {
            assert_eq!(p.evaluate(point), *value);
        }
        
        // Check p(3) = 1 + 9 = 10
        assert_eq!(p.evaluate(&GoldilocksField::from_u64(3)).to_canonical_u64(), 10);
    }
    
    #[test]
    fn test_horner_evaluation() {
        // p(x) = 1 + 2x + 3x²
        let p = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ]);
        
        // p(5) = 1 + 2*5 + 3*25 = 1 + 10 + 75 = 86
        let result = p.evaluate(&GoldilocksField::from_u64(5));
        assert_eq!(result.to_canonical_u64(), 86);
    }
    
    #[test]
    fn test_polynomial_addition() {
        // p(x) = 1 + 2x
        let p = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ]);
        
        // q(x) = 3 + 4x
        let q = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ]);
        
        // (p+q)(x) = 4 + 6x
        let sum = p.add(&q);
        
        assert_eq!(sum.coefficients[0].to_canonical_u64(), 4);
        assert_eq!(sum.coefficients[1].to_canonical_u64(), 6);
    }
    
    #[test]
    fn test_polynomial_multiplication() {
        // p(x) = 1 + 2x
        let p = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ]);
        
        // q(x) = 3 + 4x
        let q = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ]);
        
        // (p·q)(x) = 3 + 10x + 8x²
        let product = p.mul(&q);
        
        assert_eq!(product.degree(), 2);
        assert_eq!(product.coefficients[0].to_canonical_u64(), 3);
        assert_eq!(product.coefficients[1].to_canonical_u64(), 10);
        assert_eq!(product.coefficients[2].to_canonical_u64(), 8);
    }
    
    #[test]
    fn test_scalar_multiplication() {
        // p(x) = 1 + 2x + 3x²
        let p = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ]);
        
        // 5·p(x) = 5 + 10x + 15x²
        let scaled = p.scalar_mul(GoldilocksField::from_u64(5));
        
        assert_eq!(scaled.coefficients[0].to_canonical_u64(), 5);
        assert_eq!(scaled.coefficients[1].to_canonical_u64(), 10);
        assert_eq!(scaled.coefficients[2].to_canonical_u64(), 15);
    }
    
    #[test]
    fn test_batch_evaluate() {
        // p(x) = 1 + x²
        let p = UnivariatePolynomial::new(vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::zero(),
            GoldilocksField::one(),
        ]);
        
        let points = vec![
            GoldilocksField::zero(),
            GoldilocksField::one(),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let results = p.batch_evaluate(&points);
        
        // p(0) = 1, p(1) = 2, p(2) = 5, p(3) = 10
        assert_eq!(results[0].to_canonical_u64(), 1);
        assert_eq!(results[1].to_canonical_u64(), 2);
        assert_eq!(results[2].to_canonical_u64(), 5);
        assert_eq!(results[3].to_canonical_u64(), 10);
    }
}
