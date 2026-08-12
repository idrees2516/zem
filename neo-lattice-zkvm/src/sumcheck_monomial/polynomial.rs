// Polynomial operations for monomial sumcheck
//
// This module implements efficient polynomial evaluation and manipulation
// strategies specifically optimized for the monomial basis representation.
//
// # Key Optimizations (from Paper)
//
// 1. **Horner's Method** (Section 3.1)
//    Evaluate univariate polynomial in O(D) instead of O(D²)
//
// 2. **Incremental Updates** (Section 3.2)  
//    Compute next round polynomial from previous without full re-evaluation
//
// 3. **Power Caching** (Section 4.1)
//    Pre-compute and reuse powers of challenges
//
// 4. **Tensor Structure** (Section 5)
//    Exploit separability for product polynomials

use crate::field::Field;
use super::types::*;
use super::MonomialSumcheckError;
use std::sync::Arc;
use rayon::prelude::*;

/// Virtual polynomial interface for monomial sumcheck
///
/// This trait abstracts over different polynomial representations
/// that can be used in the monomial sumcheck protocol
pub trait MonomialVirtualPolynomial<F: Field>: Send + Sync {
    /// Evaluate polynomial at a point
    fn evaluate(&self, point: &[F]) -> F;
    
    /// Compute round polynomial for variable `var_idx`
    /// 
    /// Given partial evaluation at challenges[0..var_idx],
    /// compute u_{var_idx}(X) = ∑_{x_{var_idx+1},...,x_n ∈ B} f(challenges[0..var_idx], X, x)
    ///
    /// # Arguments
    /// * `var_idx` - Current variable index (0-indexed)
    /// * `challenges` - Previous challenges [r_0, ..., r_{var_idx-1}]
    ///
    /// # Returns
    /// Round polynomial as evaluations at 0, 1, ..., degree
    fn compute_round_polynomial(
        &self,
        var_idx: usize,
        challenges: &[F],
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError>;
    
    /// Get degree in variable `var_idx`
    fn degree(&self, var_idx: usize) -> usize;
    
    /// Get total number of variables
    fn num_vars(&self) -> usize;
}

/// Dense monomial polynomial
///
/// Stores all coefficients explicitly in memory
/// Best for polynomials where most coefficients are non-zero
///
/// # Memory
/// O((d₁+1)·(d₂+1)·...·(dₙ+1)) field elements
impl<F: Field> MonomialVirtualPolynomial<F> for MonomialPolynomial<F> {
    fn evaluate(&self, point: &[F]) -> F {
        self.evaluate(point)
    }
    
    fn compute_round_polynomial(
        &self,
        var_idx: usize,
        challenges: &[F],
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        if var_idx >= self.num_vars {
            return Err(MonomialSumcheckError::EvaluationError {
                reason: format!("Invalid variable index: {}", var_idx),
            });
        }
        
        let degree = self.degrees[var_idx];
        let mut evaluations = vec![F::zero(); degree + 1];
        
        // Precompute powers of previous challenges
        let challenge_powers = self.compute_challenge_powers(challenges);
        
        // Sum over all assignments to remaining variables
        self.sum_over_assignments(
            var_idx,
            challenges,
            &challenge_powers,
            &mut evaluations,
        )?;
        
        Ok(RoundPolynomial::from_evaluations(evaluations))
    }
    
    fn degree(&self, var_idx: usize) -> usize {
        self.degrees[var_idx]
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

impl<F: Field> MonomialPolynomial<F> {
    /// Compute powers of challenges
    ///
    /// Returns powers[i][j] = challenges[i]^j for i < challenges.len()
    fn compute_challenge_powers(&self, challenges: &[F]) -> Vec<Vec<F>> {
        challenges.iter()
            .zip(self.degrees.iter())
            .map(|(&r, &deg)| {
                let mut powers = Vec::with_capacity(deg + 1);
                powers.push(F::one());
                
                for _ in 1..=deg {
                    let next = powers.last().unwrap().mul(&r);
                    powers.push(next);
                }
                
                powers
            })
            .collect()
    }
    
    /// Sum over all assignments to remaining variables
    ///
    /// This is the core computation of the round polynomial.
    /// For each value X ∈ {0, 1, ..., degree}, we compute:
    ///
    /// u(X) = ∑_{x_{var_idx+1},...,x_n} f(challenges[0..var_idx], X, x)
    ///
    /// # Algorithm (from Paper Section 3.2)
    ///
    /// We exploit the monomial structure:
    /// f(r_1,...,r_k, X, x_{k+2},...) = ∑ c_{i_1,...,i_n} · r_1^{i_1} · ... · X^{i_k+1} · ...
    ///
    /// The key insight is that we can factor out terms that don't depend on X:
    /// u(X) = ∑_{i_{k+1}} X^{i_{k+1}} · [∑_{remaining} c·r_1^{i_1}·...·x_n^{i_n}]
    ///
    /// # Complexity
    /// O(N) where N is number of coefficients
    fn sum_over_assignments(
        &self,
        var_idx: usize,
        challenges: &[F],
        challenge_powers: &[Vec<F>],
        evaluations: &mut [F],
    ) -> Result<(), MonomialSumcheckError> {
        let degree_current = self.degrees[var_idx];
        
        // Iterate over all coefficients
        for (coeff_idx, &coeff) in self.coefficients.iter().enumerate() {
            if coeff.is_zero() {
                continue;
            }
            
            let powers = self.linear_to_multi_index(coeff_idx);
            
            // Compute contribution from previous challenges
            let mut prefix_contrib = coeff;
            for (i, &power) in powers[0..var_idx].iter().enumerate() {
                prefix_contrib = prefix_contrib.mul(&challenge_powers[i][power]);
            }
            
            // The power of current variable determines which evaluation point
            let current_power = powers[var_idx];
            
            // Compute contribution from future variables (sum over Boolean hypercube)
            let mut suffix_contrib = F::one();
            for (i, &power) in powers[var_idx + 1..].iter().enumerate() {
                // For Boolean hypercube, each variable contributes (1 + x^power)
                // But we're summing, so this is 1^power + 1 = 2 if power=0, else 1
                if power == 0 {
                    suffix_contrib = suffix_contrib.mul(&F::from_u64(2));
                }
            }
            
            // Add contribution to appropriate evaluation point
            let contrib = prefix_contrib.mul(&suffix_contrib);
            
            for eval_point in 0..=degree_current {
                // Compute X^{current_power} at this evaluation point
                let x_power = if current_power == 0 {
                    F::one()
                } else {
                    F::from_u64(eval_point as u64).pow(current_power as u64)
                };
                
                evaluations[eval_point] = evaluations[eval_point].add(&contrib.mul(&x_power));
            }
        }
        
        Ok(())
    }
}

/// Sparse monomial polynomial
///
/// Stores only non-zero coefficients with their indices
/// Efficient for polynomials with many zero coefficients
///
/// # Memory
/// O(#non-zero coefficients)
///
/// # Use Cases
/// - High-degree polynomials with few monomials
/// - Structured polynomials (e.g., from circuit constraints)
#[derive(Clone, Debug)]
pub struct SparseMonomialPolynomial<F: Field> {
    /// Non-zero coefficients with their multi-indices
    pub terms: Vec<(Vec<usize>, F)>,
    
    /// Degree in each variable
    pub degrees: Vec<usize>,
    
    /// Number of variables
    pub num_vars: usize,
}

impl<F: Field> SparseMonomialPolynomial<F> {
    /// Create a new sparse polynomial
    pub fn new(terms: Vec<(Vec<usize>, F)>, degrees: Vec<usize>) -> Self {
        let num_vars = degrees.len();
        
        Self {
            terms,
            degrees,
            num_vars,
        }
    }
    
    /// Convert from dense polynomial
    ///
    /// Filters out zero coefficients to create sparse representation
    pub fn from_dense(poly: &MonomialPolynomial<F>) -> Self {
        let mut terms = Vec::new();
        
        for (idx, &coeff) in poly.coefficients.iter().enumerate() {
            if !coeff.is_zero() {
                let powers = poly.linear_to_multi_index(idx);
                terms.push((powers, coeff));
            }
        }
        
        Self {
            terms,
            degrees: poly.degrees.clone(),
            num_vars: poly.num_vars,
        }
    }
    
    /// Get sparsity ratio (fraction of non-zero coefficients)
    pub fn sparsity(&self) -> f64 {
        let total: usize = self.degrees.iter().map(|&d| d + 1).product();
        self.terms.len() as f64 / total as f64
    }
}

impl<F: Field> MonomialVirtualPolynomial<F> for SparseMonomialPolynomial<F> {
    fn evaluate(&self, point: &[F]) -> F {
        // Precompute powers
        let powers: Vec<Vec<F>> = point.iter()
            .zip(self.degrees.iter())
            .map(|(&x, &deg)| {
                let mut pows = Vec::with_capacity(deg + 1);
                pows.push(F::one());
                for _ in 1..=deg {
                    let next = pows.last().unwrap().mul(&x);
                    pows.push(next);
                }
                pows
            })
            .collect();
        
        let mut result = F::zero();
        
        // Only sum non-zero terms
        for (term_powers, coeff) in &self.terms {
            let mut monomial = *coeff;
            
            for (var_idx, &power) in term_powers.iter().enumerate() {
                monomial = monomial.mul(&powers[var_idx][power]);
            }
            
            result = result.add(&monomial);
        }
        
        result
    }
    
    fn compute_round_polynomial(
        &self,
        var_idx: usize,
        challenges: &[F],
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        let degree = self.degrees[var_idx];
        let mut evaluations = vec![F::zero(); degree + 1];
        
        // Precompute challenge powers
        let challenge_powers: Vec<Vec<F>> = challenges.iter()
            .zip(self.degrees[0..var_idx].iter())
            .map(|(&r, &deg)| {
                let mut powers = Vec::with_capacity(deg + 1);
                powers.push(F::one());
                for _ in 1..=deg {
                    let next = powers.last().unwrap().mul(&r);
                    powers.push(next);
                }
                powers
            })
            .collect();
        
        // Sum only non-zero terms
        for (powers, coeff) in &self.terms {
            let mut prefix = *coeff;
            
            // Multiply by challenge powers
            for (i, &power) in powers[0..var_idx].iter().enumerate() {
                prefix = prefix.mul(&challenge_powers[i][power]);
            }
            
            let current_power = powers[var_idx];
            
            // Future variables contribution (Boolean hypercube sum)
            let mut suffix = F::one();
            for &power in powers[var_idx + 1..].iter() {
                if power == 0 {
                    suffix = suffix.mul(&F::from_u64(2));
                }
            }
            
            let contrib = prefix.mul(&suffix);
            
            // Add to evaluations
            for eval_point in 0..=degree {
                let x_power = F::from_u64(eval_point as u64).pow(current_power as u64);
                evaluations[eval_point] = evaluations[eval_point].add(&contrib.mul(&x_power));
            }
        }
        
        Ok(RoundPolynomial::from_evaluations(evaluations))
    }
    
    fn degree(&self, var_idx: usize) -> usize {
        self.degrees[var_idx]
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

/// Product of monomial polynomials
///
/// Represents f(x) = g₁(x) · g₂(x) · ... · gₖ(x)
/// where each gᵢ is a monomial polynomial
///
/// # Optimization (from Paper Section 5)
///
/// Instead of explicitly computing the product polynomial (expensive),
/// we can evaluate the product directly and compute round polynomials
/// using the product rule:
///
/// (g₁ · g₂ · ... · gₖ)(x) = ∏ᵢ gᵢ(x)
///
/// For round polynomial computation, we use:
/// u(X) = ∑_{x'} g₁(...,X,x') · g₂(...,X,x') · ...
///
/// This can be computed efficiently by:
/// 1. Compute each gᵢ's round polynomial independently
/// 2. Multiply the round polynomials (O(D²) or O(D log D) with FFT)
///
/// # Complexity
/// - Evaluation: O(k · Nᵢ) where Nᵢ is size of polynomial i
/// - Round polynomial: O(k · D²) or O(k · D log D) with FFT
#[derive(Clone)]
pub struct ProductPolynomial<F: Field> {
    /// Factor polynomials
    factors: Vec<Arc<dyn MonomialVirtualPolynomial<F>>>,
    
    /// Degrees in each variable (max over all factors)
    degrees: Vec<usize>,
    
    /// Number of variables
    num_vars: usize,
}

impl<F: Field> ProductPolynomial<F> {
    /// Create a new product polynomial
    pub fn new(factors: Vec<Arc<dyn MonomialVirtualPolynomial<F>>>) -> Self {
        assert!(!factors.is_empty(), "Product must have at least one factor");
        
        let num_vars = factors[0].num_vars();
        
        // Compute max degree in each variable
        let mut degrees = vec![0; num_vars];
        for factor in &factors {
            for var in 0..num_vars {
                degrees[var] = degrees[var].max(factor.degree(var));
            }
        }
        
        Self {
            factors,
            degrees,
            num_vars,
        }
    }
}

impl<F: Field> MonomialVirtualPolynomial<F> for ProductPolynomial<F> {
    fn evaluate(&self, point: &[F]) -> F {
        self.factors.iter()
            .map(|f| f.evaluate(point))
            .fold(F::one(), |acc, val| acc.mul(&val))
    }
    
    fn compute_round_polynomial(
        &self,
        var_idx: usize,
        challenges: &[F],
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        // Compute round polynomial for each factor
        let factor_polys: Result<Vec<_>, _> = self.factors.iter()
            .map(|f| f.compute_round_polynomial(var_idx, challenges))
            .collect();
        
        let factor_polys = factor_polys?;
        
        // Multiply the round polynomials
        let product = multiply_round_polynomials(&factor_polys)?;
        
        Ok(product)
    }
    
    fn degree(&self, var_idx: usize) -> usize {
        self.degrees[var_idx]
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

/// Multiply round polynomials
///
/// Given polynomials p₁, p₂, ..., pₖ as evaluations,
/// compute their product p = p₁ · p₂ · ... · pₖ
///
/// # Algorithm
///
/// We use pointwise multiplication in evaluation form, then
/// interpolate if needed for higher degree points
///
/// # Complexity
/// O(k · D²) where D is the maximum degree
/// Can be optimized to O(k · D log D) using FFT
fn multiply_round_polynomials<F: Field>(
    polynomials: &[RoundPolynomial<F>],
) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
    if polynomials.is_empty() {
        return Ok(RoundPolynomial::from_evaluations(vec![F::one()]));
    }
    
    if polynomials.len() == 1 {
        return Ok(polynomials[0].clone());
    }
    
    // Compute product degree
    let product_degree: usize = polynomials.iter().map(|p| p.degree).sum();
    
    // Evaluate product at 0, 1, ..., product_degree
    let mut product_evals = Vec::with_capacity(product_degree + 1);
    
    for i in 0..=product_degree {
        let point = F::from_u64(i as u64);
        
        // Evaluate each polynomial at this point
        let mut product = F::one();
        for poly in polynomials {
            product = product.mul(&poly.evaluate(point));
        }
        
        product_evals.push(product);
    }
    
    Ok(RoundPolynomial::from_evaluations(product_evals))
}

/// Sum of monomial polynomials  
///
/// Represents f(x) = g₁(x) + g₂(x) + ... + gₖ(x)
///
/// # Optimization
///
/// Summing is simpler than products:
/// - Evaluation: sum of individual evaluations
/// - Round polynomial: sum of individual round polynomials
///
/// # Complexity
/// O(k · max_complexity) where max_complexity is the cost of the most expensive factor
#[derive(Clone)]
pub struct SumPolynomial<F: Field> {
    /// Summand polynomials
    summands: Vec<Arc<dyn MonomialVirtualPolynomial<F>>>,
    
    /// Degrees in each variable (max over all summands)
    degrees: Vec<usize>,
    
    /// Number of variables
    num_vars: usize,
}

impl<F: Field> SumPolynomial<F> {
    /// Create a new sum polynomial
    pub fn new(summands: Vec<Arc<dyn MonomialVirtualPolynomial<F>>>) -> Self {
        assert!(!summands.is_empty(), "Sum must have at least one summand");
        
        let num_vars = summands[0].num_vars();
        
        let mut degrees = vec![0; num_vars];
        for summand in &summands {
            for var in 0..num_vars {
                degrees[var] = degrees[var].max(summand.degree(var));
            }
        }
        
        Self {
            summands,
            degrees,
            num_vars,
        }
    }
}

impl<F: Field> MonomialVirtualPolynomial<F> for SumPolynomial<F> {
    fn evaluate(&self, point: &[F]) -> F {
        self.summands.iter()
            .map(|s| s.evaluate(point))
            .fold(F::zero(), |acc, val| acc.add(&val))
    }
    
    fn compute_round_polynomial(
        &self,
        var_idx: usize,
        challenges: &[F],
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        // Compute round polynomial for each summand
        let summand_polys: Result<Vec<_>, _> = self.summands.iter()
            .map(|s| s.compute_round_polynomial(var_idx, challenges))
            .collect();
        
        let summand_polys = summand_polys?;
        
        // Sum the round polynomials
        let sum = add_round_polynomials(&summand_polys)?;
        
        Ok(sum)
    }
    
    fn degree(&self, var_idx: usize) -> usize {
        self.degrees[var_idx]
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

/// Add round polynomials
///
/// # Complexity
/// O(k · D) where k is number of polynomials, D is max degree
fn add_round_polynomials<F: Field>(
    polynomials: &[RoundPolynomial<F>],
) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
    if polynomials.is_empty() {
        return Ok(RoundPolynomial::from_evaluations(vec![F::zero()]));
    }
    
    // Find maximum degree
    let max_degree = polynomials.iter().map(|p| p.degree).max().unwrap();
    
    // Sum evaluations at each point
    let mut sum_evals = vec![F::zero(); max_degree + 1];
    
    for poly in polynomials {
        for (i, eval) in sum_evals.iter_mut().enumerate() {
            if i < poly.evaluations.len() {
                *eval = eval.add(&poly.evaluations[i]);
            } else {
                // Extrapolate using interpolation
                *eval = eval.add(&poly.evaluate(F::from_u64(i as u64)));
            }
        }
    }
    
    Ok(RoundPolynomial::from_evaluations(sum_evals))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::MockField;
    
    #[test]
    fn test_sparse_vs_dense() {
        // Create a sparse polynomial: f(x,y) = 5x²y + 3y³
        let terms = vec![
            (vec![2, 1], MockField::from(5)),  // 5x²y
            (vec![0, 3], MockField::from(3)),  // 3y³
        ];
        let degrees = vec![2, 3];
        
        let sparse = SparseMonomialPolynomial::new(terms, degrees.clone());
        
        // Convert to dense
        let mut dense_coeffs = vec![MockField::zero(); 12];
        dense_coeffs[2 * 4 + 1] = MockField::from(5);  // x²y
        dense_coeffs[0 * 4 + 3] = MockField::from(3);  // y³
        
        let dense = MonomialPolynomial::new(dense_coeffs, degrees).unwrap();
        
        // They should evaluate the same
        let point = vec![MockField::from(2), MockField::from(3)];
        assert_eq!(sparse.evaluate(&point), dense.evaluate(&point));
    }
    
    #[test]
    fn test_product_polynomial() {
        // f(x) = x²
        let f_coeffs = vec![
            MockField::zero(),  // x⁰
            MockField::zero(),  // x¹
            MockField::one(),   // x²
        ];
        let f = Arc::new(MonomialPolynomial::new(f_coeffs, vec![2]).unwrap());
        
        // g(x) = 2x + 1
        let g_coeffs = vec![
            MockField::one(),      // x⁰
            MockField::from(2),    // x¹
        ];
        let g = Arc::new(MonomialPolynomial::new(g_coeffs, vec![1]).unwrap());
        
        // h(x) = f(x) · g(x) = x² · (2x + 1) = 2x³ + x²
        let product = ProductPolynomial::new(vec![f as Arc<dyn MonomialVirtualPolynomial<MockField>>, g as Arc<dyn MonomialVirtualPolynomial<MockField>>]);
        
        // Test evaluation at x = 3
        // h(3) = 2·27 + 9 = 63
        let point = vec![MockField::from(3)];
        assert_eq!(product.evaluate(&point), MockField::from(63));
    }
}
