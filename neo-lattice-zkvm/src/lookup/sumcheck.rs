// Sumcheck Protocol Implementation
//
// This module implements the sumcheck protocol, a fundamental building block for
// many zero-knowledge proof systems. The sumcheck protocol allows a prover to
// convince a verifier that a claimed sum over a Boolean hypercube is correct,
// reducing the verification to a single polynomial evaluation.
//
// # Mathematical Foundation
//
// Given an ℓ-variate polynomial g(X_1, ..., X_ℓ) over field F, the prover claims:
//   H = Σ_{b∈{0,1}^ℓ} g(b)
//
// The protocol reduces this claim to verifying g(r) at a random point r ∈ F^ℓ.
//
// # Protocol Flow
//
// For each variable X_i (i = 1 to ℓ):
// 1. Prover sends univariate polynomial g_i(X_i) = Σ_{b∈{0,1}^{ℓ-i}} g(r_1,...,r_{i-1},X_i,b)
// 2. Verifier checks: g_i(0) + g_i(1) = current_sum
// 3. Verifier samples random r_i ∈ F
// 4. Update current_sum = g_i(r_i)
//
// After ℓ rounds, verifier checks g(r_1, ..., r_ℓ) = final_sum
//
// # Complexity
//
// - Prover: O(2^ℓ) field operations per round, O(ℓ · 2^ℓ) total
// - Verifier: O(ℓ) field operations plus one evaluation of g
// - Communication: O(ℓ · d) field elements where d is the degree
//
// # Variants
//
// - Multilinear sumcheck: For multilinear polynomials (degree 1 in each variable)
// - Univariate sumcheck: For summation over subgroups
// - Sparse sumcheck: Optimized for sparse polynomials
// - Batched sumcheck: Combine multiple sumcheck instances
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876) and classical sumcheck literature

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Multivariate polynomial representation
///
/// Represents a polynomial g(X_1, ..., X_ℓ) by its evaluations over {0,1}^ℓ.
/// For a multilinear polynomial, this is the most natural representation.
#[derive(Debug, Clone)]
pub struct MultivariatePolynomial<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    /// Evaluations over Boolean hypercube {0,1}^num_vars
    /// Stored in lexicographic order: (0,0,...,0), (0,0,...,1), ..., (1,1,...,1)
    pub evaluations: Vec<F>,
}

impl<F: Field> MultivariatePolynomial<F> {
    /// Create a new multivariate polynomial from evaluations
    ///
    /// # Parameters
    ///
    /// - num_vars: Number of variables ℓ
    /// - evaluations: 2^ℓ evaluations over {0,1}^ℓ
    pub fn new(num_vars: usize, evaluations: Vec<F>) -> LookupResult<Self> {
        let expected_size = 1 << num_vars;
        if evaluations.len() != expected_size {
            return Err(LookupError::InvalidPolynomialSize {
                expected: expected_size,
                got: evaluations.len(),
            });
        }
        
        Ok(Self {
            num_vars,
            evaluations,
        })
    }
    
    /// Evaluate the polynomial at a point
    ///
    /// # Algorithm
    ///
    /// For multilinear polynomials, use the multilinear extension formula:
    /// g(r_1, ..., r_ℓ) = Σ_{b∈{0,1}^ℓ} g(b) · eq(r, b)
    ///
    /// where eq(r, b) = ∏_i (r_i · b_i + (1 - r_i) · (1 - b_i))
    ///
    /// # Complexity
    ///
    /// O(2^ℓ) field operations
    pub fn evaluate(&self, point: &[F]) -> LookupResult<F> {
        if point.len() != self.num_vars {
            return Err(LookupError::InvalidPointSize {
                expected: self.num_vars,
                got: point.len(),
            });
        }
        
        let mut result = F::zero();
        
        for (i, &eval) in self.evaluations.iter().enumerate() {
            // Convert index i to binary representation
            let binary = Self::index_to_binary(i, self.num_vars);
            
            // Compute eq(point, binary)
            let eq_value = Self::compute_eq(point, &binary);
            
            result = result + eval * eq_value;
        }
        
        Ok(result)
    }
    
    /// Convert index to binary representation
    ///
    /// # Algorithm
    ///
    /// Extract bits of i to get (b_1, ..., b_ℓ) where i = Σ b_j · 2^j
    fn index_to_binary(index: usize, num_vars: usize) -> Vec<F> {
        (0..num_vars)
            .map(|j| {
                if (index >> j) & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect()
    }
    
    /// Compute eq function: eq(x, e) = ∏_i (x_i · e_i + (1 - x_i) · (1 - e_i))
    ///
    /// # Algorithm
    ///
    /// For each coordinate i:
    /// - If e_i = 1: contribute x_i
    /// - If e_i = 0: contribute (1 - x_i)
    ///
    /// # Complexity
    ///
    /// O(ℓ) field operations
    fn compute_eq(x: &[F], e: &[F]) -> F {
        x.iter()
            .zip(e.iter())
            .map(|(&x_i, &e_i)| {
                if e_i == F::one() {
                    x_i
                } else {
                    F::one() - x_i
                }
            })
            .fold(F::one(), |acc, val| acc * val)
    }
    
    /// Compute the sum over the Boolean hypercube
    ///
    /// Returns Σ_{b∈{0,1}^ℓ} g(b)
    ///
    /// # Complexity
    ///
    /// O(2^ℓ) - just sum all evaluations
    pub fn sum_over_hypercube(&self) -> F {
        self.evaluations.iter().fold(F::zero(), |acc, &val| acc + val)
    }
}

/// Round polynomial in sumcheck protocol
///
/// Represents the univariate polynomial g_i(X_i) sent by the prover in round i.
#[derive(Debug, Clone, PartialEq)]
pub struct RoundPolynomial<F: Field> {
    /// Coefficients of the polynomial: g_i(X) = Σ c_j X^j
    pub coefficients: Vec<F>,
}

impl<F: Field> RoundPolynomial<F> {
    /// Create a new round polynomial
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }
    
    /// Evaluate the polynomial at a point
    ///
    /// # Algorithm
    ///
    /// Use Horner's method: g(x) = c_0 + x(c_1 + x(c_2 + ...))
    ///
    /// # Complexity
    ///
    /// O(d) where d is the degree
    pub fn evaluate(&self, x: F) -> F {
        self.coefficients
            .iter()
            .rev()
            .fold(F::zero(), |acc, &coeff| acc * x + coeff)
    }
    
    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }
}

/// Sumcheck proof
///
/// Contains the round polynomials sent by the prover.
#[derive(Debug, Clone)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials, one per variable
    pub round_polynomials: Vec<RoundPolynomial<F>>,
}

/// Sumcheck prover
///
/// Generates sumcheck proofs for polynomial summations.
#[derive(Debug)]
pub struct SumcheckProver<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> SumcheckProver<F> {
    /// Create a new sumcheck prover
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Generate a sumcheck proof
    ///
    /// # Algorithm
    ///
    /// For each round i = 1 to ℓ:
    /// 1. Compute g_i(X_i) = Σ_{b∈{0,1}^{ℓ-i}} g(r_1,...,r_{i-1},X_i,b)
    /// 2. Send g_i as a univariate polynomial
    /// 3. Receive random challenge r_i
    /// 4. Update polynomial: g ← g(r_1,...,r_i,X_{i+1},...,X_ℓ)
    ///
    /// # Optimization
    ///
    /// Use dynamic programming to avoid recomputing sums:
    /// - Maintain partial sums for each prefix of variables
    /// - Update incrementally as challenges arrive
    ///
    /// # Complexity
    ///
    /// O(ℓ · 2^ℓ) field operations total
    pub fn prove(
        &mut self,
        polynomial: &MultivariatePolynomial<F>,
        challenges: &[F],
    ) -> LookupResult<SumcheckProof<F>> {
        if challenges.len() != polynomial.num_vars {
            return Err(LookupError::InvalidChallengeSize {
                expected: polynomial.num_vars,
                got: challenges.len(),
            });
        }
        
        let mut round_polynomials = Vec::new();
        let mut current_evals = polynomial.evaluations.clone();
        let num_vars = polynomial.num_vars;
        
        for round in 0..num_vars {
            // Compute round polynomial g_i(X_i)
            let round_poly = self.compute_round_polynomial(&current_evals, num_vars - round)?;
            round_polynomials.push(round_poly.clone());
            
            // Update evaluations for next round
            if round < num_vars - 1 {
                current_evals = self.update_evaluations(
                    &current_evals,
                    challenges[round],
                    num_vars - round,
                )?;
            }
        }
        
        Ok(SumcheckProof { round_polynomials })
    }
    
    /// Compute the round polynomial for the current round
    ///
    /// # Algorithm
    ///
    /// For multilinear polynomials (degree 1 in each variable):
    /// g_i(X_i) = Σ_{b∈{0,1}^{ℓ-i}} g(r_1,...,r_{i-1},X_i,b)
    ///
    /// This is a univariate polynomial of degree at most d_i where d_i is
    /// the degree of g in variable X_i.
    ///
    /// For multilinear case: g_i(X) = a_0 + a_1 · X where:
    /// - a_0 = Σ_{b: b_i=0} g(r_1,...,r_{i-1},0,b)
    /// - a_1 = Σ_{b: b_i=1} g(r_1,...,r_{i-1},1,b) - a_0
    ///
    /// # Complexity
    ///
    /// O(2^{ℓ-i}) for round i
    fn compute_round_polynomial(
        &self,
        evaluations: &[F],
        remaining_vars: usize,
    ) -> LookupResult<RoundPolynomial<F>> {
        if remaining_vars == 0 {
            return Ok(RoundPolynomial::new(vec![evaluations[0]]));
        }
        
        let half_size = 1 << (remaining_vars - 1);
        
        // For multilinear: compute g(0) and g(1)
        let mut g_0 = F::zero();
        let mut g_1 = F::zero();
        
        for i in 0..half_size {
            g_0 = g_0 + evaluations[i];
            g_1 = g_1 + evaluations[i + half_size];
        }
        
        // Polynomial is g(X) = g_0 + (g_1 - g_0) · X
        let coefficients = vec![g_0, g_1 - g_0];
        
        Ok(RoundPolynomial::new(coefficients))
    }
    
    /// Update evaluations after receiving a challenge
    ///
    /// # Algorithm
    ///
    /// Given challenge r_i, compute:
    /// g(r_1,...,r_i,X_{i+1},...,X_ℓ) = (1-r_i)·g(r_1,...,r_{i-1},0,X_{i+1},...,X_ℓ)
    ///                                  + r_i·g(r_1,...,r_{i-1},1,X_{i+1},...,X_ℓ)
    ///
    /// # Complexity
    ///
    /// O(2^{ℓ-i}) for round i
    fn update_evaluations(
        &self,
        evaluations: &[F],
        challenge: F,
        remaining_vars: usize,
    ) -> LookupResult<Vec<F>> {
        let half_size = 1 << (remaining_vars - 1);
        let mut new_evals = Vec::with_capacity(half_size);
        
        let one_minus_r = F::one() - challenge;
        
        for i in 0..half_size {
            let eval_0 = evaluations[i];
            let eval_1 = evaluations[i + half_size];
            
            // Linear interpolation: (1-r)·eval_0 + r·eval_1
            let new_eval = one_minus_r * eval_0 + challenge * eval_1;
            new_evals.push(new_eval);
        }
        
        Ok(new_evals)
    }
}

impl<F: Field> Default for SumcheckProver<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Sumcheck verifier
///
/// Verifies sumcheck proofs.
#[derive(Debug)]
pub struct SumcheckVerifier<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> SumcheckVerifier<F> {
    /// Create a new sumcheck verifier
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Verify a sumcheck proof
    ///
    /// # Algorithm
    ///
    /// For each round i = 1 to ℓ:
    /// 1. Check degree: deg(g_i) ≤ d_i
    /// 2. Check consistency: g_i(0) + g_i(1) = current_sum
    /// 3. Sample random challenge r_i
    /// 4. Update current_sum = g_i(r_i)
    ///
    /// After all rounds:
    /// 5. Verify final evaluation: g(r_1,...,r_ℓ) = final_sum
    ///
    /// # Complexity
    ///
    /// O(ℓ) field operations plus one evaluation of g
    pub fn verify(
        &mut self,
        claimed_sum: F,
        proof: &SumcheckProof<F>,
        challenges: &[F],
        final_evaluation: F,
    ) -> LookupResult<bool> {
        if proof.round_polynomials.len() != challenges.len() {
            return Err(LookupError::InvalidProofSize {
                expected: challenges.len(),
                got: proof.round_polynomials.len(),
            });
        }
        
        let mut current_sum = claimed_sum;
        
        for (round, (poly, &challenge)) in proof
            .round_polynomials
            .iter()
            .zip(challenges.iter())
            .enumerate()
        {
            // Check degree (for multilinear, should be 1)
            if poly.degree() > 1 {
                return Err(LookupError::InvalidPolynomialDegree {
                    expected: 1,
                    got: poly.degree(),
                });
            }
            
            // Check consistency: g_i(0) + g_i(1) = current_sum
            let g_0 = poly.evaluate(F::zero());
            let g_1 = poly.evaluate(F::one());
            let sum = g_0 + g_1;
            
            if sum != current_sum {
                return Ok(false);
            }
            
            // Update current sum
            current_sum = poly.evaluate(challenge);
        }
        
        // Verify final evaluation
        Ok(current_sum == final_evaluation)
    }
    
    /// Generate random challenges
    ///
    /// In practice, these would be generated using Fiat-Shamir transform
    /// by hashing the transcript.
    ///
    /// # Algorithm
    ///
    /// For each round i:
    /// 1. Hash the transcript so far (including round polynomial)
    /// 2. Derive challenge r_i from the hash
    ///
    /// # Complexity
    ///
    /// O(ℓ) hash operations
    pub fn generate_challenges(&self, num_challenges: usize, seed: &[u8]) -> Vec<F> {
        // Placeholder: In practice, use Fiat-Shamir
        (0..num_challenges)
            .map(|i| {
                let mut bytes = seed.to_vec();
                bytes.push(i as u8);
                F::from_bytes(&bytes)
            })
            .collect()
    }
}

impl<F: Field> Default for SumcheckVerifier<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Univariate sumcheck lemma
///
/// For a univariate polynomial f and subgroup H of size t:
/// Σ_{a∈H} f(a) = t · f(0)
///
/// This is useful for efficient summation over subgroups.
#[derive(Debug)]
pub struct UnivariateSumcheck<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> UnivariateSumcheck<F> {
    /// Verify the univariate sumcheck lemma
    ///
    /// # Algorithm
    ///
    /// Check: Σ_{a∈H} f(a) = |H| · f(0)
    ///
    /// This holds because for any polynomial f and subgroup H:
    /// Σ_{a∈H} f(a) = Σ_{a∈H} Σ_i c_i a^i = Σ_i c_i Σ_{a∈H} a^i
    ///
    /// For i > 0: Σ_{a∈H} a^i = 0 (sum of roots of unity)
    /// For i = 0: Σ_{a∈H} 1 = |H|
    ///
    /// Therefore: Σ_{a∈H} f(a) = c_0 · |H| = |H| · f(0)
    ///
    /// # Complexity
    ///
    /// O(1) - just check the equation
    pub fn verify(
        claimed_sum: F,
        subgroup_size: usize,
        f_at_zero: F,
    ) -> bool {
        let expected_sum = F::from(subgroup_size as u64) * f_at_zero;
        claimed_sum == expected_sum
    }
}

/// Batched sumcheck
///
/// Combines multiple sumcheck instances into a single protocol.
#[derive(Debug)]
pub struct BatchedSumcheck<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> BatchedSumcheck<F> {
    /// Batch multiple sumcheck instances
    ///
    /// # Algorithm
    ///
    /// Given k polynomials g_1, ..., g_k with claimed sums H_1, ..., H_k:
    /// 1. Sample random coefficients α_1, ..., α_k
    /// 2. Compute combined polynomial: g = Σ α_i · g_i
    /// 3. Compute combined sum: H = Σ α_i · H_i
    /// 4. Run sumcheck on (g, H)
    ///
    /// This reduces k sumcheck instances to one, saving communication.
    ///
    /// # Complexity
    ///
    /// Same as single sumcheck, but verifies k claims
    pub fn batch(
        polynomials: &[MultivariatePolynomial<F>],
        claimed_sums: &[F],
        coefficients: &[F],
    ) -> LookupResult<(MultivariatePolynomial<F>, F)> {
        if polynomials.len() != claimed_sums.len()
            || polynomials.len() != coefficients.len()
        {
            return Err(LookupError::BatchSizeMismatch);
        }
        
        if polynomials.is_empty() {
            return Err(LookupError::EmptyBatch);
        }
        
        let num_vars = polynomials[0].num_vars;
        let size = polynomials[0].evaluations.len();
        
        // Verify all polynomials have same number of variables
        for poly in polynomials {
            if poly.num_vars != num_vars {
                return Err(LookupError::InconsistentPolynomialSizes);
            }
        }
        
        // Compute combined polynomial
        let mut combined_evals = vec![F::zero(); size];
        for (i, poly) in polynomials.iter().enumerate() {
            let coeff = coefficients[i];
            for (j, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[j] = combined_evals[j] + coeff * eval;
            }
        }
        
        // Compute combined sum
        let combined_sum = claimed_sums
            .iter()
            .zip(coefficients.iter())
            .fold(F::zero(), |acc, (&sum, &coeff)| acc + coeff * sum);
        
        let combined_poly = MultivariatePolynomial::new(num_vars, combined_evals)?;
        
        Ok((combined_poly, combined_sum))
    }
}

/// Sparse sumcheck
///
/// Optimized sumcheck for sparse polynomials (many zero evaluations).
#[derive(Debug)]
pub struct SparseSumcheck<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> SparseSumcheck<F> {
    /// Compute sumcheck for sparse polynomial
    ///
    /// # Algorithm
    ///
    /// Instead of iterating over all 2^ℓ evaluations, only process non-zero entries:
    /// 1. Maintain sparse representation: {(index, value)}
    /// 2. For each round, compute g_i(X) only from non-zero entries
    /// 3. Update sparse representation after each challenge
    ///
    /// # Complexity
    ///
    /// O(ℓ · s) where s is the number of non-zero entries
    /// This is much better than O(ℓ · 2^ℓ) when s << 2^ℓ
    pub fn prove_sparse(
        sparse_evals: &[(usize, F)],
        num_vars: usize,
        challenges: &[F],
    ) -> LookupResult<SumcheckProof<F>> {
        let mut round_polynomials = Vec::new();
        let mut current_sparse = sparse_evals.to_vec();
        
        for round in 0..num_vars {
            // Compute round polynomial from sparse representation
            let round_poly = Self::compute_sparse_round_polynomial(
                &current_sparse,
                num_vars - round,
            )?;
            round_polynomials.push(round_poly.clone());
            
            // Update sparse representation
            if round < num_vars - 1 {
                current_sparse = Self::update_sparse_evaluations(
                    &current_sparse,
                    challenges[round],
                    num_vars - round,
                )?;
            }
        }
        
        Ok(SumcheckProof { round_polynomials })
    }
    
    /// Compute round polynomial from sparse representation
    fn compute_sparse_round_polynomial(
        sparse_evals: &[(usize, F)],
        remaining_vars: usize,
    ) -> LookupResult<RoundPolynomial<F>> {
        let mut g_0 = F::zero();
        let mut g_1 = F::zero();
        
        let half_size = 1 << (remaining_vars - 1);
        
        for &(index, value) in sparse_evals {
            if index < half_size {
                g_0 = g_0 + value;
            } else {
                g_1 = g_1 + value;
            }
        }
        
        Ok(RoundPolynomial::new(vec![g_0, g_1 - g_0]))
    }
    
    /// Update sparse representation after challenge
    fn update_sparse_evaluations(
        sparse_evals: &[(usize, F)],
        challenge: F,
        remaining_vars: usize,
    ) -> LookupResult<Vec<(usize, F)>> {
        let half_size = 1 << (remaining_vars - 1);
        let one_minus_r = F::one() - challenge;
        
        let mut new_sparse = Vec::new();
        let mut combined: std::collections::HashMap<usize, F> = std::collections::HashMap::new();
        
        for &(index, value) in sparse_evals {
            let new_index = index % half_size;
            let coeff = if index < half_size {
                one_minus_r
            } else {
                challenge
            };
            
            let new_value = coeff * value;
            *combined.entry(new_index).or_insert(F::zero()) = 
                combined.get(&new_index).copied().unwrap_or(F::zero()) + new_value;
        }
        
        for (index, value) in combined {
            if value != F::zero() {
                new_sparse.push((index, value));
            }
        }
        
        Ok(new_sparse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    #[test]
    fn test_multivariate_polynomial_evaluation() {
        // f(x, y) = x + y over {0,1}²
        // Evaluations: f(0,0)=0, f(0,1)=1, f(1,0)=1, f(1,1)=2
        let evals = vec![
            Goldilocks::from(0u64),
            Goldilocks::from(1u64),
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
        ];
        
        let poly = MultivariatePolynomial::new(2, evals).unwrap();
        
        // Evaluate at (0.5, 0.5) should give 1
        let point = vec![Goldilocks::from(1u64) / Goldilocks::from(2u64); 2];
        let result = poly.evaluate(&point).unwrap();
        
        // For multilinear extension: f(0.5, 0.5) = 0.25·0 + 0.25·1 + 0.25·1 + 0.25·2 = 1
        assert_eq!(result, Goldilocks::from(1u64));
    }
    
    #[test]
    fn test_sumcheck_protocol() {
        // Simple polynomial: f(x, y) = x + y
        let evals = vec![
            Goldilocks::from(0u64),
            Goldilocks::from(1u64),
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
        ];
        
        let poly = MultivariatePolynomial::new(2, evals).unwrap();
        let claimed_sum = poly.sum_over_hypercube(); // Should be 4
        
        let challenges = vec![
            Goldilocks::from(3u64),
            Goldilocks::from(5u64),
        ];
        
        let mut prover = SumcheckProver::new();
        let proof = prover.prove(&poly, &challenges).unwrap();
        
        let final_eval = poly.evaluate(&challenges).unwrap();
        
        let mut verifier = SumcheckVerifier::new();
        let valid = verifier
            .verify(claimed_sum, &proof, &challenges, final_eval)
            .unwrap();
        
        assert!(valid);
    }
    
    #[test]
    fn test_univariate_sumcheck() {
        // For subgroup of size 4, sum should be 4 * f(0)
        let f_at_zero = Goldilocks::from(7u64);
        let subgroup_size = 4;
        let claimed_sum = Goldilocks::from(28u64); // 4 * 7
        
        let valid = UnivariateSumcheck::verify(claimed_sum, subgroup_size, f_at_zero);
        assert!(valid);
        
        let invalid_sum = Goldilocks::from(30u64);
        let invalid = UnivariateSumcheck::verify(invalid_sum, subgroup_size, f_at_zero);
        assert!(!invalid);
    }
}
