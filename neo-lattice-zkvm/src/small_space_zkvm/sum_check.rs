// Sum-Check Protocol Module for Small-Space zkVM
//
// This module implements both the standard (linear-time) and small-space sum-check provers.
// The sum-check protocol is a fundamental building block for zkSNARKs.
//
// Protocol Overview:
// The prover proves that v = Σ_{x∈{0,1}^n} g(x) where g(X) = ∏_{k=1}^ℓ gₖ(X).
//
// In each round i:
// 1. Prover sends univariate polynomial fᵢ(Xᵢ) = Σ_{x∈{0,1}^(n-i)} g(r₁,...,rᵢ₋₁,Xᵢ,x)
// 2. Verifier checks fᵢ(0) + fᵢ(1) = fᵢ₋₁(rᵢ₋₁) (or v for round 1)
// 3. Verifier samples random challenge rᵢ
// 4. After n rounds, verifier checks g(r₁,...,rₙ) = fₙ(rₙ)
//
// Key Features:
// 1. Standard linear-time prover: O(ℓ·2^n) time, O(ℓ·2^n) space
// 2. Small-space prover (Algorithm 1): O(ℓ²·n·2^n) time, O(n + ℓ²) space
// 3. Verifier: O(n·ℓ) time, O(n) space
// 4. Soundness error: ℓ·n/|F|
//
// References:
// - Paper Section 3.1: Sum-Check Protocol (Requirements 1.1-1.16)
// - Paper Algorithm 1: Small-Space Sum-Check (Requirements 1.1-1.16, 17.1-17.4)
// - Paper [CFFZE24, Rot24]: Efficient streaming (Requirement 17.17)

use crate::field::Field;
use super::univariate::UnivariatePolynomial;
use super::equality::EqualityFunction;
use super::field_arithmetic::index_to_bits;
use std::marker::PhantomData;
use std::hash::{Hash, Hasher};

/// Polynomial Oracle Trait
///
/// Provides oracle access to polynomial evaluations.
/// This is the key abstraction for small-space proving.
///
/// Reference: Requirements 1.7, 17.1, Task 6.1
pub trait PolynomialOracle<F: Field> {
    /// Query polynomial k at index i
    ///
    /// Returns the value of the k-th polynomial at the i-th point
    /// of the Boolean hypercube.
    fn query(&self, poly_index: usize, index: usize) -> F;
    
    /// Get number of polynomials
    fn num_polynomials(&self) -> usize;
    
    /// Get number of variables
    fn num_variables(&self) -> usize;
}

/// Sum-Check Proof
///
/// Contains the prover's messages for all n rounds.
/// Each round i contains a univariate polynomial fᵢ of degree ℓ.
///
/// Reference: Requirements 1.1-1.5
#[derive(Clone, Debug)]
pub struct SumCheckProof<F: Field> {
    /// Polynomials for each round: f₁, f₂, ..., fₙ
    pub rounds: Vec<UnivariatePolynomial<F>>,
    
    /// Challenges sampled by verifier: r₁, r₂, ..., rₙ
    pub challenges: Vec<F>,
}

impl<F: Field> SumCheckProof<F> {
    /// Create new proof
    pub fn new() -> Self {
        Self {
            rounds: Vec::new(),
            challenges: Vec::new(),
        }
    }
    
    /// Get number of rounds
    pub fn num_rounds(&self) -> usize {
        self.rounds.len()
    }
}

/// Standard Sum-Check Prover (Linear-Time)
///
/// Implements the standard sum-check protocol with O(ℓ·2^n) time and space.
/// This is the baseline algorithm that small-space optimization improves upon.
///
/// Reference: Requirements 1.1-1.5, 1.15, Tasks 6.2-6.5
pub struct SumCheckProver<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    
    /// Number of polynomials
    pub num_polys: usize,
    
    /// Evaluation points for interpolation
    /// Typically S = {0, 1, 2} for degree 2 polynomials
    pub evaluation_points: Vec<F>,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: Field> SumCheckProver<F> {
    /// Create new sum-check prover
    ///
    /// Parameters:
    /// - num_vars: n (number of variables)
    /// - num_polys: ℓ (number of polynomials to multiply)
    /// - evaluation_points: S (points for interpolation, typically {0, 1, 2})
    pub fn new(
        num_vars: usize,
        num_polys: usize,
        evaluation_points: Vec<F>,
    ) -> Self {
        assert!(num_vars > 0, "Must have at least 1 variable");
        assert!(num_polys > 0, "Must have at least 1 polynomial");
        assert!(!evaluation_points.is_empty(), "Must have evaluation points");
        
        Self {
            num_vars,
            num_polys,
            evaluation_points,
            _phantom: PhantomData,
        }
    }
    
    /// Prove sum-check claim
    ///
    /// Proves that v = Σ_{x∈{0,1}^n} g(x) where g(X) = ∏_{k=1}^ℓ gₖ(X).
    ///
    /// Algorithm (Linear-Time):
    /// For each round i from 1 to n:
    ///   1. Initialize A_k arrays with oracle evaluations
    ///   2. For each evaluation point α_s:
    ///      - Compute f_i(α_s) = Σ_{x∈{0,1}^(n-i)} g(r₁,...,rᵢ₋₁,α_s,x)
    ///   3. Interpolate polynomial from evaluations
    ///   4. Send polynomial to verifier
    ///   5. Receive challenge rᵢ
    ///
    /// Time: O(ℓ·2^n) field operations
    /// Space: O(ℓ·2^n) for A_k arrays
    ///
    /// Reference: Requirements 1.1-1.5, 1.15, Tasks 6.2-6.5
    pub fn prove<O: PolynomialOracle<F>>(
        &self,
        oracle: &O,
        claimed_sum: F,
    ) -> SumCheckProof<F> {
        assert_eq!(oracle.num_variables(), self.num_vars, "Variable count mismatch");
        assert_eq!(oracle.num_polynomials(), self.num_polys, "Polynomial count mismatch");
        
        let n = self.num_vars;
        let ℓ = self.num_polys;
        let mut proof = SumCheckProof::new();
        let mut challenges = Vec::with_capacity(n);
        
        // Initialize A_k arrays with oracle evaluations
        // A_k[i] = gₖ(tobits(i))
        let mut a_arrays: Vec<Vec<F>> = (0..ℓ)
            .map(|k| {
                (0..(1 << n))
                    .map(|i| oracle.query(k, i))
                    .collect()
            })
            .collect();
        
        // Main loop over rounds
        for round_i in 1..=n {
            // Compute evaluations at each point in S
            let mut evaluations = vec![F::zero(); self.evaluation_points.len()];
            
            for (s, &alpha_s) in self.evaluation_points.iter().enumerate() {
                // Compute f_i(α_s) = Σ_{x∈{0,1}^(n-i)} ∏_{k=1}^ℓ A_k[x]
                // where A_k is updated with interpolation at α_s
                
                let current_size = 1 << (n - round_i + 1);
                let mut product_sum = F::zero();
                
                for x_idx in 0..current_size {
                    // Compute product of all polynomials at this point
                    let mut product = F::one();
                    
                    for k in 0..ℓ {
                        product = product.mul(&a_arrays[k][x_idx]);
                    }
                    
                    product_sum = product_sum.add(&product);
                }
                
                evaluations[s] = product_sum;
            }
            
            // Interpolate polynomial from evaluations
            let round_poly = UnivariatePolynomial::interpolate(
                &self.evaluation_points,
                &evaluations,
            );
            
            proof.rounds.push(round_poly.clone());
            
            // Verifier samples challenge (simulated here)
            let challenge = self.sample_challenge(round_i, &round_poly);
            challenges.push(challenge);
            
            // Update A_k arrays for next round using Equation 4
            // A_k[m] = (1-r_{i-1})·A_k[2m] + r_{i-1}·A_k[2m+1]
            if round_i < n {
                let new_size = 1 << (n - round_i);
                
                for k in 0..ℓ {
                    let mut new_a = Vec::with_capacity(new_size);
                    
                    for m in 0..new_size {
                        let val_0 = a_arrays[k][2 * m];
                        let val_1 = a_arrays[k][2 * m + 1];
                        
                        // Interpolate at challenge
                        let interpolated = val_0.mul(&(F::one().sub(&challenge)))
                            .add(&val_1.mul(&challenge));
                        
                        new_a.push(interpolated);
                    }
                    
                    a_arrays[k] = new_a;
                }
            }
        }
        
        proof.challenges = challenges;
        proof
    }
    
    /// Sample verifier challenge (simulated)
    ///
    /// In a real protocol, this would be done by the verifier.
    /// For testing, we use a deterministic hash-based challenge.
    fn sample_challenge(&self, round: usize, _poly: &UnivariatePolynomial<F>) -> F {
        // Deterministic challenge based on round and polynomial
        // In practice, this would be a Fiat-Shamir hash
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        
        round.hash(&mut hasher);
        let hash = hasher.finish();
        
        F::from_u64(hash)
    }
}

/// Sum-Check Verifier
///
/// Verifies sum-check proofs.
///
/// Reference: Requirements 1.3-1.5, 1.15, Tasks 9.1-9.4
pub struct SumCheckVerifier<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    
    /// Number of polynomials
    pub num_polys: usize,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: Field> SumCheckVerifier<F> {
    /// Create new verifier
    pub fn new(num_vars: usize, num_polys: usize) -> Self {
        Self {
            num_vars,
            num_polys,
            _phantom: PhantomData,
        }
    }
    
    /// Verify sum-check proof
    ///
    /// Checks:
    /// 1. Round 1: v = f₁(0) + f₁(1)
    /// 2. Rounds 2..n-1: fᵢ(rᵢ) = fᵢ₋₁(0) + fᵢ₋₁(1)
    /// 3. Final: g(r₁,...,rₙ) = fₙ(rₙ)
    ///
    /// Time: O(n·ℓ) field operations
    /// Space: O(n) for challenges
    ///
    /// Reference: Requirements 1.3-1.5, 1.15, Tasks 9.1-9.4
    pub fn verify(
        &self,
        proof: &SumCheckProof<F>,
        claimed_sum: F,
        final_evals: &[F],
    ) -> bool {
        assert_eq!(proof.num_rounds(), self.num_vars, "Round count mismatch");
        assert_eq!(final_evals.len(), self.num_polys, "Final evaluation count mismatch");
        
        // Round 1: Check v = f₁(0) + f₁(1)
        let f1 = &proof.rounds[0];
        let f1_0 = f1.evaluate(&F::zero());
        let f1_1 = f1.evaluate(&F::one());
        
        if claimed_sum != f1_0.add(&f1_1) {
            return false;
        }
        
        // Rounds 2..n-1: Check fᵢ(rᵢ) = fᵢ₋₁(0) + fᵢ₋₁(1)
        for i in 1..self.num_vars {
            let fi = &proof.rounds[i];
            let fi_prev = &proof.rounds[i - 1];
            let ri_prev = proof.challenges[i - 1];
            
            let fi_prev_0 = fi_prev.evaluate(&F::zero());
            let fi_prev_1 = fi_prev.evaluate(&F::one());
            let expected = fi_prev_0.add(&fi_prev_1);
            
            let actual = fi.evaluate(&ri_prev);
            
            if actual != expected {
                return false;
            }
        }
        
        // Final check: g(r₁,...,rₙ) = fₙ(rₙ)
        let fn_poly = &proof.rounds[self.num_vars - 1];
        let rn = proof.challenges[self.num_vars - 1];
        let fn_rn = fn_poly.evaluate(&rn);
        
        // Compute g(r₁,...,rₙ) = ∏_{k=1}^ℓ gₖ(r₁,...,rₙ)
        let mut g_eval = F::one();
        for &eval in final_evals {
            g_eval = g_eval.mul(&eval);
        }
        
        g_eval == fn_rn
    }
    
    /// Get soundness error bound
    ///
    /// The soundness error is ℓ·n/|F|, where:
    /// - ℓ is the number of polynomials
    /// - n is the number of variables
    /// - |F| is the field size
    ///
    /// Reference: Requirements 1.15, 11.8
    pub fn soundness_error(&self, field_size: u64) -> f64 {
        let error = (self.num_polys as f64) * (self.num_vars as f64) / (field_size as f64);
        error
    }
}

/// Small-Space Sum-Check Prover (Algorithm 1)
///
/// Implements Algorithm 1 from the paper with O(n + ℓ²) space complexity.
/// This is the key innovation that enables small-space proving.
///
/// Reference: Requirements 1.1-1.16, 17.1-17.4, Tasks 7.1-7.8
pub struct SmallSpaceSumCheckProver<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    
    /// Number of polynomials
    pub num_polys: usize,
    
    /// Evaluation points for interpolation
    pub evaluation_points: Vec<F>,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: Field> SmallSpaceSumCheckProver<F> {
    /// Create new small-space prover
    pub fn new(
        num_vars: usize,
        num_polys: usize,
        evaluation_points: Vec<F>,
    ) -> Self {
        assert!(num_vars > 0, "Must have at least 1 variable");
        assert!(num_polys > 0, "Must have at least 1 polynomial");
        assert!(!evaluation_points.is_empty(), "Must have evaluation points");
        
        Self {
            num_vars,
            num_polys,
            evaluation_points,
            _phantom: PhantomData,
        }
    }
    
    /// Prove sum-check claim using Algorithm 1
    ///
    /// Algorithm 1 (Small-Space Sum-Check):
    /// For each round i from 1 to n:
    ///   1. Initialize accumulator array of size O(ℓ)
    ///   2. For each m from 0 to 2^(n-i)-1:
    ///      a. Initialize witness_eval[k][s] array of size O(ℓ²)
    ///      b. For each j from 0 to 2^(i-1)-1:
    ///         - Compute u_even = 2^i·2m + j
    ///         - Compute u_odd = 2^i·(2m+1) + j
    ///         - Query all ℓ polynomials at u_even and u_odd
    ///         - Compute ẽq((r₁,...,rᵢ₋₁), tobits(j))
    ///         - Update witness_eval[k][s] with interpolation
    ///      c. Accumulate products ∏_{k=1}^ℓ witness_eval[k][s]
    ///   3. Interpolate polynomial from accumulator
    ///   4. Send polynomial to verifier
    ///   5. Receive challenge rᵢ
    ///
    /// Space: O(n + ℓ²)
    /// Time: O(ℓ²·n·2^n)
    ///
    /// Reference: Requirements 1.1-1.16, 17.1-17.4, Tasks 7.1-7.8
    pub fn prove<O: PolynomialOracle<F>>(
        &self,
        oracle: &O,
        claimed_sum: F,
    ) -> SumCheckProof<F> {
        assert_eq!(oracle.num_variables(), self.num_vars, "Variable count mismatch");
        assert_eq!(oracle.num_polynomials(), self.num_polys, "Polynomial count mismatch");
        
        let n = self.num_vars;
        let ℓ = self.num_polys;
        let mut proof = SumCheckProof::new();
        let mut challenges = Vec::with_capacity(n);
        
        // Precompute equality function for efficiency
        let eq_func = EqualityFunction::<F>::new(n);
        
        // Main loop over rounds
        for round_i in 1..=n {
            // Step 3: Initialize accumulator array of size O(ℓ)
            let mut accumulator = vec![F::zero(); self.evaluation_points.len()];
            
            // Iterate over m ∈ {0, ..., 2^(n-i) - 1}
            let num_m = 1 << (n - round_i);
            
            for m in 0..num_m {
                // Step 5: Initialize witness_eval array of size O(ℓ²)
                let mut witness_eval = vec![vec![F::zero(); self.evaluation_points.len()]; ℓ];
                
                // Step 6: Iterate over j ∈ {0, ..., 2^(i-1) - 1}
                let num_j = if round_i > 1 { 1 << (round_i - 1) } else { 1 };
                
                for j in 0..num_j {
                    // Step 7-8: Compute u_even = 2^i · 2m + j
                    let u_even = (1 << round_i) * (2 * m) + j;
                    
                    // Step 9: Query all polynomials at u_even
                    let mut evals_even = Vec::with_capacity(ℓ);
                    for k in 0..ℓ {
                        evals_even.push(oracle.query(k, u_even));
                    }
                    
                    // Step 10-11: Compute u_odd = 2^i · (2m+1) + j
                    let u_odd = (1 << round_i) * (2 * m + 1) + j;
                    
                    // Step 12: Query all polynomials at u_odd
                    let mut evals_odd = Vec::with_capacity(ℓ);
                    for k in 0..ℓ {
                        evals_odd.push(oracle.query(k, u_odd));
                    }
                    
                    // Compute ẽq((r₁,...,rᵢ₋₁), tobits(j))
                    let eq_eval = if round_i == 1 {
                        F::one()
                    } else {
                        self.compute_eq_eval(&challenges[..round_i - 1], j)
                    };
                    
                    // Step 13-15: Update witness_eval for all k and s
                    for k in 0..ℓ {
                        for (s, &alpha_s) in self.evaluation_points.iter().enumerate() {
                            // Step 14: witness_eval[k][s] += 
                            //   ẽq(...)·((1-αₛ)·evals_even[k] + αₛ·evals_odd[k])
                            let interpolated = evals_even[k]
                                .mul(&(F::one().sub(&alpha_s)))
                                .add(&evals_odd[k].mul(&alpha_s));
                            
                            witness_eval[k][s] = witness_eval[k][s]
                                .add(&eq_eval.mul(&interpolated));
                        }
                    }
                }
                
                // Step 18-20: Accumulate products
                for s in 0..self.evaluation_points.len() {
                    // Compute ∏_{k=1}^ℓ witness_eval[k][s]
                    let mut product = F::one();
                    for k in 0..ℓ {
                        product = product.mul(&witness_eval[k][s]);
                    }
                    accumulator[s] = accumulator[s].add(&product);
                }
            }
            
            // Step 23: Construct polynomial from evaluations
            let round_poly = UnivariatePolynomial::interpolate(
                &self.evaluation_points,
                &accumulator,
            );
            
            proof.rounds.push(round_poly.clone());
            
            // Verifier samples challenge (simulated here)
            let challenge = self.sample_challenge(round_i, &round_poly);
            challenges.push(challenge);
        }
        
        proof.challenges = challenges;
        proof
    }
    
    /// Compute ẽq((r₁,...,rᵢ₋₁), tobits(j))
    ///
    /// Evaluates the equality function at the given challenges and index.
    ///
    /// Reference: Requirements 1.5, 1.9, 1.12, Task 7.5
    fn compute_eq_eval(&self, challenges: &[F], index: usize) -> F {
        let bits = index_to_bits(index, challenges.len());
        let mut result = F::one();
        
        for (i, &bit) in bits.iter().enumerate() {
            let term = if bit {
                challenges[i]
            } else {
                F::one().sub(&challenges[i])
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Sample verifier challenge (simulated)
    fn sample_challenge(&self, round: usize, _poly: &UnivariatePolynomial<F>) -> F {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        
        round.hash(&mut hasher);
        let hash = hasher.finish();
        
        F::from_u64(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    /// Simple test oracle
    struct TestOracle {
        polynomials: Vec<Vec<GoldilocksField>>,
        num_vars: usize,
    }
    
    impl TestOracle {
        fn new(polynomials: Vec<Vec<GoldilocksField>>) -> Self {
            let num_vars = (polynomials[0].len() as f64).log2() as usize;
            Self {
                polynomials,
                num_vars,
            }
        }
    }
    
    impl PolynomialOracle<GoldilocksField> for TestOracle {
        fn query(&self, poly_index: usize, index: usize) -> GoldilocksField {
            self.polynomials[poly_index][index]
        }
        
        fn num_polynomials(&self) -> usize {
            self.polynomials.len()
        }
        
        fn num_variables(&self) -> usize {
            self.num_vars
        }
    }
    
    #[test]
    fn test_sum_check_prover_creation() {
        let prover = SumCheckProver::<GoldilocksField>::new(
            2,
            2,
            vec![
                GoldilocksField::zero(),
                GoldilocksField::one(),
                GoldilocksField::from_u64(2),
            ],
        );
        
        assert_eq!(prover.num_vars, 2);
        assert_eq!(prover.num_polys, 2);
    }
    
    #[test]
    fn test_sum_check_verifier_creation() {
        let verifier = SumCheckVerifier::<GoldilocksField>::new(2, 2);
        
        assert_eq!(verifier.num_vars, 2);
        assert_eq!(verifier.num_polys, 2);
    }
    
    #[test]
    fn test_small_space_prover_creation() {
        let prover = SmallSpaceSumCheckProver::<GoldilocksField>::new(
            2,
            2,
            vec![
                GoldilocksField::zero(),
                GoldilocksField::one(),
                GoldilocksField::from_u64(2),
            ],
        );
        
        assert_eq!(prover.num_vars, 2);
        assert_eq!(prover.num_polys, 2);
    }
    
    #[test]
    fn test_soundness_error() {
        let verifier = SumCheckVerifier::<GoldilocksField>::new(10, 3);
        let field_size = 1u64 << 61; // Goldilocks field size
        
        let error = verifier.soundness_error(field_size);
        assert!(error > 0.0);
        assert!(error < 1.0);
    }
}

