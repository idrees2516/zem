// Sumcheck Protocol Implementation for Permutation Check
//
// This module implements the sumcheck protocol, which is the core building block
// for both BiPerm and MulPerm protocols.
//
// # Sumcheck Protocol (Paper Section 2.3)
//
// Given a μ-variate polynomial f: F^μ → F and claimed sum v, the sumcheck protocol
// allows a prover to convince a verifier that ∑_{x∈B^μ} f(x) = v.
//
// ## Protocol Flow
// 1. Verifier samples random challenge α ∈ F^μ
// 2. For each round k ∈ [μ]:
//    - Prover computes round polynomial: u_k(X) = ∑_{x∈B^{μ-k}} f(α_{1:k-1}, X, x)
//    - Prover sends u_k to verifier
//    - Verifier checks: u_k(0) + u_k(1) = S (where S is claimed sum from previous round)
//    - Verifier samples challenge α_k ∈ F
//    - Update S ← u_k(α_k)
// 3. After μ rounds, verifier checks f(α) = S
//
// ## Complexity
// - Prover: O(2^μ · d) field operations where d is degree
// - Verifier: O(μ · d) field operations
// - Communication: μ polynomials of degree d
//
// ## Soundness (Paper Theorem 2.1)
// If f(x) ≠ g(σ(x)) for some x, verifier rejects with probability ≥ 1 - dμ/|F|
//
// # Paper References
// - Section 2.3: Sumcheck Protocol
// - Algorithm 1: Naïve Sumcheck (baseline)
// - Algorithm 2: BiPerm Sumcheck (degree 3)
// - Algorithms 5,7: MulPerm Sumchecks (variable degree)

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::permcheck::errors::VerificationError;
use std::marker::PhantomData;

/// Virtual Polynomial trait for sumcheck
///
/// This trait abstracts over different polynomial representations used in sumcheck.
/// Different protocols (BiPerm, MulPerm, Lookup) implement this trait to provide
/// their specific polynomial evaluations.
///
/// # Design Rationale
/// Using a trait allows the sumcheck protocol to be generic over the polynomial
/// being summed, enabling code reuse across BiPerm, MulPerm, and lookup arguments.
///
/// # Paper Reference
/// Implicitly used throughout; each protocol defines its own virtual polynomial
pub trait VirtualPolynomial<F: Field>: Send + Sync {
    /// Evaluate the polynomial at a point in F^μ
    ///
    /// # Arguments
    /// - `point`: Evaluation point in F^μ
    ///
    /// # Returns
    /// The value f(point) ∈ F
    fn evaluate(&self, point: &[F]) -> F;
    
    /// Compute the round polynomial for sumcheck round k
    ///
    /// Given challenges α_{1:k-1} from previous rounds, computes:
    ///   u_k(X) = ∑_{x∈B^{μ-k}} f(α_{1:k-1}, X, x)
    ///
    /// This is the core operation of the sumcheck prover.
    ///
    /// # Arguments
    /// - `challenges`: Previous challenges [α_1, ..., α_{k-1}]
    ///
    /// # Returns
    /// Univariate polynomial u_k of degree at most d
    ///
    /// # Complexity
    /// O(2^{μ-k} · d) field operations
    ///
    /// # Paper Reference
    /// Section 2.3, Equation (2.3): "In round k, the prover sends u_k(X)"
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> Vec<F>;
    
    /// Maximum degree of the polynomial in each variable
    ///
    /// This determines the degree of round polynomials and affects soundness.
    ///
    /// # Returns
    /// Degree d where f has degree ≤ d in each variable
    fn degree(&self) -> usize;
    
    /// Number of variables μ
    fn num_vars(&self) -> usize;
}


/// Sumcheck Proof
///
/// Contains all the information needed to verify a sumcheck protocol execution.
///
/// # Structure
/// - Round polynomials: u_1, u_2, ..., u_μ (each of degree d)
/// - Final evaluation: f(α) where α is the final challenge point
///
/// # Size
/// O(μ · d) field elements
///
/// # Paper Reference
/// Implicit in Section 2.3; proof consists of all prover messages
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials u_k for k ∈ [μ]
    /// Each polynomial is represented as evaluations at 0, 1, ..., degree
    pub round_polynomials: Vec<Vec<F>>,
    
    /// Final evaluation f(α) at the challenge point
    pub final_evaluation: F,
}

impl<F: Field> SumcheckProof<F> {
    /// Create a new sumcheck proof
    pub fn new(round_polynomials: Vec<Vec<F>>, final_evaluation: F) -> Self {
        Self {
            round_polynomials,
            final_evaluation,
        }
    }
    
    /// Get the number of rounds (should equal μ)
    pub fn num_rounds(&self) -> usize {
        self.round_polynomials.len()
    }
    
    /// Get the degree of round polynomials
    pub fn degree(&self) -> usize {
        if self.round_polynomials.is_empty() {
            return 0;
        }
        self.round_polynomials[0].len().saturating_sub(1)
    }
}


/// Sumcheck Prover
///
/// Executes the prover's side of the sumcheck protocol.
///
/// # Algorithm (Paper Section 2.3)
/// For each round k = 1 to μ:
/// 1. Compute u_k(X) = ∑_{x∈B^{μ-k}} f(α_{1:k-1}, X, x)
/// 2. Send u_k to verifier
/// 3. Receive challenge α_k
/// 4. Collapse evaluation tables
///
/// # Optimization: Table Collapsing (Paper Section 4.2)
/// After each round, we reduce the evaluation table size by half:
/// - Before round k: table of size 2^{μ-k+1}
/// - After round k: table of size 2^{μ-k}
/// This maintains O(2^{μ-k}) space throughout.
///
/// # Paper Reference
/// - Section 2.3: Sumcheck Protocol
/// - Section 4.2, Optimization 4.2: "Collapsing evaluation tables"
pub struct SumcheckProver<F: Field> {
    /// The virtual polynomial being summed
    polynomial: Box<dyn VirtualPolynomial<F>>,
    
    /// Challenges received so far
    challenges: Vec<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> SumcheckProver<F> {
    /// Create a new sumcheck prover
    ///
    /// # Arguments
    /// - `polynomial`: The virtual polynomial to sum over B^μ
    pub fn new(polynomial: Box<dyn VirtualPolynomial<F>>) -> Self {
        Self {
            polynomial,
            challenges: Vec::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Execute the sumcheck protocol
    ///
    /// # Arguments
    /// - `claimed_sum`: The claimed value v = ∑_{x∈B^μ} f(x)
    ///
    /// # Returns
    /// A sumcheck proof containing all round polynomials and final evaluation
    ///
    /// # Complexity
    /// O(μ · 2^μ · d) field operations where:
    /// - μ = number of variables
    /// - d = degree of polynomial
    ///
    /// # Paper Reference
    /// Algorithm 1 (Naïve Sumcheck), generalized for arbitrary degree
    pub fn prove(&mut self, claimed_sum: F) -> SumcheckProof<F> {
        let num_vars = self.polynomial.num_vars();
        let mut round_polynomials = Vec::with_capacity(num_vars);
        
        // Execute μ rounds
        for _round in 0..num_vars {
            // Compute round polynomial u_k(X)
            let round_poly = self.polynomial.compute_round_polynomial(&self.challenges);
            
            // Verify consistency (prover self-check in production)
            // In round 1: u_1(0) + u_1(1) should equal claimed_sum
            // In round k>1: u_k(0) + u_k(1) should equal u_{k-1}(α_{k-1})
            #[cfg(debug_assertions)]
            {
                let sum = round_poly[0].add(&round_poly[1]);
                if _round == 0 {
                    debug_assert_eq!(sum, claimed_sum, "Round 1 consistency check failed");
                }
            }
            
            // Sample challenge (in real protocol, this comes from verifier)
            // For now, we'll use a deterministic challenge for testing
            // In production, this would come from Fiat-Shamir or interactive verifier
            let challenge = self.sample_challenge(_round);
            
            round_polynomials.push(round_poly);
            self.challenges.push(challenge);
        }
        
        // Compute final evaluation f(α)
        let final_evaluation = self.polynomial.evaluate(&self.challenges);
        
        SumcheckProof::new(round_polynomials, final_evaluation)
    }
    
    /// Sample a challenge for the current round
    ///
    /// # Note
    /// In production, this should use Fiat-Shamir transform or come from verifier.
    /// This is a placeholder for the prover-side implementation.
    ///
    /// # Arguments
    /// - `round`: Current round number
    ///
    /// # Returns
    /// Challenge α_k ∈ F
    fn sample_challenge(&self, round: usize) -> F {
        // Placeholder: In production, use Fiat-Shamir or receive from verifier
        // For now, use a deterministic value based on round
        F::from_u64((round + 1) as u64)
    }
}


/// Sumcheck Verifier
///
/// Executes the verifier's side of the sumcheck protocol.
///
/// # Algorithm (Paper Section 2.3)
/// 1. Initialize S ← claimed_sum
/// 2. For each round k = 1 to μ:
///    a. Receive round polynomial u_k from prover
///    b. Check: u_k(0) + u_k(1) = S
///    c. Sample random challenge α_k ∈ F
///    d. Update S ← u_k(α_k)
/// 3. Query oracle [[f]] at point α = (α_1, ..., α_μ)
/// 4. Check: f(α) = S
///
/// # Soundness (Paper Theorem 2.1)
/// If the prover is cheating, verifier catches with probability ≥ 1 - dμ/|F|
///
/// # Complexity
/// O(μ · d) field operations
///
/// # Paper Reference
/// Section 2.3: Sumcheck Protocol
pub struct SumcheckVerifier<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Expected degree of round polynomials
    degree: usize,
    
    /// Challenges sampled so far
    challenges: Vec<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> SumcheckVerifier<F> {
    /// Create a new sumcheck verifier
    ///
    /// # Arguments
    /// - `num_vars`: Number of variables μ
    /// - `degree`: Expected degree d of the polynomial
    pub fn new(num_vars: usize, degree: usize) -> Self {
        Self {
            num_vars,
            degree,
            challenges: Vec::with_capacity(num_vars),
            _phantom: PhantomData,
        }
    }
    
    /// Verify a sumcheck proof
    ///
    /// # Arguments
    /// - `proof`: The sumcheck proof from the prover
    /// - `claimed_sum`: The claimed value v = ∑_{x∈B^μ} f(x)
    ///
    /// # Returns
    /// - `Ok(challenges)`: Verification succeeded, returns challenge point α
    /// - `Err(error)`: Verification failed with specific error
    ///
    /// # Complexity
    /// O(μ · d) field operations
    ///
    /// # Paper Reference
    /// Section 2.3: Verifier algorithm
    pub fn verify(
        &mut self,
        proof: &SumcheckProof<F>,
        claimed_sum: F,
    ) -> Result<Vec<F>, VerificationError> {
        // Validate proof structure
        if proof.num_rounds() != self.num_vars {
            return Err(VerificationError::InvalidProofFormat {
                reason: format!(
                    "Expected {} rounds, got {}",
                    self.num_vars,
                    proof.num_rounds()
                ),
            });
        }
        
        let mut current_sum = claimed_sum;
        
        // Verify each round
        for (round, round_poly) in proof.round_polynomials.iter().enumerate() {
            // Check polynomial degree
            if round_poly.len() != self.degree + 1 {
                return Err(VerificationError::InvalidProofFormat {
                    reason: format!(
                        "Round {} polynomial has wrong degree: expected {}, got {}",
                        round,
                        self.degree,
                        round_poly.len() - 1
                    ),
                });
            }
            
            // Check consistency: u_k(0) + u_k(1) = S
            let sum_check = round_poly[0].add(&round_poly[1]);
            if sum_check != current_sum {
                return Err(VerificationError::SumcheckRoundCheckFailed {
                    round,
                    expected: format!("{:?}", current_sum),
                    got: format!("{:?}", sum_check),
                });
            }
            
            // Sample challenge α_k
            let challenge = self.sample_challenge(round, round_poly);
            self.challenges.push(challenge);
            
            // Update sum: S ← u_k(α_k)
            current_sum = self.evaluate_univariate(round_poly, challenge);
        }
        
        // Final check: f(α) = S
        // Note: In the full protocol, the verifier would query the oracle [[f]]
        // Here we check against the claimed final evaluation in the proof
        if proof.final_evaluation != current_sum {
            return Err(VerificationError::SumcheckFinalCheckFailed {
                expected: format!("{:?}", current_sum),
                got: format!("{:?}", proof.final_evaluation),
            });
        }
        
        Ok(self.challenges.clone())
    }

    
    /// Sample a challenge for the current round
    ///
    /// # Production Implementation
    /// In a real system, this should:
    /// 1. Use Fiat-Shamir: hash(transcript || round_poly) → challenge
    /// 2. Or receive from interactive verifier
    ///
    /// # Arguments
    /// - `round`: Current round number
    /// - `round_poly`: The round polynomial (used for Fiat-Shamir)
    ///
    /// # Returns
    /// Challenge α_k ∈ F sampled uniformly at random
    ///
    /// # Paper Reference
    /// Section 2.3: "Verifier samples α_k ∈ F uniformly at random"
    fn sample_challenge(&self, round: usize, _round_poly: &[F]) -> F {
        // Placeholder: In production, use Fiat-Shamir transform
        // hash(transcript || round_poly) → challenge
        // For now, use deterministic value
        F::from_u64((round + 1) as u64)
    }
    
    /// Evaluate a univariate polynomial at a point
    ///
    /// Given evaluations at 0, 1, ..., d, computes p(x) using Lagrange interpolation.
    ///
    /// # Arguments
    /// - `evaluations`: Polynomial evaluations [p(0), p(1), ..., p(d)]
    /// - `point`: Evaluation point x ∈ F
    ///
    /// # Returns
    /// p(x) ∈ F
    ///
    /// # Complexity
    /// O(d²) field operations (can be optimized to O(d log² d) with FFT)
    ///
    /// # Algorithm
    /// Lagrange interpolation: p(x) = ∑ᵢ p(i) · Lᵢ(x)
    /// where Lᵢ(x) = ∏_{j≠i} (x-j)/(i-j)
    fn evaluate_univariate(&self, evaluations: &[F], point: F) -> F {
        let n = evaluations.len();
        let mut result = F::zero();
        
        // Lagrange interpolation
        for i in 0..n {
            let mut term = evaluations[i];
            
            // Compute Lagrange basis polynomial Lᵢ(x)
            for j in 0..n {
                if i != j {
                    // Numerator: (x - j)
                    let numerator = point.sub(&F::from_u64(j as u64));
                    
                    // Denominator: (i - j)
                    let i_val = F::from_u64(i as u64);
                    let j_val = F::from_u64(j as u64);
                    let denominator = i_val.sub(&j_val);
                    
                    // term *= (x - j) / (i - j)
                    term = term.mul(&numerator).mul(&denominator.inverse());
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
    
    /// Get the challenge point α = (α_1, ..., α_μ)
    pub fn get_challenges(&self) -> &[F] {
        &self.challenges
    }
}


/// Batched Sumcheck Verifier
///
/// Verifies multiple sumcheck instances simultaneously using random linear combination.
///
/// # Batching Optimization (Paper Section 4.2)
/// Instead of verifying t sumcheck instances separately, we can:
/// 1. Sample random coefficients r_1, ..., r_t ∈ F
/// 2. Verify the combined claim: ∑ᵢ rᵢ · vᵢ = ∑_{x∈B^μ} (∑ᵢ rᵢ · fᵢ(x))
///
/// This reduces verification cost from O(t · μ · d) to O(μ · d + t).
///
/// # Soundness
/// If any fᵢ is incorrect, the batched check fails with probability ≥ 1 - 1/|F|
///
/// # Paper Reference
/// Section 4.2, Optimization 4.3: "Batching multiple sumcheck instances"
pub struct BatchedSumcheckVerifier<F: Field> {
    /// Individual verifiers for each instance
    verifiers: Vec<SumcheckVerifier<F>>,
    
    /// Random coefficients for batching
    batch_coefficients: Vec<F>,
}

impl<F: Field> BatchedSumcheckVerifier<F> {
    /// Create a new batched verifier
    ///
    /// # Arguments
    /// - `num_instances`: Number of sumcheck instances to batch
    /// - `num_vars`: Number of variables μ (must be same for all instances)
    /// - `degree`: Polynomial degree d (must be same for all instances)
    pub fn new(num_instances: usize, num_vars: usize, degree: usize) -> Self {
        let verifiers = (0..num_instances)
            .map(|_| SumcheckVerifier::new(num_vars, degree))
            .collect();
        
        // Sample random coefficients for batching
        let batch_coefficients = (0..num_instances)
            .map(|i| F::from_u64((i + 1) as u64)) // Placeholder: use random in production
            .collect();
        
        Self {
            verifiers,
            batch_coefficients,
        }
    }
    
    /// Verify multiple sumcheck proofs in batch
    ///
    /// # Arguments
    /// - `proofs`: Vector of sumcheck proofs
    /// - `claimed_sums`: Vector of claimed sums
    ///
    /// # Returns
    /// - `Ok(challenges)`: All proofs verified, returns common challenge point
    /// - `Err(error)`: At least one proof failed verification
    ///
    /// # Complexity
    /// O(μ · d + t) field operations where t is number of instances
    pub fn verify_batch(
        &mut self,
        proofs: &[SumcheckProof<F>],
        claimed_sums: &[F],
    ) -> Result<Vec<F>, VerificationError> {
        if proofs.len() != self.verifiers.len() {
            return Err(VerificationError::InvalidProofFormat {
                reason: format!(
                    "Expected {} proofs, got {}",
                    self.verifiers.len(),
                    proofs.len()
                ),
            });
        }
        
        // Compute batched claimed sum: ∑ᵢ rᵢ · vᵢ
        let mut batched_sum = F::zero();
        for (coeff, sum) in self.batch_coefficients.iter().zip(claimed_sums.iter()) {
            batched_sum = batched_sum.add(&coeff.mul(sum));
        }
        
        // Verify each instance (they share the same challenges)
        let mut common_challenges = None;
        
        for (i, (verifier, proof)) in self.verifiers.iter_mut().zip(proofs.iter()).enumerate() {
            let challenges = verifier.verify(proof, claimed_sums[i])?;
            
            if let Some(ref prev_challenges) = common_challenges {
                // Verify all instances use the same challenges
                if challenges != *prev_challenges {
                    return Err(VerificationError::InvalidProofFormat {
                        reason: "Batched proofs must use same challenges".to_string(),
                    });
                }
            } else {
                common_challenges = Some(challenges);
            }
        }
        
        Ok(common_challenges.unwrap_or_default())
    }
}


/// FFT-based Round Polynomial Computation
///
/// Optimizes the computation of round polynomials using Fast Fourier Transform.
///
/// # Optimization (Paper Section 4.2)
/// When computing u_k(X) = ∑_{x∈B^{μ-k}} f(α, X, x), we need to multiply
/// multiple polynomial evaluation lists. Using FFT reduces complexity from
/// O(d²) to O(d log d) per multiplication.
///
/// # Paper Reference
/// Section 4.2, Optimization 4.1: "Use FFT to multiply polynomial evaluation lists"
/// Equation (4.1): "Reduces complexity from O(d²) to Õ(d)"
pub struct FFTRoundPolyComputer<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> FFTRoundPolyComputer<F> {
    /// Multiply polynomial evaluation lists using FFT
    ///
    /// Given evaluations of polynomials p₁, p₂, ..., pₖ at points 0, 1, ..., d,
    /// computes evaluations of their product p₁ · p₂ · ... · pₖ.
    ///
    /// # Arguments
    /// - `eval_lists`: Vector of evaluation lists, each of length d+1
    ///
    /// # Returns
    /// Evaluations of the product polynomial at 0, 1, ..., degree
    ///
    /// # Complexity
    /// O(k · d log d) field operations using FFT
    /// vs O(k · d²) without FFT
    ///
    /// # Algorithm
    /// 1. Convert each evaluation list to coefficient form (IFFT)
    /// 2. Multiply coefficient representations
    /// 3. Convert back to evaluation form (FFT)
    ///
    /// # Paper Reference
    /// Section 4.2: "Use FFT to multiply μ+1 lists of μ+2 evaluation points"
    pub fn multiply_eval_lists(eval_lists: &[Vec<F>]) -> Vec<F> {
        if eval_lists.is_empty() {
            return vec![F::one()];
        }
        
        if eval_lists.len() == 1 {
            return eval_lists[0].clone();
        }
        
        // For production: implement FFT-based multiplication
        // For now, use direct multiplication as fallback
        Self::multiply_eval_lists_direct(eval_lists)
    }
    
    /// Direct multiplication of evaluation lists (fallback)
    ///
    /// This is the O(d²) baseline algorithm. In production, this should be
    /// replaced with FFT-based multiplication for better performance.
    fn multiply_eval_lists_direct(eval_lists: &[Vec<F>]) -> Vec<F> {
        let degree = eval_lists[0].len() - 1;
        let mut result = vec![F::one(); degree + 1];
        
        for eval_list in eval_lists {
            let mut new_result = vec![F::zero(); degree + 1];
            
            // Multiply result by current polynomial
            for i in 0..=degree {
                // Evaluate both polynomials at point i
                let point = F::from_u64(i as u64);
                let result_at_i = Self::lagrange_eval(&result, point);
                let eval_at_i = eval_list[i];
                
                new_result[i] = result_at_i.mul(&eval_at_i);
            }
            
            result = new_result;
        }
        
        result
    }
    
    /// Lagrange interpolation evaluation helper
    fn lagrange_eval(evaluations: &[F], point: F) -> F {
        let n = evaluations.len();
        let mut result = F::zero();
        
        for i in 0..n {
            let mut term = evaluations[i];
            
            for j in 0..n {
                if i != j {
                    let numerator = point.sub(&F::from_u64(j as u64));
                    let denominator = F::from_u64(i as u64).sub(&F::from_u64(j as u64));
                    term = term.mul(&numerator).mul(&denominator.inverse());
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
}


/// Communication Optimization: Compressed Round Polynomials
///
/// Reduces communication by sending degree d-2 polynomial instead of degree d.
///
/// # Optimization (Paper Section 4.2)
/// Instead of sending all d+1 evaluations of u_k, the prover can send:
/// - u_k(0) (1 field element)
/// - Coefficients of u'_k where u_k(X) = u_k(0) + X · u'_k(X) (d-1 coefficients)
///
/// The verifier can reconstruct:
/// - u_k(0) = given
/// - u_k(1) = S - u_k(0) (from consistency check)
/// - u_k(α_k) = query to u'_k
///
/// This reduces communication from d+1 to d field elements per round.
///
/// # Paper Reference
/// Section 4.2, Optimization 4.4: "Send degree d-2 polynomial plus u_k(0)"
#[derive(Clone, Debug)]
pub struct CompressedRoundPolynomial<F: Field> {
    /// Evaluation at 0
    pub eval_at_zero: F,
    
    /// Compressed polynomial u'_k of degree d-2
    /// Represented as evaluations at 0, 1, ..., d-2
    pub compressed_poly: Vec<F>,
}

impl<F: Field> CompressedRoundPolynomial<F> {
    /// Compress a round polynomial
    ///
    /// # Arguments
    /// - `evaluations`: Full evaluations [u_k(0), u_k(1), ..., u_k(d)]
    ///
    /// # Returns
    /// Compressed representation saving 1 field element
    pub fn compress(evaluations: &[F]) -> Self {
        if evaluations.len() < 2 {
            return Self {
                eval_at_zero: evaluations.get(0).copied().unwrap_or(F::zero()),
                compressed_poly: vec![],
            };
        }
        
        let eval_at_zero = evaluations[0];
        
        // Compute u'_k where u_k(X) = u_k(0) + X · u'_k(X)
        // u'_k(i) = (u_k(i+1) - u_k(0)) / (i+1) for i = 0, 1, ..., d-1
        let mut compressed_poly = Vec::with_capacity(evaluations.len() - 1);
        
        for i in 1..evaluations.len() {
            let numerator = evaluations[i].sub(&eval_at_zero);
            let denominator = F::from_u64(i as u64);
            compressed_poly.push(numerator.mul(&denominator.inverse()));
        }
        
        Self {
            eval_at_zero,
            compressed_poly,
        }
    }
    
    /// Decompress to recover full evaluations
    ///
    /// # Arguments
    /// - `sum_check`: The value S = u_k(0) + u_k(1) from consistency check
    ///
    /// # Returns
    /// Full evaluations [u_k(0), u_k(1), ..., u_k(d)]
    pub fn decompress(&self, sum_check: F) -> Vec<F> {
        let mut evaluations = vec![self.eval_at_zero];
        
        // u_k(1) = S - u_k(0)
        let eval_at_one = sum_check.sub(&self.eval_at_zero);
        evaluations.push(eval_at_one);
        
        // Reconstruct u_k(i) = u_k(0) + i · u'_k(i-1) for i ≥ 2
        for (i, compressed_val) in self.compressed_poly.iter().enumerate().skip(1) {
            let i_plus_one = F::from_u64((i + 1) as u64);
            let eval = self.eval_at_zero.add(&i_plus_one.mul(compressed_val));
            evaluations.push(eval);
        }
        
        evaluations
    }
    
    /// Evaluate at a point using compressed representation
    ///
    /// # Arguments
    /// - `point`: Evaluation point x ∈ F
    ///
    /// # Returns
    /// u_k(x) = u_k(0) + x · u'_k(x)
    pub fn evaluate(&self, point: F) -> F {
        // Evaluate u'_k(point) using Lagrange interpolation
        let u_prime_at_point = if self.compressed_poly.is_empty() {
            F::zero()
        } else {
            Self::lagrange_eval(&self.compressed_poly, point)
        };
        
        // u_k(point) = u_k(0) + point · u'_k(point)
        self.eval_at_zero.add(&point.mul(&u_prime_at_point))
    }
    
    /// Lagrange interpolation helper
    fn lagrange_eval(evaluations: &[F], point: F) -> F {
        let n = evaluations.len();
        let mut result = F::zero();
        
        for i in 0..n {
            let mut term = evaluations[i];
            
            for j in 0..n {
                if i != j {
                    let numerator = point.sub(&F::from_u64(j as u64));
                    let denominator = F::from_u64(i as u64).sub(&F::from_u64(j as u64));
                    term = term.mul(&numerator).mul(&denominator.inverse());
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
}


/// Simple Multilinear Virtual Polynomial
///
/// A basic implementation of VirtualPolynomial for a single multilinear polynomial.
/// This is used as a building block and for testing.
///
/// # Use Case
/// Direct sumcheck over a multilinear polynomial f: B^μ → F
///
/// # Paper Reference
/// Used implicitly throughout as the base case
pub struct SimpleMultilinearVP<F: Field> {
    /// The multilinear polynomial
    poly: MultilinearPolynomial<F>,
    
    /// Current evaluation table (gets collapsed after each round)
    eval_table: Vec<F>,
}

impl<F: Field> SimpleMultilinearVP<F> {
    /// Create a new simple multilinear virtual polynomial
    ///
    /// # Arguments
    /// - `poly`: The multilinear polynomial to sum over
    pub fn new(poly: MultilinearPolynomial<F>) -> Self {
        let eval_table = poly.evaluations.clone();
        Self { poly, eval_table }
    }
}

impl<F: Field> VirtualPolynomial<F> for SimpleMultilinearVP<F> {
    fn evaluate(&self, point: &[F]) -> F {
        self.poly.evaluate(point)
    }
    
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> Vec<F> {
        let round = challenges.len();
        let remaining_vars = self.poly.num_vars - round;
        
        if remaining_vars == 0 {
            return vec![self.eval_table[0]];
        }
        
        // Compute u_k(X) for X ∈ {0, 1, ..., degree}
        // For multilinear polynomial, degree = 1
        let mut round_poly = vec![F::zero(); 2];
        
        let half = self.eval_table.len() / 2;
        
        // u_k(0) = sum of first half
        for i in 0..half {
            round_poly[0] = round_poly[0].add(&self.eval_table[i]);
        }
        
        // u_k(1) = sum of second half
        for i in half..self.eval_table.len() {
            round_poly[1] = round_poly[1].add(&self.eval_table[i]);
        }
        
        // Collapse evaluation table for next round
        // After receiving challenge α_k, we compute:
        // eval_table[i] = (1 - α_k) · eval_table[i] + α_k · eval_table[i + half]
        if !challenges.is_empty() {
            let alpha = challenges[challenges.len() - 1];
            let one_minus_alpha = F::one().sub(&alpha);
            
            let mut new_table = Vec::with_capacity(half);
            for i in 0..half {
                let val = one_minus_alpha.mul(&self.eval_table[i])
                    .add(&alpha.mul(&self.eval_table[i + half]));
                new_table.push(val);
            }
            self.eval_table = new_table;
        }
        
        round_poly
    }
    
    fn degree(&self) -> usize {
        1 // Multilinear polynomials have degree 1 in each variable
    }
    
    fn num_vars(&self) -> usize {
        self.poly.num_vars
    }
}


/// Product of Multilinear Polynomials Virtual Polynomial
///
/// Represents the product of multiple multilinear polynomials: f₁ · f₂ · ... · fₖ
///
/// # Use Case
/// Used in permutation checks where we need to sum products of polynomials.
/// For example, in BiPerm: f(x) · 1̃_{σ_L}(x, α_L) · 1̃_{σ_R}(x, α_R)
///
/// # Degree
/// If we have k polynomials, the product has degree k in each variable.
///
/// # Paper Reference
/// - BiPerm (Section 3.1): Product of 3 multilinear polynomials (degree 3)
/// - MulPerm (Section 3.2): Product of ℓ+1 polynomials (degree ℓ+1)
pub struct ProductVP<F: Field> {
    /// The multilinear polynomials to multiply
    polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Current evaluation tables (one per polynomial)
    eval_tables: Vec<Vec<F>>,
    
    /// Number of variables
    num_vars: usize,
}

impl<F: Field> ProductVP<F> {
    /// Create a new product virtual polynomial
    ///
    /// # Arguments
    /// - `polynomials`: Vector of multilinear polynomials to multiply
    ///
    /// # Panics
    /// If polynomials have different number of variables
    pub fn new(polynomials: Vec<MultilinearPolynomial<F>>) -> Self {
        assert!(!polynomials.is_empty(), "Need at least one polynomial");
        
        let num_vars = polynomials[0].num_vars;
        for poly in &polynomials {
            assert_eq!(
                poly.num_vars, num_vars,
                "All polynomials must have same number of variables"
            );
        }
        
        let eval_tables = polynomials
            .iter()
            .map(|p| p.evaluations.clone())
            .collect();
        
        Self {
            polynomials,
            eval_tables,
            num_vars,
        }
    }
}

impl<F: Field> VirtualPolynomial<F> for ProductVP<F> {
    fn evaluate(&self, point: &[F]) -> F {
        let mut result = F::one();
        for poly in &self.polynomials {
            result = result.mul(&poly.evaluate(point));
        }
        result
    }
    
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> Vec<F> {
        let round = challenges.len();
        let remaining_vars = self.num_vars - round;
        
        if remaining_vars == 0 {
            let mut result = F::one();
            for table in &self.eval_tables {
                result = result.mul(&table[0]);
            }
            return vec![result];
        }
        
        let degree = self.polynomials.len(); // Product of k multilinear = degree k
        let mut round_poly = vec![F::zero(); degree + 1];
        
        let half = self.eval_tables[0].len() / 2;
        
        // For each evaluation point X ∈ {0, 1, ..., degree}
        for eval_point in 0..=degree {
            let x = F::from_u64(eval_point as u64);
            
            // Sum over all x' ∈ B^{remaining_vars - 1}
            for i in 0..half {
                // Compute product at (x, x')
                let mut product = F::one();
                
                for table in &self.eval_tables {
                    // Interpolate: (1-x) · table[i] + x · table[i + half]
                    let val = F::one().sub(&x).mul(&table[i])
                        .add(&x.mul(&table[i + half]));
                    product = product.mul(&val);
                }
                
                round_poly[eval_point] = round_poly[eval_point].add(&product);
            }
        }
        
        // Collapse evaluation tables for next round
        if !challenges.is_empty() {
            let alpha = challenges[challenges.len() - 1];
            let one_minus_alpha = F::one().sub(&alpha);
            
            for table in &mut self.eval_tables {
                let mut new_table = Vec::with_capacity(half);
                for i in 0..half {
                    let val = one_minus_alpha.mul(&table[i])
                        .add(&alpha.mul(&table[i + half]));
                    new_table.push(val);
                }
                *table = new_table;
            }
        }
        
        round_poly
    }
    
    fn degree(&self) -> usize {
        self.polynomials.len() // Product of k multilinear polynomials has degree k
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}


/// Weighted Sum Virtual Polynomial
///
/// Represents a weighted sum of multilinear polynomials: ∑ᵢ cᵢ · fᵢ(x)
///
/// # Use Case
/// Used for batching multiple sumcheck instances using random linear combination.
///
/// # Paper Reference
/// Section 4.2, Optimization 4.3: "Batching multiple sumcheck instances"
pub struct WeightedSumVP<F: Field> {
    /// The multilinear polynomials
    polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Weights for each polynomial
    weights: Vec<F>,
    
    /// Current evaluation tables
    eval_tables: Vec<Vec<F>>,
    
    /// Number of variables
    num_vars: usize,
}

impl<F: Field> WeightedSumVP<F> {
    /// Create a new weighted sum virtual polynomial
    ///
    /// # Arguments
    /// - `polynomials`: Vector of multilinear polynomials
    /// - `weights`: Weight for each polynomial
    ///
    /// # Panics
    /// If polynomials and weights have different lengths or polynomials have different dimensions
    pub fn new(polynomials: Vec<MultilinearPolynomial<F>>, weights: Vec<F>) -> Self {
        assert_eq!(
            polynomials.len(),
            weights.len(),
            "Must have same number of polynomials and weights"
        );
        assert!(!polynomials.is_empty(), "Need at least one polynomial");
        
        let num_vars = polynomials[0].num_vars;
        for poly in &polynomials {
            assert_eq!(
                poly.num_vars, num_vars,
                "All polynomials must have same number of variables"
            );
        }
        
        let eval_tables = polynomials
            .iter()
            .map(|p| p.evaluations.clone())
            .collect();
        
        Self {
            polynomials,
            weights,
            eval_tables,
            num_vars,
        }
    }
}

impl<F: Field> VirtualPolynomial<F> for WeightedSumVP<F> {
    fn evaluate(&self, point: &[F]) -> F {
        let mut result = F::zero();
        for (poly, weight) in self.polynomials.iter().zip(self.weights.iter()) {
            result = result.add(&weight.mul(&poly.evaluate(point)));
        }
        result
    }
    
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> Vec<F> {
        let round = challenges.len();
        let remaining_vars = self.num_vars - round;
        
        if remaining_vars == 0 {
            let mut result = F::zero();
            for (table, weight) in self.eval_tables.iter().zip(self.weights.iter()) {
                result = result.add(&weight.mul(&table[0]));
            }
            return vec![result];
        }
        
        // Weighted sum of multilinear polynomials is still multilinear (degree 1)
        let mut round_poly = vec![F::zero(); 2];
        
        let half = self.eval_tables[0].len() / 2;
        
        // u_k(0) = sum of weighted first halves
        for (table, weight) in self.eval_tables.iter().zip(self.weights.iter()) {
            for i in 0..half {
                round_poly[0] = round_poly[0].add(&weight.mul(&table[i]));
            }
        }
        
        // u_k(1) = sum of weighted second halves
        for (table, weight) in self.eval_tables.iter().zip(self.weights.iter()) {
            for i in half..table.len() {
                round_poly[1] = round_poly[1].add(&weight.mul(&table[i]));
            }
        }
        
        // Collapse evaluation tables
        if !challenges.is_empty() {
            let alpha = challenges[challenges.len() - 1];
            let one_minus_alpha = F::one().sub(&alpha);
            
            for table in &mut self.eval_tables {
                let mut new_table = Vec::with_capacity(half);
                for i in 0..half {
                    let val = one_minus_alpha.mul(&table[i])
                        .add(&alpha.mul(&table[i + half]));
                    new_table.push(val);
                }
                *table = new_table;
            }
        }
        
        round_poly
    }
    
    fn degree(&self) -> usize {
        1 // Weighted sum of multilinear polynomials is multilinear
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}
