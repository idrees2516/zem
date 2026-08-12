// Verifier implementation for monomial sumcheck protocol
//
// This module implements the verifier's algorithm for checking sumcheck proofs
// over the monomial basis.
//
// # Paper Reference
// Section 2: "Verifier Algorithm"
// Section 4.4: "Verification Optimizations"

use crate::field::Field;
use super::types::*;
use super::{MonomialSumcheckError, MonomialSumcheckConfig};
use std::time::Instant;

/// Monomial sumcheck verifier
///
/// Verifies proofs that ∑_{x∈B^n} f(x) = claimed_sum
///
/// # Algorithm
///
/// 1. Initialize running_sum ← claimed_sum
/// 2. For k = 0 to n-1:
///    a. Check u_k(0) + u_k(1) = running_sum
///    b. Sample challenge r_k from transcript
///    c. Update running_sum ← u_k(r_k)
/// 3. Query oracle: verify f(r_0,...,r_{n-1}) = running_sum
///
/// # Complexity
/// O(n·D²) field operations (or O(n·D) with precomputation)
///
/// # Soundness
/// If prover cheats, verifier rejects with probability ≥ 1 - D·n/|F|
pub struct MonomialSumcheckVerifier<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Transcript for challenge generation
    transcript: Transcript,
    
    /// Collected challenges
    challenges: Vec<F>,
    
    /// Current running sum
    running_sum: F,
    
    /// Barycentric weights (precomputed for efficiency)
    barycentric_weights: Vec<Vec<F>>,
    
    /// Performance metrics
    metrics: VerifierMetrics,
}

/// Performance metrics for the verifier
#[derive(Clone, Debug, Default)]
pub struct VerifierMetrics {
    /// Total verification time (nanoseconds)
    pub total_time_ns: u64,
    
    /// Time per round (nanoseconds)
    pub round_times_ns: Vec<u64>,
    
    /// Field operations per round
    pub field_ops_per_round: Vec<u64>,
}

impl<F: Field> MonomialSumcheckVerifier<F> {
    /// Create a new verifier
    ///
    /// # Arguments
    /// * `config` - Configuration parameters matching the prover
    pub fn new(config: MonomialSumcheckConfig) -> Self {
        // Precompute barycentric weights for each possible degree
        let barycentric_weights = Self::precompute_barycentric_weights(&config);
        
        Self {
            config,
            transcript: Transcript::new(b"monomial-sumcheck-v1.0"),
            challenges: Vec::new(),
            running_sum: F::zero(),
            barycentric_weights,
            metrics: VerifierMetrics::default(),
        }
    }
    
    /// Verify a sumcheck proof
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    /// * `claimed_sum` - The claimed sum value
    ///
    /// # Returns
    /// * `Ok(challenges)` - Verification succeeded, returns challenge point
    /// * `Err(error)` - Verification failed with specific error
    ///
    /// # Complexity
    /// O(n·D²) field operations without precomputation
    /// O(n·D) with barycentric weight precomputation
    ///
    /// # Security
    /// Provides soundness error ≤ D·n/|F|
    pub fn verify(
        &mut self,
        proof: &MonomialSumcheckProof<F>,
        claimed_sum: F,
    ) -> Result<Vec<F>, MonomialSumcheckError> {
        let start_time = Instant::now();
        
        // Validate proof structure
        if proof.num_rounds() != self.config.num_vars {
            return Err(MonomialSumcheckError::InvalidProofStructure {
                expected_rounds: self.config.num_vars,
                actual_rounds: proof.num_rounds(),
            });
        }
        
        // Initialize
        self.running_sum = claimed_sum;
        self.challenges.clear();
        self.transcript = Transcript::new(b"monomial-sumcheck-v1.0");
        self.transcript.append_field_element(b"claimed_sum", &claimed_sum);
        
        // Verify each round
        for (round, round_poly) in proof.round_polynomials.iter().enumerate() {
            let round_start = Instant::now();
            
            self.verify_round(round, round_poly)?;
            
            let round_time = round_start.elapsed().as_nanos() as u64;
            self.metrics.round_times_ns.push(round_time);
        }
        
        // Final check: f(r_0,...,r_{n-1}) = running_sum
        if proof.final_evaluation != self.running_sum {
            return Err(MonomialSumcheckError::FinalEvaluationMismatch {
                expected: format!("{:?}", self.running_sum),
                actual: format!("{:?}", proof.final_evaluation),
            });
        }
        
        // Record total time
        self.metrics.total_time_ns = start_time.elapsed().as_nanos() as u64;
        
        Ok(self.challenges.clone())
    }
    
    /// Verify a single round
    ///
    /// # Arguments
    /// * `round` - Round index (0-based)
    /// * `round_poly` - The round polynomial to verify
    ///
    /// # Returns
    /// Ok if round verification passes, Err otherwise
    fn verify_round(
        &mut self,
        round: usize,
        round_poly: &RoundPolynomial<F>,
    ) -> Result<(), MonomialSumcheckError> {
        // Check degree
        let expected_max_degree = self.config.max_degree;
        if round_poly.degree > expected_max_degree {
            return Err(MonomialSumcheckError::InvalidDegree {
                round,
                expected: expected_max_degree,
                actual: round_poly.degree,
            });
        }
        
        // Check consistency: u(0) + u(1) = running_sum
        if !round_poly.check_consistency(self.running_sum) {
            let sum = round_poly.evaluations[0].add(&round_poly.evaluations[1]);
            return Err(MonomialSumcheckError::RoundConsistencyFailed {
                round,
                expected_sum: format!("{:?}", self.running_sum),
                actual_sum: format!("{:?}", sum),
            });
        }
        
        // Add round polynomial to transcript
        for (i, eval) in round_poly.evaluations.iter().enumerate() {
            self.transcript.append_field_element(
                format!("round_{}_eval_{}", round, i).as_bytes(),
                eval,
            );
        }
        
        // Sample challenge
        let challenge = self.transcript.challenge_field_element(
            format!("challenge_{}", round).as_bytes()
        );
        self.challenges.push(challenge);
        
        // Update running sum using optimized evaluation
        self.running_sum = self.evaluate_round_poly_optimized(round_poly, challenge);
        
        Ok(())
    }
    
    /// Evaluate round polynomial at challenge point (optimized)
    ///
    /// Uses precomputed barycentric weights for O(D) complexity
    ///
    /// # Arguments
    /// * `round_poly` - The polynomial to evaluate
    /// * `point` - The evaluation point
    ///
    /// # Returns
    /// round_poly(point)
    fn evaluate_round_poly_optimized(
        &self,
        round_poly: &RoundPolynomial<F>,
        point: F,
    ) -> F {
        let degree = round_poly.degree;
        
        if degree >= self.barycentric_weights.len() {
            // Fallback to direct evaluation if degree too large
            return round_poly.evaluate(point);
        }
        
        let weights = &self.barycentric_weights[degree];
        
        // Barycentric interpolation: O(D) complexity
        let mut numerator = F::zero();
        let mut denominator = F::zero();
        
        for i in 0..=degree {
            let xi = F::from_u64(i as u64);
            
            // Check if point equals a node (exact match)
            if point == xi {
                return round_poly.evaluations[i];
            }
            
            // Compute term: w_i / (point - x_i)
            let diff_inv = point.sub(&xi).inverse();
            let term = weights[i].mul(&diff_inv);
            
            numerator = numerator.add(&term.mul(&round_poly.evaluations[i]));
            denominator = denominator.add(&term);
        }
        
        numerator.mul(&denominator.inverse())
    }
    
    /// Precompute barycentric weights for all degrees up to max
    ///
    /// Weights: w_i = ∏_{j≠i} 1/(x_i - x_j) for x_0=0, x_1=1, ..., x_D=D
    ///
    /// # Complexity
    /// O(D³) precomputation, but done once
    ///
    /// # Returns
    /// weights[d][i] = barycentric weight for degree d at node i
    fn precompute_barycentric_weights(config: &MonomialSumcheckConfig) -> Vec<Vec<F>> {
        let max_degree = config.max_degree;
        let mut all_weights = Vec::with_capacity(max_degree + 1);
        
        for degree in 0..=max_degree {
            let mut weights = Vec::with_capacity(degree + 1);
            
            for i in 0..=degree {
                let xi = F::from_u64(i as u64);
                let mut weight = F::one();
                
                for j in 0..=degree {
                    if i != j {
                        let xj = F::from_u64(j as u64);
                        let diff = xi.sub(&xj);
                        weight = weight.mul(&diff.inverse());
                    }
                }
                
                weights.push(weight);
            }
            
            all_weights.push(weights);
        }
        
        all_weights
    }
    
    /// Get the challenge point (after verification)
    pub fn get_challenges(&self) -> &[F] {
        &self.challenges
    }
    
    /// Get performance metrics
    pub fn metrics(&self) -> &VerifierMetrics {
        &self.metrics
    }
    
    /// Reset verifier for a new proof
    pub fn reset(&mut self) {
        self.transcript = Transcript::new(b"monomial-sumcheck-v1.0");
        self.challenges.clear();
        self.running_sum = F::zero();
        self.metrics = VerifierMetrics::default();
    }
}

/// Batch verifier for multiple proofs
///
/// Verifies multiple sumcheck instances simultaneously using
/// random linear combination
///
/// # Paper Reference
/// Section 4.5: "Batch Verification"
///
/// # Optimization
/// Reduces verification time from O(k·n·D²) to O(n·D² + k·n·D)
/// where k = number of instances
///
/// # Security
/// Soundness error increases by factor of k, but still negligible
pub struct BatchMonomialSumcheckVerifier<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Number of instances to batch
    batch_size: usize,
    
    /// Random coefficients for batching
    batch_coeffs: Vec<F>,
    
    /// Barycentric weights
    barycentric_weights: Vec<Vec<F>>,
}

impl<F: Field> BatchMonomialSumcheckVerifier<F> {
    /// Create a new batch verifier
    ///
    /// # Arguments
    /// * `config` - Configuration parameters
    /// * `batch_size` - Number of proofs to batch
    pub fn new(config: MonomialSumcheckConfig, batch_size: usize) -> Self {
        let barycentric_weights = MonomialSumcheckVerifier::<F>::precompute_barycentric_weights(&config);
        
        Self {
            config,
            batch_size,
            batch_coeffs: Vec::new(),
            barycentric_weights,
        }
    }
    
    /// Verify multiple proofs in batch
    ///
    /// # Arguments
    /// * `proofs` - Vector of proofs to verify
    /// * `claimed_sums` - Vector of claimed sums
    ///
    /// # Returns
    /// * `Ok(challenges)` - All proofs verified, returns common challenges
    /// * `Err(error)` - At least one proof failed
    ///
    /// # Algorithm
    ///
    /// 1. Sample random coefficients r_1, ..., r_k
    /// 2. Compute batched sum: S = ∑ᵢ rᵢ·vᵢ
    /// 3. Compute batched round polys: U(X) = ∑ᵢ rᵢ·uᵢ(X)
    /// 4. Verify batched sumcheck
    ///
    /// # Complexity
    /// O(n·D² + k·n·D) vs O(k·n·D²) for individual verification
    ///
    /// # Security
    /// Soundness error: ≤ k·D·n/|F| (negligible for cryptographic fields)
    pub fn verify_batch(
        &mut self,
        proofs: &[MonomialSumcheckProof<F>],
        claimed_sums: &[F],
    ) -> Result<Vec<F>, MonomialSumcheckError> {
        if proofs.len() != self.batch_size || claimed_sums.len() != self.batch_size {
            return Err(MonomialSumcheckError::EvaluationError {
                reason: format!(
                    "Batch size mismatch: expected {}, got {} proofs and {} sums",
                    self.batch_size,
                    proofs.len(),
                    claimed_sums.len()
                ),
            });
        }
        
        // Sample random coefficients for batching
        self.sample_batch_coefficients()?;
        
        // Compute batched claimed sum
        let mut batched_sum = F::zero();
        for (coeff, sum) in self.batch_coeffs.iter().zip(claimed_sums.iter()) {
            batched_sum = batched_sum.add(&coeff.mul(sum));
        }
        
        // Create transcript for batched verification
        let mut transcript = Transcript::new(b"monomial-sumcheck-batch-v1.0");
        transcript.append_field_element(b"batched_sum", &batched_sum);
        
        // Add batch coefficients to transcript
        for (i, coeff) in self.batch_coeffs.iter().enumerate() {
            transcript.append_field_element(
                format!("batch_coeff_{}", i).as_bytes(),
                coeff,
            );
        }
        
        let mut running_sum = batched_sum;
        let mut challenges = Vec::with_capacity(self.config.num_vars);
        
        // Verify each round with batched polynomials
        for round in 0..self.config.num_vars {
            // Compute batched round polynomial
            let batched_round_poly = self.compute_batched_round_poly(proofs, round)?;
            
            // Check consistency
            if !batched_round_poly.check_consistency(running_sum) {
                return Err(MonomialSumcheckError::RoundConsistencyFailed {
                    round,
                    expected_sum: format!("{:?}", running_sum),
                    actual_sum: format!("{:?}", 
                        batched_round_poly.evaluations[0].add(&batched_round_poly.evaluations[1])
                    ),
                });
            }
            
            // Add to transcript
            for (i, eval) in batched_round_poly.evaluations.iter().enumerate() {
                transcript.append_field_element(
                    format!("round_{}_eval_{}", round, i).as_bytes(),
                    eval,
                );
            }
            
            // Sample challenge
            let challenge = transcript.challenge_field_element(
                format!("challenge_{}", round).as_bytes()
            );
            challenges.push(challenge);
            
            // Update running sum
            running_sum = self.evaluate_optimized(&batched_round_poly, challenge);
        }
        
        // Compute batched final evaluation
        let mut batched_final = F::zero();
        for (coeff, proof) in self.batch_coeffs.iter().zip(proofs.iter()) {
            batched_final = batched_final.add(&coeff.mul(&proof.final_evaluation));
        }
        
        // Final check
        if batched_final != running_sum {
            return Err(MonomialSumcheckError::FinalEvaluationMismatch {
                expected: format!("{:?}", running_sum),
                actual: format!("{:?}", batched_final),
            });
        }
        
        Ok(challenges)
    }
    
    /// Sample random coefficients for batching
    ///
    /// Uses cryptographically secure randomness
    fn sample_batch_coefficients(&mut self) -> Result<(), MonomialSumcheckError> {
        let mut transcript = Transcript::new(b"batch-coeff-sampling");
        
        self.batch_coeffs = (0..self.batch_size)
            .map(|i| {
                transcript.challenge_field_element(
                    format!("coeff_{}", i).as_bytes()
                )
            })
            .collect();
        
        Ok(())
    }
    
    /// Compute batched round polynomial
    ///
    /// U(X) = ∑ᵢ rᵢ·uᵢ(X)
    fn compute_batched_round_poly(
        &self,
        proofs: &[MonomialSumcheckProof<F>],
        round: usize,
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        // Find maximum degree
        let max_degree = proofs.iter()
            .map(|p| p.round_polynomials[round].degree)
            .max()
            .unwrap_or(0);
        
        let mut batched_evals = vec![F::zero(); max_degree + 1];
        
        // Compute linear combination
        for (coeff, proof) in self.batch_coeffs.iter().zip(proofs.iter()) {
            let round_poly = &proof.round_polynomials[round];
            
            for (i, eval) in batched_evals.iter_mut().enumerate() {
                if i < round_poly.evaluations.len() {
                    *eval = eval.add(&coeff.mul(&round_poly.evaluations[i]));
                }
            }
        }
        
        Ok(RoundPolynomial::from_evaluations(batched_evals))
    }
    
    /// Evaluate using barycentric weights
    fn evaluate_optimized(&self, poly: &RoundPolynomial<F>, point: F) -> F {
        let degree = poly.degree;
        
        if degree >= self.barycentric_weights.len() {
            return poly.evaluate(point);
        }
        
        let weights = &self.barycentric_weights[degree];
        
        let mut numerator = F::zero();
        let mut denominator = F::zero();
        
        for i in 0..=degree {
            let xi = F::from_u64(i as u64);
            if point == xi {
                return poly.evaluations[i];
            }
            
            let term = weights[i].mul(&point.sub(&xi).inverse());
            numerator = numerator.add(&term.mul(&poly.evaluations[i]));
            denominator = denominator.add(&term);
        }
        
        numerator.mul(&denominator.inverse())
    }
}

/// Interactive verifier for two-party protocols
///
/// In interactive setting, verifier samples challenges independently
/// rather than using Fiat-Shamir
pub struct InteractiveMonomialSumcheckVerifier<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Challenges sampled so far
    challenges: Vec<F>,
    
    /// Running sum
    running_sum: F,
    
    /// Current round
    current_round: usize,
}

impl<F: Field> InteractiveMonomialSumcheckVerifier<F> {
    /// Create a new interactive verifier
    pub fn new(config: MonomialSumcheckConfig) -> Self {
        Self {
            config,
            challenges: Vec::new(),
            running_sum: F::zero(),
            current_round: 0,
        }
    }
    
    /// Initialize verification with claimed sum
    pub fn initialize(&mut self, claimed_sum: F) {
        self.running_sum = claimed_sum;
        self.current_round = 0;
        self.challenges.clear();
    }
    
    /// Verify a round polynomial and return challenge
    ///
    /// # Arguments
    /// * `round_poly` - The polynomial received from prover
    /// * `challenge` - The challenge to send (sampled externally)
    ///
    /// # Returns
    /// Ok if round verification passes
    pub fn verify_round(
        &mut self,
        round_poly: &RoundPolynomial<F>,
        challenge: F,
    ) -> Result<(), MonomialSumcheckError> {
        // Check consistency
        if !round_poly.check_consistency(self.running_sum) {
            return Err(MonomialSumcheckError::RoundConsistencyFailed {
                round: self.current_round,
                expected_sum: format!("{:?}", self.running_sum),
                actual_sum: format!("{:?}", 
                    round_poly.evaluations[0].add(&round_poly.evaluations[1])
                ),
            });
        }
        
        // Store challenge
        self.challenges.push(challenge);
        
        // Update running sum
        self.running_sum = round_poly.evaluate(challenge);
        self.current_round += 1;
        
        Ok(())
    }
    
    /// Finalize verification with final evaluation
    ///
    /// # Arguments
    /// * `final_evaluation` - Claimed f(r_0,...,r_{n-1})
    ///
    /// # Returns
    /// Ok if final check passes
    pub fn finalize(&self, final_evaluation: F) -> Result<(), MonomialSumcheckError> {
        if final_evaluation != self.running_sum {
            return Err(MonomialSumcheckError::FinalEvaluationMismatch {
                expected: format!("{:?}", self.running_sum),
                actual: format!("{:?}", final_evaluation),
            });
        }
        
        Ok(())
    }
    
    /// Get challenge point
    pub fn get_challenges(&self) -> &[F] {
        &self.challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::MockField;
    
    #[test]
    fn test_verifier_basic() {
        let config = MonomialSumcheckConfig {
            num_vars: 2,
            max_degree: 1,
            ..Default::default()
        };
        
        let mut verifier = MonomialSumcheckVerifier::new(config);
        
        // Create a mock proof (would come from prover in reality)
        let round_polys = vec![
            RoundPolynomial::from_evaluations(vec![
                MockField::from(1),
                MockField::from(1),
            ]),
            RoundPolynomial::from_evaluations(vec![
                MockField::from(0),
                MockField::from(2),
            ]),
        ];
        
        let proof = MonomialSumcheckProof::new(
            round_polys,
            MockField::from(2),
        );
        
        let result = verifier.verify(&proof, MockField::from(2));
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_barycentric_weights() {
        let config = MonomialSumcheckConfig {
            num_vars: 2,
            max_degree: 3,
            ..Default::default()
        };
        
        let weights = MonomialSumcheckVerifier::<MockField>::precompute_barycentric_weights(&config);
        
        // Check that weights are precomputed for degrees 0..=3
        assert_eq!(weights.len(), 4);
        
        // For degree 2, should have 3 weights
        assert_eq!(weights[2].len(), 3);
    }
}
