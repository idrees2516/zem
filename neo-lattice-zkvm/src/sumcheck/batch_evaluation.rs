// Batch Evaluation Argument (Shout-style)
// Reduces T evaluations to single random evaluation
//
// Paper Reference: "Twist and Shout" (2025-105), Section 3 "Batch Evaluation"
// Also: "Sum-check Is All You Need" (2025-2041), Section 4.4
//
// This module implements a critical optimization for reducing multiple polynomial
// evaluation claims to a single claim using random linear combination.
//
// Key Problem:
// After sum-check, we often need to verify multiple polynomial evaluations:
// - f_1(r) = y_1
// - f_2(r) = y_2
// - ...
// - f_T(r) = y_T
//
// Naively, this requires T separate opening proofs, which is expensive.
//
// Solution: Batch Evaluation via Random Linear Combination
// Verifier sends random challenge α ∈ F
// Prover proves: Σ_i α^i · f_i(r) = Σ_i α^i · y_i
//
// By Schwartz-Zippel lemma, if this holds for random α, then all individual
// evaluations hold with high probability.
//
// Benefits:
// 1. Communication: T proofs → 1 proof
// 2. Verification: T checks → 1 check
// 3. Soundness: Only loses factor of T/|F| in soundness error
//
// Mathematical Background:
// Define the batched polynomial:
// g(x) = Σ_{i=1}^T α^{i-1} · f_i(x)
//
// And batched evaluation:
// y = Σ_{i=1}^T α^{i-1} · y_i
//
// Then proving g(r) = y is equivalent to proving all f_i(r) = y_i
// with soundness error ≤ T/|F|.
//
// Shout Optimization:
// The "Shout" paper introduces an additional optimization for memory checking:
// Instead of committing to all f_i separately, we can commit to their sum
// and use a clever encoding to batch verify.
//
// This is particularly useful for memory checking where we have many
// read/write operations to verify.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey};

/// Batch evaluation claim
///
/// Represents a claim that f_i(r) = y_i for some polynomial f_i
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    /// Polynomial identifier (index or commitment)
    pub poly_id: usize,
    
    /// Evaluation point r
    pub point: Vec<F>,
    
    /// Claimed evaluation y_i = f_i(r)
    pub claimed_value: F,
}

impl<F: Field> EvaluationClaim<F> {
    /// Create new evaluation claim
    pub fn new(poly_id: usize, point: Vec<F>, claimed_value: F) -> Self {
        Self {
            poly_id,
            point,
            claimed_value,
        }
    }
}

/// Batch evaluation prover
///
/// Paper Reference: "Twist and Shout", Section 3.1
///
/// Combines multiple evaluation claims into a single claim using
/// random linear combination.
pub struct BatchEvaluationProver<F: Field> {
    /// The polynomials being evaluated
    polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Evaluation claims to batch
    claims: Vec<EvaluationClaim<F>>,
    
    /// Random challenge for batching (from verifier)
    alpha: Option<F>,
}

impl<F: Field> BatchEvaluationProver<F> {
    /// Create batch evaluation prover
    ///
    /// Paper Reference: Section 3.1, Setup
    ///
    /// # Arguments
    /// * `polynomials` - The polynomials f_1, ..., f_T
    /// * `claims` - Evaluation claims for each polynomial
    ///
    /// # Returns
    /// Prover that can batch all claims into one
    pub fn new(
        polynomials: Vec<MultilinearPolynomial<F>>,
        claims: Vec<EvaluationClaim<F>>,
    ) -> Result<Self, String> {
        if polynomials.len() != claims.len() {
            return Err(format!(
                "Number of polynomials ({}) must match number of claims ({})",
                polynomials.len(), claims.len()
            ));
        }
        
        // Verify all claims are for the same point
        if !claims.is_empty() {
            let point = &claims[0].point;
            for claim in &claims[1..] {
                if claim.point != *point {
                    return Err("All claims must be for the same evaluation point".to_string());
                }
            }
        }
        
        Ok(Self {
            polynomials,
            claims,
            alpha: None,
        })
    }
    
    /// Set batching challenge
    ///
    /// Paper Reference: Section 3.1, Step 1
    ///
    /// The verifier sends random α ∈ F to batch the claims.
    /// This must be done after the prover commits to all polynomials
    /// to ensure soundness.
    pub fn set_challenge(&mut self, alpha: F) {
        self.alpha = Some(alpha);
    }
    
    /// Compute batched polynomial
    ///
    /// Paper Reference: Section 3.1, Step 2
    ///
    /// Computes g(x) = Σ_{i=1}^T α^{i-1} · f_i(x)
    ///
    /// This is the polynomial we'll prove an evaluation for.
    ///
    /// Key Property:
    /// If g(r) = Σ_i α^{i-1} · y_i, then with high probability
    /// f_i(r) = y_i for all i.
    pub fn compute_batched_polynomial(&self) -> Result<MultilinearPolynomial<F>, String> {
        let alpha = self.alpha.ok_or("Challenge not set")?;
        
        if self.polynomials.is_empty() {
            return Err("No polynomials to batch".to_string());
        }
        
        let num_vars = self.polynomials[0].num_vars();
        let size = 1 << num_vars;
        
        // Initialize batched evaluations to zero
        let mut batched_evals = vec![F::zero(); size];
        
        // Compute g(x) = Σ_i α^{i-1} · f_i(x)
        let mut alpha_power = F::one();
        
        for poly in &self.polynomials {
            let evals = poly.evaluations();
            
            for (j, eval) in evals.iter().enumerate() {
                batched_evals[j] = batched_evals[j].add(&alpha_power.mul(eval));
            }
            
            alpha_power = alpha_power.mul(&alpha);
        }
        
        MultilinearPolynomial::from_evaluations(batched_evals)
    }
    
    /// Compute batched claimed value
    ///
    /// Paper Reference: Section 3.1, Step 2
    ///
    /// Computes y = Σ_{i=1}^T α^{i-1} · y_i
    ///
    /// This is the claimed evaluation of the batched polynomial.
    pub fn compute_batched_claim(&self) -> Result<F, String> {
        let alpha = self.alpha.ok_or("Challenge not set")?;
        
        let mut batched_value = F::zero();
        let mut alpha_power = F::one();
        
        for claim in &self.claims {
            batched_value = batched_value.add(&alpha_power.mul(&claim.claimed_value));
            alpha_power = alpha_power.mul(&alpha);
        }
        
        Ok(batched_value)
    }
    
    /// Verify batching soundness
    ///
    /// Paper Reference: Section 3.1, Theorem 3.1
    ///
    /// Theorem: If g(r) = y for random α, then f_i(r) = y_i for all i
    /// with probability ≥ 1 - T/|F|
    ///
    /// Proof: By Schwartz-Zippel lemma on the polynomial
    /// p(α) = Σ_i α^{i-1} · (f_i(r) - y_i)
    ///
    /// This polynomial has degree ≤ T-1, so it has at most T-1 roots.
    /// If p(α) = 0 for random α, then p is the zero polynomial with
    /// probability ≥ 1 - (T-1)/|F|.
    pub fn soundness_error(&self, field_size: u64) -> f64 {
        let t = self.claims.len() as f64;
        t / (field_size as f64)
    }
}

/// Batch evaluation verifier
pub struct BatchEvaluationVerifier<F: Field> {
    /// Number of claims being batched
    num_claims: usize,
    
    /// Evaluation point (same for all claims)
    point: Vec<F>,
    
    /// Random challenge for batching
    alpha: F,
}

impl<F: Field> BatchEvaluationVerifier<F> {
    /// Create batch evaluation verifier
    pub fn new(num_claims: usize, point: Vec<F>, alpha: F) -> Self {
        Self {
            num_claims,
            point,
            alpha,
        }
    }
    
    /// Compute batched claimed value from individual claims
    ///
    /// The verifier computes y = Σ_i α^{i-1} · y_i
    /// and checks that the batched polynomial evaluates to y at r.
    pub fn compute_batched_claim(&self, claimed_values: &[F]) -> Result<F, String> {
        if claimed_values.len() != self.num_claims {
            return Err(format!(
                "Expected {} claimed values, got {}",
                self.num_claims, claimed_values.len()
            ));
        }
        
        let mut batched_value = F::zero();
        let mut alpha_power = F::one();
        
        for value in claimed_values {
            batched_value = batched_value.add(&alpha_power.mul(value));
            alpha_power = alpha_power.mul(&self.alpha);
        }
        
        Ok(batched_value)
    }
    
    /// Verify batched evaluation
    ///
    /// Given a proof that g(r) = y, the verifier accepts if:
    /// y = Σ_i α^{i-1} · y_i
    ///
    /// This reduces T evaluation checks to 1 check.
    pub fn verify(
        &self,
        claimed_values: &[F],
        batched_proof_value: F,
    ) -> Result<bool, String> {
        let expected_value = self.compute_batched_claim(claimed_values)?;
        
        Ok(batched_proof_value.to_canonical_u64() == expected_value.to_canonical_u64())
    }
}

/// Shout-style batch evaluation with commitment
///
/// Paper Reference: "Twist and Shout", Section 3.2 "Shout Protocol"
///
/// This extends basic batching with polynomial commitments.
/// Instead of sending all f_i, the prover commits to them and
/// uses the commitment scheme to prove the batched evaluation.
pub struct ShoutBatchEvaluation<F: Field> {
    /// Commitment key
    commitment_key: CommitmentKey<F>,
    
    /// Commitments to individual polynomials
    commitments: Vec<AjtaiCommitment<F>>,
    
    /// Batching challenge
    alpha: Option<F>,
}

impl<F: Field> ShoutBatchEvaluation<F> {
    /// Create Shout batch evaluation
    ///
    /// Paper Reference: Section 3.2, Setup
    ///
    /// # Arguments
    /// * `commitment_key` - Key for Ajtai commitments
    /// * `commitments` - Commitments to f_1, ..., f_T
    pub fn new(
        commitment_key: CommitmentKey<F>,
        commitments: Vec<AjtaiCommitment<F>>,
    ) -> Self {
        Self {
            commitment_key,
            commitments,
            alpha: None,
        }
    }
    
    /// Set batching challenge
    pub fn set_challenge(&mut self, alpha: F) {
        self.alpha = Some(alpha);
    }
    
    /// Compute batched commitment
    ///
    /// Paper Reference: Section 3.2, "Commitment Batching"
    ///
    /// Computes C_g = Σ_i α^{i-1} · C_i
    ///
    /// where C_i is the commitment to f_i.
    ///
    /// Key Property:
    /// Due to homomorphic property of Ajtai commitments:
    /// C_g is a valid commitment to g(x) = Σ_i α^{i-1} · f_i(x)
    ///
    /// This allows us to batch commitments without recomputing them.
    pub fn compute_batched_commitment(&self) -> Result<AjtaiCommitment<F>, String> {
        let alpha = self.alpha.ok_or("Challenge not set")?;
        
        if self.commitments.is_empty() {
            return Err("No commitments to batch".to_string());
        }
        
        // Start with first commitment
        let mut batched = self.commitments[0].clone();
        let mut alpha_power = alpha;
        
        // Add remaining commitments with powers of alpha
        for commitment in &self.commitments[1..] {
            // C_g += α^i · C_i
            // This uses the homomorphic property of Ajtai commitments
            batched = batched.add_scaled(commitment, &alpha_power);
            alpha_power = alpha_power.mul(&alpha);
        }
        
        Ok(batched)
    }
    
    /// Prove batched evaluation
    ///
    /// Paper Reference: Section 3.2, Protocol 3.2
    ///
    /// Given polynomials f_1, ..., f_T and point r, prove:
    /// g(r) = Σ_i α^{i-1} · f_i(r)
    ///
    /// where g is the batched polynomial.
    ///
    /// The proof consists of:
    /// 1. Batched commitment C_g
    /// 2. Opening proof for g(r)
    ///
    /// Verifier checks:
    /// 1. C_g = Σ_i α^{i-1} · C_i (commitment batching)
    /// 2. Opening proof verifies for C_g at point r
    pub fn prove_batched_evaluation(
        &self,
        polynomials: &[MultilinearPolynomial<F>],
        point: &[F],
    ) -> Result<BatchEvaluationProof<F>, String> {
        let alpha = self.alpha.ok_or("Challenge not set")?;
        
        // Compute batched polynomial
        let mut batched_evals = vec![F::zero(); 1 << point.len()];
        let mut alpha_power = F::one();
        
        for poly in polynomials {
            for (j, eval) in poly.evaluations().iter().enumerate() {
                batched_evals[j] = batched_evals[j].add(&alpha_power.mul(eval));
            }
            alpha_power = alpha_power.mul(&alpha);
        }
        
        let batched_poly = MultilinearPolynomial::from_evaluations(batched_evals)?;
        
        // Evaluate at point
        let batched_value = batched_poly.evaluate(point);
        
        // Compute batched commitment
        let batched_commitment = self.compute_batched_commitment()?;
        
        // Create opening proof (simplified - full implementation would use PCS)
        Ok(BatchEvaluationProof {
            batched_commitment,
            batched_value,
            point: point.to_vec(),
        })
    }
}

/// Batch evaluation proof
#[derive(Clone, Debug)]
pub struct BatchEvaluationProof<F: Field> {
    /// Batched commitment C_g = Σ_i α^{i-1} · C_i
    pub batched_commitment: AjtaiCommitment<F>,
    
    /// Batched evaluation y = Σ_i α^{i-1} · y_i
    pub batched_value: F,
    
    /// Evaluation point r
    pub point: Vec<F>,
}

impl<F: Field> BatchEvaluationProof<F> {
    /// Get proof size in bytes
    ///
    /// Key Benefit:
    /// Proof size is O(1) instead of O(T) for T evaluations.
    pub fn size_in_bytes(&self, field_element_size: usize) -> usize {
        // Commitment size + 1 field element + point size
        let commitment_size = 100; // Approximate Ajtai commitment size
        commitment_size + field_element_size + (self.point.len() * field_element_size)
    }
}

/// Batch evaluation for multiple points
///
/// Paper Reference: Section 3.3 "Multi-point Batching"
///
/// When we have evaluations at different points, we can still batch
/// using a two-level random linear combination:
/// 1. Batch polynomials at each point
/// 2. Batch across points
pub struct MultiPointBatchEvaluation<F: Field> {
    /// Polynomials being evaluated
    polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Evaluation points
    points: Vec<Vec<F>>,
    
    /// Claimed values: claims[i][j] = f_i(points[j])
    claims: Vec<Vec<F>>,
    
    /// First-level batching challenge (for polynomials)
    alpha: Option<F>,
    
    /// Second-level batching challenge (for points)
    beta: Option<F>,
}

impl<F: Field> MultiPointBatchEvaluation<F> {
    /// Create multi-point batch evaluation
    pub fn new(
        polynomials: Vec<MultilinearPolynomial<F>>,
        points: Vec<Vec<F>>,
        claims: Vec<Vec<F>>,
    ) -> Result<Self, String> {
        if claims.len() != polynomials.len() {
            return Err("Claims must match polynomials".to_string());
        }
        
        for claim_row in &claims {
            if claim_row.len() != points.len() {
                return Err("Each polynomial must have claims for all points".to_string());
            }
        }
        
        Ok(Self {
            polynomials,
            points,
            claims,
            alpha: None,
            beta: None,
        })
    }
    
    /// Set batching challenges
    pub fn set_challenges(&mut self, alpha: F, beta: F) {
        self.alpha = Some(alpha);
        self.beta = Some(beta);
    }
    
    /// Compute fully batched claim
    ///
    /// Paper Reference: Section 3.3, "Two-Level Batching"
    ///
    /// Computes: Σ_j β^j · [Σ_i α^i · f_i(r_j)]
    ///
    /// This reduces T×P evaluations to 1 evaluation.
    pub fn compute_batched_claim(&self) -> Result<F, String> {
        let alpha = self.alpha.ok_or("Alpha not set")?;
        let beta = self.beta.ok_or("Beta not set")?;
        
        let mut total = F::zero();
        let mut beta_power = F::one();
        
        for point_idx in 0..self.points.len() {
            let mut point_sum = F::zero();
            let mut alpha_power = F::one();
            
            for poly_idx in 0..self.polynomials.len() {
                let claim = self.claims[poly_idx][point_idx];
                point_sum = point_sum.add(&alpha_power.mul(&claim));
                alpha_power = alpha_power.mul(&alpha);
            }
            
            total = total.add(&beta_power.mul(&point_sum));
            beta_power = beta_power.mul(&beta);
        }
        
        Ok(total)
    }
    
    /// Soundness error for multi-point batching
    ///
    /// Error is approximately (T + P) / |F| where:
    /// - T is number of polynomials
    /// - P is number of points
    pub fn soundness_error(&self, field_size: u64) -> f64 {
        let t = self.polynomials.len() as f64;
        let p = self.points.len() as f64;
        (t + p) / (field_size as f64)
    }
}
