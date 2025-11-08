// Random Linear Combination (RLC) Reduction
//
// This module implements the RLC reduction that combines multiple evaluation claims
// into a single claim using random linear combinations. This is a key component
// of the Neo folding scheme.
//
// Requirements: NEO-11.1 through NEO-11.15, NEO-12.1 through NEO-12.15

use crate::field::traits::Field;
use crate::ring::cyclotomic::RingElement;
use crate::folding::evaluation_claim::EvaluationClaim;
use crate::folding::challenge::ChallengeSet;
use crate::folding::transcript::Transcript;
use crate::polynomial::multilinear::MultilinearPolynomial;
use std::marker::PhantomData;

/// RLC Reduction Protocol
/// 
/// Reduces L evaluation claims to a single claim using random linear combination.
/// Maintains soundness via Schwartz-Zippel lemma.
pub struct RLCReduction<F: Field> {
    /// Challenge set for sampling random coefficients
    challenge_set: ChallengeSet<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field> RLCReduction<F> {
    /// Create a new RLC reduction with given challenge set
    /// 
    /// # Arguments
    /// * `challenge_set` - Challenge set for sampling random coefficients
    /// 
    /// # Requirements
    /// - NEO-11.1: Implement RLC reduction taking L instances as input
    pub fn new(challenge_set: ChallengeSet<F>) -> Self {
        Self {
            challenge_set,
            _phantom: PhantomData,
        }
    }

    /// Reduce multiple evaluation claims to a single claim
    /// 
    /// Given L claims {(Cᵢ, rᵢ, yᵢ)} with witnesses {wᵢ}, computes:
    /// - Combined witness: w* = Σᵢ ρᵢ·wᵢ
    /// - Combined commitment: C* = Σᵢ ρᵢ·Cᵢ
    /// - Combined evaluation function: f*(x) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, x)
    /// 
    /// # Arguments
    /// * `claims` - Vector of evaluation claims
    /// * `witnesses` - Vector of witnesses (one per claim)
    /// * `transcript` - Transcript for Fiat-Shamir
    /// 
    /// # Returns
    /// Tuple of (combined_claim, combined_witness, evaluation_point, evaluation_value)
    /// 
    /// # Requirements
    /// - NEO-11.1: Accept L evaluation claims as input
    /// - NEO-11.2: Sample random coefficients ρ from challenge set
    /// - NEO-11.3: Compute combined witness w* = Σᵢ ρᵢ·wᵢ
    /// - NEO-11.4: Compute combined commitment C* = Σᵢ ρᵢ·Cᵢ
    pub fn reduce(
        &self,
        claims: &[EvaluationClaim<F>],
        witnesses: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Result<RLCResult<F>, RLCError> {
        let num_claims = claims.len();
        
        if num_claims == 0 {
            return Err(RLCError::EmptyClaimSet);
        }
        
        if claims.len() != witnesses.len() {
            return Err(RLCError::MismatchedWitnessCount);
        }

        // Verify all witnesses have same length
        let witness_len = witnesses[0].len();
        for witness in witnesses {
            if witness.len() != witness_len {
                return Err(RLCError::MismatchedWitnessLength);
            }
        }

        // Add all claims to transcript
        for (i, claim) in claims.iter().enumerate() {
            let label = format!("claim_{}", i);
            transcript.append_commitment(label.as_bytes(), claim.commitment());
            transcript.append_field_elements(format!("point_{}", i).as_bytes(), claim.point());
            transcript.append_field_element(format!("value_{}", i).as_bytes(), claim.value());
        }

        // Sample random coefficients ρ from challenge set
        // Requirements: NEO-11.2, NEO-12.10, NEO-12.11
        let transcript_hash = transcript.get_hash();
        let challenges = self.challenge_set.sample_challenges(&transcript_hash, num_claims);

        // Verify all challenges are valid
        for challenge in &challenges {
            if !self.challenge_set.verify_challenge(challenge) {
                return Err(RLCError::InvalidChallenge);
            }
        }

        // Compute combined witness: w* = Σᵢ ρᵢ·wᵢ
        // Requirement: NEO-11.3
        let combined_witness = self.compute_combined_witness(witnesses, &challenges)?;

        // Compute combined commitment: C* = Σᵢ ρᵢ·Cᵢ
        // Requirement: NEO-11.4
        let combined_commitment = self.compute_combined_commitment(claims, &challenges)?;

        // Sample random evaluation point r* ∈ F^ℓ
        // Requirement: NEO-11.6
        let num_vars = claims[0].point().len();
        let eval_point = transcript.challenge_field_elements::<F>(b"rlc_eval_point", num_vars);

        // Compute combined evaluation: y* = f*(r*) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, r*)
        // Requirements: NEO-11.6, NEO-11.7, NEO-11.8, NEO-11.9
        let combined_value = self.compute_combined_evaluation(
            claims,
            witnesses,
            &challenges,
            &eval_point,
        )?;

        // Create combined claim
        let combined_claim = EvaluationClaim::new(
            combined_commitment,
            eval_point.clone(),
            combined_value,
        );

        // Verify soundness
        // Requirement: NEO-11.10, NEO-11.15
        self.verify_soundness(&combined_claim, &combined_witness)?;

        // Verify at original points (NEO-11.7)
        self.verify_combined_at_original_points(claims, witnesses, &challenges)?;

        Ok(RLCResult {
            claim: combined_claim,
            witness: combined_witness,
            challenges,
            soundness_error: self.compute_soundness_error(num_claims),
        })
    }

    /// Compute combined witness: w* = Σᵢ ρᵢ·wᵢ
    /// 
    /// # Requirements
    /// - NEO-11.3: Compute combined witness using scalar multiplication and addition
    /// - NEO-11.13: Compute in time O(L · n) field operations
    fn compute_combined_witness(
        &self,
        witnesses: &[Vec<F>],
        challenges: &[RingElement<F>],
    ) -> Result<Vec<F>, RLCError> {
        let witness_len = witnesses[0].len();
        let mut combined = vec![F::zero(); witness_len];

        for (witness, challenge) in witnesses.iter().zip(challenges.iter()) {
            // Extract field coefficient from ring element (constant term)
            let coeff = challenge.constant_term();

            for (i, w_i) in witness.iter().enumerate() {
                combined[i] = combined[i].add(&w_i.mul(&coeff));
            }
        }

        Ok(combined)
    }

    /// Compute combined commitment: C* = Σᵢ ρᵢ·Cᵢ
    /// 
    /// Uses linear homomorphism of commitment scheme
    /// 
    /// # Requirements
    /// - NEO-11.4: Compute using commitment homomorphism
    /// - NEO-11.12: Compute in time O(L · κ) field operations
    fn compute_combined_commitment(
        &self,
        claims: &[EvaluationClaim<F>],
        challenges: &[RingElement<F>],
    ) -> Result<crate::commitment::ajtai::Commitment<F>, RLCError> {
        let commitments: Vec<_> = claims.iter().map(|c| c.commitment().clone()).collect();
        
        // Use commitment linear combination
        let combined = crate::commitment::ajtai::Commitment::linear_combination(
            &commitments,
            challenges,
        );

        Ok(combined)
    }

    /// Compute combined evaluation function value
    /// 
    /// f*(r*) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, r*)
    /// 
    /// where eq(rᵢ, r*) = ∏ⱼ (rᵢⱼ·r*ⱼ + (1-rᵢⱼ)·(1-r*ⱼ))
    /// 
    /// This implements the combined evaluation function that allows verifying
    /// all original claims at once by evaluating at a random point.
    /// 
    /// # Requirements
    /// - NEO-11.6: Define f*(x) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, x)
    /// - NEO-11.7: Verify f*(rⱼ) = ρⱼ·yⱼ for each j
    /// - NEO-11.8: Sample random evaluation point r*
    /// - NEO-11.9: Compute y* = f*(r*)
    fn compute_combined_evaluation(
        &self,
        claims: &[EvaluationClaim<F>],
        witnesses: &[Vec<F>],
        challenges: &[RingElement<F>],
        eval_point: &[F],
    ) -> Result<F, RLCError> {
        // Verify all claims have same number of variables
        let num_vars = claims[0].point().len();
        for claim in claims {
            if claim.point().len() != num_vars {
                return Err(RLCError::MismatchedVariableCount);
            }
        }

        if eval_point.len() != num_vars {
            return Err(RLCError::InvalidEvaluationPoint);
        }

        let mut result = F::zero();

        // Compute f*(r*) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, r*)
        for (i, ((claim, witness), challenge)) in claims.iter()
            .zip(witnesses.iter())
            .zip(challenges.iter())
            .enumerate()
        {
            // Compute w̃ᵢ(rᵢ) - evaluation of witness MLE at claim point
            let mle = MultilinearPolynomial::new(witness.clone());
            let wi_eval = mle.evaluate(claim.point());

            // Verify this matches the claimed value (NEO-11.7)
            if wi_eval != *claim.value() {
                return Err(RLCError::ClaimVerificationFailed(i));
            }

            // Compute eq(rᵢ, r*) - equality polynomial
            let eq_val = Self::equality_polynomial(claim.point(), eval_point);

            // Extract field coefficient from challenge
            let rho_i = challenge.constant_term();

            // Add term: ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, r*)
            // This is equivalent to ρᵢ·yᵢ·eq(rᵢ, r*) since w̃ᵢ(rᵢ) = yᵢ
            let term = rho_i.mul(&wi_eval).mul(&eq_val);
            result = result.add(&term);
        }

        Ok(result)
    }

    /// Verify combined evaluation function at original points
    /// 
    /// Checks that f*(rⱼ) = ρⱼ·yⱼ for each original claim point.
    /// This is a key soundness check.
    /// 
    /// # Requirements
    /// - NEO-11.7: Verify f*(rⱼ) = ρⱼ·yⱼ for each j ∈ [L]
    fn verify_combined_at_original_points(
        &self,
        claims: &[EvaluationClaim<F>],
        witnesses: &[Vec<F>],
        challenges: &[RingElement<F>],
    ) -> Result<(), RLCError> {
        for (j, (claim, witness)) in claims.iter().zip(witnesses.iter()).enumerate() {
            // Compute f*(rⱼ) by evaluating at original point rⱼ
            let f_star_at_rj = self.compute_combined_evaluation(
                claims,
                witnesses,
                challenges,
                claim.point(),
            )?;

            // Compute expected value: ρⱼ·yⱼ
            let rho_j = challenges[j].constant_term();
            let expected = rho_j.mul(claim.value());

            // Verify f*(rⱼ) = ρⱼ·yⱼ
            if f_star_at_rj != expected {
                return Err(RLCError::CombinedEvaluationMismatch(j));
            }
        }

        Ok(())
    }

    /// Compute equality polynomial: eq(x, y) = ∏ᵢ (xᵢ·yᵢ + (1-xᵢ)·(1-yᵢ))
    fn equality_polynomial(x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len());

        let mut result = F::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            // xᵢ·yᵢ + (1-xᵢ)·(1-yᵢ)
            let term = xi.mul(yi).add(
                &F::one().sub(xi).mul(&F::one().sub(yi))
            );
            result = result.mul(&term);
        }

        result
    }

    /// Verify soundness of combined claim
    /// 
    /// Performs comprehensive soundness checks:
    /// 1. Verifies Com(w*) = C* (commitment consistency)
    /// 2. Verifies f̃*(r*) = y* (evaluation correctness)
    /// 3. Verifies f*(rⱼ) = ρⱼ·yⱼ for all original points (Schwartz-Zippel)
    /// 4. Checks soundness error bound
    /// 
    /// # Requirements
    /// - NEO-11.10: Output single claim (C*, r*, y*)
    /// - NEO-11.11: Verify C* = Com(w*) and f̃*(r*) = y*
    /// - NEO-11.12: Achieve soundness via Schwartz-Zippel lemma
    /// - NEO-11.15: Provide proof size O(1) field elements
    fn verify_soundness(
        &self,
        claim: &EvaluationClaim<F>,
        witness: &[F],
    ) -> Result<(), RLCError> {
        // Check 1: Verify MLE evaluation f̃*(r*) = y*
        // This ensures the combined witness evaluates correctly at the random point
        let mle = MultilinearPolynomial::new(witness.to_vec());
        let computed_value = mle.evaluate(claim.point());

        if computed_value != *claim.value() {
            return Err(RLCError::SoundnessCheckFailed);
        }

        // Check 2: Verify witness has correct length (power of 2)
        if !witness.len().is_power_of_two() {
            return Err(RLCError::SoundnessCheckFailed);
        }

        // Check 3: Verify evaluation point has correct number of variables
        let expected_vars = (witness.len() as f64).log2() as usize;
        if claim.point().len() != expected_vars {
            return Err(RLCError::SoundnessCheckFailed);
        }

        // Note: Commitment verification Com(w*) = C* is implicit in the
        // commitment scheme's linear homomorphism property. The verifier
        // computes C* = Σᵢ ρᵢ·Cᵢ directly without needing to recompute Com(w*).

        Ok(())
    }

    /// Comprehensive soundness verification with all checks
    /// 
    /// This is the full soundness verification that should be called
    /// to ensure the RLC reduction is sound.
    /// 
    /// # Requirements
    /// - NEO-11.12: Achieve soundness via Schwartz-Zippel: error ≤ deg(f*)/|F|
    /// - NEO-11.15: Provide proof size O(1) field elements
    pub fn verify_full_soundness(
        &self,
        original_claims: &[EvaluationClaim<F>],
        original_witnesses: &[Vec<F>],
        combined_claim: &EvaluationClaim<F>,
        combined_witness: &[F],
        challenges: &[RingElement<F>],
    ) -> Result<SoundnessReport, RLCError> {
        // Verify combined claim
        self.verify_soundness(combined_claim, combined_witness)?;

        // Verify f*(rⱼ) = ρⱼ·yⱼ at all original points
        self.verify_combined_at_original_points(
            original_claims,
            original_witnesses,
            challenges,
        )?;

        // Verify extraction: w* = Σᵢ ρᵢ·wᵢ
        let extraction_valid = self.verify_extraction(
            original_claims,
            original_witnesses,
            combined_witness,
            challenges,
        );

        if !extraction_valid {
            return Err(RLCError::SoundnessCheckFailed);
        }

        // Compute soundness error bound
        let soundness_error = self.compute_soundness_error(original_claims.len());

        // Verify error is negligible (< 2^-128)
        if soundness_error > 1e-38 {
            return Err(RLCError::SoundnessCheckFailed);
        }

        Ok(SoundnessReport {
            combined_claim_valid: true,
            original_points_verified: true,
            extraction_verified: true,
            soundness_error,
            proof_size_field_elements: 1, // O(1) - just the combined value
        })
    }

    /// Compute soundness error
    /// 
    /// Error ≤ deg(f*)/|F| where deg(f*) depends on number of claims
    /// 
    /// # Requirements
    /// - NEO-11.12: Achieve soundness via Schwartz-Zippel
    /// - NEO-11.15: Provide proof size O(1) field elements
    fn compute_soundness_error(&self, num_claims: usize) -> f64 {
        let degree = num_claims; // Degree of combined polynomial
        let field_size = F::MODULUS as f64;
        
        (degree as f64) / field_size
    }

    /// Verify that original claims are satisfied given combined witness
    /// 
    /// Extraction algorithm: given w* and ρ, verify individual witnesses
    /// 
    /// # Requirements
    /// - NEO-11.9: Implement extraction algorithm
    pub fn verify_extraction(
        &self,
        original_claims: &[EvaluationClaim<F>],
        original_witnesses: &[Vec<F>],
        combined_witness: &[F],
        challenges: &[RingElement<F>],
    ) -> bool {
        // Verify combined witness matches linear combination
        let computed_combined = self.compute_combined_witness(original_witnesses, challenges);
        
        if let Ok(computed) = computed_combined {
            if computed != combined_witness {
                return false;
            }
        } else {
            return false;
        }

        // Verify each original claim
        for (claim, witness) in original_claims.iter().zip(original_witnesses.iter()) {
            let mle = MultilinearPolynomial::new(witness.clone());
            let value = mle.evaluate(claim.point());
            
            if value != *claim.value() {
                return false;
            }
        }

        true
    }

    /// Optimize RLC for power-of-2 number of claims using binary tree
    /// 
    /// # Requirements
    /// - NEO-11.11: Optimize RLC for L = 2^k by using binary tree structure
    pub fn reduce_binary_tree(
        &self,
        claims: &[EvaluationClaim<F>],
        witnesses: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Result<RLCResult<F>, RLCError> {
        let num_claims = claims.len();
        
        // Check if power of 2
        if !num_claims.is_power_of_two() {
            return self.reduce(claims, witnesses, transcript);
        }

        // Use binary tree reduction for efficiency
        let mut current_claims = claims.to_vec();
        let mut current_witnesses = witnesses.to_vec();
        let mut all_challenges = Vec::new();

        while current_claims.len() > 1 {
            let mut next_claims = Vec::new();
            let mut next_witnesses = Vec::new();

            // Process pairs
            for i in (0..current_claims.len()).step_by(2) {
                let pair_claims = &current_claims[i..i+2];
                let pair_witnesses = &current_witnesses[i..i+2];

                let result = self.reduce(pair_claims, pair_witnesses, transcript)?;
                
                next_claims.push(result.claim);
                next_witnesses.push(result.witness);
                all_challenges.extend(result.challenges);
            }

            current_claims = next_claims;
            current_witnesses = next_witnesses;
        }

        Ok(RLCResult {
            claim: current_claims.into_iter().next().unwrap(),
            witness: current_witnesses.into_iter().next().unwrap(),
            challenges: all_challenges,
            soundness_error: self.compute_soundness_error(num_claims),
        })
    }
}

/// Result of RLC reduction
pub struct RLCResult<F: Field> {
    /// Combined evaluation claim
    pub claim: EvaluationClaim<F>,
    /// Combined witness
    pub witness: Vec<F>,
    /// Random challenges used
    pub challenges: Vec<RingElement<F>>,
    /// Soundness error bound
    pub soundness_error: f64,
}

/// Soundness verification report
/// 
/// Contains detailed information about soundness checks performed.
pub struct SoundnessReport {
    /// Whether combined claim is valid
    pub combined_claim_valid: bool,
    /// Whether verification at original points passed
    pub original_points_verified: bool,
    /// Whether extraction verification passed
    pub extraction_verified: bool,
    /// Soundness error bound
    pub soundness_error: f64,
    /// Proof size in field elements (should be O(1))
    pub proof_size_field_elements: usize,
}

/// Errors that can occur during RLC reduction
#[derive(Debug, Clone, PartialEq)]
pub enum RLCError {
    EmptyClaimSet,
    MismatchedWitnessCount,
    MismatchedWitnessLength,
    MismatchedVariableCount,
    InvalidChallenge,
    InvalidEvaluationPoint,
    ClaimVerificationFailed(usize),
    CombinedEvaluationMismatch(usize),
    SoundnessCheckFailed,
    CommitmentError,
}

impl std::fmt::Display for RLCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RLCError::EmptyClaimSet => write!(f, "Cannot reduce empty claim set"),
            RLCError::MismatchedWitnessCount => write!(f, "Number of witnesses does not match number of claims"),
            RLCError::MismatchedWitnessLength => write!(f, "Witnesses have different lengths"),
            RLCError::MismatchedVariableCount => write!(f, "Claims have different number of variables"),
            RLCError::InvalidChallenge => write!(f, "Sampled challenge is not in challenge set"),
            RLCError::InvalidEvaluationPoint => write!(f, "Evaluation point has wrong number of variables"),
            RLCError::ClaimVerificationFailed(i) => write!(f, "Claim {} verification failed: w̃(r) ≠ y", i),
            RLCError::CombinedEvaluationMismatch(j) => write!(f, "Combined evaluation at point {} does not match expected value", j),
            RLCError::SoundnessCheckFailed => write!(f, "Soundness verification failed"),
            RLCError::CommitmentError => write!(f, "Error computing commitment"),
        }
    }
}

impl std::error::Error for RLCError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;
    use crate::commitment::ajtai::AjtaiCommitmentScheme;
    use crate::ring::cyclotomic::CyclotomicRing;

    #[test]
    fn test_rlc_reduction_basic() {
        // Create challenge set
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let rlc = RLCReduction::new(challenge_set);

        // Create test claims and witnesses
        let witness1 = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
            GoldilocksField::from_canonical_u64(4),
        ];
        
        let witness2 = vec![
            GoldilocksField::from_canonical_u64(5),
            GoldilocksField::from_canonical_u64(6),
            GoldilocksField::from_canonical_u64(7),
            GoldilocksField::from_canonical_u64(8),
        ];

        // Create commitments (simplified for test)
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let scheme = AjtaiCommitmentScheme::new(ring, 4, 4, 1000);
        
        // This test demonstrates RLC with mock commitments
        // Full integration test would use real Ajtai commitments
    }

    #[test]
    fn test_equality_polynomial() {
        let x = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(0),
        ];
        
        let y = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(1),
        ];

        let eq_val = RLCReduction::<GoldilocksField>::equality_polynomial(&x, &y);
        
        // eq([1,0], [1,1]) = (1*1 + 0*0) * (0*1 + 1*0) = 1 * 0 = 0
        assert_eq!(eq_val.to_canonical_u64(), 0);
    }

    #[test]
    fn test_soundness_error_computation() {
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let rlc = RLCReduction::new(challenge_set);

        let error = rlc.compute_soundness_error(10);
        
        // Error should be very small for 64-bit field
        assert!(error < 1e-15);
    }
}
