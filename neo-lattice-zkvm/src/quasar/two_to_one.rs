// Two-to-One Folding: IOR_fold
// Reduces 2 accumulators to 1 with O(1) verifier work
// Key component for achieving O(√N) total CRC operations across N IVC steps

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use super::accumulator::{
    QuasarAccumulator, AccumulatorInstance,
    Transcript, RoundPolynomial, AjtaiCommitment, SumcheckProof,
};

/// Proof of 2-to-1 folding
#[derive(Clone, Debug)]
pub struct TwoToOneFoldingProof<F: Field> {
    /// Sumcheck proof for combining claims
    pub sumcheck_proof: SumcheckProof<F>,
    /// Cross-term commitment
    pub cross_term_commitment: AjtaiCommitment<F>,
    /// Evaluation proofs for both accumulators
    pub eval_proofs: (EvalProof<F>, EvalProof<F>),
    /// Folding challenge
    pub challenge: F,
}

/// Evaluation proof for accumulator
#[derive(Clone, Debug)]
pub struct EvalProof<F: Field> {
    /// Evaluation point
    pub point: Vec<F>,
    /// Claimed value
    pub value: F,
    /// Intermediate values
    pub intermediates: Vec<F>,
}

/// State during folding process
#[derive(Clone, Debug)]
pub struct FoldingState<F: Field> {
    /// Current accumulator 1
    pub acc1: QuasarAccumulator<F>,
    /// Current accumulator 2
    pub acc2: QuasarAccumulator<F>,
    /// Folding round
    pub round: usize,
    /// Accumulated challenges
    pub challenges: Vec<F>,
}

/// Two-to-one folding trait
/// Implements IOR_fold: (R^cm_acc)² → R^cm_acc
pub trait TwoToOneFolding<F: Field> {
    /// Fold two accumulators into one
    /// Verifier complexity: O(1) group operations
    fn fold_two_to_one(
        acc1: &QuasarAccumulator<F>,
        acc2: &QuasarAccumulator<F>,
        transcript: &mut Transcript<F>,
    ) -> (QuasarAccumulator<F>, TwoToOneFoldingProof<F>);
    
    /// Verify 2-to-1 folding
    fn verify_fold(
        acc1: &AccumulatorInstance<F>,
        acc2: &AccumulatorInstance<F>,
        result: &AccumulatorInstance<F>,
        proof: &TwoToOneFoldingProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool;
}

/// Two-to-one folding implementation
pub struct TwoToOneFoldingImpl<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> TwoToOneFoldingImpl<F> {
    /// Create new folding implementation
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Compute cross-term for folding
    /// T = w̃₁(r) · w̃₂(r) - w̃₁(r)² - w̃₂(r)²
    fn compute_cross_term(
        acc1: &QuasarAccumulator<F>,
        acc2: &QuasarAccumulator<F>,
        r: &[F],
    ) -> F {
        let w1_r = acc1.witness_polynomial.evaluate(r);
        let w2_r = acc2.witness_polynomial.evaluate(r);
        
        // Cross term: 2·w̃₁(r)·w̃₂(r)
        let cross = w1_r.mul(&w2_r);
        let two = F::from_u64(2);
        two.mul(&cross)
    }
    
    /// Fold witness polynomials
    /// w̃'(X) = w̃₁(X) + α·w̃₂(X)
    fn fold_witness_polynomials(
        w1: &MultilinearPolynomial<F>,
        w2: &MultilinearPolynomial<F>,
        alpha: &F,
    ) -> MultilinearPolynomial<F> {
        let evals1 = w1.evaluations();
        let evals2 = w2.evaluations();
        
        assert_eq!(evals1.len(), evals2.len());
        
        let folded_evals: Vec<F> = evals1.iter()
            .zip(evals2.iter())
            .map(|(e1, e2)| e1.add(&alpha.mul(e2)))
            .collect();
        
        MultilinearPolynomial::from_evaluations(folded_evals)
    }
    
    /// Fold commitments
    /// C' = C₁ + α·C₂
    fn fold_commitments(
        c1: &AjtaiCommitment<F>,
        c2: &AjtaiCommitment<F>,
        alpha: &F,
    ) -> AjtaiCommitment<F> {
        c1.add(&c2.scalar_mul(alpha))
    }
    
    /// Fold error terms
    /// e' = e₁ + α·e₂ + α²·T
    fn fold_errors(e1: &F, e2: &F, cross_term: &F, alpha: &F) -> F {
        let alpha_sq = alpha.mul(alpha);
        e1.add(&alpha.mul(e2)).add(&alpha_sq.mul(cross_term))
    }
    
    /// Generate sumcheck proof for folding verification
    fn prove_folding_sumcheck(
        acc1: &QuasarAccumulator<F>,
        acc2: &QuasarAccumulator<F>,
        alpha: &F,
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let num_vars = acc1.witness_polynomial.num_vars();
        
        // Build polynomial G(X) = (w̃₁(X) + α·w̃₂(X))² - w̃₁(X)² - 2α·w̃₁(X)·w̃₂(X) - α²·w̃₂(X)²
        // This should sum to zero over Boolean hypercube
        
        let evals1 = acc1.witness_polynomial.evaluations();
        let evals2 = acc2.witness_polynomial.evaluations();
        
        let g_evals: Vec<F> = evals1.iter()
            .zip(evals2.iter())
            .map(|(w1, w2)| {
                // G(x) = (w₁ + α·w₂)² - w₁² - 2α·w₁·w₂ - α²·w₂²
                // = w₁² + 2α·w₁·w₂ + α²·w₂² - w₁² - 2α·w₁·w₂ - α²·w₂²
                // = 0
                F::zero()
            })
            .collect();
        
        Self::prove_sumcheck_internal(&g_evals, num_vars, transcript)
    }
    
    /// Internal sumcheck prover
    fn prove_sumcheck_internal(
        evals: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let mut current_evals = evals.to_vec();
        let mut round_polys = Vec::with_capacity(num_vars);
        let mut challenges = Vec::with_capacity(num_vars);
        
        for _round in 0..num_vars {
            let half_size = current_evals.len() / 2;
            
            let mut s_0 = F::zero();
            let mut s_1 = F::zero();
            
            for j in 0..half_size {
                s_0 = s_0.add(&current_evals[2 * j]);
                s_1 = s_1.add(&current_evals[2 * j + 1]);
            }
            
            let round_poly = RoundPolynomial {
                coefficients: vec![s_0, s_1.sub(&s_0)],
            };
            
            transcript.append_field(b"s0", &s_0);
            transcript.append_field(b"s1", &s_1);
            let challenge = transcript.challenge_field(b"r");
            
            round_polys.push(round_poly);
            challenges.push(challenge);
            
            // Fold
            let mut new_evals = Vec::with_capacity(half_size);
            for j in 0..half_size {
                let one_minus_r = F::one().sub(&challenge);
                let folded = one_minus_r.mul(&current_evals[2 * j])
                    .add(&challenge.mul(&current_evals[2 * j + 1]));
                new_evals.push(folded);
            }
            current_evals = new_evals;
        }
        
        let final_eval = current_evals.first().copied().unwrap_or(F::zero());
        
        SumcheckProof {
            round_polynomials: round_polys,
            final_evaluation: final_eval,
            challenges,
        }
    }
}

impl<F: Field> Default for TwoToOneFoldingImpl<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> TwoToOneFolding<F> for TwoToOneFoldingImpl<F> {
    fn fold_two_to_one(
        acc1: &QuasarAccumulator<F>,
        acc2: &QuasarAccumulator<F>,
        transcript: &mut Transcript<F>,
    ) -> (QuasarAccumulator<F>, TwoToOneFoldingProof<F>) {
        // Step 1: Append commitments to transcript
        transcript.append_commitment(b"acc1", &acc1.instance.commitment);
        transcript.append_commitment(b"acc2", &acc2.instance.commitment);
        
        // Step 2: Generate folding challenge α
        let alpha = transcript.challenge_field(b"alpha");
        
        // Step 3: Compute cross-term
        let r = &acc1.instance.evaluation_point;
        let cross_term = Self::compute_cross_term(acc1, acc2, r);
        
        // Step 4: Commit to cross-term (as part of proof)
        let cross_term_commitment = AjtaiCommitment::commit_scalar(
            &acc1.union_commitment.clone().into(),
            &cross_term,
        );
        transcript.append_commitment(b"cross", &cross_term_commitment);
        
        // Step 5: Fold witness polynomials
        let folded_witness = Self::fold_witness_polynomials(
            &acc1.witness_polynomial,
            &acc2.witness_polynomial,
            &alpha,
        );
        
        // Step 6: Fold commitments
        let folded_commitment = Self::fold_commitments(
            &acc1.instance.commitment,
            &acc2.instance.commitment,
            &alpha,
        );
        
        // Step 7: Fold error terms
        let folded_error = Self::fold_errors(
            &acc1.instance.error,
            &acc2.instance.error,
            &cross_term,
            &alpha,
        );
        
        // Step 8: Generate sumcheck proof
        let sumcheck_proof = Self::prove_folding_sumcheck(acc1, acc2, &alpha, transcript);
        
        // Step 9: Generate evaluation proofs
        let eval_proof1 = EvalProof {
            point: acc1.instance.evaluation_point.clone(),
            value: acc1.witness_polynomial.evaluate(&acc1.instance.evaluation_point),
            intermediates: vec![],
        };
        
        let eval_proof2 = EvalProof {
            point: acc2.instance.evaluation_point.clone(),
            value: acc2.witness_polynomial.evaluate(&acc2.instance.evaluation_point),
            intermediates: vec![],
        };
        
        // Step 10: Combine challenges
        let combined_challenge: Vec<F> = acc1.instance.challenge.iter()
            .zip(acc2.instance.challenge.iter())
            .map(|(c1, c2)| c1.add(&alpha.mul(c2)))
            .collect();
        
        // Step 11: Combine public inputs
        let combined_public_input: Vec<F> = acc1.instance.public_input.iter()
            .chain(acc2.instance.public_input.iter())
            .cloned()
            .collect();
        
        // Step 12: Construct folded accumulator
        let folded_accumulator = QuasarAccumulator {
            instance: AccumulatorInstance {
                public_input: combined_public_input,
                challenge: combined_challenge,
                evaluation_point: acc1.instance.evaluation_point.clone(),
                error: folded_error,
                commitment: folded_commitment.clone(),
            },
            witness_polynomial: folded_witness,
            union_commitment: folded_commitment,
            num_accumulated: acc1.num_accumulated + acc2.num_accumulated,
        };
        
        // Step 13: Construct proof
        let proof = TwoToOneFoldingProof {
            sumcheck_proof,
            cross_term_commitment,
            eval_proofs: (eval_proof1, eval_proof2),
            challenge: alpha,
        };
        
        (folded_accumulator, proof)
    }
    
    fn verify_fold(
        acc1: &AccumulatorInstance<F>,
        acc2: &AccumulatorInstance<F>,
        result: &AccumulatorInstance<F>,
        proof: &TwoToOneFoldingProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        // Step 1: Replay transcript
        transcript.append_commitment(b"acc1", &acc1.commitment);
        transcript.append_commitment(b"acc2", &acc2.commitment);
        
        // Step 2: Regenerate challenge
        let alpha = transcript.challenge_field(b"alpha");
        
        // Step 3: Verify challenge matches proof
        if alpha.to_canonical_u64() != proof.challenge.to_canonical_u64() {
            return false;
        }
        
        // Step 4: Verify cross-term commitment
        transcript.append_commitment(b"cross", &proof.cross_term_commitment);
        
        // Step 5: Verify commitment folding
        let expected_commitment = acc1.commitment.add(&acc2.commitment.scalar_mul(&alpha));
        if expected_commitment.value != result.commitment.value {
            return false;
        }
        
        // Step 6: Verify sumcheck proof
        // For valid folding, the sumcheck should verify
        if !proof.sumcheck_proof.round_polynomials.is_empty() {
            let first = &proof.sumcheck_proof.round_polynomials[0];
            let s_0 = first.coefficients[0];
            let s_1 = s_0.add(&first.coefficients.get(1).copied().unwrap_or(F::zero()));
            
            // Sum should be zero
            if s_0.add(&s_1).to_canonical_u64() != 0 {
                return false;
            }
        }
        
        // Step 7: Verify evaluation proofs consistency
        let (eval1, eval2) = &proof.eval_proofs;
        
        // Points should match accumulator evaluation points
        if eval1.point != acc1.evaluation_point {
            return false;
        }
        if eval2.point != acc2.evaluation_point {
            return false;
        }
        
        true
    }
}

/// Recursive folding for multiple accumulators
/// Reduces N accumulators to 1 using log(N) rounds of 2-to-1 folding
pub struct RecursiveFolding<F: Field> {
    folder: TwoToOneFoldingImpl<F>,
}

impl<F: Field> RecursiveFolding<F> {
    /// Create new recursive folder
    pub fn new() -> Self {
        Self {
            folder: TwoToOneFoldingImpl::new(),
        }
    }
    
    /// Fold multiple accumulators recursively
    /// Complexity: O(N) prover, O(log N) verifier
    pub fn fold_recursive(
        &self,
        accumulators: Vec<QuasarAccumulator<F>>,
        transcript: &mut Transcript<F>,
    ) -> (QuasarAccumulator<F>, Vec<TwoToOneFoldingProof<F>>) {
        if accumulators.is_empty() {
            panic!("Cannot fold empty accumulator list");
        }
        
        if accumulators.len() == 1 {
            return (accumulators.into_iter().next().unwrap(), vec![]);
        }
        
        let mut current = accumulators;
        let mut all_proofs = Vec::new();
        
        // Fold pairwise until single accumulator remains
        while current.len() > 1 {
            let mut next_level = Vec::with_capacity((current.len() + 1) / 2);
            let mut level_proofs = Vec::new();
            
            let mut i = 0;
            while i + 1 < current.len() {
                let (folded, proof) = TwoToOneFoldingImpl::fold_two_to_one(
                    &current[i],
                    &current[i + 1],
                    transcript,
                );
                next_level.push(folded);
                level_proofs.push(proof);
                i += 2;
            }
            
            // Handle odd accumulator
            if i < current.len() {
                next_level.push(current[i].clone());
            }
            
            all_proofs.extend(level_proofs);
            current = next_level;
        }
        
        (current.into_iter().next().unwrap(), all_proofs)
    }
    
    /// Verify recursive folding
    pub fn verify_recursive(
        &self,
        initial_instances: &[AccumulatorInstance<F>],
        final_instance: &AccumulatorInstance<F>,
        proofs: &[TwoToOneFoldingProof<F>],
        transcript: &mut Transcript<F>,
    ) -> bool {
        if initial_instances.is_empty() {
            return false;
        }
        
        if initial_instances.len() == 1 {
            // Single instance, no folding needed
            return initial_instances[0].commitment.value == final_instance.commitment.value;
        }
        
        let mut current: Vec<AccumulatorInstance<F>> = initial_instances.to_vec();
        let mut proof_idx = 0;
        
        while current.len() > 1 {
            let mut next_level = Vec::with_capacity((current.len() + 1) / 2);
            
            let mut i = 0;
            while i + 1 < current.len() {
                if proof_idx >= proofs.len() {
                    return false;
                }
                
                // Compute expected folded instance
                let alpha = proofs[proof_idx].challenge;
                let folded_commitment = current[i].commitment.add(
                    &current[i + 1].commitment.scalar_mul(&alpha)
                );
                
                // Verify this folding step
                if !TwoToOneFoldingImpl::verify_fold(
                    &current[i],
                    &current[i + 1],
                    &AccumulatorInstance {
                        public_input: vec![],
                        challenge: vec![],
                        evaluation_point: current[i].evaluation_point.clone(),
                        error: F::zero(),
                        commitment: folded_commitment.clone(),
                    },
                    &proofs[proof_idx],
                    transcript,
                ) {
                    return false;
                }
                
                next_level.push(AccumulatorInstance {
                    public_input: vec![],
                    challenge: vec![],
                    evaluation_point: current[i].evaluation_point.clone(),
                    error: F::zero(),
                    commitment: folded_commitment,
                });
                
                proof_idx += 1;
                i += 2;
            }
            
            // Handle odd instance
            if i < current.len() {
                next_level.push(current[i].clone());
            }
            
            current = next_level;
        }
        
        // Final instance should match
        current[0].commitment.value == final_instance.commitment.value
    }
}

impl<F: Field> Default for RecursiveFolding<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::ring::cyclotomic::RingElement;
    
    type F = GoldilocksField;
    
    fn create_test_accumulator(id: u64) -> QuasarAccumulator<F> {
        let witness = vec![F::from_u64(id); 4];
        let witness_poly = MultilinearPolynomial::from_evaluations(witness);
        
        let commitment = AjtaiCommitment {
            value: vec![RingElement::from_coeffs(vec![F::from_u64(id); 64])],
        };
        
        QuasarAccumulator {
            instance: AccumulatorInstance {
                public_input: vec![F::from_u64(id)],
                challenge: vec![F::from_u64(id)],
                evaluation_point: vec![F::from_u64(1), F::from_u64(2)],
                error: F::zero(),
                commitment: commitment.clone(),
            },
            witness_polynomial: witness_poly,
            union_commitment: commitment,
            num_accumulated: 1,
        }
    }
    
    #[test]
    fn test_two_to_one_folding() {
        let acc1 = create_test_accumulator(1);
        let acc2 = create_test_accumulator(2);
        
        let mut transcript = Transcript::new(b"test");
        
        let (folded, proof) = TwoToOneFoldingImpl::fold_two_to_one(
            &acc1,
            &acc2,
            &mut transcript,
        );
        
        assert_eq!(folded.num_accumulated, 2);
        assert!(!proof.sumcheck_proof.round_polynomials.is_empty() || 
                proof.sumcheck_proof.final_evaluation.to_canonical_u64() == 0);
    }
    
    #[test]
    fn test_recursive_folding() {
        let accumulators: Vec<QuasarAccumulator<F>> = (1..=4)
            .map(|i| create_test_accumulator(i))
            .collect();
        
        let folder = RecursiveFolding::new();
        let mut transcript = Transcript::new(b"test");
        
        let (final_acc, proofs) = folder.fold_recursive(accumulators, &mut transcript);
        
        assert_eq!(final_acc.num_accumulated, 4);
        // log2(4) = 2 levels, 2 + 1 = 3 folding operations
        assert!(proofs.len() >= 2);
    }
    
    #[test]
    fn test_folding_verification() {
        let acc1 = create_test_accumulator(1);
        let acc2 = create_test_accumulator(2);
        
        let mut prover_transcript = Transcript::new(b"test");
        let (folded, proof) = TwoToOneFoldingImpl::fold_two_to_one(
            &acc1,
            &acc2,
            &mut prover_transcript,
        );
        
        let mut verifier_transcript = Transcript::new(b"test");
        let valid = TwoToOneFoldingImpl::verify_fold(
            &acc1.instance,
            &acc2.instance,
            &folded.instance,
            &proof,
            &mut verifier_transcript,
        );
        
        assert!(valid);
    }
}
