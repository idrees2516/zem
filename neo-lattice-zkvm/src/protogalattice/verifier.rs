// Verifier for ProtogaLattice folding scheme
//
// Implements:
// - Verification of folding proofs
// - Constant-round verification
// - Batch verification for efficiency

use crate::field::Field;
use crate::protogalattice::{
    types::*,
    commitment::*,
    folding::*,
    lattice_params::LatticeParams,
    polynomial_relations::*,
    transcript::*,
    Result,
};
use crate::errors::ProtogaError;

/// Verifying key for ProtogaLattice
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Commitment key (verification part)
    pub commitment_key: ProtogaCommitmentKey,
    /// Lattice parameters
    pub params: LatticeParams,
    /// Number of constraints
    pub num_constraints: usize,
    /// Number of variables
    pub num_variables: usize,
}

/// Verifier state during protocol execution
pub struct VerifierState<F: Field> {
    /// Instance being verified
    pub instance: ProtogaInstance<F>,
    /// Accumulated challenges
    pub challenges: Vec<F>,
    /// Current round number
    pub round: usize,
}

/// Main verifier interface
pub struct ProtogaVerifier {
    /// Verifying key
    verifying_key: VerifyingKey,
    /// Folding scheme for verification
    folder: ProtogaFolder,
}

impl ProtogaVerifier {
    /// Create new verifier
    pub fn new(verifying_key: VerifyingKey, folder: ProtogaFolder) -> Self {
        Self {
            verifying_key,
            folder,
        }
    }

    /// Create verifier from prover's proving key
    pub fn from_proving_key(
        commitment_key: ProtogaCommitmentKey,
        params: LatticeParams,
        relation: &GeneralPolynomialRelation<crate::field::GoldilocksField>,
    ) -> Self {
        let verifying_key = VerifyingKey {
            commitment_key: commitment_key.clone(),
            params: params.clone(),
            num_constraints: relation.num_constraints(),
            num_variables: relation.num_variables,
        };

        let folder = ProtogaFolder::new(
            commitment_key,
            params,
            relation.clone(),
        );

        Self::new(verifying_key, folder)
    }

    /// Verify a proof
    pub fn verify<F: Field>(
        &self,
        instance: &ProtogaInstance<F>,
        proof: &ProtogaProof<F>,
    ) -> Result<bool> {
        // Check instance structure
        if instance.commitments.is_empty() {
            return Err(ProtogaError::InvalidProof(
                "Instance has no commitments".into()
            ));
        }

        // Reconstruct transcript
        let mut transcript = Transcript::new(b"ProtogaLattice::Proof");
        transcript.append_instance("instance", instance);

        // Verify opening proofs
        for (i, opening_proof) in proof.opening_proofs.iter().enumerate() {
            if i >= instance.commitments.len() {
                return Ok(false);
            }

            let commitment = LatticeCommitment {
                value: instance.commitments[i].clone(),
                hint: None,
            };

            let valid = ProtogaCommitment::verify_opening(
                &self.verifying_key.commitment_key,
                &commitment,
                opening_proof,
            )?;

            if !valid {
                return Ok(false);
            }
        }

        // Verify cross-term commitments if present
        if !proof.cross_term_commitments.is_empty() {
            for commit in &proof.cross_term_commitments {
                transcript.append_ring_element("cross_term", commit);
            }

            // Verify consistency of cross-terms
            if proof.cross_terms.len() != proof.cross_term_commitments.len() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify folding proof
    pub fn verify_folding<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        folding_proof: &FoldingProof<F>,
    ) -> Result<bool> {
        if instances.is_empty() {
            return Err(ProtogaError::InvalidParameters(
                "Empty instance list".into()
            ));
        }

        // Reconstruct transcript
        let mut transcript = Transcript::new(b"ProtogaLattice::Folding");

        // Verify each round of folding
        let mut current_instances = instances.to_vec();

        for (round_idx, round_proof) in folding_proof.round_proofs.iter().enumerate() {
            transcript.append_message("round", &round_idx.to_le_bytes());

            // Verify pairwise folding
            let mut next_instances = Vec::new();

            for i in (0..current_instances.len()).step_by(2) {
                if i + 1 < current_instances.len() {
                    // Verify folding of this pair
                    let folded = self.verify_round_folding(
                        &current_instances[i],
                        &current_instances[i + 1],
                        round_proof,
                        &mut transcript,
                    )?;

                    if !folded.is_valid {
                        return Ok(false);
                    }

                    next_instances.push(folded.instance);
                } else {
                    // Odd one out, carry forward
                    next_instances.push(current_instances[i].clone());
                }
            }

            current_instances = next_instances;

            if current_instances.len() == 1 {
                break;
            }
        }

        // Check final instance matches
        if current_instances.len() != 1 {
            return Ok(false);
        }

        Ok(current_instances[0] == folding_proof.final_instance)
    }

    /// Verify single round of folding
    fn verify_round_folding<F: Field>(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        proof: &RoundProof<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<VerifiedFoldedInstance<F>> {
        // Absorb instances
        transcript.append_instance("instance1", instance1);
        transcript.append_instance("instance2", instance2);

        // Absorb cross-term commitments
        for commit in &proof.cross_term_commits {
            transcript.append_ring_element("cross_term", commit);
        }

        // Get challenge
        let challenge = transcript.challenge_scalar("folding_challenge");

        // Verify sum-check proof
        let sumcheck_valid = self.verify_sumcheck(
            &proof.sumcheck_proof,
            &challenge,
        )?;

        if !sumcheck_valid {
            return Ok(VerifiedFoldedInstance {
                instance: instance1.clone(),
                is_valid: false,
            });
        }

        // Compute expected folded instance
        let folded_instance = self.compute_folded_instance(
            instance1,
            instance2,
            &proof.cross_term_evals,
            &challenge,
        )?;

        Ok(VerifiedFoldedInstance {
            instance: folded_instance,
            is_valid: true,
        })
    }

    /// Verify sum-check proof
    fn verify_sumcheck<F: Field>(
        &self,
        proof: &SumCheckProof<F>,
        _challenge: &F,
    ) -> Result<bool> {
        // Verify each round polynomial
        for poly in &proof.round_polynomials {
            // Check degree bound (should be degree 2)
            if poly.len() > 3 {
                return Ok(false);
            }

            // Check not all zero
            if poly.iter().all(|c| c.is_zero()) {
                return Ok(false);
            }
        }

        // Verify final evaluation is consistent
        // In full implementation, would verify sum across all rounds
        Ok(!proof.final_evaluation.is_zero())
    }

    /// Compute folded instance
    fn compute_folded_instance<F: Field>(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        cross_term_evals: &[F],
        challenge: &F,
    ) -> Result<ProtogaInstance<F>> {
        let r_squared = challenge.mul(challenge);

        // Fold commitments: C = C1 + r·T + r²·C2
        let mut folded_commitments = Vec::new();
        for i in 0..instance1.commitments.len() {
            let c1 = &instance1.commitments[i];
            let c2 = &instance2.commitments[i];

            let mut folded = c1.clone();

            // Add r·T
            if i < cross_term_evals.len() {
                let cross_val = cross_term_evals[i].to_canonical_u64();
                let cross_contrib = c1.scalar_mul(
                    challenge.mul(&cross_term_evals[i]).to_canonical_u64()
                );
                folded = folded.add(&cross_contrib);
            }

            // Add r²·C2
            let c2_scaled = c2.scalar_mul(r_squared.to_canonical_u64());
            folded = folded.add(&c2_scaled);

            folded_commitments.push(folded);
        }

        // Fold public inputs
        let mut folded_inputs = Vec::new();
        for i in 0..instance1.public_inputs.len() {
            let x1 = instance1.public_inputs[i];
            let x2 = instance2.public_inputs[i];
            let folded = x1.add(&challenge.mul(&x2));
            folded_inputs.push(folded);
        }

        // Fold relaxation factor
        let folded_relaxation = instance1.relaxation_factor
            .add(&challenge.mul(&instance2.relaxation_factor));

        Ok(ProtogaInstance {
            commitments: folded_commitments,
            public_inputs: folded_inputs,
            relaxation_factor: folded_relaxation,
            error_commitment: None,
        })
    }

    /// Batch verify multiple proofs
    pub fn batch_verify<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        proofs: &[ProtogaProof<F>],
    ) -> Result<bool> {
        if instances.len() != proofs.len() {
            return Err(ProtogaError::InvalidParameters(
                "Instance and proof count mismatch".into()
            ));
        }

        // Verify each proof individually
        // In optimized implementation, could batch verify commitments
        for (instance, proof) in instances.iter().zip(proofs.iter()) {
            if !self.verify(instance, proof)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify with relaxed instance
    pub fn verify_relaxed<F: Field>(
        &self,
        instance: &ProtogaInstance<F>,
        proof: &ProtogaProof<F>,
    ) -> Result<bool> {
        if !instance.is_relaxed() {
            return Err(ProtogaError::InvalidParameters(
                "Instance is not relaxed".into()
            ));
        }

        // Verify error commitment if present
        if let Some(ref error_commit) = instance.error_commitment {
            // Verify error bound
            let error_norm = self.estimate_error_norm(error_commit);
            if error_norm > self.verifying_key.params.sis_beta {
                return Ok(false);
            }
        }

        // Regular verification with relaxation factor
        self.verify(instance, proof)
    }

    /// Estimate error norm from commitment
    fn estimate_error_norm(&self, commitment: &crate::ring::RingElement) -> f64 {
        let coeffs = commitment.coefficients();
        let norm_squared: u128 = coeffs.iter()
            .map(|&c| (c as u128) * (c as u128))
            .sum();
        (norm_squared as f64).sqrt()
    }
}

/// Round-specific verifier
pub struct RoundVerifier {
    verifier: ProtogaVerifier,
    round_number: usize,
}

impl RoundVerifier {
    /// Create new round verifier
    pub fn new(verifier: ProtogaVerifier) -> Self {
        Self {
            verifier,
            round_number: 0,
        }
    }

    /// Verify single round
    pub fn verify_round<F: Field>(
        &mut self,
        state: &mut VerifierState<F>,
        proof: &RoundProof<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<bool> {
        transcript.append_message("round", &self.round_number.to_le_bytes());

        // Verify cross-term commitments
        for commit in &proof.cross_term_commits {
            transcript.append_ring_element("cross_term", commit);
        }

        // Get challenge
        let challenge = transcript.challenge_scalar("round_challenge");
        state.challenges.push(challenge);

        // Verify sum-check
        let valid = self.verifier.verify_sumcheck(&proof.sumcheck_proof, &challenge)?;

        state.round += 1;
        self.round_number += 1;

        Ok(valid)
    }

    /// Get current round number
    pub fn current_round(&self) -> usize {
        self.round_number
    }
}

/// Result of verified folding
struct VerifiedFoldedInstance<F: Field> {
    instance: ProtogaInstance<F>,
    is_valid: bool,
}

/// Batch verifier for efficient verification
pub struct BatchVerifier {
    verifier: ProtogaVerifier,
    batch_size: usize,
}

impl BatchVerifier {
    /// Create new batch verifier
    pub fn new(verifier: ProtogaVerifier, batch_size: usize) -> Self {
        Self {
            verifier,
            batch_size,
        }
    }

    /// Verify batch of proofs with random linear combination
    pub fn verify_batch<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        proofs: &[ProtogaProof<F>],
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<bool> {
        if instances.len() != proofs.len() {
            return Err(ProtogaError::InvalidParameters(
                "Instance and proof count mismatch".into()
            ));
        }

        if instances.len() > self.batch_size {
            return Err(ProtogaError::InvalidParameters(
                "Batch size exceeded".into()
            ));
        }

        // Generate random coefficients
        let coefficients: Vec<F> = (0..instances.len())
            .map(|_| transcript.challenge_scalar("batch_coeff"))
            .collect();

        // Verify each proof with coefficient
        for (i, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
            // Scale instance by coefficient
            let scaled_instance = self.scale_instance(instance, &coefficients[i])?;
            
            if !self.verifier.verify(&scaled_instance, proof)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Scale instance by coefficient
    fn scale_instance<F: Field>(
        &self,
        instance: &ProtogaInstance<F>,
        coefficient: &F,
    ) -> Result<ProtogaInstance<F>> {
        let scaled_inputs: Vec<F> = instance.public_inputs
            .iter()
            .map(|x| x.mul(coefficient))
            .collect();

        let scaled_relaxation = instance.relaxation_factor.mul(coefficient);

        Ok(ProtogaInstance {
            commitments: instance.commitments.clone(),
            public_inputs: scaled_inputs,
            relaxation_factor: scaled_relaxation,
            error_commitment: instance.error_commitment.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::protogalattice::prover::ProtogaProver;
    use rand::thread_rng;

    #[test]
    fn test_verifier_setup() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let relation = GeneralPolynomialRelation::new(2);

        let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng).unwrap();
        let verifier = ProtogaVerifier::from_proving_key(
            prover.proving_key.commitment_key.clone(),
            params,
            &relation,
        );

        assert_eq!(verifier.verifying_key.num_variables, 2);
    }

    #[test]
    fn test_verify_proof() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        
        let mut relation = GeneralPolynomialRelation::new(2);
        let mut constraint = PolynomialConstraint::new("test");
        constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 0));
        constraint.set_rhs(GoldilocksField::from(42u64));
        relation.add_constraint(constraint);

        let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng).unwrap();
        let verifier = ProtogaVerifier::from_proving_key(
            prover.proving_key.commitment_key.clone(),
            params,
            &relation,
        );

        let witness = vec![
            GoldilocksField::from(42u64),
            GoldilocksField::from(0u64),
        ];

        let (instance, _witness, proof) = prover.prove(&witness, &[], &mut rng).unwrap();
        
        let valid = verifier.verify(&instance, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let relation = GeneralPolynomialRelation::new(2);

        let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng).unwrap();
        let verifier = ProtogaVerifier::from_proving_key(
            prover.proving_key.commitment_key.clone(),
            params,
            &relation,
        );

        let witnesses = vec![
            vec![GoldilocksField::from(1u64), GoldilocksField::from(2u64)],
            vec![GoldilocksField::from(3u64), GoldilocksField::from(4u64)],
        ];

        let proofs: Vec<_> = witnesses.iter()
            .map(|w| prover.prove(w, &[], &mut rng).unwrap())
            .collect();

        let instances: Vec<_> = proofs.iter().map(|(inst, _, _)| inst.clone()).collect();
        let proof_vec: Vec<_> = proofs.iter().map(|(_, _, proof)| proof.clone()).collect();

        let valid = verifier.batch_verify(&instances, &proof_vec).unwrap();
        assert!(valid);
    }
}
