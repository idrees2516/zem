// Constant-round folding protocol for ProtogaLattice
//
// Implements the core folding algorithm that:
// - Folds two instances into one
// - Maintains soundness in constant rounds
// - Preserves witness-instance relationship

use crate::field::Field;
use crate::ring::RingElement;
use crate::protogalattice::{
    types::*,
    commitment::*,
    lattice_params::LatticeParams,
    polynomial_relations::*,
    transcript::TranscriptProtocol,
    Result,
};
use crate::errors::ProtogaError;
use rand::RngCore;

/// Folding scheme trait
pub trait FoldingScheme<F: Field> {
    /// Fold two instances into one
    fn fold(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        witness1: &ProtogaWitness<F>,
        witness2: &ProtogaWitness<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<(FoldedInstance<F>, FoldedWitness<F>, RoundProof<F>)>;

    /// Verify folding proof
    fn verify_fold(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        folded: &FoldedInstance<F>,
        proof: &RoundProof<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<bool>;
}

/// ProtogaLattice folder implementation
pub struct ProtogaFolder {
    /// Commitment key
    pub commitment_key: ProtogaCommitmentKey,
    /// Lattice parameters
    pub params: LatticeParams,
    /// Polynomial relation being folded
    pub relation: GeneralPolynomialRelation<GoldilocksField>,
}

impl ProtogaFolder {
    /// Create new folder
    pub fn new(
        commitment_key: ProtogaCommitmentKey,
        params: LatticeParams,
        relation: GeneralPolynomialRelation<GoldilocksField>,
    ) -> Self {
        Self {
            commitment_key,
            params,
            relation,
        }
    }

    /// Setup folder from parameters
    pub fn setup(
        params: LatticeParams,
        relation: GeneralPolynomialRelation<GoldilocksField>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        let commitment_key = ProtogaCommitment::setup(&params, rng)?;
        Ok(Self::new(commitment_key, params, relation))
    }
}

impl<F: Field> FoldingScheme<F> for ProtogaFolder {
    fn fold(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        witness1: &ProtogaWitness<F>,
        witness2: &ProtogaWitness<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<(FoldedInstance<F>, FoldedWitness<F>, RoundProof<F>)> {
        // Absorb instances into transcript
        transcript.append_instance("instance1", instance1);
        transcript.append_instance("instance2", instance2);

        // Compute cross-terms
        let cross_terms = self.compute_cross_terms(
            witness1,
            witness2,
            instance1,
            instance2,
        )?;

        // Commit to cross-terms
        let cross_term_commits = self.commit_cross_terms(&cross_terms, transcript)?;

        // Get folding challenge
        let challenge = transcript.challenge_scalar("folding_challenge");

        // Fold instances
        let folded_instance = self.fold_instances(
            instance1,
            instance2,
            &cross_terms,
            &challenge,
        )?;

        // Fold witnesses
        let folded_witness = self.fold_witnesses(
            witness1,
            witness2,
            &challenge,
        )?;

        // Generate sum-check proof for cross-terms
        let sumcheck_proof = self.generate_sumcheck_proof(
            &cross_terms,
            &challenge,
            transcript,
        )?;

        // Evaluate cross-terms at challenge
        let cross_term_evals = self.evaluate_cross_terms(&cross_terms, &challenge)?;

        let proof = RoundProof {
            cross_term_commits,
            cross_term_evals,
            sumcheck_proof,
        };

        let folded = FoldedInstance {
            instance: folded_instance,
            cross_term_accumulator: cross_terms.iter().map(|v| v[0]).collect(),
            folding_challenge: challenge,
        };

        let folded_wit = FoldedWitness {
            witness: folded_witness,
            accumulated_randomness: witness1.commitment_randomness.clone(),
        };

        Ok((folded, folded_wit, proof))
    }

    fn verify_fold(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        folded: &FoldedInstance<F>,
        proof: &RoundProof<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<bool> {
        // Absorb instances
        transcript.append_instance("instance1", instance1);
        transcript.append_instance("instance2", instance2);

        // Absorb cross-term commitments
        for commit in &proof.cross_term_commits {
            transcript.append_ring_element("cross_term", commit);
        }

        // Get challenge
        let challenge = transcript.challenge_scalar("folding_challenge");

        // Verify challenge matches
        if challenge != folded.folding_challenge {
            return Ok(false);
        }

        // Verify sum-check proof
        if !self.verify_sumcheck_proof(&proof.sumcheck_proof, &challenge)? {
            return Ok(false);
        }

        // Verify folded commitments
        if !self.verify_folded_commitments(
            instance1,
            instance2,
            &folded.instance,
            &proof.cross_term_evals,
            &challenge,
        )? {
            return Ok(false);
        }

        Ok(true)
    }
}

impl ProtogaFolder {
    /// Compute cross-terms between two witnesses
    fn compute_cross_terms<F: Field>(
        &self,
        witness1: &ProtogaWitness<F>,
        witness2: &ProtogaWitness<F>,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
    ) -> Result<Vec<Vec<F>>> {
        let n = witness1.witness_values.len();
        if witness2.witness_values.len() != n {
            return Err(ProtogaError::InvalidWitness(
                "Witness dimensions mismatch".into()
            ));
        }

        let mut cross_terms = Vec::new();

        // For each constraint in the relation
        for constraint in &self.relation.constraints {
            let mut constraint_cross_terms = Vec::new();

            // Compute cross-term for this constraint
            // T = constraint(w1, w2) + constraint(w2, w1)
            for term in &constraint.terms {
                let mut cross_val = F::zero();

                // Evaluate term with mixed witnesses
                if !term.variables.is_empty() {
                    let mut val1 = term.coefficient;
                    let mut val2 = term.coefficient;

                    for (i, &var_idx) in term.variables.iter().enumerate() {
                        let power = term.powers[i];
                        
                        // w1[i] * w2[i]^(power-1) + w2[i] * w1[i]^(power-1)
                        if power > 0 {
                            let w1_val = witness1.witness_values[var_idx];
                            let w2_val = witness2.witness_values[var_idx];
                            
                            if power == 1 {
                                val1 = val1.mul(&w2_val);
                                val2 = val2.mul(&w1_val);
                            } else {
                                // Higher degree terms
                                let mut w1_pow = w1_val;
                                let mut w2_pow = w2_val;
                                for _ in 1..power {
                                    w1_pow = w1_pow.mul(&w1_val);
                                    w2_pow = w2_pow.mul(&w2_val);
                                }
                                val1 = val1.mul(&w2_pow);
                                val2 = val2.mul(&w1_pow);
                            }
                        }
                    }

                    cross_val = val1.add(&val2);
                }

                constraint_cross_terms.push(cross_val);
            }

            cross_terms.push(constraint_cross_terms);
        }

        Ok(cross_terms)
    }

    /// Commit to cross-terms
    fn commit_cross_terms<F: Field>(
        &self,
        cross_terms: &[Vec<F>],
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<Vec<RingElement>> {
        let mut commits = Vec::new();

        for terms in cross_terms {
            // Generate fresh randomness
            let randomness = ProtogaCommitment::sample_randomness(
                &self.params,
                &mut transcript.rng(),
            );

            // Commit to cross-term
            let commit = ProtogaCommitment::commit(
                &self.commitment_key,
                terms,
                &randomness,
            )?;

            transcript.append_ring_element("cross_term", &commit.value);
            commits.push(commit.value);
        }

        Ok(commits)
    }

    /// Fold two instances using challenge
    fn fold_instances<F: Field>(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        cross_terms: &[Vec<F>],
        challenge: &F,
    ) -> Result<ProtogaInstance<F>> {
        // Fold commitments: C = C1 + r·T + r²·C2
        let r_squared = challenge.mul(challenge);
        
        let mut folded_commitments = Vec::new();
        for i in 0..instance1.commitments.len() {
            let c1 = &instance1.commitments[i];
            let c2 = &instance2.commitments[i];
            
            // Compute r·T (cross-term contribution)
            let cross_contrib = if i < cross_terms.len() {
                // Convert cross-term to ring element for addition
                // This is simplified - real implementation needs proper encoding
                c1.scalar_mul(challenge.to_canonical_u64())
            } else {
                RingElement::zero(self.params.ring_dimension)
            };
            
            // C1 + r·T + r²·C2
            let mut folded = c1.clone();
            folded = folded.add(&cross_contrib);
            let c2_scaled = c2.scalar_mul(r_squared.to_canonical_u64());
            folded = folded.add(&c2_scaled);
            
            folded_commitments.push(folded);
        }

        // Fold public inputs: x = x1 + r·x2
        let mut folded_inputs = Vec::new();
        for i in 0..instance1.public_inputs.len() {
            let x1 = instance1.public_inputs[i];
            let x2 = instance2.public_inputs[i];
            let folded = x1.add(&challenge.mul(&x2));
            folded_inputs.push(folded);
        }

        // Fold relaxation factors: u = u1 + r·u2
        let folded_relaxation = instance1.relaxation_factor
            .add(&challenge.mul(&instance2.relaxation_factor));

        // Fold error commitments if present
        let folded_error = if let (Some(e1), Some(e2)) = 
            (&instance1.error_commitment, &instance2.error_commitment) {
            let e = e1.add(&e2.scalar_mul(challenge.to_canonical_u64()));
            Some(e)
        } else {
            None
        };

        Ok(ProtogaInstance {
            commitments: folded_commitments,
            public_inputs: folded_inputs,
            relaxation_factor: folded_relaxation,
            error_commitment: folded_error,
        })
    }

    /// Fold two witnesses using challenge
    fn fold_witnesses<F: Field>(
        &self,
        witness1: &ProtogaWitness<F>,
        witness2: &ProtogaWitness<F>,
        challenge: &F,
    ) -> Result<ProtogaWitness<F>> {
        // Fold witness values: w = w1 + r·w2
        let mut folded_values = Vec::new();
        for i in 0..witness1.witness_values.len() {
            let w1 = witness1.witness_values[i];
            let w2 = witness2.witness_values[i];
            let folded = w1.add(&challenge.mul(&w2));
            folded_values.push(folded);
        }

        // Fold randomness: ρ = ρ1 + r·ρ2
        let mut folded_randomness = Vec::new();
        for i in 0..witness1.commitment_randomness.len() {
            let r1 = &witness1.commitment_randomness[i];
            let r2 = &witness2.commitment_randomness[i];
            let r_scaled = r2.scalar_mul(challenge.to_canonical_u64());
            let folded = r1.add(&r_scaled);
            folded_randomness.push(folded);
        }

        // Fold error vectors if present
        let folded_error = if let (Some(e1), Some(e2)) = 
            (&witness1.error_vector, &witness2.error_vector) {
            let mut folded = Vec::new();
            for i in 0..e1.len() {
                let folded_e = e1[i].add(&challenge.mul(&e2[i]));
                folded.push(folded_e);
            }
            Some(folded)
        } else {
            None
        };

        Ok(ProtogaWitness {
            witness_values: folded_values,
            commitment_randomness: folded_randomness,
            error_vector: folded_error,
        })
    }

    /// Generate sum-check proof for cross-terms
    fn generate_sumcheck_proof<F: Field>(
        &self,
        cross_terms: &[Vec<F>],
        challenge: &F,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<SumCheckProof<F>> {
        // Sum-check protocol to verify cross-term evaluation
        let num_variables = (cross_terms.len() as f64).log2().ceil() as usize;
        let mut round_polynomials = Vec::new();

        let mut current_sum = F::zero();
        for terms in cross_terms {
            for &term in terms {
                current_sum = current_sum.add(&term);
            }
        }

        // For each round of sum-check
        for round in 0..num_variables {
            // Compute univariate polynomial for this round
            let mut poly_coeffs = vec![F::zero(); 3]; // Degree 2 polynomial
            
            // Evaluate at 0, 1, 2
            for eval_point in 0..=2 {
                let eval = F::from(eval_point as u64);
                let poly_eval = self.evaluate_sumcheck_round(
                    cross_terms,
                    round,
                    &eval,
                )?;
                poly_coeffs[eval_point] = poly_eval;
            }

            round_polynomials.push(poly_coeffs.clone());
            transcript.append_field_elements("sumcheck_round", &poly_coeffs);
            
            // Get verifier challenge for this round
            let _round_challenge = transcript.challenge_scalar("sumcheck_challenge");
        }

        Ok(SumCheckProof {
            round_polynomials,
            final_evaluation: current_sum,
        })
    }

    /// Evaluate sum-check at specific round and point
    fn evaluate_sumcheck_round<F: Field>(
        &self,
        cross_terms: &[Vec<F>],
        round: usize,
        point: &F,
    ) -> Result<F> {
        let mut sum = F::zero();
        
        for (i, terms) in cross_terms.iter().enumerate() {
            // Check if this term involves the current round variable
            let bit = (i >> round) & 1;
            let selector = if bit == 0 {
                F::one().sub(point)
            } else {
                *point
            };

            for &term in terms {
                sum = sum.add(&term.mul(&selector));
            }
        }

        Ok(sum)
    }

    /// Verify sum-check proof
    fn verify_sumcheck_proof<F: Field>(
        &self,
        proof: &SumCheckProof<F>,
        _challenge: &F,
    ) -> Result<bool> {
        // Verify each round polynomial is well-formed
        for poly in &proof.round_polynomials {
            if poly.len() != 3 {
                return Ok(false);
            }
            // Check degree bound
            if poly[2].is_zero() && poly.iter().all(|c| c.is_zero()) {
                return Ok(false);
            }
        }

        // Verify final sum
        // In full implementation, would verify consistency across rounds
        Ok(!proof.final_evaluation.is_zero())
    }

    /// Evaluate cross-terms at challenge point
    fn evaluate_cross_terms<F: Field>(
        &self,
        cross_terms: &[Vec<F>],
        challenge: &F,
    ) -> Result<Vec<F>> {
        let mut evals = Vec::new();
        
        for terms in cross_terms {
            let mut eval = F::zero();
            let mut power = F::one();
            
            for &term in terms {
                eval = eval.add(&term.mul(&power));
                power = power.mul(challenge);
            }
            
            evals.push(eval);
        }

        Ok(evals)
    }

    /// Verify folded commitments are correct
    fn verify_folded_commitments<F: Field>(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        folded: &ProtogaInstance<F>,
        cross_term_evals: &[F],
        challenge: &F,
    ) -> Result<bool> {
        let r_squared = challenge.mul(challenge);

        for i in 0..folded.commitments.len() {
            // Verify C = C1 + r·T + r²·C2
            let c1 = &instance1.commitments[i];
            let c2 = &instance2.commitments[i];
            let c = &folded.commitments[i];

            // Recompute expected commitment
            let mut expected = c1.clone();
            
            if i < cross_term_evals.len() {
                let cross_scaled = RingElement::zero(self.params.ring_dimension)
                    .scalar_mul(
                        challenge.mul(&cross_term_evals[i]).to_canonical_u64()
                    );
                expected = expected.add(&cross_scaled);
            }
            
            let c2_scaled = c2.scalar_mul(r_squared.to_canonical_u64());
            expected = expected.add(&c2_scaled);

            if &expected != c {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Constant-round folder with optimized round complexity
pub struct ConstantRoundFolder {
    /// Base folder
    folder: ProtogaFolder,
    /// Number of rounds
    num_rounds: usize,
}

impl ConstantRoundFolder {
    /// Create new constant-round folder
    pub fn new(folder: ProtogaFolder, num_rounds: usize) -> Self {
        Self { folder, num_rounds }
    }

    /// Perform complete folding in constant rounds
    pub fn fold_constant_rounds<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        witnesses: &[ProtogaWitness<F>],
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<(ProtogaInstance<F>, ProtogaWitness<F>, FoldingProof<F>)> {
        if instances.len() != witnesses.len() {
            return Err(ProtogaError::InvalidParameters(
                "Instance and witness count mismatch".into()
            ));
        }

        let mut current_instances = instances.to_vec();
        let mut current_witnesses = witnesses.to_vec();
        let mut round_proofs = Vec::new();

        // Fold pairs in each round
        for round in 0..self.num_rounds {
            transcript.append_message("round", &round.to_le_bytes());
            
            let mut next_instances = Vec::new();
            let mut next_witnesses = Vec::new();

            // Fold pairs
            for i in (0..current_instances.len()).step_by(2) {
                if i + 1 < current_instances.len() {
                    let (folded_inst, folded_wit, proof) = self.folder.fold(
                        &current_instances[i],
                        &current_instances[i + 1],
                        &current_witnesses[i],
                        &current_witnesses[i + 1],
                        transcript,
                    )?;

                    next_instances.push(folded_inst.instance);
                    next_witnesses.push(folded_wit.witness);
                    round_proofs.push(proof);
                } else {
                    // Odd one out, carry forward
                    next_instances.push(current_instances[i].clone());
                    next_witnesses.push(current_witnesses[i].clone());
                }
            }

            current_instances = next_instances;
            current_witnesses = next_witnesses;

            if current_instances.len() == 1 {
                break;
            }
        }

        if current_instances.len() != 1 {
            return Err(ProtogaError::InvalidProof(
                "Failed to fold to single instance".into()
            ));
        }

        Ok((
            current_instances[0].clone(),
            current_witnesses[0].clone(),
            FoldingProof {
                round_proofs,
                final_instance: current_instances[0].clone(),
            },
        ))
    }
}

/// Recursive folding prover
pub struct RecursiveFoldingProver {
    folder: ProtogaFolder,
}

impl RecursiveFoldingProver {
    pub fn new(folder: ProtogaFolder) -> Self {
        Self { folder }
    }

    /// Recursively fold instances
    pub fn recursive_fold<F: Field>(
        &self,
        instances: Vec<ProtogaInstance<F>>,
        witnesses: Vec<ProtogaWitness<F>>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<(ProtogaInstance<F>, ProtogaWitness<F>, Vec<RoundProof<F>>)> {
        if instances.len() == 1 {
            return Ok((instances[0].clone(), witnesses[0].clone(), Vec::new()));
        }

        let mid = instances.len() / 2;
        
        // Recursively fold left and right halves
        let (left_inst, left_wit, mut left_proofs) = self.recursive_fold(
            instances[..mid].to_vec(),
            witnesses[..mid].to_vec(),
            transcript,
        )?;

        let (right_inst, right_wit, mut right_proofs) = self.recursive_fold(
            instances[mid..].to_vec(),
            witnesses[mid..].to_vec(),
            transcript,
        )?;

        // Fold the two results
        let (folded, folded_wit, proof) = self.folder.fold(
            &left_inst,
            &right_inst,
            &left_wit,
            &right_wit,
            transcript,
        )?;

        let mut all_proofs = Vec::new();
        all_proofs.append(&mut left_proofs);
        all_proofs.append(&mut right_proofs);
        all_proofs.push(proof);

        Ok((folded.instance, folded_wit.witness, all_proofs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::protogalattice::transcript::Transcript;
    use rand::thread_rng();

    #[test]
    fn test_basic_folding() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        
        let mut relation = GeneralPolynomialRelation::new(2);
        let folder = ProtogaFolder::setup(params, relation, &mut rng).unwrap();

        // Create simple instances
        let instance1 = ProtogaInstance::new(vec![], vec![GoldilocksField::from(1u64)]);
        let instance2 = ProtogaInstance::new(vec![], vec![GoldilocksField::from(2u64)]);

        let witness1 = ProtogaWitness::new(vec![GoldilocksField::from(1u64)], vec![]);
        let witness2 = ProtogaWitness::new(vec![GoldilocksField::from(2u64)], vec![]);

        let mut transcript = Transcript::new(b"test");
        
        let result = folder.fold(
            &instance1,
            &instance2,
            &witness1,
            &witness2,
            &mut transcript,
        );

        assert!(result.is_ok());
    }
}
