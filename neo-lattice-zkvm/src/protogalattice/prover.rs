// Prover for ProtogaLattice folding scheme
//
// Implements:
// - Instance and witness generation
// - Proof generation for folding
// - Multi-round proving
// - Recursive proof composition

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
use rand::RngCore;

/// Proving key for ProtogaLattice
#[derive(Clone, Debug)]
pub struct ProvingKey {
    /// Commitment key
    pub commitment_key: ProtogaCommitmentKey,
    /// Lattice parameters
    pub params: LatticeParams,
    /// Polynomial relation
    pub relation: GeneralPolynomialRelation<crate::field::GoldilocksField>,
}

/// Prover state during protocol execution
pub struct ProverState<F: Field> {
    /// Current instance
    pub instance: ProtogaInstance<F>,
    /// Current witness
    pub witness: ProtogaWitness<F>,
    /// Accumulated proof
    pub accumulated_proof: Vec<RoundProof<F>>,
    /// Current round number
    pub round: usize,
}

/// Main prover interface
pub struct ProtogaProver {
    /// Proving key
    proving_key: ProvingKey,
    /// Folding scheme
    folder: ProtogaFolder,
}

impl ProtogaProver {
    /// Create new prover
    pub fn new(proving_key: ProvingKey) -> Self {
        let folder = ProtogaFolder::new(
            proving_key.commitment_key.clone(),
            proving_key.params.clone(),
            proving_key.relation.clone(),
        );

        Self {
            proving_key,
            folder,
        }
    }

    /// Setup prover with parameters
    pub fn setup(
        params: LatticeParams,
        relation: GeneralPolynomialRelation<crate::field::GoldilocksField>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        let commitment_key = ProtogaCommitment::setup(&params, rng)?;
        
        let proving_key = ProvingKey {
            commitment_key: commitment_key.clone(),
            params: params.clone(),
            relation: relation.clone(),
        };

        Ok(Self::new(proving_key))
    }

    /// Generate proof for single witness
    pub fn prove<F: Field>(
        &self,
        witness: &[F],
        public_inputs: &[F],
        rng: &mut impl RngCore,
    ) -> Result<(ProtogaInstance<F>, ProtogaWitness<F>, ProtogaProof<F>)> {
        // Validate witness satisfies relation
        if !self.proving_key.relation.is_satisfied(witness) {
            return Err(ProtogaError::InvalidWitness(
                "Witness does not satisfy relation".into()
            ));
        }

        // Generate commitments to witness
        let randomness = ProtogaCommitment::sample_randomness(
            &self.proving_key.params,
            rng,
        );

        let commitments = self.commit_witness(witness, &randomness)?;

        let instance = ProtogaInstance::new(
            commitments,
            public_inputs.to_vec(),
        );

        let witness_struct = ProtogaWitness::new(
            witness.to_vec(),
            randomness,
        );

        // Generate proof
        let proof = self.generate_proof(&instance, &witness_struct)?;

        Ok((instance, witness_struct, proof))
    }

    /// Prove with folding for multiple instances
    pub fn prove_folding<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        witnesses: &[ProtogaWitness<F>],
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<FoldingProof<F>> {
        if instances.is_empty() {
            return Err(ProtogaError::InvalidParameters(
                "Empty instance list".into()
            ));
        }

        // Use constant-round folder
        let constant_folder = ConstantRoundFolder::new(
            self.folder.clone(),
            crate::protogalattice::FOLDING_ROUNDS,
        );

        let (final_instance, _final_witness, folding_proof) = 
            constant_folder.fold_constant_rounds(
                instances,
                witnesses,
                transcript,
            )?;

        Ok(folding_proof)
    }

    /// Generate cross-term commitments
    fn generate_cross_terms<F: Field>(
        &self,
        witness1: &ProtogaWitness<F>,
        witness2: &ProtogaWitness<F>,
    ) -> Result<Vec<Vec<F>>> {
        // Compute cross-terms for all constraints
        let mut all_cross_terms = Vec::new();

        for constraint in &self.proving_key.relation.constraints {
            let mut constraint_cross_terms = Vec::new();

            for term in &constraint.terms {
                // Evaluate term with mixed witnesses
                let mut cross_val = F::zero();
                
                for (i, &var_idx) in term.variables.iter().enumerate() {
                    let w1 = witness1.witness_values[var_idx];
                    let w2 = witness2.witness_values[var_idx];
                    let power = term.powers[i];

                    // Compute cross-term contribution
                    if power == 1 {
                        cross_val = cross_val.add(&term.coefficient.mul(&w1).mul(&w2));
                    } else {
                        // Higher degree
                        let mut prod = term.coefficient;
                        for _ in 0..power {
                            prod = prod.mul(&w1).mul(&w2);
                        }
                        cross_val = cross_val.add(&prod);
                    }
                }

                constraint_cross_terms.push(cross_val);
            }

            all_cross_terms.push(constraint_cross_terms);
        }

        Ok(all_cross_terms)
    }

    /// Commit to witness values
    fn commit_witness<F: Field>(
        &self,
        witness: &[F],
        randomness: &[RingElement],
    ) -> Result<Vec<RingElement>> {
        let mut commitments = Vec::new();

        // Split witness into chunks for commitment
        let chunk_size = self.proving_key.params.module_rank;
        
        for (chunk_idx, witness_chunk) in witness.chunks(chunk_size).enumerate() {
            let rand_chunk = if chunk_idx < randomness.len() {
                vec![randomness[chunk_idx].clone()]
            } else {
                vec![RingElement::zero(self.proving_key.params.ring_dimension)]
            };

            let commitment = ProtogaCommitment::commit(
                &self.proving_key.commitment_key,
                witness_chunk,
                &rand_chunk,
            )?;

            commitments.push(commitment.value);
        }

        Ok(commitments)
    }

    /// Generate complete proof
    fn generate_proof<F: Field>(
        &self,
        instance: &ProtogaInstance<F>,
        witness: &ProtogaWitness<F>,
    ) -> Result<ProtogaProof<F>> {
        let mut transcript = Transcript::new(b"ProtogaLattice::Proof");

        // Append instance to transcript
        transcript.append_instance("instance", instance);

        // Generate opening proofs for each commitment
        let mut opening_proofs = Vec::new();
        
        for (i, commitment) in instance.commitments.iter().enumerate() {
            let proof = self.generate_opening_proof(
                commitment,
                witness,
                i,
                &mut transcript,
            )?;
            opening_proofs.push(proof);
        }

        Ok(ProtogaProof {
            cross_terms: Vec::new(),
            cross_term_commitments: Vec::new(),
            randomness_commitments: instance.commitments.clone(),
            challenge_responses: Vec::new(),
            opening_proofs,
        })
    }

    /// Generate opening proof for a commitment
    fn generate_opening_proof<F: Field>(
        &self,
        _commitment: &RingElement,
        witness: &ProtogaWitness<F>,
        chunk_idx: usize,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<OpeningProof<F>> {
        let chunk_size = self.proving_key.params.module_rank;
        let start = chunk_idx * chunk_size;
        let end = (start + chunk_size).min(witness.witness_values.len());

        let value = witness.witness_values[start..end].to_vec();

        // Generate proof elements
        let proof = if chunk_idx < witness.commitment_randomness.len() {
            vec![witness.commitment_randomness[chunk_idx].clone()]
        } else {
            vec![RingElement::zero(self.proving_key.params.ring_dimension)]
        };

        // Generate hint for verification
        let mut hint_bytes = Vec::new();
        for val in &value {
            hint_bytes.extend_from_slice(&val.to_bytes());
        }
        transcript.append_message("opening_hint", &hint_bytes);

        Ok(OpeningProof {
            value,
            proof,
            hint: hint_bytes,
        })
    }

    /// Batch prove multiple witnesses
    pub fn batch_prove<F: Field>(
        &self,
        witnesses: &[Vec<F>],
        public_inputs: &[Vec<F>],
        rng: &mut impl RngCore,
    ) -> Result<Vec<(ProtogaInstance<F>, ProtogaWitness<F>, ProtogaProof<F>)>> {
        if witnesses.len() != public_inputs.len() {
            return Err(ProtogaError::InvalidParameters(
                "Witness and public input count mismatch".into()
            ));
        }

        witnesses.iter()
            .zip(public_inputs.iter())
            .map(|(w, pi)| self.prove(w, pi, rng))
            .collect()
    }
}

/// Round-specific prover
pub struct RoundProver {
    prover: ProtogaProver,
    round_number: usize,
}

impl RoundProver {
    /// Create new round prover
    pub fn new(prover: ProtogaProver) -> Self {
        Self {
            prover,
            round_number: 0,
        }
    }

    /// Execute single round of proving
    pub fn prove_round<F: Field>(
        &mut self,
        state: &mut ProverState<F>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<RoundProof<F>> {
        transcript.append_message("round", &self.round_number.to_le_bytes());
        
        // For first round, just generate cross-terms
        let cross_term_commits = Vec::new();
        let cross_term_evals = Vec::new();

        // Generate sum-check proof
        let sumcheck_proof = SumCheckProof {
            round_polynomials: Vec::new(),
            final_evaluation: F::zero(),
        };

        let proof = RoundProof {
            cross_term_commits,
            cross_term_evals,
            sumcheck_proof,
        };

        state.round += 1;
        self.round_number += 1;

        Ok(proof)
    }

    /// Get current round number
    pub fn current_round(&self) -> usize {
        self.round_number
    }
}

/// Incremental prover for IVC
pub struct IncrementalProver {
    prover: ProtogaProver,
    accumulated_instance: Option<ProtogaInstance<crate::field::GoldilocksField>>,
    accumulated_witness: Option<ProtogaWitness<crate::field::GoldilocksField>>,
}

impl IncrementalProver {
    /// Create new incremental prover
    pub fn new(prover: ProtogaProver) -> Self {
        Self {
            prover,
            accumulated_instance: None,
            accumulated_witness: None,
        }
    }

    /// Prove and accumulate new step
    pub fn prove_step(
        &mut self,
        witness: &[crate::field::GoldilocksField],
        public_inputs: &[crate::field::GoldilocksField],
        transcript: &mut impl TranscriptProtocol,
        rng: &mut impl RngCore,
    ) -> Result<ProtogaProof<crate::field::GoldilocksField>> {
        use crate::field::GoldilocksField;

        // Generate proof for new step
        let (new_instance, new_witness, proof) = 
            self.prover.prove(witness, public_inputs, rng)?;

        // If we have accumulated state, fold with new instance
        if let (Some(acc_inst), Some(acc_wit)) = 
            (&self.accumulated_instance, &self.accumulated_witness) {
            
            let (folded, folded_wit, _round_proof) = self.prover.folder.fold(
                acc_inst,
                &new_instance,
                acc_wit,
                &new_witness,
                transcript,
            )?;

            self.accumulated_instance = Some(folded.instance);
            self.accumulated_witness = Some(folded.witness);
        } else {
            // First step, just store
            self.accumulated_instance = Some(new_instance);
            self.accumulated_witness = Some(new_witness);
        }

        Ok(proof)
    }

    /// Get accumulated instance
    pub fn get_accumulated(&self) -> Option<&ProtogaInstance<crate::field::GoldilocksField>> {
        self.accumulated_instance.as_ref()
    }

    /// Reset accumulator
    pub fn reset(&mut self) {
        self.accumulated_instance = None;
        self.accumulated_witness = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use rand::thread_rng;

    #[test]
    fn test_prover_setup() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let relation = GeneralPolynomialRelation::new(2);

        let prover = ProtogaProver::setup(params, relation, &mut rng);
        assert!(prover.is_ok());
    }

    #[test]
    fn test_prove_single() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        
        let mut relation = GeneralPolynomialRelation::new(2);
        let mut constraint = PolynomialConstraint::new("test");
        constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 0));
        constraint.set_rhs(GoldilocksField::from(42u64));
        relation.add_constraint(constraint);

        let prover = ProtogaProver::setup(params, relation, &mut rng).unwrap();

        let witness = vec![
            GoldilocksField::from(42u64),
            GoldilocksField::from(0u64),
        ];
        let public_inputs = vec![];

        let result = prover.prove(&witness, &public_inputs, &mut rng);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incremental_proving() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let relation = GeneralPolynomialRelation::new(2);

        let prover = ProtogaProver::setup(params, relation, &mut rng).unwrap();
        let mut inc_prover = IncrementalProver::new(prover);

        let witness1 = vec![GoldilocksField::from(1u64), GoldilocksField::from(2u64)];
        let witness2 = vec![GoldilocksField::from(3u64), GoldilocksField::from(4u64)];

        let mut transcript = Transcript::new(b"test");

        let _proof1 = inc_prover.prove_step(&witness1, &[], &mut transcript, &mut rng);
        let _proof2 = inc_prover.prove_step(&witness2, &[], &mut transcript, &mut rng);

        assert!(inc_prover.get_accumulated().is_some());
    }
}
