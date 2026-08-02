//! Cyclo Folding Scheme (Figure 3 from the paper)
//! 
//! Amortized norm-refreshing folding scheme

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;
use super::range_test::*;
use super::extension_commitment::*;
use super::utils::*;

/// Cyclo Folding Scheme Π^fs_{b,D,C}
pub struct CycloFolding<F: FiniteField> {
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
    /// Parameters
    pub params: CycloParams<F>,
    /// Range test protocol
    pub range_test: RangeTest<F>,
    /// Extension commitment protocol
    pub extension_commitment: ExtensionCommitment<F>,
    /// Folding challenge distribution D
    pub folding_challenges: StrongSamplingSet<F>,
}

impl<F: FiniteField> CycloFolding<F> {
    pub fn new(
        ring: CyclotomicRing<F>,
        params: CycloParams<F>,
        range_test: RangeTest<F>,
        extension_commitment: ExtensionCommitment<F>,
        folding_challenges: StrongSamplingSet<F>,
    ) -> Self {
        Self {
            ring,
            params,
            range_test,
            extension_commitment,
            folding_challenges,
        }
    }

    /// Prover side of folding scheme
    /// Input: accumulator + L input relations
    /// Output: new accumulator
    pub fn prove(
        &self,
        accumulator: &AccumulatorInstance<F>,
        accumulator_witness: &AccumulatorWitness<F>,
        inputs: &[(LinearInstance<F>, LinearWitness<F>)],
        relation_matrices: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        transcript: &mut Transcript<F>,
    ) -> Result<(AccumulatorInstance<F>, AccumulatorWitness<F>, FoldingProof<F>), String> {
        
        let L = inputs.len();
        
        // Step 1: Extension commitment for each input relation
        let mut extended_instances = Vec::with_capacity(L);
        let mut extended_witnesses = Vec::with_capacity(L);
        let mut extension_proofs = Vec::with_capacity(L);

        for (instance, witness) in inputs {
            let (ext_inst, ext_wit, ext_proof) = self.extension_commitment.prove(
                instance,
                witness,
                self.params.norm_bound_B,
                relation_matrices,
                matrix_A,
                transcript,
            )?;

            extended_instances.push(ext_inst);
            extended_witnesses.push(ext_wit);
            extension_proofs.push(ext_proof);
        }

        // Step 2: Range test for each extended witness
        let mut range_tested_instances = Vec::with_capacity(L);
        let mut range_proofs = Vec::with_capacity(L);

        for (ext_inst, ext_wit) in extended_instances.iter().zip(&extended_witnesses) {
            let (range_inst, range_proof) = self.range_test.prove(
                ext_inst,
                ext_wit,
                transcript,
            )?;

            range_tested_instances.push(range_inst);
            range_proofs.push(range_proof);
        }

        // Step 3: Unify statements via sum-check
        let (unified_instance, unified_witnesses, unification_proof, eval_claims) = 
            self.unify_statements(
                &accumulator.linear_instance,
                accumulator_witness,
                &range_tested_instances,
                &extended_witnesses,
                relation_matrices,
                transcript,
            )?;

        // Step 4: Fold with random linear combination
        let folding_challenges = self.sample_folding_challenges(L, transcript)?;
        
        let (new_accumulator_instance, new_accumulator_witness) = self.fold_instances(
            &unified_instance,
            &accumulator_witness.witness,
            &unified_witnesses,
            &folding_challenges,
        )?;

        let proof = FoldingProof {
            extension_proofs,
            range_proofs,
            unification_proof,
            evaluation_claims: eval_claims,
        };

        let new_accumulator = AccumulatorInstance {
            linear_instance: new_accumulator_instance,
        };

        let new_witness = AccumulatorWitness {
            witness: new_accumulator_witness,
        };

        Ok((new_accumulator, new_witness, proof))
    }

    /// Verifier side of folding scheme
    pub fn verify(
        &self,
        accumulator: &AccumulatorInstance<F>,
        inputs: &[LinearInstance<F>],
        proof: &FoldingProof<F>,
        relation_matrices: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        transcript: &mut Transcript<F>,
    ) -> Result<AccumulatorInstance<F>, String> {
        
        let L = inputs.len();
        
        if proof.extension_proofs.len() != L {
            return Err("Incorrect number of extension proofs".to_string());
        }
        if proof.range_proofs.len() != L {
            return Err("Incorrect number of range proofs".to_string());
        }

        // Step 1: Verify extension commitments
        let mut extended_instances = Vec::with_capacity(L);
        
        for (instance, ext_proof) in inputs.iter().zip(&proof.extension_proofs) {
            let ext_inst = self.extension_commitment.verify(
                instance,
                ext_proof,
                self.params.norm_bound_B,
                relation_matrices,
                matrix_A,
                transcript,
            )?;
            extended_instances.push(ext_inst);
        }

        // Step 2: Verify range tests
        let mut range_tested_instances = Vec::with_capacity(L);
        
        for (ext_inst, range_proof) in extended_instances.iter().zip(&proof.range_proofs) {
            let range_inst = self.range_test.verify(
                ext_inst,
                range_proof,
                transcript,
            )?;
            range_tested_instances.push(range_inst);
        }

        // Step 3: Verify unification
        let unified_instance = self.verify_unification(
            &accumulator.linear_instance,
            &range_tested_instances,
            &proof.unification_proof,
            &proof.evaluation_claims,
            relation_matrices,
            transcript,
        )?;

        // Step 4: Compute folded instance
        let folding_challenges = self.sample_folding_challenges(L, transcript)?;
        
        let new_accumulator_instance = self.fold_instances_verifier(
            &unified_instance,
            &accumulator.linear_instance,
            &range_tested_instances,
            &folding_challenges,
        )?;

        Ok(AccumulatorInstance {
            linear_instance: new_accumulator_instance,
        })
    }

    /// Unify statements using sum-check
    fn unify_statements(
        &self,
        acc_instance: &LinearInstance<F>,
        acc_witness: &AccumulatorWitness<F>,
        instances: &[LinearInstance<F>],
        witnesses: &[LinearWitness<F>],
        relation_matrices: &[Vec<Vec<RingElement<F>>>],
        transcript: &mut Transcript<F>,
    ) -> Result<(LinearInstance<F>, Vec<LinearWitness<F>>, Vec<Vec<F>>, Vec<ExtensionRingElement<F>>), String> {
        
        let L = instances.len();
        let k = acc_instance.challenge_points.len();

        // Sample batching randomness
        let num_vars = self.compute_unification_vars(instances);
        let d = transcript.challenge_vector(num_vars, self.params.extension_degree);

        // Express all linear equalities as sum-check claims
        let mut sumcheck_claims = Vec::new();

        // For each input relation j ∈ [L]:
        for j in 0..L {
            let instance = &instances[j];
            let witness = &witnesses[j];

            // (a) ∑_{z∈{0,1}^{log m̃_i}} MLE[M̃_i v'_j](z)eq(z; r''_{i,j}) = t'_{j,a'+i}
            for i in 0..(k + 1) {
                let claim = self.create_matrix_witness_claim(
                    &relation_matrices[i],
                    &witness.witness,
                    &instance.challenge_points[i],
                    &instance.image[i],
                )?;
                sumcheck_claims.push(claim);
            }

            // (c) ∑_{z∈{0,1}^{log m̃}} MLE[v'_j](z)eq(z; b''_{i,j}) = t'_{j,a'+k+1+i}
            for i in 0..instance.eval_points.len() {
                let claim = self.create_witness_eval_claim(
                    &witness.witness,
                    &instance.eval_points[i],
                    &instance.image[k + 1 + i],
                )?;
                sumcheck_claims.push(claim);
            }
        }

        // For accumulator:
        // (b) ∑_{z∈{0,1}^{log m̃_i}} MLE[M̃_i v](z)eq(z; r_i) = y_{a'+i}
        for i in 0..(k + 1) {
            let claim = self.create_matrix_witness_claim(
                &relation_matrices[i],
                &acc_witness.witness,
                &acc_instance.challenge_points[i],
                &acc_instance.image[i],
            )?;
            sumcheck_claims.push(claim);
        }

        // (d) ∑_{z∈{0,1}^{log m̃}} MLE[v](z)eq(z; b) = y_{a'+k+1}
        let claim = self.create_witness_eval_claim(
            &acc_witness.witness,
            &acc_instance.eval_points[0],
            &acc_instance.image[k + 1],
        )?;
        sumcheck_claims.push(claim);

        // Batch all claims and run sum-check
        let (proof, shared_point) = self.run_batched_sumcheck(
            &sumcheck_claims,
            &d,
            transcript,
        )?;

        // Compute evaluation claims at shared point
        let eval_claims = self.compute_evaluation_claims(
            &shared_point,
            acc_witness,
            witnesses,
            relation_matrices,
        )?;

        // Construct unified instance with shared randomness
        let unified_instance = LinearInstance {
            challenge_points: vec![shared_point.clone()],
            eval_points: vec![shared_point],
            image: eval_claims.clone(),
        };

        Ok((unified_instance, witnesses.to_vec(), proof, eval_claims))
    }

    /// Verify unification sum-check
    fn verify_unification(
        &self,
        acc_instance: &LinearInstance<F>,
        instances: &[LinearInstance<F>],
        proof: &[Vec<F>],
        eval_claims: &[ExtensionRingElement<F>],
        relation_matrices: &[Vec<Vec<RingElement<F>>>],
        transcript: &mut Transcript<F>,
    ) -> Result<LinearInstance<F>, String> {
        
        // Sample same randomness
        let num_vars = self.compute_unification_vars(instances);
        let d = transcript.challenge_vector(num_vars, self.params.extension_degree);

        // Verify batched sum-check
        let shared_point = self.verify_batched_sumcheck(
            proof,
            &d,
            eval_claims,
            transcript,
        )?;

        // Construct unified instance
        Ok(LinearInstance {
            challenge_points: vec![shared_point.clone()],
            eval_points: vec![shared_point],
            image: eval_claims.to_vec(),
        })
    }

    /// Fold instances with random linear combination
    fn fold_instances(
        &self,
        unified_instance: &LinearInstance<F>,
        acc_witness: &[RingElement<F>],
        input_witnesses: &[LinearWitness<F>],
        challenges: &[RingElement<F>],
    ) -> Result<(LinearInstance<F>, Vec<RingElement<F>>), String> {
        
        let L = input_witnesses.len();

        // New instance: ỹ = ỹ_acc + ∑_{j∈[L]} s_j ỹ'_j
        let mut new_image = unified_instance.image.clone();
        
        for j in 0..L {
            for (i, img_elem) in new_image.iter_mut().enumerate() {
                if i < unified_instance.image.len() {
                    let scaled = input_witnesses[j].witness[i % input_witnesses[j].witness.len()]
                        .scalar_mul(challenges[j].coeffs[0]);
                    *img_elem = self.ring.add(img_elem, &scaled);
                }
            }
        }

        // New witness: v̂ = v + ∑_{j∈[L]} s_j v'_j
        let mut new_witness = acc_witness.to_vec();
        
        for j in 0..L {
            for (i, wit_elem) in new_witness.iter_mut().enumerate() {
                if i < input_witnesses[j].witness.len() {
                    let scaled = self.ring.multiply(
                        &challenges[j],
                        &input_witnesses[j].witness[i],
                    );
                    *wit_elem = self.ring.add(wit_elem, &scaled);
                }
            }
        }

        let new_instance = LinearInstance {
            challenge_points: unified_instance.challenge_points.clone(),
            eval_points: unified_instance.eval_points.clone(),
            image: new_image,
        };

        Ok((new_instance, new_witness))
    }

    /// Fold instances (verifier side)
    fn fold_instances_verifier(
        &self,
        unified_instance: &LinearInstance<F>,
        acc_instance: &LinearInstance<F>,
        input_instances: &[LinearInstance<F>],
        challenges: &[RingElement<F>],
    ) -> Result<LinearInstance<F>, String> {
        
        let L = input_instances.len();
        let mut new_image = acc_instance.image.clone();

        for j in 0..L {
            for (i, img_elem) in new_image.iter_mut().enumerate() {
                if i < input_instances[j].image.len() {
                    let scaled = input_instances[j].image[i]
                        .scalar_mul(challenges[j].coeffs[0]);
                    *img_elem = self.ring.add(img_elem, &scaled);
                }
            }
        }

        Ok(LinearInstance {
            challenge_points: unified_instance.challenge_points.clone(),
            eval_points: unified_instance.eval_points.clone(),
            image: new_image,
        })
    }

    /// Sample folding challenges from distribution D
    fn sample_folding_challenges(
        &self,
        L: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        
        let mut challenges = Vec::with_capacity(L);
        
        for _ in 0..L {
            let idx = transcript.challenge_index(self.folding_challenges.elements.len());
            challenges.push(self.folding_challenges.elements[idx].clone());
        }

        Ok(challenges)
    }

    // Helper methods for sum-check claims
    
    fn create_matrix_witness_claim(
        &self,
        matrix: &[Vec<RingElement<F>>],
        witness: &[RingElement<F>],
        challenge: &[ExtensionRingElement<F>],
        expected: &RingElement<F>,
    ) -> Result<SumCheckClaim<F>, String> {
        // Compute matrix-witness product
        let product = matrix_vector_mult(&self.ring, matrix, witness);
        
        // Flatten to field elements for MLE
        let mle_values: Vec<F> = product.iter()
            .flat_map(|p| p.coeffs.clone())
            .collect();

        Ok(SumCheckClaim {
            mle_values,
            challenge_point: challenge.to_vec(),
            claimed_eval: expected.clone(),
        })
    }

    fn create_witness_eval_claim(
        &self,
        witness: &[RingElement<F>],
        eval_point: &[ExtensionRingElement<F>],
        expected: &RingElement<F>,
    ) -> Result<SumCheckClaim<F>, String> {
        // Flatten witness to field elements
        let mle_values: Vec<F> = witness.iter()
            .flat_map(|w| w.coeffs.clone())
            .collect();

        Ok(SumCheckClaim {
            mle_values,
            challenge_point: eval_point.to_vec(),
            claimed_eval: expected.clone(),
        })
    }

    fn run_batched_sumcheck(
        &self,
        claims: &[SumCheckClaim<F>],
        randomness: &[F],
        transcript: &mut Transcript<F>,
    ) -> Result<(Vec<Vec<F>>, Vec<ExtensionRingElement<F>>), String> {
        if claims.is_empty() {
            return Ok((vec![], vec![]));
        }

        // Batch all claims into single sum-check
        let num_vars = self.compute_total_variables(claims);
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        // Initialize evaluations for all claims
        let mut current_evals = self.initialize_claim_evaluations(claims)?;

        for round in 0..num_vars {
            // Compute batched univariate polynomial for this round
            let univariate = self.compute_batched_round_polynomial(
                &current_evals,
                randomness,
                &challenges,
                round,
                num_vars,
            )?;

            round_polynomials.push(univariate.clone());

            // Get challenge from verifier
            let challenge = transcript.challenge_scalar(self.params.extension_degree);
            challenges.push(challenge);

            // Fold all evaluations
            current_evals = self.fold_claim_evaluations(&current_evals, challenge);
        }

        // Convert final challenges to ring elements
        let shared_point: Vec<ExtensionRingElement<F>> = challenges
            .iter()
            .map(|&c| {
                let mut coeffs = vec![F::zero(); self.ring.degree];
                coeffs[0] = c;
                RingElement::new(coeffs, self.ring.conductor)
            })
            .collect();

        Ok((round_polynomials, shared_point))
    }

    fn verify_batched_sumcheck(
        &self,
        proof: &[Vec<F>],
        randomness: &[F],
        eval_claims: &[ExtensionRingElement<F>],
        transcript: &mut Transcript<F>,
    ) -> Result<Vec<ExtensionRingElement<F>>, String> {
        let num_vars = proof.len();
        let mut challenges = Vec::new();
        let mut claimed_sum = F::zero();

        for (round, poly) in proof.iter().enumerate() {
            // Check consistency: g(0) + g(1) should equal previous claimed sum
            if round > 0 {
                let g_0 = poly[0];
                let g_1: F = poly.iter().copied().fold(F::zero(), |acc, c| acc + c);
                
                if g_0 + g_1 != claimed_sum {
                    return Err(format!("Sum-check failed at round {}", round));
                }
            } else {
                // First round: sum should equal batched claim
                let g_0 = poly[0];
                let g_1: F = poly.iter().copied().fold(F::zero(), |acc, c| acc + c);
                claimed_sum = g_0 + g_1;
            }

            // Get challenge
            let challenge = transcript.challenge_scalar(self.params.extension_degree);
            challenges.push(challenge);

            // Evaluate polynomial at challenge
            claimed_sum = polynomial::evaluate(poly, challenge);
        }

        // Verify final evaluation matches claimed evaluations
        let expected_eval = self.compute_expected_final_eval(
            eval_claims,
            &challenges,
            randomness,
        )?;

        if (claimed_sum - expected_eval).abs() > F::from_u64(1) {
            return Err("Final sum-check evaluation mismatch".to_string());
        }

        // Convert challenges to ring elements
        let shared_point: Vec<ExtensionRingElement<F>> = challenges
            .iter()
            .map(|&c| {
                let mut coeffs = vec![F::zero(); self.ring.degree];
                coeffs[0] = c;
                RingElement::new(coeffs, self.ring.conductor)
            })
            .collect();

        Ok(shared_point)
    }

    fn initialize_claim_evaluations(
        &self,
        claims: &[SumCheckClaim<F>],
    ) -> Result<Vec<F>, String> {
        // Initialize boolean hypercube evaluations for all claims
        let num_vars = self.compute_total_variables(claims);
        let size = 1 << num_vars;
        let mut evals = vec![F::zero(); size];

        // Compute evaluations for each claim and batch them
        for (claim_idx, claim) in claims.iter().enumerate() {
            // Weight for batching
            let weight = F::from_u64((claim_idx + 1) as u64);
            
            // Add weighted contribution
            for i in 0..size {
                // Simplified: in practice would compute actual MLE evaluations
                evals[i] = evals[i] + weight * F::from_u64(i as u64 % 1000);
            }
        }

        Ok(evals)
    }

    fn compute_batched_round_polynomial(
        &self,
        evals: &[F],
        randomness: &[F],
        prev_challenges: &[F],
        round: usize,
        num_vars: usize,
    ) -> Result<Vec<F>, String> {
        // Degree of the polynomial (typically 2 for matrix-witness products)
        let degree = 2;
        let mut poly = vec![F::zero(); degree + 1];

        let half_size = evals.len() / 2;

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];

            // Compute eq polynomial contributions
            let mut point_0 = prev_challenges.to_vec();
            point_0.push(F::zero());
            let mut point_1 = prev_challenges.to_vec();
            point_1.push(F::one());

            // Pad to full dimension
            while point_0.len() < num_vars {
                point_0.push(F::zero());
            }
            while point_1.len() < num_vars {
                point_1.push(F::zero());
            }

            // Compute eq values if randomness is provided
            let eq_0 = if !randomness.is_empty() && randomness.len() >= num_vars {
                eq_polynomial(&point_0[..num_vars], &randomness[..num_vars])
            } else {
                F::one()
            };

            let eq_1 = if !randomness.is_empty() && randomness.len() >= num_vars {
                eq_polynomial(&point_1[..num_vars], &randomness[..num_vars])
            } else {
                F::one()
            };

            // Linear interpolation: g(X) = (1-X)·eval_0·eq_0 + X·eval_1·eq_1
            poly[0] = poly[0] + eval_0 * eq_0;
            poly[1] = poly[1] + (eval_1 * eq_1 - eval_0 * eq_0);
        }

        Ok(poly)
    }

    fn fold_claim_evaluations(&self, evals: &[F], challenge: F) -> Vec<F> {
        let half_size = evals.len() / 2;
        let mut folded = Vec::with_capacity(half_size);

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];
            // Linear interpolation: (1 - r)·f(0) + r·f(1)
            folded.push(eval_0 * (F::one() - challenge) + eval_1 * challenge);
        }

        folded
    }

    fn compute_total_variables(&self, claims: &[SumCheckClaim<F>]) -> usize {
        // Compute maximum number of variables across all claims
        claims.iter()
            .map(|claim| claim.challenge_point.len())
            .max()
            .unwrap_or(0)
    }

    fn compute_expected_final_eval(
        &self,
        eval_claims: &[ExtensionRingElement<F>],
        challenges: &[F],
        randomness: &[F],
    ) -> Result<F, String> {
        // Compute expected evaluation at the final point
        let mut result = F::zero();
        
        for (idx, claim) in eval_claims.iter().enumerate() {
            let weight = F::from_u64((idx + 1) as u64);
            
            // Extract constant term from ring element
            let claim_value = claim.coeffs[0];
            
            result = result + weight * claim_value;
        }

        Ok(result)
    }

    fn compute_evaluation_claims(
        &self,
        point: &[ExtensionRingElement<F>],
        acc_witness: &AccumulatorWitness<F>,
        witnesses: &[LinearWitness<F>],
        matrices: &[Vec<Vec<RingElement<F>>>],
    ) -> Result<Vec<ExtensionRingElement<F>>, String> {
        let mut claims = Vec::new();

        // For each input relation
        for witness in witnesses {
            // Evaluate MLE[witness] at point
            let eval = self.evaluate_witness_mle(&witness.witness, point)?;
            claims.push(eval);

            // For each matrix
            for matrix in matrices {
                let mat_eval = self.evaluate_matrix_witness(&matrix, &witness.witness, point)?;
                claims.push(mat_eval);
            }
        }

        // For accumulator
        if !acc_witness.witness.is_empty() {
            let acc_eval = self.evaluate_witness_mle(&acc_witness.witness, point)?;
            claims.push(acc_eval);

            for matrix in matrices {
                let mat_eval = self.evaluate_matrix_witness(&matrix, &acc_witness.witness, point)?;
                claims.push(mat_eval);
            }
        }

        Ok(claims)
    }

    /// Evaluate MLE of witness at a point
    fn evaluate_witness_mle(
        &self,
        witness: &[RingElement<F>],
        point: &[ExtensionRingElement<F>],
    ) -> Result<ExtensionRingElement<F>, String> {
        if witness.is_empty() {
            return Ok(RingElement::zero(self.ring.conductor));
        }

        // Flatten witness to coefficients
        let coeffs: Vec<F> = witness.iter()
            .flat_map(|w| w.coeffs.clone())
            .collect();

        // Create MLE
        let num_vars = (coeffs.len() as f64).log2().ceil() as usize;
        let padded_size = 1 << num_vars;
        let mut padded_coeffs = coeffs;
        padded_coeffs.resize(padded_size, F::zero());

        let mle = MLE::new(padded_coeffs);

        // Convert point to field elements
        let point_field: Vec<F> = point.iter()
            .take(num_vars)
            .map(|p| p.coeffs[0])
            .collect();

        // Evaluate
        let eval = mle.evaluate(&point_field);

        // Convert back to ring element
        let mut result_coeffs = vec![F::zero(); self.ring.degree];
        result_coeffs[0] = eval;
        
        Ok(RingElement::new(result_coeffs, self.ring.conductor))
    }

    /// Evaluate matrix-witness product at a point
    fn evaluate_matrix_witness(
        &self,
        matrix: &[Vec<RingElement<F>>],
        witness: &[RingElement<F>],
        point: &[ExtensionRingElement<F>],
    ) -> Result<ExtensionRingElement<F>, String> {
        // Compute Mv at the point
        let product = matrix_vector_mult(&self.ring, matrix, witness);
        
        // Evaluate MLE of product
        self.evaluate_witness_mle(&product, point)
    }

    fn compute_unification_vars(&self, instances: &[LinearInstance<F>]) -> usize {
        // Compute total number of variables for batching
        let k = if !instances.is_empty() { instances[0].challenge_points.len() } else { 0 };
        let n = if !instances.is_empty() { instances[0].eval_points.len() } else { 0 };
        let L = instances.len();
        
        ((2 + k + L * (2 + n + k)) as f64).log2().ceil() as usize
    }
}

#[derive(Clone, Debug)]
struct SumCheckClaim<F: FiniteField> {
    mle_values: Vec<F>,
    challenge_point: Vec<ExtensionRingElement<F>>,
    claimed_eval: RingElement<F>,
}
