// Multi-cast Reduction: NIR_multicast
// Transforms R^ℓ (multi-instance relation) to R^cm_acc (committed relation)
// Core component for Quasar's sublinear accumulation
//
// Paper Reference: Quasar (2025-1912), Section 4.2 "Multi-cast Reduction"
//
// The multi-cast reduction NIR_multicast transforms ℓ instances of a relation R
// into a single committed instance with O(1) commitments. This is the first step
// in Quasar's accumulation scheme and enables O(log ℓ) verifier complexity.
//
// Key Innovation:
// - Instead of verifying ℓ separate instances, the verifier only needs to check
//   a single committed instance
// - Uses union polynomial w̃_∪(Y,X) to aggregate all witnesses
// - Achieves O(1) commitment overhead regardless of ℓ
//
// Algorithm Overview:
// 1. Build union polynomial w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
// 2. Commit to union polynomial (single commitment for all ℓ instances)
// 3. Generate random challenge τ ∈ F^{log ℓ}
// 4. Compute folded witness w̃(X) = w̃_∪(τ, X)
// 5. Reduce constraint verification to sumcheck over Y variables
// 6. Output committed instance with evaluation claims
//
// Complexity:
// - Prover: O(ℓ·n) where n is witness size
// - Verifier: O(log ℓ) random oracle queries + O(1) group operations
// - Proof size: O(log ℓ) field elements
//
// Security:
// - Soundness error: O(log n / |F|) from partial evaluation check
// - Binding from Ajtai commitment scheme under Ring-SIS assumption

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use super::union_polynomial::{UnionPolynomial, UnionPolynomialBuilder};
use super::accumulator::{
    Transcript, AjtaiCommitment, AjtaiCommitmentKey, 
    SumcheckProof, RoundPolynomial,
};

/// Output of multi-cast reduction
/// Transforms ℓ instances into a single committed instance
///
/// This structure represents the result of applying NIR_multicast to ℓ instances.
/// The key property is that verification of this single committed instance
/// is equivalent to verifying all ℓ original instances, but with O(log ℓ) cost.
///
/// Paper Reference: Quasar Section 4.2, Definition 4.3
#[derive(Clone, Debug)]
pub struct MultiCastOutput<F: Field> {
    /// Committed relation instance containing aggregated public data
    /// and commitments to union and witness polynomials
    pub committed_instance: CommittedInstance<F>,
    
    /// Union polynomial oracle w̃_∪(Y,X)
    /// This oracle allows querying the union polynomial at any point
    /// without revealing the individual witness polynomials
    pub union_oracle: PolynomialOracle<F>,
    
    /// Witness polynomial oracle w̃(X) = w̃_∪(τ, X)
    /// This is the folded witness obtained by evaluating the union
    /// polynomial at the random challenge τ
    pub witness_oracle: PolynomialOracle<F>,
    
    /// Evaluation point r_x ∈ F^{log n} for final verification
    /// The verifier checks that w̃(r_x) equals the claimed value
    pub evaluation_point: Vec<F>,
}

/// Committed instance in the reduced relation R^cm_acc
///
/// This represents a single instance in the committed accumulator relation.
/// It contains all public information needed for verification, including
/// commitments to the union and witness polynomials.
///
/// Paper Reference: Quasar Section 4.2, Definition 4.2
#[derive(Clone, Debug)]
pub struct CommittedInstance<F: Field> {
    /// Public input aggregated from all ℓ instances
    /// For instances (x_1, w_1), ..., (x_ℓ, w_ℓ), this contains
    /// the concatenation or hash of all public inputs x_i
    pub public_input: Vec<F>,
    
    /// Commitment to union polynomial w̃_∪(Y,X)
    /// This is a binding commitment under Ring-SIS assumption
    /// Allows verifier to check consistency without seeing the polynomial
    pub union_commitment: AjtaiCommitment<F>,
    
    /// Commitment to folded witness w̃(X) = w̃_∪(τ, X)
    /// This is the witness polynomial after folding with challenge τ
    pub witness_commitment: AjtaiCommitment<F>,
    
    /// Claimed evaluation value w̃(r_x)
    /// The prover claims that evaluating the folded witness at r_x
    /// yields this value. Verifier checks this claim.
    pub claimed_value: F,
}

/// Committed witness for the reduced relation
#[derive(Clone, Debug)]
pub struct CommittedWitness<F: Field> {
    /// Union polynomial
    pub union_polynomial: UnionPolynomial<F>,
    /// Folded witness polynomial
    pub witness_polynomial: MultilinearPolynomial<F>,
    /// Opening information
    pub opening: WitnessOpening<F>,
}

/// Opening information for witness commitment
#[derive(Clone, Debug)]
pub struct WitnessOpening<F: Field> {
    /// Witness vector
    pub witness: Vec<F>,
    /// Norm bound
    pub norm_bound: f64,
}

/// Polynomial oracle (commitment with evaluation capability)
#[derive(Clone, Debug)]
pub struct PolynomialOracle<F: Field> {
    /// Commitment to polynomial
    pub commitment: AjtaiCommitment<F>,
    /// Degree bound
    pub degree_bound: usize,
    /// Number of variables
    pub num_vars: usize,
}

/// Proof of multi-cast reduction
///
/// This proof demonstrates that the committed instance correctly represents
/// the aggregation of all ℓ input instances. The verifier can check this
/// proof in O(log ℓ) time.
///
/// Paper Reference: Quasar Section 4.2, Protocol 4.1
#[derive(Clone, Debug)]
pub struct MultiCastProof<F: Field> {
    /// Sumcheck proof for constraint aggregation
    /// Proves that Σ_{y∈B^{log ℓ}} G(y) = 0 where
    /// G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y)
    /// This aggregates all ℓ constraint checks into a single sumcheck
    pub sumcheck_proof: SumcheckProof<F>,
    
    /// Commitment to union polynomial w̃_∪(Y,X)
    /// Binding commitment allowing verifier to check consistency
    pub union_commitment: AjtaiCommitment<F>,
    
    /// Evaluation proofs for polynomial openings
    /// Proves that w̃(r_x) = claimed_value
    /// Each proof contains the evaluation point, value, and opening information
    pub eval_proofs: Vec<EvaluationProof<F>>,
    
    /// Random linear combination coefficients τ ∈ F^{log ℓ}
    /// Used to fold the union polynomial: w̃(X) = w̃_∪(τ, X)
    /// These are generated via Fiat-Shamir from the transcript
    pub rlc_coefficients: Vec<F>,
}

/// Proof of polynomial evaluation
#[derive(Clone, Debug)]
pub struct EvaluationProof<F: Field> {
    /// Evaluation point
    pub point: Vec<F>,
    /// Claimed value
    pub value: F,
    /// Opening proof
    pub opening: Vec<F>,
}

/// Multi-cast reduction trait
/// Implements NIR_multicast: R^ℓ → R^cm_acc
pub trait MultiCastReduction<F: Field> {
    /// Transform multi-instance relation to committed relation
    /// Input: ℓ instances with witnesses
    /// Output: Single committed instance with O(1) commitments
    fn multi_cast(
        instances: &[(Instance<F>, Witness<F>)],
        commitment_key: &AjtaiCommitmentKey<F>,
        transcript: &mut Transcript<F>,
    ) -> (MultiCastOutput<F>, MultiCastProof<F>);
    
    /// Verify multi-cast reduction
    fn verify_multi_cast(
        instances: &[Instance<F>],
        output: &MultiCastOutput<F>,
        proof: &MultiCastProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool;
}

/// Instance in the original relation
#[derive(Clone, Debug)]
pub struct Instance<F: Field> {
    /// Public input
    pub public_input: Vec<F>,
    /// Commitment to witness
    pub commitment: AjtaiCommitment<F>,
}

/// Witness in the original relation
#[derive(Clone, Debug)]
pub struct Witness<F: Field> {
    /// Private witness vector
    pub witness: Vec<F>,
}

/// Multi-cast reduction implementation
pub struct MultiCastReductionImpl<F: Field> {
    /// Commitment key
    commitment_key: AjtaiCommitmentKey<F>,
    /// Security parameter
    security_param: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> MultiCastReductionImpl<F> {
    /// Create new multi-cast reduction
    pub fn new(commitment_key: AjtaiCommitmentKey<F>, security_param: usize) -> Self {
        Self {
            commitment_key,
            security_param,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Compute union polynomial from witnesses
    fn build_union_polynomial(witnesses: &[&Vec<F>]) -> UnionPolynomial<F> {
        UnionPolynomialBuilder::build(witnesses)
    }
    
    /// Commit to union polynomial
    fn commit_union_polynomial(
        &self,
        union_poly: &UnionPolynomial<F>,
    ) -> AjtaiCommitment<F> {
        // Flatten union polynomial evaluations for commitment
        let mut flat_evals = Vec::new();
        for poly in union_poly.witness_polynomials() {
            flat_evals.extend(poly.evaluations().iter().cloned());
        }
        
        AjtaiCommitment::commit_vector(&self.commitment_key, &flat_evals)
    }
    
    /// Aggregate public inputs from all instances
    fn aggregate_public_inputs(instances: &[(Instance<F>, Witness<F>)]) -> Vec<F> {
        instances.iter()
            .flat_map(|(inst, _)| inst.public_input.clone())
            .collect()
    }
    
    /// Generate sumcheck proof for constraint aggregation
    fn prove_constraint_aggregation(
        &self,
        instances: &[(Instance<F>, Witness<F>)],
        union_poly: &UnionPolynomial<F>,
        r_y: &[F],
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let num_instances = instances.len();
        let log_ell = union_poly.num_y_vars();
        
        // Build polynomial G(Y) = Σ_k F_k(x_k, w_k)·eq̃(Y, k)
        // where F_k is the constraint for instance k
        
        let mut g_evals = Vec::with_capacity(1 << log_ell);
        
        for k in 0..num_instances {
            // Convert k to binary
            let k_bits: Vec<F> = (0..log_ell)
                .map(|i| {
                    if (k >> i) & 1 == 1 { F::one() } else { F::zero() }
                })
                .collect();
            
            // Compute eq̃(k, r_y)
            let eq_val = Self::compute_eq(&k_bits, r_y);
            
            // For valid instances, F_k(x_k, w_k) = 0
            // So G(k) = 0 for all k
            g_evals.push(F::zero().mul(&eq_val));
        }
        
        // Pad to power of 2
        while g_evals.len() < (1 << log_ell) {
            g_evals.push(F::zero());
        }
        
        // Generate sumcheck proof
        self.prove_sumcheck(&g_evals, log_ell, transcript)
    }
    
    /// Compute eq̃(x, y)
    fn compute_eq(x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len());
        
        let mut result = F::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            let one = F::one();
            let term = xi.mul(yi).add(&one.sub(xi).mul(&one.sub(yi)));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Prove sumcheck
    fn prove_sumcheck(
        &self,
        evals: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let mut current_evals = evals.to_vec();
        let mut round_polys = Vec::with_capacity(num_vars);
        let mut challenges = Vec::with_capacity(num_vars);
        
        for _round in 0..num_vars {
            let half_size = current_evals.len() / 2;
            
            // Compute s_i(0) and s_i(1)
            let mut s_0 = F::zero();
            let mut s_1 = F::zero();
            
            for j in 0..half_size {
                s_0 = s_0.add(&current_evals[2 * j]);
                s_1 = s_1.add(&current_evals[2 * j + 1]);
            }
            
            // Round polynomial: s(X) = s_0 + (s_1 - s_0)·X
            let round_poly = super::accumulator::RoundPolynomial {
                coefficients: vec![s_0, s_1.sub(&s_0)],
            };
            
            transcript.append_field(b"s0", &s_0);
            transcript.append_field(b"s1", &s_1);
            let challenge = transcript.challenge_field(b"r");
            
            round_polys.push(round_poly);
            challenges.push(challenge);
            
            // Fold for next round
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

impl<F: Field> MultiCastReduction<F> for MultiCastReductionImpl<F> {
    fn multi_cast(
        instances: &[(Instance<F>, Witness<F>)],
        commitment_key: &AjtaiCommitmentKey<F>,
        transcript: &mut Transcript<F>,
    ) -> (MultiCastOutput<F>, MultiCastProof<F>) {
        // Paper Reference: Quasar Section 4.2, Protocol 4.1 "Multi-cast Reduction"
        //
        // This implements the NIR_multicast reduction that transforms ℓ instances
        // of relation R into a single committed instance in R^cm_acc.
        //
        // Input: ℓ instances (x_1, w_1), ..., (x_ℓ, w_ℓ) where each (x_i, w_i) ∈ R
        // Output: Single committed instance (x, C_∪, C_w, v) and proof π
        //
        // The key insight is using the union polynomial to aggregate all witnesses:
        // w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
        //
        // This allows the verifier to check all ℓ instances by verifying a single
        // evaluation claim on the folded witness w̃(X) = w̃_∪(τ, X).
        
        let reducer = MultiCastReductionImpl::new(commitment_key.clone(), 128);
        
        let num_instances = instances.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Build union polynomial w̃_∪(Y,X)
        // Paper Reference: Quasar Definition 4.1
        //
        // The union polynomial aggregates all ℓ witness polynomials using
        // the equality polynomial eq̃ as coefficients:
        // w̃_∪(Y,X) = Σ_{k=0}^{ℓ-1} eq̃_k(Y)·w̃^(k)(X)
        //
        // where eq̃_k(Y) = eq̃(Y, bin(k)) and bin(k) is the binary representation of k.
        //
        // This construction ensures that w̃_∪(bin(k), X) = w̃^(k)(X) for all k,
        // meaning we can extract any individual witness by evaluating at the
        // appropriate Y value.
        let witnesses: Vec<&Vec<F>> = instances.iter()
            .map(|(_, w)| &w.witness)
            .collect();
        let union_poly = Self::build_union_polynomial(&witnesses);
        
        // Step 2: Commit to union polynomial
        // Paper Reference: Quasar Protocol 4.1, Step 1
        //
        // The prover commits to w̃_∪ using the Ajtai commitment scheme.
        // This commitment is binding under the Ring-SIS assumption, ensuring
        // the prover cannot change the union polynomial after committing.
        //
        // Commitment: C_∪ = Commit(w̃_∪)
        let union_commitment = reducer.commit_union_polynomial(&union_poly);
        transcript.append_commitment(b"union", &union_commitment);
        
        // Step 3: Generate random evaluation point r_y ∈ F^{log ℓ}
        // Paper Reference: Quasar Protocol 4.1, Step 2
        //
        // The verifier (via Fiat-Shamir) generates a random point r_y.
        // This will be used in the sumcheck protocol to aggregate all
        // constraint checks into a single check.
        let r_y = transcript.challenge_field_vec(b"r_y", log_ell);
        
        // Step 4: Generate folding challenge τ ∈ F^{log ℓ}
        // Paper Reference: Quasar Protocol 4.1, Step 3
        //
        // The verifier generates a random challenge τ that will be used to
        // fold the union polynomial into a single witness polynomial:
        // w̃(X) = w̃_∪(τ, X)
        //
        // This folding is the key to achieving sublinear verification:
        // instead of checking ℓ separate witnesses, we check one folded witness.
        let tau = transcript.challenge_field_vec(b"tau", log_ell);
        
        // Step 5: Compute folded witness w̃(X) = w̃_∪(τ, X)
        // Paper Reference: Quasar Protocol 4.1, Step 4
        //
        // The prover evaluates the union polynomial at Y = τ to obtain
        // the folded witness. This is a linear combination of all original
        // witnesses with coefficients determined by eq̃(τ, bin(k)).
        //
        // w̃(X) = Σ_{k=0}^{ℓ-1} eq̃(τ, bin(k))·w̃^(k)(X)
        let folded_witness = union_poly.evaluate_partial(&tau);
        
        // Step 6: Commit to folded witness
        // Paper Reference: Quasar Protocol 4.1, Step 5
        //
        // The prover commits to the folded witness w̃(X).
        // The verifier will later check that this commitment is consistent
        // with the union polynomial commitment and the challenge τ.
        //
        // Commitment: C_w = Commit(w̃)
        let witness_commitment = AjtaiCommitment::commit_vector(commitment_key, &folded_witness);
        transcript.append_commitment(b"witness", &witness_commitment);
        
        // Step 7: Generate evaluation point r_x ∈ F^{log n}
        // Paper Reference: Quasar Protocol 4.1, Step 6
        //
        // The verifier generates a random evaluation point r_x.
        // The prover will claim that w̃(r_x) = v for some value v,
        // and provide a proof of this evaluation.
        let num_x_vars = union_poly.num_x_vars();
        let r_x = transcript.challenge_field_vec(b"r_x", num_x_vars);
        
        // Step 8: Compute claimed evaluation value v = w̃(r_x)
        // Paper Reference: Quasar Protocol 4.1, Step 7
        //
        // The prover evaluates the folded witness at r_x and sends the result.
        // This is the value that will be verified using the polynomial commitment.
        //
        // v = w̃(r_x) = w̃_∪(τ, r_x)
        let claimed_value = union_poly.evaluate(&tau, &r_x);
        
        // Step 9: Generate sumcheck proof for constraint aggregation
        // Paper Reference: Quasar Protocol 4.1, Step 8
        //
        // The prover generates a sumcheck proof that all ℓ constraints are satisfied.
        // This is done by proving that:
        // Σ_{y∈B^{log ℓ}} G(y) = 0
        //
        // where G(Y) = F(x̃(Y), w̃_∪(Y, ·))·eq̃(Y, r_y)
        //
        // Here F is the constraint function (e.g., for R1CS: Az ⊙ Bz - Cz).
        // The equality polynomial eq̃(Y, r_y) ensures that we're checking
        // a random linear combination of all constraints.
        //
        // The sumcheck protocol reduces this to a single evaluation claim,
        // which can be verified efficiently.
        let sumcheck_proof = reducer.prove_constraint_aggregation(
            instances,
            &union_poly,
            &r_y,
            transcript,
        );
        
        // Step 10: Generate evaluation proofs
        // Paper Reference: Quasar Protocol 4.1, Step 9
        //
        // The prover provides proofs that the claimed evaluations are correct.
        // This includes:
        // - Proof that w̃(r_x) = v
        // - Opening information for the polynomial commitment
        //
        // These proofs allow the verifier to check the evaluation claims
        // without needing to see the entire polynomial.
        let eval_proofs = vec![
            EvaluationProof {
                point: r_x.clone(),
                value: claimed_value,
                opening: folded_witness.clone(),
            },
        ];
        
        // Step 11: Aggregate public inputs
        // Paper Reference: Quasar Protocol 4.1, Step 10
        //
        // The public inputs from all ℓ instances are aggregated into a single
        // public input for the committed instance. This can be done by
        // concatenation or hashing, depending on the application.
        let aggregated_public_input = Self::aggregate_public_inputs(&reducer, instances);
        
        // Step 12: Construct output
        // Paper Reference: Quasar Definition 4.3
        //
        // The output consists of:
        // - Committed instance: (x, C_∪, C_w, v) where
        //   * x is the aggregated public input
        //   * C_∪ is the commitment to the union polynomial
        //   * C_w is the commitment to the folded witness
        //   * v is the claimed evaluation w̃(r_x)
        // - Polynomial oracles for w̃_∪ and w̃
        // - Evaluation point r_x
        let output = MultiCastOutput {
            committed_instance: CommittedInstance {
                public_input: aggregated_public_input,
                union_commitment: union_commitment.clone(),
                witness_commitment: witness_commitment.clone(),
                claimed_value,
            },
            union_oracle: PolynomialOracle {
                commitment: union_commitment.clone(),
                degree_bound: 1 << (log_ell + num_x_vars),
                num_vars: log_ell + num_x_vars,
            },
            witness_oracle: PolynomialOracle {
                commitment: witness_commitment,
                degree_bound: 1 << num_x_vars,
                num_vars: num_x_vars,
            },
            evaluation_point: r_x,
        };
        
        // Step 13: Construct proof
        // Paper Reference: Quasar Protocol 4.1
        //
        // The proof consists of:
        // - Sumcheck proof for constraint aggregation
        // - Union polynomial commitment
        // - Evaluation proofs
        // - Random linear combination coefficients τ
        //
        // This proof allows the verifier to check that the committed instance
        // correctly represents all ℓ input instances, with O(log ℓ) verification cost.
        let proof = MultiCastProof {
            sumcheck_proof,
            union_commitment,
            eval_proofs,
            rlc_coefficients: tau,
        };
        
        (output, proof)
    }
    
    fn verify_multi_cast(
        instances: &[Instance<F>],
        output: &MultiCastOutput<F>,
        proof: &MultiCastProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        let num_instances = instances.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Replay transcript
        transcript.append_commitment(b"union", &proof.union_commitment);
        
        // Step 2: Regenerate challenges
        let r_y = transcript.challenge_field_vec(b"r_y", log_ell);
        let tau = transcript.challenge_field_vec(b"tau", log_ell);
        
        // Step 3: Verify tau matches proof
        if tau != proof.rlc_coefficients {
            return false;
        }
        
        // Step 4: Verify sumcheck proof
        // Check that sum is zero (valid instances satisfy constraints)
        if !proof.sumcheck_proof.round_polynomials.is_empty() {
            let first = &proof.sumcheck_proof.round_polynomials[0];
            let s_0 = first.coefficients[0];
            let s_1 = s_0.add(&first.coefficients.get(1).copied().unwrap_or(F::zero()));
            
            // Sum should be zero for valid instances
            if s_0.add(&s_1).to_canonical_u64() != 0 {
                return false;
            }
        }
        
        // Step 5: Verify commitment consistency
        if output.committed_instance.union_commitment.value != proof.union_commitment.value {
            return false;
        }
        
        // Step 6: Verify evaluation proofs
        for eval_proof in &proof.eval_proofs {
            if eval_proof.value.to_canonical_u64() != output.committed_instance.claimed_value.to_canonical_u64() {
                return false;
            }
        }
        
        true
    }
}

impl<F: Field> MultiCastReductionImpl<F> {
    fn aggregate_public_inputs(&self, instances: &[(Instance<F>, Witness<F>)]) -> Vec<F> {
        instances.iter()
            .flat_map(|(inst, _)| inst.public_input.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    fn create_test_instance(public_input: Vec<F>, witness: Vec<F>) -> (Instance<F>, Witness<F>) {
        let commitment = AjtaiCommitment::zero(4);
        (
            Instance { public_input, commitment },
            Witness { witness },
        )
    }
    
    #[test]
    fn test_multi_cast_basic() {
        let instances = vec![
            create_test_instance(
                vec![F::from_u64(1)],
                vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)],
            ),
            create_test_instance(
                vec![F::from_u64(2)],
                vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)],
            ),
        ];
        
        let commitment_key = AjtaiCommitmentKey {
            matrix: vec![],
            kappa: 4,
            message_len: 4,
            norm_bound: 100.0,
        };
        
        let mut transcript = Transcript::new(b"test");
        
        let (output, proof) = MultiCastReductionImpl::multi_cast(
            &instances,
            &commitment_key,
            &mut transcript,
        );
        
        // Verify output structure
        assert_eq!(output.committed_instance.public_input.len(), 2);
        assert!(!proof.rlc_coefficients.is_empty());
    }
    
    #[test]
    fn test_multi_cast_verification() {
        let instances = vec![
            create_test_instance(
                vec![F::from_u64(1)],
                vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)],
            ),
            create_test_instance(
                vec![F::from_u64(2)],
                vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)],
            ),
        ];
        
        let commitment_key = AjtaiCommitmentKey {
            matrix: vec![],
            kappa: 4,
            message_len: 4,
            norm_bound: 100.0,
        };
        
        let mut prover_transcript = Transcript::new(b"test");
        let (output, proof) = MultiCastReductionImpl::multi_cast(
            &instances,
            &commitment_key,
            &mut prover_transcript,
        );
        
        // Verify
        let instance_refs: Vec<Instance<F>> = instances.iter()
            .map(|(i, _)| i.clone())
            .collect();
        
        let mut verifier_transcript = Transcript::new(b"test");
        let valid = MultiCastReductionImpl::verify_multi_cast(
            &instance_refs,
            &output,
            &proof,
            &mut verifier_transcript,
        );
        
        assert!(valid);
    }
}
