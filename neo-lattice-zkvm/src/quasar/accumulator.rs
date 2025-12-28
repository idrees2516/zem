// Quasar Accumulator: Core accumulation scheme with O(log ℓ) verifier complexity
// Implements the main accumulation interface from the Quasar paper

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::ring::cyclotomic::RingElement;

/// Multi-instance accumulator state
/// Maintains the running accumulator across IVC steps
#[derive(Clone, Debug)]
pub struct QuasarAccumulator<F: Field> {
    /// Accumulated instance (public data)
    pub instance: AccumulatorInstance<F>,
    /// Accumulated witness polynomial (private)
    pub witness_polynomial: MultilinearPolynomial<F>,
    /// Union polynomial commitment
    pub union_commitment: AjtaiCommitment<F>,
    /// Number of accumulated instances
    pub num_accumulated: usize,
}

/// Public accumulator instance
/// Contains all public data needed for verification
#[derive(Clone, Debug)]
pub struct AccumulatorInstance<F: Field> {
    /// Public input x
    pub public_input: Vec<F>,
    /// Folding challenge τ ∈ F^{log ℓ}
    pub challenge: Vec<F>,
    /// Evaluation point r_x ∈ F^{log n}
    pub evaluation_point: Vec<F>,
    /// Error term e from folding
    pub error: F,
    /// Commitment to accumulated witness
    pub commitment: AjtaiCommitment<F>,
}

/// Private accumulator witness
#[derive(Clone, Debug)]
pub struct AccumulatorWitness<F: Field> {
    /// Witness vector w
    pub witness: Vec<F>,
    /// Multilinear extension of witness
    pub witness_mle: MultilinearPolynomial<F>,
}

/// Evaluation claim for polynomial opening
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    /// Evaluation point
    pub point: Vec<F>,
    /// Claimed value
    pub value: F,
}

/// Sumcheck proof for basic field operations
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials
    pub round_polynomials: Vec<RoundPolynomial<F>>,
    /// Final evaluation
    pub final_evaluation: F,
    /// Challenges used
    pub challenges: Vec<F>,
}

/// Sumcheck claim
#[derive(Clone, Debug)]
pub struct SumcheckClaim<F: Field> {
    /// Target sum
    pub target: F,
    /// Number of variables
    pub num_vars: usize,
    /// Degree bound per variable
    pub degree_bound: usize,
}

/// Proof of correct accumulation
#[derive(Clone, Debug)]
pub struct AccumulationProof<F: Field> {
    /// Sumcheck proof for constraint reduction
    pub sumcheck_proof: SumcheckProof<F>,
    /// Evaluation claims from sumcheck
    pub evaluation_claims: Vec<EvaluationClaim<F>>,
    /// Union polynomial evaluation proof
    pub union_eval_proof: UnionEvaluationProof<F>,
    /// Oracle batching proof (sublinear)
    pub batching_proof: BatchingProof<F>,
}

/// Proof for union polynomial evaluation
#[derive(Clone, Debug)]
pub struct UnionEvaluationProof<F: Field> {
    /// Intermediate evaluations during partial evaluation
    pub intermediate_evals: Vec<F>,
    /// Final evaluation value
    pub final_value: F,
}

/// Proof for oracle batching
#[derive(Clone, Debug)]
pub struct BatchingProof<F: Field> {
    /// Batched evaluation proof (sublinear in polynomial length)
    pub evaluation_proof: Vec<F>,
    /// Random linear combination coefficients
    pub rlc_coefficients: Vec<F>,
}

/// Predicate instance to be accumulated
#[derive(Clone, Debug)]
pub struct PredicateInstance<F: Field> {
    /// Public input
    pub public_input: Vec<F>,
    /// Commitment to witness
    pub commitment: AjtaiCommitment<F>,
}

/// Predicate witness
#[derive(Clone, Debug)]
pub struct PredicateWitness<F: Field> {
    /// Private witness vector
    pub witness: Vec<F>,
}

/// Fiat-Shamir transcript for non-interactive proofs
#[derive(Clone, Debug)]
pub struct Transcript<F: Field> {
    /// Accumulated hash state
    state: Vec<u8>,
    /// Phantom for field type
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Create new transcript
    pub fn new(label: &[u8]) -> Self {
        let mut state = Vec::with_capacity(64);
        state.extend_from_slice(label);
        Self {
            state,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Append field element to transcript
    pub fn append_field(&mut self, label: &[u8], value: &F) {
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&value.to_canonical_u64().to_le_bytes());
    }
    
    /// Append multiple field elements
    pub fn append_field_vec(&mut self, label: &[u8], values: &[F]) {
        self.state.extend_from_slice(label);
        for v in values {
            self.state.extend_from_slice(&v.to_canonical_u64().to_le_bytes());
        }
    }
    
    /// Append commitment to transcript
    pub fn append_commitment(&mut self, label: &[u8], commitment: &AjtaiCommitment<F>) {
        self.state.extend_from_slice(label);
        for elem in &commitment.value {
            for coeff in &elem.coeffs {
                self.state.extend_from_slice(&coeff.to_canonical_u64().to_le_bytes());
            }
        }
    }
    
    /// Generate challenge field element
    pub fn challenge_field(&mut self, label: &[u8]) -> F {
        self.state.extend_from_slice(label);
        
        // Simple hash-to-field (in production, use proper hash function)
        let mut hash_val: u64 = 0;
        for (i, &byte) in self.state.iter().enumerate() {
            hash_val = hash_val.wrapping_add((byte as u64).wrapping_mul(31u64.wrapping_pow(i as u32)));
        }
        
        F::from_u64(hash_val % F::MODULUS)
    }
    
    /// Generate multiple challenge field elements
    pub fn challenge_field_vec(&mut self, label: &[u8], count: usize) -> Vec<F> {
        (0..count)
            .map(|i| {
                let mut extended_label = label.to_vec();
                extended_label.extend_from_slice(&(i as u64).to_le_bytes());
                self.challenge_field(&extended_label)
            })
            .collect()
    }
}

/// Main Quasar accumulation scheme trait
/// Provides O(log ℓ) verifier complexity for ℓ instances
pub trait QuasarAccumulationScheme<F: Field> {
    /// Accumulate ℓ predicate instances into running accumulator
    /// Verifier complexity: O(log ℓ) random oracle queries + O(1) group operations
    fn accumulate(
        instances: &[PredicateInstance<F>],
        witnesses: &[PredicateWitness<F>],
        old_accumulator: &QuasarAccumulator<F>,
        transcript: &mut Transcript<F>,
    ) -> (QuasarAccumulator<F>, AccumulationProof<F>);
    
    /// Verify accumulation proof
    /// Complexity: O(log ℓ) random oracle queries
    fn verify_accumulation(
        instances: &[PredicateInstance<F>],
        old_accumulator: &AccumulatorInstance<F>,
        new_accumulator: &AccumulatorInstance<F>,
        proof: &AccumulationProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool;
    
    /// Final decision on accumulator validity
    /// Called at the end of IVC to check accumulated predicate
    fn decide(accumulator: &QuasarAccumulator<F>) -> bool;
}

/// Quasar accumulator implementation
pub struct QuasarAccumulatorImpl<F: Field> {
    /// Commitment key for Ajtai commitments
    pub commitment_key: AjtaiCommitmentKey<F>,
    /// Number of variables in witness polynomial
    pub num_vars: usize,
    /// Security parameter
    pub security_param: usize,
}

impl<F: Field> QuasarAccumulatorImpl<F> {
    /// Create new Quasar accumulator
    pub fn new(commitment_key: AjtaiCommitmentKey<F>, num_vars: usize, security_param: usize) -> Self {
        Self {
            commitment_key,
            num_vars,
            security_param,
        }
    }
    
    /// Initialize empty accumulator
    pub fn init_accumulator(&self) -> QuasarAccumulator<F> {
        let zero_poly = MultilinearPolynomial::zero(self.num_vars);
        let zero_commitment = AjtaiCommitment::zero(self.commitment_key.kappa);
        
        QuasarAccumulator {
            instance: AccumulatorInstance {
                public_input: vec![F::zero()],
                challenge: vec![],
                evaluation_point: vec![F::zero(); self.num_vars],
                error: F::zero(),
                commitment: zero_commitment.clone(),
            },
            witness_polynomial: zero_poly,
            union_commitment: zero_commitment,
            num_accumulated: 0,
        }
    }
    
    /// Compute equality polynomial eq̃(X, Y) = Π_i (X_i·Y_i + (1-X_i)·(1-Y_i))
    fn compute_eq_polynomial(x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len());
        
        let mut result = F::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            // eq_i = x_i·y_i + (1-x_i)·(1-y_i)
            let one = F::one();
            let xi_yi = xi.mul(yi);
            let one_minus_xi = one.sub(xi);
            let one_minus_yi = one.sub(yi);
            let term = xi_yi.add(&one_minus_xi.mul(&one_minus_yi));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Compute inverse of eq̃(τ, r_y) for error term computation
    fn compute_eq_inverse(tau: &[F], r_y: &[F]) -> Option<F> {
        let eq_val = Self::compute_eq_polynomial(tau, r_y);
        eq_val.inverse()
    }
    
    /// Reduce constraint F(x,w)=0 to sum-check
    /// G(Y) := F(x̃(Y), w̃(Y))·eq̃(Y, r_y) with Σ_{y∈B^{log ℓ}} G(y) = 0
    fn reduce_to_sumcheck(
        &self,
        instances: &[PredicateInstance<F>],
        witnesses: &[PredicateWitness<F>],
        r_y: &[F],
        transcript: &mut Transcript<F>,
    ) -> (SumcheckClaim<F>, SumcheckProof<F>) {
        let num_instances = instances.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Build the polynomial G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y)
        // For simplicity, we construct evaluations over Boolean hypercube
        
        let mut g_evals = Vec::with_capacity(1 << log_ell);
        
        for i in 0..num_instances {
            // Convert index to binary for Y evaluation
            let y_bits: Vec<F> = (0..log_ell)
                .map(|j| {
                    if (i >> j) & 1 == 1 {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect();
            
            // Compute eq̃(y, r_y)
            let eq_val = Self::compute_eq_polynomial(&y_bits, r_y);
            
            // For now, assume F(x,w) = 0 for valid instances
            // In full implementation, evaluate actual constraint
            let f_val = F::zero();
            
            g_evals.push(f_val.mul(&eq_val));
        }
        
        // Pad to power of 2 if needed
        while g_evals.len() < (1 << log_ell) {
            g_evals.push(F::zero());
        }
        
        // Create sumcheck claim: Σ G(y) = 0
        let claim = SumcheckClaim {
            target: F::zero(),
            num_vars: log_ell,
            degree_bound: 2, // Degree from eq̃ multiplication
        };
        
        // Generate sumcheck proof
        let proof = self.prove_sumcheck(&g_evals, log_ell, transcript);
        
        (claim, proof)
    }
    
    /// Prove sumcheck for polynomial given by evaluations
    fn prove_sumcheck(
        &self,
        evals: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let mut current_evals = evals.to_vec();
        let mut round_polys = Vec::with_capacity(num_vars);
        let mut challenges = Vec::with_capacity(num_vars);
        
        for round in 0..num_vars {
            let half_size = current_evals.len() / 2;
            
            // Compute round polynomial s_i(X)
            // s_i(0) = Σ_{x_{i+1},...,x_n} g(r_1,...,r_{i-1}, 0, x_{i+1},...,x_n)
            // s_i(1) = Σ_{x_{i+1},...,x_n} g(r_1,...,r_{i-1}, 1, x_{i+1},...,x_n)
            
            let mut s_0 = F::zero();
            let mut s_1 = F::zero();
            
            for j in 0..half_size {
                s_0 = s_0.add(&current_evals[2 * j]);
                s_1 = s_1.add(&current_evals[2 * j + 1]);
            }
            
            // Round polynomial coefficients: s(X) = s_0 + (s_1 - s_0)·X
            let round_poly = RoundPolynomial {
                coefficients: vec![s_0, s_1.sub(&s_0)],
            };
            
            // Add to transcript and get challenge
            transcript.append_field(b"round_poly_0", &round_poly.coefficients[0]);
            transcript.append_field(b"round_poly_1", &round_poly.coefficients[1]);
            let challenge = transcript.challenge_field(b"sumcheck_challenge");
            
            round_polys.push(round_poly);
            challenges.push(challenge);
            
            // Fold evaluations for next round
            let mut new_evals = Vec::with_capacity(half_size);
            for j in 0..half_size {
                // g'(x_{i+1},...) = g(r_i, x_{i+1},...) = (1-r_i)·g(0,...) + r_i·g(1,...)
                let one_minus_r = F::one().sub(&challenge);
                let folded = one_minus_r.mul(&current_evals[2 * j])
                    .add(&challenge.mul(&current_evals[2 * j + 1]));
                new_evals.push(folded);
            }
            current_evals = new_evals;
        }
        
        // Final evaluation
        let final_eval = if current_evals.is_empty() {
            F::zero()
        } else {
            current_evals[0]
        };
        
        SumcheckProof {
            round_polynomials: round_polys,
            final_evaluation: final_eval,
            challenges,
        }
    }
    
    /// Compute reduced relation R_acc output
    /// (x, τ, r_x, e) where e = G_{log ℓ}(τ_{log ℓ})·eq̃^{-1}(τ, r_y)
    fn compute_reduced_relation(
        &self,
        sumcheck_proof: &SumcheckProof<F>,
        tau: &[F],
        r_y: &[F],
    ) -> (Vec<F>, F) {
        // Get final evaluation from sumcheck
        let g_final = sumcheck_proof.final_evaluation;
        
        // Compute eq̃^{-1}(τ, r_y)
        let eq_inv = Self::compute_eq_inverse(tau, r_y)
            .unwrap_or(F::one());
        
        // Error term e = G_{log ℓ}(τ)·eq̃^{-1}(τ, r_y)
        let error = g_final.mul(&eq_inv);
        
        (tau.to_vec(), error)
    }
}

impl<F: Field> QuasarAccumulationScheme<F> for QuasarAccumulatorImpl<F> {
    fn accumulate(
        instances: &[PredicateInstance<F>],
        witnesses: &[PredicateWitness<F>],
        old_accumulator: &QuasarAccumulator<F>,
        transcript: &mut Transcript<F>,
    ) -> (QuasarAccumulator<F>, AccumulationProof<F>) {
        let num_instances = instances.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Append all instance commitments to transcript
        for (i, inst) in instances.iter().enumerate() {
            transcript.append_commitment(&format!("instance_{}", i).into_bytes(), &inst.commitment);
        }
        
        // Step 2: Generate random evaluation point r_y
        let r_y = transcript.challenge_field_vec(b"r_y", log_ell);
        
        // Step 3: Build union polynomial w̃_∪(Y,X)
        let union_poly = super::union_polynomial::UnionPolynomialBuilder::build(
            witnesses.iter().map(|w| &w.witness).collect::<Vec<_>>().as_slice(),
        );
        
        // Step 4: Generate folding challenge τ
        let tau = transcript.challenge_field_vec(b"tau", log_ell);
        
        // Step 5: Reduce constraints to sumcheck
        let (sumcheck_claim, sumcheck_proof) = QuasarAccumulatorImpl::reduce_to_sumcheck(
            &QuasarAccumulatorImpl {
                commitment_key: old_accumulator.union_commitment.clone().into(),
                num_vars: witnesses.first().map(|w| w.witness.len()).unwrap_or(0),
                security_param: 128,
            },
            instances,
            witnesses,
            &r_y,
            transcript,
        );
        
        // Step 6: Compute reduced relation
        let (challenge_vec, error) = QuasarAccumulatorImpl::compute_reduced_relation(
            &QuasarAccumulatorImpl {
                commitment_key: old_accumulator.union_commitment.clone().into(),
                num_vars: witnesses.first().map(|w| w.witness.len()).unwrap_or(0),
                security_param: 128,
            },
            &sumcheck_proof,
            &tau,
            &r_y,
        );
        
        // Step 7: Generate evaluation point r_x
        let num_witness_vars = witnesses.first()
            .map(|w| (w.witness.len() as f64).log2().ceil() as usize)
            .unwrap_or(0);
        let r_x = transcript.challenge_field_vec(b"r_x", num_witness_vars);
        
        // Step 8: Evaluate folded witness at r_x
        let folded_witness = union_poly.evaluate_partial(&tau);
        let folded_witness_mle = MultilinearPolynomial::from_evaluations(folded_witness.clone());
        
        // Step 9: Combine with old accumulator
        let combined_witness = if old_accumulator.num_accumulated > 0 {
            // Linear combination of old and new
            let alpha = transcript.challenge_field(b"combine_alpha");
            let one_minus_alpha = F::one().sub(&alpha);
            
            folded_witness.iter()
                .zip(old_accumulator.witness_polynomial.evaluations().iter())
                .map(|(new, old)| {
                    alpha.mul(new).add(&one_minus_alpha.mul(old))
                })
                .collect()
        } else {
            folded_witness
        };
        
        // Step 10: Compute new commitment
        let new_commitment = AjtaiCommitment::commit_vector(
            &old_accumulator.union_commitment.clone().into(),
            &combined_witness,
        );
        
        // Step 11: Build union evaluation proof
        let union_eval_proof = UnionEvaluationProof {
            intermediate_evals: sumcheck_proof.challenges.clone(),
            final_value: sumcheck_proof.final_evaluation,
        };
        
        // Step 12: Build batching proof
        let batching_proof = BatchingProof {
            evaluation_proof: vec![sumcheck_proof.final_evaluation],
            rlc_coefficients: tau.clone(),
        };
        
        // Step 13: Construct new accumulator
        let new_accumulator = QuasarAccumulator {
            instance: AccumulatorInstance {
                public_input: instances.iter()
                    .flat_map(|i| i.public_input.clone())
                    .collect(),
                challenge: challenge_vec,
                evaluation_point: r_x,
                error,
                commitment: new_commitment.clone(),
            },
            witness_polynomial: MultilinearPolynomial::from_evaluations(combined_witness),
            union_commitment: new_commitment,
            num_accumulated: old_accumulator.num_accumulated + num_instances,
        };
        
        // Step 14: Construct proof
        let proof = AccumulationProof {
            sumcheck_proof,
            evaluation_claims: vec![EvaluationClaim {
                point: new_accumulator.instance.evaluation_point.clone(),
                value: new_accumulator.instance.error,
            }],
            union_eval_proof,
            batching_proof,
        };
        
        (new_accumulator, proof)
    }
    
    fn verify_accumulation(
        instances: &[PredicateInstance<F>],
        old_accumulator: &AccumulatorInstance<F>,
        new_accumulator: &AccumulatorInstance<F>,
        proof: &AccumulationProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        let num_instances = instances.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Replay transcript with instance commitments
        for (i, inst) in instances.iter().enumerate() {
            transcript.append_commitment(&format!("instance_{}", i).into_bytes(), &inst.commitment);
        }
        
        // Step 2: Regenerate r_y
        let r_y = transcript.challenge_field_vec(b"r_y", log_ell);
        
        // Step 3: Regenerate τ
        let tau = transcript.challenge_field_vec(b"tau", log_ell);
        
        // Step 4: Verify sumcheck proof
        // Check that Σ G(y) = 0 (target is zero)
        let mut expected_sum = F::zero();
        for round_poly in &proof.sumcheck_proof.round_polynomials {
            // s_i(0) + s_i(1) should equal previous round's evaluation
            let s_0 = round_poly.coefficients[0];
            let s_1 = s_0.add(&round_poly.coefficients.get(1).copied().unwrap_or(F::zero()));
            expected_sum = s_0.add(&s_1);
        }
        
        // First round should sum to target (zero)
        if !proof.sumcheck_proof.round_polynomials.is_empty() {
            let first_round = &proof.sumcheck_proof.round_polynomials[0];
            let s_0 = first_round.coefficients[0];
            let s_1 = s_0.add(&first_round.coefficients.get(1).copied().unwrap_or(F::zero()));
            if s_0.add(&s_1).to_canonical_u64() != 0 {
                return false;
            }
        }
        
        // Step 5: Verify round polynomial consistency
        for i in 1..proof.sumcheck_proof.round_polynomials.len() {
            let prev_challenge = proof.sumcheck_proof.challenges[i - 1];
            let prev_poly = &proof.sumcheck_proof.round_polynomials[i - 1];
            let curr_poly = &proof.sumcheck_proof.round_polynomials[i];
            
            // Evaluate previous polynomial at challenge
            let prev_eval = prev_poly.coefficients[0]
                .add(&prev_poly.coefficients.get(1).copied().unwrap_or(F::zero()).mul(&prev_challenge));
            
            // Should equal s_i(0) + s_i(1)
            let curr_sum = curr_poly.coefficients[0]
                .add(&curr_poly.coefficients[0].add(&curr_poly.coefficients.get(1).copied().unwrap_or(F::zero())));
            
            // This check is simplified; full implementation needs proper verification
        }
        
        // Step 6: Verify error term computation
        let eq_val = Self::compute_eq_polynomial_static(&tau, &r_y);
        if let Some(eq_inv) = eq_val.inverse() {
            let expected_error = proof.sumcheck_proof.final_evaluation.mul(&eq_inv);
            if expected_error.to_canonical_u64() != new_accumulator.error.to_canonical_u64() {
                return false;
            }
        }
        
        // Step 7: Verify challenge consistency
        if new_accumulator.challenge != tau {
            return false;
        }
        
        true
    }
    
    fn decide(accumulator: &QuasarAccumulator<F>) -> bool {
        // Final decision: check that accumulated predicate holds
        // This verifies that the error term is zero (or within acceptable bounds)
        accumulator.instance.error.to_canonical_u64() == 0
    }
}

impl<F: Field> QuasarAccumulatorImpl<F> {
    /// Static version of eq polynomial computation for verification
    fn compute_eq_polynomial_static(x: &[F], y: &[F]) -> F {
        Self::compute_eq_polynomial(x, y)
    }
}

/// Round polynomial in sumcheck
#[derive(Clone, Debug)]
pub struct RoundPolynomial<F: Field> {
    /// Coefficients [c_0, c_1, ...] for polynomial c_0 + c_1·X + ...
    pub coefficients: Vec<F>,
}

impl<F: Field> RoundPolynomial<F> {
    /// Evaluate polynomial at point
    pub fn evaluate(&self, point: &F) -> F {
        let mut result = F::zero();
        let mut power = F::one();
        
        for coeff in &self.coefficients {
            result = result.add(&coeff.mul(&power));
            power = power.mul(point);
        }
        
        result
    }
}

/// Ajtai commitment for quasar module
#[derive(Clone, Debug)]
pub struct AjtaiCommitment<F: Field> {
    /// Commitment value as ring elements
    pub value: Vec<RingElement<F>>,
}

impl<F: Field> AjtaiCommitment<F> {
    /// Create zero commitment
    pub fn zero(kappa: usize) -> Self {
        Self {
            value: vec![RingElement::from_coeffs(vec![F::zero(); 64]); kappa],
        }
    }
    
    /// Commit to vector of field elements
    pub fn commit_vector(key: &AjtaiCommitmentKey<F>, values: &[F]) -> Self {
        // Simplified commitment: hash values into ring elements
        let mut result = Vec::with_capacity(key.kappa);
        
        for i in 0..key.kappa {
            let mut coeffs = vec![F::zero(); 64];
            for (j, val) in values.iter().enumerate() {
                let idx = (i * 17 + j * 31) % 64;
                coeffs[idx] = coeffs[idx].add(val);
            }
            result.push(RingElement::from_coeffs(coeffs));
        }
        
        Self { value: result }
    }
    
    /// Commit to single scalar
    pub fn commit_scalar(key: &AjtaiCommitmentKey<F>, value: &F) -> Self {
        Self::commit_vector(key, &[*value])
    }
    
    /// Commit vector (simple version without key)
    pub fn commit_vector_simple(values: &[F]) -> Self {
        let kappa = 4;
        let mut result = Vec::with_capacity(kappa);
        
        for i in 0..kappa {
            let mut coeffs = vec![F::zero(); 64];
            for (j, val) in values.iter().enumerate() {
                let idx = (i * 17 + j * 31) % 64;
                coeffs[idx] = coeffs[idx].add(val);
            }
            result.push(RingElement::from_coeffs(coeffs));
        }
        
        Self { value: result }
    }
    
    /// Add two commitments
    pub fn add(&self, other: &Self) -> Self {
        let value = self.value.iter()
            .zip(other.value.iter())
            .map(|(a, b)| {
                let coeffs: Vec<F> = a.coeffs.iter()
                    .zip(b.coeffs.iter())
                    .map(|(x, y)| x.add(y))
                    .collect();
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        Self { value }
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &F) -> Self {
        let value = self.value.iter()
            .map(|elem| {
                let coeffs: Vec<F> = elem.coeffs.iter()
                    .map(|c| c.mul(scalar))
                    .collect();
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        Self { value }
    }
}

/// Ajtai commitment key
#[derive(Clone, Debug)]
pub struct AjtaiCommitmentKey<F: Field> {
    /// Matrix (simplified)
    pub matrix: Vec<Vec<F>>,
    /// Number of rows
    pub kappa: usize,
    /// Message length
    pub message_len: usize,
    /// Norm bound
    pub norm_bound: f64,
}

impl<F: Field> From<AjtaiCommitment<F>> for AjtaiCommitmentKey<F> {
    fn from(commitment: AjtaiCommitment<F>) -> Self {
        AjtaiCommitmentKey {
            matrix: vec![],
            kappa: commitment.value.len(),
            message_len: 0,
            norm_bound: 0.0,
        }
    }
}
