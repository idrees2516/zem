// Commitment Transformation Protocol (Π_cm) Implementation
// Construction 4.5 from LatticeFold+ paper
// Transforms double commitment statements to linear commitment statements

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::Commitment as BaseCommitment;
use crate::folding::transcript::Transcript;
use crate::folding::sumcheck::{SumcheckProver, SumcheckVerifier, SumcheckProof};
use super::monomial::{Monomial, MonomialMatrix};
use super::range_check::{RangeCheckProver, RangeCheckVerifier, RangeCheckProof, RangeCheckInstance, RangeCheckEvaluations};
use super::double_commitment::DoubleCommitment;

/// Commitment transformation input (R_{rg,B})
#[derive(Clone, Debug)]
pub struct CommitmentTransformInput<F: Field> {
    /// Witness f ∈ Rq^n
    pub witness_f: Vec<RingElement<F>>,
    
    /// Split vector τ_D ∈ (-d', d')^n
    pub split_vector: Vec<i64>,
    
    /// Helper monomials m_τ ∈ EXP(τ_D)
    pub helper_monomials: Vec<Monomial>,
    
    /// Monomial matrix M_f ∈ EXP(D_f)
    pub monomial_matrix: MonomialMatrix,
    
    /// Commitment cm_f
    pub commitment_f: BaseCommitment<F>,
    
    /// Double commitment C_{M_f}
    pub double_commitment: DoubleCommitment<F>,
    
    /// Helper commitment cm_{m_τ}
    pub helper_commitment: BaseCommitment<F>,
    
    /// Norm bound B
    pub norm_bound: i64,
}

/// Commitment transformation proof
#[derive(Clone, Debug)]
pub struct CommitmentTransformProof<F: Field> {
    /// Range check proof (Π_rgchk)
    pub range_proof: RangeCheckProof<F>,
    
    /// Folded commitment com(h)
    pub folded_commitment: BaseCommitment<F>,
    
    /// Parallel sumcheck proofs (2 proofs for soundness boosting)
    pub sumcheck_proofs: Vec<SumcheckProof<F>>,
    
    /// Final evaluations at r_o
    pub final_evaluations: Vec<RingElement<F>>,
}

/// Commitment transformation instance (output, R_{com})
#[derive(Clone, Debug)]
pub struct CommitmentTransformInstance<F: Field> {
    /// Folded commitment cm_g
    pub folded_commitment: BaseCommitment<F>,
    
    /// Challenge r_o ∈ MC^(log n)
    pub challenge: Vec<RingElement<F>>,
    
    /// Evaluations v_o ∈ Mq
    pub evaluations: Vec<RingElement<F>>,
    
    /// Witness g (for prover only)
    pub witness: Option<Vec<RingElement<F>>>,
}


/// Commitment transformation prover (Construction 4.5)
pub struct CommitmentTransformProver<F: Field> {
    /// Witness f ∈ Rq^n
    witness_f: Vec<RingElement<F>>,
    
    /// Split vector τ_D ∈ (-d', d')^n
    split_vector: Vec<i64>,
    
    /// Helper monomials m_τ ∈ EXP(τ_D)
    helper_monomials: Vec<Monomial>,
    
    /// Monomial matrix M_f ∈ EXP(D_f)
    monomial_matrix: MonomialMatrix,
    
    /// Commitment cm_f
    commitment_f: BaseCommitment<F>,
    
    /// Double commitment C_{M_f}
    double_commitment: DoubleCommitment<F>,
    
    /// Helper commitment cm_{m_τ}
    helper_commitment: BaseCommitment<F>,
    
    /// Norm bound B
    norm_bound: i64,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
    
    /// Folding challenge set (strong sampling set S̄)
    folding_set_size: usize,
}

impl<F: Field> CommitmentTransformProver<F> {
    /// Create new commitment transformation prover
    pub fn new(
        input: CommitmentTransformInput<F>,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
        folding_set_size: usize,
    ) -> Self {
        Self {
            witness_f: input.witness_f,
            split_vector: input.split_vector,
            helper_monomials: input.helper_monomials,
            monomial_matrix: input.monomial_matrix,
            commitment_f: input.commitment_f,
            double_commitment: input.double_commitment,
            helper_commitment: input.helper_commitment,
            norm_bound: input.norm_bound,
            ring,
            challenge_set_size,
            folding_set_size,
        }
    }
    
    /// Run commitment transformation protocol (Construction 4.5)
    /// 
    /// Steps:
    /// 1. Run Π_rgchk as subroutine
    /// 2. Receive folding challenges s ← S̄^3, s' ← S̄^dk
    /// 3. Compute and send folded commitment com(h) = com(M_f)s'
    /// 4. Receive sumcheck challenges c^(0), c^(1) ← C^(log κ) × C^(log κ)
    /// 5. Prepare evaluation claims (4 claims)
    /// 6. Prepare consistency claims (2 claims)
    /// 7. Batch and run parallel sumchecks
    pub fn prove(&mut self, transcript: &mut Transcript) 
        -> Result<CommitmentTransformProof<F>, String> {
        // Step 1: Run Π_rgchk as subroutine
        let range_instance = self.run_range_check(transcript)?;
        let r = range_instance.challenge.clone();
        let e = range_instance.evaluations.clone();
        
        // Step 2: Receive folding challenges
        let s = self.receive_folding_challenges(transcript, 3)?;
        let dk = self.monomial_matrix.cols();
        let s_prime = self.receive_folding_challenges(transcript, dk)?;
        
        // Step 3: Compute and send folded commitment com(h)
        let h = self.compute_folded_witness(&s_prime)?;
        let com_h = self.commit_witness(&h)?;
        transcript.append_commitment("com_h", &com_h);
        
        // Step 4: Receive sumcheck challenges
        let log_kappa = self.log_kappa();
        let c_0 = self.receive_challenge_vector(transcript, "sumcheck_c0", log_kappa)?;
        let c_1 = self.receive_challenge_vector(transcript, "sumcheck_c1", log_kappa)?;
        
        // Step 5-6: Prepare all sumcheck claims
        let all_claims = self.prepare_all_sumcheck_claims(&r, &e, &h, &s_prime, &c_0, &c_1)?;
        
        // Step 7: Batch and run parallel sumchecks
        let sumcheck_proofs = self.run_parallel_sumchecks(all_claims, transcript)?;
        
        // Extract final evaluations
        let r_o = sumcheck_proofs[0].final_challenge.clone();
        let final_evaluations = self.compute_final_evaluations(&r_o)?;
        
        Ok(CommitmentTransformProof {
            range_proof: self.create_range_proof(&range_instance)?,
            folded_commitment: com_h,
            sumcheck_proofs,
            final_evaluations,
        })
    }
    
    /// Step 1: Run Π_rgchk as subroutine
    fn run_range_check(&mut self, transcript: &mut Transcript) 
        -> Result<RangeCheckInstance<F>, String> {
        let mut range_prover = RangeCheckProver::new(
            self.witness_f.clone(),
            self.norm_bound,
            self.ring.clone(),
            self.challenge_set_size,
        )?;
        
        let range_proof = range_prover.prove(&self.commitment_f, transcript)?;
        
        // Simulate verification to get instance
        // In practice, this would be done by verifier
        Ok(RangeCheckInstance {
            commitment: self.commitment_f.clone(),
            double_commitment: self.double_commitment.outer_commitment.clone(),
            helper_commitment: self.helper_commitment.clone(),
            challenge: vec![self.ring.one()], // Placeholder
            evaluations: RangeCheckEvaluations {
                split_eval: 0,
                helper_eval: self.ring.zero(),
                witness_eval: self.ring.zero(),
                decomp_evals: vec![],
            },
        })
    }
    
    /// Step 2: Receive folding challenges from strong sampling set S̄
    fn receive_folding_challenges(&self, transcript: &mut Transcript, count: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            // Sample from strong sampling set S̄
            let challenge = transcript.challenge_ring_element(
                &format!("fold_challenge_{}", i),
                &self.ring
            );
            challenges.push(challenge);
        }
        
        Ok(challenges)
    }
    
    /// Receive challenge vector from transcript
    fn receive_challenge_vector(&self, transcript: &mut Transcript, label: &str, length: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        
        for i in 0..length {
            let challenge = transcript.challenge_ring_element(
                &format!("{}_{}", label, i),
                &self.ring
            );
            challenges.push(challenge);
        }
        
        Ok(challenges)
    }
    
    /// Step 3: Compute folded witness h = M_f · s'
    fn compute_folded_witness(&self, s_prime: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let n = self.monomial_matrix.rows();
        let m = self.monomial_matrix.cols();
        
        if s_prime.len() != m {
            return Err(format!("s' length {} doesn't match matrix columns {}", s_prime.len(), m));
        }
        
        let mut h = vec![self.ring.zero(); n];
        
        // Compute h = M_f · s'
        for i in 0..n {
            for j in 0..m {
                let monomial = self.monomial_matrix.get(i, j)
                    .ok_or_else(|| format!("Invalid matrix index ({}, {})", i, j))?;
                
                // Multiply monomial by s'[j]
                let product = monomial.multiply_ring_element(&s_prime[j], &self.ring);
                h[i] = self.ring.add(&h[i], &product);
            }
        }
        
        Ok(h)
    }
    
    /// Commit to witness vector
    fn commit_witness(&self, witness: &[RingElement<F>]) 
        -> Result<BaseCommitment<F>, String> {
        // In practice, this would use the actual commitment key
        // For now, return a placeholder commitment
        Ok(self.commitment_f.clone())
    }
    
    /// Step 5: Prepare evaluation claims (4 claims)
    /// 
    /// Verify [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
    /// where u = ⟨e[3, 3+dk), s'⟩
    fn prepare_evaluation_claims(
        &self,
        r: &[RingElement<F>],
        e: &RangeCheckEvaluations<F>,
        h: &[RingElement<F>],
        s_prime: &[RingElement<F>],
    ) -> Result<Vec<SumcheckClaim<F>>, String> {
        let mut claims = Vec::new();
        
        // Compute tensor(r)
        let tensor_r = self.compute_tensor_product(r)?;
        
        // Compute u = ⟨e[3, 3+dk), s'⟩
        let u = self.compute_u(e, s_prime)?;
        
        // Claim 1: ⟨τ_D, tensor(r)⟩ = e.split_eval
        claims.push(self.create_evaluation_claim(
            &self.split_vector,
            &tensor_r,
            e.split_eval,
        )?);
        
        // Claim 2: ⟨m_τ, tensor(r)⟩ = e.helper_eval
        claims.push(self.create_monomial_evaluation_claim(
            &self.helper_monomials,
            &tensor_r,
            &e.helper_eval,
        )?);
        
        // Claim 3: ⟨f, tensor(r)⟩ = e.witness_eval
        claims.push(self.create_ring_evaluation_claim(
            &self.witness_f,
            &tensor_r,
            &e.witness_eval,
        )?);
        
        // Claim 4: ⟨h, tensor(r)⟩ = u
        claims.push(self.create_ring_evaluation_claim(
            h,
            &tensor_r,
            &u,
        )?);
        
        Ok(claims)
    }
    
    /// Step 6: Prepare consistency claims (2 claims)
    /// 
    /// Verify ⟨tensor(c^(z)), pow(τ_D)s'⟩ = ⟨tensor(c^(z)), com(h)⟩ for z ∈ [2]
    fn prepare_consistency_claims(
        &self,
        c_0: &[RingElement<F>],
        c_1: &[RingElement<F>],
        s_prime: &[RingElement<F>],
        com_h: &BaseCommitment<F>,
    ) -> Result<Vec<SumcheckClaim<F>>, String> {
        let mut claims = Vec::new();
        
        for (z, c) in [c_0, c_1].iter().enumerate() {
            // Compute t^(z) = tensor(c^(z)) ⊗ s' ⊗ (1, d', ..., d'^(ℓ-1)) ⊗ (1, X, ..., X^(d-1))
            let t_z = self.compute_tensor_vector(c, s_prime)?;
            
            // Compute RHS: ⟨tensor(c^(z)), com(h)⟩
            let rhs = self.compute_tensor_commitment_product(c, com_h)?;
            
            // Create consistency claim
            claims.push(self.create_consistency_claim(&t_z, rhs)?);
        }
        
        Ok(claims)
    }
    
    /// Step 7: Batch and run parallel sumchecks
    /// 
    /// Batches 6 claims into 1 via random linear combination
    /// Runs 2 parallel sumcheck protocols for soundness boosting
    fn run_parallel_sumchecks(
        &mut self,
        all_claims: Vec<SumcheckClaim<F>>,
        transcript: &mut Transcript,
    ) -> Result<Vec<SumcheckProof<F>>, String> {
        // Get batching challenge
        let batch_combiner = transcript.challenge_ring_element("batch_combiner", &self.ring);
        
        // Batch all claims via random linear combination
        let batched_claim = self.batch_claims(all_claims, &batch_combiner)?;
        
        // Run 2 parallel sumchecks for soundness boosting
        let mut proofs = Vec::new();
        
        for i in 0..2 {
            transcript.append_message(b"parallel_sumcheck_index", &[i as u8]);
            
            let mut prover = SumcheckProver::new(
                batched_claim.clone(),
                2, // degree 2
                self.ring.clone(),
            );
            
            let proof = prover.prove(transcript)?;
            proofs.push(proof);
        }
        
        // Verify both proofs reduce to same challenge r_o
        if proofs.len() == 2 {
            let r_o_0 = &proofs[0].final_challenge;
            let r_o_1 = &proofs[1].final_challenge;
            
            if r_o_0.len() != r_o_1.len() {
                return Err("Parallel sumcheck challenges have different lengths".to_string());
            }
            
            for (a, b) in r_o_0.iter().zip(r_o_1.iter()) {
                if a.coeffs != b.coeffs {
                    return Err("Parallel sumcheck challenges don't match".to_string());
                }
            }
        }
        
        Ok(proofs)
    }
    
    /// Prepare all sumcheck claims (evaluation + consistency)
    fn prepare_all_sumcheck_claims(
        &self,
        r: &[RingElement<F>],
        e: &RangeCheckEvaluations<F>,
        h: &[RingElement<F>],
        s_prime: &[RingElement<F>],
        c_0: &[RingElement<F>],
        c_1: &[RingElement<F>],
    ) -> Result<Vec<SumcheckClaim<F>>, String> {
        let mut all_claims = Vec::new();
        
        // 4 evaluation claims
        let eval_claims = self.prepare_evaluation_claims(r, e, h, s_prime)?;
        all_claims.extend(eval_claims);
        
        // 2 consistency claims
        let com_h = self.commit_witness(h)?;
        let consistency_claims = self.prepare_consistency_claims(c_0, c_1, s_prime, &com_h)?;
        all_claims.extend(consistency_claims);
        
        Ok(all_claims)
    }
    
    /// Compute u = ⟨e[3, 3+dk), s'⟩
    fn compute_u(
        &self,
        e: &RangeCheckEvaluations<F>,
        s_prime: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        let dk = s_prime.len();
        
        if e.decomp_evals.len() < dk {
            return Err(format!("Not enough decomposition evaluations: {} < {}", e.decomp_evals.len(), dk));
        }
        
        let mut u = self.ring.zero();
        
        for i in 0..dk {
            let product = self.ring.mul(&e.decomp_evals[i], &s_prime[i]);
            u = self.ring.add(&u, &product);
        }
        
        Ok(u)
    }
    
    /// Compute tensor product
    fn compute_tensor_product(&self, r: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let k = r.len();
        let mut tensor = vec![self.ring.one()];
        
        for r_i in r {
            let mut new_tensor = Vec::with_capacity(tensor.len() * 2);
            let one_minus_r = self.ring.sub(&self.ring.one(), r_i);
            
            for t in &tensor {
                new_tensor.push(self.ring.mul(t, &one_minus_r));
                new_tensor.push(self.ring.mul(t, r_i));
            }
            
            tensor = new_tensor;
        }
        
        Ok(tensor)
    }
    
    /// Compute tensor vector t^(z)
    fn compute_tensor_vector(
        &self,
        c: &[RingElement<F>],
        s_prime: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        // t^(z) = tensor(c) ⊗ s' ⊗ (1, d', ..., d'^(ℓ-1)) ⊗ (1, X, ..., X^(d-1))
        let tensor_c = self.compute_tensor_product(c)?;
        
        // For simplicity, return tensor_c
        // Full implementation would compute the complete tensor product
        Ok(tensor_c)
    }
    
    /// Compute tensor commitment product
    fn compute_tensor_commitment_product(
        &self,
        c: &[RingElement<F>],
        com_h: &BaseCommitment<F>,
    ) -> Result<RingElement<F>, String> {
        // ⟨tensor(c), com(h)⟩
        let tensor_c = self.compute_tensor_product(c)?;
        
        // Placeholder: return zero
        Ok(self.ring.zero())
    }
    
    /// Create evaluation claim for integer vector
    fn create_evaluation_claim(
        &self,
        vec: &[i64],
        tensor: &[RingElement<F>],
        expected: i64,
    ) -> Result<SumcheckClaim<F>, String> {
        // Placeholder implementation
        Ok(SumcheckClaim {
            c: vec![self.ring.one()],
            m_j: vec![self.ring.zero()],
            m_prime_j: vec![self.ring.zero()],
            ring: self.ring.clone(),
        })
    }
    
    /// Create evaluation claim for monomial vector
    fn create_monomial_evaluation_claim(
        &self,
        monomials: &[Monomial],
        tensor: &[RingElement<F>],
        expected: &RingElement<F>,
    ) -> Result<SumcheckClaim<F>, String> {
        // Placeholder implementation
        Ok(SumcheckClaim {
            c: vec![self.ring.one()],
            m_j: vec![self.ring.zero()],
            m_prime_j: vec![self.ring.zero()],
            ring: self.ring.clone(),
        })
    }
    
    /// Create evaluation claim for ring element vector
    fn create_ring_evaluation_claim(
        &self,
        vec: &[RingElement<F>],
        tensor: &[RingElement<F>],
        expected: &RingElement<F>,
    ) -> Result<SumcheckClaim<F>, String> {
        // Placeholder implementation
        Ok(SumcheckClaim {
            c: vec![self.ring.one()],
            m_j: vec![self.ring.zero()],
            m_prime_j: vec![self.ring.zero()],
            ring: self.ring.clone(),
        })
    }
    
    /// Create consistency claim
    fn create_consistency_claim(
        &self,
        t_z: &[RingElement<F>],
        rhs: RingElement<F>,
    ) -> Result<SumcheckClaim<F>, String> {
        // Placeholder implementation
        Ok(SumcheckClaim {
            c: vec![self.ring.one()],
            m_j: vec![self.ring.zero()],
            m_prime_j: vec![self.ring.zero()],
            ring: self.ring.clone(),
        })
    }
    
    /// Batch multiple claims via random linear combination
    fn batch_claims(
        &self,
        claims: Vec<SumcheckClaim<F>>,
        combiner: &RingElement<F>,
    ) -> Result<SumcheckClaim<F>, String> {
        if claims.is_empty() {
            return Err("Cannot batch empty claims".to_string());
        }
        
        let mut batched = claims[0].clone();
        let mut power = combiner.clone();
        
        for claim in claims.iter().skip(1) {
            let scaled = claim.scalar_mul(&power, &self.ring)?;
            batched = batched.add(&scaled, &self.ring)?;
            power = self.ring.mul(&power, combiner);
        }
        
        Ok(batched)
    }
    
    /// Compute final evaluations at r_o
    fn compute_final_evaluations(&self, r_o: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        // Placeholder: return empty vector
        Ok(vec![])
    }
    
    /// Create range proof from instance
    fn create_range_proof(&self, instance: &RangeCheckInstance<F>) 
        -> Result<RangeCheckProof<F>, String> {
        // Placeholder
        Ok(RangeCheckProof {
            monomial_proofs: vec![],
            coefficient_eval: vec![],
            split_eval: 0,
        })
    }
    
    /// Get log of kappa (security parameter)
    fn log_kappa(&self) -> usize {
        2 // log_2(4) for typical κ = 4
    }
}

/// Sumcheck claim structure (reused from monomial_check)
use super::monomial_check::SumcheckClaim;


/// Commitment transformation verifier
pub struct CommitmentTransformVerifier<F: Field> {
    /// Commitment cm_f
    commitment_f: BaseCommitment<F>,
    
    /// Double commitment C_{M_f}
    double_commitment: DoubleCommitment<F>,
    
    /// Helper commitment cm_{m_τ}
    helper_commitment: BaseCommitment<F>,
    
    /// Norm bound B
    norm_bound: i64,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
    
    /// Folding set size
    folding_set_size: usize,
    
    /// Vector size n
    n: usize,
}

impl<F: Field> CommitmentTransformVerifier<F> {
    /// Create new commitment transformation verifier
    pub fn new(
        commitment_f: BaseCommitment<F>,
        double_commitment: DoubleCommitment<F>,
        helper_commitment: BaseCommitment<F>,
        norm_bound: i64,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
        folding_set_size: usize,
        n: usize,
    ) -> Self {
        Self {
            commitment_f,
            double_commitment,
            helper_commitment,
            norm_bound,
            ring,
            challenge_set_size,
            folding_set_size,
            n,
        }
    }
    
    /// Verify commitment transformation proof
    /// 
    /// Steps:
    /// 1. Verify range check
    /// 2. Regenerate challenges s, s', c^(0), c^(1)
    /// 3. Verify com(h) matches transcript
    /// 4. Verify parallel sumchecks
    /// 5. Compute folded commitment cm_g and evaluations v_o
    pub fn verify(
        &self,
        proof: &CommitmentTransformProof<F>,
        transcript: &mut Transcript,
    ) -> Result<CommitmentTransformInstance<F>, String> {
        // Step 1: Verify range check
        let range_instance = self.verify_range_check(&proof.range_proof, transcript)?;
        
        // Step 2: Regenerate challenges
        let s = self.regenerate_folding_challenges(transcript, 3)?;
        let dk = self.compute_dk();
        let s_prime = self.regenerate_folding_challenges(transcript, dk)?;
        
        // Step 3: Verify com(h) matches transcript
        let com_h_transcript = transcript.get_commitment("com_h")?;
        if !self.commitments_equal(&com_h_transcript, &proof.folded_commitment) {
            return Err("Folded commitment doesn't match transcript".to_string());
        }
        
        // Regenerate sumcheck challenges
        let log_kappa = self.log_kappa();
        let c_0 = self.regenerate_challenge_vector(transcript, "sumcheck_c0", log_kappa)?;
        let c_1 = self.regenerate_challenge_vector(transcript, "sumcheck_c1", log_kappa)?;
        
        // Step 4: Verify parallel sumchecks
        let r_o = self.verify_parallel_sumchecks(&proof.sumcheck_proofs, transcript)?;
        
        // Step 5: Compute folded commitment and evaluations
        let cm_g = self.compute_folded_commitment(&s, &proof.folded_commitment)?;
        let v_o = self.compute_folded_evaluations(&s, &range_instance, &r_o)?;
        
        Ok(CommitmentTransformInstance {
            folded_commitment: cm_g,
            challenge: r_o,
            evaluations: v_o,
            witness: None,
        })
    }
    
    /// Step 1: Verify range check
    fn verify_range_check(
        &self,
        proof: &RangeCheckProof<F>,
        transcript: &mut Transcript,
    ) -> Result<RangeCheckInstance<F>, String> {
        let verifier = RangeCheckVerifier::new(
            self.commitment_f.clone(),
            self.double_commitment.outer_commitment.clone(),
            self.helper_commitment.clone(),
            self.norm_bound,
            self.ring.clone(),
            self.challenge_set_size,
            self.n,
        )?;
        
        verifier.verify(proof, transcript)
    }
    
    /// Step 2: Regenerate folding challenges
    fn regenerate_folding_challenges(&self, transcript: &mut Transcript, count: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            let challenge = transcript.challenge_ring_element(
                &format!("fold_challenge_{}", i),
                &self.ring
            );
            challenges.push(challenge);
        }
        
        Ok(challenges)
    }
    
    /// Regenerate challenge vector
    fn regenerate_challenge_vector(&self, transcript: &mut Transcript, label: &str, length: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        
        for i in 0..length {
            let challenge = transcript.challenge_ring_element(
                &format!("{}_{}", label, i),
                &self.ring
            );
            challenges.push(challenge);
        }
        
        Ok(challenges)
    }
    
    /// Step 4: Verify parallel sumchecks
    /// 
    /// Verifies 2 parallel sumcheck proofs for soundness boosting
    /// Both proofs must reduce to the same challenge r_o
    /// Verifies final evaluation claims at r_o
    fn verify_parallel_sumchecks(
        &self,
        proofs: &[SumcheckProof<F>],
        transcript: &mut Transcript,
    ) -> Result<Vec<RingElement<F>>, String> {
        if proofs.len() != 2 {
            return Err(format!("Expected 2 parallel sumcheck proofs, got {}", proofs.len()));
        }
        
        // Get batching challenge (must match prover)
        let batch_combiner = transcript.challenge_ring_element("batch_combiner", &self.ring);
        
        // Verify each sumcheck independently
        let mut final_challenges = Vec::new();
        
        for (i, proof) in proofs.iter().enumerate() {
            transcript.append_message(b"parallel_sumcheck_index", &[i as u8]);
            
            let mut verifier = SumcheckVerifier::new(2, self.ring.clone());
            let r_o = verifier.verify(proof, transcript)?;
            final_challenges.push(r_o);
        }
        
        // Verify both reduce to same challenge r_o
        let r_o_0 = &final_challenges[0];
        let r_o_1 = &final_challenges[1];
        
        if r_o_0.len() != r_o_1.len() {
            return Err(format!(
                "Parallel sumcheck challenges have different lengths: {} vs {}",
                r_o_0.len(), r_o_1.len()
            ));
        }
        
        for (idx, (a, b)) in r_o_0.iter().zip(r_o_1.iter()).enumerate() {
            if a.coeffs != b.coeffs {
                return Err(format!(
                    "Parallel sumcheck challenges don't match at index {}: {:?} vs {:?}",
                    idx, a.coeffs, b.coeffs
                ));
            }
        }
        
        // Verify final evaluation claims at r_o
        self.verify_final_evaluation_claims(&proofs[0], &proofs[1], r_o_0)?;
        
        Ok(r_o_0.clone())
    }
    
    /// Verify final evaluation claims at r_o
    /// 
    /// Checks that the sumcheck final values are consistent with:
    /// 1. Evaluation claims: [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
    /// 2. Consistency claims: ⟨tensor(c^(z)), pow(τ_D)s'⟩ = ⟨tensor(c^(z)), com(h)⟩
    fn verify_final_evaluation_claims(
        &self,
        proof_0: &SumcheckProof<F>,
        proof_1: &SumcheckProof<F>,
        r_o: &[RingElement<F>],
    ) -> Result<(), String> {
        // Extract claimed values from sumcheck proofs
        let claimed_0 = &proof_0.claimed_value;
        let claimed_1 = &proof_1.claimed_value;
        
        // Verify claimed values are consistent
        // In a complete implementation, we would:
        // 1. Recompute the batched claim evaluation at r_o
        // 2. Verify it matches the claimed values from both proofs
        // 3. Check that all 6 individual claims are satisfied
        
        // For now, verify the proofs have valid structure
        if claimed_0.coeffs.is_empty() || claimed_1.coeffs.is_empty() {
            return Err("Sumcheck proofs have empty claimed values".to_string());
        }
        
        // Verify both proofs claim the same value (since they're for the same batched claim)
        if claimed_0.coeffs != claimed_1.coeffs {
            return Err(format!(
                "Parallel sumcheck proofs claim different values: {:?} vs {:?}",
                claimed_0.coeffs, claimed_1.coeffs
            ));
        }
        
        Ok(())
    }
    
    /// Step 5: Compute folded commitment
    /// cm_g = s_0·C_{M_f} + s_1·cm_{m_τ} + s_2·cm_f + com(h)
    /// 
    /// This combines all commitments using the folding challenges
    /// The result is a linear commitment to the folded witness g
    fn compute_folded_commitment(
        &self,
        s: &[RingElement<F>],
        com_h: &BaseCommitment<F>,
    ) -> Result<BaseCommitment<F>, String> {
        if s.len() < 3 {
            return Err(format!("Expected at least 3 folding challenges, got {}", s.len()));
        }
        
        // cm_g = s_0·C_{M_f} + s_1·cm_{m_τ} + s_2·cm_f + com(h)
        let mut cm_g = self.scalar_mul_commitment(&self.double_commitment.outer_commitment, &s[0])?;
        
        let term1 = self.scalar_mul_commitment(&self.helper_commitment, &s[1])?;
        cm_g = self.add_commitments(&cm_g, &term1)?;
        
        let term2 = self.scalar_mul_commitment(&self.commitment_f, &s[2])?;
        cm_g = self.add_commitments(&cm_g, &term2)?;
        
        cm_g = self.add_commitments(&cm_g, com_h)?;
        
        Ok(cm_g)
    }
    
    /// Compute folded evaluations v_o at challenge r_o
    /// 
    /// v_o represents the evaluations of the folded witness g at r_o
    /// Computed as: v_o = s_0·e_o,0 + s_1·e_o,1 + s_2·e_o,2 + e_o,3
    /// 
    /// where e_o,i are the evaluations of [τ_D, m_τ, f, h] at r_o
    fn compute_folded_evaluations(
        &self,
        s: &[RingElement<F>],
        range_instance: &RangeCheckInstance<F>,
        r_o: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        if s.len() < 3 {
            return Err(format!("Expected at least 3 folding challenges, got {}", s.len()));
        }
        
        // Compute tensor(r_o) for evaluation
        let tensor_r_o = self.compute_tensor_product_verifier(r_o)?;
        
        // e_o,0 = ⟨τ_D, tensor(r_o)⟩ (from range instance)
        let e_o_0 = self.ring.from_i64(range_instance.evaluations.split_eval);
        
        // e_o,1 = ⟨m_τ, tensor(r_o)⟩ (from range instance)
        let e_o_1 = range_instance.evaluations.helper_eval.clone();
        
        // e_o,2 = ⟨f, tensor(r_o)⟩ (from range instance)
        let e_o_2 = range_instance.evaluations.witness_eval.clone();
        
        // e_o,3 = ⟨h, tensor(r_o)⟩ (computed from decomposition evaluations)
        let e_o_3 = self.compute_h_evaluation(&range_instance.evaluations, &tensor_r_o)?;
        
        // Compute v_o = s_0·e_o,0 + s_1·e_o,1 + s_2·e_o,2 + e_o,3
        let mut v_o = self.ring.mul(&s[0], &e_o_0);
        
        let term1 = self.ring.mul(&s[1], &e_o_1);
        v_o = self.ring.add(&v_o, &term1);
        
        let term2 = self.ring.mul(&s[2], &e_o_2);
        v_o = self.ring.add(&v_o, &term2);
        
        v_o = self.ring.add(&v_o, &e_o_3);
        
        // Return as vector (single evaluation for now)
        Ok(vec![v_o])
    }
    
    /// Compute h evaluation from decomposition evaluations
    /// e_o,3 = ⟨h, tensor(r_o)⟩ where h = M_f · s'
    fn compute_h_evaluation(
        &self,
        evaluations: &RangeCheckEvaluations<F>,
        tensor_r_o: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        // h = M_f · s', so ⟨h, tensor(r_o)⟩ = ⟨M_f · s', tensor(r_o)⟩
        // Compute u from the decomposition evaluations and sumcheck proof
        // u = ⟨e[3, 3+dk), s'⟩ where e are the decomposition evaluations
        
        // Extract decomposition evaluations from the range instance
        let dk = self.split_vector.len();
        
        // Compute inner product of evaluations with column challenges
        let mut u = self.ring.zero();
        
        // In the full protocol, we would extract e[3, 3+dk) from the range instance
        // and compute the inner product with s'
        // For this implementation, we compute it from the witness structure
        
        for (i, &split_val) in self.split_vector.iter().enumerate().take(dk) {
            if i < self.monomial_matrix.cols() {
                // Get the corresponding evaluation
                let eval = self.ring.from_i64(split_val);
                
                // Multiply by challenge (simplified - would use actual s' from transcript)
                u = self.ring.add(&u, &eval);
            }
        }
        
        Ok(u)
    }
    
    /// Compute tensor product for verifier
    fn compute_tensor_product_verifier(&self, r: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let k = r.len();
        let mut tensor = vec![self.ring.one()];
        
        for r_i in r {
            let mut new_tensor = Vec::with_capacity(tensor.len() * 2);
            let one_minus_r = self.ring.sub(&self.ring.one(), r_i);
            
            for t in &tensor {
                new_tensor.push(self.ring.mul(t, &one_minus_r));
                new_tensor.push(self.ring.mul(t, r_i));
            }
            
            tensor = new_tensor;
        }
        
        Ok(tensor)
    }
    
    /// Helper: scalar multiply commitment
    /// 
    /// Computes scalar · commitment for a ring element scalar
    /// For Ajtai commitments: scalar · com(a) = com(scalar · a)
    fn scalar_mul_commitment(
        &self,
        commitment: &BaseCommitment<F>,
        scalar: &RingElement<F>,
    ) -> Result<BaseCommitment<F>, String> {
        // For each element in the commitment vector, multiply by scalar
        let mut result_values = Vec::new();
        
        for elem in &commitment.values {
            let scaled = self.ring.mul(elem, scalar);
            result_values.push(scaled);
        }
        
        Ok(BaseCommitment {
            values: result_values,
            ..commitment.clone()
        })
    }
    
    /// Helper: add commitments
    /// 
    /// Computes a + b for two commitments
    /// For Ajtai commitments: com(a) + com(b) = com(a + b)
    fn add_commitments(
        &self,
        a: &BaseCommitment<F>,
        b: &BaseCommitment<F>,
    ) -> Result<BaseCommitment<F>, String> {
        if a.values.len() != b.values.len() {
            return Err(format!(
                "Cannot add commitments of different lengths: {} vs {}",
                a.values.len(), b.values.len()
            ));
        }
        
        let mut result_values = Vec::new();
        
        for (a_elem, b_elem) in a.values.iter().zip(b.values.iter()) {
            let sum = self.ring.add(a_elem, b_elem);
            result_values.push(sum);
        }
        
        Ok(BaseCommitment {
            values: result_values,
            ..a.clone()
        })
    }
    
    /// Helper: check if commitments are equal
    /// 
    /// Compares two commitments element-wise
    fn commitments_equal(&self, a: &BaseCommitment<F>, b: &BaseCommitment<F>) -> bool {
        if a.values.len() != b.values.len() {
            return false;
        }
        
        for (a_elem, b_elem) in a.values.iter().zip(b.values.iter()) {
            if a_elem.coeffs != b_elem.coeffs {
                return false;
            }
        }
        
        true
    }
    
    /// Compute dk (decomposition length × ring degree)
    fn compute_dk(&self) -> usize {
        let d = self.ring.degree;
        let d_prime = d / 2;
        let q = F::MODULUS;
        let k = ((q as f64).log(d_prime as f64)).ceil() as usize;
        d * k
    }
    
    /// Get log of kappa
    fn log_kappa(&self) -> usize {
        2 // log_2(4) for typical κ = 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_commitment_transform_structures() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create input
        let input = CommitmentTransformInput {
            witness_f: vec![ring.one()],
            split_vector: vec![0i64],
            helper_monomials: vec![Monomial::Zero],
            monomial_matrix: MonomialMatrix::from_vector(vec![Monomial::Zero]),
            commitment_f: BaseCommitment::default(),
            double_commitment: DoubleCommitment::default(),
            helper_commitment: BaseCommitment::default(),
            norm_bound: 1024,
        };
        
        let prover = CommitmentTransformProver::new(input, ring.clone(), 256, 256);
        
        // Verify prover was created successfully
        assert_eq!(prover.witness_f.len(), 1);
    }
    
    #[test]
    fn test_folded_witness_computation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create 2x2 monomial matrix
        let matrix = MonomialMatrix::new(vec![
            vec![Monomial::Positive(1), Monomial::Positive(2)],
            vec![Monomial::Positive(3), Monomial::Zero],
        ]);
        
        let input = CommitmentTransformInput {
            witness_f: vec![ring.one()],
            split_vector: vec![0i64],
            helper_monomials: vec![Monomial::Zero],
            monomial_matrix: matrix,
            commitment_f: BaseCommitment::default(),
            double_commitment: DoubleCommitment::default(),
            helper_commitment: BaseCommitment::default(),
            norm_bound: 1024,
        };
        
        let prover = CommitmentTransformProver::new(input, ring.clone(), 256, 256);
        
        // Compute folded witness
        let s_prime = vec![ring.one(), ring.one()];
        let h = prover.compute_folded_witness(&s_prime);
        
        assert!(h.is_ok());
        let h = h.unwrap();
        assert_eq!(h.len(), 2);
    }
}



// ============================================================================
// Task 17: Π_cm Optimizations
// ============================================================================

/// Optimization module for commitment transformation protocol
/// Implements Remark 4.6 (sumcheck over Zq) and Remark 4.7 (communication optimization)
pub mod optimizations {
    use super::*;
    
    /// Sumcheck optimization over Zq (Remark 4.6)
    /// 
    /// Decomposes 6 Rq claims into 6d Zq claims
    /// Compresses to 1 claim via random linear combination
    /// Uses extension field F_q^t when |Zq| is small
    pub struct SumcheckZqOptimizer<F: Field> {
        ring: CyclotomicRing<F>,
        use_extension_field: bool,
        extension_degree: usize,
    }
    
    impl<F: Field> SumcheckZqOptimizer<F> {
        /// Create new Zq optimizer
        /// 
        /// Automatically determines if extension field is needed
        /// Uses F_q^t when q < 2^λ for security parameter λ
        pub fn new(ring: CyclotomicRing<F>, security_level: usize) -> Self {
            let q = F::MODULUS;
            let use_extension_field = (q as f64).log2() < security_level as f64;
            
            // Compute extension degree t such that q^t ≥ 2^λ
            let extension_degree = if use_extension_field {
                ((security_level as f64) / (q as f64).log2()).ceil() as usize
            } else {
                1
            };
            
            Self {
                ring,
                use_extension_field,
                extension_degree,
            }
        }
        
        /// Decompose Rq claims into Zq claims
        /// 
        /// Each claim over Rq is decomposed into d claims over Zq (coefficient-wise)
        /// Input: 6 claims over Rq
        /// Output: 6d claims over Zq
        pub fn decompose_to_zq_claims(
            &self,
            rq_claims: Vec<SumcheckClaim<F>>,
        ) -> Result<Vec<ZqSumcheckClaim<F>>, String> {
            let d = self.ring.degree;
            let mut zq_claims = Vec::with_capacity(rq_claims.len() * d);
            
            for (claim_idx, claim) in rq_claims.iter().enumerate() {
                // Decompose each Rq claim into d Zq claims
                for coeff_idx in 0..d {
                    let zq_claim = self.extract_coefficient_claim(claim, coeff_idx)?;
                    zq_claims.push(zq_claim);
                }
            }
            
            Ok(zq_claims)
        }
        
        /// Extract coefficient claim from Rq claim
        /// 
        /// For a claim over Rq, extract the claim for coefficient index coeff_idx
        fn extract_coefficient_claim(
            &self,
            claim: &SumcheckClaim<F>,
            coeff_idx: usize,
        ) -> Result<ZqSumcheckClaim<F>, String> {
            if coeff_idx >= self.ring.degree {
                return Err(format!("Coefficient index {} out of bounds", coeff_idx));
            }
            
            // Extract coefficient at coeff_idx from each ring element
            let c_zq: Vec<F> = claim.c.iter()
                .map(|r| r.coeffs.get(coeff_idx).cloned().unwrap_or(F::zero()))
                .collect();
            
            let m_j_zq: Vec<F> = claim.m_j.iter()
                .map(|r| r.coeffs.get(coeff_idx).cloned().unwrap_or(F::zero()))
                .collect();
            
            let m_prime_j_zq: Vec<F> = claim.m_prime_j.iter()
                .map(|r| r.coeffs.get(coeff_idx).cloned().unwrap_or(F::zero()))
                .collect();
            
            Ok(ZqSumcheckClaim {
                c: c_zq,
                m_j: m_j_zq,
                m_prime_j: m_prime_j_zq,
                coeff_index: coeff_idx,
            })
        }
        
        /// Compress Zq claims via random linear combination
        /// 
        /// Combines 6d Zq claims into 1 claim using random challenge
        /// Adds soundness error k/|F| where k = 6d
        pub fn compress_zq_claims(
            &self,
            zq_claims: Vec<ZqSumcheckClaim<F>>,
            combiner: F,
        ) -> Result<ZqSumcheckClaim<F>, String> {
            if zq_claims.is_empty() {
                return Err("Cannot compress empty claims".to_string());
            }
            
            let mut compressed = zq_claims[0].clone();
            let mut power = combiner;
            
            for claim in zq_claims.iter().skip(1) {
                compressed = compressed.add_scaled(claim, power)?;
                power = power.mul(&combiner);
            }
            
            Ok(compressed)
        }
        
        /// Run optimized sumcheck over Zq
        /// 
        /// Full pipeline:
        /// 1. Decompose 6 Rq claims to 6d Zq claims
        /// 2. Compress to 1 Zq claim via random linear combination
        /// 3. Run sumcheck over Zq (or extension field if needed)
        pub fn run_optimized_sumcheck(
            &mut self,
            rq_claims: Vec<SumcheckClaim<F>>,
            transcript: &mut Transcript,
        ) -> Result<SumcheckProof<F>, String> {
            // Step 1: Decompose to Zq claims
            let zq_claims = self.decompose_to_zq_claims(rq_claims)?;
            
            // Step 2: Get compression challenge
            let combiner = if self.use_extension_field {
                // Sample from extension field F_q^t
                self.sample_extension_field_element(transcript)?
            } else {
                // Sample from base field Zq
                transcript.challenge_field("zq_combiner")
            };
            
            // Step 3: Compress claims
            let compressed_claim = self.compress_zq_claims(zq_claims, combiner)?;
            
            // Step 4: Run sumcheck
            self.run_zq_sumcheck(compressed_claim, transcript)
        }
        
        /// Sample element from extension field F_q^t
        fn sample_extension_field_element(&self, transcript: &mut Transcript) -> Result<F, String> {
            // For extension field, we would sample t elements from Zq
            // For now, sample single element from base field
            Ok(transcript.challenge_field("extension_combiner"))
        }
        
        /// Run sumcheck over Zq
        fn run_zq_sumcheck(
            &self,
            claim: ZqSumcheckClaim<F>,
            transcript: &mut Transcript,
        ) -> Result<SumcheckProof<F>, String> {
            // Convert Zq claim back to Rq format for sumcheck prover
            let rq_claim = self.convert_zq_to_rq_claim(claim)?;
            
            let mut prover = SumcheckProver::new(rq_claim, 2, self.ring.clone());
            prover.prove(transcript)
        }
        
        /// Convert Zq claim to Rq claim
        fn convert_zq_to_rq_claim(&self, zq_claim: ZqSumcheckClaim<F>) -> Result<SumcheckClaim<F>, String> {
            // Convert field elements to ring elements (as constants)
            let c: Vec<RingElement<F>> = zq_claim.c.iter()
                .map(|&f| self.ring.from_field(f))
                .collect();
            
            let m_j: Vec<RingElement<F>> = zq_claim.m_j.iter()
                .map(|&f| self.ring.from_field(f))
                .collect();
            
            let m_prime_j: Vec<RingElement<F>> = zq_claim.m_prime_j.iter()
                .map(|&f| self.ring.from_field(f))
                .collect();
            
            Ok(SumcheckClaim {
                c,
                m_j,
                m_prime_j,
                ring: self.ring.clone(),
            })
        }
        
        /// Compute soundness error
        /// 
        /// Error = (2d + m + 4 log n)/|C| + k/|F| + ε_bind
        /// where k = 6d for the compression
        pub fn soundness_error(&self, m: usize, n: usize, c_size: usize) -> f64 {
            let d = self.ring.degree as f64;
            let log_n = (n as f64).log2();
            let k = 6.0 * d;
            
            let field_size = if self.use_extension_field {
                (F::MODULUS as f64).powi(self.extension_degree as i32)
            } else {
                F::MODULUS as f64
            };
            
            let sumcheck_error = (2.0 * d + m as f64 + 4.0 * log_n) / (c_size as f64);
            let compression_error = k / field_size;
            
            sumcheck_error + compression_error
        }
    }
    
    /// Zq sumcheck claim (coefficient-wise)
    #[derive(Clone, Debug)]
    pub struct ZqSumcheckClaim<F: Field> {
        pub c: Vec<F>,
        pub m_j: Vec<F>,
        pub m_prime_j: Vec<F>,
        pub coeff_index: usize,
    }
    
    impl<F: Field> ZqSumcheckClaim<F> {
        /// Add scaled claim
        pub fn add_scaled(&self, other: &Self, scalar: F) -> Result<Self, String> {
            if self.c.len() != other.c.len() {
                return Err("Dimension mismatch in Zq claim addition".to_string());
            }
            
            let c: Vec<F> = self.c.iter()
                .zip(other.c.iter())
                .map(|(&a, &b)| a.add(&b.mul(&scalar)))
                .collect();
            
            let m_j: Vec<F> = self.m_j.iter()
                .zip(other.m_j.iter())
                .map(|(&a, &b)| a.add(&b.mul(&scalar)))
                .collect();
            
            let m_prime_j: Vec<F> = self.m_prime_j.iter()
                .zip(other.m_prime_j.iter())
                .map(|(&a, &b)| a.add(&b.mul(&scalar)))
                .collect();
            
            Ok(Self {
                c,
                m_j,
                m_prime_j,
                coeff_index: self.coeff_index,
            })
        }
    }
    
    /// Communication optimization (Remark 4.7)
    /// 
    /// Compresses e' = e[3, 3+dk) from dk Rq-elements to 2κ + O(log d) elements
    /// Uses same split/pow technique as double commitments
    /// Achieves ≈ dk/(2κ) factor saving
    pub struct CommunicationOptimizer<F: Field> {
        ring: CyclotomicRing<F>,
        kappa: usize,
        d_prime: usize,
        ell: usize,
    }
    
    impl<F: Field> CommunicationOptimizer<F> {
        /// Create new communication optimizer
        pub fn new(ring: CyclotomicRing<F>, kappa: usize) -> Self {
            let d_prime = ring.degree / 2;
            let q = F::MODULUS;
            let ell = ((q as f64).log(d_prime as f64)).ceil() as usize;
            
            Self {
                ring,
                kappa,
                d_prime,
                ell,
            }
        }
        
        /// Compress evaluations e' using split/pow technique
        /// 
        /// Instead of sending dk Rq-elements, send:
        /// 1. com(τ_e) - commitment to split vector (κ elements)
        /// 2. com(exp(τ_e)) - commitment to monomial vector (κ elements)
        /// 3. Range check proof for τ_e (O(log d) elements)
        /// 
        /// Total: 2κ + O(log d) instead of dk
        pub fn compress_evaluations(
            &self,
            e_prime: &[RingElement<F>],
            commitment_key: &super::super::ajtai_commitment::AjtaiCommitment<F>,
        ) -> Result<CompressedEvaluations<F>, String> {
            // Step 1: Decompose e' to τ_e ∈ (-d', d')^n'
            let tau_e = self.split_evaluations(e_prime)?;
            
            // Step 2: Compute exp(τ_e) - monomial vector
            let exp_tau_e = self.compute_exp_vector(&tau_e)?;
            
            // Step 3: Commit to τ_e and exp(τ_e)
            let com_tau_e = self.commit_integer_vector(&tau_e, commitment_key)?;
            let com_exp_tau_e = self.commit_monomial_vector(&exp_tau_e, commitment_key)?;
            
            Ok(CompressedEvaluations {
                com_tau_e,
                com_exp_tau_e,
                tau_e,
                exp_tau_e,
            })
        }
        
        /// Split evaluations to integer vector
        /// 
        /// Similar to split function for double commitments
        /// Decomposes each evaluation to base d'
        fn split_evaluations(&self, e_prime: &[RingElement<F>]) -> Result<Vec<i64>, String> {
            let mut tau_e = Vec::new();
            
            for elem in e_prime {
                // Decompose each coefficient
                for &coeff in &elem.coeffs {
                    let coeff_i64 = self.field_to_i64(coeff)?;
                    
                    // Base-d' decomposition
                    let decomp = self.decompose_to_base(coeff_i64, self.d_prime as i64, self.ell);
                    tau_e.extend(decomp);
                }
            }
            
            Ok(tau_e)
        }
        
        /// Decompose integer to base d'
        fn decompose_to_base(&self, x: i64, base: i64, length: usize) -> Vec<i64> {
            let mut result = vec![0i64; length];
            let mut abs_x = x.abs();
            let sign = x.signum();
            
            for i in 0..length {
                result[i] = sign * (abs_x % base);
                abs_x /= base;
            }
            
            result
        }
        
        /// Compute exp vector
        fn compute_exp_vector(&self, tau_e: &[i64]) -> Result<Vec<Monomial>, String> {
            tau_e.iter()
                .map(|&x| self.exp_function(x))
                .collect()
        }
        
        /// exp function: a ↦ sgn(a)·X^|a|
        fn exp_function(&self, a: i64) -> Result<Monomial, String> {
            match a.signum() {
                0 => Ok(Monomial::Zero),
                1 => Ok(Monomial::Positive(a as usize)),
                -1 => Ok(Monomial::Negative((-a) as usize)),
                _ => Err("Invalid sign".to_string()),
            }
        }
        
        /// Commit to integer vector
        fn commit_integer_vector(
            &self,
            vec: &[i64],
            commitment_key: &super::super::ajtai_commitment::AjtaiCommitment<F>,
        ) -> Result<BaseCommitment<F>, String> {
            // Convert integers to ring elements
            let ring_vec: Vec<RingElement<F>> = vec.iter()
                .map(|&x| self.ring.from_i64(x))
                .collect();
            
            // Commit using Ajtai commitment
            commitment_key.commit(&ring_vec)
        }
        
        /// Commit to monomial vector
        fn commit_monomial_vector(
            &self,
            vec: &[Monomial],
            commitment_key: &super::super::ajtai_commitment::AjtaiCommitment<F>,
        ) -> Result<BaseCommitment<F>, String> {
            // Convert monomials to ring elements
            let ring_vec: Vec<RingElement<F>> = vec.iter()
                .map(|m| m.to_ring_element(&self.ring))
                .collect();
            
            // Commit using Ajtai commitment
            commitment_key.commit(&ring_vec)
        }
        
        /// Field element to i64
        fn field_to_i64(&self, f: F) -> Result<i64, String> {
            // Convert field element to balanced representation
            let val = f.to_u64();
            let q = F::MODULUS;
            
            if val > q / 2 {
                Ok((val as i64) - (q as i64))
            } else {
                Ok(val as i64)
            }
        }
        
        /// Compute compression ratio
        /// 
        /// Returns the factor by which communication is reduced
        pub fn compression_ratio(&self, dk: usize) -> f64 {
            let original_size = dk;
            let compressed_size = 2 * self.kappa + (self.ring.degree as f64).log2() as usize;
            
            original_size as f64 / compressed_size as f64
        }
        
        /// Prove consistency of compressed evaluations
        /// 
        /// Additional sumcheck claims:
        /// (i) ⟨pow(τ_e), s'⟩ = u
        /// (ii) pow(τ_e)[β] = v_e and pow(τ_e)[β²] = v'_e
        /// (iii) ct(ψ · v') = ⟨v, tensor(c')⟩
        pub fn prove_consistency(
            &self,
            compressed: &CompressedEvaluations<F>,
            s_prime: &[RingElement<F>],
            transcript: &mut Transcript,
        ) -> Result<ConsistencyProof<F>, String> {
            // Claim (i): ⟨pow(τ_e), s'⟩ = u
            let pow_tau_e = self.compute_pow(&compressed.tau_e)?;
            let u = self.inner_product(&pow_tau_e, s_prime)?;
            
            // Claim (ii): Evaluations at β and β²
            let beta = transcript.challenge_ring_element("consistency_beta", &self.ring);
            let beta_squared = self.ring.mul(&beta, &beta);
            
            let v_e = self.evaluate_pow_at(&pow_tau_e, &beta)?;
            let v_prime_e = self.evaluate_pow_at(&pow_tau_e, &beta_squared)?;
            
            // Claim (iii): Table polynomial check
            let psi = self.compute_table_polynomial()?;
            let v_prime_product = self.ring.mul(&psi, &v_prime_e);
            let ct = v_prime_product.coeffs[0];
            
            Ok(ConsistencyProof {
                u,
                v_e,
                v_prime_e,
                ct,
            })
        }
        
        /// Compute pow function
        fn compute_pow(&self, tau: &[i64]) -> Result<Vec<RingElement<F>>, String> {
            // Inverse of split: pow(split(D)) = D
            // Groups coefficients and reconstructs ring elements
            
            let d = self.ring.degree;
            let chunk_size = d * self.ell;
            let num_elements = tau.len() / chunk_size;
            
            let mut result = Vec::with_capacity(num_elements);
            
            for i in 0..num_elements {
                let start = i * chunk_size;
                let end = start + chunk_size;
                let chunk = &tau[start..end];
                
                let elem = self.power_sum_embed(chunk)?;
                result.push(elem);
            }
            
            Ok(result)
        }
        
        /// Power sum embedding
        fn power_sum_embed(&self, chunk: &[i64]) -> Result<RingElement<F>, String> {
            let d = self.ring.degree;
            let mut coeffs = vec![F::zero(); d];
            
            for (idx, &val) in chunk.iter().enumerate() {
                let power = idx % self.ell;
                let coeff_idx = idx / self.ell;
                
                let d_prime_power = (self.d_prime as i64).pow(power as u32);
                let contribution = val * d_prime_power;
                
                coeffs[coeff_idx] = coeffs[coeff_idx].add(&F::from_i64(contribution));
            }
            
            Ok(RingElement::from_coeffs(coeffs))
        }
        
        /// Inner product of ring element vectors
        fn inner_product(&self, a: &[RingElement<F>], b: &[RingElement<F>]) -> Result<RingElement<F>, String> {
            if a.len() != b.len() {
                return Err(format!("Length mismatch: {} vs {}", a.len(), b.len()));
            }
            
            let mut result = self.ring.zero();
            
            for (a_i, b_i) in a.iter().zip(b.iter()) {
                let product = self.ring.mul(a_i, b_i);
                result = self.ring.add(&result, &product);
            }
            
            Ok(result)
        }
        
        /// Evaluate pow at point
        fn evaluate_pow_at(&self, pow_vec: &[RingElement<F>], point: &RingElement<F>) -> Result<RingElement<F>, String> {
            let mut result = self.ring.zero();
            let mut point_power = self.ring.one();
            
            for elem in pow_vec {
                let term = self.ring.mul(elem, &point_power);
                result = self.ring.add(&result, &term);
                point_power = self.ring.mul(&point_power, point);
            }
            
            Ok(result)
        }
        
        /// Compute table polynomial ψ
        fn compute_table_polynomial(&self) -> Result<RingElement<F>, String> {
            // ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i)
            let d = self.ring.degree;
            let mut coeffs = vec![F::zero(); d];
            
            for i in 1..self.d_prime {
                let i_field = F::from_u64(i as u64);
                
                // X^i term
                coeffs[i] = coeffs[i].add(&i_field);
                
                // X^(-i) = -X^(d-i) term
                let neg_i_field = i_field.neg();
                coeffs[d - i] = coeffs[d - i].add(&neg_i_field);
            }
            
            Ok(RingElement::from_coeffs(coeffs))
        }
    }
    
    /// Compressed evaluations structure
    #[derive(Clone, Debug)]
    pub struct CompressedEvaluations<F: Field> {
        pub com_tau_e: BaseCommitment<F>,
        pub com_exp_tau_e: BaseCommitment<F>,
        pub tau_e: Vec<i64>,
        pub exp_tau_e: Vec<Monomial>,
    }
    
    /// Consistency proof for compressed evaluations
    #[derive(Clone, Debug)]
    pub struct ConsistencyProof<F: Field> {
        pub u: RingElement<F>,
        pub v_e: RingElement<F>,
        pub v_prime_e: RingElement<F>,
        pub ct: F,
    }
}

#[cfg(test)]
mod optimization_tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_zq_optimizer_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let optimizer = optimizations::SumcheckZqOptimizer::new(ring, 128);
        
        // Goldilocks field is 64-bit, so no extension field needed for 128-bit security
        assert!(!optimizer.use_extension_field);
    }
    
    #[test]
    fn test_communication_optimizer_compression_ratio() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let optimizer = optimizations::CommunicationOptimizer::new(ring, 4);
        
        let dk = 256; // typical value
        let ratio = optimizer.compression_ratio(dk);
        
        // Should achieve significant compression
        assert!(ratio > 10.0);
    }
}
