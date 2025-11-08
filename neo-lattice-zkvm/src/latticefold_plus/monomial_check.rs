// Monomial Set Check Protocol (Π_mon) Implementation
// Verifies committed matrix M has all entries in monomial set M
// Construction 4.2 from LatticeFold+ paper

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::Commitment as BaseCommitment;
use crate::folding::transcript::Transcript;
use crate::folding::sumcheck::{SumcheckProver, SumcheckVerifier, SumcheckProof};
use super::monomial::{Monomial, MonomialMatrix};
use super::double_commitment::{DoubleCommitment, DoubleOpeningRelation};

/// Input relation R_{m,in} for monomial set check
/// x = C_M ∈ Rq^κ, w = M ∈ Rq^(n×m)
/// M_{i,j} ∈ M for all (i,j) ∈ [n] × [m]
#[derive(Clone, Debug)]
pub struct MonomialSetCheckInput<F: Field> {
    /// Double commitment C_M
    pub commitment: BaseCommitment<F>,
    
    /// Witness matrix M ∈ Rq^(n×m) (for prover only)
    pub matrix: Option<MonomialMatrix<F>>,
    
    /// Double opening relation
    pub opening_relation: Option<DoubleOpeningRelation<F>>,
}

/// Output relation R_{m,out} for monomial set check
/// x = (C_M ∈ Rq^κ, r ∈ C^(log n), e ∈ Rq^m), w = M ∈ Rq^(n×m)
/// M^⊤ tensor(r) = e ∧ (C_M, (split(com(M)), M)) ∈ R_{dopen,m}
#[derive(Clone, Debug)]
pub struct MonomialSetCheckOutput<F: Field> {
    /// Double commitment C_M
    pub commitment: BaseCommitment<F>,
    
    /// Challenge r ∈ C^(log n)
    pub challenge_r: Vec<RingElement<F>>,
    
    /// Evaluations e ∈ Rq^m
    pub evaluations: Vec<RingElement<F>>,
    
    /// Witness matrix M (for prover only)
    pub matrix: Option<MonomialMatrix<F>>,
}

/// Monomial set check prover
pub struct MonomialSetCheckProver<F: Field> {
    /// Monomial matrix M ∈ M^(n×m)
    matrix: MonomialMatrix<F>,
    
    /// Double commitment C_M
    double_commitment: DoubleCommitment<F>,
    
    /// Challenge set C (strong sampling set)
    challenge_set_size: usize,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Cached tensor products for efficiency
    tensor_cache: std::collections::HashMap<Vec<u8>, Vec<RingElement<F>>>,
}

/// Monomial set check verifier
pub struct MonomialSetCheckVerifier<F: Field> {
    /// Double commitment C_M
    commitment: BaseCommitment<F>,
    
    /// Challenge set size |C|
    challenge_set_size: usize,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Number of rows n
    n: usize,
    
    /// Number of columns m
    m: usize,
}

/// Monomial set check proof
#[derive(Clone, Debug)]
pub struct MonomialSetCheckProof<F: Field> {
    /// Degree-3 sumcheck proof
    pub sumcheck_proof: SumcheckProof<F>,
    
    /// Multilinear evaluations {e_j = M̃_{*,j}(r)}_{j∈[m]}
    pub evaluations: Vec<RingElement<F>>,
}

/// Monomial set check instance (reduced)
#[derive(Clone, Debug)]
pub struct MonomialSetCheckInstance<F: Field> {
    /// Double commitment C_M
    pub commitment: BaseCommitment<F>,
    
    /// Challenge r ∈ C^(log n)
    pub challenge_r: Vec<RingElement<F>>,
    
    /// Evaluations e ∈ Rq^m
    pub evaluations: Vec<RingElement<F>>,
}

impl<F: Field> MonomialSetCheckProver<F> {
    /// Create new monomial set check prover
    pub fn new(
        matrix: MonomialMatrix<F>,
        double_commitment: DoubleCommitment<F>,
        challenge_set_size: usize,
        ring: CyclotomicRing<F>,
    ) -> Self {
        Self {
            matrix,
            double_commitment,
            challenge_set_size,
            ring,
        }
    }
    
    /// Run monomial set check protocol (Construction 4.2)
    /// 
    /// Protocol:
    /// 1. V → P: c ← C^(log n), β ← C
    /// 2. P ↔ V: Degree-3 sumcheck for batched claims
    /// 3. P → V: {e_j = M̃_{*,j}(r)}_{j∈[m]}
    /// 4. V: Verify final check
    pub fn prove(&mut self, transcript: &mut Transcript) 
        -> Result<MonomialSetCheckProof<F>, String> {
        // Step 1: Receive challenges from transcript
        let log_n = (self.matrix.rows() as f64).log2().ceil() as usize;
        let c = self.receive_challenge_vector(transcript, "monomial_c", log_n)?;
        let beta = self.receive_challenge_field(transcript, "monomial_beta")?;
        
        // Step 2: Prepare sumcheck claims
        let claims = self.prepare_sumcheck_claims(&c, &beta)?;
        
        // Step 3: Run batched degree-3 sumcheck
        let sumcheck_proof = self.run_batched_sumcheck(claims, transcript)?;
        
        // Step 4: Compute and send multilinear evaluations
        let r = sumcheck_proof.final_challenge.clone();
        let evaluations = self.compute_evaluations(&r)?;
        
        // Append evaluations to transcript
        for (j, eval) in evaluations.iter().enumerate() {
            transcript.append_ring_element(&format!("eval_{}", j), eval);
        }
        
        Ok(MonomialSetCheckProof {
            sumcheck_proof,
            evaluations,
        })
    }
    
    /// Receive challenge vector from transcript
    fn receive_challenge_vector(&self, transcript: &mut Transcript, label: &str, length: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        for i in 0..length {
            let challenge = transcript.challenge_ring_element(&format!("{}_{}", label, i), &self.ring);
            challenges.push(challenge);
        }
        Ok(challenges)
    }
    
    /// Receive challenge field element from transcript
    fn receive_challenge_field(&self, transcript: &mut Transcript, label: &str) 
        -> Result<RingElement<F>, String> {
        Ok(transcript.challenge_ring_element(label, &self.ring))
    }
    
    /// Prepare sumcheck claims (Corollary 4.1)
    /// 
    /// For each column j ∈ [m]:
    /// Claim: Σ_{i∈[n]} eq(c, ⟨i⟩) · (m̃^(j)(⟨i⟩)² - m̃'^(j)(⟨i⟩)) = 0
    /// 
    /// where:
    /// - m^(j) = (ev_{M_{0,j}}(β), ..., ev_{M_{n-1,j}}(β))
    /// - m'^(j) = (ev_{M_{0,j}}(β²), ..., ev_{M_{n-1,j}}(β²))
    fn prepare_sumcheck_claims(&self, c: &[RingElement<F>], beta: &RingElement<F>) 
        -> Result<Vec<SumcheckClaim<F>>, String> {
        let m = self.matrix.cols();
        let mut claims = Vec::with_capacity(m);
        
        for j in 0..m {
            // Compute m^(j) = evaluations at β
            let m_j = self.compute_evaluations_at_beta(j, beta)?;
            
            // Compute m'^(j) = evaluations at β²
            let beta_squared = self.ring.mul(beta, beta);
            let m_prime_j = self.compute_evaluations_at_beta(j, &beta_squared)?;
            
            // Create sumcheck claim
            let claim = SumcheckClaim::new(
                c.clone(),
                m_j,
                m_prime_j,
                self.ring.clone(),
            );
            
            claims.push(claim);
        }
        
        Ok(claims)
    }
    
    /// Compute evaluations at β for column j
    /// m^(j) = (ev_{M_{0,j}}(β), ..., ev_{M_{n-1,j}}(β))
    fn compute_evaluations_at_beta(&self, col: usize, beta: &RingElement<F>) 
        -> Result<Vec<RingElement<F>>, String> {
        let n = self.matrix.rows();
        let mut evaluations = Vec::with_capacity(n);
        
        for row in 0..n {
            let monomial = self.matrix.get(row, col)
                .ok_or_else(|| format!("Invalid matrix index ({}, {})", row, col))?;
            
            let eval = self.evaluate_monomial(monomial, beta)?;
            evaluations.push(eval);
        }
        
        Ok(evaluations)
    }
    
    /// Evaluate monomial at point β
    /// For monomial X^k: ev_{X^k}(β) = β^k
    fn evaluate_monomial(&self, monomial: &Monomial, beta: &RingElement<F>) 
        -> Result<RingElement<F>, String> {
        match monomial {
            Monomial::Zero => Ok(self.ring.zero()),
            Monomial::Positive(exp) => {
                // Compute β^exp using repeated squaring
                self.power_ring_element(beta, *exp)
            }
            Monomial::Negative(exp) => {
                // Compute -β^exp
                let pos_result = self.power_ring_element(beta, *exp)?;
                Ok(self.ring.neg(&pos_result))
            }
        }
    }
    
    /// Compute β^exp using repeated squaring
    fn power_ring_element(&self, base: &RingElement<F>, exp: usize) 
        -> Result<RingElement<F>, String> {
        if exp == 0 {
            return Ok(self.ring.one());
        }
        
        let mut result = self.ring.one();
        let mut base_power = base.clone();
        let mut remaining_exp = exp;
        
        while remaining_exp > 0 {
            if remaining_exp % 2 == 1 {
                result = self.ring.mul(&result, &base_power);
            }
            base_power = self.ring.mul(&base_power, &base_power);
            remaining_exp /= 2;
        }
        
        Ok(result)
    }
    
    /// Run batched sumcheck protocol
    /// Batches m claims into one via random linear combination
    fn run_batched_sumcheck(&mut self, claims: Vec<SumcheckClaim<F>>, transcript: &mut Transcript) 
        -> Result<SumcheckProof<F>, String> {
        // Get batching challenge α
        let alpha = transcript.challenge_ring_element("sumcheck_combiner", &self.ring);
        
        // Batch claims: Σ_j α^j · claim_j
        let batched_claim = self.batch_claims(claims, &alpha)?;
        
        // Run degree-3 sumcheck protocol
        let mut prover = SumcheckProver::new(batched_claim, 3, self.ring.clone());
        prover.prove(transcript)
    }
    
    /// Batch multiple sumcheck claims via random linear combination
    fn batch_claims(&self, claims: Vec<SumcheckClaim<F>>, alpha: &RingElement<F>) 
        -> Result<SumcheckClaim<F>, String> {
        if claims.is_empty() {
            return Err("Cannot batch empty claims".to_string());
        }
        
        let mut batched = claims[0].clone();
        let mut alpha_power = alpha.clone();
        
        for claim in claims.iter().skip(1) {
            let scaled_claim = claim.scalar_mul(&alpha_power, &self.ring)?;
            batched = batched.add(&scaled_claim, &self.ring)?;
            alpha_power = self.ring.mul(&alpha_power, alpha);
        }
        
        Ok(batched)
    }
    
    /// Compute multilinear evaluations {e_j = M̃_{*,j}(r)}_{j∈[m]}
    /// 
    /// Optimized for monomial matrices: O(n) Zq-additions
    /// Uses sparse representation of monomials
    fn compute_evaluations(&self, r: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let m = self.matrix.cols();
        let tensor_r = self.compute_tensor_product(r)?;
        
        let mut evaluations = Vec::with_capacity(m);
        
        for j in 0..m {
            let column = self.matrix.column(j);
            let eval = self.multilinear_eval(&column, &tensor_r)?;
            evaluations.push(eval);
        }
        
        Ok(evaluations)
    }
    
    /// Compute tensor product tensor(r) = ⊗_{i∈[k]} (1-rᵢ, rᵢ)
    fn compute_tensor_product(&self, r: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let k = r.len();
        let size = 1 << k;
        
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
    
    /// Compute multilinear evaluation M̃_{*,j}(r) = ⟨M_{*,j}, tensor(r)⟩
    /// 
    /// Optimized for monomials: O(n) Zq-additions instead of multiplications
    fn multilinear_eval(&self, column: &[Monomial], tensor: &[RingElement<F>]) 
        -> Result<RingElement<F>, String> {
        let d = self.ring.degree;
        let mut result_coeffs = vec![F::zero(); d];
        
        for (i, monomial) in column.iter().enumerate() {
            if i >= tensor.len() {
                return Err(format!("Tensor index {} out of bounds", i));
            }
            
            match monomial {
                Monomial::Zero => continue,
                Monomial::Positive(exp) => {
                    // Add tensor[i] rotated by exp
                    let coeff = tensor[i].coeffs[0]; // Constant term
                    result_coeffs[*exp] = result_coeffs[*exp].add(&coeff);
                }
                Monomial::Negative(exp) => {
                    // Subtract tensor[i] rotated by exp
                    let coeff = tensor[i].coeffs[0]; // Constant term
                    result_coeffs[*exp] = result_coeffs[*exp].sub(&coeff);
                }
            }
        }
        
        Ok(RingElement::from_coeffs(result_coeffs))
    }
    
    /// Get number of rows (log scale)
    fn log_n(&self) -> usize {
        (self.matrix.rows() as f64).log2().ceil() as usize
    }
}

impl<F: Field> MonomialSetCheckVerifier<F> {
    /// Create new monomial set check verifier
    pub fn new(
        commitment: BaseCommitment<F>,
        challenge_set_size: usize,
        ring: CyclotomicRing<F>,
        n: usize,
        m: usize,
    ) -> Self {
        Self {
            commitment,
            challenge_set_size,
            ring,
            n,
            m,
        }
    }
    
    /// Verify monomial set check proof
    /// 
    /// Steps:
    /// 1. Regenerate challenges c, β from transcript
    /// 2. Verify degree-3 sumcheck proof
    /// 3. Verify final check (Equation 12)
    /// 4. Return reduced instance
    pub fn verify(&self, proof: &MonomialSetCheckProof<F>, transcript: &mut Transcript) 
        -> Result<MonomialSetCheckInstance<F>, String> {
        // Step 1: Regenerate challenges
        let log_n = (self.n as f64).log2().ceil() as usize;
        let c = self.regenerate_challenge_vector(transcript, "monomial_c", log_n)?;
        let beta = transcript.challenge_ring_element("monomial_beta", &self.ring);
        
        // Step 2: Verify sumcheck
        let alpha = transcript.challenge_ring_element("sumcheck_combiner", &self.ring);
        let mut verifier = SumcheckVerifier::new(3, self.ring.clone());
        let r = verifier.verify(&proof.sumcheck_proof, transcript)?;
        
        // Step 3: Verify final check (Equation 12)
        self.verify_final_check(&c, &r, &beta, &alpha, &proof.evaluations, &proof.sumcheck_proof)?;
        
        // Step 4: Verify evaluations in transcript
        for (j, eval) in proof.evaluations.iter().enumerate() {
            transcript.append_ring_element(&format!("eval_{}", j), eval);
        }
        
        // Return reduced instance
        Ok(MonomialSetCheckInstance {
            commitment: self.commitment.clone(),
            challenge_r: r,
            evaluations: proof.evaluations.clone(),
        })
    }
    
    /// Regenerate challenge vector from transcript
    fn regenerate_challenge_vector(&self, transcript: &mut Transcript, label: &str, length: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        for i in 0..length {
            let challenge = transcript.challenge_ring_element(&format!("{}_{}", label, i), &self.ring);
            challenges.push(challenge);
        }
        Ok(challenges)
    }
    
    /// Verify final check (Equation 12)
    /// 
    /// Check: eq(c, r) · Σ_j α^j · (ev_{e_j}(β)² - ev_{e_j}(β²)) = claimed_value
    fn verify_final_check(
        &self,
        c: &[RingElement<F>],
        r: &[RingElement<F>],
        beta: &RingElement<F>],
        alpha: &RingElement<F>],
        evaluations: &[RingElement<F>],
        sumcheck_proof: &SumcheckProof<F>,
    ) -> Result<(), String> {
        // Compute eq(c, r)
        let eq_c_r = self.compute_eq(c, r)?;
        
        // Compute Σ_j α^j · (ev_{e_j}(β)² - ev_{e_j}(β²))
        let mut sum = self.ring.zero();
        let mut alpha_power = self.ring.one();
        let beta_squared = self.ring.mul(beta, beta);
        
        for e_j in evaluations {
            // Evaluate e_j at β and β²
            let eval_beta = self.evaluate_at_point(e_j, beta)?;
            let eval_beta_sq = self.evaluate_at_point(e_j, &beta_squared)?;
            
            // Compute ev_{e_j}(β)² - ev_{e_j}(β²)
            let eval_beta_squared = self.ring.mul(&eval_beta, &eval_beta);
            let diff = self.ring.sub(&eval_beta_squared, &eval_beta_sq);
            
            // Add α^j · diff to sum
            let scaled = self.ring.mul(&alpha_power, &diff);
            sum = self.ring.add(&sum, &scaled);
            
            alpha_power = self.ring.mul(&alpha_power, alpha);
        }
        
        // Compute expected = eq(c, r) · sum
        let expected = self.ring.mul(&eq_c_r, &sum);
        
        // Get claimed value from sumcheck
        let claimed = sumcheck_proof.claimed_value.clone();
        
        // Verify equality
        if expected.coeffs != claimed.coeffs {
            return Err("Final check failed: expected != claimed".to_string());
        }
        
        Ok(())
    }
    
    /// Compute equality polynomial eq(b, x) = ∏_{i∈[k]} ((1-bᵢ)(1-xᵢ) + bᵢxᵢ)
    fn compute_eq(&self, b: &[RingElement<F>], x: &[RingElement<F>]) 
        -> Result<RingElement<F>, String> {
        if b.len() != x.len() {
            return Err(format!("Length mismatch: b={}, x={}", b.len(), x.len()));
        }
        
        let mut result = self.ring.one();
        
        for (b_i, x_i) in b.iter().zip(x.iter()) {
            // Compute (1-bᵢ)(1-xᵢ) + bᵢxᵢ
            let one = self.ring.one();
            let one_minus_b = self.ring.sub(&one, b_i);
            let one_minus_x = self.ring.sub(&one, x_i);
            let term1 = self.ring.mul(&one_minus_b, &one_minus_x);
            let term2 = self.ring.mul(b_i, x_i);
            let factor = self.ring.add(&term1, &term2);
            
            result = self.ring.mul(&result, &factor);
        }
        
        Ok(result)
    }
    
    /// Evaluate polynomial at point
    fn evaluate_at_point(&self, poly: &RingElement<F>, point: &RingElement<F>) 
        -> Result<RingElement<F>, String> {
        // For ring elements, evaluation is polynomial evaluation
        // p(X) evaluated at β
        let mut result = self.ring.zero();
        let mut point_power = self.ring.one();
        
        for coeff in &poly.coeffs {
            let term = self.ring.scalar_mul(&point_power, coeff);
            result = self.ring.add(&result, &term);
            point_power = self.ring.mul(&point_power, point);
        }
        
        Ok(result)
    }
}

/// Sumcheck claim for monomial set check
#[derive(Clone, Debug)]
pub struct SumcheckClaim<F: Field> {
    /// Challenge vector c
    pub c: Vec<RingElement<F>>,
    
    /// Evaluations at β
    pub m_j: Vec<RingElement<F>>,
    
    /// Evaluations at β²
    pub m_prime_j: Vec<RingElement<F>>,
    
    /// Ring
    pub ring: CyclotomicRing<F>,
}

impl<F: Field> SumcheckClaim<F> {
    /// Create new sumcheck claim
    pub fn new(
        c: Vec<RingElement<F>>,
        m_j: Vec<RingElement<F>>,
        m_prime_j: Vec<RingElement<F>>,
        ring: CyclotomicRing<F>,
    ) -> Self {
        Self { c, m_j, m_prime_j, ring }
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &RingElement<F>, ring: &CyclotomicRing<F>) 
        -> Result<Self, String> {
        let m_j: Vec<_> = self.m_j.iter()
            .map(|x| ring.mul(x, scalar))
            .collect();
        
        let m_prime_j: Vec<_> = self.m_prime_j.iter()
            .map(|x| ring.mul(x, scalar))
            .collect();
        
        Ok(Self {
            c: self.c.clone(),
            m_j,
            m_prime_j,
            ring: ring.clone(),
        })
    }
    
    /// Addition
    pub fn add(&self, other: &Self, ring: &CyclotomicRing<F>) 
        -> Result<Self, String> {
        if self.m_j.len() != other.m_j.len() {
            return Err("Dimension mismatch in claim addition".to_string());
        }
        
        let m_j: Vec<_> = self.m_j.iter()
            .zip(other.m_j.iter())
            .map(|(a, b)| ring.add(a, b))
            .collect();
        
        let m_prime_j: Vec<_> = self.m_prime_j.iter()
            .zip(other.m_prime_j.iter())
            .map(|(a, b)| ring.add(a, b))
            .collect();
        
        Ok(Self {
            c: self.c.clone(),
            m_j,
            m_prime_j,
            ring: ring.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_monomial_evaluation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let matrix = MonomialMatrix::identity(4, &ring);
        let dcom = DoubleCommitment::commit_vector(&AjtaiCommitment::new(ring.clone(), 4, 4, 1<<20, [0u8;32]), &vec![ring.one(); 4]).unwrap();
        
        let prover = MonomialSetCheckProver::new(matrix, dcom, 256, ring.clone());
        
        let beta = ring.one();
        let monomial = Monomial::Positive(2);
        
        let eval = prover.evaluate_monomial(&monomial, &beta).unwrap();
        // β^2 where β = 1 should be 1
        assert_eq!(eval.coeffs[0], GoldilocksField::one());
    }
    
    #[test]
    fn test_tensor_product() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let matrix = MonomialMatrix::identity(4, &ring);
        let dcom = DoubleCommitment::commit_vector(&AjtaiCommitment::new(ring.clone(), 4, 4, 1<<20, [0u8;32]), &vec![ring.one(); 4]).unwrap();
        
        let prover = MonomialSetCheckProver::new(matrix, dcom, 256, ring.clone());
        
        let r = vec![ring.one(), ring.zero()];
        let tensor = prover.compute_tensor_product(&r).unwrap();
        
        // tensor(1, 0) = [(1-1)(1-0), (1-1)·0, 1·(1-0), 1·0] = [0, 0, 1, 0]
        assert_eq!(tensor.len(), 4);
    }
}
