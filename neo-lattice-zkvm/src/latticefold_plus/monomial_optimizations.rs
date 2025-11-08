// Optimizations for Monomial Set Check Protocol (Π_mon)
// Remark 4.2: Batching for multiple matrices
// Remark 4.3: Efficient monomial commitment

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::Commitment as BaseCommitment;
use crate::folding::transcript::Transcript;
use super::monomial::{Monomial, MonomialMatrix};
use super::monomial_check::{MonomialSetCheckProof, MonomialSetCheckProver, SumcheckClaim};
use super::double_commitment::DoubleCommitment;
use super::ajtai_commitment::AjtaiCommitment;

/// Batched monomial set check prover (Remark 4.2)
/// Combines all sumcheck statements via random linear combination
/// Runs single sumcheck for all matrices
pub struct BatchedMonomialSetCheckProver<F: Field> {
    /// Multiple monomial matrices to check
    matrices: Vec<MonomialMatrix>,
    
    /// Double commitments for each matrix
    double_commitments: Vec<DoubleCommitment<F>>,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
}

impl<F: Field> BatchedMonomialSetCheckProver<F> {
    /// Create new batched prover
    pub fn new(
        matrices: Vec<MonomialMatrix>,
        double_commitments: Vec<DoubleCommitment<F>>,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
    ) -> Result<Self, String> {
        if matrices.len() != double_commitments.len() {
            return Err("Number of matrices must match number of commitments".to_string());
        }
        
        if matrices.is_empty() {
            return Err("Must provide at least one matrix".to_string());
        }
        
        Ok(Self {
            matrices,
            double_commitments,
            ring,
            challenge_set_size,
        })
    }
    
    /// Run batched monomial set check protocol
    /// 
    /// Optimization: Combine all sumcheck statements via random linear combination
    /// Single sumcheck for all matrices instead of L separate sumchecks
    pub fn prove_batch(&mut self, transcript: &mut Transcript) 
        -> Result<Vec<MonomialSetCheckProof<F>>, String> {
        let num_matrices = self.matrices.len();
        
        // Get batch combiner challenge
        let batch_combiner = transcript.challenge_ring_element("batch_combiner", &self.ring);
        
        // Collect all sumcheck claims from all matrices
        let mut all_claims = Vec::new();
        let mut all_challenges_c = Vec::new();
        let mut all_challenges_beta = Vec::new();
        
        for (idx, matrix) in self.matrices.iter().enumerate() {
            // Generate challenges for this matrix
            let log_n = (matrix.rows() as f64).log2().ceil() as usize;
            let c = self.generate_challenge_vector(transcript, &format!("c_{}", idx), log_n)?;
            let beta = transcript.challenge_ring_element(&format!("beta_{}", idx), &self.ring);
            
            all_challenges_c.push(c.clone());
            all_challenges_beta.push(beta.clone());
            
            // Prepare sumcheck claims for this matrix
            let claims = self.prepare_sumcheck_claims_for_matrix(matrix, &c, &beta)?;
            
            // Weight by batch_combiner^idx
            let weight = self.power_ring_element(&batch_combiner, idx)?;
            
            for claim in claims {
                let weighted_claim = claim.scalar_mul(&weight, &self.ring)?;
                all_claims.push(weighted_claim);
            }
        }
        
        // Run single sumcheck for all batched claims
        let combined_claim = self.combine_claims(all_claims)?;
        let sumcheck_proof = self.run_sumcheck(combined_claim, transcript)?;
        
        // Compute evaluations for each matrix
        let r = sumcheck_proof.final_challenge.clone();
        let mut proofs = Vec::new();
        
        for matrix in &self.matrices {
            let evaluations = self.compute_evaluations(matrix, &r)?;
            
            proofs.push(MonomialSetCheckProof {
                sumcheck_proof: sumcheck_proof.clone(),
                evaluations,
            });
        }
        
        Ok(proofs)
    }
    
    /// Generate challenge vector from transcript
    fn generate_challenge_vector(&self, transcript: &mut Transcript, label: &str, length: usize) 
        -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        for i in 0..length {
            let challenge = transcript.challenge_ring_element(&format!("{}_{}", label, i), &self.ring);
            challenges.push(challenge);
        }
        Ok(challenges)
    }
    
    /// Prepare sumcheck claims for a single matrix
    fn prepare_sumcheck_claims_for_matrix(
        &self,
        matrix: &MonomialMatrix,
        c: &[RingElement<F>],
        beta: &RingElement<F>,
    ) -> Result<Vec<SumcheckClaim<F>>, String> {
        let m = matrix.cols();
        let mut claims = Vec::with_capacity(m);
        
        for j in 0..m {
            let m_j = self.compute_evaluations_at_beta(matrix, j, beta)?;
            let beta_squared = self.ring.mul(beta, beta);
            let m_prime_j = self.compute_evaluations_at_beta(matrix, j, &beta_squared)?;
            
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
    fn compute_evaluations_at_beta(
        &self,
        matrix: &MonomialMatrix,
        col: usize,
        beta: &RingElement<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let n = matrix.rows();
        let mut evaluations = Vec::with_capacity(n);
        
        for row in 0..n {
            let monomial = matrix.get(row, col)
                .ok_or_else(|| format!("Invalid matrix index ({}, {})", row, col))?;
            
            let eval = self.evaluate_monomial(monomial, beta)?;
            evaluations.push(eval);
        }
        
        Ok(evaluations)
    }
    
    /// Evaluate monomial at point
    fn evaluate_monomial(&self, monomial: &Monomial, beta: &RingElement<F>) 
        -> Result<RingElement<F>, String> {
        match monomial {
            Monomial::Zero => Ok(self.ring.zero()),
            Monomial::Positive(exp) => self.power_ring_element(beta, *exp),
            Monomial::Negative(exp) => {
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
    
    /// Combine multiple claims into one
    fn combine_claims(&self, claims: Vec<SumcheckClaim<F>>) 
        -> Result<SumcheckClaim<F>, String> {
        if claims.is_empty() {
            return Err("Cannot combine empty claims".to_string());
        }
        
        // All claims are already weighted, just sum them
        let mut combined = claims[0].clone();
        
        for claim in claims.iter().skip(1) {
            combined = combined.add(claim, &self.ring)?;
        }
        
        Ok(combined)
    }
    
    /// Run sumcheck protocol
    fn run_sumcheck(&mut self, claim: SumcheckClaim<F>, transcript: &mut Transcript) 
        -> Result<crate::folding::sumcheck::SumcheckProof<F>, String> {
        use crate::folding::sumcheck::SumcheckProver;
        
        let mut prover = SumcheckProver::new(claim, 3, self.ring.clone());
        prover.prove(transcript)
    }
    
    /// Compute evaluations for a matrix
    fn compute_evaluations(&self, matrix: &MonomialMatrix, r: &[RingElement<F>]) 
        -> Result<Vec<RingElement<F>>, String> {
        let m = matrix.cols();
        let tensor_r = self.compute_tensor_product(r)?;
        
        let mut evaluations = Vec::with_capacity(m);
        
        for j in 0..m {
            let column = matrix.column(j);
            let eval = self.multilinear_eval(&column, &tensor_r)?;
            evaluations.push(eval);
        }
        
        Ok(evaluations)
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
    
    /// Compute multilinear evaluation (optimized for monomials)
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
                    let coeff = tensor[i].coeffs[0];
                    result_coeffs[*exp] = result_coeffs[*exp].add(&coeff);
                }
                Monomial::Negative(exp) => {
                    let coeff = tensor[i].coeffs[0];
                    result_coeffs[*exp] = result_coeffs[*exp].sub(&coeff);
                }
            }
        }
        
        Ok(RingElement::from_coeffs(result_coeffs))
    }
}


/// Efficient monomial commitment (Remark 4.3)
/// Optimizes com(M) to use only Rq-additions instead of multiplications
/// Achieves O(nκm) Rq-additions = nκdm Zq-additions
pub struct EfficientMonomialCommitment<F: Field> {
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
    
    /// Ring
    ring: CyclotomicRing<F>,
}

impl<F: Field> EfficientMonomialCommitment<F> {
    /// Create new efficient monomial commitment
    pub fn new(commitment_key: AjtaiCommitment<F>, ring: CyclotomicRing<F>) -> Self {
        Self {
            commitment_key,
            ring,
        }
    }
    
    /// Commit to monomial matrix efficiently
    /// 
    /// Optimization: com(M_{*,j}) = A·M_{*,j} is sum of A's columns (after rotation/sign flip)
    /// Only requires nκm Rq-additions instead of Rq-multiplications
    /// 
    /// For m ≈ d = 64, q ≈ 2^128:
    /// - Monomial commitment: ≈ nκm Rq-additions = nκdm Zq-additions (parallelizable)
    /// - Regular commitment: nκ Rq-multiplications = Ω(nκd log d) Zq-multiplications
    /// - Speedup: (d log d) / m ≈ 6x for typical parameters
    pub fn commit_efficient(&self, matrix: &MonomialMatrix) 
        -> Result<BaseCommitment<F>, String> {
        let n = matrix.rows();
        let m = matrix.cols();
        let kappa = self.commitment_key.kappa();
        
        // Result will be κ × m matrix of ring elements
        let mut result = vec![vec![self.ring.zero(); m]; kappa];
        
        for j in 0..m {
            for i in 0..n {
                let monomial = matrix.get(i, j)
                    .ok_or_else(|| format!("Invalid matrix index ({}, {})", i, j))?;
                
                // Get column i of commitment matrix A
                let a_col = self.commitment_key.get_column(i)?;
                
                // Apply monomial operation to column
                match monomial {
                    Monomial::Zero => {
                        // Zero monomial: no contribution
                        continue;
                    }
                    Monomial::Positive(exp) => {
                        // X^exp: rotate column left by exp positions
                        for k in 0..kappa {
                            let rotated = self.rotate_ring_element(&a_col[k], *exp);
                            result[k][j] = self.ring.add(&result[k][j], &rotated);
                        }
                    }
                    Monomial::Negative(exp) => {
                        // -X^exp: rotate and negate
                        for k in 0..kappa {
                            let rotated = self.rotate_ring_element(&a_col[k], *exp);
                            let negated = self.ring.neg(&rotated);
                            result[k][j] = self.ring.add(&result[k][j], &negated);
                        }
                    }
                }
            }
        }
        
        // Convert to commitment
        Ok(BaseCommitment::from_matrix(result))
    }
    
    /// Rotate ring element left by exp positions
    /// X^exp * a(X) rotates coefficients
    fn rotate_ring_element(&self, elem: &RingElement<F>, exp: usize) -> RingElement<F> {
        let d = self.ring.degree;
        let mut new_coeffs = vec![F::zero(); d];
        
        for i in 0..d {
            let new_idx = (i + exp) % d;
            if new_idx < d - exp {
                // No wraparound
                new_coeffs[new_idx] = elem.coeffs[i];
            } else {
                // Wraparound: multiply by -1 due to X^d = -1
                new_coeffs[new_idx] = elem.coeffs[i].neg();
            }
        }
        
        RingElement::from_coeffs(new_coeffs)
    }
    
    /// Analyze commitment cost
    pub fn commitment_cost_analysis(&self, matrix: &MonomialMatrix) -> CommitmentCost {
        let n = matrix.rows();
        let kappa = self.commitment_key.kappa();
        let m = matrix.cols();
        let d = self.ring.degree;
        
        // Monomial commitment cost
        let monomial_additions = n * kappa * d * m;
        
        // Regular commitment cost (using NTT)
        let regular_multiplications = n * kappa * d * ((d as f64).log2() as usize);
        
        // Speedup factor
        let speedup_factor = (regular_multiplications as f64) / (monomial_additions as f64);
        
        CommitmentCost {
            monomial_additions,
            regular_multiplications,
            speedup_factor,
        }
    }
}

/// Commitment cost analysis
#[derive(Debug, Clone)]
pub struct CommitmentCost {
    /// Number of Zq-additions for monomial commitment
    pub monomial_additions: usize,
    
    /// Number of Zq-multiplications for regular commitment
    pub regular_multiplications: usize,
    
    /// Speedup factor
    pub speedup_factor: f64,
}

impl CommitmentCost {
    /// Print cost analysis
    pub fn print_analysis(&self) {
        println!("Commitment Cost Analysis:");
        println!("  Monomial additions: {}", self.monomial_additions);
        println!("  Regular multiplications: {}", self.regular_multiplications);
        println!("  Speedup factor: {:.2}x", self.speedup_factor);
    }
}

/// Parallel monomial commitment
/// Leverages parallelism for even faster commitment
pub struct ParallelMonomialCommitment<F: Field> {
    /// Base efficient commitment
    base: EfficientMonomialCommitment<F>,
    
    /// Number of threads
    num_threads: usize,
}

impl<F: Field> ParallelMonomialCommitment<F> {
    /// Create new parallel monomial commitment
    pub fn new(
        commitment_key: AjtaiCommitment<F>,
        ring: CyclotomicRing<F>,
        num_threads: usize,
    ) -> Self {
        let base = EfficientMonomialCommitment::new(commitment_key, ring);
        
        Self {
            base,
            num_threads,
        }
    }
    
    /// Commit to monomial matrix in parallel
    /// 
    /// Parallelization strategy:
    /// - Split columns across threads
    /// - Each thread computes commitment for subset of columns
    /// - Combine results
    pub fn commit_parallel(&self, matrix: &MonomialMatrix) 
        -> Result<BaseCommitment<F>, String> {
        // Parallel implementation using rayon for multi-threaded commitment
        use rayon::prelude::*;
        
        let kappa = self.base.commitment_key.kappa();
        let cols = matrix.cols();
        
        // Process each row of the commitment matrix in parallel
        let result_values: Result<Vec<Vec<RingElement<F>>>, String> = (0..kappa)
            .into_par_iter()
            .map(|k| {
                let mut row_result = vec![RingElement::from_coeffs(vec![F::zero(); self.base.ring.degree]); cols];
                
                for j in 0..cols {
                    for i in 0..matrix.rows() {
                        match &matrix.entries[i][j] {
                            Monomial::Zero => continue,
                            Monomial::Positive(exp) => {
                                let a_col = self.base.commitment_key.get_column(i);
                                let rotated = a_col.rotate_left(*exp);
                                row_result[j] = self.base.ring.add(&row_result[j], &rotated);
                            }
                            Monomial::Negative(exp) => {
                                let a_col = self.base.commitment_key.get_column(i);
                                let rotated = a_col.rotate_left(*exp);
                                row_result[j] = self.base.ring.sub(&row_result[j], &rotated);
                            }
                        }
                    }
                }
                
                Ok(row_result)
            })
            .collect();
        
        let values = result_values?;
        
        Ok(BaseCommitment {
            values: values.into_iter().flatten().collect(),
            opening_info: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_batched_monomial_check() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create two monomial matrices
        let matrix1 = MonomialMatrix::identity(4, &ring);
        let matrix2 = MonomialMatrix::identity(4, &ring);
        
        let matrices = vec![matrix1, matrix2];
        let dcom1 = DoubleCommitment::default();
        let dcom2 = DoubleCommitment::default();
        let double_commitments = vec![dcom1, dcom2];
        
        let batched_prover = BatchedMonomialSetCheckProver::new(
            matrices,
            double_commitments,
            ring,
            256,
        );
        
        assert!(batched_prover.is_ok());
    }
    
    #[test]
    fn test_efficient_commitment_cost() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let commitment_key = AjtaiCommitment::new(ring.clone(), 4, 16, 1<<20, [0u8; 32]);
        
        let efficient_commit = EfficientMonomialCommitment::new(commitment_key, ring.clone());
        
        let matrix = MonomialMatrix::identity(16, &ring);
        let cost = efficient_commit.commitment_cost_analysis(&matrix);
        
        // Verify speedup
        assert!(cost.speedup_factor > 1.0);
        cost.print_analysis();
    }
    
    #[test]
    fn test_rotation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let commitment_key = AjtaiCommitment::new(ring.clone(), 4, 16, 1<<20, [0u8; 32]);
        
        let efficient_commit = EfficientMonomialCommitment::new(commitment_key, ring.clone());
        
        // Create ring element [1, 2, 3, 0, 0, ...]
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::one();
        coeffs[1] = GoldilocksField::from_u64(2);
        coeffs[2] = GoldilocksField::from_u64(3);
        let elem = RingElement::from_coeffs(coeffs);
        
        // Rotate by 1
        let rotated = efficient_commit.rotate_ring_element(&elem, 1);
        
        // Should be [0, 1, 2, 3, 0, ...]
        assert_eq!(rotated.coeffs[0], GoldilocksField::zero());
        assert_eq!(rotated.coeffs[1], GoldilocksField::one());
        assert_eq!(rotated.coeffs[2], GoldilocksField::from_u64(2));
        assert_eq!(rotated.coeffs[3], GoldilocksField::from_u64(3));
    }
}

