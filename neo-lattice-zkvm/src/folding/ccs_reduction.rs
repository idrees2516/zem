// CCS to Evaluation Claims Reduction
// Implements NEO-8 and NEO-9 requirements for reducing CCS to evaluation claims

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::commitment::Commitment;
use super::ccs::{CCSStructure, CCSInstance, MatrixMLE};
use super::sumcheck::{SumCheckProof, run_sumcheck};
use super::evaluation_claim::EvaluationClaim;

/// CCS polynomial g(x) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(x)
pub struct CCSPolynomial<F: Field> {
    /// CCS structure
    structure: CCSStructure<F>,
    /// Full witness z = (1, x, w)
    witness: Vec<F>,
    /// Matrix-vector products vⱼ = Mⱼz cached as MLEs
    matrix_vector_mles: Vec<MultilinearPolynomial<F>>,
}

impl<F: Field> CCSPolynomial<F> {
    /// Create CCS polynomial from instance
    pub fn new(instance: &CCSInstance<F>) -> Self {
        let witness = instance.full_witness();
        
        // Compute matrix-vector products vⱼ = Mⱼz for j ∈ [t]
        let mut matrix_vector_mles = Vec::with_capacity(instance.structure.t);
        
        for matrix in &instance.structure.matrices {
            let v = matrix.mul_vector(&witness);
            
            // Pad to power of 2 for MLE
            let mut v_padded = v;
            let target_len = v_padded.len().next_power_of_two();
            v_padded.resize(target_len, F::zero());
            
            matrix_vector_mles.push(MultilinearPolynomial::new(v_padded));
        }
        
        Self {
            structure: instance.structure.clone(),
            witness,
            matrix_vector_mles,
        }
    }

    /// Evaluate g(x) at point x
    /// g(x) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(x)
    pub fn evaluate(&self, point: &[F]) -> F {
        let mut result = F::zero();
        
        // For each term i in the sum
        for i in 0..self.structure.q {
            // Compute product: ∏_{j∈Sᵢ} (Mⱼz)~(x)
            let mut product = F::one();
            
            for &j in &self.structure.selectors[i] {
                let eval = self.matrix_vector_mles[j].evaluate(point);
                product = product.mul(&eval);
            }
            
            // Add weighted term: cᵢ · product
            let term = self.structure.constants[i].mul(&product);
            result = result.add(&term);
        }
        
        result
    }

    /// Compute sum over Boolean hypercube: Σ_{x∈{0,1}^ℓ} g(x)
    /// For valid CCS instance, this should equal 0
    pub fn compute_sum(&self) -> F {
        let num_vars = self.matrix_vector_mles[0].num_vars();
        let num_points = 1 << num_vars;
        
        let mut sum = F::zero();
        
        for assignment in 0..num_points {
            // Convert assignment to Boolean point
            let mut point = Vec::with_capacity(num_vars);
            for j in 0..num_vars {
                let bit = (assignment >> j) & 1;
                point.push(F::from_u64(bit as u64));
            }
            
            sum = sum.add(&self.evaluate(&point));
        }
        
        sum
    }

    /// Get number of variables
    pub fn num_vars(&self) -> usize {
        self.matrix_vector_mles[0].num_vars()
    }

    /// Get maximum degree (determined by maximum selector size)
    pub fn max_degree(&self) -> usize {
        self.structure.selectors
            .iter()
            .map(|s| s.len())
            .max()
            .unwrap_or(0)
    }
}

/// Reduction from CCS to evaluation claims
pub struct CCSReduction<F: Field> {
    /// CCS instance
    instance: CCSInstance<F>,
    /// CCS polynomial
    polynomial: CCSPolynomial<F>,
}

impl<F: Field> CCSReduction<F> {
    /// Create reduction from CCS instance
    pub fn new(instance: CCSInstance<F>) -> Self {
        let polynomial = CCSPolynomial::new(&instance);
        
        Self {
            instance,
            polynomial,
        }
    }

    /// Run sum-check protocol to reduce CCS to evaluation claims
    /// Returns: (sum-check proof, evaluation point r, evaluation claims)
    pub fn reduce_to_evaluation_claims(
        &self,
        challenge_fn: impl Fn(usize) -> F,
    ) -> Result<(SumCheckProof<F>, Vec<F>, Vec<EvaluationClaim<F>>), String> {
        // Verify CCS is satisfied (sum should be 0)
        let claimed_sum = F::zero();
        
        // Run sum-check protocol
        let num_vars = self.polynomial.num_vars();
        let max_degree = self.polynomial.max_degree();
        
        let eval_fn = |point: &[F]| self.polynomial.evaluate(point);
        
        let proof = run_sumcheck(
            num_vars,
            max_degree,
            claimed_sum,
            eval_fn,
            &challenge_fn,
        )?;
        
        // Extract evaluation point r from challenges
        let r: Vec<F> = proof.rounds.iter().map(|round| round.challenge).collect();
        
        // Generate evaluation claims for each matrix-vector product
        let claims = self.generate_matrix_vector_claims(&r)?;
        
        Ok((proof, r, claims))
    }

    /// Generate evaluation claims for matrix-vector products
    /// For each j ∈ [t], create claim: (C, r, vⱼ) where vⱼ = (Mⱼz)~(r)
    fn generate_matrix_vector_claims(
        &self,
        r: &[F],
    ) -> Result<Vec<EvaluationClaim<F>>, String> {
        let mut claims = Vec::with_capacity(self.instance.structure.t);
        
        // Get commitment to witness from instance
        // In production, this would be precomputed during setup phase
        let commitment = self.compute_witness_commitment()?;
        
        for j in 0..self.instance.structure.t {
            // Evaluate (Mⱼz)~(r)
            let value = self.polynomial.matrix_vector_mles[j].evaluate(r);
            
            let claim = EvaluationClaim::new(
                commitment.clone(),
                r.to_vec(),
                value,
            );
            
            claims.push(claim);
        }
        
        Ok(claims)
    }

    /// Reduce matrix-vector evaluation to witness evaluation
    /// Express (Mz)~(r) as inner product: ⟨z, M̃(r)⟩
    pub fn reduce_matrix_vector_to_witness(
        &self,
        matrix_idx: usize,
        r: &[F],
    ) -> Result<(Vec<F>, F), String> {
        if matrix_idx >= self.instance.structure.t {
            return Err("Matrix index out of bounds".to_string());
        }

        let matrix = &self.instance.structure.matrices[matrix_idx];
        let matrix_mle = matrix.multilinear_extension();
        
        // Compute column MLEs: M̃ⱼ(r) for j ∈ [n]
        let n = self.instance.structure.n;
        let log_m = (self.instance.structure.m as f64).log2().ceil() as usize;
        let log_n = (n as f64).log2().ceil() as usize;
        
        let mut r_prime = Vec::with_capacity(n);
        
        for j in 0..n {
            // Convert column index to binary representation
            let mut y = Vec::with_capacity(log_n);
            let mut idx = j;
            for _ in 0..log_n {
                y.push(F::from_u64((idx & 1) as u64));
                idx >>= 1;
            }
            
            // Evaluate M̃(r, y) to get column MLE at r
            let mut full_point = r.to_vec();
            full_point.extend_from_slice(&y);
            
            // Pad to correct length if needed
            while full_point.len() < log_m + log_n {
                full_point.push(F::zero());
            }
            
            let col_eval = matrix_mle.evaluate(&full_point[..log_m], &full_point[log_m..]);
            r_prime.push(col_eval);
        }
        
        // Compute claimed value: v = ⟨z, r'⟩
        let z = self.instance.full_witness();
        let mut value = F::zero();
        for (z_i, r_i) in z.iter().zip(r_prime.iter()) {
            value = value.add(&z_i.mul(r_i));
        }
        
        Ok((r_prime, value))
    }

    /// Verify consistency of evaluation claims
    /// Compute commitment to witness
    /// 
    /// In production, this would be precomputed during setup and stored.
    /// For now, we compute it on-demand using the Ajtai commitment scheme.
    fn compute_witness_commitment(&self) -> Result<Commitment<F>, String> {
        use crate::ring::CyclotomicRing;
        use crate::commitment::AjtaiCommitmentScheme;
        
        // Get ring parameters from global configuration
        let ring_degree = crate::config::get_ring_degree();
        let ring = CyclotomicRing::new(ring_degree);
        
        // Create commitment scheme with parameters from global configuration
        let kappa = crate::config::get_commitment_dimension();
        let witness_dim = (self.instance.witness.len() + ring_degree - 1) / ring_degree;
        let norm_bound = crate::config::get_norm_bound();
        
        let scheme = AjtaiCommitmentScheme::new(
            ring.clone(),
            kappa,
            witness_dim,
            norm_bound,
        );
        
        // Pack witness into ring elements
        let ring_witness = self.pack_witness_to_ring(&ring)?;
        
        // Compute commitment
        scheme.commit(&ring_witness)
    }
    
    /// Pack field witness into ring elements
    fn pack_witness_to_ring(&self, ring: &CyclotomicRing<F>) -> Result<Vec<crate::ring::RingElement<F>>, String> {
        use crate::ring::RingElement;
        
        let d = ring.degree();
        let witness = &self.instance.witness;
        let num_ring_elements = (witness.len() + d - 1) / d;
        
        let mut ring_witness = Vec::with_capacity(num_ring_elements);
        
        for i in 0..num_ring_elements {
            let start = i * d;
            let end = (start + d).min(witness.len());
            
            let mut coeffs = witness[start..end].to_vec();
            
            // Pad with zeros if needed
            while coeffs.len() < d {
                coeffs.push(F::zero());
            }
            
            ring_witness.push(RingElement::new(coeffs));
        }
        
        Ok(ring_witness)
    }

    /// Check that g(r) = Σᵢ cᵢ · ∏_{j∈Sᵢ} vⱼ
    pub fn verify_claim_consistency(
        &self,
        r: &[F],
        claimed_values: &[F],
    ) -> bool {
        if claimed_values.len() != self.instance.structure.t {
            return false;
        }

        // Compute g(r) directly
        let g_r = self.polynomial.evaluate(r);
        
        // Compute from claimed values: Σᵢ cᵢ · ∏_{j∈Sᵢ} vⱼ
        let mut computed = F::zero();
        
        for i in 0..self.instance.structure.q {
            let mut product = F::one();
            
            for &j in &self.instance.structure.selectors[i] {
                product = product.mul(&claimed_values[j]);
            }
            
            let term = self.instance.structure.constants[i].mul(&product);
            computed = computed.add(&term);
        }
        
        g_r == computed
    }
}

/// Optimized matrix MLE computation with caching
pub struct MatrixMLECache<F: Field> {
    /// Cached matrix MLEs
    cache: Vec<Option<Vec<F>>>,
    /// CCS structure
    structure: CCSStructure<F>,
}

impl<F: Field> MatrixMLECache<F> {
    /// Create new cache
    pub fn new(structure: CCSStructure<F>) -> Self {
        let cache = vec![None; structure.t];
        Self { cache, structure }
    }

    /// Get or compute matrix MLE at point r
    pub fn get_or_compute(&mut self, matrix_idx: usize, r: &[F]) -> Vec<F> {
        if let Some(ref cached) = self.cache[matrix_idx] {
            return cached.clone();
        }

        // Compute and cache
        let matrix = &self.structure.matrices[matrix_idx];
        let matrix_mle = matrix.multilinear_extension();
        
        let n = self.structure.n;
        let log_n = (n as f64).log2().ceil() as usize;
        let log_m = (self.structure.m as f64).log2().ceil() as usize;
        
        let mut result = Vec::with_capacity(n);
        
        for j in 0..n {
            let mut y = Vec::with_capacity(log_n);
            let mut idx = j;
            for _ in 0..log_n {
                y.push(F::from_u64((idx & 1) as u64));
                idx >>= 1;
            }
            
            let mut full_point = r.to_vec();
            full_point.extend_from_slice(&y);
            
            while full_point.len() < log_m + log_n {
                full_point.push(F::zero());
            }
            
            let eval = matrix_mle.evaluate(&full_point[..log_m], &full_point[log_m..]);
            result.push(eval);
        }
        
        self.cache[matrix_idx] = Some(result.clone());
        result
    }

    /// Clear cache
    pub fn clear(&mut self) {
        for entry in &mut self.cache {
            *entry = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::folding::ccs::SparseMatrix;

    #[test]
    fn test_ccs_polynomial_evaluation() {
        type F = GoldilocksField;
        
        // Create simple R1CS as CCS: x * x = x (for x = 1)
        let mut a = SparseMatrix::new(1, 3);
        a.add_entry(0, 1, F::one());
        
        let mut b = SparseMatrix::new(1, 3);
        b.add_entry(0, 1, F::one());
        
        let mut c = SparseMatrix::new(1, 3);
        c.add_entry(0, 1, F::one());
        
        let structure = CCSStructure::from_r1cs(1, 3, a, b, c).unwrap();
        let public_input = vec![F::one()];
        let witness = vec![];
        
        let instance = CCSInstance::new(structure, public_input, witness);
        let polynomial = CCSPolynomial::new(&instance);
        
        // Sum over Boolean hypercube should be 0 for valid instance
        let sum = polynomial.compute_sum();
        assert_eq!(sum, F::zero());
    }

    #[test]
    fn test_ccs_reduction() {
        type F = GoldilocksField;
        
        // Create simple R1CS
        let mut a = SparseMatrix::new(1, 3);
        a.add_entry(0, 1, F::one());
        
        let mut b = SparseMatrix::new(1, 3);
        b.add_entry(0, 1, F::one());
        
        let mut c = SparseMatrix::new(1, 3);
        c.add_entry(0, 1, F::one());
        
        let structure = CCSStructure::from_r1cs(1, 3, a, b, c).unwrap();
        let public_input = vec![F::one()];
        let witness = vec![];
        
        let instance = CCSInstance::new(structure, public_input, witness);
        let reduction = CCSReduction::new(instance);
        
        // Run reduction with deterministic challenges
        let challenge_fn = |round: usize| F::from_u64((round + 1) as u64);
        
        let result = reduction.reduce_to_evaluation_claims(challenge_fn);
        assert!(result.is_ok());
        
        let (proof, r, claims) = result.unwrap();
        assert_eq!(claims.len(), 3); // Three matrices in R1CS
    }

    #[test]
    fn test_matrix_mle_cache() {
        type F = GoldilocksField;
        
        let mut matrix = SparseMatrix::new(2, 2);
        matrix.add_entry(0, 0, F::from_u64(1));
        matrix.add_entry(1, 1, F::from_u64(2));
        
        let structure = CCSStructure::new(
            2, 2, 1, 1, 1,
            vec![matrix],
            vec![vec![0]],
            vec![F::one()],
        ).unwrap();
        
        let mut cache = MatrixMLECache::new(structure);
        
        let r = vec![F::zero()];
        let result1 = cache.get_or_compute(0, &r);
        let result2 = cache.get_or_compute(0, &r);
        
        // Should return same cached result
        assert_eq!(result1, result2);
    }
}
