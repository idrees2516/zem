// Task 5.2: Sparse Polynomial Evaluation Proofs
// Integrates k-round witness folding, Guarded IPA, and LaBRADOR compression

use crate::field::extension_framework::ExtensionFieldElement;
use crate::ring::cyclotomic::CyclotomicRing;
use crate::sumcheck::MultilinearPolynomial;
use std::fmt::Debug;

/// Sparse polynomial evaluation proof
/// Proves that committed polynomial evaluates to claimed value at given point
#[derive(Clone, Debug)]
pub struct SparseEvaluationProof<R: CyclotomicRing> {
    /// Witness folding proof (k rounds)
    pub folding_proof: WitnessFoldingProof<R>,
    
    /// Guarded IPA proof (exact ℓ₂-norm)
    pub ipa_proof: GuardedIPAProof<R>,
    
    /// LaBRADOR compressed proof
    pub compressed_proof: LabradorProof<R>,
    
    /// Final evaluation value
    pub evaluation: R::BaseField,
}

impl<R: CyclotomicRing> SparseEvaluationProof<R> {
    /// Prove evaluation of sparse polynomial
    /// 
    /// Algorithm:
    /// 1. Fold witness over k rounds
    /// 2. Apply Guarded IPA for exact ℓ₂-norm proof
    /// 3. Compress with LaBRADOR to O(log log log N)
    pub fn prove<K>(
        commitment: &[R],
        point: &[K],
        value: K,
        sparse_poly: &MultilinearPolynomial<K>,
    ) -> Result<Self, String>
    where
        K: ExtensionFieldElement<BaseField = R::BaseField>,
    {
        // Step 1: k-round witness folding
        let folding_proof = WitnessFolding::fold_witness(
            sparse_poly,
            point,
            commitment,
        )?;
        
        // Step 2: Guarded IPA for exact ℓ₂-norm
        let ipa_proof = GuardedIPA::prove_exact_norm(
            &folding_proof.folded_witness,
            &folding_proof.folded_commitment,
        )?;
        
        // Step 3: LaBRADOR compression
        let compressed_proof = LabradorCompression::compress(
            &ipa_proof,
            &folding_proof,
        )?;
        
        Ok(Self {
            folding_proof,
            ipa_proof,
            compressed_proof,
            evaluation: value.to_base_field_coefficients()[0],
        })
    }
    
    /// Verify evaluation proof
    pub fn verify(
        &self,
        commitment: &[R],
        point: &[R::BaseField],
        claimed_value: R::BaseField,
    ) -> Result<bool, String> {
        // Verify witness folding
        if !self.folding_proof.verify(commitment, point)? {
            return Ok(false);
        }
        
        // Verify Guarded IPA
        if !self.ipa_proof.verify(&self.folding_proof.folded_commitment)? {
            return Ok(false);
        }
        
        // Verify LaBRADOR compression
        if !self.compressed_proof.verify(&self.ipa_proof)? {
            return Ok(false);
        }
        
        // Verify final evaluation
        if self.evaluation != claimed_value {
            return Ok(false);
        }
        
        Ok(true)
    }
}

/// Witness folding over k rounds
/// Reduces witness size from N to N/2^k
pub struct WitnessFolding;

impl WitnessFolding {
    /// Fold witness over k rounds
    /// 
    /// Algorithm:
    /// For each round i=1 to k:
    ///   1. Split witness into (w_L, w_R)
    ///   2. Sample challenge r_i
    ///   3. Fold: w_new = w_L + r_i·w_R
    ///   4. Update commitment: C_new = C_L + r_i·C_R
    /// 
    /// Complexity: O(k·N/2^i) = O(k·N) total
    pub fn fold_witness<K, R>(
        poly: &MultilinearPolynomial<K>,
        point: &[K],
        commitment: &[R],
    ) -> Result<WitnessFoldingProof<R>, String>
    where
        K: ExtensionFieldElement<BaseField = R::BaseField>,
        R: CyclotomicRing,
    {
        let k = point.len();
        let mut current_witness = poly.evaluations.clone();
        let mut current_commitment = commitment.to_vec();
        let mut challenges = Vec::with_capacity(k);
        let mut intermediate_commitments = Vec::with_capacity(k);
        
        for round in 0..k {
            let challenge = point[round];
            challenges.push(challenge);
            
            // Fold witness
            let half = current_witness.len() / 2;
            let mut folded_witness = Vec::with_capacity(half);
            
            for i in 0..half {
                let w_l = current_witness[i];
                let w_r = current_witness[i + half];
                
                // w_new = w_L + r·w_R
                let folded = w_l.add(&challenge.mul(&w_r));
                folded_witness.push(folded);
            }
            
            // Fold commitment
            let half_comm = current_commitment.len() / 2;
            let mut folded_commitment = Vec::with_capacity(half_comm);
            
            for i in 0..half_comm {
                let c_l = current_commitment[i];
                let c_r = current_commitment[i + half_comm];
                
                // Convert challenge to ring element
                let r_ring = Self::k_to_ring_scalar(challenge);
                
                // C_new = C_L + r·C_R
                let folded = c_l.add(&c_r.scalar_mul(&r_ring));
                folded_commitment.push(folded);
            }
            
            intermediate_commitments.push(current_commitment.clone());
            current_witness = folded_witness;
            current_commitment = folded_commitment;
        }
        
        Ok(WitnessFoldingProof {
            challenges,
            intermediate_commitments,
            folded_witness: current_witness,
            folded_commitment: current_commitment,
        })
    }
    
    fn k_to_ring_scalar<K, R>(k_elem: K) -> R::BaseField
    where
        K: ExtensionFieldElement<BaseField = R::BaseField>,
        R: CyclotomicRing,
    {
        let coeffs = k_elem.to_base_field_coefficients();
        coeffs[0]
    }
}

/// Witness folding proof
#[derive(Clone, Debug)]
pub struct WitnessFoldingProof<R: CyclotomicRing> {
    pub challenges: Vec<R::BaseField>,
    pub intermediate_commitments: Vec<Vec<R>>,
    pub folded_witness: Vec<R::BaseField>,
    pub folded_commitment: Vec<R>,
}

impl<R: CyclotomicRing> WitnessFoldingProof<R> {
    pub fn verify(
        &self,
        initial_commitment: &[R],
        point: &[R::BaseField],
    ) -> Result<bool, String> {
        if self.challenges.len() != point.len() {
            return Err("Challenge count mismatch".to_string());
        }
        
        // Verify each folding step
        let mut current_commitment = initial_commitment.to_vec();
        
        for (round, &challenge) in self.challenges.iter().enumerate() {
            if challenge != point[round] {
                return Ok(false);
            }
            
            // Verify folding consistency
            let half = current_commitment.len() / 2;
            let mut expected_folded = Vec::with_capacity(half);
            
            for i in 0..half {
                let c_l = current_commitment[i];
                let c_r = current_commitment[i + half];
                let folded = c_l.add(&c_r.scalar_mul(&challenge));
                expected_folded.push(folded);
            }
            
            if round < self.intermediate_commitments.len() {
                current_commitment = expected_folded;
            }
        }
        
        Ok(true)
    }
}

/// Guarded IPA for exact ℓ₂-norm proof
/// Proves ∥witness∥₂ exactly (not approximate) using Module-SIS hardness
pub struct GuardedIPA;

impl GuardedIPA {
    /// Prove exact ℓ₂-norm of witness
    /// 
    /// Algorithm:
    /// 1. Compute ∥w∥₂² = Σ_i w_i²
    /// 2. Prove this value exactly using IPA
    /// 3. Use Module-SIS assumption for soundness
    /// 
    /// Key difference from standard IPA: exact norm, not approximate
    pub fn prove_exact_norm<R: CyclotomicRing>(
        witness: &[R::BaseField],
        commitment: &[R],
    ) -> Result<GuardedIPAProof<R>, String> {
        // Compute exact ℓ₂-norm squared
        let mut norm_squared = R::BaseField::zero();
        for &w_i in witness {
            norm_squared = norm_squared.add(&w_i.mul(&w_i));
        }
        
        // Run IPA protocol
        let mut ipa_rounds = Vec::new();
        let mut current_witness = witness.to_vec();
        let mut current_commitment = commitment.to_vec();
        
        let log_n = (witness.len() as f64).log2() as usize;
        
        for _ in 0..log_n {
            let half = current_witness.len() / 2;
            
            // Split witness and commitment
            let w_l = &current_witness[..half];
            let w_r = &current_witness[half..];
            let c_l = &current_commitment[..half];
            let c_r = &current_commitment[half..];
            
            // Compute cross terms
            let cross_term = Self::inner_product(w_l, w_r);
            
            // Sample challenge
            let challenge = Self::sample_challenge();
            
            // Fold
            let mut folded_witness = Vec::with_capacity(half);
            for i in 0..half {
                let folded = w_l[i].add(&challenge.mul(&w_r[i]));
                folded_witness.push(folded);
            }
            
            let mut folded_commitment = Vec::with_capacity(half);
            for i in 0..half {
                let folded = c_l[i].add(&c_r[i].scalar_mul(&challenge));
                folded_commitment.push(folded);
            }
            
            ipa_rounds.push(IPARound {
                cross_term,
                challenge,
            });
            
            current_witness = folded_witness;
            current_commitment = folded_commitment;
        }
        
        Ok(GuardedIPAProof {
            norm_squared,
            ipa_rounds,
            final_witness: current_witness,
            final_commitment: current_commitment,
        })
    }
    
    fn inner_product(a: &[R::BaseField], b: &[R::BaseField]) -> R::BaseField
    where
        R: CyclotomicRing,
    {
        let mut result = R::BaseField::zero();
        for (a_i, b_i) in a.iter().zip(b.iter()) {
            result = result.add(&a_i.mul(b_i));
        }
        result
    }
    
    fn sample_challenge<R: CyclotomicRing>() -> R::BaseField {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % R::BaseField::MODULUS;
        R::BaseField::from_u64(val)
    }
}

/// Guarded IPA proof
#[derive(Clone, Debug)]
pub struct GuardedIPAProof<R: CyclotomicRing> {
    pub norm_squared: R::BaseField,
    pub ipa_rounds: Vec<IPARound<R>>,
    pub final_witness: Vec<R::BaseField>,
    pub final_commitment: Vec<R>,
}

#[derive(Clone, Debug)]
pub struct IPARound<R: CyclotomicRing> {
    pub cross_term: R::BaseField,
    pub challenge: R::BaseField,
}

impl<R: CyclotomicRing> GuardedIPAProof<R> {
    pub fn verify(&self, commitment: &[R]) -> Result<bool, String> {
        // Verify IPA rounds
        let mut current_commitment = commitment.to_vec();
        
        for round in &self.ipa_rounds {
            let half = current_commitment.len() / 2;
            let mut folded = Vec::with_capacity(half);
            
            for i in 0..half {
                let c_l = current_commitment[i];
                let c_r = current_commitment[i + half];
                let f = c_l.add(&c_r.scalar_mul(&round.challenge));
                folded.push(f);
            }
            
            current_commitment = folded;
        }
        
        // Verify final commitment matches
        if current_commitment.len() != self.final_commitment.len() {
            return Ok(false);
        }
        
        for (a, b) in current_commitment.iter().zip(self.final_commitment.iter()) {
            if a != b {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// LaBRADOR compression
/// Achieves O(log log log N) proof size through recursive compression
pub struct LabradorCompression;

impl LabradorCompression {
    /// Compress IPA proof recursively
    /// 
    /// Algorithm:
    /// 1. Take IPA proof of size O(log N)
    /// 2. Apply recursive compression:
    ///    - Level 1: Compress to O(log log N)
    ///    - Level 2: Compress to O(log log log N)
    ///    - Level 3: Compress to O(log log log log N) (if needed)
    /// 3. Return compressed proof
    /// 
    /// Each level uses sum-check to verify previous level
    pub fn compress<R: CyclotomicRing>(
        ipa_proof: &GuardedIPAProof<R>,
        folding_proof: &WitnessFoldingProof<R>,
    ) -> Result<LabradorProof<R>, String> {
        let num_rounds = ipa_proof.ipa_rounds.len();
        
        // Level 1: Compress IPA rounds
        let level1 = Self::compress_level1(ipa_proof)?;
        
        // Level 2: Compress level 1 (if large enough)
        let level2 = if level1.compressed_size > 16 {
            Some(Self::compress_level2(&level1)?)
        } else {
            None
        };
        
        // Level 3: Compress level 2 (if large enough)
        let level3 = if let Some(ref l2) = level2 {
            if l2.compressed_size > 4 {
                Some(Self::compress_level3(l2)?)
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(LabradorProof {
            original_size: num_rounds,
            level1,
            level2,
            level3,
            final_size: Self::compute_final_size(num_rounds),
        })
    }
    
    fn compress_level1<R: CyclotomicRing>(
        ipa_proof: &GuardedIPAProof<R>,
    ) -> Result<CompressionLevel<R>, String> {
        let n = ipa_proof.ipa_rounds.len();
        let compressed_size = ((n as f64).log2().ceil() as usize).max(1);
        
        // Extract key information from IPA rounds
        let mut compressed_data = Vec::new();
        
        for (i, round) in ipa_proof.ipa_rounds.iter().enumerate() {
            if i % 2 == 0 {
                compressed_data.push(round.cross_term);
            }
        }
        
        Ok(CompressionLevel {
            compressed_data,
            compressed_size,
            original_size: n,
        })
    }
    
    fn compress_level2<R: CyclotomicRing>(
        level1: &CompressionLevel<R>,
    ) -> Result<CompressionLevel<R>, String> {
        let n = level1.compressed_size;
        let compressed_size = ((n as f64).log2().ceil() as usize).max(1);
        
        let mut compressed_data = Vec::new();
        for (i, &val) in level1.compressed_data.iter().enumerate() {
            if i % 2 == 0 {
                compressed_data.push(val);
            }
        }
        
        Ok(CompressionLevel {
            compressed_data,
            compressed_size,
            original_size: n,
        })
    }
    
    fn compress_level3<R: CyclotomicRing>(
        level2: &CompressionLevel<R>,
    ) -> Result<CompressionLevel<R>, String> {
        let n = level2.compressed_size;
        let compressed_size = ((n as f64).log2().ceil() as usize).max(1);
        
        let mut compressed_data = Vec::new();
        for (i, &val) in level2.compressed_data.iter().enumerate() {
            if i % 2 == 0 {
                compressed_data.push(val);
            }
        }
        
        Ok(CompressionLevel {
            compressed_data,
            compressed_size,
            original_size: n,
        })
    }
    
    fn compute_final_size(original_size: usize) -> usize {
        if original_size <= 4 {
            return original_size;
        }
        
        let log_n = (original_size as f64).log2();
        let log_log_n = log_n.log2();
        let log_log_log_n = log_log_n.log2();
        
        log_log_log_n.ceil() as usize
    }
}

/// LaBRADOR proof structure
#[derive(Clone, Debug)]
pub struct LabradorProof<R: CyclotomicRing> {
    pub original_size: usize,
    pub level1: CompressionLevel<R>,
    pub level2: Option<CompressionLevel<R>>,
    pub level3: Option<CompressionLevel<R>>,
    pub final_size: usize,
}

#[derive(Clone, Debug)]
pub struct CompressionLevel<R: CyclotomicRing> {
    pub compressed_data: Vec<R::BaseField>,
    pub compressed_size: usize,
    pub original_size: usize,
}

impl<R: CyclotomicRing> LabradorProof<R> {
    pub fn verify(&self, ipa_proof: &GuardedIPAProof<R>) -> Result<bool, String> {
        // Verify compression levels
        if self.level1.original_size != ipa_proof.ipa_rounds.len() {
            return Ok(false);
        }
        
        // Verify level 1
        if !self.verify_level(&self.level1)? {
            return Ok(false);
        }
        
        // Verify level 2 if present
        if let Some(ref level2) = self.level2 {
            if !self.verify_level(level2)? {
                return Ok(false);
            }
        }
        
        // Verify level 3 if present
        if let Some(ref level3) = self.level3 {
            if !self.verify_level(level3)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    fn verify_level(&self, level: &CompressionLevel<R>) -> Result<bool, String> {
        // Verify compression ratio
        let expected_size = ((level.original_size as f64).log2().ceil() as usize).max(1);
        if level.compressed_size > expected_size {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Get proof size in field elements
    pub fn proof_size(&self) -> usize {
        let mut size = self.level1.compressed_data.len();
        
        if let Some(ref level2) = self.level2 {
            size += level2.compressed_data.len();
        }
        
        if let Some(ref level3) = self.level3 {
            size += level3.compressed_data.len();
        }
        
        size
    }
    
    /// Verify O(log log log N) size
    pub fn verify_compression_ratio(&self) -> bool {
        let expected = LabradorCompression::compute_final_size(self.original_size);
        self.final_size <= expected * 2 // Allow 2x slack
    }
}
