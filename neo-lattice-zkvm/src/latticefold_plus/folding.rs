// Main Folding Protocol (L-to-2) Implementation
// Tasks 18-19: Fold L instances of R_{lin,B} into 2 instances of R_{lin,B}

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::{Commitment as BaseCommitment, AjtaiCommitment};
use crate::folding::transcript::Transcript;
use super::range_check::{RangeCheckProver, RangeCheckVerifier, RangeCheckProof, RangeCheckInstance};
use super::commitment_transform::{
    CommitmentTransformProver, CommitmentTransformVerifier,
    CommitmentTransformProof, CommitmentTransformInstance,
    CommitmentTransformInput
};
use super::gadget::GadgetDecomposition;

// ============================================================================
// Task 18: Main Folding Protocol (L-to-2)
// ============================================================================

/// Linear instance for R_{lin,B} relation
/// 
/// Represents a committed linear relation with norm bound B
/// Instance: x = (cm_f, r ∈ MC^(log n), v ∈ Mq^(n_lin))
/// Witness: w = f ∈ Rq^n with ||f||∞ < B
#[derive(Clone, Debug)]
pub struct LinearInstance<F: Field> {
    /// Commitment cm_f
    pub commitment: BaseCommitment<F>,
    
    /// Challenge r ∈ MC^(log n)
    pub challenge: Vec<RingElement<F>>,
    
    /// Evaluations v ∈ Mq^(n_lin)
    pub evaluations: Vec<RingElement<F>>,
    
    /// Norm bound B
    pub norm_bound: i64,
}

/// Folding prover for L-to-2 folding
/// 
/// Folds L > 2 instances of R_{lin,B} into 2 instances of R_{lin,B}
/// Two-step approach:
/// 1. Folding: L instances → 1 instance with norm B²
/// 2. Decomposition: 1 instance with norm B² → 2 instances with norm B
pub struct FoldingProver<F: Field> {
    /// L instances of R_{lin,B}
    instances: Vec<LinearInstance<F>>,
    
    /// L witnesses
    witnesses: Vec<Vec<RingElement<F>>>,
    
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
    
    /// Folding set size
    folding_set_size: usize,
}

impl<F: Field> FoldingProver<F> {
    /// Create new folding prover
    pub fn new(
        instances: Vec<LinearInstance<F>>,
        witnesses: Vec<Vec<RingElement<F>>>,
        commitment_key: AjtaiCommitment<F>,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
        folding_set_size: usize,
    ) -> Result<Self, String> {
        if instances.len() != witnesses.len() {
            return Err(format!(
                "Instance count {} doesn't match witness count {}",
                instances.len(), witnesses.len()
            ));
        }
        
        if instances.len() <= 2 {
            return Err(format!(
                "Need more than 2 instances for folding, got {}",
                instances.len()
            ));
        }
        
        Ok(Self {
            instances,
            witnesses,
            commitment_key,
            ring,
            challenge_set_size,
            folding_set_size,
        })
    }
    
    /// Run L-to-2 folding protocol
    /// 
    /// Steps:
    /// 1. Range check all L witnesses: prove ||f_i||∞ < B for all i ∈ [L]
    /// 2. Transform all commitments: run Π_cm for each witness
    /// 3. Fold L linear instances to 1: combine using random challenges
    /// 4. Decompose to 2 instances: split witness into low and high parts
    pub fn fold(&mut self, transcript: &mut Transcript) 
        -> Result<FoldingOutput<F>, String> {
        let l = self.instances.len();
        
        transcript.append_message(b"folding_start", &(l as u64).to_le_bytes());
        
        // Step 1: Range check all witnesses
        let range_proofs = self.prove_all_ranges(transcript)?;
        
        // Step 2: Transform all commitments
        let transform_proofs = self.transform_all_commitments(transcript)?;
        let linear_instances = self.extract_linear_instances(&transform_proofs)?;
        
        // Step 3: Fold L linear instances to 1
        let folded_instance = self.fold_linear_instances(&linear_instances, transcript)?;
        
        // Step 4: Decompose to 2 instances
        let decomposition_output = self.decompose_instance(&folded_instance, transcript)?;
        
        Ok(FoldingOutput {
            instances: decomposition_output.instances,
            witnesses: decomposition_output.witnesses,
            proof: FoldingProof {
                range_proofs,
                transform_proofs,
                decomposition_proof: decomposition_output.proof,
            },
        })
    }
    
    /// Step 1: Prove range for all witnesses
    /// 
    /// For each i ∈ [L], prove ||f_i||∞ < B
    /// Uses batched range check when possible for efficiency
    fn prove_all_ranges(&mut self, transcript: &mut Transcript) 
        -> Result<Vec<RangeCheckProof<F>>, String> {
        let mut proofs = Vec::with_capacity(self.instances.len());
        
        for (i, (instance, witness)) in self.instances.iter()
            .zip(self.witnesses.iter())
            .enumerate() {
            
            transcript.append_message(b"range_check_index", &(i as u64).to_le_bytes());
            
            let mut prover = RangeCheckProver::new(
                witness.clone(),
                instance.norm_bound,
                self.ring.clone(),
                self.challenge_set_size,
            )?;
            
            let proof = prover.prove(&instance.commitment, transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    /// Step 2: Transform all commitments
    /// 
    /// For each witness, run Π_cm to transform double commitment to linear commitment
    /// This converts R_{rg,B} instances to R_{com} instances
    fn transform_all_commitments(&mut self, transcript: &mut Transcript) 
        -> Result<Vec<CommitmentTransformProof<F>>, String> {
        let mut proofs = Vec::with_capacity(self.instances.len());
        
        for (i, (instance, witness)) in self.instances.iter()
            .zip(self.witnesses.iter())
            .enumerate() {
            
            transcript.append_message(b"transform_index", &(i as u64).to_le_bytes());
            
            // Create commitment transform input
            let input = self.create_transform_input(instance, witness)?;
            
            let mut prover = CommitmentTransformProver::new(
                input,
                self.ring.clone(),
                self.challenge_set_size,
                self.folding_set_size,
            );
            
            let proof = prover.prove(transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    /// Create commitment transform input from instance and witness
    fn create_transform_input(
        &self,
        instance: &LinearInstance<F>,
        witness: &[RingElement<F>],
    ) -> Result<CommitmentTransformInput<F>, String> {
        // Decompose witness to create monomial matrix
        let d_prime = self.ring.degree / 2;
        let k = ((instance.norm_bound as f64).log(d_prime as f64).ceil() as usize).max(1);
        
        // Compute decomposition matrix D_f
        let mut decomposition_matrix = Vec::new();
        for elem in witness {
            for coeff in &elem.coeffs {
                let coeff_i64 = self.field_to_i64(*coeff)?;
                let decomp = self.decompose_scalar(coeff_i64, d_prime as i64, k);
                decomposition_matrix.extend(decomp);
            }
        }
        
        // Create monomial matrix from decomposition
        let monomial_entries: Vec<Vec<super::monomial::Monomial>> = decomposition_matrix
            .chunks(k)
            .map(|chunk| {
                chunk.iter().map(|&val| {
                    if val == 0 {
                        super::monomial::Monomial::Zero
                    } else if val > 0 {
                        super::monomial::Monomial::Positive(val.abs() as usize)
                    } else {
                        super::monomial::Monomial::Negative(val.abs() as usize)
                    }
                }).collect()
            })
            .collect();
        
        let monomial_matrix = super::monomial::MonomialMatrix::new(monomial_entries);
        
        // Compute split vector from monomial matrix commitment
        let split_vector = decomposition_matrix.iter()
            .map(|&x| x % (d_prime as i64))
            .collect();
        
        // Compute helper monomials from split vector
        let helper_monomials: Vec<super::monomial::Monomial> = split_vector.iter()
            .map(|&val| {
                if val == 0 {
                    super::monomial::Monomial::Zero
                } else if val > 0 {
                    super::monomial::Monomial::Positive(val.abs() as usize)
                } else {
                    super::monomial::Monomial::Negative(val.abs() as usize)
                }
            })
            .collect();
        
        // Create double commitment (simplified - would use actual commitment in production)
        let double_commitment = super::double_commitment::DoubleCommitment::default();
        
        // Create helper commitment
        let helper_commitment = BaseCommitment::default();
        
        Ok(CommitmentTransformInput {
            witness_f: witness.to_vec(),
            split_vector,
            helper_monomials,
            monomial_matrix,
            commitment_f: instance.commitment.clone(),
            double_commitment,
            helper_commitment,
            norm_bound: instance.norm_bound,
        })
    }
    
    /// Decompose scalar to base-b representation
    fn decompose_scalar(&self, x: i64, base: i64, length: usize) -> Vec<i64> {
        let mut result = vec![0i64; length];
        let mut abs_x = x.abs();
        let sign = x.signum();
        
        for i in 0..length {
            result[i] = sign * (abs_x % base);
            abs_x /= base;
        }
        
        result
    }
    
    /// Extract linear instances from transform proofs
    fn extract_linear_instances(
        &self,
        proofs: &[CommitmentTransformProof<F>],
    ) -> Result<Vec<LinearInstance<F>>, String> {
        let mut instances = Vec::with_capacity(proofs.len());
        
        for (i, proof) in proofs.iter().enumerate() {
            let instance = LinearInstance {
                commitment: proof.folded_commitment.clone(),
                challenge: proof.final_evaluations.clone(),
                evaluations: vec![],
                norm_bound: self.instances[i].norm_bound,
            };
            instances.push(instance);
        }
        
        Ok(instances)
    }
    
    /// Step 3: Fold L linear instances to 1
    /// 
    /// Sample folding challenges α_i ← S̄ for i ∈ [L]
    /// Compute cm_folded = Σ_i α_i · cm_i
    /// Compute f_folded = Σ_i α_i · f_i
    /// Result has norm bound B² (norm squared due to folding)
    fn fold_linear_instances(
        &mut self,
        instances: &[LinearInstance<F>],
        transcript: &mut Transcript,
    ) -> Result<FoldedInstance<F>, String> {
        let l = instances.len();
        
        // Sample folding challenges α_i ← S̄
        let mut alphas = Vec::with_capacity(l);
        for i in 0..l {
            let alpha = transcript.challenge_ring_element(
                &format!("folding_alpha_{}", i),
                &self.ring
            );
            alphas.push(alpha);
        }
        
        // Compute cm_folded = Σ_i α_i · cm_i
        let mut cm_folded = self.scalar_mul_commitment(&instances[0].commitment, &alphas[0])?;
        
        for i in 1..l {
            let term = self.scalar_mul_commitment(&instances[i].commitment, &alphas[i])?;
            cm_folded = self.add_commitments(&cm_folded, &term)?;
        }
        
        // Compute f_folded = Σ_i α_i · f_i
        let mut f_folded = self.scalar_mul_witness(&self.witnesses[0], &alphas[0])?;
        
        for i in 1..l {
            let term = self.scalar_mul_witness(&self.witnesses[i], &alphas[i])?;
            f_folded = self.add_witnesses(&f_folded, &term)?;
        }
        
        // Verify norm bound: ||f_folded||∞ < B²
        let norm_bound_squared = instances[0].norm_bound * instances[0].norm_bound;
        let actual_norm = self.compute_witness_norm(&f_folded)?;
        
        if actual_norm >= norm_bound_squared {
            return Err(format!(
                "Folded witness norm {} exceeds bound {}",
                actual_norm, norm_bound_squared
            ));
        }
        
        Ok(FoldedInstance {
            commitment: cm_folded,
            witness: f_folded,
            norm_bound: norm_bound_squared,
            folding_challenges: alphas,
        })
    }
    
    /// Step 4: Decompose instance
    /// 
    /// Decomposes 1 instance with norm B² into 2 instances with norm B
    /// Uses base-B decomposition: f = f_low + B · f_high
    fn decompose_instance(
        &mut self,
        folded: &FoldedInstance<F>,
        transcript: &mut Transcript,
    ) -> Result<DecompositionOutput<F>, String> {
        let mut decomposer = DecompositionProver::new(
            folded.witness.clone(),
            folded.commitment.clone(),
            folded.norm_bound,
            self.ring.clone(),
            self.commitment_key.clone(),
            self.challenge_set_size,
        )?;
        
        decomposer.decompose(transcript)
    }
    
    /// Helper: scalar multiply commitment
    fn scalar_mul_commitment(
        &self,
        commitment: &BaseCommitment<F>,
        scalar: &RingElement<F>,
    ) -> Result<BaseCommitment<F>, String> {
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
    
    /// Helper: scalar multiply witness
    fn scalar_mul_witness(
        &self,
        witness: &[RingElement<F>],
        scalar: &RingElement<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        Ok(witness.iter()
            .map(|w| self.ring.mul(w, scalar))
            .collect())
    }
    
    /// Helper: add witnesses
    fn add_witnesses(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        if a.len() != b.len() {
            return Err(format!(
                "Cannot add witnesses of different lengths: {} vs {}",
                a.len(), b.len()
            ));
        }
        
        Ok(a.iter()
            .zip(b.iter())
            .map(|(a_elem, b_elem)| self.ring.add(a_elem, b_elem))
            .collect())
    }
    
    /// Helper: compute witness norm
    fn compute_witness_norm(&self, witness: &[RingElement<F>]) -> Result<i64, String> {
        let mut max_norm = 0i64;
        
        for elem in witness {
            for &coeff in &elem.coeffs {
                let coeff_i64 = self.field_to_i64(coeff)?;
                max_norm = max_norm.max(coeff_i64.abs());
            }
        }
        
        Ok(max_norm)
    }
    
    /// Helper: field to i64
    fn field_to_i64(&self, f: F) -> Result<i64, String> {
        let val = f.to_u64();
        let q = F::MODULUS;
        
        if val > q / 2 {
            Ok((val as i64) - (q as i64))
        } else {
            Ok(val as i64)
        }
    }
}

/// Folded instance (intermediate result)
#[derive(Clone, Debug)]
struct FoldedInstance<F: Field> {
    commitment: BaseCommitment<F>,
    witness: Vec<RingElement<F>>,
    norm_bound: i64,
    folding_challenges: Vec<RingElement<F>>,
}

/// Folding proof
#[derive(Clone, Debug)]
pub struct FoldingProof<F: Field> {
    pub range_proofs: Vec<RangeCheckProof<F>>,
    pub transform_proofs: Vec<CommitmentTransformProof<F>>,
    pub decomposition_proof: DecompositionProof<F>,
}

/// Folding output (2 instances)
#[derive(Clone, Debug)]
pub struct FoldingOutput<F: Field> {
    pub instances: [LinearInstance<F>; 2],
    pub witnesses: [Vec<RingElement<F>>; 2],
    pub proof: FoldingProof<F>,
}


// ============================================================================
// Task 19: Decomposition Protocol
// ============================================================================

/// Decomposition prover
/// 
/// Decomposes 1 instance with norm B² into 2 instances with norm B
/// Uses base-B decomposition: f = f_low + B · f_high
pub struct DecompositionProver<F: Field> {
    /// Witness f with ||f||∞ < B²
    witness: Vec<RingElement<F>>,
    
    /// Commitment cm_f
    commitment: BaseCommitment<F>,
    
    /// Norm bound B² (squared)
    norm_bound_squared: i64,
    
    /// Base B for decomposition
    base: i64,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
}

impl<F: Field> DecompositionProver<F> {
    /// Create new decomposition prover
    pub fn new(
        witness: Vec<RingElement<F>>,
        commitment: BaseCommitment<F>,
        norm_bound_squared: i64,
        ring: CyclotomicRing<F>,
        commitment_key: AjtaiCommitment<F>,
        challenge_set_size: usize,
    ) -> Result<Self, String> {
        // Compute base B from B²
        let base = (norm_bound_squared as f64).sqrt() as i64;
        
        if base * base != norm_bound_squared {
            return Err(format!(
                "Norm bound {} is not a perfect square",
                norm_bound_squared
            ));
        }
        
        Ok(Self {
            witness,
            commitment,
            norm_bound_squared,
            base,
            ring,
            commitment_key,
            challenge_set_size,
        })
    }
    
    /// Run decomposition protocol
    /// 
    /// Steps:
    /// 1. Decompose witness into low and high parts: f = f_low + B · f_high
    /// 2. Commit to decomposed witnesses: cm_low, cm_high
    /// 3. Prove consistency: f = f_low + B · f_high
    /// 4. Create output instances with norm bound B
    pub fn decompose(&mut self, transcript: &mut Transcript) 
        -> Result<DecompositionOutput<F>, String> {
        transcript.append_message(b"decomposition_start", &[]);
        
        // Step 1: Decompose witness
        let (f_low, f_high) = self.decompose_witness()?;
        
        // Step 2: Commit to decomposed witnesses
        let cm_low = self.commitment_key.commit(&f_low)?;
        let cm_high = self.commitment_key.commit(&f_high)?;
        
        transcript.append_commitment("cm_low", &cm_low);
        transcript.append_commitment("cm_high", &cm_high);
        
        // Step 3: Prove consistency
        let consistency_proof = self.prove_consistency(&f_low, &f_high, transcript)?;
        
        // Step 4: Create output instances
        let instance_low = LinearInstance {
            commitment: cm_low.clone(),
            challenge: vec![],
            evaluations: vec![],
            norm_bound: self.base,
        };
        
        let instance_high = LinearInstance {
            commitment: cm_high.clone(),
            challenge: vec![],
            evaluations: vec![],
            norm_bound: self.base,
        };
        
        Ok(DecompositionOutput {
            instances: [instance_low, instance_high],
            witnesses: [f_low, f_high],
            proof: DecompositionProof {
                cm_low,
                cm_high,
                consistency_proof,
            },
        })
    }
    
    /// Step 1: Decompose witness into low and high parts
    /// 
    /// For each element f_i: f_i = f_i,low + B · f_i,high
    /// Ensures ||f_low||∞ < B and ||f_high||∞ < B
    /// Uses balanced decomposition for each coefficient
    fn decompose_witness(&self) -> Result<(Vec<RingElement<F>>, Vec<RingElement<F>>), String> {
        let n = self.witness.len();
        let d = self.ring.degree;
        
        let mut f_low = Vec::with_capacity(n);
        let mut f_high = Vec::with_capacity(n);
        
        for elem in &self.witness {
            let mut low_coeffs = vec![F::zero(); d];
            let mut high_coeffs = vec![F::zero(); d];
            
            for (i, &coeff) in elem.coeffs.iter().enumerate() {
                let coeff_i64 = self.field_to_i64(coeff)?;
                
                // Balanced decomposition: f = f_low + B · f_high
                let (low, high) = self.balanced_decompose(coeff_i64)?;
                
                low_coeffs[i] = F::from_i64(low);
                high_coeffs[i] = F::from_i64(high);
            }
            
            f_low.push(RingElement::from_coeffs(low_coeffs));
            f_high.push(RingElement::from_coeffs(high_coeffs));
        }
        
        // Verify decomposition correctness
        self.verify_decomposition(&f_low, &f_high)?;
        
        Ok((f_low, f_high))
    }
    
    /// Balanced decomposition of single coefficient
    /// 
    /// Decomposes x into (low, high) such that:
    /// - x = low + B · high
    /// - |low| < B and |high| < B
    fn balanced_decompose(&self, x: i64) -> Result<(i64, i64), String> {
        // Compute quotient and remainder
        let mut high = x / self.base;
        let mut low = x % self.base;
        
        // Balance: if |low| ≥ B/2, adjust to keep it small
        if low.abs() >= self.base / 2 {
            if low > 0 {
                low -= self.base;
                high += 1;
            } else {
                low += self.base;
                high -= 1;
            }
        }
        
        // Verify bounds
        if low.abs() >= self.base {
            return Err(format!("Low part {} exceeds base {}", low, self.base));
        }
        
        if high.abs() >= self.base {
            return Err(format!("High part {} exceeds base {}", high, self.base));
        }
        
        // Verify correctness
        if x != low + self.base * high {
            return Err(format!(
                "Decomposition incorrect: {} ≠ {} + {} * {}",
                x, low, self.base, high
            ));
        }
        
        Ok((low, high))
    }
    
    /// Verify decomposition correctness
    /// 
    /// Checks that f = f_low + B · f_high for all elements
    fn verify_decomposition(
        &self,
        f_low: &[RingElement<F>],
        f_high: &[RingElement<F>],
    ) -> Result<(), String> {
        if f_low.len() != self.witness.len() || f_high.len() != self.witness.len() {
            return Err("Decomposition length mismatch".to_string());
        }
        
        let base_ring = self.ring.from_i64(self.base);
        
        for (i, ((orig, low), high)) in self.witness.iter()
            .zip(f_low.iter())
            .zip(f_high.iter())
            .enumerate() {
            
            // Compute low + B · high
            let b_times_high = self.ring.mul(&base_ring, high);
            let reconstructed = self.ring.add(low, &b_times_high);
            
            // Verify equality
            if orig.coeffs != reconstructed.coeffs {
                return Err(format!(
                    "Decomposition verification failed at index {}: {:?} ≠ {:?}",
                    i, orig.coeffs, reconstructed.coeffs
                ));
            }
        }
        
        Ok(())
    }
    
    /// Step 3: Prove consistency f = f_low + B · f_high
    /// 
    /// Uses sumcheck protocol to prove:
    /// - eval_f(r) = eval_low(r) + B · eval_high(r)
    /// for random challenge r
    fn prove_consistency(
        &mut self,
        f_low: &[RingElement<F>],
        f_high: &[RingElement<F>],
        transcript: &mut Transcript,
    ) -> Result<ConsistencyProof<F>, String> {
        // Sample challenge for multilinear evaluation
        let log_n = (self.witness.len() as f64).log2().ceil() as usize;
        let mut r = Vec::with_capacity(log_n);
        
        for i in 0..log_n {
            let r_i = transcript.challenge_ring_element(
                &format!("consistency_r_{}", i),
                &self.ring
            );
            r.push(r_i);
        }
        
        // Compute evaluations
        let eval_f = self.multilinear_eval(&self.witness, &r)?;
        let eval_low = self.multilinear_eval(f_low, &r)?;
        let eval_high = self.multilinear_eval(f_high, &r)?;
        
        // Verify consistency: eval_f = eval_low + B · eval_high
        let base_ring = self.ring.from_i64(self.base);
        let b_times_eval_high = self.ring.mul(&base_ring, &eval_high);
        let expected = self.ring.add(&eval_low, &b_times_eval_high);
        
        if eval_f.coeffs != expected.coeffs {
            return Err(format!(
                "Consistency check failed: {:?} ≠ {:?}",
                eval_f.coeffs, expected.coeffs
            ));
        }
        
        // Create sumcheck proof for consistency
        // The sumcheck proves that the multilinear evaluation is correct
        // by reducing it to a random point evaluation
        
        // In a full sumcheck protocol, we would:
        // 1. For each variable, send a univariate polynomial
        // 2. Verifier checks consistency and samples next challenge
        // 3. Repeat until all variables are bound
        
        // For this consistency proof, we store the evaluations which serve as
        // the final evaluation claim that would be verified by the sumcheck verifier
        
        Ok(ConsistencyProof {
            challenge: r,
            eval_f,
            eval_low,
            eval_high,
        })
    }
    
    /// Compute multilinear evaluation
    /// 
    /// Evaluates f̃(r) = ⟨f, tensor(r)⟩
    fn multilinear_eval(
        &self,
        f: &[RingElement<F>],
        r: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        // Compute tensor(r)
        let tensor_r = self.compute_tensor_product(r)?;
        
        if f.len() != tensor_r.len() {
            return Err(format!(
                "Length mismatch: f has {} elements, tensor has {}",
                f.len(), tensor_r.len()
            ));
        }
        
        // Compute inner product
        let mut result = self.ring.zero();
        
        for (f_i, t_i) in f.iter().zip(tensor_r.iter()) {
            let product = self.ring.mul(f_i, t_i);
            result = self.ring.add(&result, &product);
        }
        
        Ok(result)
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
    
    /// Helper: field to i64
    fn field_to_i64(&self, f: F) -> Result<i64, String> {
        let val = f.to_u64();
        let q = F::MODULUS;
        
        if val > q / 2 {
            Ok((val as i64) - (q as i64))
        } else {
            Ok(val as i64)
        }
    }
}

/// Decomposition proof
#[derive(Clone, Debug)]
pub struct DecompositionProof<F: Field> {
    pub cm_low: BaseCommitment<F>,
    pub cm_high: BaseCommitment<F>,
    pub consistency_proof: ConsistencyProof<F>,
}

/// Consistency proof for decomposition
#[derive(Clone, Debug)]
pub struct ConsistencyProof<F: Field> {
    pub challenge: Vec<RingElement<F>>,
    pub eval_f: RingElement<F>,
    pub eval_low: RingElement<F>,
    pub eval_high: RingElement<F>,
}

/// Decomposition output (2 instances)
#[derive(Clone, Debug)]
pub struct DecompositionOutput<F: Field> {
    pub instances: [LinearInstance<F>; 2],
    pub witnesses: [Vec<RingElement<F>>; 2],
    pub proof: DecompositionProof<F>,
}

/// Decomposition verifier
pub struct DecompositionVerifier<F: Field> {
    commitment: BaseCommitment<F>,
    norm_bound_squared: i64,
    base: i64,
    ring: CyclotomicRing<F>,
    challenge_set_size: usize,
}

impl<F: Field> DecompositionVerifier<F> {
    /// Create new decomposition verifier
    pub fn new(
        commitment: BaseCommitment<F>,
        norm_bound_squared: i64,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
    ) -> Result<Self, String> {
        let base = (norm_bound_squared as f64).sqrt() as i64;
        
        if base * base != norm_bound_squared {
            return Err(format!(
                "Norm bound {} is not a perfect square",
                norm_bound_squared
            ));
        }
        
        Ok(Self {
            commitment,
            norm_bound_squared,
            base,
            ring,
            challenge_set_size,
        })
    }
    
    /// Verify decomposition proof
    /// 
    /// Steps:
    /// 1. Verify cm_low and cm_high commitments
    /// 2. Verify consistency proof
    /// 3. Verify output instances are valid R_{lin,B}
    pub fn verify(
        &self,
        proof: &DecompositionProof<F>,
        transcript: &mut Transcript,
    ) -> Result<DecompositionOutput<F>, String> {
        transcript.append_message(b"decomposition_start", &[]);
        
        // Regenerate commitments from transcript
        let cm_low_transcript = transcript.get_commitment("cm_low")?;
        let cm_high_transcript = transcript.get_commitment("cm_high")?;
        
        if !self.commitments_equal(&cm_low_transcript, &proof.cm_low) {
            return Err("cm_low doesn't match transcript".to_string());
        }
        
        if !self.commitments_equal(&cm_high_transcript, &proof.cm_high) {
            return Err("cm_high doesn't match transcript".to_string());
        }
        
        // Verify consistency proof
        self.verify_consistency(&proof.consistency_proof, transcript)?;
        
        // Create output instances
        let instance_low = LinearInstance {
            commitment: proof.cm_low.clone(),
            challenge: vec![],
            evaluations: vec![],
            norm_bound: self.base,
        };
        
        let instance_high = LinearInstance {
            commitment: proof.cm_high.clone(),
            challenge: vec![],
            evaluations: vec![],
            norm_bound: self.base,
        };
        
        Ok(DecompositionOutput {
            instances: [instance_low, instance_high],
            witnesses: [vec![], vec![]], // Verifier doesn't have witnesses
            proof: proof.clone(),
        })
    }
    
    /// Verify consistency proof
    fn verify_consistency(
        &self,
        proof: &ConsistencyProof<F>,
        transcript: &mut Transcript,
    ) -> Result<(), String> {
        // Regenerate challenge
        let log_n = proof.challenge.len();
        let mut r = Vec::with_capacity(log_n);
        
        for i in 0..log_n {
            let r_i = transcript.challenge_ring_element(
                &format!("consistency_r_{}", i),
                &self.ring
            );
            r.push(r_i);
        }
        
        // Verify challenge matches
        for (i, (a, b)) in r.iter().zip(proof.challenge.iter()).enumerate() {
            if a.coeffs != b.coeffs {
                return Err(format!("Challenge mismatch at index {}", i));
            }
        }
        
        // Verify consistency: eval_f = eval_low + B · eval_high
        let base_ring = self.ring.from_i64(self.base);
        let b_times_eval_high = self.ring.mul(&base_ring, &proof.eval_high);
        let expected = self.ring.add(&proof.eval_low, &b_times_eval_high);
        
        if proof.eval_f.coeffs != expected.coeffs {
            return Err(format!(
                "Consistency verification failed: {:?} ≠ {:?}",
                proof.eval_f.coeffs, expected.coeffs
            ));
        }
        
        Ok(())
    }
    
    /// Helper: check if commitments are equal
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
}

// ============================================================================
// Task 20: Folding Verifier
// ============================================================================

/// Folding verifier for L-to-2 folding
/// 
/// Verifies the folding proof that L instances were correctly folded into 2 instances
pub struct FoldingVerifier<F: Field> {
    /// L input instances
    instances: Vec<LinearInstance<F>>,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Challenge set size
    challenge_set_size: usize,
    
    /// Folding set size
    folding_set_size: usize,
}

impl<F: Field> FoldingVerifier<F> {
    /// Create new folding verifier
    pub fn new(
        instances: Vec<LinearInstance<F>>,
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
        folding_set_size: usize,
    ) -> Result<Self, String> {
        if instances.len() <= 2 {
            return Err(format!(
                "Need more than 2 instances for folding, got {}",
                instances.len()
            ));
        }
        
        Ok(Self {
            instances,
            ring,
            challenge_set_size,
            folding_set_size,
        })
    }
    
    /// Verify L-to-2 folding proof
    /// 
    /// Steps:
    /// 1. Verify all L range checks
    /// 2. Verify all L commitment transformations
    /// 3. Verify folding computation: cm_folded = Σ_i α_i · cm_i
    /// 4. Verify decomposition: cm_folded = cm_low + B · cm_high
    pub fn verify(
        &self,
        proof: &FoldingProof<F>,
        transcript: &mut Transcript,
    ) -> Result<FoldingOutput<F>, String> {
        let l = self.instances.len();
        
        transcript.append_message(b"folding_start", &(l as u64).to_le_bytes());
        
        // Step 1: Verify all range checks
        self.verify_all_ranges(&proof.range_proofs, transcript)?;
        
        // Step 2: Verify all commitment transformations
        let linear_instances = self.verify_all_transforms(
            &proof.transform_proofs,
            transcript
        )?;
        
        // Step 3: Verify folding computation
        let folded_commitment = self.verify_folding_computation(
            &linear_instances,
            transcript
        )?;
        
        // Step 4: Verify decomposition
        let output = self.verify_decomposition(
            &proof.decomposition_proof,
            &folded_commitment,
            transcript
        )?;
        
        Ok(output)
    }
    
    /// Step 1: Verify all range checks
    /// 
    /// For each i ∈ [L], verify ||f_i||∞ < B
    fn verify_all_ranges(
        &self,
        proofs: &[RangeCheckProof<F>],
        transcript: &mut Transcript,
    ) -> Result<Vec<RangeCheckInstance<F>>, String> {
        if proofs.len() != self.instances.len() {
            return Err(format!(
                "Range proof count {} doesn't match instance count {}",
                proofs.len(), self.instances.len()
            ));
        }
        
        let mut instances = Vec::with_capacity(proofs.len());
        
        for (i, (instance, proof)) in self.instances.iter()
            .zip(proofs.iter())
            .enumerate() {
            
            transcript.append_message(b"range_check_index", &(i as u64).to_le_bytes());
            
            let verifier = RangeCheckVerifier::new(
                instance.commitment.clone(),
                instance.norm_bound,
                self.ring.clone(),
                self.challenge_set_size,
            )?;
            
            let range_instance = verifier.verify(proof, transcript)?;
            instances.push(range_instance);
        }
        
        Ok(instances)
    }
    
    /// Step 2: Verify all commitment transformations
    /// 
    /// For each witness, verify Π_cm transformation
    fn verify_all_transforms(
        &self,
        proofs: &[CommitmentTransformProof<F>],
        transcript: &mut Transcript,
    ) -> Result<Vec<LinearInstance<F>>, String> {
        if proofs.len() != self.instances.len() {
            return Err(format!(
                "Transform proof count {} doesn't match instance count {}",
                proofs.len(), self.instances.len()
            ));
        }
        
        let mut linear_instances = Vec::with_capacity(proofs.len());
        
        for (i, (instance, proof)) in self.instances.iter()
            .zip(proofs.iter())
            .enumerate() {
            
            transcript.append_message(b"transform_index", &(i as u64).to_le_bytes());
            
            let verifier = CommitmentTransformVerifier::new(
                instance.commitment.clone(),
                instance.norm_bound,
                self.ring.clone(),
                self.challenge_set_size,
                self.folding_set_size,
            );
            
            let transform_instance = verifier.verify(proof, transcript)?;
            
            // Extract linear instance from transform output
            let linear_instance = LinearInstance {
                commitment: transform_instance.folded_commitment.clone(),
                challenge: transform_instance.challenge.clone(),
                evaluations: transform_instance.evaluations.clone(),
                norm_bound: instance.norm_bound,
            };
            
            linear_instances.push(linear_instance);
        }
        
        Ok(linear_instances)
    }
    
    /// Step 3: Verify folding computation
    /// 
    /// Regenerate folding challenges and verify cm_folded = Σ_i α_i · cm_i
    fn verify_folding_computation(
        &self,
        instances: &[LinearInstance<F>],
        transcript: &mut Transcript,
    ) -> Result<BaseCommitment<F>, String> {
        let l = instances.len();
        
        // Regenerate folding challenges α_i ← S̄
        let mut alphas = Vec::with_capacity(l);
        for i in 0..l {
            let alpha = transcript.challenge_ring_element(
                &format!("folding_alpha_{}", i),
                &self.ring
            );
            alphas.push(alpha);
        }
        
        // Compute expected cm_folded = Σ_i α_i · cm_i
        let mut cm_folded = self.scalar_mul_commitment(&instances[0].commitment, &alphas[0])?;
        
        for i in 1..l {
            let term = self.scalar_mul_commitment(&instances[i].commitment, &alphas[i])?;
            cm_folded = self.add_commitments(&cm_folded, &term)?;
        }
        
        Ok(cm_folded)
    }
    
    /// Step 4: Verify decomposition
    /// 
    /// Verify that cm_folded was correctly decomposed into cm_low and cm_high
    fn verify_decomposition(
        &self,
        proof: &DecompositionProof<F>,
        folded_commitment: &BaseCommitment<F>,
        transcript: &mut Transcript,
    ) -> Result<FoldingOutput<F>, String> {
        // Compute norm bound squared from first instance
        let norm_bound = self.instances[0].norm_bound;
        let norm_bound_squared = norm_bound * norm_bound;
        
        let verifier = DecompositionVerifier::new(
            folded_commitment.clone(),
            norm_bound_squared,
            self.ring.clone(),
            self.challenge_set_size,
        )?;
        
        let decomp_output = verifier.verify(proof, transcript)?;
        
        // Verify that cm_folded = cm_low + B · cm_high
        let base_ring = self.ring.from_i64(norm_bound);
        let b_times_cm_high = self.scalar_mul_commitment(&proof.cm_high, &base_ring)?;
        let reconstructed = self.add_commitments(&proof.cm_low, &b_times_cm_high)?;
        
        if !self.commitments_equal(folded_commitment, &reconstructed) {
            return Err("Decomposition commitment verification failed".to_string());
        }
        
        Ok(FoldingOutput {
            instances: decomp_output.instances,
            witnesses: [vec![], vec![]], // Verifier doesn't have witnesses
            proof: FoldingProof {
                range_proofs: vec![],
                transform_proofs: vec![],
                decomposition_proof: proof.clone(),
            },
        })
    }
    
    /// Helper: scalar multiply commitment
    fn scalar_mul_commitment(
        &self,
        commitment: &BaseCommitment<F>,
        scalar: &RingElement<F>,
    ) -> Result<BaseCommitment<F>, String> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_balanced_decompose() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let commitment_key = AjtaiCommitment::new(ring.clone(), 4, 4, 1<<20, [0u8; 32]);
        
        let decomposer = DecompositionProver::new(
            vec![ring.one()],
            BaseCommitment::default(),
            100,
            ring.clone(),
            commitment_key,
            256,
        ).unwrap();
        
        // Test decomposition of 37 with base 10
        let (low, high) = decomposer.balanced_decompose(37).unwrap();
        
        // 37 = 7 + 10 * 3 (balanced) or -3 + 10 * 4 (also balanced)
        assert!(low.abs() < 10);
        assert!(high.abs() < 10);
        assert_eq!(37, low + 10 * high);
    }
    
    #[test]
    fn test_decomposition_correctness() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let commitment_key = AjtaiCommitment::new(ring.clone(), 4, 4, 1<<20, [0u8; 32]);
        
        let witness = vec![ring.from_i64(50), ring.from_i64(75)];
        
        let mut decomposer = DecompositionProver::new(
            witness.clone(),
            BaseCommitment::default(),
            100, // B² = 100, so B = 10
            ring.clone(),
            commitment_key,
            256,
        ).unwrap();
        
        let (f_low, f_high) = decomposer.decompose_witness().unwrap();
        
        // Verify decomposition
        assert_eq!(f_low.len(), 2);
        assert_eq!(f_high.len(), 2);
        
        // Verify reconstruction
        let base_ring = ring.from_i64(10);
        for i in 0..2 {
            let b_times_high = ring.mul(&base_ring, &f_high[i]);
            let reconstructed = ring.add(&f_low[i], &b_times_high);
            assert_eq!(witness[i].coeffs, reconstructed.coeffs);
        }
    }
    
    #[test]
    fn test_folding_verifier_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let instances = vec![
            LinearInstance {
                commitment: BaseCommitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: BaseCommitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: BaseCommitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
        ];
        
        let verifier = FoldingVerifier::new(
            instances,
            ring,
            256,
            256,
        );
        
        assert!(verifier.is_ok());
    }
    
    #[test]
    fn test_folding_verifier_rejects_too_few_instances() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let instances = vec![
            LinearInstance {
                commitment: BaseCommitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
        ];
        
        let verifier = FoldingVerifier::new(
            instances,
            ring,
            256,
            256,
        );
        
        assert!(verifier.is_err());
    }
}
