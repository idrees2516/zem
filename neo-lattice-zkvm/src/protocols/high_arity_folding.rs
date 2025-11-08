// High-Arity Folding Protocol (Π_fold)
// Figure 4 from Symphony paper
// Folds ℓ_np R1CS statements into two efficiently provable statements

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::field::symphony_extension::SymphonyExtensionField;
use crate::ring::tensor::TensorElement;
use crate::commitment::ajtai::Commitment;
use crate::folding::transcript::Transcript;
use super::single_instance::{
    SingleInstanceProtocol, GeneralizedR1CSInstance, GeneralizedR1CSWitness,
    SingleInstanceOutput, SingleInstanceProof,
};
use super::rok_traits::{
    ReductionOfKnowledge, LinearInstance, LinearWitness,
    BatchLinearInstance, BatchLinearWitness,
};
use std::marker::PhantomData;

/// Multi-instance input for high-arity folding
#[derive(Clone, Debug)]
pub struct MultiInstanceInput<F: Field> {
    /// ℓ_np R1CS instances
    pub instances: Vec<GeneralizedR1CSInstance<F>>,
    
    /// ℓ_np R1CS witnesses
    pub witnesses: Vec<GeneralizedR1CSWitness<F>>,
}

/// Folded output after high-arity folding
#[derive(Clone, Debug)]
pub struct FoldedOutput<F: Field> {
    /// Folded linear instance
    pub linear_instance: LinearInstance<F>,
    
    /// Folded batch linear instance
    pub batch_linear_instance: BatchLinearInstance<F>,
    
    /// Folded witness (for prover only)
    pub folded_witness: Option<FoldedWitness<F>>,
    
    /// Message commitments from Fiat-Shamir
    pub message_commitments: Vec<Commitment<F>>,
}

/// Folded witness
#[derive(Clone, Debug)]
pub struct FoldedWitness<F: Field> {
    /// Folded witness f_* = Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ
    pub witness: Vec<RingElement<F>>,
    
    /// Folded opening scalar
    pub opening_scalar: RingElement<F>,
    
    /// Witness norm
    pub norm: f64,
}

/// High-arity folding proof
#[derive(Clone, Debug)]
pub struct HighArityFoldingProof<F: Field> {
    /// Single-instance proofs for each of ℓ_np instances
    pub single_instance_proofs: Vec<SingleInstanceProof<F>>,
    
    /// Merged sumcheck outputs
    pub merged_sumcheck_outputs: MergedSumcheckOutputs<F>,
    
    /// Folding challenge β ∈ S^{ℓ_np}
    pub folding_challenge: Vec<RingElement<F>>,
}

/// Merged sumcheck outputs
#[derive(Clone, Debug)]
pub struct MergedSumcheckOutputs<F: Field> {
    /// First merged claim output e_*
    pub hadamard_output: SymphonyExtensionField<F>,
    
    /// Second merged claim output u_*
    pub monomial_output: Vec<TensorElement<F>>,
    
    /// Shared evaluation point r
    pub evaluation_point: Vec<SymphonyExtensionField<F>>,
}

/// High-arity folding protocol
pub struct HighArityFoldingProtocol<F: Field> {
    /// Ring parameters
    ring: CyclotomicRing<F>,
    
    /// Challenge set size |S|
    challenge_set_size: usize,
    
    /// Folding arity ℓ_np
    folding_arity: usize,
    
    /// Single-instance protocol
    single_instance_protocol: SingleInstanceProtocol<F>,
    
    /// Challenge set S ⊆ Rq with ∥S∥_op ≤ 15
    challenge_set: Vec<RingElement<F>>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> HighArityFoldingProtocol<F> {
    /// Create new high-arity folding protocol
    pub fn new(
        ring: CyclotomicRing<F>,
        challenge_set_size: usize,
        folding_arity: usize,
    ) -> Result<Self, String> {
        // Validate folding arity
        if folding_arity < 2 {
            return Err("Folding arity must be at least 2".to_string());
        }
        
        if !folding_arity.is_power_of_two() {
            return Err("Folding arity must be a power of 2".to_string());
        }
        
        // Create single-instance protocol
        let single_instance_protocol = SingleInstanceProtocol::new(
            ring.clone(),
            challenge_set_size,
        );
        
        // Generate challenge set S with operator norm ≤ 15
        let challenge_set = Self::generate_challenge_set(&ring, challenge_set_size)?;
        
        Ok(Self {
            ring,
            challenge_set_size,
            folding_arity,
            single_instance_protocol,
            challenge_set,
            _phantom: PhantomData,
        })
    }

    /// Prover: fold ℓ_np R1CS instances into two statements
    /// 
    /// Protocol (Figure 4):
    /// 1. Execute ℓ_np parallel Π_gr1cs with shared randomness
    /// 2. Merge 2ℓ_np sumcheck claims into 2 claims
    /// 3. Verify evaluation consistency
    /// 4. Sample folding challenge β ← S^{ℓ_np}
    /// 5. Compute folded commitments c_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·c_ℓ
    /// 6. Compute folded witnesses f_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ
    pub fn fold(
        &self,
        input: &MultiInstanceInput<F>,
        transcript: &mut Transcript,
    ) -> Result<(FoldedOutput<F>, HighArityFoldingProof<F>), String> {
        let ell_np = input.instances.len();
        
        // Validate input
        if ell_np != self.folding_arity {
            return Err(format!(
                "Input size {} does not match folding arity {}",
                ell_np, self.folding_arity
            ));
        }
        
        if input.witnesses.len() != ell_np {
            return Err("Number of witnesses must match number of instances".to_string());
        }
        
        // Step 1: Execute ℓ_np parallel Π_gr1cs with shared randomness
        let parallel_outputs = self.execute_parallel_reductions(
            &input.instances,
            &input.witnesses,
            transcript,
        )?;
        
        // Step 2: Merge 2ℓ_np sumcheck claims into 2 claims
        let merged_outputs = self.merge_sumcheck_claims(
            &parallel_outputs,
            transcript,
        )?;
        
        // Step 3: Verify evaluation consistency
        self.verify_evaluation_consistency(
            &parallel_outputs,
            &merged_outputs,
        )?;
        
        // Step 4: Sample folding challenge β ← S^{ℓ_np}
        let beta = self.sample_folding_challenge(transcript, ell_np)?;
        
        // Step 5: Compute folded commitments
        let folded_commitment = self.fold_commitments(
            &input.instances,
            &beta,
        )?;
        
        // Step 6: Compute folded witnesses
        let folded_witness = self.fold_witnesses(
            &input.witnesses,
            &beta,
        )?;
        
        // Step 7: Verify norm bounds
        self.verify_folded_norm_bounds(&folded_witness, &input.instances[0])?;
        
        // Step 8: Construct output
        let output = self.construct_folded_output(
            folded_commitment,
            folded_witness,
            &merged_outputs,
            &parallel_outputs,
        )?;
        
        let proof = HighArityFoldingProof {
            single_instance_proofs: parallel_outputs.iter()
                .map(|(_, proof)| proof.clone())
                .collect(),
            merged_sumcheck_outputs: merged_outputs,
            folding_challenge: beta,
        };
        
        Ok((output, proof))
    }

    /// Verifier: verify high-arity folding proof
    pub fn verify(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        output: &FoldedOutput<F>,
        proof: &HighArityFoldingProof<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        let ell_np = instances.len();
        
        // Validate input
        if ell_np != self.folding_arity {
            return Err(format!(
                "Input size {} does not match folding arity {}",
                ell_np, self.folding_arity
            ));
        }
        
        if proof.single_instance_proofs.len() != ell_np {
            return Err("Number of proofs must match number of instances".to_string());
        }
        
        // Step 1: Verify each single-instance proof with shared randomness
        let mut single_outputs = Vec::with_capacity(ell_np);
        for (instance, si_proof) in instances.iter().zip(&proof.single_instance_proofs) {
            let output = self.single_instance_protocol.verify(
                instance,
                si_proof,
                transcript,
            )?;
            single_outputs.push(output);
        }
        
        // Step 2: Verify merged sumcheck claims
        self.verify_merged_sumcheck_claims(
            &single_outputs,
            &proof.merged_sumcheck_outputs,
            transcript,
        )?;
        
        // Step 3: Verify evaluation consistency
        self.verify_evaluation_consistency_from_outputs(
            &single_outputs,
            &proof.merged_sumcheck_outputs,
        )?;
        
        // Step 4: Recompute folding challenge β ← S^{ℓ_np}
        let beta = self.sample_folding_challenge(transcript, ell_np)?;
        
        // Verify β matches proof
        if beta.len() != proof.folding_challenge.len() {
            return Err("Folding challenge length mismatch".to_string());
        }
        for (b1, b2) in beta.iter().zip(&proof.folding_challenge) {
            if b1 != b2 {
                return Err("Folding challenge mismatch".to_string());
            }
        }
        
        // Step 5: Verify folded commitments
        let expected_commitment = self.fold_commitments(instances, &beta)?;
        if expected_commitment != output.linear_instance.commitment {
            return Err("Folded commitment mismatch".to_string());
        }
        
        // Step 6: Verify output consistency
        self.verify_output_consistency(
            &single_outputs,
            output,
            &proof.merged_sumcheck_outputs,
        )?;
        
        Ok(true)
    }
    
    /// Execute ℓ_np parallel Π_gr1cs with shared randomness
    fn execute_parallel_reductions(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        witnesses: &[GeneralizedR1CSWitness<F>],
        transcript: &mut Transcript,
    ) -> Result<Vec<(SingleInstanceOutput<F>, SingleInstanceProof<F>)>, String> {
        let ell_np = instances.len();
        let mut outputs = Vec::with_capacity(ell_np);
        
        // Generate shared randomness for all instances
        // This is critical for batching: all instances use same challenges
        let shared_seed = transcript.challenge_bytes(b"shared_randomness", 32);
        
        for (instance, witness) in instances.iter().zip(witnesses) {
            // Create instance-specific transcript that includes shared seed
            let mut instance_transcript = transcript.clone();
            instance_transcript.append_message(b"shared_seed", &shared_seed);
            instance_transcript.append_message(
                b"instance_index",
                &outputs.len().to_le_bytes(),
            );
            
            // Execute single-instance reduction
            let (output, proof) = self.single_instance_protocol.reduce(
                instance,
                witness,
                &mut instance_transcript,
            )?;
            
            outputs.push((output, proof));
        }
        
        Ok(outputs)
    }
    
    /// Merge 2ℓ_np sumcheck claims into 2 claims using random linear combination
    /// 
    /// First merged claim (Hadamard): Σ_{b,ℓ,j} α^{(ℓ-1)·d+j-1}·f_{ℓ,j}(b) = 0
    /// Second merged claim (Monomial): batched monomial checks with α combiners
    fn merge_sumcheck_claims(
        &self,
        parallel_outputs: &[(SingleInstanceOutput<F>, SingleInstanceProof<F>)],
        transcript: &mut Transcript,
    ) -> Result<MergedSumcheckOutputs<F>, String> {
        let ell_np = parallel_outputs.len();
        let d = self.ring.degree();
        
        // Sample random combiner α ← K
        let alpha = self.sample_extension_field_challenge(transcript, b"alpha")?;
        
        // Merge Hadamard sumcheck claims
        // Each instance has d Hadamard checks, we combine all ℓ_np·d checks
        let mut hadamard_sum = SymphonyExtensionField::zero();
        let mut alpha_power = SymphonyExtensionField::one();
        
        for (output, _) in parallel_outputs {
            for j in 0..d {
                // Get Hadamard output for instance ℓ, component j
                let hadamard_j = &output.hadamard_outputs[j];
                
                // Accumulate: α^{(ℓ-1)·d+j-1}·e_{ℓ,j}
                hadamard_sum = hadamard_sum.add(&hadamard_j.mul(&alpha_power));
                alpha_power = alpha_power.mul(&alpha);
            }
        }
        
        // Merge monomial check claims
        // Each instance has k_g monomial vectors, we combine all ℓ_np·k_g checks
        let k_g = parallel_outputs[0].0.monomial_outputs.len();
        let mut monomial_outputs = Vec::with_capacity(k_g);
        
        for i in 0..k_g {
            let mut monomial_sum = TensorElement::zero(self.ring.degree());
            let mut alpha_power = SymphonyExtensionField::one();
            
            for (output, _) in parallel_outputs {
                let monomial_i = &output.monomial_outputs[i];
                
                // Accumulate: α^{ℓ-1}·u^(i)_ℓ
                monomial_sum = monomial_sum.add(&monomial_i.scalar_mul(&alpha_power));
                alpha_power = alpha_power.mul(&alpha);
            }
            
            monomial_outputs.push(monomial_sum);
        }
        
        // Use shared evaluation point from first instance
        // All instances share the same evaluation point due to shared randomness
        let evaluation_point = parallel_outputs[0].0.evaluation_point.clone();
        
        Ok(MergedSumcheckOutputs {
            hadamard_output: hadamard_sum,
            monomial_output: monomial_outputs,
            evaluation_point,
        })
    }
    
    /// Verify merged sumcheck claims (verifier version)
    fn verify_merged_sumcheck_claims(
        &self,
        single_outputs: &[SingleInstanceOutput<F>],
        merged_outputs: &MergedSumcheckOutputs<F>,
        transcript: &mut Transcript,
    ) -> Result<(), String> {
        let d = self.ring.degree();
        
        // Recompute random combiner α ← K
        let alpha = self.sample_extension_field_challenge(transcript, b"alpha")?;
        
        // Verify Hadamard merge
        let mut expected_hadamard = SymphonyExtensionField::zero();
        let mut alpha_power = SymphonyExtensionField::one();
        
        for output in single_outputs {
            for j in 0..d {
                let hadamard_j = &output.hadamard_outputs[j];
                expected_hadamard = expected_hadamard.add(&hadamard_j.mul(&alpha_power));
                alpha_power = alpha_power.mul(&alpha);
            }
        }
        
        if expected_hadamard != merged_outputs.hadamard_output {
            return Err("Merged Hadamard output mismatch".to_string());
        }
        
        // Verify monomial merge
        let k_g = single_outputs[0].monomial_outputs.len();
        for i in 0..k_g {
            let mut expected_monomial = TensorElement::zero(self.ring.degree());
            let mut alpha_power = SymphonyExtensionField::one();
            
            for output in single_outputs {
                let monomial_i = &output.monomial_outputs[i];
                expected_monomial = expected_monomial.add(&monomial_i.scalar_mul(&alpha_power));
                alpha_power = alpha_power.mul(&alpha);
            }
            
            if expected_monomial != merged_outputs.monomial_output[i] {
                return Err(format!("Merged monomial output {} mismatch", i));
            }
        }
        
        Ok(())
    }
    
    /// Verify evaluation consistency between parallel outputs and merged outputs
    fn verify_evaluation_consistency(
        &self,
        parallel_outputs: &[(SingleInstanceOutput<F>, SingleInstanceProof<F>)],
        merged_outputs: &MergedSumcheckOutputs<F>,
    ) -> Result<(), String> {
        // Verify all instances share the same evaluation point
        for (i, (output, _)) in parallel_outputs.iter().enumerate() {
            if output.evaluation_point.len() != merged_outputs.evaluation_point.len() {
                return Err(format!(
                    "Instance {} evaluation point length mismatch",
                    i
                ));
            }
            
            for (j, (e1, e2)) in output.evaluation_point.iter()
                .zip(&merged_outputs.evaluation_point)
                .enumerate()
            {
                if e1 != e2 {
                    return Err(format!(
                        "Instance {} evaluation point mismatch at position {}",
                        i, j
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Verify evaluation consistency from outputs (verifier version)
    fn verify_evaluation_consistency_from_outputs(
        &self,
        single_outputs: &[SingleInstanceOutput<F>],
        merged_outputs: &MergedSumcheckOutputs<F>,
    ) -> Result<(), String> {
        // Similar to verify_evaluation_consistency but for verifier
        for (i, output) in single_outputs.iter().enumerate() {
            if output.evaluation_point.len() != merged_outputs.evaluation_point.len() {
                return Err(format!(
                    "Instance {} evaluation point length mismatch",
                    i
                ));
            }
            
            for (j, (e1, e2)) in output.evaluation_point.iter()
                .zip(&merged_outputs.evaluation_point)
                .enumerate()
            {
                if e1 != e2 {
                    return Err(format!(
                        "Instance {} evaluation point mismatch at position {}",
                        i, j
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Sample folding challenge β ← S^{ℓ_np} from challenge set S
    fn sample_folding_challenge(
        &self,
        transcript: &mut Transcript,
        ell_np: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        let mut beta = Vec::with_capacity(ell_np);
        
        for i in 0..ell_np {
            // Sample index from challenge set
            let challenge_bytes = transcript.challenge_bytes(
                b"folding_challenge",
                32,
            );
            
            // Convert to index in challenge set
            let mut index_bytes = [0u8; 8];
            index_bytes.copy_from_slice(&challenge_bytes[..8]);
            let index = u64::from_le_bytes(index_bytes) as usize % self.challenge_set.len();
            
            // Get challenge from set
            let challenge = self.challenge_set[index].clone();
            beta.push(challenge);
            
            // Update transcript for next challenge
            transcript.append_message(b"beta_index", &i.to_le_bytes());
        }
        
        Ok(beta)
    }
    
    /// Compute folded commitments: c_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·c_ℓ
    fn fold_commitments(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        beta: &[RingElement<F>],
    ) -> Result<Commitment<F>, String> {
        if instances.len() != beta.len() {
            return Err("Instance and challenge count mismatch".to_string());
        }
        
        // Initialize with zero commitment
        let mut folded = Commitment::zero();
        
        // Accumulate: c_* = Σ β_ℓ·c_ℓ
        for (instance, beta_ell) in instances.iter().zip(beta) {
            let scaled = instance.commitment.scalar_mul(beta_ell)?;
            folded = folded.add(&scaled)?;
        }
        
        Ok(folded)
    }
    
    /// Compute folded witnesses: f_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ
    fn fold_witnesses(
        &self,
        witnesses: &[GeneralizedR1CSWitness<F>],
        beta: &[RingElement<F>],
    ) -> Result<FoldedWitness<F>, String> {
        if witnesses.len() != beta.len() {
            return Err("Witness and challenge count mismatch".to_string());
        }
        
        let n = witnesses[0].witness_matrix.len();
        let mut folded_witness = vec![RingElement::zero(&self.ring); n];
        
        // Accumulate: f_* = Σ β_ℓ·f_ℓ
        for (witness, beta_ell) in witnesses.iter().zip(beta) {
            if witness.witness_matrix.len() != n {
                return Err("Witness dimension mismatch".to_string());
            }
            
            for (i, f_ell_i) in witness.witness_matrix.iter().enumerate() {
                // f_*[i] += β_ℓ·f_ℓ[i]
                let scaled = f_ell_i.mul(beta_ell);
                folded_witness[i] = folded_witness[i].add(&scaled);
            }
        }
        
        // Compute folded opening scalar (sum of individual opening scalars)
        let mut opening_scalar = RingElement::zero(&self.ring);
        for (witness, beta_ell) in witnesses.iter().zip(beta) {
            let scaled = witness.opening_scalar.mul(beta_ell);
            opening_scalar = opening_scalar.add(&scaled);
        }
        
        // Compute norm of folded witness
        let norm = Self::compute_witness_norm(&folded_witness);
        
        Ok(FoldedWitness {
            witness: folded_witness,
            opening_scalar,
            norm,
        })
    }
    
    /// Verify folded witness satisfies norm bounds
    /// 
    /// Theorem 4.1: ∥f_*∥_2 ≤ ℓ_np·∥S∥_op·B√(nd/ℓ_h)
    fn verify_folded_norm_bounds(
        &self,
        folded_witness: &FoldedWitness<F>,
        instance: &GeneralizedR1CSInstance<F>,
    ) -> Result<(), String> {
        let ell_np = self.folding_arity as f64;
        let s_op_norm = 15.0; // ∥S∥_op ≤ 15 from challenge set design
        let n = folded_witness.witness.len() as f64;
        let d = self.ring.degree() as f64;
        let ell_h = instance.block_size as f64;
        let b = instance.norm_bound;
        
        // Compute bound: ℓ_np·∥S∥_op·B√(nd/ℓ_h)
        let bound = ell_np * s_op_norm * b * (n * d / ell_h).sqrt();
        
        if folded_witness.norm > bound {
            return Err(format!(
                "Folded witness norm {} exceeds bound {}",
                folded_witness.norm, bound
            ));
        }
        
        Ok(())
    }
    
    /// Construct folded output from folding results
    fn construct_folded_output(
        &self,
        folded_commitment: Commitment<F>,
        folded_witness: FoldedWitness<F>,
        merged_outputs: &MergedSumcheckOutputs<F>,
        parallel_outputs: &[(SingleInstanceOutput<F>, SingleInstanceProof<F>)],
    ) -> Result<FoldedOutput<F>, String> {
        // Construct linear instance from Hadamard output
        let linear_instance = LinearInstance {
            commitment: folded_commitment.clone(),
            evaluation_point: merged_outputs.evaluation_point.clone(),
            claimed_value: merged_outputs.hadamard_output.clone(),
        };
        
        // Construct batch linear instance from monomial outputs
        let batch_linear_instance = BatchLinearInstance {
            commitment: folded_commitment,
            evaluation_point: merged_outputs.evaluation_point.clone(),
            claimed_values: merged_outputs.monomial_output.clone(),
        };
        
        // Collect message commitments from all parallel proofs
        let mut message_commitments = Vec::new();
        for (_, proof) in parallel_outputs {
            message_commitments.extend(proof.message_commitments.clone());
        }
        
        Ok(FoldedOutput {
            linear_instance,
            batch_linear_instance,
            folded_witness: Some(folded_witness),
            message_commitments,
        })
    }
    
    /// Verify output consistency
    fn verify_output_consistency(
        &self,
        single_outputs: &[SingleInstanceOutput<F>],
        folded_output: &FoldedOutput<F>,
        merged_outputs: &MergedSumcheckOutputs<F>,
    ) -> Result<(), String> {
        // Verify linear instance consistency
        if folded_output.linear_instance.claimed_value != merged_outputs.hadamard_output {
            return Err("Linear instance claimed value mismatch".to_string());
        }
        
        // Verify batch linear instance consistency
        if folded_output.batch_linear_instance.claimed_values.len() 
            != merged_outputs.monomial_output.len() 
        {
            return Err("Batch linear instance length mismatch".to_string());
        }
        
        for (v1, v2) in folded_output.batch_linear_instance.claimed_values.iter()
            .zip(&merged_outputs.monomial_output)
        {
            if v1 != v2 {
                return Err("Batch linear instance claimed value mismatch".to_string());
            }
        }
        
        Ok(())
    }
    
    /// Generate challenge set S ⊆ Rq with ∥S∥_op ≤ 15
    /// 
    /// Uses LaBRADOR challenge set design from Section 2.2
    fn generate_challenge_set(
        ring: &CyclotomicRing<F>,
        size: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        let d = ring.degree();
        let mut challenge_set = Vec::with_capacity(size);
        
        // Generate challenges with small coefficients
        // LaBRADOR uses coefficients in {-1, 0, 1} with controlled Hamming weight
        for i in 0..size {
            let mut coeffs = vec![F::zero(); d];
            
            // Use deterministic generation based on index
            let mut seed = i;
            let hamming_weight = d / 4; // 25% non-zero coefficients
            
            for j in 0..hamming_weight {
                let pos = (seed * 6364136223846793005 + 1442695040888963407) % d;
                let sign = if (seed & 1) == 0 { F::one() } else { F::zero().sub(&F::one()) };
                coeffs[pos] = sign;
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            }
            
            let element = RingElement::from_coefficients(coeffs, ring.clone())?;
            
            // Verify operator norm
            let op_norm = element.operator_norm();
            if op_norm > 15.0 {
                return Err(format!(
                    "Challenge {} has operator norm {} > 15",
                    i, op_norm
                ));
            }
            
            challenge_set.push(element);
        }
        
        Ok(challenge_set)
    }
    
    /// Sample extension field challenge from transcript
    fn sample_extension_field_challenge(
        &self,
        transcript: &mut Transcript,
        label: &[u8],
    ) -> Result<SymphonyExtensionField<F>, String> {
        let challenge_bytes = transcript.challenge_bytes(label, 32);
        SymphonyExtensionField::from_bytes(&challenge_bytes)
    }
    
    /// Compute L2 norm of witness vector
    fn compute_witness_norm(witness: &[RingElement<F>]) -> f64 {
        let mut sum_sq = 0.0;
        for w in witness {
            let norm = w.l2_norm();
            sum_sq += norm * norm;
        }
        sum_sq.sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_high_arity_folding_basic() {
        let ring = CyclotomicRing::<M61>::new(64).unwrap();
        let protocol = HighArityFoldingProtocol::new(ring, 256, 2).unwrap();
        
        assert_eq!(protocol.folding_arity, 2);
        assert_eq!(protocol.challenge_set_size, 256);
        assert!(!protocol.challenge_set.is_empty());
    }
    
    #[test]
    fn test_challenge_set_generation() {
        let ring = CyclotomicRing::<M61>::new(64).unwrap();
        let challenge_set = HighArityFoldingProtocol::<M61>::generate_challenge_set(&ring, 128).unwrap();
        
        assert_eq!(challenge_set.len(), 128);
        
        for elem in &challenge_set {
            let norm = elem.operator_norm();
            assert!(norm <= 15.0, "Challenge set element has norm {}, expected ≤ 15", norm);
        }
    }
    
    #[test]
    fn test_sumcheck_merging() {
        let ring = CyclotomicRing::<M61>::new(64).unwrap();
        let protocol = HighArityFoldingProtocol::new(ring, 256, 2).unwrap();
        
        let outputs = vec![
            SingleInstanceOutput {
                linear_instance: LinearInstance {
                    commitment: Commitment { elements: vec![RingElement::zero()] },
                    evaluation_point: vec![SymphonyExtensionField::zero()],
                    claimed_value: SymphonyExtensionField::zero(),
                },
                batch_linear_instance: BatchLinearInstance {
                    commitment: Commitment { elements: vec![RingElement::zero()] },
                    evaluation_point: vec![SymphonyExtensionField::zero()],
                    claimed_values: vec![TensorElement::zero()],
                },
            },
            SingleInstanceOutput {
                linear_instance: LinearInstance {
                    commitment: Commitment { elements: vec![RingElement::zero()] },
                    evaluation_point: vec![SymphonyExtensionField::zero()],
                    claimed_value: SymphonyExtensionField::zero(),
                },
                batch_linear_instance: BatchLinearInstance {
                    commitment: Commitment { elements: vec![RingElement::zero()] },
                    evaluation_point: vec![SymphonyExtensionField::zero()],
                    claimed_values: vec![TensorElement::zero()],
                },
            },
        ];
        
        let mut transcript = Transcript::new(b"test");
        let merged = protocol.merge_sumcheck_claims(&outputs, &mut transcript).unwrap();
        
        assert_eq!(merged.hadamard_output, SymphonyExtensionField::zero());
        assert!(!merged.monomial_output.is_empty());
    }
    
    #[test]
    fn test_witness_folding() {
        let ring = CyclotomicRing::<M61>::new(64).unwrap();
        let protocol = HighArityFoldingProtocol::new(ring.clone(), 256, 2).unwrap();
        
        let witnesses = vec![
            GeneralizedR1CSWitness {
                witness_matrix: vec![vec![M61::from_u64(1); 10]; 5],
            },
            GeneralizedR1CSWitness {
                witness_matrix: vec![vec![M61::from_u64(2); 10]; 5],
            },
        ];
        
        let beta = vec![RingElement::one(), RingElement::one()];
        let folded = protocol.fold_witnesses(&witnesses, &beta).unwrap();
        
        assert!(!folded.witness.is_empty());
        assert!(folded.norm >= 0.0);
    }
    
    #[test]
    fn test_norm_bounds() {
        let ring = CyclotomicRing::<M61>::new(64).unwrap();
        let protocol = HighArityFoldingProtocol::new(ring.clone(), 256, 2).unwrap();
        
        let witnesses = vec![
            GeneralizedR1CSWitness {
                witness_matrix: vec![vec![M61::from_u64(1); 10]; 5],
            },
            GeneralizedR1CSWitness {
                witness_matrix: vec![vec![M61::from_u64(1); 10]; 5],
            },
        ];
        
        let beta = vec![RingElement::one(), RingElement::one()];
        let folded = protocol.fold_witnesses(&witnesses, &beta).unwrap();
        
        assert!(folded.norm < 1000.0, "Witness norm {} exceeds expected bound", folded.norm);
    }
}
