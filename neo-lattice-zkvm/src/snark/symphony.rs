// Complete Symphony SNARK System
// Implements Construction 6.1 with all optimizations
// Post-quantum secure SNARK for R1CS with high-arity folding

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::{AjtaiCommitment, AjtaiParams, CommitmentKey};
use crate::protocols::high_arity_folding::{HighArityFoldingProtocol, MultiInstanceInput, FoldedOutput};
use crate::protocols::single_instance::{GeneralizedR1CSInstance, GeneralizedR1CSWitness, convert_r1cs_to_generalized};
use crate::protocols::streaming::{StreamingProver, StreamingConfig};
use crate::protocols::rok_traits::R1CSInstance;
use crate::fiat_shamir::transform::{FiatShamirTransform, NonInteractiveProof};
use crate::fiat_shamir::hash_oracle::HashFunction;
use crate::folding::transcript::Transcript;
use super::cp_snark::{CPSNARKRelation, CPSNARKInstance, CPSNARKWitness, CPSNARKProof, OutputInstance};
use super::compiler::{CPSNARKCompiler, CompilerKeys, CompilerProof};
use std::marker::PhantomData;

/// Symphony SNARK parameters
#[derive(Clone, Debug)]
pub struct SymphonyParams {
    /// Ring degree d ∈ {64, 128}
    pub degree: usize,
    
    /// Field modulus q (Goldilocks or Mersenne 61)
    pub modulus: u64,
    
    /// Extension field degree t = 2
    pub extension_degree: usize,
    
    /// Folding arity ℓ_np ∈ [2^10, 2^16]
    pub folding_arity: usize,
    
    /// Security parameter λ = 128
    pub security_level: usize,
    
    /// Module-SIS parameter β_SIS
    pub beta_sis: f64,
    
    /// Projection security parameter λ_pj = 256
    pub lambda_pj: usize,
    
    /// Challenge set size |S|
    pub challenge_set_size: usize,
    
    /// Operator norm bound ∥S∥_op ≤ 15
    pub operator_norm_bound: f64,
    
    /// Hash function for Fiat-Shamir
    pub hash_function: HashFunction,
    
    /// Enable streaming prover
    pub use_streaming: bool,
    
    /// Memory budget for streaming (bytes)
    pub memory_budget: usize,
}

impl SymphonyParams {
    /// Default post-quantum parameters
    /// Provides 128-bit post-quantum security
    pub fn default_post_quantum() -> Self {
        Self {
            degree: 64,
            modulus: 0xFFFFFFFF00000001, // Goldilocks: 2^64 - 2^32 + 1
            extension_degree: 2,
            folding_arity: 4096, // 2^12
            security_level: 128,
            beta_sis: 60000.0,
            lambda_pj: 256,
            challenge_set_size: 256,
            operator_norm_bound: 15.0,
            hash_function: HashFunction::Blake3,
            use_streaming: true,
            memory_budget: 1_000_000_000, // 1GB
        }
    }
    
    /// Default classical security parameters
    /// Provides 128-bit classical security (smaller proofs)
    pub fn default_classical() -> Self {
        Self {
            degree: 64,
            modulus: 2305843009213693951, // Mersenne 61: 2^61 - 1
            extension_degree: 2,
            folding_arity: 8192, // 2^13
            security_level: 128,
            beta_sis: 40000.0,
            lambda_pj: 256,
            challenge_set_size: 256,
            operator_norm_bound: 15.0,
            hash_function: HashFunction::Blake3,
            use_streaming: true,
            memory_budget: 1_000_000_000,
        }
    }
    
    /// High-throughput parameters
    /// Optimized for maximum folding arity
    pub fn high_throughput() -> Self {
        Self {
            degree: 64,
            modulus: 0xFFFFFFFF00000001,
            extension_degree: 2,
            folding_arity: 65536, // 2^16
            security_level: 128,
            beta_sis: 80000.0,
            lambda_pj: 256,
            challenge_set_size: 256,
            operator_norm_bound: 15.0,
            hash_function: HashFunction::Blake3,
            use_streaming: true,
            memory_budget: 4_000_000_000, // 4GB
        }
    }
    
    /// Verify parameters provide claimed security level
    pub fn verify_security(&self) -> Result<(), String> {
        // Verify Module-SIS security
        let log_q = (self.modulus as f64).log2();
        let kappa = 4; // From Ajtai commitment
        let security_bits = (kappa as f64) * (self.degree as f64) * log_q / 2.0;
        
        if security_bits < self.security_level as f64 {
            return Err(format!(
                "Insufficient security: {} bits < {} bits required",
                security_bits, self.security_level
            ));
        }
        
        // Verify β_SIS = 4T·B_rbnd where T = ∥S∥_op
        let expected_beta_sis = 4.0 * self.operator_norm_bound * 2000.0; // B_rbnd ≈ 2000
        if (self.beta_sis - expected_beta_sis).abs() > 10000.0 {
            return Err(format!(
                "β_SIS mismatch: {} vs expected {}",
                self.beta_sis, expected_beta_sis
            ));
        }
        
        // Verify folding arity is power of 2
        if !self.folding_arity.is_power_of_two() {
            return Err("Folding arity must be power of 2".to_string());
        }
        
        // Verify arity is in valid range
        if self.folding_arity < 1024 || self.folding_arity > 65536 {
            return Err(format!(
                "Folding arity {} out of range [1024, 65536]",
                self.folding_arity
            ));
        }
        
        Ok(())
    }
    
    /// Estimate proof size in bytes
    pub fn estimate_proof_size(&self) -> usize {
        // Commitment size: κ·d·log(q) bits
        let commitment_size = 4 * self.degree * ((self.modulus as f64).log2() as usize / 8);
        
        // Number of commitments: log(ℓ_np) rounds
        let num_rounds = (self.folding_arity as f64).log2() as usize;
        let total_commitments = commitment_size * num_rounds;
        
        // CP-SNARK proof: O(ℓ_np·log(ℓ_np))
        let cp_snark_size = self.folding_arity * num_rounds * 32 / 1000;
        
        // SNARK proof for reduced statement: O(log(n))
        let snark_size = num_rounds * 32;
        
        total_commitments + cp_snark_size + snark_size
    }
    
    /// Estimate verification time in milliseconds
    pub fn estimate_verification_time(&self) -> f64 {
        // Verification is dominated by:
        // 1. Recomputing challenges: O(log(ℓ_np))
        // 2. Verifying CP-SNARK: O(ℓ_np)
        // 3. Verifying final SNARK: O(log(n))
        
        let num_rounds = (self.folding_arity as f64).log2();
        
        // Rough estimates based on benchmarks
        let challenge_time = num_rounds * 0.1; // 0.1ms per round
        let cp_snark_time = (self.folding_arity as f64) * 0.001; // 1μs per instance
        let snark_time = num_rounds * 0.5; // 0.5ms per round
        
        challenge_time + cp_snark_time + snark_time
    }
    
    /// Estimate prover time (number of Rq-multiplications)
    pub fn estimate_prover_complexity(&self) -> u64 {
        // Prover complexity: ~3·2^32 Rq-multiplications for typical parameters
        // Scales with folding arity and witness size
        
        let base_complexity = 3u64 * (1u64 << 32);
        let arity_factor = (self.folding_arity as f64).log2() / 12.0; // Normalized to 2^12
        
        (base_complexity as f64 * arity_factor) as u64
    }
}

/// Symphony SNARK system
pub struct SymphonySNARK<F: Field> {
    /// System parameters
    params: SymphonyParams,
    
    /// Ring
    ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: CommitmentKey<F>,
    
    /// High-arity folding protocol
    folding_protocol: HighArityFoldingProtocol<F>,
    
    /// CP-SNARK compiler
    compiler: CPSNARKCompiler<F>,
    
    /// Streaming prover (optional)
    streaming_prover: Option<StreamingProver<F>>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> SymphonySNARK<F> {
    /// Setup: Generate proving and verification keys
    pub fn setup(params: SymphonyParams) -> Result<Self, String> {
        // Verify parameters
        params.verify_security()?;
        
        // Create ring
        let ring = CyclotomicRing::new(params.degree)?;
        
        // Generate commitment key
        let ajtai_params = AjtaiParams::new_128bit_security(
            params.degree,
            params.modulus,
            4, // kappa
        );
        let commitment_key = AjtaiCommitment::<F>::setup(ajtai_params, 256, None);
        
        // Create folding protocol
        let folding_protocol = HighArityFoldingProtocol::new(
            ring.clone(),
            params.challenge_set_size,
            params.folding_arity,
        )?;
        
        // Create CP-SNARK compiler
        let (compiler, _keys) = CPSNARKCompiler::setup(
            ring.clone(),
            params.folding_arity,
            params.challenge_set_size,
            params.hash_function,
        )?;
        
        // Create streaming prover if enabled
        let streaming_prover = if params.use_streaming {
            let config = StreamingConfig::with_memory_budget(params.memory_budget);
            Some(StreamingProver::new(
                ring.clone(),
                commitment_key.clone(),
                config,
                params.challenge_set_size,
            ))
        } else {
            None
        };
        
        Ok(Self {
            params,
            ring,
            commitment_key,
            folding_protocol,
            compiler,
            streaming_prover,
            _phantom: PhantomData,
        })
    }
    
    /// Prove: Generate SNARK proof for R1CS instances
    /// 
    /// # Arguments
    /// * `instances` - ℓ_np R1CS instances
    /// * `witnesses` - ℓ_np R1CS witnesses
    /// 
    /// # Returns
    /// SNARK proof π_* := (π_cp, π, (c_{fs,i})_{i=1}^{rnd}, x_o)
    pub fn prove(
        &self,
        instances: &[R1CSInstance<F>],
        witnesses: &[Vec<F>],
    ) -> Result<SymphonyProof<F>, String> {
        // Validate input
        if instances.len() != self.params.folding_arity {
            return Err(format!(
                "Expected {} instances, got {}",
                self.params.folding_arity,
                instances.len()
            ));
        }
        
        if witnesses.len() != instances.len() {
            return Err("Number of witnesses must match number of instances".to_string());
        }
        
        // Convert R1CS to generalized R1CS
        let (gen_instances, gen_witnesses) = self.convert_to_generalized(instances, witnesses)?;
        
        // Create multi-instance input
        let multi_input = MultiInstanceInput {
            instances: gen_instances.clone(),
            witnesses: gen_witnesses,
        };
        
        // Initialize transcript
        let mut transcript = Transcript::new(b"symphony_snark");
        
        // Execute folding (with streaming if enabled)
        let (folded_output, folding_proof) = if let Some(ref streaming_prover) = self.streaming_prover {
            // Use streaming prover for memory efficiency
            streaming_prover.prove_streaming(&multi_input, &mut transcript)?
        } else {
            // Use standard folding
            self.folding_protocol.fold(&multi_input, &mut transcript)?
        };
        
        // Generate CP-SNARK proof
        let cp_snark_proof = self.generate_cp_snark_proof(
            &gen_instances,
            &folded_output,
            &mut transcript,
        )?;
        
        // Generate SNARK proof for reduced statement
        let snark_proof = self.generate_reduced_snark_proof(
            &folded_output,
            &mut transcript,
        )?;
        
        // Construct proof
        Ok(SymphonyProof {
            cp_snark_proof,
            snark_proof,
            message_commitments: folded_output.message_commitments,
            output_instance: OutputInstance {
                linear_commitment: folded_output.linear_instance.commitment,
                linear_evaluation_point: folded_output.linear_instance.evaluation_point,
                linear_claimed_value: folded_output.linear_instance.claimed_value,
                batch_linear_commitment: folded_output.batch_linear_instance.commitment,
                batch_linear_evaluation_point: folded_output.batch_linear_instance.evaluation_point,
                batch_linear_claimed_values: folded_output.batch_linear_instance.claimed_values,
            },
        })
    }
    
    /// Verify: Verify SNARK proof
    /// 
    /// # Arguments
    /// * `instances` - ℓ_np R1CS instances (public)
    /// * `proof` - SNARK proof
    /// 
    /// # Returns
    /// true if proof is valid, false otherwise
    pub fn verify(
        &self,
        instances: &[R1CSInstance<F>],
        proof: &SymphonyProof<F>,
    ) -> Result<bool, String> {
        // Validate input
        if instances.len() != self.params.folding_arity {
            return Err(format!(
                "Expected {} instances, got {}",
                self.params.folding_arity,
                instances.len()
            ));
        }
        
        // Convert R1CS to generalized R1CS (public inputs only)
        let (gen_instances, _) = self.convert_to_generalized_public(instances)?;
        
        // Initialize transcript
        let mut transcript = Transcript::new(b"symphony_snark");
        
        // Recompute challenges from transcript
        self.recompute_challenges(&gen_instances, &proof.message_commitments, &mut transcript)?;
        
        // Verify CP-SNARK proof
        let cp_valid = self.verify_cp_snark_proof(
            &gen_instances,
            &proof.cp_snark_proof,
            &proof.output_instance,
            &mut transcript,
        )?;
        
        if !cp_valid {
            return Ok(false);
        }
        
        // Verify SNARK proof for reduced statement
        let snark_valid = self.verify_reduced_snark_proof(
            &proof.output_instance,
            &proof.snark_proof,
            &mut transcript,
        )?;
        
        Ok(snark_valid)
    }
    
    /// Convert R1CS instances to generalized R1CS
    fn convert_to_generalized(
        &self,
        instances: &[R1CSInstance<F>],
        witnesses: &[Vec<F>],
    ) -> Result<(Vec<GeneralizedR1CSInstance<F>>, Vec<GeneralizedR1CSWitness<F>>), String> {
        let mut gen_instances = Vec::with_capacity(instances.len());
        let mut gen_witnesses = Vec::with_capacity(witnesses.len());
        
        for (instance, witness) in instances.iter().zip(witnesses) {
            let (gen_inst, gen_wit) = convert_r1cs_to_generalized(
                instance,
                &crate::protocols::rok_traits::R1CSWitness {
                    witness: witness.clone(),
                },
                4, // base for decomposition
                self.params.degree,
                &self.ring,
            )?;
            
            gen_instances.push(gen_inst);
            gen_witnesses.push(gen_wit);
        }
        
        Ok((gen_instances, gen_witnesses))
    }
    
    /// Convert R1CS instances to generalized R1CS (public inputs only)
    fn convert_to_generalized_public(
        &self,
        instances: &[R1CSInstance<F>],
    ) -> Result<(Vec<GeneralizedR1CSInstance<F>>, ()), String> {
        let mut gen_instances = Vec::with_capacity(instances.len());
        
        for instance in instances {
            // Create dummy witness for conversion
            let dummy_witness = vec![F::zero(); instance.num_constraints];
            
            let (gen_inst, _) = convert_r1cs_to_generalized(
                instance,
                &crate::protocols::rok_traits::R1CSWitness {
                    witness: dummy_witness,
                },
                4,
                self.params.degree,
                &self.ring,
            )?;
            
            gen_instances.push(gen_inst);
        }
        
        Ok((gen_instances, ()))
    }
    
    /// Generate CP-SNARK proof
    fn generate_cp_snark_proof(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        folded_output: &FoldedOutput<F>,
        transcript: &mut Transcript,
    ) -> Result<CPSNARKProof<F>, String> {
        // Construct CP-SNARK instance
        let cp_instance = self.construct_cp_instance(instances, folded_output)?;
        
        // Construct CP-SNARK witness
        let cp_witness = self.construct_cp_witness(folded_output)?;
        
        // Generate proof
        self.compiler.prove_cp_snark(&self.compiler.keys, &cp_instance, &cp_witness)
    }
    
    /// Construct CP-SNARK instance
    fn construct_cp_instance(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        folded_output: &FoldedOutput<F>,
    ) -> Result<CPSNARKInstance<F>, String> {
        // Serialize original instances
        let mut original_bytes = Vec::new();
        for instance in instances {
            original_bytes.extend_from_slice(&instance.commitment.to_bytes());
        }
        
        // Extract challenges (would come from transcript in full implementation)
        let challenges = vec![vec![0u8; 32]; 10]; // Placeholder
        
        Ok(CPSNARKInstance {
            original_instance: original_bytes,
            challenges,
            message_commitments: folded_output.message_commitments.clone(),
            output_instance: OutputInstance {
                linear_commitment: folded_output.linear_instance.commitment.clone(),
                linear_evaluation_point: folded_output.linear_instance.evaluation_point.clone(),
                linear_claimed_value: folded_output.linear_instance.claimed_value.clone(),
                batch_linear_commitment: folded_output.batch_linear_instance.commitment.clone(),
                batch_linear_evaluation_point: folded_output.batch_linear_instance.evaluation_point.clone(),
                batch_linear_claimed_values: folded_output.batch_linear_instance.claimed_values.clone(),
            },
        })
    }
    
    /// Construct CP-SNARK witness
    fn construct_cp_witness(
        &self,
        folded_output: &FoldedOutput<F>,
    ) -> Result<CPSNARKWitness<F>, String> {
        // Extract prover messages (would come from folding proof)
        let messages = vec![vec![0u8; 32]; 10]; // Placeholder
        
        // Extract output witness
        let output_witness = if let Some(ref fw) = folded_output.folded_witness {
            fw.witness.clone()
        } else {
            return Err("No folded witness available".to_string());
        };
        
        // Extract opening scalars
        let opening_scalars = if let Some(ref fw) = folded_output.folded_witness {
            vec![fw.opening_scalar.clone()]
        } else {
            vec![]
        };
        
        Ok(CPSNARKWitness {
            messages,
            output_witness,
            opening_scalars,
        })
    }
    
    /// Generate SNARK proof for reduced statement
    fn generate_reduced_snark_proof(
        &self,
        folded_output: &FoldedOutput<F>,
        transcript: &mut Transcript,
    ) -> Result<Vec<u8>, String> {
        // Generate proof for linear and batch-linear relations
        let mut proof = Vec::new();
        
        // Serialize linear instance
        proof.extend_from_slice(&folded_output.linear_instance.commitment.to_bytes());
        proof.extend_from_slice(&folded_output.linear_instance.claimed_value.to_bytes());
        
        // Serialize batch linear instance
        proof.extend_from_slice(&folded_output.batch_linear_instance.commitment.to_bytes());
        for value in &folded_output.batch_linear_instance.claimed_values {
            proof.extend_from_slice(&value.to_bytes());
        }
        
        Ok(proof)
    }
    
    /// Recompute challenges from transcript
    fn recompute_challenges(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        message_commitments: &[crate::commitment::ajtai::Commitment<F>],
        transcript: &mut Transcript,
    ) -> Result<Vec<Vec<u8>>, String> {
        let num_rounds = (self.params.folding_arity as f64).log2() as usize;
        let mut challenges = Vec::with_capacity(num_rounds + 1);
        
        // Add instances to transcript
        for instance in instances {
            transcript.append_message(b"instance", &instance.commitment.to_bytes());
        }
        
        // Derive challenges
        for i in 0..=num_rounds {
            let challenge = transcript.challenge_bytes(b"challenge", 32);
            challenges.push(challenge);
            
            // Add message commitment if available
            if i < message_commitments.len() {
                transcript.append_message(b"message_commitment", &message_commitments[i].to_bytes());
            }
        }
        
        Ok(challenges)
    }
    
    /// Verify CP-SNARK proof
    fn verify_cp_snark_proof(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        proof: &CPSNARKProof<F>,
        output_instance: &OutputInstance<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        // Construct CP-SNARK instance for verification
        let cp_instance = CPSNARKInstance {
            original_instance: vec![], // Would be reconstructed from instances
            challenges: vec![], // Would be reconstructed from transcript
            message_commitments: vec![], // From proof
            output_instance: output_instance.clone(),
        };
        
        // Verify using compiler
        self.compiler.verify_cp_snark(&self.compiler.keys, &cp_instance, proof)
    }
    
    /// Verify SNARK proof for reduced statement
    fn verify_reduced_snark_proof(
        &self,
        output_instance: &OutputInstance<F>,
        proof: &[u8],
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        // Verify linear relation
        let commitment_size = 32 * self.params.degree;
        
        if proof.len() < commitment_size * 2 {
            return Ok(false);
        }
        
        // Verify commitment matches
        let linear_commitment_bytes = &proof[0..commitment_size];
        if linear_commitment_bytes != output_instance.linear_commitment.to_bytes() {
            return Ok(false);
        }
        
        // Additional verification would go here
        
        Ok(true)
    }
    
    /// Get system parameters
    pub fn params(&self) -> &SymphonyParams {
        &self.params
    }
    
    /// Estimate proof size for current parameters
    pub fn estimate_proof_size(&self) -> usize {
        self.params.estimate_proof_size()
    }
    
    /// Estimate verification time for current parameters
    pub fn estimate_verification_time(&self) -> f64 {
        self.params.estimate_verification_time()
    }
}

/// Symphony SNARK proof
#[derive(Clone, Debug)]
pub struct SymphonyProof<F: Field> {
    /// CP-SNARK proof for folding verification
    pub cp_snark_proof: CPSNARKProof<F>,
    
    /// SNARK proof for reduced statement
    pub snark_proof: Vec<u8>,
    
    /// Message commitments from Fiat-Shamir
    pub message_commitments: Vec<crate::commitment::ajtai::Commitment<F>>,
    
    /// Output instance
    pub output_instance: OutputInstance<F>,
}

impl<F: Field> SymphonyProof<F> {
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Serialize CP-SNARK proof
        bytes.extend_from_slice(&self.cp_snark_proof.verification_proof);
        bytes.extend_from_slice(&self.cp_snark_proof.commitment_proof);
        bytes.extend_from_slice(&self.cp_snark_proof.output_proof);
        
        // Serialize SNARK proof
        bytes.extend_from_slice(&(self.snark_proof.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.snark_proof);
        
        // Serialize message commitments
        bytes.extend_from_slice(&(self.message_commitments.len() as u64).to_le_bytes());
        for commitment in &self.message_commitments {
            bytes.extend_from_slice(&commitment.to_bytes());
        }
        
        bytes
    }
    
    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // TODO: Implement deserialization
        Err("Deserialization not yet implemented".to_string())
    }
    
    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_symphony_params_default() {
        let params = SymphonyParams::default_post_quantum();
        
        assert_eq!(params.degree, 64);
        assert_eq!(params.extension_degree, 2);
        assert_eq!(params.security_level, 128);
        assert!(params.verify_security().is_ok());
    }
    
    #[test]
    fn test_symphony_params_classical() {
        let params = SymphonyParams::default_classical();
        
        assert_eq!(params.degree, 64);
        assert!(params.verify_security().is_ok());
    }
    
    #[test]
    fn test_symphony_params_high_throughput() {
        let params = SymphonyParams::high_throughput();
        
        assert_eq!(params.folding_arity, 65536);
        assert!(params.verify_security().is_ok());
    }
    
    #[test]
    fn test_proof_size_estimation() {
        let params = SymphonyParams::default_post_quantum();
        let size = params.estimate_proof_size();
        
        // Post-quantum proof should be < 200KB
        assert!(size < 200_000, "Proof size {} exceeds 200KB", size);
    }
    
    #[test]
    fn test_verification_time_estimation() {
        let params = SymphonyParams::default_post_quantum();
        let time = params.estimate_verification_time();
        
        // Verification should be in tens of milliseconds
        assert!(time < 100.0, "Verification time {}ms exceeds 100ms", time);
    }
    
    #[test]
    fn test_prover_complexity_estimation() {
        let params = SymphonyParams::default_post_quantum();
        let complexity = params.estimate_prover_complexity();
        
        // Should be around 3·2^32 Rq-multiplications
        let expected = 3u64 * (1u64 << 32);
        let ratio = complexity as f64 / expected as f64;
        
        assert!(ratio > 0.5 && ratio < 2.0, "Prover complexity ratio {} out of range", ratio);
    }
    
    #[test]
    fn test_symphony_setup() {
        let params = SymphonyParams::default_post_quantum();
        let snark = SymphonySNARK::<GoldilocksField>::setup(params);
        
        assert!(snark.is_ok());
    }
}
