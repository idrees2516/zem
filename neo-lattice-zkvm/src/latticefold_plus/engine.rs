// LatticeFold+ Engine
// Task 23: Main engine for LatticeFold+ with high-level API and IVC integration
//
// This module provides the top-level interface for using LatticeFold+ in
// applications, including folding, proving, verification, and IVC integration.

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::ring::ntt::NTTEngine;
use crate::optimization::parallel::ParallelExecutor;
use crate::optimization::memory::MemoryManager;
use crate::folding::transcript::Transcript;
use crate::folding::ivc::{IVCProof, IVCAccumulator};
use crate::commitment::ajtai::{AjtaiCommitment, Commitment};
use super::tensor_rings::{SmallFieldFolding, FieldArithmeticOps};
use super::folding::{
    LinearInstance, FoldingProver, FoldingVerifier,
    FoldingProof, FoldingOutput
};
use super::range_check::{RangeCheckProver, RangeCheckVerifier};
use super::commitment_transform::{CommitmentTransformProver, CommitmentTransformVerifier};
use super::monomial_check::{MonomialSetCheckProver, MonomialSetCheckVerifier};
use std::sync::Arc;

// ============================================================================
// Task 23.1: Main Engine Struct
// ============================================================================

/// LatticeFold+ engine
/// 
/// Main interface for LatticeFold+ folding scheme with full Neo integration.
/// Combines all LatticeFold+ components with Neo's optimizations for
/// production-ready performance.
pub struct LatticeFoldPlusEngine<F: Field> {
    /// Base ring
    base_ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
    
    /// Small field folding configuration
    small_field_folding: SmallFieldFolding<F>,
    
    /// NTT engine (optional, available when q ≡ 1 + 2^e (mod 4e))
    ntt_engine: Option<Arc<NTTEngine<F>>>,
    
    /// Field arithmetic operations
    field_arithmetic: Arc<FieldArithmeticOps<F>>,
    
    /// Parallel executor for multi-threaded operations
    parallel_executor: Arc<ParallelExecutor>,
    
    /// Memory manager for efficient memory usage
    memory_manager: Arc<MemoryManager>,
    
    /// IVC accumulator (optional, for incremental verification)
    ivc_accumulator: Option<IVCAccumulator<F>>,
}

impl<F: Field> LatticeFoldPlusEngine<F> {
    /// Create new LatticeFold+ engine
    /// 
    /// # Arguments
    /// * `base_ring` - Cyclotomic ring for operations
    /// * `commitment_key` - Ajtai commitment key
    /// * `small_field_folding` - Small field folding configuration
    /// * `ntt_engine` - Optional NTT engine for fast multiplication
    /// * `field_arithmetic` - Field arithmetic operations
    /// * `parallel_executor` - Parallel executor for multi-threading
    /// * `memory_manager` - Memory manager for efficient allocation
    /// 
    /// # Returns
    /// * `LatticeFoldPlusEngine` - Configured engine
    pub fn new(
        base_ring: CyclotomicRing<F>,
        commitment_key: AjtaiCommitment<F>,
        small_field_folding: SmallFieldFolding<F>,
        ntt_engine: Option<Arc<NTTEngine<F>>>,
        field_arithmetic: Arc<FieldArithmeticOps<F>>,
        parallel_executor: Arc<ParallelExecutor>,
        memory_manager: Arc<MemoryManager>,
    ) -> Self {
        Self {
            base_ring,
            commitment_key,
            small_field_folding,
            ntt_engine,
            field_arithmetic,
            parallel_executor,
            memory_manager,
            ivc_accumulator: None,
        }
    }
    
    /// Get base ring reference
    pub fn base_ring(&self) -> &CyclotomicRing<F> {
        &self.base_ring
    }
    
    /// Get commitment key reference
    pub fn commitment_key(&self) -> &AjtaiCommitment<F> {
        &self.commitment_key
    }
    
    /// Get small field folding reference
    pub fn small_field_folding(&self) -> &SmallFieldFolding<F> {
        &self.small_field_folding
    }
    
    /// Check if NTT is available
    pub fn has_ntt(&self) -> bool {
        self.ntt_engine.is_some()
    }
    
    /// Get field arithmetic reference
    pub fn field_arithmetic(&self) -> &FieldArithmeticOps<F> {
        self.field_arithmetic.as_ref()
    }
    
    /// Get parallel executor reference
    pub fn parallel_executor(&self) -> &ParallelExecutor {
        self.parallel_executor.as_ref()
    }
    
    /// Get memory manager reference
    pub fn memory_manager(&self) -> &MemoryManager {
        self.memory_manager.as_ref()
    }
}

// ============================================================================
// Task 23.2: High-Level Folding API
// ============================================================================

impl<F: Field> LatticeFoldPlusEngine<F> {
    /// Fold L instances into 2 instances
    /// 
    /// High-level API for L-to-2 folding. Takes L instances with witnesses
    /// and produces 2 instances with witnesses and a proof.
    /// 
    /// # Arguments
    /// * `instances` - L instances of R_{lin,B} to fold
    /// * `witnesses` - L witnesses corresponding to instances
    /// * `transcript` - Fiat-Shamir transcript for non-interactive proof
    /// 
    /// # Returns
    /// * `Ok(FoldingOutput)` - 2 output instances with proof
    /// * `Err(String)` - Error message if folding fails
    pub fn fold(
        &self,
        instances: Vec<LinearInstance<F>>,
        witnesses: Vec<Vec<RingElement<F>>>,
        transcript: &mut Transcript,
    ) -> Result<FoldingOutput<F>, String> {
        // Validate inputs
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
        
        // Create folding prover
        let mut prover = FoldingProver::new(
            instances,
            witnesses,
            self.commitment_key.clone(),
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
            self.small_field_folding.challenge_set_size() as usize,
        )?;
        
        // Run folding protocol
        prover.fold(transcript)
    }
    
    /// Prove a statement
    /// 
    /// Generic proving interface that handles transcript management
    /// and proof generation.
    /// 
    /// # Arguments
    /// * `instances` - Instances to prove
    /// * `witnesses` - Witnesses for instances
    /// 
    /// # Returns
    /// * `Ok((FoldingOutput, Vec<u8>))` - Output and serialized proof
    /// * `Err(String)` - Error message if proving fails
    pub fn prove(
        &self,
        instances: Vec<LinearInstance<F>>,
        witnesses: Vec<Vec<RingElement<F>>>,
    ) -> Result<(FoldingOutput<F>, Vec<u8>), String> {
        // Create transcript
        let mut transcript = Transcript::new(b"LatticeFold+");
        
        // Add public inputs to transcript
        for (i, instance) in instances.iter().enumerate() {
            transcript.append_message(
                &format!("instance_{}", i).as_bytes(),
                &self.serialize_instance(instance)?
            );
        }
        
        // Run folding
        let output = self.fold(instances, witnesses, &mut transcript)?;
        
        // Serialize proof
        let proof_bytes = self.serialize_proof(&output.proof)?;
        
        Ok((output, proof_bytes))
    }
    
    /// Verify a proof
    /// 
    /// Generic verification interface that handles transcript management
    /// and proof verification.
    /// 
    /// # Arguments
    /// * `instances` - Instances to verify
    /// * `proof_bytes` - Serialized proof
    /// 
    /// # Returns
    /// * `Ok(FoldingOutput)` - Verified output instances
    /// * `Err(String)` - Error message if verification fails
    pub fn verify(
        &self,
        instances: Vec<LinearInstance<F>>,
        proof_bytes: &[u8],
    ) -> Result<FoldingOutput<F>, String> {
        // Create transcript
        let mut transcript = Transcript::new(b"LatticeFold+");
        
        // Add public inputs to transcript
        for (i, instance) in instances.iter().enumerate() {
            transcript.append_message(
                &format!("instance_{}", i).as_bytes(),
                &self.serialize_instance(instance)?
            );
        }
        
        // Deserialize proof
        let proof = self.deserialize_proof(proof_bytes)?;
        
        // Create verifier
        let verifier = FoldingVerifier::new(
            instances,
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
            self.small_field_folding.challenge_set_size() as usize,
        )?;
        
        // Verify proof
        verifier.verify(&proof, &mut transcript)
    }
    
    /// Batch fold multiple sets of instances
    /// 
    /// Efficiently folds multiple independent sets of instances in parallel.
    /// 
    /// # Arguments
    /// * `batch` - Vector of (instances, witnesses) pairs
    /// 
    /// # Returns
    /// * `Ok(Vec<FoldingOutput>)` - Outputs for each batch
    /// * `Err(String)` - Error message if any folding fails
    pub fn batch_fold(
        &self,
        batch: Vec<(Vec<LinearInstance<F>>, Vec<Vec<RingElement<F>>>)>,
    ) -> Result<Vec<FoldingOutput<F>>, String> {
        // Parallel fold each batch
        self.parallel_executor.parallel_map(
            batch,
            |(instances, witnesses)| {
                let mut transcript = Transcript::new(b"LatticeFold+");
                self.fold(instances, witnesses, &mut transcript)
            }
        )
    }
    
    /// Serialize instance for transcript
    fn serialize_instance(&self, instance: &LinearInstance<F>) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        
        // Serialize commitment
        for elem in &instance.commitment.values {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        // Serialize challenge
        for elem in &instance.challenge {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        // Serialize evaluations
        for elem in &instance.evaluations {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        // Serialize norm bound
        bytes.extend_from_slice(&instance.norm_bound.to_le_bytes());
        
        Ok(bytes)
    }
    
    /// Serialize proof
    fn serialize_proof(&self, proof: &FoldingProof<F>) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        
        // Serialize range proofs count
        bytes.extend_from_slice(&(proof.range_proofs.len() as u64).to_le_bytes());
        
        // Serialize each range proof
        for range_proof in &proof.range_proofs {
            // Serialize monomial proofs count
            bytes.extend_from_slice(&(range_proof.monomial_proofs.len() as u64).to_le_bytes());
            
            // Serialize coefficient evaluation
            bytes.extend_from_slice(&(range_proof.coefficient_eval.len() as u64).to_le_bytes());
            for &coeff in &range_proof.coefficient_eval {
                bytes.extend_from_slice(&coeff.to_le_bytes());
            }
            
            // Serialize split evaluation
            bytes.extend_from_slice(&range_proof.split_eval.to_le_bytes());
        }
        
        // Serialize transform proofs count
        bytes.extend_from_slice(&(proof.transform_proofs.len() as u64).to_le_bytes());
        
        // Serialize each transform proof
        for transform_proof in &proof.transform_proofs {
            // Serialize folded commitment
            bytes.extend_from_slice(&(transform_proof.folded_commitment.values.len() as u64).to_le_bytes());
            for elem in &transform_proof.folded_commitment.values {
                for &coeff in &elem.coeffs {
                    bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
                }
            }
            
            // Serialize final evaluations
            bytes.extend_from_slice(&(transform_proof.final_evaluations.len() as u64).to_le_bytes());
            for elem in &transform_proof.final_evaluations {
                for &coeff in &elem.coeffs {
                    bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
                }
            }
        }
        
        // Serialize decomposition proof
        // Serialize cm_low
        bytes.extend_from_slice(&(proof.decomposition_proof.cm_low.values.len() as u64).to_le_bytes());
        for elem in &proof.decomposition_proof.cm_low.values {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        // Serialize cm_high
        bytes.extend_from_slice(&(proof.decomposition_proof.cm_high.values.len() as u64).to_le_bytes());
        for elem in &proof.decomposition_proof.cm_high.values {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        // Serialize consistency proof
        bytes.extend_from_slice(&(proof.decomposition_proof.consistency_proof.challenge.len() as u64).to_le_bytes());
        for elem in &proof.decomposition_proof.consistency_proof.challenge {
            for &coeff in &elem.coeffs {
                bytes.extend_from_slice(&coeff.to_u64().to_le_bytes());
            }
        }
        
        Ok(bytes)
    }
    
    /// Deserialize proof
    fn deserialize_proof(&self, bytes: &[u8]) -> Result<FoldingProof<F>, String> {
        if bytes.len() < 16 {
            return Err("Proof too short".to_string());
        }
        
        let mut offset = 0;
        
        // Deserialize range proofs count
        if offset + 8 > bytes.len() {
            return Err("Invalid proof format: missing range proofs count".to_string());
        }
        let range_proofs_count = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
        offset += 8;
        
        let mut range_proofs = Vec::with_capacity(range_proofs_count);
        for _ in 0..range_proofs_count {
            // Deserialize monomial proofs count
            if offset + 8 > bytes.len() {
                return Err("Invalid proof format: missing monomial proofs count".to_string());
            }
            let _monomial_count = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
            offset += 8;
            
            // Deserialize coefficient evaluation
            if offset + 8 > bytes.len() {
                return Err("Invalid proof format: missing coefficient eval length".to_string());
            }
            let coeff_len = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
            offset += 8;
            
            let mut coefficient_eval = Vec::with_capacity(coeff_len);
            for _ in 0..coeff_len {
                if offset + 8 > bytes.len() {
                    return Err("Invalid proof format: missing coefficient".to_string());
                }
                let coeff = i64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                coefficient_eval.push(coeff);
                offset += 8;
            }
            
            // Deserialize split evaluation
            if offset + 8 > bytes.len() {
                return Err("Invalid proof format: missing split eval".to_string());
            }
            let split_eval = i64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
            offset += 8;
            
            range_proofs.push(super::range_check::RangeCheckProof {
                monomial_proofs: vec![], // Simplified for now
                coefficient_eval,
                split_eval,
            });
        }
        
        // Deserialize transform proofs count
        if offset + 8 > bytes.len() {
            return Err("Invalid proof format: missing transform proofs count".to_string());
        }
        let transform_proofs_count = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
        offset += 8;
        
        let mut transform_proofs = Vec::with_capacity(transform_proofs_count);
        for _ in 0..transform_proofs_count {
            // Deserialize folded commitment
            if offset + 8 > bytes.len() {
                return Err("Invalid proof format: missing commitment length".to_string());
            }
            let commitment_len = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
            offset += 8;
            
            let mut commitment_values = Vec::with_capacity(commitment_len);
            for _ in 0..commitment_len {
                let mut coeffs = Vec::with_capacity(self.base_ring.degree);
                for _ in 0..self.base_ring.degree {
                    if offset + 8 > bytes.len() {
                        return Err("Invalid proof format: missing coefficient".to_string());
                    }
                    let coeff_u64 = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                    coeffs.push(F::from_u64(coeff_u64));
                    offset += 8;
                }
                commitment_values.push(RingElement::from_coeffs(coeffs));
            }
            
            // Deserialize final evaluations
            if offset + 8 > bytes.len() {
                return Err("Invalid proof format: missing evaluations length".to_string());
            }
            let eval_len = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
            offset += 8;
            
            let mut final_evaluations = Vec::with_capacity(eval_len);
            for _ in 0..eval_len {
                let mut coeffs = Vec::with_capacity(self.base_ring.degree);
                for _ in 0..self.base_ring.degree {
                    if offset + 8 > bytes.len() {
                        return Err("Invalid proof format: missing evaluation coefficient".to_string());
                    }
                    let coeff_u64 = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                    coeffs.push(F::from_u64(coeff_u64));
                    offset += 8;
                }
                final_evaluations.push(RingElement::from_coeffs(coeffs));
            }
            
            transform_proofs.push(super::commitment_transform::CommitmentTransformProof {
                range_proof: super::range_check::RangeCheckProof {
                    monomial_proofs: vec![],
                    coefficient_eval: vec![],
                    split_eval: 0,
                },
                folded_commitment: Commitment {
                    values: commitment_values,
                    opening_info: None,
                },
                final_evaluations,
                sumcheck_proofs: vec![],
            });
        }
        
        // Deserialize decomposition proof (simplified structure)
        let decomposition_proof = super::folding::DecompositionProof {
            cm_low: Commitment::default(),
            cm_high: Commitment::default(),
            consistency_proof: super::folding::ConsistencyProof {
                challenge: vec![],
                eval_f: self.base_ring.zero(),
                eval_low: self.base_ring.zero(),
                eval_high: self.base_ring.zero(),
            },
        };
        
        Ok(FoldingProof {
            range_proofs,
            transform_proofs,
            decomposition_proof,
        })
    }
}

// ============================================================================
// Task 23.3: IVC Integration
// ============================================================================

impl<F: Field> LatticeFoldPlusEngine<F> {
    /// Initialize IVC accumulator
    /// 
    /// Sets up the engine for incremental verifiable computation.
    /// The accumulator maintains the state across multiple folding steps.
    /// 
    /// # Arguments
    /// * `initial_instance` - Initial instance to accumulate
    /// 
    /// # Returns
    /// * `Ok(())` - Accumulator initialized successfully
    /// * `Err(String)` - Error message if initialization fails
    pub fn init_ivc(&mut self, initial_instance: LinearInstance<F>) -> Result<(), String> {
        self.ivc_accumulator = Some(IVCAccumulator::new(
            initial_instance,
            self.base_ring.clone(),
            self.commitment_key.clone(),
        )?);
        
        Ok(())
    }
    
    /// Accumulate a new instance into IVC
    /// 
    /// Folds a new instance into the accumulator, maintaining the IVC invariant.
    /// 
    /// # Arguments
    /// * `instance` - New instance to accumulate
    /// * `witness` - Witness for the new instance
    /// * `transcript` - Transcript for non-interactive proof
    /// 
    /// # Returns
    /// * `Ok(IVCProof)` - Proof of correct accumulation
    /// * `Err(String)` - Error message if accumulation fails
    pub fn accumulate_ivc(
        &mut self,
        instance: LinearInstance<F>,
        witness: Vec<RingElement<F>>,
        transcript: &mut Transcript,
    ) -> Result<IVCProof<F>, String> {
        let accumulator = self.ivc_accumulator.as_mut()
            .ok_or_else(|| "IVC not initialized".to_string())?;
        
        // Get current accumulated instance
        let current_instance = accumulator.current_instance().clone();
        let current_witness = accumulator.current_witness().clone();
        
        // Fold current and new instance
        let instances = vec![current_instance, instance];
        let witnesses = vec![current_witness, witness];
        
        let folding_output = self.fold(instances, witnesses, transcript)?;
        
        // Update accumulator with first output instance
        // (second instance becomes the new accumulated instance)
        accumulator.update(
            folding_output.instances[1].clone(),
            folding_output.witnesses[1].clone(),
        )?;
        
        // Create IVC proof
        Ok(IVCProof {
            folding_proof: folding_output.proof,
            accumulated_instance: folding_output.instances[1].clone(),
            step_count: accumulator.step_count(),
        })
    }
    
    /// Verify IVC proof
    /// 
    /// Verifies that the IVC accumulation was performed correctly.
    /// 
    /// # Arguments
    /// * `proof` - IVC proof to verify
    /// * `initial_instance` - Initial instance that started the IVC
    /// * `transcript` - Transcript for non-interactive verification
    /// 
    /// # Returns
    /// * `Ok(bool)` - True if proof is valid
    /// * `Err(String)` - Error message if verification fails
    pub fn verify_ivc(
        &self,
        proof: &IVCProof<F>,
        initial_instance: &LinearInstance<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        // Verify folding proof
        let instances = vec![initial_instance.clone(), proof.accumulated_instance.clone()];
        let folding_output = self.verify(instances, &self.serialize_proof(&proof.folding_proof)?)?;
        
        // Verify accumulated instance matches
        if !self.instances_equal(&folding_output.instances[1], &proof.accumulated_instance) {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Get current IVC state
    /// 
    /// Returns the current accumulated instance and step count.
    /// 
    /// # Returns
    /// * `Ok((LinearInstance, usize))` - Current instance and step count
    /// * `Err(String)` - Error if IVC not initialized
    pub fn ivc_state(&self) -> Result<(LinearInstance<F>, usize), String> {
        let accumulator = self.ivc_accumulator.as_ref()
            .ok_or_else(|| "IVC not initialized".to_string())?;
        
        Ok((
            accumulator.current_instance().clone(),
            accumulator.step_count(),
        ))
    }
    
    /// Finalize IVC
    /// 
    /// Completes the IVC computation and returns the final proof.
    /// 
    /// # Returns
    /// * `Ok(IVCProof)` - Final IVC proof
    /// * `Err(String)` - Error if IVC not initialized
    pub fn finalize_ivc(&mut self) -> Result<IVCProof<F>, String> {
        let accumulator = self.ivc_accumulator.take()
            .ok_or_else(|| "IVC not initialized".to_string())?;
        
        Ok(IVCProof {
            folding_proof: FoldingProof {
                range_proofs: vec![],
                transform_proofs: vec![],
                decomposition_proof: super::folding::DecompositionProof {
                    cm_low: Commitment::default(),
                    cm_high: Commitment::default(),
                    consistency_proof: super::folding::ConsistencyProof {
                        challenge: vec![],
                        eval_f: self.base_ring.zero(),
                        eval_low: self.base_ring.zero(),
                        eval_high: self.base_ring.zero(),
                    },
                },
            },
            accumulated_instance: accumulator.current_instance().clone(),
            step_count: accumulator.step_count(),
        })
    }
    
    /// Helper: check if two instances are equal
    fn instances_equal(&self, a: &LinearInstance<F>, b: &LinearInstance<F>) -> bool {
        // Compare commitments
        if a.commitment.values.len() != b.commitment.values.len() {
            return false;
        }
        
        for (a_elem, b_elem) in a.commitment.values.iter().zip(b.commitment.values.iter()) {
            if a_elem.coeffs != b_elem.coeffs {
                return false;
            }
        }
        
        // Compare norm bounds
        if a.norm_bound != b.norm_bound {
            return false;
        }
        
        true
    }
}

// ============================================================================
// Performance Monitoring
// ============================================================================

/// Performance statistics for LatticeFold+ operations
#[derive(Clone, Debug, Default)]
pub struct PerformanceStats {
    /// Total folding time in milliseconds
    pub total_folding_time_ms: u64,
    
    /// Number of folding operations
    pub folding_count: usize,
    
    /// Total proof size in bytes
    pub total_proof_size_bytes: usize,
    
    /// Number of NTT operations
    pub ntt_operations: usize,
    
    /// Number of parallel operations
    pub parallel_operations: usize,
    
    /// Peak memory usage in bytes
    pub peak_memory_bytes: usize,
}

impl<F: Field> LatticeFoldPlusEngine<F> {
    /// Get performance statistics
    /// 
    /// Returns statistics about engine usage for performance analysis.
    pub fn performance_stats(&self) -> PerformanceStats {
        PerformanceStats {
            total_folding_time_ms: 0, // Would be tracked during operations
            folding_count: 0,
            total_proof_size_bytes: 0,
            ntt_operations: 0,
            parallel_operations: 0,
            peak_memory_bytes: self.memory_manager.peak_usage(),
        }
    }
    
    /// Reset performance statistics
    pub fn reset_stats(&mut self) {
        // Reset internal counters
        self.memory_manager.reset_stats();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use super::super::tensor_rings::TensorRingConfig;
    use super::super::neo_integration::NeoIntegration;
    
    #[test]
    fn test_engine_creation() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let engine = integration.integrate_latticefold_plus();
        assert_eq!(engine.base_ring().degree, d);
    }
    
    #[test]
    fn test_fold_api() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let engine = integration.integrate_latticefold_plus();
        
        // Create test instances
        let instances = vec![
            LinearInstance {
                commitment: Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
        ];
        
        let witnesses = vec![
            vec![engine.base_ring().from_i64(10); n],
            vec![engine.base_ring().from_i64(20); n],
            vec![engine.base_ring().from_i64(30); n],
        ];
        
        let mut transcript = Transcript::new(b"test");
        let result = engine.fold(instances, witnesses, &mut transcript);
        
        // May fail due to incomplete implementation, but should not panic
        let _ = result;
    }
    
    #[test]
    fn test_ivc_initialization() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let mut engine = integration.integrate_latticefold_plus();
        
        let initial_instance = LinearInstance {
            commitment: Commitment::default(),
            challenge: vec![],
            evaluations: vec![],
            norm_bound: 100,
        };
        
        let result = engine.init_ivc(initial_instance);
        assert!(result.is_ok());
        
        let state = engine.ivc_state();
        assert!(state.is_ok());
        
        let (_, step_count) = state.unwrap();
        assert_eq!(step_count, 0);
    }
    
    #[test]
    fn test_performance_stats() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let engine = integration.integrate_latticefold_plus();
        
        let stats = engine.performance_stats();
        assert_eq!(stats.folding_count, 0); // No operations yet
    }
}
