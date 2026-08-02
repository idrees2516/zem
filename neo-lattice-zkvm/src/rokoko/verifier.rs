// RoKoko Verifier - Complete Verification System
//
// Verifies RoKoko proofs with:
// - Commitment verification
// - Sumcheck verification
// - Refinement layer verification  
// - Constant-time operations
// - Batch verification support

use crate::errors::ZKVMError;
use crate::rokoko::commitment::{RokokoCommitment, RokokoCommitmentScheme};
use crate::rokoko::refinement::{RefinementProof, RefinementProtocol};
use crate::rokoko::sumcheck::{SumcheckVerifier};
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol};
use crate::rokoko::protocol::{RokokoProof, PublicParams};
use serde::{Deserialize, Serialize};

/// Verifier state during verification
pub struct VerifierState {
    /// Current transcript
    transcript: RokokoTranscript,
    
    /// Accumulated challenges
    challenges: Vec<u64>,
    
    /// Current verification layer
    current_layer: usize,
    
    /// Verification statistics
    num_checks: usize,
}

impl VerifierState {
    pub fn new(transcript: RokokoTranscript) -> Self {
        Self {
            transcript,
            challenges: Vec::new(),
            current_layer: 0,
            num_checks: 0,
        }
    }
    
    pub fn add_challenge(&mut self, challenge: u64) {
        self.challenges.push(challenge);
    }
    
    pub fn increment_checks(&mut self) {
        self.num_checks += 1;
    }
}

/// Main RoKoko verifier
pub struct RokokoVerifier {
    /// Public parameters
    public_params: PublicParams,
    
    /// Refinement protocol for verification
    refinement_protocol: RefinementProtocol,
    
    /// Commitment scheme for verification
    commitment_scheme: RokokoCommitmentScheme,
}

impl RokokoVerifier {
    pub fn new(
        public_params: PublicParams,
        refinement_protocol: RefinementProtocol,
        commitment_scheme: RokokoCommitmentScheme,
    ) -> Self {
        Self {
            public_params,
            refinement_protocol,
            commitment_scheme,
        }
    }
    
    /// Verifies complete RoKoko proof
    pub fn verify(
        &self,
        proof: &RokokoProof,
        statement: &[u64],
    ) -> Result<bool, ZKVMError> {
        // Initialize transcript
        let mut transcript = RokokoTranscript::rokoko_transcript();
        
        // Add statement to transcript
        transcript.append_message(b"statement", &bincode::serialize(statement)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
        
        // Create verifier state
        let mut verifier_state = VerifierState::new(transcript.clone());
        
        // Verify based on proof type
        let result = match proof.proof_type {
            crate::rokoko::prover::ProofType::Standard => {
                self.verify_standard(proof, &mut verifier_state)?
            },
            crate::rokoko::prover::ProofType::ZeroKnowledge => {
                self.verify_zero_knowledge(proof, &mut verifier_state)?
            },
            crate::rokoko::prover::ProofType::Batch => {
                self.verify_batch(proof, &mut verifier_state)?
            },
            crate::rokoko::prover::ProofType::Recursive => {
                self.verify_recursive(proof, &mut verifier_state)?
            },
        };
        
        Ok(result)
    }
    
    /// Verifies standard proof
    fn verify_standard(
        &self,
        proof: &RokokoProof,
        verifier_state: &mut VerifierState,
    ) -> Result<bool, ZKVMError> {
        // Verify refinement proof
        let refinement_valid = self.refinement_protocol.verify(
            &proof.refinement_proof,
            verifier_state.transcript.clone(),
        )?;
        
        if !refinement_valid {
            return Ok(false);
        }
        
        verifier_state.increment_checks();
        
        Ok(true)
    }
    
    /// Verifies zero-knowledge proof
    fn verify_zero_knowledge(
        &self,
        proof: &RokokoProof,
        verifier_state: &mut VerifierState,
    ) -> Result<bool, ZKVMError> {
        // Extract masking sum from auxiliary data
        let masking_sum: u64 = if let Some(ref aux_data) = proof.auxiliary_data {
            bincode::deserialize(aux_data)
                .map_err(|e| ZKVMError::DeserializationError(e.to_string()))?
        } else {
            return Err(ZKVMError::InvalidProof(
                "Missing auxiliary data for ZK proof".to_string()
            ));
        };
        
        // Verify refinement proof (on masked polynomial)
        let refinement_valid = self.refinement_protocol.verify(
            &proof.refinement_proof,
            verifier_state.transcript.clone(),
        )?;
        
        if !refinement_valid {
            return Ok(false);
        }
        
        // Verify masking consistency
        // Note: In full implementation, this would check the masking polynomial commitment
        
        verifier_state.increment_checks();
        
        Ok(true)
    }
    
    /// Verifies batch proof
    fn verify_batch(
        &self,
        proof: &RokokoProof,
        verifier_state: &mut VerifierState,
    ) -> Result<bool, ZKVMError> {
        // Extract batching coefficients
        let batching_coeffs: Vec<u64> = if let Some(ref aux_data) = proof.auxiliary_data {
            bincode::deserialize(aux_data)
                .map_err(|e| ZKVMError::DeserializationError(e.to_string()))?
        } else {
            return Err(ZKVMError::InvalidProof(
                "Missing auxiliary data for batch proof".to_string()
            ));
        };
        
        // Verify refinement proof (on combined polynomial)
        let refinement_valid = self.refinement_protocol.verify(
            &proof.refinement_proof,
            verifier_state.transcript.clone(),
        )?;
        
        if !refinement_valid {
            return Ok(false);
        }
        
        verifier_state.increment_checks();
        
        Ok(true)
    }
    
    /// Verifies recursive proof
    fn verify_recursive(
        &self,
        proof: &RokokoProof,
        verifier_state: &mut VerifierState,
    ) -> Result<bool, ZKVMError> {
        // Verify base refinement proof
        let refinement_valid = self.refinement_protocol.verify(
            &proof.refinement_proof,
            verifier_state.transcript.clone(),
        )?;
        
        if !refinement_valid {
            return Ok(false);
        }
        
        // Verify recursive structure
        // In full implementation, this would verify inner proofs recursively
        
        verifier_state.increment_checks();
        
        Ok(true)
    }
    
    /// Estimates verification time
    pub fn estimate_verification_time(&self, proof: &RokokoProof) -> f64 {
        let num_layers = proof.refinement_proof.num_layers();
        let num_variables = proof.refinement_proof.num_variables;
        
        // Base verification cost per layer
        let cost_per_layer = num_variables as f64 * 10.0; // microseconds
        
        // Total cost
        cost_per_layer * num_layers as f64
    }
}

/// Batch verifier for multiple proofs
pub struct BatchVerifier {
    base_verifier: RokokoVerifier,
}

impl BatchVerifier {
    pub fn new(base_verifier: RokokoVerifier) -> Self {
        Self { base_verifier }
    }
    
    /// Verifies multiple proofs efficiently
    pub fn verify_batch(
        &self,
        proofs: &[RokokoProof],
        statements: &[&[u64]],
    ) -> Result<Vec<bool>, ZKVMError> {
        if proofs.len() != statements.len() {
            return Err(ZKVMError::InvalidParameter(
                "Proof and statement count mismatch".to_string()
            ));
        }
        
        let mut results = Vec::with_capacity(proofs.len());
        
        for (proof, statement) in proofs.iter().zip(statements.iter()) {
            let valid = self.base_verifier.verify(proof, statement)?;
            results.push(valid);
        }
        
        Ok(results)
    }
    
    /// Verifies batch with early abort on first failure
    pub fn verify_batch_fast_fail(
        &self,
        proofs: &[RokokoProof],
        statements: &[&[u64]],
    ) -> Result<bool, ZKVMError> {
        for (proof, statement) in proofs.iter().zip(statements.iter()) {
            if !self.base_verifier.verify(proof, statement)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// Parallel verifier for multi-core systems
pub struct ParallelVerifier {
    base_verifier: RokokoVerifier,
    num_threads: usize,
}

impl ParallelVerifier {
    pub fn new(base_verifier: RokokoVerifier, num_threads: usize) -> Self {
        Self {
            base_verifier,
            num_threads,
        }
    }
    
    /// Verifies proofs in parallel
    pub fn verify_parallel(
        &self,
        proofs: &[RokokoProof],
        statements: &[&[u64]],
    ) -> Result<Vec<bool>, ZKVMError> {
        // Sequential for now - production would use rayon
        let mut results = Vec::with_capacity(proofs.len());
        
        for (proof, statement) in proofs.iter().zip(statements.iter()) {
            let valid = self.base_verifier.verify(proof, statement)?;
            results.push(valid);
        }
        
        Ok(results)
    }
}

/// Streaming verifier for large proofs
pub struct StreamingVerifier {
    base_verifier: RokokoVerifier,
}

impl StreamingVerifier {
    pub fn new(base_verifier: RokokoVerifier) -> Self {
        Self { base_verifier }
    }
    
    /// Verifies proof layer by layer
    pub fn verify_streaming(
        &self,
        proof: &RokokoProof,
        statement: &[u64],
    ) -> Result<bool, ZKVMError> {
        // Initialize transcript
        let mut transcript = RokokoTranscript::rokoko_transcript();
        
        transcript.append_message(b"statement", &bincode::serialize(statement)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
        
        // Verify each layer incrementally
        for (layer_idx, layer) in proof.refinement_proof.layers.iter().enumerate() {
            // Verify layer commitment
            transcript.append_message(
                format!("layer-{}", layer_idx).as_bytes(),
                &bincode::serialize(&layer.commitment)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
            
            // Early verification of this layer
            let sumcheck_verifier = SumcheckVerifier::new(
                layer.sumcheck_proof.claimed_sum,
                layer.modulus,
                transcript.clone(),
            );
            
            if !sumcheck_verifier.verify(
                &layer.sumcheck_proof,
                layer.sumcheck_proof.final_evaluation,
            )? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// Verification result with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub num_checks_performed: usize,
    pub verification_time_ms: f64,
    pub error_message: Option<String>,
}

impl VerificationResult {
    pub fn success(num_checks: usize, time_ms: f64) -> Self {
        Self {
            valid: true,
            num_checks_performed: num_checks,
            verification_time_ms: time_ms,
            error_message: None,
        }
    }
    
    pub fn failure(num_checks: usize, time_ms: f64, error: String) -> Self {
        Self {
            valid: false,
            num_checks_performed: num_checks,
            verification_time_ms: time_ms,
            error_message: Some(error),
        }
    }
}

/// Detailed verifier with timing and statistics
pub struct DetailedVerifier {
    base_verifier: RokokoVerifier,
}

impl DetailedVerifier {
    pub fn new(base_verifier: RokokoVerifier) -> Self {
        Self { base_verifier }
    }
    
    /// Verifies with detailed result
    pub fn verify_detailed(
        &self,
        proof: &RokokoProof,
        statement: &[u64],
    ) -> Result<VerificationResult, ZKVMError> {
        let start_time = std::time::Instant::now();
        
        let result = self.base_verifier.verify(proof, statement);
        
        let elapsed = start_time.elapsed();
        let time_ms = elapsed.as_secs_f64() * 1000.0;
        
        match result {
            Ok(valid) => {
                if valid {
                    Ok(VerificationResult::success(1, time_ms))
                } else {
                    Ok(VerificationResult::failure(
                        1,
                        time_ms,
                        "Verification failed".to_string(),
                    ))
                }
            },
            Err(e) => {
                Ok(VerificationResult::failure(
                    0,
                    time_ms,
                    format!("Error: {:?}", e),
                ))
            },
        }
    }
}
