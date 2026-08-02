// Batch Proof Aggregation for RoKoko
//
// Implements efficient batching techniques to:
// - Aggregate multiple proofs into a single proof
// - Verify multiple statements simultaneously
// - Reduce total proof size and verification time
// - Support incremental batch building

use crate::errors::ZKVMError;
use crate::rokoko::commitment::{RokokoCommitment, RokokoCommitmentScheme, EvaluationProof};
use crate::rokoko::polynomial::MultilinearPolynomial;
use crate::rokoko::protocol::{RokokoProof, PublicParams};
use crate::rokoko::prover::{RokokoProver, ProofType};
use crate::rokoko::refinement::{RefinementProof, RefinementProtocol};
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol, BatchTranscript};
use crate::rokoko::verifier::RokokoVerifier;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Batch proof containing aggregated proofs
#[derive(Clone, Serialize, Deserialize)]
pub struct BatchProof {
    /// Number of proofs in batch
    pub batch_size: usize,
    
    /// Aggregated refinement proof
    pub aggregated_proof: RefinementProof,
    
    /// Random coefficients used for batching
    pub batching_coefficients: Vec<u64>,
    
    /// Individual commitments for each proof
    pub individual_commitments: Vec<Vec<RokokoCommitment>>,
    
    /// Batch type identifier
    pub batch_type: BatchType,
}

impl BatchProof {
    pub fn new(
        batch_size: usize,
        aggregated_proof: RefinementProof,
        batching_coefficients: Vec<u64>,
        individual_commitments: Vec<Vec<RokokoCommitment>>,
        batch_type: BatchType,
    ) -> Self {
        Self {
            batch_size,
            aggregated_proof,
            batching_coefficients,
            individual_commitments,
            batch_type,
        }
    }
    
    /// Computes total batch proof size
    pub fn size_bytes(&self) -> usize {
        let agg_size = self.aggregated_proof.total_size_bytes();
        let coeffs_size = self.batching_coefficients.len() * 8;
        let comms_size: usize = self.individual_commitments.iter()
            .map(|comms| comms.iter().map(|c| c.size_bytes()).sum::<usize>())
            .sum();
        
        agg_size + coeffs_size + comms_size + 16
    }
    
    /// Computes compression ratio vs individual proofs
    pub fn compression_ratio(&self, individual_proof_size: usize) -> f64 {
        let total_individual = self.batch_size * individual_proof_size;
        let batch_size = self.size_bytes();
        
        total_individual as f64 / batch_size as f64
    }
}

/// Type of batch aggregation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BatchType {
    /// Random linear combination
    RandomLinearCombination,
    
    /// Tensor product batching
    TensorProduct,
    
    /// Hierarchical batching
    Hierarchical,
    
    /// Recursive batching
    Recursive,
}

/// Batch prover for aggregating multiple proofs
pub struct BatchProver {
    /// Base prover
    base_prover: RokokoProver,
    
    /// Refinement protocol
    refinement_protocol: RefinementProtocol,
    
    /// Commitment scheme
    commitment_scheme: RokokoCommitmentScheme,
    
    /// Maximum batch size
    max_batch_size: usize,
}

impl BatchProver {
    pub fn new(
        base_prover: RokokoProver,
        refinement_protocol: RefinementProtocol,
        commitment_scheme: RokokoCommitmentScheme,
        max_batch_size: usize,
    ) -> Self {
        Self {
            base_prover,
            refinement_protocol,
            commitment_scheme,
            max_batch_size,
        }
    }
    
    /// Proves multiple statements and aggregates into batch proof
    pub fn prove_batch<R: RngCore + CryptoRng>(
        &mut self,
        witnesses: &[&[u64]],
        statements: &[&[u64]],
        rng: &mut R,
    ) -> Result<BatchProof, ZKVMError> {
        if witnesses.len() != statements.len() {
            return Err(ZKVMError::InvalidParameter(
                "Witness and statement count mismatch".to_string()
            ));
        }
        
        if witnesses.len() > self.max_batch_size {
            return Err(ZKVMError::InvalidParameter(
                format!("Batch size {} exceeds maximum {}", witnesses.len(), self.max_batch_size)
            ));
        }
        
        let batch_size = witnesses.len();
        
        // Create batch transcript
        let mut batch_transcript = BatchTranscript::new(batch_size);
        
        // Generate individual witness polynomials and commitments
        let mut polynomials = Vec::with_capacity(batch_size);
        let mut all_commitments = Vec::with_capacity(batch_size);
        
        for (idx, (witness, statement)) in witnesses.iter().zip(statements.iter()).enumerate() {
            let transcript = batch_transcript.get_transcript(idx)?;
            
            // Add statement to transcript
            transcript.append_message(b"statement", &bincode::serialize(statement)
                .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
            
            // Construct witness polynomial
            let poly = self.construct_witness_polynomial(witness)?;
            
            // Generate commitment
            let (commitment, _) = self.commitment_scheme.commit_multilinear(&poly, rng)?;
            
            // Add commitment to transcript
            transcript.append_message(b"commitment", &bincode::serialize(&commitment)
                .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
            
            polynomials.push(poly);
            all_commitments.push(vec![commitment]);
        }
        
        // Generate batching coefficients using Fiat-Shamir
        let batching_coeffs = batch_transcript.generate_batching_coefficients(batch_size)?;
        
        // Compute combined polynomial via random linear combination
        let combined_poly = self.combine_polynomials(&polynomials, &batching_coeffs)?;
        
        // Generate aggregated refinement proof
        let aggregated_proof = self.refinement_protocol.prove(
            combined_poly,
            RokokoTranscript::new(b"batch-aggregation"),
            rng,
        )?;
        
        Ok(BatchProof::new(
            batch_size,
            aggregated_proof,
            batching_coeffs,
            all_commitments,
            BatchType::RandomLinearCombination,
        ))
    }
    
    /// Combines multiple polynomials using random linear combination
    fn combine_polynomials(
        &self,
        polynomials: &[MultilinearPolynomial],
        coefficients: &[u64],
    ) -> Result<MultilinearPolynomial, ZKVMError> {
        if polynomials.is_empty() {
            return Err(ZKVMError::InvalidParameter("No polynomials to combine".to_string()));
        }
        
        if polynomials.len() != coefficients.len() {
            return Err(ZKVMError::InvalidParameter("Coefficient count mismatch".to_string()));
        }
        
        let modulus = polynomials[0].modulus;
        let num_vars = polynomials[0].num_variables();
        let size = 1 << num_vars;
        
        // Ensure all polynomials have same structure
        for poly in polynomials {
            if poly.modulus != modulus {
                return Err(ZKVMError::InvalidParameter("Modulus mismatch".to_string()));
            }
            if poly.num_variables() != num_vars {
                return Err(ZKVMError::InvalidParameter("Variable count mismatch".to_string()));
            }
        }
        
        // Compute: ∑_i coeff_i · poly_i
        let mut combined_evals = vec![0u128; size];
        
        for (poly, &coeff) in polynomials.iter().zip(coefficients.iter()) {
            let coeff_wide = coeff as u128;
            
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + coeff_wide * eval as u128) % modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        
        MultilinearPolynomial::new(evals, modulus)
    }
    
    /// Constructs witness polynomial from values
    fn construct_witness_polynomial(&self, witness: &[u64]) -> Result<MultilinearPolynomial, ZKVMError> {
        let num_vars = (witness.len() as f64).log2().ceil() as usize;
        let padded_size = 1 << num_vars;
        
        let mut padded_witness = witness.to_vec();
        padded_witness.resize(padded_size, 0);
        
        MultilinearPolynomial::new(
            padded_witness,
            self.refinement_protocol.commitment_schemes[0].key.params.modulus,
        )
    }
}

/// Batch verifier for aggregated proofs
pub struct BatchVerifier {
    /// Base verifier
    base_verifier: RokokoVerifier,
    
    /// Refinement protocol
    refinement_protocol: RefinementProtocol,
    
    /// Commitment scheme
    commitment_scheme: RokokoCommitmentScheme,
}

impl BatchVerifier {
    pub fn new(
        base_verifier: RokokoVerifier,
        refinement_protocol: RefinementProtocol,
        commitment_scheme: RokokoCommitmentScheme,
    ) -> Self {
        Self {
            base_verifier,
            refinement_protocol,
            commitment_scheme,
        }
    }
    
    /// Verifies batch proof against multiple statements
    pub fn verify_batch(
        &self,
        batch_proof: &BatchProof,
        statements: &[&[u64]],
    ) -> Result<bool, ZKVMError> {
        if batch_proof.batch_size != statements.len() {
            return Ok(false);
        }
        
        // Recreate batch transcript
        let mut batch_transcript = BatchTranscript::new(batch_proof.batch_size);
        
        // Add statements and commitments to transcripts
        for (idx, (statement, commitments)) in statements.iter()
            .zip(batch_proof.individual_commitments.iter())
            .enumerate() {
            
            let transcript = batch_transcript.get_transcript(idx)?;
            
            transcript.append_message(b"statement", &bincode::serialize(statement)
                .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
            
            for commitment in commitments {
                transcript.append_message(b"commitment", &bincode::serialize(commitment)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
            }
        }
        
        // Regenerate batching coefficients (must match)
        let expected_coeffs = batch_transcript.generate_batching_coefficients(batch_proof.batch_size)?;
        
        if expected_coeffs != batch_proof.batching_coefficients {
            return Ok(false);
        }
        
        // Verify aggregated refinement proof
        let verification_transcript = RokokoTranscript::new(b"batch-aggregation");
        
        self.refinement_protocol.verify(
            &batch_proof.aggregated_proof,
            verification_transcript,
        )
    }
}

/// Incremental batch builder for streaming scenarios
pub struct IncrementalBatchBuilder {
    /// Accumulated polynomials
    polynomials: Vec<MultilinearPolynomial>,
    
    /// Accumulated commitments
    commitments: Vec<Vec<RokokoCommitment>>,
    
    /// Accumulated statements
    statements: Vec<Vec<u64>>,
    
    /// Maximum batch size
    max_size: usize,
    
    /// Current size
    current_size: usize,
}

impl IncrementalBatchBuilder {
    pub fn new(max_size: usize) -> Self {
        Self {
            polynomials: Vec::with_capacity(max_size),
            commitments: Vec::with_capacity(max_size),
            statements: Vec::with_capacity(max_size),
            max_size,
            current_size: 0,
        }
    }
    
    /// Adds a proof to the batch
    pub fn add_proof<R: RngCore + CryptoRng>(
        &mut self,
        witness: &[u64],
        statement: &[u64],
        commitment_scheme: &RokokoCommitmentScheme,
        rng: &mut R,
    ) -> Result<bool, ZKVMError> {
        if self.current_size >= self.max_size {
            return Ok(false); // Batch full
        }
        
        // Construct polynomial
        let num_vars = (witness.len() as f64).log2().ceil() as usize;
        let padded_size = 1 << num_vars;
        let mut padded_witness = witness.to_vec();
        padded_witness.resize(padded_size, 0);
        
        let poly = MultilinearPolynomial::new(
            padded_witness,
            commitment_scheme.key.params.modulus,
        )?;
        
        // Generate commitment
        let (commitment, _) = commitment_scheme.commit_multilinear(&poly, rng)?;
        
        self.polynomials.push(poly);
        self.commitments.push(vec![commitment]);
        self.statements.push(statement.to_vec());
        self.current_size += 1;
        
        Ok(true)
    }
    
    /// Checks if batch is ready to finalize
    pub fn is_full(&self) -> bool {
        self.current_size >= self.max_size
    }
    
    /// Returns current batch size
    pub fn size(&self) -> usize {
        self.current_size
    }
    
    /// Finalizes and builds batch proof
    pub fn finalize<R: RngCore + CryptoRng>(
        self,
        refinement_protocol: &mut RefinementProtocol,
        rng: &mut R,
    ) -> Result<BatchProof, ZKVMError> {
        if self.polynomials.is_empty() {
            return Err(ZKVMError::InvalidParameter("Empty batch".to_string()));
        }
        
        let batch_size = self.polynomials.len();
        
        // Generate batching coefficients
        let modulus = self.polynomials[0].modulus;
        let batching_coeffs: Vec<u64> = (0..batch_size)
            .map(|_| rng.gen::<u64>() % modulus)
            .collect();
        
        // Combine polynomials
        let num_vars = self.polynomials[0].num_variables();
        let size = 1 << num_vars;
        let mut combined_evals = vec![0u128; size];
        
        for (poly, &coeff) in self.polynomials.iter().zip(batching_coeffs.iter()) {
            let coeff_wide = coeff as u128;
            
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + coeff_wide * eval as u128) % modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        let combined_poly = MultilinearPolynomial::new(evals, modulus)?;
        
        // Generate aggregated proof
        let aggregated_proof = refinement_protocol.prove(
            combined_poly,
            RokokoTranscript::new(b"incremental-batch"),
            rng,
        )?;
        
        Ok(BatchProof::new(
            batch_size,
            aggregated_proof,
            batching_coeffs,
            self.commitments,
            BatchType::RandomLinearCombination,
        ))
    }
}

/// Hierarchical batch aggregator for very large batches
pub struct HierarchicalBatcher {
    /// Batch size at each level
    level_sizes: Vec<usize>,
    
    /// Current level batches
    current_batches: Vec<Vec<MultilinearPolynomial>>,
}

impl HierarchicalBatcher {
    pub fn new(level_sizes: Vec<usize>) -> Self {
        let num_levels = level_sizes.len();
        
        Self {
            level_sizes,
            current_batches: vec![Vec::new(); num_levels],
        }
    }
    
    /// Adds proof to hierarchical structure
    pub fn add_polynomial(&mut self, poly: MultilinearPolynomial) -> Result<(), ZKVMError> {
        self.current_batches[0].push(poly);
        
        // Propagate up hierarchy if level is full
        self.propagate_batches(0)
    }
    
    fn propagate_batches(&mut self, level: usize) -> Result<(), ZKVMError> {
        if level >= self.current_batches.len() {
            return Ok(());
        }
        
        if self.current_batches[level].len() >= self.level_sizes[level] {
            // Combine current level batch
            let combined = self.combine_level_batch(level)?;
            
            // Move to next level
            if level + 1 < self.current_batches.len() {
                self.current_batches[level + 1].push(combined);
                self.current_batches[level].clear();
                
                // Recursively propagate
                self.propagate_batches(level + 1)?;
            }
        }
        
        Ok(())
    }
    
    fn combine_level_batch(&self, level: usize) -> Result<MultilinearPolynomial, ZKVMError> {
        let polys = &self.current_batches[level];
        
        if polys.is_empty() {
            return Err(ZKVMError::InvalidParameter("Empty level batch".to_string()));
        }
        
        // Simple averaging for combination
        let modulus = polys[0].modulus;
        let size = polys[0].evaluations.len();
        let mut combined_evals = vec![0u128; size];
        
        for poly in polys {
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + eval as u128) % modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        
        MultilinearPolynomial::new(evals, modulus)
    }
}

/// Adaptive batcher that selects optimal batch size
pub struct AdaptiveBatcher {
    /// Target proof size
    target_proof_size: usize,
    
    /// Estimated individual proof size
    individual_proof_size: usize,
    
    /// Statistics tracker
    stats: BatchStatistics,
}

#[derive(Default)]
struct BatchStatistics {
    total_proofs: usize,
    total_batches: usize,
    average_batch_size: f64,
    total_size_saved: usize,
}

impl AdaptiveBatcher {
    pub fn new(target_proof_size: usize, individual_proof_size: usize) -> Self {
        Self {
            target_proof_size,
            individual_proof_size,
            stats: BatchStatistics::default(),
        }
    }
    
    /// Computes optimal batch size for current conditions
    pub fn compute_optimal_batch_size(&self) -> usize {
        // Estimate overhead per proof in batch
        let overhead_per_proof = 100; // bytes
        
        // Compute how many can fit in target
        let max_batch = self.target_proof_size / (overhead_per_proof + 64);
        
        // Clamp to reasonable range
        max_batch.max(4).min(256)
    }
    
    /// Updates statistics
    pub fn update_stats(&mut self, batch_size: usize, proof_size: usize) {
        self.stats.total_proofs += batch_size;
        self.stats.total_batches += 1;
        
        let expected_individual_size = batch_size * self.individual_proof_size;
        if expected_individual_size > proof_size {
            self.stats.total_size_saved += expected_individual_size - proof_size;
        }
        
        self.stats.average_batch_size = 
            (self.stats.average_batch_size * (self.stats.total_batches - 1) as f64 + batch_size as f64)
            / self.stats.total_batches as f64;
    }
    
    pub fn get_statistics(&self) -> &BatchStatistics {
        &self.stats
    }
}
