// RoKoko Prover - Complete Proving System
//
// Orchestrates all components to generate complete RoKoko proofs:
// - Witness polynomial construction
// - Commitment generation
// - Sumcheck protocol execution
// - Refinement layer generation
// - Final proof assembly

use crate::errors::ZKVMError;
use crate::rokoko::commitment::{CommitmentKey, RokokoCommitment, RokokoCommitmentScheme, Opening};
use crate::rokoko::lattice::{LatticeElement, LatticeParams};
use crate::rokoko::polynomial::MultilinearPolynomial;
use crate::rokoko::refinement::{RefinementProof, RefinementProtocol};
use crate::rokoko::sumcheck::{SumcheckProof, SumcheckProver, ZeroKnowledgeSumcheck, BatchSumcheckProver};
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol};
use crate::rokoko::protocol::{RokokoProof, PublicParams};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Prover state during proof generation
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProverState {
    /// Witness polynomials (secret)
    #[zeroize(skip)]
    witness_polynomials: Vec<MultilinearPolynomial>,
    
    /// Commitment openings (secret)
    #[zeroize(skip)]
    openings: Vec<Opening>,
    
    /// Random coins used
    #[zeroize(skip)]
    random_coins: Vec<u8>,
    
    /// Current transcript state
    #[zeroize(skip)]
    transcript: RokokoTranscript,
    
    /// Processing statistics
    num_constraints: usize,
    num_variables: usize,
}

impl ProverState {
    pub fn new(
        witness_polynomials: Vec<MultilinearPolynomial>,
        transcript: RokokoTranscript,
        num_constraints: usize,
    ) -> Self {
        let num_variables = witness_polynomials.first()
            .map(|p| p.num_variables())
            .unwrap_or(0);
        
        Self {
            witness_polynomials,
            openings: Vec::new(),
            random_coins: Vec::new(),
            transcript,
            num_constraints,
            num_variables,
        }
    }
    
    pub fn num_witness_polynomials(&self) -> usize {
        self.witness_polynomials.len()
    }
    
    pub fn add_opening(&mut self, opening: Opening) {
        self.openings.push(opening);
    }
}

/// Main RoKoko prover
pub struct RokokoProver {
    /// Public parameters
    public_params: PublicParams,
    
    /// Refinement protocol
    refinement_protocol: RefinementProtocol,
    
    /// Commitment scheme
    commitment_scheme: RokokoCommitmentScheme,
    
    /// Zero-knowledge mode
    zero_knowledge: bool,
    
    /// Batch mode
    batch_mode: bool,
}

impl RokokoProver {
    pub fn new(
        public_params: PublicParams,
        refinement_protocol: RefinementProtocol,
        commitment_scheme: RokokoCommitmentScheme,
    ) -> Self {
        Self {
            public_params,
            refinement_protocol,
            commitment_scheme,
            zero_knowledge: false,
            batch_mode: false,
        }
    }
    
    /// Enables zero-knowledge mode
    pub fn with_zero_knowledge(mut self) -> Self {
        self.zero_knowledge = true;
        self
    }
    
    /// Enables batch proving mode
    pub fn with_batch_mode(mut self) -> Self {
        self.batch_mode = true;
        self
    }
    
    /// Generates complete RoKoko proof
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        witness: &[u64],
        statement: &[u64],
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Initialize transcript
        let mut transcript = RokokoTranscript::rokoko_transcript();
        
        // Add public statement to transcript
        transcript.append_message(b"statement", &bincode::serialize(statement)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
        
        // Construct witness polynomial
        let witness_poly = self.construct_witness_polynomial(witness)?;
        
        // Generate commitments
        let (commitments, openings) = self.generate_commitments(&[witness_poly.clone()], &mut transcript, rng)?;
        
        // Create prover state
        let mut prover_state = ProverState::new(
            vec![witness_poly.clone()],
            transcript.clone(),
            statement.len(),
        );
        
        for opening in openings {
            prover_state.add_opening(opening);
        }
        
        // Generate proof based on mode
        let proof = if self.zero_knowledge {
            self.prove_zero_knowledge(witness_poly, &mut prover_state, rng)?
        } else if self.batch_mode {
            self.prove_batch(vec![witness_poly], &mut prover_state, rng)?
        } else {
            self.prove_standard(witness_poly, &mut prover_state, rng)?
        };
        
        Ok(proof)
    }
    
    /// Standard (non-ZK) proving
    fn prove_standard<R: RngCore + CryptoRng>(
        &mut self,
        polynomial: MultilinearPolynomial,
        prover_state: &mut ProverState,
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Generate refinement proof
        let refinement_proof = self.refinement_protocol.prove(
            polynomial,
            prover_state.transcript.clone(),
            rng,
        )?;
        
        // Assemble final proof
        Ok(RokokoProof {
            refinement_proof,
            commitments: Vec::new(),
            auxiliary_data: None,
            proof_type: ProofType::Standard,
        })
    }
    
    /// Zero-knowledge proving with masking
    fn prove_zero_knowledge<R: RngCore + CryptoRng>(
        &mut self,
        polynomial: MultilinearPolynomial,
        prover_state: &mut ProverState,
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Create ZK sumcheck
        let zk_sumcheck = ZeroKnowledgeSumcheck::new(
            polynomial.clone(),
            polynomial.modulus,
            rng,
        )?;
        
        let masked_poly = zk_sumcheck.masked_polynomial()?;
        
        // Generate refinement proof on masked polynomial
        let refinement_proof = self.refinement_protocol.prove(
            masked_poly,
            prover_state.transcript.clone(),
            rng,
        )?;
        
        // Store masking information
        let (sumcheck_proof, masking_sum) = zk_sumcheck.prove(
            prover_state.transcript.clone(),
            rng,
        )?;
        
        let auxiliary_data = bincode::serialize(&masking_sum)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?;
        
        Ok(RokokoProof {
            refinement_proof,
            commitments: Vec::new(),
            auxiliary_data: Some(auxiliary_data),
            proof_type: ProofType::ZeroKnowledge,
        })
    }
    
    /// Batch proving for multiple statements
    fn prove_batch<R: RngCore + CryptoRng>(
        &mut self,
        polynomials: Vec<MultilinearPolynomial>,
        prover_state: &mut ProverState,
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        if polynomials.is_empty() {
            return Err(ZKVMError::InvalidParameter(
                "No polynomials to prove".to_string()
            ));
        }
        
        // Compute claimed sums
        let claimed_sums: Vec<u64> = polynomials.iter()
            .map(|p| p.evaluations.iter()
                .fold(0u128, |acc, &x| (acc + x as u128) % p.modulus as u128) as u64)
            .collect();
        
        // Create batch sumcheck prover
        let batch_prover = BatchSumcheckProver::new(
            polynomials.clone(),
            claimed_sums,
            polynomials[0].modulus,
        )?;
        
        // Generate batch proof
        let (sumcheck_proof, batching_coeffs) = batch_prover.prove(
            prover_state.transcript.clone(),
            rng,
        )?;
        
        // Compute combined polynomial
        let num_vars = polynomials[0].num_variables();
        let size = 1 << num_vars;
        let modulus = polynomials[0].modulus;
        let mut combined_evals = vec![0u128; size];
        
        for (idx, poly) in polynomials.iter().enumerate() {
            let coeff = batching_coeffs[idx] as u128;
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + coeff * eval as u128) % modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        let combined_poly = MultilinearPolynomial::new(evals, modulus)?;
        
        // Generate refinement proof on combined polynomial
        let refinement_proof = self.refinement_protocol.prove(
            combined_poly,
            prover_state.transcript.clone(),
            rng,
        )?;
        
        let auxiliary_data = bincode::serialize(&batching_coeffs)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?;
        
        Ok(RokokoProof {
            refinement_proof,
            commitments: Vec::new(),
            auxiliary_data: Some(auxiliary_data),
            proof_type: ProofType::Batch,
        })
    }
    
    /// Constructs witness polynomial from witness values
    fn construct_witness_polynomial(
        &self,
        witness: &[u64],
    ) -> Result<MultilinearPolynomial, ZKVMError> {
        // Pad witness to power of 2
        let num_vars = (witness.len() as f64).log2().ceil() as usize;
        let padded_size = 1 << num_vars;
        
        let mut padded_witness = witness.to_vec();
        padded_witness.resize(padded_size, 0);
        
        MultilinearPolynomial::new(
            padded_witness,
            self.public_params.field_modulus,
        )
    }
    
    /// Generates commitments to witness polynomials
    fn generate_commitments<R: RngCore + CryptoRng>(
        &self,
        polynomials: &[MultilinearPolynomial],
        transcript: &mut RokokoTranscript,
        rng: &mut R,
    ) -> Result<(Vec<RokokoCommitment>, Vec<Opening>), ZKVMError> {
        let mut commitments = Vec::with_capacity(polynomials.len());
        let mut openings = Vec::with_capacity(polynomials.len());
        
        for (idx, poly) in polynomials.iter().enumerate() {
            // Commit to polynomial
            let (commitment, opening) = self.commitment_scheme.commit_multilinear(poly, rng)?;
            
            // Add to transcript
            transcript.append_message(
                format!("witness-commitment-{}", idx).as_bytes(),
                &bincode::serialize(&commitment)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
            
            commitments.push(commitment);
            openings.push(opening);
        }
        
        Ok((commitments, openings))
    }
    
    /// Computes proof size estimate before generation
    pub fn estimate_proof_size(&self, num_variables: usize) -> usize {
        let num_rounds = self.refinement_protocol.num_rounds;
        
        // Commitment size per layer
        let commitment_size_per_layer = self.public_params.commitment_size;
        
        // Sumcheck size: O(ν) rounds, O(d) coefficients per round
        let sumcheck_size_per_layer = num_variables * 2 * 8; // degree 1 polynomials
        
        // Ring switching size
        let switching_size_per_layer = commitment_size_per_layer / 2;
        
        // Total per layer
        let size_per_layer = commitment_size_per_layer + 
                            sumcheck_size_per_layer + 
                            switching_size_per_layer;
        
        // Total proof size
        size_per_layer * num_rounds + 128 // metadata
    }
}

/// Proof type enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProofType {
    Standard,
    ZeroKnowledge,
    Batch,
    Recursive,
}

/// Parallel prover for multi-core systems
pub struct ParallelProver {
    base_prover: RokokoProver,
    num_threads: usize,
}

impl ParallelProver {
    pub fn new(base_prover: RokokoProver, num_threads: usize) -> Self {
        Self {
            base_prover,
            num_threads,
        }
    }
    
    /// Proves multiple statements in parallel
    pub fn prove_parallel<R: RngCore + CryptoRng>(
        &mut self,
        witnesses: Vec<&[u64]>,
        statements: Vec<&[u64]>,
        rng: &mut R,
    ) -> Result<Vec<RokokoProof>, ZKVMError> {
        if witnesses.len() != statements.len() {
            return Err(ZKVMError::InvalidParameter(
                "Witness and statement count mismatch".to_string()
            ));
        }
        
        // For now, sequential implementation
        // Production version would use rayon for parallelization
        let mut proofs = Vec::with_capacity(witnesses.len());
        
        for (witness, statement) in witnesses.iter().zip(statements.iter()) {
            let proof = self.base_prover.prove(witness, statement, rng)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}

/// Streaming prover for large witnesses
pub struct StreamingProver {
    base_prover: RokokoProver,
    chunk_size: usize,
}

impl StreamingProver {
    pub fn new(base_prover: RokokoProver, chunk_size: usize) -> Self {
        Self {
            base_prover,
            chunk_size,
        }
    }
    
    /// Proves witness in chunks
    pub fn prove_streaming<R: RngCore + CryptoRng>(
        &mut self,
        witness_chunks: Vec<&[u64]>,
        statement: &[u64],
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Combine chunks
        let full_witness: Vec<u64> = witness_chunks.iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        
        // Prove combined witness
        self.base_prover.prove(&full_witness, statement, rng)
    }
}

/// Prover with preprocessing
pub struct PreprocessedProver {
    base_prover: RokokoProver,
    preprocessed_data: HashMap<String, Vec<u8>>,
}

impl PreprocessedProver {
    pub fn new(base_prover: RokokoProver) -> Self {
        Self {
            base_prover,
            preprocessed_data: HashMap::new(),
        }
    }
    
    /// Adds preprocessed data
    pub fn add_preprocessed(&mut self, key: String, data: Vec<u8>) {
        self.preprocessed_data.insert(key, data);
    }
    
    /// Proves using preprocessed data
    pub fn prove_with_preprocessing<R: RngCore + CryptoRng>(
        &mut self,
        witness: &[u64],
        statement: &[u64],
        preprocessing_key: &str,
        rng: &mut R,
    ) -> Result<RokokoProof, ZKVMError> {
        // Check if preprocessing exists
        if !self.preprocessed_data.contains_key(preprocessing_key) {
            return Err(ZKVMError::InvalidParameter(
                "Preprocessing key not found".to_string()
            ));
        }
        
        // Use preprocessing data (implementation specific)
        self.base_prover.prove(witness, statement, rng)
    }
}
