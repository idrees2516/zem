// Refinement Protocol for RoKoko - Committed Refinement
//
// Implements the core refinement technique that makes RoKoko succinct
// Combines polynomial commitments with sumcheck protocol in layers
//
// STRUCTURE: Multiple refinement rounds with decreasing moduli
// - Layer 0: Full computation over large modulus q_0
// - Layer 1: Refined computation over q_1 < q_0  
// - Layer k: Final layer over small modulus q_k
//
// COMPRESSION: Logarithmic proof size through ring switching
// SECURITY: Each layer maintains soundness, composable security

use crate::errors::ZKVMError;
use crate::rokoko::commitment::{CommitmentKey, RokokoCommitment, RokokoCommitmentScheme, Opening, EvaluationProof};
use crate::rokoko::lattice::{LatticeElement, LatticeParams};
use crate::rokoko::polynomial::MultilinearPolynomial;
use crate::rokoko::ring_switching::{RingSwitchingProof, RingSwitchingProtocol, MultiLayerSwitching};
use crate::rokoko::sumcheck::{SumcheckProof, SumcheckProver, SumcheckVerifier};
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Single layer of refinement
#[derive(Clone, Serialize, Deserialize)]
pub struct RefinementLayer {
    /// Layer index (0 = first layer)
    pub layer_index: usize,
    
    /// Polynomial commitment for this layer
    pub commitment: RokokoCommitment,
    
    /// Sumcheck proof for this layer
    pub sumcheck_proof: SumcheckProof,
    
    /// Ring switching proof to next layer
    pub switching_proof: Option<RingSwitchingProof>,
    
    /// Modulus for this layer
    pub modulus: u64,
    
    /// Evaluation proof at random point
    pub evaluation_proof: EvaluationProof,
}

impl RefinementLayer {
    pub fn new(
        layer_index: usize,
        commitment: RokokoCommitment,
        sumcheck_proof: SumcheckProof,
        switching_proof: Option<RingSwitchingProof>,
        modulus: u64,
        evaluation_proof: EvaluationProof,
    ) -> Self {
        Self {
            layer_index,
            commitment,
            sumcheck_proof,
            switching_proof,
            modulus,
            evaluation_proof,
        }
    }
    
    pub fn size_bytes(&self) -> usize {
        let comm_size = self.commitment.size_bytes();
        let sumcheck_size = self.sumcheck_proof.size_bytes();
        let switching_size = self.switching_proof.as_ref()
            .map(|p| p.size_bytes())
            .unwrap_or(0);
        let eval_size = self.evaluation_proof.size_bytes();
        
        comm_size + sumcheck_size + switching_size + eval_size + 16
    }
}

/// Complete refinement proof
#[derive(Clone, Serialize, Deserialize)]
pub struct RefinementProof {
    /// All refinement layers
    pub layers: Vec<RefinementLayer>,
    
    /// Initial claimed sum
    pub initial_sum: u64,
    
    /// Final evaluation
    pub final_evaluation: u64,
    
    /// Number of variables
    pub num_variables: usize,
    
    /// Initial modulus
    pub initial_modulus: u64,
    
    /// Final modulus  
    pub final_modulus: u64,
}

impl RefinementProof {
    pub fn new(
        layers: Vec<RefinementLayer>,
        initial_sum: u64,
        final_evaluation: u64,
        num_variables: usize,
        initial_modulus: u64,
        final_modulus: u64,
    ) -> Self {
        Self {
            layers,
            initial_sum,
            final_evaluation,
            num_variables,
            initial_modulus,
            final_modulus,
        }
    }
    
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }
    
    pub fn total_size_bytes(&self) -> usize {
        self.layers.iter().map(|l| l.size_bytes()).sum::<usize>() + 48
    }
    
    pub fn compression_factor(&self) -> f64 {
        (self.initial_modulus as f64 / self.final_modulus as f64).log2()
    }
}

/// Refinement protocol implementation
pub struct RefinementProtocol {
    /// Commitment schemes for each layer
    commitment_schemes: Vec<RokokoCommitmentScheme>,
    
    /// Ring switching for compression
    multi_layer_switching: MultiLayerSwitching,
    
    /// Number of refinement rounds
    num_rounds: usize,
    
    /// Security parameter
    security_parameter: usize,
}

impl RefinementProtocol {
    pub fn new(
        commitment_keys: Vec<CommitmentKey>,
        initial_modulus: u64,
        final_modulus: u64,
        num_rounds: usize,
        dimension: usize,
        security_parameter: usize,
    ) -> Result<Self, ZKVMError> {
        if commitment_keys.len() != num_rounds {
            return Err(ZKVMError::InvalidParameter(
                "Mismatch in commitment keys and rounds".to_string()
            ));
        }
        
        let commitment_schemes: Vec<_> = commitment_keys
            .into_iter()
            .map(RokokoCommitmentScheme::new)
            .collect();
        
        let max_error_per_layer = (dimension as f64).sqrt();
        
        let multi_layer_switching = MultiLayerSwitching::new(
            initial_modulus,
            final_modulus,
            num_rounds.saturating_sub(1),
            dimension,
            max_error_per_layer,
        )?;
        
        Ok(Self {
            commitment_schemes,
            multi_layer_switching,
            num_rounds,
            security_parameter,
        })
    }
    
    /// Proves a statement through refinement layers
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        polynomial: MultilinearPolynomial,
        mut transcript: RokokoTranscript,
        rng: &mut R,
    ) -> Result<RefinementProof, ZKVMError> {
        let initial_sum = polynomial.evaluations.iter()
            .fold(0u128, |acc, &x| (acc + x as u128) % polynomial.modulus as u128) as u64;
        
        let num_variables = polynomial.num_variables();
        let initial_modulus = polynomial.modulus;
        
        let mut layers = Vec::with_capacity(self.num_rounds);
        let mut current_poly = polynomial;
        let mut current_modulus = initial_modulus;
        
        for layer_idx in 0..self.num_rounds {
            transcript.append_message(
                format!("layer-{}", layer_idx).as_bytes(),
                &layer_idx.to_le_bytes()
            )?;
            
            let (commitment, opening) = self.commitment_schemes[layer_idx]
                .commit_multilinear(&current_poly, rng)?;
            
            transcript.append_message(
                b"commitment",
                &bincode::serialize(&commitment)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
            
            let sumcheck_prover = SumcheckProver::new(
                current_poly.clone(),
                current_modulus,
                transcript.clone(),
            );
            
            let sumcheck_proof = sumcheck_prover.prove(rng)?;
            let evaluation_point = sumcheck_proof.evaluation_point.clone();
            
            let evaluation_proof = self.commitment_schemes[layer_idx]
                .prove_evaluation(&commitment, &opening, &evaluation_point, rng)?;
            
            let switching_proof = if layer_idx < self.num_rounds - 1 {
                let next_modulus = self.multi_layer_switching.moduli[layer_idx + 1];
                
                let source_params = self.commitment_schemes[layer_idx].key.params.clone();
                let mut target_params = source_params.clone();
                target_params.modulus = next_modulus;
                
                let max_error = (source_params.dimension as f64).sqrt();
                let mut switching_protocol = RingSwitchingProtocol::new(
                    source_params,
                    target_params,
                    max_error,
                )?;
                
                let switched_commitment_elements = switching_protocol.prove_switching(
                    &commitment.commitment,
                    &mut transcript,
                    rng,
                )?;
                
                let switched_evals: Vec<u64> = current_poly.evaluations.iter()
                    .map(|&x| {
                        let scaled = (x as f64 * next_modulus as f64 / current_modulus as f64).round();
                        (scaled as u64) % next_modulus
                    })
                    .collect();
                
                current_poly = MultilinearPolynomial::new(switched_evals, next_modulus)?;
                current_modulus = next_modulus;
                
                Some(switched_commitment_elements)
            } else {
                None
            };
            
            let layer = RefinementLayer::new(
                layer_idx,
                commitment,
                sumcheck_proof,
                switching_proof,
                current_modulus,
                evaluation_proof,
            );
            
            layers.push(layer);
        }
        
        let final_evaluation = current_poly.evaluations[0];
        let final_modulus = current_modulus;
        
        Ok(RefinementProof::new(
            layers,
            initial_sum,
            final_evaluation,
            num_variables,
            initial_modulus,
            final_modulus,
        ))
    }
    
    /// Verifies a refinement proof
    pub fn verify(
        &self,
        proof: &RefinementProof,
        mut transcript: RokokoTranscript,
    ) -> Result<bool, ZKVMError> {
        if proof.layers.len() != self.num_rounds {
            return Ok(false);
        }
        
        let mut current_sum = proof.initial_sum;
        let mut current_modulus = proof.initial_modulus;
        
        for (layer_idx, layer) in proof.layers.iter().enumerate() {
            transcript.append_message(
                format!("layer-{}", layer_idx).as_bytes(),
                &layer_idx.to_le_bytes()
            )?;
            
            transcript.append_message(
                b"commitment",
                &bincode::serialize(&layer.commitment)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
            
            let sumcheck_verifier = SumcheckVerifier::new(
                current_sum,
                current_modulus,
                transcript.clone(),
            );
            
            let eval_point = layer.sumcheck_proof.evaluation_point.clone();
            let claimed_eval = layer.sumcheck_proof.final_evaluation;
            
            if !sumcheck_verifier.verify(&layer.sumcheck_proof, claimed_eval)? {
                return Ok(false);
            }
            
            if !self.commitment_schemes[layer_idx].verify_evaluation(
                &layer.commitment,
                &layer.evaluation_proof,
                &eval_point,
                claimed_eval,
            )? {
                return Ok(false);
            }
            
            if let Some(ref switching_proof) = layer.switching_proof {
                let next_modulus = self.multi_layer_switching.moduli[layer_idx + 1];
                
                let source_params = self.commitment_schemes[layer_idx].key.params.clone();
                let mut target_params = source_params.clone();
                target_params.modulus = next_modulus;
                
                let max_error = (source_params.dimension as f64).sqrt();
                let switching_protocol = RingSwitchingProtocol::new(
                    source_params,
                    target_params,
                    max_error,
                )?;
                
                if !switching_protocol.verify_switching(
                    &layer.commitment.commitment,
                    switching_proof,
                    &mut transcript,
                )? {
                    return Ok(false);
                }
                
                current_modulus = next_modulus;
            }
            
            current_sum = claimed_eval;
        }
        
        if current_sum != proof.final_evaluation {
            return Ok(false);
        }
        
        if current_modulus != proof.final_modulus {
            return Ok(false);
        }
        
        Ok(true)
    }
}

/// Batch refinement for multiple polynomials
pub struct BatchRefinement {
    base_protocol: RefinementProtocol,
    batch_size: usize,
}

impl BatchRefinement {
    pub fn new(
        base_protocol: RefinementProtocol,
        batch_size: usize,
    ) -> Self {
        Self {
            base_protocol,
            batch_size,
        }
    }
    
    pub fn prove_batch<R: RngCore + CryptoRng>(
        &mut self,
        polynomials: Vec<MultilinearPolynomial>,
        transcript: RokokoTranscript,
        rng: &mut R,
    ) -> Result<(RefinementProof, Vec<u64>), ZKVMError> {
        if polynomials.len() != self.batch_size {
            return Err(ZKVMError::InvalidParameter(
                "Batch size mismatch".to_string()
            ));
        }
        
        let modulus = polynomials[0].modulus;
        let coefficients: Vec<u64> = (0..self.batch_size)
            .map(|_| rng.gen::<u64>() % modulus)
            .collect();
        
        let num_vars = polynomials[0].num_variables();
        let size = 1 << num_vars;
        let mut combined_evals = vec![0u128; size];
        
        for (idx, poly) in polynomials.iter().enumerate() {
            let coeff = coefficients[idx] as u128;
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + coeff * eval as u128) % modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        let combined_poly = MultilinearPolynomial::new(evals, modulus)?;
        
        let proof = self.base_protocol.prove(combined_poly, transcript, rng)?;
        
        Ok((proof, coefficients))
    }
}

/// Incremental refinement for streaming data
pub struct IncrementalRefinement {
    current_layer: usize,
    accumulated_layers: Vec<RefinementLayer>,
    protocol: RefinementProtocol,
}

impl IncrementalRefinement {
    pub fn new(protocol: RefinementProtocol) -> Self {
        Self {
            current_layer: 0,
            accumulated_layers: Vec::new(),
            protocol,
        }
    }
    
    pub fn add_layer<R: RngCore + CryptoRng>(
        &mut self,
        polynomial: MultilinearPolynomial,
        transcript: &mut RokokoTranscript,
        rng: &mut R,
    ) -> Result<RefinementLayer, ZKVMError> {
        if self.current_layer >= self.protocol.num_rounds {
            return Err(ZKVMError::ProofGenerationError(
                "All layers completed".to_string()
            ));
        }
        
        let (commitment, opening) = self.protocol.commitment_schemes[self.current_layer]
            .commit_multilinear(&polynomial, rng)?;
        
        let sumcheck_prover = SumcheckProver::new(
            polynomial.clone(),
            polynomial.modulus,
            transcript.clone(),
        );
        
        let sumcheck_proof = sumcheck_prover.prove(rng)?;
        let evaluation_point = sumcheck_proof.evaluation_point.clone();
        
        let evaluation_proof = self.protocol.commitment_schemes[self.current_layer]
            .prove_evaluation(&commitment, &opening, &evaluation_point, rng)?;
        
        let layer = RefinementLayer::new(
            self.current_layer,
            commitment,
            sumcheck_proof,
            None,
            polynomial.modulus,
            evaluation_proof,
        );
        
        self.accumulated_layers.push(layer.clone());
        self.current_layer += 1;
        
        Ok(layer)
    }
    
    pub fn is_complete(&self) -> bool {
        self.current_layer >= self.protocol.num_rounds
    }
    
    pub fn finalize(self) -> Vec<RefinementLayer> {
        self.accumulated_layers
    }
}
