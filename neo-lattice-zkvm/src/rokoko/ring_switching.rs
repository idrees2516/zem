// Ring Switching Protocol for RoKoko
//
// Implements modulus switching and ring dimension reduction for proof compression
// This is a key component of the committed refinement technique
//
// PROTOCOL: Switches from (R_q, q) to (R_p, p) where p < q
// SECURITY: Maintains soundness under modulus reduction with controlled error growth
// COMPRESSION: Achieves log(q/p) compression factor per layer

use crate::errors::ZKVMError;
use crate::rokoko::lattice::{LatticeElement, LatticeParams, ModulusSwitching};
use crate::rokoko::polynomial::MultilinearPolynomial;
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ring switching proof from modulus q to modulus p
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RingSwitchingProof {
    /// Switched lattice elements
    pub switched_elements: Vec<LatticeElement>,
    
    /// Error correction terms
    pub error_terms: Vec<LatticeElement>,
    
    /// Old modulus q
    pub old_modulus: u64,
    
    /// New modulus p
    pub new_modulus: u64,
    
    /// Rounding error bound
    pub error_bound: f64,
}

impl RingSwitchingProof {
    pub fn new(
        switched_elements: Vec<LatticeElement>,
        error_terms: Vec<LatticeElement>,
        old_modulus: u64,
        new_modulus: u64,
        error_bound: f64,
    ) -> Self {
        Self {
            switched_elements,
            error_terms,
            old_modulus,
            new_modulus,
            error_bound,
        }
    }
    
    pub fn compression_factor(&self) -> f64 {
        (self.old_modulus as f64 / self.new_modulus as f64).log2()
    }
    
    pub fn size_bytes(&self) -> usize {
        let elem_size = self.switched_elements.len() * 
            self.switched_elements[0].coeffs.len() * 8;
        let error_size = self.error_terms.len() * 
            self.error_terms[0].coeffs.len() * 8;
        elem_size + error_size + 32
    }
}

/// Protocol for switching between rings
pub struct RingSwitchingProtocol {
    /// Source lattice parameters
    source_params: LatticeParams,
    
    /// Target lattice parameters
    target_params: LatticeParams,
    
    /// Error accumulation tracker
    accumulated_error: f64,
    
    /// Maximum allowed error
    max_error: f64,
}

impl RingSwitchingProtocol {
    pub fn new(
        source_params: LatticeParams,
        target_params: LatticeParams,
        max_error: f64,
    ) -> Result<Self, ZKVMError> {
        source_params.validate()?;
        target_params.validate()?;
        
        if source_params.modulus <= target_params.modulus {
            return Err(ZKVMError::InvalidParameter(
                "Target modulus must be smaller than source".to_string()
            ));
        }
        
        if source_params.dimension != target_params.dimension {
            return Err(ZKVMError::InvalidParameter(
                "Dimension mismatch in ring switching".to_string()
            ));
        }
        
        Ok(Self {
            source_params,
            target_params,
            accumulated_error: 0.0,
            max_error,
        })
    }
    
    /// Switches a single lattice element from q to p
    pub fn switch_element(
        &mut self,
        element: &LatticeElement,
    ) -> Result<(LatticeElement, LatticeElement), ZKVMError> {
        // Compute scaling factor: scale = p/q
        let scale = self.target_params.modulus as f64 / self.source_params.modulus as f64;
        
        // Switch coefficients with rounding
        let mut switched_coeffs = Vec::with_capacity(element.coeffs.len());
        let mut error_coeffs = Vec::with_capacity(element.coeffs.len());
        
        for &coeff in &element.coeffs {
            // Scale and round: c' = round(c * p/q)
            let scaled = (coeff as f64 * scale).round();
            let switched = (scaled as u64) % self.target_params.modulus;
            
            // Compute rounding error: e = c' - c*p/q
            let exact_scaled = coeff as f64 * scale;
            let error = scaled - exact_scaled;
            let error_coeff = (error.abs() as u64) % self.target_params.modulus;
            
            switched_coeffs.push(switched);
            error_coeffs.push(error_coeff);
        }
        
        // Update accumulated error
        let switch_error = ModulusSwitching::error_bound(
            self.source_params.modulus,
            self.target_params.modulus,
            self.source_params.dimension,
        );
        self.accumulated_error += switch_error;
        
        if self.accumulated_error > self.max_error {
            return Err(ZKVMError::ProofGenerationError(
                "Error accumulation exceeds maximum".to_string()
            ));
        }
        
        let switched_elem = LatticeElement::new(switched_coeffs, self.target_params.modulus);
        let error_elem = LatticeElement::new(error_coeffs, self.target_params.modulus);
        
        Ok((switched_elem, error_elem))
    }
    
    /// Switches multiple elements (batch operation)
    pub fn switch_elements(
        &mut self,
        elements: &[LatticeElement],
    ) -> Result<(Vec<LatticeElement>, Vec<LatticeElement>), ZKVMError> {
        let mut switched_elements = Vec::with_capacity(elements.len());
        let mut error_terms = Vec::with_capacity(elements.len());
        
        for element in elements {
            let (switched, error) = self.switch_element(element)?;
            switched_elements.push(switched);
            error_terms.push(error);
        }
        
        Ok((switched_elements, error_terms))
    }
    
    /// Proves correct ring switching
    pub fn prove_switching<R: RngCore + CryptoRng>(
        &mut self,
        elements: &[LatticeElement],
        transcript: &mut RokokoTranscript,
        rng: &mut R,
    ) -> Result<RingSwitchingProof, ZKVMError> {
        // Add elements to transcript
        for (i, elem) in elements.iter().enumerate() {
            transcript.append_message(
                format!("source-elem-{}", i).as_bytes(),
                &bincode::serialize(&elem.coeffs)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
        }
        
        // Perform switching
        let (switched_elements, error_terms) = self.switch_elements(elements)?;
        
        // Add switched elements to transcript
        for (i, elem) in switched_elements.iter().enumerate() {
            transcript.append_message(
                format!("switched-elem-{}", i).as_bytes(),
                &bincode::serialize(&elem.coeffs)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
        }
        
        // Generate challenge for error verification
        let challenge = transcript.challenge_scalar(b"switch-challenge")?;
        
        // Compute error bound
        let error_bound = ModulusSwitching::error_bound(
            self.source_params.modulus,
            self.target_params.modulus,
            self.source_params.dimension,
        );
        
        Ok(RingSwitchingProof::new(
            switched_elements,
            error_terms,
            self.source_params.modulus,
            self.target_params.modulus,
            error_bound,
        ))
    }
    
    /// Verifies ring switching proof
    pub fn verify_switching(
        &self,
        original_elements: &[LatticeElement],
        proof: &RingSwitchingProof,
        transcript: &mut RokokoTranscript,
    ) -> Result<bool, ZKVMError> {
        // Verify moduli match
        if proof.old_modulus != self.source_params.modulus {
            return Ok(false);
        }
        if proof.new_modulus != self.target_params.modulus {
            return Ok(false);
        }
        
        // Add original elements to transcript
        for (i, elem) in original_elements.iter().enumerate() {
            transcript.append_message(
                format!("source-elem-{}", i).as_bytes(),
                &bincode::serialize(&elem.coeffs)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
        }
        
        // Add switched elements to transcript
        for (i, elem) in proof.switched_elements.iter().enumerate() {
            transcript.append_message(
                format!("switched-elem-{}", i).as_bytes(),
                &bincode::serialize(&elem.coeffs)
                    .map_err(|e| ZKVMError::SerializationError(e.to_string()))?
            )?;
        }
        
        // Regenerate challenge
        let challenge = transcript.challenge_scalar(b"switch-challenge")?;
        
        // Verify each switched element
        for i in 0..original_elements.len() {
            if !self.verify_single_switch(
                &original_elements[i],
                &proof.switched_elements[i],
                &proof.error_terms[i],
            )? {
                return Ok(false);
            }
        }
        
        // Verify error bound
        let expected_bound = ModulusSwitching::error_bound(
            self.source_params.modulus,
            self.target_params.modulus,
            self.source_params.dimension,
        );
        
        if (proof.error_bound - expected_bound).abs() > 1e-6 {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Verifies a single element switch
    fn verify_single_switch(
        &self,
        original: &LatticeElement,
        switched: &LatticeElement,
        error: &LatticeElement,
    ) -> Result<bool, ZKVMError> {
        let scale = self.target_params.modulus as f64 / self.source_params.modulus as f64;
        
        for i in 0..original.coeffs.len() {
            let orig_coeff = original.coeffs[i];
            let switch_coeff = switched.coeffs[i];
            let error_coeff = error.coeffs[i];
            
            // Verify: switched ≈ original * scale (mod p)
            let expected = ((orig_coeff as f64 * scale).round() as u64) 
                % self.target_params.modulus;
            
            let diff = if switch_coeff >= expected {
                switch_coeff - expected
            } else {
                self.target_params.modulus - (expected - switch_coeff)
            };
            
            // Error should be small
            if diff > error_coeff + 1 {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    pub fn accumulated_error(&self) -> f64 {
        self.accumulated_error
    }
    
    pub fn can_switch(&self) -> bool {
        let next_error = ModulusSwitching::error_bound(
            self.source_params.modulus,
            self.target_params.modulus,
            self.source_params.dimension,
        );
        self.accumulated_error + next_error <= self.max_error
    }
}

/// Multi-layer ring switching for refinement protocol
pub struct MultiLayerSwitching {
    /// Switching protocols for each layer
    layers: Vec<RingSwitchingProtocol>,
    
    /// Moduli progression: q_0 > q_1 > ... > q_k
    moduli: Vec<u64>,
    
    /// Total compression factor
    total_compression: f64,
}

impl MultiLayerSwitching {
    pub fn new(
        initial_modulus: u64,
        final_modulus: u64,
        num_layers: usize,
        dimension: usize,
        max_error_per_layer: f64,
    ) -> Result<Self, ZKVMError> {
        if num_layers < 1 {
            return Err(ZKVMError::InvalidParameter(
                "Need at least one layer".to_string()
            ));
        }
        
        if initial_modulus <= final_modulus {
            return Err(ZKVMError::InvalidParameter(
                "Initial modulus must be larger".to_string()
            ));
        }
        
        // Compute geometric progression of moduli
        let ratio = (initial_modulus as f64 / final_modulus as f64).powf(1.0 / num_layers as f64);
        let mut moduli = vec![initial_modulus];
        
        for i in 1..num_layers {
            let next_modulus = (initial_modulus as f64 / ratio.powi(i as i32)) as u64;
            moduli.push(next_modulus);
        }
        moduli.push(final_modulus);
        
        // Create switching protocols for each layer
        let mut layers = Vec::with_capacity(num_layers);
        
        for i in 0..num_layers {
            let source_params = LatticeParams {
                dimension,
                modulus: moduli[i],
                error_stddev: 3.2,
                module_rank: 4,
                rejection_factor: 12.0,
                smoothing_param: 1.5,
            };
            
            let target_params = LatticeParams {
                dimension,
                modulus: moduli[i + 1],
                error_stddev: 3.2,
                module_rank: 4,
                rejection_factor: 12.0,
                smoothing_param: 1.5,
            };
            
            layers.push(RingSwitchingProtocol::new(
                source_params,
                target_params,
                max_error_per_layer,
            )?);
        }
        
        let total_compression = (initial_modulus as f64 / final_modulus as f64).log2();
        
        Ok(Self {
            layers,
            moduli,
            total_compression,
        })
    }
    
    /// Switches through all layers
    pub fn switch_through_layers<R: RngCore + CryptoRng>(
        &mut self,
        initial_elements: &[LatticeElement],
        transcript: &mut RokokoTranscript,
        rng: &mut R,
    ) -> Result<Vec<RingSwitchingProof>, ZKVMError> {
        let mut current_elements = initial_elements.to_vec();
        let mut proofs = Vec::with_capacity(self.layers.len());
        
        for (layer_idx, layer) in self.layers.iter_mut().enumerate() {
            transcript.append_message(
                format!("layer-{}", layer_idx).as_bytes(),
                &layer_idx.to_le_bytes()
            )?;
            
            let proof = layer.prove_switching(&current_elements, transcript, rng)?;
            current_elements = proof.switched_elements.clone();
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    /// Verifies multi-layer switching
    pub fn verify_layers(
        &self,
        initial_elements: &[LatticeElement],
        proofs: &[RingSwitchingProof],
        transcript: &mut RokokoTranscript,
    ) -> Result<bool, ZKVMError> {
        if proofs.len() != self.layers.len() {
            return Ok(false);
        }
        
        let mut current_elements = initial_elements.to_vec();
        
        for (layer_idx, (layer, proof)) in self.layers.iter().zip(proofs.iter()).enumerate() {
            transcript.append_message(
                format!("layer-{}", layer_idx).as_bytes(),
                &layer_idx.to_le_bytes()
            )?;
            
            if !layer.verify_switching(&current_elements, proof, transcript)? {
                return Ok(false);
            }
            
            current_elements = proof.switched_elements.clone();
        }
        
        Ok(true)
    }
    
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }
    
    pub fn compression_factor(&self) -> f64 {
        self.total_compression
    }
    
    pub fn final_modulus(&self) -> u64 {
        *self.moduli.last().unwrap()
    }
}

/// Adaptive ring switching that adjusts moduli based on error
pub struct AdaptiveSwitching {
    /// Current parameters
    current_params: LatticeParams,
    
    /// Target security level
    target_security: f64,
    
    /// Error budget
    error_budget: f64,
    
    /// Used error
    used_error: f64,
}

impl AdaptiveSwitching {
    pub fn new(
        initial_params: LatticeParams,
        target_security: f64,
        error_budget: f64,
    ) -> Self {
        Self {
            current_params: initial_params,
            target_security,
            error_budget,
            used_error: 0.0,
        }
    }
    
    /// Computes optimal next modulus
    pub fn compute_next_modulus(&self) -> u64 {
        let remaining_budget = self.error_budget - self.used_error;
        
        // Compute maximum compression that stays within budget
        let max_ratio = remaining_budget / (self.current_params.dimension as f64).sqrt();
        
        // Ensure minimum security
        let min_modulus = (2.0_f64.powf(self.target_security)) as u64;
        
        let next_modulus = ((self.current_params.modulus as f64 / max_ratio) as u64)
            .max(min_modulus);
        
        next_modulus
    }
    
    /// Performs adaptive switch
    pub fn adaptive_switch<R: RngCore + CryptoRng>(
        &mut self,
        elements: &[LatticeElement],
        transcript: &mut RokokoTranscript,
        rng: &mut R,
    ) -> Result<RingSwitchingProof, ZKVMError> {
        let next_modulus = self.compute_next_modulus();
        
        let target_params = LatticeParams {
            dimension: self.current_params.dimension,
            modulus: next_modulus,
            error_stddev: self.current_params.error_stddev,
            module_rank: self.current_params.module_rank,
            rejection_factor: self.current_params.rejection_factor,
            smoothing_param: self.current_params.smoothing_param,
        };
        
        let mut protocol = RingSwitchingProtocol::new(
            self.current_params.clone(),
            target_params.clone(),
            self.error_budget - self.used_error,
        )?;
        
        let proof = protocol.prove_switching(elements, transcript, rng)?;
        
        self.used_error += protocol.accumulated_error();
        self.current_params = target_params;
        
        Ok(proof)
    }
    
    pub fn remaining_budget(&self) -> f64 {
        self.error_budget - self.used_error
    }
    
    pub fn can_continue(&self) -> bool {
        self.remaining_budget() > 0.0 && 
            self.current_params.modulus > (2.0_f64.powf(self.target_security)) as u64
    }
}
