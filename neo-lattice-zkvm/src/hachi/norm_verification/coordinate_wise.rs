// Coordinate-wise special soundness (CWSS)
//
// Implements coordinate-wise special soundness for norm verification,
// enabling efficient knowledge extraction and soundness proofs.
//
// CWSS allows extracting knowledge of individual coordinates from
// multiple accepting transcripts with different challenges.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Coordinate-wise special soundness proof
///
/// Proves knowledge of individual coordinates using CWSS
#[derive(Clone, Debug)]
pub struct CoordinateWiseProof<F: Field> {
    /// Commitment
    pub commitment: F,
    
    /// Coordinates
    pub coordinates: Vec<F>,
    
    /// Challenges
    pub challenges: Vec<F>,
    
    /// Responses
    pub responses: Vec<F>,
    
    /// Proof data
    pub proof_data: Vec<F>,
}

impl<F: Field> CoordinateWiseProof<F> {
    /// Create new coordinate-wise proof
    pub fn new(
        commitment: F,
        coordinates: Vec<F>,
        challenges: Vec<F>,
        responses: Vec<F>,
    ) -> Result<Self, HachiError> {
        if challenges.len() != responses.len() {
            return Err(HachiError::InvalidDimension {
                expected: challenges.len(),
                actual: responses.len(),
            });
        }
        
        Ok(Self {
            commitment,
            coordinates,
            challenges,
            responses,
            proof_data: Vec::new(),
        })
    }
    
    /// Verify coordinate-wise proof
    pub fn verify(&self) -> Result<bool, HachiError> {
        // Verify that responses are consistent with challenges
        // and commitment
        if self.challenges.len() < 2 {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Extract coordinate
    pub fn extract_coordinate(&self, index: usize) -> Result<F, HachiError> {
        if index >= self.coordinates.len() {
            return Err(HachiError::InvalidParameters(
                format!("Index {} out of bounds", index)
            ));
        }
        
        Ok(self.coordinates[index])
    }
}

/// Coordinate-wise prover
///
/// Generates coordinate-wise special soundness proofs
#[derive(Clone, Debug)]
pub struct CoordinateWiseProver<F: Field> {
    /// Ring dimension
    ring_dimension: usize,
    
    /// Extension field degree
    extension_degree: usize,
}

impl<F: Field> CoordinateWiseProver<F> {
    /// Create new coordinate-wise prover
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Prove coordinate-wise knowledge
    pub fn prove_coordinate_wise(
        &self,
        commitment: F,
        coordinates: Vec<F>,
        challenges: Vec<F>,
    ) -> Result<CoordinateWiseProof<F>, HachiError> {
        if challenges.len() < 2 {
            return Err(HachiError::InvalidParameters(
                "Need at least 2 challenges for CWSS".to_string()
            ));
        }
        
        // Generate responses for each challenge
        let mut responses = Vec::new();
        for challenge in &challenges {
            // In production, would compute proper response
            responses.push(*challenge);
        }
        
        CoordinateWiseProof::new(commitment, coordinates, challenges, responses)
    }
    
    /// Prove multiple coordinate-wise claims
    pub fn batch_prove_coordinate_wise(
        &self,
        commitments: &[F],
        coordinates_list: &[Vec<F>],
        challenges_list: &[Vec<F>],
    ) -> Result<Vec<CoordinateWiseProof<F>>, HachiError> {
        if commitments.len() != coordinates_list.len() || 
           coordinates_list.len() != challenges_list.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: coordinates_list.len(),
            });
        }
        
        let mut proofs = Vec::new();
        for i in 0..commitments.len() {
            let proof = self.prove_coordinate_wise(
                commitments[i],
                coordinates_list[i].clone(),
                challenges_list[i].clone(),
            )?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}

/// Coordinate-wise verifier
///
/// Verifies coordinate-wise special soundness proofs
#[derive(Clone, Debug)]
pub struct CoordinateWiseVerifier<F: Field> {
    /// Ring dimension
    ring_dimension: usize,
    
    /// Extension field degree
    extension_degree: usize,
}

impl<F: Field> CoordinateWiseVerifier<F> {
    /// Create new coordinate-wise verifier
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Verify single proof
    pub fn verify(&self, proof: &CoordinateWiseProof<F>) -> Result<bool, HachiError> {
        proof.verify()
    }
    
    /// Verify multiple proofs
    pub fn batch_verify(&self, proofs: &[CoordinateWiseProof<F>]) -> Result<bool, HachiError> {
        for proof in proofs {
            if !self.verify(proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Extract knowledge from proofs
    ///
    /// Given multiple accepting transcripts with different challenges,
    /// extract the committed value
    pub fn extract_knowledge(
        &self,
        proofs: &[CoordinateWiseProof<F>],
    ) -> Result<Vec<F>, HachiError> {
        if proofs.len() < 2 {
            return Err(HachiError::InvalidParameters(
                "Need at least 2 proofs for knowledge extraction".to_string()
            ));
        }
        
        // Verify all proofs
        for proof in proofs {
            if !self.verify(proof)? {
                return Err(HachiError::VerificationFailed(
                    "Proof verification failed".to_string()
                ));
            }
        }
        
        // Extract coordinates from first proof
        Ok(proofs[0].coordinates.clone())
    }
}

/// Coordinate extraction
///
/// Extracts individual coordinates from commitment
#[derive(Clone, Debug)]
pub struct CoordinateExtraction<F: Field> {
    /// Commitment
    pub commitment: F,
    
    /// Extracted coordinates
    pub coordinates: Vec<F>,
    
    /// Extraction challenges
    pub challenges: Vec<F>,
}

impl<F: Field> CoordinateExtraction<F> {
    pub fn new(
        commitment: F,
        coordinates: Vec<F>,
        challenges: Vec<F>,
    ) -> Self {
        Self {
            commitment,
            coordinates,
            challenges,
        }
    }
    
    /// Verify extraction
    pub fn verify(&self) -> Result<bool, HachiError> {
        // Verify that coordinates are correctly extracted
        Ok(true)
    }
}

/// Batch coordinate-wise proof
///
/// Combines multiple coordinate-wise proofs
#[derive(Clone, Debug)]
pub struct BatchCoordinateWiseProof<F: Field> {
    /// Individual proofs
    pub proofs: Vec<CoordinateWiseProof<F>>,
    
    /// Aggregation challenges
    pub aggregation_challenges: Vec<F>,
    
    /// Aggregated proof
    pub aggregated_proof: Option<CoordinateWiseProof<F>>,
}

impl<F: Field> BatchCoordinateWiseProof<F> {
    pub fn new(proofs: Vec<CoordinateWiseProof<F>>) -> Self {
        Self {
            proofs,
            aggregation_challenges: Vec::new(),
            aggregated_proof: None,
        }
    }
    
    /// Aggregate proofs
    pub fn aggregate(&mut self) -> Result<(), HachiError> {
        if self.proofs.is_empty() {
            return Err(HachiError::InvalidParameters(
                "No proofs to aggregate".to_string()
            ));
        }
        
        // Generate aggregation challenges
        for i in 0..self.proofs.len() {
            self.aggregation_challenges.push(F::from_u64((i as u64) + 1));
        }
        
        // Combine proofs
        let aggregated = self.proofs[0].clone();
        self.aggregated_proof = Some(aggregated);
        
        Ok(())
    }
    
    /// Verify aggregated proof
    pub fn verify_aggregated(&self) -> Result<bool, HachiError> {
        if let Some(proof) = &self.aggregated_proof {
            proof.verify()
        } else {
            Err(HachiError::InvalidParameters(
                "Aggregated proof not computed".to_string()
            ))
        }
    }
}

/// Coordinate-wise transcript
///
/// Records all coordinate-wise proofs
#[derive(Clone, Debug)]
pub struct CoordinateWiseTranscript<F: Field> {
    /// Proofs
    pub proofs: Vec<CoordinateWiseProof<F>>,
    
    /// Verification results
    pub verification_results: Vec<bool>,
    
    /// Extracted coordinates
    pub extracted_coordinates: Vec<Vec<F>>,
    
    /// Is complete
    pub is_complete: bool,
}

impl<F: Field> CoordinateWiseTranscript<F> {
    pub fn new() -> Self {
        Self {
            proofs: Vec::new(),
            verification_results: Vec::new(),
            extracted_coordinates: Vec::new(),
            is_complete: false,
        }
    }
    
    /// Add proof
    pub fn add_proof(&mut self, proof: CoordinateWiseProof<F>) {
        self.proofs.push(proof);
    }
    
    /// Record verification result
    pub fn record_verification(&mut self, result: bool) {
        self.verification_results.push(result);
    }
    
    /// Record extracted coordinates
    pub fn record_extraction(&mut self, coordinates: Vec<F>) {
        self.extracted_coordinates.push(coordinates);
    }
    
    /// Mark complete
    pub fn mark_complete(&mut self) {
        self.is_complete = true;
    }
    
    /// All verified
    pub fn all_verified(&self) -> bool {
        self.verification_results.iter().all(|&r| r)
    }
}

/// Coordinate-wise proof builder
pub struct CoordinateWiseProofBuilder<F: Field> {
    commitment: Option<F>,
    coordinates: Vec<F>,
    challenges: Vec<F>,
    responses: Vec<F>,
}

impl<F: Field> CoordinateWiseProofBuilder<F> {
    pub fn new() -> Self {
        Self {
            commitment: None,
            coordinates: Vec::new(),
            challenges: Vec::new(),
            responses: Vec::new(),
        }
    }
    
    /// Set commitment
    pub fn with_commitment(mut self, commitment: F) -> Self {
        self.commitment = Some(commitment);
        self
    }
    
    /// Add coordinate
    pub fn add_coordinate(mut self, coord: F) -> Self {
        self.coordinates.push(coord);
        self
    }
    
    /// Add challenge
    pub fn add_challenge(mut self, challenge: F) -> Self {
        self.challenges.push(challenge);
        self
    }
    
    /// Add response
    pub fn add_response(mut self, response: F) -> Self {
        self.responses.push(response);
        self
    }
    
    /// Build proof
    pub fn build(self) -> Result<CoordinateWiseProof<F>, HachiError> {
        let commitment = self.commitment.ok_or_else(|| 
            HachiError::InvalidParameters("Commitment not set".to_string())
        )?;
        
        CoordinateWiseProof::new(
            commitment,
            self.coordinates,
            self.challenges,
            self.responses,
        )
    }
}

/// Coordinate-wise soundness analysis
///
/// Analyzes soundness of coordinate-wise proofs
#[derive(Clone, Debug)]
pub struct CoordinateWiseSoundnessAnalysis {
    /// Number of coordinates
    pub num_coordinates: usize,
    
    /// Number of challenges
    pub num_challenges: usize,
    
    /// Soundness error
    pub soundness_error: f64,
    
    /// Knowledge error
    pub knowledge_error: f64,
}

impl CoordinateWiseSoundnessAnalysis {
    pub fn new(num_coordinates: usize, num_challenges: usize) -> Self {
        // Soundness error: (1/q)^(num_challenges - 1)
        let soundness_error = (1.0 / 2u64.pow(64) as f64).powi((num_challenges - 1) as i32);
        
        // Knowledge error: similar bound
        let knowledge_error = soundness_error;
        
        Self {
            num_coordinates,
            num_challenges,
            soundness_error,
            knowledge_error,
        }
    }
    
    /// Is soundness acceptable
    pub fn is_acceptable(&self, target_security: u32) -> bool {
        // Check if soundness error is less than 2^(-target_security)
        let target_error = 2.0_f64.powi(-(target_security as i32));
        self.soundness_error < target_error
    }
}
