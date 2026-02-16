// Verification phase of Hachi protocol
//
// Verifies evaluation proofs for multilinear polynomial commitments.
//
// Verification Algorithm:
// 1. Verify ring switching proof
// 2. Verify sumcheck proof
// 3. Verify norm verification proof
// 4. Check consistency

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;
use super::setup::SetupData;
use super::commit::CommitmentData;
use super::prove::EvaluationProof;

/// Verification result
///
/// Result of proof verification
#[derive(Clone, Debug)]
pub struct VerificationResult {
    /// Is valid
    pub is_valid: bool,
    
    /// Verification time (ms)
    pub verification_time_ms: u64,
    
    /// Error message if invalid
    pub error: Option<String>,
}

impl VerificationResult {
    /// Create success result
    pub fn success(verification_time_ms: u64) -> Self {
        Self {
            is_valid: true,
            verification_time_ms,
            error: None,
        }
    }
    
    /// Create failure result
    pub fn failure(error: String, verification_time_ms: u64) -> Self {
        Self {
            is_valid: false,
            verification_time_ms,
            error: Some(error),
        }
    }
}

/// Verify phase executor
///
/// Executes the verification algorithm
pub struct VerifyPhase;

impl VerifyPhase {
    /// Execute verification algorithm
    pub fn execute<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        claimed_value: F,
        proof: &EvaluationProof<F>,
    ) -> Result<bool, HachiError> {
        // Verify evaluation point dimension
        if evaluation_point.len() != params.num_variables() {
            return Err(HachiError::InvalidDimension {
                expected: params.num_variables(),
                actual: evaluation_point.len(),
            });
        }
        
        // Step 1: Verify ring switching proof
        let ring_switching_valid = Self::verify_ring_switching_proof(
            params,
            setup_data,
            commitment,
            evaluation_point,
            &proof.ring_switching_proof,
        )?;
        
        if !ring_switching_valid {
            return Ok(false);
        }
        
        // Step 2: Verify sumcheck proof
        let sumcheck_valid = Self::verify_sumcheck_proof(
            params,
            setup_data,
            commitment,
            evaluation_point,
            claimed_value,
            &proof.sumcheck_proof,
        )?;
        
        if !sumcheck_valid {
            return Ok(false);
        }
        
        // Step 3: Verify norm verification proof
        let norm_valid = Self::verify_norm_verification_proof(
            params,
            setup_data,
            &proof.norm_verification_proof,
        )?;
        
        if !norm_valid {
            return Ok(false);
        }
        
        // Step 4: Check consistency
        let consistent = Self::check_consistency(
            params,
            commitment,
            evaluation_point,
            claimed_value,
            proof,
        )?;
        
        Ok(consistent)
    }
    
    /// Verify ring switching proof
    fn verify_ring_switching_proof<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        proof: &[F],
    ) -> Result<bool, HachiError> {
        // In production, would verify ring switching protocol
        // For now, accept all proofs
        Ok(true)
    }
    
    /// Verify sumcheck proof
    fn verify_sumcheck_proof<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        claimed_value: F,
        proof: &[F],
    ) -> Result<bool, HachiError> {
        // In production, would verify sumcheck protocol
        // For now, accept all proofs
        Ok(true)
    }
    
    /// Verify norm verification proof
    fn verify_norm_verification_proof<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        proof: &[F],
    ) -> Result<bool, HachiError> {
        // In production, would verify norm bounds
        // For now, accept all proofs
        Ok(true)
    }
    
    /// Check consistency
    fn check_consistency<F: Field>(
        params: &HachiParams<F>,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        claimed_value: F,
        proof: &EvaluationProof<F>,
    ) -> Result<bool, HachiError> {
        // Verify that final evaluation matches claimed value
        Ok(proof.final_evaluation == claimed_value)
    }
}

/// Batch verification
///
/// Verifies multiple proofs
pub struct BatchVerifyPhase;

impl BatchVerifyPhase {
    /// Verify multiple proofs
    pub fn execute<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        commitments: &[CommitmentData<F>],
        evaluation_points: &[Vec<F>],
        claimed_values: &[F],
        proofs: &[EvaluationProof<F>],
    ) -> Result<bool, HachiError> {
        if commitments.len() != evaluation_points.len() ||
           evaluation_points.len() != claimed_values.len() ||
           claimed_values.len() != proofs.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: evaluation_points.len(),
            });
        }
        
        for i in 0..commitments.len() {
            let valid = VerifyPhase::execute(
                params,
                setup_data,
                &commitments[i],
                &evaluation_points[i],
                claimed_values[i],
                &proofs[i],
            )?;
            
            if !valid {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// Verification transcript
///
/// Records verification execution
#[derive(Clone, Debug)]
pub struct VerificationTranscript<F: Field> {
    /// Commitment
    pub commitment: Option<CommitmentData<F>>,
    
    /// Evaluation point
    pub evaluation_point: Option<Vec<F>>,
    
    /// Claimed value
    pub claimed_value: Option<F>,
    
    /// Proof
    pub proof: Option<EvaluationProof<F>>,
    
    /// Verification result
    pub result: Option<bool>,
    
    /// Verification time (ms)
    pub verification_time_ms: u64,
}

impl<F: Field> VerificationTranscript<F> {
    pub fn new() -> Self {
        Self {
            commitment: None,
            evaluation_point: None,
            claimed_value: None,
            proof: None,
            result: None,
            verification_time_ms: 0,
        }
    }
    
    /// Record commitment
    pub fn record_commitment(&mut self, commitment: CommitmentData<F>) {
        self.commitment = Some(commitment);
    }
    
    /// Record evaluation point
    pub fn record_evaluation_point(&mut self, point: Vec<F>) {
        self.evaluation_point = Some(point);
    }
    
    /// Record claimed value
    pub fn record_claimed_value(&mut self, value: F) {
        self.claimed_value = Some(value);
    }
    
    /// Record proof
    pub fn record_proof(&mut self, proof: EvaluationProof<F>) {
        self.proof = Some(proof);
    }
    
    /// Record result
    pub fn record_result(&mut self, result: bool) {
        self.result = Some(result);
    }
    
    /// Record time
    pub fn record_time(&mut self, time_ms: u64) {
        self.verification_time_ms = time_ms;
    }
    
    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.commitment.is_some() &&
        self.evaluation_point.is_some() &&
        self.claimed_value.is_some() &&
        self.proof.is_some() &&
        self.result.is_some()
    }
}

/// Verification statistics
#[derive(Clone, Debug)]
pub struct VerificationStats {
    /// Verification time (ms)
    pub verification_time_ms: u64,
    
    /// Number of verifications
    pub num_verifications: usize,
    
    /// Number of valid proofs
    pub num_valid: usize,
    
    /// Number of invalid proofs
    pub num_invalid: usize,
}

impl VerificationStats {
    pub fn new() -> Self {
        Self {
            verification_time_ms: 0,
            num_verifications: 0,
            num_valid: 0,
            num_invalid: 0,
        }
    }
    
    /// Average verification time
    pub fn avg_verification_time_ms(&self) -> f64 {
        if self.num_verifications > 0 {
            self.verification_time_ms as f64 / self.num_verifications as f64
        } else {
            0.0
        }
    }
    
    /// Validity rate
    pub fn validity_rate(&self) -> f64 {
        if self.num_verifications > 0 {
            self.num_valid as f64 / self.num_verifications as f64
        } else {
            0.0
        }
    }
}

/// Verification cache
///
/// Caches verification results
pub struct VerificationCache<F: Field> {
    /// Cached results
    cache: Vec<(CommitmentData<F>, Vec<F>, F, bool)>,
    
    /// Cache size limit
    max_size: usize,
}

impl<F: Field> VerificationCache<F> {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Vec::new(),
            max_size,
        }
    }
    
    /// Look up cached result
    pub fn lookup(
        &self,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        claimed_value: F,
    ) -> Option<bool> {
        for (cached_commit, cached_point, cached_value, result) in &self.cache {
            if cached_commit.commitment() == commitment.commitment() &&
               cached_point == evaluation_point &&
               *cached_value == claimed_value {
                return Some(*result);
            }
        }
        None
    }
    
    /// Cache result
    pub fn cache(
        &mut self,
        commitment: CommitmentData<F>,
        evaluation_point: Vec<F>,
        claimed_value: F,
        result: bool,
    ) {
        if self.cache.len() >= self.max_size {
            self.cache.remove(0);
        }
        self.cache.push((commitment, evaluation_point, claimed_value, result));
    }
}
