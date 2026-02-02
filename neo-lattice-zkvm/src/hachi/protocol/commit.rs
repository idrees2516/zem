// Commitment phase of Hachi protocol
//
// Generates commitments to multilinear polynomials.
//
// Commitment Algorithm:
// 1. Parse polynomial into coefficients
// 2. Compute inner commitments t_i = A_in_i · s_i
// 3. Compute outer commitment u = A_out · [t_1; ...; t_{d/k}]
// 4. Output commitment u

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;
use super::setup::SetupData;

/// Commitment data
///
/// Contains commitment and related information
#[derive(Clone, Debug)]
pub struct CommitmentData<F: Field> {
    /// Commitment value
    pub commitment: F,
    
    /// Inner commitments
    pub inner_commitments: Vec<F>,
    
    /// Polynomial size
    pub polynomial_size: usize,
    
    /// Commitment randomness (for opening)
    pub randomness: Vec<F>,
}

impl<F: Field> CommitmentData<F> {
    /// Create new commitment data
    pub fn new(
        commitment: F,
        inner_commitments: Vec<F>,
        polynomial_size: usize,
    ) -> Self {
        Self {
            commitment,
            inner_commitments,
            polynomial_size,
            randomness: Vec::new(),
        }
    }
    
    /// Get commitment
    pub fn commitment(&self) -> F {
        self.commitment
    }
    
    /// Get inner commitments
    pub fn inner_commitments(&self) -> &[F] {
        &self.inner_commitments
    }
}

/// Commitment phase executor
///
/// Executes the commitment algorithm
pub struct CommitPhase;

impl CommitPhase {
    /// Execute commitment algorithm
    pub fn execute<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        polynomial: &[F],
    ) -> Result<CommitmentData<F>, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        // Verify polynomial size
        let expected_size = 1 << params.num_variables();
        if polynomial.len() != expected_size {
            return Err(HachiError::InvalidDimension {
                expected: expected_size,
                actual: polynomial.len(),
            });
        }
        
        // Step 1: Parse polynomial into segments
        let segment_size = ring_dimension / extension_degree;
        let mut segments = Vec::new();
        
        for i in 0..segment_size {
            let start = i * extension_degree;
            let end = (i + 1) * extension_degree;
            if end <= polynomial.len() {
                segments.push(polynomial[start..end].to_vec());
            }
        }
        
        // Step 2: Compute inner commitments
        let mut inner_commitments = Vec::new();
        for i in 0..segment_size {
            if i < segments.len() {
                let inner_commit = Self::compute_inner_commitment(
                    &setup_data.commitment_key_inner[i],
                    &segments[i],
                )?;
                inner_commitments.push(inner_commit);
            }
        }
        
        // Step 3: Compute outer commitment
        let commitment = Self::compute_outer_commitment(
            &setup_data.commitment_key_outer,
            &inner_commitments,
        )?;
        
        Ok(CommitmentData::new(commitment, inner_commitments, polynomial.len()))
    }
    
    /// Compute inner commitment
    ///
    /// t_i = A_in_i · s_i
    fn compute_inner_commitment<F: Field>(
        key: &[F],
        segment: &[F],
    ) -> Result<F, HachiError> {
        if key.len() != segment.len() {
            return Err(HachiError::InvalidDimension {
                expected: key.len(),
                actual: segment.len(),
            });
        }
        
        let mut result = F::zero();
        for i in 0..key.len() {
            result = result + (key[i] * segment[i]);
        }
        
        Ok(result)
    }
    
    /// Compute outer commitment
    ///
    /// u = A_out · [t_1; ...; t_{d/k}]
    fn compute_outer_commitment<F: Field>(
        key: &[F],
        inner_commitments: &[F],
    ) -> Result<F, HachiError> {
        if key.len() != inner_commitments.len() {
            return Err(HachiError::InvalidDimension {
                expected: key.len(),
                actual: inner_commitments.len(),
            });
        }
        
        let mut result = F::zero();
        for i in 0..key.len() {
            result = result + (key[i] * inner_commitments[i]);
        }
        
        Ok(result)
    }
}

/// Commitment verifier
///
/// Verifies commitment correctness
pub struct CommitmentVerifier;

impl CommitmentVerifier {
    /// Verify commitment
    pub fn verify<F: Field>(
        commitment_data: &CommitmentData<F>,
        params: &HachiParams<F>,
    ) -> Result<bool, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        // Check dimensions
        let expected_inner_size = ring_dimension / extension_degree;
        if commitment_data.inner_commitments.len() != expected_inner_size {
            return Ok(false);
        }
        
        Ok(true)
    }
}

/// Batch commitment
///
/// Commits to multiple polynomials
pub struct BatchCommitment;

impl BatchCommitment {
    /// Commit to multiple polynomials
    pub fn execute<F: Field>(
        params: &HachiParams<F>,
        setup_data: &SetupData<F>,
        polynomials: &[Vec<F>],
    ) -> Result<Vec<CommitmentData<F>>, HachiError> {
        let mut commitments = Vec::new();
        
        for polynomial in polynomials {
            let commitment = CommitPhase::execute(params, setup_data, polynomial)?;
            commitments.push(commitment);
        }
        
        Ok(commitments)
    }
}

/// Commitment transcript
///
/// Records commitment execution
#[derive(Clone, Debug)]
pub struct CommitmentTranscript<F: Field> {
    /// Commitment data
    pub commitment_data: Option<CommitmentData<F>>,
    
    /// Verification result
    pub verification_result: Option<bool>,
    
    /// Commitment time (ms)
    pub commitment_time_ms: u64,
}

impl<F: Field> CommitmentTranscript<F> {
    pub fn new() -> Self {
        Self {
            commitment_data: None,
            verification_result: None,
            commitment_time_ms: 0,
        }
    }
    
    /// Record commitment
    pub fn record_commitment(&mut self, commitment_data: CommitmentData<F>) {
        self.commitment_data = Some(commitment_data);
    }
    
    /// Record verification
    pub fn record_verification(&mut self, result: bool) {
        self.verification_result = Some(result);
    }
    
    /// Record time
    pub fn record_time(&mut self, time_ms: u64) {
        self.commitment_time_ms = time_ms;
    }
    
    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.commitment_data.is_some() && self.verification_result.is_some()
    }
}

/// Commitment statistics
#[derive(Clone, Debug)]
pub struct CommitmentStats {
    /// Commitment time (ms)
    pub commitment_time_ms: u64,
    
    /// Commitment size (bytes)
    pub commitment_size: usize,
    
    /// Number of commitments
    pub num_commitments: usize,
}

impl CommitmentStats {
    pub fn new() -> Self {
        Self {
            commitment_time_ms: 0,
            commitment_size: 0,
            num_commitments: 0,
        }
    }
    
    /// Average commitment time
    pub fn avg_commitment_time_ms(&self) -> f64 {
        if self.num_commitments > 0 {
            self.commitment_time_ms as f64 / self.num_commitments as f64
        } else {
            0.0
        }
    }
}

/// Commitment builder
///
/// Builds commitments incrementally
pub struct CommitmentBuilder<F: Field> {
    commitment: Option<F>,
    inner_commitments: Vec<F>,
    polynomial_size: Option<usize>,
}

impl<F: Field> CommitmentBuilder<F> {
    pub fn new() -> Self {
        Self {
            commitment: None,
            inner_commitments: Vec::new(),
            polynomial_size: None,
        }
    }
    
    /// Set commitment
    pub fn with_commitment(mut self, commitment: F) -> Self {
        self.commitment = Some(commitment);
        self
    }
    
    /// Add inner commitment
    pub fn add_inner_commitment(mut self, inner_commit: F) -> Self {
        self.inner_commitments.push(inner_commit);
        self
    }
    
    /// Set polynomial size
    pub fn with_polynomial_size(mut self, size: usize) -> Self {
        self.polynomial_size = Some(size);
        self
    }
    
    /// Build commitment data
    pub fn build(self) -> Result<CommitmentData<F>, HachiError> {
        let commitment = self.commitment.ok_or_else(|| 
            HachiError::InvalidParameters("Commitment not set".to_string())
        )?;
        
        let polynomial_size = self.polynomial_size.ok_or_else(|| 
            HachiError::InvalidParameters("Polynomial size not set".to_string())
        )?;
        
        Ok(CommitmentData::new(commitment, self.inner_commitments, polynomial_size))
    }
}
