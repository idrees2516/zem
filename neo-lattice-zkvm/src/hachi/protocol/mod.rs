// Complete Hachi protocol implementation
//
// Implements the full Hachi polynomial commitment scheme,
// combining all layers (primitives, embedding, commitment, ring switching,
// sumcheck, norm verification) into a complete protocol.
//
// Protocol phases:
// 1. Setup: Generate public parameters
// 2. Commit: Commit to multilinear polynomial
// 3. Prove: Generate evaluation proof
// 4. Verify: Verify evaluation proof

pub mod setup;
pub mod commit;
pub mod prove;
pub mod verify;
pub mod recursive;

pub use setup::*;
pub use commit::*;
pub use prove::*;
pub use verify::*;
pub use recursive::*;

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Hachi Polynomial Commitment Scheme
///
/// Complete implementation of Hachi PCS with all protocol phases
#[derive(Clone, Debug)]
pub struct HachiPCS<F: Field> {
    /// Public parameters
    pub params: HachiParams<F>,
    
    /// Setup data
    pub setup_data: Option<SetupData<F>>,
}

impl<F: Field> HachiPCS<F> {
    /// Create new Hachi PCS
    pub fn new(params: HachiParams<F>) -> Self {
        Self {
            params,
            setup_data: None,
        }
    }
    
    /// Setup phase
    pub fn setup(&mut self) -> Result<(), HachiError> {
        let setup_data = SetupPhase::execute(&self.params)?;
        self.setup_data = Some(setup_data);
        Ok(())
    }
    
    /// Get prover
    pub fn prover(&self) -> Result<HachiProver<F>, HachiError> {
        let setup_data = self.setup_data.as_ref().ok_or_else(|| 
            HachiError::InvalidParameters("Setup not executed".to_string())
        )?;
        
        Ok(HachiProver::new(self.params.clone(), setup_data.clone()))
    }
    
    /// Get verifier
    pub fn verifier(&self) -> Result<HachiVerifier<F>, HachiError> {
        let setup_data = self.setup_data.as_ref().ok_or_else(|| 
            HachiError::InvalidParameters("Setup not executed".to_string())
        )?;
        
        Ok(HachiVerifier::new(self.params.clone(), setup_data.clone()))
    }
}

/// Hachi Prover
///
/// Generates commitments and evaluation proofs
#[derive(Clone, Debug)]
pub struct HachiProver<F: Field> {
    /// Parameters
    params: HachiParams<F>,
    
    /// Setup data
    setup_data: SetupData<F>,
}

impl<F: Field> HachiProver<F> {
    /// Create new prover
    pub fn new(params: HachiParams<F>, setup_data: SetupData<F>) -> Self {
        Self { params, setup_data }
    }
    
    /// Commit to polynomial
    pub fn commit(&self, polynomial: &[F]) -> Result<CommitmentData<F>, HachiError> {
        CommitPhase::execute(&self.params, &self.setup_data, polynomial)
    }
    
    /// Generate evaluation proof
    pub fn prove(
        &self,
        polynomial: &[F],
        evaluation_point: &[F],
        claimed_value: F,
    ) -> Result<EvaluationProof<F>, HachiError> {
        ProvePhase::execute(
            &self.params,
            &self.setup_data,
            polynomial,
            evaluation_point,
            claimed_value,
        )
    }
}

/// Hachi Verifier
///
/// Verifies commitments and evaluation proofs
#[derive(Clone, Debug)]
pub struct HachiVerifier<F: Field> {
    /// Parameters
    params: HachiParams<F>,
    
    /// Setup data
    setup_data: SetupData<F>,
}

impl<F: Field> HachiVerifier<F> {
    /// Create new verifier
    pub fn new(params: HachiParams<F>, setup_data: SetupData<F>) -> Self {
        Self { params, setup_data }
    }
    
    /// Verify evaluation proof
    pub fn verify(
        &self,
        commitment: &CommitmentData<F>,
        evaluation_point: &[F],
        claimed_value: F,
        proof: &EvaluationProof<F>,
    ) -> Result<bool, HachiError> {
        VerifyPhase::execute(
            &self.params,
            &self.setup_data,
            commitment,
            evaluation_point,
            claimed_value,
            proof,
        )
    }
}

/// Protocol transcript
///
/// Records all protocol messages for verification
#[derive(Clone, Debug)]
pub struct ProtocolTranscript<F: Field> {
    /// Commitment
    pub commitment: Option<CommitmentData<F>>,
    
    /// Evaluation point
    pub evaluation_point: Option<Vec<F>>,
    
    /// Claimed value
    pub claimed_value: Option<F>,
    
    /// Proof
    pub proof: Option<EvaluationProof<F>>,
    
    /// Verification result
    pub verification_result: Option<bool>,
}

impl<F: Field> ProtocolTranscript<F> {
    pub fn new() -> Self {
        Self {
            commitment: None,
            evaluation_point: None,
            claimed_value: None,
            proof: None,
            verification_result: None,
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
    
    /// Record verification result
    pub fn record_verification(&mut self, result: bool) {
        self.verification_result = Some(result);
    }
    
    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.commitment.is_some() &&
        self.evaluation_point.is_some() &&
        self.claimed_value.is_some() &&
        self.proof.is_some() &&
        self.verification_result.is_some()
    }
}

/// Protocol statistics
///
/// Collects statistics about protocol execution
#[derive(Clone, Debug)]
pub struct ProtocolStats {
    /// Setup time (ms)
    pub setup_time_ms: u64,
    
    /// Commitment time (ms)
    pub commitment_time_ms: u64,
    
    /// Proof generation time (ms)
    pub proof_time_ms: u64,
    
    /// Verification time (ms)
    pub verification_time_ms: u64,
    
    /// Commitment size (bytes)
    pub commitment_size: usize,
    
    /// Proof size (bytes)
    pub proof_size: usize,
}

impl ProtocolStats {
    pub fn new() -> Self {
        Self {
            setup_time_ms: 0,
            commitment_time_ms: 0,
            proof_time_ms: 0,
            verification_time_ms: 0,
            commitment_size: 0,
            proof_size: 0,
        }
    }
    
    /// Total time
    pub fn total_time_ms(&self) -> u64 {
        self.setup_time_ms + self.commitment_time_ms + 
        self.proof_time_ms + self.verification_time_ms
    }
    
    /// Total size
    pub fn total_size(&self) -> usize {
        self.commitment_size + self.proof_size
    }
}
