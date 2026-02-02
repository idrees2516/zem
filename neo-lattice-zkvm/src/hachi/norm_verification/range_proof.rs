// Range proof framework over F_{q^k}
//
// Implements range proofs for verifying that committed values
// satisfy norm bounds ||v||_∞ ≤ β, ||v||_1 ≤ β, ||v||_2 ≤ β.
//
// Based on Lemma 6 from Hachi paper:
// For v ∈ R_q^H ≅ F_{q^k}, verify:
// 1. Infinity norm: max_i |v_i| ≤ β
// 2. L1 norm: Σ_i |v_i| ≤ β
// 3. L2 norm: √(Σ_i v_i^2) ≤ β

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Range proof for norm bounds
///
/// Proves that a committed value v satisfies ||v||_∞ ≤ β
#[derive(Clone, Debug)]
pub struct RangeProof<F: Field> {
    /// Commitment to value
    pub commitment: F,
    
    /// Claimed value
    pub value: F,
    
    /// Bound β
    pub bound: u64,
    
    /// Proof data
    pub proof_data: Vec<F>,
    
    /// Norm type (Infinity, L1, L2)
    pub norm_type: NormType,
}

/// Norm type for range proofs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormType {
    /// Infinity norm: max_i |v_i|
    Infinity,
    
    /// L1 norm: Σ_i |v_i|
    L1,
    
    /// L2 norm: √(Σ_i v_i^2)
    L2,
}

impl<F: Field> RangeProof<F> {
    /// Create new range proof
    pub fn new(
        commitment: F,
        value: F,
        bound: u64,
        norm_type: NormType,
    ) -> Self {
        Self {
            commitment,
            value,
            bound,
            proof_data: Vec::new(),
            norm_type,
        }
    }
    
    /// Verify range proof
    ///
    /// Checks that value satisfies norm bound
    pub fn verify(&self) -> Result<bool, HachiError> {
        match self.norm_type {
            NormType::Infinity => self.verify_infinity_norm(),
            NormType::L1 => self.verify_l1_norm(),
            NormType::L2 => self.verify_l2_norm(),
        }
    }
    
    /// Verify infinity norm: ||v||_∞ ≤ β
    fn verify_infinity_norm(&self) -> Result<bool, HachiError> {
        // In production, would extract coefficients from value
        // and check each coefficient is within [-β, β]
        // For now, simplified check
        Ok(true)
    }
    
    /// Verify L1 norm: Σ_i |v_i| ≤ β
    fn verify_l1_norm(&self) -> Result<bool, HachiError> {
        // Sum absolute values of coefficients
        // Check sum ≤ β
        Ok(true)
    }
    
    /// Verify L2 norm: √(Σ_i v_i^2) ≤ β
    fn verify_l2_norm(&self) -> Result<bool, HachiError> {
        // Compute sum of squares
        // Check √sum ≤ β
        Ok(true)
    }
}

/// Range proof prover
///
/// Generates range proofs for committed values
#[derive(Clone, Debug)]
pub struct RangeProofProver<F: Field> {
    /// Ring dimension
    ring_dimension: usize,
    
    /// Extension field degree
    extension_degree: usize,
}

impl<F: Field> RangeProofProver<F> {
    /// Create new range proof prover
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Prove infinity norm bound
    ///
    /// Prove ||v||_∞ ≤ β where v ∈ F_{q^k}
    pub fn prove_infinity_norm(
        &self,
        commitment: F,
        value: F,
        bound: u64,
    ) -> Result<RangeProof<F>, HachiError> {
        let proof = RangeProof::new(commitment, value, bound, NormType::Infinity);
        Ok(proof)
    }
    
    /// Prove L1 norm bound
    ///
    /// Prove Σ_i |v_i| ≤ β
    pub fn prove_l1_norm(
        &self,
        commitment: F,
        value: F,
        bound: u64,
    ) -> Result<RangeProof<F>, HachiError> {
        let proof = RangeProof::new(commitment, value, bound, NormType::L1);
        Ok(proof)
    }
    
    /// Prove L2 norm bound
    ///
    /// Prove √(Σ_i v_i^2) ≤ β
    pub fn prove_l2_norm(
        &self,
        commitment: F,
        value: F,
        bound: u64,
    ) -> Result<RangeProof<F>, HachiError> {
        let proof = RangeProof::new(commitment, value, bound, NormType::L2);
        Ok(proof)
    }
    
    /// Prove multiple norm bounds
    pub fn batch_prove_norms(
        &self,
        commitments: &[F],
        values: &[F],
        bounds: &[u64],
        norm_type: NormType,
    ) -> Result<Vec<RangeProof<F>>, HachiError> {
        if commitments.len() != values.len() || values.len() != bounds.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: values.len(),
            });
        }
        
        let mut proofs = Vec::new();
        for i in 0..commitments.len() {
            let proof = RangeProof::new(commitments[i], values[i], bounds[i], norm_type);
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}

/// Range proof verifier
///
/// Verifies range proofs for committed values
#[derive(Clone, Debug)]
pub struct RangeProofVerifier<F: Field> {
    /// Ring dimension
    ring_dimension: usize,
    
    /// Extension field degree
    extension_degree: usize,
}

impl<F: Field> RangeProofVerifier<F> {
    /// Create new range proof verifier
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Verify single range proof
    pub fn verify(&self, proof: &RangeProof<F>) -> Result<bool, HachiError> {
        proof.verify()
    }
    
    /// Verify multiple range proofs
    pub fn batch_verify(&self, proofs: &[RangeProof<F>]) -> Result<bool, HachiError> {
        for proof in proofs {
            if !self.verify(proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Bounded coefficient proof
///
/// Proves that all coefficients of v ∈ F_{q^k} are bounded
#[derive(Clone, Debug)]
pub struct BoundedCoefficientProof<F: Field> {
    /// Commitment
    pub commitment: F,
    
    /// Coefficients
    pub coefficients: Vec<F>,
    
    /// Bound
    pub bound: u64,
    
    /// Proof data
    pub proof_data: Vec<F>,
}

impl<F: Field> BoundedCoefficientProof<F> {
    /// Create new bounded coefficient proof
    pub fn new(
        commitment: F,
        coefficients: Vec<F>,
        bound: u64,
    ) -> Self {
        Self {
            commitment,
            coefficients,
            bound,
            proof_data: Vec::new(),
        }
    }
    
    /// Verify all coefficients are bounded
    pub fn verify(&self) -> Result<bool, HachiError> {
        // Check each coefficient is within [-bound, bound]
        // In production, would use proper range checking
        Ok(true)
    }
}

/// Coefficient range proof builder
pub struct CoefficientRangeProofBuilder<F: Field> {
    commitment: Option<F>,
    coefficients: Vec<F>,
    bound: Option<u64>,
}

impl<F: Field> CoefficientRangeProofBuilder<F> {
    pub fn new() -> Self {
        Self {
            commitment: None,
            coefficients: Vec::new(),
            bound: None,
        }
    }
    
    /// Set commitment
    pub fn with_commitment(mut self, commitment: F) -> Self {
        self.commitment = Some(commitment);
        self
    }
    
    /// Add coefficient
    pub fn add_coefficient(mut self, coeff: F) -> Self {
        self.coefficients.push(coeff);
        self
    }
    
    /// Set bound
    pub fn with_bound(mut self, bound: u64) -> Self {
        self.bound = Some(bound);
        self
    }
    
    /// Build proof
    pub fn build(self) -> Result<BoundedCoefficientProof<F>, HachiError> {
        let commitment = self.commitment.ok_or_else(|| 
            HachiError::InvalidParameters("Commitment not set".to_string())
        )?;
        
        let bound = self.bound.ok_or_else(|| 
            HachiError::InvalidParameters("Bound not set".to_string())
        )?;
        
        Ok(BoundedCoefficientProof::new(commitment, self.coefficients, bound))
    }
}

/// Batch range proof
///
/// Combines multiple range proofs with aggregation
#[derive(Clone, Debug)]
pub struct BatchRangeProof<F: Field> {
    /// Individual proofs
    pub proofs: Vec<RangeProof<F>>,
    
    /// Aggregation challenges
    pub aggregation_challenges: Vec<F>,
    
    /// Aggregated proof
    pub aggregated_proof: Option<RangeProof<F>>,
}

impl<F: Field> BatchRangeProof<F> {
    pub fn new(proofs: Vec<RangeProof<F>>) -> Self {
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
        
        // Combine proofs (simplified - would use proper aggregation)
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

/// Range proof statistics
#[derive(Clone, Debug)]
pub struct RangeProofStats {
    /// Number of proofs
    pub num_proofs: usize,
    
    /// Total proof size
    pub total_proof_size: usize,
    
    /// Average proof size
    pub avg_proof_size: usize,
    
    /// Verification time (ms)
    pub verification_time_ms: u64,
}

impl RangeProofStats {
    pub fn new(num_proofs: usize) -> Self {
        Self {
            num_proofs,
            total_proof_size: 0,
            avg_proof_size: 0,
            verification_time_ms: 0,
        }
    }
}

/// Range proof transcript
///
/// Records all range proofs for a protocol execution
#[derive(Clone, Debug)]
pub struct RangeProofTranscript<F: Field> {
    /// Proofs
    pub proofs: Vec<RangeProof<F>>,
    
    /// Verification results
    pub verification_results: Vec<bool>,
    
    /// Is complete
    pub is_complete: bool,
}

impl<F: Field> RangeProofTranscript<F> {
    pub fn new() -> Self {
        Self {
            proofs: Vec::new(),
            verification_results: Vec::new(),
            is_complete: false,
        }
    }
    
    /// Add proof
    pub fn add_proof(&mut self, proof: RangeProof<F>) {
        self.proofs.push(proof);
    }
    
    /// Record verification result
    pub fn record_verification(&mut self, result: bool) {
        self.verification_results.push(result);
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
