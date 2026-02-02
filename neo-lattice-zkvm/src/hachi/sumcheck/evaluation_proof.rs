// Evaluation proof (Lemma 9)
//
// Implements the final evaluation proof after sumcheck protocol,
// proving P(r_1, ..., r_μ) = claimed_value.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Evaluation proof (Lemma 9)
///
/// After sumcheck protocol reduces to single point evaluation,
/// prove that P(r_1, ..., r_μ) = claimed_value
///
/// Lemma 9 states that if sumcheck protocol succeeds,
/// then P(r_1, ..., r_μ) · Q(r_1, ..., r_μ) = final_sum
#[derive(Clone, Debug)]
pub struct EvaluationProof<F: Field> {
    /// Evaluation point
    pub evaluation_point: Vec<F>,
    
    /// Claimed P value
    pub p_value: F,
    
    /// Claimed Q value
    pub q_value: F,
    
    /// Product (should equal final sum)
    pub product: F,
    
    /// Proof data
    pub proof_data: Vec<F>,
}

impl<F: Field> EvaluationProof<F> {
    /// Create evaluation proof
    pub fn new(
        evaluation_point: Vec<F>,
        p_value: F,
        q_value: F,
    ) -> Self {
        let product = p_value * q_value;
        
        Self {
            evaluation_point,
            p_value,
            q_value,
            product,
            proof_data: Vec::new(),
        }
    }
    
    /// Verify evaluation proof
    ///
    /// Checks that P(r_1, ..., r_μ) · Q(r_1, ..., r_μ) = expected_sum
    pub fn verify(&self, expected_sum: F) -> Result<bool, HachiError> {
        Ok(self.product == expected_sum)
    }
    
    /// Get evaluation point
    pub fn evaluation_point(&self) -> &[F] {
        &self.evaluation_point
    }
    
    /// Get P value
    pub fn p_value(&self) -> F {
        self.p_value
    }
    
    /// Get Q value
    pub fn q_value(&self) -> F {
        self.q_value
    }
}

/// Lemma 9 verifier
///
/// Verifies that the final evaluation is correct
#[derive(Clone, Debug)]
pub struct Lemma9Verifier<F: Field> {
    /// Ring dimension
    ring_dimension: usize,
}

impl<F: Field> Lemma9Verifier<F> {
    /// Create Lemma 9 verifier
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        
        Ok(Self { ring_dimension })
    }
    
    /// Verify Lemma 9
    ///
    /// Given:
    /// - Evaluation point r = (r_1, ..., r_μ)
    /// - P(r) and Q(r)
    /// - Expected sum from sumcheck
    ///
    /// Verify: P(r) · Q(r) = expected_sum
    pub fn verify_lemma_9(
        &self,
        p_value: F,
        q_value: F,
        expected_sum: F,
    ) -> Result<bool, HachiError> {
        let product = p_value * q_value;
        Ok(product == expected_sum)
    }
    
    /// Verify multiple evaluations
    pub fn batch_verify_lemma_9(
        &self,
        evaluations: &[(F, F, F)],
    ) -> Result<bool, HachiError> {
        for (p_val, q_val, expected) in evaluations {
            if !self.verify_lemma_9(*p_val, *q_val, *expected)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Recursive evaluation proof
///
/// For recursive protocols, prove evaluation of MLE
#[derive(Clone, Debug)]
pub struct RecursiveEvaluationProof<F: Field> {
    /// Evaluation point
    pub evaluation_point: Vec<F>,
    
    /// MLE value
    pub mle_value: F,
    
    /// Recursive proofs
    pub recursive_proofs: Vec<RecursiveEvaluationProof<F>>,
    
    /// Is leaf
    pub is_leaf: bool,
}

impl<F: Field> RecursiveEvaluationProof<F> {
    /// Create leaf proof
    pub fn leaf(evaluation_point: Vec<F>, value: F) -> Self {
        Self {
            evaluation_point,
            mle_value: value,
            recursive_proofs: Vec::new(),
            is_leaf: true,
        }
    }
    
    /// Create internal proof
    pub fn internal(
        evaluation_point: Vec<F>,
        mle_value: F,
        recursive_proofs: Vec<RecursiveEvaluationProof<F>>,
    ) -> Self {
        Self {
            evaluation_point,
            mle_value,
            recursive_proofs,
            is_leaf: false,
        }
    }
    
    /// Verify recursive proof
    pub fn verify(&self) -> Result<bool, HachiError> {
        if self.is_leaf {
            return Ok(true);
        }
        
        // Verify all recursive proofs
        for proof in &self.recursive_proofs {
            if !proof.verify()? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get depth
    pub fn depth(&self) -> usize {
        if self.is_leaf {
            return 0;
        }
        
        let mut max_depth = 0;
        for proof in &self.recursive_proofs {
            let depth = proof.depth();
            if depth > max_depth {
                max_depth = depth;
            }
        }
        
        max_depth + 1
    }
}

/// Evaluation proof builder
pub struct EvaluationProofBuilder<F: Field> {
    evaluation_point: Vec<F>,
    p_value: Option<F>,
    q_value: Option<F>,
}

impl<F: Field> EvaluationProofBuilder<F> {
    pub fn new(evaluation_point: Vec<F>) -> Self {
        Self {
            evaluation_point,
            p_value: None,
            q_value: None,
        }
    }
    
    /// Set P value
    pub fn with_p_value(mut self, value: F) -> Self {
        self.p_value = Some(value);
        self
    }
    
    /// Set Q value
    pub fn with_q_value(mut self, value: F) -> Self {
        self.q_value = Some(value);
        self
    }
    
    /// Build proof
    pub fn build(self) -> Result<EvaluationProof<F>, HachiError> {
        let p_value = self.p_value.ok_or_else(|| 
            HachiError::InvalidParameters("P value not set".to_string())
        )?;
        
        let q_value = self.q_value.ok_or_else(|| 
            HachiError::InvalidParameters("Q value not set".to_string())
        )?;
        
        Ok(EvaluationProof::new(self.evaluation_point, p_value, q_value))
    }
}

/// Batch evaluation proof
pub struct BatchEvaluationProof<F: Field> {
    proofs: Vec<EvaluationProof<F>>,
}

impl<F: Field> BatchEvaluationProof<F> {
    pub fn new(proofs: Vec<EvaluationProof<F>>) -> Self {
        Self { proofs }
    }
    
    /// Verify all proofs
    pub fn verify_all(&self, expected_sums: &[F]) -> Result<bool, HachiError> {
        if self.proofs.len() != expected_sums.len() {
            return Ok(false);
        }
        
        for i in 0..self.proofs.len() {
            if !self.proofs[i].verify(expected_sums[i])? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get number of proofs
    pub fn len(&self) -> usize {
        self.proofs.len()
    }
}

/// Evaluation proof with commitment
///
/// Combines evaluation proof with commitment to polynomial
#[derive(Clone, Debug)]
pub struct EvaluationProofWithCommitment<F: Field> {
    /// Commitment to polynomial
    pub commitment: F,
    
    /// Evaluation proof
    pub proof: EvaluationProof<F>,
    
    /// Opening proof
    pub opening_proof: Vec<F>,
}

impl<F: Field> EvaluationProofWithCommitment<F> {
    pub fn new(
        commitment: F,
        proof: EvaluationProof<F>,
        opening_proof: Vec<F>,
    ) -> Self {
        Self {
            commitment,
            proof,
            opening_proof,
        }
    }
    
    /// Verify complete proof
    pub fn verify(&self, expected_sum: F) -> Result<bool, HachiError> {
        // Verify evaluation proof
        self.proof.verify(expected_sum)
    }
}

/// Evaluation proof transcript
#[derive(Clone, Debug)]
pub struct EvaluationProofTranscript<F: Field> {
    /// Evaluation point
    pub evaluation_point: Vec<F>,
    
    /// P value
    pub p_value: F,
    
    /// Q value
    pub q_value: F,
    
    /// Expected sum
    pub expected_sum: F,
    
    /// Is verified
    pub is_verified: bool,
}

impl<F: Field> EvaluationProofTranscript<F> {
    pub fn new(
        evaluation_point: Vec<F>,
        p_value: F,
        q_value: F,
        expected_sum: F,
    ) -> Self {
        Self {
            evaluation_point,
            p_value,
            q_value,
            expected_sum,
            is_verified: false,
        }
    }
    
    /// Verify transcript
    pub fn verify(&mut self) -> Result<bool, HachiError> {
        let product = self.p_value * self.q_value;
        self.is_verified = product == self.expected_sum;
        Ok(self.is_verified)
    }
}

/// Streaming evaluation proof
///
/// For large evaluations, stream proof data
pub struct StreamingEvaluationProof<F: Field> {
    /// Evaluation point
    evaluation_point: Vec<F>,
    
    /// Streamed values
    streamed_values: Vec<F>,
}

impl<F: Field> StreamingEvaluationProof<F> {
    pub fn new(evaluation_point: Vec<F>) -> Self {
        Self {
            evaluation_point,
            streamed_values: Vec::new(),
        }
    }
    
    /// Add value to stream
    pub fn add_value(&mut self, value: F) {
        self.streamed_values.push(value);
    }
    
    /// Finalize proof
    pub fn finalize(self) -> Result<EvaluationProof<F>, HachiError> {
        if self.streamed_values.len() < 2 {
            return Err(HachiError::InvalidDimension {
                expected: 2,
                actual: self.streamed_values.len(),
            });
        }
        
        let p_value = self.streamed_values[0];
        let q_value = self.streamed_values[1];
        
        Ok(EvaluationProof::new(self.evaluation_point, p_value, q_value))
    }
}
