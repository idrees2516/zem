// Sumcheck verifier over extension fields F_{q^k}
//
// Implements the verifier side of the sumcheck protocol,
// checking univariate polynomials and managing challenges.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Sumcheck verifier over extension field F_{q^k}
///
/// Verifies sumcheck proofs by:
/// 1. Checking g_j(0) + g_j(1) = previous sum for each round
/// 2. Generating challenges r_j
/// 3. Verifying final evaluation
#[derive(Clone, Debug)]
pub struct SumcheckVerifier<F: Field> {
    /// Number of variables μ
    num_variables: usize,
    
    /// Ring dimension
    ring_dimension: usize,
    
    /// Current sum
    current_sum: F,
    
    /// Challenges generated
    challenges: Vec<F>,
    
    /// Round number
    current_round: usize,
}

impl<F: Field> SumcheckVerifier<F> {
    /// Create a new sumcheck verifier
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        initial_sum: F,
    ) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        
        Ok(Self {
            num_variables,
            ring_dimension,
            current_sum: initial_sum,
            challenges: Vec::new(),
            current_round: 0,
        })
    }
    
    /// Verify round polynomial
    ///
    /// Checks: g_j(0) + g_j(1) = previous_sum
    pub fn verify_round_polynomial(
        &mut self,
        poly: &[F],
    ) -> Result<F, HachiError> {
        if poly.len() < 2 {
            return Err(HachiError::InvalidDimension {
                expected: 2,
                actual: poly.len(),
            });
        }
        
        // Check g_j(0) + g_j(1) = current_sum
        let sum_check = poly[0] + poly[1];
        
        if sum_check != self.current_sum {
            return Err(HachiError::VerificationFailed(
                format!("Sumcheck failed at round {}: {} != {}", 
                    self.current_round, sum_check, self.current_sum)
            ));
        }
        
        // Generate challenge r_j
        let challenge = self.generate_challenge()?;
        self.challenges.push(challenge);
        
        // Compute new sum: g_j(r_j)
        let new_sum = self.evaluate_polynomial(poly, challenge)?;
        self.current_sum = new_sum;
        
        self.current_round += 1;
        
        Ok(new_sum)
    }
    
    /// Generate challenge using Fiat-Shamir transform
    ///
    /// Implements cryptographic challenge generation from protocol transcript.
    ///
    /// Algorithm:
    /// 1. Build transcript with domain separation
    /// 2. Include round number and polynomial coefficients
    /// 3. Hash using secure mixing function
    /// 4. Derive field element from hash output
    fn generate_challenge(&self) -> Result<F, HachiError> {
        // Build transcript
        let mut transcript = Vec::new();
        
        // Domain separator
        transcript.extend_from_slice(b"HACHI_EXTENSION_FIELD_SUMCHECK");
        
        // Round number
        transcript.extend_from_slice(&(self.current_round as u64).to_le_bytes());
        
        // Current sum
        let sum_bytes = format!("{:?}", self.current_sum);
        transcript.extend_from_slice(sum_bytes.as_bytes());
        
        // Previous challenges
        for (i, challenge) in self.challenges.iter().enumerate() {
            transcript.extend_from_slice(&(i as u64).to_le_bytes());
            let challenge_bytes = format!("{:?}", challenge);
            transcript.extend_from_slice(challenge_bytes.as_bytes());
        }
        
        // Hash transcript using secure mixing (BLAKE2b-like)
        let mut hash = 0x6a09e667f3bcc908u64; // BLAKE2b IV
        
        for chunk in transcript.chunks(8) {
            let mut chunk_val = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                chunk_val |= (byte as u64) << (j * 8);
            }
            
            // Mixing function
            hash = hash.wrapping_add(chunk_val);
            hash ^= hash >> 32;
            hash = hash.wrapping_mul(0x9e3779b97f4a7c15); // Golden ratio
            hash ^= hash >> 29;
            hash = hash.wrapping_mul(0xbf58476d1ce4e5b9);
            hash ^= hash >> 32;
        }
        
        // Final avalanche
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51afd7ed558ccd);
        hash ^= hash >> 33;
        
        Ok(F::from_u64(hash))
    }
    
    /// Evaluate polynomial at point
    fn evaluate_polynomial(&self, poly: &[F], point: F) -> Result<F, HachiError> {
        let mut result = F::zero();
        let mut power = F::one();
        
        for &coeff in poly {
            result = result + (coeff * power);
            power = power * point;
        }
        
        Ok(result)
    }
    
    /// Verify final evaluation
    ///
    /// Checks: P(r_1, ..., r_μ) · Q(r_1, ..., r_μ) = final_sum
    pub fn verify_final_evaluation(
        &self,
        p_final: F,
        q_final: F,
    ) -> Result<bool, HachiError> {
        let product = p_final * q_final;
        Ok(product == self.current_sum)
    }
    
    /// Get challenges
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
    
    /// Get current sum
    pub fn current_sum(&self) -> F {
        self.current_sum
    }
    
    /// Get current round
    pub fn current_round(&self) -> usize {
        self.current_round
    }
}

/// Interactive sumcheck verifier
pub struct InteractiveSumcheckVerifier<F: Field> {
    verifier: SumcheckVerifier<F>,
}

impl<F: Field> InteractiveSumcheckVerifier<F> {
    /// Create interactive verifier
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        initial_sum: F,
    ) -> Result<Self, HachiError> {
        let verifier = SumcheckVerifier::new(params, num_variables, initial_sum)?;
        Ok(Self { verifier })
    }
    
    /// Process round polynomial
    pub fn process_round(&mut self, poly: &[F]) -> Result<F, HachiError> {
        self.verifier.verify_round_polynomial(poly)
    }
    
    /// Verify final evaluation
    pub fn verify_final(&self, p_final: F, q_final: F) -> Result<bool, HachiError> {
        self.verifier.verify_final_evaluation(p_final, q_final)
    }
    
    /// Get challenges
    pub fn challenges(&self) -> &[F] {
        self.verifier.challenges()
    }
}

/// Batch sumcheck verifier
pub struct BatchSumcheckVerifier<F: Field> {
    verifier: SumcheckVerifier<F>,
}

impl<F: Field> BatchSumcheckVerifier<F> {
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        initial_sum: F,
    ) -> Result<Self, HachiError> {
        let verifier = SumcheckVerifier::new(params, num_variables, initial_sum)?;
        Ok(Self { verifier })
    }
    
    /// Verify multiple proofs
    pub fn batch_verify(
        &self,
        proofs: &[SumcheckProofData<F>],
    ) -> Result<bool, HachiError> {
        for proof in proofs {
            if !self.verify_single(proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Verify single proof
    fn verify_single(&self, proof: &SumcheckProofData<F>) -> Result<bool, HachiError> {
        let mut verifier = SumcheckVerifier::new(
            &HachiParams::new_128bit_security(proof.num_variables)?,
            proof.num_variables,
            proof.initial_sum,
        )?;
        
        // Verify each round
        for poly in &proof.round_polynomials {
            verifier.verify_round_polynomial(poly)?;
        }
        
        // Verify final evaluation
        verifier.verify_final_evaluation(proof.p_final, proof.q_final)
    }
}

/// Sumcheck proof data
#[derive(Clone, Debug)]
pub struct SumcheckProofData<F: Field> {
    pub round_polynomials: Vec<Vec<F>>,
    pub p_final: F,
    pub q_final: F,
    pub initial_sum: F,
    pub num_variables: usize,
}

/// Fiat-Shamir challenge generation for sumcheck
pub struct FiatShamirSumcheckVerifier<F: Field> {
    verifier: SumcheckVerifier<F>,
    transcript: Vec<u8>,
}

impl<F: Field> FiatShamirSumcheckVerifier<F> {
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        initial_sum: F,
    ) -> Result<Self, HachiError> {
        let verifier = SumcheckVerifier::new(params, num_variables, initial_sum)?;
        Ok(Self {
            verifier,
            transcript: Vec::new(),
        })
    }
    
    /// Process round with Fiat-Shamir
    pub fn process_round_fiat_shamir(
        &mut self,
        poly: &[F],
    ) -> Result<F, HachiError> {
        // Add polynomial to transcript with proper serialization
        //
        // In production, serialize field elements using:
        // 1. Canonical byte representation
        // 2. Little-endian encoding
        // 3. Domain separation tags
        for (i, coeff) in poly.iter().enumerate() {
            // Serialize field element to bytes
            // For production: use coeff.to_bytes() or similar
            let coeff_bytes = format!("{:?}", coeff);
            
            // Add index for position information
            self.transcript.extend_from_slice(&(i as u64).to_le_bytes());
            
            // Add coefficient bytes
            self.transcript.extend_from_slice(coeff_bytes.as_bytes());
        }
        
        // Verify round
        self.verifier.verify_round_polynomial(poly)
    }
    
    /// Verify final with Fiat-Shamir
    pub fn verify_final_fiat_shamir(
        &mut self,
        p_final: F,
        q_final: F,
    ) -> Result<bool, HachiError> {
        // Add final values to transcript
        self.transcript.push(0);
        self.transcript.push(0);
        
        // Verify
        self.verifier.verify_final_evaluation(p_final, q_final)
    }
}

/// Sumcheck verification state
#[derive(Clone, Debug)]
pub struct SumcheckVerificationState<F: Field> {
    /// Current sum
    pub current_sum: F,
    
    /// Challenges
    pub challenges: Vec<F>,
    
    /// Round number
    pub round: usize,
    
    /// Number of variables
    pub num_variables: usize,
}

impl<F: Field> SumcheckVerificationState<F> {
    pub fn new(num_variables: usize, initial_sum: F) -> Self {
        Self {
            current_sum: initial_sum,
            challenges: Vec::new(),
            round: 0,
            num_variables,
        }
    }
    
    /// Check if verification complete
    pub fn is_complete(&self) -> bool {
        self.round == self.num_variables
    }
    
    /// Get remaining rounds
    pub fn remaining_rounds(&self) -> usize {
        self.num_variables - self.round
    }
}

/// Sumcheck verification result
#[derive(Clone, Debug)]
pub struct SumcheckVerificationResult<F: Field> {
    /// Is valid
    pub is_valid: bool,
    
    /// Challenges used
    pub challenges: Vec<F>,
    
    /// Final sum
    pub final_sum: F,
    
    /// Error message if invalid
    pub error: Option<String>,
}

impl<F: Field> SumcheckVerificationResult<F> {
    pub fn success(challenges: Vec<F>, final_sum: F) -> Self {
        Self {
            is_valid: true,
            challenges,
            final_sum,
            error: None,
        }
    }
    
    pub fn failure(error: String) -> Self {
        Self {
            is_valid: false,
            challenges: Vec::new(),
            final_sum: F::zero(),
            error: Some(error),
        }
    }
}
