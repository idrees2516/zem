// Sumcheck Protocol for RoKoko - Complete Production Implementation
//
// The sumcheck protocol proves that a claimed sum S equals the sum of a multilinear
// polynomial f over the Boolean hypercube: S = Σ_{x ∈ {0,1}^ν} f(x)
//
// PROTOCOL STRUCTURE:
// 1. Prover sends univariate g_1(X_1) = Σ_{x_2,...,x_ν ∈ {0,1}^{ν-1}} f(X_1, x_2,...,x_ν)
// 2. Verifier checks g_1(0) + g_1(1) = S and samples random r_1
// 3. Repeat for remaining variables with S' = g_1(r_1)
// 4. Final: verify f(r_1,...,r_ν) = g_ν(r_ν) via oracle
//
// SECURITY: Soundness error 2^-λ per round, composable
// COMPLEXITY: O(ν) rounds, O(d) communication per round

use crate::errors::ZKVMError;
use crate::rokoko::polynomial::{MultilinearPolynomial, UnivariatePolynomial, PolynomialOps};
use crate::rokoko::transcript::{RokokoTranscript, TranscriptProtocol};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Complete sumcheck proof containing all round polynomials
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SumcheckProof {
    /// Univariate polynomials for each round (ν total)
    pub round_polynomials: Vec<UnivariatePolynomial>,
    
    /// Initial claimed sum
    pub claimed_sum: u64,
    
    /// Final evaluation point (r_1,...,r_ν)
    pub evaluation_point: Vec<u64>,
    
    /// Final evaluation f(r_1,...,r_ν)
    pub final_evaluation: u64,
}

impl SumcheckProof {
    pub fn new(
        round_polynomials: Vec<UnivariatePolynomial>,
        claimed_sum: u64,
        evaluation_point: Vec<u64>,
        final_evaluation: u64,
    ) -> Self {
        Self { round_polynomials, claimed_sum, evaluation_point, final_evaluation }
    }
    
    pub fn num_rounds(&self) -> usize {
        self.round_polynomials.len()
    }
    
    pub fn size_bytes(&self) -> usize {
        let poly_size: usize = self.round_polynomials.iter()
            .map(|p| p.coefficients.len() * 8).sum();
        poly_size + 8 + self.evaluation_point.len() * 8 + 8
    }
}

/// Prover state machine for sumcheck protocol
pub struct SumcheckProver {
    /// Current polynomial (reduced after each round)
    current_polynomial: MultilinearPolynomial,
    
    /// Number of variables remaining
    remaining_vars: usize,
    
    /// Accumulated challenge points
    challenge_points: Vec<u64>,
    
    /// Field modulus
    modulus: u64,
    
    /// Transcript for Fiat-Shamir
    transcript: RokokoTranscript,
}

impl SumcheckProver {
    pub fn new(
        polynomial: MultilinearPolynomial,
        modulus: u64,
        transcript: RokokoTranscript,
    ) -> Self {
        let num_vars = polynomial.num_variables();
        Self {
            current_polynomial: polynomial,
            remaining_vars: num_vars,
            challenge_points: Vec::with_capacity(num_vars),
            modulus,
            transcript,
        }
    }
    
    /// Computes initial claimed sum H = Σ_{x∈{0,1}^ν} f(x)
    pub fn compute_initial_sum(&self) -> u64 {
        let mut sum = 0u128;
        for &val in &self.current_polynomial.evaluations {
            sum = (sum + val as u128) % self.modulus as u128;
        }
        sum as u64
    }
    
    /// Generates univariate polynomial for current round
    /// g_i(X) = Σ_{x_{i+1},...,x_ν ∈ {0,1}^{ν-i}} f(r_1,...,r_{i-1},X,x_{i+1},...,x_ν)
    fn generate_round_polynomial(&self) -> Result<UnivariatePolynomial, ZKVMError> {
        if self.remaining_vars == 0 {
            return Err(ZKVMError::ProofGenerationError(
                "No variables remaining".to_string()
            ));
        }
        
        let n = self.current_polynomial.evaluations.len();
        let half = n / 2;
        
        // For multilinear polynomials, binding polynomial is degree 1:
        // g(X) = c_0 + c_1·X where:
        // c_0 = Σ_{w∈{0,1}^{ν-1}} f(0,w)
        // c_1 = Σ_{w∈{0,1}^{ν-1}} [f(1,w) - f(0,w)]
        
        let mut sum_0 = 0u128;
        let mut sum_1 = 0u128;
        
        for i in 0..half {
            sum_0 = (sum_0 + self.current_polynomial.evaluations[i] as u128) 
                % self.modulus as u128;
            sum_1 = (sum_1 + self.current_polynomial.evaluations[i + half] as u128) 
                % self.modulus as u128;
        }
        
        let c0 = sum_0 as u64;
        let c1 = sub_mod(sum_1 as u64, c0, self.modulus);
        
        Ok(UnivariatePolynomial::new(vec![c0, c1], self.modulus))
    }
    
    /// Executes one round of the protocol
    pub fn prove_round<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<UnivariatePolynomial, ZKVMError> {
        // Generate round polynomial
        let round_poly = self.generate_round_polynomial()?;
        
        // Add to transcript
        self.transcript.append_message(b"round_poly", &bincode::serialize(&round_poly.coefficients)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
        
        // Get challenge from transcript (Fiat-Shamir)
        let challenge = self.transcript.challenge_scalar(b"challenge")?;
        let challenge_reduced = challenge % self.modulus;
        
        // Partially evaluate polynomial at challenge
        self.current_polynomial = self.current_polynomial.partial_eval(challenge_reduced)?;
        self.challenge_points.push(challenge_reduced);
        self.remaining_vars -= 1;
        
        Ok(round_poly)
    }
    
    /// Generates complete sumcheck proof
    pub fn prove<R: RngCore + CryptoRng>(
        mut self,
        rng: &mut R,
    ) -> Result<SumcheckProof, ZKVMError> {
        let num_rounds = self.remaining_vars;
        let initial_sum = self.compute_initial_sum();
        
        let mut round_polynomials = Vec::with_capacity(num_rounds);
        
        // Execute all rounds
        for _ in 0..num_rounds {
            let poly = self.prove_round(rng)?;
            round_polynomials.push(poly);
        }
        
        // Final evaluation should be at single point
        if self.current_polynomial.evaluations.len() != 1 {
            return Err(ZKVMError::ProofGenerationError(
                "Invalid final polynomial size".to_string()
            ));
        }
        
        let final_eval = self.current_polynomial.evaluations[0];
        
        Ok(SumcheckProof::new(
            round_polynomials,
            initial_sum,
            self.challenge_points,
            final_eval,
        ))
    }
}

/// Verifier for sumcheck protocol
pub struct SumcheckVerifier {
    /// Current expected sum
    current_sum: u64,
    
    /// Accumulated challenges
    challenges: Vec<u64>,
    
    /// Field modulus
    modulus: u64,
    
    /// Transcript for Fiat-Shamir
    transcript: RokokoTranscript,
}

impl SumcheckVerifier {
    pub fn new(
        claimed_sum: u64,
        modulus: u64,
        transcript: RokokoTranscript,
    ) -> Self {
        Self {
            current_sum: claimed_sum,
            challenges: Vec::new(),
            modulus,
            transcript,
        }
    }
    
    /// Verifies one round of the protocol
    pub fn verify_round(
        &mut self,
        round_polynomial: &UnivariatePolynomial,
    ) -> Result<bool, ZKVMError> {
        // Check g(0) + g(1) = current_sum
        let eval_0 = round_polynomial.evaluate(0);
        let eval_1 = round_polynomial.evaluate(1);
        let sum = add_mod(eval_0, eval_1, self.modulus);
        
        if sum != self.current_sum {
            return Ok(false);
        }
        
        // Add to transcript
        self.transcript.append_message(b"round_poly", &bincode::serialize(&round_polynomial.coefficients)
            .map_err(|e| ZKVMError::SerializationError(e.to_string()))?)?;
        
        // Generate challenge
        let challenge = self.transcript.challenge_scalar(b"challenge")?;
        let challenge_reduced = challenge % self.modulus;
        
        // Update current sum to g(r_i)
        self.current_sum = round_polynomial.evaluate(challenge_reduced);
        self.challenges.push(challenge_reduced);
        
        Ok(true)
    }
    
    /// Verifies complete sumcheck proof
    /// oracle_eval should be f(r_1,...,r_ν) obtained from commitment opening
    pub fn verify(
        mut self,
        proof: &SumcheckProof,
        oracle_eval: u64,
    ) -> Result<bool, ZKVMError> {
        // Verify initial sum matches
        if self.current_sum != proof.claimed_sum {
            return Ok(false);
        }
        
        // Verify all rounds
        for poly in &proof.round_polynomials {
            if !self.verify_round(poly)? {
                return Ok(false);
            }
        }
        
        // Verify final evaluation
        if self.current_sum != oracle_eval {
            return Ok(false);
        }
        
        // Verify evaluation point matches
        if self.challenges != proof.evaluation_point {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    pub fn evaluation_point(&self) -> &[u64] {
        &self.challenges
    }
}

/// Batch sumcheck for multiple polynomials with random linear combination
pub struct BatchSumcheckProver {
    /// Individual polynomials
    polynomials: Vec<MultilinearPolynomial>,
    
    /// Claimed sums for each polynomial
    claimed_sums: Vec<u64>,
    
    /// Random batching coefficients
    batching_coeffs: Vec<u64>,
    
    /// Field modulus
    modulus: u64,
}

impl BatchSumcheckProver {
    pub fn new(
        polynomials: Vec<MultilinearPolynomial>,
        claimed_sums: Vec<u64>,
        modulus: u64,
    ) -> Result<Self, ZKVMError> {
        if polynomials.is_empty() {
            return Err(ZKVMError::InvalidParameter("Empty polynomial list".to_string()));
        }
        
        if polynomials.len() != claimed_sums.len() {
            return Err(ZKVMError::InvalidParameter("Length mismatch".to_string()));
        }
        
        // Check all polynomials have same number of variables
        let num_vars = polynomials[0].num_variables();
        for poly in &polynomials[1..] {
            if poly.num_variables() != num_vars {
                return Err(ZKVMError::InvalidParameter(
                    "Polynomials have different variable counts".to_string()
                ));
            }
        }
        
        Ok(Self {
            polynomials,
            claimed_sums,
            batching_coeffs: Vec::new(),
            modulus,
        })
    }
    
    /// Generates random batching coefficients
    pub fn generate_batching_coefficients<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) {
        self.batching_coeffs = (0..self.polynomials.len())
            .map(|_| rng.gen::<u64>() % self.modulus)
            .collect();
    }
    
    /// Computes random linear combination of polynomials
    fn compute_combined_polynomial(&self) -> Result<MultilinearPolynomial, ZKVMError> {
        if self.batching_coeffs.is_empty() {
            return Err(ZKVMError::ProofGenerationError(
                "Batching coefficients not generated".to_string()
            ));
        }
        
        let num_vars = self.polynomials[0].num_variables();
        let size = 1 << num_vars;
        let mut combined_evals = vec![0u128; size];
        
        for (idx, poly) in self.polynomials.iter().enumerate() {
            let coeff = self.batching_coeffs[idx] as u128;
            for (i, &eval) in poly.evaluations.iter().enumerate() {
                combined_evals[i] = (combined_evals[i] + coeff * eval as u128) 
                    % self.modulus as u128;
            }
        }
        
        let evals: Vec<u64> = combined_evals.iter().map(|&x| x as u64).collect();
        MultilinearPolynomial::new(evals, self.modulus)
    }
    
    /// Computes combined claimed sum
    fn compute_combined_sum(&self) -> Result<u64, ZKVMError> {
        if self.batching_coeffs.is_empty() {
            return Err(ZKVMError::ProofGenerationError(
                "Batching coefficients not generated".to_string()
            ));
        }
        
        let mut combined_sum = 0u128;
        for (idx, &sum) in self.claimed_sums.iter().enumerate() {
            let coeff = self.batching_coeffs[idx] as u128;
            combined_sum = (combined_sum + coeff * sum as u128) % self.modulus as u128;
        }
        
        Ok(combined_sum as u64)
    }
    
    /// Generates batch sumcheck proof
    pub fn prove<R: RngCore + CryptoRng>(
        mut self,
        transcript: RokokoTranscript,
        rng: &mut R,
    ) -> Result<(SumcheckProof, Vec<u64>), ZKVMError> {
        self.generate_batching_coefficients(rng);
        
        let combined_poly = self.compute_combined_polynomial()?;
        let prover = SumcheckProver::new(combined_poly, self.modulus, transcript);
        
        let proof = prover.prove(rng)?;
        Ok((proof, self.batching_coeffs))
    }
}

/// Zero-knowledge sumcheck with random masking polynomial
pub struct ZeroKnowledgeSumcheck {
    /// Original polynomial
    polynomial: MultilinearPolynomial,
    
    /// Random masking polynomial
    masking_polynomial: MultilinearPolynomial,
    
    /// Masking sum
    masking_sum: u64,
    
    /// Field modulus
    modulus: u64,
}

impl ZeroKnowledgeSumcheck {
    pub fn new<R: RngCore + CryptoRng>(
        polynomial: MultilinearPolynomial,
        modulus: u64,
        rng: &mut R,
    ) -> Result<Self, ZKVMError> {
        let num_vars = polynomial.num_variables();
        let size = 1 << num_vars;
        
        // Sample random masking polynomial
        let masking_evals: Vec<u64> = (0..size)
            .map(|_| rng.gen::<u64>() % modulus)
            .collect();
        
        let masking_polynomial = MultilinearPolynomial::new(masking_evals, modulus)?;
        
        // Compute masking sum
        let mut masking_sum = 0u128;
        for &eval in &masking_polynomial.evaluations {
            masking_sum = (masking_sum + eval as u128) % modulus as u128;
        }
        
        Ok(Self {
            polynomial,
            masking_polynomial,
            masking_sum: masking_sum as u64,
            modulus,
        })
    }
    
    /// Returns masked polynomial f' = f + r
    pub fn masked_polynomial(&self) -> Result<MultilinearPolynomial, ZKVMError> {
        self.polynomial.add(&self.masking_polynomial)
    }
    
    /// Returns masked sum
    pub fn masked_sum(&self) -> u64 {
        let original_sum = self.polynomial.evaluations.iter()
            .fold(0u128, |acc, &x| (acc + x as u128) % self.modulus as u128) as u64;
        
        add_mod(original_sum, self.masking_sum, self.modulus)
    }
    
    /// Proves zero-knowledge sumcheck
    pub fn prove<R: RngCore + CryptoRng>(
        self,
        transcript: RokokoTranscript,
        rng: &mut R,
    ) -> Result<(SumcheckProof, u64), ZKVMError> {
        let masked_poly = self.masked_polynomial()?;
        let prover = SumcheckProver::new(masked_poly, self.modulus, transcript);
        
        let proof = prover.prove(rng)?;
        Ok((proof, self.masking_sum))
    }
}

// Arithmetic helper functions

#[inline(always)]
fn add_mod(a: u64, b: u64, modulus: u64) -> u64 {
    let sum = (a as u128 + b as u128) % modulus as u128;
    sum as u64
}

#[inline(always)]
fn sub_mod(a: u64, b: u64, modulus: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        modulus - (b - a)
    }
}
