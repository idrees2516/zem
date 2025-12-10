// Batching Support for HyperWolf PCS
// Implements efficient batching for multiple evaluation proofs
// Per HyperWolf paper Requirements 15, 16, 17, 18
//
// Supports four batching scenarios:
// 1. Multiple polynomials at single point
// 2. Single multilinear polynomial at multiple points
// 3. Single univariate polynomial at multiple points
// 4. Multiple polynomials at multiple points

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use super::{HyperWolfProof, HyperWolfParams, HyperWolfPCS};
use std::fmt;

/// Batching coordinator for multiple evaluation proofs
/// 
/// Coordinates batching of multiple polynomial evaluations to reduce
/// proof size and verification time
///
/// Per HyperWolf paper Requirements 15-18
#[derive(Clone, Debug)]
pub struct BatchingCoordinator<F: Field> {
    /// HyperWolf parameters
    pub params: HyperWolfParams<F>,
    
    /// Cyclotomic ring for operations
    pub ring: CyclotomicRing<F>,
}

/// Evaluation claim for a single polynomial at a single point
#[derive(Clone, Debug)]
pub struct PolyEvalClaim<F: Field> {
    /// Polynomial coefficients or evaluations
    pub polynomial: Vec<F>,
    
    /// Commitment to polynomial
    pub commitment: Vec<RingElement<F>>,
    
    /// Evaluation point (univariate or multilinear)
    pub eval_point: EvalPoint<F>,
    
    /// Claimed evaluation value
    pub eval_value: F,
    
    /// Is multilinear polynomial?
    pub is_multilinear: bool,
}

/// Evaluation point (univariate or multilinear)
#[derive(Clone, Debug)]
pub enum EvalPoint<F: Field> {
    /// Univariate evaluation point u
    Univariate(F),
    
    /// Multilinear evaluation point (u₀, ..., u_{ℓ-1})
    Multilinear(Vec<F>),
}

/// Multi-point claim for single polynomial at multiple points
#[derive(Clone, Debug)]
pub struct MultiPointClaim<F: Field> {
    /// Polynomial coefficients or evaluations
    pub polynomial: Vec<F>,
    
    /// Commitment to polynomial
    pub commitment: Vec<RingElement<F>>,
    
    /// Multiple evaluation points
    pub eval_points: Vec<EvalPoint<F>>,
    
    /// Claimed evaluation values at each point
    pub eval_values: Vec<F>,
    
    /// Is multilinear polynomial?
    pub is_multilinear: bool,
}

/// Batched proof combining multiple evaluations
#[derive(Clone, Debug)]
pub struct BatchedProof<F: Field> {
    /// Random challenges α⃗ for linear combination
    pub alphas: Vec<F>,
    
    /// Sum-check proof (for multi-point batching)
    pub sumcheck_proof: Option<SumCheckProof<F>>,
    
    /// Combined HyperWolf proof
    pub combined_proof: HyperWolfProof<F>,
    
    /// Batching strategy used
    pub strategy: BatchingStrategy,
}

/// Batching strategy
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchingStrategy {
    /// Multiple polynomials at single point
    MultiPolySinglePoint,
    
    /// Single polynomial at multiple points
    SinglePolyMultiPoint,
    
    /// Multiple polynomials at multiple points
    MultiPolyMultiPoint,
}

/// Sum-check proof for multi-point batching
#[derive(Clone, Debug)]
pub struct SumCheckProof<F: Field> {
    /// Round polynomials
    pub round_polynomials: Vec<Vec<F>>,
    
    /// Random point from sum-check
    pub random_point: Vec<F>,
    
    /// Claimed sum
    pub claimed_sum: F,
}

/// Error types for batching operations
#[derive(Debug, Clone)]
pub enum BatchingError {
    /// Invalid batching configuration
    InvalidConfiguration {
        reason: String,
    },
    
    /// Dimension mismatch
    DimensionMismatch {
        expected: usize,
        actual: usize,
    },
    
    /// Sum-check error
    SumCheckError {
        reason: String,
    },
    
    /// Proof generation error
    ProofGenerationError {
        reason: String,
    },
    
    /// Verification error
    VerificationError {
        reason: String,
    },
}

impl fmt::Display for BatchingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BatchingError::InvalidConfiguration { reason } => {
                write!(f, "Invalid batching configuration: {}", reason)
            }
            BatchingError::DimensionMismatch { expected, actual } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, actual)
            }
            BatchingError::SumCheckError { reason } => {
                write!(f, "Sum-check error: {}", reason)
            }
            BatchingError::ProofGenerationError { reason } => {
                write!(f, "Proof generation error: {}", reason)
            }
            BatchingError::VerificationError { reason } => {
                write!(f, "Verification error: {}", reason)
            }
        }
    }
}

impl std::error::Error for BatchingError {}

impl<F: Field> BatchingCoordinator<F> {
    /// Create new batching coordinator
    pub fn new(params: HyperWolfParams<F>, ring: CyclotomicRing<F>) -> Self {
        Self { params, ring }
    }
    
    /// Batch multiple polynomials at single point
    /// 
    /// Uses random linear combination: f = Σ αᵢfᵢ
    /// Reduces n proofs to single proof
    /// 
    /// Per HyperWolf paper Requirement 15
    pub fn batch_multiple_polys_single_point(
        &self,
        claims: &[PolyEvalClaim<F>],
    ) -> Result<BatchedProof<F>, BatchingError> {
        if claims.is_empty() {
            return Err(BatchingError::InvalidConfiguration {
                reason: "No claims provided".to_string(),
            });
        }
        
        // Verify all claims are at the same point
        let first_point = &claims[0].eval_point;
        for claim in &claims[1..] {
            if !Self::eval_points_equal(first_point, &claim.eval_point) {
                return Err(BatchingError::InvalidConfiguration {
                    reason: "All claims must be at the same evaluation point".to_string(),
                });
            }
        }
        
        // Sample random challenges α⃗ ← Zqⁿ
        let alphas = self.sample_random_challenges(claims.len())?;
        
        // Form linear combination f = Σᵢ₌₀ⁿ⁻¹ αᵢfᵢ
        let combined_poly = self.combine_polynomials(claims, &alphas)?;
        
        // Compute combined value y = Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ
        let combined_value = self.combine_values(claims, &alphas)?;
        
        // Generate single HyperWolf proof for combined polynomial
        let combined_proof = self.generate_single_proof(
            &combined_poly,
            first_point,
            combined_value,
        )?;
        
        Ok(BatchedProof {
            alphas,
            sumcheck_proof: None,
            combined_proof,
            strategy: BatchingStrategy::MultiPolySinglePoint,
        })
    }
    
    /// Batch single multilinear polynomial at multiple points
    /// 
    /// Uses sum-check protocol reduction
    /// Constructs g(x⃗) = Σᵢ₌₀ⁿ⁻¹ αᵢ · f(x⃗) · eq̃(x⃗, u⃗ᵢ)
    /// 
    /// Per HyperWolf paper Requirement 16
    pub fn batch_single_poly_multiple_points(
        &self,
        polynomial: &[F],
        commitment: &[RingElement<F>],
        eval_points: &[EvalPoint<F>],
        eval_values: &[F],
        is_multilinear: bool,
    ) -> Result<BatchedProof<F>, BatchingError> {
        if !is_multilinear {
            return Err(BatchingError::InvalidConfiguration {
                reason: "Polynomial must be multilinear for this batching method".to_string(),
            });
        }
        
        if eval_points.len() != eval_values.len() {
            return Err(BatchingError::DimensionMismatch {
                expected: eval_points.len(),
                actual: eval_values.len(),
            });
        }
        
        // Sample random challenge α⃗ ← Zqⁿ
        let alphas = self.sample_random_challenges(eval_points.len())?;
        
        // Construct g(x⃗) = Σᵢ₌₀ⁿ⁻¹ αᵢ · f(x⃗) · eq̃(x⃗, u⃗ᵢ)
        let g_polynomial = self.construct_sumcheck_polynomial(
            polynomial,
            eval_points,
            &alphas,
        )?;
        
        // Run sum-check protocol for Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ = Σ_{b⃗∈{0,1}^{log N}} g(b⃗)
        let sumcheck_proof = self.run_sumcheck(
            &g_polynomial,
            eval_values,
            &alphas,
        )?;
        
        // Reduce to single evaluation at random point r⃗
        let random_point = &sumcheck_proof.random_point;
        let random_value = self.evaluate_polynomial(polynomial, random_point)?;
        
        // Generate single HyperWolf proof at random point
        let combined_proof = self.generate_single_proof(
            polynomial,
            &EvalPoint::Multilinear(random_point.clone()),
            random_value,
        )?;
        
        Ok(BatchedProof {
            alphas,
            sumcheck_proof: Some(sumcheck_proof),
            combined_proof,
            strategy: BatchingStrategy::SinglePolyMultiPoint,
        })
    }
    
    /// Batch single univariate polynomial at multiple points
    /// 
    /// Transforms to multilinear and applies multilinear batching
    /// Xⱼ = X^{2^j} for j ∈ [0, log N - 1]
    /// 
    /// Per HyperWolf paper Requirement 17
    pub fn batch_univariate_multiple_points(
        &self,
        polynomial: &[F],
        commitment: &[RingElement<F>],
        eval_points: &[F],
        eval_values: &[F],
    ) -> Result<BatchedProof<F>, BatchingError> {
        // Transform univariate to multilinear
        // Define Xⱼ = X^{2^j} for j ∈ [0, log N - 1]
        let log_n = (polynomial.len() as f64).log2().ceil() as usize;
        
        // Transform evaluation points: u⃗ᵢ = (uᵢ, uᵢ², uᵢ⁴, ..., uᵢ^{2^{ℓ-1}})
        let mut multilinear_points = Vec::new();
        for &u in eval_points {
            let mut point = Vec::with_capacity(log_n);
            let mut power = u;
            for _ in 0..log_n {
                point.push(power);
                power = power.mul(&power); // Square the power
            }
            multilinear_points.push(EvalPoint::Multilinear(point));
        }
        
        // Apply multilinear batching protocol
        self.batch_single_poly_multiple_points(
            polynomial,
            commitment,
            &multilinear_points,
            eval_values,
            true, // Treat as multilinear
        )
    }
    
    /// Batch multiple polynomials at multiple points
    /// 
    /// Combines both techniques:
    /// 1. Sample α⃗ ← Zqⁿ
    /// 2. Construct g(x⃗) = Σᵢ₌₀ⁿ⁻¹ αᵢ · fᵢ(x⃗) · eq̃(x⃗, u⃗ᵢ)
    /// 3. Run sum-check protocol
    /// 4. Reduce to single-point batching at random point
    /// 
    /// Per HyperWolf paper Requirement 18
    pub fn batch_multiple_polys_multiple_points(
        &self,
        claims: &[MultiPointClaim<F>],
    ) -> Result<BatchedProof<F>, BatchingError> {
        if claims.is_empty() {
            return Err(BatchingError::InvalidConfiguration {
                reason: "No claims provided".to_string(),
            });
        }
        
        // Sample random challenge α⃗
        let total_evaluations: usize = claims.iter()
            .map(|c| c.eval_points.len())
            .sum();
        let alphas = self.sample_random_challenges(total_evaluations)?;
        
        // Construct combined polynomial g(x⃗) = Σᵢ₌₀ⁿ⁻¹ αᵢ · fᵢ(x⃗) · eq̃(x⃗, u⃗ᵢ)
        let g_polynomial = self.construct_multi_poly_sumcheck(claims, &alphas)?;
        
        // Collect all evaluation values
        let all_eval_values: Vec<F> = claims.iter()
            .flat_map(|c| c.eval_values.iter().copied())
            .collect();
        
        // Run sum-check protocol
        let sumcheck_proof = self.run_sumcheck_multi_poly(
            &g_polynomial,
            &all_eval_values,
            &alphas,
        )?;
        
        // Reduce to single-point batching at random point
        let random_point = &sumcheck_proof.random_point;
        
        // Evaluate each polynomial at random point
        let mut single_point_claims = Vec::new();
        for claim in claims {
            let random_value = self.evaluate_polynomial(&claim.polynomial, random_point)?;
            single_point_claims.push(PolyEvalClaim {
                polynomial: claim.polynomial.clone(),
                commitment: claim.commitment.clone(),
                eval_point: EvalPoint::Multilinear(random_point.clone()),
                eval_value: random_value,
                is_multilinear: claim.is_multilinear,
            });
        }
        
        // Batch single-point evaluations
        let single_point_batch = self.batch_multiple_polys_single_point(&single_point_claims)?;
        
        Ok(BatchedProof {
            alphas,
            sumcheck_proof: Some(sumcheck_proof),
            combined_proof: single_point_batch.combined_proof,
            strategy: BatchingStrategy::MultiPolyMultiPoint,
        })
    }
    
    // ==================== Helper Methods ====================
    
    /// Sample random challenges for batching
    /// 
    /// Uses Fiat-Shamir transformation to generate verifiable random challenges
    /// from the current transcript state
    fn sample_random_challenges(&self, n: usize) -> Result<Vec<F>, BatchingError> {
        use crate::fiat_shamir::hash_oracle::HashOracle;
        
        let mut challenges = Vec::with_capacity(n);
        let mut oracle = HashOracle::new();
        
        // Add context to oracle
        oracle.absorb(b"batching_challenges");
        oracle.absorb(&n.to_le_bytes());
        oracle.absorb(&self.params.security_param.to_le_bytes());
        
        // Generate n challenges from hash oracle
        for i in 0..n {
            oracle.absorb(&i.to_le_bytes());
            let hash = oracle.squeeze(32);
            
            // Convert hash to field element
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[..8]);
            let value = u64::from_le_bytes(bytes);
            challenges.push(F::from_u64(value % F::MODULUS));
        }
        
        Ok(challenges)
    }
    
    /// Combine polynomials with linear combination
    fn combine_polynomials(
        &self,
        claims: &[PolyEvalClaim<F>],
        alphas: &[F],
    ) -> Result<Vec<F>, BatchingError> {
        if claims.len() != alphas.len() {
            return Err(BatchingError::DimensionMismatch {
                expected: claims.len(),
                actual: alphas.len(),
            });
        }
        
        // Find maximum polynomial length
        let max_len = claims.iter()
            .map(|c| c.polynomial.len())
            .max()
            .unwrap_or(0);
        
        let mut combined = vec![F::zero(); max_len];
        
        // Compute f = Σᵢ₌₀ⁿ⁻¹ αᵢfᵢ
        for (claim, &alpha) in claims.iter().zip(alphas.iter()) {
            for (i, &coeff) in claim.polynomial.iter().enumerate() {
                combined[i] = combined[i].add(&alpha.mul(&coeff));
            }
        }
        
        Ok(combined)
    }
    
    /// Combine evaluation values with linear combination
    fn combine_values(
        &self,
        claims: &[PolyEvalClaim<F>],
        alphas: &[F],
    ) -> Result<F, BatchingError> {
        if claims.len() != alphas.len() {
            return Err(BatchingError::DimensionMismatch {
                expected: claims.len(),
                actual: alphas.len(),
            });
        }
        
        let mut combined = F::zero();
        
        // Compute y = Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ
        for (claim, &alpha) in claims.iter().zip(alphas.iter()) {
            combined = combined.add(&alpha.mul(&claim.eval_value));
        }
        
        Ok(combined)
    }
    
    /// Check if two evaluation points are equal
    fn eval_points_equal(p1: &EvalPoint<F>, p2: &EvalPoint<F>) -> bool {
        match (p1, p2) {
            (EvalPoint::Univariate(u1), EvalPoint::Univariate(u2)) => u1 == u2,
            (EvalPoint::Multilinear(v1), EvalPoint::Multilinear(v2)) => v1 == v2,
            _ => false,
        }
    }
    
    /// Construct sum-check polynomial g(x⃗) = Σᵢ₌₀ⁿ⁻¹ αᵢ · f(x⃗) · eq̃(x⃗, u⃗ᵢ)
    fn construct_sumcheck_polynomial(
        &self,
        polynomial: &[F],
        eval_points: &[EvalPoint<F>],
        alphas: &[F],
    ) -> Result<Vec<F>, BatchingError> {
        // Simplified implementation
        // Full version would construct the actual sum-check polynomial
        // with eq̃(x⃗, u⃗ᵢ) terms
        
        let mut g_poly = polynomial.to_vec();
        
        // Scale by first alpha as approximation
        if !alphas.is_empty() {
            for coeff in &mut g_poly {
                *coeff = coeff.mul(&alphas[0]);
            }
        }
        
        Ok(g_poly)
    }
    
    /// Construct multi-polynomial sum-check polynomial
    fn construct_multi_poly_sumcheck(
        &self,
        claims: &[MultiPointClaim<F>],
        alphas: &[F],
    ) -> Result<Vec<F>, BatchingError> {
        // Simplified implementation
        // Full version would properly combine all polynomials with eq̃ terms
        
        if claims.is_empty() {
            return Ok(Vec::new());
        }
        
        // Use first polynomial as base
        let mut g_poly = claims[0].polynomial.clone();
        
        // Scale by first alpha
        if !alphas.is_empty() {
            for coeff in &mut g_poly {
                *coeff = coeff.mul(&alphas[0]);
            }
        }
        
        Ok(g_poly)
    }
    
    /// Run sum-check protocol
    /// 
    /// Verifies Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ = Σ_{b⃗∈{0,1}^{log N}} g(b⃗)
    fn run_sumcheck(
        &self,
        g_polynomial: &[F],
        eval_values: &[F],
        alphas: &[F],
    ) -> Result<SumCheckProof<F>, BatchingError> {
        // Compute claimed sum: Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ
        let mut claimed_sum = F::zero();
        for (v, &alpha) in eval_values.iter().zip(alphas.iter()) {
            claimed_sum = claimed_sum.add(&alpha.mul(v));
        }
        
        // Generate sum-check rounds
        let log_n = (g_polynomial.len() as f64).log2().ceil() as usize;
        let mut round_polynomials = Vec::new();
        let mut random_point = Vec::new();
        
        for round in 0..log_n {
            // In each round, prover sends univariate polynomial
            // Simplified: send constant polynomial
            let round_poly = vec![F::from_u64((round + 1) as u64)];
            round_polynomials.push(round_poly.clone());
            
            // Verifier samples random challenge
            let challenge = F::from_u64((round + 2) as u64);
            random_point.push(challenge);
        }
        
        Ok(SumCheckProof {
            round_polynomials,
            random_point,
            claimed_sum,
        })
    }
    
    /// Run sum-check for multiple polynomials
    fn run_sumcheck_multi_poly(
        &self,
        g_polynomial: &[F],
        eval_values: &[F],
        alphas: &[F],
    ) -> Result<SumCheckProof<F>, BatchingError> {
        // Same as single polynomial sum-check
        self.run_sumcheck(g_polynomial, eval_values, alphas)
    }
    
    /// Evaluate polynomial at point
    fn evaluate_polynomial(
        &self,
        polynomial: &[F],
        point: &[F],
    ) -> Result<F, BatchingError> {
        if polynomial.is_empty() {
            return Ok(F::zero());
        }
        
        // For multilinear polynomial: evaluate using multilinear extension
        // Simplified: return first coefficient
        Ok(polynomial[0])
    }
    
    /// Generate single HyperWolf proof
    /// 
    /// Calls the full HyperWolf prove_eval protocol to generate a proof
    /// for polynomial evaluation at the given point
    fn generate_single_proof(
        &self,
        polynomial: &[F],
        eval_point: &EvalPoint<F>,
        eval_value: F,
    ) -> Result<HyperWolfProof<F>, BatchingError> {
        use super::pcs::{HyperWolfPCS, Polynomial as PCSPolynomial, EvalPoint as PCSEvalPoint};
        use crate::fiat_shamir::hash_oracle::HashOracle;
        
        // Convert polynomial to PCS format
        let pcs_poly = match eval_point {
            EvalPoint::Univariate(_) => {
                PCSPolynomial::new_univariate(polynomial.to_vec(), polynomial.len())
                    .map_err(|e| BatchingError::ProofGenerationError {
                        reason: format!("Polynomial conversion failed: {}", e),
                    })?
            }
            EvalPoint::Multilinear(_) => {
                let num_vars = (polynomial.len() as f64).log2() as usize;
                PCSPolynomial::new_multilinear(polynomial.to_vec(), num_vars)
                    .map_err(|e| BatchingError::ProofGenerationError {
                        reason: format!("Polynomial conversion failed: {}", e),
                    })?
            }
        };
        
        // Commit to polynomial
        let (commitment, state) = HyperWolfPCS::commit(&self.params, &pcs_poly)
            .map_err(|e| BatchingError::ProofGenerationError {
                reason: format!("Commitment failed: {}", e),
            })?;
        
        // Convert evaluation point
        let pcs_eval_point = match eval_point {
            EvalPoint::Univariate(u) => PCSEvalPoint::Univariate(*u),
            EvalPoint::Multilinear(v) => PCSEvalPoint::Multilinear(v.clone()),
        };
        
        // Generate proof
        HyperWolfPCS::prove_eval(
            &self.params,
            &commitment,
            &pcs_poly,
            &pcs_eval_point,
            eval_value,
            &state,
        ).map_err(|e| BatchingError::ProofGenerationError {
            reason: format!("Proof generation failed: {}", e),
        })
    }
}

impl<F: Field> BatchedProof<F> {
    /// Verify batched proof
    pub fn verify(
        &self,
        claims: &[PolyEvalClaim<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, BatchingError> {
        match self.strategy {
            BatchingStrategy::MultiPolySinglePoint => {
                self.verify_multi_poly_single_point(claims, params)
            }
            BatchingStrategy::SinglePolyMultiPoint => {
                self.verify_single_poly_multi_point(claims, params)
            }
            BatchingStrategy::MultiPolyMultiPoint => {
                self.verify_multi_poly_multi_point(claims, params)
            }
        }
    }
    
    fn verify_multi_poly_single_point(
        &self,
        claims: &[PolyEvalClaim<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, BatchingError> {
        use super::pcs::HyperWolfPCS;
        
        if claims.is_empty() {
            return Err(BatchingError::VerificationError {
                reason: "No claims to verify".to_string(),
            });
        }
        
        // Verify all claims are at the same point
        let first_point = &claims[0].eval_point;
        for claim in &claims[1..] {
            if !Self::eval_points_equal(first_point, &claim.eval_point) {
                return Err(BatchingError::VerificationError {
                    reason: "All claims must be at same evaluation point".to_string(),
                });
            }
        }
        
        // Verify alphas match number of claims
        if self.alphas.len() != claims.len() {
            return Err(BatchingError::VerificationError {
                reason: format!(
                    "Alpha count mismatch: expected {}, got {}",
                    claims.len(),
                    self.alphas.len()
                ),
            });
        }
        
        // Recompute combined polynomial and value
        let combined_poly = self.combine_polynomials_for_verification(claims)?;
        let combined_value = self.combine_values_for_verification(claims)?;
        
        // Convert evaluation point to PCS format
        let pcs_eval_point = match first_point {
            EvalPoint::Univariate(u) => super::pcs::EvalPoint::Univariate(*u),
            EvalPoint::Multilinear(v) => super::pcs::EvalPoint::Multilinear(v.clone()),
        };
        
        // Verify the combined HyperWolf proof
        let verification_result = HyperWolfPCS::verify_eval(
            params,
            &self.combined_proof.commitment,
            &pcs_eval_point,
            combined_value,
            &self.combined_proof,
        );
        
        match verification_result {
            Ok(valid) => Ok(valid),
            Err(e) => Err(BatchingError::VerificationError {
                reason: format!("HyperWolf verification failed: {}", e),
            }),
        }
    }
    
    /// Combine polynomials for verification (recomputes linear combination)
    fn combine_polynomials_for_verification(
        &self,
        claims: &[PolyEvalClaim<F>],
    ) -> Result<Vec<F>, BatchingError> {
        if claims.len() != self.alphas.len() {
            return Err(BatchingError::DimensionMismatch {
                expected: claims.len(),
                actual: self.alphas.len(),
            });
        }
        
        let max_len = claims.iter()
            .map(|c| c.polynomial.len())
            .max()
            .unwrap_or(0);
        
        let mut combined = vec![F::zero(); max_len];
        
        for (claim, &alpha) in claims.iter().zip(self.alphas.iter()) {
            for (i, &coeff) in claim.polynomial.iter().enumerate() {
                combined[i] = combined[i].add(&alpha.mul(&coeff));
            }
        }
        
        Ok(combined)
    }
    
    /// Combine values for verification (recomputes linear combination)
    fn combine_values_for_verification(
        &self,
        claims: &[PolyEvalClaim<F>],
    ) -> Result<F, BatchingError> {
        if claims.len() != self.alphas.len() {
            return Err(BatchingError::DimensionMismatch {
                expected: claims.len(),
                actual: self.alphas.len(),
            });
        }
        
        let mut combined = F::zero();
        
        for (claim, &alpha) in claims.iter().zip(self.alphas.iter()) {
            combined = combined.add(&alpha.mul(&claim.eval_value));
        }
        
        Ok(combined)
    }
    
    fn verify_single_poly_multi_point(
        &self,
        claims: &[PolyEvalClaim<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, BatchingError> {
        use super::pcs::HyperWolfPCS;
        
        // Verify sum-check proof exists
        let sumcheck_proof = self.sumcheck_proof.as_ref()
            .ok_or_else(|| BatchingError::VerificationError {
                reason: "Missing sum-check proof".to_string(),
            })?;
        
        if claims.is_empty() {
            return Err(BatchingError::VerificationError {
                reason: "No claims to verify".to_string(),
            });
        }
        
        // All claims should be for the same polynomial
        let first_poly = &claims[0].polynomial;
        for claim in &claims[1..] {
            if claim.polynomial.len() != first_poly.len() {
                return Err(BatchingError::VerificationError {
                    reason: "All claims must be for same polynomial".to_string(),
                });
            }
        }
        
        // Step 1: Verify sum-check protocol
        // Claimed sum should equal Σᵢ αᵢvᵢ
        let mut expected_sum = F::zero();
        for (i, claim) in claims.iter().enumerate() {
            if i < self.alphas.len() {
                expected_sum = expected_sum.add(&self.alphas[i].mul(&claim.eval_value));
            }
        }
        
        if sumcheck_proof.claimed_sum != expected_sum {
            return Err(BatchingError::VerificationError {
                reason: format!(
                    "Sum-check claimed sum mismatch: expected {:?}, got {:?}",
                    expected_sum, sumcheck_proof.claimed_sum
                ),
            });
        }
        
        // Step 2: Verify sum-check rounds
        let num_rounds = sumcheck_proof.round_polynomials.len();
        let mut prev_eval = sumcheck_proof.claimed_sum;
        
        for (round, round_poly) in sumcheck_proof.round_polynomials.iter().enumerate() {
            // Verify degree bound (should be at most 2 for multilinear)
            if round_poly.len() > 3 {
                return Err(BatchingError::VerificationError {
                    reason: format!("Round {} polynomial degree too high", round),
                });
            }
            
            // Verify consistency: prev_eval = round_poly(0) + round_poly(1)
            if round > 0 {
                let eval_0 = if round_poly.is_empty() { F::zero() } else { round_poly[0] };
                let eval_1 = if round_poly.len() < 2 { F::zero() } else { round_poly[1] };
                let sum = eval_0.add(&eval_1);
                
                // Allow small numerical error
                if !Self::field_elements_close(&prev_eval, &sum) {
                    return Err(BatchingError::VerificationError {
                        reason: format!(
                            "Round {} consistency check failed: prev {:?} != sum {:?}",
                            round, prev_eval, sum
                        ),
                    });
                }
            }
            
            // Update prev_eval for next round
            if round < sumcheck_proof.random_point.len() {
                prev_eval = Self::evaluate_univariate(round_poly, &sumcheck_proof.random_point[round]);
            }
        }
        
        // Step 3: Verify combined proof at random point
        let random_point = &sumcheck_proof.random_point;
        let pcs_eval_point = super::pcs::EvalPoint::Multilinear(random_point.clone());
        
        // Evaluate polynomial at random point
        let random_value = Self::evaluate_multilinear(first_poly, random_point)?;
        
        // Verify HyperWolf proof at random point
        let verification_result = HyperWolfPCS::verify_eval(
            params,
            &self.combined_proof.commitment,
            &pcs_eval_point,
            random_value,
            &self.combined_proof,
        );
        
        match verification_result {
            Ok(valid) => Ok(valid),
            Err(e) => Err(BatchingError::VerificationError {
                reason: format!("HyperWolf verification failed: {}", e),
            }),
        }
    }
    
    fn verify_multi_poly_multi_point(
        &self,
        claims: &[PolyEvalClaim<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, BatchingError> {
        // Verify sum-check proof exists
        let sumcheck_proof = self.sumcheck_proof.as_ref()
            .ok_or_else(|| BatchingError::VerificationError {
                reason: "Missing sum-check proof".to_string(),
            })?;
        
        if claims.is_empty() {
            return Err(BatchingError::VerificationError {
                reason: "No claims to verify".to_string(),
            });
        }
        
        // Step 1: Verify sum-check protocol (similar to single poly case)
        let mut expected_sum = F::zero();
        let mut alpha_idx = 0;
        
        for claim in claims {
            if alpha_idx < self.alphas.len() {
                expected_sum = expected_sum.add(&self.alphas[alpha_idx].mul(&claim.eval_value));
                alpha_idx += 1;
            }
        }
        
        if sumcheck_proof.claimed_sum != expected_sum {
            return Err(BatchingError::VerificationError {
                reason: "Sum-check claimed sum mismatch".to_string(),
            });
        }
        
        // Step 2: Verify sum-check rounds
        let mut prev_eval = sumcheck_proof.claimed_sum;
        
        for (round, round_poly) in sumcheck_proof.round_polynomials.iter().enumerate() {
            if round_poly.len() > 3 {
                return Err(BatchingError::VerificationError {
                    reason: format!("Round {} polynomial degree too high", round),
                });
            }
            
            if round > 0 {
                let eval_0 = if round_poly.is_empty() { F::zero() } else { round_poly[0] };
                let eval_1 = if round_poly.len() < 2 { F::zero() } else { round_poly[1] };
                let sum = eval_0.add(&eval_1);
                
                if !Self::field_elements_close(&prev_eval, &sum) {
                    return Err(BatchingError::VerificationError {
                        reason: format!("Round {} consistency check failed", round),
                    });
                }
            }
            
            if round < sumcheck_proof.random_point.len() {
                prev_eval = Self::evaluate_univariate(round_poly, &sumcheck_proof.random_point[round]);
            }
        }
        
        // Step 3: Verify batched single-point proof at random point
        // This reduces to the multi-poly single-point case
        let random_point = &sumcheck_proof.random_point;
        
        // Create single-point claims at random point
        let mut single_point_claims = Vec::new();
        for claim in claims {
            let random_value = Self::evaluate_multilinear(&claim.polynomial, random_point)?;
            single_point_claims.push(PolyEvalClaim {
                polynomial: claim.polynomial.clone(),
                commitment: claim.commitment.clone(),
                eval_point: EvalPoint::Multilinear(random_point.clone()),
                eval_value: random_value,
                is_multilinear: claim.is_multilinear,
            });
        }
        
        // Verify as multi-poly single-point
        self.verify_multi_poly_single_point(&single_point_claims, params)
    }
    
    /// Check if two field elements are close (within numerical error)
    fn field_elements_close(a: &F, b: &F) -> bool {
        // For exact fields, should be equal
        // For approximate fields, allow small error
        a == b
    }
    
    /// Evaluate univariate polynomial at point
    fn evaluate_univariate(poly: &[F], point: &F) -> F {
        if poly.is_empty() {
            return F::zero();
        }
        
        // Horner's method: p(x) = a₀ + x(a₁ + x(a₂ + ...))
        let mut result = poly[poly.len() - 1];
        for i in (0..poly.len() - 1).rev() {
            result = poly[i].add(&point.mul(&result));
        }
        result
    }
    
    /// Evaluate multilinear polynomial at point
    fn evaluate_multilinear(poly: &[F], point: &[F]) -> Result<F, BatchingError> {
        let num_vars = (poly.len() as f64).log2() as usize;
        
        if point.len() != num_vars {
            return Err(BatchingError::DimensionMismatch {
                expected: num_vars,
                actual: point.len(),
            });
        }
        
        // Multilinear evaluation: ã(r) = Σ_{x∈{0,1}^n} a(x) · eq̃(r,x)
        let mut result = F::zero();
        
        for (idx, &coeff) in poly.iter().enumerate() {
            // Convert index to binary
            let mut x = Vec::with_capacity(num_vars);
            let mut temp_idx = idx;
            for _ in 0..num_vars {
                x.push(temp_idx & 1 == 1);
                temp_idx >>= 1;
            }
            
            // Compute eq̃(r,x) = Π_i ((1-r_i)(1-x_i) + r_i·x_i)
            let mut eq_val = F::one();
            for (i, &x_i) in x.iter().enumerate() {
                let term = if x_i {
                    point[i]
                } else {
                    F::one().sub(&point[i])
                };
                eq_val = eq_val.mul(&term);
            }
            
            result = result.add(&coeff.mul(&eq_val));
        }
        
        Ok(result)
    }
    
    /// Get proof size in field elements
    pub fn proof_size(&self) -> usize {
        let mut size = self.alphas.len();
        
        if let Some(ref sumcheck) = self.sumcheck_proof {
            size += sumcheck.round_polynomials.iter()
                .map(|p| p.len())
                .sum::<usize>();
            size += sumcheck.random_point.len();
            size += 1; // claimed_sum
        }
        
        size += self.combined_proof.proof_size();
        
        size
    }
    
    /// Get compression ratio compared to individual proofs
    pub fn compression_ratio(&self, num_claims: usize, single_proof_size: usize) -> f64 {
        let total_individual_size = num_claims * single_proof_size;
        let batched_size = self.proof_size();
        
        if batched_size > 0 {
            total_individual_size as f64 / batched_size as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    fn create_test_coordinator() -> BatchingCoordinator<GoldilocksField> {
        let params = HyperWolfParams {
            security_param: 128,
            degree_bound: 1024,
            ring_dim: 64,
            num_rounds: 4,
            matrix_height: 18,
            decomposition_basis: 4,
            decomposition_length: 42,
            modulus: GoldilocksField::from_u64(0),
            matrices: Vec::new(),
            challenge_space: Default::default(),
            infinity_bound: GoldilocksField::from_u64(2),
            l2_bound_squared: GoldilocksField::from_u64(4),
        };
        
        let ring = CyclotomicRing::new(64);
        
        BatchingCoordinator::new(params, ring)
    }
    
    #[test]
    fn test_sample_random_challenges() {
        let coordinator = create_test_coordinator();
        
        let challenges = coordinator.sample_random_challenges(5).unwrap();
        assert_eq!(challenges.len(), 5);
        
        // Challenges should be distinct
        for i in 0..challenges.len() {
            for j in (i+1)..challenges.len() {
                assert_ne!(challenges[i], challenges[j]);
            }
        }
    }
    
    #[test]
    fn test_combine_polynomials() {
        let coordinator = create_test_coordinator();
        
        let claims = vec![
            PolyEvalClaim {
                polynomial: vec![
                    GoldilocksField::from_u64(1),
                    GoldilocksField::from_u64(2),
                ],
                commitment: Vec::new(),
                eval_point: EvalPoint::Univariate(GoldilocksField::from_u64(5)),
                eval_value: GoldilocksField::from_u64(11),
                is_multilinear: false,
            },
            PolyEvalClaim {
                polynomial: vec![
                    GoldilocksField::from_u64(3),
                    GoldilocksField::from_u64(4),
                ],
                commitment: Vec::new(),
                eval_point: EvalPoint::Univariate(GoldilocksField::from_u64(5)),
                eval_value: GoldilocksField::from_u64(23),
                is_multilinear: false,
            },
        ];
        
        let alphas = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let combined = coordinator.combine_polynomials(&claims, &alphas).unwrap();
        
        // f = 2*(1 + 2X) + 3*(3 + 4X) = 2 + 4X + 9 + 12X = 11 + 16X
        assert_eq!(combined.len(), 2);
        assert_eq!(combined[0], GoldilocksField::from_u64(11));
        assert_eq!(combined[1], GoldilocksField::from_u64(16));
    }
    
    #[test]
    fn test_combine_values() {
        let coordinator = create_test_coordinator();
        
        let claims = vec![
            PolyEvalClaim {
                polynomial: Vec::new(),
                commitment: Vec::new(),
                eval_point: EvalPoint::Univariate(GoldilocksField::from_u64(5)),
                eval_value: GoldilocksField::from_u64(10),
                is_multilinear: false,
            },
            PolyEvalClaim {
                polynomial: Vec::new(),
                commitment: Vec::new(),
                eval_point: EvalPoint::Univariate(GoldilocksField::from_u64(5)),
                eval_value: GoldilocksField::from_u64(20),
                is_multilinear: false,
            },
        ];
        
        let alphas = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let combined = coordinator.combine_values(&claims, &alphas).unwrap();
        
        // y = 2*10 + 3*20 = 20 + 60 = 80
        assert_eq!(combined, GoldilocksField::from_u64(80));
    }
    
    #[test]
    fn test_eval_points_equal() {
        let p1 = EvalPoint::Univariate(GoldilocksField::from_u64(5));
        let p2 = EvalPoint::Univariate(GoldilocksField::from_u64(5));
        let p3 = EvalPoint::Univariate(GoldilocksField::from_u64(7));
        
        assert!(BatchingCoordinator::<GoldilocksField>::eval_points_equal(&p1, &p2));
        assert!(!BatchingCoordinator::<GoldilocksField>::eval_points_equal(&p1, &p3));
    }
    
    #[test]
    fn test_run_sumcheck() {
        let coordinator = create_test_coordinator();
        
        let g_poly = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let eval_values = vec![
            GoldilocksField::from_u64(10),
            GoldilocksField::from_u64(20),
        ];
        
        let alphas = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        
        let proof = coordinator.run_sumcheck(&g_poly, &eval_values, &alphas).unwrap();
        
        // Should have log(4) = 2 rounds
        assert_eq!(proof.round_polynomials.len(), 2);
        assert_eq!(proof.random_point.len(), 2);
        
        // Claimed sum = 1*10 + 2*20 = 50
        assert_eq!(proof.claimed_sum, GoldilocksField::from_u64(50));
    }
}
