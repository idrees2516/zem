// Main Polynomial Commitment Scheme Interface for HyperWolf
// Implements high-level PCS operations: setup, commit, open, prove_eval, verify_eval
// Per HyperWolf paper Requirements 1 and 14
//
// This module provides the main user-facing API for HyperWolf PCS,
// supporting both univariate and multilinear polynomials with:
// - O(N) prover time
// - O(log N) verification time
// - O(log N) proof size (without LaBRADOR)
// - Exact ℓ₂-soundness under standard M-SIS assumption

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing, IntegerRingMap, GadgetDecomposition};
use crate::fiat_shamir::hash_oracle::HashOracle;
use super::{
    HyperWolfParams,
    HyperWolfProof,
    EvaluationProof,
    GuardedIPA,
    AuxiliaryVectors,
    LeveledCommitment,
};
use std::fmt;

/// Polynomial representation for PCS
/// 
/// Supports both univariate and multilinear polynomials
#[derive(Clone, Debug)]
pub enum Polynomial<F: Field> {
    /// Univariate polynomial f(X) = Σᵢ₌₀^{N-1} fᵢXⁱ
    Univariate {
        /// Coefficients in monomial basis
        coefficients: Vec<F>,
        /// Degree bound N
        degree_bound: usize,
    },
    
    /// Multilinear polynomial f(X₀, ..., X_{ℓ-1})
    /// Represented by evaluations on Boolean hypercube {0,1}^ℓ
    Multilinear {
        /// Evaluations on Boolean hypercube
        evaluations: Vec<F>,
        /// Number of variables ℓ
        num_vars: usize,
    },
}

/// Evaluation point for polynomial
#[derive(Clone, Debug)]
pub enum EvalPoint<F: Field> {
    /// Univariate evaluation at point u
    Univariate(F),
    
    /// Multilinear evaluation at point (u₀, ..., u_{ℓ-1})
    Multilinear(Vec<F>),
}

/// Commitment to polynomial
#[derive(Clone, Debug)]
pub struct Commitment<F: Field> {
    /// Commitment value cm = F_{k-1,0}(s⃗)
    pub value: Vec<RingElement<F>>,
    
    /// Commitment level (k-1 for top-level)
    pub level: usize,
}

/// Commitment state (for prover)
/// 
/// Contains witness and auxiliary information needed for proving
#[derive(Clone, Debug)]
pub struct CommitmentState<F: Field> {
    /// Original polynomial
    pub polynomial: Polynomial<F>,
    
    /// Witness vector s⃗ ∈ R_q^n after MR and G^{-1}
    pub witness: Vec<RingElement<F>>,
    
    /// ℓ₂-norm squared b = ∥s⃗∥₂²
    pub norm_squared: RingElement<F>,
    
    /// Infinity norm bound β₂
    pub infinity_bound: f64,
}

/// Error types for PCS operations
#[derive(Debug, Clone)]
pub enum PCSError {
    /// Setup error
    SetupError {
        reason: String,
    },
    
    /// Commitment error
    CommitmentError {
        reason: String,
    },
    
    /// Opening error
    OpeningError {
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
    
    /// Invalid polynomial
    InvalidPolynomial {
        reason: String,
    },
    
    /// Invalid evaluation point
    InvalidEvalPoint {
        reason: String,
    },
    
    /// Parameter error
    ParameterError {
        reason: String,
    },
    
    /// Dimension mismatch
    DimensionMismatch {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for PCSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PCSError::SetupError { reason } => {
                write!(f, "Setup error: {}", reason)
            }
            PCSError::CommitmentError { reason } => {
                write!(f, "Commitment error: {}", reason)
            }
            PCSError::OpeningError { reason } => {
                write!(f, "Opening error: {}", reason)
            }
            PCSError::ProofGenerationError { reason } => {
                write!(f, "Proof generation error: {}", reason)
            }
            PCSError::VerificationError { reason } => {
                write!(f, "Verification error: {}", reason)
            }
            PCSError::InvalidPolynomial { reason } => {
                write!(f, "Invalid polynomial: {}", reason)
            }
            PCSError::InvalidEvalPoint { reason } => {
                write!(f, "Invalid evaluation point: {}", reason)
            }
            PCSError::ParameterError { reason } => {
                write!(f, "Parameter error: {}", reason)
            }
            PCSError::DimensionMismatch { expected, actual } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for PCSError {}

impl<F: Field> Polynomial<F> {
    /// Create univariate polynomial from coefficients
    /// 
    /// # Arguments
    /// * `coefficients` - Coefficients in monomial basis [f₀, f₁, ..., f_{N-1}]
    /// * `degree_bound` - Degree bound N (must be power of 2)
    pub fn new_univariate(coefficients: Vec<F>, degree_bound: usize) -> Result<Self, PCSError> {
        if !degree_bound.is_power_of_two() {
            return Err(PCSError::InvalidPolynomial {
                reason: format!("Degree bound must be power of 2, got {}", degree_bound),
            });
        }
        
        if coefficients.len() > degree_bound {
            return Err(PCSError::InvalidPolynomial {
                reason: format!(
                    "Too many coefficients: {} > degree bound {}",
                    coefficients.len(),
                    degree_bound
                ),
            });
        }
        
        // Pad with zeros if needed
        let mut padded_coeffs = coefficients;
        padded_coeffs.resize(degree_bound, F::zero());
        
        Ok(Self::Univariate {
            coefficients: padded_coeffs,
            degree_bound,
        })
    }
    
    /// Create multilinear polynomial from evaluations
    /// 
    /// # Arguments
    /// * `evaluations` - Evaluations on Boolean hypercube {0,1}^ℓ
    /// * `num_vars` - Number of variables ℓ
    pub fn new_multilinear(evaluations: Vec<F>, num_vars: usize) -> Result<Self, PCSError> {
        let expected_size = 1 << num_vars;
        
        if evaluations.len() != expected_size {
            return Err(PCSError::InvalidPolynomial {
                reason: format!(
                    "Evaluations size {} doesn't match 2^{} = {}",
                    evaluations.len(),
                    num_vars,
                    expected_size
                ),
            });
        }
        
        Ok(Self::Multilinear {
            evaluations,
            num_vars,
        })
    }
    
    /// Evaluate polynomial at point
    pub fn evaluate(&self, point: &EvalPoint<F>) -> Result<F, PCSError> {
        match (self, point) {
            (Self::Univariate { coefficients, .. }, EvalPoint::Univariate(u)) => {
                // Horner's method: f(u) = f₀ + u(f₁ + u(f₂ + ...))
                let mut result = F::zero();
                for coeff in coefficients.iter().rev() {
                    result = result.mul(u).add(coeff);
                }
                Ok(result)
            }
            (Self::Multilinear { evaluations, num_vars }, EvalPoint::Multilinear(u_vec)) => {
                if u_vec.len() != *num_vars {
                    return Err(PCSError::InvalidEvalPoint {
                        reason: format!(
                            "Evaluation point has {} coordinates, expected {}",
                            u_vec.len(),
                            num_vars
                        ),
                    });
                }
                
                // Multilinear evaluation using tensor product
                let mut result = evaluations.clone();
                
                for (i, &u_i) in u_vec.iter().enumerate() {
                    let half_len = result.len() / 2;
                    let mut new_result = Vec::with_capacity(half_len);
                    
                    for j in 0..half_len {
                        // Interpolate: (1-u_i) * result[j] + u_i * result[j + half_len]
                        let one_minus_u = F::one().sub(&u_i);
                        let term1 = one_minus_u.mul(&result[j]);
                        let term2 = u_i.mul(&result[j + half_len]);
                        new_result.push(term1.add(&term2));
                    }
                    
                    result = new_result;
                }
                
                Ok(result[0])
            }
            _ => Err(PCSError::InvalidEvalPoint {
                reason: "Polynomial type doesn't match evaluation point type".to_string(),
            }),
        }
    }
    
    /// Get coefficient vector
    pub fn to_coefficient_vector(&self) -> Vec<F> {
        match self {
            Self::Univariate { coefficients, .. } => coefficients.clone(),
            Self::Multilinear { evaluations, .. } => evaluations.clone(),
        }
    }
    
    /// Get degree bound
    pub fn degree_bound(&self) -> usize {
        match self {
            Self::Univariate { degree_bound, .. } => *degree_bound,
            Self::Multilinear { num_vars, .. } => 1 << num_vars,
        }
    }
    
    /// Check if univariate
    pub fn is_univariate(&self) -> bool {
        matches!(self, Self::Univariate { .. })
    }
    
    /// Check if multilinear
    pub fn is_multilinear(&self) -> bool {
        matches!(self, Self::Multilinear { .. })
    }
}

/// Main HyperWolf PCS implementation
/// 
/// Provides setup, commit, open, prove_eval, and verify_eval operations
pub struct HyperWolfPCS;

impl HyperWolfPCS {
    /// Setup: Generate public parameters
    /// 
    /// Returns pp = ((Aᵢ ∈ R_q^{κ×2κι})_{i∈[1,k-1]}, A₀ ∈ R_q^{κ×2ι})
    /// 
    /// # Arguments
    /// * `security_param` - Security parameter λ (typically 128)
    /// * `degree_bound` - Polynomial degree bound N (must be power of 2)
    /// * `ring_dim` - Ring dimension d (must be 64 for standard config)
    /// 
    /// # Returns
    /// HyperWolf parameters with validated security properties
    /// 
    /// Per HyperWolf paper Requirement 1.1
    pub fn setup<F: Field>(
        security_param: usize,
        degree_bound: usize,
        ring_dim: usize,
    ) -> Result<HyperWolfParams<F>, PCSError> {
        // Generate parameters
        let params = HyperWolfParams::new(security_param, degree_bound, ring_dim)
            .map_err(|e| PCSError::SetupError {
                reason: format!("Parameter generation failed: {}", e),
            })?;
        
        // Validate all security properties
        params.validate_all()
            .map_err(|e| PCSError::SetupError {
                reason: format!("Parameter validation failed: {}", e),
            })?;
        
        Ok(params)
    }
    
    /// Commit to polynomial
    /// 
    /// Computes cm = F_{k-1,0}(s⃗) where s⃗ = G^{-1}_{b,N/d}(MR(f⃗))
    /// 
    /// # Arguments
    /// * `params` - Public parameters from setup
    /// * `polynomial` - Polynomial to commit to
    /// 
    /// # Returns
    /// (Commitment, CommitmentState) where state is needed for proving
    /// 
    /// Per HyperWolf paper Requirements 1.2-1.3
    pub fn commit<F: Field>(
        params: &HyperWolfParams<F>,
        polynomial: &Polynomial<F>,
    ) -> Result<(Commitment<F>, CommitmentState<F>), PCSError> {
        let ring = params.ring();
        
        // Validate polynomial degree bound
        if polynomial.degree_bound() != params.degree_bound {
            return Err(PCSError::InvalidPolynomial {
                reason: format!(
                    "Polynomial degree bound {} doesn't match params {}",
                    polynomial.degree_bound(),
                    params.degree_bound
                ),
            });
        }
        
        // Step 1: Convert polynomial to coefficient vector f⃗
        let coeff_vector = polynomial.to_coefficient_vector();
        
        // Step 2: Apply integer-to-ring mapping MR: Z_q^{Nd} → R_q^N
        let ring_vector = Self::integer_to_ring_mapping(&coeff_vector, params.ring_dim);
        
        // Step 3: Apply gadget decomposition G^{-1}_{b,N/d}
        let witness = Self::gadget_decomposition(&ring_vector, params)?;
        
        // Step 4: Compute leveled commitment cm = F_{k-1,0}(s⃗)
        let commitment_value = Self::compute_leveled_commitment(&witness, params)?;
        
        // Step 5: Compute norm bounds for proving
        let norm_squared = Self::compute_norm_squared(&witness, ring);
        let infinity_bound = params.infinity_bound;
        
        let commitment = Commitment {
            value: commitment_value,
            level: params.num_rounds - 1,
        };
        
        let state = CommitmentState {
            polynomial: polynomial.clone(),
            witness,
            norm_squared,
            infinity_bound,
        };
        
        Ok((commitment, state))
    }
    
    /// Open commitment to verify polynomial
    /// 
    /// Verifies that F_{k-1,0}(s⃗) = cm where s⃗ is derived from f
    /// 
    /// # Arguments
    /// * `params` - Public parameters
    /// * `commitment` - Commitment to verify
    /// * `polynomial` - Claimed polynomial
    /// * `state` - Commitment state from commit
    /// 
    /// # Returns
    /// true if opening is valid, false otherwise
    /// 
    /// Per HyperWolf paper Requirement 1.4
    pub fn open<F: Field>(
        params: &HyperWolfParams<F>,
        commitment: &Commitment<F>,
        polynomial: &Polynomial<F>,
        state: &CommitmentState<F>,
    ) -> Result<bool, PCSError> {
        let ring = params.ring();
        
        // Verify polynomial matches state
        if polynomial.to_coefficient_vector() != state.polynomial.to_coefficient_vector() {
            return Ok(false);
        }
        
        // Recompute commitment from witness
        let recomputed_cm = Self::compute_leveled_commitment(&state.witness, params)?;
        
        // Verify commitment matches
        if recomputed_cm.len() != commitment.value.len() {
            return Ok(false);
        }
        
        for (computed, claimed) in recomputed_cm.iter().zip(commitment.value.iter()) {
            if !ring.equal(computed, claimed) {
                return Ok(false);
            }
        }
        
        // Verify witness norm bounds
        let actual_infinity_norm = Self::compute_infinity_norm(&state.witness, ring);
        if actual_infinity_norm > state.infinity_bound {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Prove evaluation: f(u) = v or f(u⃗) = v
    /// 
    /// Runs k-round protocol to generate proof
    /// 
    /// # Arguments
    /// * `params` - Public parameters
    /// * `commitment` - Commitment to polynomial
    /// * `polynomial` - Polynomial (for prover)
    /// * `eval_point` - Evaluation point u or u⃗
    /// * `eval_value` - Claimed evaluation value v
    /// * `state` - Commitment state from commit
    /// 
    /// # Returns
    /// HyperWolf proof π
    /// 
    /// Per HyperWolf paper Requirement 1.5
    pub fn prove_eval<F: Field>(
        params: &HyperWolfParams<F>,
        commitment: &Commitment<F>,
        polynomial: &Polynomial<F>,
        eval_point: &EvalPoint<F>,
        eval_value: F,
        state: &CommitmentState<F>,
    ) -> Result<HyperWolfProof<F>, PCSError> {
        let ring = params.ring();
        
        // Verify evaluation is correct
        let computed_value = polynomial.evaluate(eval_point)
            .map_err(|e| PCSError::ProofGenerationError {
                reason: format!("Evaluation failed: {}", e),
            })?;
        
        if computed_value != eval_value {
            return Err(PCSError::ProofGenerationError {
                reason: format!(
                    "Evaluation mismatch: computed {} ≠ claimed {}",
                    computed_value.to_canonical_u64(),
                    eval_value.to_canonical_u64()
                ),
            });
        }
        
        // Construct auxiliary vectors for evaluation point
        let auxiliary = Self::construct_auxiliary_vectors(eval_point, params)?;
        
        // Initialize Fiat-Shamir oracle
        let mut oracle = HashOracle::new();
        
        // Add public inputs to transcript
        Self::add_public_inputs_to_transcript(
            &mut oracle,
            commitment,
            eval_point,
            eval_value,
            params,
        );
        
        // Generate k-round proof
        let proof = HyperWolfProof::generate(
            &state.witness,
            &auxiliary,
            eval_value,
            &state.norm_squared,
            &commitment.value,
            params,
            &mut oracle,
        ).map_err(|e| PCSError::ProofGenerationError {
            reason: format!("Proof generation failed: {}", e),
        })?;
        
        Ok(proof)
    }
    
    /// Verify evaluation proof
    /// 
    /// Verifies k-round proof for f(u) = v or f(u⃗) = v
    /// 
    /// # Arguments
    /// * `params` - Public parameters
    /// * `commitment` - Commitment to polynomial
    /// * `eval_point` - Evaluation point u or u⃗
    /// * `eval_value` - Claimed evaluation value v
    /// * `proof` - HyperWolf proof π
    /// 
    /// # Returns
    /// true if proof is valid, false otherwise
    /// 
    /// Per HyperWolf paper Requirement 1.6
    pub fn verify_eval<F: Field>(
        params: &HyperWolfParams<F>,
        commitment: &Commitment<F>,
        eval_point: &EvalPoint<F>,
        eval_value: F,
        proof: &HyperWolfProof<F>,
    ) -> Result<bool, PCSError> {
        // Construct auxiliary vectors for evaluation point
        let auxiliary = Self::construct_auxiliary_vectors(eval_point, params)?;
        
        // Initialize Fiat-Shamir oracle
        let mut oracle = HashOracle::new();
        
        // Add public inputs to transcript
        Self::add_public_inputs_to_transcript(
            &mut oracle,
            commitment,
            eval_point,
            eval_value,
            params,
        );
        
        // Compute norm bound for verification
        let norm_bound_squared = Self::compute_norm_bound_squared(params);
        
        // Verify k-round proof
        proof.verify(
            &auxiliary,
            eval_value,
            &norm_bound_squared,
            &commitment.value,
            params,
            &mut oracle,
        ).map_err(|e| PCSError::VerificationError {
            reason: format!("Proof verification failed: {}", e),
        })?;
        
        Ok(true)
    }
    
    // ==================== Helper Methods ====================
    
    /// Apply integer-to-ring mapping MR: Z_q^{Nd} → R_q^N
    /// 
    /// Groups d consecutive coefficients into each ring element
    /// 
    /// Per HyperWolf paper Requirement 21
    fn integer_to_ring_mapping<F: Field>(
        coeffs: &[F],
        ring_dim: usize,
    ) -> Vec<RingElement<F>> {
        let num_elements = (coeffs.len() + ring_dim - 1) / ring_dim;
        let mut ring_vector = Vec::with_capacity(num_elements);
        
        for i in 0..num_elements {
            let start = i * ring_dim;
            let end = (start + ring_dim).min(coeffs.len());
            
            let mut element_coeffs = coeffs[start..end].to_vec();
            // Pad with zeros if needed
            while element_coeffs.len() < ring_dim {
                element_coeffs.push(F::zero());
            }
            
            ring_vector.push(RingElement::from_coeffs(element_coeffs));
        }
        
        ring_vector
    }
    
    /// Apply gadget decomposition G^{-1}_{b,m}
    /// 
    /// Decomposes each ring element into ι components in base b
    /// 
    /// Per HyperWolf paper Requirement 20
    fn gadget_decomposition<F: Field>(
        ring_vector: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, PCSError> {
        let basis = params.decomposition_basis;
        let iota = params.decomposition_length;
        let ring_dim = params.ring_dim;
        
        let mut decomposed = Vec::with_capacity(ring_vector.len() * iota);
        
        for element in ring_vector {
            let coeffs = element.coefficients();
            
            // Decompose each coefficient in base b
            for i in 0..iota {
                let mut decomp_coeffs = Vec::with_capacity(ring_dim);
                
                for coeff in coeffs {
                    // Extract i-th digit in base b
                    let val = coeff.to_canonical_u64();
                    let digit = (val / basis.pow(i as u32)) % basis;
                    decomp_coeffs.push(F::from_u64(digit));
                }
                
                decomposed.push(RingElement::from_coeffs(decomp_coeffs));
            }
        }
        
        Ok(decomposed)
    }
    
    /// Compute leveled commitment F_{k-1,0}(s⃗)
    /// 
    /// Uses hierarchical commitment structure
    /// 
    /// Per HyperWolf paper Requirement 5
    fn compute_leveled_commitment<F: Field>(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, PCSError> {
        let ring = params.ring();
        let k = params.num_rounds;
        
        // Get top-level matrix A_{k-1}
        let matrix = params.get_matrix(k - 1)
            .ok_or_else(|| PCSError::CommitmentError {
                reason: format!("Matrix A_{} not found", k - 1),
            })?;
        
        // Compute A_{k-1} · s⃗ mod q
        let mut result = Vec::with_capacity(matrix.len());
        
        for row in matrix {
            if row.len() != witness.len() {
                return Err(PCSError::DimensionMismatch {
                    expected: row.len(),
                    actual: witness.len(),
                });
            }
            
            let mut sum = RingElement::zero(ring.dimension());
            
            for (j, elem) in row.iter().enumerate() {
                let product = ring.mul(elem, &witness[j]);
                sum = ring.add(&sum, &product);
            }
            
            result.push(sum);
        }
        
        Ok(result)
    }
    
    /// Compute ℓ₂-norm squared: ⟨s⃗, σ⁻¹(s⃗)⟩
    fn compute_norm_squared<F: Field>(
        witness: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> RingElement<F> {
        let mut result = RingElement::zero(ring.dimension());
        
        for elem in witness {
            let conjugated = ring.conjugate(elem);
            let product = ring.mul(elem, &conjugated);
            result = ring.add(&result, &product);
        }
        
        result
    }
    
    /// Compute infinity norm ∥s⃗∥∞
    fn compute_infinity_norm<F: Field>(
        witness: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> f64 {
        let mut max_norm = 0.0;
        
        for element in witness {
            let element_norm = ring.infinity_norm(element);
            if element_norm > max_norm {
                max_norm = element_norm;
            }
        }
        
        max_norm
    }
    
    /// Construct auxiliary vectors for evaluation point
    fn construct_auxiliary_vectors<F: Field>(
        eval_point: &EvalPoint<F>,
        params: &HyperWolfParams<F>,
    ) -> Result<AuxiliaryVectors<F>, PCSError> {
        let ring = params.ring();
        let ring_dim = params.ring_dim;
        let num_rounds = params.num_rounds;
        
        match eval_point {
            EvalPoint::Univariate(u) => {
                AuxiliaryVectors::new_univariate(*u, ring_dim, num_rounds, ring)
                    .map_err(|e| PCSError::ProofGenerationError {
                        reason: format!("Auxiliary vector construction failed: {}", e),
                    })
            }
            EvalPoint::Multilinear(u_vec) => {
                AuxiliaryVectors::new_multilinear(u_vec, ring_dim, num_rounds, ring)
                    .map_err(|e| PCSError::ProofGenerationError {
                        reason: format!("Auxiliary vector construction failed: {}", e),
                    })
            }
        }
    }
    
    /// Add public inputs to Fiat-Shamir transcript
    fn add_public_inputs_to_transcript<F: Field>(
        oracle: &mut HashOracle,
        commitment: &Commitment<F>,
        eval_point: &EvalPoint<F>,
        eval_value: F,
        params: &HyperWolfParams<F>,
    ) {
        // Add commitment
        for elem in &commitment.value {
            for coeff in elem.coefficients() {
                oracle.absorb(&coeff.to_canonical_u64().to_le_bytes());
            }
        }
        
        // Add evaluation point
        match eval_point {
            EvalPoint::Univariate(u) => {
                oracle.absorb(&u.to_canonical_u64().to_le_bytes());
            }
            EvalPoint::Multilinear(u_vec) => {
                for u in u_vec {
                    oracle.absorb(&u.to_canonical_u64().to_le_bytes());
                }
            }
        }
        
        // Add evaluation value
        oracle.absorb(&eval_value.to_canonical_u64().to_le_bytes());
        
        // Add parameters
        oracle.absorb(&params.security_param.to_le_bytes());
        oracle.absorb(&params.degree_bound.to_le_bytes());
        oracle.absorb(&params.ring_dim.to_le_bytes());
    }
    
    /// Compute norm bound squared for verification
    fn compute_norm_bound_squared<F: Field>(
        params: &HyperWolfParams<F>,
    ) -> RingElement<F> {
        // β₁² = β₂² · nd
        let beta_2_squared = params.infinity_bound * params.infinity_bound;
        let n = params.witness_dimension();
        let d = params.ring_dim;
        let bound_squared = beta_2_squared * (n * d) as f64;
        
        RingElement::from_constant(
            F::from_u64(bound_squared as u64),
            params.ring_dim,
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use rand::{Rng, thread_rng};
    
    fn create_random_univariate(degree_bound: usize) -> Polynomial<GoldilocksField> {
        let mut rng = thread_rng();
        let coeffs: Vec<GoldilocksField> = (0..degree_bound)
            .map(|_| GoldilocksField::from_u64(rng.gen::<u64>() % 1000))
            .collect();
        
        Polynomial::new_univariate(coeffs, degree_bound).unwrap()
    }
    
    fn create_random_multilinear(num_vars: usize) -> Polynomial<GoldilocksField> {
        let mut rng = thread_rng();
        let size = 1 << num_vars;
        let evals: Vec<GoldilocksField> = (0..size)
            .map(|_| GoldilocksField::from_u64(rng.gen::<u64>() % 1000))
            .collect();
        
        Polynomial::new_multilinear(evals, num_vars).unwrap()
    }
    
    #[test]
    fn test_polynomial_univariate_creation() {
        let coeffs = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let poly = Polynomial::new_univariate(coeffs.clone(), 4);
        assert!(poly.is_ok());
        
        let poly = poly.unwrap();
        assert!(poly.is_univariate());
        assert_eq!(poly.degree_bound(), 4);
        
        // Should be padded to degree bound
        let coeff_vec = poly.to_coefficient_vector();
        assert_eq!(coeff_vec.len(), 4);
        assert_eq!(coeff_vec[3], GoldilocksField::zero());
    }
    
    #[test]
    fn test_polynomial_univariate_evaluation() {
        // f(X) = 1 + 2X + 3X²
        let coeffs = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let poly = Polynomial::new_univariate(coeffs, 4).unwrap();
        let point = EvalPoint::Univariate(GoldilocksField::from_u64(2));
        
        // f(2) = 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17
        let result = poly.evaluate(&point).unwrap();
        assert_eq!(result.to_canonical_u64(), 17);
    }
    
    #[test]
    fn test_polynomial_multilinear_creation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let poly = Polynomial::new_multilinear(evals, 2);
        assert!(poly.is_ok());
        
        let poly = poly.unwrap();
        assert!(poly.is_multilinear());
        assert_eq!(poly.degree_bound(), 4);
    }
    
    #[test]
    fn test_polynomial_multilinear_evaluation() {
        // f(X₀, X₁) with evaluations [1, 2, 3, 4] on {0,1}²
        let evals = vec![
            GoldilocksField::from_u64(1),  // f(0,0) = 1
            GoldilocksField::from_u64(2),  // f(1,0) = 2
            GoldilocksField::from_u64(3),  // f(0,1) = 3
            GoldilocksField::from_u64(4),  // f(1,1) = 4
        ];
        
        let poly = Polynomial::new_multilinear(evals, 2).unwrap();
        
        // Evaluate at (0, 0)
        let point = EvalPoint::Multilinear(vec![
            GoldilocksField::zero(),
            GoldilocksField::zero(),
        ]);
        let result = poly.evaluate(&point).unwrap();
        assert_eq!(result.to_canonical_u64(), 1);
        
        // Evaluate at (1, 1)
        let point = EvalPoint::Multilinear(vec![
            GoldilocksField::one(),
            GoldilocksField::one(),
        ]);
        let result = poly.evaluate(&point).unwrap();
        assert_eq!(result.to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_setup() {
        let result = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64);
        assert!(result.is_ok(), "Setup should succeed with valid parameters");
        
        let params = result.unwrap();
        assert_eq!(params.security_param, 128);
        assert_eq!(params.degree_bound, 1024);
        assert_eq!(params.ring_dim, 64);
    }
    
    #[test]
    fn test_setup_invalid_params() {
        // Invalid security parameter
        let result = HyperWolfPCS::setup::<GoldilocksField>(256, 1024, 64);
        assert!(result.is_err());
        
        // Invalid ring dimension
        let result = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 32);
        assert!(result.is_err());
        
        // Invalid degree bound (not power of 2)
        let result = HyperWolfPCS::setup::<GoldilocksField>(128, 1000, 64);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_commit_univariate() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let poly = create_random_univariate(1024);
        
        let result = HyperWolfPCS::commit(&params, &poly);
        assert!(result.is_ok(), "Commit should succeed for valid polynomial");
        
        let (commitment, state) = result.unwrap();
        assert_eq!(commitment.level, params.num_rounds - 1);
        assert!(!commitment.value.is_empty());
        assert!(!state.witness.is_empty());
    }
    
    #[test]
    fn test_commit_multilinear() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let poly = create_random_multilinear(10); // 2^10 = 1024
        
        let result = HyperWolfPCS::commit(&params, &poly);
        assert!(result.is_ok(), "Commit should succeed for valid polynomial");
        
        let (commitment, state) = result.unwrap();
        assert_eq!(commitment.level, params.num_rounds - 1);
        assert!(!commitment.value.is_empty());
    }
    
    #[test]
    fn test_commit_wrong_degree_bound() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let poly = create_random_univariate(512); // Wrong degree bound
        
        let result = HyperWolfPCS::commit(&params, &poly);
        assert!(result.is_err(), "Commit should fail for wrong degree bound");
    }
    
    #[test]
    fn test_open() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let poly = create_random_univariate(1024);
        
        let (commitment, state) = HyperWolfPCS::commit(&params, &poly).unwrap();
        
        // Opening with correct polynomial should succeed
        let result = HyperWolfPCS::open(&params, &commitment, &poly, &state);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Opening should verify for correct polynomial");
    }
    
    #[test]
    fn test_open_wrong_polynomial() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let poly = create_random_univariate(1024);
        let wrong_poly = create_random_univariate(1024);
        
        let (commitment, state) = HyperWolfPCS::commit(&params, &poly).unwrap();
        
        // Opening with wrong polynomial should fail
        let result = HyperWolfPCS::open(&params, &commitment, &wrong_poly, &state);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Opening should fail for wrong polynomial");
    }
    
    #[test]
    fn test_integer_to_ring_mapping() {
        let coeffs = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let ring_vector = HyperWolfPCS::integer_to_ring_mapping(&coeffs, 2);
        
        // Should create 2 ring elements, each with 2 coefficients
        assert_eq!(ring_vector.len(), 2);
        assert_eq!(ring_vector[0].coefficients()[0], GoldilocksField::from_u64(1));
        assert_eq!(ring_vector[0].coefficients()[1], GoldilocksField::from_u64(2));
        assert_eq!(ring_vector[1].coefficients()[0], GoldilocksField::from_u64(3));
        assert_eq!(ring_vector[1].coefficients()[1], GoldilocksField::from_u64(4));
    }
    
    #[test]
    fn test_gadget_decomposition() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        
        let ring_vector = vec![
            RingElement::from_constant(GoldilocksField::from_u64(42), 64),
        ];
        
        let result = HyperWolfPCS::gadget_decomposition(&ring_vector, &params);
        assert!(result.is_ok());
        
        let decomposed = result.unwrap();
        // Should have ι elements
        assert_eq!(decomposed.len(), params.decomposition_length);
    }
    
    #[test]
    fn test_compute_norm_squared() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let ring = params.ring();
        
        let witness = vec![
            RingElement::from_constant(GoldilocksField::from_u64(1), 64),
            RingElement::from_constant(GoldilocksField::from_u64(2), 64),
        ];
        
        let norm_squared = HyperWolfPCS::compute_norm_squared(&witness, ring);
        
        // For constant ring elements, ⟨s⃗, σ⁻¹(s⃗)⟩ = Σᵢ sᵢ²
        // = 1² + 2² = 5
        let ct = ring.constant_term(&norm_squared);
        assert_eq!(ct.to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_compute_infinity_norm() {
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        let ring = params.ring();
        
        let witness = vec![
            RingElement::from_constant(GoldilocksField::from_u64(10), 64),
            RingElement::from_constant(GoldilocksField::from_u64(5), 64),
        ];
        
        let infinity_norm = HyperWolfPCS::compute_infinity_norm(&witness, ring);
        
        // Should be max(10, 5) = 10
        assert_eq!(infinity_norm, 10.0);
    }
    
    #[test]
    fn test_full_pcs_workflow_univariate() {
        // Setup
        let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1024, 64).unwrap();
        
        // Create polynomial f(X) = 1 + 2X + 3X²
        let coeffs = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        let poly = Polynomial::new_univariate(coeffs, 1024).unwrap();
        
        // Commit
        let (commitment, state) = HyperWolfPCS::commit(&params, &poly).unwrap();
        
        // Open
        let open_result = HyperWolfPCS::open(&params, &commitment, &poly, &state).unwrap();
        assert!(open_result, "Opening should succeed");
        
        // Evaluate at point u = 2
        let eval_point = EvalPoint::Univariate(GoldilocksField::from_u64(2));
        let eval_value = poly.evaluate(&eval_point).unwrap();
        
        println!("Full PCS workflow test:");
        println!("  Polynomial degree bound: {}", poly.degree_bound());
        println!("  Evaluation point: 2");
        println!("  Evaluation value: {}", eval_value.to_canonical_u64());
        println!("  Commitment size: {} ring elements", commitment.value.len());
        println!("  Witness size: {} ring elements", state.witness.len());
    }
    
    #[test]
    fn test_different_degree_bounds() {
        for log_n in 10..=12 {
            let degree_bound = 1 << log_n;
            let params = HyperWolfPCS::setup::<GoldilocksField>(128, degree_bound, 64).unwrap();
            let poly = create_random_univariate(degree_bound);
            
            let result = HyperWolfPCS::commit(&params, &poly);
            assert!(result.is_ok(), "Commit should succeed for N = 2^{}", log_n);
            
            let (commitment, state) = result.unwrap();
            let open_result = HyperWolfPCS::open(&params, &commitment, &poly, &state).unwrap();
            assert!(open_result, "Opening should succeed for N = 2^{}", log_n);
            
            println!("N = 2^{}: commitment size = {} ring elements", 
                log_n, commitment.value.len());
        }
    }
}
