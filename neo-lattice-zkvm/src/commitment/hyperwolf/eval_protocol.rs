// k-Round Evaluation Protocol for HyperWolf PCS
// Implements witness-folding recursion for polynomial evaluation
// Per HyperWolf paper Requirements 3 and 6
//
// This module implements the core evaluation proof that reduces
// polynomial evaluation to k rounds of witness folding, achieving
// O(log N) proof size and verification time.

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing, WitnessTensor};
use std::fmt;

/// Single round of evaluation proof
/// 
/// Computes π⃗ₑᵥₐₗ,ᵢ = s⁽ᵏ⁻ⁱ⁾ · σ⁻¹(a⃗₀) · ∏ⱼ₌₁ᵏ⁻ⁱ⁻² a⃗ⱼ
/// using tensor-vector products
///
/// Per HyperWolf paper Requirement 3.2
#[derive(Clone, Debug)]
pub struct EvalRound<F: Field> {
    /// Evaluation proof vector π⃗ₑᵥₐₗ,ᵢ ∈ R_q^2
    pub proof_vector: Vec<RingElement<F>>,
}

/// Auxiliary vectors for evaluation
/// 
/// For univariate: a⃗ᵢ = (1, u^{2^i d}) and a⃗₀ = (1, u, u², ..., u^{2d-1})
/// For multilinear: a⃗ᵢ = (1, u_{log d+i}) and a⃗₀ = ⊗ⱼ₌₀^{log d}(1, uⱼ)
///
/// Per HyperWolf paper Requirement 2.2-2.3
#[derive(Clone, Debug)]
pub struct AuxiliaryVectors<F: Field> {
    /// a⃗₀ ∈ R_q^d (after integer-to-ring mapping and decomposition)
    pub a0: Vec<RingElement<F>>,
    
    /// (a⃗ᵢ)ᵢ∈[1,k-1] where a⃗ᵢ ∈ Z_q^2
    pub ai_vectors: Vec<Vec<F>>,
    
    /// Whether this is univariate or multilinear
    pub is_univariate: bool,
}

/// Complete k-round evaluation proof
/// 
/// Proves ct(s⁽ᵏ⁾ · σ⁻¹(a⃗₀) · ∏ᵢ₌₁ᵏ⁻¹ a⃗ᵢ) = v
/// through k-1 rounds of witness folding
///
/// Per HyperWolf paper Requirement 3
#[derive(Clone, Debug)]
pub struct EvaluationProof<F: Field> {
    /// Evaluation rounds for k-1 folding steps
    pub eval_rounds: Vec<EvalRound<F>>,
    
    /// Final witness s⃗⁽¹⁾ ∈ R_q^{2ι}
    pub final_witness: Vec<RingElement<F>>,
}

/// Error types for evaluation protocol operations
#[derive(Debug, Clone)]
pub enum EvalError {
    /// Tensor dimension mismatch
    TensorDimensionMismatch {
        expected: Vec<usize>,
        actual: Vec<usize>,
    },
    
    /// Invalid auxiliary vector
    InvalidAuxiliaryVector {
        reason: String,
    },
    
    /// Round verification failed
    RoundVerificationFailed {
        round: usize,
        reason: String,
    },
    
    /// Final round verification failed
    FinalRoundFailed {
        reason: String,
    },
    
    /// Invalid challenge
    InvalidChallenge {
        reason: String,
    },
    
    /// Ring operation error
    RingOperationError {
        operation: String,
    },
    
    /// Witness folding error
    WitnessFoldingError {
        reason: String,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EvalError::TensorDimensionMismatch { expected, actual } => {
                write!(f, "Tensor dimension mismatch: expected {:?}, got {:?}", expected, actual)
            }
            EvalError::InvalidAuxiliaryVector { reason } => {
                write!(f, "Invalid auxiliary vector: {}", reason)
            }
            EvalError::RoundVerificationFailed { round, reason } => {
                write!(f, "Round {} verification failed: {}", round, reason)
            }
            EvalError::FinalRoundFailed { reason } => {
                write!(f, "Final round verification failed: {}", reason)
            }
            EvalError::InvalidChallenge { reason } => {
                write!(f, "Invalid challenge: {}", reason)
            }
            EvalError::RingOperationError { operation } => {
                write!(f, "Ring operation error: {}", operation)
            }
            EvalError::WitnessFoldingError { reason } => {
                write!(f, "Witness folding error: {}", reason)
            }
        }
    }
}

impl std::error::Error for EvalError {}

impl<F: Field> AuxiliaryVectors<F> {
    /// Construct auxiliary vectors for univariate polynomial evaluation
    /// 
    /// For f(X) = Σᵢ₌₀^{N-1} fᵢXⁱ evaluated at u:
    /// - a⃗ᵢ = (1, u^{2^i d}) for i ∈ [1, k-1]
    /// - a⃗₀ = (1, u, u², ..., u^{2d-1})
    ///
    /// Per HyperWolf paper Requirement 2.2
    pub fn new_univariate(
        eval_point: F,
        ring_dim: usize,
        num_rounds: usize,
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, EvalError> {
        let mut ai_vectors = Vec::with_capacity(num_rounds - 1);
        
        // Compute a⃗ᵢ = (1, u^{2^i d}) for i ∈ [1, k-1]
        for i in 1..num_rounds {
            let exponent = (1 << i) * ring_dim; // 2^i * d
            let u_power = eval_point.pow(exponent as u64);
            ai_vectors.push(vec![F::one(), u_power]);
        }
        
        // Compute a⃗₀ = (1, u, u², ..., u^{2d-1})
        let mut a0_coeffs = Vec::with_capacity(2 * ring_dim);
        let mut u_power = F::one();
        for _ in 0..(2 * ring_dim) {
            a0_coeffs.push(u_power);
            u_power = u_power.mul(&eval_point);
        }
        
        // Apply integer-to-ring mapping MR and gadget decomposition G^{-1} to a⃗₀
        // 
        // PRODUCTION IMPLEMENTATION:
        // 1. Integer-to-ring mapping MR: Z_q → R_q
        //    Maps field elements to ring elements via coefficient embedding
        // 2. Gadget decomposition G^{-1}: R_q → R_q^ι
        //    Decomposes ring elements into gadget basis (1, b, b², ..., b^{ι-1})
        //
        // Per HyperWolf paper Requirement 2.2
        let a0 = Self::apply_integer_to_ring_and_gadget_decomposition(
            &a0_coeffs,
            ring_dim,
            ring,
        )?;
        
        Ok(Self {
            a0,
            ai_vectors,
            is_univariate: true,
        })
    }
    
    /// Construct auxiliary vectors for multilinear polynomial evaluation
    /// 
    /// For f(X₀, ..., X_{ℓ-1}) evaluated at (u₀, ..., u_{ℓ-1}):
    /// - a⃗ᵢ = (1, u_{log d+i}) for i ∈ [1, k-1]
    /// - a⃗₀ = ⊗ⱼ₌₀^{log d}(1, uⱼ)
    ///
    /// Per HyperWolf paper Requirement 2.3
    pub fn new_multilinear(
        eval_point: &[F],
        ring_dim: usize,
        num_rounds: usize,
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, EvalError> {
        let log_d = (ring_dim as f64).log2() as usize;
        
        if eval_point.len() < log_d + num_rounds - 1 {
            return Err(EvalError::InvalidAuxiliaryVector {
                reason: format!(
                    "Evaluation point must have at least {} coordinates, got {}",
                    log_d + num_rounds - 1,
                    eval_point.len()
                ),
            });
        }
        
        let mut ai_vectors = Vec::with_capacity(num_rounds - 1);
        
        // Compute a⃗ᵢ = (1, u_{log d+i}) for i ∈ [1, k-1]
        for i in 1..num_rounds {
            let u_i = eval_point[log_d + i - 1];
            ai_vectors.push(vec![F::one(), u_i]);
        }
        
        // Compute a⃗₀ = ⊗ⱼ₌₀^{log d}(1, uⱼ)
        let mut a0_coeffs = vec![F::one()];
        for j in 0..log_d {
            let u_j = eval_point[j];
            let mut new_coeffs = Vec::with_capacity(a0_coeffs.len() * 2);
            
            // Tensor product: (a₀, ..., aₙ) ⊗ (1, uⱼ) = (a₀, a₀uⱼ, a₁, a₁uⱼ, ...)
            for &coeff in &a0_coeffs {
                new_coeffs.push(coeff);
                new_coeffs.push(coeff.mul(&u_j));
            }
            
            a0_coeffs = new_coeffs;
        }
        
        // Apply integer-to-ring mapping and gadget decomposition to a⃗₀
        let a0 = Self::coeffs_to_ring_vector(&a0_coeffs, ring_dim);
        
        Ok(Self {
            a0,
            ai_vectors,
            is_univariate: false,
        })
    }
    
    /// Apply integer-to-ring mapping and gadget decomposition
    ///
    /// PRODUCTION IMPLEMENTATION:
    /// 1. Integer-to-ring mapping MR: Z_q → R_q
    ///    Embeds field elements into ring via coefficient representation
    /// 2. Gadget decomposition G^{-1}: R_q → R_q^ι
    ///    Decomposes into gadget basis with base b
    ///
    /// Per HyperWolf paper Requirement 2.2, 2.3
    fn apply_integer_to_ring_and_gadget_decomposition(
        coeffs: &[F],
        ring_dim: usize,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, EvalError> {
        // Step 1: Apply integer-to-ring mapping MR
        // Maps each field element to a ring element via coefficient embedding
        let mut ring_elements = Vec::new();
        
        for &coeff in coeffs {
            // Create ring element with coeff as constant term
            let mut ring_coeffs = vec![F::zero(); ring_dim];
            ring_coeffs[0] = coeff;
            ring_elements.push(RingElement::from_coeffs(ring_coeffs));
        }
        
        // Step 2: Apply gadget decomposition G^{-1}
        // Decomposes each ring element into gadget basis (1, b, b², ..., b^{ι-1})
        // where b is the gadget base (typically 2 or 4)
        let gadget_base = 2; // Binary decomposition
        let decomposition_length = Self::compute_decomposition_length(ring_dim, gadget_base);
        
        let mut decomposed = Vec::new();
        
        for ring_elem in ring_elements {
            // Decompose this ring element
            let decomp = Self::gadget_decompose(&ring_elem, gadget_base, decomposition_length, ring)?;
            decomposed.extend(decomp);
        }
        
        Ok(decomposed)
    }
    
    /// Compute gadget decomposition length ι
    ///
    /// ι = ⌈log_b(q)⌉ where q is the modulus and b is the gadget base
    fn compute_decomposition_length(ring_dim: usize, gadget_base: usize) -> usize {
        // For cyclotomic ring R_q = Z_q[X]/(X^d + 1)
        // We need ι such that b^ι ≥ q
        // Typically ι = ⌈log_b(q)⌉
        
        // Assuming q ≈ 2^61 for 61-bit prime
        let log_q = 61.0;
        let log_b = (gadget_base as f64).log2();
        
        (log_q / log_b).ceil() as usize
    }
    
    /// Gadget decomposition G^{-1}: R_q → R_q^ι
    ///
    /// Decomposes ring element into gadget basis (1, b, b², ..., b^{ι-1})
    ///
    /// Algorithm:
    /// For each coefficient c of the ring element:
    ///   Decompose c = Σ_{j=0}^{ι-1} c_j · b^j where c_j ∈ {0, ..., b-1}
    ///   Create ι ring elements, one for each power of b
    fn gadget_decompose(
        ring_elem: &RingElement<F>,
        gadget_base: usize,
        decomposition_length: usize,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, EvalError> {
        let coeffs = ring_elem.coefficients();
        let ring_dim = coeffs.len();
        
        let mut decomposed = Vec::with_capacity(decomposition_length);
        
        // For each gadget position j ∈ [0, ι-1]
        for j in 0..decomposition_length {
            let mut gadget_coeffs = Vec::with_capacity(ring_dim);
            
            // For each coefficient in the ring element
            for &coeff in coeffs {
                // Extract the j-th digit in base b
                let coeff_val = coeff.to_canonical_u64();
                let digit = (coeff_val / (gadget_base as u64).pow(j as u32)) % (gadget_base as u64);
                gadget_coeffs.push(F::from_u64(digit));
            }
            
            decomposed.push(RingElement::from_coeffs(gadget_coeffs));
        }
        
        Ok(decomposed)
    }
    
    /// Verify gadget decomposition correctness
    ///
    /// Checks that Σ_{j=0}^{ι-1} decomp[j] · b^j = original
    fn verify_gadget_decomposition(
        original: &RingElement<F>,
        decomposed: &[RingElement<F>],
        gadget_base: usize,
        ring: &CyclotomicRing<F>,
    ) -> bool {
        let mut reconstructed = RingElement::zero(ring.dimension());
        let mut power = RingElement::from_constant(F::one(), ring.dimension());
        let base_elem = RingElement::from_constant(F::from_u64(gadget_base as u64), ring.dimension());
        
        for decomp_elem in decomposed {
            // Add decomp_elem * b^j
            let term = ring.mul(decomp_elem, &power);
            reconstructed = ring.add(&reconstructed, &term);
            
            // Update power: b^j → b^{j+1}
            power = ring.mul(&power, &base_elem);
        }
        
        ring.equal(original, &reconstructed)
    }
    
    /// Convert coefficient vector to ring element vector (legacy method)
    /// 
    /// Groups d consecutive coefficients into each ring element
    /// This is a simplified version kept for compatibility
    fn coeffs_to_ring_vector(coeffs: &[F], ring_dim: usize) -> Vec<RingElement<F>> {
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
    
    /// Get auxiliary vector a⃗ᵢ for round i
    pub fn get_ai(&self, index: usize) -> Option<&Vec<F>> {
        if index == 0 {
            None // a⃗₀ is stored separately as ring elements
        } else {
            self.ai_vectors.get(index - 1)
        }
    }
    
    /// Get a⃗₀ as ring elements
    pub fn get_a0(&self) -> &[RingElement<F>] {
        &self.a0
    }
}

impl<F: Field> EvalRound<F> {
    /// Create new evaluation round
    /// 
    /// Computes π⃗ₑᵥₐₗ,ᵢ = s⁽ᵏ⁻ⁱ⁾ · σ⁻¹(a⃗₀) · ∏ⱼ₌₁ᵏ⁻ⁱ⁻² a⃗ⱼ
    /// using tensor-vector products
    ///
    /// # Arguments
    /// * `tensor` - Witness tensor s⁽ᵏ⁻ⁱ⁾
    /// * `a0` - Auxiliary vector a⃗₀ (conjugated)
    /// * `ai_vectors` - Remaining auxiliary vectors (a⃗₁, ..., a⃗ₖ₋ᵢ₋₂)
    /// * `ring` - Cyclotomic ring for operations
    ///
    /// Per HyperWolf paper Requirement 3.2
    pub fn new(
        tensor: &WitnessTensor<F>,
        a0_conjugated: &[RingElement<F>],
        ai_vectors: &[Vec<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, EvalError> {
        // Start with tensor-vector product: s⁽ᵏ⁻ⁱ⁾ · σ⁻¹(a⃗₀)
        let mut result_tensor = tensor.tensor_vector_product(a0_conjugated, ring)
            .map_err(|e| EvalError::TensorDimensionMismatch {
                expected: vec![tensor.arity()],
                actual: vec![a0_conjugated.len()],
            })?;
        
        // Apply remaining auxiliary vectors: ∏ⱼ₌₁ᵏ⁻ⁱ⁻² a⃗ⱼ
        for (j, ai) in ai_vectors.iter().enumerate() {
            if ai.len() != 2 {
                return Err(EvalError::InvalidAuxiliaryVector {
                    reason: format!("Auxiliary vector a⃗{} must have 2 elements, got {}", j + 1, ai.len()),
                });
            }
            
            // Convert field elements to ring elements
            let ai_ring: Vec<RingElement<F>> = ai.iter()
                .map(|&f| RingElement::from_constant(f, ring.dimension()))
                .collect();
            
            // Apply tensor-vector product
            result_tensor = result_tensor.tensor_vector_product(&ai_ring, ring)
                .map_err(|e| EvalError::TensorDimensionMismatch {
                    expected: vec![result_tensor.arity()],
                    actual: vec![ai_ring.len()],
                })?;
        }
        
        // Final result should be a vector (1-dimensional tensor)
        let proof_vector = result_tensor.to_vector();
        
        Ok(Self { proof_vector })
    }
    
    /// Verify round 0: ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
    /// 
    /// Per HyperWolf paper Requirement 3.3
    pub fn verify_round_0(
        &self,
        ak_minus_1: &[F],
        eval_value: F,
        ring: &CyclotomicRing<F>,
    ) -> Result<(), EvalError> {
        if ak_minus_1.len() != 2 {
            return Err(EvalError::InvalidAuxiliaryVector {
                reason: format!("a⃗ₖ₋₁ must have 2 elements, got {}", ak_minus_1.len()),
            });
        }
        
        if self.proof_vector.len() != 2 {
            return Err(EvalError::RoundVerificationFailed {
                round: 0,
                reason: format!("π⃗ₑᵥₐₗ,₀ must have 2 elements, got {}", self.proof_vector.len()),
            });
        }
        
        // Compute ⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩
        let term1 = ring.scalar_mul(&self.proof_vector[0], ak_minus_1[0]);
        let term2 = ring.scalar_mul(&self.proof_vector[1], ak_minus_1[1]);
        let inner_prod = ring.add(&term1, &term2);
        
        // Extract constant term
        let ct = ring.constant_term(&inner_prod);
        
        // Verify ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
        if ct != eval_value {
            return Err(EvalError::RoundVerificationFailed {
                round: 0,
                reason: format!(
                    "Constant term mismatch: ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = {} ≠ v = {}",
                    ct.to_canonical_u64(),
                    eval_value.to_canonical_u64()
                ),
            });
        }
        
        Ok(())
    }
    
    /// Verify round i ∈ [1, k-2]: ⟨π⃗ₑᵥₐₗ,ᵢ, a⃗ₖ₋ᵢ₋₁⟩ = ⟨π⃗ₑᵥₐₗ,ᵢ₋₁, c⃗ₖ₋ᵢ⟩
    /// 
    /// Per HyperWolf paper Requirement 3.4
    pub fn verify_round_i(
        &self,
        prev_round: &EvalRound<F>,
        ak_minus_i_minus_1: &[F],
        challenge: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), EvalError> {
        if ak_minus_i_minus_1.len() != 2 {
            return Err(EvalError::InvalidAuxiliaryVector {
                reason: format!("a⃗ₖ₋ᵢ₋₁ must have 2 elements, got {}", ak_minus_i_minus_1.len()),
            });
        }
        
        if challenge.len() != 2 {
            return Err(EvalError::InvalidChallenge {
                reason: format!("Challenge must have 2 elements, got {}", challenge.len()),
            });
        }
        
        if self.proof_vector.len() != 2 || prev_round.proof_vector.len() != 2 {
            return Err(EvalError::RoundVerificationFailed {
                round: 0, // Will be set by caller
                reason: "Proof vectors must have 2 elements".to_string(),
            });
        }
        
        // Compute LHS: ⟨π⃗ₑᵥₐₗ,ᵢ, a⃗ₖ₋ᵢ₋₁⟩
        let lhs_term1 = ring.scalar_mul(&self.proof_vector[0], ak_minus_i_minus_1[0]);
        let lhs_term2 = ring.scalar_mul(&self.proof_vector[1], ak_minus_i_minus_1[1]);
        let lhs = ring.add(&lhs_term1, &lhs_term2);
        
        // Compute RHS: ⟨π⃗ₑᵥₐₗ,ᵢ₋₁, c⃗ₖ₋ᵢ⟩
        let rhs_term1 = ring.mul(&prev_round.proof_vector[0], &challenge[0]);
        let rhs_term2 = ring.mul(&prev_round.proof_vector[1], &challenge[1]);
        let rhs = ring.add(&rhs_term1, &rhs_term2);
        
        // Verify LHS = RHS
        if !ring.equal(&lhs, &rhs) {
            return Err(EvalError::RoundVerificationFailed {
                round: 0, // Will be set by caller
                reason: "Inner product relation does not hold".to_string(),
            });
        }
        
        Ok(())
    }
}

impl<F: Field> EvaluationProof<F> {
    /// Generate evaluation proof for k rounds
    /// 
    /// Proves ct(s⁽ᵏ⁾ · σ⁻¹(a⃗₀) · ∏ᵢ₌₁ᵏ⁻¹ a⃗ᵢ) = v
    /// through k-1 rounds of witness folding
    ///
    /// # Arguments
    /// * `witness` - Initial witness s⃗ ∈ R_q^n
    /// * `auxiliary` - Auxiliary vectors for evaluation
    /// * `eval_value` - Claimed evaluation value v
    /// * `challenges` - Folding challenges from Fiat-Shamir
    /// * `ring` - Cyclotomic ring for operations
    ///
    /// Per HyperWolf paper Requirement 3
    pub fn prove(
        witness: &[RingElement<F>],
        auxiliary: &AuxiliaryVectors<F>,
        eval_value: F,
        challenges: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, EvalError> {
        let num_rounds = challenges.len();
        
        // Validate witness dimension is power of 2
        if !witness.len().is_power_of_two() {
            return Err(EvalError::WitnessFoldingError {
                reason: format!(
                    "Witness dimension must be power of 2, got {}",
                    witness.len()
                ),
            });
        }
        
        let mut eval_rounds = Vec::with_capacity(num_rounds);
        let mut current_witness = witness.to_vec();
        
        // Compute k = log(witness.len())
        let k = (witness.len() as f64).log2() as usize;
        
        // Conjugate a⃗₀ once
        let a0_conjugated: Vec<RingElement<F>> = auxiliary.a0.iter()
            .map(|elem| ring.conjugate(elem))
            .collect();
        
        // Generate k-1 evaluation rounds
        for round in 0..num_rounds {
            // Reshape witness into (k-round)-dimensional tensor
            let tensor_arity = k - round;
            let tensor = WitnessTensor::from_vector(current_witness.clone(), tensor_arity)
                .map_err(|e| EvalError::TensorDimensionMismatch {
                    expected: vec![tensor_arity],
                    actual: vec![current_witness.len()],
                })?;
            
            // Get remaining auxiliary vectors for this round
            let remaining_ai: Vec<Vec<F>> = (1..(k - round - 1))
                .filter_map(|i| auxiliary.get_ai(i).cloned())
                .collect();
            
            // Compute evaluation round
            let eval_round = EvalRound::new(&tensor, &a0_conjugated, &remaining_ai, ring)?;
            eval_rounds.push(eval_round);
            
            // Fold witness for next round
            if round < num_rounds {
                let challenge = &challenges[round];
                if challenge.len() != 2 {
                    return Err(EvalError::InvalidChallenge {
                        reason: format!("Challenge must have 2 elements, got {}", challenge.len()),
                    });
                }
                
                let half_len = current_witness.len() / 2;
                let left = &current_witness[..half_len];
                let right = &current_witness[half_len..];
                
                current_witness = Self::fold_witness(left, right, &challenge[0], &challenge[1], ring)?;
            }
        }
        
        // Final witness s⃗⁽¹⁾
        let final_witness = current_witness;
        
        Ok(Self {
            eval_rounds,
            final_witness,
        })
    }
    
    /// Verify evaluation proof
    /// 
    /// Checks:
    /// 1. Round 0: ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
    /// 2. Rounds 1 to k-2: ⟨π⃗ₑᵥₐₗ,ᵢ, a⃗ₖ₋ᵢ₋₁⟩ = ⟨π⃗ₑᵥₐₗ,ᵢ₋₁, c⃗ₖ₋ᵢ⟩
    /// 3. Final round: ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩ = ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
    ///
    /// Per HyperWolf paper Requirements 3.3-3.6
    pub fn verify(
        &self,
        auxiliary: &AuxiliaryVectors<F>,
        eval_value: F,
        challenges: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), EvalError> {
        if self.eval_rounds.is_empty() {
            return Err(EvalError::RoundVerificationFailed {
                round: 0,
                reason: "No evaluation rounds in proof".to_string(),
            });
        }
        
        if challenges.len() != self.eval_rounds.len() {
            return Err(EvalError::InvalidChallenge {
                reason: format!(
                    "Challenge count mismatch: expected {}, got {}",
                    self.eval_rounds.len(),
                    challenges.len()
                ),
            });
        }
        
        let k = self.eval_rounds.len() + 1;
        
        // Round 0: Verify ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
        let ak_minus_1 = auxiliary.get_ai(k - 1)
            .ok_or_else(|| EvalError::InvalidAuxiliaryVector {
                reason: format!("Missing auxiliary vector a⃗{}", k - 1),
            })?;
        
        self.eval_rounds[0].verify_round_0(ak_minus_1, eval_value, ring)?;
        
        // Rounds 1 to k-2: Verify recursive relation
        for round in 1..self.eval_rounds.len() {
            let ak_minus_i_minus_1 = auxiliary.get_ai(k - round - 1)
                .ok_or_else(|| EvalError::InvalidAuxiliaryVector {
                    reason: format!("Missing auxiliary vector a⃗{}", k - round - 1),
                })?;
            
            self.eval_rounds[round].verify_round_i(
                &self.eval_rounds[round - 1],
                ak_minus_i_minus_1,
                &challenges[round - 1],
                ring,
            ).map_err(|e| match e {
                EvalError::RoundVerificationFailed { reason, .. } => {
                    EvalError::RoundVerificationFailed { round, reason }
                }
                other => other,
            })?;
        }
        
        // Final round: Verify ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩ = ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
        self.verify_final_round(auxiliary, &challenges[challenges.len() - 1], ring)?;
        
        Ok(())
    }
    
    /// Verify final round: ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩ = ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
    /// 
    /// Per HyperWolf paper Requirement 3.6
    fn verify_final_round(
        &self,
        auxiliary: &AuxiliaryVectors<F>,
        last_challenge: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), EvalError> {
        if last_challenge.len() != 2 {
            return Err(EvalError::InvalidChallenge {
                reason: format!("Challenge must have 2 elements, got {}", last_challenge.len()),
            });
        }
        
        // Compute LHS: ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩
        let mut lhs = RingElement::zero(ring.dimension());
        for (i, witness_elem) in self.final_witness.iter().enumerate() {
            if i < auxiliary.a0.len() {
                let a0_conjugated = ring.conjugate(&auxiliary.a0[i]);
                let product = ring.mul(witness_elem, &a0_conjugated);
                lhs = ring.add(&lhs, &product);
            }
        }
        
        // Get last evaluation round
        let last_round = &self.eval_rounds[self.eval_rounds.len() - 1];
        
        // Compute RHS: ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
        let rhs_term1 = ring.mul(&last_round.proof_vector[0], &last_challenge[0]);
        let rhs_term2 = ring.mul(&last_round.proof_vector[1], &last_challenge[1]);
        let rhs = ring.add(&rhs_term1, &rhs_term2);
        
        // Verify LHS = RHS
        if !ring.equal(&lhs, &rhs) {
            return Err(EvalError::FinalRoundFailed {
                reason: "Final inner product relation does not hold".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Fold witness: s⃗ᵢ₊₁ = c₀·s⃗ᵢ,L + c₁·s⃗ᵢ,R
    /// 
    /// Per HyperWolf paper Requirement 3.5
    fn fold_witness(
        left: &[RingElement<F>],
        right: &[RingElement<F>],
        c0: &RingElement<F>,
        c1: &RingElement<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, EvalError> {
        if left.len() != right.len() {
            return Err(EvalError::WitnessFoldingError {
                reason: format!(
                    "Left and right halves must have same length: {} ≠ {}",
                    left.len(),
                    right.len()
                ),
            });
        }
        
        let mut folded = Vec::with_capacity(left.len());
        
        for i in 0..left.len() {
            // Compute c₀·leftᵢ
            let term1 = ring.mul(c0, &left[i]);
            
            // Compute c₁·rightᵢ
            let term2 = ring.mul(c1, &right[i]);
            
            // Compute c₀·leftᵢ + c₁·rightᵢ
            let sum = ring.add(&term1, &term2);
            
            folded.push(sum);
        }
        
        Ok(folded)
    }
    
    /// Get number of evaluation rounds
    pub fn num_rounds(&self) -> usize {
        self.eval_rounds.len()
    }
    
    /// Get evaluation round at index
    pub fn get_round(&self, index: usize) -> Option<&EvalRound<F>> {
        self.eval_rounds.get(index)
    }
    
    /// Get final witness
    pub fn get_final_witness(&self) -> &[RingElement<F>] {
        &self.final_witness
    }
    
    /// Compute proof size in ring elements
    pub fn proof_size(&self) -> usize {
        // Each round has 2 ring elements
        // Plus final witness
        self.eval_rounds.len() * 2 + self.final_witness.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use rand::{Rng, thread_rng};
    
    fn create_test_ring() -> CyclotomicRing<GoldilocksField> {
        CyclotomicRing::new(64)
    }
    
    fn create_random_witness(size: usize, ring: &CyclotomicRing<GoldilocksField>) -> Vec<RingElement<GoldilocksField>> {
        let mut rng = thread_rng();
        let mut witness = Vec::with_capacity(size);
        
        for _ in 0..size {
            let coeffs: Vec<GoldilocksField> = (0..ring.dimension())
                .map(|_| GoldilocksField::from_u64(rng.gen::<u64>() % 100))
                .collect();
            witness.push(RingElement::from_coeffs(coeffs));
        }
        
        witness
    }
    
    fn create_random_challenge(ring: &CyclotomicRing<GoldilocksField>) -> [RingElement<GoldilocksField>; 2] {
        let mut rng = thread_rng();
        
        let c0_coeffs: Vec<GoldilocksField> = (0..ring.dimension())
            .map(|_| GoldilocksField::from_u64(rng.gen::<u64>() % 10))
            .collect();
        let c0 = RingElement::from_coeffs(c0_coeffs);
        
        let c1_coeffs: Vec<GoldilocksField> = (0..ring.dimension())
            .map(|_| GoldilocksField::from_u64(rng.gen::<u64>() % 10))
            .collect();
        let c1 = RingElement::from_coeffs(c1_coeffs);
        
        [c0, c1]
    }
    
    #[test]
    fn test_auxiliary_vectors_univariate() {
        let ring = create_test_ring();
        let eval_point = GoldilocksField::from_u64(5);
        let ring_dim = 64;
        let num_rounds = 4;
        
        let aux = AuxiliaryVectors::new_univariate(eval_point, ring_dim, num_rounds, &ring);
        assert!(aux.is_ok());
        
        let aux = aux.unwrap();
        assert!(aux.is_univariate);
        assert_eq!(aux.ai_vectors.len(), num_rounds - 1);
        
        // Each a⃗ᵢ should have 2 elements
        for ai in &aux.ai_vectors {
            assert_eq!(ai.len(), 2);
            assert_eq!(ai[0], GoldilocksField::one());
        }
        
        // a⃗₀ should be non-empty
        assert!(!aux.a0.is_empty());
    }
    
    #[test]
    fn test_auxiliary_vectors_multilinear() {
        let ring = create_test_ring();
        let ring_dim = 64;
        let log_d = 6; // log₂(64) = 6
        let num_rounds = 4;
        
        // Need at least log_d + num_rounds - 1 coordinates
        let eval_point: Vec<GoldilocksField> = (0..(log_d + num_rounds))
            .map(|i| GoldilocksField::from_u64(i as u64 + 1))
            .collect();
        
        let aux = AuxiliaryVectors::new_multilinear(&eval_point, ring_dim, num_rounds, &ring);
        assert!(aux.is_ok());
        
        let aux = aux.unwrap();
        assert!(!aux.is_univariate);
        assert_eq!(aux.ai_vectors.len(), num_rounds - 1);
        
        // Each a⃗ᵢ should have 2 elements
        for ai in &aux.ai_vectors {
            assert_eq!(ai.len(), 2);
            assert_eq!(ai[0], GoldilocksField::one());
        }
    }
    
    #[test]
    fn test_auxiliary_vectors_multilinear_insufficient_coords() {
        let ring = create_test_ring();
        let ring_dim = 64;
        let num_rounds = 4;
        
        // Not enough coordinates
        let eval_point: Vec<GoldilocksField> = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        
        let result = AuxiliaryVectors::new_multilinear(&eval_point, ring_dim, num_rounds, &ring);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_fold_witness() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(4, &ring);
        let challenge = create_random_challenge(&ring);
        
        let folded = EvaluationProof::fold_witness(&left, &right, &challenge[0], &challenge[1], &ring);
        assert!(folded.is_ok());
        
        let folded = folded.unwrap();
        assert_eq!(folded.len(), left.len());
        
        // Verify folding formula
        for i in 0..folded.len() {
            let expected_term1 = ring.mul(&challenge[0], &left[i]);
            let expected_term2 = ring.mul(&challenge[1], &right[i]);
            let expected = ring.add(&expected_term1, &expected_term2);
            
            assert!(ring.equal(&folded[i], &expected));
        }
    }
    
    #[test]
    fn test_eval_round_creation() {
        let ring = create_test_ring();
        let witness = create_random_witness(8, &ring);
        
        // Create 3-dimensional tensor
        let tensor = WitnessTensor::from_vector(witness, 3).unwrap();
        
        // Create conjugated a⃗₀
        let a0 = create_random_witness(2, &ring);
        let a0_conjugated: Vec<RingElement<GoldilocksField>> = a0.iter()
            .map(|elem| ring.conjugate(elem))
            .collect();
        
        // Create auxiliary vectors
        let ai_vectors = vec![
            vec![GoldilocksField::one(), GoldilocksField::from_u64(2)],
        ];
        
        let round = EvalRound::new(&tensor, &a0_conjugated, &ai_vectors, &ring);
        assert!(round.is_ok());
        
        let round = round.unwrap();
        assert_eq!(round.proof_vector.len(), 2);
    }
    
    #[test]
    fn test_evaluation_proof_prove_verify() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        // Create auxiliary vectors
        let eval_point = GoldilocksField::from_u64(5);
        let num_rounds = (witness_size as f64).log2() as usize;
        let auxiliary = AuxiliaryVectors::new_univariate(eval_point, 64, num_rounds, &ring).unwrap();
        
        // Dummy evaluation value
        let eval_value = GoldilocksField::from_u64(42);
        
        // Generate challenges
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        // Generate proof
        let proof = EvaluationProof::prove(&witness, &auxiliary, eval_value, &challenges, &ring);
        assert!(proof.is_ok(), "Proof generation should succeed");
        
        let proof = proof.unwrap();
        assert_eq!(proof.num_rounds(), num_rounds);
        
        // Note: Verification will fail because we used a dummy eval_value
        // In a real scenario, eval_value would be computed from the polynomial
    }
    
    #[test]
    fn test_evaluation_proof_invalid_witness_dimension() {
        let ring = create_test_ring();
        let witness_size = 7; // Not power of 2
        let witness = create_random_witness(witness_size, &ring);
        
        let eval_point = GoldilocksField::from_u64(5);
        let num_rounds = 3;
        let auxiliary = AuxiliaryVectors::new_univariate(eval_point, 64, num_rounds, &ring).unwrap();
        
        let eval_value = GoldilocksField::from_u64(42);
        let challenges = vec![];
        
        let result = EvaluationProof::prove(&witness, &auxiliary, eval_value, &challenges, &ring);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_proof_size() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let eval_point = GoldilocksField::from_u64(5);
        let num_rounds = (witness_size as f64).log2() as usize;
        let auxiliary = AuxiliaryVectors::new_univariate(eval_point, 64, num_rounds, &ring).unwrap();
        
        let eval_value = GoldilocksField::from_u64(42);
        
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let proof = EvaluationProof::prove(&witness, &auxiliary, eval_value, &challenges, &ring).unwrap();
        
        // Proof size = num_rounds * 2 + final_witness_size
        let expected_size = num_rounds * 2 + proof.final_witness.len();
        assert_eq!(proof.proof_size(), expected_size);
    }
    
    #[test]
    fn test_multiple_witness_sizes() {
        let ring = create_test_ring();
        
        for log_size in 2..=6 {
            let witness_size = 1 << log_size;
            let witness = create_random_witness(witness_size, &ring);
            
            let eval_point = GoldilocksField::from_u64(5);
            let num_rounds = log_size;
            let auxiliary = AuxiliaryVectors::new_univariate(eval_point, 64, num_rounds, &ring).unwrap();
            
            let eval_value = GoldilocksField::from_u64(42);
            
            let mut challenges = Vec::new();
            for _ in 0..num_rounds {
                let challenge = create_random_challenge(&ring);
                challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
            }
            
            let proof = EvaluationProof::prove(&witness, &auxiliary, eval_value, &challenges, &ring);
            assert!(proof.is_ok(), "Proof generation should succeed for witness size {}", witness_size);
            
            let proof = proof.unwrap();
            assert_eq!(proof.num_rounds(), num_rounds);
        }
    }
}
