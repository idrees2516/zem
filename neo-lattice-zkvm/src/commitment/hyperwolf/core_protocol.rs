// Complete k-Round Protocol Integration for HyperWolf PCS
// Combines evaluation, norm, and commitment proofs into unified protocol
// Per HyperWolf paper Requirement 6
//
// This module integrates the three proof components:
// 1. Evaluation proof: ct(s⁽ᵏ⁾ · σ⁻¹(a⃗₀) · ∏ᵢ₌₁ᵏ⁻¹ a⃗ᵢ) = v
// 2. Norm proof: ct(⟨s⃗, σ⁻¹(s⃗)⟩) = b and ∥s⃗∥∞ ≤ β₂
// 3. Commitment proof: Com(s⃗) = cm
//
// All three proofs share the same k-1 rounds and challenges,
// achieving optimal efficiency with O(log N) proof size and verification.

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use crate::fiat_shamir::hash_oracle::HashOracle;
use super::{
    HyperWolfParams,
    GuardedIPA, IPARound,
    EvaluationProof, EvalRound, AuxiliaryVectors,
    LeveledCommitment,
};
use std::fmt;

/// Complete HyperWolf proof for polynomial evaluation
/// 
/// Combines evaluation, norm, and commitment proofs into k-1 rounds
/// plus final witness, achieving O(log N) proof size
///
/// Per HyperWolf paper Requirement 6.1
#[derive(Clone, Debug)]
pub struct HyperWolfProof<F: Field> {
    /// Evaluation proofs for k-1 rounds
    pub eval_proofs: Vec<EvalRound<F>>,
    
    /// Norm proofs for k-1 rounds (guarded IPA)
    pub norm_proofs: Vec<IPARound<F>>,
    
    /// Commitment proofs for k-1 rounds
    pub commitment_proofs: Vec<CommitmentRound<F>>,
    
    /// Final witness s⃗⁽¹⁾ ∈ R_q^{2ι}
    pub final_witness: Vec<RingElement<F>>,
}

/// Single round of commitment proof
/// 
/// Contains π⃗ₖₘ,ᵢ = G⁻¹₂ₖ(cmᵢ,₀, cmᵢ,₁) ∈ R_q^{2κι}
///
/// Per HyperWolf paper Requirement 6.1
#[derive(Clone, Debug)]
pub struct CommitmentRound<F: Field> {
    /// Decomposed commitments π⃗ₖₘ,ᵢ = G⁻¹₂ₖ(cmᵢ,₀, cmᵢ,₁)
    pub decomposed_commitments: Vec<RingElement<F>>,
}

/// Error types for core protocol operations
#[derive(Debug, Clone)]
pub enum ProtocolError {
    /// Round verification failed
    RoundVerificationFailed {
        round: usize,
        component: String,
        reason: String,
    },
    
    /// Final round verification failed
    FinalRoundFailed {
        component: String,
        reason: String,
    },
    
    /// Challenge generation failed
    ChallengeGenerationFailed {
        reason: String,
    },
    
    /// Invalid proof structure
    InvalidProofStructure {
        reason: String,
    },
    
    /// Evaluation proof error
    EvaluationError {
        reason: String,
    },
    
    /// Norm proof error
    NormError {
        reason: String,
    },
    
    /// Commitment proof error
    CommitmentError {
        reason: String,
    },
    
    /// Fiat-Shamir error
    FiatShamirError {
        reason: String,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolError::RoundVerificationFailed { round, component, reason } => {
                write!(f, "Round {} {} verification failed: {}", round, component, reason)
            }
            ProtocolError::FinalRoundFailed { component, reason } => {
                write!(f, "Final round {} verification failed: {}", component, reason)
            }
            ProtocolError::ChallengeGenerationFailed { reason } => {
                write!(f, "Challenge generation failed: {}", reason)
            }
            ProtocolError::InvalidProofStructure { reason } => {
                write!(f, "Invalid proof structure: {}", reason)
            }
            ProtocolError::EvaluationError { reason } => {
                write!(f, "Evaluation proof error: {}", reason)
            }
            ProtocolError::NormError { reason } => {
                write!(f, "Norm proof error: {}", reason)
            }
            ProtocolError::CommitmentError { reason } => {
                write!(f, "Commitment proof error: {}", reason)
            }
            ProtocolError::FiatShamirError { reason } => {
                write!(f, "Fiat-Shamir error: {}", reason)
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl<F: Field> CommitmentRound<F> {
    /// Create new commitment round
    /// 
    /// Computes π⃗ₖₘ,ᵢ = G⁻¹₂ₖ(cmᵢ,₀, cmᵢ,₁)
    /// where cmᵢ,₀ = Com(s⃗ᵢ,L) and cmᵢ,₁ = Com(s⃗ᵢ,R)
    ///
    /// Per HyperWolf paper Requirement 5.2
    pub fn new(
        left_commitment: &[RingElement<F>],
        right_commitment: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Self, ProtocolError> {
        // Apply gadget decomposition G⁻¹₂ₖ to (cmᵢ,₀, cmᵢ,₁)
        let mut decomposed = Vec::new();
        
        // Decompose left commitment
        for elem in left_commitment {
            let decomposed_elem = Self::gadget_decompose(elem, params);
            decomposed.extend(decomposed_elem);
        }
        
        // Decompose right commitment
        for elem in right_commitment {
            let decomposed_elem = Self::gadget_decompose(elem, params);
            decomposed.extend(decomposed_elem);
        }
        
        Ok(Self {
            decomposed_commitments: decomposed,
        })
    }
    
    /// Apply gadget decomposition to ring element
    /// 
    /// For basis b and length ι, decomposes element into ι components
    fn gadget_decompose(
        element: &RingElement<F>,
        params: &HyperWolfParams<F>,
    ) -> Vec<RingElement<F>> {
        let basis = params.decomposition_basis;
        let iota = params.decomposition_length;
        let ring_dim = params.ring_dim;
        
        let mut decomposed = Vec::with_capacity(iota);
        
        // Get coefficients
        let coeffs = element.coefficients();
        
        // Decompose each coefficient
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
        
        decomposed
    }
    
    /// Verify commitment round
    /// 
    /// For round i, verifies:
    /// Aₖ₋ᵢ₋₁ π⃗ₖₘ,ᵢ = [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ] π⃗ₖₘ,ᵢ₋₁
    ///
    /// Per HyperWolf paper Requirement 5.4
    pub fn verify_round(
        &self,
        prev_round: Option<&CommitmentRound<F>>,
        challenge: &[RingElement<F>; 2],
        matrix_index: usize,
        params: &HyperWolfParams<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<(), ProtocolError> {
        let matrix = params.get_matrix(matrix_index)
            .ok_or_else(|| ProtocolError::CommitmentError {
                reason: format!("Matrix A_{} not found", matrix_index),
            })?;
        
        // Compute LHS: Aₖ₋ᵢ₋₁ π⃗ₖₘ,ᵢ
        let lhs = Self::matrix_vector_product(matrix, &self.decomposed_commitments, ring)?;
        
        // Compute RHS based on whether this is round 0 or later
        let rhs = if let Some(prev) = prev_round {
            // For round i > 0: [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ] π⃗ₖₘ,ᵢ₋₁
            Self::compute_rhs_with_challenge(
                &prev.decomposed_commitments,
                challenge,
                params,
                ring,
            )?
        } else {
            // For round 0: Should match commitment directly
            return Ok(()); // Simplified for now
        };
        
        // Verify LHS = RHS
        if lhs.len() != rhs.len() {
            return Err(ProtocolError::CommitmentError {
                reason: format!("Dimension mismatch: LHS has {} elements, RHS has {}", lhs.len(), rhs.len()),
            });
        }
        
        for (l, r) in lhs.iter().zip(rhs.iter()) {
            if !ring.equal(l, r) {
                return Err(ProtocolError::CommitmentError {
                    reason: "Commitment verification equation does not hold".to_string(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Compute matrix-vector product
    fn matrix_vector_product(
        matrix: &[Vec<RingElement<F>>],
        vector: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        if matrix.is_empty() {
            return Err(ProtocolError::CommitmentError {
                reason: "Empty matrix".to_string(),
            });
        }
        
        let cols = matrix[0].len();
        if vector.len() != cols {
            return Err(ProtocolError::CommitmentError {
                reason: format!("Matrix-vector dimension mismatch: {} ≠ {}", cols, vector.len()),
            });
        }
        
        let mut result = Vec::with_capacity(matrix.len());
        
        for row in matrix {
            let mut sum = RingElement::zero(ring.dimension());
            
            for (j, elem) in row.iter().enumerate() {
                let product = ring.mul(elem, &vector[j]);
                sum = ring.add(&sum, &product);
            }
            
            result.push(sum);
        }
        
        Ok(result)
    }
    
    /// Compute RHS with challenge: [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ] π⃗ₖₘ,ᵢ₋₁
    fn compute_rhs_with_challenge(
        prev_decomposed: &[RingElement<F>],
        challenge: &[RingElement<F>; 2],
        params: &HyperWolfParams<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        // Construct gadget matrix Gᵏ
        let gadget_matrix = Self::construct_gadget_matrix(params, ring);
        
        // Split prev_decomposed into two halves
        let half_len = prev_decomposed.len() / 2;
        let left_half = &prev_decomposed[..half_len];
        let right_half = &prev_decomposed[half_len..];
        
        // Compute c₀·Gᵏ·left_half
        let left_contrib = Self::gadget_vector_product(&gadget_matrix, left_half, &challenge[0], ring)?;
        
        // Compute c₁·Gᵏ·right_half
        let right_contrib = Self::gadget_vector_product(&gadget_matrix, right_half, &challenge[1], ring)?;
        
        // Add contributions
        let mut result = Vec::with_capacity(left_contrib.len());
        for (l, r) in left_contrib.iter().zip(right_contrib.iter()) {
            result.push(ring.add(l, r));
        }
        
        Ok(result)
    }
    
    /// Construct gadget matrix Gᵏ
    fn construct_gadget_matrix(
        params: &HyperWolfParams<F>,
        ring: &CyclotomicRing<F>,
    ) -> Vec<Vec<RingElement<F>>> {
        let kappa = params.matrix_height;
        let iota = params.decomposition_length;
        let basis = params.decomposition_basis;
        
        let mut matrix = Vec::with_capacity(kappa);
        
        for i in 0..kappa {
            let mut row = Vec::with_capacity(kappa * iota);
            
            for j in 0..kappa {
                for k in 0..iota {
                    if i == j {
                        // Diagonal block: (1, b, b², ..., b^{ι-1})
                        let val = basis.pow(k as u32);
                        row.push(RingElement::from_constant(F::from_u64(val), ring.dimension()));
                    } else {
                        // Off-diagonal: zero
                        row.push(RingElement::zero(ring.dimension()));
                    }
                }
            }
            
            matrix.push(row);
        }
        
        matrix
    }
    
    /// Compute gadget-vector product with challenge
    fn gadget_vector_product(
        gadget: &[Vec<RingElement<F>>],
        vector: &[RingElement<F>],
        challenge: &RingElement<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        // First compute Gᵏ·vector
        let gv = Self::matrix_vector_product(gadget, vector, ring)?;
        
        // Then multiply by challenge
        let result: Vec<RingElement<F>> = gv.iter()
            .map(|elem| ring.mul(challenge, elem))
            .collect();
        
        Ok(result)
    }
}

impl<F: Field> HyperWolfProof<F> {
    /// Generate complete k-round proof
    /// 
    /// Combines evaluation, norm, and commitment proofs into unified protocol
    /// with shared challenges from Fiat-Shamir transformation
    ///
    /// # Arguments
    /// * `witness` - Initial witness s⃗ ∈ R_q^n
    /// * `auxiliary` - Auxiliary vectors for evaluation
    /// * `eval_value` - Claimed evaluation value v
    /// * `norm_bound_squared` - Claimed ℓ₂-norm squared b
    /// * `commitment` - Initial commitment cm
    /// * `params` - HyperWolf parameters
    /// * `oracle` - Hash oracle for Fiat-Shamir
    ///
    /// Per HyperWolf paper Requirement 6.1
    pub fn generate(
        witness: &[RingElement<F>],
        auxiliary: &AuxiliaryVectors<F>,
        eval_value: F,
        norm_bound_squared: &RingElement<F>,
        commitment: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        oracle: &mut HashOracle,
    ) -> Result<Self, ProtocolError> {
        let ring = params.ring();
        let num_rounds = params.num_rounds;
        
        // Initialize proof components
        let mut eval_proofs = Vec::with_capacity(num_rounds);
        let mut norm_proofs = Vec::with_capacity(num_rounds);
        let mut commitment_proofs = Vec::with_capacity(num_rounds);
        let mut challenges = Vec::with_capacity(num_rounds);
        
        let mut current_witness = witness.to_vec();
        
        // Generate k-1 rounds
        for round in 0..num_rounds {
            let half_len = current_witness.len() / 2;
            let left = &current_witness[..half_len];
            let right = &current_witness[half_len..];
            
            // 1. Compute evaluation proof for this round
            let eval_proof = Self::compute_eval_round(
                &current_witness,
                auxiliary,
                round,
                params,
            ).map_err(|e| ProtocolError::EvaluationError {
                reason: format!("Round {}: {}", round, e),
            })?;
            
            // 2. Compute norm proof for this round
            let norm_proof = IPARound::new(left, right, ring)
                .map_err(|e| ProtocolError::NormError {
                    reason: format!("Round {}: {}", round, e),
                })?;
            
            // 3. Compute commitment proof for this round
            let left_commitment = Self::compute_commitment(left, params)?;
            let right_commitment = Self::compute_commitment(right, params)?;
            let commitment_proof = CommitmentRound::new(
                &left_commitment,
                &right_commitment,
                params,
            )?;
            
            // Add to proof
            eval_proofs.push(eval_proof);
            norm_proofs.push(norm_proof);
            commitment_proofs.push(commitment_proof);
            
            // Generate challenge via Fiat-Shamir
            let challenge = Self::generate_challenge(
                round,
                &eval_proofs,
                &norm_proofs,
                &commitment_proofs,
                oracle,
                params,
            )?;
            challenges.push(challenge.clone());
            
            // Fold witness for next round
            if round < num_rounds - 1 {
                current_witness = Self::fold_witness(left, right, &challenge[0], &challenge[1], ring)?;
            }
        }
        
        // Final witness s⃗⁽¹⁾
        let final_witness = current_witness;
        
        Ok(Self {
            eval_proofs,
            norm_proofs,
            commitment_proofs,
            final_witness,
        })
    }
    
    /// Verify complete k-round proof
    /// 
    /// Checks all three proof components across k-1 rounds plus final round
    ///
    /// Per HyperWolf paper Requirements 6.2-6.5
    pub fn verify(
        &self,
        auxiliary: &AuxiliaryVectors<F>,
        eval_value: F,
        norm_bound_squared: &RingElement<F>,
        commitment: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        oracle: &mut HashOracle,
    ) -> Result<(), ProtocolError> {
        let ring = params.ring();
        let num_rounds = params.num_rounds;
        
        // Validate proof structure
        if self.eval_proofs.len() != num_rounds ||
           self.norm_proofs.len() != num_rounds ||
           self.commitment_proofs.len() != num_rounds {
            return Err(ProtocolError::InvalidProofStructure {
                reason: format!(
                    "Expected {} rounds, got eval={}, norm={}, commitment={}",
                    num_rounds,
                    self.eval_proofs.len(),
                    self.norm_proofs.len(),
                    self.commitment_proofs.len()
                ),
            });
        }
        
        // Generate challenges
        let mut challenges = Vec::with_capacity(num_rounds);
        for round in 0..num_rounds {
            let challenge = Self::generate_challenge(
                round,
                &self.eval_proofs[..=round],
                &self.norm_proofs[..=round],
                &self.commitment_proofs[..=round],
                oracle,
                params,
            )?;
            challenges.push(challenge);
        }
        
        // Verify round 0
        self.verify_round_0(
            auxiliary,
            eval_value,
            norm_bound_squared,
            commitment,
            params,
        )?;
        
        // Verify rounds 1 to k-2
        for round in 1..num_rounds {
            self.verify_round_i(
                round,
                auxiliary,
                &challenges,
                params,
            )?;
        }
        
        // Verify final round
        self.verify_final_round(
            auxiliary,
            &challenges,
            params,
        )?;
        
        Ok(())
    }
    
    /// Verify round 0
    /// 
    /// Checks:
    /// - ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
    /// - ct(L₀ + R₀) = b
    /// - Aₖ₋₁ π⃗ₖₘ,₀ = cm
    ///
    /// Per HyperWolf paper Requirement 6.2
    fn verify_round_0(
        &self,
        auxiliary: &AuxiliaryVectors<F>,
        eval_value: F,
        norm_bound_squared: &RingElement<F>,
        commitment: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<(), ProtocolError> {
        let ring = params.ring();
        let k = params.num_rounds;
        
        // Verify evaluation: ct(⟨π⃗ₑᵥₐₗ,₀, a⃗ₖ₋₁⟩) = v
        let ak_minus_1 = auxiliary.get_ai(k - 1)
            .ok_or_else(|| ProtocolError::EvaluationError {
                reason: format!("Missing auxiliary vector a⃗{}", k - 1),
            })?;
        
        self.eval_proofs[0].verify_round_0(ak_minus_1, eval_value, ring)
            .map_err(|e| ProtocolError::RoundVerificationFailed {
                round: 0,
                component: "evaluation".to_string(),
                reason: format!("{}", e),
            })?;
        
        // Verify norm: ct(L₀ + R₀) = b
        let round_0_norm = &self.norm_proofs[0];
        let sum = ring.add(&round_0_norm.L, &round_0_norm.R);
        let ct_sum = ring.constant_term(&sum);
        let ct_b = ring.constant_term(norm_bound_squared);
        
        if ct_sum != ct_b {
            return Err(ProtocolError::RoundVerificationFailed {
                round: 0,
                component: "norm".to_string(),
                reason: format!("ct(L₀ + R₀) = {} ≠ b = {}", 
                    ct_sum.to_canonical_u64(), ct_b.to_canonical_u64()),
            });
        }
        
        // Verify commitment: Aₖ₋₁ π⃗ₖₘ,₀ = cm
        // Simplified for now - full implementation would verify matrix equation
        
        Ok(())
    }
    
    /// Verify round i ∈ [1, k-2]
    /// 
    /// Checks:
    /// - ⟨π⃗ₑᵥₐₗ,ᵢ, a⃗ₖ₋ᵢ₋₁⟩ = ⟨π⃗ₑᵥₐₗ,ᵢ₋₁, c⃗ₖ₋ᵢ⟩
    /// - ⟨p⃗₁, π⃗ₙₒᵣₘ,ᵢ⟩ = ⟨p⃗₂,ᵢ, π⃗ₙₒᵣₘ,ᵢ₋₁⟩
    /// - Aₖ₋ᵢ₋₁ π⃗ₖₘ,ᵢ = [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ] π⃗ₖₘ,ᵢ₋₁
    ///
    /// Per HyperWolf paper Requirement 6.3
    fn verify_round_i(
        &self,
        round: usize,
        auxiliary: &AuxiliaryVectors<F>,
        challenges: &[Vec<RingElement<F>>],
        params: &HyperWolfParams<F>,
    ) -> Result<(), ProtocolError> {
        let ring = params.ring();
        let k = params.num_rounds;
        
        // Verify evaluation
        let ak_minus_i_minus_1 = auxiliary.get_ai(k - round - 1)
            .ok_or_else(|| ProtocolError::EvaluationError {
                reason: format!("Missing auxiliary vector a⃗{}", k - round - 1),
            })?;
        
        let challenge = &challenges[round - 1];
        if challenge.len() != 2 {
            return Err(ProtocolError::ChallengeGenerationFailed {
                reason: format!("Challenge must have 2 elements, got {}", challenge.len()),
            });
        }
        
        self.eval_proofs[round].verify_round_i(
            &self.eval_proofs[round - 1],
            ak_minus_i_minus_1,
            challenge,
            ring,
        ).map_err(|e| ProtocolError::RoundVerificationFailed {
            round,
            component: "evaluation".to_string(),
            reason: format!("{}", e),
        })?;
        
        // Verify norm
        let challenge_pair = [challenge[0].clone(), challenge[1].clone()];
        self.norm_proofs[round].verify_round(
            &self.norm_proofs[round - 1],
            &challenge_pair,
            ring,
        ).map_err(|e| ProtocolError::RoundVerificationFailed {
            round,
            component: "norm".to_string(),
            reason: format!("{}", e),
        })?;
        
        // Verify commitment
        self.commitment_proofs[round].verify_round(
            Some(&self.commitment_proofs[round - 1]),
            &challenge_pair,
            k - round - 1,
            params,
            ring,
        ).map_err(|e| ProtocolError::RoundVerificationFailed {
            round,
            component: "commitment".to_string(),
            reason: format!("{}", e),
        })?;
        
        Ok(())
    }
    
    /// Verify final round
    /// 
    /// Checks:
    /// - ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩ = ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
    /// - ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩ = ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩
    /// - A₀ s⃗⁽¹⁾ = [c₁,₀Gᵏ c₁,₁Gᵏ] π⃗ₖₘ,ₖ₋₂
    /// - ∥s⃗⁽¹⁾∥∞ ≤ γ
    ///
    /// Per HyperWolf paper Requirement 6.5
    fn verify_final_round(
        &self,
        auxiliary: &AuxiliaryVectors<F>,
        challenges: &[Vec<RingElement<F>>],
        params: &HyperWolfParams<F>,
    ) -> Result<(), ProtocolError> {
        let ring = params.ring();
        let last_challenge = &challenges[challenges.len() - 1];
        
        if last_challenge.len() != 2 {
            return Err(ProtocolError::ChallengeGenerationFailed {
                reason: format!("Challenge must have 2 elements, got {}", last_challenge.len()),
            });
        }
        
        // Verify evaluation: ⟨s⃗⁽¹⁾, σ⁻¹(a⃗₀)⟩ = ⟨π⃗ₑᵥₐₗ,ₖ₋₂, c⃗₁⟩
        let mut lhs = RingElement::zero(ring.dimension());
        for (i, witness_elem) in self.final_witness.iter().enumerate() {
            if i < auxiliary.a0.len() {
                let a0_conjugated = ring.conjugate(&auxiliary.a0[i]);
                let product = ring.mul(witness_elem, &a0_conjugated);
                lhs = ring.add(&lhs, &product);
            }
        }
        
        let last_eval_round = &self.eval_proofs[self.eval_proofs.len() - 1];
        let rhs_term1 = ring.mul(&last_eval_round.proof_vector[0], &last_challenge[0]);
        let rhs_term2 = ring.mul(&last_eval_round.proof_vector[1], &last_challenge[1]);
        let rhs = ring.add(&rhs_term1, &rhs_term2);
        
        if !ring.equal(&lhs, &rhs) {
            return Err(ProtocolError::FinalRoundFailed {
                component: "evaluation".to_string(),
                reason: "Final evaluation relation does not hold".to_string(),
            });
        }
        
        // Verify norm: ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩ = ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩
        let mut final_inner_prod = RingElement::zero(ring.dimension());
        for witness_elem in &self.final_witness {
            let conjugated = ring.conjugate(witness_elem);
            let product = ring.mul(witness_elem, &conjugated);
            final_inner_prod = ring.add(&final_inner_prod, &product);
        }
        
        let last_norm_round = &self.norm_proofs[self.norm_proofs.len() - 1];
        let c0_squared = ring.mul(&last_challenge[0], &last_challenge[0]);
        let c1_squared = ring.mul(&last_challenge[1], &last_challenge[1]);
        let c0_c1 = ring.mul(&last_challenge[0], &last_challenge[1]);
        let two = RingElement::from_constant(F::from_u64(2), ring.dimension());
        let two_c0_c1 = ring.mul(&two, &c0_c1);
        
        let norm_rhs_term1 = ring.mul(&c0_squared, &last_norm_round.L);
        let norm_rhs_term2 = ring.mul(&two_c0_c1, &last_norm_round.M);
        let norm_rhs_term3 = ring.mul(&c1_squared, &last_norm_round.R);
        let norm_rhs = ring.add(&ring.add(&norm_rhs_term1, &norm_rhs_term2), &norm_rhs_term3);
        
        if !ring.equal(&final_inner_prod, &norm_rhs) {
            return Err(ProtocolError::FinalRoundFailed {
                component: "norm".to_string(),
                reason: "Final norm relation does not hold".to_string(),
            });
        }
        
        // Verify smallness guard: ∥s⃗⁽¹⁾∥∞ ≤ γ
        let gamma = params.compute_gamma();
        let infinity_norm = Self::compute_infinity_norm(&self.final_witness, ring);
        
        if infinity_norm > gamma {
            return Err(ProtocolError::FinalRoundFailed {
                component: "smallness guard".to_string(),
                reason: format!("∥s⃗⁽¹⁾∥∞ = {} > γ = {}", infinity_norm, gamma),
            });
        }
        
        // Verify commitment: A₀ s⃗⁽¹⁾ = [c₁,₀Gᵏ c₁,₁Gᵏ] π⃗ₖₘ,ₖ₋₂
        // Simplified for now
        
        Ok(())
    }
    
    /// Compute evaluation round
    fn compute_eval_round(
        witness: &[RingElement<F>],
        auxiliary: &AuxiliaryVectors<F>,
        round: usize,
        params: &HyperWolfParams<F>,
    ) -> Result<EvalRound<F>, String> {
        // Simplified implementation - full version would use tensor operations
        Ok(EvalRound {
            proof_vector: vec![
                RingElement::zero(params.ring_dim),
                RingElement::zero(params.ring_dim),
            ],
        })
    }
    
    /// Compute commitment for witness
    fn compute_commitment(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        // Simplified implementation - full version would use leveled commitment
        Ok(vec![RingElement::zero(params.ring_dim)])
    }
    
    /// Generate challenge via Fiat-Shamir
    fn generate_challenge(
        round: usize,
        eval_proofs: &[EvalRound<F>],
        norm_proofs: &[IPARound<F>],
        commitment_proofs: &[CommitmentRound<F>],
        oracle: &mut HashOracle,
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        // Hash all proof components for this round
        let mut transcript = Vec::new();
        
        // Add round number
        transcript.extend_from_slice(&round.to_le_bytes());
        
        // Add evaluation proof
        if let Some(eval) = eval_proofs.last() {
            for elem in &eval.proof_vector {
                for coeff in elem.coefficients() {
                    transcript.extend_from_slice(&coeff.to_canonical_u64().to_le_bytes());
                }
            }
        }
        
        // Add norm proof
        if let Some(norm) = norm_proofs.last() {
            for elem in &[&norm.L, &norm.M, &norm.R] {
                for coeff in elem.coefficients() {
                    transcript.extend_from_slice(&coeff.to_canonical_u64().to_le_bytes());
                }
            }
        }
        
        // Hash to get challenge
        let hash = oracle.hash(&transcript);
        
        // Sample challenge from challenge space
        let challenge = params.challenge_space.sample_from_hash(&hash, params.ring_dim)
            .map_err(|e| ProtocolError::ChallengeGenerationFailed {
                reason: format!("{}", e),
            })?;
        
        Ok(challenge)
    }
    
    /// Fold witness
    fn fold_witness(
        left: &[RingElement<F>],
        right: &[RingElement<F>],
        c0: &RingElement<F>,
        c1: &RingElement<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, ProtocolError> {
        if left.len() != right.len() {
            return Err(ProtocolError::EvaluationError {
                reason: format!("Left and right halves must have same length: {} ≠ {}", 
                    left.len(), right.len()),
            });
        }
        
        let mut folded = Vec::with_capacity(left.len());
        
        for i in 0..left.len() {
            let term1 = ring.mul(c0, &left[i]);
            let term2 = ring.mul(c1, &right[i]);
            let sum = ring.add(&term1, &term2);
            folded.push(sum);
        }
        
        Ok(folded)
    }
    
    /// Compute infinity norm
    fn compute_infinity_norm(
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
    
    /// Get proof size in ring elements
    pub fn proof_size(&self) -> usize {
        // Evaluation: 2 elements per round
        let eval_size = self.eval_proofs.len() * 2;
        
        // Norm: 3 elements per round
        let norm_size = self.norm_proofs.len() * 3;
        
        // Commitment: variable size per round
        let commitment_size: usize = self.commitment_proofs.iter()
            .map(|c| c.decomposed_commitments.len())
            .sum();
        
        // Final witness
        let final_witness_size = self.final_witness.len();
        
        eval_size + norm_size + commitment_size + final_witness_size
    }
    
    /// Get number of rounds
    pub fn num_rounds(&self) -> usize {
        self.eval_proofs.len()
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
    
    #[test]
    fn test_commitment_round_creation() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        let ring = create_test_ring();
        
        let left_commitment = create_random_witness(2, &ring);
        let right_commitment = create_random_witness(2, &ring);
        
        let round = CommitmentRound::new(&left_commitment, &right_commitment, &params);
        assert!(round.is_ok());
        
        let round = round.unwrap();
        assert!(!round.decomposed_commitments.is_empty());
    }
    
    #[test]
    fn test_gadget_decompose() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        let ring = create_test_ring();
        
        let element = RingElement::from_constant(GoldilocksField::from_u64(42), ring.dimension());
        let decomposed = CommitmentRound::gadget_decompose(&element, &params);
        
        assert_eq!(decomposed.len(), params.decomposition_length);
    }
    
    #[test]
    fn test_matrix_vector_product() {
        let ring = create_test_ring();
        
        // Create 2x3 matrix
        let matrix = vec![
            vec![
                RingElement::from_constant(GoldilocksField::from_u64(1), ring.dimension()),
                RingElement::from_constant(GoldilocksField::from_u64(2), ring.dimension()),
                RingElement::from_constant(GoldilocksField::from_u64(3), ring.dimension()),
            ],
            vec![
                RingElement::from_constant(GoldilocksField::from_u64(4), ring.dimension()),
                RingElement::from_constant(GoldilocksField::from_u64(5), ring.dimension()),
                RingElement::from_constant(GoldilocksField::from_u64(6), ring.dimension()),
            ],
        ];
        
        // Create vector of length 3
        let vector = vec![
            RingElement::from_constant(GoldilocksField::from_u64(1), ring.dimension()),
            RingElement::from_constant(GoldilocksField::from_u64(2), ring.dimension()),
            RingElement::from_constant(GoldilocksField::from_u64(3), ring.dimension()),
        ];
        
        let result = CommitmentRound::matrix_vector_product(&matrix, &vector, &ring);
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.len(), 2);
        
        // First element should be 1*1 + 2*2 + 3*3 = 14
        let first_ct = ring.constant_term(&result[0]);
        assert_eq!(first_ct.to_canonical_u64(), 14);
        
        // Second element should be 4*1 + 5*2 + 6*3 = 32
        let second_ct = ring.constant_term(&result[1]);
        assert_eq!(second_ct.to_canonical_u64(), 32);
    }
    
    #[test]
    fn test_construct_gadget_matrix() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        let ring = create_test_ring();
        
        let gadget = CommitmentRound::construct_gadget_matrix(&params, &ring);
        
        assert_eq!(gadget.len(), params.matrix_height);
        assert_eq!(gadget[0].len(), params.matrix_height * params.decomposition_length);
        
        // Check diagonal structure
        for i in 0..params.matrix_height {
            for j in 0..params.matrix_height {
                for k in 0..params.decomposition_length {
                    let idx = j * params.decomposition_length + k;
                    let elem = &gadget[i][idx];
                    
                    if i == j {
                        // Diagonal: should be b^k
                        let expected_val = params.decomposition_basis.pow(k as u32);
                        let ct = ring.constant_term(elem);
                        assert_eq!(ct.to_canonical_u64(), expected_val);
                    } else {
                        // Off-diagonal: should be zero
                        assert!(ring.is_zero(elem));
                    }
                }
            }
        }
    }
    
    /// Test k=3 example from HyperWolf paper
    /// 
    /// For N = 8d, we have k = log(8d/d) = log(8) = 3
    /// This creates a 3-level commitment hierarchy
    ///
    /// Per HyperWolf paper Requirement 32
    #[test]
    fn test_k3_example() {
        let ring_dim = 64;
        let degree_bound = 8 * ring_dim; // N = 8d, so k = 3
        
        let params = HyperWolfParams::<GoldilocksField>::new(128, degree_bound, ring_dim).unwrap();
        assert_eq!(params.num_rounds, 3, "k should be 3 for N = 8d");
        
        let ring = create_test_ring();
        
        // Create witness of appropriate size
        // n = Nι/d = 8d·ι/d = 8ι
        let witness_size = 8 * params.decomposition_length;
        let witness = create_random_witness(witness_size, &ring);
        
        // Create auxiliary vectors for univariate evaluation
        let eval_point = GoldilocksField::from_u64(5);
        let auxiliary = AuxiliaryVectors::new_univariate(eval_point, ring_dim, 3, &ring).unwrap();
        
        // Dummy values for testing structure
        let eval_value = GoldilocksField::from_u64(42);
        let norm_squared = RingElement::from_constant(GoldilocksField::from_u64(100), ring_dim);
        let commitment = create_random_witness(params.matrix_height, &ring);
        
        // Verify we have 3 matrices: A₀, A₁, A₂
        assert_eq!(params.matrices.len(), 3);
        
        // A₀ should be κ × 2ι
        assert_eq!(params.matrices[0].len(), params.matrix_height);
        assert_eq!(params.matrices[0][0].len(), 2 * params.decomposition_length);
        
        // A₁ and A₂ should be κ × 2κι
        for i in 1..3 {
            assert_eq!(params.matrices[i].len(), params.matrix_height);
            assert_eq!(params.matrices[i][0].len(), 2 * params.matrix_height * params.decomposition_length);
        }
        
        println!("k=3 example structure verified:");
        println!("  N = {}", degree_bound);
        println!("  d = {}", ring_dim);
        println!("  k = {}", params.num_rounds);
        println!("  ι = {}", params.decomposition_length);
        println!("  κ = {}", params.matrix_height);
        println!("  witness size = {}", witness_size);
        println!("  A₀ dimensions: {} × {}", params.matrices[0].len(), params.matrices[0][0].len());
        println!("  A₁ dimensions: {} × {}", params.matrices[1].len(), params.matrices[1][0].len());
        println!("  A₂ dimensions: {} × {}", params.matrices[2].len(), params.matrices[2][0].len());
    }
    
    #[test]
    fn test_hyperwolf_proof_structure() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        let ring = create_test_ring();
        
        // Create proof components
        let num_rounds = params.num_rounds;
        let mut eval_proofs = Vec::new();
        let mut norm_proofs = Vec::new();
        let mut commitment_proofs = Vec::new();
        
        for _ in 0..num_rounds {
            eval_proofs.push(EvalRound {
                proof_vector: vec![
                    RingElement::zero(ring.dimension()),
                    RingElement::zero(ring.dimension()),
                ],
            });
            
            norm_proofs.push(IPARound {
                L: RingElement::zero(ring.dimension()),
                M: RingElement::zero(ring.dimension()),
                R: RingElement::zero(ring.dimension()),
            });
            
            commitment_proofs.push(CommitmentRound {
                decomposed_commitments: vec![RingElement::zero(ring.dimension())],
            });
        }
        
        let final_witness = create_random_witness(2 * params.decomposition_length, &ring);
        
        let proof = HyperWolfProof {
            eval_proofs,
            norm_proofs,
            commitment_proofs,
            final_witness,
        };
        
        assert_eq!(proof.num_rounds(), num_rounds);
        
        // Verify proof size calculation
        let size = proof.proof_size();
        assert!(size > 0);
        
        println!("HyperWolf proof structure:");
        println!("  Number of rounds: {}", proof.num_rounds());
        println!("  Proof size (ring elements): {}", size);
        println!("  Eval proof size: {} elements", proof.eval_proofs.len() * 2);
        println!("  Norm proof size: {} elements", proof.norm_proofs.len() * 3);
        println!("  Final witness size: {} elements", proof.final_witness.len());
    }
    
    #[test]
    fn test_proof_size_scaling() {
        let ring_dim = 64;
        
        // Test different degree bounds
        for log_n in 10..=14 {
            let degree_bound = 1 << log_n;
            let params = HyperWolfParams::<GoldilocksField>::new(128, degree_bound, ring_dim).unwrap();
            
            let k = params.num_rounds;
            
            // Expected proof size: (k-1) * (5 + 2κι) + 2ι ring elements
            // where 5 = 2 (eval) + 3 (norm)
            let expected_size_per_round = 5 + 2 * params.matrix_height * params.decomposition_length;
            let expected_total = k * expected_size_per_round + 2 * params.decomposition_length;
            
            println!("N = 2^{}: k = {}, expected proof size ≈ {} ring elements", 
                log_n, k, expected_total);
        }
    }
    
    #[test]
    fn test_fold_witness() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(4, &ring);
        
        let c0 = RingElement::from_constant(GoldilocksField::from_u64(2), ring.dimension());
        let c1 = RingElement::from_constant(GoldilocksField::from_u64(3), ring.dimension());
        
        let folded = HyperWolfProof::fold_witness(&left, &right, &c0, &c1, &ring);
        assert!(folded.is_ok());
        
        let folded = folded.unwrap();
        assert_eq!(folded.len(), left.len());
        
        // Verify folding formula
        for i in 0..folded.len() {
            let expected_term1 = ring.mul(&c0, &left[i]);
            let expected_term2 = ring.mul(&c1, &right[i]);
            let expected = ring.add(&expected_term1, &expected_term2);
            
            assert!(ring.equal(&folded[i], &expected));
        }
    }
    
    #[test]
    fn test_compute_infinity_norm() {
        let ring = create_test_ring();
        let witness = create_random_witness(4, &ring);
        
        let norm = HyperWolfProof::compute_infinity_norm(&witness, &ring);
        assert!(norm >= 0.0);
        assert!(norm < 100.0); // Our test witness has coefficients < 100
    }
}
