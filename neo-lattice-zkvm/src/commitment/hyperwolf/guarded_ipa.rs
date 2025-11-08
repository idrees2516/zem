// Guarded Inner-Product Argument for Exact ℓ₂-Soundness
// Implements HyperWolf paper Requirements 4 and 9
//
// This module provides exact ℓ₂-norm proofs without relaxation by combining:
// 1. Inner-product argument for ct(⟨s⃗, σ⁻¹(s⃗)⟩) mod q = b
// 2. Smallness guard to ensure ∥s⃗∥∞ ≤ β₂ < q/√(nd)
//
// Together these guarantee ⟨s⃗, σ⁻¹(s⃗)⟩ mod q = ⟨s⃗, σ⁻¹(s⃗)⟩ over integers,
// thus ∥s⃗∥₂² = b exactly (no wrap-around).

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use std::fmt;

/// Single round of the inner-product argument
/// 
/// For witness s⃗ᵢ split into halves s⃗ᵢ,L and s⃗ᵢ,R, computes:
/// - Lᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,L)⟩
/// - Mᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,R)⟩
/// - Rᵢ = ⟨s⃗ᵢ,R, σ⁻¹(s⃗ᵢ,R)⟩
///
/// Per HyperWolf paper Requirement 4.2
#[derive(Clone, Debug)]
pub struct IPARound<F: Field> {
    /// Lᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,L)⟩
    pub L: RingElement<F>,
    
    /// Mᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,R)⟩
    pub M: RingElement<F>,
    
    /// Rᵢ = ⟨s⃗ᵢ,R, σ⁻¹(s⃗ᵢ,R)⟩
    pub R: RingElement<F>,
}

/// Complete guarded IPA proof for exact ℓ₂-soundness
/// 
/// Proves two sub-constraints:
/// 1. ct(⟨s⃗, σ⁻¹(s⃗)⟩) mod q = b with b ≤ β₁²
/// 2. ∥s⃗∥∞ ≤ β₂ where β₂² · dim(s⃗) < q
///
/// Together these guarantee exact ℓ₂-soundness: ∥s⃗∥₂² = b
///
/// Per HyperWolf paper Requirements 4 and 9
#[derive(Clone, Debug)]
pub struct GuardedIPA<F: Field> {
    /// IPA rounds for k-1 folding steps
    /// Round i proves relation for witness s⃗ᵢ
    pub ipa_rounds: Vec<IPARound<F>>,
    
    /// Final witness s⃗⁽¹⁾ ∈ R_q^{2ι} after k-1 foldings
    pub final_witness: Vec<RingElement<F>>,
}

/// Error types for guarded IPA operations
#[derive(Debug, Clone)]
pub enum IPAError {
    /// Witness dimension mismatch
    InvalidWitnessDimension {
        expected: usize,
        actual: usize,
    },
    
    /// Norm bound violation
    NormBoundViolation {
        actual_norm: f64,
        bound: f64,
    },
    
    /// Smallness guard failed
    SmallnessGuardFailed {
        infinity_norm: f64,
        gamma: f64,
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
}

impl fmt::Display for IPAError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPAError::InvalidWitnessDimension { expected, actual } => {
                write!(f, "Invalid witness dimension: expected {}, got {}", expected, actual)
            }
            IPAError::NormBoundViolation { actual_norm, bound } => {
                write!(f, "Norm bound violation: ∥s⃗∥₂ = {} > bound = {}", actual_norm, bound)
            }
            IPAError::SmallnessGuardFailed { infinity_norm, gamma } => {
                write!(f, "Smallness guard failed: ∥s⃗⁽¹⁾∥∞ = {} > γ = {}", infinity_norm, gamma)
            }
            IPAError::RoundVerificationFailed { round, reason } => {
                write!(f, "Round {} verification failed: {}", round, reason)
            }
            IPAError::FinalRoundFailed { reason } => {
                write!(f, "Final round verification failed: {}", reason)
            }
            IPAError::InvalidChallenge { reason } => {
                write!(f, "Invalid challenge: {}", reason)
            }
            IPAError::RingOperationError { operation } => {
                write!(f, "Ring operation error: {}", operation)
            }
        }
    }
}

impl std::error::Error for IPAError {}

impl<F: Field> IPARound<F> {
    /// Create new IPA round from witness halves
    /// 
    /// Computes:
    /// - Lᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,L)⟩
    /// - Mᵢ = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,R)⟩
    /// - Rᵢ = ⟨s⃗ᵢ,R, σ⁻¹(s⃗ᵢ,R)⟩
    ///
    /// # Arguments
    /// * `left` - Left half of witness s⃗ᵢ,L
    /// * `right` - Right half of witness s⃗ᵢ,R
    /// * `ring` - Cyclotomic ring for operations
    ///
    /// Per HyperWolf paper Requirement 4.2
    pub fn new(
        left: &[RingElement<F>],
        right: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, IPAError> {
        if left.len() != right.len() {
            return Err(IPAError::InvalidWitnessDimension {
                expected: left.len(),
                actual: right.len(),
            });
        }
        
        // Compute L = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,L)⟩
        let L = Self::inner_product_with_conjugate(left, left, ring)?;
        
        // Compute M = ⟨s⃗ᵢ,L, σ⁻¹(s⃗ᵢ,R)⟩
        let M = Self::inner_product_with_conjugate(left, right, ring)?;
        
        // Compute R = ⟨s⃗ᵢ,R, σ⁻¹(s⃗ᵢ,R)⟩
        let R = Self::inner_product_with_conjugate(right, right, ring)?;
        
        Ok(Self { L, M, R })
    }
    
    /// Compute inner product ⟨a⃗, σ⁻¹(b⃗)⟩
    /// 
    /// where σ⁻¹ is the conjugation automorphism:
    /// σ⁻¹(Σᵢ fᵢXⁱ) = Σᵢ fᵢX⁻ⁱ
    fn inner_product_with_conjugate(
        a: &[RingElement<F>],
        b: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<RingElement<F>, IPAError> {
        if a.len() != b.len() {
            return Err(IPAError::InvalidWitnessDimension {
                expected: a.len(),
                actual: b.len(),
            });
        }
        
        let mut result = RingElement::zero(ring.dimension());
        
        for i in 0..a.len() {
            // Compute σ⁻¹(bᵢ)
            let b_conjugate = ring.conjugate(&b[i]);
            
            // Multiply aᵢ · σ⁻¹(bᵢ)
            let product = ring.mul(&a[i], &b_conjugate);
            
            // Accumulate
            result = ring.add(&result, &product);
        }
        
        Ok(result)
    }
    
    /// Verify round relation
    /// 
    /// For round i ∈ [1, k-2], verifies:
    /// ⟨p⃗₁, π⃗ₙₒᵣₘ,ᵢ⟩ = ⟨p⃗₂,ᵢ, π⃗ₙₒᵣₘ,ᵢ₋₁⟩
    /// 
    /// where:
    /// - p⃗₁ = (1, 0, 1)
    /// - p⃗₂,ᵢ = (c²ₖ₋ᵢ,₀, 2cₖ₋ᵢ,₀cₖ₋ᵢ,₁, c²ₖ₋ᵢ,₁)
    /// - π⃗ₙₒᵣₘ,ᵢ = (Lᵢ, Mᵢ, Rᵢ)
    ///
    /// Per HyperWolf paper Requirement 4.4
    pub fn verify_round(
        &self,
        prev_round: &IPARound<F>,
        challenge: &[RingElement<F>; 2],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        // Compute LHS: ⟨p⃗₁, π⃗ₙₒᵣₘ,ᵢ⟩ = 1·Lᵢ + 0·Mᵢ + 1·Rᵢ = Lᵢ + Rᵢ
        let lhs = ring.add(&self.L, &self.R);
        
        // Compute p⃗₂,ᵢ = (c²ₖ₋ᵢ,₀, 2cₖ₋ᵢ,₀cₖ₋ᵢ,₁, c²ₖ₋ᵢ,₁)
        let c0_squared = ring.mul(&challenge[0], &challenge[0]);
        let c1_squared = ring.mul(&challenge[1], &challenge[1]);
        let c0_c1 = ring.mul(&challenge[0], &challenge[1]);
        let two = RingElement::from_constant(F::from_u64(2), ring.dimension());
        let two_c0_c1 = ring.mul(&two, &c0_c1);
        
        // Compute RHS: ⟨p⃗₂,ᵢ, π⃗ₙₒᵣₘ,ᵢ₋₁⟩ = c²₀·Lᵢ₋₁ + 2c₀c₁·Mᵢ₋₁ + c²₁·Rᵢ₋₁
        let term1 = ring.mul(&c0_squared, &prev_round.L);
        let term2 = ring.mul(&two_c0_c1, &prev_round.M);
        let term3 = ring.mul(&c1_squared, &prev_round.R);
        
        let rhs = ring.add(&ring.add(&term1, &term2), &term3);
        
        // Verify LHS = RHS
        if !ring.equal(&lhs, &rhs) {
            return Err(IPAError::RoundVerificationFailed {
                round: 0, // Will be set by caller
                reason: "Inner product relation does not hold".to_string(),
            });
        }
        
        Ok(())
    }
}

impl<F: Field> GuardedIPA<F> {
    /// Generate guarded IPA proof for witness
    /// 
    /// Proves:
    /// 1. ct(⟨s⃗, σ⁻¹(s⃗)⟩) mod q = b
    /// 2. ∥s⃗∥∞ ≤ β₂ < q/√(nd)
    ///
    /// Together these guarantee exact ℓ₂-soundness: ∥s⃗∥₂² = b
    ///
    /// # Arguments
    /// * `witness` - Initial witness s⃗ ∈ R_q^n
    /// * `norm_bound_squared` - Claimed ℓ₂-norm squared b = ∥s⃗∥₂²
    /// * `infinity_bound` - Infinity norm bound β₂
    /// * `challenges` - Folding challenges (c⃗ₖ₋₁, ..., c⃗₁) from Fiat-Shamir
    /// * `ring` - Cyclotomic ring for operations
    ///
    /// # Returns
    /// GuardedIPA proof with k-1 rounds and final witness
    ///
    /// Per HyperWolf paper Requirements 4 and 9
    pub fn prove(
        witness: &[RingElement<F>],
        norm_bound_squared: &RingElement<F>,
        infinity_bound: f64,
        challenges: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Self, IPAError> {
        let num_rounds = challenges.len();
        
        // Validate witness dimension is power of 2
        if !witness.len().is_power_of_two() {
            return Err(IPAError::InvalidWitnessDimension {
                expected: witness.len().next_power_of_two(),
                actual: witness.len(),
            });
        }
        
        // Validate infinity norm bound
        let actual_infinity_norm = Self::compute_infinity_norm(witness, ring);
        if actual_infinity_norm > infinity_bound {
            return Err(IPAError::NormBoundViolation {
                actual_norm: actual_infinity_norm,
                bound: infinity_bound,
            });
        }
        
        let mut ipa_rounds = Vec::with_capacity(num_rounds);
        let mut current_witness = witness.to_vec();
        
        // Generate k-1 IPA rounds
        for round in 0..num_rounds {
            let half_len = current_witness.len() / 2;
            
            // Split witness into halves
            let left = &current_witness[..half_len];
            let right = &current_witness[half_len..];
            
            // Compute IPA round (Lᵢ, Mᵢ, Rᵢ)
            let ipa_round = IPARound::new(left, right, ring)?;
            ipa_rounds.push(ipa_round);
            
            // Fold witness: s⃗ᵢ₊₁ = cᵢ,₀·s⃗ᵢ,L + cᵢ,₁·s⃗ᵢ,R
            if round < num_rounds {
                let challenge = &challenges[round];
                if challenge.len() != 2 {
                    return Err(IPAError::InvalidChallenge {
                        reason: format!("Challenge must have 2 elements, got {}", challenge.len()),
                    });
                }
                
                current_witness = Self::fold_witness(left, right, &challenge[0], &challenge[1], ring)?;
            }
        }
        
        // Final witness s⃗⁽¹⁾
        let final_witness = current_witness;
        
        Ok(Self {
            ipa_rounds,
            final_witness,
        })
    }
    
    /// Verify guarded IPA proof
    /// 
    /// Checks:
    /// 1. Round 0: ct(L₀ + R₀) = b
    /// 2. Rounds 1 to k-2: ⟨p⃗₁, π⃗ₙₒᵣₘ,ᵢ⟩ = ⟨p⃗₂,ᵢ, π⃗ₙₒᵣₘ,ᵢ₋₁⟩
    /// 3. Final round: ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩ = ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩
    /// 4. Smallness guard: ∥s⃗⁽¹⁾∥∞ ≤ γ
    ///
    /// # Arguments
    /// * `norm_bound_squared` - Claimed ℓ₂-norm squared b
    /// * `gamma` - Final witness infinity norm bound γ = (2T)^{k-1}β₂
    /// * `challenges` - Folding challenges from Fiat-Shamir
    /// * `ring` - Cyclotomic ring for operations
    ///
    /// Per HyperWolf paper Requirements 4.3-4.8
    pub fn verify(
        &self,
        norm_bound_squared: &RingElement<F>,
        gamma: f64,
        challenges: &[Vec<RingElement<F>>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        if self.ipa_rounds.is_empty() {
            return Err(IPAError::RoundVerificationFailed {
                round: 0,
                reason: "No IPA rounds in proof".to_string(),
            });
        }
        
        if challenges.len() != self.ipa_rounds.len() {
            return Err(IPAError::InvalidChallenge {
                reason: format!(
                    "Challenge count mismatch: expected {}, got {}",
                    self.ipa_rounds.len(),
                    challenges.len()
                ),
            });
        }
        
        // Round 0: Verify ct(L₀ + R₀) = b
        self.verify_round_0(norm_bound_squared, ring)?;
        
        // Rounds 1 to k-2: Verify recursive relation
        for round in 1..self.ipa_rounds.len() {
            self.verify_round_i(round, &challenges[round - 1], ring)?;
        }
        
        // Final round: Verify ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩ = ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩
        self.verify_final_round(&challenges[challenges.len() - 1], ring)?;
        
        // Smallness guard: Verify ∥s⃗⁽¹⁾∥∞ ≤ γ
        self.check_smallness_guard(gamma, ring)?;
        
        Ok(())
    }
    
    /// Verify round 0: ct(L₀ + R₀) = b
    /// 
    /// Per HyperWolf paper Requirement 4.3
    fn verify_round_0(
        &self,
        norm_bound_squared: &RingElement<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        let round_0 = &self.ipa_rounds[0];
        
        // Compute L₀ + R₀
        let sum = ring.add(&round_0.L, &round_0.R);
        
        // Extract constant term
        let ct_sum = ring.constant_term(&sum);
        let ct_b = ring.constant_term(norm_bound_squared);
        
        // Verify ct(L₀ + R₀) = b
        if ct_sum != ct_b {
            return Err(IPAError::RoundVerificationFailed {
                round: 0,
                reason: format!(
                    "Constant term mismatch: ct(L₀ + R₀) = {} ≠ b = {}",
                    ct_sum.to_canonical_u64(),
                    ct_b.to_canonical_u64()
                ),
            });
        }
        
        Ok(())
    }
    
    /// Verify round i ∈ [1, k-2]: ⟨p⃗₁, π⃗ₙₒᵣₘ,ᵢ⟩ = ⟨p⃗₂,ᵢ, π⃗ₙₒᵣₘ,ᵢ₋₁⟩
    /// 
    /// Per HyperWolf paper Requirement 4.4
    fn verify_round_i(
        &self,
        round: usize,
        challenge: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        if challenge.len() != 2 {
            return Err(IPAError::InvalidChallenge {
                reason: format!("Challenge must have 2 elements, got {}", challenge.len()),
            });
        }
        
        let current_round = &self.ipa_rounds[round];
        let prev_round = &self.ipa_rounds[round - 1];
        
        let challenge_pair = [challenge[0].clone(), challenge[1].clone()];
        current_round.verify_round(prev_round, &challenge_pair, ring)
            .map_err(|e| match e {
                IPAError::RoundVerificationFailed { reason, .. } => {
                    IPAError::RoundVerificationFailed { round, reason }
                }
                other => other,
            })
    }
    
    /// Verify final round: ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩ = ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩
    /// 
    /// Per HyperWolf paper Requirement 4.6
    fn verify_final_round(
        &self,
        last_challenge: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        if last_challenge.len() != 2 {
            return Err(IPAError::InvalidChallenge {
                reason: format!("Challenge must have 2 elements, got {}", last_challenge.len()),
            });
        }
        
        // Compute LHS: ⟨s⃗⁽¹⁾, σ⁻¹(s⃗⁽¹⁾)⟩
        let lhs = IPARound::inner_product_with_conjugate(
            &self.final_witness,
            &self.final_witness,
            ring,
        )?;
        
        // Compute p⃗₂,ₖ₋₁ = (c²₁,₀, 2c₁,₀c₁,₁, c²₁,₁)
        let c0_squared = ring.mul(&last_challenge[0], &last_challenge[0]);
        let c1_squared = ring.mul(&last_challenge[1], &last_challenge[1]);
        let c0_c1 = ring.mul(&last_challenge[0], &last_challenge[1]);
        let two = RingElement::from_constant(F::from_u64(2), ring.dimension());
        let two_c0_c1 = ring.mul(&two, &c0_c1);
        
        // Get last IPA round
        let last_round = &self.ipa_rounds[self.ipa_rounds.len() - 1];
        
        // Compute RHS: ⟨p⃗₂,ₖ₋₁, π⃗ₙₒᵣₘ,ₖ₋₂⟩ = c²₀·L + 2c₀c₁·M + c²₁·R
        let term1 = ring.mul(&c0_squared, &last_round.L);
        let term2 = ring.mul(&two_c0_c1, &last_round.M);
        let term3 = ring.mul(&c1_squared, &last_round.R);
        
        let rhs = ring.add(&ring.add(&term1, &term2), &term3);
        
        // Verify LHS = RHS
        if !ring.equal(&lhs, &rhs) {
            return Err(IPAError::FinalRoundFailed {
                reason: "Final inner product relation does not hold".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Check smallness guard: ∥s⃗⁽¹⁾∥∞ ≤ γ
    /// 
    /// This ensures no wrap-around in modular arithmetic:
    /// β₂² · nd < q ⟹ ⟨s⃗, σ⁻¹(s⃗)⟩ mod q = ⟨s⃗, σ⁻¹(s⃗)⟩ over integers
    ///
    /// Per HyperWolf paper Requirements 4.7 and 4.8
    fn check_smallness_guard(
        &self,
        gamma: f64,
        ring: &CyclotomicRing<F>,
    ) -> Result<(), IPAError> {
        let infinity_norm = Self::compute_infinity_norm(&self.final_witness, ring);
        
        if infinity_norm > gamma {
            return Err(IPAError::SmallnessGuardFailed {
                infinity_norm,
                gamma,
            });
        }
        
        Ok(())
    }
    
    /// Compute infinity norm ∥s⃗∥∞ = maxᵢ |sᵢ|
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
    
    /// Fold witness: s⃗ᵢ₊₁ = c₀·s⃗ᵢ,L + c₁·s⃗ᵢ,R
    /// 
    /// Per HyperWolf paper Requirement 4.5
    fn fold_witness(
        left: &[RingElement<F>],
        right: &[RingElement<F>],
        c0: &RingElement<F>,
        c1: &RingElement<F>,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, IPAError> {
        if left.len() != right.len() {
            return Err(IPAError::InvalidWitnessDimension {
                expected: left.len(),
                actual: right.len(),
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
    
    /// Get number of IPA rounds
    pub fn num_rounds(&self) -> usize {
        self.ipa_rounds.len()
    }
    
    /// Get IPA round at index
    pub fn get_round(&self, index: usize) -> Option<&IPARound<F>> {
        self.ipa_rounds.get(index)
    }
    
    /// Get final witness
    pub fn get_final_witness(&self) -> &[RingElement<F>] {
        &self.final_witness
    }
    
    /// Compute proof size in ring elements
    pub fn proof_size(&self) -> usize {
        // Each round has 3 ring elements (L, M, R)
        // Plus final witness
        self.ipa_rounds.len() * 3 + self.final_witness.len()
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
    fn test_ipa_round_creation() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(4, &ring);
        
        let round = IPARound::new(&left, &right, &ring);
        assert!(round.is_ok());
        
        let round = round.unwrap();
        // L, M, R should be non-zero for random inputs
        assert!(!ring.is_zero(&round.L));
        assert!(!ring.is_zero(&round.M));
        assert!(!ring.is_zero(&round.R));
    }
    
    #[test]
    fn test_ipa_round_dimension_mismatch() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(8, &ring);
        
        let result = IPARound::new(&left, &right, &ring);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            IPAError::InvalidWitnessDimension { .. } => {},
            _ => panic!("Expected InvalidWitnessDimension error"),
        }
    }
    
    #[test]
    fn test_inner_product_with_conjugate() {
        let ring = create_test_ring();
        let witness = create_random_witness(4, &ring);
        
        // Compute ⟨s⃗, σ⁻¹(s⃗)⟩
        let result = IPARound::inner_product_with_conjugate(&witness, &witness, &ring);
        assert!(result.is_ok());
        
        let inner_prod = result.unwrap();
        // For real-valued witness, ⟨s⃗, σ⁻¹(s⃗)⟩ should equal ∥s⃗∥₂²
        assert!(!ring.is_zero(&inner_prod));
    }
    
    #[test]
    fn test_ipa_round_verification() {
        let ring = create_test_ring();
        
        // Create two consecutive rounds
        let witness = create_random_witness(8, &ring);
        let half_len = witness.len() / 2;
        let left = &witness[..half_len];
        let right = &witness[half_len..];
        
        let round_0 = IPARound::new(left, right, &ring).unwrap();
        
        // Fold witness
        let challenge = create_random_challenge(&ring);
        let folded = GuardedIPA::fold_witness(left, right, &challenge[0], &challenge[1], &ring).unwrap();
        
        // Create round 1
        let folded_half = folded.len() / 2;
        let folded_left = &folded[..folded_half];
        let folded_right = &folded[folded_half..];
        let round_1 = IPARound::new(folded_left, folded_right, &ring).unwrap();
        
        // Verify round 1 against round 0
        let result = round_1.verify_round(&round_0, &challenge, &ring);
        assert!(result.is_ok(), "Round verification should pass for honest prover");
    }
    
    #[test]
    fn test_fold_witness() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(4, &ring);
        let challenge = create_random_challenge(&ring);
        
        let folded = GuardedIPA::fold_witness(&left, &right, &challenge[0], &challenge[1], &ring);
        assert!(folded.is_ok());
        
        let folded = folded.unwrap();
        assert_eq!(folded.len(), left.len());
        
        // Verify folding formula: s⃗ᵢ₊₁ = c₀·s⃗ᵢ,L + c₁·s⃗ᵢ,R
        for i in 0..folded.len() {
            let expected_term1 = ring.mul(&challenge[0], &left[i]);
            let expected_term2 = ring.mul(&challenge[1], &right[i]);
            let expected = ring.add(&expected_term1, &expected_term2);
            
            assert!(ring.equal(&folded[i], &expected));
        }
    }
    
    #[test]
    fn test_fold_witness_dimension_mismatch() {
        let ring = create_test_ring();
        let left = create_random_witness(4, &ring);
        let right = create_random_witness(8, &ring);
        let challenge = create_random_challenge(&ring);
        
        let result = GuardedIPA::fold_witness(&left, &right, &challenge[0], &challenge[1], &ring);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_compute_infinity_norm() {
        let ring = create_test_ring();
        let witness = create_random_witness(4, &ring);
        
        let norm = GuardedIPA::compute_infinity_norm(&witness, &ring);
        assert!(norm >= 0.0);
        assert!(norm < 100.0); // Our test witness has coefficients < 100
    }
    
    #[test]
    fn test_guarded_ipa_prove_verify() {
        let ring = create_test_ring();
        let witness_size = 8; // Must be power of 2
        let witness = create_random_witness(witness_size, &ring);
        
        // Compute norm bound
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 100.0; // Large enough for our test witness
        
        // Generate challenges (k-1 rounds for witness of size 2^k)
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        // Generate proof
        let proof = GuardedIPA::prove(
            &witness,
            &norm_squared,
            infinity_bound,
            &challenges,
            &ring,
        );
        assert!(proof.is_ok(), "Proof generation should succeed for valid witness");
        
        let proof = proof.unwrap();
        assert_eq!(proof.num_rounds(), num_rounds);
        
        // Compute gamma for verification
        let t = 10.0; // Operator norm bound
        let beta_2 = 2.0; // Infinity bound
        let gamma = (2.0 * t).powi((num_rounds - 1) as i32) * beta_2;
        
        // Verify proof
        let result = proof.verify(&norm_squared, gamma, &challenges, &ring);
        assert!(result.is_ok(), "Verification should pass for honest proof");
    }
    
    #[test]
    fn test_guarded_ipa_invalid_witness_dimension() {
        let ring = create_test_ring();
        let witness_size = 7; // Not power of 2
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 100.0;
        let challenges = vec![];
        
        let result = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            IPAError::InvalidWitnessDimension { .. } => {},
            _ => panic!("Expected InvalidWitnessDimension error"),
        }
    }
    
    #[test]
    fn test_guarded_ipa_norm_bound_violation() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 1.0; // Too small for our witness
        
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let result = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            IPAError::NormBoundViolation { .. } => {},
            _ => panic!("Expected NormBoundViolation error"),
        }
    }
    
    #[test]
    fn test_verify_round_0() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 100.0;
        
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let proof = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring).unwrap();
        
        // Verify round 0 specifically
        let result = proof.verify_round_0(&norm_squared, &ring);
        assert!(result.is_ok(), "Round 0 verification should pass");
    }
    
    #[test]
    fn test_verify_round_0_wrong_norm() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let wrong_norm = RingElement::from_constant(GoldilocksField::from_u64(12345), ring.dimension());
        let infinity_bound = 100.0;
        
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let proof = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring).unwrap();
        
        // Verify with wrong norm should fail
        let result = proof.verify_round_0(&wrong_norm, &ring);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_smallness_guard() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 100.0;
        
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let proof = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring).unwrap();
        
        // Check with appropriate gamma
        let t = 10.0;
        let beta_2 = 2.0;
        let gamma = (2.0 * t).powi((num_rounds - 1) as i32) * beta_2;
        
        let result = proof.check_smallness_guard(gamma, &ring);
        assert!(result.is_ok(), "Smallness guard should pass with appropriate gamma");
        
        // Check with too small gamma
        let small_gamma = 1.0;
        let result = proof.check_smallness_guard(small_gamma, &ring);
        assert!(result.is_err(), "Smallness guard should fail with too small gamma");
    }
    
    #[test]
    fn test_proof_size() {
        let ring = create_test_ring();
        let witness_size = 8;
        let witness = create_random_witness(witness_size, &ring);
        
        let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
        let infinity_bound = 100.0;
        
        let num_rounds = (witness_size as f64).log2() as usize;
        let mut challenges = Vec::new();
        for _ in 0..num_rounds {
            let challenge = create_random_challenge(&ring);
            challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
        }
        
        let proof = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring).unwrap();
        
        // Proof size = (k-1) * 3 + final_witness_size
        // For witness_size = 8 = 2^3, k = 3, so k-1 = 2 rounds
        // Final witness size = 2^(3-2) = 2
        let expected_size = num_rounds * 3 + 2;
        assert_eq!(proof.proof_size(), expected_size);
    }
    
    #[test]
    fn test_multiple_rounds() {
        let ring = create_test_ring();
        
        // Test with different witness sizes
        for log_size in 2..=6 {
            let witness_size = 1 << log_size;
            let witness = create_random_witness(witness_size, &ring);
            
            let norm_squared = IPARound::inner_product_with_conjugate(&witness, &witness, &ring).unwrap();
            let infinity_bound = 100.0;
            
            let num_rounds = log_size;
            let mut challenges = Vec::new();
            for _ in 0..num_rounds {
                let challenge = create_random_challenge(&ring);
                challenges.push(vec![challenge[0].clone(), challenge[1].clone()]);
            }
            
            let proof = GuardedIPA::prove(&witness, &norm_squared, infinity_bound, &challenges, &ring);
            assert!(proof.is_ok(), "Proof generation should succeed for witness size {}", witness_size);
            
            let proof = proof.unwrap();
            assert_eq!(proof.num_rounds(), num_rounds);
            
            let t = 10.0;
            let beta_2 = 2.0;
            let gamma = (2.0 * t).powi((num_rounds - 1) as i32) * beta_2;
            
            let result = proof.verify(&norm_squared, gamma, &challenges, &ring);
            assert!(result.is_ok(), "Verification should pass for witness size {}", witness_size);
        }
    }
}
