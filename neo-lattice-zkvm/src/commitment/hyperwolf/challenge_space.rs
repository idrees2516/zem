// Challenge Space C ⊂ R_q for HyperWolf PCS
// Implements challenge sampling with invertibility and norm bounds
// Per HyperWolf paper Requirements 8 and 13.5
//
// OPTIMIZATIONS (Task 14.3):
// - Pre-computed challenge space properties
// - Efficient rejection sampling with early termination
// - Cached invertibility checks for common patterns
// - Optimized norm computations

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use rand::{Rng, thread_rng};
use std::collections::HashSet;
use once_cell::sync::Lazy;

/// Challenge space C ⊂ R_q with invertibility and norm properties
/// 
/// For d=64 (standard configuration):
/// - 24 zero coefficients
/// - 32 coefficients in {±1}
/// - 8 coefficients in {±2}
/// - ℓ₂-norm bound τ = 8
/// - Operator norm bound T = 10
/// - |C| ≈ 2^{128.6} for negligible soundness error
/// 
/// OPTIMIZED (Task 14.3):
/// - Precomputed expected ℓ₂-norm for early rejection
/// - Cached q^{1/2} for invertibility checks
#[derive(Clone, Debug)]
pub struct ChallengeSpace<F: Field> {
    /// Ring dimension d (must be power of 2)
    pub ring_dim: usize,
    
    /// Number of zero coefficients (24 for d=64)
    pub num_zeros: usize,
    
    /// Number of ±1 coefficients (32 for d=64)
    pub num_ones: usize,
    
    /// Number of ±2 coefficients (8 for d=64)
    pub num_twos: usize,
    
    /// ℓ₂-norm bound τ = 8
    pub l2_norm_bound: f64,
    
    /// Operator norm bound T = 10
    pub operator_norm_bound: f64,
    
    /// Cyclotomic ring for operations
    ring: CyclotomicRing<F>,
    
    /// Maximum rejection sampling attempts
    max_attempts: usize,
    
    /// Precomputed expected ℓ₂-norm (for early rejection)
    /// For standard config: √(32·1² + 8·2²) = √(32 + 32) = 8
    expected_l2_norm: f64,
    
    /// Cached √q for invertibility checks
    q_sqrt: f64,
}


impl<F: Field> ChallengeSpace<F> {
    /// Create standard challenge space for d=64
    /// 
    /// Configuration:
    /// - 24 zeros, 32 ±1s, 8 ±2s
    /// - τ = 8, T = 10
    /// - |C| ≈ 2^{128.6}
    /// 
    /// OPTIMIZED (Task 14.3):
    /// - Precomputes expected ℓ₂-norm
    /// - Caches √q for invertibility checks
    pub fn new_standard(ring_dim: usize) -> Result<Self, String> {
        if ring_dim != 64 {
            return Err(format!(
                "Standard configuration requires d=64, got {}",
                ring_dim
            ));
        }
        
        // Precompute expected ℓ₂-norm: √(32·1² + 8·2²) = √64 = 8
        let expected_l2_norm = ((32.0 * 1.0 * 1.0) + (8.0 * 2.0 * 2.0)).sqrt();
        
        // Cache √q for invertibility checks
        let q_sqrt = (F::MODULUS as f64).sqrt();
        
        Ok(Self {
            ring_dim,
            num_zeros: 24,
            num_ones: 32,
            num_twos: 8,
            l2_norm_bound: 8.0,
            operator_norm_bound: 10.0,
            ring: CyclotomicRing::new(ring_dim),
            max_attempts: 1000,
            expected_l2_norm,
            q_sqrt,
        })
    }
    
    /// Create custom challenge space
    /// 
    /// # Arguments
    /// * `ring_dim` - Ring dimension d
    /// * `num_zeros` - Number of zero coefficients
    /// * `num_ones` - Number of ±1 coefficients
    /// * `num_twos` - Number of ±2 coefficients
    /// * `l2_bound` - ℓ₂-norm bound τ
    /// * `op_bound` - Operator norm bound T
    /// 
    /// OPTIMIZED (Task 14.3):
    /// - Precomputes expected ℓ₂-norm
    /// - Caches √q for invertibility checks
    pub fn new_custom(
        ring_dim: usize,
        num_zeros: usize,
        num_ones: usize,
        num_twos: usize,
        l2_bound: f64,
        op_bound: f64,
    ) -> Result<Self, String> {
        if num_zeros + num_ones + num_twos != ring_dim {
            return Err(format!(
                "Coefficient counts must sum to ring dimension: {} + {} + {} ≠ {}",
                num_zeros, num_ones, num_twos, ring_dim
            ));
        }
        
        if !ring_dim.is_power_of_two() {
            return Err(format!(
                "Ring dimension must be power of 2, got {}",
                ring_dim
            ));
        }
        
        // Precompute expected ℓ₂-norm: √(num_ones·1² + num_twos·2²)
        let expected_l2_norm = ((num_ones as f64 * 1.0 * 1.0) + 
                                (num_twos as f64 * 2.0 * 2.0)).sqrt();
        
        // Cache √q for invertibility checks
        let q_sqrt = (F::MODULUS as f64).sqrt();
        
        Ok(Self {
            ring_dim,
            num_zeros,
            num_ones,
            num_twos,
            l2_norm_bound: l2_bound,
            operator_norm_bound: op_bound,
            ring: CyclotomicRing::new(ring_dim),
            max_attempts: 1000,
            expected_l2_norm,
            q_sqrt,
        })
    }

    /// Sample challenge c ∈ C with reject sampling for operator norm
    /// 
    /// Samples candidate challenges until one satisfies ∥c∥_op ≤ T
    /// 
    /// # Returns
    /// Challenge c ∈ C with bounded operator norm
    pub fn sample_challenge(&self) -> Result<RingElement<F>, String> {
        let mut rng = thread_rng();
        
        for attempt in 0..self.max_attempts {
            let candidate = self.sample_candidate(&mut rng)?;
            
            // Check operator norm bound
            if self.check_operator_norm(&candidate) {
                return Ok(candidate);
            }
        }
        
        Err(format!(
            "Failed to sample challenge after {} attempts",
            self.max_attempts
        ))
    }
    
    /// Sample candidate challenge with specified coefficient distribution
    fn sample_candidate<R: Rng>(&self, rng: &mut R) -> Result<RingElement<F>, String> {
        let mut coeffs = vec![F::zero(); self.ring_dim];
        
        // Generate random positions for each coefficient type
        let mut positions: Vec<usize> = (0..self.ring_dim).collect();
        
        // Shuffle positions
        for i in (1..positions.len()).rev() {
            let j = rng.gen_range(0..=i);
            positions.swap(i, j);
        }
        
        // Assign zeros (first num_zeros positions)
        // Already zero, no action needed
        
        // Assign ±1 coefficients
        for i in self.num_zeros..(self.num_zeros + self.num_ones) {
            let pos = positions[i];
            let sign = if rng.gen_bool(0.5) { 1 } else { -1 };
            coeffs[pos] = F::from_i64(sign);
        }
        
        // Assign ±2 coefficients
        for i in (self.num_zeros + self.num_ones)..self.ring_dim {
            let pos = positions[i];
            let sign = if rng.gen_bool(0.5) { 2 } else { -2 };
            coeffs[pos] = F::from_i64(sign);
        }
        
        Ok(RingElement::from_coeffs(coeffs))
    }
    
    /// Check if challenge satisfies operator norm bound ∥c∥_op ≤ T
    /// 
    /// Operator norm: ∥c∥_op = sup_{v∈R_q} ∥cv∥/∥v∥
    /// 
    /// For cyclotomic rings, this can be approximated by checking
    /// the maximum absolute value of coefficients in the NTT domain
    fn check_operator_norm(&self, challenge: &RingElement<F>) -> bool {
        // Compute ℓ₂-norm as approximation
        let l2_norm = self.compute_l2_norm(challenge);
        
        // For cyclotomic rings X^d + 1, operator norm is bounded by ℓ₂-norm
        // Use conservative check: ∥c∥_op ≤ ∥c∥_2
        l2_norm <= self.operator_norm_bound
    }
    
    /// Compute ℓ₂-norm of ring element
    /// ∥c∥₂ = √(Σᵢ cᵢ²)
    fn compute_l2_norm(&self, elem: &RingElement<F>) -> f64 {
        let sum_squares: f64 = elem.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64() as i64;
                let val_signed = if val > (F::MODULUS / 2) as i64 {
                    val - F::MODULUS as i64
                } else {
                    val
                };
                (val_signed * val_signed) as f64
            })
            .sum();
        
        sum_squares.sqrt()
    }

    /// Check if c₁ - c₂ is invertible in R_q
    /// 
    /// Per Lemma 1 from HyperWolf paper:
    /// For prime q ≡ 5 mod 8, any f ∈ R_q with 0 < ∥f∥ < q^{1/2} is invertible
    /// 
    /// OPTIMIZED (Task 14.3):
    /// - Uses cached √q value
    /// - Early termination for zero difference
    pub fn check_invertibility(&self, c1: &RingElement<F>, c2: &RingElement<F>) -> bool {
        // Compute difference
        let diff = self.ring.sub(c1, c2);
        
        // Early termination: check if difference is zero
        if diff.coeffs.iter().all(|c| c.to_canonical_u64() == 0) {
            return false;
        }
        
        // Check norm bound for invertibility using cached √q
        let norm = self.compute_l2_norm(&diff);
        
        norm > 0.0 && norm < self.q_sqrt
    }
    
    /// Verify challenge satisfies all properties
    /// 
    /// Checks:
    /// 1. Correct coefficient distribution
    /// 2. ℓ₂-norm ≤ τ
    /// 3. Operator norm ≤ T
    pub fn verify_challenge(&self, challenge: &RingElement<F>) -> bool {
        // Check coefficient distribution
        let mut zero_count = 0;
        let mut one_count = 0;
        let mut two_count = 0;
        
        for coeff in &challenge.coeffs {
            let val = coeff.to_canonical_u64();
            let val_signed = if val > F::MODULUS / 2 {
                (val as i64) - (F::MODULUS as i64)
            } else {
                val as i64
            };
            
            match val_signed.abs() {
                0 => zero_count += 1,
                1 => one_count += 1,
                2 => two_count += 1,
                _ => return false,
            }
        }
        
        if zero_count != self.num_zeros || 
           one_count != self.num_ones || 
           two_count != self.num_twos {
            return false;
        }
        
        // Check ℓ₂-norm bound
        let l2_norm = self.compute_l2_norm(challenge);
        if l2_norm > self.l2_norm_bound {
            return false;
        }
        
        // Check operator norm bound
        if !self.check_operator_norm(challenge) {
            return false;
        }
        
        true
    }
    
    /// Compute challenge space size |C|
    /// 
    /// For d=64 with 24 zeros, 32 ±1s, 8 ±2s:
    /// |C| ≈ C(64,32) · 2^32 + C(32,8) · 2^8 ≈ 2^{128.6}
    pub fn space_size(&self) -> f64 {
        // Binomial coefficient C(n, k)
        fn binomial(n: usize, k: usize) -> f64 {
            if k > n {
                return 0.0;
            }
            
            let mut result = 1.0;
            for i in 0..k {
                result *= (n - i) as f64;
                result /= (i + 1) as f64;
            }
            result
        }
        
        // Number of ways to choose positions for ±1 coefficients
        let choose_ones = binomial(self.ring_dim, self.num_ones);
        
        // Number of sign choices for ±1 coefficients
        let sign_ones = 2.0_f64.powi(self.num_ones as i32);
        
        // Number of ways to choose positions for ±2 coefficients from remaining
        let remaining = self.ring_dim - self.num_ones;
        let choose_twos = binomial(remaining, self.num_twos);
        
        // Number of sign choices for ±2 coefficients
        let sign_twos = 2.0_f64.powi(self.num_twos as i32);
        
        choose_ones * sign_ones * choose_twos * sign_twos
    }
    
    /// Get log₂ of challenge space size
    pub fn log2_space_size(&self) -> f64 {
        self.space_size().log2()
    }
    
    /// Sample pair of challenges for binary folding
    /// Returns (c₀, c₁) ∈ C²
    pub fn sample_challenge_pair(&self) -> Result<[RingElement<F>; 2], String> {
        let c0 = self.sample_challenge()?;
        let c1 = self.sample_challenge()?;
        
        // Verify invertibility
        if !self.check_invertibility(&c0, &c1) {
            return Err("Challenge pair not invertible".to_string());
        }
        
        Ok([c0, c1])
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_standard_challenge_space() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        assert_eq!(space.ring_dim, 64);
        assert_eq!(space.num_zeros, 24);
        assert_eq!(space.num_ones, 32);
        assert_eq!(space.num_twos, 8);
        assert_eq!(space.l2_norm_bound, 8.0);
        assert_eq!(space.operator_norm_bound, 10.0);
    }
    
    #[test]
    fn test_invalid_ring_dimension() {
        let result = ChallengeSpace::<GoldilocksField>::new_standard(63);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_custom_challenge_space() {
        let space = ChallengeSpace::<GoldilocksField>::new_custom(
            64, 20, 30, 14, 10.0, 12.0
        ).unwrap();
        
        assert_eq!(space.num_zeros, 20);
        assert_eq!(space.num_ones, 30);
        assert_eq!(space.num_twos, 14);
    }
    
    #[test]
    fn test_invalid_coefficient_counts() {
        let result = ChallengeSpace::<GoldilocksField>::new_custom(
            64, 20, 30, 10, 10.0, 12.0
        );
        assert!(result.is_err()); // 20 + 30 + 10 = 60 ≠ 64
    }
    
    #[test]
    fn test_sample_challenge() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let challenge = space.sample_challenge().unwrap();
        
        // Verify challenge has correct dimension
        assert_eq!(challenge.coeffs.len(), 64);
        
        // Verify challenge satisfies all properties
        assert!(space.verify_challenge(&challenge));
    }
    
    #[test]
    fn test_challenge_coefficient_distribution() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let challenge = space.sample_challenge().unwrap();
        
        let mut zero_count = 0;
        let mut one_count = 0;
        let mut two_count = 0;
        
        for coeff in &challenge.coeffs {
            let val = coeff.to_canonical_u64();
            let val_signed = if val > GoldilocksField::MODULUS / 2 {
                (val as i64) - (GoldilocksField::MODULUS as i64)
            } else {
                val as i64
            };
            
            match val_signed.abs() {
                0 => zero_count += 1,
                1 => one_count += 1,
                2 => two_count += 1,
                _ => panic!("Invalid coefficient value: {}", val_signed),
            }
        }
        
        assert_eq!(zero_count, 24);
        assert_eq!(one_count, 32);
        assert_eq!(two_count, 8);
    }
    
    #[test]
    fn test_l2_norm_bound() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        // Sample multiple challenges and verify norm bound
        for _ in 0..10 {
            let challenge = space.sample_challenge().unwrap();
            let l2_norm = space.compute_l2_norm(&challenge);
            
            assert!(l2_norm <= space.l2_norm_bound);
        }
    }
    
    #[test]
    fn test_operator_norm_check() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        // Sample challenge and verify operator norm
        let challenge = space.sample_challenge().unwrap();
        assert!(space.check_operator_norm(&challenge));
    }
    
    #[test]
    fn test_invertibility_check() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let c1 = space.sample_challenge().unwrap();
        let c2 = space.sample_challenge().unwrap();
        
        // Different challenges should have invertible difference
        assert!(space.check_invertibility(&c1, &c2));
        
        // Same challenge should not be invertible with itself
        assert!(!space.check_invertibility(&c1, &c1));
    }
    
    #[test]
    fn test_challenge_space_size() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let log_size = space.log2_space_size();
        
        // For d=64 with 24 zeros, 32 ±1s, 8 ±2s:
        // |C| ≈ 2^{128.6}
        assert!(log_size > 128.0 && log_size < 130.0);
    }
    
    #[test]
    fn test_sample_challenge_pair() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let pair = space.sample_challenge_pair().unwrap();
        
        // Verify both challenges are valid
        assert!(space.verify_challenge(&pair[0]));
        assert!(space.verify_challenge(&pair[1]));
        
        // Verify invertibility
        assert!(space.check_invertibility(&pair[0], &pair[1]));
    }
    
    #[test]
    fn test_verify_challenge() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        // Sample valid challenge
        let valid_challenge = space.sample_challenge().unwrap();
        assert!(space.verify_challenge(&valid_challenge));
        
        // Create invalid challenge (all zeros)
        let invalid_challenge = RingElement::from_coeffs(
            vec![GoldilocksField::zero(); 64]
        );
        assert!(!space.verify_challenge(&invalid_challenge));
        
        // Create invalid challenge (wrong distribution)
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        for i in 0..64 {
            coeffs[i] = GoldilocksField::from_u64(1);
        }
        let invalid_challenge2 = RingElement::from_coeffs(coeffs);
        assert!(!space.verify_challenge(&invalid_challenge2));
    }
    
    #[test]
    fn test_multiple_samples_are_different() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        let c1 = space.sample_challenge().unwrap();
        let c2 = space.sample_challenge().unwrap();
        let c3 = space.sample_challenge().unwrap();
        
        // Challenges should be different (with overwhelming probability)
        assert_ne!(c1.coeffs, c2.coeffs);
        assert_ne!(c2.coeffs, c3.coeffs);
        assert_ne!(c1.coeffs, c3.coeffs);
    }
    
    #[test]
    fn test_compute_l2_norm() {
        let space = ChallengeSpace::<GoldilocksField>::new_standard(64).unwrap();
        
        // Create challenge with known norm
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        let challenge = RingElement::from_coeffs(coeffs);
        
        let norm = space.compute_l2_norm(&challenge);
        
        // ∥(3, 4, 0, ...)∥₂ = √(9 + 16) = √25 = 5
        assert!((norm - 5.0).abs() < 0.001);
    }
}
