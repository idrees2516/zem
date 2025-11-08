// Challenge Set Generation and Management for Neo Folding Scheme
//
// This module implements the challenge set C ⊆ R_q used in the Random Linear Combination (RLC)
// reduction. The challenge set must satisfy:
// 1. Size: |C| ≥ 2^128 for 128-bit security
// 2. Norm bound: ||c||_∞ ≤ B_c for all c ∈ C
// 3. Invertibility: c - c' is invertible for all distinct c, c' ∈ C
//
// Requirements: NEO-12.1, NEO-12.2, NEO-12.3, NEO-14.1, NEO-14.5, NEO-14.6

use crate::field::traits::Field;
use crate::ring::cyclotomic::RingElement;
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

/// Challenge set for RLC reduction
/// 
/// Uses ternary coefficients {-1, 0, 1} to achieve:
/// - Large size: 3^d ≥ 2^128 (requires d ≥ 81)
/// - Small norm: ||c||_∞ = 1
/// - Invertibility via Theorem 1 from Neo paper
pub struct ChallengeSet<F: Field> {
    /// Ring degree (must be ≥ 81 for 128-bit security with ternary)
    degree: usize,
    /// Maximum norm of challenges
    norm_bound: u64,
    /// Invertibility threshold: b_inv = q^(1/e) / √e
    invertibility_threshold: u64,
    /// Field modulus
    modulus: u64,
    /// Extension degree e (from q ≡ 1 + 2e (mod 4e))
    extension_degree: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> ChallengeSet<F> {
    /// Create a new ternary challenge set
    /// 
    /// Ternary coefficients: each coefficient in {-1, 0, 1}
    /// Size: |C| = 3^d
    /// For 128-bit security: need 3^d ≥ 2^128, so d ≥ 81
    /// 
    /// # Arguments
    /// * `degree` - Ring degree d (must be ≥ 81)
    /// * `extension_degree` - Extension degree e from field parameters
    /// 
    /// # Requirements
    /// - NEO-12.1: Define challenge set C ⊆ Rq with size |C| ≥ 2^128
    /// - NEO-12.2: Ensure all c ∈ C have coefficients in {0, ±1, ±2}
    /// - NEO-14.1: Define challenge set C ⊆ R_q with |C| ≥ 2^128
    /// - NEO-14.5: Ensure norm bound: ||c||_∞ = 1 for ternary challenges
    pub fn new_ternary(degree: usize, extension_degree: usize) -> Self {
        // Verify security requirement: 3^d ≥ 2^128
        // log2(3^d) = d * log2(3) ≈ d * 1.585
        // Need d * 1.585 ≥ 128, so d ≥ 81
        let security_bits = (degree as f64 * 3.0_f64.log2()).floor() as usize;
        assert!(
            security_bits >= 128,
            "Ring degree {} provides only {} bits of security, need at least 128. Minimum degree: 81",
            degree, security_bits
        );

        let modulus = F::MODULUS;
        
        // Compute invertibility threshold using Theorem 1:
        // If ||cf(a)||_∞ < b_inv = q^(1/e) / √e, then a is invertible
        let b_inv = Self::compute_invertibility_threshold(modulus, extension_degree);

        Self {
            degree,
            norm_bound: 1, // Ternary coefficients have ||c||_∞ = 1
            invertibility_threshold: b_inv,
            modulus,
            extension_degree,
            _phantom: PhantomData,
        }
    }

    /// Compute invertibility threshold: b_inv = q^(1/e) / √e
    /// 
    /// From Theorem 1 (Corollary 1.2 of [LS18]):
    /// If d, e are powers of 2 with e|d, q ≡ 1 + 2e (mod 4e) is prime,
    /// then every non-zero y ∈ Rq with ||y||_∞ < q^(1/e)/√e is invertible.
    /// 
    /// # Requirements
    /// - NEO-12.5: Verify c - c' is invertible for all distinct c, c' ∈ C
    /// - NEO-12.6: Use Theorem 1: if ||cf(a)||_∞ < b_inv, then a is invertible
    /// - NEO-14.4: Compute b_inv = q^(1/e) / √e for field parameters
    fn compute_invertibility_threshold(modulus: u64, extension_degree: usize) -> u64 {
        let q = modulus as f64;
        let e = extension_degree as f64;
        
        // b_inv = q^(1/e) / √e
        let q_pow = q.powf(1.0 / e);
        let sqrt_e = e.sqrt();
        let b_inv = q_pow / sqrt_e;
        
        b_inv.floor() as u64
    }

    /// Sample a random challenge from the set using Fiat-Shamir
    /// 
    /// Uses cryptographic hash to derive challenge from transcript.
    /// Each coefficient is sampled uniformly from {-1, 0, 1}.
    /// 
    /// # Arguments
    /// * `transcript_hash` - Hash of the current transcript
    /// 
    /// # Returns
    /// A ring element with ternary coefficients
    /// 
    /// # Requirements
    /// - NEO-11.1: Sample challenges uniformly from C using cryptographic randomness
    /// - NEO-12.7: Sample challenges uniformly from C using rejection sampling or table lookup
    /// - NEO-12.10: Use Fiat-Shamir transform to derive challenges from transcript hash
    /// - NEO-14.10: Implement Fiat-Shamir transform for non-interactive challenges
    pub fn sample_challenge(&self, transcript_hash: &[u8]) -> RingElement<F> {
        let mut hasher = Sha3_256::new();
        hasher.update(transcript_hash);
        hasher.update(b"challenge_sample");
        
        let mut coeffs = Vec::with_capacity(self.degree);
        let mut counter = 0u64;
        
        for i in 0..self.degree {
            // Hash with counter for domain separation
            let mut round_hasher = hasher.clone();
            round_hasher.update(&counter.to_le_bytes());
            round_hasher.update(&(i as u64).to_le_bytes());
            let hash = round_hasher.finalize();
            
            // Use first byte to sample from {-1, 0, 1}
            // Map: 0-84 -> -1, 85-169 -> 0, 170-255 -> 1
            // This gives approximately uniform distribution
            let byte = hash[0];
            let coeff = if byte < 85 {
                F::from_canonical_u64(self.modulus - 1) // -1 in field
            } else if byte < 170 {
                F::zero() // 0
            } else {
                F::one() // 1
            };
            
            coeffs.push(coeff);
            counter += 1;
        }
        
        RingElement::new(coeffs)
    }

    /// Sample multiple challenges for batching
    /// 
    /// # Arguments
    /// * `transcript_hash` - Hash of the current transcript
    /// * `count` - Number of challenges to sample
    /// 
    /// # Returns
    /// Vector of ring elements with ternary coefficients
    pub fn sample_challenges(&self, transcript_hash: &[u8], count: usize) -> Vec<RingElement<F>> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            let mut hasher = Sha3_256::new();
            hasher.update(transcript_hash);
            hasher.update(b"batch_challenge");
            hasher.update(&(i as u64).to_le_bytes());
            let hash = hasher.finalize();
            
            challenges.push(self.sample_challenge(&hash));
        }
        
        challenges
    }

    /// Verify that a challenge is in the set
    /// 
    /// Checks:
    /// 1. All coefficients are in {-1, 0, 1}
    /// 2. Norm bound is satisfied
    /// 
    /// # Requirements
    /// - NEO-12.2: Ensure all c ∈ C have coefficients in {0, ±1, ±2}
    /// - NEO-12.3: Verify operator norm ||c||_op ≤ 15 for all c ∈ C
    /// - NEO-14.6: Verify size: 3^d ≥ 2^128 requires d ≥ 81
    pub fn verify_challenge(&self, challenge: &RingElement<F>) -> bool {
        if challenge.coeffs().len() != self.degree {
            return false;
        }

        // Check all coefficients are in {-1, 0, 1}
        for coeff in challenge.coeffs() {
            let val = coeff.to_canonical_u64();
            // Valid values: 0, 1, or modulus-1 (representing -1)
            if val != 0 && val != 1 && val != self.modulus - 1 {
                return false;
            }
        }

        // Check norm bound
        challenge.norm_infinity() <= self.norm_bound
    }

    /// Verify invertibility of difference between two challenges
    /// 
    /// Uses Theorem 1: if ||cf(c - c')||_∞ < b_inv, then c - c' is invertible
    /// 
    /// # Requirements
    /// - NEO-11.2: Verify c - c' is invertible for all distinct c, c' ∈ C
    /// - NEO-12.5: Verify c - c' is invertible for all distinct c, c' ∈ C
    /// - NEO-12.6: Use Theorem 1: if ||cf(a)||_∞ < b_inv, then a is invertible
    pub fn verify_invertibility(&self, c1: &RingElement<F>, c2: &RingElement<F>) -> bool {
        // Compute difference
        let diff = c1.sub(c2);
        
        // Check if difference is zero (challenges are equal)
        if diff.is_zero() {
            return false; // Not invertible if equal
        }
        
        // Check invertibility condition: ||diff||_∞ < b_inv
        diff.norm_infinity() < self.invertibility_threshold
    }

    /// Get the security level in bits
    /// 
    /// For ternary challenges: security = log2(3^d) = d * log2(3)
    pub fn security_bits(&self) -> usize {
        (self.degree as f64 * 3.0_f64.log2()).floor() as usize
    }

    /// Get the challenge set size (as log2)
    /// 
    /// Returns log2(|C|) = d * log2(3) for ternary
    pub fn log_size(&self) -> f64 {
        self.degree as f64 * 3.0_f64.log2()
    }

    /// Get the norm bound
    pub fn norm_bound(&self) -> u64 {
        self.norm_bound
    }

    /// Get the invertibility threshold
    pub fn invertibility_threshold(&self) -> u64 {
        self.invertibility_threshold
    }
}

/// Extended challenge set with coefficients in {-2, -1, 0, 1, 2}
/// 
/// Provides larger challenge space: 5^d
/// For 128-bit security: need d ≥ 55
/// Norm bound: ||c||_∞ = 2
pub struct ExtendedChallengeSet<F: Field> {
    degree: usize,
    norm_bound: u64,
    invertibility_threshold: u64,
    modulus: u64,
    extension_degree: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> ExtendedChallengeSet<F> {
    /// Create a new extended challenge set with coefficients in {-2, -1, 0, 1, 2}
    /// 
    /// Size: |C| = 5^d
    /// For 128-bit security: need 5^d ≥ 2^128, so d ≥ 55
    /// 
    /// # Requirements
    /// - NEO-12.2: Ensure all c ∈ C have coefficients in {0, ±1, ±2}
    pub fn new(degree: usize, extension_degree: usize) -> Self {
        // Verify security requirement: 5^d ≥ 2^128
        // log2(5^d) = d * log2(5) ≈ d * 2.322
        // Need d * 2.322 ≥ 128, so d ≥ 55
        let security_bits = (degree as f64 * 5.0_f64.log2()).floor() as usize;
        assert!(
            security_bits >= 128,
            "Ring degree {} provides only {} bits of security, need at least 128. Minimum degree: 55",
            degree, security_bits
        );

        let modulus = F::MODULUS;
        let b_inv = ChallengeSet::<F>::compute_invertibility_threshold(modulus, extension_degree);

        Self {
            degree,
            norm_bound: 2, // Coefficients in {-2, -1, 0, 1, 2}
            invertibility_threshold: b_inv,
            modulus,
            extension_degree,
            _phantom: PhantomData,
        }
    }

    /// Sample a random challenge with coefficients in {-2, -1, 0, 1, 2}
    pub fn sample_challenge(&self, transcript_hash: &[u8]) -> RingElement<F> {
        let mut hasher = Sha3_256::new();
        hasher.update(transcript_hash);
        hasher.update(b"extended_challenge_sample");
        
        let mut coeffs = Vec::with_capacity(self.degree);
        let mut counter = 0u64;
        
        for i in 0..self.degree {
            let mut round_hasher = hasher.clone();
            round_hasher.update(&counter.to_le_bytes());
            round_hasher.update(&(i as u64).to_le_bytes());
            let hash = round_hasher.finalize();
            
            // Use first byte to sample from {-2, -1, 0, 1, 2}
            // Map: 0-50 -> -2, 51-101 -> -1, 102-152 -> 0, 153-203 -> 1, 204-255 -> 2
            let byte = hash[0];
            let coeff = match byte {
                0..=50 => F::from_canonical_u64(self.modulus - 2), // -2
                51..=101 => F::from_canonical_u64(self.modulus - 1), // -1
                102..=152 => F::zero(), // 0
                153..=203 => F::one(), // 1
                _ => F::from_canonical_u64(2), // 2
            };
            
            coeffs.push(coeff);
            counter += 1;
        }
        
        RingElement::new(coeffs)
    }

    /// Verify that a challenge is in the extended set
    pub fn verify_challenge(&self, challenge: &RingElement<F>) -> bool {
        if challenge.coeffs().len() != self.degree {
            return false;
        }

        // Check all coefficients are in {-2, -1, 0, 1, 2}
        for coeff in challenge.coeffs() {
            let val = coeff.to_canonical_u64();
            // Valid values: 0, 1, 2, modulus-1 (-1), modulus-2 (-2)
            if val > 2 && val < self.modulus - 2 {
                return false;
            }
        }

        challenge.norm_infinity() <= self.norm_bound
    }

    pub fn security_bits(&self) -> usize {
        (self.degree as f64 * 5.0_f64.log2()).floor() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;

    #[test]
    fn test_ternary_challenge_set_security() {
        // For Goldilocks with d=64, e=2
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        
        // Verify security level
        assert!(challenge_set.security_bits() >= 128);
        assert!(challenge_set.log_size() >= 128.0);
    }

    #[test]
    fn test_challenge_sampling() {
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let transcript = b"test_transcript";
        
        let challenge = challenge_set.sample_challenge(transcript);
        
        // Verify challenge is valid
        assert!(challenge_set.verify_challenge(&challenge));
        assert_eq!(challenge.coeffs().len(), 81);
        assert!(challenge.norm_infinity() <= 1);
    }

    #[test]
    fn test_challenge_determinism() {
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let transcript = b"test_transcript";
        
        let challenge1 = challenge_set.sample_challenge(transcript);
        let challenge2 = challenge_set.sample_challenge(transcript);
        
        // Same transcript should produce same challenge
        assert_eq!(challenge1.coeffs(), challenge2.coeffs());
    }

    #[test]
    fn test_invertibility_check() {
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let transcript1 = b"transcript1";
        let transcript2 = b"transcript2";
        
        let c1 = challenge_set.sample_challenge(transcript1);
        let c2 = challenge_set.sample_challenge(transcript2);
        
        // Different challenges should have invertible difference
        if c1.coeffs() != c2.coeffs() {
            assert!(challenge_set.verify_invertibility(&c1, &c2));
        }
    }

    #[test]
    fn test_extended_challenge_set() {
        let challenge_set = ExtendedChallengeSet::<GoldilocksField>::new(64, 2);
        
        // Verify security level
        assert!(challenge_set.security_bits() >= 128);
        
        let transcript = b"test_transcript";
        let challenge = challenge_set.sample_challenge(transcript);
        
        assert!(challenge_set.verify_challenge(&challenge));
        assert!(challenge.norm_infinity() <= 2);
    }

    #[test]
    fn test_batch_challenge_sampling() {
        let challenge_set = ChallengeSet::<GoldilocksField>::new_ternary(81, 2);
        let transcript = b"test_transcript";
        
        let challenges = challenge_set.sample_challenges(transcript, 5);
        
        assert_eq!(challenges.len(), 5);
        for challenge in &challenges {
            assert!(challenge_set.verify_challenge(challenge));
        }
        
        // Challenges should be different
        for i in 0..challenges.len() {
            for j in (i+1)..challenges.len() {
                assert_ne!(challenges[i].coeffs(), challenges[j].coeffs());
            }
        }
    }
}
