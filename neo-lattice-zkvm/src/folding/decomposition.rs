// Witness Decomposition for Norm Control
// Implements NEO-11 and NEO-12 requirements for witness decomposition

use crate::field::Field;
use crate::ring::RingElement;
use crate::commitment::{Commitment, AjtaiCommitmentScheme};
use crate::polynomial::MultilinearPolynomial;

/// Witness decomposition into base-b digits
/// Decomposes w with ||w||_∞ ≤ B into w = Σⱼ bʲ·wⱼ where ||wⱼ||_∞ < b
#[derive(Clone, Debug)]
pub struct WitnessDecomposition<F: Field> {
    /// Decomposition base b
    pub base: u64,
    /// Number of digits ℓ = ⌈log_b(B)⌉
    pub num_digits: usize,
    /// Original norm bound B
    pub norm_bound: u64,
    /// Decomposed witnesses w₀, ..., w_{ℓ-1}
    pub digits: Vec<Vec<F>>,
}

impl<F: Field> WitnessDecomposition<F> {
    /// Create decomposition with optimal base selection
    /// For norm bound B, choose b ≈ √B
    pub fn new(witness: &[F], norm_bound: u64) -> Result<Self, String> {
        // Choose base b ≈ √B for optimal decomposition
        let base = Self::optimal_base(norm_bound);
        
        // Compute number of digits: ℓ = ⌈log_b(B)⌉
        let num_digits = Self::compute_num_digits(norm_bound, base);
        
        // Decompose witness
        let digits = Self::decompose_witness(witness, base, num_digits)?;
        
        Ok(Self {
            base,
            num_digits,
            norm_bound,
            digits,
        })
    }

    /// Create decomposition with custom base
    pub fn with_base(witness: &[F], norm_bound: u64, base: u64) -> Result<Self, String> {
        if base < 2 {
            return Err("Base must be at least 2".to_string());
        }

        let num_digits = Self::compute_num_digits(norm_bound, base);
        let digits = Self::decompose_witness(witness, base, num_digits)?;
        
        Ok(Self {
            base,
            num_digits,
            norm_bound,
            digits,
        })
    }

    /// Compute optimal base: b ≈ √B
    fn optimal_base(norm_bound: u64) -> u64 {
        let sqrt_b = (norm_bound as f64).sqrt() as u64;
        sqrt_b.max(2) // Ensure base is at least 2
    }

    /// Compute number of digits: ℓ = ⌈log_b(B)⌉
    fn compute_num_digits(norm_bound: u64, base: u64) -> usize {
        if norm_bound == 0 {
            return 1;
        }
        
        let log_b = (norm_bound as f64).log(base as f64);
        log_b.ceil() as usize
    }

    /// Decompose witness into base-b digits with balanced representation
    /// Each element w[i] = Σⱼ bʲ·wⱼ[i] where wⱼ[i] ∈ [-b/2, b/2)
    fn decompose_witness(
        witness: &[F],
        base: u64,
        num_digits: usize,
    ) -> Result<Vec<Vec<F>>, String> {
        let n = witness.len();
        let mut digits = vec![vec![F::zero(); n]; num_digits];
        
        for (i, &w_i) in witness.iter().enumerate() {
            // Convert field element to canonical u64
            let mut value = w_i.to_canonical_u64();
            let modulus = F::MODULUS;
            
            // Use balanced representation: map to [-q/2, q/2]
            if value > modulus / 2 {
                value = modulus - value;
                // Handle negative values
                let decomp = Self::decompose_value_balanced(value, base, num_digits);
                for (j, digit) in decomp.iter().enumerate() {
                    // Negate the digits
                    if *digit != 0 {
                        digits[j][i] = F::from_u64(modulus - digit);
                    }
                }
            } else {
                let decomp = Self::decompose_value_balanced(value, base, num_digits);
                for (j, digit) in decomp.iter().enumerate() {
                    digits[j][i] = F::from_u64(digit);
                }
            }
        }
        
        Ok(digits)
    }

    /// Decompose a single value into base-b digits with balanced representation
    /// Returns digits d₀, ..., d_{ℓ-1} where value = Σⱼ bʲ·dⱼ and |dⱼ| < b/2
    fn decompose_value_balanced(mut value: u64, base: u64, num_digits: usize) -> Vec<u64> {
        let mut digits = vec![0u64; num_digits];
        let half_base = base / 2;
        
        for j in 0..num_digits {
            let mut digit = value % base;
            value /= base;
            
            // Balance: if digit > b/2, use negative representation
            if digit > half_base {
                digit = base - digit;
                value += 1; // Carry
            }
            
            digits[j] = digit;
        }
        
        digits
    }

    /// Verify decomposition correctness: w = Σⱼ bʲ·wⱼ
    pub fn verify_decomposition(&self, original: &[F]) -> bool {
        let n = original.len();
        
        for i in 0..n {
            let mut reconstructed = F::zero();
            let mut base_power = F::one();
            let base_field = F::from_u64(self.base);
            
            for j in 0..self.num_digits {
                let term = self.digits[j][i].mul(&base_power);
                reconstructed = reconstructed.add(&term);
                base_power = base_power.mul(&base_field);
            }
            
            if reconstructed != original[i] {
                return false;
            }
        }
        
        true
    }

    /// Verify norm bounds: ||wⱼ||_∞ < b for all j
    pub fn verify_norm_bounds(&self) -> bool {
        let half_base = self.base / 2;
        
        for digit_witness in &self.digits {
            for &value in digit_witness {
                let canonical = value.to_canonical_u64();
                let modulus = F::MODULUS;
                
                // Check balanced representation: value in [-b/2, b/2)
                let abs_value = if canonical > modulus / 2 {
                    modulus - canonical
                } else {
                    canonical
                };
                
                if abs_value >= half_base {
                    return false;
                }
            }
        }
        
        true
    }

    /// Get digit witness at index j
    pub fn get_digit(&self, j: usize) -> Option<&Vec<F>> {
        self.digits.get(j)
    }

    /// Compute optimal base for RLC with L instances
    /// Choose b such that after RLC, ||Σᵢ ρᵢ·wᵢ,ⱼ||_∞ ≤ β
    pub fn optimal_base_for_rlc(
        norm_bound: u64,
        target_norm: u64,
        num_instances: usize,
        challenge_norm: u64,
    ) -> u64 {
        // b ≈ (β / (L·||ρ||_∞))^(1/ℓ)
        let num_digits = Self::compute_num_digits(norm_bound, 2);
        
        let ratio = target_norm as f64 / (num_instances as f64 * challenge_norm as f64);
        let base = ratio.powf(1.0 / num_digits as f64);
        
        base.max(2.0) as u64
    }
}

/// Proof of witness decomposition
#[derive(Clone, Debug)]
pub struct DecompositionProof<F: Field> {
    /// Commitments to digit witnesses: C₀, ..., C_{ℓ-1}
    pub digit_commitments: Vec<Commitment<F>>,
    /// Digit evaluations at point r: y₀, ..., y_{ℓ-1}
    pub digit_evaluations: Vec<F>,
    /// Evaluation point r
    pub point: Vec<F>,
}

impl<F: Field> DecompositionProof<F> {
    /// Create decomposition proof
    pub fn new(
        decomposition: &WitnessDecomposition<F>,
        commitment_scheme: &AjtaiCommitmentScheme<F>,
        point: &[F],
    ) -> Result<Self, String> {
        let mut digit_commitments = Vec::with_capacity(decomposition.num_digits);
        let mut digit_evaluations = Vec::with_capacity(decomposition.num_digits);
        
        // Commit to each digit witness and compute evaluation
        for digit_witness in &decomposition.digits {
            // Convert to ring elements for commitment
            let ring_witness: Vec<RingElement<F>> = digit_witness
                .iter()
                .map(|&f| RingElement::from_constant(f))
                .collect();
            
            // Compute commitment
            let commitment = commitment_scheme.commit(&ring_witness)?;
            digit_commitments.push(commitment);
            
            // Compute MLE evaluation at point
            let mle = MultilinearPolynomial::new(digit_witness.clone());
            let evaluation = mle.evaluate(point);
            digit_evaluations.push(evaluation);
        }
        
        Ok(Self {
            digit_commitments,
            digit_evaluations,
            point: point.to_vec(),
        })
    }

    /// Verify commitment reconstruction: C = Σⱼ bʲ·Cⱼ
    pub fn verify_commitment_reconstruction(
        &self,
        original_commitment: &Commitment<F>,
        base: u64,
    ) -> Result<bool, String> {
        // Compute Σⱼ bʲ·Cⱼ
        let mut base_power = F::one();
        let base_field = F::from_u64(base);
        
        let mut ring_scalars = Vec::with_capacity(self.digit_commitments.len());
        for _ in 0..self.digit_commitments.len() {
            ring_scalars.push(RingElement::from_constant(base_power));
            base_power = base_power.mul(&base_field);
        }
        
        // Get ring from global configuration
        let ring_degree = crate::config::get_ring_degree();
        let ring = crate::ring::CyclotomicRing::new(ring_degree);
        let reconstructed = Commitment::linear_combination(
            &self.digit_commitments,
            &ring_scalars,
            &ring,
        );
        
        Ok(reconstructed == *original_commitment)
    }

    /// Verify evaluation reconstruction: y = Σⱼ bʲ·yⱼ
    pub fn verify_evaluation_reconstruction(
        &self,
        original_evaluation: F,
        base: u64,
    ) -> bool {
        let mut reconstructed = F::zero();
        let mut base_power = F::one();
        let base_field = F::from_u64(base);
        
        for &y_j in &self.digit_evaluations {
            let term = y_j.mul(&base_power);
            reconstructed = reconstructed.add(&term);
            base_power = base_power.mul(&base_field);
        }
        
        reconstructed == original_evaluation
    }

    /// Get number of digits
    pub fn num_digits(&self) -> usize {
        self.digit_commitments.len()
    }
}

/// Decomposition with RLC (Random Linear Combination) support
pub struct RLCDecomposition<F: Field> {
    /// Base decomposition
    decomposition: WitnessDecomposition<F>,
    /// Number of instances being combined
    num_instances: usize,
    /// Target norm after RLC
    target_norm: u64,
}

impl<F: Field> RLCDecomposition<F> {
    /// Create RLC decomposition with optimal parameters
    pub fn new(
        witness: &[F],
        norm_bound: u64,
        num_instances: usize,
        target_norm: u64,
        challenge_norm: u64,
    ) -> Result<Self, String> {
        // Compute optimal base for RLC
        let base = WitnessDecomposition::optimal_base_for_rlc(
            norm_bound,
            target_norm,
            num_instances,
            challenge_norm,
        );
        
        let decomposition = WitnessDecomposition::with_base(witness, norm_bound, base)?;
        
        Ok(Self {
            decomposition,
            num_instances,
            target_norm,
        })
    }

    /// Verify that RLC will maintain norm bounds
    pub fn verify_rlc_norm_bound(&self, challenge_norm: u64) -> bool {
        // After RLC: ||Σᵢ ρᵢ·wᵢ,ⱼ||_∞ ≤ L·||ρ||_∞·||wⱼ||_∞
        let max_digit_norm = self.decomposition.base / 2;
        let rlc_norm = self.num_instances as u64 * challenge_norm * max_digit_norm;
        
        rlc_norm <= self.target_norm
    }

    /// Get base decomposition
    pub fn decomposition(&self) -> &WitnessDecomposition<F> {
        &self.decomposition
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_decompose_value_balanced() {
        let value = 100u64;
        let base = 10u64;
        let num_digits = 3;
        
        let digits = WitnessDecomposition::<GoldilocksField>::decompose_value_balanced(
            value, base, num_digits
        );
        
        // Reconstruct value
        let mut reconstructed = 0u64;
        let mut base_power = 1u64;
        for digit in digits {
            reconstructed += digit * base_power;
            base_power *= base;
        }
        
        assert_eq!(reconstructed, value);
    }

    #[test]
    fn test_witness_decomposition() {
        type F = GoldilocksField;
        
        let witness = vec![
            F::from_u64(100),
            F::from_u64(200),
            F::from_u64(50),
        ];
        
        let norm_bound = 200;
        let decomposition = WitnessDecomposition::new(&witness, norm_bound).unwrap();
        
        // Verify decomposition correctness
        assert!(decomposition.verify_decomposition(&witness));
        
        // Verify norm bounds
        assert!(decomposition.verify_norm_bounds());
    }

    #[test]
    fn test_optimal_base_selection() {
        let norm_bound = 1024u64;
        let base = WitnessDecomposition::<GoldilocksField>::optimal_base(norm_bound);
        
        // Should be approximately √1024 = 32
        assert!(base >= 30 && base <= 34);
    }

    #[test]
    fn test_decomposition_proof() {
        type F = GoldilocksField;
        
        let witness = vec![
            F::from_u64(10),
            F::from_u64(20),
            F::from_u64(30),
            F::from_u64(40),
        ];
        
        let norm_bound = 50;
        let decomposition = WitnessDecomposition::new(&witness, norm_bound).unwrap();
        
        // Verify reconstruction
        assert!(decomposition.verify_decomposition(&witness));
        
        // Verify each digit has small norm
        for digit_witness in &decomposition.digits {
            for &value in digit_witness {
                let canonical = value.to_canonical_u64();
                assert!(canonical < decomposition.base);
            }
        }
    }

    #[test]
    fn test_rlc_decomposition() {
        type F = GoldilocksField;
        
        let witness = vec![F::from_u64(100); 8];
        let norm_bound = 100;
        let num_instances = 2;
        let target_norm = 200;
        let challenge_norm = 2;
        
        let rlc_decomp = RLCDecomposition::new(
            &witness,
            norm_bound,
            num_instances,
            target_norm,
            challenge_norm,
        ).unwrap();
        
        // Verify RLC norm bound
        assert!(rlc_decomp.verify_rlc_norm_bound(challenge_norm));
    }

    #[test]
    fn test_num_digits_computation() {
        let norm_bound = 1000u64;
        let base = 10u64;
        
        let num_digits = WitnessDecomposition::<GoldilocksField>::compute_num_digits(
            norm_bound, base
        );
        
        // log_10(1000) = 3, so need 3 digits
        assert_eq!(num_digits, 3);
    }
}
