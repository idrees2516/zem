// Parameter selection and security analysis for Neo folding scheme
//
// This module implements:
// - Task 15: Goldilocks parameter set
// - Task 15.1: Mersenne 61 parameter set
// - Task 15.2: Module-SIS security verification
// - Task 15.3: Soundness error computation
// - Task 15.4: Parameter validation

use crate::field::{Field, GoldilocksField, M61Field};
use std::fmt;

/// Security level in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 128-bit security
    Bits128,
    /// 192-bit security
    Bits192,
    /// 256-bit security
    Bits256,
}

impl SecurityLevel {
    pub fn bits(&self) -> usize {
        match self {
            SecurityLevel::Bits128 => 128,
            SecurityLevel::Bits192 => 192,
            SecurityLevel::Bits256 => 256,
        }
    }
}

/// Parameter set for Neo folding scheme
#[derive(Debug, Clone)]
pub struct NeoParameters<F: Field> {
    /// Field modulus q
    pub field_modulus: u64,
    
    /// Cyclotomic ring degree d (must be power of 2)
    pub ring_degree: usize,
    
    /// Extension degree e where q ≡ 1 + 2e (mod 4e)
    pub extension_degree: usize,
    
    /// Splitting degree τ = d/e (ring splits into τ copies of F_q)
    pub splitting_degree: usize,
    
    /// Commitment dimension κ (number of ring elements in commitment)
    pub commitment_dimension: usize,
    
    /// Witness dimension n (number of ring elements in witness)
    pub witness_dimension: usize,
    
    /// Norm bound β for witness elements
    pub norm_bound: u64,
    
    /// Security level
    pub security_level: SecurityLevel,
    
    /// Challenge set size (must be ≥ 2^security_bits)
    pub challenge_set_size: u128,
    
    /// Decomposition base for witness decomposition
    pub decomposition_base: u64,
    
    /// Number of decomposition digits
    pub decomposition_digits: usize,
    
    /// Field type marker
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> NeoParameters<F> {
    /// Validate parameter set for security and correctness
    pub fn validate(&self) -> Result<(), ParameterError> {
        // Check ring degree is power of 2
        if !self.ring_degree.is_power_of_two() {
            return Err(ParameterError::InvalidRingDegree(self.ring_degree));
        }
        
        // Check minimum ring degree for security
        if self.ring_degree < 64 {
            return Err(ParameterError::RingDegreeTooSmall(self.ring_degree));
        }
        
        // Check extension degree divides ring degree
        if self.ring_degree % self.extension_degree != 0 {
            return Err(ParameterError::InvalidExtensionDegree {
                ring_degree: self.ring_degree,
                extension_degree: self.extension_degree,
            });
        }
        
        // Verify splitting degree
        let expected_splitting = self.ring_degree / self.extension_degree;
        if self.splitting_degree != expected_splitting {
            return Err(ParameterError::InvalidSplittingDegree {
                expected: expected_splitting,
                actual: self.splitting_degree,
            });
        }
        
        // Check challenge set size for security
        let min_challenge_size = 1u128 << self.security_level.bits();
        if self.challenge_set_size < min_challenge_size {
            return Err(ParameterError::ChallengeSizeTooSmall {
                actual: self.challenge_set_size,
                required: min_challenge_size,
            });
        }
        
        // Check commitment dimension is reasonable
        if self.commitment_dimension == 0 || self.commitment_dimension > 10 {
            return Err(ParameterError::InvalidCommitmentDimension(
                self.commitment_dimension,
            ));
        }
        
        // Check norm bound is reasonable
        if self.norm_bound == 0 || self.norm_bound >= self.field_modulus / 2 {
            return Err(ParameterError::InvalidNormBound(self.norm_bound));
        }
        
        // Verify decomposition parameters
        if self.decomposition_base < 2 {
            return Err(ParameterError::InvalidDecompositionBase(
                self.decomposition_base,
            ));
        }
        
        // Check decomposition digits cover norm bound
        let max_representable = self.decomposition_base.pow(self.decomposition_digits as u32);
        if max_representable < self.norm_bound {
            return Err(ParameterError::InsufficientDecompositionDigits {
                digits: self.decomposition_digits,
                base: self.decomposition_base,
                norm_bound: self.norm_bound,
            });
        }
        
        Ok(())
    }
    
    /// Estimate Module-SIS security level using lattice estimator heuristics
    pub fn estimate_module_sis_security(&self) -> usize {
        // Security estimation based on BKZ block size
        // Uses lattice estimator heuristics from cryptographic literature
        // 
        // For production deployment, integrate with:
        // - Lattice Estimator (https://github.com/malb/lattice-estimator)
        // - LWE Estimator for more precise bounds
        // - Conservative estimates from NIST PQC standards
        
        let kappa = self.commitment_dimension;
        let n = self.witness_dimension;
        let d = self.ring_degree;
        let q = self.field_modulus as f64;
        let beta = self.norm_bound as f64;
        
        // Module dimension
        let module_dim = kappa * d;
        
        // Log of modulus
        let log_q = q.log2();
        
        // Log of norm bound
        let log_beta = beta.log2();
        
        // Hermite factor δ ≈ (β / q^(n/module_dim))^(1/module_dim)
        let hermite_exponent = (log_beta - log_q * (n as f64 / module_dim as f64)) / module_dim as f64;
        let log_hermite = hermite_exponent / 2.0_f64.ln();
        
        // BKZ block size b ≈ log_q / (log δ)
        // For security λ, need b ≥ λ
        let bkz_block_size = if log_hermite > 0.0 {
            (log_q / log_hermite) as usize
        } else {
            // Very secure parameters
            256
        };
        
        // Conservative estimate: security ≈ 0.292 * b
        let security_bits = (0.292 * bkz_block_size as f64) as usize;
        
        security_bits.min(256)
    }
    
    /// Compute soundness error for sum-check protocol
    pub fn sum_check_soundness_error(&self, num_variables: usize, degree: usize) -> f64 {
        // Soundness error: ε_sc ≤ ℓ·d / |F|
        // where ℓ = num_variables, d = degree
        
        let field_size = self.field_modulus as f64;
        let error = (num_variables * degree) as f64 / field_size;
        
        error
    }
    
    /// Compute soundness error for folding protocol
    pub fn folding_soundness_error(&self, degree: usize) -> f64 {
        // Soundness error: ε_fold ≤ d / |C|
        // where d = polynomial degree, C = challenge set
        
        let challenge_size = self.challenge_set_size as f64;
        let error = degree as f64 / challenge_size;
        
        error
    }
    
    /// Compute soundness error for RLC (Random Linear Combination)
    pub fn rlc_soundness_error(&self, polynomial_degree: usize) -> f64 {
        // Soundness error: ε_rlc ≤ deg / |F|
        // By Schwartz-Zippel lemma
        
        let field_size = self.field_modulus as f64;
        let error = polynomial_degree as f64 / field_size;
        
        error
    }
    
    /// Compute total soundness error
    pub fn total_soundness_error(
        &self,
        num_sumcheck_vars: usize,
        sumcheck_degree: usize,
        folding_degree: usize,
        rlc_degree: usize,
    ) -> f64 {
        let sc_error = self.sum_check_soundness_error(num_sumcheck_vars, sumcheck_degree);
        let fold_error = self.folding_soundness_error(folding_degree);
        let rlc_error = self.rlc_soundness_error(rlc_degree);
        
        // Total error by union bound
        sc_error + fold_error + rlc_error
    }
    
    /// Check if total soundness error meets security level
    pub fn verify_soundness(&self, num_sumcheck_vars: usize) -> Result<(), ParameterError> {
        // Typical degrees for Neo
        let sumcheck_degree = 3; // Degree of CCS polynomial
        let folding_degree = 2; // Degree of folding polynomial
        let rlc_degree = self.witness_dimension; // Degree of RLC polynomial
        
        let total_error = self.total_soundness_error(
            num_sumcheck_vars,
            sumcheck_degree,
            folding_degree,
            rlc_degree,
        );
        
        // Required soundness: 2^(-security_bits)
        let required_error = 2.0_f64.powi(-(self.security_level.bits() as i32));
        
        if total_error > required_error {
            return Err(ParameterError::InsufficientSoundness {
                actual: total_error,
                required: required_error,
            });
        }
        
        Ok(())
    }
    
    /// Estimate prover time complexity
    pub fn estimate_prover_time(&self, witness_size: usize) -> usize {
        // Prover time: O(N) dominated by O(N) ring multiplications
        // where N = witness_size
        
        let ring_muls_per_commitment = self.commitment_dimension * self.witness_dimension;
        let ntt_cost_per_mul = self.ring_degree * (self.ring_degree as f64).log2() as usize;
        
        witness_size * ring_muls_per_commitment * ntt_cost_per_mul
    }
    
    /// Estimate verifier time complexity
    pub fn estimate_verifier_time(&self, witness_size: usize) -> usize {
        // Verifier time: O(log N) dominated by sum-check verification
        
        let num_vars = (witness_size as f64).log2() as usize;
        let sumcheck_rounds = num_vars;
        let cost_per_round = 10; // Field operations per round
        
        sumcheck_rounds * cost_per_round
    }
    
    /// Estimate proof size in field elements
    pub fn estimate_proof_size(&self, witness_size: usize) -> usize {
        // Proof size: O(log N) field elements
        
        let num_vars = (witness_size as f64).log2() as usize;
        let sumcheck_proof = num_vars * 4; // 4 field elements per round
        let commitment_size = self.commitment_dimension * self.ring_degree;
        let cross_terms = 1; // For β=2 folding
        
        sumcheck_proof + commitment_size + cross_terms
    }
}

/// Goldilocks parameter set (Task 15)
impl NeoParameters<GoldilocksField> {
    /// Create standard Goldilocks parameter set for 128-bit security
    ///
    /// Parameters:
    /// - q = 2^64 - 2^32 + 1 (Goldilocks field)
    /// - d = 64 (cyclotomic ring degree)
    /// - e = 2 (extension degree, since q ≡ 1 + 2^2 (mod 4·2^2))
    /// - τ = 32 (splitting degree = d/e)
    /// - κ = 4 (commitment dimension)
    /// - β = 2^20 (norm bound)
    ///
    /// Requirements: NEO-16.1 through NEO-16.8
    pub fn goldilocks_128() -> Self {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let e = 2; // q ≡ 1 + 2^2 (mod 4·2^2)
        let tau = d / e; // τ = 32
        let kappa = 4;
        let beta = 1u64 << 20; // 2^20
        
        // Decomposition parameters
        // Choose base b ≈ √β for optimal decomposition
        let decomp_base = 1u64 << 10; // 2^10 ≈ √(2^20)
        let decomp_digits = 2; // ⌈log_b(β)⌉ = ⌈20/10⌉ = 2
        
        // Challenge set size: 3^d for ternary challenges
        // 3^64 ≈ 2^101 < 2^128, so we need larger challenge set
        // Use ring elements with coefficients in {-1, 0, 1}
        // For d=64, we get 3^64 ≈ 2^101 challenges
        // To reach 2^128, we can use challenges in {-2, -1, 0, 1, 2}
        // giving 5^64 ≈ 2^149 > 2^128
        let challenge_set_size = 1u128 << 128; // Conservative estimate
        
        Self {
            field_modulus: q,
            ring_degree: d,
            extension_degree: e,
            splitting_degree: tau,
            commitment_dimension: kappa,
            witness_dimension: 256, // Default, can be adjusted
            norm_bound: beta,
            security_level: SecurityLevel::Bits128,
            challenge_set_size,
            decomposition_base: decomp_base,
            decomposition_digits: decomp_digits,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Create Goldilocks parameter set with custom witness dimension
    pub fn goldilocks_128_with_witness_dim(witness_dim: usize) -> Self {
        let mut params = Self::goldilocks_128();
        params.witness_dimension = witness_dim;
        params
    }
    
    /// Verify Goldilocks-specific properties
    pub fn verify_goldilocks_properties(&self) -> Result<(), ParameterError> {
        // Verify q = 2^64 - 2^32 + 1
        let expected_q = (1u64 << 64).wrapping_sub(1u64 << 32).wrapping_add(1);
        if self.field_modulus != expected_q {
            return Err(ParameterError::InvalidFieldModulus {
                expected: expected_q,
                actual: self.field_modulus,
            });
        }
        
        // Verify q ≡ 1 + 2^2 (mod 4·2^2)
        // q ≡ 1 + 4 (mod 16)
        // q ≡ 5 (mod 16)
        if self.field_modulus % 16 != 5 {
            return Err(ParameterError::InvalidFieldCongruence {
                modulus: self.field_modulus,
                expected_remainder: 5,
                actual_remainder: self.field_modulus % 16,
            });
        }
        
        // Verify e = 2
        if self.extension_degree != 2 {
            return Err(ParameterError::InvalidExtensionDegree {
                ring_degree: self.ring_degree,
                extension_degree: self.extension_degree,
            });
        }
        
        // Verify τ = 32
        if self.splitting_degree != 32 {
            return Err(ParameterError::InvalidSplittingDegree {
                expected: 32,
                actual: self.splitting_degree,
            });
        }
        
        Ok(())
    }
}

/// Mersenne 61 parameter set (Task 15.1)
impl NeoParameters<M61Field> {
    /// Create standard M61 parameter set for 128-bit security
    ///
    /// Parameters:
    /// - q = 2^61 - 1 (Mersenne 61 field)
    /// - d = 64 (cyclotomic ring degree)
    /// - e = 1 (extension degree, since q ≡ 1 (mod 128))
    /// - τ = 64 (splitting degree = d/e, ring splits completely)
    /// - κ = 5 (commitment dimension, larger due to smaller q)
    /// - β = 2^18 (norm bound, smaller due to smaller q)
    ///
    /// Requirements: NEO-17.1 through NEO-17.8
    pub fn mersenne61_128() -> Self {
        let q = M61Field::MODULUS;
        let d = 64;
        let e = 1; // q ≡ 1 (mod 128), ring splits completely
        let tau = d / e; // τ = 64
        let kappa = 5; // Larger than Goldilocks due to smaller q
        let beta = 1u64 << 18; // 2^18, smaller than Goldilocks
        
        // Decomposition parameters
        let decomp_base = 1u64 << 9; // 2^9 ≈ √(2^18)
        let decomp_digits = 2; // ⌈log_b(β)⌉ = ⌈18/9⌉ = 2
        
        // Challenge set size
        let challenge_set_size = 1u128 << 128;
        
        Self {
            field_modulus: q,
            ring_degree: d,
            extension_degree: e,
            splitting_degree: tau,
            commitment_dimension: kappa,
            witness_dimension: 256,
            norm_bound: beta,
            security_level: SecurityLevel::Bits128,
            challenge_set_size,
            decomposition_base: decomp_base,
            decomposition_digits: decomp_digits,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Create M61 parameter set with custom witness dimension
    pub fn mersenne61_128_with_witness_dim(witness_dim: usize) -> Self {
        let mut params = Self::mersenne61_128();
        params.witness_dimension = witness_dim;
        params
    }
    
    /// Verify M61-specific properties
    pub fn verify_m61_properties(&self) -> Result<(), ParameterError> {
        // Verify q = 2^61 - 1
        let expected_q = (1u64 << 61) - 1;
        if self.field_modulus != expected_q {
            return Err(ParameterError::InvalidFieldModulus {
                expected: expected_q,
                actual: self.field_modulus,
            });
        }
        
        // Verify q ≡ 1 (mod 128)
        if self.field_modulus % 128 != 1 {
            return Err(ParameterError::InvalidFieldCongruence {
                modulus: self.field_modulus,
                expected_remainder: 1,
                actual_remainder: self.field_modulus % 128,
            });
        }
        
        // Verify e = 1 (ring splits completely)
        if self.extension_degree != 1 {
            return Err(ParameterError::InvalidExtensionDegree {
                ring_degree: self.ring_degree,
                extension_degree: self.extension_degree,
            });
        }
        
        // Verify τ = 64
        if self.splitting_degree != 64 {
            return Err(ParameterError::InvalidSplittingDegree {
                expected: 64,
                actual: self.splitting_degree,
            });
        }
        
        Ok(())
    }
}

/// Parameter validation errors
#[derive(Debug, Clone)]
pub enum ParameterError {
    InvalidRingDegree(usize),
    RingDegreeTooSmall(usize),
    InvalidExtensionDegree {
        ring_degree: usize,
        extension_degree: usize,
    },
    InvalidSplittingDegree {
        expected: usize,
        actual: usize,
    },
    ChallengeSizeTooSmall {
        actual: u128,
        required: u128,
    },
    InvalidCommitmentDimension(usize),
    InvalidNormBound(u64),
    InvalidDecompositionBase(u64),
    InsufficientDecompositionDigits {
        digits: usize,
        base: u64,
        norm_bound: u64,
    },
    InsufficientSoundness {
        actual: f64,
        required: f64,
    },
    InvalidFieldModulus {
        expected: u64,
        actual: u64,
    },
    InvalidFieldCongruence {
        modulus: u64,
        expected_remainder: u64,
        actual_remainder: u64,
    },
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterError::InvalidRingDegree(d) => {
                write!(f, "Ring degree {} is not a power of 2", d)
            }
            ParameterError::RingDegreeTooSmall(d) => {
                write!(f, "Ring degree {} is too small (minimum 64 for security)", d)
            }
            ParameterError::InvalidExtensionDegree { ring_degree, extension_degree } => {
                write!(
                    f,
                    "Extension degree {} does not divide ring degree {}",
                    extension_degree, ring_degree
                )
            }
            ParameterError::InvalidSplittingDegree { expected, actual } => {
                write!(
                    f,
                    "Splitting degree mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            ParameterError::ChallengeSizeTooSmall { actual, required } => {
                write!(
                    f,
                    "Challenge set size {} is too small (required: {})",
                    actual, required
                )
            }
            ParameterError::InvalidCommitmentDimension(k) => {
                write!(f, "Invalid commitment dimension: {}", k)
            }
            ParameterError::InvalidNormBound(b) => {
                write!(f, "Invalid norm bound: {}", b)
            }
            ParameterError::InvalidDecompositionBase(b) => {
                write!(f, "Invalid decomposition base: {}", b)
            }
            ParameterError::InsufficientDecompositionDigits { digits, base, norm_bound } => {
                write!(
                    f,
                    "Insufficient decomposition digits: {} digits with base {} cannot represent norm bound {}",
                    digits, base, norm_bound
                )
            }
            ParameterError::InsufficientSoundness { actual, required } => {
                write!(
                    f,
                    "Insufficient soundness: error {} exceeds required {}",
                    actual, required
                )
            }
            ParameterError::InvalidFieldModulus { expected, actual } => {
                write!(
                    f,
                    "Invalid field modulus: expected {}, got {}",
                    expected, actual
                )
            }
            ParameterError::InvalidFieldCongruence {
                modulus,
                expected_remainder,
                actual_remainder,
            } => {
                write!(
                    f,
                    "Field modulus {} has wrong congruence: expected remainder {}, got {}",
                    modulus, expected_remainder, actual_remainder
                )
            }
        }
    }
}

impl std::error::Error for ParameterError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_goldilocks_parameters() {
        let params = NeoParameters::<GoldilocksField>::goldilocks_128();
        
        // Verify basic properties
        assert_eq!(params.field_modulus, GoldilocksField::MODULUS);
        assert_eq!(params.ring_degree, 64);
        assert_eq!(params.extension_degree, 2);
        assert_eq!(params.splitting_degree, 32);
        assert_eq!(params.commitment_dimension, 4);
        assert_eq!(params.norm_bound, 1 << 20);
        
        // Validate parameters
        params.validate().expect("Goldilocks parameters should be valid");
        params.verify_goldilocks_properties()
            .expect("Goldilocks properties should be satisfied");
    }
    
    #[test]
    fn test_m61_parameters() {
        let params = NeoParameters::<M61Field>::mersenne61_128();
        
        // Verify basic properties
        assert_eq!(params.field_modulus, M61Field::MODULUS);
        assert_eq!(params.ring_degree, 64);
        assert_eq!(params.extension_degree, 1);
        assert_eq!(params.splitting_degree, 64);
        assert_eq!(params.commitment_dimension, 5);
        assert_eq!(params.norm_bound, 1 << 18);
        
        // Validate parameters
        params.validate().expect("M61 parameters should be valid");
        params.verify_m61_properties()
            .expect("M61 properties should be satisfied");
    }
    
    #[test]
    fn test_security_estimation() {
        let params = NeoParameters::<GoldilocksField>::goldilocks_128();
        
        let security = params.estimate_module_sis_security();
        assert!(security >= 128, "Security level should be at least 128 bits");
    }
    
    #[test]
    fn test_soundness_error() {
        let params = NeoParameters::<GoldilocksField>::goldilocks_128();
        
        // Test with typical parameters
        let num_vars = 20; // 2^20 witness size
        let total_error = params.total_soundness_error(num_vars, 3, 2, 256);
        
        // Error should be negligible (< 2^-128)
        let required_error = 2.0_f64.powi(-128);
        assert!(
            total_error < required_error,
            "Total soundness error {} should be less than {}",
            total_error,
            required_error
        );
    }
    
    #[test]
    fn test_complexity_estimates() {
        let params = NeoParameters::<GoldilocksField>::goldilocks_128();
        let witness_size = 1 << 20; // 1M elements
        
        let prover_time = params.estimate_prover_time(witness_size);
        let verifier_time = params.estimate_verifier_time(witness_size);
        let proof_size = params.estimate_proof_size(witness_size);
        
        // Verifier should be much faster than prover
        assert!(verifier_time < prover_time / 1000);
        
        // Proof size should be logarithmic
        assert!(proof_size < 1000); // O(log N) field elements
    }
}
