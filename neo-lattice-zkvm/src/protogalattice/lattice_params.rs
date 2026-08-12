// Lattice parameters for ProtogaLattice security
//
// Implements secure parameter selection based on:
// - Module-SIS hardness
// - Module-LWE hardness
// - Rejection sampling bounds

use std::f64::consts::PI;
use serde::{Serialize, Deserialize};

/// Security level in bits
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit security
    Classical128,
    /// 192-bit security
    Classical192,
    /// 256-bit security
    Classical256,
}

/// Lattice parameters for the scheme
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatticeParams {
    /// Ring dimension (power of 2)
    pub ring_dimension: usize,
    /// Modulus q
    pub modulus: u64,
    /// Module rank for commitment keys
    pub module_rank: usize,
    /// Gadget decomposition base
    pub gadget_base: usize,
    /// Number of gadget digits
    pub gadget_digits: usize,
    /// Standard deviation for discrete Gaussian sampling
    pub gaussian_stddev: f64,
    /// Rejection sampling bound
    pub rejection_bound: f64,
    /// Security level
    pub security_level: SecurityLevel,
    /// SIS hardness parameter (beta)
    pub sis_beta: f64,
    /// LWE error width
    pub lwe_error_width: f64,
}

impl LatticeParams {
    /// Create parameters for 128-bit security
    pub fn new_128() -> Self {
        Self {
            ring_dimension: 1024,
            modulus: (1u64 << 61) - 1,
            module_rank: 4,
            gadget_base: 256,
            gadget_digits: 8,
            gaussian_stddev: 3.2,
            rejection_bound: 12.0,
            security_level: SecurityLevel::Classical128,
            sis_beta: 1000.0,
            lwe_error_width: 3.2,
        }
    }

    /// Create parameters for 192-bit security
    pub fn new_192() -> Self {
        Self {
            ring_dimension: 2048,
            modulus: (1u64 << 61) - 1,
            module_rank: 5,
            gadget_base: 256,
            gadget_digits: 8,
            gaussian_stddev: 3.2,
            rejection_bound: 12.0,
            security_level: SecurityLevel::Classical192,
            sis_beta: 2000.0,
            lwe_error_width: 3.2,
        }
    }

    /// Create parameters for 256-bit security
    pub fn new_256() -> Self {
        Self {
            ring_dimension: 2048,
            modulus: (1u64 << 61) - 1,
            module_rank: 6,
            gadget_base: 512,
            gadget_digits: 8,
            gaussian_stddev: 3.2,
            rejection_bound: 12.0,
            security_level: SecurityLevel::Classical256,
            sis_beta: 4000.0,
            lwe_error_width: 3.2,
        }
    }

    /// Validate parameters for security
    pub fn validate(&self) -> Result<(), &'static str> {
        // Check ring dimension is power of 2
        if !self.ring_dimension.is_power_of_two() {
            return Err("Ring dimension must be power of 2");
        }

        // Check modulus is prime
        if !is_prime_approx(self.modulus) {
            return Err("Modulus should be prime");
        }

        // Check SIS hardness
        let log_q = (self.modulus as f64).log2();
        let sis_hardness = self.estimate_sis_hardness();
        let target_bits = match self.security_level {
            SecurityLevel::Classical128 => 128.0,
            SecurityLevel::Classical192 => 192.0,
            SecurityLevel::Classical256 => 256.0,
        };

        if sis_hardness < target_bits {
            return Err("SIS hardness insufficient");
        }

        // Check LWE hardness
        let lwe_hardness = self.estimate_lwe_hardness();
        if lwe_hardness < target_bits {
            return Err("LWE hardness insufficient");
        }

        // Check rejection sampling is efficient
        if self.rejection_bound < 2.0 {
            return Err("Rejection bound too small");
        }

        Ok(())
    }

    /// Estimate SIS hardness in bits
    pub fn estimate_sis_hardness(&self) -> f64 {
        // Simplified hardness estimate
        // Real implementation should use up-to-date lattice estimators
        let n = self.ring_dimension as f64;
        let m = (self.module_rank * self.ring_dimension) as f64;
        let log_q = (self.modulus as f64).log2();
        let log_beta = self.sis_beta.log2();

        // BKZ block size estimate
        let delta = (log_q - log_beta) / m;
        let bkz_blocksize = (n * log_q) / (delta * m);

        // Security bits (conservative estimate)
        (bkz_blocksize / 8.0).min(log_q)
    }

    /// Estimate LWE hardness in bits
    pub fn estimate_lwe_hardness(&self) -> f64 {
        // Simplified hardness estimate
        let n = self.ring_dimension as f64;
        let log_q = (self.modulus as f64).log2();
        let log_stddev = self.lwe_error_width.log2();

        // Conservative estimate
        let alpha = (log_stddev - log_q).exp2();
        let security = (n * (log_q / (2.0 * PI * alpha)).log2()) / 2.0;

        security.min(log_q)
    }

    /// Get total number of ring elements in a module
    pub fn module_size(&self) -> usize {
        self.module_rank * self.ring_dimension
    }

    /// Get gadget vector length
    pub fn gadget_length(&self) -> usize {
        self.gadget_digits * self.module_rank
    }

    /// Compute rejection sampling acceptance probability
    pub fn rejection_acceptance_prob(&self) -> f64 {
        // Probability that a sample is accepted
        let m = self.rejection_bound;
        let sigma = self.gaussian_stddev;
        
        // Conservative bound: exp(1/2) * exp(-1/(2m^2))
        let prob = (1.0 / (2.0 * m * m)).exp() / (std::f64::consts::E.sqrt());
        prob.min(1.0)
    }

    /// Expected number of rejection sampling iterations
    pub fn expected_rejections(&self) -> f64 {
        1.0 / self.rejection_acceptance_prob()
    }

    /// Check if parameters support given number of folding rounds
    pub fn supports_folding_rounds(&self, rounds: usize) -> bool {
        // Each round adds noise
        let noise_growth = (rounds as f64) * self.gaussian_stddev.powi(2);
        let max_noise = self.sis_beta / 2.0;
        
        noise_growth < max_noise
    }

    /// Compute soundness error
    pub fn soundness_error(&self) -> f64 {
        // Soundness error depends on challenge space
        let challenge_bits = (self.modulus as f64).log2();
        2.0_f64.powf(-challenge_bits)
    }

    /// Get recommended number of repetitions for target security
    pub fn recommended_repetitions(&self, target_security_bits: usize) -> usize {
        let single_soundness = self.soundness_error();
        let total_soundness = 2.0_f64.powf(-(target_security_bits as f64));
        
        (total_soundness.log2() / single_soundness.log2()).ceil() as usize
    }
}

/// Approximate primality test (deterministic for small primes)
fn is_prime_approx(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }

    // Miller-Rabin test with fixed witnesses for 64-bit numbers
    let witnesses = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    
    let mut d = n - 1;
    let mut r = 0;
    while d % 2 == 0 {
        d /= 2;
        r += 1;
    }

    'witness_loop: for &a in &witnesses {
        if a >= n {
            continue;
        }

        let mut x = mod_exp(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }

        for _ in 0..r - 1 {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                continue 'witness_loop;
            }
        }
        
        return false;
    }

    true
}

/// Modular exponentiation: (base^exp) mod m
fn mod_exp(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut result = 1u64;
    base %= m;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = mod_mul(result, base, m);
        }
        exp >>= 1;
        base = mod_mul(base, base, m);
    }
    
    result
}

/// Modular multiplication: (a * b) mod m
fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Discrete Gaussian sampler parameters
#[derive(Clone, Debug)]
pub struct GaussianSamplerParams {
    /// Standard deviation
    pub stddev: f64,
    /// Tail cut parameter (samples beyond this are rejected)
    pub tail_cut: f64,
    /// Precision for cumulative distribution
    pub precision: usize,
}

impl GaussianSamplerParams {
    /// Create new sampler parameters
    pub fn new(stddev: f64) -> Self {
        Self {
            stddev,
            tail_cut: stddev * 12.0, // 12 sigma covers ~99.999999999% 
            precision: 64,
        }
    }

    /// Probability density function
    pub fn pdf(&self, x: f64) -> f64 {
        let coefficient = 1.0 / (self.stddev * (2.0 * PI).sqrt());
        let exponent = -(x * x) / (2.0 * self.stddev * self.stddev);
        coefficient * exponent.exp()
    }

    /// Check if value is within tail cut
    pub fn is_within_tail(&self, x: f64) -> bool {
        x.abs() <= self.tail_cut
    }
}

/// Parameters for folding soundness
#[derive(Clone, Debug)]
pub struct FoldingParams {
    /// Number of folding rounds
    pub num_rounds: usize,
    /// Challenge space size (bits)
    pub challenge_bits: usize,
    /// Accumulated soundness error
    pub total_soundness_error: f64,
}

impl FoldingParams {
    /// Create folding parameters
    pub fn new(num_rounds: usize, challenge_bits: usize) -> Self {
        let single_error = 2.0_f64.powf(-(challenge_bits as f64));
        let total_error = (single_error * num_rounds as f64).min(1.0);
        
        Self {
            num_rounds,
            challenge_bits,
            total_soundness_error: total_error,
        }
    }

    /// Check if parameters provide target security
    pub fn achieves_security(&self, target_bits: usize) -> bool {
        let target_error = 2.0_f64.powf(-(target_bits as f64));
        self.total_soundness_error <= target_error
    }

    /// Get required challenge space for target security
    pub fn required_challenge_space(num_rounds: usize, target_bits: usize) -> usize {
        let target_error = 2.0_f64.powf(-(target_bits as f64));
        let per_round_error = target_error / num_rounds as f64;
        (-(per_round_error.log2())).ceil() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_128() {
        let params = LatticeParams::new_128();
        assert!(params.validate().is_ok());
        assert!(params.estimate_sis_hardness() >= 128.0);
        assert!(params.estimate_lwe_hardness() >= 128.0);
    }

    #[test]
    fn test_primality() {
        assert!(is_prime_approx(2));
        assert!(is_prime_approx(3));
        assert!(is_prime_approx(5));
        assert!(is_prime_approx(7));
        assert!(!is_prime_approx(4));
        assert!(!is_prime_approx(9));
        assert!(is_prime_approx((1u64 << 61) - 1));
    }

    #[test]
    fn test_rejection_sampling() {
        let params = LatticeParams::new_128();
        let prob = params.rejection_acceptance_prob();
        assert!(prob > 0.0 && prob <= 1.0);
        
        let expected = params.expected_rejections();
        assert!(expected >= 1.0);
    }

    #[test]
    fn test_folding_params() {
        let params = FoldingParams::new(3, 128);
        assert!(params.achieves_security(120));
        assert!(!params.achieves_security(130));
    }
}
