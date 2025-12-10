// Security Parameter Validation
//
// This module provides comprehensive security parameter validation
// for SALSAA constructions, ensuring all parameters meet security requirements.

use crate::ring::cyclotomic::CyclotomicRing;
use crate::salsaa::applications::snark_params::SecurityLevel;

/// Security parameters validator
pub struct SecurityParams {
    /// Security level λ
    pub security_level: SecurityLevel,
    
    /// Ring parameters
    pub ring: CyclotomicRing,
    
    /// Modulus q
    pub modulus: u64,
    
    /// Norm bound β
    pub beta: f64,
    
    /// Witness dimensions
    pub n: usize,
    pub m: usize,
}

impl SecurityParams {
    /// Create security parameters for a given security level
    pub fn for_security_level(
        security_level: SecurityLevel,
        n: usize,
        m: usize,
        beta: f64,
    ) -> Result<Self, String> {
        let lambda = security_level.bits();
        
        // Choose ring parameters
        let conductor = Self::choose_conductor(lambda);
        let modulus = Self::choose_modulus(lambda, conductor)?;
        let ring = CyclotomicRing::new(conductor, modulus)?;
        
        // Validate parameters
        Self::verify_vsis_hardness(&ring, modulus, beta, n, security_level)?;
        
        Ok(Self {
            security_level,
            ring,
            modulus,
            beta,
            n,
            m,
        })
    }
    
    /// Choose conductor for security level
    fn choose_conductor(lambda: usize) -> u64 {
        match lambda {
            128 => 256,
            192 => 512,
            256 => 1024,
            _ => 256,
        }
    }
    
    /// Choose modulus for security level
    fn choose_modulus(lambda: usize, conductor: u64) -> Result<u64, String> {
        // Target: q ≈ 2^(2λ)
        let target_bits = 2 * lambda;
        let start = 1u64 << target_bits;
        
        for offset in 0..10000 {
            let candidate = start + offset * conductor;
            if Self::is_prime(candidate) && candidate % conductor == 1 {
                return Ok(candidate);
            }
        }
        
        Err(format!("Could not find suitable modulus for λ={}", lambda))
    }
    
    /// Primality test
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        
        // Miller-Rabin
        let witnesses = [2u64, 3, 5, 7, 11, 13, 17, 19, 23];
        let mut d = n - 1;
        let mut r = 0;
        while d % 2 == 0 {
            d /= 2;
            r += 1;
        }
        
        'witness: for &a in &witnesses {
            if a >= n {
                continue;
            }
            
            let mut x = Self::mod_pow(a, d, n);
            if x == 1 || x == n - 1 {
                continue 'witness;
            }
            
            for _ in 0..r - 1 {
                x = Self::mod_mul(x, x, n);
                if x == n - 1 {
                    continue 'witness;
                }
            }
            
            return false;
        }
        
        true
    }
    
    fn mod_pow(mut a: u64, mut b: u64, n: u64) -> u64 {
        let mut result = 1u64;
        a %= n;
        
        while b > 0 {
            if b % 2 == 1 {
                result = Self::mod_mul(result, a, n);
            }
            a = Self::mod_mul(a, a, n);
            b /= 2;
        }
        
        result
    }
    
    fn mod_mul(a: u64, b: u64, n: u64) -> u64 {
        ((a as u128 * b as u128) % n as u128) as u64
    }
    
    /// Verify vSIS hardness
    ///
    /// Checks:
    /// 1. Correctness: β < q / (2√n)
    /// 2. Hardness: Hermite factor δ ≥ 1.005
    /// 3. Norm-check: q > 2β²
    pub fn verify_vsis_hardness(
        ring: &CyclotomicRing,
        q: u64,
        beta: f64,
        n: usize,
        security_level: SecurityLevel,
    ) -> Result<(), String> {
        let phi = ring.degree();
        let lambda = security_level.bits();
        
        // Check 1: Correctness condition
        let correctness_bound = (q as f64) / (2.0 * (n as f64).sqrt());
        if beta >= correctness_bound {
            return Err(format!(
                "Correctness violated: β = {:.2e} >= {:.2e}",
                beta, correctness_bound
            ));
        }
        
        // Check 2: Hermite factor for hardness
        let hermite_factor = (beta * (n as f64).sqrt() / (q as f64))
            .powf(1.0 / (n * phi) as f64);
        
        if hermite_factor < 1.005 {
            return Err(format!(
                "Hardness violated: Hermite factor {:.6} < 1.005",
                hermite_factor
            ));
        }
        
        // Check 3: Norm-check correctness
        if (q as f64) <= 2.0 * beta * beta {
            return Err(format!(
                "Norm-check violated: q = {} <= 2β² = {:.2e}",
                q,
                2.0 * beta * beta
            ));
        }
        
        // Check 4: Security level
        let actual_security = Self::estimate_security_bits(ring, q, beta, n);
        if actual_security < lambda {
            return Err(format!(
                "Security level violated: {} bits < {} bits",
                actual_security, lambda
            ));
        }
        
        Ok(())
    }
    
    /// Estimate actual security level in bits
    fn estimate_security_bits(ring: &CyclotomicRing, q: u64, beta: f64, n: usize) -> usize {
        let phi = ring.degree();
        
        // Use lattice reduction complexity estimate
        // Security ≈ log₂(δ^{-nφ}) where δ is Hermite factor
        let hermite_factor = (beta * (n as f64).sqrt() / (q as f64))
            .powf(1.0 / (n * phi) as f64);
        
        let security = -(hermite_factor.ln() * (n * phi) as f64) / 2f64.ln();
        security.max(0.0) as usize
    }
    
    /// Verify all parameter relationships
    pub fn verify_all(&self) -> Result<(), String> {
        // Verify vSIS
        Self::verify_vsis_hardness(
            &self.ring,
            self.modulus,
            self.beta,
            self.n,
            self.security_level,
        )?;
        
        // Verify ring parameters
        if self.ring.degree() < 64 {
            return Err("Ring degree too small".to_string());
        }
        
        if self.ring.splitting_degree() > 16 {
            return Err("Splitting degree too large".to_string());
        }
        
        // Verify dimensions
        if self.n == 0 || self.m == 0 {
            return Err("Invalid dimensions".to_string());
        }
        
        if self.m < self.n {
            return Err("Witness size must be >= statement size".to_string());
        }
        
        Ok(())
    }
    
    /// Get security summary
    pub fn summary(&self) -> String {
        let actual_security = Self::estimate_security_bits(
            &self.ring,
            self.modulus,
            self.beta,
            self.n,
        );
        
        format!(
            "Security Parameters:\n\
             Target security: {} bits\n\
             Actual security: {} bits\n\
             Ring: Z[ζ_{}] / {}Z\n\
             Ring degree: φ = {}\n\
             Splitting degree: e = {}\n\
             Dimensions: n = {}, m = {}\n\
             Norm bound: β = {:.2e}\n\
             Modulus: q = {}",
            self.security_level.bits(),
            actual_security,
            self.ring.conductor(),
            self.modulus,
            self.ring.degree(),
            self.ring.splitting_degree(),
            self.n,
            self.m,
            self.beta,
            self.modulus,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_params_128() {
        let params = SecurityParams::for_security_level(
            SecurityLevel::Bits128,
            128,
            1024,
            1e6,
        );
        
        assert!(params.is_ok());
        let params = params.unwrap();
        
        println!("{}", params.summary());
        assert!(params.verify_all().is_ok());
    }
    
    #[test]
    fn test_primality() {
        assert!(SecurityParams::is_prime(2));
        assert!(SecurityParams::is_prime(17));
        assert!(SecurityParams::is_prime(97));
        assert!(!SecurityParams::is_prime(4));
        assert!(!SecurityParams::is_prime(100));
    }
}
