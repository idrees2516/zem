// Parameter selection for Hachi
// Based on paper Section 1.3 and security analysis

use crate::field::Field;
use super::errors::{HachiError, Result};

/// Hachi parameters
/// 
/// **Paper Reference:** Section 1.3 "Parameter Setup"
/// 
/// **Security Requirements:**
/// - λ: Security parameter (typically 128 or 256)
/// - d = 2^α: Ring dimension (power of 2, d ≥ 64)
/// - k = 2^κ: Extension degree (divides d/2)
/// - q ≡ 5 (mod 8): Prime modulus for invertibility
/// - κ, n: Module-SIS dimensions
/// - β_SIS = 4T·B_rbnd: Module-SIS hardness parameter
#[derive(Clone, Debug)]
pub struct HachiParams {
    /// Security parameter λ (bits)
    pub lambda: usize,
    
    /// Ring dimension d = 2^α
    pub ring_dimension: usize,
    
    /// Ring dimension exponent α (d = 2^α)
    pub alpha: usize,
    
    /// Extension degree k = 2^κ
    pub extension_degree: usize,
    
    /// Extension degree exponent κ (k = 2^κ)
    pub kappa: usize,
    
    /// Prime modulus q
    pub modulus: u64,
    
    /// Module-SIS row dimension κ
    pub msis_kappa: usize,
    
    /// Module-SIS column dimension n
    pub msis_n: usize,
    
    /// Module-SIS hardness parameter β_SIS
    pub beta_sis: f64,
    
    /// Operator norm bound T = ||S||_op (typically 15 for LaBRADOR)
    pub operator_norm_bound: f64,
    
    /// Standard norm bound B_bnd
    pub b_bnd: f64,
    
    /// Relaxed norm bound B_rbnd = 2·B_bnd
    pub b_rbnd: f64,
    
    /// Number of variables in multilinear polynomial
    pub num_variables: usize,
}

impl HachiParams {
    /// Create parameters for 128-bit security
    /// 
    /// **Paper Reference:** Section 1.3, Table 1
    /// 
    /// **Default Configuration:**
    /// - λ = 128
    /// - d = 256 (α = 8)
    /// - k = 16 (κ = 4)
    /// - q = 2^64 - 2^32 + 1 (Goldilocks)
    /// - κ = 4, n = 8
    /// - T = 15 (LaBRADOR challenge set)
    pub fn new_128bit_security(num_variables: usize) -> Result<Self> {
        Self::new_with_params(
            128,           // lambda
            256,           // ring_dimension
            16,            // extension_degree
            4,             // msis_kappa
            8,             // msis_n
            num_variables,
        )
    }
    
    /// Create parameters for 256-bit security
    /// 
    /// **Paper Reference:** Section 1.3
    /// 
    /// **Configuration:**
    /// - λ = 256
    /// - d = 512 (α = 9)
    /// - k = 32 (κ = 5)
    /// - Larger MSIS dimensions
    pub fn new_256bit_security(num_variables: usize) -> Result<Self> {
        Self::new_with_params(
            256,           // lambda
            512,           // ring_dimension
            32,            // extension_degree
            8,             // msis_kappa
            16,            // msis_n
            num_variables,
        )
    }
    
    /// Create parameters with custom configuration
    /// 
    /// **Validation:**
    /// 1. d must be power of 2 and d ≥ 64
    /// 2. k must be power of 2 and divide d/2
    /// 3. q ≡ 5 (mod 8) for invertibility
    /// 4. Security level must be achieved
    pub fn new_with_params(
        lambda: usize,
        ring_dimension: usize,
        extension_degree: usize,
        msis_kappa: usize,
        msis_n: usize,
        num_variables: usize,
    ) -> Result<Self> {
        // Validate ring dimension
        if !ring_dimension.is_power_of_two() {
            return Err(HachiError::InvalidRingDimension(
                format!("Ring dimension {} must be power of 2", ring_dimension)
            ));
        }
        if ring_dimension < 64 {
            return Err(HachiError::InvalidRingDimension(
                format!("Ring dimension {} must be at least 64 for security", ring_dimension)
            ));
        }
        
        // Validate extension degree
        if !extension_degree.is_power_of_two() {
            return Err(HachiError::InvalidExtensionDegree(
                format!("Extension degree {} must be power of 2", extension_degree)
            ));
        }
        if (ring_dimension / 2) % extension_degree != 0 {
            return Err(HachiError::InvalidExtensionDegree(
                format!("Extension degree {} must divide d/2 = {}", 
                    extension_degree, ring_dimension / 2)
            ));
        }
        
        // Compute exponents
        let alpha = ring_dimension.trailing_zeros() as usize;
        let kappa = extension_degree.trailing_zeros() as usize;
        
        // Use Goldilocks field modulus
        let modulus = 0xFFFFFFFF00000001u64; // 2^64 - 2^32 + 1
        
        // Validate modulus
        if modulus % 8 != 5 {
            return Err(HachiError::InvalidModulus(
                format!("Modulus {} must be ≡ 5 (mod 8)", modulus)
            ));
        }
        
        // Set operator norm bound (LaBRADOR challenge set)
        let operator_norm_bound = 15.0;
        
        // Compute norm bounds
        // B_rbnd chosen to ensure security
        let b_rbnd = Self::compute_relaxed_norm_bound(
            lambda,
            ring_dimension,
            msis_kappa,
            msis_n,
            modulus,
        );
        let b_bnd = b_rbnd / 2.0;
        
        // Compute β_SIS = 4T·B_rbnd
        let beta_sis = 4.0 * operator_norm_bound * b_rbnd;
        
        let params = Self {
            lambda,
            ring_dimension,
            alpha,
            extension_degree,
            kappa,
            modulus,
            msis_kappa,
            msis_n,
            beta_sis,
            operator_norm_bound,
            b_bnd,
            b_rbnd,
            num_variables,
        };
        
        // Verify security level
        params.verify_security()?;
        
        Ok(params)
    }
    
    /// Compute relaxed norm bound B_rbnd
    /// 
    /// **Paper Reference:** Section 1.3
    /// 
    /// **Formula:** B_rbnd chosen such that Module-SIS_{q,κ,n,β_SIS} is hard
    /// where β_SIS = 4T·B_rbnd
    fn compute_relaxed_norm_bound(
        lambda: usize,
        d: usize,
        kappa: usize,
        n: usize,
        q: u64,
    ) -> f64 {
        // Simplified bound computation
        // In production, use full lattice estimator
        let log_q = (q as f64).log2();
        let dimension = (kappa * n * d) as f64;
        
        // Hermite factor for λ-bit security
        let delta = 1.0045_f64.powf(lambda as f64 / dimension);
        
        // Gaussian heuristic
        let gh = (dimension / (2.0 * std::f64::consts::PI * std::f64::consts::E)).sqrt() 
                 * q.pow(kappa as u32) as f64;
        
        // B_rbnd ≈ δ^d · gh / (4T)
        let b_rbnd = delta.powf(dimension) * gh / (4.0 * 15.0);
        
        b_rbnd.max(1000.0) // Minimum bound for practical security
    }
    
    /// Verify security level
    /// 
    /// **Paper Reference:** Section 1.3 "Security Analysis"
    /// 
    /// **Checks:**
    /// 1. Module-SIS hardness
    /// 2. Lattice estimator bounds
    /// 3. Concrete security level ≥ λ
    fn verify_security(&self) -> Result<()> {
        // Check β_SIS = 4T·B_rbnd
        let expected_beta_sis = 4.0 * self.operator_norm_bound * self.b_rbnd;
        if (self.beta_sis - expected_beta_sis).abs() > 1e-6 {
            return Err(HachiError::InvalidSecurityParameter(
                format!("β_SIS mismatch: expected {}, got {}", 
                    expected_beta_sis, self.beta_sis)
            ));
        }
        
        // Estimate security level using lattice estimator
        let log_q = (self.modulus as f64).log2();
        let dimension = (self.msis_kappa * self.msis_n * self.ring_dimension) as f64;
        let log_beta = self.beta_sis.log2();
        
        // Simplified security estimate
        // In production, use full BKZ/sieve cost models
        let estimated_security = dimension * (log_q - log_beta) / 2.0;
        
        if estimated_security < self.lambda as f64 {
            return Err(HachiError::InvalidSecurityParameter(
                format!("Insufficient security: estimated {} bits, need {} bits",
                    estimated_security, self.lambda)
            ));
        }
        
        Ok(())
    }
    
    /// Get conductor f = 2d for cyclotomic ring
    pub fn conductor(&self) -> u64 {
        2 * self.ring_dimension as u64
    }
    
    /// Get Euler's totient φ(f) = d
    pub fn euler_totient(&self) -> usize {
        self.ring_dimension
    }
    
    /// Get number of CRT slots: φ/e where e is splitting degree
    pub fn num_crt_slots(&self) -> usize {
        // For Goldilocks field, e = 32
        // This is the multiplicative order of q mod f
        let e = self.compute_splitting_degree();
        self.ring_dimension / e
    }
    
    /// Compute splitting degree e: multiplicative order of q mod f
    fn compute_splitting_degree(&self) -> usize {
        let f = self.conductor();
        let q = self.modulus;
        
        let mut e = 1;
        let mut power = q % f;
        
        while power != 1 && e < f as usize {
            power = (power * q) % f;
            e += 1;
        }
        
        e
    }
    
    /// Get size of fixed subgroup H
    pub fn fixed_subgroup_size(&self) -> usize {
        self.ring_dimension / self.extension_degree
    }
    
    /// Validate compatibility with another parameter set
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.modulus == other.modulus &&
        self.ring_dimension == other.ring_dimension &&
        self.extension_degree == other.extension_degree
    }
}

/// Parameter presets for common configurations
pub struct HachiPresets;

impl HachiPresets {
    /// Small parameters for testing (NOT SECURE)
    pub fn test_params() -> Result<HachiParams> {
        HachiParams::new_with_params(
            80,    // lambda (reduced for testing)
            64,    // ring_dimension
            4,     // extension_degree
            2,     // msis_kappa
            4,     // msis_n
            10,    // num_variables
        )
    }
    
    /// Parameters for ℓ = 20 variables (medium)
    pub fn medium_params() -> Result<HachiParams> {
        HachiParams::new_128bit_security(20)
    }
    
    /// Parameters for ℓ = 30 variables (large, as in paper)
    pub fn large_params() -> Result<HachiParams> {
        HachiParams::new_128bit_security(30)
    }
    
    /// Parameters for ℓ = 40 variables (very large)
    pub fn very_large_params() -> Result<HachiParams> {
        HachiParams::new_256bit_security(40)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_128bit_params() {
        let params = HachiParams::new_128bit_security(30).unwrap();
        assert_eq!(params.lambda, 128);
        assert_eq!(params.ring_dimension, 256);
        assert_eq!(params.extension_degree, 16);
        assert!(params.ring_dimension.is_power_of_two());
        assert!(params.extension_degree.is_power_of_two());
    }
    
    #[test]
    fn test_256bit_params() {
        let params = HachiParams::new_256bit_security(40).unwrap();
        assert_eq!(params.lambda, 256);
        assert_eq!(params.ring_dimension, 512);
        assert_eq!(params.extension_degree, 32);
    }
    
    #[test]
    fn test_invalid_ring_dimension() {
        let result = HachiParams::new_with_params(128, 100, 16, 4, 8, 30);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_extension_degree() {
        let result = HachiParams::new_with_params(128, 256, 17, 4, 8, 30);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_extension_degree_divides_d_over_2() {
        let result = HachiParams::new_with_params(128, 256, 256, 4, 8, 30);
        assert!(result.is_err()); // 256 does not divide 256/2 = 128
    }
    
    #[test]
    fn test_beta_sis_formula() {
        let params = HachiParams::new_128bit_security(30).unwrap();
        let expected = 4.0 * params.operator_norm_bound * params.b_rbnd;
        assert!((params.beta_sis - expected).abs() < 1e-6);
    }
    
    #[test]
    fn test_conductor() {
        let params = HachiParams::new_128bit_security(30).unwrap();
        assert_eq!(params.conductor(), 2 * params.ring_dimension as u64);
    }
    
    #[test]
    fn test_compatibility() {
        let params1 = HachiParams::new_128bit_security(30).unwrap();
        let params2 = HachiParams::new_128bit_security(20).unwrap();
        assert!(params1.is_compatible_with(&params2));
    }
}
