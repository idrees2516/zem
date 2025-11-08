// Production Configuration System for Neo
//
// Provides centralized configuration management for all Neo components.
// Replaces hardcoded parameters with configurable, validated settings.

use crate::field::Field;
use crate::parameters::{NeoParameters, SecurityLevel};
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;

/// Global configuration instance
static GLOBAL_CONFIG: Lazy<Arc<RwLock<Option<NeoConfig>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Neo system configuration
///
/// Centralizes all configuration parameters for production deployment.
/// Thread-safe and validated on initialization.
#[derive(Debug, Clone)]
pub struct NeoConfig {
    /// Ring degree for cyclotomic rings
    pub ring_degree: usize,
    
    /// Commitment dimension κ
    pub commitment_dimension: usize,
    
    /// Norm bound β for witnesses
    pub norm_bound: u64,
    
    /// Security level
    pub security_level: SecurityLevel,
    
    /// Field-specific parameters
    pub field_params: FieldConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
    
    /// Verification settings
    pub verification: VerificationConfig,
}

/// Field-specific configuration
#[derive(Debug, Clone)]
pub struct FieldConfig {
    /// Field modulus
    pub modulus: u64,
    
    /// Extension degree e
    pub extension_degree: usize,
    
    /// Splitting degree τ = d/e
    pub splitting_degree: usize,
    
    /// Use extension field for sum-check
    pub use_extension_field: bool,
}

/// Performance tuning configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable parallel processing
    pub enable_parallel: bool,
    
    /// Number of threads (0 = auto)
    pub num_threads: usize,
    
    /// Enable SIMD optimizations
    pub enable_simd: bool,
    
    /// Enable NTT caching
    pub enable_ntt_cache: bool,
    
    /// Memory pool size
    pub memory_pool_size: usize,
    
    /// NTT block size for cache optimization
    pub ntt_block_size: usize,
}

/// Verification configuration
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Verify all intermediate proofs
    pub verify_intermediate: bool,
    
    /// Check norm bounds strictly
    pub strict_norm_checks: bool,
    
    /// Verify challenge derivation
    pub verify_challenges: bool,
    
    /// Maximum allowed soundness error
    pub max_soundness_error: f64,
}

impl NeoConfig {
    /// Create default configuration for Goldilocks field
    pub fn goldilocks_default() -> Self {
        Self {
            ring_degree: 64,
            commitment_dimension: 4,
            norm_bound: 1u64 << 20,
            security_level: SecurityLevel::Bits128,
            field_params: FieldConfig {
                modulus: 18446744069414584321, // 2^64 - 2^32 + 1
                extension_degree: 2,
                splitting_degree: 32,
                use_extension_field: true,
            },
            performance: PerformanceConfig {
                enable_parallel: true,
                num_threads: 0, // Auto-detect
                enable_simd: true,
                enable_ntt_cache: true,
                memory_pool_size: 100,
                ntt_block_size: 64,
            },
            verification: VerificationConfig {
                verify_intermediate: true,
                strict_norm_checks: true,
                verify_challenges: true,
                max_soundness_error: 2.0_f64.powi(-128),
            },
        }
    }
    
    /// Create default configuration for M61 field
    pub fn m61_default() -> Self {
        Self {
            ring_degree: 64,
            commitment_dimension: 5,
            norm_bound: 1u64 << 18,
            security_level: SecurityLevel::Bits128,
            field_params: FieldConfig {
                modulus: 2305843009213693951, // 2^61 - 1
                extension_degree: 1,
                splitting_degree: 64,
                use_extension_field: true,
            },
            performance: PerformanceConfig {
                enable_parallel: true,
                num_threads: 0,
                enable_simd: true,
                enable_ntt_cache: true,
                memory_pool_size: 100,
                ntt_block_size: 64,
            },
            verification: VerificationConfig {
                verify_intermediate: true,
                strict_norm_checks: true,
                verify_challenges: true,
                max_soundness_error: 2.0_f64.powi(-128),
            },
        }
    }
    
    /// Create production configuration with high security
    pub fn production_high_security() -> Self {
        let mut config = Self::goldilocks_default();
        config.security_level = SecurityLevel::Bits256;
        config.verification.verify_intermediate = true;
        config.verification.strict_norm_checks = true;
        config.verification.max_soundness_error = 2.0_f64.powi(-256);
        config
    }
    
    /// Create development configuration with relaxed checks
    pub fn development() -> Self {
        let mut config = Self::goldilocks_default();
        config.verification.verify_intermediate = false;
        config.verification.strict_norm_checks = false;
        config
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check ring degree is power of 2
        if !self.ring_degree.is_power_of_two() {
            return Err(format!("Ring degree {} must be power of 2", self.ring_degree));
        }
        
        // Check minimum ring degree
        if self.ring_degree < 64 {
            return Err(format!("Ring degree {} too small (minimum 64)", self.ring_degree));
        }
        
        // Check extension degree divides ring degree
        if self.ring_degree % self.field_params.extension_degree != 0 {
            return Err("Extension degree must divide ring degree".to_string());
        }
        
        // Verify splitting degree
        let expected_splitting = self.ring_degree / self.field_params.extension_degree;
        if self.field_params.splitting_degree != expected_splitting {
            return Err(format!(
                "Splitting degree mismatch: expected {}, got {}",
                expected_splitting, self.field_params.splitting_degree
            ));
        }
        
        // Check commitment dimension
        if self.commitment_dimension == 0 || self.commitment_dimension > 10 {
            return Err(format!("Invalid commitment dimension: {}", self.commitment_dimension));
        }
        
        // Check norm bound
        if self.norm_bound == 0 || self.norm_bound >= self.field_params.modulus / 2 {
            return Err(format!("Invalid norm bound: {}", self.norm_bound));
        }
        
        Ok(())
    }
    
    /// Convert to NeoParameters for a specific field
    pub fn to_parameters<F: Field>(&self) -> NeoParameters<F> {
        NeoParameters {
            field_modulus: self.field_params.modulus,
            ring_degree: self.ring_degree,
            extension_degree: self.field_params.extension_degree,
            splitting_degree: self.field_params.splitting_degree,
            commitment_dimension: self.commitment_dimension,
            witness_dimension: 256, // Default
            norm_bound: self.norm_bound,
            security_level: self.security_level,
            challenge_set_size: 1u128 << 128,
            decomposition_base: (self.norm_bound as f64).sqrt() as u64,
            decomposition_digits: 2,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Initialize global configuration
///
/// Must be called before using any Neo components in production.
/// Thread-safe and idempotent.
pub fn init_config(config: NeoConfig) -> Result<(), String> {
    // Validate configuration
    config.validate()?;
    
    // Set global config
    let mut global = GLOBAL_CONFIG.write().unwrap();
    *global = Some(config);
    
    Ok(())
}

/// Get global configuration
///
/// Returns the current global configuration, or default if not initialized.
pub fn get_config() -> NeoConfig {
    let global = GLOBAL_CONFIG.read().unwrap();
    global.clone().unwrap_or_else(NeoConfig::goldilocks_default)
}

/// Get ring degree from global configuration
pub fn get_ring_degree() -> usize {
    get_config().ring_degree
}

/// Get commitment dimension from global configuration
pub fn get_commitment_dimension() -> usize {
    get_config().commitment_dimension
}

/// Get norm bound from global configuration
pub fn get_norm_bound() -> u64 {
    get_config().norm_bound
}

/// Check if parallel processing is enabled
pub fn is_parallel_enabled() -> bool {
    get_config().performance.enable_parallel
}

/// Check if SIMD is enabled
pub fn is_simd_enabled() -> bool {
    get_config().performance.enable_simd
}

/// Get NTT block size
pub fn get_ntt_block_size() -> usize {
    get_config().performance.ntt_block_size
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_goldilocks_config() {
        let config = NeoConfig::goldilocks_default();
        assert!(config.validate().is_ok());
        assert_eq!(config.ring_degree, 64);
        assert_eq!(config.commitment_dimension, 4);
    }
    
    #[test]
    fn test_m61_config() {
        let config = NeoConfig::m61_default();
        assert!(config.validate().is_ok());
        assert_eq!(config.ring_degree, 64);
        assert_eq!(config.commitment_dimension, 5);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = NeoConfig::goldilocks_default();
        
        // Invalid ring degree
        config.ring_degree = 63;
        assert!(config.validate().is_err());
        
        // Too small ring degree
        config.ring_degree = 32;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_global_config() {
        let config = NeoConfig::goldilocks_default();
        init_config(config.clone()).unwrap();
        
        let retrieved = get_config();
        assert_eq!(retrieved.ring_degree, config.ring_degree);
    }
}
