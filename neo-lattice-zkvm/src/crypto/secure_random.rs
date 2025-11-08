// Secure Randomness Sources
// Requirement 11: Cryptographically secure random number generation
// 
// Provides platform-specific secure randomness for all cryptographic operations
// including challenge generation, commitment randomness, and protocol execution.

use rand::{Rng, RngCore, SeedableRng, CryptoRng};
use rand_chacha::ChaCha20Rng;
use getrandom::getrandom;
use sha3::{Sha3_256, Digest};
use std::fmt;

/// Error types for secure randomness operations
#[derive(Debug, Clone)]
pub enum RandomnessError {
    /// Platform RNG unavailable
    PlatformRngUnavailable {
        reason: String,
    },
    
    /// Insufficient entropy
    InsufficientEntropy {
        requested: usize,
        available: usize,
    },
    
    /// PRF construction failed
    PrfConstructionFailed {
        reason: String,
    },
    
    /// Seed generation failed
    SeedGenerationFailed {
        reason: String,
    },
}

impl fmt::Display for RandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RandomnessError::PlatformRngUnavailable { reason } => {
                write!(f, "Platform RNG unavailable: {}", reason)
            }
            RandomnessError::InsufficientEntropy { requested, available } => {
                write!(f, "Insufficient entropy: requested {}, available {}", requested, available)
            }
            RandomnessError::PrfConstructionFailed { reason } => {
                write!(f, "PRF construction failed: {}", reason)
            }
            RandomnessError::SeedGenerationFailed { reason } => {
                write!(f, "Seed generation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for RandomnessError {}

/// Secure random number generator
/// 
/// Provides cryptographically secure randomness using platform-specific sources.
/// Falls back to ChaCha20 CSPRNG seeded from OS entropy.
pub struct SecureRng {
    /// Internal ChaCha20 RNG
    inner: ChaCha20Rng,
    
    /// Entropy source description
    source: String,
    
    /// Number of bytes generated
    bytes_generated: usize,
    
    /// Reseed threshold (reseed after this many bytes)
    reseed_threshold: usize,
}

impl SecureRng {
    /// Create new secure RNG from OS entropy
    /// 
    /// Uses platform-specific secure random sources:
    /// - Linux/Android: /dev/urandom
    /// - Windows: BCryptGenRandom
    /// - macOS/iOS: SecRandomCopyBytes
    /// - WASM: crypto.getRandomValues
    pub fn new() -> Result<Self, RandomnessError> {
        let mut seed = [0u8; 32];
        getrandom(&mut seed).map_err(|e| RandomnessError::PlatformRngUnavailable {
            reason: format!("getrandom failed: {}", e),
        })?;
        
        let inner = ChaCha20Rng::from_seed(seed);
        
        Ok(Self {
            inner,
            source: "OS entropy".to_string(),
            bytes_generated: 0,
            reseed_threshold: 1024 * 1024, // Reseed after 1MB
        })
    }
    
    /// Create RNG from explicit seed (for testing only)
    /// 
    /// WARNING: Only use for testing! Production code must use `new()`.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
            source: "explicit seed (TEST ONLY)".to_string(),
            bytes_generated: 0,
            reseed_threshold: 1024 * 1024,
        }
    }
    
    /// Generate random bytes
    /// 
    /// Automatically reseeds from OS entropy after threshold.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandomnessError> {
        // Check if reseed is needed
        if self.bytes_generated + dest.len() > self.reseed_threshold {
            self.reseed()?;
        }
        
        self.inner.fill_bytes(dest);
        self.bytes_generated += dest.len();
        
        Ok(())
    }
    
    /// Generate random u64
    pub fn next_u64(&mut self) -> Result<u64, RandomnessError> {
        if self.bytes_generated + 8 > self.reseed_threshold {
            self.reseed()?;
        }
        
        self.bytes_generated += 8;
        Ok(self.inner.next_u64())
    }
    
    /// Generate random u32
    pub fn next_u32(&mut self) -> Result<u32, RandomnessError> {
        if self.bytes_generated + 4 > self.reseed_threshold {
            self.reseed()?;
        }
        
        self.bytes_generated += 4;
        Ok(self.inner.next_u32())
    }
    
    /// Generate random value in range [0, bound)
    /// 
    /// Uses rejection sampling to ensure uniform distribution.
    pub fn gen_range(&mut self, bound: u64) -> Result<u64, RandomnessError> {
        if bound == 0 {
            return Err(RandomnessError::InsufficientEntropy {
                requested: 1,
                available: 0,
            });
        }
        
        if bound == 1 {
            return Ok(0);
        }
        
        // Compute rejection threshold to ensure uniformity
        let range = u64::MAX - (u64::MAX % bound);
        
        loop {
            let sample = self.next_u64()?;
            if sample < range {
                return Ok(sample % bound);
            }
            // Reject and resample
        }
    }
    
    /// Reseed from OS entropy
    fn reseed(&mut self) -> Result<(), RandomnessError> {
        let mut seed = [0u8; 32];
        getrandom(&mut seed).map_err(|e| RandomnessError::PlatformRngUnavailable {
            reason: format!("getrandom failed during reseed: {}", e),
        })?;
        
        self.inner = ChaCha20Rng::from_seed(seed);
        self.bytes_generated = 0;
        
        Ok(())
    }
    
    /// Get entropy source description
    pub fn source(&self) -> &str {
        &self.source
    }
    
    /// Get number of bytes generated since last reseed
    pub fn bytes_generated(&self) -> usize {
        self.bytes_generated
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u32().expect("RNG failure")
    }
    
    fn next_u64(&mut self) -> u64 {
        self.next_u64().expect("RNG failure")
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes(dest).expect("RNG failure")
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest).map_err(|e| {
            rand::Error::new(format!("SecureRng error: {}", e))
        })
    }
}

impl CryptoRng for SecureRng {}

/// Pseudorandom function (PRF) for deterministic randomness
/// 
/// Constructs a PRF from a seed and domain separator for deterministic
/// but unpredictable randomness generation.
pub struct DeterministicPrf {
    /// Master seed
    seed: [u8; 32],
    
    /// Domain separator
    domain: Vec<u8>,
    
    /// Counter for unique outputs
    counter: u64,
}

impl DeterministicPrf {
    /// Create new PRF with seed and domain separator
    /// 
    /// Domain separator prevents cross-protocol attacks by ensuring
    /// different protocols generate different random values.
    pub fn new(seed: [u8; 32], domain: &[u8]) -> Self {
        Self {
            seed,
            domain: domain.to_vec(),
            counter: 0,
        }
    }
    
    /// Generate next PRF output
    /// 
    /// Computes: PRF(seed, domain, counter) = SHA3-256(seed || domain || counter)
    pub fn next(&mut self, output_len: usize) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        
        // Hash seed
        hasher.update(&self.seed);
        
        // Hash domain separator
        hasher.update(&self.domain);
        
        // Hash counter
        hasher.update(&self.counter.to_le_bytes());
        
        // Increment counter
        self.counter += 1;
        
        // Generate output using hash expansion
        let mut output = Vec::with_capacity(output_len);
        let mut block_counter = 0u64;
        
        while output.len() < output_len {
            let mut block_hasher = hasher.clone();
            block_hasher.update(&block_counter.to_le_bytes());
            let hash = block_hasher.finalize();
            
            let remaining = output_len - output.len();
            let to_copy = remaining.min(hash.len());
            output.extend_from_slice(&hash[..to_copy]);
            
            block_counter += 1;
        }
        
        output
    }
    
    /// Generate PRF output as u64
    pub fn next_u64(&mut self) -> u64 {
        let bytes = self.next(8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
    
    /// Generate PRF output in range [0, bound)
    pub fn next_range(&mut self, bound: u64) -> u64 {
        if bound == 0 || bound == 1 {
            return 0;
        }
        
        let range = u64::MAX - (u64::MAX % bound);
        
        loop {
            let sample = self.next_u64();
            if sample < range {
                return sample % bound;
            }
        }
    }
    
    /// Reset counter
    pub fn reset(&mut self) {
        self.counter = 0;
    }
    
    /// Get current counter value
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// Uniform distribution verifier
/// 
/// Statistical tests to verify randomness quality.
pub struct UniformityTester {
    /// Number of samples
    num_samples: usize,
    
    /// Bucket counts for chi-square test
    buckets: Vec<usize>,
    
    /// Number of buckets
    num_buckets: usize,
}

impl UniformityTester {
    /// Create new uniformity tester
    pub fn new(num_buckets: usize) -> Self {
        Self {
            num_samples: 0,
            buckets: vec![0; num_buckets],
            num_buckets,
        }
    }
    
    /// Add sample to test
    pub fn add_sample(&mut self, value: u64, max_value: u64) {
        let bucket = ((value as f64 / max_value as f64) * self.num_buckets as f64) as usize;
        let bucket = bucket.min(self.num_buckets - 1);
        
        self.buckets[bucket] += 1;
        self.num_samples += 1;
    }
    
    /// Compute chi-square statistic
    /// 
    /// Returns chi-square value. Lower is better (more uniform).
    /// For uniform distribution, expect chi-square ≈ num_buckets.
    pub fn chi_square(&self) -> f64 {
        if self.num_samples == 0 {
            return 0.0;
        }
        
        let expected = self.num_samples as f64 / self.num_buckets as f64;
        let mut chi_square = 0.0;
        
        for &count in &self.buckets {
            let diff = count as f64 - expected;
            chi_square += (diff * diff) / expected;
        }
        
        chi_square
    }
    
    /// Test if distribution is uniform (p-value > 0.05)
    /// 
    /// Uses chi-square test with significance level α = 0.05.
    pub fn is_uniform(&self) -> bool {
        let chi_square = self.chi_square();
        let degrees_of_freedom = (self.num_buckets - 1) as f64;
        
        // Critical value for α = 0.05 and df = num_buckets - 1
        // Approximation: critical_value ≈ df + 2*sqrt(2*df)
        let critical_value = degrees_of_freedom + 2.0 * (2.0 * degrees_of_freedom).sqrt();
        
        chi_square <= critical_value
    }
    
    /// Reset tester
    pub fn reset(&mut self) {
        self.num_samples = 0;
        self.buckets.fill(0);
    }
}

/// Global secure RNG instance
/// 
/// Thread-local secure RNG for convenience.
thread_local! {
    static SECURE_RNG: std::cell::RefCell<SecureRng> = std::cell::RefCell::new(
        SecureRng::new().expect("Failed to initialize secure RNG")
    );
}

/// Generate secure random bytes using thread-local RNG
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, RandomnessError> {
    SECURE_RNG.with(|rng| {
        let mut bytes = vec![0u8; len];
        rng.borrow_mut().fill_bytes(&mut bytes)?;
        Ok(bytes)
    })
}

/// Generate secure random u64 using thread-local RNG
pub fn secure_random_u64() -> Result<u64, RandomnessError> {
    SECURE_RNG.with(|rng| rng.borrow_mut().next_u64())
}

/// Generate secure random value in range using thread-local RNG
pub fn secure_random_range(bound: u64) -> Result<u64, RandomnessError> {
    SECURE_RNG.with(|rng| rng.borrow_mut().gen_range(bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_rng_creation() {
        let rng = SecureRng::new();
        assert!(rng.is_ok());
        
        let rng = rng.unwrap();
        assert_eq!(rng.source(), "OS entropy");
        assert_eq!(rng.bytes_generated(), 0);
    }
    
    #[test]
    fn test_secure_rng_generation() {
        let mut rng = SecureRng::new().unwrap();
        
        // Generate some random bytes
        let mut bytes = vec![0u8; 100];
        assert!(rng.fill_bytes(&mut bytes).is_ok());
        
        // Check not all zeros
        assert!(bytes.iter().any(|&b| b != 0));
        
        // Check bytes generated counter
        assert_eq!(rng.bytes_generated(), 100);
    }
    
    #[test]
    fn test_secure_rng_u64() {
        let mut rng = SecureRng::new().unwrap();
        
        let val1 = rng.next_u64().unwrap();
        let val2 = rng.next_u64().unwrap();
        
        // Should be different (with overwhelming probability)
        assert_ne!(val1, val2);
    }
    
    #[test]
    fn test_secure_rng_range() {
        let mut rng = SecureRng::new().unwrap();
        
        // Generate 1000 samples in range [0, 100)
        for _ in 0..1000 {
            let val = rng.gen_range(100).unwrap();
            assert!(val < 100);
        }
    }
    
    #[test]
    fn test_secure_rng_reseed() {
        let mut rng = SecureRng::new().unwrap();
        rng.reseed_threshold = 100; // Low threshold for testing
        
        // Generate enough bytes to trigger reseed
        let mut bytes = vec![0u8; 150];
        assert!(rng.fill_bytes(&mut bytes).is_ok());
        
        // Should have reseeded
        assert!(rng.bytes_generated() < 150);
    }
    
    #[test]
    fn test_deterministic_prf() {
        let seed = [42u8; 32];
        let mut prf1 = DeterministicPrf::new(seed, b"test_domain");
        let mut prf2 = DeterministicPrf::new(seed, b"test_domain");
        
        // Same seed and domain should produce same outputs
        let out1 = prf1.next(32);
        let out2 = prf2.next(32);
        assert_eq!(out1, out2);
        
        // Different domains should produce different outputs
        let mut prf3 = DeterministicPrf::new(seed, b"different_domain");
        let out3 = prf3.next(32);
        assert_ne!(out1, out3);
    }
    
    #[test]
    fn test_deterministic_prf_counter() {
        let seed = [42u8; 32];
        let mut prf = DeterministicPrf::new(seed, b"test");
        
        assert_eq!(prf.counter(), 0);
        
        prf.next(32);
        assert_eq!(prf.counter(), 1);
        
        prf.next(32);
        assert_eq!(prf.counter(), 2);
        
        prf.reset();
        assert_eq!(prf.counter(), 0);
    }
    
    #[test]
    fn test_uniformity_tester() {
        let mut rng = SecureRng::new().unwrap();
        let mut tester = UniformityTester::new(10);
        
        // Generate 10000 samples
        for _ in 0..10000 {
            let val = rng.next_u64().unwrap();
            tester.add_sample(val, u64::MAX);
        }
        
        // Should be approximately uniform
        assert!(tester.is_uniform());
        
        // Chi-square should be reasonable
        let chi_square = tester.chi_square();
        assert!(chi_square < 20.0); // For 10 buckets, expect ~9
    }
    
    #[test]
    fn test_uniformity_tester_non_uniform() {
        let mut tester = UniformityTester::new(10);
        
        // Add non-uniform samples (all in first bucket)
        for _ in 0..1000 {
            tester.add_sample(0, 1000);
        }
        
        // Should not be uniform
        assert!(!tester.is_uniform());
        
        // Chi-square should be very high
        let chi_square = tester.chi_square();
        assert!(chi_square > 100.0);
    }
    
    #[test]
    fn test_global_secure_random() {
        let bytes1 = secure_random_bytes(32).unwrap();
        let bytes2 = secure_random_bytes(32).unwrap();
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }
    
    #[test]
    fn test_secure_random_u64_global() {
        let val1 = secure_random_u64().unwrap();
        let val2 = secure_random_u64().unwrap();
        
        assert_ne!(val1, val2);
    }
    
    #[test]
    fn test_secure_random_range_global() {
        for _ in 0..100 {
            let val = secure_random_range(1000).unwrap();
            assert!(val < 1000);
        }
    }
}
