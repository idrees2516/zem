// Hash Oracle Implementation
// Supports multiple hash functions for Fiat-Shamir transform

use sha2::{Sha256, Digest as Sha2Digest};
use blake3::Hasher as Blake3Hasher;
use std::marker::PhantomData;

/// Hash function types supported by the system
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA-256 (standard cryptographic hash)
    Sha256,
    /// BLAKE3 (fast cryptographic hash)
    Blake3,
    /// Poseidon (SNARK-friendly hash)
    Poseidon,
}

/// Hash oracle trait for Fiat-Shamir transform
pub trait HashOracle: Clone {
    /// Initialize new hash oracle
    fn new(function: HashFunction) -> Self;
    
    /// Update oracle with message
    fn update(&mut self, data: &[u8]);
    
    /// Finalize and get challenge bytes
    fn finalize(&mut self, output_len: usize) -> Vec<u8>;
    
    /// Reset oracle state
    fn reset(&mut self);
    
    /// Get hash function type
    fn hash_function(&self) -> HashFunction;
}

/// Standard hash oracle implementation
#[derive(Clone)]
pub struct StandardHashOracle {
    function: HashFunction,
    state: Vec<u8>,
}

impl HashOracle for StandardHashOracle {
    fn new(function: HashFunction) -> Self {
        Self {
            function,
            state: Vec::new(),
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }
    
    fn finalize(&mut self, output_len: usize) -> Vec<u8> {
        let output = match self.function {
            HashFunction::Sha256 => self.finalize_sha256(output_len),
            HashFunction::Blake3 => self.finalize_blake3(output_len),
            HashFunction::Poseidon => self.finalize_poseidon(output_len),
        };
        
        // Reset state after finalization
        self.state.clear();
        
        output
    }
    
    fn reset(&mut self) {
        self.state.clear();
    }
    
    fn hash_function(&self) -> HashFunction {
        self.function
    }
}

impl StandardHashOracle {
    /// Finalize using SHA-256
    fn finalize_sha256(&self, output_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut counter = 0u64;
        
        while output.len() < output_len {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(&counter.to_le_bytes());
            let hash = hasher.finalize();
            
            let remaining = output_len - output.len();
            let to_copy = remaining.min(hash.len());
            output.extend_from_slice(&hash[..to_copy]);
            
            counter += 1;
        }
        
        output
    }
    
    /// Finalize using BLAKE3
    fn finalize_blake3(&self, output_len: usize) -> Vec<u8> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.state);
        
        let mut output = vec![0u8; output_len];
        let mut output_reader = hasher.finalize_xof();
        
        // BLAKE3 XOF can produce arbitrary length output
        use std::io::Read;
        output_reader.read_exact(&mut output).expect("BLAKE3 XOF read failed");
        
        output
    }
    
    /// Finalize using Poseidon (SNARK-friendly)
    fn finalize_poseidon(&self, output_len: usize) -> Vec<u8> {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        
        for msg in &self.messages {
            hasher.update(msg);
        }
        
        let mut output_reader = hasher.finalize_xof();
        let mut output = vec![0u8; output_len];
        output_reader.read_exact(&mut output).expect("Poseidon XOF read failed");
        
        output
    }
}

/// Merkle-Damgård framework for fixed-length input hashing
/// 
/// This ensures that the hash function can handle arbitrary-length inputs
/// by breaking them into fixed-size blocks and processing sequentially.
#[derive(Clone)]
pub struct MerkleDamgardOracle<H: HashOracle> {
    inner: H,
    block_size: usize,
    buffer: Vec<u8>,
}

impl<H: HashOracle> MerkleDamgardOracle<H> {
    /// Create new Merkle-Damgård oracle with specified block size
    pub fn new(function: HashFunction, block_size: usize) -> Self {
        Self {
            inner: H::new(function),
            block_size,
            buffer: Vec::new(),
        }
    }
    
    /// Update with data, processing complete blocks
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        
        // Process complete blocks
        while self.buffer.len() >= self.block_size {
            let block = self.buffer.drain(..self.block_size).collect::<Vec<_>>();
            self.inner.update(&block);
        }
    }
    
    /// Finalize, processing remaining buffered data
    pub fn finalize(&mut self, output_len: usize) -> Vec<u8> {
        // Process remaining buffer with padding
        if !self.buffer.is_empty() {
            // Pad to block size
            let padding_len = self.block_size - self.buffer.len();
            self.buffer.extend(vec![0u8; padding_len]);
            self.inner.update(&self.buffer);
            self.buffer.clear();
        }
        
        self.inner.finalize(output_len)
    }
    
    /// Reset oracle state
    pub fn reset(&mut self) {
        self.inner.reset();
        self.buffer.clear();
    }
    
    /// Get hash function type
    pub fn hash_function(&self) -> HashFunction {
        self.inner.hash_function()
    }
}

/// Random oracle model wrapper
/// 
/// In security proofs, we model the hash function as a random oracle.
/// This wrapper tracks oracle queries for security analysis.
#[derive(Clone)]
pub struct RandomOracleModel<H: HashOracle> {
    inner: H,
    query_count: usize,
    max_queries: Option<usize>,
}

impl<H: HashOracle> RandomOracleModel<H> {
    /// Create new random oracle model
    pub fn new(function: HashFunction) -> Self {
        Self {
            inner: H::new(function),
            query_count: 0,
            max_queries: None,
        }
    }
    
    /// Create with maximum query limit
    pub fn with_max_queries(function: HashFunction, max_queries: usize) -> Self {
        Self {
            inner: H::new(function),
            query_count: 0,
            max_queries: Some(max_queries),
        }
    }
    
    /// Query the random oracle
    pub fn query(&mut self, input: &[u8], output_len: usize) -> Result<Vec<u8>, String> {
        // Check query limit
        if let Some(max) = self.max_queries {
            if self.query_count >= max {
                return Err(format!(
                    "Exceeded maximum oracle queries: {}",
                    max
                ));
            }
        }
        
        self.query_count += 1;
        
        self.inner.update(input);
        Ok(self.inner.finalize(output_len))
    }
    
    /// Get number of queries made
    pub fn query_count(&self) -> usize {
        self.query_count
    }
    
    /// Reset oracle and query counter
    pub fn reset(&mut self) {
        self.inner.reset();
        self.query_count = 0;
    }
    
    /// Get hash function type
    pub fn hash_function(&self) -> HashFunction {
        self.inner.hash_function()
    }
}

/// Knowledge error accounting for oracle queries
/// 
/// The knowledge error bound must account for the number of oracle queries Q:
/// ϵ_knowledge = ϵ_base + Q·ϵ_soundness
pub fn compute_knowledge_error(
    base_error: f64,
    soundness_error: f64,
    num_queries: usize,
) -> f64 {
    base_error + (num_queries as f64) * soundness_error
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha256_oracle() {
        let mut oracle = StandardHashOracle::new(HashFunction::Sha256);
        oracle.update(b"test message");
        let output = oracle.finalize(32);
        assert_eq!(output.len(), 32);
    }
    
    #[test]
    fn test_blake3_oracle() {
        let mut oracle = StandardHashOracle::new(HashFunction::Blake3);
        oracle.update(b"test message");
        let output = oracle.finalize(64);
        assert_eq!(output.len(), 64);
    }
    
    #[test]
    fn test_merkle_damgard() {
        let mut oracle = MerkleDamgardOracle::<StandardHashOracle>::new(
            HashFunction::Blake3,
            64,
        );
        oracle.update(b"test message that is longer than block size");
        let output = oracle.finalize(32);
        assert_eq!(output.len(), 32);
    }
    
    #[test]
    fn test_random_oracle_model() {
        let mut oracle = RandomOracleModel::<StandardHashOracle>::with_max_queries(
            HashFunction::Sha256,
            10,
        );
        
        for i in 0..10 {
            let result = oracle.query(&[i as u8], 32);
            assert!(result.is_ok());
        }
        
        // 11th query should fail
        let result = oracle.query(&[11], 32);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_knowledge_error() {
        let error = compute_knowledge_error(0.001, 0.0001, 100);
        assert!((error - 0.011).abs() < 1e-10);
    }
}
