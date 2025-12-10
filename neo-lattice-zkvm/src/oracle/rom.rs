// Random Oracle Model (ROM)
//
// Standard random oracle implementation with transcript management and caching.
//
// Mathematical Foundation:
// - Oracle θ: X → Y sampled uniformly from all functions X → Y
// - Consistency: θ(q) returns same r for repeated queries
// - Transcript: tr_A = {(q_i, r_i)} records all queries

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::transcript::{Oracle, OracleTranscript};
use super::errors::{OracleError, OracleResult};

/// Random Oracle implementation using hash function
///
/// Uses SHA3-256 for hashing and ChaCha20 for randomness
#[derive(Clone)]
pub struct RandomOracle {
    /// Oracle transcript
    transcript: OracleTranscript<Vec<u8>, Vec<u8>>,
    
    /// Response cache for efficiency
    cache: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Random number generator (seeded from hash)
    rng_seed: [u8; 32],
    
    /// Output length in bytes
    output_length: usize,
}

impl RandomOracle {
    /// Create a new random oracle with default output length (32 bytes)
    pub fn new() -> Self {
        Self::with_output_length(32)
    }
    
    /// Create a new random oracle with specified output length
    pub fn with_output_length(output_length: usize) -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        
        Self {
            transcript: OracleTranscript::new(),
            cache: HashMap::new(),
            rng_seed: seed,
            output_length,
        }
    }
    
    /// Create a random oracle with a specific seed (for testing)
    pub fn with_seed(seed: [u8; 32], output_length: usize) -> Self {
        Self {
            transcript: OracleTranscript::new(),
            cache: HashMap::new(),
            rng_seed: seed,
            output_length,
        }
    }
    
    /// Hash input to produce oracle response
    fn hash_input(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        
        // Include seed in hash for domain separation
        hasher.update(&self.rng_seed);
        hasher.update(input);
        
        let hash = hasher.finalize();
        
        // If output length matches hash length, return directly
        if self.output_length == 32 {
            return hash.to_vec();
        }
        
        // Otherwise, expand or truncate
        if self.output_length < 32 {
            hash[..self.output_length].to_vec()
        } else {
            // Expand using multiple hashes
            let mut output = Vec::with_capacity(self.output_length);
            let mut counter = 0u64;
            
            while output.len() < self.output_length {
                let mut hasher = Sha3_256::new();
                hasher.update(&self.rng_seed);
                hasher.update(input);
                hasher.update(&counter.to_le_bytes());
                
                let hash = hasher.finalize();
                let remaining = self.output_length - output.len();
                let to_copy = remaining.min(32);
                output.extend_from_slice(&hash[..to_copy]);
                
                counter += 1;
            }
            
            output
        }
    }
    
    /// Get output length
    pub fn output_length(&self) -> usize {
        self.output_length
    }
    
    /// Get number of queries made
    pub fn num_queries(&self) -> usize {
        self.transcript.len()
    }
}

impl Default for RandomOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle<Vec<u8>, Vec<u8>> for RandomOracle {
    fn query(&mut self, input: Vec<u8>) -> OracleResult<Vec<u8>> {
        // Check cache first
        if let Some(cached) = self.cache.get(&input) {
            return Ok(cached.clone());
        }
        
        // Check transcript
        if let Some(response) = self.transcript.get_response(&input) {
            return Ok(response.clone());
        }
        
        // Compute new response
        let response = self.hash_input(&input);
        
        // Record in transcript
        self.transcript.record(input.clone(), response.clone())?;
        
        // Cache response
        self.cache.insert(input, response.clone());
        
        Ok(response)
    }
    
    fn transcript(&self) -> &OracleTranscript<Vec<u8>, Vec<u8>> {
        &self.transcript
    }
    
    fn transcript_mut(&mut self) -> &mut OracleTranscript<Vec<u8>, Vec<u8>> {
        &mut self.transcript
    }
}

/// Random oracle for field elements
///
/// Specialized oracle that outputs field elements
pub struct FieldOracle<F> {
    /// Underlying random oracle
    rom: RandomOracle,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F> FieldOracle<F> {
    /// Create a new field oracle
    pub fn new(output_length: usize) -> Self {
        Self {
            rom: RandomOracle::with_output_length(output_length),
            _phantom: PhantomData,
        }
    }
    
    /// Query the oracle (returns raw bytes)
    pub fn query_bytes(&mut self, input: Vec<u8>) -> OracleResult<Vec<u8>> {
        self.rom.query(input)
    }
    
    /// Get transcript
    pub fn transcript(&self) -> &OracleTranscript<Vec<u8>, Vec<u8>> {
        self.rom.transcript()
    }
}

/// Helper functions for common oracle patterns
pub mod utils {
    use super::*;
    
    /// Query oracle with serializable input
    pub fn query_serializable<T: Serialize>(
        oracle: &mut RandomOracle,
        input: &T,
    ) -> OracleResult<Vec<u8>> {
        let input_bytes = bincode::serialize(input)
            .map_err(|e| OracleError::SerializationError(e.to_string()))?;
        oracle.query(input_bytes)
    }
    
    /// Query oracle and deserialize response
    pub fn query_and_deserialize<T: Serialize, R: for<'de> Deserialize<'de>>(
        oracle: &mut RandomOracle,
        input: &T,
    ) -> OracleResult<R> {
        let response_bytes = query_serializable(oracle, input)?;
        bincode::deserialize(&response_bytes)
            .map_err(|e| OracleError::DeserializationError(e.to_string()))
    }
    
    /// Create a domain-separated oracle
    pub fn domain_separated(domain: &[u8], output_length: usize) -> RandomOracle {
        let mut hasher = Sha3_256::new();
        hasher.update(b"DOMAIN_SEPARATION");
        hasher.update(domain);
        let seed_hash = hasher.finalize();
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_hash);
        
        RandomOracle::with_seed(seed, output_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_oracle_creation() {
        let oracle = RandomOracle::new();
        assert_eq!(oracle.output_length(), 32);
        assert_eq!(oracle.num_queries(), 0);
    }
    
    #[test]
    fn test_random_oracle_query() {
        let mut oracle = RandomOracle::new();
        
        let input = vec![1u8, 2, 3];
        let response1 = oracle.query(input.clone()).unwrap();
        
        assert_eq!(response1.len(), 32);
        assert_eq!(oracle.num_queries(), 1);
        
        // Same query should return same response
        let response2 = oracle.query(input.clone()).unwrap();
        assert_eq!(response1, response2);
        assert_eq!(oracle.num_queries(), 1); // Should not increase
    }
    
    #[test]
    fn test_random_oracle_consistency() {
        let mut oracle = RandomOracle::new();
        
        let input1 = vec![1u8, 2, 3];
        let input2 = vec![4u8, 5, 6];
        
        let response1 = oracle.query(input1.clone()).unwrap();
        let response2 = oracle.query(input2.clone()).unwrap();
        
        // Different inputs should give different outputs (with high probability)
        assert_ne!(response1, response2);
        
        // Repeated queries should be consistent
        assert_eq!(oracle.query(input1).unwrap(), response1);
        assert_eq!(oracle.query(input2).unwrap(), response2);
    }
    
    #[test]
    fn test_random_oracle_custom_length() {
        let mut oracle = RandomOracle::with_output_length(16);
        
        let input = vec![1u8, 2, 3];
        let response = oracle.query(input).unwrap();
        
        assert_eq!(response.len(), 16);
    }
    
    #[test]
    fn test_random_oracle_long_output() {
        let mut oracle = RandomOracle::with_output_length(100);
        
        let input = vec![1u8, 2, 3];
        let response = oracle.query(input).unwrap();
        
        assert_eq!(response.len(), 100);
    }
    
    #[test]
    fn test_random_oracle_deterministic_with_seed() {
        let seed = [42u8; 32];
        
        let mut oracle1 = RandomOracle::with_seed(seed, 32);
        let mut oracle2 = RandomOracle::with_seed(seed, 32);
        
        let input = vec![1u8, 2, 3];
        
        let response1 = oracle1.query(input.clone()).unwrap();
        let response2 = oracle2.query(input).unwrap();
        
        assert_eq!(response1, response2);
    }
    
    #[test]
    fn test_domain_separated_oracle() {
        let mut oracle1 = utils::domain_separated(b"domain1", 32);
        let mut oracle2 = utils::domain_separated(b"domain2", 32);
        
        let input = vec![1u8, 2, 3];
        
        let response1 = oracle1.query(input.clone()).unwrap();
        let response2 = oracle2.query(input).unwrap();
        
        // Different domains should give different outputs
        assert_ne!(response1, response2);
    }
}
