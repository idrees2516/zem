// Fiat-Shamir Transformation
//
// Mathematical Foundation:
// The Fiat-Shamir heuristic transforms an interactive protocol
// into a non-interactive one by replacing verifier challenges
// with hash function outputs.
//
// Transformation:
// Interactive: V sends challenge ρ ← {0,1}^λ
// Non-interactive: ρ = H(transcript)
//
// Security: In the Random Oracle Model, this preserves
// knowledge soundness with negligible loss.

use crate::field::Field;
use crate::oracle::Oracle;
use sha3::{Sha3_256, Digest};

/// Fiat-Shamir Transformer
///
/// Converts interactive protocols to non-interactive using hash functions.
pub struct FiatShamirTransformer<O> {
    /// Oracle for challenge generation
    oracle: O,
    
    /// Transcript accumulator
    transcript: Vec<u8>,
}

impl<O: Oracle<Vec<u8>, Vec<u8>>> FiatShamirTransformer<O> {
    /// Create a new Fiat-Shamir transformer
    pub fn new(oracle: O) -> Self {
        Self {
            oracle,
            transcript: Vec::new(),
        }
    }
    
    /// Add message to transcript
    ///
    /// This should be called for each prover message.
    pub fn add_message(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
    }
    
    /// Generate challenge from current transcript
    ///
    /// Mathematical Process:
    /// ρ = H(transcript || domain_separator || counter)
    ///
    /// The domain separator ensures different protocols
    /// don't interfere with each other.
    pub fn generate_challenge<F: Field>(&mut self, domain: &[u8], counter: usize) -> F {
        let mut challenge_input = self.transcript.clone();
        challenge_input.extend_from_slice(domain);
        challenge_input.extend_from_slice(&counter.to_le_bytes());
        
        let challenge_bytes = self.oracle.query(challenge_input)
            .expect("Oracle query failed");
        
        self.transcript.extend_from_slice(&challenge_bytes);
        
        F::from_bytes_mod_order(&challenge_bytes)
    }
    
    /// Generate multiple challenges
    pub fn generate_challenges<F: Field>(&mut self, domain: &[u8], count: usize) -> Vec<F> {
        (0..count)
            .map(|i| self.generate_challenge(domain, i))
            .collect()
    }
    
    /// Get current transcript
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
    
    /// Reset transcript
    pub fn reset(&mut self) {
        self.transcript.clear();
    }
}

/// Fiat-Shamir with domain separation
///
/// Ensures different protocol instances don't interfere.
pub struct DomainSeparatedFS<O> {
    transformer: FiatShamirTransformer<O>,
    domain: Vec<u8>,
}

impl<O: Oracle<Vec<u8>, Vec<u8>>> DomainSeparatedFS<O> {
    pub fn new(oracle: O, domain: &[u8]) -> Self {
        Self {
            transformer: FiatShamirTransformer::new(oracle),
            domain: domain.to_vec(),
        }
    }
    
    pub fn add_message(&mut self, message: &[u8]) {
        self.transformer.add_message(message);
    }
    
    pub fn generate_challenge<F: Field>(&mut self, counter: usize) -> F {
        self.transformer.generate_challenge(&self.domain, counter)
    }
    
    pub fn generate_challenges<F: Field>(&mut self, count: usize) -> Vec<F> {
        self.transformer.generate_challenges(&self.domain, count)
    }
}

/// Batch Fiat-Shamir
///
/// Optimized for generating many challenges at once.
pub struct BatchFS;

impl BatchFS {
    /// Generate batch of challenges efficiently
    ///
    /// Uses a single hash and expands it to multiple challenges.
    pub fn generate_batch<F: Field>(transcript: &[u8], count: usize) -> Vec<F> {
        let mut challenges = Vec::with_capacity(count);
        let mut hasher = Sha3_256::new();
        hasher.update(transcript);
        
        for i in 0..count {
            let mut counter_hasher = hasher.clone();
            counter_hasher.update(&i.to_le_bytes());
            let hash = counter_hasher.finalize();
            challenges.push(F::from_bytes_mod_order(&hash));
        }
        
        challenges
    }
}
