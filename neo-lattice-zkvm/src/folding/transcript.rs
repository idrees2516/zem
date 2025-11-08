// Transcript Management and Fiat-Shamir Transform
//
// This module implements transcript management for the Neo folding scheme,
// providing Fiat-Shamir transformation for non-interactive proofs.
//
// Requirements: NEO-9.8, NEO-12.10, NEO-12.11, NEO-12.12, NEO-12.13, NEO-14.10, NEO-14.13

use crate::field::traits::Field;
use crate::ring::cyclotomic::RingElement;
use crate::commitment::ajtai::Commitment;
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

/// Transcript for Fiat-Shamir transform
/// 
/// Maintains a running hash of all protocol messages and generates
/// deterministic challenges from the transcript state.
pub struct Transcript {
    /// Running hash state
    hasher: Sha3_256,
    /// Challenge counter for domain separation
    challenge_counter: u64,
}

impl Transcript {
    /// Create a new transcript with a protocol label
    /// 
    /// # Arguments
    /// * `label` - Protocol identifier for domain separation
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Neo-Folding-Transcript");
        hasher.update(label);
        
        Self {
            hasher,
            challenge_counter: 0,
        }
    }

    /// Append a message to the transcript
    /// 
    /// # Arguments
    /// * `label` - Message label for domain separation
    /// * `message` - Message bytes
    /// 
    /// # Requirements
    /// - NEO-12.12: Implement canonical serialization for field elements
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        // Append label length and label
        self.hasher.update(&(label.len() as u64).to_le_bytes());
        self.hasher.update(label);
        
        // Append message length and message
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }

    /// Append a field element to the transcript
    /// 
    /// Uses canonical representation: smallest non-negative residue
    /// 
    /// # Requirements
    /// - NEO-12.12: Implement canonical serialization for field elements
    /// - NEO-12.13: Ensure deterministic serialization for reproducibility
    pub fn append_field_element<F: Field>(&mut self, label: &[u8], element: &F) {
        let bytes = element.to_canonical_u64().to_le_bytes();
        self.append_message(label, &bytes);
    }

    /// Append multiple field elements to the transcript
    pub fn append_field_elements<F: Field>(&mut self, label: &[u8], elements: &[F]) {
        self.append_message(label, b"field_elements_begin");
        self.append_message(b"count", &(elements.len() as u64).to_le_bytes());
        
        for (i, element) in elements.iter().enumerate() {
            let element_label = format!("element_{}", i);
            self.append_field_element(element_label.as_bytes(), element);
        }
        
        self.append_message(label, b"field_elements_end");
    }

    /// Append a ring element to the transcript
    /// 
    /// Serializes all coefficients in order
    /// 
    /// # Requirements
    /// - NEO-12.12: Implement serialization for ring elements
    pub fn append_ring_element<F: Field>(&mut self, label: &[u8], element: &RingElement<F>) {
        self.append_message(label, b"ring_element_begin");
        
        for (i, coeff) in element.coeffs().iter().enumerate() {
            let coeff_label = format!("coeff_{}", i);
            self.append_field_element(coeff_label.as_bytes(), coeff);
        }
        
        self.append_message(label, b"ring_element_end");
    }

    /// Append a commitment to the transcript
    /// 
    /// Serializes all ring elements in the commitment
    /// 
    /// # Requirements
    /// - NEO-12.12: Implement serialization for commitments
    pub fn append_commitment<F: Field>(&mut self, label: &[u8], commitment: &Commitment<F>) {
        self.append_message(label, b"commitment_begin");
        
        for (i, ring_elem) in commitment.values().iter().enumerate() {
            let elem_label = format!("commitment_elem_{}", i);
            self.append_ring_element(elem_label.as_bytes(), ring_elem);
        }
        
        self.append_message(label, b"commitment_end");
    }

    /// Append a u64 value to the transcript
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    /// Get challenge bytes from the transcript
    /// 
    /// Uses challenge counter for domain separation between different challenges
    /// 
    /// # Arguments
    /// * `label` - Challenge label
    /// * `num_bytes` - Number of random bytes to generate
    /// 
    /// # Returns
    /// Deterministic random bytes derived from transcript
    /// 
    /// # Requirements
    /// - NEO-12.10: Sample random coefficients using cryptographic randomness
    /// - NEO-12.11: Implement Fiat-Shamir transform for non-interactive challenges
    /// - NEO-14.10: Hash transcript to generate challenge
    pub fn challenge_bytes(&mut self, label: &[u8], num_bytes: usize) -> Vec<u8> {
        // Clone hasher to preserve transcript state
        let mut challenge_hasher = self.hasher.clone();
        
        // Add challenge-specific data
        challenge_hasher.update(b"challenge");
        challenge_hasher.update(label);
        challenge_hasher.update(&self.challenge_counter.to_le_bytes());
        
        // Increment counter for next challenge
        self.challenge_counter += 1;
        
        // Generate bytes by repeated hashing if needed
        let mut result = Vec::with_capacity(num_bytes);
        let mut counter = 0u64;
        
        while result.len() < num_bytes {
            let mut round_hasher = challenge_hasher.clone();
            round_hasher.update(&counter.to_le_bytes());
            let hash = round_hasher.finalize();
            
            let bytes_needed = num_bytes - result.len();
            let bytes_to_take = bytes_needed.min(hash.len());
            result.extend_from_slice(&hash[..bytes_to_take]);
            
            counter += 1;
        }
        
        result
    }

    /// Get a challenge field element from the transcript
    /// 
    /// Derives a uniformly random field element using rejection sampling
    /// 
    /// # Requirements
    /// - NEO-12.10: Derive field element challenges from transcript hash
    /// - NEO-12.13: Ensure uniform distribution of challenges
    pub fn challenge_field_element<F: Field>(&mut self, label: &[u8]) -> F {
        let modulus = F::MODULUS;
        let mut counter = 0u64;
        
        loop {
            // Get 8 bytes for u64
            let mut challenge_label = label.to_vec();
            challenge_label.extend_from_slice(&counter.to_le_bytes());
            let bytes = self.challenge_bytes(&challenge_label, 8);
            
            let value = u64::from_le_bytes(bytes.try_into().unwrap());
            
            // Rejection sampling to ensure uniform distribution
            // Accept if value < modulus
            if value < modulus {
                return F::from_canonical_u64(value);
            }
            
            counter += 1;
            
            // Safety check: should succeed quickly for 64-bit fields
            if counter > 100 {
                // Fallback: use modular reduction (slightly biased but acceptable)
                return F::from_canonical_u64(value % modulus);
            }
        }
    }

    /// Get multiple challenge field elements
    pub fn challenge_field_elements<F: Field>(&mut self, label: &[u8], count: usize) -> Vec<F> {
        (0..count)
            .map(|i| {
                let element_label = format!("{}_{}", String::from_utf8_lossy(label), i);
                self.challenge_field_element::<F>(element_label.as_bytes())
            })
            .collect()
    }

    /// Get a challenge ring element from the transcript
    /// 
    /// Derives a ring element with uniformly random coefficients
    /// 
    /// # Arguments
    /// * `label` - Challenge label
    /// * `degree` - Ring degree (number of coefficients)
    /// 
    /// # Requirements
    /// - NEO-12.10: Derive ring element challenges from transcript hash
    pub fn challenge_ring_element<F: Field>(&mut self, label: &[u8], degree: usize) -> RingElement<F> {
        let coeffs = self.challenge_field_elements::<F>(label, degree);
        RingElement::new(coeffs)
    }

    /// Get the current transcript hash
    /// 
    /// Returns the hash of all messages appended so far
    pub fn get_hash(&self) -> Vec<u8> {
        let hasher = self.hasher.clone();
        hasher.finalize().to_vec()
    }

    /// Clone the transcript at current state
    pub fn fork(&self, label: &[u8]) -> Self {
        let mut forked = Self {
            hasher: self.hasher.clone(),
            challenge_counter: 0,
        };
        forked.append_message(b"fork", label);
        forked
    }
}

/// Transcript builder for structured protocol execution
pub struct TranscriptBuilder {
    transcript: Transcript,
}

impl TranscriptBuilder {
    /// Create a new transcript builder
    pub fn new(protocol_label: &str) -> Self {
        Self {
            transcript: Transcript::new(protocol_label.as_bytes()),
        }
    }

    /// Add a protocol round
    pub fn round(mut self, round_num: usize) -> Self {
        self.transcript.append_u64(b"round", round_num as u64);
        self
    }

    /// Add public input
    pub fn public_input<F: Field>(mut self, input: &[F]) -> Self {
        self.transcript.append_field_elements::<F>(b"public_input", input);
        self
    }

    /// Add commitment
    pub fn commitment<F: Field>(mut self, label: &str, commitment: &Commitment<F>) -> Self {
        self.transcript.append_commitment(label.as_bytes(), commitment);
        self
    }

    /// Add prover message
    pub fn prover_message(mut self, label: &str, message: &[u8]) -> Self {
        self.transcript.append_message(label.as_bytes(), message);
        self
    }

    /// Build the transcript
    pub fn build(self) -> Transcript {
        self.transcript
    }

    /// Get mutable reference to transcript
    pub fn transcript_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;

    #[test]
    fn test_transcript_determinism() {
        let mut transcript1 = Transcript::new(b"test");
        let mut transcript2 = Transcript::new(b"test");

        let elem = GoldilocksField::from_canonical_u64(12345);
        
        transcript1.append_field_element(b"test_elem", &elem);
        transcript2.append_field_element(b"test_elem", &elem);

        let challenge1 = transcript1.challenge_field_element::<GoldilocksField>(b"challenge");
        let challenge2 = transcript2.challenge_field_element::<GoldilocksField>(b"challenge");

        assert_eq!(challenge1.to_canonical_u64(), challenge2.to_canonical_u64());
    }

    #[test]
    fn test_challenge_uniqueness() {
        let mut transcript = Transcript::new(b"test");
        
        let challenge1 = transcript.challenge_field_element::<GoldilocksField>(b"challenge1");
        let challenge2 = transcript.challenge_field_element::<GoldilocksField>(b"challenge2");

        // Different labels should produce different challenges
        assert_ne!(challenge1.to_canonical_u64(), challenge2.to_canonical_u64());
    }

    #[test]
    fn test_transcript_fork() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_u64(b"value", 42);

        let mut fork1 = transcript.fork(b"fork1");
        let mut fork2 = transcript.fork(b"fork2");

        let challenge1 = fork1.challenge_field_element::<GoldilocksField>(b"challenge");
        let challenge2 = fork2.challenge_field_element::<GoldilocksField>(b"challenge");

        // Forks should produce different challenges
        assert_ne!(challenge1.to_canonical_u64(), challenge2.to_canonical_u64());
    }

    #[test]
    fn test_field_element_serialization() {
        let mut transcript = Transcript::new(b"test");
        
        let elements = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
        ];

        transcript.append_field_elements(b"elements", &elements);
        
        let hash1 = transcript.get_hash();
        
        // Recreate with same elements
        let mut transcript2 = Transcript::new(b"test");
        transcript2.append_field_elements(b"elements", &elements);
        let hash2 = transcript2.get_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_challenge_bytes() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_u64(b"seed", 12345);

        let bytes1 = transcript.challenge_bytes(b"challenge", 32);
        let bytes2 = transcript.challenge_bytes(b"challenge", 32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        
        // Same label should produce same bytes
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_transcript_builder() {
        let elem = GoldilocksField::from_canonical_u64(42);
        let input = vec![elem, elem];

        let mut transcript = TranscriptBuilder::new("test_protocol")
            .round(0)
            .public_input(&input)
            .prover_message("msg", b"hello")
            .build();

        let challenge = transcript.challenge_field_element::<GoldilocksField>(b"test");
        assert!(challenge.to_canonical_u64() < GoldilocksField::MODULUS);
    }
}
