// Fiat-Shamir transcript for ProtogaLattice
//
// Implements cryptographic transcript for:
// - Non-interactive challenge generation
// - Binding prover and verifier to protocol state
// - Providing random oracle functionality

use crate::field::Field;
use crate::ring::RingElement;
use crate::protogalattice::types::ProtogaInstance;
use sha3::{Sha3_256, Digest};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Transcript protocol trait
pub trait TranscriptProtocol {
    /// Append message to transcript
    fn append_message(&mut self, label: &'static str, message: &[u8]);
    
    /// Append field element
    fn append_scalar<F: Field>(&mut self, label: &'static str, scalar: &F);
    
    /// Append multiple field elements
    fn append_field_elements<F: Field>(&mut self, label: &'static str, elements: &[F]);
    
    /// Append ring element
    fn append_ring_element(&mut self, label: &'static str, element: &RingElement);
    
    /// Append instance
    fn append_instance<F: Field>(&mut self, label: &'static str, instance: &ProtogaInstance<F>);
    
    /// Get challenge scalar
    fn challenge_scalar<F: Field>(&mut self, label: &'static str) -> F;
    
    /// Get challenge bytes
    fn challenge_bytes(&mut self, label: &'static str, dest: &mut [u8]);
    
    /// Get RNG for sampling
    fn rng(&mut self) -> Box<dyn RngCore>;
    
    /// Clone transcript state
    fn fork(&self, label: &'static str) -> Self where Self: Sized;
}

/// Concrete transcript implementation using SHA3-256
pub struct Transcript {
    hasher: Sha3_256,
    challenge_counter: u64,
}

impl Transcript {
    /// Create new transcript with domain separator
    pub fn new(domain_sep: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ProtogaLattice v1.0");
        hasher.update(domain_sep);
        
        Self {
            hasher,
            challenge_counter: 0,
        }
    }

    /// Squeeze bytes from transcript
    fn squeeze_bytes(&mut self, dest: &mut [u8]) {
        // Update with counter for domain separation
        self.hasher.update(&self.challenge_counter.to_le_bytes());
        self.challenge_counter += 1;
        
        // Finalize and copy
        let hash = self.hasher.finalize_reset();
        let copy_len = dest.len().min(hash.len());
        dest[..copy_len].copy_from_slice(&hash[..copy_len]);
        
        // If need more bytes, hash again
        if dest.len() > hash.len() {
            let mut remaining = dest.len() - hash.len();
            let mut offset = hash.len();
            
            while remaining > 0 {
                let hash = self.hasher.finalize_reset();
                let copy_len = remaining.min(hash.len());
                dest[offset..offset + copy_len].copy_from_slice(&hash[..copy_len]);
                offset += copy_len;
                remaining -= copy_len;
            }
        }
        
        // Re-initialize with previous state
        for byte in &hash {
            self.hasher.update(&[*byte]);
        }
    }
}

impl TranscriptProtocol for Transcript {
    fn append_message(&mut self, label: &'static str, message: &[u8]) {
        self.hasher.update(label.as_bytes());
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }

    fn append_scalar<F: Field>(&mut self, label: &'static str, scalar: &F) {
        let bytes = scalar.to_bytes();
        self.append_message(label, &bytes);
    }

    fn append_field_elements<F: Field>(&mut self, label: &'static str, elements: &[F]) {
        self.hasher.update(label.as_bytes());
        self.hasher.update(&(elements.len() as u64).to_le_bytes());
        
        for element in elements {
            let bytes = element.to_bytes();
            self.hasher.update(&bytes);
        }
    }

    fn append_ring_element(&mut self, label: &'static str, element: &RingElement) {
        self.hasher.update(label.as_bytes());
        let coeffs = element.coefficients();
        self.hasher.update(&(coeffs.len() as u64).to_le_bytes());
        
        for &coeff in coeffs {
            self.hasher.update(&coeff.to_le_bytes());
        }
    }

    fn append_instance<F: Field>(&mut self, label: &'static str, instance: &ProtogaInstance<F>) {
        self.hasher.update(label.as_bytes());
        
        // Append commitments
        self.hasher.update(&(instance.commitments.len() as u64).to_le_bytes());
        for commitment in &instance.commitments {
            self.append_ring_element("commitment", commitment);
        }
        
        // Append public inputs
        self.append_field_elements("public_inputs", &instance.public_inputs);
        
        // Append relaxation factor
        self.append_scalar("relaxation", &instance.relaxation_factor);
        
        // Append error commitment if present
        if let Some(ref error_commit) = instance.error_commitment {
            self.append_message("has_error", &[1u8]);
            self.append_ring_element("error", error_commit);
        } else {
            self.append_message("has_error", &[0u8]);
        }
    }

    fn challenge_scalar<F: Field>(&mut self, label: &'static str) -> F {
        self.append_message("challenge_label", label.as_bytes());
        
        let mut bytes = vec![0u8; 32];
        self.squeeze_bytes(&mut bytes);
        
        // Convert bytes to field element
        F::from_bytes(&bytes).unwrap_or_else(|| {
            // Fallback: hash again if conversion fails
            self.squeeze_bytes(&mut bytes);
            F::from_bytes(&bytes).expect("Failed to generate challenge")
        })
    }

    fn challenge_bytes(&mut self, label: &'static str, dest: &mut [u8]) {
        self.append_message("challenge_label", label.as_bytes());
        self.squeeze_bytes(dest);
    }

    fn rng(&mut self) -> Box<dyn RngCore> {
        let mut seed = [0u8; 32];
        self.challenge_bytes("rng_seed", &mut seed);
        Box::new(ChaCha20Rng::from_seed(seed))
    }

    fn fork(&self, label: &'static str) -> Self {
        let mut forked = self.clone();
        forked.append_message("fork", label.as_bytes());
        forked
    }
}

impl Clone for Transcript {
    fn clone(&self) -> Self {
        // Create new transcript and replay state
        let mut cloned = Transcript::new(b"");
        cloned.hasher = self.hasher.clone();
        cloned.challenge_counter = self.challenge_counter;
        cloned
    }
}

/// Merlin transcript wrapper for compatibility
pub struct MerlinTranscript {
    inner: Transcript,
}

impl MerlinTranscript {
    /// Create new Merlin-compatible transcript
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            inner: Transcript::new(label),
        }
    }

    /// Append protocol message
    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.inner.append_message(
            std::str::from_utf8(label).unwrap_or("unknown"),
            message,
        );
    }

    /// Build RNG for witness sampling
    pub fn build_rng(&mut self) -> TranscriptRng {
        let mut seed = [0u8; 32];
        self.inner.challenge_bytes("build_rng", &mut seed);
        TranscriptRng::new(seed)
    }
}

/// RNG derived from transcript
pub struct TranscriptRng {
    rng: ChaCha20Rng,
}

impl TranscriptRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl RngCore for TranscriptRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

/// Batch transcript for parallel proof generation
pub struct BatchTranscript {
    transcripts: Vec<Transcript>,
}

impl BatchTranscript {
    /// Create batch transcript
    pub fn new(batch_size: usize, domain_sep: &[u8]) -> Self {
        let transcripts = (0..batch_size)
            .map(|i| {
                let mut sep = domain_sep.to_vec();
                sep.extend_from_slice(&i.to_le_bytes());
                Transcript::new(&sep)
            })
            .collect();

        Self { transcripts }
    }

    /// Get transcript for index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Transcript> {
        self.transcripts.get_mut(index)
    }

    /// Get all transcripts
    pub fn all_mut(&mut self) -> &mut [Transcript] {
        &mut self.transcripts
    }

    /// Merge batch challenges
    pub fn merge_challenges<F: Field>(&mut self, label: &'static str) -> Vec<F> {
        self.transcripts
            .iter_mut()
            .map(|t| t.challenge_scalar(label))
            .collect()
    }
}

/// Structured transcript for complex protocols
pub struct StructuredTranscript {
    transcript: Transcript,
    phase: ProtocolPhase,
    round_number: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolPhase {
    Setup,
    Commitment,
    Challenge,
    Response,
    Verification,
}

impl StructuredTranscript {
    /// Create new structured transcript
    pub fn new(domain_sep: &[u8]) -> Self {
        Self {
            transcript: Transcript::new(domain_sep),
            phase: ProtocolPhase::Setup,
            round_number: 0,
        }
    }

    /// Begin new phase
    pub fn begin_phase(&mut self, phase: ProtocolPhase) {
        self.phase = phase;
        let phase_id = phase as u8;
        self.transcript.append_message("phase", &[phase_id]);
    }

    /// Begin new round
    pub fn begin_round(&mut self) {
        self.round_number += 1;
        self.transcript.append_message(
            "round",
            &self.round_number.to_le_bytes(),
        );
    }

    /// Get inner transcript
    pub fn inner_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }

    /// Get current phase
    pub fn current_phase(&self) -> ProtocolPhase {
        self.phase
    }

    /// Get current round
    pub fn current_round(&self) -> usize {
        self.round_number
    }
}

impl TranscriptProtocol for StructuredTranscript {
    fn append_message(&mut self, label: &'static str, message: &[u8]) {
        self.transcript.append_message(label, message);
    }

    fn append_scalar<F: Field>(&mut self, label: &'static str, scalar: &F) {
        self.transcript.append_scalar(label, scalar);
    }

    fn append_field_elements<F: Field>(&mut self, label: &'static str, elements: &[F]) {
        self.transcript.append_field_elements(label, elements);
    }

    fn append_ring_element(&mut self, label: &'static str, element: &RingElement) {
        self.transcript.append_ring_element(label, element);
    }

    fn append_instance<F: Field>(&mut self, label: &'static str, instance: &ProtogaInstance<F>) {
        self.transcript.append_instance(label, instance);
    }

    fn challenge_scalar<F: Field>(&mut self, label: &'static str) -> F {
        self.transcript.challenge_scalar(label)
    }

    fn challenge_bytes(&mut self, label: &'static str, dest: &mut [u8]) {
        self.transcript.challenge_bytes(label, dest);
    }

    fn rng(&mut self) -> Box<dyn RngCore> {
        self.transcript.rng()
    }

    fn fork(&self, label: &'static str) -> Self {
        Self {
            transcript: self.transcript.fork(label),
            phase: self.phase,
            round_number: self.round_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_message("msg", b"hello");
        t2.append_message("msg", b"hello");

        let c1: GoldilocksField = t1.challenge_scalar("challenge");
        let c2: GoldilocksField = t2.challenge_scalar("challenge");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_different_messages() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_message("msg", b"hello");
        t2.append_message("msg", b"world");

        let c1: GoldilocksField = t1.challenge_scalar("challenge");
        let c2: GoldilocksField = t2.challenge_scalar("challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_transcript_fork() {
        let mut t1 = Transcript::new(b"test");
        t1.append_message("msg", b"base");

        let mut t2 = t1.fork("fork1");
        let mut t3 = t1.fork("fork2");

        let c2: GoldilocksField = t2.challenge_scalar("challenge");
        let c3: GoldilocksField = t3.challenge_scalar("challenge");

        assert_ne!(c2, c3);
    }

    #[test]
    fn test_structured_transcript() {
        let mut st = StructuredTranscript::new(b"test");
        
        assert_eq!(st.current_phase(), ProtocolPhase::Setup);
        assert_eq!(st.current_round(), 0);

        st.begin_phase(ProtocolPhase::Commitment);
        assert_eq!(st.current_phase(), ProtocolPhase::Commitment);

        st.begin_round();
        assert_eq!(st.current_round(), 1);
    }

    #[test]
    fn test_batch_transcript() {
        let mut batch = BatchTranscript::new(3, b"test");
        
        for i in 0..3 {
            let t = batch.get_mut(i).unwrap();
            t.append_message("index", &i.to_le_bytes());
        }

        let challenges: Vec<GoldilocksField> = batch.merge_challenges("challenge");
        assert_eq!(challenges.len(), 3);
        
        // Each should be different due to different indices
        assert_ne!(challenges[0], challenges[1]);
        assert_ne!(challenges[1], challenges[2]);
    }
}
