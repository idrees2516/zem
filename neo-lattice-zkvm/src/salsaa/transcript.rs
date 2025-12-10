// Fiat-Shamir transcript for SALSAA protocols
//
// Mathematical Background:
// The Fiat-Shamir transform converts interactive protocols into non-interactive
// proofs by replacing verifier challenges with hash-based randomness.
//
// Transcript Operations:
// 1. Append messages: Add prover messages to transcript
// 2. Generate challenges: Derive verifier challenges from transcript state
// 3. Domain separation: Ensure different protocol steps use different randomness
//
// Challenge Types in SALSAA:
// - F_{q^e}^× challenges: For sumcheck, batching (non-zero extension field elements)
// - R_q challenges: For folding, splitting (ring elements)
// - Vectors: For batching multiple instances
//
// Security:
// - Uses Blake3 for cryptographic hashing
// - Provides 128-bit security when challenges are in F_{q^e} with q^e ≥ 2^128
// - Domain separation prevents cross-protocol attacks
//
// Reference: SALSAA paper Section 4, Requirements 18.1, 18.2

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::ExtFieldElement;
use crate::salsaa::matrix::Matrix;
use blake3::Hasher;
use std::sync::Arc;

/// Fiat-Shamir transcript for non-interactive proofs
///
/// Maintains a running hash of all protocol messages and generates
/// deterministic challenges based on the transcript state.
pub struct Transcript {
    /// Blake3 hasher for transcript state
    hasher: Hasher,
    
    /// Domain separator for protocol identification
    domain_separator: Vec<u8>,
}

impl Transcript {
    /// Create new transcript with domain separator
    ///
    /// The domain separator ensures that different protocols or protocol
    /// instances produce different challenges, preventing cross-protocol attacks.
    ///
    /// Example domain separators:
    /// - b"SALSAA-SNARK-v1"
    /// - b"SALSAA-PCS-v1"
    /// - b"SALSAA-Folding-v1"
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        
        // Initialize with domain separator
        hasher.update(b"SALSAA-Transcript-v1");
        hasher.update(&(domain_separator.len() as u64).to_le_bytes());
        hasher.update(domain_separator);
        
        Self {
            hasher,
            domain_separator: domain_separator.to_vec(),
        }
    }
    
    /// Append arbitrary message to transcript
    ///
    /// Messages are length-prefixed to prevent ambiguity:
    /// transcript ← H(transcript || len(message) || message)
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }
    
    /// Append field element to transcript
    pub fn append_field_element<F: Field>(&mut self, label: &[u8], element: &F) {
        let bytes = element.to_canonical_u64().to_le_bytes();
        self.append_message(label, &bytes);
    }
    
    /// Append ring element to transcript
    ///
    /// Serializes all coefficients in canonical form
    pub fn append_ring_element<F: Field>(&mut self, label: &[u8], element: &RingElement<F>) {
        self.hasher.update(label);
        self.hasher.update(&(element.coeffs.len() as u64).to_le_bytes());
        
        for coeff in &element.coeffs {
            let bytes = coeff.to_canonical_u64().to_le_bytes();
            self.hasher.update(&bytes);
        }
    }
    
    /// Append extension field element to transcript
    pub fn append_ext_field_element<F: Field>(
        &mut self,
        label: &[u8],
        element: &ExtFieldElement<F>,
    ) {
        self.hasher.update(label);
        self.hasher.update(&(element.coeffs.len() as u64).to_le_bytes());
        
        for coeff in &element.coeffs {
            let bytes = coeff.to_canonical_u64().to_le_bytes();
            self.hasher.update(&bytes);
        }
    }
    
    /// Append matrix to transcript
    ///
    /// Serializes dimensions and all elements
    pub fn append_matrix<F: Field>(&mut self, label: &[u8], matrix: &Matrix<F>) {
        self.hasher.update(label);
        self.hasher.update(&(matrix.rows as u64).to_le_bytes());
        self.hasher.update(&(matrix.cols as u64).to_le_bytes());
        
        for element in &matrix.data {
            for coeff in &element.coeffs {
                let bytes = coeff.to_canonical_u64().to_le_bytes();
                self.hasher.update(&bytes);
            }
        }
    }
    
    /// Append vector of ring elements to transcript
    pub fn append_ring_vector<F: Field>(&mut self, label: &[u8], vector: &[RingElement<F>]) {
        self.hasher.update(label);
        self.hasher.update(&(vector.len() as u64).to_le_bytes());
        
        for element in vector {
            for coeff in &element.coeffs {
                let bytes = coeff.to_canonical_u64().to_le_bytes();
                self.hasher.update(&bytes);
            }
        }
    }
    
    /// Append vector of extension field elements to transcript
    pub fn append_ext_field_vector<F: Field>(
        &mut self,
        label: &[u8],
        vector: &[ExtFieldElement<F>],
    ) {
        self.hasher.update(label);
        self.hasher.update(&(vector.len() as u64).to_le_bytes());
        
        for element in vector {
            for coeff in &element.coeffs {
                let bytes = coeff.to_canonical_u64().to_le_bytes();
                self.hasher.update(&bytes);
            }
        }
    }
    
    /// Generate challenge in F_{q^e}^× (non-zero extension field element)
    ///
    /// Used for:
    /// - Sumcheck round challenges r_j ∈ F_{q^e}^×
    /// - Batching challenges ρ ∈ F_{q^e}^×
    /// - Random linear combinations
    ///
    /// Algorithm:
    /// 1. Hash transcript state with label
    /// 2. Expand hash output to e field elements
    /// 3. Reject if result is zero (negligible probability)
    /// 4. Return non-zero extension field element
    ///
    /// Security: Provides 128-bit security when q^e ≥ 2^128
    pub fn challenge_ext_field<F: Field>(
        &mut self,
        label: &[u8],
        degree: usize,
        modulus_type: crate::ring::crt::ModulusType,
    ) -> ExtFieldElement<F> {
        // Create challenge hasher from current state
        let mut challenge_hasher = self.hasher.clone();
        challenge_hasher.update(b"challenge");
        challenge_hasher.update(label);
        
        // Generate e field elements from hash
        let mut coeffs = Vec::with_capacity(degree);
        let hash_output = challenge_hasher.finalize();
        
        // Use hash output to generate coefficients
        // Each coefficient uses 8 bytes from hash (via XOF mode)
        let mut xof = blake3::Hasher::new_derive_key(label);
        xof.update(hash_output.as_bytes());
        
        let mut reader = xof.finalize_xof();
        let mut buffer = [0u8; 8];
        
        for _ in 0..degree {
            reader.fill(&mut buffer);
            let value = u64::from_le_bytes(buffer);
            
            // Reduce modulo field characteristic
            let field_elem = F::from_u64(value);
            coeffs.push(field_elem);
        }
        
        // Update transcript with generated challenge
        let challenge = ExtFieldElement {
            coeffs,
            degree,
            modulus_type,
        };
        
        self.append_ext_field_element(b"challenge-generated", &challenge);
        
        // Check non-zero (negligible probability of failure)
        if !challenge.is_nonzero() {
            // Retry with modified label (should never happen in practice)
            return self.challenge_ext_field(b"challenge-retry", degree, challenge.modulus_type);
        }
        
        challenge
    }
    
    /// Generate challenge in R_q (ring element)
    ///
    /// Used for:
    /// - Folding challenges γ ∈ R_q
    /// - Splitting challenges α ∈ R_q
    ///
    /// Algorithm:
    /// 1. Hash transcript state with label
    /// 2. Expand hash output to φ field elements (ring degree)
    /// 3. Return ring element
    pub fn challenge_ring<F: Field>(
        &mut self,
        label: &[u8],
        ring: &CyclotomicRing<F>,
    ) -> RingElement<F> {
        // Create challenge hasher from current state
        let mut challenge_hasher = self.hasher.clone();
        challenge_hasher.update(b"challenge-ring");
        challenge_hasher.update(label);
        
        // Generate φ field elements from hash
        let mut coeffs = Vec::with_capacity(ring.degree);
        let hash_output = challenge_hasher.finalize();
        
        // Use XOF mode to generate sufficient randomness
        let mut xof = blake3::Hasher::new_derive_key(label);
        xof.update(hash_output.as_bytes());
        
        let mut reader = xof.finalize_xof();
        let mut buffer = [0u8; 8];
        
        for _ in 0..ring.degree {
            reader.fill(&mut buffer);
            let value = u64::from_le_bytes(buffer);
            let field_elem = F::from_u64(value);
            coeffs.push(field_elem);
        }
        
        let challenge = RingElement::from_coeffs(coeffs);
        
        // Update transcript with generated challenge
        self.append_ring_element(b"challenge-ring-generated", &challenge);
        
        challenge
    }
    
    /// Generate vector of challenges in F_{q^e}^×
    ///
    /// Used for:
    /// - Batching vectors u ∈ F_{q^e}^{rφ/e}
    /// - Multiple sumcheck challenges
    ///
    /// Each challenge is generated independently from the transcript state
    pub fn challenge_ext_field_vector<F: Field>(
        &mut self,
        label: &[u8],
        count: usize,
        degree: usize,
        modulus_type: crate::ring::crt::ModulusType,
    ) -> Vec<ExtFieldElement<F>> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            let challenge_label = format!("{}-{}", String::from_utf8_lossy(label), i);
            let challenge = self.challenge_ext_field(
                challenge_label.as_bytes(),
                degree,
                modulus_type.clone(),
            );
            challenges.push(challenge);
        }
        
        challenges
    }
    
    /// Generate vector of ring challenges
    ///
    /// Used for:
    /// - Multiple folding/splitting operations
    /// - Batching in ring domain
    pub fn challenge_ring_vector<F: Field>(
        &mut self,
        label: &[u8],
        count: usize,
        ring: &CyclotomicRing<F>,
    ) -> Vec<RingElement<F>> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            let challenge_label = format!("{}-{}", String::from_utf8_lossy(label), i);
            let challenge = self.challenge_ring(challenge_label.as_bytes(), ring);
            challenges.push(challenge);
        }
        
        challenges
    }
    
    /// Get current transcript state as bytes
    ///
    /// Useful for debugging or external verification
    pub fn state(&self) -> Vec<u8> {
        self.hasher.finalize().as_bytes().to_vec()
    }
    
    /// Clone transcript for branching protocols
    ///
    /// Allows creating independent transcript branches for parallel protocol execution
    pub fn fork(&self, branch_label: &[u8]) -> Self {
        let mut forked = Self {
            hasher: self.hasher.clone(),
            domain_separator: self.domain_separator.clone(),
        };
        
        forked.append_message(b"fork", branch_label);
        forked
    }
}

impl Clone for Transcript {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
            domain_separator: self.domain_separator.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::ring::crt::ModulusType;
    
    fn create_test_ring() -> Arc<CyclotomicRing<GoldilocksField>> {
        Arc::new(CyclotomicRing::new(64))
    }
    
    #[test]
    fn test_transcript_creation() {
        let transcript = Transcript::new(b"test-protocol");
        assert_eq!(transcript.domain_separator, b"test-protocol");
    }
    
    #[test]
    fn test_append_message() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"label1", b"message1");
        transcript.append_message(b"label2", b"message2");
        
        // State should be deterministic
        let state1 = transcript.state();
        
        let mut transcript2 = Transcript::new(b"test");
        transcript2.append_message(b"label1", b"message1");
        transcript2.append_message(b"label2", b"message2");
        let state2 = transcript2.state();
        
        assert_eq!(state1, state2);
    }
    
    #[test]
    fn test_append_field_element() {
        let mut transcript = Transcript::new(b"test");
        let elem = GoldilocksField::from_u64(42);
        transcript.append_field_element(b"field-elem", &elem);
        
        // Should update transcript state
        let state = transcript.state();
        assert!(!state.is_empty());
    }
    
    #[test]
    fn test_append_ring_element() {
        let mut transcript = Transcript::new(b"test");
        let ring = create_test_ring();
        let elem = ring.from_u64(123);
        
        transcript.append_ring_element(b"ring-elem", &elem);
        
        let state = transcript.state();
        assert!(!state.is_empty());
    }
    
    #[test]
    fn test_challenge_ext_field() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"setup", b"initial-message");
        
        let challenge = transcript.challenge_ext_field::<GoldilocksField>(
            b"challenge1",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        assert_eq!(challenge.degree, 4);
        assert!(challenge.is_nonzero());
    }
    
    #[test]
    fn test_challenge_ring() {
        let mut transcript = Transcript::new(b"test");
        let ring = create_test_ring();
        
        transcript.append_message(b"setup", b"initial-message");
        let challenge = transcript.challenge_ring(b"challenge1", &ring);
        
        assert_eq!(challenge.coeffs.len(), ring.degree);
    }
    
    #[test]
    fn test_challenge_determinism() {
        let mut transcript1 = Transcript::new(b"test");
        transcript1.append_message(b"msg", b"data");
        let challenge1 = transcript1.challenge_ext_field::<GoldilocksField>(
            b"chal",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        let mut transcript2 = Transcript::new(b"test");
        transcript2.append_message(b"msg", b"data");
        let challenge2 = transcript2.challenge_ext_field::<GoldilocksField>(
            b"chal",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        // Same transcript should produce same challenge
        assert_eq!(challenge1.coeffs.len(), challenge2.coeffs.len());
        for (c1, c2) in challenge1.coeffs.iter().zip(challenge2.coeffs.iter()) {
            assert_eq!(c1.to_canonical_u64(), c2.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_challenge_different_labels() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"msg", b"data");
        
        let challenge1 = transcript.challenge_ext_field::<GoldilocksField>(
            b"chal1",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        let challenge2 = transcript.challenge_ext_field::<GoldilocksField>(
            b"chal2",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        // Different labels should produce different challenges
        let mut different = false;
        for (c1, c2) in challenge1.coeffs.iter().zip(challenge2.coeffs.iter()) {
            if c1.to_canonical_u64() != c2.to_canonical_u64() {
                different = true;
                break;
            }
        }
        assert!(different);
    }
    
    #[test]
    fn test_challenge_vector() {
        let mut transcript = Transcript::new(b"test");
        
        let challenges = transcript.challenge_ext_field_vector::<GoldilocksField>(
            b"batch",
            5,
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        assert_eq!(challenges.len(), 5);
        
        // All should be non-zero
        for challenge in &challenges {
            assert!(challenge.is_nonzero());
        }
    }
    
    #[test]
    fn test_transcript_fork() {
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"msg", b"data");
        
        let mut fork1 = transcript.fork(b"branch1");
        let mut fork2 = transcript.fork(b"branch2");
        
        fork1.append_message(b"fork-msg", b"fork1-data");
        fork2.append_message(b"fork-msg", b"fork2-data");
        
        // Forks should have different states
        let state1 = fork1.state();
        let state2 = fork2.state();
        
        assert_ne!(state1, state2);
    }
    
    #[test]
    fn test_append_matrix() {
        let mut transcript = Transcript::new(b"test");
        let ring = create_test_ring();
        
        let mut data = Vec::new();
        for i in 0..6 {
            data.push(ring.from_u64((i + 1) as u64));
        }
        let matrix = Matrix::from_data(2, 3, data);
        
        transcript.append_matrix(b"matrix", &matrix);
        
        let state = transcript.state();
        assert!(!state.is_empty());
    }
    
    #[test]
    fn test_domain_separation() {
        let mut transcript1 = Transcript::new(b"protocol-A");
        transcript1.append_message(b"msg", b"data");
        let challenge1 = transcript1.challenge_ext_field::<GoldilocksField>(
            b"chal",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        let mut transcript2 = Transcript::new(b"protocol-B");
        transcript2.append_message(b"msg", b"data");
        let challenge2 = transcript2.challenge_ext_field::<GoldilocksField>(
            b"chal",
            4,
            ModulusType::PowerOfTwoCyclotomic,
        );
        
        // Different domain separators should produce different challenges
        let mut different = false;
        for (c1, c2) in challenge1.coeffs.iter().zip(challenge2.coeffs.iter()) {
            if c1.to_canonical_u64() != c2.to_canonical_u64() {
                different = true;
                break;
            }
        }
        assert!(different);
    }
}
