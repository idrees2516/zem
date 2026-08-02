// Transcript Management for RoKoko Protocol
//
// Implements Fiat-Shamir heuristic for non-interactive proofs using Merlin transcripts
// Provides domain separation, challenge generation, and replay protection
//
// SECURITY: Uses SHA3-256 in sponge construction for quantum resistance
// All operations are domain-separated to prevent cross-protocol attacks

use crate::errors::ZKVMError;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol label for domain separation
const PROTOCOL_LABEL: &[u8] = b"RoKoko-v1.0";

/// Transcript trait for Fiat-Shamir transformation
pub trait TranscriptProtocol {
    /// Appends a message to the transcript
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) -> Result<(), ZKVMError>;
    
    /// Appends a 64-bit value
    fn append_u64(&mut self, label: &'static [u8], value: u64) -> Result<(), ZKVMError>;
    
    /// Appends a point (vector of field elements)
    fn append_point(&mut self, label: &'static [u8], point: &[u64]) -> Result<(), ZKVMError>;
    
    /// Appends polynomial coefficients
    fn append_polynomial(&mut self, coeffs: &[u64]) -> Result<(), ZKVMError>;
    
    /// Generates a challenge scalar
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<u64, ZKVMError>;
    
    /// Generates multiple challenge scalars
    fn challenge_scalars(&mut self, label: &'static [u8], n: usize) -> Result<Vec<u64>, ZKVMError>;
    
    /// Generates challenge bytes
    fn challenge_bytes(&mut self, label: &'static [u8], n: usize) -> Result<Vec<u8>, ZKVMError>;
}

/// Merlin-style transcript for RoKoko protocol
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RokokoTranscript {
    /// Internal state (SHA3-256 hasher)
    #[zeroize(skip)]
    state: Sha3_256,
    
    /// Domain separator
    domain: Vec<u8>,
    
    /// Message counter for replay protection
    message_count: u64,
}

impl RokokoTranscript {
    /// Creates new transcript with protocol label
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut state = Sha3_256::new();
        
        // Initialize with protocol label
        state.update(PROTOCOL_LABEL);
        state.update(&(protocol_name.len() as u64).to_le_bytes());
        state.update(protocol_name);
        
        Self {
            state,
            domain: protocol_name.to_vec(),
            message_count: 0,
        }
    }
    
    /// Creates transcript for RoKoko protocol
    pub fn rokoko_transcript() -> Self {
        Self::new(b"rokoko-sumcheck")
    }
    
    /// Adds domain separator
    pub fn with_domain(mut self, domain: &[u8]) -> Self {
        self.state.update(b"domain-sep");
        self.state.update(&(domain.len() as u64).to_le_bytes());
        self.state.update(domain);
        self.domain.extend_from_slice(domain);
        self
    }
    
    /// Builds message with domain separation
    fn build_message(&mut self, label: &'static [u8], data: &[u8]) {
        // Message format: [counter || label_len || label || data_len || data]
        self.state.update(&self.message_count.to_le_bytes());
        self.state.update(&(label.len() as u64).to_le_bytes());
        self.state.update(label);
        self.state.update(&(data.len() as u64).to_le_bytes());
        self.state.update(data);
        
        self.message_count += 1;
    }
    
    /// Extracts challenge bytes from transcript
    fn extract_bytes(&mut self, label: &'static [u8], n: usize) -> Vec<u8> {
        // Finalize current state
        let mut result_state = self.state.clone();
        result_state.update(b"challenge");
        result_state.update(&(label.len() as u64).to_le_bytes());
        result_state.update(label);
        result_state.update(&(n as u64).to_le_bytes());
        
        let mut output = Vec::with_capacity(n);
        let mut hash = result_state.finalize_reset();
        
        while output.len() < n {
            let to_copy = n.min(32) - output.len();
            output.extend_from_slice(&hash[..to_copy]);
            
            if output.len() < n {
                // Re-hash for more bytes (sponge construction)
                let mut hasher = Sha3_256::new();
                hasher.update(&hash);
                hash = hasher.finalize();
            }
        }
        
        // Update transcript state with challenge
        self.state.update(b"challenge-used");
        self.state.update(&output);
        self.message_count += 1;
        
        output
    }
}

impl TranscriptProtocol for RokokoTranscript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) -> Result<(), ZKVMError> {
        self.build_message(label, message);
        Ok(())
    }
    
    fn append_u64(&mut self, label: &'static [u8], value: u64) -> Result<(), ZKVMError> {
        self.build_message(label, &value.to_le_bytes());
        Ok(())
    }
    
    fn append_point(&mut self, label: &'static [u8], point: &[u64]) -> Result<(), ZKVMError> {
        let bytes: Vec<u8> = point.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect();
        self.build_message(label, &bytes);
        Ok(())
    }
    
    fn append_polynomial(&mut self, coeffs: &[u64]) -> Result<(), ZKVMError> {
        self.append_point(b"polynomial", coeffs)
    }
    
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Result<u64, ZKVMError> {
        let bytes = self.extract_bytes(label, 8);
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(array))
    }
    
    fn challenge_scalars(&mut self, label: &'static [u8], n: usize) -> Result<Vec<u64>, ZKVMError> {
        let bytes = self.extract_bytes(label, n * 8);
        let mut scalars = Vec::with_capacity(n);
        
        for chunk in bytes.chunks_exact(8) {
            let mut array = [0u8; 8];
            array.copy_from_slice(chunk);
            scalars.push(u64::from_le_bytes(array));
        }
        
        Ok(scalars)
    }
    
    fn challenge_bytes(&mut self, label: &'static [u8], n: usize) -> Result<Vec<u8>, ZKVMError> {
        Ok(self.extract_bytes(label, n))
    }
}

impl Default for RokokoTranscript {
    fn default() -> Self {
        Self::rokoko_transcript()
    }
}

/// Batch transcript for multiple parallel proofs
pub struct BatchTranscript {
    /// Individual transcripts
    transcripts: Vec<RokokoTranscript>,
    
    /// Batching coefficient transcript
    batch_transcript: RokokoTranscript,
}

impl BatchTranscript {
    pub fn new(num_proofs: usize) -> Self {
        let transcripts = (0..num_proofs)
            .map(|i| RokokoTranscript::rokoko_transcript()
                .with_domain(&format!("proof-{}", i).as_bytes()))
            .collect();
        
        let batch_transcript = RokokoTranscript::new(b"batch-coefficients");
        
        Self {
            transcripts,
            batch_transcript,
        }
    }
    
    pub fn get_transcript(&mut self, index: usize) -> Result<&mut RokokoTranscript, ZKVMError> {
        self.transcripts.get_mut(index)
            .ok_or_else(|| ZKVMError::InvalidParameter("Invalid transcript index".to_string()))
    }
    
    pub fn generate_batching_coefficients(&mut self, n: usize) -> Result<Vec<u64>, ZKVMError> {
        // Combine all transcript states
        for transcript in &self.transcripts {
            let state_bytes = bincode::serialize(&transcript.message_count)
                .map_err(|e| ZKVMError::SerializationError(e.to_string()))?;
            self.batch_transcript.append_message(b"transcript-state", &state_bytes)?;
        }
        
        // Generate coefficients
        self.batch_transcript.challenge_scalars(b"batch-coeffs", n)
    }
}

/// Structured transcript for complex protocols
pub struct StructuredTranscript<P> {
    /// Base transcript
    transcript: RokokoTranscript,
    
    /// Phase tracking
    current_phase: Vec<String>,
    
    /// Protocol phantom
    _phantom: PhantomData<P>,
}

impl<P> StructuredTranscript<P> {
    pub fn new(protocol_name: &str) -> Self {
        Self {
            transcript: RokokoTranscript::new(protocol_name.as_bytes()),
            current_phase: Vec::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Enters a new protocol phase
    pub fn enter_phase(&mut self, phase: &str) -> Result<(), ZKVMError> {
        self.current_phase.push(phase.to_string());
        let phase_path = self.current_phase.join("/");
        self.transcript.append_message(b"enter-phase", phase_path.as_bytes())
    }
    
    /// Exits current protocol phase
    pub fn exit_phase(&mut self) -> Result<(), ZKVMError> {
        if let Some(phase) = self.current_phase.pop() {
            self.transcript.append_message(b"exit-phase", phase.as_bytes())
        } else {
            Err(ZKVMError::InvalidParameter("No phase to exit".to_string()))
        }
    }
    
    /// Appends message with phase context
    pub fn append(&mut self, label: &str, data: &[u8]) -> Result<(), ZKVMError> {
        let full_label = format!("{}/{}", self.current_phase.join("/"), label);
        self.transcript.append_message(full_label.as_bytes(), data)
    }
    
    /// Generates challenge with phase context
    pub fn challenge(&mut self, label: &str) -> Result<u64, ZKVMError> {
        let full_label = format!("{}/{}", self.current_phase.join("/"), label);
        self.transcript.challenge_scalar(full_label.as_bytes())
    }
    
    pub fn inner(&mut self) -> &mut RokokoTranscript {
        &mut self.transcript
    }
}

/// Transcript builder for complex protocols
pub struct TranscriptBuilder {
    protocol_name: String,
    domains: Vec<Vec<u8>>,
    initial_messages: Vec<(Vec<u8>, Vec<u8>)>,
}

impl TranscriptBuilder {
    pub fn new(protocol_name: &str) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            domains: Vec::new(),
            initial_messages: Vec::new(),
        }
    }
    
    pub fn with_domain(mut self, domain: &[u8]) -> Self {
        self.domains.push(domain.to_vec());
        self
    }
    
    pub fn with_message(mut self, label: &[u8], message: &[u8]) -> Self {
        self.initial_messages.push((label.to_vec(), message.to_vec()));
        self
    }
    
    pub fn build(self) -> Result<RokokoTranscript, ZKVMError> {
        let mut transcript = RokokoTranscript::new(self.protocol_name.as_bytes());
        
        for domain in self.domains {
            transcript = transcript.with_domain(&domain);
        }
        
        for (label, message) in self.initial_messages {
            transcript.append_message(&label, &message)?;
        }
        
        Ok(transcript)
    }
}

/// Transcript cloning for parallel verification
pub trait TranscriptClone {
    fn fork(&self, label: &[u8]) -> Self;
}

impl TranscriptClone for RokokoTranscript {
    fn fork(&self, label: &[u8]) -> Self {
        let mut forked = self.clone();
        forked.state.update(b"fork");
        forked.state.update(&(label.len() as u64).to_le_bytes());
        forked.state.update(label);
        forked.message_count += 1;
        forked
    }
}

/// Verifies transcript consistency between prover and verifier
pub fn verify_transcript_consistency(
    prover_transcript: &RokokoTranscript,
    verifier_transcript: &RokokoTranscript,
) -> bool {
    prover_transcript.message_count == verifier_transcript.message_count
        && prover_transcript.domain == verifier_transcript.domain
}
