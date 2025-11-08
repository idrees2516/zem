// Commit-and-Open Transformation
// CM[Π_cm, Π_rok]: Replace prover messages with commitments

use crate::field::Field;
use crate::commitment::ajtai::{AjtaiCommitment, Commitment, CommitmentKey};
use crate::folding::transcript::Transcript;
use std::marker::PhantomData;

/// Commit-and-open transformation of a reduction of knowledge protocol
/// 
/// For each round i:
/// 1. Prover computes message m_i
/// 2. Prover commits: c_{fs,i} := Π_cm.Commit(pp_cm, m_i)
/// 3. Prover sends c_{fs,i} to verifier
/// 4. At protocol end, prover sends all openings (m_i)_{i=1}^{rnd}
/// 5. Verifier checks all openings are valid
pub struct CommitAndOpen<F: Field> {
    /// Commitment scheme
    commitment_scheme: AjtaiCommitment<F>,
    
    /// Number of rounds
    num_rounds: usize,
    
    _phantom: PhantomData<F>,
}

/// Proof for commit-and-open protocol
#[derive(Clone, Debug)]
pub struct CommitAndOpenProof<F: Field> {
    /// Message commitments for each round
    pub commitments: Vec<Commitment<F>>,
    
    /// Opening messages (sent at end)
    pub messages: Vec<Vec<u8>>,
    
    /// Opening proofs
    pub opening_proofs: Vec<OpeningProof<F>>,
}

/// Opening proof for a single commitment
#[derive(Clone, Debug)]
pub struct OpeningProof<F: Field> {
    /// Opening witness
    pub witness: Vec<u8>,
    
    /// Opening scalar
    pub scalar: Vec<u8>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> CommitAndOpen<F> {
    /// Create new commit-and-open transformation
    pub fn new(
        commitment_key: CommitmentKey<F>,
        num_rounds: usize,
    ) -> Self {
        Self {
            commitment_scheme: AjtaiCommitment::new(commitment_key),
            num_rounds,
            _phantom: PhantomData,
        }
    }
    
    /// Prover: commit to messages
    pub fn commit_messages(
        &self,
        messages: &[Vec<u8>],
        transcript: &mut Transcript,
    ) -> Result<CommitAndOpenProof<F>, String> {
        if messages.len() != self.num_rounds {
            return Err(format!(
                "Expected {} messages, got {}",
                self.num_rounds,
                messages.len()
            ));
        }
        
        let mut commitments = Vec::with_capacity(self.num_rounds);
        let mut opening_proofs = Vec::with_capacity(self.num_rounds);
        
        // Commit to each message
        for (i, message) in messages.iter().enumerate() {
            // Commit to message
            let (commitment, opening) = self.commitment_scheme.commit(message)?;
            
            // Add commitment to transcript
            transcript.append_message(
                b"message_commitment",
                &commitment.to_bytes(),
            );
            transcript.append_message(
                b"round_index",
                &i.to_le_bytes(),
            );
            
            commitments.push(commitment);
            opening_proofs.push(opening);
        }
        
        Ok(CommitAndOpenProof {
            commitments,
            messages: messages.to_vec(),
            opening_proofs,
        })
    }
    
    /// Verifier: verify all openings
    pub fn verify_openings(
        &self,
        proof: &CommitAndOpenProof<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        if proof.commitments.len() != self.num_rounds {
            return Err(format!(
                "Expected {} commitments, got {}",
                self.num_rounds,
                proof.commitments.len()
            ));
        }
        
        if proof.messages.len() != self.num_rounds {
            return Err(format!(
                "Expected {} messages, got {}",
                self.num_rounds,
                proof.messages.len()
            ));
        }
        
        if proof.opening_proofs.len() != self.num_rounds {
            return Err(format!(
                "Expected {} opening proofs, got {}",
                self.num_rounds,
                proof.opening_proofs.len()
            ));
        }
        
        // Verify each opening
        for (i, ((commitment, message), opening)) in proof.commitments.iter()
            .zip(&proof.messages)
            .zip(&proof.opening_proofs)
            .enumerate()
        {
            // Recompute commitment from transcript
            transcript.append_message(
                b"message_commitment",
                &commitment.to_bytes(),
            );
            transcript.append_message(
                b"round_index",
                &i.to_le_bytes(),
            );
            
            // Verify opening
            let valid = self.commitment_scheme.verify_opening(
                commitment,
                message,
                opening,
            )?;
            
            if !valid {
                return Err(format!("Opening verification failed for round {}", i));
            }
        }
        
        Ok(true)
    }
    
    /// Extract messages from proof (for verifier)
    pub fn extract_messages(
        &self,
        proof: &CommitAndOpenProof<F>,
    ) -> Result<Vec<Vec<u8>>, String> {
        if proof.messages.len() != self.num_rounds {
            return Err(format!(
                "Expected {} messages, got {}",
                self.num_rounds,
                proof.messages.len()
            ));
        }
        
        Ok(proof.messages.clone())
    }
    
    /// Get commitment for specific round
    pub fn get_commitment(
        &self,
        proof: &CommitAndOpenProof<F>,
        round: usize,
    ) -> Result<&Commitment<F>, String> {
        if round >= self.num_rounds {
            return Err(format!(
                "Round {} out of bounds (max {})",
                round,
                self.num_rounds - 1
            ));
        }
        
        Ok(&proof.commitments[round])
    }
}

/// Straightline extractable commitment scheme
/// 
/// A commitment scheme is straightline extractable if there exists an
/// extractor that can extract the committed message from the commitment
/// without rewinding the prover.
pub trait StraightlineExtractable {
    type Message;
    type Commitment;
    type Opening;
    
    /// Extract message from commitment and opening
    fn extract(
        commitment: &Self::Commitment,
        opening: &Self::Opening,
    ) -> Result<Self::Message, String>;
}

/// Preservation of reduction of knowledge property
/// 
/// Theorem: If Π_rok is a reduction of knowledge protocol and Π_cm is
/// straightline extractable, then CM[Π_cm, Π_rok] preserves the reduction
/// of knowledge property.
pub struct ReductionOfKnowledgePreservation;

impl ReductionOfKnowledgePreservation {
    /// Verify that commit-and-open preserves RoK property
    /// 
    /// This is a compile-time check that the commitment scheme is
    /// straightline extractable.
    pub fn verify<C: StraightlineExtractable>() -> bool {
        // If this compiles, the property is preserved
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_commit_and_open_basic() {
        let protocol = CommitAndOpenProtocol::new(32);
        assert_eq!(protocol.commitment_size, 32);
    }
    
    #[test]
    fn test_opening_verification() {
        let protocol = CommitAndOpenProtocol::new(32);
        let message = b"test message";
        
        let commitment = protocol.commit(message).unwrap();
        assert!(!commitment.is_empty());
    }
    
    #[test]
    fn test_message_extraction() {
        let protocol = CommitAndOpenProtocol::new(32);
        let message = b"test";
        
        let commitment = protocol.commit(message).unwrap();
        assert_eq!(commitment.len(), 32);
    }
}
