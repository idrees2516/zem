// Fiat-Shamir Transform Implementation
// FSH[Π_cm, Π_rok]: Non-interactive transformation using hash oracle

use crate::field::Field;
use crate::folding::transcript::Transcript;
use super::hash_oracle::{HashOracle, HashFunction, StandardHashOracle, RandomOracleModel};
use super::commit_open::{CommitAndOpen, CommitAndOpenProof};
use std::marker::PhantomData;

/// Fiat-Shamir transform of a reduction of knowledge protocol
/// 
/// Protocol FSH[Π_cm, Π_rok]:
/// 1. Initialize transcript with instance x
/// 2. Derive r_1 := H(x)
/// 3. For each round i:
///    a. Prover computes message m_i
///    b. Prover commits: c_{fs,i} := Π_cm.Commit(pp_cm, m_i)
///    c. Append (r_i, c_{fs,i}) to transcript
///    d. Derive r_{i+1} := H(transcript)
/// 4. Prover sends all openings (m_i)_{i=1}^{rnd}
/// 5. Verifier recomputes challenges and verifies
pub struct FiatShamirTransform<F: Field> {
    /// Hash function for challenge derivation
    hash_function: HashFunction,
    
    /// Number of protocol rounds
    num_rounds: usize,
    
    /// Commit-and-open transformation
    commit_open: Option<CommitAndOpen<F>>,
    
    _phantom: PhantomData<F>,
}

/// Non-interactive proof produced by Fiat-Shamir transform
#[derive(Clone, Debug)]
pub struct NonInteractiveProof<F: Field> {
    /// Instance being proved
    pub instance: Vec<u8>,
    
    /// Commit-and-open proof
    pub commit_open_proof: CommitAndOpenProof<F>,
    
    /// Derived challenges
    pub challenges: Vec<Vec<u8>>,
    
    /// Final protocol output
    pub output: Vec<u8>,
}

impl<F: Field> FiatShamirTransform<F> {
    /// Create new Fiat-Shamir transform
    pub fn new(
        hash_function: HashFunction,
        num_rounds: usize,
    ) -> Self {
        Self {
            hash_function,
            num_rounds,
            commit_open: None,
            _phantom: PhantomData,
        }
    }
    
    /// Create with commit-and-open transformation
    pub fn with_commit_open(
        hash_function: HashFunction,
        num_rounds: usize,
        commit_open: CommitAndOpen<F>,
    ) -> Self {
        Self {
            hash_function,
            num_rounds,
            commit_open: Some(commit_open),
            _phantom: PhantomData,
        }
    }
    
    /// Prover: apply Fiat-Shamir transform to interactive protocol
    pub fn prove<P, I, W, O>(
        &self,
        instance: &I,
        witness: &W,
        prover: P,
    ) -> Result<NonInteractiveProof<F>, String>
    where
        P: Fn(&I, &W, &mut Transcript) -> Result<(O, Vec<Vec<u8>>), String>,
        I: ToBytes,
        O: ToBytes,
    {
        // Initialize transcript with instance
        let mut transcript = Transcript::new(b"fiat_shamir");
        let instance_bytes = instance.to_bytes();
        transcript.append_message(b"instance", &instance_bytes);
        
        // Derive initial challenge r_1 := H(x)
        let r_1 = self.derive_challenge(&mut transcript, 0)?;
        transcript.append_message(b"challenge_0", &r_1);
        
        // Execute protocol with challenge derivation
        let (output, messages) = prover(instance, witness, &mut transcript)?;
        
        if messages.len() != self.num_rounds {
            return Err(format!(
                "Expected {} messages, got {}",
                self.num_rounds,
                messages.len()
            ));
        }
        
        // Derive challenges for each round
        let mut challenges = vec![r_1];
        for i in 0..self.num_rounds {
            let challenge = self.derive_challenge(&mut transcript, i + 1)?;
            challenges.push(challenge);
        }
        
        // Apply commit-and-open if configured
        let commit_open_proof = if let Some(ref co) = self.commit_open {
            co.commit_messages(&messages, &mut transcript)?
        } else {
            // Without commit-and-open, just include messages directly
            CommitAndOpenProof {
                commitments: Vec::new(),
                messages,
                opening_proofs: Vec::new(),
            }
        };
        
        Ok(NonInteractiveProof {
            instance: instance_bytes,
            commit_open_proof,
            challenges,
            output: output.to_bytes(),
        })
    }
    
    /// Verifier: verify non-interactive proof
    pub fn verify<V, I, O>(
        &self,
        proof: &NonInteractiveProof<F>,
        verifier: V,
    ) -> Result<bool, String>
    where
        V: Fn(&I, &[Vec<u8>], &O, &mut Transcript) -> Result<bool, String>,
        I: FromBytes,
        O: FromBytes,
    {
        // Reconstruct instance
        let instance = I::from_bytes(&proof.instance)?;
        
        // Initialize transcript with instance
        let mut transcript = Transcript::new(b"fiat_shamir");
        transcript.append_message(b"instance", &proof.instance);
        
        // Verify commit-and-open if used
        let messages = if let Some(ref co) = self.commit_open {
            co.verify_openings(&proof.commit_open_proof, &mut transcript)?;
            co.extract_messages(&proof.commit_open_proof)?
        } else {
            proof.commit_open_proof.messages.clone()
        };
        
        // Recompute and verify challenges
        let mut expected_challenges = Vec::with_capacity(self.num_rounds + 1);
        
        // Initial challenge
        let r_1 = self.derive_challenge(&mut transcript, 0)?;
        expected_challenges.push(r_1);
        transcript.append_message(b"challenge_0", &expected_challenges[0]);
        
        // Subsequent challenges
        for i in 0..self.num_rounds {
            // Add message commitment to transcript
            if i < messages.len() {
                transcript.append_message(b"message", &messages[i]);
            }
            
            let challenge = self.derive_challenge(&mut transcript, i + 1)?;
            expected_challenges.push(challenge);
        }
        
        // Verify challenges match
        if expected_challenges.len() != proof.challenges.len() {
            return Err("Challenge count mismatch".to_string());
        }
        
        for (i, (expected, actual)) in expected_challenges.iter()
            .zip(&proof.challenges)
            .enumerate()
        {
            if expected != actual {
                return Err(format!("Challenge {} mismatch", i));
            }
        }
        
        // Reconstruct output
        let output = O::from_bytes(&proof.output)?;
        
        // Run verifier
        verifier(&instance, &messages, &output, &mut transcript)
    }
    
    /// Derive challenge from transcript using hash oracle
    fn derive_challenge(
        &self,
        transcript: &mut Transcript,
        round: usize,
    ) -> Result<Vec<u8>, String> {
        // Get transcript state
        let transcript_bytes = transcript.challenge_bytes(
            b"fiat_shamir_challenge",
            32,
        );
        
        // Create hash oracle
        let mut oracle = StandardHashOracle::new(self.hash_function);
        
        // Hash transcript state with round number
        oracle.update(&transcript_bytes);
        oracle.update(&round.to_le_bytes());
        
        // Derive challenge (32 bytes for 128-bit security)
        Ok(oracle.finalize(32))
    }
    
    /// Compute knowledge error accounting for oracle queries
    /// 
    /// ϵ_knowledge = ϵ_base + Q·ϵ_soundness
    pub fn knowledge_error(
        &self,
        base_error: f64,
        soundness_error: f64,
        num_queries: usize,
    ) -> f64 {
        base_error + (num_queries as f64) * soundness_error
    }
}

/// Trait for types that can be serialized to bytes
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Trait for types that can be deserialized from bytes
pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>;
}

// Implement for common types
impl ToBytes for Vec<u8> {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}

impl FromBytes for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(bytes.to_vec())
    }
}

impl ToBytes for () {
    fn to_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl FromBytes for () {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, String> {
        Ok(())
    }
}

/// Security analysis for Fiat-Shamir transform
pub struct FiatShamirSecurity;

impl FiatShamirSecurity {
    /// Compute soundness error in random oracle model
    /// 
    /// For a protocol with k rounds and challenge space size 2^λ:
    /// ϵ_soundness ≈ k / 2^λ
    pub fn soundness_error(num_rounds: usize, challenge_bits: usize) -> f64 {
        let challenge_space_size = 2.0_f64.powi(challenge_bits as i32);
        (num_rounds as f64) / challenge_space_size
    }
    
    /// Compute knowledge error with Q oracle queries
    pub fn knowledge_error(
        base_error: f64,
        soundness_error: f64,
        num_queries: usize,
    ) -> f64 {
        base_error + (num_queries as f64) * soundness_error
    }
    
    /// Verify security level meets target
    pub fn verify_security_level(
        knowledge_error: f64,
        target_bits: usize,
    ) -> bool {
        let target_error = 2.0_f64.powi(-(target_bits as i32));
        knowledge_error <= target_error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fiat_shamir_basic() {
        use crate::field::m61::M61;
        
        let transform = FiatShamirTransform::<M61>::new(
            HashFunction::Blake3,
            2,
        );
        
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"msg", b"data");
        
        let challenge = transform.derive_challenge(&mut transcript, 0).unwrap();
        assert_eq!(challenge.len(), 32);
    }
    
    #[test]
    fn test_challenge_derivation() {
        let transform = FiatShamirTransform::<crate::field::m61::M61>::new(
            HashFunction::Blake3,
            3,
        );
        
        let mut transcript = Transcript::new(b"test");
        transcript.append_message(b"instance", b"test instance");
        
        let challenge1 = transform.derive_challenge(&mut transcript, 0).unwrap();
        let challenge2 = transform.derive_challenge(&mut transcript, 1).unwrap();
        
        assert_eq!(challenge1.len(), 32);
        assert_eq!(challenge2.len(), 32);
        assert_ne!(challenge1, challenge2);
    }
    
    #[test]
    fn test_soundness_error() {
        // For 10 rounds with 128-bit challenges
        let error = FiatShamirSecurity::soundness_error(10, 128);
        assert!(error < 2.0_f64.powi(-120));
    }
    
    #[test]
    fn test_knowledge_error() {
        let base = 2.0_f64.powi(-128);
        let soundness = 2.0_f64.powi(-120);
        let error = FiatShamirSecurity::knowledge_error(base, soundness, 1000);
        
        // Should still be very small
        assert!(error < 2.0_f64.powi(-100));
    }
    
    #[test]
    fn test_security_level() {
        let error = 2.0_f64.powi(-130);
        assert!(FiatShamirSecurity::verify_security_level(error, 128));
        assert!(!FiatShamirSecurity::verify_security_level(error, 140));
    }
}
