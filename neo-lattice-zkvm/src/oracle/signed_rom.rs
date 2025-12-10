// Signed Random Oracle Model
//
// Oracle model with signing oracle access for aggregate signatures.
//
// Mathematical Foundation:
// - Combines random oracle with signing oracle O_sk
// - Signing oracle: σ ← sign^θ(sk, m)
// - Maintains transcript of signing queries Q_σ

use std::collections::HashMap;
use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

use super::rom::RandomOracle;
use super::transcript::{Oracle, OracleTranscript};
use super::errors::{OracleError, OracleResult};

/// Signing oracle that signs messages
///
/// Maintains transcript of all signing queries
pub struct SigningOracle<M, Sig> {
    /// Transcript of signing queries: (message, signature) pairs
    signing_transcript: Vec<(M, Sig)>,
    
    /// Secret key (opaque bytes)
    secret_key: Vec<u8>,
    
    /// Random oracle for signing
    ro: RandomOracle,
}

impl<M, Sig> SigningOracle<M, Sig>
where
    M: Clone + Serialize,
    Sig: Clone + for<'de> Deserialize<'de>,
{
    /// Create a new signing oracle with secret key
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            signing_transcript: Vec::new(),
            secret_key,
            ro: RandomOracle::new(),
        }
    }
    
    /// Sign a message
    ///
    /// # Arguments
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// Signature σ ← sign^θ(sk, m)
    pub fn sign(&mut self, message: M) -> OracleResult<Sig> {
        // Serialize message
        let message_bytes = bincode::serialize(&message)
            .map_err(|e| OracleError::SigningError(e.to_string()))?;
        
        // Compute signature using RO(sk || message)
        let mut query = Vec::with_capacity(self.secret_key.len() + message_bytes.len() + 8);
        query.extend_from_slice(b"SIGN");
        query.extend_from_slice(&self.secret_key);
        query.extend_from_slice(&message_bytes);
        
        let signature_bytes = self.ro.query(query)?;
        
        // Deserialize signature
        let signature: Sig = bincode::deserialize(&signature_bytes)
            .map_err(|e| OracleError::SigningError(e.to_string()))?;
        
        // Record in transcript
        self.signing_transcript.push((message, signature.clone()));
        
        Ok(signature)
    }
    
    /// Get all signing queries
    pub fn get_signing_queries(&self) -> &[(M, Sig)] {
        &self.signing_transcript
    }
    
    /// Get number of signing queries
    pub fn num_queries(&self) -> usize {
        self.signing_transcript.len()
    }
    
    /// Clear signing transcript
    pub fn clear(&mut self) {
        self.signing_transcript.clear();
    }
}

/// Signed Random Oracle Model
///
/// Combines random oracle with signing oracle
pub struct SignedOracle<M, Sig> {
    /// Random oracle component
    ro: RandomOracle,
    
    /// Signing oracle component
    signing_oracle: SigningOracle<M, Sig>,
}

impl<M, Sig> SignedOracle<M, Sig>
where
    M: Clone + Serialize,
    Sig: Clone + for<'de> Deserialize<'de>,
{
    /// Create a new signed oracle
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            ro: RandomOracle::new(),
            signing_oracle: SigningOracle::new(secret_key),
        }
    }
    
    /// Query random oracle
    pub fn query_ro(&mut self, input: Vec<u8>) -> OracleResult<Vec<u8>> {
        self.ro.query(input)
    }
    
    /// Query signing oracle
    pub fn query_sign(&mut self, message: M) -> OracleResult<Sig> {
        self.signing_oracle.sign(message)
    }
    
    /// Get random oracle transcript
    pub fn ro_transcript(&self) -> &OracleTranscript<Vec<u8>, Vec<u8>> {
        self.ro.transcript()
    }
    
    /// Get signing queries
    pub fn signing_queries(&self) -> &[(M, Sig)] {
        self.signing_oracle.get_signing_queries()
    }
    
    /// Get number of signing queries
    pub fn num_signing_queries(&self) -> usize {
        self.signing_oracle.num_queries()
    }
}

/// Helper for BLS signature scheme integration
pub mod bls {
    use super::*;
    
    /// BLS signature (group element)
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BLSSignature {
        pub signature: Vec<u8>,
    }
    
    /// BLS signing oracle
    pub type BLSSigningOracle = SigningOracle<Vec<u8>, BLSSignature>;
    
    /// Create BLS signing oracle
    pub fn create_bls_oracle(secret_key: Vec<u8>) -> BLSSigningOracle {
        SigningOracle::new(secret_key)
    }
}

/// Helper for Schnorr signature scheme integration
pub mod schnorr {
    use super::*;
    
    /// Schnorr signature (R, z)
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SchnorrSignature {
        pub r: Vec<u8>,  // R = g^r
        pub z: Vec<u8>,  // z = r + e·sk
    }
    
    /// Schnorr signing oracle
    pub type SchnorrSigningOracle = SigningOracle<Vec<u8>, SchnorrSignature>;
    
    /// Create Schnorr signing oracle
    pub fn create_schnorr_oracle(secret_key: Vec<u8>) -> SchnorrSigningOracle {
        SigningOracle::new(secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TestSignature {
        data: Vec<u8>,
    }
    
    #[test]
    fn test_signing_oracle_creation() {
        let sk = vec![1u8, 2, 3];
        let oracle = SigningOracle::<Vec<u8>, TestSignature>::new(sk);
        assert_eq!(oracle.num_queries(), 0);
    }
    
    #[test]
    fn test_signing_oracle_sign() {
        let sk = vec![1u8, 2, 3];
        let mut oracle = SigningOracle::<Vec<u8>, TestSignature>::new(sk);
        
        let message = vec![4u8, 5, 6];
        let sig1 = oracle.sign(message.clone()).unwrap();
        
        assert_eq!(oracle.num_queries(), 1);
        
        // Same message should give same signature (deterministic)
        let sig2 = oracle.sign(message.clone()).unwrap();
        assert_eq!(sig1.data, sig2.data);
        assert_eq!(oracle.num_queries(), 2); // Both queries recorded
    }
    
    #[test]
    fn test_signed_oracle_creation() {
        let sk = vec![1u8, 2, 3];
        let oracle = SignedOracle::<Vec<u8>, TestSignature>::new(sk);
        assert_eq!(oracle.num_signing_queries(), 0);
    }
    
    #[test]
    fn test_signed_oracle_query_ro() {
        let sk = vec![1u8, 2, 3];
        let mut oracle = SignedOracle::<Vec<u8>, TestSignature>::new(sk);
        
        let input = vec![4u8, 5, 6];
        let response1 = oracle.query_ro(input.clone()).unwrap();
        let response2 = oracle.query_ro(input).unwrap();
        
        assert_eq!(response1, response2);
    }
    
    #[test]
    fn test_signed_oracle_query_sign() {
        let sk = vec![1u8, 2, 3];
        let mut oracle = SignedOracle::<Vec<u8>, TestSignature>::new(sk);
        
        let message = vec![4u8, 5, 6];
        let sig = oracle.query_sign(message).unwrap();
        
        assert_eq!(oracle.num_signing_queries(), 1);
        assert!(!sig.data.is_empty());
    }
    
    #[test]
    fn test_bls_oracle() {
        let sk = vec![1u8, 2, 3];
        let mut oracle = bls::create_bls_oracle(sk);
        
        let message = vec![4u8, 5, 6];
        let sig = oracle.sign(message).unwrap();
        
        assert!(!sig.signature.is_empty());
    }
    
    #[test]
    fn test_schnorr_oracle() {
        let sk = vec![1u8, 2, 3];
        let mut oracle = schnorr::create_schnorr_oracle(sk);
        
        let message = vec![4u8, 5, 6];
        let sig = oracle.sign(message).unwrap();
        
        assert!(!sig.r.is_empty());
        assert!(!sig.z.is_empty());
    }
}
