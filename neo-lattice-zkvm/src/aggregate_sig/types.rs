// Type definitions for aggregate signatures

use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

/// Message type for signatures
pub type Message = Vec<u8>;

/// Verification key for a signature scheme
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey<G> {
    /// Group element representing the public key
    pub key: G,
    /// Additional metadata
    pub metadata: Vec<u8>,
}

impl<G> VerificationKey<G> {
    pub fn new(key: G) -> Self {
        Self {
            key,
            metadata: Vec::new(),
        }
    }
    
    pub fn with_metadata(key: G, metadata: Vec<u8>) -> Self {
        Self { key, metadata }
    }
}

/// Signature in a group
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature<G> {
    /// Group elements in the signature
    pub elements: Vec<G>,
    /// Additional signature data
    pub data: Vec<u8>,
}

impl<G> Signature<G> {
    pub fn new(elements: Vec<G>) -> Self {
        Self {
            elements,
            data: Vec::new(),
        }
    }
    
    pub fn with_data(elements: Vec<G>, data: Vec<u8>) -> Self {
        Self { elements, data }
    }
}

/// Public parameters for signature scheme
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureParameters<G> {
    /// Generator elements
    pub generators: Vec<G>,
    /// System parameters
    pub params: Vec<u8>,
}

impl<G> SignatureParameters<G> {
    pub fn new(generators: Vec<G>, params: Vec<u8>) -> Self {
        Self { generators, params }
    }
}

/// Statement for aggregate signature verification
/// Contains the public keys and messages being verified
#[derive(Clone, Debug)]
pub struct AggregateStatement<G> {
    /// List of (verification_key, message) pairs
    pub public_keys_messages: Vec<(VerificationKey<G>, Message)>,
}

impl<G> AggregateStatement<G> {
    pub fn new(public_keys_messages: Vec<(VerificationKey<G>, Message)>) -> Self {
        Self { public_keys_messages }
    }
    
    pub fn len(&self) -> usize {
        self.public_keys_messages.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.public_keys_messages.is_empty()
    }
}

/// Witness for aggregate signature verification
/// Contains the individual signatures and oracle responses
#[derive(Clone, Debug)]
pub struct AggregateWitness<G> {
    /// Individual signatures for each (vk, message) pair
    pub signatures: Vec<Signature<G>>,
    /// Oracle responses for forced queries (AGM modification)
    pub oracle_responses: Vec<Vec<u8>>,
}

impl<G> AggregateWitness<G> {
    pub fn new(signatures: Vec<Signature<G>>, oracle_responses: Vec<Vec<u8>>) -> Self {
        Self {
            signatures,
            oracle_responses,
        }
    }
}

/// Aggregate signature proof (wraps underlying O-SNARK proof)
#[derive(Clone, Debug)]
pub struct AggregateSignatureProof<P> {
    /// The SNARK proof
    pub proof: P,
    /// Metadata about the aggregation
    pub metadata: AggregateMetadata,
}

/// Metadata about an aggregate signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateMetadata {
    /// Number of signatures aggregated
    pub num_signatures: usize,
    /// Timestamp of aggregation
    pub timestamp: u64,
    /// Additional metadata
    pub extra: Vec<u8>,
}

impl AggregateMetadata {
    pub fn new(num_signatures: usize) -> Self {
        Self {
            num_signatures,
            timestamp: 0,
            extra: Vec::new(),
        }
    }
}

impl<P> AggregateSignatureProof<P> {
    pub fn new(proof: P, num_signatures: usize) -> Self {
        Self {
            proof,
            metadata: AggregateMetadata::new(num_signatures),
        }
    }
}
