// Core types for Relativized SNARK module

use serde::{Serialize, Deserialize};

/// Public parameters for SNARK
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    /// Security parameter
    pub lambda: usize,
    
    /// Parameters data
    pub data: Vec<u8>,
}

impl PublicParameters {
    /// Create new public parameters
    pub fn new(lambda: usize, data: Vec<u8>) -> Self {
        Self { lambda, data }
    }
}

/// Indexer key (prover key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerKey {
    /// Key data
    pub data: Vec<u8>,
}

impl IndexerKey {
    /// Create new indexer key
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Verifier key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierKey {
    /// Key data
    pub data: Vec<u8>,
}

impl VerifierKey {
    /// Create new verifier key
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// SNARK proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Proof data
    pub data: Vec<u8>,
    
    /// Oracle responses (for AGM modifications)
    pub oracle_responses: Option<Vec<Vec<u8>>>,
}

impl Proof {
    /// Create new proof
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            oracle_responses: None,
        }
    }
    
    /// Create proof with oracle responses
    pub fn with_oracle_responses(data: Vec<u8>, oracle_responses: Vec<Vec<u8>>) -> Self {
        Self {
            data,
            oracle_responses: Some(oracle_responses),
        }
    }
}

/// Circuit representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circuit {
    /// Circuit data
    pub data: Vec<u8>,
    
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Number of variables
    pub num_variables: usize,
}

impl Circuit {
    /// Create new circuit
    pub fn new(data: Vec<u8>, num_constraints: usize, num_variables: usize) -> Self {
        Self {
            data,
            num_constraints,
            num_variables,
        }
    }
}

/// Statement (public input)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Statement {
    /// Statement data
    pub data: Vec<u8>,
}

impl Statement {
    /// Create new statement
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Witness (private input)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    /// Witness data
    pub data: Vec<u8>,
}

impl Witness {
    /// Create new witness
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Result of extraction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionResult {
    /// Extracted witness
    pub witness: Witness,
    
    /// Whether extraction succeeded
    pub success: bool,
    
    /// Additional information
    pub info: Option<String>,
}

impl ExtractionResult {
    /// Create successful extraction result
    pub fn success(witness: Witness) -> Self {
        Self {
            witness,
            success: true,
            info: None,
        }
    }
    
    /// Create failed extraction result
    pub fn failure(info: String) -> Self {
        Self {
            witness: Witness::new(Vec::new()),
            success: false,
            info: Some(info),
        }
    }
}
