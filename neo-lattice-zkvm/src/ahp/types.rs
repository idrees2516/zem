// AHP Type Definitions
//
// Defines the core types for Algebraic Holographic Proofs

use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

/// AHP Round
///
/// Represents a single round of interaction in the AHP protocol.
/// Each round consists of:
/// - Prover messages (polynomial commitments)
/// - Verifier challenges
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AHPRound<F> {
    /// Polynomials committed by prover in this round
    pub prover_polynomials: Vec<Vec<F>>,
    
    /// Challenges sent by verifier in this round
    pub verifier_challenges: Vec<F>,
    
    /// Round number
    pub round_number: usize,
}

/// AHP Proof
///
/// Complete proof transcript for an AHP.
/// Contains all rounds of interaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AHPProof<F> {
    /// All rounds of the protocol
    pub rounds: Vec<AHPRound<F>>,
    
    /// Final evaluations: (point, value, opening_proof)
    pub evaluations: Vec<Evaluation<F>>,
}

/// Polynomial Evaluation
///
/// Represents an evaluation y = p(z) with opening proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evaluation<F> {
    /// Evaluation point z
    pub point: Vec<F>,
    
    /// Evaluation value y = p(z)
    pub value: F,
    
    /// Index of polynomial being evaluated
    pub polynomial_index: usize,
}

/// AHP Instance
///
/// Public instance for the AHP (statement being proved).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AHPInstance<F> {
    /// Public inputs
    pub public_inputs: Vec<F>,
    
    /// Circuit size parameters
    pub num_constraints: usize,
    pub num_variables: usize,
    pub num_public_inputs: usize,
}

/// AHP Witness
///
/// Private witness for the AHP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AHPWitness<F> {
    /// Private witness values
    pub witness_values: Vec<F>,
}

/// AHP Parameters
///
/// System parameters for the AHP.
#[derive(Clone, Debug)]
pub struct AHPParameters<F> {
    /// Maximum degree of polynomials
    pub max_degree: usize,
    
    /// Number of rounds
    pub num_rounds: usize,
    
    /// Field size (in bits)
    pub field_size_bits: usize,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F> AHPParameters<F> {
    pub fn new(max_degree: usize, num_rounds: usize, field_size_bits: usize) -> Self {
        Self {
            max_degree,
            num_rounds,
            field_size_bits,
            _phantom: PhantomData,
        }
    }
}

/// Prover State
///
/// Maintains state across rounds for the prover.
#[derive(Clone, Debug)]
pub struct ProverState<F> {
    /// Current round number
    pub current_round: usize,
    
    /// Committed polynomials so far
    pub committed_polynomials: Vec<Vec<F>>,
    
    /// Received challenges so far
    pub received_challenges: Vec<F>,
    
    /// Random coins used by prover
    pub random_coins: Vec<F>,
}

impl<F: Clone> ProverState<F> {
    pub fn new() -> Self {
        Self {
            current_round: 0,
            committed_polynomials: Vec::new(),
            received_challenges: Vec::new(),
            random_coins: Vec::new(),
        }
    }
    
    pub fn add_polynomial(&mut self, poly: Vec<F>) {
        self.committed_polynomials.push(poly);
    }
    
    pub fn add_challenge(&mut self, challenge: F) {
        self.received_challenges.push(challenge);
    }
    
    pub fn next_round(&mut self) {
        self.current_round += 1;
    }
}

/// Verifier State
///
/// Maintains state across rounds for the verifier.
#[derive(Clone, Debug)]
pub struct VerifierState<F> {
    /// Current round number
    pub current_round: usize,
    
    /// Challenges sent so far
    pub sent_challenges: Vec<F>,
    
    /// Received polynomial commitments
    pub received_commitments: Vec<Vec<u8>>,
}

impl<F: Clone> VerifierState<F> {
    pub fn new() -> Self {
        Self {
            current_round: 0,
            sent_challenges: Vec::new(),
            received_commitments: Vec::new(),
        }
    }
    
    pub fn add_challenge(&mut self, challenge: F) {
        self.sent_challenges.push(challenge);
    }
    
    pub fn add_commitment(&mut self, commitment: Vec<u8>) {
        self.received_commitments.push(commitment);
    }
    
    pub fn next_round(&mut self) {
        self.current_round += 1;
    }
}
