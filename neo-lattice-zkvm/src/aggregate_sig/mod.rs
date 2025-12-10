// Aggregate Signature Module
//
// This module implements AGM-secure aggregate signatures using O-SNARKs.
// The construction allows aggregating n signatures into a single SNARK proof.
//
// Mathematical Foundation (Section 5):
// - Setup: Generate SNARK parameters and signature scheme parameters
// - Aggregation: Prove ∀i: vfy^θ(vk_i, m_i, σ_i) = 1 using O-SNARK
// - Verification: Verify single SNARK proof instead of n signatures
// - Security: EU-ACK security reduces to EU-CMA security of base signature

pub mod types;
pub mod errors;
pub mod construction;
pub mod circuit;
pub mod security;

pub use types::*;
pub use errors::*;
pub use construction::AggregateSignature;
pub use circuit::AggregateVerificationCircuit;
pub use security::{
    EUCMAGame,
    EUACKGame,
    EUACKAdversary,
    EUACKToEUCMAReduction,
    ExtractorFailureAdversary,
};

