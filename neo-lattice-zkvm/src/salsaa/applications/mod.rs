// SALSAA Applications
//
// This module contains complete applications built from atomic RoK protocols:
// - SNARK: Succinct Non-interactive Argument of Knowledge
// - PCS: Polynomial Commitment Scheme
// - Folding Scheme: IVC accumulation
//
// Reference: SALSAA paper Theorems 1, 2, 3

pub mod snark_params;
pub mod snark_prover;
pub mod snark_verifier;
pub mod pcs;
pub mod folding_params;
pub mod folding_prover;
pub mod folding_verifier;

pub use snark_params::SNARKParams;
pub use snark_prover::SNARKProver;
pub use snark_verifier::SNARKVerifier;
pub use pcs::{PCSCommitment, PCS};
pub use folding_params::FoldingParams;
pub use folding_prover::FoldingProver;
pub use folding_verifier::FoldingVerifier;
