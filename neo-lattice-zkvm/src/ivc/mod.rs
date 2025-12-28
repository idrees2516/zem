// IVC (Incrementally Verifiable Computation) Module
//
// Implements AGM-secure IVC with unbounded-depth security.
//
// Key Innovation: Oracle forcing ensures group representations are available
// for straight-line extraction without exponential blowup.
//
// Mathematical Foundation:
// - Function: F: {0,1}^n_in × {0,1}^n_w → {0,1}^n_out
// - Depth predicates: dpt^≤_D ensures well-founded recursion
// - IVC Prover: P^θ(ipk, z_0, z_i, (w_i, z_{i-1}, π_{i-1})) → π_i
// - IVC Verifier: V^θ(ivk, z_0, z_out, π_out) → ⊤/⊥
// - Extractor: Uses single Γ for all iterations (avoids exponential blowup)

pub mod incremental_computation;
pub mod depth_predicates;
pub mod prover;
pub mod verifier;
pub mod extractor;
pub mod circuit;
pub mod reduction;
pub mod types;
pub mod errors;
pub mod snark_builder;

pub use incremental_computation::IncrementalComputation;
pub use depth_predicates::DepthPredicates;
pub use prover::IVCProver;
pub use verifier::IVCVerifier;
pub use extractor::IVCExtractor;
pub use circuit::RecursiveVerificationCircuit;
pub use reduction::{IVCSecurityReduction, IVCAdversary, IVCAdversaryOutput, SNARKAdversaryOutput};
pub use types::{IVCState, IVCWitness, IVCProof};
pub use errors::{IVCError, IVCResult};
pub use snark_builder::{SNARKBuilder, SNARKSystem, SNARKConfig, SNARKProof, ConstraintSystemType};
