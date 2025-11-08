// HyperWolf Polynomial Commitment Scheme
// Implements logarithmic verification with standard soundness
// Per HyperWolf paper: https://eprint.iacr.org/2025/1903

mod params;
mod challenge_space;
mod leveled_commit;
mod guarded_ipa;
mod eval_protocol;
mod core_protocol;
mod pcs;
pub mod labrador;
pub mod batching;
pub mod neo_bridge;
pub mod error;
pub mod memory_pool;

pub use params::HyperWolfParams;
pub use challenge_space::ChallengeSpace;
pub use leveled_commit::LeveledCommitment;
pub use guarded_ipa::{GuardedIPA, IPARound, IPAError};
pub use eval_protocol::{EvaluationProof, EvalRound, AuxiliaryVectors, EvalError};
pub use core_protocol::{HyperWolfProof, CommitmentRound, ProtocolError};
pub use pcs::{HyperWolfPCS, Polynomial, EvalPoint, Commitment, CommitmentState, PCSError};
pub use labrador::{LabradorProof, LabradorParams, LabradorError, SparsityStats};
pub use batching::{BatchingCoordinator, BatchedProof, PolyEvalClaim, MultiPointClaim, BatchingStrategy, BatchingError};
pub use neo_bridge::{CommitmentBridge, UnifiedCommitment, EquivalenceProof, CommitmentScheme, BridgeError};
pub use error::{HyperWolfError, Result};
pub use memory_pool::{RingWorkspace, VectorOps, get_buffer};
