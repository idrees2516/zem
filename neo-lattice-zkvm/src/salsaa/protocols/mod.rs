// SALSAA Protocol Implementations
//
// This module contains all atomic RoK (Reduction of Knowledge) protocols
// that compose to form complete SNARK, PCS, and folding schemes.
//
// Protocol Hierarchy:
// - Atomic protocols: Individual reductions between relations
// - Compositions: Chains of atomic protocols
// - Applications: Complete SNARK/PCS/Folding built from compositions
//
// Reference: SALSAA paper Section 5-6

pub mod lde_tensor;
pub mod sumcheck;
pub mod norm_check;
pub mod norm_composition;
pub mod folding;
pub mod split;
pub mod random_projection;
pub mod base_decomposition;
pub mod batching;
pub mod join;
pub mod r1cs;

pub use lde_tensor::LDETensorReduction;
pub use sumcheck::{SumcheckReduction, SumcheckProof, RoundPolynomial};
pub use norm_check::NormCheckReduction;
pub use norm_composition::NormCheckComposition;
pub use folding::{FoldingReduction, ChallengeSet};
pub use split::{SplitReduction, SplitProof};
pub use random_projection::{TensorRandomProjection, RandomProjectionProof};
pub use base_decomposition::BaseDecomposition;
pub use batching::{BatchingReduction, EnhancedBatchingReduction};
pub use join::JoinReduction;
pub use r1cs::R1CSReduction;
