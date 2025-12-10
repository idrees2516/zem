// Phase 5: Lattice-Based Polynomial Commitments Integration Module

pub mod hyperwolf_adapter;
pub mod sparse_eval;
pub mod small_value_opt;
pub mod key_management;

pub use hyperwolf_adapter::{HyperWolfTwistShout, SparseCommitment};
pub use sparse_eval::{SparseEvaluationProof, WitnessFolding};
pub use small_value_opt::{NeoPayPerBit, SparsityTracker, SmallValueOptimizer};
pub use key_management::{CommitmentKeyManager, SRSGenerator, ParameterSelector};
