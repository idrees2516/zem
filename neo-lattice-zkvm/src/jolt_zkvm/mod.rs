// Jolt-Style zkVM with Twist and Shout
// Implements tasks 6.1, 6.2, 6.3, 6.4 and Phase 7 from the specification

pub mod core;
pub mod cycle_proof;
pub mod instruction_tables;
pub mod riscv;
pub mod shard_proof;
pub mod symphony_folding;

pub use core::{LatticeJoltZkVM, ZkVMConfig};
pub use cycle_proof::{CycleProof, CycleProver};
pub use instruction_tables::{InstructionTable, InstructionDecomposition, InstructionTableSet};
pub use riscv::{RiscVInstruction, DecodedInstruction};
pub use shard_proof::{ShardProof, ShardProver, BatchedProof, ConstraintProof};
pub use symphony_folding::{
    SymphonyTwistShoutFolder, FoldingConfig, ShoutInstance, TwistInstance,
    FoldedInstance, BatchFoldedResult,
};
