// Small-Space zkVM Prover Implementation
//
// This module implements the small-space zkVM prover based on the paper:
// "Proving CPU Executions in Small Space" by Vineet Nair, Justin Thaler, and Michael Zhu (2025-611)
//
// The implementation achieves O(K + T^(1/2)) or O(K + log T) space complexity
// while maintaining prover time within 2× of linear-space implementations.

pub mod field_arithmetic;
pub mod mle;
pub mod equality;
pub mod univariate;
pub mod sum_check;
pub mod small_value_optimization;
pub mod riscv_vm;
pub mod streaming_witness;
pub mod r1cs;
pub mod spartan;
pub mod pcnext;
pub mod shout;
pub mod sparse_dense_sumcheck;
pub mod shout_advanced;
pub mod dimension_selection;
pub mod phase5_integration;

pub use field_arithmetic::*;
pub use mle::*;
pub use equality::*;
pub use univariate::*;
pub use sum_check::*;
pub use small_value_optimization::*;
pub use riscv_vm::*;
pub use streaming_witness::*;
pub use r1cs::*;
pub use spartan::*;
pub use pcnext::*;
pub use shout::*;
pub use sparse_dense_sumcheck::*;
pub use shout_advanced::*;
pub use dimension_selection::*;
pub use phase5_integration::*;
