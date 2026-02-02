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
pub mod twist;
pub mod twist_advanced;
pub mod prefix_suffix;
pub mod prefix_suffix_applications;
pub mod phase6_7_integration;
pub mod hyrax;
pub mod bulletproofs;
pub mod dory;
pub mod hash_based_commitments;
pub mod polynomial_commitments;
pub mod space_time_tradeoff;
pub mod jolt_integration;
pub mod grand_product_check;
pub mod lasso;
pub mod spice;
pub mod error_handling;
pub mod lattice_integration;

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
pub use twist::*;
pub use twist_advanced::*;
pub use prefix_suffix::*;
pub use prefix_suffix_applications::*;
pub use phase6_7_integration::*;
pub use hyrax::*;
pub use bulletproofs::*;
pub use dory::*;
pub use hash_based_commitments::*;
pub use polynomial_commitments::*;
pub use space_time_tradeoff::*;
pub use jolt_integration::*;
pub use grand_product_check::*;
pub use lasso::*;
pub use spice::*;
pub use error_handling::*;
pub use lattice_integration::*;
