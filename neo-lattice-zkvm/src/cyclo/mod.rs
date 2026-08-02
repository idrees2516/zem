/// Cyclo: Lightweight Lattice-based Folding via Partial Range Checks
/// 
/// This module implements the Cyclo folding scheme from the paper:
/// "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks"
/// by Garreta, Lipmaa, Luhaäär, and Osadnik (2026)
/// 
/// Key features:
/// - Amortized norm-refreshing folding scheme
/// - No decomposition/range-check on accumulated witnesses
/// - Extension commitment for witness decomposition
/// - Range test via sum-check protocol
/// - Support for R1CS/CCS over finite fields
/// - Parallel sum-check execution with rayon
/// - Streaming witness processing for memory efficiency
/// - Recursive verification circuit generation
/// - Proof-carrying data (PCD) construction

pub mod types;
pub mod parameters;
pub mod cyclotomic;
pub mod commitment;
pub mod range_test;
pub mod extension_commitment;
pub mod folding;
pub mod r1cs_reduction;
pub mod strong_sampling;
pub mod utils;
pub mod parallel;
pub mod streaming;
pub mod recursive;
pub mod pcd;

pub use types::*;
pub use parameters::*;
pub use cyclotomic::*;
pub use commitment::*;
pub use range_test::*;
pub use extension_commitment::*;
pub use folding::*;
pub use r1cs_reduction::*;
pub use strong_sampling::*;
pub use parallel::*;
pub use streaming::*;
pub use recursive::*;
pub use pcd::*;

#[cfg(test)]
mod tests;
