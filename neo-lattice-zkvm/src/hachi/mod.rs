// Hachi: Efficient Lattice-Based Multilinear Polynomial Commitments over Extension Fields
// Complete production implementation based on Nguyen, O'Rourke, and Zhang (2026)

pub mod types;
pub mod params;
pub mod errors;

// Mathematical primitives
pub mod primitives;

// Extension field embedding
pub mod embedding;

// Commitment scheme
pub mod commitment;

// Ring switching protocol
pub mod ring_switching;

// Sumcheck protocol
pub mod sumcheck;

// Norm verification
pub mod norm_verification;

// Complete protocol
pub mod protocol;

// Optimizations
pub mod optimization;

// Re-exports for convenience
pub use types::*;
pub use params::*;
pub use errors::*;
pub use protocol::{HachiPCS, HachiProver, HachiVerifier};
