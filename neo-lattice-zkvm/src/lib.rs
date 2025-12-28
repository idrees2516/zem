// Neo Lattice zkVM - Complete Post-Quantum Zero-Knowledge Virtual Machine
// Synthesizes primitives from Quasar, SALSAA, Neo, Symphony, and Sum-check Survey papers

pub mod field;
pub mod ring;
pub mod polynomial;
pub mod commitment;
pub mod sumcheck;
pub mod neo;
pub mod quasar;
pub mod snark;
pub mod ivc;
pub mod pcd;
pub mod api;
pub mod optimization;
pub mod distributed;
pub mod streaming;
pub mod serialization;
pub mod constraint_systems;
pub mod small_space_zkvm;

// Re-export commonly used types
pub use field::{Field, GoldilocksField};
pub use ring::{CyclotomicRing, RingElement};
pub use commitment::ajtai::{AjtaiCommitment, CommitmentKey, AjtaiParams};
pub use sumcheck::{
    SALSAASumCheckProver, SALSAASumCheckVerifier,
    MultilinearPolynomial, UnivariatePolynomial,
};
pub use neo::{
    CCSInstance, CCSWitness, CCSConstraintSystem,
    NeoFoldingScheme, FoldedCCSInstance, FoldedCCSWitness,
};
pub use quasar::{
    QuasarAccumulator, QuasarAccumulationScheme,
    AccumulatorInstance, AccumulatorWitness,
};
