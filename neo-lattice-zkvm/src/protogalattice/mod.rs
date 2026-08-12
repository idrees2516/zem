// ProtogaLattice: Constant-Round Lattice-based Folding for General Polynomial Relations
//
// This module implements the complete ProtogaLattice scheme from the paper:
// "ProtogaLattice: Constant-Round Lattice-based Folding for general polynomial relations"
//
// Key Features:
// - Constant-round folding for arbitrary polynomial relations
// - Lattice-based security assumptions (Module-SIS and Module-LWE)
// - Support for multivariate polynomial constraints
// - Efficient prover and verifier with optimal round complexity
// - Incremental Verifiable Computation (IVC) compatibility

pub mod types;
pub mod polynomial_relations;
pub mod commitment;
pub mod folding;
pub mod prover;
pub mod verifier;
pub mod transcript;
pub mod lattice_params;
pub mod error_correction;
pub mod optimization;

pub use types::{
    ProtogaInstance, ProtogaWitness, ProtogaProof,
    FoldedInstance, FoldedWitness, FoldingProof,
    PolynomialRelation, RelationInstance,
};

pub use polynomial_relations::{
    GeneralPolynomialRelation, PolynomialConstraint,
    MultilinearConstraint, UnivariateConstraint,
};

pub use commitment::{
    LatticeCommitment, CommitmentScheme,
    ProtogaCommitmentKey, ProtogaOpeningProof,
};

pub use folding::{
    ProtogaFolder, FoldingScheme,
    ConstantRoundFolder, RecursiveFoldingProver,
};

pub use prover::{
    ProtogaProver, ProvingKey,
    ProverState, RoundProver,
};

pub use verifier::{
    ProtogaVerifier, VerifyingKey,
    VerifierState, RoundVerifier,
};

use crate::errors::ProtogaError;

/// Security parameter controlling lattice hardness
pub const SECURITY_PARAMETER: usize = 128;

/// Modulus for the lattice ring
pub const RING_MODULUS: u64 = (1u64 << 61) - 1; // Prime close to 2^61

/// Polynomial degree for cyclotomic ring
pub const RING_DEGREE: usize = 1024;

/// Number of folding rounds (constant)
pub const FOLDING_ROUNDS: usize = 3;

pub type Result<T> = std::result::Result<T, ProtogaError>;
