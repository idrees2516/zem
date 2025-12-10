// Linear-Time Permutation Check Protocol Implementation
//
// This module implements the BiPerm and MulPerm protocols from
// "Linear-Time Permutation Check" by Bünz, Chen, and DeStefano (2025).
//
// The protocols provide permutation and lookup arguments with:
// - Polylogarithmic soundness error
// - Logarithmic verification cost  
// - Linear or near-linear prover time

pub mod foundation;
pub mod permutation;
pub mod sumcheck;
pub mod biperm;
pub mod mulperm;
pub mod errors;

// Future modules (to be implemented)
// pub mod lookup;
// pub mod pcs;

pub use foundation::{
    BooleanHypercube,
    EqualityPolynomial,
};

pub use permutation::{
    Permutation,
    PermutationMLE,
    IndicatorFunction,
    ArithmetizationStrategy,
};

pub use sumcheck::{
    VirtualPolynomial,
    SumcheckProof,
    SumcheckProver,
    SumcheckVerifier,
    BatchedSumcheckVerifier,
    FFTRoundPolyComputer,
    CompressedRoundPolynomial,
    SimpleMultilinearVP,
    ProductVP,
    WeightedSumVP,
};

pub use biperm::{
    BiPermIndex,
    SparseIndicator,
    BiPermVirtualPoly,
    BiPermProof,
    BiPermProver,
    BiPermVerifier,
};

pub use mulperm::{
    MulPermIndex,
    PartialProductComputer,
    Sumcheck1Prover,
    Sumcheck1Verifier,
    PartialProductBatcher,
    Sumcheck2Prover,
    Sumcheck2Verifier,
    MulPermProof,
    MulPermProver,
    MulPermVerifier,
};

pub use errors::{
    PermCheckError,
    VerificationError,
};
