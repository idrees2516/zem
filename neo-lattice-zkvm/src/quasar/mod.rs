// Quasar: Sublinear Accumulation Schemes for Multiple Instances
// Implementation based on the Quasar paper (2025-1912)
// Provides O(log ℓ) verifier complexity for accumulating ℓ instances

pub mod accumulator;
pub mod constraint_reduction;
pub mod multicast;
pub mod oracle_batching;
pub mod two_to_one;
pub mod union_polynomial;

pub use accumulator::{
    QuasarAccumulator, AccumulatorInstance, AccumulatorWitness,
    AccumulationProof, QuasarAccumulationScheme,
};
pub use constraint_reduction::{
    ConstraintFunction, ConstraintReduction, ConstraintReductionProof,
    R1CSConstraint,
};
pub use multicast::{
    MultiCastReduction, MultiCastOutput, MultiCastProof,
    CommittedInstance, CommittedWitness,
};
pub use oracle_batching::{
    OracleBatching, OracleBatchingProof, BatchedEvaluationProof,
};
pub use two_to_one::{
    TwoToOneFolding, TwoToOneFoldingProof, FoldingState,
};
pub use union_polynomial::{
    UnionPolynomial, UnionPolynomialBuilder, PartialEvaluationProof,
};
