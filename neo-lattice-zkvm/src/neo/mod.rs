// Neo: Lattice-based Folding Scheme for CCS over Small Fields
// Implementation based on the Neo paper (2025-294)
// Provides pay-per-bit commitments and efficient folding for CCS

pub mod ccs;
pub mod union_polynomial;
pub mod folding;
pub mod decomposition;
pub mod reductions;
pub mod challenge_set;

pub use ccs::{
    CCSInstance, CCSWitness, CCSConstraintSystem,
    SparseMatrix, SelectorSet,
};
pub use union_polynomial::{
    NeoUnionPolynomial, UnionPolynomialComputation,
};
pub use folding::{
    NeoFoldingScheme, FoldedCCSInstance, FoldedCCSWitness,
    NeoFoldingProof, FoldingParameters,
};
pub use decomposition::{
    DecompositionReduction, DecompositionProof,
    BaseDecomposition,
};
pub use reductions::{
    CCSReduction, RLCReduction, CCSReductionProof,
    RLCReductionProof, EvaluationClaim,
};
pub use challenge_set::{
    ChallengeSet, ChallengeSetBuilder,
    SmallFieldChallengeSet,
};
