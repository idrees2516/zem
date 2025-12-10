// SALSAA (Sumcheck-Aided Lattice-based Succinct Arguments and Applications)
// Main module for SALSAA framework integration

pub mod matrix;
pub mod lde;
pub mod relations;
pub mod transcript;
pub mod protocols;

pub use matrix::{Matrix, TensorStructure};
pub use lde::LDEContext;
pub use relations::{
    LinearRelation, LinearStatement, LinearWitness,
    LDERelation, LDEStatement, LDEWitness,
    SumcheckRelation, SumcheckStatement, SumcheckWitness,
    NormRelation, NormStatement, NormWitness,
    R1CSRelation, R1CSStatement, R1CSWitness,
};
pub use transcript::Transcript;
pub use protocols::{
    LDETensorReduction, SumcheckReduction, SumcheckProof, RoundPolynomial,
    NormCheckReduction, NormCheckComposition,
    FoldingReduction, ChallengeSet,
    SplitReduction, SplitProof,
    TensorRandomProjection, RandomProjectionProof,
    BaseDecomposition,
    BatchingReduction, EnhancedBatchingReduction,
    JoinReduction,
    R1CSReduction,
};
