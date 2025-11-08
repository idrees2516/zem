// LatticeFold+ implementation
// Faster, Simpler, Shorter Lattice-Based Folding

pub mod monomial;
pub mod table_polynomial;
pub mod gadget;
pub mod ajtai_commitment;
pub mod double_commitment;
pub mod monomial_check;
pub mod range_check;
pub mod monomial_optimizations;
pub mod commitment_transform;
pub mod folding;
pub mod tensor_rings;
pub mod neo_integration;
pub mod engine;

pub use monomial::{Monomial, MonomialMatrix, MonomialSet};
pub use table_polynomial::TablePolynomial;
pub use gadget::{GadgetDecomposition, GadgetMatrix};
pub use ajtai_commitment::{AjtaiCommitment, LazyMatrix, OpeningInfo, MSISParameters};
pub use double_commitment::{DoubleCommitment, SplitFunction, PowFunction, DoubleOpeningRelation};
pub use monomial_check::{
    MonomialSetCheckProver, MonomialSetCheckVerifier, 
    MonomialSetCheckProof, MonomialSetCheckInstance,
    MonomialSetCheckInput, MonomialSetCheckOutput
};
pub use range_check::{
    WarmupRangeProver, WarmupRangeVerifier,
    WarmupRangeProof, WarmupRangeInstance,
    RangeCheckProver, RangeCheckVerifier,
    RangeCheckProof, RangeCheckInstance,
    RangeCheckEvaluations
};
pub use monomial_optimizations::{
    BatchedMonomialSetCheckProver,
    EfficientMonomialCommitment,
    ParallelMonomialCommitment,
    CommitmentCost
};
pub use commitment_transform::{
    CommitmentTransformProver, CommitmentTransformVerifier,
    CommitmentTransformProof, CommitmentTransformInstance,
    CommitmentTransformInput
};
pub use folding::{
    LinearInstance, FoldingProver, FoldingVerifier, FoldingProof, FoldingOutput,
    DecompositionProver, DecompositionVerifier,
    DecompositionProof, DecompositionOutput, ConsistencyProof
};
pub use tensor_rings::{
    TensorRingConfig, SmallFieldFolding,
    NTTAcceleratedOps, FieldArithmeticOps
};
pub use neo_integration::NeoIntegration;
pub use engine::{LatticeFoldPlusEngine, PerformanceStats};
