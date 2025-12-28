// Sum-Check Protocol Implementation Module

pub mod multilinear;
pub mod tensor_bridge;
pub mod dense_prover;
pub mod dense_verifier;
pub mod sparse_prover;
pub mod univariate;
pub mod salsaa_relations;
pub mod salsaa_reductions;

pub use multilinear::MultilinearPolynomial;
pub use tensor_bridge::TensorOfRings;
pub use dense_prover::{DenseSumCheckProver, SumCheckProof, SALSAASumCheckProver, BatchedNormCheck};
pub use dense_verifier::{DenseSumCheckVerifier, VerificationResult, SALSAASumCheckVerifier, LDEEvaluationVerifier};
pub use sparse_prover::{SparseSumCheckProver, GeneralizedSparseSumCheck};
pub use univariate::UnivariatePolynomial;
pub use salsaa_relations::{
    LinearRelation, WitnessMatrix, LDERelation, LDETensorRelation,
    SumcheckRelation, LDEEvaluationClaim, MatrixStructure, StructuredMatrix,
};
pub use salsaa_reductions::{
    NormCheckRoK, NormCheckProof, SumcheckRoK, SumcheckRoKProof,
    ImprovedBatching, ImprovedBatchingProof, R1CSReduction, R1CSReductionProof,
};

// Task 13 optimizations
pub mod virtual_polynomial;
pub mod batch_evaluation;
pub mod memory_checking;
pub mod small_value_preservation;
pub mod streaming_prover;

pub use virtual_polynomial::{
    VirtualPolynomial, VirtualPolynomialBuilder, ProductTerm, VirtualPolynomialProof,
};
pub use batch_evaluation::{
    BatchEvaluationProver, BatchEvaluationVerifier, EvaluationClaim,
    ShoutBatchEvaluation, BatchEvaluationProof, MultiPointBatchEvaluation,
};
pub use memory_checking::{
    MemoryCheckingProver, MemoryCheckingVerifier, MemoryOperation, MemoryOp,
    MemoryCheckingProof, PermutationProof, OneHotProof, TimestampProof,
};
pub use small_value_preservation::{
    SmallValueWitness, SmallValueCommitment, RangeProof,
    BatchSmallValueCommitment, BatchRangeProof, SmallValueStats,
};
pub use streaming_prover::{
    StreamingSumCheckProver, BatchedStreamingProver, StreamingStats,
};
