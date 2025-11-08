// Neo: Lattice-based Folding Scheme for CCS
// Implementation of the Neo protocol from the paper
// Extended with LatticeFold+ for improved performance

pub mod field;
pub mod ring;
pub mod polynomial;
pub mod commitment;
pub mod folding;
pub mod parameters;
pub mod optimization;
pub mod config;
pub mod latticefold_plus;
pub mod protocols;
pub mod fiat_shamir;
pub mod snark;
pub mod applications;

pub use field::{Field, GoldilocksField, M61Field};
pub use polynomial::MultilinearPolynomial;
pub use folding::{
    EvaluationClaim, CCSStructure, CCSInstance, SparseMatrix,
    SumCheckProof, WitnessDecomposition, CCSReduction,
};
pub use parameters::{NeoParameters, SecurityLevel, ParameterError};
pub use optimization::{
    ParallelConfig, MemoryPool, BufferPool, CSRMatrix, NTTCache,
};
pub use config::{NeoConfig, init_config, get_config};
pub use latticefold_plus::{
    Monomial, MonomialMatrix, MonomialSet,
    TablePolynomial, GadgetDecomposition,
};
pub use protocols::{
    HadamardReductionProtocol, HadamardInstance, HadamardWitness,
    SingleInstanceProtocol, GeneralizedR1CSInstance, GeneralizedR1CSWitness,
    ReductionOfKnowledge, LinearInstance, BatchLinearInstance,
    HighArityFoldingProtocol, MultiInstanceInput, FoldedOutput,
};
pub use fiat_shamir::{
    FiatShamirTransform, NonInteractiveProof,
    CommitAndOpen, HashOracle, HashFunction,
};
pub use snark::{
    SymphonySNARK, SymphonyProof, SymphonyParams,
    CPSNARKCompiler, CPSNARKRelation,
    WitnessExtractor, ExtractedWitness,
};
pub use applications::{
    ZkVMProver, ExecutionProof,
    AggregateSignatureProver, AggregateSignatureProof,
    SignatureScheme,
};
pub use folding::two_layer::{TwoLayerFoldingProtocol, TwoLayerConfig};
pub use protocols::streaming::{StreamingProver, StreamingConfig};
