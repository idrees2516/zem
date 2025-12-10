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
pub mod sumcheck;
pub mod crypto;
pub mod shout;
pub mod twist;
pub mod virtual_poly;
pub mod lattice_pcs;
pub mod jolt_zkvm;
pub mod agm;
pub mod oracle;
pub mod rel_snark;
pub mod ivc;
pub mod o_snark;
pub mod aggregate_sig;
pub mod pcd;
pub mod api;
pub mod integration;
pub mod permcheck;
pub mod lookup;
pub mod salsaa;  // SALSAA: Sumcheck-Aided Lattice-based Succinct Arguments

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
pub use jolt_zkvm::{
    LatticeJoltZkVM, ZkVMConfig, CycleProof, CycleProver,
    InstructionTable, InstructionTableSet, RiscVInstruction, DecodedInstruction,
};
pub use agm::{
    GroupRepresentation, GroupRepresentationManager,
    AlgebraicAdversary, AlgebraicOutput,
    GroupParser, AGMError,
};
pub use oracle::{
    Oracle, OracleTranscript, OracleQuery,
    RandomOracle, AROM, SignedOracle,
    AROMEmulator, OracleError,
};
pub use rel_snark::{
    RelativizedSNARK, OracleForcing, ForcingStrategy,
    PublicParameters, IndexerKey, VerifierKey, Proof,
    Circuit, Statement, Witness, RelSNARKError,
};
pub use ivc::{
    IncrementalComputation, DepthPredicates,
    IVCProver, IVCVerifier, IVCExtractor,
    RecursiveVerificationCircuit, IVCSecurityReduction,
    IVCState, IVCWitness, IVCProof, IVCError,
};
pub use o_snark::{
    OSNARK, OAdPoKGame, OAdPoKChallenger,
    KZGWithBLS, KZGWithSchnorr,
    AuxiliaryInput, SigningQuery, OSNARKError,
};
pub use aggregate_sig::{
    AggregateSignature, AggregateStatement, AggregateWitness,
    AggregateSignatureProof, AggregateVerificationCircuit,
    EUCMAGame, EUACKGame, EUACKToEUCMAReduction,
    VerificationKey, Signature, SignatureParameters,
    AggregateSignatureError,
};
pub use pcd::{
    PCDTranscript, PCDVertex, PCDEdge, PCDProof,
    DirectedAcyclicGraph, PCDExtractor, PCDProver,
    PCDComplianceChecker, PCDCircuit, CompliancePredicate,
    PCDError,
};
pub use api::{
    SecurityLevel,
    IVCBuilder, IVCSystem,
    AggregateSignatureBuilder, AggregateSignatureSystem,
    PCDBuilder, PCDSystem,
    fibonacci_ivc_example, aggregate_signature_example, pcd_dag_example,
};
pub use integration::{
    SymphonyRelSNARK,
    AGMConfig, OracleForcingStrategy,
    NeoAGMConfig, IntegrationMode,
};
