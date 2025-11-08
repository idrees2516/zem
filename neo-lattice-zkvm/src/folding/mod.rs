// Folding scheme components for Neo

pub mod evaluation_claim;
pub mod ccs;
pub mod sumcheck;
pub mod decomposition;
pub mod ccs_reduction;
pub mod challenge;
pub mod transcript;
pub mod rlc;
pub mod neo_folding;
pub mod ivc;
pub mod compression;
pub mod two_layer;

pub use evaluation_claim::{EvaluationClaim, FoldingProof, BatchedEvaluationClaims};
pub use ccs::{CCSStructure, CCSInstance, SparseMatrix, DenseMatrix, MatrixMLE};
pub use sumcheck::{SumCheckProver, SumCheckVerifier, SumCheckProof, UnivariatePolynomial, MultilinearSumCheck};
pub use decomposition::{WitnessDecomposition, DecompositionProof, RLCDecomposition};
pub use ccs_reduction::{CCSPolynomial, CCSReduction, MatrixMLECache};
pub use challenge::{ChallengeSet, ExtendedChallengeSet};
pub use transcript::{Transcript, TranscriptBuilder};
pub use rlc::{RLCReduction, RLCResult, RLCError};
pub use neo_folding::{NeoFoldingScheme, FoldingResult, FoldingError};
pub use ivc::{IVCAccumulator, IVCProver, IVCVerifier, IVCStepProof, IVCFinalProof, RecursiveVerifierCircuit};
pub use compression::{ProofCompression, CompressedProof, SNARKBackend, AccumulatorRelation, ProofAggregation};
pub use two_layer::{TwoLayerFoldingProtocol, TwoLayerConfig, TwoLayerProof};
