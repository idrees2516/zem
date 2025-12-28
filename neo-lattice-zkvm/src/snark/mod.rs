// SNARK Construction Module
// Implements Symphony's complete SNARK system
// Plus SpeedySpartan and Spartan++ (Tasks 11.1-11.3)

pub mod compiler;
pub mod cp_snark;
pub mod symphony;
pub mod extraction;
pub mod monomial_embedding;
pub mod structured_projection;
pub mod neo_integration;
pub mod speedy_spartan;
pub mod spartan_plusplus;
pub mod circuit_compiler;
pub mod groth16_agm;
pub mod errors;

pub use compiler::{CPSNARKCompiler, CompilerProof};
pub use cp_snark::{CPSNARKRelation, CPSNARKInstance, CPSNARKWitness, CPSNARKProof};
pub use symphony::{SymphonySNARK, SymphonyProof, SymphonyParams};
pub use extraction::{WitnessExtractor, ExtractedWitness};
pub use monomial_embedding::{
    MonomialSet, TablePolynomial, MonomialRangeProof, MonomialRangeProver,
};
pub use structured_projection::{
    StructuredProjection, ProjectionProof, ProjectionProver,
};
pub use neo_integration::{SymphonyNeoIntegration, estimate_cost_savings};
pub use speedy_spartan::{SpeedySpartan, SpeedySpartanProof, PlonkishGate, GateType};
pub use spartan_plusplus::{SpartanPlusPlus, SpartanPlusPlusProof, CCS, SparseMatrix};
pub use circuit_compiler::{CircuitCompiler, R1CS, PlonkishCircuit};
pub use groth16_agm::{ModifiedGroth16, Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey};
pub use errors::SNARKError;
