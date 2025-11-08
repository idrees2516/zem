// SNARK Construction Module
// Implements Symphony's complete SNARK system

pub mod compiler;
pub mod cp_snark;
pub mod symphony;
pub mod extraction;
pub mod neo_integration;

pub use compiler::{CPSNARKCompiler, CompilerProof};
pub use cp_snark::{CPSNARKRelation, CPSNARKInstance, CPSNARKWitness, CPSNARKProof};
pub use symphony::{SymphonySNARK, SymphonyProof, SymphonyParams};
pub use extraction::{WitnessExtractor, ExtractedWitness};
pub use neo_integration::{SymphonyNeoIntegration, estimate_cost_savings};
