// SALSAA Integration Module
//
// This module provides integration adapters for SALSAA with existing
// neo-lattice-zkvm components:
// - zkVM circuit compilation and execution
// - Polynomial commitment schemes
// - IVC and recursive proof composition

pub mod zkvm_adapter;
pub mod pcs_adapter;
pub mod ivc_adapter;

pub use zkvm_adapter::{ZkVMSNARKAdapter, ZkVMIntegration, ZkVMCircuit, ZkVMWitness};
pub use pcs_adapter::{SALSAAPCSAdapter, PCSBackend, PCSIntegration, PolynomialCommitment};
pub use ivc_adapter::{
    SALSAAIVCAdapter,
    IVCIntegration,
    IVCAccumulator,
    IVCVerifierState,
    IVCStep,
    RecursiveProofComposer,
};
