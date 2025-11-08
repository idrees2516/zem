// Applications Module
// High-level applications built on Symphony SNARK

pub mod zkvm;
pub mod signatures;

pub use zkvm::{ZkVMProver, ExecutionProof, RiscVInstruction};
pub use signatures::{
    AggregateSignatureProver, AggregateSignatureProof,
    SignatureScheme, PublicKey, Signature, Message,
    SignatureBatch, SignatureAggregator,
};
