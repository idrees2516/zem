// Reduction of Knowledge (RoK) Protocols Module
// Implements the building block protocols for Symphony's high-arity folding

pub mod hadamard;
pub mod single_instance;
pub mod high_arity_folding;
pub mod streaming;
pub mod rok_traits;

pub use hadamard::{HadamardReductionProtocol, HadamardInstance, HadamardWitness, HadamardProof};
pub use single_instance::{SingleInstanceProtocol, GeneralizedR1CSInstance, GeneralizedR1CSWitness};
pub use high_arity_folding::{HighArityFoldingProtocol, MultiInstanceInput, FoldedOutput};
pub use streaming::StreamingProver;
pub use rok_traits::{ReductionOfKnowledge, LinearInstance, BatchLinearInstance};
