// Sumcheck protocol module
//
// Implements the sumcheck protocol over extension fields F_{q^k},
// enabling efficient verification without cyclotomic ring operations.

pub mod extension_field_prover;
pub mod extension_field_verifier;
pub mod round_protocol;
pub mod evaluation_proof;
pub mod batching;

pub use extension_field_prover::*;
pub use extension_field_verifier::*;
pub use round_protocol::*;
pub use evaluation_proof::*;
pub use batching::*;
