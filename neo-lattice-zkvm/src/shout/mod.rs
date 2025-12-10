// Shout Protocol Module
// Batch evaluation argument for read-only memory using sparse sum-check

pub mod one_hot;
pub mod protocol;
pub mod prover;
pub mod verifier;
pub mod virtual_polynomials;

pub use one_hot::{OneHotAddress, OneHotEncoding};
pub use protocol::{ShoutProtocol, ShoutConfig};
pub use prover::ShoutProver;
pub use verifier::ShoutVerifier;
pub use virtual_polynomials::VirtualReadValues;
