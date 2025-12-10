// Sum-Check Protocol Implementation Module

pub mod multilinear;
pub mod tensor_bridge;
pub mod dense_prover;
pub mod dense_verifier;
pub mod sparse_prover;
pub mod univariate;

pub use multilinear::MultilinearPolynomial;
pub use tensor_bridge::TensorOfRings;
pub use dense_prover::{DenseSumCheckProver, SumCheckProof};
pub use dense_verifier::{DenseSumCheckVerifier, VerificationResult};
pub use sparse_prover::{SparseSumCheckProver, GeneralizedSparseSumCheck};
pub use univariate::UnivariatePolynomial;
