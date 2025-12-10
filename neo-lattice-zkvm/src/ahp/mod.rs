// Algebraic Holographic Proof (AHP) Module
//
// This module implements the AHP framework and compiler to O-SNARKs.
//
// Mathematical Foundation (Theorem 7, Appendix D.1):
// An AHP is an information-theoretic proof system where:
// - Prover commits to polynomials p_i
// - Verifier sends challenges ρ_i
// - Prover provides evaluations y_i = p_i(z_i)
// - Verifier checks algebraic relations
//
// Compilation to O-SNARK:
// 1. Replace polynomial commitments with PCS (e.g., KZG)
// 2. Apply Fiat-Shamir to make non-interactive
// 3. Add extraction in presence of signing oracle
//
// Key Property:
// If AHP has knowledge soundness and PCS is extractable with signing oracle,
// then compiled O-SNARK has O-AdPoK security.

pub mod types;
pub mod prover;
pub mod verifier;
pub mod compiler;
pub mod polynomial;
pub mod fiat_shamir;
pub mod errors;

pub use types::*;
pub use prover::AHPProver;
pub use verifier::AHPVerifier;
pub use compiler::{AHPCompiler, CompiledOSNARK, PolynomialCommitmentScheme};
pub use polynomial::{Polynomial, MultilinearPolynomial};
pub use fiat_shamir::{FiatShamirTransformer, DomainSeparatedFS, BatchFS};
pub use errors::{AHPError, AHPResult};
