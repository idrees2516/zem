// Relativized SNARK Module
//
// Implements SNARKs with oracle access and AGM-aware extraction.
//
// Mathematical Foundation:
// - Setup: G(1^λ) → pp
// - Indexing: I^θ(i, pp) → (ipk, ivk) with oracle access
// - Proving: P^θ(ipk, x, w) → π with oracle access
// - Verification: V^θ(ivk, x, π) → ⊤/⊥ with oracle access
// - Extraction: E(pp, i, x, π, tr_P, Γ) → w (AGM-aware)
//
// References:
// - AGM-Secure Functionalities with Cryptographic Proofs (2025)
// - Definition 1: Relativized SNARK with SLE in AGM+O

pub mod interface;
pub mod oracle_forcing;
pub mod fiat_shamir_optimization;
pub mod types;
pub mod errors;

pub use interface::RelativizedSNARK;
pub use oracle_forcing::{OracleForcing, ForcingStrategy};
pub use fiat_shamir_optimization::{
    FiatShamirDetector, ZeroOverheadOracleForcing, FiatShamirBenchmark,
    FiatShamirOptimizationConfig
};
pub use types::{
    PublicParameters, IndexerKey, VerifierKey, Proof,
    Circuit, Statement, Witness, ExtractionResult,
};
pub use errors::{RelSNARKError, RelSNARKResult};

#[cfg(test)]
mod tests;
