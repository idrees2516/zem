// O-SNARK Module
//
// Implements SNARKs with extraction in presence of additional oracles (e.g., signing oracles)
//
// Mathematical Foundation (Definition 5):
// O-SNARK extends rel-SNARK with O-AdPoK (adaptive proof of knowledge with oracle)
// 
// Key Innovation: Extractor E gets access to auxiliary oracle transcript Q
// - Q contains signing oracle queries: (m_i, σ_i)
// - Extraction: w ← E(pp, i, aux, x, π, Q, tr_A, Γ)
// - Security: Pr[V^θ accepts ∧ (x, w) ∉ R^θ] ≤ negl(λ) even with signing oracle
//
// Applications:
// - Aggregate signatures (Section 5.2)
// - KZG with BLS/Schnorr signatures (Appendix D)
// - Any SNARK composed with AGM-secure signatures

pub mod interface;
pub mod o_adpok;
pub mod kzg_security;
pub mod bls_analysis;
pub mod schnorr_analysis;
pub mod dlog_reduction;
pub mod auxiliary_input;
pub mod types;
pub mod errors;

pub use interface::OSNARK;
pub use o_adpok::{OAdPoKGame, OAdPoKChallenger};
pub use kzg_security::{KZGWithBLS, KZGWithSchnorr};
pub use bls_analysis::{BLSSignatureAnalyzer, DiscreteLogBreakInfo};
pub use schnorr_analysis::{SchnorrSignatureAnalyzer, SchnorrSignatureComponents, SubstitutionResult};
pub use dlog_reduction::{BLSDiscreteLogReduction, SchnorrDiscreteLogReduction, SecurityProofHelper};
pub use auxiliary_input::{
    AuxiliaryInputDistribution, SignatureAuxiliaryDistribution, GenericAuxiliaryDistribution,
    AuxiliaryOracle, SigningOracleAux, ZAuxiliaryOAdPoK, AuxiliaryInputBuilder
};
pub use types::{AuxiliaryInput, SigningQuery};
pub use errors::{OSNARKError, OSNARKResult};
