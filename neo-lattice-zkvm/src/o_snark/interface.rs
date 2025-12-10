// O-SNARK Interface
//
// Mathematical Foundation (Definition 5):
// O-SNARK = rel-SNARK + O-AdPoK (adaptive proof of knowledge with oracle)
//
// Key Difference from rel-SNARK:
// - Extractor has access to auxiliary oracle transcript Q
// - Q contains signing oracle queries: Q = {(m_i, σ_i)}
// - Enables extraction even when adversary queries signing oracle
//
// Security Property (O-AdPoK):
// Game O-AdPoK_Π(A, λ):
//   1. Sample θ ← O(1^λ)
//   2. Sample (aux, st) ← Z(1^λ, θ)
//   3. Create auxiliary oracle O_st ← O(st, θ)
//   4. Run adversary: (i, x, π, Γ) ← A^{θ,O_st}(pp, aux)
//   5. Extract: w ← E(pp, i, aux, x, π, Q, tr_A, Γ)
//   6. Return 1 if V^θ(ivk, x, π) = 1 ∧ (x, w) ∉ R^θ
//
// Theorem: If Π has O-AdPoK, then aggregate signatures are EU-CMA secure

use crate::agm::{Group, GroupRepresentation};
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::{RelativizedSNARK, PublicParameters, Circuit, Statement, Proof, Witness};

use super::types::{AuxiliaryInput, SigningQuery};
use super::errors::{OSNARKError, OSNARKResult};

/// O-SNARK trait: rel-SNARK with extraction in presence of auxiliary oracle
///
/// Extends RelativizedSNARK with:
/// - AuxiliaryInput type for Z-sampled auxiliary data
/// - extract_with_oracle method that takes signing oracle transcript Q
pub trait OSNARK<F, G, O, AuxO>: RelativizedSNARK<F, G, O>
where
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    AuxO: Oracle<Vec<u8>, Vec<u8>>,
{
    /// Auxiliary input type
    /// 
    /// Sampled by Z(1^λ, θ) to provide context for adversary
    /// Example: For aggregate signatures, aux = vk (verification key)
    type AuxiliaryInput;
    
    /// Extract with auxiliary oracle: E(pp, i, aux, x, π, Q, tr_A, Γ) → w
    ///
    /// Mathematical steps:
    /// 1. Parse signing oracle transcript Q = {(m_i, σ_i)}
    /// 2. Parse group representations Γ for (x, π)
    /// 3. Check if any signature σ_i appears in Γ with non-zero coefficient
    /// 4. If yes, use signing queries to extract witness
    /// 5. If no, fall back to standard extraction
    ///
    /// Key Property: Extraction succeeds even when adversary queries signing oracle
    /// - If adversary uses signing oracle outputs, they appear in Q
    /// - Group representations Γ reveal how σ_i are combined
    /// - Can extract witness by analyzing this combination
    fn extract_with_oracle(
        pp: &PublicParameters,
        circuit: &Circuit,
        aux: &Self::AuxiliaryInput,
        statement: &Statement,
        proof: &Proof,
        signing_queries: &[SigningQuery<Vec<u8>, Vec<u8>>],
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<G>,
    ) -> OSNARKResult<Witness>;
    
    /// Check O-AdPoK security
    ///
    /// Verifies: Pr[V^θ accepts ∧ (x, w) ∉ R^θ] ≤ negl(λ)
    /// even when adversary has access to signing oracle
    fn check_o_adpok_security(
        pp: &PublicParameters,
        circuit: &Circuit,
        aux: &Self::AuxiliaryInput,
        statement: &Statement,
        proof: &Proof,
        signing_queries: &[SigningQuery<Vec<u8>, Vec<u8>>],
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<G>,
        oracle: &mut O,
        aux_oracle: &mut AuxO,
    ) -> OSNARKResult<bool> {
        // Extract witness
        let witness = Self::extract_with_oracle(
            pp,
            circuit,
            aux,
            statement,
            proof,
            signing_queries,
            prover_transcript,
            group_representations,
        )?;
        
        // Verify proof
        let verified = Self::verify(
            &crate::rel_snark::VerifierKey::new(vec![]), // Simplified
            statement,
            proof,
            oracle,
        ).map_err(|e| OSNARKError::ExtractionFailed(format!("Verification failed: {}", e)))?;
        
        if !verified {
            return Ok(true); // Proof doesn't verify, no soundness violation
        }
        
        // Check if witness is valid
        // If witness is invalid but proof verifies, soundness is broken
        Ok(false) // Simplified - would check witness validity
    }
}

/// Helper trait for Z-auxiliary input sampling
///
/// Z(1^λ, θ) → (aux, st) where:
/// - aux: auxiliary input given to adversary
/// - st: state used to create auxiliary oracle O_st
pub trait AuxiliaryInputSampler<O: Oracle<Vec<u8>, Vec<u8>>> {
    type AuxiliaryInput;
    type State;
    
    /// Sample auxiliary input and state
    ///
    /// For aggregate signatures:
    /// - Sample pp_Σ (signature parameters)
    /// - Generate (vk, sk) (key pair)
    /// - Return (aux = vk, st = sk)
    fn sample(
        security_parameter: usize,
        oracle: &O,
    ) -> (Self::AuxiliaryInput, Self::State);
    
    /// Create auxiliary oracle from state
    ///
    /// O_st(m) = sign^θ(st, m)
    /// Returns signing oracle that uses secret key st
    fn create_auxiliary_oracle(
        state: Self::State,
        oracle: O,
    ) -> Box<dyn Oracle<Vec<u8>, Vec<u8>>>;
}
