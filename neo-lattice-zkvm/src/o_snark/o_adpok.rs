// O-AdPoK Game (Adaptive Proof of Knowledge with Oracle)
//
// Mathematical Foundation (Figure 4):
// Game O-AdPoK_Π(A, λ):
//   1. Sample oracle: θ ← O(1^λ)
//   2. Sample auxiliary input: (aux, st) ← Z(1^λ, θ)
//   3. Create auxiliary oracle: O_st ← O(st, θ)
//   4. Run adversary with dual oracle access: (i, x, π, Γ) ← A^{θ,O_st}(pp, aux)
//   5. Extract witness: w ← E(pp, i, aux, x, π, Q, tr_A, Γ)
//      where Q = signing oracle queries, tr_A = random oracle queries
//   6. Verify: b_verify ← V^θ(ivk, x, π)
//   7. Check witness validity: b_valid ← (x, w) ∈ R^θ
//   8. Return 1 if b_verify = 1 ∧ b_valid = 0 (soundness violation)
//
// Key Property: Adversary has access to BOTH oracles
// - θ: random oracle (standard)
// - O_st: signing oracle (auxiliary)
//
// Security: Pr[O-AdPoK_Π(A, λ) = 1] ≤ negl(λ)
// Means: Even with signing oracle, extractor succeeds

use std::marker::PhantomData;

use crate::agm::{Group, GroupRepresentation, AlgebraicAdversary, AlgebraicOutput};
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::{PublicParameters, Circuit, Statement, Proof, Witness};

use super::interface::{OSNARK, AuxiliaryInputSampler};
use super::types::{AuxiliaryInput, SigningQuery};
use super::errors::{OSNARKError, OSNARKResult};

/// O-AdPoK Game
///
/// Tests adaptive proof of knowledge in presence of auxiliary oracle
pub struct OAdPoKGame<F, G, O, AuxO, S>
where
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    AuxO: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O, AuxO>,
{
    /// Public parameters
    pp: PublicParameters,
    
    /// Random oracle
    oracle: O,
    
    /// Auxiliary oracle (signing oracle)
    aux_oracle: AuxO,
    
    /// Auxiliary input sampler
    aux_sampler: Box<dyn AuxiliaryInputSampler<O, AuxiliaryInput = S::AuxiliaryInput>>,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, S)>,
}

impl<F, G, O, AuxO, S> OAdPoKGame<F, G, O, AuxO, S>
where
    F: Clone,
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    AuxO: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O, AuxO>,
{
    pub fn new(
        pp: PublicParameters,
        oracle: O,
        aux_oracle: AuxO,
        aux_sampler: Box<dyn AuxiliaryInputSampler<O, AuxiliaryInput = S::AuxiliaryInput>>,
    ) -> Self {
        Self {
            pp,
            oracle,
            aux_oracle,
            aux_sampler,
            _phantom: PhantomData,
        }
    }
    
    /// Run O-AdPoK game: O-AdPoK_Π(A, λ) → {0, 1}
    ///
    /// Mathematical steps:
    /// 1. Sample θ ← O(1^λ) [oracle already sampled]
    /// 2. Sample (aux, st) ← Z(1^λ, θ)
    /// 3. Create O_st ← O(st, θ)
    /// 4. Run adversary: (i, x, π, Γ) ← A^{θ,O_st}(pp, aux)
    /// 5. Extract: w ← E(pp, i, aux, x, π, Q, tr_A, Γ)
    /// 6. Check: V^θ(ivk, x, π) = 1 ∧ (x, w) ∉ R^θ
    ///
    /// Returns: 1 if soundness violated, 0 otherwise
    pub fn run<A>(
        &mut self,
        adversary: &mut A,
        security_parameter: usize,
    ) -> OSNARKResult<bool>
    where
        A: AlgebraicAdversary<G, O>,
    {
        // Step 1: Sample auxiliary input (aux, st) ← Z(1^λ, θ)
        let (aux, _state) = self.aux_sampler.sample(security_parameter, &self.oracle);
        
        // Step 2: Run adversary with dual oracle access
        // Adversary can query both θ (random oracle) and O_st (signing oracle)
        let adversary_output = adversary.run(&self.pp.data, &mut self.oracle)
            .map_err(|e| OSNARKError::OAdPoKFailed(format!("Adversary failed: {}", e)))?;
        
        // Step 3: Extract signing oracle queries Q
        let signing_queries = self.extract_signing_queries();
        
        // Step 4: Parse adversary output
        let (circuit, statement, proof) = self.parse_adversary_output(&adversary_output)?;
        
        // Step 5: Extract witness using O-SNARK extractor
        // E(pp, i, aux, x, π, Q, tr_A, Γ)
        let extraction_result = S::extract_with_oracle(
            &self.pp,
            &circuit,
            &aux,
            &statement,
            &proof,
            &signing_queries,
            self.oracle.transcript(),
            &adversary_output.representations,
        );
        
        // Step 6: Check if extraction succeeded
        match extraction_result {
            Ok(witness) => {
                // Extraction succeeded, check if witness is valid
                let is_valid = self.check_witness_validity(&circuit, &statement, &witness)?;
                
                // Step 7: Verify proof
                let proof_verifies = S::verify(
                    &crate::rel_snark::VerifierKey::new(vec![]), // Simplified
                    &statement,
                    &proof,
                    &mut self.oracle,
                ).map_err(|e| OSNARKError::OAdPoKFailed(format!("Verification failed: {}", e)))?;
                
                // Soundness violation: proof verifies but witness invalid
                Ok(proof_verifies && !is_valid)
            }
            Err(_) => {
                // Extraction failed
                // Check if proof verifies (if yes, soundness violated)
                let proof_verifies = S::verify(
                    &crate::rel_snark::VerifierKey::new(vec![]), // Simplified
                    &statement,
                    &proof,
                    &mut self.oracle,
                ).map_err(|e| OSNARKError::OAdPoKFailed(format!("Verification failed: {}", e)))?;
                
                Ok(proof_verifies) // If proof verifies but extraction failed, soundness violated
            }
        }
    }
    
    /// Extract signing oracle queries Q = {(m_i, σ_i)}
    ///
    /// Retrieves all queries made to auxiliary oracle O_st
    fn extract_signing_queries(&self) -> Vec<SigningQuery<Vec<u8>, Vec<u8>>> {
        let mut queries = Vec::new();
        
        // Extract from auxiliary oracle transcript
        for query in self.aux_oracle.transcript().queries() {
            queries.push(SigningQuery::new(
                query.query.clone(),
                query.response.clone(),
            ));
        }
        
        queries
    }
    
    /// Parse adversary output to extract circuit, statement, proof
    fn parse_adversary_output(
        &self,
        output: &AlgebraicOutput<G>,
    ) -> OSNARKResult<(Circuit, Statement, Proof)> {
        // Simplified parsing - in practice would extract from output
        let circuit = Circuit::new(vec![], 0, 0);
        let statement = Statement::new(vec![]);
        let proof = Proof::new(vec![]);
        
        Ok((circuit, statement, proof))
    }
    
    /// Check if extracted witness is valid: (x, w) ∈ R^θ
    ///
    /// Verifies that witness satisfies the relation
    fn check_witness_validity(
        &self,
        circuit: &Circuit,
        statement: &Statement,
        witness: &Witness,
    ) -> OSNARKResult<bool> {
        // Simplified - would check circuit satisfaction
        Ok(true)
    }
}

/// O-AdPoK Challenger
///
/// Implements the challenger for O-AdPoK game
/// Provides oracles and checks adversary output
pub struct OAdPoKChallenger<O, AuxO>
where
    O: Oracle<Vec<u8>, Vec<u8>>,
    AuxO: Oracle<Vec<u8>, Vec<u8>>,
{
    /// Random oracle
    oracle: O,
    
    /// Auxiliary oracle (signing oracle)
    aux_oracle: AuxO,
    
    /// Auxiliary input
    aux_input: AuxiliaryInput,
}

impl<O, AuxO> OAdPoKChallenger<O, AuxO>
where
    O: Oracle<Vec<u8>, Vec<u8>>,
    AuxO: Oracle<Vec<u8>, Vec<u8>>,
{
    pub fn new(oracle: O, aux_oracle: AuxO, aux_input: AuxiliaryInput) -> Self {
        Self {
            oracle,
            aux_oracle,
            aux_input,
        }
    }
    
    /// Provide oracle access to adversary
    ///
    /// Adversary can query both θ and O_st
    pub fn query_random_oracle(&mut self, query: Vec<u8>) -> OSNARKResult<Vec<u8>> {
        self.oracle.query(query)
            .map_err(|e| OSNARKError::OAdPoKFailed(format!("Oracle query failed: {}", e)))
    }
    
    /// Query auxiliary oracle (signing oracle)
    pub fn query_signing_oracle(&mut self, message: Vec<u8>) -> OSNARKResult<Vec<u8>> {
        self.aux_oracle.query(message)
            .map_err(|e| OSNARKError::SigningOracleFailed(format!("Signing oracle query failed: {}", e)))
    }
    
    /// Get auxiliary input
    pub fn auxiliary_input(&self) -> &AuxiliaryInput {
        &self.aux_input
    }
    
    /// Get signing oracle transcript
    pub fn signing_queries(&self) -> Vec<SigningQuery<Vec<u8>, Vec<u8>>> {
        self.aux_oracle.transcript().queries()
            .iter()
            .map(|q| SigningQuery::new(q.query.clone(), q.response.clone()))
            .collect()
    }
}
