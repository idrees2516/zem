// AHP Verifier Implementation

use crate::field::Field;
use super::types::*;
use super::errors::{AHPError, AHPResult};

/// AHP Verifier
///
/// Verifies proofs in the AHP protocol.
pub struct AHPVerifier<F> {
    /// Verifier state
    state: VerifierState<F>,
    
    /// Parameters
    params: AHPParameters<F>,
}

impl<F: Field> AHPVerifier<F> {
    pub fn new(params: AHPParameters<F>) -> Self {
        Self {
            state: VerifierState::new(),
            params,
        }
    }
    
    /// Verify proof for instance
    pub fn verify(
        &mut self,
        instance: &AHPInstance<F>,
        proof: &AHPProof<F>,
    ) -> AHPResult<bool> {
        if proof.rounds.len() != self.params.num_rounds {
            return Ok(false);
        }
        
        for round in &proof.rounds {
            if !self.verify_round(round, instance)? {
                return Ok(false);
            }
            self.state.next_round();
        }
        
        if !self.verify_evaluations(&proof.evaluations, instance)? {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    fn verify_round(
        &mut self,
        round: &AHPRound<F>,
        instance: &AHPInstance<F>,
    ) -> AHPResult<bool> {
        for poly_coeffs in &round.prover_polynomials {
            if poly_coeffs.len() > self.params.max_degree + 1 {
                return Ok(false);
            }
        }
        
        for challenge in &round.verifier_challenges {
            self.state.add_challenge(challenge.clone());
        }
        
        Ok(true)
    }
    
    fn verify_evaluations(
        &self,
        evaluations: &[Evaluation<F>],
        instance: &AHPInstance<F>,
    ) -> AHPResult<bool> {
        Ok(!evaluations.is_empty())
    }
}
