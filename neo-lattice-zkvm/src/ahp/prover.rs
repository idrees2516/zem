// AHP Prover Implementation

use crate::field::Field;
use super::types::*;
use super::polynomial::Polynomial;
use super::errors::{AHPError, AHPResult};

/// AHP Prover
///
/// Generates proofs in the AHP protocol.
pub struct AHPProver<F> {
    /// Prover state
    state: ProverState<F>,
    
    /// Parameters
    params: AHPParameters<F>,
}

impl<F: Field> AHPProver<F> {
    pub fn new(params: AHPParameters<F>) -> Self {
        Self {
            state: ProverState::new(),
            params,
        }
    }
    
    /// Generate proof for instance and witness
    pub fn prove(
        &mut self,
        instance: &AHPInstance<F>,
        witness: &AHPWitness<F>,
    ) -> AHPResult<AHPProof<F>> {
        let mut rounds = Vec::new();
        
        for round_num in 0..self.params.num_rounds {
            let round = self.prove_round(round_num, instance, witness)?;
            rounds.push(round);
            self.state.next_round();
        }
        
        let evaluations = self.generate_evaluations()?;
        
        Ok(AHPProof { rounds, evaluations })
    }
    
    fn prove_round(
        &mut self,
        round_num: usize,
        instance: &AHPInstance<F>,
        witness: &AHPWitness<F>,
    ) -> AHPResult<AHPRound<F>> {
        let prover_polynomials = self.compute_round_polynomials(round_num, instance, witness)?;
        
        for poly in &prover_polynomials {
            self.state.add_polynomial(poly.clone());
        }
        
        let verifier_challenges = vec![F::one(); round_num + 1];
        
        for challenge in &verifier_challenges {
            self.state.add_challenge(challenge.clone());
        }
        
        Ok(AHPRound {
            prover_polynomials,
            verifier_challenges,
            round_number: round_num,
        })
    }
    
    fn compute_round_polynomials(
        &self,
        round_num: usize,
        instance: &AHPInstance<F>,
        witness: &AHPWitness<F>,
    ) -> AHPResult<Vec<Vec<F>>> {
        let poly_coeffs = witness.witness_values.clone();
        Ok(vec![poly_coeffs])
    }
    
    fn generate_evaluations(&self) -> AHPResult<Vec<Evaluation<F>>> {
        let mut evaluations = Vec::new();
        
        for (idx, poly_coeffs) in self.state.committed_polynomials.iter().enumerate() {
            let poly = Polynomial::new(poly_coeffs.clone());
            let point = vec![F::one()];
            let value = poly.evaluate(&F::one());
            
            evaluations.push(Evaluation {
                point,
                value,
                polynomial_index: idx,
            });
        }
        
        Ok(evaluations)
    }
}
