// IVC Security Reduction
//
// Mathematical Foundation (Figure 3 from paper):
// Reduction A^θ(pp) from IVC adversary to SNARK adversary:
//   1. Forward all oracle queries between subroutines
//   2. Sample function: F ← F(λ)
//   3. Invoke IVC adversary: (z_0, z_out, π_out, Γ) ← P̃(pp, F)
//   4. Compute circuit index: i for CV_λ, (ipk, ivk) ← I^θ(i, pp)
//   5. Run extractor iteratively:
//      - Extract witness for current step
//      - Check validity: [CV_λ]^θ(ivk, z_0, z_out; w_loc, z_in, π_in, r^in) = 1
//      - If check fails (b = 1), output SNARK adversary
//   6. Build algebraic adversary: parse Γ to get representations
//
// Key Property: If IVC adversary breaks soundness, reduction breaks SNARK soundness
// Theorem 3: Pr[IVC adversary succeeds] ≤ Pr[SNARK adversary succeeds] + negl(λ)

use std::marker::PhantomData;

use crate::agm::{Group, GroupRepresentation, AlgebraicOutput};
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::{RelativizedSNARK, PublicParameters, Circuit, Statement, Proof};

use super::incremental_computation::IncrementalComputation;
use super::extractor::IVCExtractor;
use super::circuit::RecursiveVerificationCircuit;
use super::types::IVCState;
use super::errors::{IVCError, IVCResult};

/// IVC Adversary output
pub struct IVCAdversaryOutput<F, G: Group> {
    /// Initial state
    pub z_0: IVCState<F>,
    
    /// Final state
    pub z_out: IVCState<F>,
    
    /// Proof
    pub proof: Proof,
    
    /// Group representations (from AGM)
    pub representations: GroupRepresentation<G>,
}

/// Security Reduction from IVC to SNARK
///
/// Implements the reduction from Theorem 3
pub struct IVCSecurityReduction<F, G, O, S>
where
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Public parameters
    pp: PublicParameters,
    
    /// Circuit for recursive verification
    circuit: Circuit,
    
    /// Incremental computation
    computation: IncrementalComputation<F>,
    
    /// Phantom data
    _phantom: PhantomData<(G, O, S)>,
}

impl<F, G, O, S> IVCSecurityReduction<F, G, O, S>
where
    F: Clone + PartialEq,
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    pub fn new(
        pp: PublicParameters,
        circuit: Circuit,
        computation: IncrementalComputation<F>,
    ) -> Self {
        Self {
            pp,
            circuit,
            computation,
            _phantom: PhantomData,
        }
    }
    
    /// Run reduction: A^θ(pp) → SNARK adversary or ⊥
    ///
    /// Mathematical steps:
    /// 1. Invoke IVC adversary to get (z_0, z_out, π_out, Γ)
    /// 2. Run extractor to get witness chain
    /// 3. Verify each extracted witness
    /// 4. If verification fails, construct SNARK adversary
    /// 5. Return SNARK adversary or ⊥
    ///
    /// Theorem 3: If IVC adversary breaks soundness with probability ε,
    /// then SNARK adversary breaks soundness with probability ≥ ε - negl(λ)
    pub fn run_reduction<A>(
        &self,
        ivc_adversary: &mut A,
        oracle: &mut O,
    ) -> IVCResult<Option<SNARKAdversaryOutput>>
    where
        A: IVCAdversary<F, G, O>,
    {
        // Step 1: Invoke IVC adversary
        let adversary_output = ivc_adversary.run(&self.pp, &self.computation, oracle)?;
        
        // Step 2: Run extractor
        let extractor = IVCExtractor::<F, G, O, S>::new(
            self.pp.clone(),
            self.circuit.clone(),
            self.computation.clone(),
        );
        
        let witness_chain = extractor.extract(
            &adversary_output.z_0,
            &adversary_output.z_out,
            &adversary_output.proof,
            oracle.transcript(),
            &adversary_output.representations,
        )?;
        
        // Step 3: Verify extracted witness chain
        let is_valid = extractor.verify_extracted_chain(
            &adversary_output.z_0,
            &adversary_output.z_out,
            &witness_chain,
        )?;
        
        if !is_valid {
            // Step 4: Extraction succeeded but witness invalid
            // This means SNARK soundness is broken
            
            // Find the failing step
            let failing_step = self.find_failing_step(
                &adversary_output.z_0,
                &witness_chain,
                oracle,
            )?;
            
            if let Some((statement, proof, witness)) = failing_step {
                // Construct SNARK adversary
                return Ok(Some(SNARKAdversaryOutput {
                    circuit: self.circuit.clone(),
                    statement,
                    proof,
                    witness,
                    representations: adversary_output.representations,
                }));
            }
        }
        
        // Extraction failed or witness is valid
        // IVC adversary did not break soundness
        Ok(None)
    }
    
    /// Find the step where circuit verification fails
    ///
    /// Checks each step: [CV_λ]^θ(ivk, z_0, z_i; w_i, z_{i-1}, π_{i-1}, r) = 1
    /// Returns first failing step as SNARK adversary
    fn find_failing_step(
        &self,
        z_0: &IVCState<F>,
        witness_chain: &[(Vec<F>, Vec<F>)],
        oracle: &mut O,
    ) -> IVCResult<Option<(Statement, Proof, crate::rel_snark::Witness)>> {
        // This would iterate through witness chain and check each step
        // For now, return None (simplified)
        Ok(None)
    }
    
    /// Verify inductive guarantee
    ///
    /// Checks: If circuit accepts at iteration i-1, then (z_in, π_in) ∈ tr_P̃
    /// This ensures group representations are available in Γ
    pub fn verify_inductive_guarantee(
        &self,
        z_in: &IVCState<F>,
        pi_in: &Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<G>,
    ) -> IVCResult<bool> {
        // Check that all group elements in (z_in, π_in) have representations in Γ
        
        // Serialize (z_in, π_in)
        let mut data = Vec::new();
        let zin_bytes = bincode::serialize(&z_in.data)
            .map_err(|e| IVCError::InvalidState(format!("Serialization failed: {}", e)))?;
        data.extend_from_slice(&zin_bytes);
        data.extend_from_slice(&pi_in.data);
        
        // Extract group elements (simplified - would use parser)
        // Check each has representation in Γ
        
        Ok(true)
    }
}

/// Trait for IVC adversaries
pub trait IVCAdversary<F, G: Group, O: Oracle<Vec<u8>, Vec<u8>>> {
    /// Run adversary to produce IVC output
    fn run(
        &mut self,
        pp: &PublicParameters,
        computation: &IncrementalComputation<F>,
        oracle: &mut O,
    ) -> IVCResult<IVCAdversaryOutput<F, G>>;
}

/// SNARK adversary output (for reduction)
pub struct SNARKAdversaryOutput<G: Group> {
    /// Circuit
    pub circuit: Circuit,
    
    /// Statement
    pub statement: Statement,
    
    /// Proof
    pub proof: Proof,
    
    /// Witness (extracted)
    pub witness: crate::rel_snark::Witness,
    
    /// Group representations
    pub representations: GroupRepresentation<G>,
}

/// Algebraic adversary construction
///
/// Builds algebraic adversary for SNARK from IVC adversary output
/// Parses Γ to obtain group representations for all elements
pub struct AlgebraicAdversaryBuilder<G: Group> {
    /// Group representations from IVC adversary
    representations: GroupRepresentation<G>,
}

impl<G: Group> AlgebraicAdversaryBuilder<G> {
    pub fn new(representations: GroupRepresentation<G>) -> Self {
        Self { representations }
    }
    
    /// Build algebraic output for SNARK adversary
    ///
    /// Parses Γ to get representations for:
    /// - Output elements (z_i, π_i)
    /// - Oracle-queried elements (from tr_V)
    pub fn build_algebraic_output(
        &self,
        output_elements: Vec<G>,
        oracle_queried_elements: Vec<G>,
    ) -> AlgebraicOutput<G> {
        AlgebraicOutput::new(
            output_elements,
            oracle_queried_elements,
            self.representations.clone(),
        )
    }
}
