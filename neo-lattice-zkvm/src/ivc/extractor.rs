// IVC Extractor with Straight-Line Extraction
//
// Mathematical Foundation (Figure 2 from paper):
// Ext(pp, z_0, z_out, π_out, tr_P̃, Γ):
//   Initialize: L ← [], compute circuit index i for CV_λ, x_out ← (pp, z_0, z_out), isLast ← 0
//   
//   While isLast = 0:
//     1. Extract: (w_loc, z_in, π_in, r^in) ← E(pp, i, x_out, π_out, tr_P̃, Γ)
//     2. Add to list: L ← L || (w_loc, z_out)
//     3. Check base case: if dpt^≤_0(z_in) = ⊤, set isLast ← 1
//     4. Update: x_out ← (pp, z_0, z_in), π_out ← π_in
//   
//   Return L
//
// Key Innovation: Uses SINGLE Γ for all iterations (avoids exponential blowup)
// - Initial adversary provides Γ for (z_out, π_out)
// - For iteration i-1: circuit accepts ⇒ (z_in, π_in) ∈ tr_P̃
// - Group elements in tr_P̃ have representations in Γ by parsing
// - No need to recursively compose representations

use std::marker::PhantomData;

use crate::agm::{Group, GroupRepresentation};
use crate::oracle::OracleTranscript;
use crate::rel_snark::{RelativizedSNARK, PublicParameters, Circuit, Statement, Proof, Witness};

use super::incremental_computation::IncrementalComputation;
use super::types::IVCState;
use super::errors::{IVCError, IVCResult};

/// IVC Extractor with straight-line extraction
///
/// Extracts witness chain without exponential blowup using single Γ
pub struct IVCExtractor<F, G, O, S>
where
    G: Group,
    O: crate::oracle::Oracle<Vec<u8>, Vec<u8>>,
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

impl<F, G, O, S> IVCExtractor<F, G, O, S>
where
    F: Clone,
    G: Group,
    O: crate::oracle::Oracle<Vec<u8>, Vec<u8>>,
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
    
    /// Extract witness chain: Ext(pp, z_0, z_out, π_out, tr_P̃, Γ) → [(w_i, z_i)]
    ///
    /// Mathematical steps:
    /// 1. Initialize empty list L and set current state
    /// 2. While not at base case:
    ///    a. Extract witness for current step using SNARK extractor
    ///    b. Parse extracted witness: (w_loc, z_in, π_in, r^in)
    ///    c. Add (w_loc, z_out) to L
    ///    d. Check if z_in is base case
    ///    e. Update current state to z_in
    /// 3. Return complete witness chain L
    ///
    /// Key Property: Uses SINGLE Γ for all iterations
    /// - Avoids exponential blowup from recursive composition
    /// - Group elements in (z_in, π_in) are in tr_P̃ by inductive guarantee
    /// - Representations found by parsing Γ
    pub fn extract(
        &self,
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
        proof_out: &Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<G>,
    ) -> IVCResult<Vec<(Vec<F>, Vec<F>)>> {
        // Initialize witness chain
        let mut witness_chain = Vec::new();
        
        // Current statement and proof
        let mut current_statement = self.build_statement(z_0, z_out)?;
        let mut current_proof = proof_out.clone();
        let mut current_z_out = z_out.data.clone();
        
        // Extraction loop
        let mut is_last = false;
        let mut iteration = 0;
        let max_iterations = 10000; // Safety bound
        
        while !is_last {
            if iteration >= max_iterations {
                return Err(IVCError::ExtractionFailed(
                    "Maximum iterations exceeded".to_string()
                ));
            }
            
            // Extract witness for current step using SNARK extractor
            // Uses SAME Γ for all iterations (key innovation)
            let extracted_witness = S::extract(
                &self.pp,
                &self.circuit,
                &current_statement,
                &current_proof,
                prover_transcript,
                group_representations,
            ).map_err(|e| IVCError::ExtractionFailed(format!("SNARK extraction failed: {}", e)))?;
            
            // Parse extracted witness: (w_loc, z_in, π_in, r^in)
            let (w_loc, z_in, pi_in, _r_in) = self.parse_extracted_witness(&extracted_witness)?;
            
            // Add (w_loc, z_out) to witness chain
            witness_chain.push((w_loc.clone(), current_z_out.clone()));
            
            // Check if z_in is base case
            if self.computation.is_base_case(&z_in) {
                is_last = true;
            } else {
                // Update for next iteration
                current_statement = self.build_statement(z_0, &IVCState::new(z_in.clone()))?;
                current_proof = pi_in;
                current_z_out = z_in;
            }
            
            iteration += 1;
        }
        
        Ok(witness_chain)
    }
    
    /// Parse extracted witness: (w_loc, z_in, π_in, r^in)
    ///
    /// Witness format: [w_loc || z_in || π_in || r^in]
    fn parse_extracted_witness(
        &self,
        witness: &Witness,
    ) -> IVCResult<(Vec<F>, Vec<F>, Proof, Vec<Vec<u8>>)> {
        let data = &witness.data;
        let mut offset = 0;
        
        // Parse w_loc
        let w_loc: Vec<F> = bincode::deserialize(&data[offset..])
            .map_err(|e| IVCError::InvalidWitness(format!("w_loc parsing failed: {}", e)))?;
        offset += bincode::serialized_size(&w_loc)
            .map_err(|e| IVCError::InvalidWitness(format!("w_loc size calculation failed: {}", e)))? as usize;
        
        // Parse z_in
        let z_in: Vec<F> = bincode::deserialize(&data[offset..])
            .map_err(|e| IVCError::InvalidWitness(format!("z_in parsing failed: {}", e)))?;
        offset += bincode::serialized_size(&z_in)
            .map_err(|e| IVCError::InvalidWitness(format!("z_in size calculation failed: {}", e)))? as usize;
        
        // Parse π_in (remaining data contains proof and r)
        // For simplicity, we extract proof data directly
        let remaining = &data[offset..];
        
        // Parse r^in (oracle responses)
        let r_in: Vec<Vec<u8>> = bincode::deserialize(remaining)
            .map_err(|e| IVCError::InvalidWitness(format!("r_in parsing failed: {}", e)))?;
        
        // Construct proof (simplified - in practice would parse properly)
        let pi_in = Proof::new(remaining.to_vec());
        
        Ok((w_loc, z_in, pi_in, r_in))
    }
    
    /// Build statement: (ivk, z_0, z_out)
    fn build_statement(
        &self,
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
    ) -> IVCResult<Statement> {
        let mut statement_data = Vec::new();
        
        // Add z_0
        let z0_bytes = bincode::serialize(&z_0.data)
            .map_err(|e| IVCError::InvalidState(format!("z_0 serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&z0_bytes);
        
        // Add z_out
        let zout_bytes = bincode::serialize(&z_out.data)
            .map_err(|e| IVCError::InvalidState(format!("z_out serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&zout_bytes);
        
        Ok(Statement::new(statement_data))
    }
    
    /// Verify extracted witness chain
    ///
    /// Checks: ∀i: z_i = F(z_{i-1}, w_i) and z_d = z_out
    pub fn verify_extracted_chain(
        &self,
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
        witness_chain: &[(Vec<F>, Vec<F>)],
    ) -> IVCResult<bool> {
        if witness_chain.is_empty() {
            return Ok(false);
        }
        
        let mut current_state = z_0.data.clone();
        
        // Verify each step
        for (w_i, z_i) in witness_chain {
            // Check: z_i = F(z_{i-1}, w_i)
            let computed_z_i = self.computation.apply(&current_state, w_i)?;
            
            if computed_z_i != *z_i {
                return Ok(false);
            }
            
            current_state = z_i.clone();
        }
        
        // Check final state matches z_out
        Ok(current_state == z_out.data)
    }
}
