// Recursive Verification Circuit
//
// Mathematical Foundation (Section 4.2):
// Circuit [CV_λ]^θ checks:
//   1. Function application: F(z_in, w_loc) = z_out
//   2. Base case: dpt^≤_0(z_in) = ⊤ ⇒ z_in = z_0
//   3. Recursive case: V^θ(ivk, (ivk, z_0, z_in), π_in) = 1
//   4. Oracle forcing: θ(g) = r where g = group(z_in || π_in) \ group(tr_V)
//
// Key Innovation: Oracle forcing (step 4) ensures extraction works
// - Computes g = group(z_in || π_in) \ group(tr_V)
// - Verifies oracle queries match r
// - For Fiat-Shamir: g = ∅ (optimization)

use std::marker::PhantomData;

use crate::agm::{Group, GroupParser};
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::{RelativizedSNARK, VerifierKey, Statement, Proof};

use super::incremental_computation::IncrementalComputation;
use super::types::IVCState;
use super::errors::{IVCError, IVCResult};

/// Recursive Verification Circuit
///
/// Implements the circuit that checks one IVC step
pub struct RecursiveVerificationCircuit<F, G, O, S>
where
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// IVC verifier key
    ivk: VerifierKey,
    
    /// Function being computed incrementally
    computation: IncrementalComputation<F>,
    
    /// Group parser for oracle forcing
    group_parser: GroupParser<G>,
    
    /// Phantom data
    _phantom: PhantomData<(O, S)>,
}

impl<F, G, O, S> RecursiveVerificationCircuit<F, G, O, S>
where
    F: Clone + PartialEq,
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    pub fn new(
        ivk: VerifierKey,
        computation: IncrementalComputation<F>,
        group_parser: GroupParser<G>,
    ) -> Self {
        Self {
            ivk,
            computation,
            group_parser,
            _phantom: PhantomData,
        }
    }
    
    /// Circuit computation: [CV_λ]^θ
    ///
    /// Public inputs: (ivk, z_0, z_out)
    /// Private inputs: (w_loc, z_in, π_in, r)
    ///
    /// Checks:
    /// 1. F(z_in, w_loc) = z_out
    /// 2. Base case OR recursive verification
    /// 3. Oracle forcing: θ(g) = r
    ///
    /// Returns: true if all checks pass
    pub fn compute(
        &self,
        // Public inputs
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
        // Private inputs
        w_loc: &[F],
        z_in: &IVCState<F>,
        pi_in: Option<&Proof>,
        r: &[Vec<u8>],
        oracle: &mut O,
    ) -> IVCResult<bool> {
        // Check 1: Function application F(z_in, w_loc) = z_out
        let z_computed = self.computation.apply(&z_in.data, w_loc)?;
        if z_computed != z_out.data {
            return Ok(false);
        }
        
        // Check 2: Base case or recursive case
        if self.computation.is_base_case(&z_in.data) {
            // Base case: z_in = z_0
            if z_in.data != z_0.data {
                return Ok(false);
            }
        } else {
            // Recursive case: verify previous proof
            if let Some(prev_proof) = pi_in {
                let statement = self.build_statement(z_0, z_in)?;
                let verified = S::verify(&self.ivk, &statement, prev_proof, oracle)
                    .map_err(|e| IVCError::InvalidState(format!("Recursive verification failed: {}", e)))?;
                
                if !verified {
                    return Ok(false);
                }
            } else {
                // Non-base case must have previous proof
                return Ok(false);
            }
        }
        
        // Check 3: Oracle forcing
        // Compute g = group(z_in || π_in) \ group(tr_V)
        let g = self.compute_oracle_forcing_set(z_in, pi_in, oracle)?;
        
        // Verify oracle queries match r
        if !self.verify_oracle_responses(&g, r, oracle)? {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Compute oracle forcing set: g = group(z_in || π_in) \ group(tr_V)
    ///
    /// Mathematical steps:
    /// 1. Extract all group elements from (z_in, π_in)
    /// 2. Simulate verifier to get tr_V
    /// 3. Extract group elements from tr_V
    /// 4. Compute set difference
    fn compute_oracle_forcing_set(
        &self,
        z_in: &IVCState<F>,
        pi_in: Option<&Proof>,
        oracle: &mut O,
    ) -> IVCResult<Vec<G>> {
        // Serialize z_in and π_in
        let mut data = Vec::new();
        let zin_bytes = bincode::serialize(&z_in.data)
            .map_err(|e| IVCError::InvalidState(format!("z_in serialization failed: {}", e)))?;
        data.extend_from_slice(&zin_bytes);
        
        if let Some(p) = pi_in {
            data.extend_from_slice(&p.data);
        }
        
        // Extract group elements from (z_in, π_in)
        let all_elements = self.group_parser.parse(&data)
            .map_err(|e| IVCError::InvalidState(format!("Group parsing failed: {}", e)))?;
        
        // Get verifier transcript (simplified - in practice would simulate verifier)
        let tr_v = oracle.transcript();
        
        // Extract group elements from tr_V
        let tr_v_elements = self.extract_group_elements_from_transcript(tr_v)?;
        
        // Compute set difference
        Ok(self.group_parser.compute_oracle_forcing_set(all_elements, tr_v_elements))
    }
    
    /// Extract group elements from oracle transcript
    fn extract_group_elements_from_transcript(
        &self,
        transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> IVCResult<Vec<G>> {
        let mut elements = Vec::new();
        
        for query in transcript.queries() {
            if let Ok(element) = G::from_bytes(&query.query) {
                elements.push(element);
            }
        }
        
        Ok(elements)
    }
    
    /// Verify oracle responses match expected values
    ///
    /// For each g_i ∈ g: check θ(g_i) = r_i
    fn verify_oracle_responses(
        &self,
        elements: &[G],
        r: &[Vec<u8>],
        oracle: &mut O,
    ) -> IVCResult<bool> {
        if elements.len() != r.len() {
            return Ok(false);
        }
        
        for (i, element) in elements.iter().enumerate() {
            let query = self.group_parser.serialize_group_element(element);
            let response = oracle.query(query)
                .map_err(|e| IVCError::InvalidState(format!("Oracle query failed: {}", e)))?;
            
            if response != r[i] {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Build statement for recursive verification
    fn build_statement(
        &self,
        z_0: &IVCState<F>,
        z_in: &IVCState<F>,
    ) -> IVCResult<Statement> {
        let mut statement_data = Vec::new();
        
        // Add ivk
        statement_data.extend_from_slice(&self.ivk.data);
        
        // Add z_0
        let z0_bytes = bincode::serialize(&z_0.data)
            .map_err(|e| IVCError::InvalidState(format!("z_0 serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&z0_bytes);
        
        // Add z_in
        let zin_bytes = bincode::serialize(&z_in.data)
            .map_err(|e| IVCError::InvalidState(format!("z_in serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&zin_bytes);
        
        Ok(Statement::new(statement_data))
    }
    
    /// Get verifier key
    pub fn verifier_key(&self) -> &VerifierKey {
        &self.ivk
    }
    
    /// Get computation
    pub fn computation(&self) -> &IncrementalComputation<F> {
        &self.computation
    }
}
