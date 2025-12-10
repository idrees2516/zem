// IVC Prover with AGM Modifications
//
// Mathematical Foundation (Figure 1 from paper):
// P^θ(ipk, z_0, z_i, (w_i, z_{i-1}, π_{i-1})):
//   1. Forward all oracle queries to θ
//   2. Simulate verifier: V^θ(pp, (pp, z_0, z_{i-1}), π_{i-1}) to get tr_V
//   3. Extract group elements: all_elements = group(z_{i-1} || π_{i-1})
//   4. Compute forcing set: g = all_elements \ group(tr_V)
//   5. Force oracle queries: r ← θ(g)
//   6. Generate proof: π_i ← P^θ(ipk, (ivk, z_0, z_i); w_i, z_{i-1}, π_{i-1}, r)
//
// Key Innovation: Oracle forcing ensures group representations available for extraction
// For Fiat-Shamir: g = ∅ (zero overhead) since verifier queries entire (statement, proof)

use std::marker::PhantomData;

use crate::agm::{Group, GroupParser};
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::{RelativizedSNARK, IndexerKey, VerifierKey, Statement, Witness, Proof};

use super::incremental_computation::IncrementalComputation;
use super::types::{IVCState, IVCWitness};
use super::errors::{IVCError, IVCResult};

/// IVC Prover with AGM modifications
///
/// Implements the prover algorithm from Figure 1 with oracle forcing
pub struct IVCProver<F, G, O, S>
where
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Indexer key (prover key)
    ipk: IndexerKey,
    
    /// Public parameters
    pp: Vec<u8>,
    
    /// Group parser for extracting elements
    group_parser: GroupParser<G>,
    
    /// Incremental computation
    computation: IncrementalComputation<F>,
    
    /// Phantom data
    _phantom: PhantomData<(O, S)>,
}

impl<F, G, O, S> IVCProver<F, G, O, S>
where
    F: Clone,
    G: Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    pub fn new(
        ipk: IndexerKey,
        pp: Vec<u8>,
        group_parser: GroupParser<G>,
        computation: IncrementalComputation<F>,
    ) -> Self {
        Self {
            ipk,
            pp,
            group_parser,
            computation,
            _phantom: PhantomData,
        }
    }
    
    /// Prove IVC step: P^θ(ipk, z_0, z_i, (w_i, z_{i-1}, π_{i-1})) → π_i
    ///
    /// Mathematical steps:
    /// 1. Simulate verifier to get tr_V
    /// 2. Compute g = group(z_{i-1} || π_{i-1}) \ group(tr_V)
    /// 3. Force oracle queries: r ← θ(g)
    /// 4. Build witness: (w_i, z_{i-1}, π_{i-1}, r)
    /// 5. Generate proof using underlying SNARK
    pub fn prove_step(
        &self,
        z_0: &IVCState<F>,
        z_i: &IVCState<F>,
        w_i: &[F],
        z_prev: &IVCState<F>,
        pi_prev: Option<&Proof>,
        ivk: &VerifierKey,
        oracle: &mut O,
    ) -> IVCResult<Proof> {
        // Step 1: Simulate verifier to get tr_V
        let tr_v = if let Some(prev_proof) = pi_prev {
            self.simulate_verifier(z_0, z_prev, prev_proof, ivk, oracle)?
        } else {
            // Base case: no previous proof
            OracleTranscript::new()
        };
        
        // Step 2: Extract group elements from (z_{i-1}, π_{i-1})
        let statement_proof_bytes = self.serialize_statement_proof(z_prev, pi_prev)?;
        let all_group_elements = self.group_parser
            .parse(&statement_proof_bytes)
            .map_err(|e| IVCError::InvalidState(format!("Group parsing failed: {}", e)))?;
        
        // Step 3: Extract group elements from tr_V
        let tr_v_elements = self.extract_group_elements_from_transcript(&tr_v)?;
        
        // Step 4: Compute forcing set g = group(z_{i-1} || π_{i-1}) \ group(tr_V)
        let g = self.group_parser.compute_oracle_forcing_set(
            all_group_elements,
            tr_v_elements,
        );
        
        // Step 5: Force oracle queries r ← θ(g)
        let r = self.force_oracle_queries(&g, oracle)?;
        
        // Step 6: Build statement and witness
        let statement = self.build_statement(ivk, z_0, z_i)?;
        let witness = self.build_witness(w_i, z_prev, pi_prev, &r)?;
        
        // Step 7: Generate proof using underlying SNARK
        S::prove(&self.ipk, &statement, &witness, oracle)
            .map_err(|e| IVCError::InvalidState(format!("SNARK proving failed: {}", e)))
    }
    
    /// Simulate verifier to obtain transcript tr_V
    ///
    /// Runs V^θ(ivk, (ivk, z_0, z_{i-1}), π_{i-1}) and captures oracle queries
    fn simulate_verifier(
        &self,
        z_0: &IVCState<F>,
        z_prev: &IVCState<F>,
        pi_prev: &Proof,
        ivk: &VerifierKey,
        oracle: &mut O,
    ) -> IVCResult<OracleTranscript<Vec<u8>, Vec<u8>>> {
        // Clone oracle to capture transcript
        let mut verifier_oracle = oracle.clone();
        
        // Build statement for previous step
        let statement = self.build_statement(ivk, z_0, z_prev)?;
        
        // Run verifier (result doesn't matter, we just need transcript)
        let _ = S::verify(ivk, &statement, pi_prev, &mut verifier_oracle);
        
        // Return captured transcript
        Ok(verifier_oracle.transcript().clone())
    }
    
    /// Force oracle queries for group elements
    ///
    /// For each g_i ∈ g: r_i ← θ(g_i)
    fn force_oracle_queries(
        &self,
        elements: &[G],
        oracle: &mut O,
    ) -> IVCResult<Vec<Vec<u8>>> {
        let mut responses = Vec::with_capacity(elements.len());
        
        for element in elements {
            let query = self.group_parser.serialize_group_element(element);
            let response = oracle.query(query)
                .map_err(|e| IVCError::InvalidState(format!("Oracle query failed: {}", e)))?;
            responses.push(response);
        }
        
        Ok(responses)
    }
    
    /// Extract group elements from oracle transcript
    fn extract_group_elements_from_transcript(
        &self,
        transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> IVCResult<Vec<G>> {
        let mut elements = Vec::new();
        
        for query in transcript.queries() {
            // Try to parse query as group element
            if let Ok(element) = G::from_bytes(&query.query) {
                elements.push(element);
            }
        }
        
        Ok(elements)
    }
    
    /// Serialize statement and proof for group element extraction
    fn serialize_statement_proof(
        &self,
        state: &IVCState<F>,
        proof: Option<&Proof>,
    ) -> IVCResult<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // Serialize state
        let state_bytes = bincode::serialize(&state.data)
            .map_err(|e| IVCError::InvalidState(format!("State serialization failed: {}", e)))?;
        bytes.extend_from_slice(&state_bytes);
        
        // Serialize proof if present
        if let Some(p) = proof {
            bytes.extend_from_slice(&p.data);
        }
        
        Ok(bytes)
    }
    
    /// Build statement: (ivk, z_0, z_i)
    fn build_statement(
        &self,
        ivk: &VerifierKey,
        z_0: &IVCState<F>,
        z_i: &IVCState<F>,
    ) -> IVCResult<Statement> {
        let mut statement_data = Vec::new();
        
        // Add ivk
        statement_data.extend_from_slice(&ivk.data);
        
        // Add z_0
        let z0_bytes = bincode::serialize(&z_0.data)
            .map_err(|e| IVCError::InvalidState(format!("z_0 serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&z0_bytes);
        
        // Add z_i
        let zi_bytes = bincode::serialize(&z_i.data)
            .map_err(|e| IVCError::InvalidState(format!("z_i serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&zi_bytes);
        
        Ok(Statement::new(statement_data))
    }
    
    /// Build witness: (w_i, z_{i-1}, π_{i-1}, r)
    fn build_witness(
        &self,
        w_i: &[F],
        z_prev: &IVCState<F>,
        pi_prev: Option<&Proof>,
        r: &[Vec<u8>],
    ) -> IVCResult<Witness> {
        let mut witness_data = Vec::new();
        
        // Add w_i
        let wi_bytes = bincode::serialize(w_i)
            .map_err(|e| IVCError::InvalidWitness(format!("w_i serialization failed: {}", e)))?;
        witness_data.extend_from_slice(&wi_bytes);
        
        // Add z_{i-1}
        let zprev_bytes = bincode::serialize(&z_prev.data)
            .map_err(|e| IVCError::InvalidState(format!("z_prev serialization failed: {}", e)))?;
        witness_data.extend_from_slice(&zprev_bytes);
        
        // Add π_{i-1}
        if let Some(p) = pi_prev {
            witness_data.extend_from_slice(&p.data);
        }
        
        // Add r (oracle responses)
        let r_bytes = bincode::serialize(r)
            .map_err(|e| IVCError::InvalidState(format!("r serialization failed: {}", e)))?;
        witness_data.extend_from_slice(&r_bytes);
        
        Ok(Witness::new(witness_data))
    }
    
    /// Get indexer key
    pub fn indexer_key(&self) -> &IndexerKey {
        &self.ipk
    }
    
    /// Get public parameters
    pub fn public_parameters(&self) -> &[u8] {
        &self.pp
    }
}
