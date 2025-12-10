// Aggregate Verification Circuit
//
// This module implements the circuit that verifies all individual signatures
// and checks oracle forcing consistency.
//
// Mathematical Foundation:
// The circuit checks two main properties:
// 1. All signatures verify: ∀i ∈ [n]: vfy^θ(vk_i, m_i, σ_i) = 1
// 2. Oracle forcing: θ(g) = r where g = group(σ_i) \ group(tr_Σ)
//
// Circuit Structure:
// - Public inputs: (vk_i, m_i) for i ∈ [n]
// - Private inputs: (σ_i) for i ∈ [n], and r (oracle responses)
// - Computation:
//   * For each i, check signature verification
//   * Compute oracle forcing set g
//   * Verify oracle queries match r

use std::marker::PhantomData;
use std::collections::HashSet;
use crate::oracle::{Oracle, OracleTranscript};
use crate::agm::GroupParser;
use super::types::*;
use super::errors::*;

/// Aggregate Verification Circuit
///
/// This circuit verifies that all individual signatures are valid
/// and that oracle forcing is correctly performed.
///
/// Type Parameters:
/// - F: Field type for circuit computations
/// - G: Group type for signatures
/// - O: Oracle type
pub struct AggregateVerificationCircuit<F, G, O> {
    /// Function to verify individual signatures
    /// Takes (vk, message, signature, oracle) and returns true if valid
    pub verify_signature: Box<dyn Fn(&VerificationKey<G>, &Message, &Signature<G>, &mut O) -> bool>,
    
    /// Group parser for extracting group elements
    group_parser: GroupParser<G, F>,
    
    /// Phantom data for type parameters
    _phantom: PhantomData<(F, O)>,
}

impl<F, G, O> AggregateVerificationCircuit<F, G, O>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
{
    /// Create a new aggregate verification circuit
    ///
    /// Parameters:
    /// - verify_signature: Function to verify individual signatures
    ///
    /// Returns:
    /// - New circuit instance
    pub fn new<V>(verify_signature: V) -> Self
    where
        V: Fn(&VerificationKey<G>, &Message, &Signature<G>, &mut O) -> bool + 'static,
    {
        Self {
            verify_signature: Box::new(verify_signature),
            group_parser: GroupParser::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Compute the circuit
    ///
    /// This is the main circuit computation that checks:
    /// 1. All signatures verify correctly
    /// 2. Oracle forcing is consistent
    ///
    /// Mathematical Details:
    /// The circuit implements the relation R^θ where:
    /// - Statement x = (vk_i, m_i)_{i∈[n]}
    /// - Witness w = ((σ_i)_{i∈[n]}, r)
    /// - R^θ(x, w) = 1 iff:
    ///   * ∀i ∈ [n]: vfy^θ(vk_i, m_i, σ_i) = 1
    ///   * θ(g) = r where g = group(σ_i) \ group(tr_Σ)
    ///
    /// The oracle forcing check ensures AGM security:
    /// - Compute g: group elements in signatures not queried by verifier
    /// - Verify prover queried these elements to oracle
    /// - Check oracle responses match the witness values r
    ///
    /// Parameters:
    /// - public_keys_messages: Public inputs (vk_i, m_i)
    /// - signatures: Private inputs (σ_i)
    /// - oracle_responses: Private inputs r (oracle responses for forced queries)
    /// - oracle: Oracle for verification
    ///
    /// Returns:
    /// - true if circuit accepts, false otherwise
    pub fn compute(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        signatures: &[Signature<G>],
        oracle_responses: &[Vec<u8>],
        oracle: &mut O,
    ) -> AggregateSignatureResult<bool> {
        let n = public_keys_messages.len();
        
        // Check 1: Verify signature count matches
        if signatures.len() != n {
            return Ok(false);
        }
        
        // Check 2: Verify all signatures
        // For each (vk_i, m_i, σ_i), check that vfy^θ(vk_i, m_i, σ_i) = 1
        for i in 0..n {
            let (vk, msg) = &public_keys_messages[i];
            let sig = &signatures[i];
            
            // Run signature verification with oracle access
            let verified = (self.verify_signature)(vk, msg, sig, oracle);
            
            if !verified {
                // Signature verification failed
                return Ok(false);
            }
        }
        
        // Check 3: Oracle forcing
        // Compute g = group(σ_i)_{i∈[n]} \ group(tr_Σ)
        // and verify θ(g) = r
        let oracle_forcing_valid = self.check_oracle_forcing(
            public_keys_messages,
            signatures,
            oracle_responses,
            oracle,
        )?;
        
        if !oracle_forcing_valid {
            return Ok(false);
        }
        
        // All checks passed
        Ok(true)
    }
    
    /// Check oracle forcing consistency
    ///
    /// This method implements the oracle forcing check from the AGM modification.
    ///
    /// Mathematical Details:
    /// 1. Extract all group elements from signatures: group(σ_i)_{i∈[n]}
    /// 2. Simulate verifier to get transcript tr_Σ
    /// 3. Extract group elements from transcript: group(tr_Σ)
    /// 4. Compute forcing set: g = group(σ_i) \ group(tr_Σ)
    /// 5. For each g_j ∈ g, verify θ(g_j) = r_j
    ///
    /// The forcing set g contains group elements that appear in signatures
    /// but were not queried by the verifier. The prover must explicitly
    /// query these to the oracle and provide the responses in the witness.
    ///
    /// Optimization: For Fiat-Shamir signatures, the verifier typically
    /// queries the entire signature, so g = ∅ (zero overhead).
    ///
    /// Parameters:
    /// - public_keys_messages: Public inputs
    /// - signatures: Signature witness
    /// - oracle_responses: Oracle response witness
    /// - oracle: Oracle for queries
    ///
    /// Returns:
    /// - true if oracle forcing is consistent, false otherwise
    fn check_oracle_forcing(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        signatures: &[Signature<G>],
        oracle_responses: &[Vec<u8>],
        oracle: &mut O,
    ) -> AggregateSignatureResult<bool> {
        // Step 1: Extract all group elements from signatures
        let all_sig_elements = self.extract_all_signature_elements(
            public_keys_messages,
            signatures,
        )?;
        
        // Step 2: Compute verifier transcript
        // Simulate running the verifier to see which elements it queries
        let tr_sig = self.compute_verifier_transcript(
            public_keys_messages,
            signatures,
            oracle,
        )?;
        
        // Step 3: Extract group elements from transcript
        let tr_sig_elements = self.extract_group_elements_from_transcript(&tr_sig)?;
        
        // Step 4: Compute oracle forcing set g
        let g = self.compute_oracle_forcing_set(&all_sig_elements, &tr_sig_elements);
        
        // Step 5: Verify oracle responses match
        if g.len() != oracle_responses.len() {
            // Mismatch in number of forced queries
            return Ok(false);
        }
        
        // For each element in g, verify the oracle response
        for (i, g_elem) in g.iter().enumerate() {
            // Serialize the group element for oracle query
            let query = self.serialize_group_element(g_elem)?;
            
            // Query the oracle
            let expected_response = oracle.query(query);
            
            // Check if it matches the witness
            if expected_response != oracle_responses[i] {
                // Oracle response mismatch
                return Ok(false);
            }
        }
        
        // All oracle responses match
        Ok(true)
    }
    
    /// Extract all group elements from signatures
    ///
    /// Parses verification keys and signatures to extract all group elements.
    fn extract_all_signature_elements(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        signatures: &[Signature<G>],
    ) -> AggregateSignatureResult<Vec<G>> {
        let mut all_elements = Vec::new();
        
        for i in 0..public_keys_messages.len() {
            let (vk, _msg) = &public_keys_messages[i];
            let sig = &signatures[i];
            
            // Extract from verification key
            all_elements.push(vk.key.clone());
            
            // Extract from signature
            all_elements.extend(sig.elements.clone());
        }
        
        Ok(all_elements)
    }
    
    /// Compute verifier transcript
    ///
    /// Simulates running the signature verifier for each signature
    /// to collect all oracle queries.
    ///
    /// Mathematical Details:
    /// For each signature σ_i:
    /// - Run vfy^θ(vk_i, m_i, σ_i) with a cloned oracle
    /// - Collect all queries made to the oracle
    /// - Merge into combined transcript tr_Σ
    fn compute_verifier_transcript(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        signatures: &[Signature<G>],
        oracle: &mut O,
    ) -> AggregateSignatureResult<OracleTranscript<Vec<u8>, Vec<u8>>> {
        let mut combined_transcript = OracleTranscript::new();
        
        for i in 0..public_keys_messages.len() {
            let (vk, msg) = &public_keys_messages[i];
            let sig = &signatures[i];
            
            // Clone oracle to simulate verification
            let mut verifier_oracle = oracle.clone();
            
            // Run verification
            let _verified = (self.verify_signature)(vk, msg, sig, &mut verifier_oracle);
            
            // Merge transcript
            combined_transcript.merge(verifier_oracle.transcript());
        }
        
        Ok(combined_transcript)
    }
    
    /// Extract group elements from oracle transcript
    ///
    /// Parses the transcript to find group elements that were queried.
    fn extract_group_elements_from_transcript(
        &self,
        transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> AggregateSignatureResult<Vec<G>> {
        let mut elements = Vec::new();
        
        for query in transcript.queries() {
            // Try to parse query as group element
            if let Ok(elem) = self.group_parser.try_parse_group_element(&query.query) {
                elements.push(elem);
            }
            
            // Try to parse response as group element
            if let Ok(elem) = self.group_parser.try_parse_group_element(&query.response) {
                elements.push(elem);
            }
        }
        
        Ok(elements)
    }
    
    /// Compute oracle forcing set
    ///
    /// Computes g = group(σ_i) \ group(tr_Σ)
    ///
    /// Mathematical Details:
    /// The forcing set contains all group elements that appear in signatures
    /// but were not queried by the verifier. These must be explicitly queried
    /// to ensure AGM security.
    ///
    /// For Fiat-Shamir signatures where the verifier queries the entire
    /// signature to the random oracle, g = ∅ (zero overhead).
    fn compute_oracle_forcing_set(
        &self,
        all_elements: &[G],
        transcript_elements: &[G],
    ) -> Vec<G> {
        // Convert transcript elements to set for efficient lookup
        let transcript_set: HashSet<_> = transcript_elements.iter().collect();
        
        // Filter elements not in transcript
        all_elements
            .iter()
            .filter(|elem| !transcript_set.contains(elem))
            .cloned()
            .collect()
    }
    
    /// Serialize a group element to bytes
    fn serialize_group_element(&self, elem: &G) -> AggregateSignatureResult<Vec<u8>> {
        self.group_parser.serialize_group_element(elem)
            .map_err(|e| AggregateSignatureError::SerializationError(
                format!("Failed to serialize group element: {:?}", e)
            ))
    }
}

/// Circuit trait implementation
///
/// This allows the aggregate verification circuit to be used as a circuit
/// in the SNARK system.
pub trait Circuit<F, G, O> {
    /// Compute the circuit on given inputs
    fn compute(
        &self,
        public_inputs: &[(VerificationKey<G>, Message)],
        private_inputs: &AggregateWitness<G>,
        oracle: &mut O,
    ) -> AggregateSignatureResult<bool>;
}

impl<F, G, O> Circuit<F, G, O> for AggregateVerificationCircuit<F, G, O>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
{
    fn compute(
        &self,
        public_inputs: &[(VerificationKey<G>, Message)],
        private_inputs: &AggregateWitness<G>,
        oracle: &mut O,
    ) -> AggregateSignatureResult<bool> {
        self.compute(
            public_inputs,
            &private_inputs.signatures,
            &private_inputs.oracle_responses,
            oracle,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
