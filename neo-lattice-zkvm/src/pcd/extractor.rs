// PCD Extractor with Breadth-First Traversal
//
// This module implements the PCD extractor that extracts witnesses
// using breadth-first traversal of the DAG.
//
// Mathematical Foundation (from Appendix A.1):
// The PCD extractor differs from IVC extractor in that it processes
// multiple (z, π) tuples per level instead of a single linear chain.
//
// Algorithm:
// 1. Start with output message and proof
// 2. Extract witness to get (w_loc, incoming_messages, incoming_proofs)
// 3. Add all incoming (message, proof) pairs to next level
// 4. Process all tuples in current level before moving to next
// 5. Reconstruct DAG from extracted vertices
//
// Key Difference from IVC:
// - IVC: Linear extraction (one predecessor per step)
// - PCD: Breadth-first extraction (multiple predecessors per vertex)

use std::marker::PhantomData;
use std::collections::{HashMap, VecDeque};
use crate::agm::GroupRepresentation;
use crate::oracle::{Oracle, OracleTranscript};
use crate::rel_snark::RelativizedSNARK;
use super::types::*;
use super::errors::*;
use super::transcript::PCDTranscript;
use super::compliance::PCDCircuit;

/// PCD Extractor
///
/// Extracts witnesses from a PCD proof using breadth-first traversal.
///
/// Type Parameters:
/// - F: Field type
/// - G: Group type
/// - O: Oracle type
/// - S: Relativized SNARK type
pub struct PCDExtractor<F, G, O, S>
where
    S: RelativizedSNARK<F, G, O>,
{
    /// SNARK public parameters
    pub pp: S::PublicParameters,
    
    /// PCD circuit
    pub circuit: PCDCircuit<F, O>,
    
    /// Phantom data
    _phantom: PhantomData<(G, S)>,
}

impl<F, G, O, S> PCDExtractor<F, G, O, S>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Create a new PCD extractor
    ///
    /// Parameters:
    /// - pp: SNARK public parameters
    /// - circuit: PCD circuit for extraction
    ///
    /// Returns:
    /// - New PCD extractor
    pub fn new(pp: S::PublicParameters, circuit: PCDCircuit<F, O>) -> Self {
        Self {
            pp,
            circuit,
            _phantom: PhantomData,
        }
    }
    
    /// Extract PCD witnesses using breadth-first extraction
    ///
    /// This is the main extraction algorithm from Appendix A.1.
    ///
    /// Mathematical Details:
    /// The extractor maintains a queue of (message, proof) tuples to process.
    /// For each tuple:
    /// 1. Extract witness using SNARK extractor
    /// 2. Parse witness to get (w_loc, incoming_messages, incoming_proofs)
    /// 3. Add vertex to reconstructed DAG
    /// 4. Add incoming tuples to queue
    /// 5. Continue until queue is empty (all base cases reached)
    ///
    /// Key Property:
    /// Uses single group representation Γ from initial adversary output
    /// for all extraction iterations (same as IVC).
    ///
    /// Parameters:
    /// - output_message: Output message from PCD computation
    /// - proof: SNARK proof for output message
    /// - prover_transcript: Oracle transcript from prover
    /// - group_representations: Group representations from algebraic adversary
    /// - oracle: Oracle for extraction
    ///
    /// Returns:
    /// - Reconstructed PCD transcript with all vertices and edges
    pub fn extract(
        &self,
        output_message: &[F],
        proof: &S::Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<F, G>,
        oracle: &mut O,
    ) -> PCDResult<PCDTranscript<F>> {
        // Initialize transcript for reconstructed DAG
        let mut transcript = PCDTranscript::new();
        
        // Queue of (message, proof, parent_vertex_id) tuples to process
        // parent_vertex_id is None for the initial output
        let mut queue: VecDeque<(Vec<F>, S::Proof, Option<VertexId>)> = VecDeque::new();
        queue.push_back((output_message.to_vec(), proof.clone(), None));
        
        // Map from message to vertex ID (to avoid duplicates)
        let mut message_to_vertex: HashMap<Vec<u8>, VertexId> = HashMap::new();
        
        // Process queue level by level (breadth-first)
        while !queue.is_empty() {
            // Process all tuples in current level
            let level_size = queue.len();
            
            for _ in 0..level_size {
                let (message, prf, parent_id) = queue.pop_front().unwrap();
                
                // Check if we've already processed this message
                let message_key = self.serialize_message(&message)?;
                if message_to_vertex.contains_key(&message_key) {
                    // Already processed, just add edge if needed
                    if let Some(parent) = parent_id {
                        let vertex_id = message_to_vertex[&message_key];
                        transcript.add_edge(vertex_id, parent, message.clone())?;
                    }
                    continue;
                }
                
                // Extract witness for this message
                let statement = self.build_statement(&message);
                let extracted_witness = S::extract(
                    &self.pp,
                    &self.circuit,
                    &statement,
                    &prf,
                    prover_transcript,
                    group_representations, // Same Γ for all iterations!
                ).map_err(|e| PCDError::ExtractionFailed(
                    format!("SNARK extraction failed: {:?}", e)
                ))?;
                
                // Parse extracted witness
                let (w_loc, incoming_messages, incoming_proofs) = 
                    self.parse_extracted_witness(&extracted_witness)?;
                
                // Add vertex to transcript
                let vertex_id = transcript.add_vertex(w_loc);
                message_to_vertex.insert(message_key, vertex_id);
                
                // Add edge from this vertex to parent (if exists)
                if let Some(parent) = parent_id {
                    transcript.add_edge_with_proof(
                        vertex_id,
                        parent,
                        message.clone(),
                        self.serialize_proof(&prf)?,
                    )?;
                }
                
                // Check if base case
                if incoming_messages.is_empty() {
                    // Base case reached, no more predecessors
                    continue;
                }
                
                // Add incoming messages to queue for next level
                for (inc_msg, inc_proof) in incoming_messages.iter().zip(incoming_proofs.iter()) {
                    queue.push_back((inc_msg.clone(), inc_proof.clone(), Some(vertex_id)));
                }
            }
        }
        
        // Verify transcript structure
        transcript.verify_structure()?;
        
        Ok(transcript)
    }
    
    /// Extract with level-wise processing
    ///
    /// Alternative extraction method that explicitly processes levels.
    /// This is more explicit about the breadth-first nature.
    ///
    /// Mathematical Details:
    /// Process vertices level by level:
    /// - Level 0: Output vertex
    /// - Level k: All vertices at distance k from output
    ///
    /// For each level:
    /// 1. Extract all vertices in parallel (conceptually)
    /// 2. Collect all incoming messages for next level
    /// 3. Move to next level
    ///
    /// Parameters:
    /// - output_message: Output message
    /// - proof: SNARK proof
    /// - prover_transcript: Oracle transcript
    /// - group_representations: Group representations
    /// - oracle: Oracle
    ///
    /// Returns:
    /// - Reconstructed PCD transcript
    pub fn extract_level_wise(
        &self,
        output_message: &[F],
        proof: &S::Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<F, G>,
        oracle: &mut O,
    ) -> PCDResult<PCDTranscript<F>> {
        let mut transcript = PCDTranscript::new();
        let mut current_level = vec![(output_message.to_vec(), proof.clone(), None)];
        let mut message_to_vertex: HashMap<Vec<u8>, VertexId> = HashMap::new();
        
        // Process level by level
        while !current_level.is_empty() {
            let mut next_level = Vec::new();
            
            // Process all tuples in current level
            for (message, prf, parent_id) in current_level {
                // Check for duplicates
                let message_key = self.serialize_message(&message)?;
                if message_to_vertex.contains_key(&message_key) {
                    if let Some(parent) = parent_id {
                        let vertex_id = message_to_vertex[&message_key];
                        transcript.add_edge(vertex_id, parent, message.clone())?;
                    }
                    continue;
                }
                
                // Extract witness
                let statement = self.build_statement(&message);
                let extracted_witness = S::extract(
                    &self.pp,
                    &self.circuit,
                    &statement,
                    &prf,
                    prover_transcript,
                    group_representations,
                ).map_err(|e| PCDError::ExtractionFailed(
                    format!("SNARK extraction failed: {:?}", e)
                ))?;
                
                // Parse witness
                let (w_loc, incoming_messages, incoming_proofs) = 
                    self.parse_extracted_witness(&extracted_witness)?;
                
                // Add vertex
                let vertex_id = transcript.add_vertex(w_loc);
                message_to_vertex.insert(message_key, vertex_id);
                
                // Add edge to parent
                if let Some(parent) = parent_id {
                    transcript.add_edge_with_proof(
                        vertex_id,
                        parent,
                        message.clone(),
                        self.serialize_proof(&prf)?,
                    )?;
                }
                
                // Add incoming messages to next level
                if !incoming_messages.is_empty() {
                    for (inc_msg, inc_proof) in incoming_messages.iter().zip(incoming_proofs.iter()) {
                        next_level.push((inc_msg.clone(), inc_proof.clone(), Some(vertex_id)));
                    }
                }
            }
            
            current_level = next_level;
        }
        
        transcript.verify_structure()?;
        Ok(transcript)
    }
    
    // ===== Helper Methods =====
    
    /// Build statement for SNARK extraction
    ///
    /// The statement contains the message being verified.
    ///
    /// Mathematical Details:
    /// The statement for PCD is the output message z_e.
    /// The SNARK proves that there exists a valid computation
    /// producing this message.
    fn build_statement(&self, message: &[F]) -> S::Statement {
        // Convert message to statement format
        // The statement is typically just the message itself
        // wrapped in the appropriate type
        
        // Since we don't have access to the actual Statement type constructor,
        // we use unsafe transmute as a workaround
        // In production, this would use proper serialization
        unsafe {
            std::ptr::read(message.as_ptr() as *const S::Statement)
        }
    }
    
    /// Parse extracted witness
    ///
    /// Parses the SNARK witness to extract:
    /// - w_loc: Local witness for the vertex
    /// - incoming_messages: Messages from incoming edges
    /// - incoming_proofs: Proofs for incoming messages
    ///
    /// Mathematical Details:
    /// The witness structure depends on the PCD circuit.
    /// For a vertex with M incoming edges:
    /// - w_loc: Local computation witness
    /// - (z_e1, π_1), ..., (z_eM, π_M): Incoming messages and proofs
    ///
    /// Witness Format:
    /// The witness is structured as:
    /// [w_loc_len, w_loc..., num_incoming, msg1_len, msg1..., proof1_len, proof1..., ...]
    ///
    /// Returns:
    /// - (w_loc, incoming_messages, incoming_proofs)
    fn parse_extracted_witness(
        &self,
        witness: &S::Witness,
    ) -> PCDResult<(Vec<F>, Vec<Vec<F>>, Vec<S::Proof>)> {
        // Serialize witness to bytes for parsing
        let witness_bytes = self.serialize_witness(witness)?;
        
        // Parse witness structure
        let mut offset = 0;
        
        // Read w_loc length
        if witness_bytes.len() < offset + 8 {
            return Err(PCDError::ExtractionFailed(
                "Witness too short to contain w_loc length".to_string()
            ));
        }
        let w_loc_len = usize::from_le_bytes(
            witness_bytes[offset..offset+8].try_into()
                .map_err(|_| PCDError::ExtractionFailed("Invalid w_loc length".to_string()))?
        );
        offset += 8;
        
        // Read w_loc
        let field_size = std::mem::size_of::<F>();
        if witness_bytes.len() < offset + w_loc_len * field_size {
            return Err(PCDError::ExtractionFailed(
                "Witness too short to contain w_loc".to_string()
            ));
        }
        let mut w_loc = Vec::with_capacity(w_loc_len);
        for _ in 0..w_loc_len {
            let field_bytes = &witness_bytes[offset..offset+field_size];
            let field_elem = self.deserialize_field_element(field_bytes)?;
            w_loc.push(field_elem);
            offset += field_size;
        }
        
        // Read number of incoming messages
        if witness_bytes.len() < offset + 8 {
            return Err(PCDError::ExtractionFailed(
                "Witness too short to contain num_incoming".to_string()
            ));
        }
        let num_incoming = usize::from_le_bytes(
            witness_bytes[offset..offset+8].try_into()
                .map_err(|_| PCDError::ExtractionFailed("Invalid num_incoming".to_string()))?
        );
        offset += 8;
        
        // Read incoming messages and proofs
        let mut incoming_messages = Vec::with_capacity(num_incoming);
        let mut incoming_proofs = Vec::with_capacity(num_incoming);
        
        for _ in 0..num_incoming {
            // Read message length
            if witness_bytes.len() < offset + 8 {
                return Err(PCDError::ExtractionFailed(
                    "Witness too short to contain message length".to_string()
                ));
            }
            let msg_len = usize::from_le_bytes(
                witness_bytes[offset..offset+8].try_into()
                    .map_err(|_| PCDError::ExtractionFailed("Invalid message length".to_string()))?
            );
            offset += 8;
            
            // Read message
            if witness_bytes.len() < offset + msg_len * field_size {
                return Err(PCDError::ExtractionFailed(
                    "Witness too short to contain message".to_string()
                ));
            }
            let mut message = Vec::with_capacity(msg_len);
            for _ in 0..msg_len {
                let field_bytes = &witness_bytes[offset..offset+field_size];
                let field_elem = self.deserialize_field_element(field_bytes)?;
                message.push(field_elem);
                offset += field_size;
            }
            incoming_messages.push(message);
            
            // Read proof length
            if witness_bytes.len() < offset + 8 {
                return Err(PCDError::ExtractionFailed(
                    "Witness too short to contain proof length".to_string()
                ));
            }
            let proof_len = usize::from_le_bytes(
                witness_bytes[offset..offset+8].try_into()
                    .map_err(|_| PCDError::ExtractionFailed("Invalid proof length".to_string()))?
            );
            offset += 8;
            
            // Read proof
            if witness_bytes.len() < offset + proof_len {
                return Err(PCDError::ExtractionFailed(
                    "Witness too short to contain proof".to_string()
                ));
            }
            let proof_bytes = &witness_bytes[offset..offset+proof_len];
            let proof = self.deserialize_proof(proof_bytes)?;
            incoming_proofs.push(proof);
            offset += proof_len;
        }
        
        Ok((w_loc, incoming_messages, incoming_proofs))
    }
    
    /// Serialize a message to bytes for deduplication
    ///
    /// Uses a deterministic serialization format to ensure
    /// identical messages produce identical byte sequences.
    fn serialize_message(&self, message: &[F]) -> PCDResult<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // Write message length
        bytes.extend_from_slice(&message.len().to_le_bytes());
        
        // Write each field element
        for elem in message {
            let elem_bytes = self.serialize_field_element(elem)?;
            bytes.extend_from_slice(&elem_bytes);
        }
        
        Ok(bytes)
    }
    
    /// Serialize a proof to bytes
    fn serialize_proof(&self, proof: &S::Proof) -> PCDResult<Vec<u8>> {
        // Use bincode for serialization
        bincode::serialize(proof)
            .map_err(|e| PCDError::SerializationError(format!("Failed to serialize proof: {}", e)))
    }
    
    /// Serialize a witness to bytes
    fn serialize_witness(&self, witness: &S::Witness) -> PCDResult<Vec<u8>> {
        bincode::serialize(witness)
            .map_err(|e| PCDError::SerializationError(format!("Failed to serialize witness: {}", e)))
    }
    
    /// Serialize a field element to bytes
    fn serialize_field_element(&self, elem: &F) -> PCDResult<Vec<u8>> {
        bincode::serialize(elem)
            .map_err(|e| PCDError::SerializationError(format!("Failed to serialize field element: {}", e)))
    }
    
    /// Deserialize a field element from bytes
    fn deserialize_field_element(&self, bytes: &[u8]) -> PCDResult<F> {
        bincode::deserialize(bytes)
            .map_err(|e| PCDError::DeserializationError(format!("Failed to deserialize field element: {}", e)))
    }
    
    /// Deserialize a proof from bytes
    fn deserialize_proof(&self, bytes: &[u8]) -> PCDResult<S::Proof> {
        bincode::deserialize(bytes)
            .map_err(|e| PCDError::DeserializationError(format!("Failed to deserialize proof: {}", e)))
    }
}

/// PCD Prover
///
/// Generates proofs for PCD computations.
pub struct PCDProver<F, G, O, S>
where
    S: RelativizedSNARK<F, G, O>,
{
    /// SNARK indexer key
    pub ipk: S::IndexerKey,
    
    /// SNARK public parameters
    pub pp: S::PublicParameters,
    
    /// PCD circuit
    pub circuit: PCDCircuit<F, O>,
    
    /// Phantom data
    _phantom: PhantomData<(G, S)>,
}

impl<F, G, O, S> PCDProver<F, G, O, S>
where
    F: Clone,
    G: Clone,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Create a new PCD prover
    pub fn new(
        ipk: S::IndexerKey,
        pp: S::PublicParameters,
        circuit: PCDCircuit<F, O>,
    ) -> Self {
        Self {
            ipk,
            pp,
            circuit,
            _phantom: PhantomData,
        }
    }
    
    /// Prove a PCD computation
    ///
    /// Generates a proof for the entire PCD transcript.
    ///
    /// Mathematical Details:
    /// For each vertex in topological order:
    /// 1. Collect incoming messages and proofs
    /// 2. Build witness (w_loc, incoming_messages, incoming_proofs)
    /// 3. Generate SNARK proof for this vertex
    /// 4. Store proof for use by successors
    ///
    /// Parameters:
    /// - transcript: PCD transcript to prove
    /// - oracle: Oracle for proving
    ///
    /// Returns:
    /// - PCD proof for the output message
    pub fn prove(
        &self,
        transcript: &PCDTranscript<F>,
        oracle: &mut O,
    ) -> PCDResult<PCDProof<F, S::Proof>> {
        // Get topological order
        let topo_order = transcript.graph.topological_sort()
            .ok_or(PCDError::CycleDetected)?;
        
        // Map from edge to proof
        let mut edge_proofs: HashMap<EdgeId, S::Proof> = HashMap::new();
        
        // Process vertices in topological order
        for &vertex_id in &topo_order {
            let vertex = transcript.get_vertex(vertex_id)?;
            
            // Get incoming messages and proofs
            let incoming_messages = transcript.get_incoming_messages(vertex_id);
            let incoming_proofs: Vec<S::Proof> = vertex.incoming_edges.iter()
                .filter_map(|&edge_id| edge_proofs.get(&edge_id).cloned())
                .collect();
            
            // Generate proof for each outgoing edge
            for &edge_id in &vertex.outgoing_edges {
                let edge = transcript.get_edge(edge_id)?;
                
                // Build statement and witness
                let statement = self.build_statement(&edge.message);
                let witness = self.build_witness(
                    &vertex.w_loc,
                    &incoming_messages,
                    &incoming_proofs,
                );
                
                // Generate SNARK proof
                let proof = S::prove(&self.ipk, &statement, &witness, oracle)
                    .map_err(|e| PCDError::InvalidProof(
                        format!("SNARK proving failed: {:?}", e)
                    ))?;
                
                edge_proofs.insert(edge_id, proof);
            }
        }
        
        // Get output message and proof
        let output_message = transcript.get_output_message()?;
        
        // Find the edge with the output message
        let output_edge_id = self.find_output_edge(transcript)?;
        let output_proof = edge_proofs.get(&output_edge_id)
            .ok_or(PCDError::InvalidProof("Output proof not found".to_string()))?
            .clone();
        
        // Build metadata
        let metadata = PCDMetadata {
            num_vertices: transcript.num_vertices(),
            num_edges: transcript.num_edges(),
            max_depth: transcript.max_depth(),
        };
        
        Ok(PCDProof::new(output_message, output_proof, metadata))
    }
    
    /// Build statement for SNARK proving
    ///
    /// The statement is the output message z_e.
    fn build_statement(&self, message: &[F]) -> S::Statement {
        // Convert message to statement format
        unsafe {
            std::ptr::read(message.as_ptr() as *const S::Statement)
        }
    }
    
    /// Build witness for SNARK proving
    ///
    /// Constructs the witness from:
    /// - w_loc: Local witness
    /// - incoming_messages: Messages from incoming edges
    /// - incoming_proofs: Proofs for incoming messages
    ///
    /// Witness Format:
    /// [w_loc_len, w_loc..., num_incoming, msg1_len, msg1..., proof1_len, proof1..., ...]
    fn build_witness(
        &self,
        w_loc: &[F],
        incoming_messages: &[Vec<F>],
        incoming_proofs: &[S::Proof],
    ) -> S::Witness {
        let mut witness_bytes = Vec::new();
        
        // Write w_loc length
        witness_bytes.extend_from_slice(&w_loc.len().to_le_bytes());
        
        // Write w_loc
        for elem in w_loc {
            let elem_bytes = bincode::serialize(elem).unwrap();
            witness_bytes.extend_from_slice(&elem_bytes);
        }
        
        // Write number of incoming messages
        witness_bytes.extend_from_slice(&incoming_messages.len().to_le_bytes());
        
        // Write incoming messages and proofs
        for (message, proof) in incoming_messages.iter().zip(incoming_proofs.iter()) {
            // Write message length
            witness_bytes.extend_from_slice(&message.len().to_le_bytes());
            
            // Write message
            for elem in message {
                let elem_bytes = bincode::serialize(elem).unwrap();
                witness_bytes.extend_from_slice(&elem_bytes);
            }
            
            // Write proof length
            let proof_bytes = bincode::serialize(proof).unwrap();
            witness_bytes.extend_from_slice(&proof_bytes.len().to_le_bytes());
            
            // Write proof
            witness_bytes.extend_from_slice(&proof_bytes);
        }
        
        // Deserialize to witness type
        bincode::deserialize(&witness_bytes).unwrap()
    }
    
    /// Find the edge containing the output message
    fn find_output_edge(&self, transcript: &PCDTranscript<F>) -> PCDResult<EdgeId> {
        // Find lexicographically-first edge to a sink
        let sinks = transcript.graph.sinks();
        let mut min_edge: Option<EdgeId> = None;
        
        for &sink_id in sinks {
            if let Some(vertex) = transcript.graph.get_vertex(sink_id) {
                for &edge_id in &vertex.incoming_edges {
                    let is_smaller = min_edge.as_ref().map_or(true, |min_id| {
                        edge_id < *min_id
                    });
                    
                    if is_smaller {
                        min_edge = Some(edge_id);
                    }
                }
            }
        }
        
        min_edge.ok_or(PCDError::InvalidDAG("No output edge found".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
