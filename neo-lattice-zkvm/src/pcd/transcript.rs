// PCD Transcript Management
//
// This module manages PCD transcripts, which represent the computation
// as a directed acyclic graph (DAG).

use super::types::*;
use super::errors::*;

/// PCD Transcript
///
/// Represents a PCD computation as a DAG.
/// The transcript contains:
/// - Vertices labeled by local witnesses w_loc
/// - Edges labeled by messages z_e
/// - Proofs for each edge's message
///
/// Mathematical Foundation:
/// - Each vertex v has local witness w_loc
/// - Each edge e = (u, v) has message z_e
/// - Compliance predicate ϕ^θ(z_e, w_loc, z) checks computation
///   where z = (z_e1, ..., z_eM) are incoming messages
#[derive(Clone, Debug)]
pub struct PCDTranscript<F> {
    /// The DAG structure
    pub graph: DirectedAcyclicGraph<F>,
    
    /// Output message (from lexicographically-first edge to sink)
    output_message: Option<Vec<F>>,
}

impl<F: Clone> PCDTranscript<F> {
    /// Create a new empty PCD transcript
    pub fn new() -> Self {
        Self {
            graph: DirectedAcyclicGraph::new(),
            output_message: None,
        }
    }
    
    /// Add a vertex to the transcript
    ///
    /// Parameters:
    /// - w_loc: Local witness for the vertex
    ///
    /// Returns:
    /// - Vertex ID
    pub fn add_vertex(&mut self, w_loc: Vec<F>) -> VertexId {
        self.graph.add_vertex(w_loc)
    }
    
    /// Add an edge to the transcript
    ///
    /// Parameters:
    /// - source: Source vertex ID
    /// - target: Target vertex ID
    /// - message: Message carried by the edge
    ///
    /// Returns:
    /// - Result indicating success or error
    pub fn add_edge(
        &mut self,
        source: VertexId,
        target: VertexId,
        message: Vec<F>,
    ) -> PCDResult<()> {
        if self.graph.add_edge(source, target, message) {
            Ok(())
        } else {
            Err(PCDError::InvalidDAG(
                "Failed to add edge (would create cycle or vertices don't exist)".to_string()
            ))
        }
    }
    
    /// Add an edge with proof
    pub fn add_edge_with_proof(
        &mut self,
        source: VertexId,
        target: VertexId,
        message: Vec<F>,
        proof: Vec<u8>,
    ) -> PCDResult<()> {
        self.add_edge(source, target, message)?;
        
        let edge_id = (source, target);
        if let Some(edge) = self.graph.get_edge_mut(edge_id) {
            edge.proof = Some(proof);
        }
        
        Ok(())
    }
    
    /// Get the output message
    ///
    /// The output message is from the lexicographically-first edge to a sink vertex.
    ///
    /// Mathematical Details:
    /// - Find all sink vertices (no outgoing edges)
    /// - For each sink v, find all incoming edges
    /// - Select the lexicographically-first edge e = (u, v)
    /// - Return message z_e
    pub fn get_output_message(&mut self) -> PCDResult<Vec<F>> {
        if let Some(msg) = &self.output_message {
            return Ok(msg.clone());
        }
        
        // Find sinks
        let sinks = self.graph.sinks();
        if sinks.is_empty() {
            return Err(PCDError::InvalidDAG("No sink vertices found".to_string()));
        }
        
        // Find lexicographically-first edge to a sink
        let mut min_edge: Option<(EdgeId, Vec<F>)> = None;
        
        for &sink_id in sinks {
            if let Some(vertex) = self.graph.get_vertex(sink_id) {
                for &edge_id in &vertex.incoming_edges {
                    if let Some(edge) = self.graph.get_edge(edge_id) {
                        let is_smaller = min_edge.as_ref().map_or(true, |(min_id, _)| {
                            edge_id < *min_id
                        });
                        
                        if is_smaller {
                            min_edge = Some((edge_id, edge.message.clone()));
                        }
                    }
                }
            }
        }
        
        match min_edge {
            Some((_, message)) => {
                self.output_message = Some(message.clone());
                Ok(message)
            }
            None => Err(PCDError::InvalidDAG("No edges to sink vertices".to_string())),
        }
    }
    
    /// Verify the transcript structure
    ///
    /// Checks that:
    /// - The graph is acyclic
    /// - All vertices are reachable from sources
    /// - All sinks are reachable from sources
    pub fn verify_structure(&self) -> PCDResult<()> {
        // Check acyclicity using topological sort
        if self.graph.topological_sort().is_none() {
            return Err(PCDError::CycleDetected);
        }
        
        // Check that all vertices are reachable from sources
        let reachable = self.compute_reachable_vertices();
        if reachable.len() != self.graph.vertices().len() {
            return Err(PCDError::InvalidDAG(
                "Some vertices are not reachable from sources".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Compute all vertices reachable from sources
    fn compute_reachable_vertices(&self) -> std::collections::HashSet<VertexId> {
        use std::collections::HashSet;
        
        let mut reachable = HashSet::new();
        let mut stack: Vec<VertexId> = self.graph.sources().iter().copied().collect();
        
        while let Some(current) = stack.pop() {
            if reachable.contains(&current) {
                continue;
            }
            reachable.insert(current);
            
            if let Some(vertex) = self.graph.get_vertex(current) {
                for &(_, successor) in &vertex.outgoing_edges {
                    if !reachable.contains(&successor) {
                        stack.push(successor);
                    }
                }
            }
        }
        
        reachable
    }
    
    /// Get vertices grouped by level (breadth-first)
    ///
    /// This is useful for breadth-first extraction.
    /// Returns vertices in levels where:
    /// - Level 0: source vertices
    /// - Level k: vertices whose predecessors are all in levels < k
    pub fn get_levels(&self) -> Vec<Vec<VertexId>> {
        self.graph.get_levels()
    }
    
    /// Get incoming messages for a vertex
    pub fn get_incoming_messages(&self, vertex_id: VertexId) -> Vec<Vec<F>> {
        self.graph.get_incoming_messages(vertex_id)
    }
    
    /// Get vertex by ID
    pub fn get_vertex(&self, id: VertexId) -> PCDResult<&PCDVertex<F>> {
        self.graph.get_vertex(id)
            .ok_or(PCDError::VertexNotFound(id))
    }
    
    /// Get edge by ID
    pub fn get_edge(&self, edge_id: EdgeId) -> PCDResult<&PCDEdge<F>> {
        self.graph.get_edge(edge_id)
            .ok_or(PCDError::EdgeNotFound {
                source: edge_id.0,
                target: edge_id.1,
            })
    }
    
    /// Get number of vertices
    pub fn num_vertices(&self) -> usize {
        self.graph.vertices().len()
    }
    
    /// Get number of edges
    pub fn num_edges(&self) -> usize {
        self.graph.edges().len()
    }
    
    /// Compute maximum depth (longest path from source to sink)
    pub fn max_depth(&self) -> usize {
        let levels = self.get_levels();
        levels.len()
    }
}

impl<F: Clone> Default for PCDTranscript<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
