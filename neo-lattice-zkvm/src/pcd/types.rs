// Type definitions for PCD

use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Vertex identifier in the DAG
pub type VertexId = usize;

/// Edge identifier in the DAG
pub type EdgeId = (VertexId, VertexId);

/// PCD Vertex
///
/// Represents a computation node in the DAG.
/// Each vertex has:
/// - A local witness w_loc
/// - Incoming messages from predecessor vertices
/// - An outgoing message computed from w_loc and incoming messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PCDVertex<F> {
    /// Unique identifier for this vertex
    pub id: VertexId,
    
    /// Local witness for this vertex's computation
    pub w_loc: Vec<F>,
    
    /// Incoming edges (predecessor vertex IDs)
    pub incoming_edges: Vec<EdgeId>,
    
    /// Outgoing edges (successor vertex IDs)
    pub outgoing_edges: Vec<EdgeId>,
    
    /// Whether this is a source vertex (no incoming edges)
    pub is_source: bool,
    
    /// Whether this is a sink vertex (no outgoing edges)
    pub is_sink: bool,
}

impl<F> PCDVertex<F> {
    /// Create a new PCD vertex
    pub fn new(id: VertexId, w_loc: Vec<F>) -> Self {
        Self {
            id,
            w_loc,
            incoming_edges: Vec::new(),
            outgoing_edges: Vec::new(),
            is_source: true,
            is_sink: true,
        }
    }
    
    /// Add an incoming edge
    pub fn add_incoming_edge(&mut self, edge: EdgeId) {
        self.incoming_edges.push(edge);
        self.is_source = false;
    }
    
    /// Add an outgoing edge
    pub fn add_outgoing_edge(&mut self, edge: EdgeId) {
        self.outgoing_edges.push(edge);
        self.is_sink = false;
    }
    
    /// Get number of incoming edges
    pub fn in_degree(&self) -> usize {
        self.incoming_edges.len()
    }
    
    /// Get number of outgoing edges
    pub fn out_degree(&self) -> usize {
        self.outgoing_edges.len()
    }
}

/// PCD Edge
///
/// Represents a message passed between vertices in the DAG.
/// Each edge carries a message z_e from source to target vertex.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PCDEdge<F> {
    /// Source vertex ID
    pub source: VertexId,
    
    /// Target vertex ID
    pub target: VertexId,
    
    /// Message carried by this edge
    pub message: Vec<F>,
    
    /// Proof for this edge's message
    pub proof: Option<Vec<u8>>,
}

impl<F> PCDEdge<F> {
    /// Create a new PCD edge
    pub fn new(source: VertexId, target: VertexId, message: Vec<F>) -> Self {
        Self {
            source,
            target,
            message,
            proof: None,
        }
    }
    
    /// Create edge with proof
    pub fn with_proof(source: VertexId, target: VertexId, message: Vec<F>, proof: Vec<u8>) -> Self {
        Self {
            source,
            target,
            message,
            proof: Some(proof),
        }
    }
    
    /// Get edge ID
    pub fn id(&self) -> EdgeId {
        (self.source, self.target)
    }
}

/// Directed Acyclic Graph (DAG) structure
///
/// Represents the computation graph for PCD.
/// The DAG must be acyclic (no cycles allowed).
#[derive(Clone, Debug)]
pub struct DirectedAcyclicGraph<F> {
    /// Vertices in the DAG
    vertices: HashMap<VertexId, PCDVertex<F>>,
    
    /// Edges in the DAG
    edges: HashMap<EdgeId, PCDEdge<F>>,
    
    /// Source vertices (no incoming edges)
    sources: HashSet<VertexId>,
    
    /// Sink vertices (no outgoing edges)
    sinks: HashSet<VertexId>,
    
    /// Next vertex ID to assign
    next_vertex_id: VertexId,
}

impl<F: Clone> DirectedAcyclicGraph<F> {
    /// Create a new empty DAG
    pub fn new() -> Self {
        Self {
            vertices: HashMap::new(),
            edges: HashMap::new(),
            sources: HashSet::new(),
            sinks: HashSet::new(),
            next_vertex_id: 0,
        }
    }
    
    /// Add a vertex to the DAG
    ///
    /// Returns the assigned vertex ID
    pub fn add_vertex(&mut self, w_loc: Vec<F>) -> VertexId {
        let id = self.next_vertex_id;
        self.next_vertex_id += 1;
        
        let vertex = PCDVertex::new(id, w_loc);
        self.vertices.insert(id, vertex);
        self.sources.insert(id);
        self.sinks.insert(id);
        
        id
    }
    
    /// Add an edge to the DAG
    ///
    /// Returns true if edge was added successfully, false if it would create a cycle
    pub fn add_edge(&mut self, source: VertexId, target: VertexId, message: Vec<F>) -> bool {
        // Check if vertices exist
        if !self.vertices.contains_key(&source) || !self.vertices.contains_key(&target) {
            return false;
        }
        
        // Check if edge would create a cycle
        if self.would_create_cycle(source, target) {
            return false;
        }
        
        let edge_id = (source, target);
        let edge = PCDEdge::new(source, target, message);
        
        // Update vertices
        if let Some(source_vertex) = self.vertices.get_mut(&source) {
            source_vertex.add_outgoing_edge(edge_id);
        }
        if let Some(target_vertex) = self.vertices.get_mut(&target) {
            target_vertex.add_incoming_edge(edge_id);
        }
        
        // Update sources and sinks
        self.sinks.remove(&source);
        self.sources.remove(&target);
        
        // Add edge
        self.edges.insert(edge_id, edge);
        
        true
    }
    
    /// Check if adding an edge would create a cycle
    ///
    /// Uses DFS to check if there's already a path from target to source
    fn would_create_cycle(&self, source: VertexId, target: VertexId) -> bool {
        // If target can reach source, adding edge source->target creates cycle
        self.can_reach(target, source)
    }
    
    /// Check if there's a path from start to end
    fn can_reach(&self, start: VertexId, end: VertexId) -> bool {
        if start == end {
            return true;
        }
        
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        
        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);
            
            if current == end {
                return true;
            }
            
            // Add successors to stack
            if let Some(vertex) = self.vertices.get(&current) {
                for &(_, successor) in &vertex.outgoing_edges {
                    if !visited.contains(&successor) {
                        stack.push(successor);
                    }
                }
            }
        }
        
        false
    }
    
    /// Get a vertex by ID
    pub fn get_vertex(&self, id: VertexId) -> Option<&PCDVertex<F>> {
        self.vertices.get(&id)
    }
    
    /// Get a mutable vertex by ID
    pub fn get_vertex_mut(&mut self, id: VertexId) -> Option<&mut PCDVertex<F>> {
        self.vertices.get_mut(&id)
    }
    
    /// Get an edge by ID
    pub fn get_edge(&self, edge_id: EdgeId) -> Option<&PCDEdge<F>> {
        self.edges.get(&edge_id)
    }
    
    /// Get a mutable edge by ID
    pub fn get_edge_mut(&mut self, edge_id: EdgeId) -> Option<&mut PCDEdge<F>> {
        self.edges.get_mut(&edge_id)
    }
    
    /// Get all source vertices
    pub fn sources(&self) -> &HashSet<VertexId> {
        &self.sources
    }
    
    /// Get all sink vertices
    pub fn sinks(&self) -> &HashSet<VertexId> {
        &self.sinks
    }
    
    /// Get all vertices
    pub fn vertices(&self) -> &HashMap<VertexId, PCDVertex<F>> {
        &self.vertices
    }
    
    /// Get all edges
    pub fn edges(&self) -> &HashMap<EdgeId, PCDEdge<F>> {
        &self.edges
    }
    
    /// Get incoming messages for a vertex
    ///
    /// Returns the messages from all incoming edges
    pub fn get_incoming_messages(&self, vertex_id: VertexId) -> Vec<Vec<F>> {
        let mut messages = Vec::new();
        
        if let Some(vertex) = self.vertices.get(&vertex_id) {
            for &edge_id in &vertex.incoming_edges {
                if let Some(edge) = self.edges.get(&edge_id) {
                    messages.push(edge.message.clone());
                }
            }
        }
        
        messages
    }
    
    /// Perform topological sort
    ///
    /// Returns vertices in topological order (sources first, sinks last)
    /// Returns None if the graph has a cycle
    pub fn topological_sort(&self) -> Option<Vec<VertexId>> {
        let mut in_degree: HashMap<VertexId, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue = Vec::new();
        
        // Initialize in-degrees
        for (&id, vertex) in &self.vertices {
            in_degree.insert(id, vertex.in_degree());
            if vertex.in_degree() == 0 {
                queue.push(id);
            }
        }
        
        // Process vertices
        while let Some(current) = queue.pop() {
            result.push(current);
            
            // Reduce in-degree of successors
            if let Some(vertex) = self.vertices.get(&current) {
                for &(_, successor) in &vertex.outgoing_edges {
                    if let Some(degree) = in_degree.get_mut(&successor) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push(successor);
                        }
                    }
                }
            }
        }
        
        // Check if all vertices were processed
        if result.len() == self.vertices.len() {
            Some(result)
        } else {
            None // Cycle detected
        }
    }
    
    /// Get vertices by level (breadth-first)
    ///
    /// Returns vertices grouped by their distance from sources
    /// Level 0: source vertices
    /// Level 1: vertices with edges from level 0
    /// etc.
    pub fn get_levels(&self) -> Vec<Vec<VertexId>> {
        let mut levels = Vec::new();
        let mut visited = HashSet::new();
        let mut current_level: Vec<VertexId> = self.sources.iter().copied().collect();
        
        while !current_level.is_empty() {
            levels.push(current_level.clone());
            
            for &vertex_id in &current_level {
                visited.insert(vertex_id);
            }
            
            let mut next_level = Vec::new();
            for &vertex_id in &current_level {
                if let Some(vertex) = self.vertices.get(&vertex_id) {
                    for &(_, successor) in &vertex.outgoing_edges {
                        if !visited.contains(&successor) && !next_level.contains(&successor) {
                            // Check if all predecessors have been visited
                            if let Some(succ_vertex) = self.vertices.get(&successor) {
                                let all_preds_visited = succ_vertex.incoming_edges.iter()
                                    .all(|&(pred, _)| visited.contains(&pred));
                                
                                if all_preds_visited {
                                    next_level.push(successor);
                                }
                            }
                        }
                    }
                }
            }
            
            current_level = next_level;
        }
        
        levels
    }
}

impl<F: Clone> Default for DirectedAcyclicGraph<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// PCD Proof
///
/// Proof for a PCD computation.
/// Contains the output message and the SNARK proof.
#[derive(Clone, Debug)]
pub struct PCDProof<F, P> {
    /// Output message (from lexicographically-first edge to sink)
    pub output_message: Vec<F>,
    
    /// SNARK proof
    pub proof: P,
    
    /// Metadata
    pub metadata: PCDMetadata,
}

/// Metadata for PCD proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PCDMetadata {
    /// Number of vertices in the DAG
    pub num_vertices: usize,
    
    /// Number of edges in the DAG
    pub num_edges: usize,
    
    /// Maximum depth (longest path from source to sink)
    pub max_depth: usize,
}

impl<F, P> PCDProof<F, P> {
    /// Create a new PCD proof
    pub fn new(output_message: Vec<F>, proof: P, metadata: PCDMetadata) -> Self {
        Self {
            output_message,
            proof,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
