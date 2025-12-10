// Proof-Carrying Data (PCD) Module
//
// This module implements PCD, which generalizes IVC to directed acyclic graph (DAG)
// computations instead of linear chains.
//
// Mathematical Foundation:
// - PCD transcript: DAG with vertices labeled by local witnesses and edges by messages
// - Compliance predicate: ϕ^θ(z_e, w_loc, z) checks vertex computation
// - Base case: ϕ^θ(z_e, w_loc, (⊥)) = 1 for source vertices
// - Recursive case: ϕ^θ(z_e, w_loc, (z_e1, ..., z_eM)) = 1 for internal vertices
//
// Key Difference from IVC:
// - IVC: Linear chain (each step has one predecessor)
// - PCD: DAG (each vertex can have multiple predecessors)
// - Extraction: Breadth-first instead of linear

pub mod types;
pub mod transcript;
pub mod extractor;
pub mod compliance;
pub mod errors;

pub use types::*;
pub use transcript::*;
pub use extractor::*;
pub use compliance::*;
pub use errors::*;
