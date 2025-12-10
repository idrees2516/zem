// Depth Predicates for Incremental Computation
//
// Mathematical Foundation:
// - Depth predicate family: dpt^≤ = {dpt^≤_D}_D∈ℕ
// - Well-foundedness: dpt^≤_D(z') = ⊤ ∧ z→^F_w z' ⇒ dpt^≤_{D-1}(z) = ⊤
// - Base case: dpt^≤_0(z) = ⊤ identifies source nodes (no predecessors)
//
// Key Property: Ensures recursion terminates at base case
// - For any computation chain z_0 → z_1 → ... → z_d
// - If dpt^≤_d(z_d) = ⊤, then dpt^≤_0(z_0) = ⊤
// - This guarantees extraction terminates

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use super::errors::{IVCError, IVCResult};

/// Depth predicate: checks if state has depth ≤ D
pub type DepthPredicate<F> = Box<dyn Fn(&[F]) -> bool + Send + Sync>;

/// Depth predicate family for incremental computation
///
/// Maintains predicates dpt^≤_D for each depth D
/// Ensures well-founded recursion: deeper states imply shallower predecessors
#[derive(Clone)]
pub struct DepthPredicates<F> {
    /// Map from depth D to predicate dpt^≤_D
    predicates: HashMap<usize, DepthPredicate<F>>,
    
    /// Maximum depth (for bounded computations)
    max_depth: Option<usize>,
}

impl<F: Clone> DepthPredicates<F> {
    pub fn new() -> Self {
        Self {
            predicates: HashMap::new(),
            max_depth: None,
        }
    }
    
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            predicates: HashMap::new(),
            max_depth: Some(max_depth),
        }
    }
    
    /// Register depth predicate for depth D
    ///
    /// Mathematical constraint: Must satisfy well-foundedness
    /// If dpt^≤_D(z') = ⊤ and z→z', then dpt^≤_{D-1}(z) = ⊤
    pub fn register_predicate<P>(&mut self, depth: usize, predicate: P)
    where
        P: Fn(&[F]) -> bool + Send + Sync + 'static,
    {
        self.predicates.insert(depth, Box::new(predicate));
    }
    
    /// Check if state has depth ≤ D
    ///
    /// Returns true if dpt^≤_D(state) = ⊤
    pub fn check_depth(&self, state: &[F], depth: usize) -> bool {
        if let Some(max) = self.max_depth {
            if depth > max {
                return false;
            }
        }
        
        self.predicates
            .get(&depth)
            .map(|pred| pred(state))
            .unwrap_or(false)
    }
    
    /// Check if state is base case (depth 0)
    ///
    /// Base case: dpt^≤_0(z) = ⊤ means z is a source node
    /// No predecessors exist, recursion terminates here
    pub fn is_base_case(&self, state: &[F]) -> bool {
        self.check_depth(state, 0)
    }
    
    /// Verify well-foundedness property
    ///
    /// For testing: checks that predicates form a well-founded hierarchy
    /// dpt^≤_D(z) = ⊤ ⇒ dpt^≤_{D+1}(z) = ⊤ (monotonicity)
    pub fn verify_well_foundedness(&self, test_states: &[Vec<F>]) -> IVCResult<()> {
        for state in test_states {
            let mut prev_result = false;
            
            for depth in 0..=self.max_depth.unwrap_or(100) {
                let current_result = self.check_depth(state, depth);
                
                // Monotonicity: if dpt^≤_D = ⊤, then dpt^≤_{D+1} = ⊤
                if prev_result && !current_result {
                    return Err(IVCError::InvalidState(
                        format!("Well-foundedness violated at depth {}", depth)
                    ));
                }
                
                prev_result = current_result;
            }
        }
        
        Ok(())
    }
    
    pub fn max_depth(&self) -> Option<usize> {
        self.max_depth
    }
}

impl<F: Clone> Default for DepthPredicates<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Common depth predicate patterns
pub mod patterns {
    use super::*;
    
    /// Explicit depth encoding: state contains depth field
    ///
    /// State format: [depth, ...other_data]
    /// dpt^≤_D(z) = ⊤ iff z[0] ≤ D
    pub fn explicit_depth<F: Clone + PartialOrd + From<usize>>() -> DepthPredicates<F> {
        let mut predicates = DepthPredicates::new();
        
        for d in 0..=1000 {
            let depth = d;
            predicates.register_predicate(depth, move |state: &[F]| {
                if state.is_empty() {
                    return false;
                }
                state[0] <= F::from(depth)
            });
        }
        
        predicates
    }
    
    /// Hash-based depth encoding: state contains H(depth)
    ///
    /// More succinct: |H(d)| << |d| for large d
    /// dpt^≤_D(z) = ⊤ iff ∃d≤D: z contains H(d)
    pub fn hash_depth<F: Clone + PartialEq>(
        hash_function: impl Fn(usize) -> F + Clone + 'static
    ) -> DepthPredicates<F> {
        let mut predicates = DepthPredicates::new();
        
        for d in 0..=1000 {
            let depth = d;
            let hash_fn = hash_function.clone();
            
            predicates.register_predicate(depth, move |state: &[F]| {
                if state.is_empty() {
                    return false;
                }
                
                // Check if state contains hash of any depth ≤ D
                for i in 0..=depth {
                    if state[0] == hash_fn(i) {
                        return true;
                    }
                }
                false
            });
        }
        
        predicates
    }
}
