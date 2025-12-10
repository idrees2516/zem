// Incremental Computation Framework
//
// Mathematical Foundation:
// - Function sampler: F(1^λ) → F where F: {0,1}^n_in × {0,1}^n_w → {0,1}^n_out
// - Incremental computation: (F, dpt^≤) where dpt^≤ is depth predicate family
// - Computation chain: z_0 →^F_{w_1} z_1 →^F_{w_2} ... →^F_{w_d} z_d
//   where z_i = F(z_{i-1}, w_i)
//
// Key Properties:
// 1. Well-foundedness: Recursion terminates at base case
//    dpt^≤_D(z') = ⊤ ∧ z→^F_w z' ⇒ dpt^≤_{D-1}(z) = ⊤
//
// 2. Base case detection: dpt^≤_0(z) = ⊤ identifies source nodes
//
// 3. Unbounded depth: Works for any polynomial-bounded depth d(λ)

use serde::{Serialize, Deserialize};

use super::depth_predicates::DepthPredicates;
use super::errors::{IVCError, IVCResult};

/// Function type for incremental computation
///
/// F: (z_{i-1}, w_i) → z_i
/// - z_{i-1}: previous state (n_in bits)
/// - w_i: local witness (n_w bits)
/// - z_i: next state (n_out bits)
pub type IncrementalFunction<F> = Box<dyn Fn(&[F], &[F]) -> Vec<F> + Send + Sync>;

/// Incremental Computation (F, dpt^≤)
///
/// Represents a computation that can be verified incrementally:
/// - Each step: z_i = F(z_{i-1}, w_i)
/// - Depth tracking: dpt^≤ ensures termination
/// - IVC proves: z_0 →^F_{w_1} z_1 →^F_{w_2} ... →^F_{w_d} z_d
#[derive(Clone)]
pub struct IncrementalComputation<F> {
    /// Function F: (z_prev, w) → z_next
    function: IncrementalFunction<F>,
    
    /// Depth predicate family dpt^≤
    depth_predicates: DepthPredicates<F>,
    
    /// Input size (bits)
    n_in: usize,
    
    /// Witness size (bits)
    n_w: usize,
    
    /// Output size (bits)
    n_out: usize,
}

impl<F: Clone> IncrementalComputation<F> {
    /// Create new incremental computation
    ///
    /// # Arguments
    /// * `function` - F: (z_prev, w) → z_next
    /// * `depth_predicates` - dpt^≤ family
    /// * `n_in` - Input size
    /// * `n_w` - Witness size
    /// * `n_out` - Output size
    pub fn new(
        function: IncrementalFunction<F>,
        depth_predicates: DepthPredicates<F>,
        n_in: usize,
        n_w: usize,
        n_out: usize,
    ) -> Self {
        Self {
            function,
            depth_predicates,
            n_in,
            n_w,
            n_out,
        }
    }
    
    /// Apply function: z_i = F(z_{i-1}, w_i)
    ///
    /// Core operation of incremental computation
    /// Computes next state from previous state and witness
    ///
    /// Mathematical constraint: |z_i| = n_out
    pub fn apply(&self, z_prev: &[F], w: &[F]) -> IVCResult<Vec<F>> {
        // Validate input sizes
        if z_prev.len() != self.n_in {
            return Err(IVCError::InvalidState(
                format!("Expected input size {}, got {}", self.n_in, z_prev.len())
            ));
        }
        
        if w.len() != self.n_w {
            return Err(IVCError::InvalidWitness(
                format!("Expected witness size {}, got {}", self.n_w, w.len())
            ));
        }
        
        // Apply function
        let z_next = (self.function)(z_prev, w);
        
        // Validate output size
        if z_next.len() != self.n_out {
            return Err(IVCError::FunctionApplicationFailed(
                format!("Expected output size {}, got {}", self.n_out, z_next.len())
            ));
        }
        
        Ok(z_next)
    }
    
    /// Check if state has depth ≤ D
    ///
    /// Returns dpt^≤_D(state)
    pub fn check_depth(&self, state: &[F], depth: usize) -> bool {
        self.depth_predicates.check_depth(state, depth)
    }
    
    /// Check if state is base case
    ///
    /// Base case: dpt^≤_0(z) = ⊤
    /// Means z is a source node with no predecessors
    /// IVC extraction terminates here
    pub fn is_base_case(&self, state: &[F]) -> bool {
        self.depth_predicates.is_base_case(state)
    }
    
    /// Execute computation chain
    ///
    /// Computes: z_0 →^F_{w_1} z_1 →^F_{w_2} ... →^F_{w_d} z_d
    ///
    /// # Arguments
    /// * `z_0` - Initial state
    /// * `witnesses` - Sequence of witnesses [w_1, ..., w_d]
    ///
    /// # Returns
    /// Final state z_d and all intermediate states
    pub fn execute_chain(
        &self,
        z_0: &[F],
        witnesses: &[Vec<F>],
    ) -> IVCResult<(Vec<F>, Vec<Vec<F>>)> {
        let mut states = vec![z_0.to_vec()];
        let mut current_state = z_0.to_vec();
        
        for (i, witness) in witnesses.iter().enumerate() {
            // Check depth bound if specified
            if let Some(max_depth) = self.depth_predicates.max_depth() {
                if i >= max_depth {
                    return Err(IVCError::DepthBoundExceeded);
                }
            }
            
            // Apply function
            current_state = self.apply(&current_state, witness)?;
            states.push(current_state.clone());
        }
        
        Ok((current_state, states))
    }
    
    /// Verify computation chain
    ///
    /// Checks: ∀i ∈ [d]: z_i = F(z_{i-1}, w_i)
    ///
    /// # Arguments
    /// * `z_0` - Initial state
    /// * `z_d` - Final state
    /// * `witnesses` - Witnesses [w_1, ..., w_d]
    ///
    /// # Returns
    /// true if chain is valid
    pub fn verify_chain(
        &self,
        z_0: &[F],
        z_d: &[F],
        witnesses: &[Vec<F>],
    ) -> IVCResult<bool> {
        let (computed_z_d, _) = self.execute_chain(z_0, witnesses)?;
        
        // Check if computed final state matches claimed final state
        Ok(computed_z_d == z_d)
    }
    
    /// Get function sizes
    pub fn sizes(&self) -> (usize, usize, usize) {
        (self.n_in, self.n_w, self.n_out)
    }
    
    /// Get depth predicates
    pub fn depth_predicates(&self) -> &DepthPredicates<F> {
        &self.depth_predicates
    }
}

/// Builder for incremental computations
pub struct IncrementalComputationBuilder<F> {
    function: Option<IncrementalFunction<F>>,
    depth_predicates: Option<DepthPredicates<F>>,
    n_in: usize,
    n_w: usize,
    n_out: usize,
}

impl<F: Clone> IncrementalComputationBuilder<F> {
    pub fn new() -> Self {
        Self {
            function: None,
            depth_predicates: None,
            n_in: 0,
            n_w: 0,
            n_out: 0,
        }
    }
    
    pub fn function<Fn>(mut self, f: Fn) -> Self
    where
        Fn: Fn(&[F], &[F]) -> Vec<F> + Send + Sync + 'static,
    {
        self.function = Some(Box::new(f));
        self
    }
    
    pub fn depth_predicates(mut self, predicates: DepthPredicates<F>) -> Self {
        self.depth_predicates = Some(predicates);
        self
    }
    
    pub fn sizes(mut self, n_in: usize, n_w: usize, n_out: usize) -> Self {
        self.n_in = n_in;
        self.n_w = n_w;
        self.n_out = n_out;
        self
    }
    
    pub fn build(self) -> IVCResult<IncrementalComputation<F>> {
        let function = self.function.ok_or_else(|| {
            IVCError::InvalidState("Function not provided".to_string())
        })?;
        
        let depth_predicates = self.depth_predicates.ok_or_else(|| {
            IVCError::InvalidState("Depth predicates not provided".to_string())
        })?;
        
        Ok(IncrementalComputation::new(
            function,
            depth_predicates,
            self.n_in,
            self.n_w,
            self.n_out,
        ))
    }
}

impl<F: Clone> Default for IncrementalComputationBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Common incremental computation patterns
pub mod patterns {
    use super::*;
    
    /// Fibonacci computation
    ///
    /// State: [F_n, F_{n+1}]
    /// Function: F([a, b], []) = [b, a+b]
    /// Depth: n (explicit in state)
    pub fn fibonacci<F>() -> IncrementalComputation<F>
    where
        F: Clone + std::ops::Add<Output = F> + From<usize> + PartialOrd,
    {
        let function = Box::new(|z_prev: &[F], _w: &[F]| -> Vec<F> {
            vec![z_prev[1].clone(), z_prev[0].clone() + z_prev[1].clone()]
        });
        
        let mut depth_predicates = DepthPredicates::new();
        // Base case: F_0 = 0, F_1 = 1
        depth_predicates.register_predicate(0, |state: &[F]| {
            state.len() == 2 && state[0] == F::from(0) && state[1] == F::from(1)
        });
        
        IncrementalComputation::new(function, depth_predicates, 2, 0, 2)
    }
    
    /// Counter computation
    ///
    /// State: [count]
    /// Function: F([n], []) = [n+1]
    /// Depth: count value
    pub fn counter<F>() -> IncrementalComputation<F>
    where
        F: Clone + std::ops::Add<Output = F> + From<usize> + PartialOrd,
    {
        let function = Box::new(|z_prev: &[F], _w: &[F]| -> Vec<F> {
            vec![z_prev[0].clone() + F::from(1)]
        });
        
        let mut depth_predicates = DepthPredicates::new();
        depth_predicates.register_predicate(0, |state: &[F]| {
            state.len() == 1 && state[0] == F::from(0)
        });
        
        IncrementalComputation::new(function, depth_predicates, 1, 0, 1)
    }
}
