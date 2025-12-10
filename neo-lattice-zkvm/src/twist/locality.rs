// Task 3.7: Locality-Aware Twist Prover
// Optimizes for temporal locality in memory accesses

use crate::field::extension_framework::ExtensionFieldElement;
use std::collections::HashMap;

/// Locality-aware Twist prover
/// Achieves O(i) cost for accesses to cells accessed 2^i steps prior
pub struct LocalityAwareTwistProver<K: ExtensionFieldElement> {
    /// Access history: cell -> list of access times
    pub access_history: HashMap<usize, Vec<usize>>,
    
    /// Current sparsity (number of non-zero terms)
    pub current_sparsity: usize,
    
    /// Current round number
    pub round: usize,
    
    /// Memory size
    pub memory_size: usize,
    
    /// Number of cycles
    pub num_cycles: usize,
    
    _phantom: std::marker::PhantomData<K>,
}

impl<K: ExtensionFieldElement> LocalityAwareTwistProver<K> {
    pub fn new(memory_size: usize, num_cycles: usize) -> Self {
        Self {
            access_history: HashMap::new(),
            current_sparsity: 0,
            round: 0,
            memory_size,
            num_cycles,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Process memory operation with locality tracking
    /// 
    /// Algorithm:
    /// - Find last_access_time for cell from access_history
    /// - If first access: cost = O(log K)
    /// - If accessed δ steps ago: cost = O(log δ)
    /// - Update access_history[cell].push(time)
    /// - Return locality_cost
    pub fn process_operation(
        &mut self,
        cell: usize,
        time: usize,
        is_write: bool,
    ) -> usize {
        if cell >= self.memory_size {
            return 0;
        }
        
        let history = self.access_history.entry(cell).or_insert_with(Vec::new);
        
        let locality_cost = if let Some(&last_access) = history.last() {
            // Cell was accessed before
            let delta = time - last_access;
            
            if delta == 0 {
                0  // Same cycle
            } else {
                // Cost is O(log δ) for δ steps ago
                ((delta as f64).log2().ceil() as usize).max(1)
            }
        } else {
            // First access to this cell
            let log_k = (self.memory_size as f64).log2() as usize;
            log_k
        };
        
        // Update history
        history.push(time);
        
        locality_cost
    }
    
    /// Return variable binding order optimized for locality
    /// 
    /// Algorithm:
    /// - First log_t rounds: bind time variables (enables coalescing)
    /// - Next log_k rounds: bind memory variables
    /// - Return order = [0..log_t, log_t..log_t+log_k]
    /// 
    /// Why time-first?
    /// - Temporally close accesses coalesce as time variables are bound
    /// - Sparsity decreases rapidly for local access patterns
    /// - Memory variables bound last when sparsity is minimal
    pub fn bind_time_first_order(&self) -> Vec<usize> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        let mut order = Vec::with_capacity(log_k + log_t);
        
        // First: time variables (0..log_t)
        for i in 0..log_t {
            order.push(i);
        }
        
        // Second: memory variables (log_t..log_t+log_k)
        for i in 0..log_k {
            order.push(log_t + i);
        }
        
        order
    }
    
    /// Track sparsity as variables are bound
    /// 
    /// As time variables are bound, temporally-close accesses coalesce:
    /// - After binding t_0: accesses at times differing in bit 0 coalesce
    /// - After binding t_1: accesses at times differing in bits 0-1 coalesce
    /// - Sparsity falls exponentially for local patterns
    pub fn track_sparsity(&mut self, non_zero_positions: &[usize]) {
        self.current_sparsity = non_zero_positions.len();
    }
    
    /// Get current sparsity
    pub fn get_sparsity(&self) -> usize {
        self.current_sparsity
    }
    
    /// Compute expected cost for access pattern
    /// 
    /// For local access patterns:
    /// - Most accesses are to recently-accessed cells
    /// - Cost dominated by O(log δ) for small δ
    /// - Much better than O(log K) for all accesses
    pub fn compute_expected_cost(&self) -> f64 {
        let mut total_cost = 0.0;
        let mut num_accesses = 0;
        
        for history in self.access_history.values() {
            for i in 1..history.len() {
                let delta = history[i] - history[i - 1];
                let cost = if delta == 0 {
                    0.0
                } else {
                    (delta as f64).log2()
                };
                total_cost += cost;
                num_accesses += 1;
            }
        }
        
        if num_accesses > 0 {
            total_cost / num_accesses as f64
        } else {
            0.0
        }
    }
    
    /// Analyze access pattern locality
    pub fn analyze_locality(&self) -> LocalityStats {
        let mut same_cycle = 0;
        let mut within_2 = 0;
        let mut within_4 = 0;
        let mut within_8 = 0;
        let mut within_16 = 0;
        let mut beyond_16 = 0;
        
        for history in self.access_history.values() {
            for i in 1..history.len() {
                let delta = history[i] - history[i - 1];
                
                if delta == 0 {
                    same_cycle += 1;
                } else if delta <= 2 {
                    within_2 += 1;
                } else if delta <= 4 {
                    within_4 += 1;
                } else if delta <= 8 {
                    within_8 += 1;
                } else if delta <= 16 {
                    within_16 += 1;
                } else {
                    beyond_16 += 1;
                }
            }
        }
        
        LocalityStats {
            same_cycle,
            within_2,
            within_4,
            within_8,
            within_16,
            beyond_16,
        }
    }
}

/// Locality statistics
#[derive(Clone, Debug)]
pub struct LocalityStats {
    pub same_cycle: usize,
    pub within_2: usize,
    pub within_4: usize,
    pub within_8: usize,
    pub within_16: usize,
    pub beyond_16: usize,
}

impl LocalityStats {
    pub fn total_accesses(&self) -> usize {
        self.same_cycle + self.within_2 + self.within_4 + 
        self.within_8 + self.within_16 + self.beyond_16
    }
    
    pub fn locality_ratio(&self) -> f64 {
        let total = self.total_accesses();
        if total == 0 {
            return 0.0;
        }
        
        let local = self.same_cycle + self.within_2 + self.within_4 + self.within_8;
        local as f64 / total as f64
    }
}
