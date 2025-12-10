// Task 3.1: Twist Protocol Structure with Increments
// Read-write memory checking protocol

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::MultilinearPolynomial;
use std::fmt::Debug;

/// Twist protocol configuration
pub struct TwistConfig {
    pub memory_size: usize,      // K
    pub num_cycles: usize,        // T
    pub dimension: usize,         // d for tensor decomposition
}

impl TwistConfig {
    pub fn new(memory_size: usize, num_cycles: usize) -> Self {
        let dimension = Self::select_dimension(memory_size);
        Self {
            memory_size,
            num_cycles,
            dimension,
        }
    }
    
    /// Select d based on memory size (same heuristic as Shout)
    fn select_dimension(memory_size: usize) -> usize {
        if memory_size <= (1 << 16) { 1 }
        else if memory_size <= (1 << 20) { 2 }
        else if memory_size <= (1 << 30) { 4 }
        else { 8 }
    }
    
    pub fn chunk_size(&self) -> usize {
        ((self.memory_size as f64).powf(1.0 / self.dimension as f64).ceil()) as usize
    }
}

/// Twist protocol for read-write memory
/// Key difference from Shout: memory is mutable, tracked via increments
pub struct TwistProtocol<K: ExtensionFieldElement, PCS> {
    pub config: TwistConfig,
    
    /// Commitments to read address matrices (d of them)
    pub read_address_commitments: Vec<PCS>,
    
    /// Commitments to write address matrices (d of them)
    pub write_address_commitments: Vec<PCS>,
    
    /// Commitment to increment vector
    /// Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
    /// Only T non-zero values (at most one per cycle)
    pub increment_commitment: Option<PCS>,
    
    /// Sparse increment storage
    /// Only store non-zero increments with their (cycle, value) pairs
    pub increments: Vec<(usize, K)>,
}

impl<K, PCS> TwistProtocol<K, PCS>
where
    K: ExtensionFieldElement,
{
    /// Initialize Twist protocol
    pub fn new(memory_size: usize, num_cycles: usize) -> Self {
        let config = TwistConfig::new(memory_size, num_cycles);
        
        Self {
            config,
            read_address_commitments: Vec::new(),
            write_address_commitments: Vec::new(),
            increment_commitment: None,
            increments: Vec::new(),
        }
    }
    
    pub fn memory_size(&self) -> usize {
        self.config.memory_size
    }
    
    pub fn num_cycles(&self) -> usize {
        self.config.num_cycles
    }
    
    pub fn dimension(&self) -> usize {
        self.config.dimension
    }
    
    /// Allocate storage for increments
    /// Sparse representation: only store non-zero values
    pub fn allocate_increments(&mut self) {
        self.increments = Vec::with_capacity(self.config.num_cycles);
    }
    
    /// Add increment for cycle j
    pub fn add_increment(&mut self, cycle: usize, value: K) {
        if value != K::zero() {
            self.increments.push((cycle, value));
        }
    }
    
    /// Get increment at cycle j
    pub fn get_increment(&self, cycle: usize) -> K {
        for &(c, val) in &self.increments {
            if c == cycle {
                return val;
            }
        }
        K::zero()
    }
    
    /// Get number of non-zero increments
    pub fn num_nonzero_increments(&self) -> usize {
        self.increments.len()
    }
}
