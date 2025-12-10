// Task 2.2: Shout Protocol Structure
// Batch evaluation argument for T lookups into memory of size K

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::MultilinearPolynomial;
use crate::commitment::PolynomialCommitment;
use std::fmt::Debug;

/// Shout protocol configuration
/// Determines d based on memory size K for optimal performance
pub struct ShoutConfig {
    pub memory_size: usize,
    pub num_lookups: usize,
    pub dimension: usize,
}

impl ShoutConfig {
    pub fn new(memory_size: usize, num_lookups: usize) -> Self {
        let dimension = Self::select_dimension(memory_size);
        Self {
            memory_size,
            num_lookups,
            dimension,
        }
    }
    
    /// Select d based on memory size K
    /// d=1: K ≤ 2^16, d=2: K ≤ 2^20, d=4: K ≤ 2^30, d=8: K > 2^30
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

/// Shout protocol for batch evaluation
/// Proves: z_i = f(y_i) for i=1..T where f: {0,1}^ℓ → F
pub struct ShoutProtocol<K: ExtensionFieldElement, PCS> {
    pub config: ShoutConfig,
    pub access_commitments: Vec<PCS>,
    pub table: MultilinearPolynomial<K>,
}

impl<K, PCS> ShoutProtocol<K, PCS>
where
    K: ExtensionFieldElement,
{
    pub fn new(
        memory_size: usize,
        num_lookups: usize,
        table: MultilinearPolynomial<K>,
    ) -> Result<Self, String> {
        let config = ShoutConfig::new(memory_size, num_lookups);
        
        if table.evaluations.len() != memory_size {
            return Err("Table size must match memory size".to_string());
        }
        
        Ok(Self {
            config,
            access_commitments: Vec::new(),
            table,
        })
    }
    
    pub fn memory_size(&self) -> usize {
        self.config.memory_size
    }
    
    pub fn num_lookups(&self) -> usize {
        self.config.num_lookups
    }
    
    pub fn dimension(&self) -> usize {
        self.config.dimension
    }
}
