// Task 3.2: Increment Computation
// Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))

use crate::field::extension_framework::ExtensionFieldElement;
use crate::shout::OneHotAddress;
use std::collections::HashMap;

/// Increment computation for Twist protocol
pub struct IncrementComputation<K: ExtensionFieldElement> {
    pub memory_size: usize,
    pub num_cycles: usize,
    pub dimension: usize,
}

impl<K: ExtensionFieldElement> IncrementComputation<K> {
    pub fn new(memory_size: usize, num_cycles: usize, dimension: usize) -> Self {
        Self {
            memory_size,
            num_cycles,
            dimension,
        }
    }
    
    /// Compute increment: Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
    /// 
    /// Algorithm:
    /// 1. Compute wa_kj = Π_{ℓ=1}^d wa_ℓ(k_ℓ, j) from tensor product
    /// 2. If wa_kj = 0: return 0 (cell k not written at cycle j)
    /// 3. If wa_kj = 1: return wv(j) - Val(k,j)
    pub fn compute_increment(
        &self,
        k: usize,
        j: usize,
        write_address: &OneHotAddress<K>,
        write_value: K,
        current_value: K,
    ) -> Result<K, String> {
        // Compute wa(k,j) as tensor product
        let wa_kj = self.compute_wa_at_k_j(k, j, write_address)?;
        
        if wa_kj == K::zero() {
            // Cell k not written at cycle j
            Ok(K::zero())
        } else if wa_kj == K::one() {
            // Cell k written at cycle j
            // Inc(k,j) = wv(j) - Val(k,j)
            Ok(write_value.sub(&current_value))
        } else {
            Err(format!(
                "wa(k,j) should be 0 or 1, got non-Boolean value"
            ))
        }
    }
    
    /// Compute wa(k,j) from tensor product of one-hot chunks
    /// wa(k,j) = Π_{ℓ=1}^d wa_ℓ(k_ℓ, j)
    fn compute_wa_at_k_j(
        &self,
        k: usize,
        j: usize,
        write_address: &OneHotAddress<K>,
    ) -> Result<K, String> {
        if write_address.d != self.dimension {
            return Err("Dimension mismatch".to_string());
        }
        
        let chunk_size = write_address.chunk_size;
        let mut product = K::one();
        let mut remaining_k = k;
        
        // For each dimension, extract digit and check one-hot
        for dim in 0..self.dimension {
            let k_digit = remaining_k % chunk_size;
            remaining_k /= chunk_size;
            
            // wa_ℓ(k_ℓ, j) is the k_digit-th element of chunks[dim]
            let wa_l = write_address.chunks[dim][k_digit];
            product = product.mul(&wa_l);
            
            // Early exit if product becomes 0
            if product == K::zero() {
                return Ok(K::zero());
            }
        }
        
        Ok(product)
    }
}

/// Sparse increment storage
/// Only stores non-zero increments with (cycle, value) pairs
pub struct IncrementStore<K: ExtensionFieldElement> {
    /// Sparse storage: cycle -> value
    increments: HashMap<usize, K>,
    
    /// Maximum number of cycles
    num_cycles: usize,
}

impl<K: ExtensionFieldElement> IncrementStore<K> {
    pub fn new(num_cycles: usize) -> Self {
        Self {
            increments: HashMap::new(),
            num_cycles,
        }
    }
    
    /// Add increment for cycle j
    pub fn add(&mut self, cycle: usize, value: K) {
        if cycle >= self.num_cycles {
            return;
        }
        
        if value != K::zero() {
            self.increments.insert(cycle, value);
        }
    }
    
    /// Get increment at cycle j (returns 0 if not stored)
    pub fn get(&self, cycle: usize) -> K {
        self.increments.get(&cycle).copied().unwrap_or(K::zero())
    }
    
    /// Get all non-zero increments as vector
    pub fn to_vec(&self) -> Vec<K> {
        let mut result = vec![K::zero(); self.num_cycles];
        for (&cycle, &value) in &self.increments {
            result[cycle] = value;
        }
        result
    }
    
    /// Get sparse representation
    pub fn to_sparse_vec(&self) -> Vec<(usize, K)> {
        let mut result: Vec<_> = self.increments.iter()
            .map(|(&c, &v)| (c, v))
            .collect();
        result.sort_by_key(|(c, _)| *c);
        result
    }
    
    /// Number of non-zero increments
    pub fn num_nonzero(&self) -> usize {
        self.increments.len()
    }
    
    /// Verify only T non-zero increments (at most one per cycle)
    pub fn verify_sparsity(&self) -> bool {
        self.increments.len() <= self.num_cycles
    }
    
    /// Verify increments are small (32-bit values for zkVM)
    pub fn verify_small_values(&self, max_bits: usize) -> bool {
        let max_value = (1u64 << max_bits) - 1;
        
        for &value in self.increments.values() {
            let coeffs = value.to_base_field_coefficients();
            for coeff in coeffs {
                if coeff.to_canonical_u64() > max_value {
                    return false;
                }
            }
        }
        
        true
    }
}
