// NTT optimizations for Neo
//
// Task 17.3: Implement NTT optimizations
// - Precomputed twiddle factors
// - Bit-reversal permutation optimization
// - Cache-friendly memory access patterns
// - Benchmark and profile NTT performance

use crate::field::Field;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Precomputed twiddle factors for NTT
///
/// Twiddle factors are roots of unity used in NTT computation.
/// Precomputing and caching them significantly improves performance.
#[derive(Clone)]
pub struct TwiddleFactors<F: Field> {
    /// Degree of NTT (must be power of 2)
    degree: usize,
    
    /// Forward twiddle factors: ω^i for i in 0..degree
    forward: Vec<F>,
    
    /// Inverse twiddle factors: ω^(-i) for i in 0..degree
    inverse: Vec<F>,
    
    /// Bit-reversed indices for in-place NTT
    bit_reversed_indices: Vec<usize>,
}

impl<F: Field> TwiddleFactors<F> {
    /// Compute twiddle factors for given degree
    ///
    /// # Arguments
    /// * `degree` - NTT degree (must be power of 2)
    /// * `root_of_unity` - Primitive nth root of unity
    ///
    /// # Returns
    /// Precomputed twiddle factors
    pub fn new(degree: usize, root_of_unity: F) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be power of 2");
        
        // Compute forward twiddle factors: ω^i
        let mut forward = Vec::with_capacity(degree);
        let mut current = F::one();
        for _ in 0..degree {
            forward.push(current);
            current = current.mul(&root_of_unity);
        }
        
        // Compute inverse twiddle factors: ω^(-i)
        let root_inv = root_of_unity.inv().expect("Root of unity must be invertible");
        let mut inverse = Vec::with_capacity(degree);
        let mut current = F::one();
        for _ in 0..degree {
            inverse.push(current);
            current = current.mul(&root_inv);
        }
        
        // Precompute bit-reversed indices
        let bit_reversed_indices = Self::compute_bit_reversal_indices(degree);
        
        Self {
            degree,
            forward,
            inverse,
            bit_reversed_indices,
        }
    }
    
    /// Compute bit-reversal permutation indices
    fn compute_bit_reversal_indices(n: usize) -> Vec<usize> {
        let log_n = n.trailing_zeros() as usize;
        let mut indices = vec![0; n];
        
        for i in 0..n {
            indices[i] = Self::reverse_bits(i, log_n);
        }
        
        indices
    }
    
    /// Reverse bits of a number
    fn reverse_bits(mut x: usize, num_bits: usize) -> usize {
        let mut result = 0;
        for _ in 0..num_bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }
    
    /// Get forward twiddle factor ω^i
    pub fn forward(&self, i: usize) -> F {
        self.forward[i % self.degree]
    }
    
    /// Get inverse twiddle factor ω^(-i)
    pub fn inverse(&self, i: usize) -> F {
        self.inverse[i % self.degree]
    }
    
    /// Get bit-reversed index
    pub fn bit_reversed(&self, i: usize) -> usize {
        self.bit_reversed_indices[i]
    }
    
    /// Apply bit-reversal permutation to a vector
    pub fn bit_reverse_permute(&self, data: &mut [F]) {
        assert_eq!(data.len(), self.degree);
        
        for i in 0..self.degree {
            let j = self.bit_reversed_indices[i];
            if i < j {
                data.swap(i, j);
            }
        }
    }
}

/// NTT cache for storing precomputed twiddle factors
///
/// Caches twiddle factors for different degrees to avoid recomputation.
pub struct NTTCache<F: Field> {
    /// Cached twiddle factors by degree
    cache: Arc<Mutex<HashMap<usize, TwiddleFactors<F>>>>,
}

impl<F: Field> NTTCache<F> {
    /// Create a new NTT cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Get or compute twiddle factors for given degree
    ///
    /// # Arguments
    /// * `degree` - NTT degree
    /// * `root_of_unity` - Primitive nth root of unity
    pub fn get_or_compute(
        &self,
        degree: usize,
        root_of_unity: F,
    ) -> TwiddleFactors<F> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(factors) = cache.get(&degree) {
            return factors.clone();
        }
        
        let factors = TwiddleFactors::new(degree, root_of_unity);
        cache.insert(degree, factors.clone());
        factors
    }
    
    /// Clear the cache
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
    
    /// Get cache size
    pub fn size(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
}

impl<F: Field> Default for NTTCache<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Optimized NTT implementation with precomputed twiddle factors
pub struct OptimizedNTT<F: Field> {
    /// Twiddle factors
    twiddles: TwiddleFactors<F>,
    
    /// Inverse of degree for scaling
    degree_inv: F,
}

impl<F: Field> OptimizedNTT<F> {
    /// Create a new optimized NTT
    pub fn new(degree: usize, root_of_unity: F) -> Self {
        let twiddles = TwiddleFactors::new(degree, root_of_unity);
        let degree_inv = F::from_canonical_u64(degree as u64)
            .inv()
            .expect("Degree must be invertible");
        
        Self {
            twiddles,
            degree_inv,
        }
    }
    
    /// Forward NTT (Cooley-Tukey decimation-in-time)
    ///
    /// Computes NTT in-place with O(n log n) complexity.
    /// Uses cache-friendly butterfly operations.
    ///
    /// # Arguments
    /// * `data` - Input/output data (modified in-place)
    pub fn forward_ntt(&self, data: &mut [F]) {
        let n = data.len();
        assert_eq!(n, self.twiddles.degree);
        
        // Bit-reversal permutation
        self.twiddles.bit_reverse_permute(data);
        
        // Cooley-Tukey butterfly operations
        let mut m = 1;
        while m < n {
            let m2 = m * 2;
            
            for k in 0..n / m2 {
                for j in 0..m {
                    let idx1 = k * m2 + j;
                    let idx2 = idx1 + m;
                    
                    // Twiddle factor: ω^(j * n / m2)
                    let twiddle_idx = j * (n / m2);
                    let twiddle = self.twiddles.forward(twiddle_idx);
                    
                    // Butterfly operation
                    let t = twiddle.mul(&data[idx2]);
                    let u = data[idx1];
                    
                    data[idx1] = u.add(&t);
                    data[idx2] = u.sub(&t);
                }
            }
            
            m = m2;
        }
    }
    
    /// Inverse NTT (Gentleman-Sande decimation-in-frequency)
    ///
    /// Computes inverse NTT in-place with O(n log n) complexity.
    /// Includes scaling by 1/n.
    ///
    /// # Arguments
    /// * `data` - Input/output data (modified in-place)
    pub fn inverse_ntt(&self, data: &mut [F]) {
        let n = data.len();
        assert_eq!(n, self.twiddles.degree);
        
        // Gentleman-Sande butterfly operations
        let mut m = n;
        while m > 1 {
            let m2 = m / 2;
            
            for k in 0..n / m {
                for j in 0..m2 {
                    let idx1 = k * m + j;
                    let idx2 = idx1 + m2;
                    
                    // Butterfly operation
                    let u = data[idx1];
                    let v = data[idx2];
                    
                    data[idx1] = u.add(&v);
                    
                    // Twiddle factor: ω^(-j * n / m)
                    let twiddle_idx = j * (n / m);
                    let twiddle = self.twiddles.inverse(twiddle_idx);
                    
                    data[idx2] = u.sub(&v).mul(&twiddle);
                }
            }
            
            m = m2;
        }
        
        // Bit-reversal permutation
        self.twiddles.bit_reverse_permute(data);
        
        // Scale by 1/n
        for val in data.iter_mut() {
            *val = val.mul(&self.degree_inv);
        }
    }
    
    /// Forward NTT without bit-reversal (for specialized use cases)
    pub fn forward_ntt_no_bitrev(&self, data: &mut [F]) {
        let n = data.len();
        assert_eq!(n, self.twiddles.degree);
        
        let mut m = 1;
        while m < n {
            let m2 = m * 2;
            
            for k in 0..n / m2 {
                for j in 0..m {
                    let idx1 = k * m2 + j;
                    let idx2 = idx1 + m;
                    
                    let twiddle_idx = j * (n / m2);
                    let twiddle = self.twiddles.forward(twiddle_idx);
                    
                    let t = twiddle.mul(&data[idx2]);
                    let u = data[idx1];
                    
                    data[idx1] = u.add(&t);
                    data[idx2] = u.sub(&t);
                }
            }
            
            m = m2;
        }
    }
}

/// Precompute twiddle factors for common NTT sizes
///
/// Returns a cache with precomputed twiddle factors for powers of 2
/// up to max_degree.
pub fn precompute_twiddles<F: Field>(
    max_degree: usize,
    root_of_unity: F,
) -> NTTCache<F> {
    let cache = NTTCache::new();
    
    let mut degree = 2;
    while degree <= max_degree {
        // Compute appropriate root for this degree
        let log_ratio = (max_degree / degree).trailing_zeros();
        let mut root = root_of_unity;
        for _ in 0..log_ratio {
            root = root.mul(&root); // Square to get root for smaller degree
        }
        
        cache.get_or_compute(degree, root);
        degree *= 2;
    }
    
    cache
}

/// Cache-friendly NTT with blocked computation
///
/// Processes data in cache-friendly blocks to improve memory locality.
pub struct BlockedNTT<F: Field> {
    /// Base NTT implementation
    ntt: OptimizedNTT<F>,
    
    /// Block size for cache-friendly access
    block_size: usize,
}

impl<F: Field> BlockedNTT<F> {
    /// Create a new blocked NTT
    pub fn new(degree: usize, root_of_unity: F, block_size: usize) -> Self {
        Self {
            ntt: OptimizedNTT::new(degree, root_of_unity),
            block_size,
        }
    }
    
    /// Forward NTT with blocked computation
    ///
    /// Processes data in cache-friendly blocks to improve memory locality.
    /// Uses a hybrid approach:
    /// 1. Standard NTT for small transforms (fits in L1 cache)
    /// 2. Blocked NTT for large transforms (cache-conscious)
    pub fn forward_ntt(&self, data: &mut [F]) {
        let n = data.len();
        
        // For small transforms, use standard NTT (fits in cache)
        if n <= 1024 {
            self.ntt.forward_ntt(data);
            return;
        }
        
        // For large transforms, use cache-blocked algorithm
        self.forward_ntt_blocked(data);
    }
    
    /// Cache-blocked forward NTT implementation
    fn forward_ntt_blocked(&self, data: &mut [F]) {
        let n = data.len();
        
        // Bit-reversal permutation
        self.ntt.twiddles.bit_reverse_permute(data);
        
        // Cooley-Tukey with cache blocking
        let mut m = 1;
        while m < n {
            let m2 = m * 2;
            
            // Process in blocks that fit in cache
            let num_butterflies = n / m2;
            
            if num_butterflies * m <= self.block_size {
                // Small enough to process all at once
                for k in 0..num_butterflies {
                    for j in 0..m {
                        let idx1 = k * m2 + j;
                        let idx2 = idx1 + m;
                        
                        let twiddle_idx = j * (n / m2);
                        let twiddle = self.ntt.twiddles.forward(twiddle_idx);
                        
                        let t = twiddle.mul(&data[idx2]);
                        let u = data[idx1];
                        
                        data[idx1] = u.add(&t);
                        data[idx2] = u.sub(&t);
                    }
                }
            } else {
                // Process in cache-sized blocks
                for k_block in (0..num_butterflies).step_by(self.block_size / m) {
                    let k_end = (k_block + self.block_size / m).min(num_butterflies);
                    
                    for k in k_block..k_end {
                        for j in 0..m {
                            let idx1 = k * m2 + j;
                            let idx2 = idx1 + m;
                            
                            let twiddle_idx = j * (n / m2);
                            let twiddle = self.ntt.twiddles.forward(twiddle_idx);
                            
                            let t = twiddle.mul(&data[idx2]);
                            let u = data[idx1];
                            
                            data[idx1] = u.add(&t);
                            data[idx2] = u.sub(&t);
                        }
                    }
                }
            }
            
            m = m2;
        }
    }
    
    /// Inverse NTT with blocked computation
    ///
    /// Cache-friendly inverse NTT for large transforms.
    pub fn inverse_ntt(&self, data: &mut [F]) {
        let n = data.len();
        
        // For small transforms, use standard inverse NTT
        if n <= 1024 {
            self.ntt.inverse_ntt(data);
            return;
        }
        
        // For large transforms, use cache-blocked algorithm
        self.inverse_ntt_blocked(data);
    }
    
    /// Cache-blocked inverse NTT implementation
    fn inverse_ntt_blocked(&self, data: &mut [F]) {
        let n = data.len();
        
        // Gentleman-Sande with cache blocking
        let mut m = n;
        while m > 1 {
            let m2 = m / 2;
            let num_groups = n / m;
            
            if num_groups * m2 <= self.block_size {
                // Small enough to process all at once
                for k in 0..num_groups {
                    for j in 0..m2 {
                        let idx1 = k * m + j;
                        let idx2 = idx1 + m2;
                        
                        let u = data[idx1];
                        let v = data[idx2];
                        
                        data[idx1] = u.add(&v);
                        
                        let twiddle_idx = j * (n / m);
                        let twiddle = self.ntt.twiddles.inverse(twiddle_idx);
                        
                        data[idx2] = u.sub(&v).mul(&twiddle);
                    }
                }
            } else {
                // Process in cache-sized blocks
                for k_block in (0..num_groups).step_by(self.block_size / m2) {
                    let k_end = (k_block + self.block_size / m2).min(num_groups);
                    
                    for k in k_block..k_end {
                        for j in 0..m2 {
                            let idx1 = k * m + j;
                            let idx2 = idx1 + m2;
                            
                            let u = data[idx1];
                            let v = data[idx2];
                            
                            data[idx1] = u.add(&v);
                            
                            let twiddle_idx = j * (n / m);
                            let twiddle = self.ntt.twiddles.inverse(twiddle_idx);
                            
                            data[idx2] = u.sub(&v).mul(&twiddle);
                        }
                    }
                }
            }
            
            m = m2;
        }
        
        // Bit-reversal permutation
        self.ntt.twiddles.bit_reverse_permute(data);
        
        // Scale by 1/n
        for val in data.iter_mut() {
            *val = val.mul(&self.ntt.degree_inv);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;
    
    #[test]
    fn test_bit_reversal() {
        let indices = TwiddleFactors::<GoldilocksField>::compute_bit_reversal_indices(8);
        
        // For n=8 (3 bits): bit reversal of 0b001 (1) is 0b100 (4)
        assert_eq!(indices[1], 4);
        assert_eq!(indices[2], 2);
        assert_eq!(indices[3], 6);
        assert_eq!(indices[4], 1);
    }
    
    #[test]
    fn test_twiddle_factors() {
        // Use a simple root of unity for testing
        let root = GoldilocksField::from_canonical_u64(2);
        let twiddles = TwiddleFactors::new(4, root);
        
        assert_eq!(twiddles.degree, 4);
        assert_eq!(twiddles.forward(0).to_canonical_u64(), 1); // ω^0 = 1
    }
    
    #[test]
    fn test_ntt_cache() {
        let cache = NTTCache::<GoldilocksField>::new();
        let root = GoldilocksField::from_canonical_u64(2);
        
        let factors1 = cache.get_or_compute(8, root);
        let factors2 = cache.get_or_compute(8, root);
        
        // Should return cached version
        assert_eq!(cache.size(), 1);
        assert_eq!(factors1.degree, factors2.degree);
    }
    
    #[test]
    fn test_ntt_round_trip() {
        // Find a primitive 8th root of unity in Goldilocks field
        // For testing, we'll use a simple value
        let root = GoldilocksField::from_canonical_u64(1753635133440165772);
        
        let ntt = OptimizedNTT::new(8, root);
        
        let mut data = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
            GoldilocksField::from_canonical_u64(4),
            GoldilocksField::from_canonical_u64(5),
            GoldilocksField::from_canonical_u64(6),
            GoldilocksField::from_canonical_u64(7),
            GoldilocksField::from_canonical_u64(8),
        ];
        
        let original = data.clone();
        
        // Forward then inverse should recover original
        ntt.forward_ntt(&mut data);
        ntt.inverse_ntt(&mut data);
        
        for (a, b) in data.iter().zip(original.iter()) {
            assert_eq!(a.to_canonical_u64(), b.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_precompute_twiddles() {
        let root = GoldilocksField::from_canonical_u64(2);
        let cache = precompute_twiddles(16, root);
        
        // Should have cached multiple sizes
        assert!(cache.size() > 0);
    }
}
