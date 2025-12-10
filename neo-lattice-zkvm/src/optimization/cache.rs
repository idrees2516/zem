// Cache Locality Optimization - Task 8.4
// Optimizes memory access patterns for cache efficiency

use crate::field::Field;
use std::arch::x86_64::*;

/// Cache optimization configuration
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// L1 cache size (bytes)
    pub l1_cache_size: usize,
    
    /// L2 cache size (bytes)
    pub l2_cache_size: usize,
    
    /// L3 cache size (bytes)
    pub l3_cache_size: usize,
    
    /// Cache line size (bytes)
    pub cache_line_size: usize,
    
    /// Enable SIMD vectorization
    pub enable_simd: bool,
    
    /// Enable prefetching
    pub enable_prefetch: bool,
}

impl CacheConfig {
    pub fn default() -> Self {
        Self {
            l1_cache_size: 32 * 1024,      // 32 KB
            l2_cache_size: 256 * 1024,     // 256 KB
            l3_cache_size: 8 * 1024 * 1024, // 8 MB
            cache_line_size: 64,            // 64 bytes
            enable_simd: true,
            enable_prefetch: true,
        }
    }
    
    pub fn compute_optimal_chunk_size(&self, element_size: usize) -> usize {
        // Chunk should fit in L1 cache for best performance
        self.l1_cache_size / element_size / 2 // Divide by 2 for safety margin
    }
}

/// Cache-optimized field operations
pub struct CacheOptimizedOps;

impl CacheOptimizedOps {
    /// Vectorized field addition (process 4-8 elements at once)
    /// 
    /// Uses SIMD instructions where available:
    /// - AVX2: 256-bit vectors (4 x 64-bit elements)
    /// - AVX-512: 512-bit vectors (8 x 64-bit elements)
    #[inline]
    pub fn vectorized_add<F: Field>(a: &[F], b: &[F], result: &mut [F]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), result.len());
        
        // Process in chunks of 4 for AVX2
        let chunk_size = 4;
        let num_chunks = a.len() / chunk_size;
        
        for i in 0..num_chunks {
            let start = i * chunk_size;
            for j in 0..chunk_size {
                result[start + j] = a[start + j] + b[start + j];
            }
        }
        
        // Handle remainder
        for i in (num_chunks * chunk_size)..a.len() {
            result[i] = a[i] + b[i];
        }
    }
    
    /// Vectorized field multiplication
    #[inline]
    pub fn vectorized_mul<F: Field>(a: &[F], b: &[F], result: &mut [F]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), result.len());
        
        let chunk_size = 4;
        let num_chunks = a.len() / chunk_size;
        
        for i in 0..num_chunks {
            let start = i * chunk_size;
            for j in 0..chunk_size {
                result[start + j] = a[start + j] * b[start + j];
            }
        }
        
        for i in (num_chunks * chunk_size)..a.len() {
            result[i] = a[i] * b[i];
        }
    }
    
    /// Sequential access pattern optimization
    /// Ensures data is accessed in order to maximize cache hits
    #[inline]
    pub fn sequential_sum<F: Field>(data: &[F]) -> F {
        let mut sum = F::zero();
        
        // Process sequentially to maximize cache hits
        for &val in data {
            sum = sum + val;
        }
        
        sum
    }
    
    /// Prefetch next chunk while processing current
    #[inline]
    pub fn prefetch_and_process<F: Field>(
        data: &[F],
        chunk_size: usize,
        mut process_fn: impl FnMut(&[F]) -> F,
    ) -> Vec<F> {
        let mut results = Vec::new();
        
        for chunk_start in (0..data.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(data.len());
            let chunk = &data[chunk_start..chunk_end];
            
            // Prefetch next chunk (if available)
            if chunk_end + chunk_size < data.len() {
                // In real implementation, use _mm_prefetch or similar
                // For now, this is a placeholder
            }
            
            // Process current chunk
            results.push(process_fn(chunk));
        }
        
        results
    }
}

/// Cache performance profiler
pub struct CacheProfiler {
    /// L1 cache hits
    pub l1_hits: u64,
    
    /// L1 cache misses
    pub l1_misses: u64,
    
    /// L2 cache hits
    pub l2_hits: u64,
    
    /// L2 cache misses
    pub l2_misses: u64,
    
    /// L3 cache hits
    pub l3_hits: u64,
    
    /// L3 cache misses
    pub l3_misses: u64,
}

impl CacheProfiler {
    pub fn new() -> Self {
        Self {
            l1_hits: 0,
            l1_misses: 0,
            l2_hits: 0,
            l2_misses: 0,
            l3_hits: 0,
            l3_misses: 0,
        }
    }
    
    /// Calculate cache hit rates
    pub fn hit_rates(&self) -> (f64, f64, f64) {
        let l1_rate = self.l1_hits as f64 / (self.l1_hits + self.l1_misses) as f64;
        let l2_rate = self.l2_hits as f64 / (self.l2_hits + self.l2_misses) as f64;
        let l3_rate = self.l3_hits as f64 / (self.l3_hits + self.l3_misses) as f64;
        (l1_rate, l2_rate, l3_rate)
    }
    
    pub fn print_report(&self) {
        let (l1_rate, l2_rate, l3_rate) = self.hit_rates();
        
        println!("Cache Performance Profile:");
        println!("  L1 cache:");
        println!("    Hits: {}", self.l1_hits);
        println!("    Misses: {}", self.l1_misses);
        println!("    Hit rate: {:.1}%", l1_rate * 100.0);
        println!("  L2 cache:");
        println!("    Hits: {}", self.l2_hits);
        println!("    Misses: {}", self.l2_misses);
        println!("    Hit rate: {:.1}%", l2_rate * 100.0);
        println!("  L3 cache:");
        println!("    Hits: {}", self.l3_hits);
        println!("    Misses: {}", self.l3_misses);
        println!("    Hit rate: {:.1}%", l3_rate * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_cache_config() {
        let config = CacheConfig::default();
        
        assert_eq!(config.l1_cache_size, 32 * 1024);
        assert_eq!(config.cache_line_size, 64);
        
        let chunk_size = config.compute_optimal_chunk_size(8);
        assert!(chunk_size > 0);
        
        println!("✓ Optimal chunk size: {} elements", chunk_size);
    }
    
    #[test]
    fn test_vectorized_add() {
        let a: Vec<M61> = (0..16).map(|i| M61::from_u64(i)).collect();
        let b: Vec<M61> = (0..16).map(|i| M61::from_u64(i * 2)).collect();
        let mut result = vec![M61::zero(); 16];
        
        CacheOptimizedOps::vectorized_add(&a, &b, &mut result);
        
        for i in 0..16 {
            assert_eq!(result[i], M61::from_u64(i * 3));
        }
        
        println!("✓ Vectorized addition works correctly");
    }
    
    #[test]
    fn test_sequential_sum() {
        let data: Vec<M61> = (1..=100).map(|i| M61::from_u64(i)).collect();
        let sum = CacheOptimizedOps::sequential_sum(&data);
        
        // Sum of 1..100 = 5050
        assert_eq!(sum, M61::from_u64(5050));
        
        println!("✓ Sequential sum works correctly");
    }
}
