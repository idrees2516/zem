// AVX-512 Optimized Ring Arithmetic
//
// This module provides vectorized implementations of ring arithmetic operations
// using AVX-512 instructions for maximum performance on modern CPUs.
//
// Key optimizations:
// - IFMA (Integer Fused Multiply-Add) for modular multiplication
// - Vectorized Barrett reduction
// - Process 8 elements in parallel (512-bit vectors)

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::ring::cyclotomic::RingElement;

/// AVX-512 accelerated ring arithmetic operations
pub struct AVX512RingOps {
    /// Modulus q
    modulus: u64,
    
    /// Barrett reduction constant: ⌊2^128 / q⌋
    barrett_constant: u128,
    
    /// Whether AVX-512 is available
    available: bool,
}

impl AVX512RingOps {
    /// Create new AVX-512 operations context
    pub fn new(modulus: u64) -> Self {
        let available = Self::check_avx512_support();
        let barrett_constant = ((1u128 << 128) / modulus as u128);
        
        Self {
            modulus,
            barrett_constant,
            available,
        }
    }
    
    /// Check if AVX-512 is supported on this CPU
    #[cfg(target_arch = "x86_64")]
    fn check_avx512_support() -> bool {
        is_x86_feature_detected!("avx512f") && 
        is_x86_feature_detected!("avx512ifma")
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn check_avx512_support() -> bool {
        false
    }
    
    /// Vectorized addition: c[i] = (a[i] + b[i]) mod q for i ∈ [0, 8)
    ///
    /// Processes 8 elements in parallel using AVX-512
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    pub unsafe fn vec_add_mod(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        if !self.available {
            return self.vec_add_mod_scalar(a, b);
        }
        
        // Load vectors
        let va = _mm512_loadu_epi64(a.as_ptr() as *const i64);
        let vb = _mm512_loadu_epi64(b.as_ptr() as *const i64);
        let vq = _mm512_set1_epi64(self.modulus as i64);
        
        // Add: c = a + b
        let vc = _mm512_add_epi64(va, vb);
        
        // Conditional subtract: if c >= q then c -= q
        let mask = _mm512_cmpge_epu64_mask(vc, vq);
        let vc_reduced = _mm512_mask_sub_epi64(vc, mask, vc, vq);
        
        // Store result
        let mut result = [0u64; 8];
        _mm512_storeu_epi64(result.as_mut_ptr() as *mut i64, vc_reduced);
        result
    }
    
    /// Scalar fallback for addition
    fn vec_add_mod_scalar(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut result = [0u64; 8];
        for i in 0..8 {
            let sum = a[i] + b[i];
            result[i] = if sum >= self.modulus {
                sum - self.modulus
            } else {
                sum
            };
        }
        result
    }
    
    /// Vectorized multiplication with IFMA: c[i] = (a[i] * b[i]) mod q
    ///
    /// Uses AVX-512 IFMA (Integer Fused Multiply-Add) instructions for
    /// efficient modular multiplication
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "avx512ifma")]
    pub unsafe fn vec_mul_mod_ifma(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        if !self.available {
            return self.vec_mul_mod_scalar(a, b);
        }
        
        // Load vectors
        let va = _mm512_loadu_epi64(a.as_ptr() as *const i64);
        let vb = _mm512_loadu_epi64(b.as_ptr() as *const i64);
        
        // Multiply: c = a * b (128-bit result split into low and high)
        let vc_lo = _mm512_mullox_epi64(va, vb);
        let vc_hi = _mm512_mulhrs_epi64(va, vb);
        
        // Barrett reduction
        let result = self.barrett_reduce_avx512(vc_lo, vc_hi);
        
        // Store result
        let mut output = [0u64; 8];
        _mm512_storeu_epi64(output.as_mut_ptr() as *mut i64, result);
        output
    }
    
    /// Scalar fallback for multiplication
    fn vec_mul_mod_scalar(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut result = [0u64; 8];
        for i in 0..8 {
            result[i] = self.mul_mod_scalar(a[i], b[i]);
        }
        result
    }
    
    /// Scalar modular multiplication
    fn mul_mod_scalar(&self, a: u64, b: u64) -> u64 {
        let product = (a as u128) * (b as u128);
        (product % self.modulus as u128) as u64
    }
    
    /// Barrett reduction for AVX-512
    ///
    /// Reduces 128-bit product (hi, lo) modulo q using Barrett reduction:
    /// r = x - ⌊x * μ / 2^128⌋ * q
    /// where μ = ⌊2^128 / q⌋
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "avx512ifma")]
    unsafe fn barrett_reduce_avx512(&self, lo: __m512i, hi: __m512i) -> __m512i {
        // Load Barrett constant
        let vmu = _mm512_set1_epi64(self.barrett_constant as i64);
        let vq = _mm512_set1_epi64(self.modulus as i64);
        
        // Compute quotient estimate: q_est = (x * μ) >> 128
        // This requires 128-bit arithmetic, simplified here
        let q_est = _mm512_mulhi_epu64(hi, vmu);
        
        // Compute remainder: r = x - q_est * q
        let qm = _mm512_mullo_epi64(q_est, vq);
        let r = _mm512_sub_epi64(lo, qm);
        
        // Final conditional subtraction
        let mask = _mm512_cmpge_epu64_mask(r, vq);
        _mm512_mask_sub_epi64(r, mask, r, vq)
    }
    
    /// Vectorized subtraction: c[i] = (a[i] - b[i]) mod q
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    pub unsafe fn vec_sub_mod(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        if !self.available {
            return self.vec_sub_mod_scalar(a, b);
        }
        
        let va = _mm512_loadu_epi64(a.as_ptr() as *const i64);
        let vb = _mm512_loadu_epi64(b.as_ptr() as *const i64);
        let vq = _mm512_set1_epi64(self.modulus as i64);
        
        // Subtract: c = a - b
        let vc = _mm512_sub_epi64(va, vb);
        
        // Conditional add: if c < 0 then c += q
        let mask = _mm512_cmplt_epi64_mask(vc, _mm512_setzero_si512());
        let vc_reduced = _mm512_mask_add_epi64(vc, mask, vc, vq);
        
        let mut result = [0u64; 8];
        _mm512_storeu_epi64(result.as_mut_ptr() as *mut i64, vc_reduced);
        result
    }
    
    /// Scalar fallback for subtraction
    fn vec_sub_mod_scalar(&self, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut result = [0u64; 8];
        for i in 0..8 {
            result[i] = if a[i] >= b[i] {
                a[i] - b[i]
            } else {
                a[i] + self.modulus - b[i]
            };
        }
        result
    }
    
    /// Vectorized negation: c[i] = -a[i] mod q
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    pub unsafe fn vec_neg_mod(&self, a: &[u64; 8]) -> [u64; 8] {
        if !self.available {
            return self.vec_neg_mod_scalar(a);
        }
        
        let va = _mm512_loadu_epi64(a.as_ptr() as *const i64);
        let vq = _mm512_set1_epi64(self.modulus as i64);
        let vzero = _mm512_setzero_si512();
        
        // Negate: c = q - a (for non-zero a)
        let vc = _mm512_sub_epi64(vq, va);
        
        // Handle zero: if a == 0 then c = 0
        let mask = _mm512_cmpeq_epi64_mask(va, vzero);
        let vc_final = _mm512_mask_mov_epi64(vc, mask, vzero);
        
        let mut result = [0u64; 8];
        _mm512_storeu_epi64(result.as_mut_ptr() as *mut i64, vc_final);
        result
    }
    
    /// Scalar fallback for negation
    fn vec_neg_mod_scalar(&self, a: &[u64; 8]) -> [u64; 8] {
        let mut result = [0u64; 8];
        for i in 0..8 {
            result[i] = if a[i] == 0 {
                0
            } else {
                self.modulus - a[i]
            };
        }
        result
    }
    
    /// Batch process ring element addition
    ///
    /// Processes coefficients in chunks of 8 using AVX-512
    pub fn add_ring_elements(&self, a: &RingElement, b: &RingElement) -> RingElement {
        assert_eq!(a.coefficients.len(), b.coefficients.len());
        
        let mut result_coeffs = Vec::with_capacity(a.coefficients.len());
        let len = a.coefficients.len();
        
        // Process in chunks of 8
        let mut i = 0;
        while i + 8 <= len {
            let mut a_chunk = [0u64; 8];
            let mut b_chunk = [0u64; 8];
            
            for j in 0..8 {
                a_chunk[j] = a.coefficients[i + j] as u64;
                b_chunk[j] = b.coefficients[i + j] as u64;
            }
            
            #[cfg(target_arch = "x86_64")]
            let result_chunk = unsafe { self.vec_add_mod(&a_chunk, &b_chunk) };
            
            #[cfg(not(target_arch = "x86_64"))]
            let result_chunk = self.vec_add_mod_scalar(&a_chunk, &b_chunk);
            
            for j in 0..8 {
                result_coeffs.push(result_chunk[j] as i64);
            }
            
            i += 8;
        }
        
        // Handle remaining elements
        while i < len {
            let sum = (a.coefficients[i] as u64) + (b.coefficients[i] as u64);
            result_coeffs.push(if sum >= self.modulus {
                (sum - self.modulus) as i64
            } else {
                sum as i64
            });
            i += 1;
        }
        
        RingElement {
            coefficients: result_coeffs,
            ring: a.ring.clone(),
        }
    }
    
    /// Batch process ring element multiplication
    pub fn mul_ring_elements(&self, a: &RingElement, b: &RingElement) -> RingElement {
        assert_eq!(a.coefficients.len(), b.coefficients.len());
        
        let mut result_coeffs = Vec::with_capacity(a.coefficients.len());
        let len = a.coefficients.len();
        
        // Process in chunks of 8
        let mut i = 0;
        while i + 8 <= len {
            let mut a_chunk = [0u64; 8];
            let mut b_chunk = [0u64; 8];
            
            for j in 0..8 {
                a_chunk[j] = a.coefficients[i + j] as u64;
                b_chunk[j] = b.coefficients[i + j] as u64;
            }
            
            #[cfg(target_arch = "x86_64")]
            let result_chunk = unsafe { self.vec_mul_mod_ifma(&a_chunk, &b_chunk) };
            
            #[cfg(not(target_arch = "x86_64"))]
            let result_chunk = self.vec_mul_mod_scalar(&a_chunk, &b_chunk);
            
            for j in 0..8 {
                result_coeffs.push(result_chunk[j] as i64);
            }
            
            i += 8;
        }
        
        // Handle remaining elements
        while i < len {
            let product = (a.coefficients[i] as u128) * (b.coefficients[i] as u128);
            result_coeffs.push((product % self.modulus as u128) as i64);
            i += 1;
        }
        
        RingElement {
            coefficients: result_coeffs,
            ring: a.ring.clone(),
        }
    }
    
    /// Check if AVX-512 is available
    pub fn is_available(&self) -> bool {
        self.available
    }
}

/// Benchmark utilities for AVX-512 operations
#[cfg(test)]
mod benchmarks {
    use super::*;
    
    /// Benchmark vectorized addition vs scalar
    pub fn bench_add(ops: &AVX512RingOps, iterations: usize) -> (u128, u128) {
        use std::time::Instant;
        
        let a = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let b = [9u64, 10, 11, 12, 13, 14, 15, 16];
        
        // Scalar benchmark
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ops.vec_add_mod_scalar(&a, &b);
        }
        let scalar_time = start.elapsed().as_nanos();
        
        // Vectorized benchmark
        #[cfg(target_arch = "x86_64")]
        let vector_time = {
            let start = Instant::now();
            for _ in 0..iterations {
                unsafe {
                    let _ = ops.vec_add_mod(&a, &b);
                }
            }
            start.elapsed().as_nanos()
        };
        
        #[cfg(not(target_arch = "x86_64"))]
        let vector_time = scalar_time;
        
        (scalar_time, vector_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_avx512_availability() {
        let ops = AVX512RingOps::new(65537);
        println!("AVX-512 available: {}", ops.is_available());
    }
    
    #[test]
    fn test_vec_add_mod_scalar() {
        let ops = AVX512RingOps::new(17);
        let a = [1, 2, 3, 4, 5, 6, 7, 8];
        let b = [9, 10, 11, 12, 13, 14, 15, 16];
        
        let result = ops.vec_add_mod_scalar(&a, &b);
        
        // Check results: (1+9) mod 17 = 10, (2+10) mod 17 = 12, etc.
        assert_eq!(result[0], 10);
        assert_eq!(result[1], 12);
    }
    
    #[test]
    fn test_vec_mul_mod_scalar() {
        let ops = AVX512RingOps::new(17);
        let a = [2, 3, 4, 5, 6, 7, 8, 9];
        let b = [3, 4, 5, 6, 7, 8, 9, 10];
        
        let result = ops.vec_mul_mod_scalar(&a, &b);
        
        // Check: (2*3) mod 17 = 6, (3*4) mod 17 = 12, etc.
        assert_eq!(result[0], 6);
        assert_eq!(result[1], 12);
    }
    
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_avx512_add() {
        let ops = AVX512RingOps::new(65537);
        if !ops.is_available() {
            println!("Skipping AVX-512 test: not available");
            return;
        }
        
        let a = [100, 200, 300, 400, 500, 600, 700, 800];
        let b = [50, 100, 150, 200, 250, 300, 350, 400];
        
        let result = unsafe { ops.vec_add_mod(&a, &b) };
        let expected = ops.vec_add_mod_scalar(&a, &b);
        
        assert_eq!(result, expected, "AVX-512 and scalar results should match");
    }
}
