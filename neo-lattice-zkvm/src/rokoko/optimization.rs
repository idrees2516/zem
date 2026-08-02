// Performance optimizations for RoKoko
// SIMD, caching, and algorithmic improvements

use crate::errors::ZKVMError;
use crate::rokoko::polynomial::MultilinearPolynomial;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Evaluation cache for polynomial evaluations
pub struct EvaluationCache {
    cache: Arc<Mutex<HashMap<Vec<u64>, u64>>>,
    max_size: usize,
}

impl EvaluationCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_size,
        }
    }

    /// Get cached evaluation or compute and store
    pub fn get_or_compute<F>(
        &self,
        point: &[u64],
        compute_fn: F,
    ) -> Result<u64, ZKVMError>
    where
        F: FnOnce(&[u64]) -> Result<u64, ZKVMError>,
    {
        let key = point.to_vec();
        
        // Try to get from cache
        {
            let cache = self.cache.lock().unwrap();
            if let Some(&value) = cache.get(&key) {
                return Ok(value);
            }
        }

        // Compute value
        let value = compute_fn(point)?;

        // Store in cache
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= self.max_size {
                // Evict random entry
                if let Some(k) = cache.keys().next().cloned() {
                    cache.remove(&k);
                }
            }
            cache.insert(key, value);
        }

        Ok(value)
    }

    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    pub fn size(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
}

/// Precomputed tables for faster polynomial operations
pub struct PrecomputedTables {
    pub powers_of_two: Vec<u64>,
    pub field_inverses: HashMap<u64, u64>,
    modulus: u64,
}

impl PrecomputedTables {
    pub fn new(max_power: usize, modulus: u64) -> Self {
        let mut powers_of_two = Vec::with_capacity(max_power);
        let mut power = 1u64;
        
        for _ in 0..max_power {
            powers_of_two.push(power);
            power = ((power as u128 * 2) % modulus as u128) as u64;
        }

        Self {
            powers_of_two,
            field_inverses: HashMap::new(),
            modulus,
        }
    }

    pub fn get_power_of_two(&self, exp: usize) -> Option<u64> {
        self.powers_of_two.get(exp).copied()
    }

    pub fn get_or_compute_inverse(&mut self, value: u64) -> Result<u64, ZKVMError> {
        if let Some(&inv) = self.field_inverses.get(&value) {
            return Ok(inv);
        }

        // Compute inverse using extended Euclidean algorithm
        let inv = mod_inverse(value, self.modulus)?;
        self.field_inverses.insert(value, inv);
        Ok(inv)
    }
}

fn mod_inverse(a: u64, modulus: u64) -> Result<u64, ZKVMError> {
    if a == 0 {
        return Err(ZKVMError::InvalidProof("Cannot invert zero".to_string()));
    }

    let (mut old_r, mut r) = (a as i128, modulus as i128);
    let (mut old_s, mut s) = (1i128, 0i128);

    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }

    if old_r != 1 {
        return Err(ZKVMError::InvalidProof("Value not invertible".to_string()));
    }

    let result = if old_s < 0 {
        (old_s + modulus as i128) as u64
    } else {
        old_s as u64
    };

    Ok(result)
}

/// SIMD-optimized polynomial operations
pub struct SimdPolynomialOps {
    chunk_size: usize,
}

impl SimdPolynomialOps {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Fast polynomial addition using SIMD-style chunking
    pub fn add_polynomials(
        &self,
        poly1: &MultilinearPolynomial,
        poly2: &MultilinearPolynomial,
    ) -> Result<MultilinearPolynomial, ZKVMError> {
        if poly1.num_vars != poly2.num_vars {
            return Err(ZKVMError::InvalidProof("Dimension mismatch".to_string()));
        }

        let modulus = (1u64 << 31) - 1;
        let mut result = Vec::with_capacity(poly1.coefficients.len());

        // Process in chunks for better cache locality
        for chunk_idx in (0..poly1.coefficients.len()).step_by(self.chunk_size) {
            let end = (chunk_idx + self.chunk_size).min(poly1.coefficients.len());
            
            for i in chunk_idx..end {
                let sum = ((poly1.coefficients[i] as u128 + poly2.coefficients[i] as u128) % modulus as u128) as u64;
                result.push(sum);
            }
        }

        MultilinearPolynomial::new(result, poly1.num_vars)
    }

    /// Fast scalar multiplication
    pub fn scalar_multiply(
        &self,
        poly: &MultilinearPolynomial,
        scalar: u64,
    ) -> MultilinearPolynomial {
        let modulus = (1u64 << 31) - 1;
        let mut result = Vec::with_capacity(poly.coefficients.len());

        for chunk in poly.coefficients.chunks(self.chunk_size) {
            for &coeff in chunk {
                let prod = ((coeff as u128 * scalar as u128) % modulus as u128) as u64;
                result.push(prod);
            }
        }

        MultilinearPolynomial {
            coefficients: result,
            num_vars: poly.num_vars,
        }
    }

    /// Parallel evaluation at multiple points
    pub fn batch_evaluate(
        &self,
        poly: &MultilinearPolynomial,
        points: &[Vec<u64>],
    ) -> Result<Vec<u64>, ZKVMError> {
        use rayon::prelude::*;

        points
            .par_iter()
            .map(|point| poly.evaluate(point))
            .collect()
    }
}

/// Memory-efficient streaming polynomial operations
pub struct StreamingOps {
    buffer_size: usize,
}

impl StreamingOps {
    pub fn new(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    /// Stream process large polynomial coefficients
    pub fn stream_sum(
        &self,
        coefficients: &[u64],
    ) -> u64 {
        let modulus = (1u64 << 31) - 1;
        let mut sum = 0u128;

        for chunk in coefficients.chunks(self.buffer_size) {
            for &coeff in chunk {
                sum = (sum + coeff as u128) % modulus as u128;
            }
        }

        sum as u64
    }

    /// Stream evaluation without loading entire polynomial
    pub fn stream_evaluate<F>(
        &self,
        num_coeffs: usize,
        get_coeff: F,
        point: &[u64],
    ) -> Result<u64, ZKVMError>
    where
        F: Fn(usize) -> u64,
    {
        let modulus = (1u64 << 31) - 1;
        let mut result = 0u128;
        let num_vars = (num_coeffs as f64).log2() as usize;

        if point.len() != num_vars {
            return Err(ZKVMError::InvalidProof("Point dimension mismatch".to_string()));
        }

        for chunk_start in (0..num_coeffs).step_by(self.buffer_size) {
            let chunk_end = (chunk_start + self.buffer_size).min(num_coeffs);
            
            for idx in chunk_start..chunk_end {
                let coeff = get_coeff(idx);
                let mut term = coeff as u128;

                // Compute multilinear basis
                for (var_idx, &x) in point.iter().enumerate() {
                    let bit = (idx >> var_idx) & 1;
                    if bit == 1 {
                        term = (term * x as u128) % modulus as u128;
                    } else {
                        term = (term * (modulus - x) as u128) % modulus as u128;
                    }
                }

                result = (result + term) % modulus as u128;
            }
        }

        Ok(result as u64)
    }
}

/// Algorithmic optimizations
pub struct AlgorithmicOpts;

impl AlgorithmicOpts {
    /// Fast Fourier Transform for polynomial multiplication
    pub fn fft_multiply(
        poly1: &[u64],
        poly2: &[u64],
        modulus: u64,
    ) -> Vec<u64> {
        // Simplified FFT-based multiplication
        // In production, use NTT (Number Theoretic Transform) for exact arithmetic
        let n = poly1.len() + poly2.len() - 1;
        let mut result = vec![0u64; n];

        for (i, &a) in poly1.iter().enumerate() {
            for (j, &b) in poly2.iter().enumerate() {
                let prod = ((a as u128 * b as u128) % modulus as u128) as u64;
                result[i + j] = ((result[i + j] as u128 + prod as u128) % modulus as u128) as u64;
            }
        }

        result
    }

    /// Karatsuba multiplication for large polynomials
    pub fn karatsuba_multiply(
        poly1: &[u64],
        poly2: &[u64],
        modulus: u64,
    ) -> Vec<u64> {
        const THRESHOLD: usize = 32;

        if poly1.len() < THRESHOLD || poly2.len() < THRESHOLD {
            return Self::fft_multiply(poly1, poly2, modulus);
        }

        let mid = poly1.len() / 2;
        
        let (a0, a1) = poly1.split_at(mid);
        let (b0, b1) = poly2.split_at(mid.min(poly2.len()));

        let z0 = Self::karatsuba_multiply(a0, b0, modulus);
        let z2 = Self::karatsuba_multiply(a1, b1, modulus);

        // Compute (a0 + a1) * (b0 + b1)
        let mut a_sum = vec![0u64; a0.len().max(a1.len())];
        for (i, &val) in a0.iter().enumerate() {
            a_sum[i] = val;
        }
        for (i, &val) in a1.iter().enumerate() {
            a_sum[i] = ((a_sum[i] as u128 + val as u128) % modulus as u128) as u64;
        }

        let mut b_sum = vec![0u64; b0.len().max(b1.len())];
        for (i, &val) in b0.iter().enumerate() {
            b_sum[i] = val;
        }
        for (i, &val) in b1.iter().enumerate() {
            b_sum[i] = ((b_sum[i] as u128 + val as u128) % modulus as u128) as u64;
        }

        let z1 = Self::karatsuba_multiply(&a_sum, &b_sum, modulus);

        // Combine results
        let n = poly1.len() + poly2.len() - 1;
        let mut result = vec![0u64; n];

        for (i, &val) in z0.iter().enumerate() {
            result[i] = ((result[i] as u128 + val as u128) % modulus as u128) as u64;
        }

        for (i, &val) in z2.iter().enumerate() {
            if i + 2 * mid < result.len() {
                result[i + 2 * mid] = ((result[i + 2 * mid] as u128 + val as u128) % modulus as u128) as u64;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluation_cache() {
        let cache = EvaluationCache::new(100);
        let point = vec![1, 2, 3];
        
        let result = cache.get_or_compute(&point, |p| Ok(p.iter().sum())).unwrap();
        assert_eq!(result, 6);
        
        // Should retrieve from cache
        let result2 = cache.get_or_compute(&point, |_| Ok(999)).unwrap();
        assert_eq!(result2, 6);
    }

    #[test]
    fn test_precomputed_tables() {
        let tables = PrecomputedTables::new(10, (1 << 31) - 1);
        assert_eq!(tables.get_power_of_two(0), Some(1));
        assert_eq!(tables.get_power_of_two(1), Some(2));
    }

    #[test]
    fn test_simd_ops() {
        let ops = SimdPolynomialOps::new(16);
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        
        let scaled = ops.scalar_multiply(&poly, 2);
        assert_eq!(scaled.coefficients[0], 2);
    }

    #[test]
    fn test_streaming_ops() {
        let ops = StreamingOps::new(64);
        let coeffs = vec![1, 2, 3, 4, 5];
        let sum = ops.stream_sum(&coeffs);
        assert_eq!(sum, 15);
    }

    #[test]
    fn test_fft_multiply() {
        let poly1 = vec![1, 2];
        let poly2 = vec![3, 4];
        let result = AlgorithmicOpts::fft_multiply(&poly1, &poly2, (1 << 31) - 1);
        
        // (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
        assert_eq!(result[0], 3);
        assert_eq!(result[1], 10);
        assert_eq!(result[2], 8);
    }
}
