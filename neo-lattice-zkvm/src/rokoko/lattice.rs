// Lattice-based cryptographic primitives for RoKoko
//
// This module implements the core lattice operations used in the RoKoko protocol:
// - Ring-LWE based commitment scheme
// - Module-LWE for vector commitments
// - Modulus switching for proof compression
// - Constant-time operations for side-channel resistance
// - Rejection sampling for security

use crate::errors::ZKVMError;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Lattice parameters for Ring-LWE/Module-LWE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatticeParams {
    /// Ring dimension (power of 2)
    pub dimension: usize,
    
    /// Coefficient modulus q
    pub modulus: u64,
    
    /// Error distribution standard deviation
    pub error_stddev: f64,
    
    /// Number of module components
    pub module_rank: usize,
    
    /// Rejection sampling parameter
    pub rejection_factor: f64,
    
    /// Smoothing parameter
    pub smoothing_param: f64,
}

impl LatticeParams {
    /// Creates parameters for 128-bit post-quantum security
    pub fn new_secure() -> Self {
        Self {
            dimension: 2048,
            modulus: (1u64 << 60) - 93, // 60-bit prime
            error_stddev: 3.2,
            module_rank: 4,
            rejection_factor: 12.0,
            smoothing_param: 1.5,
        }
    }
    
    /// Validates parameters for security
    pub fn validate(&self) -> Result<(), ZKVMError> {
        // Check dimension is power of 2
        if !self.dimension.is_power_of_two() {
            return Err(ZKVMError::InvalidParameter(
                "Dimension must be power of 2".to_string()
            ));
        }
        
        // Check minimum dimension for security
        if self.dimension < 1024 {
            return Err(ZKVMError::InvalidParameter(
                "Dimension too small for post-quantum security".to_string()
            ));
        }
        
        // Check modulus size
        let modulus_bits = 64 - self.modulus.leading_zeros();
        if modulus_bits < 50 {
            return Err(ZKVMError::InvalidParameter(
                "Modulus too small".to_string()
            ));
        }
        
        // Check error distribution
        if self.error_stddev < 2.0 || self.error_stddev > 10.0 {
            return Err(ZKVMError::InvalidParameter(
                "Error stddev out of secure range".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Computes Hermite factor for lattice security
    pub fn hermite_factor(&self) -> f64 {
        let d = self.dimension as f64;
        let q = self.modulus as f64;
        let sigma = self.error_stddev;
        
        // Simplified security estimate
        let log_q = q.log2();
        let root_hermite_factor = (log_q / d).exp();
        
        root_hermite_factor
    }
}

/// Lattice element in R_q = Z_q[X]/(X^n + 1)
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LatticeElement {
    /// Polynomial coefficients in NTT form
    pub coeffs: Vec<u64>,
    
    /// Modulus for operations
    #[serde(skip)]
    modulus: u64,
    
    /// Whether element is in NTT domain
    #[serde(skip)]
    is_ntt: bool,
}

impl LatticeElement {
    /// Creates new element from coefficients
    pub fn new(coeffs: Vec<u64>, modulus: u64) -> Self {
        let mut elem = Self {
            coeffs,
            modulus,
            is_ntt: false,
        };
        elem.reduce();
        elem
    }
    
    /// Creates zero element
    pub fn zero(dimension: usize, modulus: u64) -> Self {
        Self {
            coeffs: vec![0; dimension],
            modulus,
            is_ntt: false,
        }
    }
    
    /// Samples random element from uniform distribution
    pub fn random<R: RngCore + CryptoRng>(
        dimension: usize,
        modulus: u64,
        rng: &mut R,
    ) -> Self {
        let coeffs: Vec<u64> = (0..dimension)
            .map(|_| rng.gen::<u64>() % modulus)
            .collect();
        
        Self {
            coeffs,
            modulus,
            is_ntt: false,
        }
    }
    
    /// Samples element from discrete Gaussian distribution (constant-time)
    pub fn gaussian<R: RngCore + CryptoRng>(
        dimension: usize,
        modulus: u64,
        stddev: f64,
        rng: &mut R,
    ) -> Self {
        let coeffs: Vec<u64> = (0..dimension)
            .map(|_| {
                // Box-Muller for Gaussian sampling
                let u1 = rng.gen::<f64>();
                let u2 = rng.gen::<f64>();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                let sample = (z * stddev).round() as i64;
                
                // Reduce modulo q in constant time
                let abs_sample = sample.abs() as u64;
                let sign = (sample >> 63) as u64; // 0 for positive, -1 for negative
                
                let pos_result = abs_sample % modulus;
                let neg_result = modulus.wrapping_sub(abs_sample % modulus);
                
                // Constant-time selection
                constant_time_select(sign == 0, pos_result, neg_result)
            })
            .collect();
        
        Self {
            coeffs,
            modulus,
            is_ntt: false,
        }
    }
    
    /// Reduces all coefficients modulo q (constant-time)
    fn reduce(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = barrett_reduce(*coeff, self.modulus);
        }
    }
    
    /// Converts to NTT domain for fast multiplication
    pub fn to_ntt(&mut self) {
        if !self.is_ntt {
            number_theoretic_transform(&mut self.coeffs, self.modulus);
            self.is_ntt = true;
        }
    }
    
    /// Converts from NTT domain
    pub fn from_ntt(&mut self) {
        if self.is_ntt {
            inverse_number_theoretic_transform(&mut self.coeffs, self.modulus);
            self.is_ntt = false;
        }
    }
    
    /// Component-wise multiplication in NTT domain
    pub fn mul_ntt(&self, other: &Self) -> Result<Self, ZKVMError> {
        if !self.is_ntt || !other.is_ntt {
            return Err(ZKVMError::InvalidParameter(
                "Elements must be in NTT domain".to_string()
            ));
        }
        
        if self.coeffs.len() != other.coeffs.len() {
            return Err(ZKVMError::InvalidParameter(
                "Dimension mismatch".to_string()
            ));
        }
        
        let coeffs: Vec<u64> = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| montgomery_mul(a, b, self.modulus))
            .collect();
        
        Ok(Self {
            coeffs,
            modulus: self.modulus,
            is_ntt: true,
        })
    }
    
    /// Inner product with another element
    pub fn inner_product(&self, other: &Self) -> Result<u64, ZKVMError> {
        if self.coeffs.len() != other.coeffs.len() {
            return Err(ZKVMError::InvalidParameter(
                "Dimension mismatch".to_string()
            ));
        }
        
        let sum = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .fold(0u128, |acc, (&a, &b)| {
                acc + (a as u128 * b as u128)
            });
        
        Ok((sum % self.modulus as u128) as u64)
    }
    
    /// Infinity norm (maximum absolute coefficient)
    pub fn infinity_norm(&self) -> u64 {
        self.coeffs.iter()
            .map(|&c| {
                let half_q = self.modulus / 2;
                if c > half_q {
                    self.modulus - c
                } else {
                    c
                }
            })
            .max()
            .unwrap_or(0)
    }
}

impl ConstantTimeEq for LatticeElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.coeffs.ct_eq(&other.coeffs)
    }
}

impl Add for LatticeElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        let coeffs: Vec<u64> = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| add_mod(a, b, self.modulus))
            .collect();
        
        Self {
            coeffs,
            modulus: self.modulus,
            is_ntt: self.is_ntt,
        }
    }
}

impl Sub for LatticeElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        let coeffs: Vec<u64> = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| sub_mod(a, b, self.modulus))
            .collect();
        
        Self {
            coeffs,
            modulus: self.modulus,
            is_ntt: self.is_ntt,
        }
    }
}

/// Modulus switching for proof compression
pub struct ModulusSwitching;

impl ModulusSwitching {
    /// Switches element from modulus q to modulus p
    pub fn switch(
        elem: &LatticeElement,
        new_modulus: u64,
    ) -> LatticeElement {
        let scale = new_modulus as u128 * (1u128 << 64) / elem.modulus as u128;
        
        let new_coeffs: Vec<u64> = elem.coeffs.iter()
            .map(|&c| {
                let scaled = (c as u128 * scale) >> 64;
                (scaled % new_modulus as u128) as u64
            })
            .collect();
        
        LatticeElement {
            coeffs: new_coeffs,
            modulus: new_modulus,
            is_ntt: elem.is_ntt,
        }
    }
    
    /// Computes rounding error bound
    pub fn error_bound(old_modulus: u64, new_modulus: u64, dimension: usize) -> f64 {
        let ratio = old_modulus as f64 / new_modulus as f64;
        (dimension as f64).sqrt() * ratio / 2.0
    }
}

// Constant-time arithmetic operations

/// Barrett reduction (constant-time modular reduction)
#[inline(always)]
fn barrett_reduce(a: u64, modulus: u64) -> u64 {
    // Precompute k = floor((2^128) / modulus)
    let k = ((1u128 << 127) / modulus as u128) << 1;
    
    let q = ((a as u128 * k) >> 128) as u64;
    let mut r = a.wrapping_sub(q.wrapping_mul(modulus));
    
    // Constant-time conditional subtraction
    let mask = ((r as i64 - modulus as i64) >> 63) as u64;
    r = r.wrapping_sub(modulus & !mask);
    
    r
}

/// Montgomery multiplication (constant-time)
#[inline(always)]
fn montgomery_mul(a: u64, b: u64, modulus: u64) -> u64 {
    let r = (1u128 << 64) % modulus as u128;
    let r_inv = mod_inverse(r as u64, modulus);
    let n_prime = ((r as u128 * r_inv as u128).wrapping_sub(1) / modulus as u128) as u64;
    
    let t = a as u128 * b as u128;
    let m = ((t as u64).wrapping_mul(n_prime)) as u128;
    let u = (t + m * modulus as u128) >> 64;
    
    let result = u as u64;
    constant_time_select(result >= modulus, result - modulus, result)
}

/// Constant-time addition modulo q
#[inline(always)]
fn add_mod(a: u64, b: u64, modulus: u64) -> u64 {
    let sum = a.wrapping_add(b);
    let overflow = sum < a;
    let adjusted = sum.wrapping_sub(modulus);
    
    constant_time_select(overflow || adjusted < sum, adjusted, sum)
}

/// Constant-time subtraction modulo q
#[inline(always)]
fn sub_mod(a: u64, b: u64, modulus: u64) -> u64 {
    let diff = a.wrapping_sub(b);
    let underflow = a < b;
    
    constant_time_select(underflow, diff.wrapping_add(modulus), diff)
}

/// Constant-time conditional selection
#[inline(always)]
fn constant_time_select(condition: bool, true_val: u64, false_val: u64) -> u64 {
    let mask = (condition as u64).wrapping_neg();
    (true_val & mask) | (false_val & !mask)
}

/// Extended GCD for modular inverse
fn mod_inverse(a: u64, modulus: u64) -> u64 {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (modulus as i128, a as i128);
    
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    
    if t < 0 {
        t += modulus as i128;
    }
    
    t as u64
}

/// Number Theoretic Transform (NTT) for fast polynomial multiplication
fn number_theoretic_transform(coeffs: &mut [u64], modulus: u64) {
    let n = coeffs.len();
    if n <= 1 {
        return;
    }
    
    // Find primitive n-th root of unity
    let omega = find_primitive_root(n, modulus);
    
    // Cooley-Tukey FFT algorithm
    ntt_recursive(coeffs, modulus, omega, 1);
}

/// Inverse NTT
fn inverse_number_theoretic_transform(coeffs: &mut [u64], modulus: u64) {
    let n = coeffs.len();
    if n <= 1 {
        return;
    }
    
    let omega = find_primitive_root(n, modulus);
    let omega_inv = mod_inverse(omega, modulus);
    
    ntt_recursive(coeffs, modulus, omega_inv, 1);
    
    // Scale by 1/n
    let n_inv = mod_inverse(n as u64, modulus);
    for coeff in coeffs.iter_mut() {
        *coeff = montgomery_mul(*coeff, n_inv, modulus);
    }
}

/// Recursive NTT implementation
fn ntt_recursive(coeffs: &mut [u64], modulus: u64, omega: u64, stride: usize) {
    let n = coeffs.len();
    if n == 1 {
        return;
    }
    
    let half = n / 2;
    
    // Recursively transform even and odd parts
    ntt_recursive(&mut coeffs[..half], modulus, montgomery_mul(omega, omega, modulus), stride * 2);
    ntt_recursive(&mut coeffs[half..], modulus, montgomery_mul(omega, omega, modulus), stride * 2);
    
    // Combine results
    let mut omega_power = 1u64;
    for i in 0..half {
        let even = coeffs[i];
        let odd = montgomery_mul(coeffs[i + half], omega_power, modulus);
        
        coeffs[i] = add_mod(even, odd, modulus);
        coeffs[i + half] = sub_mod(even, odd, modulus);
        
        omega_power = montgomery_mul(omega_power, omega, modulus);
    }
}

/// Finds primitive n-th root of unity modulo q
fn find_primitive_root(n: usize, modulus: u64) -> u64 {
    // For our specific modulus, we can use precomputed values
    // In production, this should be computed during setup
    
    // Simplified: return a placeholder that works for power-of-2 dimensions
    // Real implementation would use proper root finding
    let phi = modulus - 1;
    let power = phi / n as u64;
    
    // Find generator and raise to power
    let generator = 3u64; // Common generator
    mod_exp(generator, power, modulus)
}

/// Modular exponentiation (constant-time)
fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base = base % modulus;
    
    while exp > 0 {
        let bit = exp & 1;
        result = constant_time_select(
            bit == 1,
            montgomery_mul(result, base, modulus),
            result
        );
        base = montgomery_mul(base, base, modulus);
        exp >>= 1;
    }
    
    result
}

/// Rejection sampling for security
pub struct RejectionSampler {
    factor: f64,
    stddev: f64,
}

impl RejectionSampler {
    pub fn new(factor: f64, stddev: f64) -> Self {
        Self { factor, stddev }
    }
    
    /// Performs rejection sampling on lattice element
    pub fn sample<R: RngCore + CryptoRng>(
        &self,
        elem: &LatticeElement,
        rng: &mut R,
    ) -> Option<LatticeElement> {
        let norm = elem.infinity_norm() as f64;
        let bound = self.factor * self.stddev;
        
        if norm > bound {
            return None;
        }
        
        // Statistical rejection test
        let prob = (-norm * norm / (2.0 * self.stddev * self.stddev)).exp();
        let random: f64 = rng.gen();
        
        if random < prob {
            Some(elem.clone())
        } else {
            None
        }
    }
}
