# Arithmetic Layer - Complete Implementation Specification

## Module: arithmetic/field.rs

### Overview
Implements arithmetic operations over the base field F_q where q is a 32-bit prime with q ≡ 5 (mod 8).

### Core Structure

```rust
/// Represents an element in F_q
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement {
    value: u64,  // Always < q, stored as u64 for arithmetic
}

/// Field parameters (compile-time constants)
pub struct FieldParams {
    pub q: u64,              // Prime modulus
    pub q_inv: u64,          // Precomputed for Barrett reduction
    pub r: u64,              // Montgomery R = 2^64 mod q
    pub r_inv: u64,          // R^{-1} mod q
    pub q_prime: u64,        // -q^{-1} mod 2^64 for Montgomery
}

impl FieldParams {
    /// Create field parameters for given prime q
    /// Requires: q ≡ 5 (mod 8), q < 2^32
    pub fn new(q: u64) -> Result<Self> {
        // Verify q is prime
        if !is_prime(q) {
            return Err(HachiError::InvalidParameter(
                format!("q = {} is not prime", q)
            ));
        }
        
        // Verify q ≡ 5 (mod 8)
        if q % 8 != 5 {
            return Err(HachiError::InvalidParameter(
                format!("q = {} is not ≡ 5 (mod 8)", q)
            ));
        }
        
        // Verify q < 2^32
        if q >= (1u64 << 32) {
            return Err(HachiError::InvalidParameter(
                format!("q = {} is too large (must be < 2^32)", q)
            ));
        }
        
        // Precompute Barrett reduction parameter
        // q_inv = floor(2^64 / q)
        let q_inv = (u128::MAX / q as u128) as u64;
        
        // Precompute Montgomery parameters
        let r = (1u128 << 64) % q as u128;
        let r = r as u64;
        
        // Extended Euclidean algorithm for q_prime
        let q_prime = mod_inverse(q, 1u64 << 64)?;
        let q_prime = (1u64 << 64).wrapping_sub(q_prime);
        
        // Compute R^{-1} mod q
        let r_inv = mod_inverse(r, q)?;
        
        Ok(FieldParams {
            q,
            q_inv,
            r,
            r_inv,
            q_prime,
        })
    }
}
```

### Basic Operations

```rust
impl FieldElement {
    /// Create field element from u64
    /// Automatically reduces modulo q
    pub fn new(value: u64, params: &FieldParams) -> Self {
        FieldElement {
            value: value % params.q,
        }
    }
    
    /// Create zero element
    pub const fn zero() -> Self {
        FieldElement { value: 0 }
    }
    
    /// Create one element
    pub const fn one() -> Self {
        FieldElement { value: 1 }
    }
    
    /// Check if element is zero
    pub const fn is_zero(&self) -> bool {
        self.value == 0
    }
    
    /// Get raw value
    pub const fn value(&self) -> u64 {
        self.value
    }
    
    /// Create from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8], params: &FieldParams) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(HachiError::InvalidParameter(
                "Expected 8 bytes for FieldElement".to_string()
            ));
        }
        
        let value = u64::from_le_bytes(bytes.try_into().unwrap());
        Ok(Self::new(value, params))
    }
    
    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 8] {
        self.value.to_le_bytes()
    }
}
```

### Addition and Subtraction

```rust
impl FieldElement {
    /// Add two field elements
    /// Uses conditional subtraction to avoid modulo operation
    pub fn add(&self, other: &Self, params: &FieldParams) -> Self {
        let sum = self.value + other.value;
        let value = if sum >= params.q {
            sum - params.q
        } else {
            sum
        };
        FieldElement { value }
    }
    
    /// Subtract two field elements
    pub fn sub(&self, other: &Self, params: &FieldParams) -> Self {
        let diff = if self.value >= other.value {
            self.value - other.value
        } else {
            self.value + params.q - other.value
        };
        FieldElement { value: diff }
    }
    
    /// Negate field element
    pub fn neg(&self, params: &FieldParams) -> Self {
        if self.value == 0 {
            *self
        } else {
            FieldElement {
                value: params.q - self.value,
            }
        }
    }
    
    /// Batch addition (SIMD-friendly)
    /// Adds corresponding elements from two slices
    pub fn batch_add(
        a: &[FieldElement],
        b: &[FieldElement],
        params: &FieldParams,
    ) -> Vec<FieldElement> {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.add(y, params))
            .collect()
    }
}
```

### Multiplication

```rust
impl FieldElement {
    /// Multiply two field elements using Barrett reduction
    /// Barrett reduction: compute q_hat = (a*b * q_inv) >> 64
    /// Then: (a*b) mod q ≈ (a*b) - q_hat * q
    pub fn mul(&self, other: &Self, params: &FieldParams) -> Self {
        let product = (self.value as u128) * (other.value as u128);
        let value = barrett_reduce(product, params);
        FieldElement { value }
    }
    
    /// Square field element (optimized)
    pub fn square(&self, params: &FieldParams) -> Self {
        self.mul(self, params)
    }
    
    /// Multiply by small constant (optimized)
    pub fn mul_small(&self, constant: u64, params: &FieldParams) -> Self {
        assert!(constant < 256, "Use mul() for large constants");
        let product = self.value * constant;
        let value = if product >= params.q {
            product % params.q
        } else {
            product
        };
        FieldElement { value }
    }
    
    /// Montgomery multiplication (for repeated multiplications)
    /// Converts to Montgomery form, multiplies, converts back
    pub fn montgomery_mul(&self, other: &Self, params: &FieldParams) -> Self {
        // Convert to Montgomery form
        let a_mont = self.to_montgomery(params);
        let b_mont = other.to_montgomery(params);
        
        // Montgomery multiplication
        let product = (a_mont as u128) * (b_mont as u128);
        let t = ((product as u64).wrapping_mul(params.q_prime)) as u128;
        let u = (product + t * (params.q as u128)) >> 64;
        let value = if u >= params.q as u128 {
            (u - params.q as u128) as u64
        } else {
            u as u64
        };
        
        // Convert back from Montgomery form
        FieldElement { value }.from_montgomery(params)
    }
    
    /// Convert to Montgomery form: a * R mod q
    fn to_montgomery(&self, params: &FieldParams) -> u64 {
        let product = (self.value as u128) * (params.r as u128);
        barrett_reduce(product, params)
    }
    
    /// Convert from Montgomery form: a * R^{-1} mod q
    fn from_montgomery(&self, params: &FieldParams) -> Self {
        let product = (self.value as u128) * (params.r_inv as u128);
        let value = barrett_reduce(product, params);
        FieldElement { value }
    }
}

/// Barrett reduction helper
/// Reduces 128-bit product modulo q using precomputed q_inv
fn barrett_reduce(product: u128, params: &FieldParams) -> u64 {
    // Compute quotient estimate: q_hat = (product * q_inv) >> 64
    let q_hat = ((product >> 64) * (params.q_inv as u128)) >> 64;
    
    // Compute remainder: r = product - q_hat * q
    let remainder = product - q_hat * (params.q as u128);
    
    // Final reduction (at most one subtraction needed)
    let value = if remainder >= params.q as u128 {
        (remainder - params.q as u128) as u64
    } else {
        remainder as u64
    };
    
    value
}
```

### Division and Inversion

```rust
impl FieldElement {
    /// Compute multiplicative inverse using extended Euclidean algorithm
    /// Returns None if element is zero
    pub fn inv(&self, params: &FieldParams) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        
        // Extended Euclidean algorithm
        let (gcd, x, _) = extended_gcd(self.value as i128, params.q as i128);
        
        assert_eq!(gcd, 1, "Element not invertible");
        
        // Ensure x is positive
        let inv = if x < 0 {
            (x + params.q as i128) as u64
        } else {
            x as u64
        };
        
        Some(FieldElement { value: inv })
    }
    
    /// Divide two field elements: a / b = a * b^{-1}
    pub fn div(&self, other: &Self, params: &FieldParams) -> Option<Self> {
        other.inv(params).map(|inv| self.mul(&inv, params))
    }
    
    /// Batch inversion using Montgomery's trick
    /// Inverts n elements with only 1 inversion + 3n multiplications
    pub fn batch_inv(elements: &[FieldElement], params: &FieldParams) -> Vec<FieldElement> {
        let n = elements.len();
        if n == 0 {
            return vec![];
        }
        
        // Compute products: prod[i] = elements[0] * ... * elements[i]
        let mut products = Vec::with_capacity(n);
        let mut acc = FieldElement::one();
        for elem in elements {
            acc = acc.mul(elem, params);
            products.push(acc);
        }
        
        // Invert final product
        let mut inv_acc = products[n - 1].inv(params)
            .expect("Cannot invert zero element");
        
        // Compute inverses in reverse
        let mut inverses = vec![FieldElement::zero(); n];
        for i in (0..n).rev() {
            if i > 0 {
                inverses[i] = inv_acc.mul(&products[i - 1], params);
                inv_acc = inv_acc.mul(&elements[i], params);
            } else {
                inverses[i] = inv_acc;
            }
        }
        
        inverses
    }
}

/// Extended Euclidean algorithm
/// Returns (gcd, x, y) such that a*x + b*y = gcd
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        return (a, 1, 0);
    }
    
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    
    (gcd, x, y)
}

/// Modular inverse: a^{-1} mod m
fn mod_inverse(a: u64, m: u64) -> Result<u64> {
    let (gcd, x, _) = extended_gcd(a as i128, m as i128);
    
    if gcd != 1 {
        return Err(HachiError::ArithmeticError(
            format!("{} is not invertible mod {}", a, m)
        ));
    }
    
    let inv = if x < 0 {
        (x + m as i128) as u64
    } else {
        x as u64
    };
    
    Ok(inv)
}
```

### Exponentiation

```rust
impl FieldElement {
    /// Compute a^exp using square-and-multiply
    pub fn pow(&self, exp: u64, params: &FieldParams) -> Self {
        if exp == 0 {
            return FieldElement::one();
        }
        
        let mut result = FieldElement::one();
        let mut base = *self;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base, params);
            }
            base = base.square(params);
            e >>= 1;
        }
        
        result
    }
    
    /// Compute a^{-1} using Fermat's little theorem: a^{-1} = a^{q-2}
    /// Faster than extended Euclidean for single inversion
    pub fn inv_fermat(&self, params: &FieldParams) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(params.q - 2, params))
    }
}
```

### Random Sampling

```rust
impl FieldElement {
    /// Sample random field element uniformly
    pub fn random<R: Rng>(rng: &mut R, params: &FieldParams) -> Self {
        // Sample u64 and reduce
        // Use rejection sampling for uniformity
        loop {
            let value = rng.gen::<u64>();
            if value < params.q {
                return FieldElement { value };
            }
        }
    }
    
    /// Sample random non-zero field element
    pub fn random_nonzero<R: Rng>(rng: &mut R, params: &FieldParams) -> Self {
        loop {
            let elem = Self::random(rng, params);
            if !elem.is_zero() {
                return elem;
            }
        }
    }
    
    /// Sample from uniform distribution over [0, bound)
    pub fn random_bounded<R: Rng>(
        rng: &mut R,
        bound: u64,
        params: &FieldParams,
    ) -> Self {
        assert!(bound <= params.q);
        let value = rng.gen_range(0..bound);
        FieldElement { value }
    }
}
```

### Trait Implementations

```rust
use std::ops::{Add, Sub, Mul, Neg};

// Note: These require FieldParams to be available
// In practice, use methods that take params explicitly

impl Add for FieldElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        // This is a simplified version
        // Real implementation needs params
        unimplemented!("Use add() method with params")
    }
}

impl Sub for FieldElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        unimplemented!("Use sub() method with params")
    }
}

impl Mul for FieldElement {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        unimplemented!("Use mul() method with params")
    }
}

impl Neg for FieldElement {
    type Output = Self;
    
    fn neg(self) -> Self {
        unimplemented!("Use neg() method with params")
    }
}

// Implement Display for debugging
impl std::fmt::Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}
```

### SIMD Optimization (AVX-512)

```rust
#[cfg(target_feature = "avx512f")]
mod simd {
    use super::*;
    use std::arch::x86_64::*;
    
    /// Batch addition using AVX-512
    /// Processes 8 elements at a time
    pub unsafe fn batch_add_simd(
        a: &[FieldElement],
        b: &[FieldElement],
        params: &FieldParams,
    ) -> Vec<FieldElement> {
        assert_eq!(a.len(), b.len());
        let n = a.len();
        let mut result = Vec::with_capacity(n);
        
        let q_vec = _mm512_set1_epi64(params.q as i64);
        
        // Process 8 elements at a time
        let chunks = n / 8;
        for i in 0..chunks {
            let offset = i * 8;
            
            // Load 8 elements from a and b
            let a_vec = _mm512_loadu_epi64(
                a[offset..].as_ptr() as *const i64
            );
            let b_vec = _mm512_loadu_epi64(
                b[offset..].as_ptr() as *const i64
            );
            
            // Add
            let sum_vec = _mm512_add_epi64(a_vec, b_vec);
            
            // Conditional subtraction: if sum >= q, subtract q
            let mask = _mm512_cmpge_epu64_mask(sum_vec, q_vec);
            let adjusted = _mm512_mask_sub_epi64(
                sum_vec,
                mask,
                sum_vec,
                q_vec,
            );
            
            // Store result
            let mut temp = [0u64; 8];
            _mm512_storeu_epi64(temp.as_mut_ptr() as *mut i64, adjusted);
            
            for &val in &temp {
                result.push(FieldElement { value: val });
            }
        }
        
        // Handle remaining elements
        for i in (chunks * 8)..n {
            result.push(a[i].add(&b[i], params));
        }
        
        result
    }
    
    /// Batch multiplication using AVX-512
    pub unsafe fn batch_mul_simd(
        a: &[FieldElement],
        b: &[FieldElement],
        params: &FieldParams,
    ) -> Vec<FieldElement> {
        // Similar to batch_add_simd but with multiplication
        // Uses Barrett reduction for each element
        unimplemented!("Implement SIMD multiplication")
    }
}
```


## Performance Targets

### Single Operations
- Addition: < 5 ns
- Multiplication (Barrett): < 10 ns
- Multiplication (Montgomery): < 8 ns
- Inversion: < 500 ns
- Exponentiation (64-bit exp): < 5 μs

### Batch Operations (n=1024)
- Batch addition: < 5 μs (< 5 ns per element)
- Batch inversion: < 500 μs (< 500 ns per element)

### SIMD Operations (n=1024)
- SIMD addition: < 2 μs (< 2 ns per element)
- SIMD multiplication: < 8 μs (< 8 ns per element)

## Next Module

The next module will implement extension field arithmetic (F_{q^k}), building on this foundation.
