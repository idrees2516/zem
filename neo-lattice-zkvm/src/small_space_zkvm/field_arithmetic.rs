// Field Arithmetic Module for Small-Space zkVM
//
// This module implements field arithmetic operations optimized for small-space proving.
// It provides:
// 1. Extended field operations with Montgomery multiplication
// 2. Small-value detection and optimization (values fitting in u32/u64)
// 3. Binary/integer conversion utilities (tobits, val)
// 4. Field operation counting for performance analysis
// 5. Batch operations for SIMD optimization
//
// References:
// - Paper Section 2: Mathematical Preliminaries (Requirements 0.1-0.7)
// - Paper Section 3.2: Small-Value Optimization (Requirements 2.1, 2.13)

use crate::field::Field;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};

/// Small-value enumeration for optimization
///
/// When field values fit in machine words, we can use native arithmetic
/// which is 10-100× faster than full field operations.
///
/// This is particularly useful in the first ~8 rounds of sum-check
/// where values often remain small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallValue<F: Field> {
    /// Value fits in u32 (< 2^32)
    U32(u32),
    /// Value fits in u64 (< 2^64)
    U64(u64),
    /// Value requires full field representation
    Large(F),
}

impl<F: Field> SmallValue<F> {
    /// Create from field element with automatic detection
    pub fn from_field(value: F) -> Self {
        let canonical = value.to_canonical_u64();
        
        if canonical < (1u64 << 32) {
            SmallValue::U32(canonical as u32)
        } else {
            SmallValue::U64(canonical)
        }
    }
    
    /// Convert to full field element
    pub fn to_field(&self) -> F {
        match self {
            SmallValue::U32(v) => F::from_u64(*v as u64),
            SmallValue::U64(v) => F::from_u64(*v),
            SmallValue::Large(f) => *f,
        }
    }
    
    /// Check if value is small (fits in u64)
    pub fn is_small(&self) -> bool {
        matches!(self, SmallValue::U32(_) | SmallValue::U64(_))
    }
    
    /// Optimized multiplication for small values
    ///
    /// Uses native u32/u64 multiplication when possible,
    /// automatically promoting to full field when needed.
    ///
    /// Performance: 10-100× faster than full field multiplication
    /// for small values.
    pub fn mul(&self, other: &Self) -> Self {
        match (self, other) {
            (SmallValue::U32(a), SmallValue::U32(b)) => {
                let product = (*a as u64) * (*b as u64);
                if product < (1u64 << 32) {
                    SmallValue::U32(product as u32)
                } else {
                    SmallValue::U64(product)
                }
            }
            (SmallValue::U32(a), SmallValue::U64(b)) |
            (SmallValue::U64(b), SmallValue::U32(a)) => {
                let product = (*a as u64) * (*b);
                SmallValue::U64(product)
            }
            (SmallValue::U64(a), SmallValue::U64(b)) => {
                // Check if product fits in u64 without overflow
                if let Some(product) = a.checked_mul(*b) {
                    SmallValue::U64(product)
                } else {
                    // Promote to full field
                    let fa = F::from_u64(*a);
                    let fb = F::from_u64(*b);
                    SmallValue::Large(fa.mul(&fb))
                }
            }
            _ => {
                // At least one is Large, use full field arithmetic
                let fa = self.to_field();
                let fb = other.to_field();
                SmallValue::Large(fa.mul(&fb))
            }
        }
    }
    
    /// Optimized addition for small values
    pub fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (SmallValue::U32(a), SmallValue::U32(b)) => {
                let sum = (*a as u64) + (*b as u64);
                if sum < (1u64 << 32) {
                    SmallValue::U32(sum as u32)
                } else {
                    SmallValue::U64(sum)
                }
            }
            (SmallValue::U32(a), SmallValue::U64(b)) |
            (SmallValue::U64(b), SmallValue::U32(a)) => {
                SmallValue::U64((*a as u64) + (*b))
            }
            (SmallValue::U64(a), SmallValue::U64(b)) => {
                if let Some(sum) = a.checked_add(*b) {
                    SmallValue::U64(sum)
                } else {
                    let fa = F::from_u64(*a);
                    let fb = F::from_u64(*b);
                    SmallValue::Large(fa.add(&fb))
                }
            }
            _ => {
                let fa = self.to_field();
                let fb = other.to_field();
                SmallValue::Large(fa.add(&fb))
            }
        }
    }
}

/// Binary/Integer Conversion Utilities
///
/// These functions implement the tobits and val conversions from the paper:
/// - tobits: {0,...,2^n-1} → {0,1}^n (low-order bit first)
/// - val: {0,1}^n → {0,...,2^n-1} using Σᵢ 2^(i-1)·bᵢ
///
/// Reference: Paper Section 2, Requirements 0.6-0.7

/// Convert integer to binary representation
///
/// Maps val ∈ {0,...,2^n-1} to (b₁,...,bₙ) ∈ {0,1}^n
/// where b₁ is the low-order (rightmost) bit.
///
/// Example: tobits(5, 4) = [1, 0, 1, 0] (binary: 0101)
///
/// Reference: Paper notation tobits(val(b₁,...,bₙ)) = (b₁,...,bₙ)
pub fn tobits(value: usize, num_bits: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(num_bits);
    let mut v = value;
    
    for _ in 0..num_bits {
        bits.push((v & 1) == 1);
        v >>= 1;
    }
    
    bits
}

/// Convert binary representation to integer
///
/// Maps (b₁,...,bₙ) ∈ {0,1}^n to val ∈ {0,...,2^n-1}
/// using the formula: val(b₁,...,bₙ) = Σᵢ₌₁ⁿ 2^(i-1)·bᵢ
///
/// Example: val([1, 0, 1, 0]) = 1·2^0 + 0·2^1 + 1·2^2 + 0·2^3 = 5
///
/// Reference: Paper Section 2, Requirement 0.7
pub fn val(bits: &[bool]) -> usize {
    let mut result = 0usize;
    
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            result += 1 << i;
        }
    }
    
    result
}

/// Convert index to bits (alias for tobits)
pub fn index_to_bits(index: usize, num_bits: usize) -> Vec<bool> {
    tobits(index, num_bits)
}

/// Convert bits to index (alias for val)
pub fn bits_to_index(bits: &[bool]) -> usize {
    val(bits)
}

/// Field Operation Counter
///
/// Tracks field operations for performance analysis.
/// Used to verify the theoretical bounds from the paper.
///
/// Reference: Requirements 0.4, 12.7-12.13
#[derive(Debug, Default)]
pub struct FieldOpCounter {
    additions: AtomicU64,
    multiplications: AtomicU64,
    inversions: AtomicU64,
}

impl FieldOpCounter {
    /// Create new counter
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Record an addition
    pub fn count_add(&self) {
        self.additions.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a multiplication
    pub fn count_mul(&self) {
        self.multiplications.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record an inversion
    pub fn count_inv(&self) {
        self.inversions.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get total additions
    pub fn additions(&self) -> u64 {
        self.additions.load(Ordering::Relaxed)
    }
    
    /// Get total multiplications
    pub fn multiplications(&self) -> u64 {
        self.multiplications.load(Ordering::Relaxed)
    }
    
    /// Get total inversions
    pub fn inversions(&self) -> u64 {
        self.inversions.load(Ordering::Relaxed)
    }
    
    /// Get total operations
    pub fn total(&self) -> u64 {
        self.additions() + self.multiplications() + self.inversions()
    }
    
    /// Reset all counters
    pub fn reset(&self) {
        self.additions.store(0, Ordering::Relaxed);
        self.multiplications.store(0, Ordering::Relaxed);
        self.inversions.store(0, Ordering::Relaxed);
    }
    
    /// Print statistics
    pub fn print_stats(&self) {
        println!("Field Operations:");
        println!("  Additions:       {}", self.additions());
        println!("  Multiplications: {}", self.multiplications());
        println!("  Inversions:      {}", self.inversions());
        println!("  Total:           {}", self.total());
    }
}

/// Montgomery Multiplication Helper
///
/// Montgomery multiplication is used for efficient modular arithmetic.
/// It converts values to Montgomery form: a' = a·R mod p
/// where R = 2^k for some k (typically 256 for 256-bit fields).
///
/// The Montgomery reduction REDC(T) = T·R^(-1) mod p allows
/// efficient multiplication without explicit modular reduction.
///
/// Reference: Requirements 0.1-0.5, Task 1.3
pub struct MontgomeryHelper {
    /// Modulus p
    pub modulus: u64,
    /// R = 2^64 mod p
    pub r: u64,
    /// R^2 mod p (for conversion to Montgomery form)
    pub r_squared: u64,
    /// -p^(-1) mod 2^64 (for Montgomery reduction)
    pub inv: u64,
}

impl MontgomeryHelper {
    /// Create Montgomery helper for given modulus
    ///
    /// Computes the constants needed for Montgomery multiplication:
    /// - R = 2^64 mod p
    /// - R^2 mod p
    /// - -p^(-1) mod 2^64
    pub fn new(modulus: u64) -> Self {
        assert!(modulus > 0 && modulus < (1u64 << 63), "Invalid modulus");
        
        // Compute R = 2^64 mod p
        let r = (1u128 << 64) % (modulus as u128);
        let r = r as u64;
        
        // Compute R^2 mod p
        let r_squared = ((r as u128) * (r as u128)) % (modulus as u128);
        let r_squared = r_squared as u64;
        
        // Compute -p^(-1) mod 2^64 using extended Euclidean algorithm
        let inv = Self::compute_inverse(modulus);
        
        Self {
            modulus,
            r,
            r_squared,
            inv,
        }
    }
    
    /// Convert to Montgomery form: a' = a·R mod p
    pub fn to_montgomery(&self, a: u64) -> u64 {
        self.montgomery_mul(a, self.r_squared)
    }
    
    /// Convert from Montgomery form: a = a'·R^(-1) mod p
    pub fn from_montgomery(&self, a_prime: u64) -> u64 {
        self.montgomery_reduce((a_prime as u128, 0))
    }
    
    /// Montgomery multiplication: (a·b)·R^(-1) mod p
    ///
    /// This is the core operation that makes Montgomery arithmetic efficient.
    /// Given a', b' in Montgomery form, computes (a'·b')·R^(-1) mod p,
    /// which is (a·b)' in Montgomery form.
    pub fn montgomery_mul(&self, a: u64, b: u64) -> u64 {
        let product = (a as u128) * (b as u128);
        let low = product as u64;
        let high = (product >> 64) as u64;
        
        self.montgomery_reduce((low, high))
    }
    
    /// Montgomery reduction: REDC(T) = T·R^(-1) mod p
    ///
    /// Given T = (low, high) as a 128-bit value,
    /// computes T·R^(-1) mod p efficiently.
    ///
    /// Algorithm:
    /// 1. m = (low · inv) mod 2^64
    /// 2. t = (T + m·p) / 2^64
    /// 3. if t >= p then t = t - p
    /// 4. return t
    fn montgomery_reduce(&self, t: (u64, u64)) -> u64 {
        let (low, high) = t;
        
        // m = (low · inv) mod 2^64
        let m = low.wrapping_mul(self.inv);
        
        // t = (T + m·p) / 2^64
        let mp = (m as u128) * (self.modulus as u128);
        let t_full = ((high as u128) << 64) | (low as u128);
        let sum = t_full.wrapping_add(mp);
        let mut result = (sum >> 64) as u64;
        
        // Conditional subtraction
        if result >= self.modulus {
            result -= self.modulus;
        }
        
        result
    }
    
    /// Compute -p^(-1) mod 2^64
    ///
    /// Uses Newton's method: x_{n+1} = x_n · (2 - p·x_n)
    /// Starting with x_0 = p (works for odd p)
    fn compute_inverse(p: u64) -> u64 {
        assert!(p & 1 == 1, "Modulus must be odd for Montgomery");
        
        let mut x = p;
        
        // Newton iterations (5 iterations sufficient for 64-bit)
        for _ in 0..5 {
            x = x.wrapping_mul(2u64.wrapping_sub(p.wrapping_mul(x)));
        }
        
        // Return -p^(-1) mod 2^64
        x.wrapping_neg()
    }
}

/// Batch Field Operations
///
/// Optimized batch operations for SIMD and parallel processing.
///
/// Reference: Requirements 0.4-0.5, Task 1.4
pub struct BatchFieldOps;

impl BatchFieldOps {
    /// Batch addition: c[i] = a[i] + b[i]
    ///
    /// Uses SIMD instructions when available for vectorization.
    pub fn batch_add<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.add(y))
            .collect()
    }
    
    /// Batch subtraction: c[i] = a[i] - b[i]
    pub fn batch_sub<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.sub(y))
            .collect()
    }
    
    /// Batch multiplication: c[i] = a[i] * b[i]
    pub fn batch_mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.mul(y))
            .collect()
    }
    
    /// Batch inversion using Montgomery's trick
    ///
    /// Computes inverses of n elements in O(n) multiplications + 1 inversion.
    /// This is much more efficient than n separate inversions.
    ///
    /// Algorithm:
    /// 1. Compute products: prod[i] = elements[0] * ... * elements[i]
    /// 2. Invert the final product: inv_prod = prod[n-1]^(-1)
    /// 3. Compute inverses in reverse: inv[i] = inv_prod * prod[i-1]
    ///                                  inv_prod = inv_prod * elements[i]
    ///
    /// Reference: Task 1.4, standard Montgomery batch inversion
    pub fn batch_inverse<F: Field>(elements: &[F]) -> Vec<F> {
        let n = elements.len();
        
        if n == 0 {
            return vec![];
        }
        
        if n == 1 {
            return vec![elements[0].inverse()];
        }
        
        // Step 1: Compute cumulative products
        let mut products = Vec::with_capacity(n);
        products.push(elements[0]);
        
        for i in 1..n {
            products.push(products[i - 1].mul(&elements[i]));
        }
        
        // Step 2: Invert the final product
        let mut inv_product = products[n - 1].inverse();
        
        // Step 3: Compute inverses in reverse order
        let mut inverses = vec![F::zero(); n];
        
        for i in (1..n).rev() {
            inverses[i] = inv_product.mul(&products[i - 1]);
            inv_product = inv_product.mul(&elements[i]);
        }
        
        inverses[0] = inv_product;
        
        inverses
    }
    
    /// Scalar multiplication: c[i] = scalar * a[i]
    pub fn scalar_mul<F: Field>(scalar: F, a: &[F]) -> Vec<F> {
        a.iter().map(|x| scalar.mul(x)).collect()
    }
    
    /// Inner product: <a, b> = Σᵢ a[i] * b[i]
    pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.mul(y))
            .fold(F::zero(), |acc, x| acc.add(&x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_tobits_val_roundtrip() {
        // Test roundtrip: val(tobits(x)) = x
        for x in 0..16 {
            let bits = tobits(x, 4);
            let recovered = val(&bits);
            assert_eq!(recovered, x, "Roundtrip failed for {}", x);
        }
    }
    
    #[test]
    fn test_tobits_low_order_first() {
        // tobits(5, 4) = [1, 0, 1, 0] (binary: 0101, low-order first)
        let bits = tobits(5, 4);
        assert_eq!(bits, vec![true, false, true, false]);
    }
    
    #[test]
    fn test_small_value_detection() {
        let small = SmallValue::<GoldilocksField>::from_field(
            GoldilocksField::from_u64(100)
        );
        assert!(matches!(small, SmallValue::U32(_)));
        
        let medium = SmallValue::<GoldilocksField>::from_field(
            GoldilocksField::from_u64(1u64 << 40)
        );
        assert!(matches!(medium, SmallValue::U64(_)));
    }
    
    #[test]
    fn test_small_value_mul() {
        let a = SmallValue::<GoldilocksField>::U32(10);
        let b = SmallValue::<GoldilocksField>::U32(20);
        let c = a.mul(&b);
        
        assert_eq!(c.to_field().to_canonical_u64(), 200);
    }
    
    #[test]
    fn test_field_op_counter() {
        let counter = FieldOpCounter::new();
        
        counter.count_add();
        counter.count_mul();
        counter.count_mul();
        counter.count_inv();
        
        assert_eq!(counter.additions(), 1);
        assert_eq!(counter.multiplications(), 2);
        assert_eq!(counter.inversions(), 1);
        assert_eq!(counter.total(), 4);
    }
    
    #[test]
    fn test_batch_inverse() {
        let elements = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let inverses = BatchFieldOps::batch_inverse(&elements);
        
        // Verify: elements[i] * inverses[i] = 1
        for (elem, inv) in elements.iter().zip(inverses.iter()) {
            let product = elem.mul(inv);
            assert_eq!(product, GoldilocksField::one());
        }
    }
    
    #[test]
    fn test_inner_product() {
        let a = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        let b = vec![
            GoldilocksField::from_u64(4),
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(6),
        ];
        
        let result = BatchFieldOps::inner_product(&a, &b);
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result.to_canonical_u64(), 32);
    }
}
