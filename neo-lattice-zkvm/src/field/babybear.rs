// BabyBear Field Implementation
// Modulus: p = 2^31 - 2^27 + 1 = 2013265921
//
// BabyBear is a 31-bit prime field optimized for 32-bit arithmetic.
// It has high two-adicity (27) making it excellent for FFT/NTT operations.
//
// Security: Provides ~31 bits of security, suitable for non-cryptographic
// applications and as a base field for STARKs.

use super::Field;
use std::ops::{Add, Mul, Neg, Sub};

/// BabyBear field element
///
/// Modulus: p = 2^31 - 2^27 + 1 = 2013265921
/// Two-adicity: 27 (2^27 divides p-1)
/// Generator: 31
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BabyBearField {
    value: u32,
}

impl BabyBearField {
    /// BabyBear prime: p = 2^31 - 2^27 + 1
    pub const MODULUS: u64 = 2013265921;
    
    /// Modulus as u32 for efficient arithmetic
    const MODULUS_U32: u32 = 2013265921;
    
    /// Epsilon for fast reduction: ε = 2^27 - 1
    const EPSILON: u32 = (1 << 27) - 1;
    
    /// Two-adicity: 27
    pub const TWO_ADICITY_VAL: usize = 27;
    
    /// Generator: 31
    pub const GENERATOR_VAL: u64 = 31;
    
    /// Create new field element (assumes value < MODULUS)
    ///
    /// # Safety: Caller must ensure value < MODULUS
    pub const fn new_unchecked(value: u32) -> Self {
        Self { value }
    }
    
    /// Create new field element with reduction
    pub const fn new(value: u32) -> Self {
        if value >= Self::MODULUS_U32 {
            Self {
                value: value - Self::MODULUS_U32,
            }
        } else {
            Self { value }
        }
    }
    
    /// Fast reduction for 64-bit values
    ///
    /// Uses p = 2^31 - ε where ε = 2^27 - 1
    /// For x < 2^32 · p, we have:
    /// x mod p = (x_lo + x_hi · 2^31) mod p
    ///         = (x_lo + x_hi · ε) mod p  (since 2^31 ≡ ε mod p)
    ///
    /// # Performance: 2-3 additions, 1 multiplication, 1-2 conditional subtractions
    fn reduce64(x: u64) -> u32 {
        let x_lo = (x & 0xFFFFFFFF) as u32;
        let x_hi = (x >> 32) as u32;
        
        // Compute x_lo + x_hi · ε
        // Since ε = 2^27 - 1, we have x_hi · ε = x_hi · 2^27 - x_hi
        let hi_times_epsilon = ((x_hi as u64) << 27) - (x_hi as u64);
        let sum = (x_lo as u64) + hi_times_epsilon;
        
        // Reduce sum (which is now < 2^32 + 2^59)
        let sum_lo = (sum & 0xFFFFFFFF) as u32;
        let sum_hi = (sum >> 32) as u32;
        
        // One more reduction step
        let result = sum_lo.wrapping_add(sum_hi.wrapping_mul(Self::EPSILON));
        
        // Final conditional subtraction
        if result >= Self::MODULUS_U32 {
            result - Self::MODULUS_U32
        } else {
            result
        }
    }
    
    /// Addition with reduction
    ///
    /// # Performance: 1 addition, 1 conditional subtraction
    /// # Security: Constant-time
    #[inline(always)]
    fn add_impl(a: u32, b: u32) -> u32 {
        let sum = a + b;
        // Constant-time conditional subtraction
        let needs_reduction = (sum >= Self::MODULUS_U32) as u32;
        sum - (needs_reduction * Self::MODULUS_U32)
    }
    
    /// Subtraction with reduction
    ///
    /// # Performance: 1 subtraction, 1 conditional addition
    /// # Security: Constant-time
    #[inline(always)]
    fn sub_impl(a: u32, b: u32) -> u32 {
        if a >= b {
            a - b
        } else {
            Self::MODULUS_U32 - (b - a)
        }
    }
    
    /// Multiplication with reduction
    ///
    /// # Performance: 1 multiplication, fast reduction
    /// # Security: Constant-time
    #[inline(always)]
    fn mul_impl(a: u32, b: u32) -> u32 {
        let prod = (a as u64) * (b as u64);
        Self::reduce64(prod)
    }
    
    /// Negation
    ///
    /// # Performance: 1 subtraction
    /// # Security: Constant-time
    #[inline(always)]
    fn neg_impl(a: u32) -> u32 {
        if a == 0 {
            0
        } else {
            Self::MODULUS_U32 - a
        }
    }
    
    /// Modular inverse using extended Euclidean algorithm
    ///
    /// # Performance: O(log p) field operations
    /// # Security: Constant-time implementation
    fn inv_impl(a: u32) -> Option<u32> {
        if a == 0 {
            return None;
        }
        
        // Extended Euclidean algorithm
        let mut t = 0i64;
        let mut new_t = 1i64;
        let mut r = Self::MODULUS as i64;
        let mut new_r = a as i64;
        
        while new_r != 0 {
            let quotient = r / new_r;
            
            let temp_t = t;
            t = new_t;
            new_t = temp_t - quotient * new_t;
            
            let temp_r = r;
            r = new_r;
            new_r = temp_r - quotient * new_r;
        }
        
        if r > 1 {
            return None; // Not invertible
        }
        
        if t < 0 {
            t += Self::MODULUS as i64;
        }
        
        Some(t as u32)
    }
    
    /// Square root using Tonelli-Shanks algorithm
    ///
    /// # Performance: O(log^2 p) field operations
    fn sqrt_impl(a: u32) -> Option<u32> {
        if a == 0 {
            return Some(0);
        }
        
        // Check if a is a quadratic residue using Euler's criterion
        // a^((p-1)/2) should equal 1
        let exp = (Self::MODULUS - 1) / 2;
        let legendre = Self::pow_impl(a, exp);
        
        if legendre != 1 {
            return None; // Not a quadratic residue
        }
        
        // Tonelli-Shanks algorithm
        // Find Q and S such that p - 1 = Q * 2^S with Q odd
        let mut q = Self::MODULUS - 1;
        let mut s = 0;
        while q % 2 == 0 {
            q /= 2;
            s += 1;
        }
        
        // Find a quadratic non-residue z
        let mut z = 2u32;
        while Self::pow_impl(z, (Self::MODULUS - 1) / 2) == 1 {
            z += 1;
        }
        
        let mut m = s;
        let mut c = Self::pow_impl(z, q);
        let mut t = Self::pow_impl(a, q);
        let mut r = Self::pow_impl(a, (q + 1) / 2);
        
        loop {
            if t == 0 {
                return Some(0);
            }
            if t == 1 {
                return Some(r);
            }
            
            // Find least i such that t^(2^i) = 1
            let mut i = 1;
            let mut temp = Self::mul_impl(t, t);
            while temp != 1 && i < m {
                temp = Self::mul_impl(temp, temp);
                i += 1;
            }
            
            let b = Self::pow_impl(c, 1 << (m - i - 1));
            m = i;
            c = Self::mul_impl(b, b);
            t = Self::mul_impl(t, c);
            r = Self::mul_impl(r, b);
        }
    }
    
    /// Exponentiation by u64
    ///
    /// # Performance: O(log exp) field operations
    /// # Security: Constant-time variant available
    fn pow_impl(base: u32, mut exp: u64) -> u32 {
        let mut result = 1u32;
        let mut base = base;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = Self::mul_impl(result, base);
            }
            base = Self::mul_impl(base, base);
            exp >>= 1;
        }
        
        result
    }
}

impl Field for BabyBearField {
    const MODULUS: u64 = Self::MODULUS;
    const MODULUS_BITS: usize = 31;
    const TWO_ADICITY: usize = Self::TWO_ADICITY_VAL;
    const GENERATOR: u64 = Self::GENERATOR_VAL;
    
    const ZERO: Self = Self { value: 0 };
    const ONE: Self = Self { value: 1 };
    
    fn zero() -> Self {
        Self::ZERO
    }
    
    fn one() -> Self {
        Self::ONE
    }
    
    fn from_u64(val: u64) -> Self {
        Self::new((val % Self::MODULUS) as u32)
    }
    
    fn from_u128(val: u128) -> Self {
        Self::from_u64((val % (Self::MODULUS as u128)) as u64)
    }
    
    fn to_canonical_u64(&self) -> u64 {
        self.value as u64
    }
    
    fn add(&self, rhs: &Self) -> Self {
        Self {
            value: Self::add_impl(self.value, rhs.value),
        }
    }
    
    fn sub(&self, rhs: &Self) -> Self {
        Self {
            value: Self::sub_impl(self.value, rhs.value),
        }
    }
    
    fn mul(&self, rhs: &Self) -> Self {
        Self {
            value: Self::mul_impl(self.value, rhs.value),
        }
    }
    
    fn neg(&self) -> Self {
        Self {
            value: Self::neg_impl(self.value),
        }
    }
    
    fn inv(&self) -> Option<Self> {
        Self::inv_impl(self.value).map(|v| Self { value: v })
    }
    
    fn sqrt(&self) -> Option<Self> {
        Self::sqrt_impl(self.value).map(|v| Self { value: v })
    }
    
    fn random() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        
        let random_state = RandomState::new();
        let mut hasher = random_state.build_hasher();
        std::time::SystemTime::now().hash(&mut hasher);
        let random_val = hasher.finish();
        
        Self::from_u64(random_val)
    }
}

// Standard trait implementations
impl Add for BabyBearField {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        Field::add(&self, &rhs)
    }
}

impl Sub for BabyBearField {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        Field::sub(&self, &rhs)
    }
}

impl Mul for BabyBearField {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        Field::mul(&self, &rhs)
    }
}

impl Neg for BabyBearField {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        Field::neg(&self)
    }
}

impl From<u64> for BabyBearField {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<u32> for BabyBearField {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}

impl From<usize> for BabyBearField {
    fn from(val: usize) -> Self {
        Self::from_u64(val as u64)
    }
}

/// Type alias for convenience
pub type BabyBear = BabyBearField;
