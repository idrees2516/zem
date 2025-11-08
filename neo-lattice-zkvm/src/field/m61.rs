// Mersenne 61 field implementation
// q = 2^61 - 1

use super::Field;

/// Mersenne 61 field element
/// Modulus: q = 2^61 - 1 = 2305843009213693951
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct M61Field {
    value: u64,
}

impl M61Field {
    /// Mersenne 61 prime: q = 2^61 - 1
    pub const MODULUS: u64 = (1u64 << 61) - 1;
    pub const MODULUS_BITS: usize = 61;
    
    /// Create new field element (assumes value < MODULUS)
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
    
    /// Ultra-fast reduction for Mersenne prime
    /// For x < 2^122, at most 2 reductions needed
    fn reduce(x: u64) -> u64 {
        let reduced = (x & Self::MODULUS) + (x >> 61);
        if reduced >= Self::MODULUS {
            reduced - Self::MODULUS
        } else {
            reduced
        }
    }
    
    /// Fast reduction for 128-bit values
    fn reduce128(x: u128) -> u64 {
        // Split into 61-bit chunks
        let lo = (x & ((1u128 << 61) - 1)) as u64;
        let mid = ((x >> 61) & ((1u128 << 61) - 1)) as u64;
        let hi = (x >> 122) as u64;
        
        // Reduce: x = lo + mid·2^61 + hi·2^122
        //           = lo + mid·2^61 + hi·2^61 (mod 2^61-1)
        //           = lo + (mid + hi)·2^61 (mod 2^61-1)
        //           = lo + (mid + hi) (mod 2^61-1)
        let sum = lo + mid + hi;
        Self::reduce(sum)
    }
    
    /// Addition implementation
    fn add_impl(a: u64, b: u64) -> u64 {
        let sum = a + b;
        Self::reduce(sum)
    }
    
    /// Subtraction implementation
    fn sub_impl(a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            Self::MODULUS - (b - a)
        }
    }
    
    /// Multiplication implementation
    fn mul_impl(a: u64, b: u64) -> u64 {
        let prod = (a as u128) * (b as u128);
        Self::reduce128(prod)
    }
    
    /// Negation implementation
    fn neg_impl(a: u64) -> u64 {
        if a == 0 {
            0
        } else {
            Self::MODULUS - a
        }
    }
    
    /// Extended Euclidean algorithm for modular inverse
    fn inv_impl(a: u64) -> Option<u64> {
        if a == 0 {
            return None;
        }
        
        let mut t = 0i128;
        let mut new_t = 1i128;
        let mut r = Self::MODULUS as i128;
        let mut new_r = a as i128;
        
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
            return None;
        }
        
        if t < 0 {
            t += Self::MODULUS as i128;
        }
        
        Some(t as u64)
    }
}

impl Field for M61Field {
    const MODULUS: u64 = Self::MODULUS;
    const MODULUS_BITS: usize = Self::MODULUS_BITS;
    const TWO_ADICITY: usize = 0; // 2^61 - 1 ≡ 1 (mod 128)
    
    fn zero() -> Self {
        Self { value: 0 }
    }
    
    fn one() -> Self {
        Self { value: 1 }
    }
    
    fn from_u64(val: u64) -> Self {
        Self {
            value: if val >= Self::MODULUS {
                Self::reduce(val)
            } else {
                val
            }
        }
    }
    
    fn to_canonical_u64(&self) -> u64 {
        self.value
    }
    
    fn add(&self, rhs: &Self) -> Self {
        Self {
            value: Self::add_impl(self.value, rhs.value)
        }
    }
    
    fn sub(&self, rhs: &Self) -> Self {
        Self {
            value: Self::sub_impl(self.value, rhs.value)
        }
    }
    
    fn mul(&self, rhs: &Self) -> Self {
        Self {
            value: Self::mul_impl(self.value, rhs.value)
        }
    }
    
    fn neg(&self) -> Self {
        Self {
            value: Self::neg_impl(self.value)
        }
    }
    
    fn inv(&self) -> Option<Self> {
        Self::inv_impl(self.value).map(|v| Self { value: v })
    }
    
    fn sqrt(&self) -> Option<Self> {
        if self.value == 0 {
            return Some(Self::zero());
        }
        
        // Check if quadratic residue
        let exp = (Self::MODULUS - 1) / 2;
        let legendre = self.pow(exp);
        
        if legendre.value != 1 {
            return None;
        }
        
        // For q ≡ 3 (mod 4), sqrt(a) = a^((q+1)/4)
        // But 2^61 - 1 ≡ 1 (mod 4), so we need Tonelli-Shanks
        
        let mut q = Self::MODULUS - 1;
        let mut s = 0;
        while q % 2 == 0 {
            q /= 2;
            s += 1;
        }
        
        let mut z = 2u64;
        while Self::from_u64(z).pow((Self::MODULUS - 1) / 2).value == 1 {
            z += 1;
        }
        
        let mut m = s;
        let mut c = Self::from_u64(z).pow(q);
        let mut t = self.pow(q);
        let mut r = self.pow((q + 1) / 2);
        
        loop {
            if t.value == 0 {
                return Some(Self::zero());
            }
            if t.value == 1 {
                return Some(r);
            }
            
            let mut i = 1;
            let mut temp = t.mul(&t);
            while temp.value != 1 && i < m {
                temp = temp.mul(&temp);
                i += 1;
            }
            
            let b = c.pow(1 << (m - i - 1));
            m = i;
            c = b.mul(&b);
            t = t.mul(&c);
            r = r.mul(&b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let a = M61Field::from_u64(5);
        let b = M61Field::from_u64(7);
        
        assert_eq!(a.add(&b).to_canonical_u64(), 12);
        assert_eq!(a.mul(&b).to_canonical_u64(), 35);
        assert_eq!(b.sub(&a).to_canonical_u64(), 2);
    }
    
    #[test]
    fn test_modular_arithmetic() {
        let a = M61Field::from_u64(M61Field::MODULUS - 1);
        let b = M61Field::from_u64(2);
        
        assert_eq!(a.add(&b).to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_inverse() {
        let a = M61Field::from_u64(7);
        let a_inv = a.inv().unwrap();
        
        assert_eq!(a.mul(&a_inv), M61Field::one());
    }
    
    #[test]
    fn test_mersenne_reduction() {
        // Test that Mersenne reduction works correctly
        let large = (1u64 << 61) + 5;
        let reduced = M61Field::from_u64(large);
        assert_eq!(reduced.to_canonical_u64(), 6); // (2^61 + 5) mod (2^61 - 1) = 6
    }
}

/// Type alias for Mersenne 61 field (for Symphony compatibility)
pub type Mersenne61Field = M61Field;
