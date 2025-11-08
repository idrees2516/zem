// Goldilocks field implementation
// q = 2^64 - 2^32 + 1

use super::Field;

/// Goldilocks field element
/// Modulus: q = 2^64 - 2^32 + 1 = 18446744069414584321
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoldilocksField {
    value: u64,
}

impl GoldilocksField {
    /// Goldilocks prime: q = 2^64 - 2^32 + 1
    pub const MODULUS: u64 = 0xFFFFFFFF00000001u64;
    
    /// Epsilon for fast reduction: ε = 2^32 - 1
    const EPSILON: u64 = 0xFFFFFFFFu64;
    
    /// Create new field element (assumes value < MODULUS)
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
    
    /// Fast reduction for 128-bit values
    /// Uses q = 2^64 - ε where ε = 2^32 - 1
    /// x mod q = lo + hi·ε (mod q)
    fn reduce128(x: u128) -> u64 {
        let lo = x as u64;
        let hi = (x >> 64) as u64;
        
        // Compute lo + hi·ε
        let sum = lo as u128 + (hi as u128) * (Self::EPSILON as u128);
        let sum_lo = sum as u64;
        let sum_hi = (sum >> 64) as u64;
        
        // Final reduction
        let result = sum_lo.wrapping_add(sum_hi.wrapping_mul(Self::EPSILON));
        
        // Conditional subtraction
        if result >= Self::MODULUS {
            result - Self::MODULUS
        } else {
            result
        }
    }
    
    /// Addition implementation
    fn add_impl(a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        Self::reduce128(sum)
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
            return None; // Not invertible
        }
        
        if t < 0 {
            t += Self::MODULUS as i128;
        }
        
        Some(t as u64)
    }
}

impl Field for GoldilocksField {
    const MODULUS: u64 = Self::MODULUS;
    const MODULUS_BITS: usize = 64;
    const TWO_ADICITY: usize = 32;
    
    fn zero() -> Self {
        Self { value: 0 }
    }
    
    fn one() -> Self {
        Self { value: 1 }
    }
    
    fn from_u64(val: u64) -> Self {
        Self {
            value: if val >= Self::MODULUS {
                val % Self::MODULUS
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
        // Tonelli-Shanks algorithm for square root
        // For Goldilocks, q ≡ 1 (mod 4), so we need full Tonelli-Shanks
        
        if self.value == 0 {
            return Some(Self::zero());
        }
        
        // Check if quadratic residue using Euler's criterion
        let exp = (Self::MODULUS - 1) / 2;
        let legendre = self.pow(exp);
        
        if legendre.value != 1 {
            return None; // Not a quadratic residue
        }
        
        // Find Q and S such that q - 1 = Q * 2^S with Q odd
        let mut q = Self::MODULUS - 1;
        let mut s = 0;
        while q % 2 == 0 {
            q /= 2;
            s += 1;
        }
        
        // Find a quadratic non-residue
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
            
            // Find least i such that t^(2^i) = 1
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
        let a = GoldilocksField::from_u64(5);
        let b = GoldilocksField::from_u64(7);
        
        assert_eq!(a.add(&b).to_canonical_u64(), 12);
        assert_eq!(a.mul(&b).to_canonical_u64(), 35);
        assert_eq!(b.sub(&a).to_canonical_u64(), 2);
    }
    
    #[test]
    fn test_modular_arithmetic() {
        let a = GoldilocksField::from_u64(GoldilocksField::MODULUS - 1);
        let b = GoldilocksField::from_u64(2);
        
        assert_eq!(a.add(&b).to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_inverse() {
        let a = GoldilocksField::from_u64(7);
        let a_inv = a.inv().unwrap();
        
        assert_eq!(a.mul(&a_inv), GoldilocksField::one());
    }
    
    #[test]
    fn test_zero_inverse() {
        let zero = GoldilocksField::zero();
        assert!(zero.inv().is_none());
    }
}
