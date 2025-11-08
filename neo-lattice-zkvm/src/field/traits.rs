// Field trait definition

use std::fmt::Debug;

/// Base field trait for finite field arithmetic
pub trait Field: Clone + Copy + Debug + Eq + PartialEq {
    const MODULUS: u64;
    const MODULUS_BITS: usize;
    const TWO_ADICITY: usize;
    
    /// Zero element
    fn zero() -> Self;
    
    /// One element
    fn one() -> Self;
    
    /// Create from u64
    fn from_u64(val: u64) -> Self;
    
    /// Convert to canonical u64 representation
    fn to_canonical_u64(&self) -> u64;
    
    /// Addition
    fn add(&self, rhs: &Self) -> Self;
    
    /// Subtraction
    fn sub(&self, rhs: &Self) -> Self;
    
    /// Multiplication
    fn mul(&self, rhs: &Self) -> Self;
    
    /// Negation
    fn neg(&self) -> Self;
    
    /// Multiplicative inverse (returns None if element is zero)
    fn inv(&self) -> Option<Self>;
    
    /// Exponentiation
    fn pow(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            e >>= 1;
        }
        
        result
    }
    
    /// Square root (returns None if no square root exists)
    fn sqrt(&self) -> Option<Self>;
    
    /// Batch addition for SIMD optimization
    fn batch_add(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| x.add(y)).collect()
    }
    
    /// Batch multiplication for SIMD optimization
    fn batch_mul(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| x.mul(y)).collect()
    }
}
