// Constant-Time Operations for Side-Channel Resistance
//
// This module provides constant-time implementations of critical operations
// to prevent timing attacks and other side-channel vulnerabilities.

use crate::ring::cyclotomic::RingElement;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time equality comparison
///
/// Returns 1 if a == b, 0 otherwise, in constant time
pub fn ct_eq(a: u64, b: u64) -> u8 {
    let eq = a.ct_eq(&b);
    eq.unwrap_u8()
}

/// Constant-time conditional select
///
/// Returns a if condition is true, b otherwise, in constant time
pub fn ct_select(condition: bool, a: u64, b: u64) -> u64 {
    let choice = Choice::from(condition as u8);
    u64::conditional_select(&b, &a, choice)
}

/// Constant-time modular reduction
///
/// Reduces x modulo q in constant time using Barrett reduction
pub fn ct_reduce_mod(x: u128, q: u64) -> u64 {
    // Barrett reduction constant: μ = ⌊2^128 / q⌋
    let mu = (1u128 << 128) / (q as u128);
    
    // Compute quotient estimate: q_est = (x * μ) >> 128
    let q_est = ((x as u128).wrapping_mul(mu)) >> 128;
    
    // Compute remainder: r = x - q_est * q
    let qm = q_est.wrapping_mul(q as u128);
    let mut r = x.wrapping_sub(qm) as u64;
    
    // Conditional subtraction (constant time)
    let needs_sub = r >= q;
    r = ct_select(needs_sub, r - q, r);
    
    r
}

/// Constant-time comparison: a < b
pub fn ct_lt(a: u64, b: u64) -> bool {
    // Compute difference with borrow
    let (_, borrow) = a.overflowing_sub(b);
    borrow
}

/// Constant-time comparison: a >= b
pub fn ct_ge(a: u64, b: u64) -> bool {
    !ct_lt(a, b)
}

/// Constant-time ring element multiplication
///
/// Multiplies two ring elements in constant time
pub fn ct_mul_ring_elements(a: &RingElement, b: &RingElement) -> RingElement {
    assert_eq!(a.coefficients.len(), b.coefficients.len());
    
    let q = a.ring.modulus();
    let mut result_coeffs = Vec::with_capacity(a.coefficients.len());
    
    // Perform multiplication in constant time
    for (a_coeff, b_coeff) in a.coefficients.iter().zip(b.coefficients.iter()) {
        let product = (*a_coeff as i128) * (*b_coeff as i128);
        let reduced = ct_reduce_mod(product.abs() as u128, q);
        
        // Handle sign in constant time
        let is_negative = product < 0;
        let final_value = ct_select(is_negative, q - reduced, reduced);
        
        result_coeffs.push(final_value as i64);
    }
    
    RingElement {
        coefficients: result_coeffs,
        ring: a.ring.clone(),
    }
}

/// Constant-time array comparison
///
/// Compares two arrays in constant time
pub fn ct_array_eq(a: &[u64], b: &[u64]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = Choice::from(1u8);
    for (x, y) in a.iter().zip(b.iter()) {
        result &= x.ct_eq(y);
    }
    
    result.unwrap_u8() == 1
}

/// Constant-time conditional swap
///
/// Swaps a and b if condition is true, in constant time
pub fn ct_swap(condition: bool, a: &mut u64, b: &mut u64) {
    let choice = Choice::from(condition as u8);
    let temp_a = *a;
    let temp_b = *b;
    
    *a = u64::conditional_select(&temp_a, &temp_b, choice);
    *b = u64::conditional_select(&temp_b, &temp_a, choice);
}

/// Constant-time zero check
///
/// Returns true if x == 0, in constant time
pub fn ct_is_zero(x: u64) -> bool {
    x.ct_eq(&0).unwrap_u8() == 1
}

/// Constant-time absolute value
///
/// Returns |x| in constant time
pub fn ct_abs(x: i64) -> u64 {
    let is_negative = x < 0;
    let abs_val = x.wrapping_abs() as u64;
    let neg_val = (-(x as i128)) as u64;
    
    ct_select(is_negative, neg_val, abs_val)
}

/// Constant-time minimum
///
/// Returns min(a, b) in constant time
pub fn ct_min(a: u64, b: u64) -> u64 {
    let a_lt_b = ct_lt(a, b);
    ct_select(a_lt_b, a, b)
}

/// Constant-time maximum
///
/// Returns max(a, b) in constant time
pub fn ct_max(a: u64, b: u64) -> u64 {
    let a_lt_b = ct_lt(a, b);
    ct_select(a_lt_b, b, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_eq() {
        assert_eq!(ct_eq(5, 5), 1);
        assert_eq!(ct_eq(5, 6), 0);
        assert_eq!(ct_eq(0, 0), 1);
    }
    
    #[test]
    fn test_ct_select() {
        assert_eq!(ct_select(true, 10, 20), 10);
        assert_eq!(ct_select(false, 10, 20), 20);
    }
    
    #[test]
    fn test_ct_reduce_mod() {
        let q = 17;
        assert_eq!(ct_reduce_mod(20, q), 3);
        assert_eq!(ct_reduce_mod(17, q), 0);
        assert_eq!(ct_reduce_mod(16, q), 16);
    }
    
    #[test]
    fn test_ct_comparisons() {
        assert!(ct_lt(5, 10));
        assert!(!ct_lt(10, 5));
        assert!(!ct_lt(5, 5));
        
        assert!(ct_ge(10, 5));
        assert!(ct_ge(5, 5));
        assert!(!ct_ge(5, 10));
    }
    
    #[test]
    fn test_ct_array_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        
        assert!(ct_array_eq(&a, &b));
        assert!(!ct_array_eq(&a, &c));
    }
    
    #[test]
    fn test_ct_min_max() {
        assert_eq!(ct_min(5, 10), 5);
        assert_eq!(ct_min(10, 5), 5);
        assert_eq!(ct_max(5, 10), 10);
        assert_eq!(ct_max(10, 5), 10);
    }
}
