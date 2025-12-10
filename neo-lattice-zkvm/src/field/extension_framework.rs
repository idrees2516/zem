// Complete Extension Field Framework for Sum-Check Protocol
// Implements arbitrary degree extensions K = F_q[X]/(f(X))

use super::{Field, M61Field};
use std::fmt::Debug;
use std::ops::{Add, Sub, Mul, Neg};

/// Trait for extension field elements over base field Fq
pub trait ExtensionFieldElement: Clone + Copy + Debug + Eq + PartialEq + Sized {
    type BaseField: Field;
    
    /// Extension degree t
    fn degree() -> usize;
    
    /// Zero element
    fn zero() -> Self;
    
    /// One element
    fn one() -> Self;
    
    /// Addition
    fn add(&self, rhs: &Self) -> Self;
    
    /// Subtraction
    fn sub(&self, rhs: &Self) -> Self;
    
    /// Multiplication modulo irreducible polynomial
    fn mul(&self, rhs: &Self) -> Self;
    
    /// Division (multiplication by inverse)
    fn div(&self, rhs: &Self) -> Option<Self> {
        rhs.inverse().map(|inv| self.mul(&inv))
    }
    
    /// Negation
    fn neg(&self) -> Self;
    
    /// Multiplicative inverse using Extended Euclidean algorithm
    fn inverse(&self) -> Option<Self>;
    
    /// Exponentiation using square-and-multiply
    fn pow(&self, n: u64) -> Self {
        if n == 0 {
            return Self::one();
        }
        
        let mut result = Self::one();
        let mut base = *self;
        let mut exp = n;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exp >>= 1;
        }
        
        result
    }
    
    /// Get coefficients as vector [a_0, ..., a_{t-1}]
    fn to_base_field_coefficients(&self) -> Vec<Self::BaseField>;
    
    /// Create from base field coefficients
    fn from_base_field_coefficients(coeffs: &[Self::BaseField]) -> Self;
    
    /// Embed base field element at position i
    fn from_base_field_element(a: Self::BaseField, i: usize) -> Self;
    
    /// Sample uniformly at random
    fn random<R: rand::Rng>(rng: &mut R) -> Self;
    
    /// Frobenius endomorphism: x -> x^q
    fn frobenius(&self) -> Self;
}

/// Generic extension field K = F_q[X]/(f(X)) with arbitrary degree t
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericExtensionField<F: Field, const T: usize> {
    /// Coefficients [a_0, a_1, ..., a_{t-1}] representing Σ a_i X^i
    pub coeffs: [F; T],
}

impl<F: Field, const T: usize> GenericExtensionField<F, T> {
    /// Create new extension field element from coefficients
    pub fn new(coeffs: [F; T]) -> Self {
        Self { coeffs }
    }
    
    /// Get irreducible polynomial coefficients for f(X)
    /// For degree 2: f(X) = X^2 + 1 (when q ≡ 3 mod 4)
    /// For higher degrees: use Conway polynomials or other irreducible polynomials
    fn irreducible_poly() -> Vec<F> {
        match T {
            2 => {
                // f(X) = X^2 + 1
                vec![F::one(), F::zero(), F::one()]
            }
            3 => {
                // f(X) = X^3 + X + 1 (irreducible over many fields)
                vec![F::one(), F::one(), F::zero(), F::one()]
            }
            4 => {
                // f(X) = X^4 + X + 1
                vec![F::one(), F::one(), F::zero(), F::zero(), F::one()]
            }
            _ => {
                // For general case, use X^t + X + 1 (often irreducible)
                let mut poly = vec![F::zero(); T + 1];
                poly[0] = F::one();
                poly[1] = F::one();
                poly[T] = F::one();
                poly
            }
        }
    }
    
    /// Multiply two polynomials and reduce modulo irreducible polynomial
    fn poly_mul_reduce(a: &[F; T], b: &[F; T]) -> [F; T] {
        // First compute full product (degree up to 2t-2)
        let mut product = vec![F::zero(); 2 * T - 1];
        
        for i in 0..T {
            for j in 0..T {
                let term = a[i].mul(&b[j]);
                product[i + j] = product[i + j].add(&term);
            }
        }
        
        // Reduce modulo irreducible polynomial
        let irred = Self::irreducible_poly();
        
        // Perform polynomial long division
        for i in (T..product.len()).rev() {
            if product[i].to_canonical_u64() != 0 {
                // Subtract (product[i] / irred[T]) * irred * X^(i-T)
                let coeff = product[i];
                for j in 0..=T {
                    if j + i >= T {
                        let term = coeff.mul(&irred[j]);
                        product[i - T + j] = product[i - T + j].sub(&term);
                    }
                }
            }
        }
        
        // Extract result
        let mut result = [F::zero(); T];
        for i in 0..T {
            result[i] = product[i];
        }
        result
    }
    
    /// Extended Euclidean algorithm for polynomial inverse
    fn poly_inverse(a: &[F; T]) -> Option<[F; T]> {
        // Check if a is zero
        if a.iter().all(|&x| x.to_canonical_u64() == 0) {
            return None;
        }
        
        // Extended Euclidean algorithm in polynomial ring
        let irred = Self::irreducible_poly();
        
        // Convert to Vec for easier manipulation
        let mut r0: Vec<F> = irred.clone();
        let mut r1: Vec<F> = a.iter().copied().collect();
        
        let mut s0 = vec![F::zero(); T + 1];
        s0[0] = F::one();
        let mut s1 = vec![F::zero(); T + 1];
        
        let mut t0 = vec![F::zero(); T + 1];
        let mut t1 = vec![F::zero(); T + 1];
        t1[0] = F::one();
        
        while !r1.iter().all(|&x| x.to_canonical_u64() == 0) {
            // Find degree of r0 and r1
            let deg0 = r0.iter().rposition(|&x| x.to_canonical_u64() != 0).unwrap_or(0);
            let deg1 = r1.iter().rposition(|&x| x.to_canonical_u64() != 0).unwrap_or(0);
            
            if deg1 > deg0 {
                break;
            }
            
            // Compute quotient and remainder
            let mut q = vec![F::zero(); deg0 - deg1 + 1];
            let mut rem = r0.clone();
            
            for i in (0..=deg0 - deg1).rev() {
                let lead_rem = rem[deg1 + i];
                let lead_r1 = r1[deg1];
                
                if let Some(lead_r1_inv) = lead_r1.inv() {
                    let q_coeff = lead_rem.mul(&lead_r1_inv);
                    q[i] = q_coeff;
                    
                    for j in 0..=deg1 {
                        let term = q_coeff.mul(&r1[j]);
                        rem[i + j] = rem[i + j].sub(&term);
                    }
                }
            }
            
            // Update r, s, t
            let r_new = rem;
            let s_new = poly_sub(&s0, &poly_mul(&q, &s1));
            let t_new = poly_sub(&t0, &poly_mul(&q, &t1));
            
            r0 = r1;
            r1 = r_new;
            s0 = s1;
            s1 = s_new;
            t0 = t1;
            t1 = t_new;
        }
        
        // Check if gcd is constant (invertible)
        let deg = r0.iter().rposition(|&x| x.to_canonical_u64() != 0).unwrap_or(0);
        if deg != 0 {
            return None;
        }
        
        // Normalize by leading coefficient
        if let Some(lead_inv) = r0[0].inv() {
            let mut result = [F::zero(); T];
            for i in 0..T.min(t0.len()) {
                result[i] = t0[i].mul(&lead_inv);
            }
            Some(result)
        } else {
            None
        }
    }
}

// Helper functions for polynomial arithmetic
fn poly_mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut result = vec![F::zero(); a.len() + b.len()];
    for i in 0..a.len() {
        for j in 0..b.len() {
            let term = a[i].mul(&b[j]);
            result[i + j] = result[i + j].add(&term);
        }
    }
    result
}

fn poly_sub<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let len = a.len().max(b.len());
    let mut result = vec![F::zero(); len];
    for i in 0..len {
        let a_val = if i < a.len() { a[i] } else { F::zero() };
        let b_val = if i < b.len() { b[i] } else { F::zero() };
        result[i] = a_val.sub(&b_val);
    }
    result
}

impl<F: Field, const T: usize> ExtensionFieldElement for GenericExtensionField<F, T> {
    type BaseField = F;
    
    fn degree() -> usize {
        T
    }
    
    fn zero() -> Self {
        Self {
            coeffs: [F::zero(); T],
        }
    }
    
    fn one() -> Self {
        let mut coeffs = [F::zero(); T];
        coeffs[0] = F::one();
        Self { coeffs }
    }
    
    fn add(&self, rhs: &Self) -> Self {
        let mut result = [F::zero(); T];
        for i in 0..T {
            result[i] = self.coeffs[i].add(&rhs.coeffs[i]);
        }
        Self { coeffs: result }
    }
    
    fn sub(&self, rhs: &Self) -> Self {
        let mut result = [F::zero(); T];
        for i in 0..T {
            result[i] = self.coeffs[i].sub(&rhs.coeffs[i]);
        }
        Self { coeffs: result }
    }
    
    fn mul(&self, rhs: &Self) -> Self {
        let result = Self::poly_mul_reduce(&self.coeffs, &rhs.coeffs);
        Self { coeffs: result }
    }
    
    fn neg(&self) -> Self {
        let mut result = [F::zero(); T];
        for i in 0..T {
            result[i] = self.coeffs[i].neg();
        }
        Self { coeffs: result }
    }
    
    fn inverse(&self) -> Option<Self> {
        Self::poly_inverse(&self.coeffs).map(|coeffs| Self { coeffs })
    }
    
    fn to_base_field_coefficients(&self) -> Vec<F> {
        self.coeffs.to_vec()
    }
    
    fn from_base_field_coefficients(coeffs: &[F]) -> Self {
        let mut result = [F::zero(); T];
        for i in 0..T.min(coeffs.len()) {
            result[i] = coeffs[i];
        }
        Self { coeffs: result }
    }
    
    fn from_base_field_element(a: F, i: usize) -> Self {
        let mut coeffs = [F::zero(); T];
        if i < T {
            coeffs[i] = a;
        }
        Self { coeffs }
    }
    
    fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut coeffs = [F::zero(); T];
        for i in 0..T {
            // Generate random field element
            let val = rng.gen::<u64>() % F::MODULUS;
            coeffs[i] = F::from_u64(val);
        }
        Self { coeffs }
    }
    
    fn frobenius(&self) -> Self {
        // Frobenius: x -> x^q
        // For extension fields, this permutes the coefficients
        self.pow(F::MODULUS)
    }
}

// Implement standard operators
impl<F: Field, const T: usize> Add for GenericExtensionField<F, T> {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        ExtensionFieldElement::add(&self, &rhs)
    }
}

impl<F: Field, const T: usize> Sub for GenericExtensionField<F, T> {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        ExtensionFieldElement::sub(&self, &rhs)
    }
}

impl<F: Field, const T: usize> Mul for GenericExtensionField<F, T> {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        ExtensionFieldElement::mul(&self, &rhs)
    }
}

impl<F: Field, const T: usize> Neg for GenericExtensionField<F, T> {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        ExtensionFieldElement::neg(&self)
    }
}

/// Specialized extension field for degree 2 over M61 (Mersenne 61)
/// K = F_q[X]/(X^2 + 1) where q = 2^61 - 1
pub type M61ExtensionField2 = GenericExtensionField<M61Field, 2>;

/// Specialized extension field for degree 4 over M61
pub type M61ExtensionField4 = GenericExtensionField<M61Field, 4>;

/// Specialized extension field for degree 8 over M61
pub type M61ExtensionField8 = GenericExtensionField<M61Field, 8>;

#[cfg(test)]
mod tests {
    use super::*;
    
    type K2 = M61ExtensionField2;
    
    #[test]
    fn test_field_axioms_associativity() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        let b = K2::new([M61Field::from_u64(7), M61Field::from_u64(11)]);
        let c = K2::new([M61Field::from_u64(13), M61Field::from_u64(17)]);
        
        // Addition associativity: (a + b) + c = a + (b + c)
        let left = a.add(&b).add(&c);
        let right = a.add(&b.add(&c));
        assert_eq!(left, right);
        
        // Multiplication associativity: (a * b) * c = a * (b * c)
        let left = a.mul(&b).mul(&c);
        let right = a.mul(&b.mul(&c));
        assert_eq!(left, right);
    }
    
    #[test]
    fn test_field_axioms_commutativity() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        let b = K2::new([M61Field::from_u64(7), M61Field::from_u64(11)]);
        
        // Addition commutativity: a + b = b + a
        assert_eq!(a.add(&b), b.add(&a));
        
        // Multiplication commutativity: a * b = b * a
        assert_eq!(a.mul(&b), b.mul(&a));
    }
    
    #[test]
    fn test_field_axioms_distributivity() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        let b = K2::new([M61Field::from_u64(7), M61Field::from_u64(11)]);
        let c = K2::new([M61Field::from_u64(13), M61Field::from_u64(17)]);
        
        // Distributivity: a * (b + c) = a * b + a * c
        let left = a.mul(&b.add(&c));
        let right = a.mul(&b).add(&a.mul(&c));
        assert_eq!(left, right);
    }
    
    #[test]
    fn test_field_axioms_identities() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        
        // Additive identity: a + 0 = a
        assert_eq!(a.add(&K2::zero()), a);
        
        // Multiplicative identity: a * 1 = a
        assert_eq!(a.mul(&K2::one()), a);
    }
    
    #[test]
    fn test_field_axioms_inverses() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        
        // Additive inverse: a + (-a) = 0
        assert_eq!(a.add(&a.neg()), K2::zero());
        
        // Multiplicative inverse: a * a^(-1) = 1
        if let Some(a_inv) = a.inverse() {
            let product = a.mul(&a_inv);
            assert_eq!(product, K2::one());
        }
    }
    
    #[test]
    fn test_inverse_extended_euclidean() {
        let a = K2::new([M61Field::from_u64(7), M61Field::from_u64(13)]);
        
        let a_inv = a.inverse().expect("Should have inverse");
        let product = a.mul(&a_inv);
        
        assert_eq!(product.coeffs[0], M61Field::one());
        assert_eq!(product.coeffs[1], M61Field::zero());
    }
    
    #[test]
    fn test_pow_square_and_multiply() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        
        // Test a^0 = 1
        assert_eq!(a.pow(0), K2::one());
        
        // Test a^1 = a
        assert_eq!(a.pow(1), a);
        
        // Test a^2 = a * a
        assert_eq!(a.pow(2), a.mul(&a));
        
        // Test a^3 = a * a * a
        assert_eq!(a.pow(3), a.mul(&a).mul(&a));
        
        // Test larger exponent
        let a_pow_10 = a.pow(10);
        let mut manual = K2::one();
        for _ in 0..10 {
            manual = manual.mul(&a);
        }
        assert_eq!(a_pow_10, manual);
    }
    
    #[test]
    fn test_to_base_field_coefficients() {
        let a = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        let coeffs = a.to_base_field_coefficients();
        
        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0].to_canonical_u64(), 3);
        assert_eq!(coeffs[1].to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_from_base_field_element() {
        let a = M61Field::from_u64(42);
        
        // Embed at position 0
        let ext0 = K2::from_base_field_element(a, 0);
        assert_eq!(ext0.coeffs[0], a);
        assert_eq!(ext0.coeffs[1], M61Field::zero());
        
        // Embed at position 1
        let ext1 = K2::from_base_field_element(a, 1);
        assert_eq!(ext1.coeffs[0], M61Field::zero());
        assert_eq!(ext1.coeffs[1], a);
    }
    
    #[test]
    fn test_random_sampling() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        let a = K2::random(&mut rng);
        let b = K2::random(&mut rng);
        
        // Random elements should be different (with high probability)
        assert_ne!(a, b);
        
        // Random elements should satisfy field axioms
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff, a);
    }
    
    #[test]
    fn test_x_squared_plus_one() {
        // Test that X^2 = -1 in K = F_q[X]/(X^2 + 1)
        let x = K2::new([M61Field::zero(), M61Field::one()]);
        let x_squared = x.mul(&x);
        
        // X^2 should equal -1
        let neg_one = K2::new([M61Field::from_u64(M61Field::MODULUS - 1), M61Field::zero()]);
        assert_eq!(x_squared, neg_one);
    }
    
    #[test]
    fn test_division() {
        let a = K2::new([M61Field::from_u64(10), M61Field::from_u64(20)]);
        let b = K2::new([M61Field::from_u64(3), M61Field::from_u64(5)]);
        
        let quotient = a.div(&b).expect("Division should succeed");
        let product = quotient.mul(&b);
        
        assert_eq!(product, a);
    }
}
