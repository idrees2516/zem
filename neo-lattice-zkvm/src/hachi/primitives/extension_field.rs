// Extension field F_{q^k} implementation for Hachi
// Supports k = 2^κ for κ ∈ {1, 2, 3, 4} (k ∈ {2, 4, 8, 16})

use crate::field::Field;
use super::super::errors::{HachiError, Result};

/// Extension field element F_{q^k}
/// 
/// **Paper Reference:** Section 2.1 "Extension Fields"
/// 
/// Represented as F_q[Z]/(φ(Z)) where φ is irreducible of degree k
/// Element: a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionFieldElement<F: Field> {
    /// Coefficients [a_0, a_1, ..., a_{k-1}]
    pub coeffs: Vec<F>,
    
    /// Extension degree k
    pub degree: usize,
}

impl<F: Field> ExtensionFieldElement<F> {
    /// Create new extension field element
    pub fn new(coeffs: Vec<F>) -> Self {
        let degree = coeffs.len();
        assert!(degree.is_power_of_two(), "Degree must be power of 2");
        assert!(degree >= 2 && degree <= 16, "Degree must be in {2, 4, 8, 16}");
        
        Self { coeffs, degree }
    }
    
    /// Zero element
    pub fn zero(degree: usize) -> Self {
        Self::new(vec![F::zero(); degree])
    }
    
    /// One element
    pub fn one(degree: usize) -> Self {
        let mut coeffs = vec![F::zero(); degree];
        coeffs[0] = F::one();
        Self::new(coeffs)
    }
    
    /// Embed base field element
    pub fn from_base(x: F, degree: usize) -> Self {
        let mut coeffs = vec![F::zero(); degree];
        coeffs[0] = x;
        Self::new(coeffs)
    }
    
    /// Addition in extension field
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.degree, other.degree);
        
        let coeffs = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        
        Self::new(coeffs)
    }
    
    /// Subtraction in extension field
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.degree, other.degree);
        
        let coeffs = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| a.sub(b))
            .collect();
        
        Self::new(coeffs)
    }
    
    /// Negation in extension field
    pub fn neg(&self) -> Self {
        let coeffs = self.coeffs.iter()
            .map(|a| a.neg())
            .collect();
        
        Self::new(coeffs)
    }
    
    /// Multiplication in extension field
    /// 
    /// **Paper Reference:** Section 2.1
    /// 
    /// Uses irreducible polynomial φ(Z) for reduction
    /// For k = 2^κ, we use specific irreducible polynomials
    pub fn mul(&self, other: &Self, irreducible: &IrreduciblePolynomial<F>) -> Self {
        assert_eq!(self.degree, other.degree);
        assert_eq!(self.degree, irreducible.degree);
        
        // Polynomial multiplication
        let mut product = vec![F::zero(); 2 * self.degree - 1];
        
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                let term = a.mul(b);
                product[i + j] = product[i + j].add(&term);
            }
        }
        
        // Reduce modulo irreducible polynomial
        irreducible.reduce(&product)
    }
    
    /// Scalar multiplication by base field element
    pub fn scalar_mul(&self, scalar: &F) -> Self {
        let coeffs = self.coeffs.iter()
            .map(|a| a.mul(scalar))
            .collect();
        
        Self::new(coeffs)
    }
    
    /// Multiplicative inverse
    /// 
    /// **Paper Reference:** Section 2.1
    /// 
    /// Uses extended Euclidean algorithm in F_q[Z]
    pub fn inv(&self, irreducible: &IrreduciblePolynomial<F>) -> Result<Self> {
        if self.is_zero() {
            return Err(HachiError::InternalError("Cannot invert zero".to_string()));
        }
        
        // Extended Euclidean algorithm
        let (gcd, inv_coeffs) = extended_gcd(&self.coeffs, &irreducible.coeffs)?;
        
        // Check gcd is constant (invertible)
        if gcd.len() != 1 {
            return Err(HachiError::InternalError("Element not invertible".to_string()));
        }
        
        // Normalize by gcd constant
        let gcd_inv = gcd[0].inv()
            .ok_or_else(|| HachiError::InternalError("GCD not invertible".to_string()))?;
        
        let coeffs = inv_coeffs.iter()
            .map(|c| c.mul(&gcd_inv))
            .collect();
        
        Ok(Self::new(coeffs))
    }
    
    /// Exponentiation
    pub fn pow(&self, exp: u64, irreducible: &IrreduciblePolynomial<F>) -> Self {
        let mut result = Self::one(self.degree);
        let mut base = self.clone();
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base, irreducible);
            }
            base = base.mul(&base, irreducible);
            e >>= 1;
        }
        
        result
    }
    
    /// Frobenius endomorphism: x ↦ x^q
    /// 
    /// **Paper Reference:** Section 2.1
    /// 
    /// For F_{q^k}, Frobenius is x ↦ x^q
    /// Computed efficiently using precomputed powers
    pub fn frobenius(&self, irreducible: &IrreduciblePolynomial<F>) -> Self {
        // x^q = (Σ a_i Z^i)^q = Σ a_i^q Z^{iq}
        // Since a_i ∈ F_q, a_i^q = a_i (Fermat's little theorem)
        // So we need to compute Z^{iq} mod φ(Z) for each i
        
        let mut result = Self::zero(self.degree);
        
        for (i, coeff) in self.coeffs.iter().enumerate() {
            // Compute Z^{iq} mod φ(Z)
            let power_i = irreducible.frobenius_power(i);
            let term = power_i.scalar_mul(coeff);
            result = result.add(&term);
        }
        
        result
    }
    
    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|c| c.to_canonical_u64() == 0)
    }
    
    /// Check if one
    pub fn is_one(&self) -> bool {
        self.coeffs[0].to_canonical_u64() == 1 &&
        self.coeffs[1..].iter().all(|c| c.to_canonical_u64() == 0)
    }
}

/// Irreducible polynomial φ(Z) for extension field construction
/// 
/// **Paper Reference:** Section 2.1
/// 
/// For k = 2^κ, we use specific irreducible polynomials:
/// - k = 2: Z^2 + 7 (for Goldilocks)
/// - k = 4: Z^4 + Z + 7
/// - k = 8: Z^8 + Z^4 + Z^3 + Z + 7
/// - k = 16: Z^16 + Z^5 + Z^3 + Z + 7
#[derive(Clone, Debug)]
pub struct IrreduciblePolynomial<F: Field> {
    /// Coefficients [c_0, c_1, ..., c_k]
    /// Represents c_0 + c_1·Z + ... + c_k·Z^k
    pub coeffs: Vec<F>,
    
    /// Degree k
    pub degree: usize,
    
    /// Precomputed Frobenius powers: Z^{iq} mod φ(Z) for i = 0, ..., k-1
    frobenius_powers: Vec<ExtensionFieldElement<F>>,
}

impl<F: Field> IrreduciblePolynomial<F> {
    /// Create irreducible polynomial for given degree
    /// 
    /// **Paper Reference:** Section 2.1
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two());
        assert!(degree >= 2 && degree <= 16);
        
        let coeffs = Self::get_irreducible_coeffs(degree);
        let mut poly = Self {
            coeffs,
            degree,
            frobenius_powers: Vec::new(),
        };
        
        // Precompute Frobenius powers
        poly.precompute_frobenius_powers();
        
        poly
    }
    
    /// Get irreducible polynomial coefficients for degree k
    fn get_irreducible_coeffs(k: usize) -> Vec<F> {
        let mut coeffs = vec![F::zero(); k + 1];
        
        // Constant term: 7 (non-residue for Goldilocks)
        coeffs[0] = F::from_u64(7);
        
        // Leading term: Z^k
        coeffs[k] = F::one();
        
        // Middle terms depend on k
        match k {
            2 => {
                // Z^2 + 7
            },
            4 => {
                // Z^4 + Z + 7
                coeffs[1] = F::one();
            },
            8 => {
                // Z^8 + Z^4 + Z^3 + Z + 7
                coeffs[1] = F::one();
                coeffs[3] = F::one();
                coeffs[4] = F::one();
            },
            16 => {
                // Z^16 + Z^5 + Z^3 + Z + 7
                coeffs[1] = F::one();
                coeffs[3] = F::one();
                coeffs[5] = F::one();
            },
            _ => panic!("Unsupported degree"),
        }
        
        coeffs
    }
    
    /// Reduce polynomial modulo this irreducible polynomial
    /// 
    /// **Paper Reference:** Section 2.1
    /// 
    /// Given polynomial p(Z) of degree < 2k, compute p(Z) mod φ(Z)
    pub fn reduce(&self, poly: &[F]) -> ExtensionFieldElement<F> {
        let mut result = poly.to_vec();
        
        // Long division: reduce degree from high to low
        while result.len() > self.degree {
            let lead_coeff = result.pop().unwrap();
            let lead_degree = result.len();
            
            // Subtract lead_coeff * Z^{lead_degree} * (φ(Z) / Z^k)
            // This eliminates the leading term
            for (i, c) in self.coeffs[..self.degree].iter().enumerate() {
                let idx = lead_degree - self.degree + i;
                if idx < result.len() {
                    let term = lead_coeff.mul(c);
                    result[idx] = result[idx].sub(&term);
                }
            }
        }
        
        // Pad to degree k
        while result.len() < self.degree {
            result.push(F::zero());
        }
        
        ExtensionFieldElement::new(result)
    }
    
    /// Precompute Frobenius powers
    fn precompute_frobenius_powers(&mut self) {
        self.frobenius_powers = Vec::with_capacity(self.degree);
        
        // Compute Z^{iq} mod φ(Z) for i = 0, ..., k-1
        for i in 0..self.degree {
            // Start with Z^i
            let mut power_coeffs = vec![F::zero(); i + 1];
            power_coeffs[i] = F::one();
            
            // Raise to q-th power
            // For Goldilocks, q = 2^64 - 2^32 + 1
            // We compute this iteratively
            let q = F::MODULUS;
            let mut current = self.reduce(&power_coeffs);
            
            // Binary exponentiation for Z^{iq}
            let mut exp = q;
            let mut base = current.clone();
            current = ExtensionFieldElement::one(self.degree);
            
            while exp > 0 {
                if exp & 1 == 1 {
                    current = current.mul(&base, self);
                }
                base = base.mul(&base, self);
                exp >>= 1;
            }
            
            self.frobenius_powers.push(current);
        }
    }
    
    /// Get precomputed Frobenius power Z^{iq} mod φ(Z)
    pub fn frobenius_power(&self, i: usize) -> &ExtensionFieldElement<F> {
        &self.frobenius_powers[i]
    }
}

/// Extended Euclidean algorithm for polynomials over F_q
/// 
/// Returns (gcd, s) such that s·a ≡ gcd (mod b)
fn extended_gcd<F: Field>(a: &[F], b: &[F]) -> Result<(Vec<F>, Vec<F>)> {
    // Initialize
    let mut old_r = a.to_vec();
    let mut r = b.to_vec();
    let mut old_s = vec![F::one()];
    let mut s = vec![F::zero()];
    
    while !is_zero_poly(&r) {
        // Compute quotient and remainder
        let (q, rem) = poly_div(&old_r, &r)?;
        
        // Update r
        old_r = r;
        r = rem;
        
        // Update s
        let qs = poly_mul(&q, &s);
        let new_s = poly_sub(&old_s, &qs);
        old_s = s;
        s = new_s;
    }
    
    Ok((old_r, old_s))
}

/// Polynomial division over F_q
fn poly_div<F: Field>(a: &[F], b: &[F]) -> Result<(Vec<F>, Vec<F>)> {
    if is_zero_poly(b) {
        return Err(HachiError::InternalError("Division by zero polynomial".to_string()));
    }
    
    let mut remainder = a.to_vec();
    let mut quotient = Vec::new();
    
    let b_lead = b.last().unwrap();
    let b_lead_inv = b_lead.inv()
        .ok_or_else(|| HachiError::InternalError("Leading coefficient not invertible".to_string()))?;
    
    while remainder.len() >= b.len() && !is_zero_poly(&remainder) {
        let r_lead = remainder.last().unwrap();
        let q_coeff = r_lead.mul(&b_lead_inv);
        quotient.push(q_coeff);
        
        // Subtract q_coeff * b from remainder
        for (i, b_coeff) in b.iter().enumerate() {
            let idx = remainder.len() - b.len() + i;
            let term = q_coeff.mul(b_coeff);
            remainder[idx] = remainder[idx].sub(&term);
        }
        
        remainder.pop();
    }
    
    quotient.reverse();
    Ok((quotient, remainder))
}

/// Polynomial multiplication over F_q
fn poly_mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    if a.is_empty() || b.is_empty() {
        return vec![F::zero()];
    }
    
    let mut result = vec![F::zero(); a.len() + b.len() - 1];
    
    for (i, a_coeff) in a.iter().enumerate() {
        for (j, b_coeff) in b.iter().enumerate() {
            let term = a_coeff.mul(b_coeff);
            result[i + j] = result[i + j].add(&term);
        }
    }
    
    result
}

/// Polynomial subtraction over F_q
fn poly_sub<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let max_len = a.len().max(b.len());
    let mut result = vec![F::zero(); max_len];
    
    for (i, a_coeff) in a.iter().enumerate() {
        result[i] = result[i].add(a_coeff);
    }
    
    for (i, b_coeff) in b.iter().enumerate() {
        result[i] = result[i].sub(b_coeff);
    }
    
    result
}

/// Check if polynomial is zero
fn is_zero_poly<F: Field>(p: &[F]) -> bool {
    p.iter().all(|c| c.to_canonical_u64() == 0)
}
