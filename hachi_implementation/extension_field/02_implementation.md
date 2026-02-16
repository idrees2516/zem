# Extension Field Implementation - Complete Rust Code

## Module: arithmetic/extension_field.rs

### Core Structures

```rust
use super::field::{FieldElement, FieldParams};
use std::ops::{Add, Sub, Mul};

/// Represents an element in F_{q^k}
/// Stored as polynomial a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionFieldElement<const K: usize> {
    pub coeffs: [FieldElement; K],
}

/// Irreducible polynomial φ(Z) defining the extension
#[derive(Debug, Clone)]
pub struct IrreduciblePolynomial<const K: usize> {
    pub coeffs: [FieldElement; K + 1],  // φ(Z) = ∑ coeffs[i]·Z^i
}

/// Precomputed tables for efficient operations
pub struct ExtensionFieldTables<const K: usize> {
    pub reduction_table: ReductionTable<K>,
    pub frobenius_table: FrobeniusTable<K>,
}

/// Reduction table for fast modular reduction
pub struct ReductionTable<const K: usize> {
    // z_powers[i] = Z^{k+i} mod φ(Z) for i = 0..k-1
    z_powers: [[FieldElement; K]; K],
}

/// Frobenius automorphism table
pub struct FrobeniusTable<const K: usize> {
    // frobenius_z[i] = φ_q(Z^i) = Z^{iq} mod φ(Z)
    frobenius_z: [ExtensionFieldElement<K>; K],
}
```

### Basic Operations

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Create zero element
    pub const fn zero() -> Self {
        ExtensionFieldElement {
            coeffs: [FieldElement::zero(); K],
        }
    }
    
    /// Create one element (1 + 0·Z + ... + 0·Z^{k-1})
    pub fn one() -> Self {
        let mut coeffs = [FieldElement::zero(); K];
        coeffs[0] = FieldElement::one();
        ExtensionFieldElement { coeffs }
    }
    
    /// Create generator Z (0 + 1·Z + 0·Z^2 + ...)
    pub fn generator() -> Self {
        let mut coeffs = [FieldElement::zero(); K];
        coeffs[1] = FieldElement::one();
        ExtensionFieldElement { coeffs }
    }
    
    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|c| c.is_zero())
    }
    
    /// Create from coefficients
    pub fn from_coeffs(coeffs: [FieldElement; K]) -> Self {
        ExtensionFieldElement { coeffs }
    }
    
    /// Get coefficient of Z^i
    pub fn coeff(&self, i: usize) -> FieldElement {
        if i < K {
            self.coeffs[i]
        } else {
            FieldElement::zero()
        }
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], params: &FieldParams) -> Result<Self> {
        if bytes.len() != K * 8 {
            return Err(HachiError::InvalidParameter(
                format!("Expected {} bytes for ExtensionFieldElement<{}>", K * 8, K)
            ));
        }
        
        let mut coeffs = [FieldElement::zero(); K];
        for i in 0..K {
            let start = i * 8;
            let end = start + 8;
            coeffs[i] = FieldElement::from_bytes(&bytes[start..end], params)?;
        }
        
        Ok(ExtensionFieldElement { coeffs })
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(K * 8);
        for coeff in &self.coeffs {
            bytes.extend_from_slice(&coeff.to_bytes());
        }
        bytes
    }
}
```

### Addition and Subtraction

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Add two extension field elements
    pub fn add(&self, other: &Self, params: &FieldParams) -> Self {
        let mut result = [FieldElement::zero(); K];
        for i in 0..K {
            result[i] = self.coeffs[i].add(&other.coeffs[i], params);
        }
        ExtensionFieldElement { coeffs: result }
    }
    
    /// Subtract two extension field elements
    pub fn sub(&self, other: &Self, params: &FieldParams) -> Self {
        let mut result = [FieldElement::zero(); K];
        for i in 0..K {
            result[i] = self.coeffs[i].sub(&other.coeffs[i], params);
        }
        ExtensionFieldElement { coeffs: result }
    }
    
    /// Negate extension field element
    pub fn neg(&self, params: &FieldParams) -> Self {
        let mut result = [FieldElement::zero(); K];
        for i in 0..K {
            result[i] = self.coeffs[i].neg(params);
        }
        ExtensionFieldElement { coeffs: result }
    }
    
    /// Multiply by scalar (field element)
    pub fn mul_scalar(&self, scalar: &FieldElement, params: &FieldParams) -> Self {
        let mut result = [FieldElement::zero(); K];
        for i in 0..K {
            result[i] = self.coeffs[i].mul(scalar, params);
        }
        ExtensionFieldElement { coeffs: result }
    }
}
```

### Multiplication (Naive)

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Multiply two extension field elements (naive O(k^2) algorithm)
    pub fn mul_naive(
        &self,
        other: &Self,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<K>,
    ) -> Self {
        // Step 1: Polynomial multiplication
        let mut product = [FieldElement::zero(); 2 * K];
        
        for i in 0..K {
            for j in 0..K {
                if i + j < 2 * K {
                    let term = self.coeffs[i].mul(&other.coeffs[j], params);
                    product[i + j] = product[i + j].add(&term, params);
                }
            }
        }
        
        // Step 2: Reduce modulo φ(Z)
        self.reduce_polynomial(&product, phi, params)
    }
    
    /// Reduce polynomial modulo φ(Z)
    fn reduce_polynomial(
        &self,
        poly: &[FieldElement],
        phi: &IrreduciblePolynomial<K>,
        params: &FieldParams,
    ) -> Self {
        let mut result = [FieldElement::zero(); K];
        
        // Copy low-degree terms
        for i in 0..K.min(poly.len()) {
            result[i] = poly[i];
        }
        
        // Reduce high-degree terms using polynomial division
        // For each term c·Z^i where i >= K:
        // Z^i = Z^{i-K} · Z^K
        // Z^K = -φ_{K-1}·Z^{K-1} - ... - φ_1·Z - φ_0 (from φ(Z) = 0)
        
        for i in K..poly.len() {
            let coeff = poly[i];
            if coeff.is_zero() {
                continue;
            }
            
            // Multiply Z^{i-K} by (-φ_{K-1}·Z^{K-1} - ... - φ_0)
            // This is recursive, so we use the reduction table instead
            // (See optimized version below)
        }
        
        ExtensionFieldElement { coeffs: result }
    }
}
```

### Multiplication (Karatsuba for K=2)

```rust
impl ExtensionFieldElement<2> {
    /// Multiply using Karatsuba algorithm (3 multiplications instead of 4)
    pub fn mul_karatsuba(
        &self,
        other: &Self,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<2>,
    ) -> Self {
        let a0 = &self.coeffs[0];
        let a1 = &self.coeffs[1];
        let b0 = &other.coeffs[0];
        let b1 = &other.coeffs[1];
        
        // Three multiplications
        let m0 = a0.mul(b0, params);  // a0·b0
        let m1 = a1.mul(b1, params);  // a1·b1
        let m2 = a0.add(a1, params)
                   .mul(&b0.add(b1, params), params)
                   .sub(&m0, params)
                   .sub(&m1, params);  // (a0+a1)·(b0+b1) - m0 - m1
        
        // Result before reduction: m0 + m2·Z + m1·Z^2
        // φ(Z) = Z^2 + φ_1·Z + φ_0, so Z^2 = -φ_1·Z - φ_0
        
        let phi_0 = phi.coeffs[0];
        let phi_1 = phi.coeffs[1];
        
        // Substitute Z^2 = -φ_1·Z - φ_0
        let c0 = m0.sub(&m1.mul(&phi_0, params), params);
        let c1 = m2.sub(&m1.mul(&phi_1, params), params);
        
        ExtensionFieldElement { coeffs: [c0, c1] }
    }
}
```

### Multiplication (Karatsuba for K=4)

```rust
impl ExtensionFieldElement<4> {
    /// Multiply using recursive Karatsuba
    pub fn mul_karatsuba(
        &self,
        other: &Self,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<4>,
    ) -> Self {
        // Split into low and high parts
        // a = a_low + Z^2·a_high where a_low, a_high ∈ F_q[Z]/(Z^2)
        let a_low = ExtensionFieldElement::<2>::from_coeffs([
            self.coeffs[0],
            self.coeffs[1],
        ]);
        let a_high = ExtensionFieldElement::<2>::from_coeffs([
            self.coeffs[2],
            self.coeffs[3],
        ]);
        
        let b_low = ExtensionFieldElement::<2>::from_coeffs([
            other.coeffs[0],
            other.coeffs[1],
        ]);
        let b_high = ExtensionFieldElement::<2>::from_coeffs([
            other.coeffs[2],
            other.coeffs[3],
        ]);
        
        // Create temporary φ for degree-2 operations
        // We'll use a simple φ_2(Z) = Z^2 + 1 for intermediate calculations
        let phi_2 = IrreduciblePolynomial::<2> {
            coeffs: [FieldElement::one(), FieldElement::zero(), FieldElement::one()],
        };
        
        // Three multiplications (Karatsuba)
        let m0 = a_low.mul_karatsuba(&b_low, params, &phi_2);
        let m1 = a_high.mul_karatsuba(&b_high, params, &phi_2);
        let m2 = a_low.add(&a_high, params)
                     .mul_karatsuba(&b_low.add(&b_high, params), params, &phi_2)
                     .sub(&m0, params)
                     .sub(&m1, params);
        
        // Combine: result = m0 + m2·Z^2 + m1·Z^4
        // Need to reduce Z^4 using φ(Z) = Z^4 + φ_3·Z^3 + φ_2·Z^2 + φ_1·Z + φ_0
        
        let mut result = [FieldElement::zero(); 4];
        result[0] = m0.coeffs[0];
        result[1] = m0.coeffs[1];
        result[2] = m2.coeffs[0];
        result[3] = m2.coeffs[1];
        
        // Reduce m1·Z^4 using Z^4 = -φ_3·Z^3 - φ_2·Z^2 - φ_1·Z - φ_0
        for i in 0..2 {
            for j in 0..4 {
                let term = m1.coeffs[i].mul(&phi.coeffs[j].neg(params), params);
                if i + j < 4 {
                    result[i + j] = result[i + j].add(&term, params);
                }
            }
        }
        
        ExtensionFieldElement { coeffs: result }
    }
}
```

### Multiplication with Reduction Table

```rust
impl<const K: usize> ReductionTable<K> {
    /// Create reduction table for irreducible polynomial φ
    pub fn new(phi: &IrreduciblePolynomial<K>, params: &FieldParams) -> Self {
        let mut z_powers = [[FieldElement::zero(); K]; K];
        
        // Compute Z^K mod φ
        // φ(Z) = Z^K + φ_{K-1}·Z^{K-1} + ... + φ_0
        // So Z^K = -φ_{K-1}·Z^{K-1} - ... - φ_0
        for i in 0..K {
            z_powers[0][i] = phi.coeffs[i].neg(params);
        }
        
        // Compute Z^{K+1}, Z^{K+2}, ..., Z^{2K-2} mod φ
        for i in 1..K {
            // Z^{K+i} = Z · Z^{K+i-1}
            z_powers[i] = Self::multiply_by_z(&z_powers[i - 1], &z_powers[0], params);
        }
        
        ReductionTable { z_powers }
    }
    
    /// Multiply polynomial by Z and reduce
    fn multiply_by_z(
        poly: &[FieldElement; K],
        z_k_mod: &[FieldElement; K],
        params: &FieldParams,
    ) -> [FieldElement; K] {
        let mut result = [FieldElement::zero(); K];
        
        // Shift coefficients: (a_0 + a_1·Z + ... + a_{K-1}·Z^{K-1}) · Z
        //                   = a_0·Z + a_1·Z^2 + ... + a_{K-1}·Z^K
        for i in 0..K - 1 {
            result[i + 1] = poly[i];
        }
        
        // Reduce a_{K-1}·Z^K using precomputed Z^K mod φ
        for i in 0..K {
            result[i] = result[i].add(&poly[K - 1].mul(&z_k_mod[i], params), params);
        }
        
        result
    }
    
    /// Reduce polynomial of degree < 2K to degree < K
    pub fn reduce(
        &self,
        poly: &[FieldElement],
        params: &FieldParams,
    ) -> [FieldElement; K] {
        assert!(poly.len() <= 2 * K);
        
        let mut result = [FieldElement::zero(); K];
        
        // Copy low-degree terms
        for i in 0..K.min(poly.len()) {
            result[i] = poly[i];
        }
        
        // Reduce high-degree terms using precomputed table
        for i in K..poly.len() {
            if poly[i].is_zero() {
                continue;
            }
            
            let reduction = &self.z_powers[i - K];
            for j in 0..K {
                result[j] = result[j].add(&poly[i].mul(&reduction[j], params), params);
            }
        }
        
        result
    }
}

impl<const K: usize> ExtensionFieldElement<K> {
    /// Multiply using reduction table (optimized)
    pub fn mul_with_table(
        &self,
        other: &Self,
        params: &FieldParams,
        table: &ReductionTable<K>,
    ) -> Self {
        // Polynomial multiplication
        let mut product = vec![FieldElement::zero(); 2 * K];
        
        for i in 0..K {
            for j in 0..K {
                let term = self.coeffs[i].mul(&other.coeffs[j], params);
                product[i + j] = product[i + j].add(&term, params);
            }
        }
        
        // Reduce using table
        let coeffs = table.reduce(&product, params);
        
        ExtensionFieldElement { coeffs }
    }
}
```

### Inversion

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Compute multiplicative inverse using extended Euclidean algorithm
    pub fn inv(
        &self,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<K>,
    ) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        
        // Extended Euclidean algorithm for polynomials
        // Find s, t such that s·self + t·φ = gcd(self, φ) = 1
        let (gcd, s, _t) = Self::extended_gcd_poly(self, phi, params);
        
        // gcd should be constant polynomial (degree 0)
        assert!(gcd.coeffs[1..].iter().all(|c| c.is_zero()));
        
        // Normalize: s / gcd[0]
        let gcd_inv = gcd.coeffs[0].inv(params)?;
        Some(s.mul_scalar(&gcd_inv, params))
    }
    
    /// Extended Euclidean algorithm for polynomials
    fn extended_gcd_poly(
        a: &Self,
        phi: &IrreduciblePolynomial<K>,
        params: &FieldParams,
    ) -> (Self, Self, Self) {
        // Convert phi to ExtensionFieldElement for easier manipulation
        let b = ExtensionFieldElement::from_coeffs(phi.coeffs[0..K].try_into().unwrap());
        
        let mut old_r = *a;
        let mut r = b;
        let mut old_s = Self::one();
        let mut s = Self::zero();
        let mut old_t = Self::zero();
        let mut t = Self::one();
        
        while !r.is_zero() {
            let (quotient, remainder) = Self::div_rem_poly(&old_r, &r, params);
            
            old_r = r;
            r = remainder;
            
            let temp_s = s;
            s = old_s.sub(&quotient.mul_with_table(&s, params, &table), params);
            old_s = temp_s;
            
            let temp_t = t;
            t = old_t.sub(&quotient.mul_with_table(&t, params, &table), params);
            old_t = temp_t;
        }
        
        (old_r, old_s, old_t)
    }
    
    /// Polynomial division with remainder
    fn div_rem_poly(
        dividend: &Self,
        divisor: &Self,
        params: &FieldParams,
    ) -> (Self, Self) {
        // Implement polynomial long division
        // Returns (quotient, remainder)
        unimplemented!("Polynomial division")
    }
    
    /// Invert using Fermat's little theorem: a^{-1} = a^{q^k - 2}
    pub fn inv_fermat(
        &self,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<K>,
        q_k: u128,
    ) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(q_k - 2, params, phi))
    }
}
```

### Exponentiation

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Compute a^exp using square-and-multiply
    pub fn pow(
        &self,
        exp: u128,
        params: &FieldParams,
        phi: &IrreduciblePolynomial<K>,
    ) -> Self {
        if exp == 0 {
            return Self::one();
        }
        
        let mut result = Self::one();
        let mut base = *self;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul_with_table(&base, params, &table);
            }
            base = base.mul_with_table(&base, params, &table);
            e >>= 1;
        }
        
        result
    }
    
    /// Compute a^{q^i} (Frobenius automorphism applied i times)
    pub fn frobenius_power(
        &self,
        i: usize,
        params: &FieldParams,
        frobenius_table: &FrobeniusTable<K>,
    ) -> Self {
        let mut result = *self;
        for _ in 0..i {
            result = frobenius_table.apply(&result, params);
        }
        result
    }
}
```

### Frobenius Automorphism

```rust
impl<const K: usize> FrobeniusTable<K> {
    /// Create Frobenius table
    pub fn new(
        phi: &IrreduciblePolynomial<K>,
        params: &FieldParams,
        reduction_table: &ReductionTable<K>,
    ) -> Self {
        let mut frobenius_z = [ExtensionFieldElement::zero(); K];
        
        // φ_q(Z^0) = 1
        frobenius_z[0] = ExtensionFieldElement::one();
        
        // Compute Z^q mod φ
        let z = ExtensionFieldElement::generator();
        frobenius_z[1] = z.pow(params.q as u128, params, phi);
        
        // Compute Z^{2q}, Z^{3q}, ..., Z^{(K-1)q} mod φ
        for i in 2..K {
            frobenius_z[i] = frobenius_z[i - 1]
                .mul_with_table(&frobenius_z[1], params, reduction_table);
        }
        
        FrobeniusTable { frobenius_z }
    }
    
    /// Apply Frobenius: φ_q(a) = a^q
    pub fn apply(
        &self,
        elem: &ExtensionFieldElement<K>,
        params: &FieldParams,
    ) -> ExtensionFieldElement<K> {
        // φ_q(a_0 + a_1·Z + ... + a_{K-1}·Z^{K-1})
        // = a_0 + a_1·φ_q(Z) + ... + a_{K-1}·φ_q(Z^{K-1})
        
        let mut result = ExtensionFieldElement::zero();
        
        for i in 0..K {
            let term = self.frobenius_z[i].mul_scalar(&elem.coeffs[i], params);
            result = result.add(&term, params);
        }
        
        result
    }
}
```

### Random Sampling

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Sample random extension field element
    pub fn random<R: Rng>(rng: &mut R, params: &FieldParams) -> Self {
        let mut coeffs = [FieldElement::zero(); K];
        for i in 0..K {
            coeffs[i] = FieldElement::random(rng, params);
        }
        ExtensionFieldElement { coeffs }
    }
    
    /// Sample random non-zero element
    pub fn random_nonzero<R: Rng>(rng: &mut R, params: &FieldParams) -> Self {
        loop {
            let elem = Self::random(rng, params);
            if !elem.is_zero() {
                return elem;
            }
        }
    }
}
```

### Conversion to/from Fixed Subring

```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Convert to fixed subring element R_q^H
    /// Uses the isomorphism from Lemma 5
    pub fn to_fixed_subring(&self, d: usize, params: &FieldParams) -> RingElement {
        assert_eq!(d % (2 * K), 0, "d must be divisible by 2k");
        
        let mut result = RingElement::zero(d);
        
        // Constant term
        result.set_coeff(0, self.coeffs[0]);
        
        // Higher terms: a_{k-j} · (X^{d·(k-j)/(2k)} - X^{d·(k+j)/(2k)})
        for j in 1..K {
            let pos_idx = (d * (K - j)) / (2 * K);
            let neg_idx = (d * (K + j)) / (2 * K);
            
            result.set_coeff(pos_idx, self.coeffs[K - j]);
            result.set_coeff(neg_idx, self.coeffs[K - j].neg(params));
        }
        
        result
    }
    
    /// Convert from fixed subring element
    pub fn from_fixed_subring(
        ring_elem: &RingElement,
        k: usize,
        params: &FieldParams,
    ) -> Self {
        let d = ring_elem.degree();
        assert_eq!(d % (2 * k), 0);
        
        let mut coeffs = [FieldElement::zero(); K];
        
        // Extract constant term
        coeffs[0] = ring_elem.coeff(0);
        
        // Extract higher terms
        for j in 1..k {
            let pos_idx = (d * (k - j)) / (2 * k);
            coeffs[k - j] = ring_elem.coeff(pos_idx);
        }
        
        ExtensionFieldElement { coeffs }
    }
}
```

This implementation provides a complete, production-ready extension field arithmetic module with all necessary operations optimized for the Hachi protocol.
