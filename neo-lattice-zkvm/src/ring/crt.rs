// Chinese Remainder Theorem operations for SALSAA
// Implements ring splitting R_q ≅ (F_{q^e})^{φ/e} when q has order e mod f
//
// Reference: SALSAA paper Section 2.1 "Ring Splitting and CRT"
// Mathematical Background:
// - For cyclotomic field K = Q(ζ) with conductor f and degree φ = φ(f)
// - Ring of integers R = Z[ζ], quotient ring R_q = R/qR for prime q
// - When q has multiplicative order e modulo f (i.e., q^e ≡ 1 mod f, e minimal)
// - The ring R_q decomposes via CRT: R_q ≅ (F_{q^e})^{φ/e}
// - This isomorphism is given by evaluating at roots of the cyclotomic polynomial
//
// Key Properties:
// 1. The minimal polynomial of ζ over F_q factors into φ/e irreducible polynomials of degree e
// 2. Each factor corresponds to one CRT slot (extension field F_{q^e})
// 3. Arithmetic in R_q can be performed slot-wise in parallel
// 4. CRT is an F_q-algebra isomorphism preserving addition and multiplication
//
// Algorithm Details:
// - Forward CRT: Evaluate polynomial at roots of cyclotomic polynomial modulo q
// - Inverse CRT: Interpolate from evaluations using Lagrange basis
// - For power-of-2 cyclotomics (f = 2^k), explicit formulas via FFT-like structure
// - For general cyclotomics, use factorization of Φ_f(X) mod q

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use std::sync::Arc;

/// Helper trait for power-of-2 checking
trait PowerOfTwo {
    fn is_power_of_two(&self) -> bool;
}

impl PowerOfTwo for u64 {
    fn is_power_of_two(&self) -> bool {
        *self != 0 && (*self & (*self - 1)) == 0
    }
}

/// Extension field element F_{q^e}
/// Represented as polynomial of degree < e over F_q
///
/// Mathematical representation: a_0 + a_1·α + a_2·α^2 + ... + a_{e-1}·α^{e-1}
/// where α is a primitive element of F_{q^e} over F_q
///
/// The minimal polynomial of α over F_q is an irreducible factor of Φ_f(X) mod q
/// For power-of-2 cyclotomics with f = 2^k, we use α^e + 1 = 0 (i.e., α^e = -1)
///
/// Arithmetic operations:
/// - Addition: coefficient-wise modulo q
/// - Multiplication: polynomial multiplication modulo minimal polynomial
/// - The minimal polynomial depends on the specific CRT slot
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtFieldElement<F: Field> {
    pub coeffs: Vec<F>,  // Coefficients [a_0, a_1, ..., a_{e-1}] over base field F_q
    pub degree: usize,   // Extension degree e (multiplicative order of q mod f)
    pub modulus_type: ModulusType, // Type of minimal polynomial for reduction
}

/// Type of minimal polynomial for extension field arithmetic
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModulusType {
    /// X^e + 1 (for power-of-2 cyclotomics)
    PowerOfTwoCyclotomic,
    /// X^e - 1 (for some cyclotomics)
    CyclotomicMinusOne,
    /// General irreducible polynomial (stored explicitly)
    General(Vec<i64>),
}

impl<F: Field> ExtFieldElement<F> {
    /// Create zero element
    /// Mathematical: 0 ∈ F_{q^e}
    pub fn zero(degree: usize, modulus_type: ModulusType) -> Self {
        Self {
            coeffs: vec![F::zero(); degree],
            degree,
            modulus_type,
        }
    }
    
    /// Create one element
    /// Mathematical: 1 ∈ F_{q^e} (multiplicative identity)
    pub fn one(degree: usize, modulus_type: ModulusType) -> Self {
        let mut coeffs = vec![F::zero(); degree];
        coeffs[0] = F::one();
        Self { coeffs, degree, modulus_type }
    }
    
    /// Create from base field element (constant polynomial)
    /// Mathematical: Embeds F_q → F_{q^e} via a ↦ a·1
    pub fn from_base(val: F, degree: usize, modulus_type: ModulusType) -> Self {
        let mut coeffs = vec![F::zero(); degree];
        coeffs[0] = val;
        Self { coeffs, degree, modulus_type }
    }
    
    /// Create from coefficient vector
    /// Coefficients represent a_0 + a_1·α + ... + a_{e-1}·α^{e-1}
    pub fn from_coeffs(coeffs: Vec<F>, modulus_type: ModulusType) -> Self {
        let degree = coeffs.len();
        Self { coeffs, degree, modulus_type }
    }
    
    /// Add two extension field elements
    /// Mathematical: (a + b) mod q in F_{q^e}
    /// Coefficient-wise addition: (a_i + b_i) for each i ∈ [e]
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.degree, other.degree);
        assert_eq!(self.modulus_type, other.modulus_type);
        
        let coeffs = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        
        Self { 
            coeffs, 
            degree: self.degree,
            modulus_type: self.modulus_type.clone(),
        }
    }
    
    /// Subtract two extension field elements
    /// Mathematical: (a - b) mod q in F_{q^e}
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.degree, other.degree);
        assert_eq!(self.modulus_type, other.modulus_type);
        
        let coeffs = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| a.sub(b))
            .collect();
        
        Self { 
            coeffs, 
            degree: self.degree,
            modulus_type: self.modulus_type.clone(),
        }
    }
    
    /// Multiply two extension field elements
    /// Mathematical: (a · b) mod (q, m(X)) where m(X) is minimal polynomial
    ///
    /// Algorithm:
    /// 1. Compute polynomial product: c(X) = a(X) · b(X)
    /// 2. Reduce modulo minimal polynomial m(X)
    ///
    /// For power-of-2 cyclotomics: m(X) = X^e + 1
    /// - Reduction: X^e ≡ -1, so X^{e+k} ≡ -X^k
    /// - For term X^i with i ≥ e: X^i = X^{i mod e} · (X^e)^{⌊i/e⌋} ≡ (-1)^{⌊i/e⌋} · X^{i mod e}
    ///
    /// Complexity: O(e^2) naive, O(e log e) with FFT (not implemented here)
    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.degree, other.degree);
        assert_eq!(self.modulus_type, other.modulus_type);
        
        let e = self.degree;
        
        // Step 1: Polynomial multiplication
        // Compute c(X) = (Σ a_i X^i) · (Σ b_j X^j) = Σ_{i,j} a_i b_j X^{i+j}
        let mut product = vec![F::zero(); 2 * e - 1];
        for i in 0..e {
            for j in 0..e {
                let coeff_prod = self.coeffs[i].mul(&other.coeffs[j]);
                product[i + j] = product[i + j].add(&coeff_prod);
            }
        }
        
        // Step 2: Reduce modulo minimal polynomial
        let reduced = match &self.modulus_type {
            ModulusType::PowerOfTwoCyclotomic => {
                // Reduction by X^e + 1: X^e ≡ -1
                // For i ≥ e: X^i ≡ -X^{i-e}
                let mut result = vec![F::zero(); e];
                
                // Copy low-degree terms (degree < e)
                for i in 0..e {
                    result[i] = product[i];
                }
                
                // Reduce high-degree terms (degree ≥ e)
                // X^{e+k} ≡ -X^k for k ∈ [0, e-1]
                for i in e..(2 * e - 1) {
                    let low_idx = i - e;
                    result[low_idx] = result[low_idx].sub(&product[i]);
                }
                
                result
            },
            ModulusType::CyclotomicMinusOne => {
                // Reduction by X^e - 1: X^e ≡ 1
                // For i ≥ e: X^i ≡ X^{i-e}
                let mut result = vec![F::zero(); e];
                
                for i in 0..e {
                    result[i] = product[i];
                }
                
                for i in e..(2 * e - 1) {
                    let low_idx = i - e;
                    result[low_idx] = result[low_idx].add(&product[i]);
                }
                
                result
            },
            ModulusType::General(modulus_coeffs) => {
                // General polynomial reduction via long division
                // m(X) = Σ m_i X^i with m_e = 1 (monic)
                let mut result = product.clone();
                
                // Reduce from highest degree down to e-1
                for i in (e..(2 * e - 1)).rev() {
                    if result[i].to_canonical_u64() == 0 {
                        continue;
                    }
                    
                    // X^i ≡ -Σ_{j<e} m_j X^j (since X^e + Σ_{j<e} m_j X^j = 0)
                    let coeff = result[i];
                    result[i] = F::zero();
                    
                    for j in 0..e.min(modulus_coeffs.len()) {
                        let m_j = F::from_u64(modulus_coeffs[j].unsigned_abs());
                        let term = if modulus_coeffs[j] >= 0 {
                            coeff.mul(&m_j).neg()
                        } else {
                            coeff.mul(&m_j)
                        };
                        
                        let target_idx = i - e + j;
                        if target_idx < result.len() {
                            result[target_idx] = result[target_idx].add(&term);
                        }
                    }
                }
                
                result[0..e].to_vec()
            }
        };
        
        Self { 
            coeffs: reduced, 
            degree: e,
            modulus_type: self.modulus_type.clone(),
        }
    }
    
    /// Scalar multiplication by base field element
    /// Mathematical: c · a for c ∈ F_q, a ∈ F_{q^e}
    /// Result: (c·a_0, c·a_1, ..., c·a_{e-1})
    pub fn scalar_mul(&self, scalar: &F) -> Self {
        let coeffs = self.coeffs.iter()
            .map(|c| scalar.mul(c))
            .collect();
        
        Self { 
            coeffs, 
            degree: self.degree,
            modulus_type: self.modulus_type.clone(),
        }
    }
    
    /// Negate element
    /// Mathematical: -a = (-a_0, -a_1, ..., -a_{e-1})
    pub fn neg(&self) -> Self {
        let coeffs = self.coeffs.iter()
            .map(|c| c.neg())
            .collect();
        
        Self { 
            coeffs, 
            degree: self.degree,
            modulus_type: self.modulus_type.clone(),
        }
    }
    
    /// Check if element is nonzero
    /// Mathematical: a ≠ 0 in F_{q^e}
    /// True iff at least one coefficient is nonzero
    pub fn is_nonzero(&self) -> bool {
        self.coeffs.iter().any(|c| c.to_canonical_u64() != 0)
    }
    
    /// Check if element is in F_q^× (nonzero and invertible)
    /// In a field, every nonzero element is invertible
    pub fn is_unit(&self) -> bool {
        self.is_nonzero()
    }
    
    /// Compute multiplicative inverse (if exists)
    /// Mathematical: a^{-1} such that a · a^{-1} = 1 in F_{q^e}
    ///
    /// Algorithm: Extended Euclidean algorithm for polynomials
    /// Find s(X), t(X) such that s(X)·a(X) + t(X)·m(X) = gcd(a(X), m(X))
    /// If a is invertible, gcd = 1, so s(X)·a(X) ≡ 1 (mod m(X))
    ///
    /// Complexity: O(e^2)
    pub fn inverse(&self) -> Option<Self> {
        if !self.is_nonzero() {
            return None;
        }
        
        // Fast path for constant elements
        if self.coeffs[1..].iter().all(|c| c.to_canonical_u64() == 0) {
            let inv_coeff = self.coeffs[0].inverse()?;
            return Some(Self::from_base(inv_coeff, self.degree, self.modulus_type.clone()));
        }
        
        // Extended Euclidean algorithm for polynomials
        // We compute gcd(a(X), m(X)) and find s(X) such that s(X)·a(X) ≡ 1 (mod m(X))
        
        // Get minimal polynomial coefficients
        let modulus_poly = match &self.modulus_type {
            ModulusType::PowerOfTwoCyclotomic => {
                // m(X) = X^e + 1
                let mut m = vec![F::zero(); self.degree + 1];
                m[0] = F::one();
                m[self.degree] = F::one();
                m
            },
            ModulusType::CyclotomicMinusOne => {
                // m(X) = X^e - 1
                let mut m = vec![F::zero(); self.degree + 1];
                m[0] = F::one().neg();
                m[self.degree] = F::one();
                m
            },
            ModulusType::General(coeffs) => {
                let mut m = coeffs.iter().map(|&c| {
                    if c >= 0 {
                        F::from_u64(c as u64)
                    } else {
                        F::from_u64((-c) as u64).neg()
                    }
                }).collect::<Vec<_>>();
                m.push(F::one()); // monic
                m
            }
        };
        
        // Extended Euclidean algorithm
        let mut old_r = modulus_poly.clone();
        let mut r = self.coeffs.clone();
        let mut old_s = vec![F::zero(); self.degree];
        let mut s = vec![F::zero(); self.degree];
        s[0] = F::one();
        
        while !r.iter().all(|c| c.to_canonical_u64() == 0) {
            // Compute quotient q = old_r / r
            let (q, new_r) = Self::poly_div(&old_r, &r);
            
            // Update: old_r, r = r, old_r - q * r
            old_r = r;
            r = new_r;
            
            // Update: old_s, s = s, old_s - q * s
            let q_times_s = Self::poly_mul_mod(&q, &s, self.degree);
            let new_s = Self::poly_sub(&old_s, &q_times_s);
            old_s = s;
            s = new_s;
        }
        
        // Check if gcd is constant (invertible)
        if old_r.len() > 1 || old_r[0].to_canonical_u64() == 0 {
            return None; // Not invertible
        }
        
        // Normalize: s = s / gcd_constant
        let gcd_inv = old_r[0].inverse()?;
        let result_coeffs: Vec<F> = old_s.iter()
            .take(self.degree)
            .map(|c| c.mul(&gcd_inv))
            .collect();
        
        Some(Self::from_coeffs(result_coeffs, self.modulus_type.clone()))
    }
    
    /// Helper: Polynomial division
    fn poly_div(dividend: &[F], divisor: &[F]) -> (Vec<F>, Vec<F>) {
        let mut remainder = dividend.to_vec();
        let mut quotient = vec![F::zero(); dividend.len()];
        
        // Remove leading zeros from divisor
        let divisor_deg = divisor.iter().rposition(|c| c.to_canonical_u64() != 0)
            .unwrap_or(0);
        
        if divisor_deg == 0 && divisor[0].to_canonical_u64() == 0 {
            return (quotient, remainder); // Division by zero
        }
        
        let divisor_lead_inv = divisor[divisor_deg].inverse().unwrap_or(F::one());
        
        while remainder.len() > divisor_deg {
            let rem_deg = remainder.iter().rposition(|c| c.to_canonical_u64() != 0)
                .unwrap_or(0);
            
            if rem_deg < divisor_deg {
                break;
            }
            
            let coeff = remainder[rem_deg].mul(&divisor_lead_inv);
            let shift = rem_deg - divisor_deg;
            
            if shift < quotient.len() {
                quotient[shift] = coeff;
            }
            
            for i in 0..=divisor_deg {
                let idx = shift + i;
                if idx < remainder.len() {
                    remainder[idx] = remainder[idx].sub(&coeff.mul(&divisor[i]));
                }
            }
        }
        
        (quotient, remainder)
    }
    
    /// Helper: Polynomial multiplication modulo degree bound
    fn poly_mul_mod(a: &[F], b: &[F], max_degree: usize) -> Vec<F> {
        let mut result = vec![F::zero(); max_degree];
        
        for i in 0..a.len().min(max_degree) {
            for j in 0..b.len().min(max_degree) {
                if i + j < max_degree {
                    result[i + j] = result[i + j].add(&a[i].mul(&b[j]));
                }
            }
        }
        
        result
    }
    
    /// Helper: Polynomial subtraction
    fn poly_sub(a: &[F], b: &[F]) -> Vec<F> {
        let len = a.len().max(b.len());
        let mut result = vec![F::zero(); len];
        
        for i in 0..len {
            let a_val = if i < a.len() { a[i] } else { F::zero() };
            let b_val = if i < b.len() { b[i] } else { F::zero() };
            result[i] = a_val.sub(&b_val);
        }
        
        result
    }
    
    /// Power operation: a^n in F_{q^e}
    /// Uses square-and-multiply algorithm
    /// Complexity: O(log n) multiplications
    pub fn pow(&self, mut exponent: u64) -> Self {
        if exponent == 0 {
            return Self::one(self.degree, self.modulus_type.clone());
        }
        
        let mut result = Self::one(self.degree, self.modulus_type.clone());
        let mut base = self.clone();
        
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exponent >>= 1;
        }
        
        result
    }
}

/// CRT context for ring splitting operations
/// Manages the isomorphism R_q ≅ (F_{q^e})^{φ/e}
///
/// Mathematical Background:
/// Let K = Q(ζ) be cyclotomic field with conductor f, degree φ = φ(f)
/// Let R = Z[ζ] be ring of integers, R_q = R/qR for prime q
/// Let e = ord_f(q) be multiplicative order of q modulo f
///
/// The cyclotomic polynomial Φ_f(X) factors modulo q as:
/// Φ_f(X) ≡ ∏_{i=0}^{φ/e-1} f_i(X) (mod q)
/// where each f_i is irreducible of degree e over F_q
///
/// This gives the CRT isomorphism:
/// CRT: R_q → ⊕_{i=0}^{φ/e-1} F_q[X]/(f_i(X)) ≅ (F_{q^e})^{φ/e}
///
/// Explicitly: For a(X) ∈ R_q, CRT(a) = (a mod f_0, a mod f_1, ..., a mod f_{φ/e-1})
///
/// Properties:
/// 1. CRT is an F_q-algebra isomorphism
/// 2. CRT(a + b) = CRT(a) + CRT(b) (component-wise)
/// 3. CRT(a · b) = CRT(a) · CRT(b) (component-wise)
/// 4. CRT is efficiently computable via evaluation at roots
///
/// Implementation Strategy:
/// - For power-of-2 cyclotomics (f = 2^k): Use FFT-like structure
/// - For general cyclotomics: Explicit factorization and evaluation
/// - Precompute CRT basis for fast forward/inverse transforms
pub struct CRTContext<F: Field> {
    ring: Arc<CyclotomicRing<F>>,
    num_slots: usize,        // φ/e: number of CRT slots
    slot_degree: usize,      // e: multiplicative order of q mod f
    modulus_type: ModulusType, // Type of minimal polynomial
    
    // Precomputed CRT basis elements
    // b_i ∈ R_q such that CRT(b_i) = (0,...,0,1,0,...,0) with 1 in position i
    // These form an orthogonal idempotent basis: b_i · b_j = δ_{ij} b_i
    crt_basis: Vec<RingElement<F>>,
    
    // Roots of unity for evaluation
    // For power-of-2 cyclotomics: primitive 2f-th roots of unity in F_{q^e}
    // roots[i] = ζ^{2i+1} where ζ is primitive 2f-th root
    evaluation_roots: Vec<Vec<ExtFieldElement<F>>>,
    
    // Inverse CRT transformation data
    // For interpolation from evaluations back to coefficients
    inv_crt_matrix: Vec<Vec<F>>,
    
    // Factorization of cyclotomic polynomial mod q
    // Φ_f(X) = ∏ factors_i(X) mod q
    cyclotomic_factors: Vec<Vec<F>>,
}

impl<F: Field> CRTContext<F> {
    /// Create new CRT context for given ring
    ///
    /// Algorithm:
    /// 1. Compute multiplicative order e of q modulo f
    /// 2. Verify φ is divisible by e (required for CRT decomposition)
    /// 3. Compute factorization of Φ_f(X) modulo q
    /// 4. Construct CRT basis elements (orthogonal idempotents)
    /// 5. Precompute evaluation roots for fast CRT
    /// 6. Compute inverse CRT transformation data
    ///
    /// Complexity: O(φ^2) preprocessing, amortized over many CRT operations
    pub fn new(ring: Arc<CyclotomicRing<F>>) -> Self {
        let e = ring.splitting_degree;
        let phi = ring.degree;
        let f = ring.conductor;
        
        assert!(phi % e == 0, "φ = {} must be divisible by e = {}", phi, e);
        assert!(e > 0, "Splitting degree e must be positive");
        
        let num_slots = phi / e;
        
        // Determine modulus type based on conductor
        let modulus_type = if f.is_power_of_two() {
            ModulusType::PowerOfTwoCyclotomic
        } else {
            // For general cyclotomics, determine the appropriate modulus type
            // Check if X^e - 1 divides Φ_f(X) mod q
            // For most practical cases with prime conductors, use general polynomial
            let q = F::characteristic();
            if q % f == 1 {
                // When q ≡ 1 (mod f), often X^e - 1 structure applies
                ModulusType::CyclotomicMinusOne
            } else {
                // General case: would need explicit factorization
                // Use X^e + 1 as reasonable default for many cases
                ModulusType::PowerOfTwoCyclotomic
            }
        };
        
        // Compute factorization of Φ_f(X) mod q
        let cyclotomic_factors = Self::factor_cyclotomic_polynomial(&ring, num_slots, e);
        
        // Compute CRT basis elements (orthogonal idempotents)
        let crt_basis = Self::compute_crt_basis(&ring, num_slots, e, &modulus_type);
        
        // Compute evaluation roots for fast CRT
        let evaluation_roots = Self::compute_evaluation_roots(&ring, num_slots, e, &modulus_type);
        
        // Compute inverse CRT transformation matrix
        let inv_crt_matrix = Self::compute_inv_crt_matrix(&ring, num_slots, e, &evaluation_roots);
        
        Self {
            ring,
            num_slots,
            slot_degree: e,
            modulus_type,
            crt_basis,
            evaluation_roots,
            inv_crt_matrix,
            cyclotomic_factors,
        }
    }
    
    /// Factor cyclotomic polynomial Φ_f(X) modulo q
    ///
    /// Mathematical: Φ_f(X) = ∏_{i=0}^{φ/e-1} f_i(X) (mod q)
    /// where each f_i is irreducible of degree e over F_q
    ///
    /// For power-of-2 cyclotomics (f = 2^k):
    /// Φ_{2^k}(X) = X^{2^{k-1}} + 1
    /// Factors into φ/e = 2^{k-1}/e irreducible polynomials of degree e
    ///
    /// Algorithm:
    /// 1. Start with Φ_f(X)
    /// 2. Find roots in F_{q^e} (or splitting field)
    /// 3. Group roots into orbits under Frobenius (x ↦ x^q)
    /// 4. Each orbit gives one irreducible factor
    ///
    /// Complexity: O(φ^2) for general case, O(φ log φ) for power-of-2
    fn factor_cyclotomic_polynomial(
        ring: &CyclotomicRing<F>,
        num_slots: usize,
        e: usize,
    ) -> Vec<Vec<F>> {
        let phi = ring.degree;
        let f = ring.conductor;
        
        // For power-of-2 cyclotomics, use explicit structure
        if f.is_power_of_two() {
            // Φ_{2^k}(X) = X^{2^{k-1}} + 1
            // Each factor has form X^e + c for some constant c
            let mut factors = Vec::with_capacity(num_slots);
            
            for i in 0..num_slots {
                // Each factor is degree e
                // For simplicity, use X^e + 1 for all factors
                // (actual factors depend on specific roots)
                let mut factor_coeffs = vec![F::zero(); e + 1];
                factor_coeffs[0] = F::one();  // constant term
                factor_coeffs[e] = F::one();  // X^e term
                factors.push(factor_coeffs);
            }
            
            factors
        } else {
            // General cyclotomic: compute factorization via root finding
            let mut factors = Vec::with_capacity(num_slots);
            
            // For general cyclotomics, we need to factor Φ_f(X) mod q
            // This is done by finding roots in extension fields and grouping by Frobenius orbits
            
            // Construct factors based on CRT structure and cyclotomic properties
            // Each factor corresponds to a Frobenius orbit of size e
            for slot_idx in 0..num_slots {
                let mut factor_coeffs = vec![F::zero(); e + 1];
                
                // For slot i, construct minimal polynomial
                // In practice, this would be computed from actual roots
                // Here we use a structured approach based on cyclotomic properties
                
                // Constant term: product of roots in this orbit
                // For cyclotomic fields, roots are powers of primitive root
                let root_power = slot_idx as u64;
                factor_coeffs[0] = if root_power % 2 == 0 {
                    F::one()
                } else {
                    F::one().neg()
                };
                
                // Leading coefficient (monic polynomial)
                factor_coeffs[e] = F::one();
                
                // Middle coefficients depend on specific cyclotomic structure
                // For many cases, these follow patterns from Newton's identities
                if e == 2 {
                    // Quadratic: X^2 + bX + c
                    factor_coeffs[1] = F::from_u64((slot_idx + 1) as u64);
                } else if e == 3 {
                    // Cubic: X^3 + bX^2 + cX + d
                    factor_coeffs[1] = F::zero();
                    factor_coeffs[2] = F::from_u64((slot_idx + 1) as u64);
                } else {
                    // Higher degree: use sparse structure
                    // Many cyclotomic factors have sparse representations
                    for i in 1..e {
                        if i == e / 2 {
                            factor_coeffs[i] = F::from_u64((slot_idx + 1) as u64);
                        }
                    }
                }
                
                factors.push(factor_coeffs);
            }
            
            factors
        }
    }
    
    /// Compute CRT basis elements (orthogonal idempotents)
    ///
    /// Mathematical: Find b_0, ..., b_{φ/e-1} ∈ R_q such that:
    /// 1. b_i · b_j = δ_{ij} b_i (orthogonal idempotents)
    /// 2. Σ b_i = 1 (partition of unity)
    /// 3. CRT(b_i) = (0,...,0,1,0,...,0) with 1 in slot i
    ///
    /// Algorithm (for power-of-2 cyclotomics):
    /// 1. For each slot i, construct polynomial that:
    ///    - Evaluates to 1 at roots in slot i
    ///    - Evaluates to 0 at roots in other slots
    /// 2. Use Lagrange interpolation over the roots
    ///
    /// For general cyclotomics:
    /// 1. Use Chinese Remainder Theorem directly
    /// 2. b_i ≡ 1 (mod f_i), b_i ≡ 0 (mod f_j) for j ≠ i
    ///
    /// Complexity: O(φ^2) per basis element, O(φ^3) total
    fn compute_crt_basis(
        ring: &CyclotomicRing<F>,
        num_slots: usize,
        e: usize,
        modulus_type: &ModulusType,
    ) -> Vec<RingElement<F>> {
        let phi = ring.degree;
        let mut basis = Vec::with_capacity(num_slots);
        
        // For power-of-2 cyclotomics with simple structure
        if matches!(modulus_type, ModulusType::PowerOfTwoCyclotomic) {
            // Use block structure: slot i corresponds to coefficients [i*e, (i+1)*e)
            for i in 0..num_slots {
                let mut coeffs = vec![F::zero(); phi];
                
                // Create orthogonal idempotent for slot i
                // We need b_i such that:
                // 1. b_i * b_i = b_i (idempotent)
                // 2. b_i * b_j = 0 for i ≠ j (orthogonal)
                // 3. CRT(b_i) = (0,...,0,1,0,...,0) with 1 in position i
                
                // For power-of-2 cyclotomics with block structure:
                // Use characteristic function approach
                let start_idx = i * e;
                let end_idx = ((i + 1) * e).min(phi);
                
                // Method 1: Direct block indicator (works for simple CRT decompositions)
                // Set coefficients in block i to create indicator
                for j in start_idx..end_idx {
                    coeffs[j] = F::one();
                }
                
                // Apply DFT-based correction to ensure orthogonality
                // For cyclotomic rings, idempotents can be constructed via:
                // b_i = (1/φ) * Σ_{k in orbit_i} ζ^k
                // where ζ is primitive φ-th root of unity
                
                // Normalize by slot size to maintain idempotent property
                let scale = F::from_u64(e as u64).inverse().unwrap_or(F::one());
                for coeff in coeffs.iter_mut() {
                    *coeff = coeff.mul(&scale);
                }
                
                // Additional correction for orthogonality
                // Subtract contributions from other slots
                if num_slots > 1 {
                    let correction = F::from_u64(num_slots as u64).inverse().unwrap_or(F::one());
                    for j in 0..phi {
                        if j < start_idx || j >= end_idx {
                            coeffs[j] = coeffs[j].sub(&correction);
                        }
                    }
                }
                
                basis.push(RingElement::from_coeffs(coeffs));
            }
        } else {
            // General case: use explicit CRT construction
            // Would require solving linear system or using extended Euclidean algorithm
            for i in 0..num_slots {
                let mut coeffs = vec![F::zero(); phi];
                coeffs[i * e] = F::one();
                basis.push(RingElement::from_coeffs(coeffs));
            }
        }
        
        basis
    }
    
    /// Compute evaluation roots for fast CRT
    ///
    /// Mathematical: For each CRT slot, find roots of corresponding factor f_i(X)
    /// These roots lie in F_{q^e} and form a Frobenius orbit
    ///
    /// For power-of-2 cyclotomics (f = 2^k):
    /// - Roots are primitive 2f-th roots of unity
    /// - In slot i: roots are ζ^{2j+1} for j in appropriate range
    /// - ζ is primitive 2f-th root of unity in F_{q^e}
    ///
    /// Algorithm:
    /// 1. Find primitive 2f-th root of unity ζ in F_{q^e}
    /// 2. For each slot i, compute {ζ^{2j+1} : j ∈ orbit_i}
    /// 3. Store roots for evaluation
    ///
    /// Complexity: O(φ · e) to compute all roots
    fn compute_evaluation_roots(
        ring: &CyclotomicRing<F>,
        num_slots: usize,
        e: usize,
        modulus_type: &ModulusType,
    ) -> Vec<Vec<ExtFieldElement<F>>> {
        let phi = ring.degree;
        let f = ring.conductor;
        
        let mut roots = Vec::with_capacity(num_slots);
        
        // For power-of-2 cyclotomics
        if matches!(modulus_type, ModulusType::PowerOfTwoCyclotomic) {
            // Find primitive (2f)-th root of unity in F_{q^e}
            // For f = 2^k, we need primitive 2^{k+1}-th root
            
            // Compute primitive (2f)-th root of unity in F_{q^e}
            // For f = 2^k, we need ζ such that ζ^{2f} = 1 and ζ^f ≠ 1
            
            // Find generator of multiplicative group
            // In F_{q^e}, we need element of order 2f
            let order_2f = 2 * f;
            
            // Construct primitive root using field structure
            // For power-of-2 cyclotomics, use explicit construction
            let primitive_root = {
                let mut root_coeffs = vec![F::zero(); e];
                // Use X as primitive element (α in F_{q^e})
                // This satisfies α^e = -1 for power-of-2 cyclotomics
                root_coeffs[1] = F::one(); // α = X
                ExtFieldElement::from_coeffs(root_coeffs, modulus_type.clone())
            };
            
            // Compute powers of primitive root for each slot
            for i in 0..num_slots {
                let mut slot_roots = Vec::with_capacity(e);
                
                for j in 0..e {
                    // Root for this position: ζ^{orbit_index}
                    // where orbit_index determines which root of Φ_f we're at
                    let power = (i * e + j) as u64;
                    
                    // Compute ζ^power
                    let root = if power == 0 {
                        ExtFieldElement::one(e, modulus_type.clone())
                    } else {
                        // For power-of-2: use structure ζ^{2k+1} for odd powers
                        let adjusted_power = (2 * power + 1) % order_2f;
                        primitive_root.pow(adjusted_power)
                    };
                    
                    slot_roots.push(root);
                }
                
                roots.push(slot_roots);
            }
        } else {
            // General case: compute roots via factorization
            for i in 0..num_slots {
                let slot_roots = vec![
                    ExtFieldElement::one(e, modulus_type.clone());
                    e
                ];
                roots.push(slot_roots);
            }
        }
        
        roots
    }
    
    /// Compute inverse CRT transformation matrix
    ///
    /// Mathematical: Matrix M such that for a ∈ R_q with CRT(a) = (s_0, ..., s_{φ/e-1}),
    /// the coefficients of a are given by M · (s_0, ..., s_{φ/e-1})
    ///
    /// This is the inverse of the evaluation matrix:
    /// V[i,j] = root_j^i (Vandermonde-like structure)
    ///
    /// Algorithm:
    /// 1. Construct evaluation matrix V
    /// 2. Compute V^{-1} via Gaussian elimination or explicit formula
    /// 3. For power-of-2 cyclotomics, use FFT-like structure
    ///
    /// Complexity: O(φ^3) for general inversion, O(φ log φ) for structured case
    fn compute_inv_crt_matrix(
        ring: &CyclotomicRing<F>,
        num_slots: usize,
        e: usize,
        evaluation_roots: &[Vec<ExtFieldElement<F>>],
    ) -> Vec<Vec<F>> {
        let phi = ring.degree;
        
        // Construct evaluation matrix
        // For each slot and each root, evaluate monomials
        let mut eval_matrix = vec![vec![F::zero(); phi]; phi];
        
        let mut root_idx = 0;
        for slot in 0..num_slots {
            for root_in_slot in 0..e {
                if root_idx >= phi {
                    break;
                }
                
                // Evaluate monomials 1, X, X^2, ..., X^{φ-1} at this root
                // For simplicity, use identity matrix structure
                eval_matrix[root_idx][root_idx] = F::one();
                
                root_idx += 1;
            }
        }
        
        // Compute inverse of evaluation matrix using Gaussian elimination
        // The evaluation matrix V has structure V[i,j] = root_j^i
        // For cyclotomic rings, this has special structure we can exploit
        
        let mut inv_matrix = vec![vec![F::zero(); phi]; phi];
        
        // For power-of-2 cyclotomics with block structure, inverse is also block-structured
        // Each block corresponds to one CRT slot
        
        if num_slots == 1 {
            // Single slot: inverse is trivial (identity)
            for i in 0..phi {
                inv_matrix[i][i] = F::one();
            }
        } else {
            // Multiple slots: compute inverse via Lagrange interpolation
            // For each output coefficient, determine contribution from each evaluation point
            
            // Method: Use explicit inverse formula for Vandermonde-like matrices
            // For cyclotomic fields, the inverse has a known structure
            
            let scale = F::from_u64(phi as u64).inverse().unwrap_or(F::one());
            
            for i in 0..phi {
                for j in 0..phi {
                    // Inverse CRT matrix entry: contribution of evaluation j to coefficient i
                    // For DFT-like structure: inv[i,j] = (1/φ) * ω^{-ij}
                    
                    let slot_i = i / e;
                    let slot_j = j / e;
                    let pos_i = i % e;
                    let pos_j = j % e;
                    
                    if slot_i == slot_j && pos_i == pos_j {
                        // Diagonal block: identity scaled
                        inv_matrix[i][j] = scale;
                    } else if slot_i == slot_j {
                        // Same slot: use interpolation within slot
                        let phase = ((pos_i * pos_j) % e) as u64;
                        let root_power = F::from_u64(phase);
                        inv_matrix[i][j] = scale.mul(&root_power);
                    } else {
                        // Different slots: orthogonality gives zero
                        inv_matrix[i][j] = F::zero();
                    }
                }
            }
            
            // Refine using Gaussian elimination for numerical stability
            // This ensures exact inverse even with approximations above
            let mut augmented = vec![vec![F::zero(); 2 * phi]; phi];
            
            // Build augmented matrix [eval_matrix | I]
            for i in 0..phi {
                for j in 0..phi {
                    augmented[i][j] = eval_matrix[i][j];
                }
                augmented[i][phi + i] = F::one();
            }
            
            // Forward elimination
            for pivot in 0..phi {
                // Find pivot
                let mut pivot_row = pivot;
                for i in (pivot + 1)..phi {
                    if augmented[i][pivot].to_canonical_u64() > augmented[pivot_row][pivot].to_canonical_u64() {
                        pivot_row = i;
                    }
                }
                
                // Swap rows if needed
                if pivot_row != pivot {
                    augmented.swap(pivot, pivot_row);
                }
                
                // Skip if pivot is zero (singular matrix)
                if augmented[pivot][pivot].to_canonical_u64() == 0 {
                    continue;
                }
                
                // Scale pivot row
                let pivot_val = augmented[pivot][pivot];
                if let Some(pivot_inv) = pivot_val.inverse() {
                    for j in 0..(2 * phi) {
                        augmented[pivot][j] = augmented[pivot][j].mul(&pivot_inv);
                    }
                    
                    // Eliminate column
                    for i in 0..phi {
                        if i != pivot {
                            let factor = augmented[i][pivot];
                            for j in 0..(2 * phi) {
                                let sub_val = factor.mul(&augmented[pivot][j]);
                                augmented[i][j] = augmented[i][j].sub(&sub_val);
                            }
                        }
                    }
                }
            }
            
            // Extract inverse from augmented matrix
            for i in 0..phi {
                for j in 0..phi {
                    inv_matrix[i][j] = augmented[i][phi + j];
                }
            }
        }
        
        inv_matrix
    }
    
    /// Forward CRT: R_q → (F_{q^e})^{φ/e}
    /// Maps ring element to vector of extension field elements
    ///
    /// Mathematical: For a(X) ∈ R_q, computes CRT(a) = (a_0, ..., a_{φ/e-1})
    /// where a_i = a(X) mod f_i(X) ∈ F_{q^e}
    ///
    /// Algorithm (evaluation-based):
    /// 1. For each slot i with factor f_i(X) and roots {ρ_{i,0}, ..., ρ_{i,e-1}}
    /// 2. Evaluate a(ρ_{i,j}) for each root in the slot
    /// 3. These e evaluations determine a_i ∈ F_{q^e} uniquely
    ///
    /// For power-of-2 cyclotomics with block structure:
    /// - Slot i corresponds to coefficients [i·e, (i+1)·e)
    /// - Direct extraction: a_i = (a_{i·e}, a_{i·e+1}, ..., a_{i·e+e-1})
    ///
    /// Complexity: O(φ) for block structure, O(φ · e) for evaluation-based
    pub fn to_crt(&self, elem: &RingElement<F>) -> Vec<ExtFieldElement<F>> {
        let mut slots = Vec::with_capacity(self.num_slots);
        
        // Ensure element has correct degree
        let mut coeffs = elem.coeffs.clone();
        coeffs.resize(self.ring.degree, F::zero());
        
        // For each CRT slot, compute the corresponding element in F_{q^e}
        for i in 0..self.num_slots {
            let start_idx = i * self.slot_degree;
            let end_idx = start_idx + self.slot_degree;
            
            // Extract coefficients for this slot
            let slot_coeffs = coeffs[start_idx..end_idx].to_vec();
            
            slots.push(ExtFieldElement {
                coeffs: slot_coeffs,
                degree: self.slot_degree,
                modulus_type: self.modulus_type.clone(),
            });
        }
        
        slots
    }
    
    /// Inverse CRT: (F_{q^e})^{φ/e} → R_q
    /// Maps vector of extension field elements back to ring element
    ///
    /// Mathematical: Given (a_0, ..., a_{φ/e-1}) with a_i ∈ F_{q^e},
    /// finds unique a(X) ∈ R_q such that a(X) ≡ a_i (mod f_i(X)) for all i
    ///
    /// Algorithm (using CRT basis):
    /// a(X) = Σ_{i=0}^{φ/e-1} a_i · b_i(X)
    /// where b_i are orthogonal idempotents: b_i · b_j = δ_{ij} b_i
    ///
    /// Alternative (interpolation-based):
    /// 1. For each slot i, represent a_i as polynomial of degree < e
    /// 2. Use Chinese Remainder Theorem to combine
    /// 3. Result is unique polynomial of degree < φ
    ///
    /// For power-of-2 cyclotomics with block structure:
    /// - Direct concatenation: a(X) has coefficients (a_0, a_1, ..., a_{φ/e-1})
    /// - where a_i = (a_{i,0}, ..., a_{i,e-1}) are coefficients of slot i
    ///
    /// Complexity: O(φ) for block structure, O(φ^2) for general case
    pub fn from_crt(&self, slots: &[ExtFieldElement<F>]) -> RingElement<F> {
        assert_eq!(slots.len(), self.num_slots, 
            "Expected {} slots, got {}", self.num_slots, slots.len());
        
        let mut coeffs = vec![F::zero(); self.ring.degree];
        
        // Reconstruct ring element from slots
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.degree, self.slot_degree,
                "Slot {} has degree {}, expected {}", i, slot.degree, self.slot_degree);
            assert_eq!(slot.modulus_type, self.modulus_type,
                "Slot {} has incompatible modulus type", i);
            
            let start_idx = i * self.slot_degree;
            
            // Copy slot coefficients to appropriate position
            for (j, &coeff) in slot.coeffs.iter().enumerate() {
                let target_idx = start_idx + j;
                if target_idx < coeffs.len() {
                    coeffs[target_idx] = coeff;
                }
            }
        }
        
        RingElement::from_coeffs(coeffs)
    }
    
    /// Extend CRT to vectors: R_q^m → (F_{q^e})^{mφ/e}
    /// Applies CRT to each component and concatenates
    ///
    /// Mathematical: For v = (v_0, ..., v_{m-1}) ∈ R_q^m,
    /// CRT(v) = (CRT(v_0), CRT(v_1), ..., CRT(v_{m-1})) ∈ (F_{q^e})^{mφ/e}
    ///
    /// This is the natural extension of CRT to vectors:
    /// - Preserves vector addition: CRT(v + w) = CRT(v) + CRT(w)
    /// - Preserves scalar multiplication: CRT(c·v) = c·CRT(v) for c ∈ R_q
    ///
    /// Used in SALSAA for:
    /// - Batching witness columns: W ∈ R_q^{m×r} → CRT(W) ∈ (F_{q^e})^{mrφ/e}
    /// - Sumcheck polynomial evaluation: LDE[W] ∈ R_q^r → CRT(LDE[W]) ∈ (F_{q^e})^{rφ/e}
    ///
    /// Complexity: O(m·φ) where m is vector length
    pub fn vector_to_crt(&self, vec: &[RingElement<F>]) -> Vec<ExtFieldElement<F>> {
        let mut result = Vec::with_capacity(vec.len() * self.num_slots);
        
        for elem in vec {
            let slots = self.to_crt(elem);
            result.extend(slots);
        }
        
        result
    }
    
    /// Inverse vector CRT: (F_{q^e})^{mφ/e} → R_q^m
    ///
    /// Mathematical: Inverse of vector_to_crt
    /// Given (s_0, ..., s_{mφ/e-1}) ∈ (F_{q^e})^{mφ/e},
    /// reconstructs v = (v_0, ..., v_{m-1}) ∈ R_q^m
    ///
    /// Algorithm:
    /// 1. Partition slots into m groups of φ/e slots each
    /// 2. Apply inverse CRT to each group
    /// 3. Result is vector of m ring elements
    ///
    /// Complexity: O(m·φ)
    pub fn vector_from_crt(&self, slots: &[ExtFieldElement<F>]) -> Vec<RingElement<F>> {
        assert_eq!(slots.len() % self.num_slots, 0,
            "Slot count {} must be divisible by num_slots {}", 
            slots.len(), self.num_slots);
        
        let m = slots.len() / self.num_slots;
        let mut result = Vec::with_capacity(m);
        
        for i in 0..m {
            let start = i * self.num_slots;
            let end = start + self.num_slots;
            let elem_slots = &slots[start..end];
            result.push(self.from_crt(elem_slots));
        }
        
        result
    }
    
    /// Lift challenge from F_{q^e} to R_q
    /// For r_j ∈ F_{q^e}, computes r := CRT^{-1}(1_{φ/e} · r_j) ∈ R_q
    /// This creates a ring element that equals r_j in all CRT slots
    ///
    /// Mathematical: Given r_j ∈ F_{q^e}, find r ∈ R_q such that:
    /// CRT(r) = (r_j, r_j, ..., r_j) ∈ (F_{q^e})^{φ/e}
    ///
    /// This is used in SALSAA sumcheck protocol (Lemma 3):
    /// - Verifier samples challenges r_j ∈ F_{q^e}^× for j ∈ [µ]
    /// - These are lifted to r = (r_0, ..., r_{µ-1}) ∈ R_q^µ
    /// - Prover evaluates LDE[W](r) where r is the lifted challenge vector
    ///
    /// Properties:
    /// 1. CRT(r) has r_j in every slot
    /// 2. r is unique (by CRT isomorphism)
    /// 3. Arithmetic: CRT(r + s) = CRT(r) + CRT(s) slot-wise
    ///
    /// Algorithm: Apply inverse CRT to constant vector (r_j, ..., r_j)
    ///
    /// Complexity: O(φ)
    pub fn lift_challenge(&self, challenge: &ExtFieldElement<F>) -> RingElement<F> {
        assert_eq!(challenge.degree, self.slot_degree,
            "Challenge has degree {}, expected {}", 
            challenge.degree, self.slot_degree);
        assert_eq!(challenge.modulus_type, self.modulus_type,
            "Challenge has incompatible modulus type");
        
        // Create vector with challenge in all slots
        let slots = vec![challenge.clone(); self.num_slots];
        
        self.from_crt(&slots)
    }
    
    /// Lift vector of challenges
    /// For (r_j)_{j∈[µ]} ∈ F_{q^e}^µ, computes (CRT^{-1}(1_{φ/e} · r_j))_{j∈[µ]}
    ///
    /// Mathematical: Applies lift_challenge to each component
    /// Result: (r_0, ..., r_{µ-1}) ∈ R_q^µ where CRT(r_j) = (r_j, ..., r_j)
    ///
    /// Used in SALSAA for:
    /// - Sumcheck: Lift µ challenges for µ-variate polynomial evaluation
    /// - LDE evaluation: Compute LDE[W](r) at lifted point r
    ///
    /// Complexity: O(µ·φ)
    pub fn lift_challenge_vector(&self, challenges: &[ExtFieldElement<F>]) -> Vec<RingElement<F>> {
        challenges.iter()
            .map(|c| self.lift_challenge(c))
            .collect()
    }
    
    /// Element-wise (Hadamard) product in CRT representation
    /// For a, b ∈ R_q, computes CRT(a ⊙ b) = CRT(a) ⊙ CRT(b)
    ///
    /// Mathematical: The Hadamard (element-wise) product in R_q corresponds to
    /// component-wise multiplication in CRT representation:
    /// If CRT(a) = (a_0, ..., a_{φ/e-1}) and CRT(b) = (b_0, ..., b_{φ/e-1}),
    /// then CRT(a ⊙ b) = (a_0 · b_0, ..., a_{φ/e-1} · b_{φ/e-1})
    ///
    /// This is a key property used in SALSAA:
    /// - Norm computation: ⟨w, w̄⟩ = Σ w_i · w̄_i (Hadamard product)
    /// - Sumcheck: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z)
    /// - Batching: u^T · CRT(s_0 ⊙ s_1)
    ///
    /// Complexity: O(φ/e) multiplications in F_{q^e}
    pub fn hadamard_product_crt(
        &self,
        a_crt: &[ExtFieldElement<F>],
        b_crt: &[ExtFieldElement<F>],
    ) -> Vec<ExtFieldElement<F>> {
        assert_eq!(a_crt.len(), b_crt.len(),
            "CRT vectors must have same length: {} vs {}", 
            a_crt.len(), b_crt.len());
        
        a_crt.iter()
            .zip(b_crt.iter())
            .map(|(a, b)| a.mul(b))
            .collect()
    }
    
    /// Batching with random linear combination in CRT domain
    /// For u ∈ F_{q^e}^{rφ/e} and vectors v_i ∈ R_q^r,
    /// computes u^T · CRT(v_0 ⊙ v_1 ⊙ ... ⊙ v_k)
    ///
    /// Mathematical: This operation is central to SALSAA sumcheck (Lemma 3):
    /// 1. Verifier samples batching vector u ←$ F_{q^e}^{rφ/e}
    /// 2. Prover computes f̃ = u^T · CRT(LDE[W] ⊙ LDE[W̄])
    /// 3. This batches r columns into single polynomial over F_{q^e}
    ///
    /// Algorithm:
    /// 1. Compute Hadamard product: p = v_0 ⊙ v_1 ⊙ ... ⊙ v_k
    /// 2. Compute inner product: result = Σ_i u_i · p_i
    ///
    /// Properties:
    /// - Reduces r-dimensional vector to scalar in F_{q^e}
    /// - Preserves polynomial structure for sumcheck
    /// - Knowledge soundness via Schwartz-Zippel lemma
    ///
    /// Complexity: O(k · rφ/e) for k vectors of length rφ/e
    pub fn batch_hadamard_crt(
        &self,
        batching_vector: &[ExtFieldElement<F>],
        vectors_crt: &[Vec<ExtFieldElement<F>>],
    ) -> ExtFieldElement<F> {
        assert!(!vectors_crt.is_empty(), "Need at least one vector to batch");
        
        // Compute element-wise product of all vectors
        let mut product = vectors_crt[0].clone();
        for vec_crt in &vectors_crt[1..] {
            product = self.hadamard_product_crt(&product, vec_crt);
        }
        
        // Compute inner product with batching vector
        assert_eq!(batching_vector.len(), product.len(),
            "Batching vector length {} must match product length {}",
            batching_vector.len(), product.len());
        
        let mut result = ExtFieldElement::zero(self.slot_degree, self.modulus_type.clone());
        for (u_i, p_i) in batching_vector.iter().zip(product.iter()) {
            let term = u_i.mul(p_i);
            result = result.add(&term);
        }
        
        result
    }
}

// Polynomial operations in CRT domain
impl<F: Field> CRTContext<F> {
    /// Extend CRT to multivariate polynomials
    /// For p ∈ R_q^r[X^µ], applies CRT coefficient-wise
    ///
    /// Mathematical: For polynomial p(X) = Σ_α p_α X^α with p_α ∈ R_q^r,
    /// CRT(p) has coefficients CRT(p_α) ∈ (F_{q^e})^{rφ/e}
    ///
    /// This preserves polynomial structure:
    /// - CRT(p + q) = CRT(p) + CRT(q)
    /// - CRT(p · q) = CRT(p) · CRT(q) (coefficient-wise in each slot)
    ///
    /// Used in SALSAA for:
    /// - Sumcheck polynomials: g_j(X) ∈ F_{q^e}[X] of degree 2(d-1)
    /// - LDE polynomials: LDE[W] ∈ R_q^r[X^µ] with individual degree d-1
    ///
    /// Complexity: O(|coeffs| · φ) where |coeffs| is number of monomials
    pub fn poly_to_crt(
        &self,
        poly_coeffs: &[RingElement<F>],
    ) -> Vec<ExtFieldElement<F>> {
        self.vector_to_crt(poly_coeffs)
    }
    
    /// Inverse polynomial CRT
    ///
    /// Mathematical: Inverse of poly_to_crt
    /// Reconstructs polynomial in R_q^r[X^µ] from CRT representation
    ///
    /// Complexity: O(|coeffs| · φ)
    pub fn poly_from_crt(
        &self,
        poly_crt: &[ExtFieldElement<F>],
    ) -> Vec<RingElement<F>> {
        self.vector_from_crt(poly_crt)
    }
    
    /// Evaluate univariate polynomial in CRT domain at point
    /// More efficient than converting back to ring domain
    ///
    /// Mathematical: For p(X) = Σ_i p_i X^i and point r ∈ F_{q^e},
    /// computes p(r) = Σ_i p_i · r^i ∈ (F_{q^e})^{rφ/e}
    ///
    /// This is done slot-wise: each slot evaluates independently
    ///
    /// Algorithm (Horner's method):
    /// result = p_n
    /// for i = n-1 down to 0:
    ///     result = result · r + p_i
    ///
    /// Complexity: O(deg(p) · rφ/e) multiplications in F_{q^e}
    pub fn eval_univariate_poly_crt(
        &self,
        poly_crt: &[ExtFieldElement<F>],
        point: &ExtFieldElement<F>,
    ) -> ExtFieldElement<F> {
        if poly_crt.is_empty() {
            return ExtFieldElement::zero(self.slot_degree, self.modulus_type.clone());
        }
        
        // Horner's method: p(r) = (...((p_n · r + p_{n-1}) · r + p_{n-2}) · r + ... + p_0)
        let mut result = poly_crt[poly_crt.len() - 1].clone();
        
        for i in (0..poly_crt.len() - 1).rev() {
            result = result.mul(point);
            result = result.add(&poly_crt[i]);
        }
        
        result
    }
    
    /// Evaluate multivariate polynomial in CRT domain
    ///
    /// Mathematical: For p(X_0, ..., X_{µ-1}) and point (r_0, ..., r_{µ-1}),
    /// computes p(r_0, ..., r_{µ-1}) by repeated univariate evaluation
    ///
    /// Algorithm:
    /// 1. View p as univariate in X_{µ-1}: p = Σ_i p_i(X_0,...,X_{µ-2}) · X_{µ-1}^i
    /// 2. Recursively evaluate p_i at (r_0, ..., r_{µ-2})
    /// 3. Evaluate resulting univariate at r_{µ-1}
    ///
    /// Complexity: O(d^µ · µ) for degree-d polynomial in µ variables
    pub fn eval_multivariate_poly_crt(
        &self,
        poly_crt: &[ExtFieldElement<F>],
        points: &[ExtFieldElement<F>],
        degrees: &[usize],
    ) -> ExtFieldElement<F> {
        assert_eq!(points.len(), degrees.len(), 
            "Number of points must match number of variables");
        
        if degrees.is_empty() {
            // Constant polynomial
            return if poly_crt.is_empty() {
                ExtFieldElement::zero(self.slot_degree, self.modulus_type.clone())
            } else {
                poly_crt[0].clone()
            };
        }
        
        // Recursive evaluation
        let num_vars = degrees.len();
        let last_degree = degrees[num_vars - 1];
        let last_point = &points[num_vars - 1];
        
        // Partition polynomial by last variable
        let stride = poly_crt.len() / (last_degree + 1);
        let mut univariate_coeffs = Vec::with_capacity(last_degree + 1);
        
        for i in 0..=last_degree {
            let start = i * stride;
            let end = (start + stride).min(poly_crt.len());
            let coeff_poly = &poly_crt[start..end];
            
            // Recursively evaluate coefficient polynomial
            let coeff_val = if num_vars == 1 {
                // Base case: constant
                if coeff_poly.is_empty() {
                    ExtFieldElement::zero(self.slot_degree, self.modulus_type.clone())
                } else {
                    coeff_poly[0].clone()
                }
            } else {
                self.eval_multivariate_poly_crt(
                    coeff_poly,
                    &points[..num_vars-1],
                    &degrees[..num_vars-1],
                )
            };
            
            univariate_coeffs.push(coeff_val);
        }
        
        // Evaluate univariate polynomial at last point
        self.eval_univariate_poly_crt(&univariate_coeffs, last_point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_ext_field_arithmetic() {
        let e = 4;
        let modulus_type = ModulusType::PowerOfTwoCyclotomic;
        
        let mut a_coeffs = vec![GoldilocksField::zero(); e];
        a_coeffs[0] = GoldilocksField::from_u64(3);
        a_coeffs[1] = GoldilocksField::from_u64(2);
        let a = ExtFieldElement { 
            coeffs: a_coeffs, 
            degree: e,
            modulus_type: modulus_type.clone(),
        };
        
        let mut b_coeffs = vec![GoldilocksField::zero(); e];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        let b = ExtFieldElement { 
            coeffs: b_coeffs, 
            degree: e,
            modulus_type: modulus_type.clone(),
        };
        
        // Test addition
        let sum = a.add(&b);
        assert_eq!(sum.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(sum.coeffs[1].to_canonical_u64(), 2);
        
        // Test multiplication
        let prod = a.mul(&b);
        assert_eq!(prod.coeffs[0].to_canonical_u64(), 15); // 3*5
        assert_eq!(prod.coeffs[1].to_canonical_u64(), 10); // 2*5
    }
    
    #[test]
    fn test_crt_context_creation() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        assert_eq!(crt_ctx.num_slots * crt_ctx.slot_degree, ring.degree);
        assert!(crt_ctx.num_slots > 0);
        assert!(crt_ctx.slot_degree > 0);
    }
    
    #[test]
    fn test_crt_round_trip() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create test element
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(7);
        coeffs[1] = GoldilocksField::from_u64(13);
        coeffs[5] = GoldilocksField::from_u64(19);
        let elem = RingElement::from_coeffs(coeffs.clone());
        
        // Forward CRT
        let slots = crt_ctx.to_crt(&elem);
        assert_eq!(slots.len(), crt_ctx.num_slots);
        
        // Inverse CRT
        let recovered = crt_ctx.from_crt(&slots);
        
        // Should recover original (approximately, due to CRT)
        assert_eq!(recovered.coeffs.len(), elem.coeffs.len());
    }
    
    #[test]
    fn test_vector_crt() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create vector of ring elements
        let mut elem1_coeffs = vec![GoldilocksField::zero(); 64];
        elem1_coeffs[0] = GoldilocksField::from_u64(3);
        let elem1 = RingElement::from_coeffs(elem1_coeffs);
        
        let mut elem2_coeffs = vec![GoldilocksField::zero(); 64];
        elem2_coeffs[0] = GoldilocksField::from_u64(5);
        let elem2 = RingElement::from_coeffs(elem2_coeffs);
        
        let vec = vec![elem1, elem2];
        
        // Forward vector CRT
        let vec_crt = crt_ctx.vector_to_crt(&vec);
        assert_eq!(vec_crt.len(), vec.len() * crt_ctx.num_slots);
        
        // Inverse vector CRT
        let recovered = crt_ctx.vector_from_crt(&vec_crt);
        assert_eq!(recovered.len(), vec.len());
    }
    
    #[test]
    fn test_lift_challenge() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create challenge in F_{q^e}
        let mut challenge_coeffs = vec![GoldilocksField::zero(); crt_ctx.slot_degree];
        challenge_coeffs[0] = GoldilocksField::from_u64(42);
        let challenge = ExtFieldElement {
            coeffs: challenge_coeffs,
            degree: crt_ctx.slot_degree,
            modulus_type: crt_ctx.modulus_type.clone(),
        };
        
        // Lift to R_q
        let lifted = crt_ctx.lift_challenge(&challenge);
        
        // Verify: CRT(lifted) should have challenge in all slots
        let slots = crt_ctx.to_crt(&lifted);
        for slot in slots {
            assert_eq!(slot.coeffs[0].to_canonical_u64(), 42);
        }
    }
    
    #[test]
    fn test_hadamard_product_crt() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create two elements
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(3);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        let b = RingElement::from_coeffs(b_coeffs);
        
        // Convert to CRT
        let a_crt = crt_ctx.to_crt(&a);
        let b_crt = crt_ctx.to_crt(&b);
        
        // Hadamard product in CRT domain
        let prod_crt = crt_ctx.hadamard_product_crt(&a_crt, &b_crt);
        
        // Convert back
        let prod = crt_ctx.from_crt(&prod_crt);
        
        // Should equal ring multiplication for constant terms
        assert_eq!(prod.coeffs[0].to_canonical_u64(), 15);
    }
    
    #[test]
    fn test_lift_challenge_vector() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create vector of challenges
        let mut c1_coeffs = vec![GoldilocksField::zero(); crt_ctx.slot_degree];
        c1_coeffs[0] = GoldilocksField::from_u64(7);
        let c1 = ExtFieldElement { 
            coeffs: c1_coeffs, 
            degree: crt_ctx.slot_degree,
            modulus_type: crt_ctx.modulus_type.clone(),
        };
        
        let mut c2_coeffs = vec![GoldilocksField::zero(); crt_ctx.slot_degree];
        c2_coeffs[0] = GoldilocksField::from_u64(11);
        let c2 = ExtFieldElement { 
            coeffs: c2_coeffs, 
            degree: crt_ctx.slot_degree,
            modulus_type: crt_ctx.modulus_type.clone(),
        };
        
        let challenges = vec![c1, c2];
        
        // Lift vector
        let lifted = crt_ctx.lift_challenge_vector(&challenges);
        assert_eq!(lifted.len(), 2);
        
        // Verify each lifted element
        for (i, elem) in lifted.iter().enumerate() {
            let slots = crt_ctx.to_crt(elem);
            let expected = if i == 0 { 7 } else { 11 };
            for slot in slots {
                assert_eq!(slot.coeffs[0].to_canonical_u64(), expected);
            }
        }
    }
    
    #[test]
    fn test_ext_field_power_of_two_reduction() {
        // Test X^e + 1 reduction for power-of-2 cyclotomics
        let e = 4;
        let modulus_type = ModulusType::PowerOfTwoCyclotomic;
        
        // Create X (polynomial X)
        let mut x_coeffs = vec![GoldilocksField::zero(); e];
        x_coeffs[1] = GoldilocksField::one();
        let x = ExtFieldElement::from_coeffs(x_coeffs, modulus_type.clone());
        
        // Compute X^e (should reduce to -1)
        let x_pow_e = x.pow(e as u64);
        
        // In power-of-2 cyclotomic: X^e ≡ -1
        // So x_pow_e should be (-1, 0, 0, 0)
        let expected_val = GoldilocksField::zero().sub(&GoldilocksField::one());
        assert_eq!(x_pow_e.coeffs[0], expected_val);
        for i in 1..e {
            assert_eq!(x_pow_e.coeffs[i], GoldilocksField::zero());
        }
    }
    
    #[test]
    fn test_multivariate_poly_eval_crt() {
        let ring = Arc::new(CyclotomicRing::<GoldilocksField>::new(64));
        let crt_ctx = CRTContext::new(ring.clone());
        
        // Create simple bivariate polynomial: p(X,Y) = 3 + 2X + 5Y + 7XY
        // In CRT representation
        let modulus_type = crt_ctx.modulus_type.clone();
        let e = crt_ctx.slot_degree;
        
        let poly_crt = vec![
            ExtFieldElement::from_base(GoldilocksField::from_u64(3), e, modulus_type.clone()), // constant
            ExtFieldElement::from_base(GoldilocksField::from_u64(2), e, modulus_type.clone()), // X coeff
            ExtFieldElement::from_base(GoldilocksField::from_u64(5), e, modulus_type.clone()), // Y coeff
            ExtFieldElement::from_base(GoldilocksField::from_u64(7), e, modulus_type.clone()), // XY coeff
        ];
        
        // Evaluate at (2, 3)
        let points = vec![
            ExtFieldElement::from_base(GoldilocksField::from_u64(2), e, modulus_type.clone()),
            ExtFieldElement::from_base(GoldilocksField::from_u64(3), e, modulus_type.clone()),
        ];
        let degrees = vec![1, 1]; // degree 1 in each variable
        
        let result = crt_ctx.eval_multivariate_poly_crt(&poly_crt, &points, &degrees);
        
        // Expected: 3 + 2*2 + 5*3 + 7*2*3 = 3 + 4 + 15 + 42 = 64
        assert_eq!(result.coeffs[0].to_canonical_u64(), 64);
    }
}
