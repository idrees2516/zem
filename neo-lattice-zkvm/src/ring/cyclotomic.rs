// Cyclotomic ring implementation
// R = Z[X]/(X^d + 1) for power-of-2 d

use crate::field::Field;
use super::ntt::NTT;

/// Cyclotomic ring R_q = F_q[X]/(X^d + 1)
#[derive(Clone, Debug)]
pub struct CyclotomicRing<F: Field> {
    pub degree: usize,
    pub ntt: Option<NTT<F>>,
}

/// Ring element: polynomial in R_q
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingElement<F: Field> {
    pub coeffs: Vec<F>,
}

impl<F: Field> CyclotomicRing<F> {
    /// Create new cyclotomic ring R_q = F_q[X]/(X^d + 1)
    /// Requires d to be a power of 2
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be power of 2");
        assert!(degree >= 64, "Degree must be at least 64 for security");
        
        // Try to initialize NTT if primitive root exists
        let ntt = NTT::try_new(degree);
        
        Self { degree, ntt }
    }
    
    /// Compute set operator norm: ∥S∥_op := max_{a∈S} ∥a∥_op
    /// Per Symphony paper, for LaBRADOR challenge set, ∥S∥_op ≤ 15
    pub fn set_operator_norm(elements: &[RingElement<F>]) -> f64 {
        elements.iter()
            .map(|elem| elem.operator_norm())
            .fold(0.0, f64::max)
    }
    
    /// Verify Lemma 2.3: For a ∈ M (monomial), b ∈ R, ∥a·b∥_∞ ≤ ∥b∥_∞
    /// This holds when a is a monomial (single non-zero coefficient of ±1)
    pub fn verify_lemma_2_3(&self, a: &RingElement<F>, b: &RingElement<F>) -> bool {
        // Check if a is a monomial
        let non_zero_count = a.coeffs.iter()
            .filter(|c| c.to_canonical_u64() != 0)
            .count();
        
        if non_zero_count != 1 {
            return false; // Not a monomial
        }
        
        // Compute a·b
        let product = self.mul(a, b);
        
        // Check ∥a·b∥_∞ ≤ ∥b∥_∞
        product.norm_infinity() <= b.norm_infinity()
    }
    
    /// Verify Lemma 2.4: Invertibility for ∥y∥_∞ < q^{1/e}/√e
    /// Returns true if element is likely invertible based on norm bound
    pub fn verify_lemma_2_4(&self, y: &RingElement<F>) -> bool {
        if let Some(ref ntt) = self.ntt {
            let e = ntt.exponent_e() as f64;
            let q = F::MODULUS as f64;
            
            // Compute bound: q^{1/e}/√e
            let bound = q.powf(1.0 / e) / e.sqrt();
            
            // Check if ∥y∥_∞ < bound
            (y.norm_infinity() as f64) < bound
        } else {
            false
        }
    }
    
    /// Check if NTT is available for this ring
    pub fn has_ntt(&self) -> bool {
        self.ntt.is_some()
    }
    
    /// Create zero ring element
    pub fn zero(&self) -> RingElement<F> {
        RingElement {
            coeffs: vec![F::zero(); self.degree]
        }
    }
    
    /// Create one ring element
    pub fn one(&self) -> RingElement<F> {
        let mut coeffs = vec![F::zero(); self.degree];
        coeffs[0] = F::one();
        RingElement { coeffs }
    }
    
    /// Add two ring elements
    pub fn add(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        let coeffs = a.coeffs.iter()
            .zip(b.coeffs.iter())
            .map(|(x, y)| x.add(y))
            .collect();
        
        RingElement { coeffs }
    }
    
    /// Subtract two ring elements
    pub fn sub(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        let coeffs = a.coeffs.iter()
            .zip(b.coeffs.iter())
            .map(|(x, y)| x.sub(y))
            .collect();
        
        RingElement { coeffs }
    }
    
    /// Negate ring element
    pub fn neg(&self, a: &RingElement<F>) -> RingElement<F> {
        let coeffs = a.coeffs.iter().map(|x| x.neg()).collect();
        RingElement { coeffs }
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &F, a: &RingElement<F>) -> RingElement<F> {
        let coeffs = a.coeffs.iter().map(|x| scalar.mul(x)).collect();
        RingElement { coeffs }
    }
    
    /// Multiply two ring elements
    pub fn mul(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        if let Some(ref ntt) = self.ntt {
            self.mul_ntt(a, b, ntt)
        } else {
            self.mul_schoolbook(a, b)
        }
    }
    
    /// NTT-based multiplication (O(d log d))
    fn mul_ntt(&self, a: &RingElement<F>, b: &RingElement<F>, ntt: &NTT<F>) -> RingElement<F> {
        // Forward NTT
        let a_ntt = ntt.forward(&a.coeffs);
        let b_ntt = ntt.forward(&b.coeffs);
        
        // Pointwise multiplication
        let c_ntt: Vec<F> = a_ntt.iter()
            .zip(b_ntt.iter())
            .map(|(x, y)| x.mul(y))
            .collect();
        
        // Inverse NTT
        let coeffs = ntt.inverse(&c_ntt);
        
        RingElement { coeffs }
    }
    
    /// Schoolbook multiplication (O(d^2)) - fallback when NTT unavailable
    fn mul_schoolbook(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        let d = self.degree;
        let mut result = vec![F::zero(); d];
        
        // Compute polynomial product
        for i in 0..d {
            for j in 0..d {
                let prod = a.coeffs[i].mul(&b.coeffs[j]);
                let idx = i + j;
                
                if idx < d {
                    result[idx] = result[idx].add(&prod);
                } else {
                    // Reduce by X^d = -1
                    let reduced_idx = idx - d;
                    result[reduced_idx] = result[reduced_idx].sub(&prod);
                }
            }
        }
        
        RingElement { coeffs: result }
    }
}

impl<F: Field> RingElement<F> {
    /// Create ring element from coefficient vector
    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }
    
    /// Coefficient embedding: R_q → F_q^d
    pub fn to_coefficient_vector(&self) -> Vec<F> {
        self.coeffs.clone()
    }
    
    /// Constant term extraction: R_q → F_q
    /// For f = Σᵢ fᵢXⁱ, returns f₀
    /// This is the ct(·) operation from HyperWolf paper
    pub fn constant_term(&self) -> F {
        self.coeffs[0]
    }
    
    /// Conjugation automorphism: σ⁻¹(f) = Σᵢ fᵢX⁻ⁱ
    /// For f = Σᵢ₌₀ᵈ⁻¹ fᵢXⁱ, computes σ⁻¹(f) = f₀ + f_{d-1}X + f_{d-2}X² + ... + f₁X^{d-1}
    /// In cyclotomic ring R = Z[X]/(X^d + 1), X⁻¹ = -X^{d-1}
    /// So σ⁻¹(f) reverses coefficients (except constant term) and negates them
    pub fn conjugate(&self) -> Self {
        let d = self.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Constant term stays the same
        result[0] = self.coeffs[0];
        
        // For i > 0: coefficient of X^i in σ⁻¹(f) is -f_{d-i}
        for i in 1..d {
            result[i] = self.coeffs[d - i].neg();
        }
        
        Self { coeffs: result }
    }
    
    /// Inner product with conjugate: ⟨f, σ⁻¹(g)⟩ in R_q
    /// Used in HyperWolf's guarded IPA for exact ℓ₂-norm computation
    pub fn inner_product_conjugate(&self, other: &Self) -> Self {
        assert_eq!(self.coeffs.len(), other.coeffs.len());
        
        let d = self.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Compute f · σ⁻¹(g) coefficient by coefficient
        // This is polynomial multiplication in R_q
        for i in 0..d {
            for j in 0..d {
                let g_conj_coeff = if j == 0 {
                    other.coeffs[0]
                } else {
                    other.coeffs[d - j].neg()
                };
                
                let prod = self.coeffs[i].mul(&g_conj_coeff);
                let idx = i + j;
                
                if idx < d {
                    result[idx] = result[idx].add(&prod);
                } else {
                    // Reduce by X^d = -1
                    let reduced_idx = idx - d;
                    result[reduced_idx] = result[reduced_idx].sub(&prod);
                }
            }
        }
        
        Self { coeffs: result }
    }
    
    /// Infinity norm of ring element: ∥f∥_∞ = max_i |f_i|
    pub fn norm_infinity(&self) -> u64 {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation: map to [-q/2, q/2]
                if val <= modulus / 2 {
                    val
                } else {
                    modulus - val
                }
            })
            .max()
            .unwrap_or(0)
    }
    
    /// L2 norm of ring element: ∥f∥_2 = √(Σ f_i^2)
    /// Returns the squared norm to avoid floating point
    pub fn norm_l2_squared(&self) -> u128 {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation: map to [-q/2, q/2]
                let balanced = if val <= modulus / 2 {
                    val as i128
                } else {
                    -((modulus - val) as i128)
                };
                (balanced * balanced) as u128
            })
            .sum()
    }
    
    /// L2 norm of ring element (floating point approximation)
    pub fn norm_l2(&self) -> f64 {
        (self.norm_l2_squared() as f64).sqrt()
    }
    
    /// Operator norm: ∥a∥_op := sup_{y∈R} ∥a·y∥_∞ / ∥y∥_∞
    /// For a ∈ M (monomial set), this equals the sum of absolute values of coefficients
    /// Per Eq. (1) of Symphony paper
    pub fn operator_norm(&self) -> f64 {
        // For general ring elements, operator norm is bounded by sum of absolute coefficients
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation
                if val <= modulus / 2 {
                    val as f64
                } else {
                    (modulus - val) as f64
                }
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_ring_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        assert_eq!(ring.degree, 64);
    }
    
    #[test]
    fn test_ring_addition() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(3);
        a_coeffs[1] = GoldilocksField::from_u64(4);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[1] = GoldilocksField::from_u64(6);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let c = ring.add(&a, &b);
        assert_eq!(c.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(c.coeffs[1].to_canonical_u64(), 10);
    }
    
    #[test]
    fn test_ring_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let c = ring.mul(&a, &b);
        assert_eq!(c.coeffs[0].to_canonical_u64(), 6);
    }
    
    #[test]
    fn test_norm_infinity() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(5);
        coeffs[1] = GoldilocksField::from_u64(10);
        let elem = RingElement::from_coeffs(coeffs);
        
        assert_eq!(elem.norm_infinity(), 10);
    }
    
    #[test]
    fn test_norm_l2() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        let elem = RingElement::from_coeffs(coeffs);
        
        // ∥f∥_2 = √(3^2 + 4^2) = √25 = 5
        assert_eq!(elem.norm_l2_squared(), 25);
        assert!((elem.norm_l2() - 5.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_ntt_vs_schoolbook_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create test polynomials
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        a_coeffs[1] = GoldilocksField::from_u64(3);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[2] = GoldilocksField::from_u64(7);
        let b = RingElement::from_coeffs(b_coeffs);
        
        // Multiply using NTT
        let c_ntt = ring.mul(&a, &b);
        
        // Multiply using schoolbook (temporarily disable NTT)
        let ring_no_ntt = CyclotomicRing {
            degree: ring.degree,
            ntt: None,
        };
        let c_schoolbook = ring_no_ntt.mul(&a, &b);
        
        // Results should match
        assert_eq!(c_ntt.coeffs, c_schoolbook.coeffs);
    }
    
    #[test]
    fn test_ring_axioms() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let mut c_coeffs = vec![GoldilocksField::zero(); 64];
        c_coeffs[0] = GoldilocksField::from_u64(5);
        let c = RingElement::from_coeffs(c_coeffs);
        
        // Test associativity: (a + b) + c = a + (b + c)
        let left = ring.add(&ring.add(&a, &b), &c);
        let right = ring.add(&a, &ring.add(&b, &c));
        assert_eq!(left.coeffs, right.coeffs);
        
        // Test commutativity: a + b = b + a
        let ab = ring.add(&a, &b);
        let ba = ring.add(&b, &a);
        assert_eq!(ab.coeffs, ba.coeffs);
        
        // Test distributivity: a * (b + c) = a*b + a*c
        let left = ring.mul(&a, &ring.add(&b, &c));
        let right = ring.add(&ring.mul(&a, &b), &ring.mul(&a, &c));
        assert_eq!(left.coeffs, right.coeffs);
        
        // Test multiplicative commutativity: a * b = b * a
        let ab = ring.mul(&a, &b);
        let ba = ring.mul(&b, &a);
        assert_eq!(ab.coeffs, ba.coeffs);
    }
    
    #[test]
    fn test_operator_norm() {
        // Test monomial X has operator norm 1
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[1] = GoldilocksField::from_u64(1);
        let monomial = RingElement::from_coeffs(coeffs);
        
        assert_eq!(monomial.operator_norm(), 1.0);
    }
    
    #[test]
    fn test_set_operator_norm() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create LaBRADOR-style challenge set with small coefficients
        let mut elements = Vec::new();
        
        // Element with coefficients {0, ±1, ±2}
        let mut coeffs1 = vec![GoldilocksField::zero(); 64];
        coeffs1[0] = GoldilocksField::from_u64(1);
        coeffs1[1] = GoldilocksField::from_u64(2);
        elements.push(RingElement::from_coeffs(coeffs1));
        
        let mut coeffs2 = vec![GoldilocksField::zero(); 64];
        coeffs2[0] = GoldilocksField::from_u64(2);
        coeffs2[2] = GoldilocksField::from_u64(1);
        elements.push(RingElement::from_coeffs(coeffs2));
        
        let set_norm = CyclotomicRing::<GoldilocksField>::set_operator_norm(&elements);
        
        // For LaBRADOR challenge set, ∥S∥_op ≤ 15
        assert!(set_norm <= 15.0);
    }
    
    #[test]
    fn test_lemma_2_3() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create monomial a = X
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[1] = GoldilocksField::from_u64(1);
        let a = RingElement::from_coeffs(a_coeffs);
        
        // Create arbitrary b
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[1] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        // Verify Lemma 2.3: ∥a·b∥_∞ ≤ ∥b∥_∞
        assert!(ring.verify_lemma_2_3(&a, &b));
    }
    
    #[test]
    fn test_lemma_2_4() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create element with small norm
        let mut y_coeffs = vec![GoldilocksField::zero(); 64];
        y_coeffs[0] = GoldilocksField::from_u64(10);
        let y = RingElement::from_coeffs(y_coeffs);
        
        // Should be invertible (small norm)
        assert!(ring.verify_lemma_2_4(&y));
    }
    
    #[test]
    fn test_conjugation_automorphism() {
        // Test σ⁻¹(f) for f = 1 + 2X + 3X²
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(1);
        coeffs[1] = GoldilocksField::from_u64(2);
        coeffs[2] = GoldilocksField::from_u64(3);
        let f = RingElement::from_coeffs(coeffs);
        
        let f_conj = f.conjugate();
        
        // σ⁻¹(f) = 1 - 3X - 2X²  (in balanced representation)
        assert_eq!(f_conj.coeffs[0].to_canonical_u64(), 1);
        // -3 and -2 will be represented as q-3 and q-2
        let q = GoldilocksField::MODULUS;
        assert_eq!(f_conj.coeffs[1].to_canonical_u64(), q - 3);
        assert_eq!(f_conj.coeffs[2].to_canonical_u64(), q - 2);
    }
    
    #[test]
    fn test_conjugation_involution() {
        // Test that σ⁻¹(σ⁻¹(f)) = f
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(5);
        coeffs[1] = GoldilocksField::from_u64(7);
        coeffs[5] = GoldilocksField::from_u64(11);
        let f = RingElement::from_coeffs(coeffs);
        
        let f_conj_conj = f.conjugate().conjugate();
        
        // Should get back original
        assert_eq!(f.coeffs, f_conj_conj.coeffs);
    }
    
    #[test]
    fn test_inner_product_conjugate() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Test ⟨f, σ⁻¹(f)⟩ for f = 3 + 4X
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        let f = RingElement::from_coeffs(coeffs);
        
        let inner_prod = f.inner_product_conjugate(&f);
        
        // ⟨f, σ⁻¹(f)⟩ = f · σ⁻¹(f)
        // For f = 3 + 4X, σ⁻¹(f) = 3 - 4X^{63}
        // f · σ⁻¹(f) = (3 + 4X)(3 - 4X^{63})
        //            = 9 - 12X^{63} + 12X - 16X^{64}
        //            = 9 - 12X^{63} + 12X + 16  (since X^{64} = -1)
        //            = 25 + 12X - 12X^{63}
        
        // Constant term should be 25 = 3² + 4²
        assert_eq!(inner_prod.constant_term().to_canonical_u64(), 25);
    }
    
    #[test]
    fn test_constant_term_extraction() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(42);
        coeffs[1] = GoldilocksField::from_u64(100);
        let f = RingElement::from_coeffs(coeffs);
        
        assert_eq!(f.constant_term().to_canonical_u64(), 42);
    }
    
    #[test]
    fn test_inner_product_conjugate_property() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Test that ct(⟨f, σ⁻¹(f)⟩) = ∥f∥₂² for small coefficients
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        coeffs[2] = GoldilocksField::from_u64(5);
        let f = RingElement::from_coeffs(coeffs);
        
        let inner_prod = f.inner_product_conjugate(&f);
        let ct = inner_prod.constant_term().to_canonical_u64();
        
        // ∥f∥₂² = 3² + 4² + 5² = 9 + 16 + 25 = 50
        assert_eq!(ct, 50);
    }
}
