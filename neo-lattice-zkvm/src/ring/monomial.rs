// Monomial embedding system for algebraic range proofs
// Implements monomial set M, table polynomial t(X), and Exp mapping
// Per Symphony paper Section 2.2 and LatticeFold+ Section 4.3

use crate::field::Field;
use super::{CyclotomicRing, RingElement};

/// Monomial set M := {0, 1, X, X^2, ..., X^{d-1}} ⊆ Rq
/// Per Eq. (2) of Symphony paper
#[derive(Clone, Debug)]
pub struct MonomialSet<F: Field> {
    /// Ring degree d
    pub degree: usize,
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
}

impl<F: Field> MonomialSet<F> {
    /// Create new monomial set for ring of degree d
    pub fn new(degree: usize) -> Self {
        let ring = CyclotomicRing::new(degree);
        Self { degree, ring }
    }
    
    /// Check if element is in monomial set M
    /// Element must be 0, 1, or X^i for some i ∈ [0, d-1]
    pub fn contains(&self, element: &RingElement<F>) -> bool {
        // Count non-zero coefficients
        let mut non_zero_count = 0;
        let mut non_zero_idx = 0;
        let mut non_zero_val = F::zero();
        
        for (idx, &coeff) in element.coeffs.iter().enumerate() {
            if coeff.to_canonical_u64() != 0 {
                non_zero_count += 1;
                non_zero_idx = idx;
                non_zero_val = coeff;
                
                if non_zero_count > 1 {
                    return false; // More than one non-zero coefficient
                }
            }
        }
        
        // Check if it's 0 (all coefficients zero)
        if non_zero_count == 0 {
            return true;
        }
        
        // Check if it's 1 (constant term is 1)
        if non_zero_idx == 0 && non_zero_val == F::one() {
            return true;
        }
        
        // Check if it's X^i (single coefficient of 1 at position i)
        if non_zero_val == F::one() {
            return true;
        }
        
        // Check if it's -X^i (single coefficient of -1 at position i)
        if non_zero_val == F::one().neg() {
            return true;
        }
        
        false
    }
    
    /// Get monomial X^i
    pub fn get_monomial(&self, i: usize) -> RingElement<F> {
        assert!(i < self.degree, "Monomial index out of range");
        
        let mut coeffs = vec![F::zero(); self.degree];
        coeffs[i] = F::one();
        RingElement::from_coeffs(coeffs)
    }
    
    /// Get all monomials in the set
    pub fn all_monomials(&self) -> Vec<RingElement<F>> {
        let mut monomials = Vec::with_capacity(self.degree + 2);
        
        // Add 0
        monomials.push(self.ring.zero());
        
        // Add 1
        monomials.push(self.ring.one());
        
        // Add X, X^2, ..., X^{d-1}
        for i in 1..self.degree {
            monomials.push(self.get_monomial(i));
        }
        
        monomials
    }
}

/// Table polynomial t(X) := Σ_{i∈[1,d/2)} i·(X^{-i} + X^i)
/// Per Eq. (3) of Symphony paper
#[derive(Clone, Debug)]
pub struct TablePolynomial<F: Field> {
    /// Polynomial representation
    pub poly: RingElement<F>,
    /// Ring degree d
    pub degree: usize,
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
}

impl<F: Field> TablePolynomial<F> {
    /// Create table polynomial for ring of degree d
    /// t(X) = Σ_{i∈[1,d/2)} i·(X^{-i} + X^i)
    pub fn new(degree: usize) -> Self {
        let ring = CyclotomicRing::new(degree);
        
        // Initialize coefficients
        let mut coeffs = vec![F::zero(); degree];
        
        // For i ∈ [1, d/2), add i·(X^{-i} + X^i)
        // In cyclotomic ring: X^{-i} = -X^{d-i} (since X^d = -1)
        for i in 1..(degree / 2) {
            let i_field = F::from_u64(i as u64);
            
            // Add i·X^i
            coeffs[i] = coeffs[i].add(&i_field);
            
            // Add i·X^{-i} = -i·X^{d-i}
            // But we need to be careful with the sign
            // X^{-i} mod (X^d + 1) = -X^{d-i}
            let neg_i_field = i_field.neg();
            coeffs[degree - i] = coeffs[degree - i].add(&neg_i_field);
        }
        
        let poly = RingElement::from_coeffs(coeffs);
        
        Self { poly, degree, ring }
    }
    
    /// Evaluate constant term of b·t(X) for monomial b
    /// Per Lemma 2.1: For a ∈ (-d/2, d/2), b ∈ Exp(a), ct(b·t(X)) = a
    pub fn evaluate_constant_term(&self, monomial: &RingElement<F>) -> i64 {
        // Compute b·t(X)
        let product = self.ring.mul(monomial, &self.poly);
        
        // Extract constant term
        let ct = product.constant_term();
        let ct_u64 = ct.to_canonical_u64();
        
        // Convert to signed integer (balanced representation)
        let modulus = F::MODULUS;
        if ct_u64 <= modulus / 2 {
            ct_u64 as i64
        } else {
            -((modulus - ct_u64) as i64)
        }
    }
    
    /// Verify range proof: ct(b·t(X)) = a
    /// Returns true if monomial b encodes value a
    pub fn verify_range(&self, value: i64, monomial: &RingElement<F>) -> bool {
        let computed = self.evaluate_constant_term(monomial);
        computed == value
    }
}

/// Exponential map Exp: Z → M
/// Per Eq. (4) of Symphony paper
pub struct ExponentialMap<F: Field> {
    /// Ring degree d
    pub degree: usize,
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
}

impl<F: Field> ExponentialMap<F> {
    /// Create exponential map for ring of degree d
    pub fn new(degree: usize) -> Self {
        let ring = CyclotomicRing::new(degree);
        Self { degree, ring }
    }
    
    /// Exp(a) := sgn(a)·X^a for a ∈ (-d/2, d/2), a ≠ 0
    /// For a = 0, returns one of {0, 1, X^{d/2}}
    pub fn exp(&self, value: i64) -> RingElement<F> {
        let d = self.degree as i64;
        let half_d = d / 2;
        
        assert!(
            value > -half_d && value < half_d,
            "Value {} out of range (-{}, {})",
            value,
            half_d,
            half_d
        );
        
        if value == 0 {
            // For a = 0, return 1 (could also return 0 or X^{d/2})
            return self.ring.one();
        }
        
        let mut coeffs = vec![F::zero(); self.degree];
        
        if value > 0 {
            // Positive: X^a
            coeffs[value as usize] = F::one();
        } else {
            // Negative: -X^{-a} = -X^{d+a} (since X^d = -1)
            // Actually: sgn(a)·X^a for a < 0 means -X^{|a|}
            // But in cyclotomic ring: X^{-|a|} = -X^{d-|a|}
            let abs_value = (-value) as usize;
            coeffs[self.degree - abs_value] = F::one().neg();
        }
        
        RingElement::from_coeffs(coeffs)
    }
    
    /// EXP(a) set: {Exp(a)} if a ≠ 0, {0, 1, X^{d/2}} if a = 0
    /// Per definition after Eq. (4)
    pub fn exp_set(&self, value: i64) -> Vec<RingElement<F>> {
        if value == 0 {
            // Return {0, 1, X^{d/2}}
            vec![
                self.ring.zero(),
                self.ring.one(),
                {
                    let mut coeffs = vec![F::zero(); self.degree];
                    coeffs[self.degree / 2] = F::one();
                    RingElement::from_coeffs(coeffs)
                },
            ]
        } else {
            // Return {Exp(a)}
            vec![self.exp(value)]
        }
    }
    
    /// Verify Lemma 2.1: For a ∈ (-d/2, d/2), b ∈ Exp(a), ct(b·t(X)) = a
    pub fn verify_lemma_2_1(&self, value: i64, table: &TablePolynomial<F>) -> bool {
        let d = self.degree as i64;
        let half_d = d / 2;
        
        if value <= -half_d || value >= half_d {
            return false;
        }
        
        if value == 0 {
            // For a = 0, check all elements in EXP(0)
            let exp_set = self.exp_set(0);
            for monomial in exp_set {
                let ct = table.evaluate_constant_term(&monomial);
                if ct != 0 {
                    return false;
                }
            }
            true
        } else {
            let monomial = self.exp(value);
            table.verify_range(value, &monomial)
        }
    }
    
    /// Verify converse of Lemma 2.1:
    /// If ct(b·t(X)) = a for b ∈ M, then a ∈ (-d/2, d/2)
    pub fn verify_lemma_2_1_converse(
        &self,
        monomial: &RingElement<F>,
        table: &TablePolynomial<F>,
        monomial_set: &MonomialSet<F>,
    ) -> bool {
        // Check b ∈ M
        if !monomial_set.contains(monomial) {
            return false;
        }
        
        // Compute a = ct(b·t(X))
        let a = table.evaluate_constant_term(monomial);
        
        // Check a ∈ (-d/2, d/2)
        let d = self.degree as i64;
        let half_d = d / 2;
        
        a > -half_d && a < half_d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_monomial_set_contains() {
        let monomial_set = MonomialSet::<GoldilocksField>::new(64);
        
        // Test 0
        let zero = monomial_set.ring.zero();
        assert!(monomial_set.contains(&zero));
        
        // Test 1
        let one = monomial_set.ring.one();
        assert!(monomial_set.contains(&one));
        
        // Test X
        let x = monomial_set.get_monomial(1);
        assert!(monomial_set.contains(&x));
        
        // Test X^5
        let x5 = monomial_set.get_monomial(5);
        assert!(monomial_set.contains(&x5));
        
        // Test non-monomial (1 + X)
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::one();
        coeffs[1] = GoldilocksField::one();
        let non_monomial = RingElement::from_coeffs(coeffs);
        assert!(!monomial_set.contains(&non_monomial));
    }
    
    #[test]
    fn test_table_polynomial_creation() {
        let table = TablePolynomial::<GoldilocksField>::new(64);
        assert_eq!(table.degree, 64);
        
        // Verify structure: t(X) = Σ_{i∈[1,32)} i·(X^{-i} + X^i)
        // Coefficient at position i should be i for i ∈ [1, 32)
        for i in 1..32 {
            let coeff = table.poly.coeffs[i].to_canonical_u64();
            assert_eq!(coeff, i as u64);
        }
    }
    
    #[test]
    fn test_exponential_map() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        
        // Test Exp(5) = X^5
        let exp5 = exp_map.exp(5);
        assert_eq!(exp5.coeffs[5].to_canonical_u64(), 1);
        
        // Test Exp(0) = 1
        let exp0 = exp_map.exp(0);
        assert_eq!(exp0.coeffs[0].to_canonical_u64(), 1);
        
        // Test Exp(-5)
        let exp_neg5 = exp_map.exp(-5);
        // Should be -X^{64-5} = -X^59
        assert_eq!(exp_neg5.coeffs[59], GoldilocksField::one().neg());
    }
    
    #[test]
    fn test_exp_set() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        
        // EXP(0) should have 3 elements
        let exp_set_0 = exp_map.exp_set(0);
        assert_eq!(exp_set_0.len(), 3);
        
        // EXP(5) should have 1 element
        let exp_set_5 = exp_map.exp_set(5);
        assert_eq!(exp_set_5.len(), 1);
    }
    
    #[test]
    fn test_lemma_2_1() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        let table = TablePolynomial::<GoldilocksField>::new(64);
        
        // Test for various values in (-32, 32)
        for a in -31..32 {
            assert!(
                exp_map.verify_lemma_2_1(a, &table),
                "Lemma 2.1 failed for a = {}",
                a
            );
        }
    }
    
    #[test]
    fn test_lemma_2_1_specific_values() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        let table = TablePolynomial::<GoldilocksField>::new(64);
        
        // Test a = 5
        let monomial = exp_map.exp(5);
        let ct = table.evaluate_constant_term(&monomial);
        assert_eq!(ct, 5);
        
        // Test a = -10
        let monomial = exp_map.exp(-10);
        let ct = table.evaluate_constant_term(&monomial);
        assert_eq!(ct, -10);
        
        // Test a = 0
        let monomial = exp_map.exp(0);
        let ct = table.evaluate_constant_term(&monomial);
        assert_eq!(ct, 0);
    }
    
    #[test]
    fn test_lemma_2_1_converse() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        let table = TablePolynomial::<GoldilocksField>::new(64);
        let monomial_set = MonomialSet::<GoldilocksField>::new(64);
        
        // Test with various monomials
        for i in 0..64 {
            let monomial = monomial_set.get_monomial(i);
            assert!(exp_map.verify_lemma_2_1_converse(&monomial, &table, &monomial_set));
        }
    }
    
    #[test]
    fn test_range_proof_all_values() {
        let exp_map = ExponentialMap::<GoldilocksField>::new(64);
        let table = TablePolynomial::<GoldilocksField>::new(64);
        
        // Test all values in range (-32, 32)
        for a in -31..32 {
            if a == 0 {
                // For a = 0, test all elements in EXP(0)
                let exp_set = exp_map.exp_set(0);
                for monomial in exp_set {
                    assert!(table.verify_range(0, &monomial));
                }
            } else {
                let monomial = exp_map.exp(a);
                assert!(
                    table.verify_range(a, &monomial),
                    "Range proof failed for a = {}",
                    a
                );
            }
        }
    }
    
    #[test]
    fn test_monomial_set_all_monomials() {
        let monomial_set = MonomialSet::<GoldilocksField>::new(64);
        let all_monomials = monomial_set.all_monomials();
        
        // Should have d + 2 monomials: 0, 1, X, X^2, ..., X^{d-1}
        assert_eq!(all_monomials.len(), 66); // 0, 1, and 64 powers of X
        
        // Verify all are in the set
        for monomial in &all_monomials {
            assert!(monomial_set.contains(monomial));
        }
    }
}
