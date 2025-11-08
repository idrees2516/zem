// Table polynomial implementation for LatticeFold+
// ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i) for range extraction

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use super::monomial::{Monomial, exp_function, exp_set, is_in_exp_set};

/// Table polynomial ψ for range extraction
/// ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i) where d' = d/2
pub struct TablePolynomial<F: Field> {
    pub psi: RingElement<F>,
    pub d_prime: usize,
    pub degree: usize,
}

impl<F: Field> TablePolynomial<F> {
    /// Construct table polynomial for given ring
    /// ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i)
    pub fn new(ring: &CyclotomicRing<F>) -> Self {
        let degree = ring.degree;
        let d_prime = degree / 2;
        
        let mut coeffs = vec![F::zero(); degree];
        
        // Build ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i)
        for i in 1..d_prime {
            let i_field = F::from_u64(i as u64);
            
            // Add i·X^i term
            coeffs[i] = coeffs[i].add(&i_field);
            
            // Add i·X^(-i) term
            // X^(-i) = -X^(d-i) in Rq since X^d = -1
            let neg_i_idx = degree - i;
            coeffs[neg_i_idx] = coeffs[neg_i_idx].sub(&i_field);
        }
        
        let psi = RingElement::from_coeffs(coeffs);
        
        Self {
            psi,
            d_prime,
            degree,
        }
    }
    
    /// Extract value from monomial using table polynomial
    /// For b ∈ M, computes ct(b · ψ)
    /// Lemma 2.2: If a ∈ (-d', d') and b ∈ EXP(a), then ct(b · ψ) = a
    pub fn extract_value(
        &self,
        b: &Monomial,
        ring: &CyclotomicRing<F>
    ) -> i64 {
        // Compute b · ψ
        let product = b.multiply_ring_element(&self.psi, ring);
        
        // Extract constant term
        let ct = product.constant_term();
        
        // Convert to signed integer (balanced representation)
        self.field_to_signed(ct)
    }
    
    /// Verify range extraction property (Lemma 2.2 forward direction)
    /// If a ∈ (-d', d'), then for all b ∈ EXP(a): ct(b · ψ) = a
    pub fn verify_forward(
        &self,
        a: i64,
        ring: &CyclotomicRing<F>
    ) -> bool {
        let d_prime = self.d_prime as i64;
        
        // Check a is in range
        if a.abs() >= d_prime {
            return false;
        }
        
        // Get all valid monomials for a
        let exp_set_a = exp_set(a, self.degree);
        
        // Verify ct(b · ψ) = a for all b ∈ EXP(a)
        for b in exp_set_a {
            let extracted = self.extract_value(&b, ring);
            if extracted != a {
                return false;
            }
        }
        
        true
    }
    
    /// Verify range extraction property (Lemma 2.2 backward direction)
    /// If ∃b ∈ M: ct(b · ψ) = a, then a ∈ (-d', d') and b ∈ EXP(a)
    pub fn verify_backward(
        &self,
        a: i64,
        b: &Monomial,
        ring: &CyclotomicRing<F>
    ) -> bool {
        let d_prime = self.d_prime as i64;
        
        // Extract value
        let extracted = self.extract_value(b, ring);
        
        // Check if extracted value matches a
        if extracted != a {
            return false;
        }
        
        // Check a is in range
        if a.abs() >= d_prime {
            return false;
        }
        
        // Check b is in EXP(a)
        is_in_exp_set(a, b, self.degree)
    }
    
    /// Verify complete Lemma 2.2
    pub fn verify_lemma_2_2(
        &self,
        a: i64,
        b: &Monomial,
        ring: &CyclotomicRing<F>
    ) -> bool {
        self.verify_forward(a, ring) && self.verify_backward(a, b, ring)
    }
    
    /// Convert field element to signed integer (balanced representation)
    fn field_to_signed(&self, f: F) -> i64 {
        let val = f.to_canonical_u64();
        let modulus = F::MODULUS;
        
        // Map to [-q/2, q/2]
        if val <= modulus / 2 {
            val as i64
        } else {
            (val as i64) - (modulus as i64)
        }
    }
    
    /// Create generalized table polynomial for custom table T ⊆ Zq
    /// ψ_T = Σ_{i∈[1,d']} (-T_i)·X^i + Σ_{i∈[1,d')} T_{i+d'}·X^(-i)
    /// This enables table lookup arguments (Remark 2.2)
    pub fn new_custom_table(
        table: &[i64],
        ring: &CyclotomicRing<F>
    ) -> Self {
        let degree = ring.degree;
        let d_prime = degree / 2;
        
        assert_eq!(table.len(), degree, "Table must have d elements");
        assert_eq!(table[0], 0, "Table must have 0 at index 0");
        
        let mut coeffs = vec![F::zero(); degree];
        
        // Build ψ_T = Σ_{i∈[1,d']} (-T_i)·X^i + Σ_{i∈[1,d')} T_{i+d'}·X^(-i)
        for i in 1..=d_prime {
            if i < d_prime {
                // Add T_{i+d'}·X^(-i) term
                let t_val = table[i + d_prime];
                let t_field = F::from_u64(t_val.abs() as u64);
                let t_field = if t_val < 0 { t_field.neg() } else { t_field };
                
                // X^(-i) = -X^(d-i)
                let neg_i_idx = degree - i;
                coeffs[neg_i_idx] = coeffs[neg_i_idx].sub(&t_field);
            }
            
            if i <= d_prime {
                // Add (-T_i)·X^i term
                let t_val = table[i];
                let t_field = F::from_u64(t_val.abs() as u64);
                let t_field = if t_val < 0 { t_field.neg() } else { t_field };
                
                coeffs[i] = coeffs[i].sub(&t_field);
            }
        }
        
        let psi = RingElement::from_coeffs(coeffs);
        
        Self {
            psi,
            d_prime,
            degree,
        }
    }
}

/// Helper function to compute ct(ψ · b) for verification
pub fn compute_constant_term_product<F: Field>(
    psi: &RingElement<F>,
    b: &Monomial,
    ring: &CyclotomicRing<F>
) -> F {
    let product = b.multiply_ring_element(psi, ring);
    product.constant_term()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_table_polynomial_construction() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        assert_eq!(table_poly.d_prime, 32);
        assert_eq!(table_poly.degree, 64);
        
        // ψ should have d-1 non-zero terms
        let non_zero_count = table_poly.psi.coeffs.iter()
            .filter(|c| !c.is_zero())
            .count();
        assert!(non_zero_count > 0);
    }
    
    #[test]
    fn test_range_extraction_positive() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Test positive value
        let a = 5i64;
        let b = exp_function(a, 64);
        let extracted = table_poly.extract_value(&b, &ring);
        
        assert_eq!(extracted, a);
    }
    
    #[test]
    fn test_range_extraction_negative() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Test negative value
        let a = -7i64;
        let b = exp_function(a, 64);
        let extracted = table_poly.extract_value(&b, &ring);
        
        assert_eq!(extracted, a);
    }
    
    #[test]
    fn test_range_extraction_zero() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Test zero - should work for all b ∈ EXP(0)
        let a = 0i64;
        let exp_set_0 = exp_set(a, 64);
        
        for b in exp_set_0 {
            let extracted = table_poly.extract_value(&b, &ring);
            assert_eq!(extracted, a);
        }
    }
    
    #[test]
    fn test_lemma_2_2_forward() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Test forward direction for various values
        for a in -31..32 {
            assert!(table_poly.verify_forward(a, &ring));
        }
    }
    
    #[test]
    fn test_lemma_2_2_backward() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Test backward direction
        let a = 10i64;
        let b = exp_function(a, 64);
        
        assert!(table_poly.verify_backward(a, &b, &ring));
    }
    
    #[test]
    fn test_out_of_range() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let table_poly = TablePolynomial::new(&ring);
        
        // Values outside (-d', d') should fail forward check
        assert!(!table_poly.verify_forward(32, &ring));
        assert!(!table_poly.verify_forward(-32, &ring));
        assert!(!table_poly.verify_forward(100, &ring));
    }
    
    #[test]
    fn test_custom_table() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create custom table T = {0, 1, 2, 3, ..., 63}
        let table: Vec<i64> = (0..64).collect();
        let custom_table_poly = TablePolynomial::new_custom_table(&table, &ring);
        
        assert_eq!(custom_table_poly.d_prime, 32);
        assert_eq!(custom_table_poly.degree, 64);
    }
}
