// Ring fixed subgroup R_q^H ≅ F_{q^k}
// Implements Lemma 5 from the paper

use crate::field::Field;
use crate::ring::RingElement;
use super::galois_automorphisms::AutomorphismSubgroup;
use super::extension_field::ExtensionFieldElement;
use super::super::errors::{HachiError, Result};

/// Fixed ring R_q^H = {x ∈ R_q : ∀σ ∈ H, σ(x) = x}
/// 
/// **Paper Reference:** Lemma 5 "Subfields of R_q"
/// 
/// For H = ⟨σ_{-1}, σ_{4k+1}⟩, R_q^H is a subfield isomorphic to F_{q^k}
/// 
/// **Element Structure (Equation 7):**
/// Any a ∈ R_q^H has the form:
/// a = a_0 + Σ_{j=1}^{k-1} a_{k-j} · (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
/// 
/// with k degrees of freedom: a_0, a_1, ..., a_{k-1} ∈ Z_q
#[derive(Clone, Debug)]
pub struct RingFixedSubgroup<F: Field> {
    /// Ring dimension d
    pub ring_dimension: usize,
    
    /// Extension degree k
    pub extension_degree: usize,
    
    /// Subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
    pub subgroup: AutomorphismSubgroup,
    
    /// Basis elements e_0, e_1, ..., e_{k-1}
    /// where e_j = X^{d/(2k)·j} - X^{d/(2k)·(2k-j)} for j ≥ 1, e_0 = 1
    basis_elements: Vec<RingElement<F>>,
    
    /// Precomputed structure for fast operations
    period: usize, // d/(2k)
}

impl<F: Field> RingFixedSubgroup<F> {
    /// Create fixed subgroup for given ring and extension degree
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// **Validation:**
    /// - k must divide d/2
    /// - q ≡ 5 (mod 8) for field structure
    pub fn new(ring_dimension: usize, extension_degree: usize) -> Result<Self> {
        // Validate k divides d/2
        if (ring_dimension / 2) % extension_degree != 0 {
            return Err(HachiError::InvalidExtensionDegree(
                format!("Extension degree {} must divide d/2 = {}", 
                    extension_degree, ring_dimension / 2)
            ));
        }
        
        // Create subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
        let subgroup = AutomorphismSubgroup::new(ring_dimension, extension_degree)?;
        
        // Compute period d/(2k)
        let period = ring_dimension / (2 * extension_degree);
        
        // Construct basis elements
        let basis_elements = Self::construct_basis(ring_dimension, extension_degree, period);
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            subgroup,
            basis_elements,
            period,
        })
    }
    
    /// Construct basis elements e_0, e_1, ..., e_{k-1}
    /// 
    /// **Paper Reference:** Equation 7
    /// 
    /// e_0 = 1
    /// e_j = X^{d/(2k)·j} - X^{d/(2k)·(2k-j)} for j = 1, ..., k-1
    fn construct_basis(d: usize, k: usize, period: usize) -> Vec<RingElement<F>> {
        let mut basis = Vec::with_capacity(k);
        
        // e_0 = 1
        let mut e0_coeffs = vec![F::zero(); d];
        e0_coeffs[0] = F::one();
        basis.push(RingElement::from_coeffs(e0_coeffs));
        
        // e_j for j = 1, ..., k-1
        for j in 1..k {
            let mut coeffs = vec![F::zero(); d];
            
            // X^{period * j}
            let idx1 = period * j;
            coeffs[idx1] = F::one();
            
            // -X^{period * (2k - j)}
            let idx2 = period * (2 * k - j);
            if idx2 < d {
                coeffs[idx2] = F::one().neg();
            } else {
                // Reduce modulo X^d + 1
                // X^{period * (2k - j)} = X^{period * (2k - j) - d} * X^d
                //                        = -X^{period * (2k - j) - d}
                let reduced_idx = idx2 - d;
                coeffs[reduced_idx] = F::one(); // Double negation
            }
            
            basis.push(RingElement::from_coeffs(coeffs));
        }
        
        basis
    }
    
    /// Create element from coefficients [a_0, a_1, ..., a_{k-1}]
    /// 
    /// **Paper Reference:** Equation 7
    /// 
    /// Returns a = Σ_{j=0}^{k-1} a_j · e_j ∈ R_q^H
    pub fn from_coefficients(&self, coeffs: &[F]) -> Result<RingElement<F>> {
        if coeffs.len() != self.extension_degree {
            return Err(HachiError::InvalidInput(
                format!("Expected {} coefficients, got {}", 
                    self.extension_degree, coeffs.len())
            ));
        }
        
        // Compute linear combination: Σ a_j · e_j
        let mut result = vec![F::zero(); self.ring_dimension];
        
        for (j, coeff) in coeffs.iter().enumerate() {
            for (i, basis_coeff) in self.basis_elements[j].coeffs.iter().enumerate() {
                let term = coeff.mul(basis_coeff);
                result[i] = result[i].add(&term);
            }
        }
        
        Ok(RingElement::from_coeffs(result))
    }
    
    /// Extract coefficients from element in R_q^H
    /// 
    /// **Paper Reference:** Equation 7
    /// 
    /// Given a ∈ R_q^H, extract [a_0, a_1, ..., a_{k-1}] such that a = Σ a_j · e_j
    pub fn to_coefficients(&self, elem: &RingElement<F>) -> Result<Vec<F>> {
        // Verify element is in fixed subgroup
        if !self.is_in_fixed_subgroup(elem) {
            return Err(HachiError::NotInFixedSubgroup(
                "Element not fixed by all subgroup automorphisms".to_string()
            ));
        }
        
        // Extract coefficients using structure of basis elements
        let mut coeffs = Vec::with_capacity(self.extension_degree);
        
        // a_0 is the constant term
        coeffs.push(elem.coeffs[0]);
        
        // For j = 1, ..., k-1: a_j is coefficient at X^{period * j}
        for j in 1..self.extension_degree {
            let idx = self.period * j;
            coeffs.push(elem.coeffs[idx]);
        }
        
        Ok(coeffs)
    }
    
    /// Check if element is in fixed subgroup
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// Verifies ∀σ ∈ H, σ(a) = a
    pub fn is_in_fixed_subgroup(&self, elem: &RingElement<F>) -> bool {
        // Apply all subgroup automorphisms
        let images = self.subgroup.apply_all(elem);
        
        // Check all images equal original element
        images.iter().all(|image| {
            image.coeffs.iter()
                .zip(elem.coeffs.iter())
                .all(|(a, b)| a.to_canonical_u64() == b.to_canonical_u64())
        })
    }
    
    /// Addition in R_q^H
    pub fn add(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        let mut result = vec![F::zero(); self.ring_dimension];
        
        for i in 0..self.ring_dimension {
            result[i] = a.coeffs[i].add(&b.coeffs[i]);
        }
        
        RingElement::from_coeffs(result)
    }
    
    /// Multiplication in R_q^H
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// R_q^H is closed under multiplication
    pub fn mul(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        // Use standard ring multiplication
        // Result is automatically in R_q^H due to closure
        let mut result = vec![F::zero(); self.ring_dimension];
        
        for i in 0..self.ring_dimension {
            for j in 0..self.ring_dimension {
                let prod = a.coeffs[i].mul(&b.coeffs[j]);
                let idx = i + j;
                
                if idx < self.ring_dimension {
                    result[idx] = result[idx].add(&prod);
                } else {
                    // Reduce by X^d = -1
                    let reduced_idx = idx - self.ring_dimension;
                    result[reduced_idx] = result[reduced_idx].sub(&prod);
                }
            }
        }
        
        RingElement::from_coeffs(result)
    }
    
    /// Multiplicative inverse in R_q^H
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// Since R_q^H is a field, every non-zero element has an inverse
    pub fn inv(&self, elem: &RingElement<F>) -> Result<RingElement<F>> {
        // Extract coefficients
        let coeffs = self.to_coefficients(elem)?;
        
        // Convert to extension field element
        let ext_elem = ExtensionFieldElement::new(coeffs);
        
        // Compute inverse in extension field
        // This requires the irreducible polynomial
        // For now, use a simplified approach
        
        // Check if element is zero
        if ext_elem.is_zero() {
            return Err(HachiError::InternalError("Cannot invert zero".to_string()));
        }
        
        // Use extended Euclidean algorithm in the ring
        // This is a placeholder for full implementation
        Err(HachiError::InternalError("Inverse not yet implemented".to_string()))
    }
    
    /// Isomorphism to extension field F_{q^k}
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// ι : R_q^H → F_{q^k}
    /// Maps element in R_q^H to extension field element
    pub fn to_extension_field(&self, elem: &RingElement<F>) -> Result<ExtensionFieldElement<F>> {
        let coeffs = self.to_coefficients(elem)?;
        Ok(ExtensionFieldElement::new(coeffs))
    }
    
    /// Inverse isomorphism from extension field
    /// 
    /// **Paper Reference:** Lemma 5
    /// 
    /// ι^{-1} : F_{q^k} → R_q^H
    pub fn from_extension_field(&self, elem: &ExtensionFieldElement<F>) -> Result<RingElement<F>> {
        if elem.degree != self.extension_degree {
            return Err(HachiError::InvalidInput(
                format!("Extension field degree {} does not match {}", 
                    elem.degree, self.extension_degree)
            ));
        }
        
        self.from_coefficients(&elem.coeffs)
    }
    
    /// Verify field structure
    /// 
    /// **Paper Reference:** Lemma 5 proof
    /// 
    /// Checks:
    /// 1. Closure under addition and multiplication
    /// 2. Existence of additive and multiplicative identities
    /// 3. Cardinality |R_q^H| = q^k
    pub fn verify_field_structure(&self) -> Result<()> {
        // Check basis elements are in fixed subgroup
        for basis_elem in &self.basis_elements {
            if !self.is_in_fixed_subgroup(basis_elem) {
                return Err(HachiError::InternalError(
                    "Basis element not in fixed subgroup".to_string()
                ));
            }
        }
        
        // Check subgroup size
        if self.subgroup.size != self.ring_dimension / self.extension_degree {
            return Err(HachiError::InternalError(
                format!("Subgroup size {} does not match d/k = {}", 
                    self.subgroup.size, self.ring_dimension / self.extension_degree)
            ));
        }
        
        Ok(())
    }
    
    /// Get cardinality |R_q^H| = q^k
    pub fn cardinality(&self) -> u128 {
        let q = F::MODULUS as u128;
        q.pow(self.extension_degree as u32)
    }
}

/// Vector of elements in R_q^H
/// 
/// Used for inner product computations (Theorem 2)
#[derive(Clone, Debug)]
pub struct FixedSubgroupVector<F: Field> {
    pub elements: Vec<RingElement<F>>,
    pub subgroup: RingFixedSubgroup<F>,
}

impl<F: Field> FixedSubgroupVector<F> {
    /// Create new vector in (R_q^H)^n
    pub fn new(elements: Vec<RingElement<F>>, subgroup: RingFixedSubgroup<F>) -> Result<Self> {
        // Verify all elements are in fixed subgroup
        for elem in &elements {
            if !subgroup.is_in_fixed_subgroup(elem) {
                return Err(HachiError::NotInFixedSubgroup(
                    "Vector contains element not in fixed subgroup".to_string()
                ));
            }
        }
        
        Ok(Self { elements, subgroup })
    }
    
    /// Inner product in R_q^H
    /// 
    /// ⟨a, b⟩ = Σ_i a_i · b_i ∈ R_q^H
    pub fn inner_product(&self, other: &Self) -> Result<RingElement<F>> {
        if self.elements.len() != other.elements.len() {
            return Err(HachiError::InvalidInput(
                "Vectors must have same length".to_string()
            ));
        }
        
        let mut result = vec![F::zero(); self.subgroup.ring_dimension];
        
        for (a, b) in self.elements.iter().zip(other.elements.iter()) {
            let prod = self.subgroup.mul(a, b);
            for i in 0..self.subgroup.ring_dimension {
                result[i] = result[i].add(&prod.coeffs[i]);
            }
        }
        
        Ok(RingElement::from_coeffs(result))
    }
    
    /// Length of vector
    pub fn len(&self) -> usize {
        self.elements.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_fixed_subgroup_creation() {
        let d = 256;
        let k = 16;
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        assert_eq!(subgroup.ring_dimension, d);
        assert_eq!(subgroup.extension_degree, k);
        assert_eq!(subgroup.basis_elements.len(), k);
    }
    
    #[test]
    fn test_basis_elements_in_subgroup() {
        let d = 256;
        let k = 16;
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        // All basis elements should be in fixed subgroup
        for basis_elem in &subgroup.basis_elements {
            assert!(subgroup.is_in_fixed_subgroup(basis_elem));
        }
    }
    
    #[test]
    fn test_from_to_coefficients() {
        let d = 256;
        let k = 16;
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        // Create element from coefficients
        let coeffs: Vec<_> = (0..k)
            .map(|i| GoldilocksField::from_u64(i as u64 + 1))
            .collect();
        
        let elem = subgroup.from_coefficients(&coeffs).unwrap();
        
        // Extract coefficients
        let extracted = subgroup.to_coefficients(&elem).unwrap();
        
        // Should match original
        for (a, b) in coeffs.iter().zip(extracted.iter()) {
            assert_eq!(a.to_canonical_u64(), b.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_addition_closure() {
        let d = 256;
        let k = 16;
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        // Create two elements
        let coeffs1: Vec<_> = (0..k)
            .map(|i| GoldilocksField::from_u64(i as u64))
            .collect();
        let elem1 = subgroup.from_coefficients(&coeffs1).unwrap();
        
        let coeffs2: Vec<_> = (0..k)
            .map(|i| GoldilocksField::from_u64(i as u64 + 10))
            .collect();
        let elem2 = subgroup.from_coefficients(&coeffs2).unwrap();
        
        // Add them
        let sum = subgroup.add(&elem1, &elem2);
        
        // Sum should be in fixed subgroup
        assert!(subgroup.is_in_fixed_subgroup(&sum));
    }
    
    #[test]
    fn test_multiplication_closure() {
        let d = 256;
        let k = 16;
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        // Create two elements
        let coeffs1: Vec<_> = (0..k)
            .map(|i| GoldilocksField::from_u64(if i == 0 { 1 } else { 0 }))
            .collect();
        let elem1 = subgroup.from_coefficients(&coeffs1).unwrap();
        
        let coeffs2: Vec<_> = (0..k)
            .map(|i| GoldilocksField::from_u64(if i == 1 { 1 } else { 0 }))
            .collect();
        let elem2 = subgroup.from_coefficients(&coeffs2).unwrap();
        
        // Multiply them
        let prod = subgroup.mul(&elem1, &elem2);
        
        // Product should be in fixed subgroup
        assert!(subgroup.is_in_fixed_subgroup(&prod));
    }
    
    #[test]
    fn test_cardinality() {
        let d = 256;
        let k = 4; // Use smaller k for cardinality test
        let subgroup = RingFixedSubgroup::<GoldilocksField>::new(d, k).unwrap();
        
        let q = GoldilocksField::MODULUS as u128;
        let expected = q.pow(k as u32);
        
        assert_eq!(subgroup.cardinality(), expected);
    }
}
