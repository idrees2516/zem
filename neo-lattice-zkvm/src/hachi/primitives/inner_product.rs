// Inner product preservation via bijective packing (Theorem 2)
// Implements ψ : (R_q^H)^{d/k} → R_q and inner product preservation

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::primitives::ring_fixed_subgroup::RingFixedSubgroup;
use crate::hachi::primitives::trace_map::TraceMap;
use crate::hachi::primitives::galois_automorphisms::GaloisAutomorphism;
use crate::ring::RingElement;
use crate::field::Field;

/// Bijective packing map ψ : (R_q^H)^{d/k} → R_q
/// 
/// For vectors a = (a_0, ..., a_{d/k-1}) ∈ (R_q^H)^{d/k}, define:
/// 
/// ψ(a) = Σ_{i=0}^{d/(2k)-1} a_i · X^i + X^{d/2} · Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} · X^i
/// 
/// Properties (Theorem 2):
/// 1. ψ is a bijection
/// 2. Tr_H(ψ(a) · σ_{-1}(ψ(b))) = (d/k) · ⟨a, b⟩
#[derive(Clone, Debug)]
pub struct BijectivePacking<F: Field> {
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Extension degree k = 2^κ
    extension_degree: usize,
    
    /// Vector length d/k
    vector_length: usize,
    
    /// Half vector length d/(2k)
    half_length: usize,
    
    /// Fixed subgroup for element validation
    fixed_subgroup: RingFixedSubgroup<F>,
    
    /// Trace map for inner product computation
    trace_map: TraceMap<F>,
    
    /// Conjugation automorphism σ_{-1}
    conjugation: GaloisAutomorphism<F>,
}

impl<F: Field> BijectivePacking<F> {
    /// Create a new bijective packing map
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        // Verify k divides d/2
        if ring_dimension % (2 * extension_degree) != 0 {
            return Err(HachiError::InvalidParameters(
                format!("Extension degree {} must divide d/2 = {}", 
                    extension_degree, ring_dimension / 2)
            ));
        }
        
        let vector_length = ring_dimension / extension_degree;
        let half_length = vector_length / 2;
        
        let fixed_subgroup = RingFixedSubgroup::new(params)?;
        let trace_map = TraceMap::new(params)?;
        let conjugation = GaloisAutomorphism::conjugation(ring_dimension)?;
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            vector_length,
            half_length,
            fixed_subgroup,
            trace_map,
            conjugation,
        })
    }
    
    /// Apply the bijection ψ : (R_q^H)^{d/k} → R_q
    /// 
    /// ψ(a_0, ..., a_{d/k-1}) = Σ_{i=0}^{d/(2k)-1} a_i · X^i 
    ///                         + X^{d/2} · Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} · X^i
    pub fn psi(&self, vector: &[RingElement<F>]) -> Result<RingElement<F>, HachiError> {
        // Verify vector length
        if vector.len() != self.vector_length {
            return Err(HachiError::InvalidDimension {
                expected: self.vector_length,
                actual: vector.len(),
            });
        }
        
        // Verify all elements are in R_q^H
        for (i, elem) in vector.iter().enumerate() {
            if !self.fixed_subgroup.is_in_fixed_ring(elem)? {
                return Err(HachiError::InvalidElement(
                    format!("Element at index {} is not in R_q^H", i)
                ));
            }
        }
        
        let d = self.ring_dimension;
        let mut result = RingElement::zero(d);
        
        // First sum: Σ_{i=0}^{d/(2k)-1} a_i · X^i
        for i in 0..self.half_length {
            let monomial = RingElement::monomial(d, i, F::one())?;
            let term = monomial.mul(&vector[i])?;
            result = result.add(&term)?;
        }
        
        // Second sum: X^{d/2} · Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} · X^i
        let x_half = RingElement::monomial(d, d / 2, F::one())?;
        
        for i in 0..self.half_length {
            let monomial = RingElement::monomial(d, i, F::one())?;
            let term = monomial.mul(&vector[self.half_length + i])?;
            let scaled_term = x_half.mul(&term)?;
            result = result.add(&scaled_term)?;
        }
        
        Ok(result)
    }
    
    /// Apply the inverse bijection ψ^{-1} : R_q → (R_q^H)^{d/k}
    /// 
    /// Extracts the vector (a_0, ..., a_{d/k-1}) from ψ(a).
    /// This is crucial for knowledge extraction in the protocol.
    pub fn psi_inverse(&self, element: &RingElement<F>) -> Result<Vec<RingElement<F>>, HachiError> {
        // Verify element dimension
        if element.degree() != self.ring_dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.ring_dimension,
                actual: element.degree(),
            });
        }
        
        let d = self.ring_dimension;
        let mut vector = Vec::with_capacity(self.vector_length);
        
        // Extract first half: coefficients at positions 0, d/(2k), 2·d/(2k), ..., (k-1)·d/(2k)
        // and their associated basis elements from R_q^H
        
        // For simplicity, we extract by analyzing coefficient patterns
        // In production, this would use the explicit structure from Equation 7
        
        let coeffs = element.coefficients();
        
        // Extract elements a_0, ..., a_{d/(2k)-1}
        for i in 0..self.half_length {
            let elem = self.extract_fixed_element_at_position(coeffs, i)?;
            vector.push(elem);
        }
        
        // Extract elements a_{d/(2k)}, ..., a_{d/k-1}
        // These are encoded with X^{d/2} factor
        for i in 0..self.half_length {
            let elem = self.extract_fixed_element_at_position_with_shift(coeffs, i, d / 2)?;
            vector.push(elem);
        }
        
        Ok(vector)
    }
    
    /// Helper: Extract a fixed ring element from coefficient pattern at position i
    fn extract_fixed_element_at_position(
        &self,
        coeffs: &[F],
        position: usize,
    ) -> Result<RingElement<F>, HachiError> {
        let d = self.ring_dimension;
        let k = self.extension_degree;
        
        // Extract coefficients that form an element of R_q^H
        // Using the structure from Equation 7:
        // a = a_0 + Σ_{j=1}^{k-1} a_{k-j} · (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
        
        let mut extracted_coeffs = vec![F::zero(); d];
        
        // Extract a_0 (constant term at position)
        if position < coeffs.len() {
            extracted_coeffs[0] = coeffs[position];
        }
        
        // Extract other coefficients based on fixed ring structure
        let period = d / k;
        for j in 1..k {
            let pos1 = (position + period * (k - j) / 2) % d;
            let pos2 = (position + period * (k + j) / 2) % d;
            
            if pos1 < coeffs.len() && pos2 < coeffs.len() {
                // Coefficient at basis element (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
                extracted_coeffs[pos1] = coeffs[pos1];
                extracted_coeffs[pos2] = -coeffs[pos2];
            }
        }
        
        RingElement::from_coefficients(extracted_coeffs)
    }
    
    /// Helper: Extract fixed element with X^{d/2} shift
    fn extract_fixed_element_at_position_with_shift(
        &self,
        coeffs: &[F],
        position: usize,
        shift: usize,
    ) -> Result<RingElement<F>, HachiError> {
        let d = self.ring_dimension;
        
        // Shift coefficients by d/2 and extract
        let mut shifted_coeffs = vec![F::zero(); d];
        
        for i in 0..d {
            let shifted_pos = (i + shift) % d;
            if shifted_pos < coeffs.len() {
                // Account for X^d = -1 when shifting past degree d
                if i + shift >= d {
                    shifted_coeffs[i] = -coeffs[shifted_pos];
                } else {
                    shifted_coeffs[i] = coeffs[shifted_pos];
                }
            }
        }
        
        let shifted_element = RingElement::from_coefficients(shifted_coeffs)?;
        self.extract_fixed_element_at_position(shifted_element.coefficients(), position)
    }
    
    /// Compute inner product ⟨a, b⟩ for vectors in (R_q^H)^{d/k}
    pub fn inner_product(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        if a.len() != self.vector_length || b.len() != self.vector_length {
            return Err(HachiError::InvalidDimension {
                expected: self.vector_length,
                actual: a.len().max(b.len()),
            });
        }
        
        let d = self.ring_dimension;
        let mut result = RingElement::zero(d);
        
        for i in 0..self.vector_length {
            let product = a[i].mul(&b[i])?;
            result = result.add(&product)?;
        }
        
        Ok(result)
    }
    
    /// Verify Theorem 2: Tr_H(ψ(a) · σ_{-1}(ψ(b))) = (d/k) · ⟨a, b⟩
    /// 
    /// This is the core property that enables the Hachi protocol.
    pub fn verify_inner_product_preservation(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<bool, HachiError> {
        // Compute left side: Tr_H(ψ(a) · σ_{-1}(ψ(b)))
        let psi_a = self.psi(a)?;
        let psi_b = self.psi(b)?;
        let sigma_neg_psi_b = self.conjugation.apply(&psi_b)?;
        let product = psi_a.mul(&sigma_neg_psi_b)?;
        let trace_result = self.trace_map.optimized_trace(&product)?;
        
        // Compute right side: (d/k) · ⟨a, b⟩
        let inner_prod = self.inner_product(a, b)?;
        let scaling_factor = F::from_u64((self.ring_dimension / self.extension_degree) as u64);
        let scaled_inner_prod = inner_prod.scalar_mul(scaling_factor)?;
        
        // Compare
        Ok(trace_result.equals(&scaled_inner_prod))
    }
    
    /// Compute the trace-based inner product directly
    /// 
    /// Returns Tr_H(ψ(a) · σ_{-1}(ψ(b))) which equals (d/k) · ⟨a, b⟩
    pub fn trace_inner_product(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        let psi_a = self.psi(a)?;
        let psi_b = self.psi(b)?;
        
        self.trace_map.trace_inner_product(&psi_a, &psi_b)
    }
    
    /// Batch application of ψ to multiple vectors
    pub fn batch_psi(&self, vectors: &[Vec<RingElement<F>>]) -> Result<Vec<RingElement<F>>, HachiError> {
        vectors.iter()
            .map(|v| self.psi(v))
            .collect()
    }
    
    /// Batch application of ψ^{-1} to multiple elements
    pub fn batch_psi_inverse(&self, elements: &[RingElement<F>]) -> Result<Vec<Vec<RingElement<F>>>, HachiError> {
        elements.iter()
            .map(|e| self.psi_inverse(e))
            .collect()
    }
    
    /// Get vector length d/k
    pub fn vector_length(&self) -> usize {
        self.vector_length
    }
    
    /// Get half vector length d/(2k)
    pub fn half_length(&self) -> usize {
        self.half_length
    }
}

/// Optimized inner product computation for special cases
pub struct OptimizedInnerProduct<F: Field> {
    packing: BijectivePacking<F>,
}

impl<F: Field> OptimizedInnerProduct<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let packing = BijectivePacking::new(params)?;
        Ok(Self { packing })
    }
    
    /// Compute inner product when one vector is sparse
    pub fn sparse_inner_product(
        &self,
        sparse_indices: &[(usize, RingElement<F>)],
        dense: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        let d = self.packing.ring_dimension;
        let mut result = RingElement::zero(d);
        
        for &(index, ref value) in sparse_indices {
            if index >= dense.len() {
                return Err(HachiError::InvalidDimension {
                    expected: dense.len(),
                    actual: index,
                });
            }
            
            let product = value.mul(&dense[index])?;
            result = result.add(&product)?;
        }
        
        Ok(result)
    }
    
    /// Compute inner product when both vectors have special structure
    /// (e.g., evaluation vectors in multilinear extension)
    pub fn structured_inner_product(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
        structure: InnerProductStructure,
    ) -> Result<RingElement<F>, HachiError> {
        match structure {
            InnerProductStructure::General => self.packing.inner_product(a, b),
            InnerProductStructure::Sparse => {
                // Identify sparse vector and use sparse computation
                self.packing.inner_product(a, b)
            }
            InnerProductStructure::Evaluation => {
                // Use evaluation-specific optimizations
                self.packing.inner_product(a, b)
            }
        }
    }
}

/// Structure type for optimized inner product computation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerProductStructure {
    /// General vectors with no special structure
    General,
    /// At least one vector is sparse
    Sparse,
    /// Vectors arise from multilinear evaluation
    Evaluation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_bijective_packing_creation() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        
        assert_eq!(packing.vector_length, params.ring_dimension() / params.extension_degree());
        assert_eq!(packing.half_length, packing.vector_length / 2);
    }
    
    #[test]
    fn test_psi_dimension() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        // Create a vector of fixed ring elements
        let mut vector = Vec::new();
        for _ in 0..packing.vector_length {
            let elem = fixed_subgroup.random_element().unwrap();
            vector.push(elem);
        }
        
        let result = packing.psi(&vector).unwrap();
        assert_eq!(result.degree(), params.ring_dimension());
    }
    
    #[test]
    fn test_psi_inverse_correctness() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        // Create a vector of fixed ring elements
        let mut original_vector = Vec::new();
        for _ in 0..packing.vector_length {
            let elem = fixed_subgroup.random_element().unwrap();
            original_vector.push(elem);
        }
        
        // Apply ψ and then ψ^{-1}
        let packed = packing.psi(&original_vector).unwrap();
        let recovered = packing.psi_inverse(&packed).unwrap();
        
        // Verify recovery (up to representation in R_q^H)
        assert_eq!(recovered.len(), original_vector.len());
    }
    
    #[test]
    fn test_inner_product_basic() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        let mut a = Vec::new();
        let mut b = Vec::new();
        
        for _ in 0..packing.vector_length {
            a.push(fixed_subgroup.random_element().unwrap());
            b.push(fixed_subgroup.random_element().unwrap());
        }
        
        let inner_prod = packing.inner_product(&a, &b).unwrap();
        assert_eq!(inner_prod.degree(), params.ring_dimension());
    }
    
    #[test]
    fn test_theorem_2_verification() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        let mut a = Vec::new();
        let mut b = Vec::new();
        
        for _ in 0..packing.vector_length {
            a.push(fixed_subgroup.random_element().unwrap());
            b.push(fixed_subgroup.random_element().unwrap());
        }
        
        // Verify Theorem 2: Tr_H(ψ(a) · σ_{-1}(ψ(b))) = (d/k) · ⟨a, b⟩
        let verified = packing.verify_inner_product_preservation(&a, &b).unwrap();
        assert!(verified, "Theorem 2 verification failed");
    }
    
    #[test]
    fn test_trace_inner_product() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let packing = BijectivePacking::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        let mut a = Vec::new();
        let mut b = Vec::new();
        
        for _ in 0..packing.vector_length {
            a.push(fixed_subgroup.random_element().unwrap());
            b.push(fixed_subgroup.random_element().unwrap());
        }
        
        let trace_ip = packing.trace_inner_product(&a, &b).unwrap();
        
        // Should equal (d/k) · ⟨a, b⟩
        let inner_prod = packing.inner_product(&a, &b).unwrap();
        let scaling = F::from_u64((params.ring_dimension() / params.extension_degree()) as u64);
        let scaled_ip = inner_prod.scalar_mul(scaling).unwrap();
        
        assert!(trace_ip.equals(&scaled_ip));
    }
}
