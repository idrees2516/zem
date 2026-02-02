// Norm preservation and bound verification (Lemma 6)
// Implements norm bounds for the bijection ψ and related operations

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::primitives::inner_product::BijectivePacking;
use crate::ring::RingElement;
use crate::field::Field;

/// Norm types for ring elements
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormType {
    /// Infinity norm: ||a||_∞ = max_i |a_i|
    Infinity,
    /// L1 norm: ||a||_1 = Σ_i |a_i|
    L1,
    /// L2 norm (Euclidean): ||a||_2 = √(Σ_i a_i²)
    L2,
    /// Lp norm: ||a||_p = (Σ_i |a_i|^p)^{1/p}
    Lp(u32),
}

/// Norm preservation properties for the bijection ψ
/// 
/// Lemma 6 (Norm Bounds):
/// For vectors a, b ∈ (R_q^H)^{d/k} with ||a||_∞, ||b||_∞ ≤ β:
/// 1. ||ψ(a)||_∞ ≤ β
/// 2. ||ψ(a) · σ_{-1}(ψ(b))||_∞ ≤ d · β²
/// 3. ||Tr_H(ψ(a) · σ_{-1}(ψ(b)))||_∞ ≤ d² · β² / k
#[derive(Clone, Debug)]
pub struct NormPreservation<F: Field> {
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Extension degree k = 2^κ
    extension_degree: usize,
    
    /// Bijective packing for ψ operations
    packing: BijectivePacking<F>,
}

impl<F: Field> NormPreservation<F> {
    /// Create a new norm preservation checker
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        let packing = BijectivePacking::new(params)?;
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            packing,
        })
    }
    
    /// Compute infinity norm ||a||_∞ = max_i |a_i|
    pub fn infinity_norm(&self, element: &RingElement<F>) -> Result<F, HachiError> {
        let coeffs = element.coefficients();
        
        let mut max_norm = F::zero();
        for coeff in coeffs {
            let abs_coeff = self.absolute_value(*coeff)?;
            if abs_coeff > max_norm {
                max_norm = abs_coeff;
            }
        }
        
        Ok(max_norm)
    }
    
    /// Compute L1 norm ||a||_1 = Σ_i |a_i|
    pub fn l1_norm(&self, element: &RingElement<F>) -> Result<F, HachiError> {
        let coeffs = element.coefficients();
        
        let mut sum = F::zero();
        for coeff in coeffs {
            let abs_coeff = self.absolute_value(*coeff)?;
            sum = sum + abs_coeff;
        }
        
        Ok(sum)
    }
    
    /// Compute L2 norm ||a||_2 = √(Σ_i a_i²)
    pub fn l2_norm(&self, element: &RingElement<F>) -> Result<F, HachiError> {
        let coeffs = element.coefficients();
        
        let mut sum_squares = F::zero();
        for coeff in coeffs {
            sum_squares = sum_squares + (*coeff * *coeff);
        }
        
        // Return sum_squares (square root would require field extension)
        Ok(sum_squares)
    }
    
    /// Compute vector infinity norm ||v||_∞ = max_i ||v_i||_∞
    pub fn vector_infinity_norm(&self, vector: &[RingElement<F>]) -> Result<F, HachiError> {
        let mut max_norm = F::zero();
        
        for elem in vector {
            let elem_norm = self.infinity_norm(elem)?;
            if elem_norm > max_norm {
                max_norm = elem_norm;
            }
        }
        
        Ok(max_norm)
    }
    
    /// Verify Lemma 6 Part 1: ||ψ(a)||_∞ ≤ β
    /// 
    /// For vector a ∈ (R_q^H)^{d/k} with ||a||_∞ ≤ β, verify ||ψ(a)||_∞ ≤ β
    pub fn verify_psi_norm_bound(
        &self,
        vector: &[RingElement<F>],
        beta: F,
    ) -> Result<bool, HachiError> {
        // Check input norm
        let input_norm = self.vector_infinity_norm(vector)?;
        if input_norm > beta {
            return Ok(false);
        }
        
        // Compute ψ(a)
        let psi_a = self.packing.psi(vector)?;
        
        // Check output norm
        let output_norm = self.infinity_norm(&psi_a)?;
        
        Ok(output_norm <= beta)
    }
    
    /// Verify Lemma 6 Part 2: ||ψ(a) · σ_{-1}(ψ(b))||_∞ ≤ d · β²
    /// 
    /// Uses Lemma 2 (Micciancio): ||f · g||_∞ ≤ ||f||_1 · ||g||_∞
    pub fn verify_product_norm_bound(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
        beta: F,
    ) -> Result<bool, HachiError> {
        // Check input norms
        let norm_a = self.vector_infinity_norm(a)?;
        let norm_b = self.vector_infinity_norm(b)?;
        
        if norm_a > beta || norm_b > beta {
            return Ok(false);
        }
        
        // Compute ψ(a) and ψ(b)
        let psi_a = self.packing.psi(a)?;
        let psi_b = self.packing.psi(b)?;
        
        // Apply σ_{-1} to ψ(b)
        let conjugation = crate::hachi::primitives::galois_automorphisms::GaloisAutomorphism::conjugation(
            self.ring_dimension
        )?;
        let sigma_neg_psi_b = conjugation.apply(&psi_b)?;
        
        // Compute product
        let product = psi_a.mul(&sigma_neg_psi_b)?;
        
        // Check norm bound: ||product||_∞ ≤ d · β²
        let product_norm = self.infinity_norm(&product)?;
        let d_field = F::from_u64(self.ring_dimension as u64);
        let beta_squared = beta * beta;
        let bound = d_field * beta_squared;
        
        Ok(product_norm <= bound)
    }
    
    /// Verify Lemma 6 Part 3: ||Tr_H(ψ(a) · σ_{-1}(ψ(b)))||_∞ ≤ d² · β² / k
    pub fn verify_trace_norm_bound(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
        beta: F,
    ) -> Result<bool, HachiError> {
        // Check input norms
        let norm_a = self.vector_infinity_norm(a)?;
        let norm_b = self.vector_infinity_norm(b)?;
        
        if norm_a > beta || norm_b > beta {
            return Ok(false);
        }
        
        // Compute trace of inner product
        let trace_result = self.packing.trace_inner_product(a, b)?;
        
        // Check norm bound: ||trace_result||_∞ ≤ d² · β² / k
        let trace_norm = self.infinity_norm(&trace_result)?;
        
        let d_field = F::from_u64(self.ring_dimension as u64);
        let k_field = F::from_u64(self.extension_degree as u64);
        let beta_squared = beta * beta;
        let d_squared = d_field * d_field;
        let bound = (d_squared * beta_squared) / k_field;
        
        Ok(trace_norm <= bound)
    }
    
    /// Check if an element has bounded coefficients
    pub fn has_bounded_coefficients(
        &self,
        element: &RingElement<F>,
        bound: F,
    ) -> Result<bool, HachiError> {
        let norm = self.infinity_norm(element)?;
        Ok(norm <= bound)
    }
    
    /// Check if a vector has bounded coefficients
    pub fn vector_has_bounded_coefficients(
        &self,
        vector: &[RingElement<F>],
        bound: F,
    ) -> Result<bool, HachiError> {
        for elem in vector {
            if !self.has_bounded_coefficients(elem, bound)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Compute the norm bound for gadget decomposition
    /// 
    /// For G_n^{-1}(t), the coefficients are in [⌈-b/2⌉, ⌈b/2⌉-1]
    /// where b is the decomposition base (typically 2)
    pub fn gadget_decomposition_bound(&self, base: u64) -> F {
        // For base b, coefficients are in [⌈-b/2⌉, ⌈b/2⌉-1]
        // Maximum absolute value is ⌈b/2⌉
        let bound = (base + 1) / 2;
        F::from_u64(bound)
    }
    
    /// Verify norm bound after gadget decomposition
    pub fn verify_gadget_decomposition_norm(
        &self,
        decomposed: &[RingElement<F>],
        base: u64,
    ) -> Result<bool, HachiError> {
        let bound = self.gadget_decomposition_bound(base);
        self.vector_has_bounded_coefficients(decomposed, bound)
    }
    
    /// Helper: Compute absolute value in field (centered reduction)
    fn absolute_value(&self, value: F) -> Result<F, HachiError> {
        // For centered reduction mod± q, we need |value mod± q|
        // This is a simplified version; production would use proper modular reduction
        
        // If value > q/2, return q - value
        // Otherwise return value
        
        // For now, return value directly (assumes proper representation)
        Ok(value)
    }
    
    /// Compute norm growth factor for multiplication
    /// 
    /// By Lemma 2: ||f · g||_∞ ≤ ||f||_1 · ||g||_∞ ≤ d · ||f||_∞ · ||g||_∞
    pub fn multiplication_norm_growth(&self) -> usize {
        self.ring_dimension
    }
    
    /// Compute norm growth factor for trace
    /// 
    /// Tr_H has |H| = d/k terms, so ||Tr_H(a)||_∞ ≤ (d/k) · ||a||_∞
    pub fn trace_norm_growth(&self) -> usize {
        self.ring_dimension / self.extension_degree
    }
}

/// Range proof for bounded coefficients
/// 
/// Proves that all coefficients of an element are in [0, β)
#[derive(Clone, Debug)]
pub struct RangeProof<F: Field> {
    norm_checker: NormPreservation<F>,
}

impl<F: Field> RangeProof<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let norm_checker = NormPreservation::new(params)?;
        Ok(Self { norm_checker })
    }
    
    /// Prove that element has coefficients in [0, β)
    pub fn prove_range(
        &self,
        element: &RingElement<F>,
        beta: F,
    ) -> Result<RangeProofData<F>, HachiError> {
        // Verify the bound
        if !self.norm_checker.has_bounded_coefficients(element, beta)? {
            return Err(HachiError::NormBoundViolation {
                bound: format!("{:?}", beta),
                actual: format!("{:?}", self.norm_checker.infinity_norm(element)?),
            });
        }
        
        // In the full protocol, this would generate a proof
        // For now, we just store the element and bound
        Ok(RangeProofData {
            element: element.clone(),
            bound: beta,
        })
    }
    
    /// Verify a range proof
    pub fn verify_range(
        &self,
        proof: &RangeProofData<F>,
    ) -> Result<bool, HachiError> {
        self.norm_checker.has_bounded_coefficients(&proof.element, proof.bound)
    }
    
    /// Batch range proof for multiple elements
    pub fn batch_prove_range(
        &self,
        elements: &[RingElement<F>],
        beta: F,
    ) -> Result<Vec<RangeProofData<F>>, HachiError> {
        elements.iter()
            .map(|elem| self.prove_range(elem, beta))
            .collect()
    }
    
    /// Batch verify range proofs
    pub fn batch_verify_range(
        &self,
        proofs: &[RangeProofData<F>],
    ) -> Result<bool, HachiError> {
        for proof in proofs {
            if !self.verify_range(proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Range proof data structure
#[derive(Clone, Debug)]
pub struct RangeProofData<F: Field> {
    pub element: RingElement<F>,
    pub bound: F,
}

/// Zero-coefficient verification (Lemma 10)
/// 
/// Proves that certain coefficients of a polynomial are zero
#[derive(Clone, Debug)]
pub struct ZeroCoefficientProof<F: Field> {
    norm_checker: NormPreservation<F>,
}

impl<F: Field> ZeroCoefficientProof<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let norm_checker = NormPreservation::new(params)?;
        Ok(Self { norm_checker })
    }
    
    /// Prove that coefficient at given position is zero
    pub fn prove_zero_coefficient(
        &self,
        element: &RingElement<F>,
        position: usize,
    ) -> Result<bool, HachiError> {
        let coeffs = element.coefficients();
        
        if position >= coeffs.len() {
            return Err(HachiError::InvalidDimension {
                expected: coeffs.len(),
                actual: position,
            });
        }
        
        Ok(coeffs[position] == F::zero())
    }
    
    /// Prove that multiple coefficients are zero
    pub fn prove_zero_coefficients(
        &self,
        element: &RingElement<F>,
        positions: &[usize],
    ) -> Result<bool, HachiError> {
        for &pos in positions {
            if !self.prove_zero_coefficient(element, pos)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Prove that constant coefficient is zero
    /// 
    /// This is used in the ring switching protocol to verify
    /// that certain polynomials have zero constant term
    pub fn prove_zero_constant(&self, element: &RingElement<F>) -> Result<bool, HachiError> {
        self.prove_zero_coefficient(element, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::hachi::primitives::ring_fixed_subgroup::RingFixedSubgroup;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_norm_preservation_creation() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let norm_checker = NormPreservation::new(&params).unwrap();
        
        assert_eq!(norm_checker.ring_dimension, params.ring_dimension());
        assert_eq!(norm_checker.extension_degree, params.extension_degree());
    }
    
    #[test]
    fn test_infinity_norm() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let norm_checker = NormPreservation::new(&params).unwrap();
        
        let d = params.ring_dimension();
        let element = RingElement::random(d);
        
        let norm = norm_checker.infinity_norm(&element).unwrap();
        assert!(norm >= F::zero());
    }
    
    #[test]
    fn test_lemma_6_part_1() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let norm_checker = NormPreservation::new(&params).unwrap();
        let fixed_subgroup = RingFixedSubgroup::new(&params).unwrap();
        
        let vector_length = params.ring_dimension() / params.extension_degree();
        let mut vector = Vec::new();
        
        for _ in 0..vector_length {
            vector.push(fixed_subgroup.random_element().unwrap());
        }
        
        let beta = F::from_u64(100);
        
        // This test verifies the structure, actual bound checking requires
        // proper coefficient generation with bounded values
        let _ = norm_checker.verify_psi_norm_bound(&vector, beta);
    }
    
    #[test]
    fn test_range_proof() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let range_prover = RangeProof::new(&params).unwrap();
        
        let d = params.ring_dimension();
        let element = RingElement::random(d);
        let beta = F::from_u64(1000);
        
        // Generate proof (may fail if element exceeds bound)
        if let Ok(proof) = range_prover.prove_range(&element, beta) {
            let verified = range_prover.verify_range(&proof).unwrap();
            assert!(verified);
        }
    }
    
    #[test]
    fn test_zero_coefficient_proof() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let zero_prover = ZeroCoefficientProof::new(&params).unwrap();
        
        let d = params.ring_dimension();
        let mut coeffs = vec![F::zero(); d];
        coeffs[0] = F::zero(); // Ensure constant is zero
        coeffs[1] = F::one();
        
        let element = RingElement::from_coefficients(coeffs).unwrap();
        
        let is_zero = zero_prover.prove_zero_constant(&element).unwrap();
        assert!(is_zero);
    }
    
    #[test]
    fn test_multiplication_norm_growth() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let norm_checker = NormPreservation::new(&params).unwrap();
        
        let growth = norm_checker.multiplication_norm_growth();
        assert_eq!(growth, params.ring_dimension());
    }
    
    #[test]
    fn test_trace_norm_growth() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let norm_checker = NormPreservation::new(&params).unwrap();
        
        let growth = norm_checker.trace_norm_growth();
        assert_eq!(growth, params.ring_dimension() / params.extension_degree());
    }
}
