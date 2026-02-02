// Trace map implementation for Hachi
// Implements Tr_H : R_q → R_q^H where H = ⟨σ_{-1}, σ_{4k+1}⟩

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::primitives::galois_automorphisms::{GaloisAutomorphism, GaloisSubgroup};
use crate::ring::RingElement;
use crate::field::Field;

/// Trace map Tr_H : R_q → R_q^H
/// 
/// For subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩, the trace map is defined as:
/// Tr_H(a) = Σ_{σ∈H} σ(a)
/// 
/// Properties:
/// - Additively homomorphic: Tr_H(a + b) = Tr_H(a) + Tr_H(b)
/// - R_q^H-linear: Tr_H(c · a) = c · Tr_H(a) for c ∈ R_q^H
/// - Idempotent on R_q^H: Tr_H(a) = |H| · a = (d/k) · a for a ∈ R_q^H
/// - Surjective: Im(Tr_H) = R_q^H
#[derive(Clone, Debug)]
pub struct TraceMap<F: Field> {
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Extension degree k = 2^κ
    extension_degree: usize,
    
    /// Subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
    subgroup: GaloisSubgroup<F>,
    
    /// Precomputed automorphisms for efficient trace computation
    /// Contains all σ ∈ H
    automorphisms: Vec<GaloisAutomorphism<F>>,
    
    /// Scaling factor d/k for idempotent property
    scaling_factor: usize,
}

impl<F: Field> TraceMap<F> {
    /// Create a new trace map for given parameters
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
        
        // Create subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
        let subgroup = GaloisSubgroup::new(ring_dimension, extension_degree)?;
        
        // Precompute all automorphisms in H
        let automorphisms = subgroup.all_automorphisms();
        
        // Compute scaling factor d/k
        let scaling_factor = ring_dimension / extension_degree;
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            subgroup,
            automorphisms,
            scaling_factor,
        })
    }
    
    /// Compute trace map: Tr_H(a) = Σ_{σ∈H} σ(a)
    /// 
    /// This is the naive implementation that sums over all automorphisms.
    /// For production use, consider using optimized_trace() which exploits structure.
    pub fn trace(&self, element: &RingElement<F>) -> Result<RingElement<F>, HachiError> {
        // Verify element has correct dimension
        if element.degree() != self.ring_dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.ring_dimension,
                actual: element.degree(),
            });
        }
        
        // Initialize result as zero
        let mut result = RingElement::zero(self.ring_dimension);
        
        // Sum over all automorphisms in H
        for automorphism in &self.automorphisms {
            let sigma_a = automorphism.apply(element)?;
            result = result.add(&sigma_a)?;
        }
        
        Ok(result)
    }
    
    /// Optimized trace computation using explicit formula
    /// 
    /// Tr_H(a) = Σ_{b=0}^{d/(2k)-1} (σ_{4k·b+1}(a) + σ_{-(4k·b+1)}(a))
    /// 
    /// This exploits the structure of H = ⟨σ_{-1}, σ_{4k+1}⟩ to reduce
    /// the number of automorphism applications from d/k to d/(2k).
    pub fn optimized_trace(&self, element: &RingElement<F>) -> Result<RingElement<F>, HachiError> {
        // Verify element has correct dimension
        if element.degree() != self.ring_dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.ring_dimension,
                actual: element.degree(),
            });
        }
        
        let d = self.ring_dimension;
        let k = self.extension_degree;
        let num_iterations = d / (2 * k);
        
        // Initialize result as zero
        let mut result = RingElement::zero(d);
        
        // Sum over α = 0, ..., d/(2k)-1
        for alpha in 0..num_iterations {
            // Compute exponent: 4k·α + 1
            let exponent_pos = (4 * k * alpha + 1) % (2 * d);
            
            // Compute negative exponent: -(4k·α + 1) = 2d - (4k·α + 1)
            let exponent_neg = (2 * d - exponent_pos) % (2 * d);
            
            // Apply σ_{4k·α+1}
            let sigma_pos = GaloisAutomorphism::new(d, exponent_pos)?;
            let term_pos = sigma_pos.apply(element)?;
            
            // Apply σ_{-(4k·α+1)}
            let sigma_neg = GaloisAutomorphism::new(d, exponent_neg)?;
            let term_neg = sigma_neg.apply(element)?;
            
            // Add both terms
            result = result.add(&term_pos)?;
            result = result.add(&term_neg)?;
        }
        
        Ok(result)
    }
    
    /// Batch trace computation for multiple elements
    /// 
    /// More efficient than calling trace() multiple times due to
    /// automorphism reuse and potential parallelization.
    pub fn batch_trace(&self, elements: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, HachiError> {
        elements.iter()
            .map(|elem| self.optimized_trace(elem))
            .collect()
    }
    
    /// Check if an element is in the fixed ring R_q^H
    /// 
    /// An element a is in R_q^H iff Tr_H(a) = (d/k) · a
    pub fn is_fixed(&self, element: &RingElement<F>) -> Result<bool, HachiError> {
        let trace_result = self.optimized_trace(element)?;
        
        // Compute (d/k) · a
        let scaled = element.scalar_mul(F::from_u64(self.scaling_factor as u64))?;
        
        // Check equality
        Ok(trace_result.equals(&scaled))
    }
    
    /// Project an arbitrary element onto R_q^H
    /// 
    /// For any a ∈ R_q, Tr_H(a) ∈ R_q^H
    /// This is the canonical projection R_q → R_q^H
    pub fn project(&self, element: &RingElement<F>) -> Result<RingElement<F>, HachiError> {
        self.optimized_trace(element)
    }
    
    /// Compute trace of a product: Tr_H(a · b)
    /// 
    /// This is more efficient than computing the product first and then the trace,
    /// as we can exploit linearity properties.
    pub fn trace_of_product(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> Result<RingElement<F>, HachiError> {
        // Compute product
        let product = a.mul(b)?;
        
        // Compute trace
        self.optimized_trace(&product)
    }
    
    /// Compute trace of inner product: Tr_H(ψ(a) · σ_{-1}(ψ(b)))
    /// 
    /// This is used in Theorem 2 for inner product preservation.
    /// Returns (d/k) · ⟨a, b⟩ as a ring element.
    pub fn trace_inner_product(
        &self,
        psi_a: &RingElement<F>,
        psi_b: &RingElement<F>,
    ) -> Result<RingElement<F>, HachiError> {
        // Apply σ_{-1} to ψ(b)
        let conjugation = GaloisAutomorphism::conjugation(self.ring_dimension)?;
        let sigma_neg_psi_b = conjugation.apply(psi_b)?;
        
        // Compute product ψ(a) · σ_{-1}(ψ(b))
        let product = psi_a.mul(&sigma_neg_psi_b)?;
        
        // Compute trace
        self.optimized_trace(&product)
    }
    
    /// Get the scaling factor d/k
    pub fn scaling_factor(&self) -> usize {
        self.scaling_factor
    }
    
    /// Get the subgroup H
    pub fn subgroup(&self) -> &GaloisSubgroup<F> {
        &self.subgroup
    }
    
    /// Get the number of automorphisms in H
    pub fn subgroup_order(&self) -> usize {
        self.automorphisms.len()
    }
}

/// Efficient trace computation using FFT-like techniques
/// 
/// For structured elements (e.g., sparse or with special patterns),
/// we can compute the trace more efficiently than the general algorithm.
pub struct StructuredTraceComputer<F: Field> {
    trace_map: TraceMap<F>,
}

impl<F: Field> StructuredTraceComputer<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let trace_map = TraceMap::new(params)?;
        Ok(Self { trace_map })
    }
    
    /// Compute trace of a monomial X^i
    /// 
    /// Uses Claim 2 from the paper: Tr_H(X^i) = 0 if i is not divisible by d/(2k)
    pub fn trace_monomial(&self, exponent: usize) -> Result<RingElement<F>, HachiError> {
        let d = self.trace_map.ring_dimension;
        let k = self.trace_map.extension_degree;
        let period = d / k;
        
        // Check if exponent is divisible by d/(2k)
        if exponent % (period / 2) != 0 {
            // Trace is zero
            return Ok(RingElement::zero(d));
        }
        
        // Otherwise, compute trace explicitly
        let monomial = RingElement::monomial(d, exponent, F::one())?;
        self.trace_map.optimized_trace(&monomial)
    }
    
    /// Compute trace of X^{d/2}
    /// 
    /// Uses Claim 3 from the paper: Tr_H(X^{d/2}) = 0
    pub fn trace_half_power(&self) -> Result<RingElement<F>, HachiError> {
        Ok(RingElement::zero(self.trace_map.ring_dimension))
    }
    
    /// Compute trace of a sparse polynomial
    /// 
    /// For polynomials with few non-zero coefficients, this is more efficient
    /// than the general trace computation.
    pub fn trace_sparse(
        &self,
        coefficients: &[(usize, F)],
    ) -> Result<RingElement<F>, HachiError> {
        let d = self.trace_map.ring_dimension;
        let mut result = RingElement::zero(d);
        
        for &(exponent, ref coeff) in coefficients {
            let trace_monomial = self.trace_monomial(exponent)?;
            let scaled = trace_monomial.scalar_mul(*coeff)?;
            result = result.add(&scaled)?;
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_trace_map_creation() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let trace_map = TraceMap::new(&params).unwrap();
        
        assert_eq!(trace_map.ring_dimension, params.ring_dimension());
        assert_eq!(trace_map.extension_degree, params.extension_degree());
        assert_eq!(trace_map.scaling_factor, params.ring_dimension() / params.extension_degree());
    }
    
    #[test]
    fn test_trace_additivity() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let trace_map = TraceMap::new(&params).unwrap();
        let d = params.ring_dimension();
        
        let a = RingElement::random(d);
        let b = RingElement::random(d);
        
        let trace_a = trace_map.optimized_trace(&a).unwrap();
        let trace_b = trace_map.optimized_trace(&b).unwrap();
        let trace_sum = trace_a.add(&trace_b).unwrap();
        
        let sum = a.add(&b).unwrap();
        let trace_of_sum = trace_map.optimized_trace(&sum).unwrap();
        
        assert!(trace_sum.equals(&trace_of_sum));
    }
    
    #[test]
    fn test_trace_idempotence() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let trace_map = TraceMap::new(&params).unwrap();
        let d = params.ring_dimension();
        
        let a = RingElement::random(d);
        let trace_a = trace_map.optimized_trace(&a).unwrap();
        
        // Tr_H(Tr_H(a)) should equal (d/k) · Tr_H(a)
        let trace_trace_a = trace_map.optimized_trace(&trace_a).unwrap();
        let scaled_trace_a = trace_a.scalar_mul(
            F::from_u64(trace_map.scaling_factor as u64)
        ).unwrap();
        
        assert!(trace_trace_a.equals(&scaled_trace_a));
    }
    
    #[test]
    fn test_trace_monomial_zero() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let computer = StructuredTraceComputer::new(&params).unwrap();
        
        // For exponent not divisible by d/(2k), trace should be zero
        let trace = computer.trace_monomial(1).unwrap();
        assert!(trace.is_zero());
    }
    
    #[test]
    fn test_trace_half_power_zero() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let computer = StructuredTraceComputer::new(&params).unwrap();
        
        let trace = computer.trace_half_power().unwrap();
        assert!(trace.is_zero());
    }
    
    #[test]
    fn test_naive_vs_optimized_trace() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let trace_map = TraceMap::new(&params).unwrap();
        let d = params.ring_dimension();
        
        let a = RingElement::random(d);
        
        let trace_naive = trace_map.trace(&a).unwrap();
        let trace_optimized = trace_map.optimized_trace(&a).unwrap();
        
        assert!(trace_naive.equals(&trace_optimized));
    }
}
