// Generic transformation: F_{q^k} → R_q (Section 3.1 of paper)
//
// Transforms evaluation claims for ℓ-variate polynomials over F_{q^k}
// into equivalent claims for (ℓ - α + κ)-variate polynomials over R_q,
// where d = 2^α and k = 2^κ.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::primitives::{BijectivePacking, RingFixedSubgroup, ExtensionFieldK};
use crate::ring::RingElement;
use crate::field::Field;
use crate::polynomial::multilinear::MultilinearExtension;

/// Generic transformation for F_{q^k} polynomials
///
/// Given an ℓ-variate polynomial f over F_{q^k} and evaluation point x ∈ F_{q^k}^ℓ,
/// transforms to (ℓ - α + κ)-variate polynomial F over R_q.
///
/// Parameters:
/// - d = 2^α (ring dimension)
/// - k = 2^κ (extension degree)
/// - ℓ (number of variables in original polynomial)
///
/// Output dimension: ℓ - α + κ variables over R_q
#[derive(Clone, Debug)]
pub struct GenericTransform<F: Field> {
    /// Original number of variables
    num_variables: usize,
    
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Extension degree k = 2^κ
    extension_degree: usize,
    
    /// α = log₂(d)
    alpha: usize,
    
    /// κ = log₂(k)
    kappa: usize,
    
    /// Output number of variables: ℓ - α + κ
    output_variables: usize,
    
    /// Bijective packing ψ
    packing: BijectivePacking<F>,
    
    /// Fixed subgroup R_q^H
    fixed_subgroup: RingFixedSubgroup<F>,
    
    /// Extension field F_{q^k}
    extension_field: ExtensionFieldK<F>,
}

impl<F: Field> GenericTransform<F> {
    /// Create a new generic transformation
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
    ) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        // Compute α = log₂(d)
        let alpha = ring_dimension.trailing_zeros() as usize;
        if 1 << alpha != ring_dimension {
            return Err(HachiError::InvalidParameters(
                format!("Ring dimension {} must be a power of 2", ring_dimension)
            ));
        }
        
        // Compute κ = log₂(k)
        let kappa = extension_degree.trailing_zeros() as usize;
        if 1 << kappa != extension_degree {
            return Err(HachiError::InvalidParameters(
                format!("Extension degree {} must be a power of 2", extension_degree)
            ));
        }
        
        // Verify ℓ ≥ α - κ
        if num_variables < alpha.saturating_sub(kappa) {
            return Err(HachiError::InvalidParameters(
                format!("Number of variables {} too small for α={}, κ={}", 
                    num_variables, alpha, kappa)
            ));
        }
        
        // Compute output variables: ℓ - α + κ
        let output_variables = num_variables + kappa - alpha;
        
        let packing = BijectivePacking::new(params)?;
        let fixed_subgroup = RingFixedSubgroup::new(params)?;
        let extension_field = ExtensionFieldK::new(params)?;
        
        Ok(Self {
            num_variables,
            ring_dimension,
            extension_degree,
            alpha,
            kappa,
            output_variables,
            packing,
            fixed_subgroup,
            extension_field,
        })
    }
    
    /// Transform polynomial coefficients from F_{q^k} to R_q
    ///
    /// Given f ∈ F_{q^k}[X_1, ..., X_ℓ], construct F ∈ R_q[X_1, ..., X_{ℓ-α+κ}]
    ///
    /// Algorithm:
    /// 1. Partition variables: outer (ℓ-α+κ), inner (α-κ)
    /// 2. For each outer index i ∈ {0,1}^{ℓ-α+κ}:
    ///    - Collect inner coefficients f_{i||j} for j ∈ {0,1}^{α-κ}
    ///    - Pack into R_q^H: (f_{i||j})_j ∈ (R_q^H)^{2^{α-κ}}
    ///    - Apply ψ: F_i = ψ((f_{i||j})_j) ∈ R_q
    /// 3. Output: F = (F_i)_{i∈{0,1}^{ℓ-α+κ}}
    pub fn transform_coefficients(
        &self,
        coefficients: &[ExtensionFieldElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        // Verify coefficient count
        let expected_count = 1 << self.num_variables;
        if coefficients.len() != expected_count {
            return Err(HachiError::InvalidDimension {
                expected: expected_count,
                actual: coefficients.len(),
            });
        }
        
        let num_outer = 1 << self.output_variables;
        let num_inner = 1 << (self.alpha - self.kappa);
        
        let mut transformed = Vec::with_capacity(num_outer);
        
        // For each outer index
        for outer_idx in 0..num_outer {
            // Collect inner coefficients
            let mut inner_coeffs = Vec::with_capacity(num_inner);
            
            for inner_idx in 0..num_inner {
                // Compute full index: outer_idx || inner_idx
                let full_idx = (outer_idx << (self.alpha - self.kappa)) | inner_idx;
                
                // Convert extension field element to R_q^H element
                let ext_elem = &coefficients[full_idx];
                let ring_elem = self.extension_to_fixed_ring(ext_elem)?;
                
                inner_coeffs.push(ring_elem);
            }
            
            // Apply ψ to pack inner coefficients
            let packed = self.packing.psi(&inner_coeffs)?;
            transformed.push(packed);
        }
        
        Ok(transformed)
    }
    
    /// Transform evaluation point from F_{q^k}^ℓ to mixed domain
    ///
    /// Input: x = (x_1, ..., x_ℓ) ∈ F_{q^k}^ℓ
    /// Output: (x_outer, x_inner) where:
    /// - x_outer ∈ F_{q^k}^{ℓ-α+κ} (outer variables)
    /// - x_inner ∈ F_{q^k}^{α-κ} (inner variables)
    pub fn transform_evaluation_point(
        &self,
        point: &[ExtensionFieldElement<F>],
    ) -> Result<(Vec<ExtensionFieldElement<F>>, Vec<ExtensionFieldElement<F>>), HachiError> {
        if point.len() != self.num_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.num_variables,
                actual: point.len(),
            });
        }
        
        // Split into outer and inner
        let split_point = self.output_variables;
        let outer = point[..split_point].to_vec();
        let inner = point[split_point..].to_vec();
        
        Ok((outer, inner))
    }
    
    /// Construct evaluation vector v = ψ((x_{ℓ-α+κ+1}^{j_1} · ... · x_ℓ^{j_{α-κ}})_j)
    ///
    /// This vector is used in the trace equation:
    /// (d/k) · y = Tr_H(Y · σ_{-1}(v))
    pub fn construct_evaluation_vector(
        &self,
        inner_point: &[ExtensionFieldElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        let num_inner = 1 << (self.alpha - self.kappa);
        
        if inner_point.len() != self.alpha - self.kappa {
            return Err(HachiError::InvalidDimension {
                expected: self.alpha - self.kappa,
                actual: inner_point.len(),
            });
        }
        
        // Compute all products x_{ℓ-α+κ+1}^{j_1} · ... · x_ℓ^{j_{α-κ}}
        // for j ∈ {0,1}^{α-κ}
        let mut products = Vec::with_capacity(num_inner);
        
        for j in 0..num_inner {
            let mut product = self.extension_field.one();
            
            // For each bit position
            for bit_pos in 0..(self.alpha - self.kappa) {
                let bit = (j >> bit_pos) & 1;
                if bit == 1 {
                    product = self.extension_field.mul(&product, &inner_point[bit_pos])?;
                }
            }
            
            // Convert to R_q^H
            let ring_elem = self.extension_to_fixed_ring(&product)?;
            products.push(ring_elem);
        }
        
        // Apply ψ
        self.packing.psi(&products)
    }
    
    /// Verify evaluation equation using trace
    ///
    /// Checks: (d/k) · y = Tr_H(Y · σ_{-1}(v))
    /// where:
    /// - y is the claimed evaluation value
    /// - Y is the prover's ring element
    /// - v is the evaluation vector
    pub fn verify_trace_equation(
        &self,
        y: &ExtensionFieldElement<F>,
        Y: &RingElement<F>,
        v: &RingElement<F>,
    ) -> Result<bool, HachiError> {
        // Compute left side: (d/k) · y
        let scaling = F::from_u64((self.ring_dimension / self.extension_degree) as u64);
        let y_ring = self.extension_to_fixed_ring(y)?;
        let left_side = y_ring.scalar_mul(scaling)?;
        
        // Compute right side: Tr_H(Y · σ_{-1}(v))
        let trace_map = crate::hachi::primitives::TraceMap::new(
            &HachiParams::from_dimensions(self.ring_dimension, self.extension_degree)?
        )?;
        let right_side = trace_map.trace_inner_product(Y, v)?;
        
        Ok(left_side.equals(&right_side))
    }
    
    /// Convert extension field element to fixed ring element
    fn extension_to_fixed_ring(
        &self,
        ext_elem: &ExtensionFieldElement<F>,
    ) -> Result<RingElement<F>, HachiError> {
        self.fixed_subgroup.from_extension_field(ext_elem)
    }
    
    /// Get output number of variables
    pub fn output_variables(&self) -> usize {
        self.output_variables
    }
    
    /// Get inner variables count (α - κ)
    pub fn inner_variables(&self) -> usize {
        self.alpha - self.kappa
    }
}

/// Extension field element wrapper
/// (Placeholder - would use actual extension field implementation)
#[derive(Clone, Debug)]
pub struct ExtensionFieldElement<F: Field> {
    coefficients: Vec<F>,
}

impl<F: Field> ExtensionFieldElement<F> {
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }
    
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_generic_transform_creation() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let transform = GenericTransform::new(&params, 30).unwrap();
        
        assert_eq!(transform.num_variables, 30);
        assert!(transform.output_variables < 30);
    }
    
    #[test]
    fn test_output_variables_calculation() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let transform = GenericTransform::new(&params, 30).unwrap();
        
        // ℓ - α + κ
        let expected = 30 - transform.alpha + transform.kappa;
        assert_eq!(transform.output_variables, expected);
    }
    
    #[test]
    fn test_evaluation_point_split() {
        let params = HachiParams::<F>::new_128bit_security(30).unwrap();
        let transform = GenericTransform::new(&params, 30).unwrap();
        
        let point: Vec<_> = (0..30)
            .map(|i| ExtensionFieldElement::new(vec![F::from_u64(i as u64)]))
            .collect();
        
        let (outer, inner) = transform.transform_evaluation_point(&point).unwrap();
        
        assert_eq!(outer.len() + inner.len(), 30);
        assert_eq!(outer.len(), transform.output_variables);
        assert_eq!(inner.len(), transform.inner_variables());
    }
}
