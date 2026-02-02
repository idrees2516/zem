// Quadratic reduction: multilinear to quadratic form
//
// Transforms multilinear polynomial evaluation claims into quadratic equations
// over ring elements, enabling efficient proof generation via split-and-fold.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Quadratic reduction for multilinear polynomials
///
/// For μ-variate multilinear polynomial f with μ = m + r:
/// f(X_1, ..., X_μ) = Σ_{i∈{0,1}^r} Σ_{j∈{0,1}^m} f_{i||j} · (X_1^{i_1} · ... · X_r^{i_r}) · (X_{r+1}^{j_1} · ... · X_μ^{j_m})
///
/// Rewrite as quadratic form:
/// f(x) = b^T · (a^T ⊗ I_{2^r}) · f = b^T · (a^T · (g^T ⊗ I_{2^r}) ⊗ I_{2^r}) · s
///
/// where:
/// - b = (x_1^{i_1} · ... · x_r^{i_r})_{i∈{0,1}^r} ∈ R_q^{2^r}
/// - a = (x_{r+1}^{j_1} · ... · x_μ^{j_m})_{j∈{0,1}^m} ∈ R_q^{2^m}
/// - f_i = (f_{i||j})_{j∈{0,1}^m} ∈ R_q^{2^m}
/// - s = G_{2^μ}^{-1}(f) ∈ R_q^{2^m·δ}
#[derive(Clone, Debug)]
pub struct QuadraticReduction<F: Field> {
    /// Total number of variables μ = m + r
    num_variables: usize,
    
    /// Number of outer variables r
    outer_variables: usize,
    
    /// Number of inner variables m
    inner_variables: usize,
    
    /// Ring dimension d
    ring_dimension: usize,
    
    /// Decomposition base (typically 2)
    decomposition_base: u64,
    
    /// Decomposition bits δ = ⌈log_base q⌉
    decomposition_bits: usize,
}

impl<F: Field> QuadraticReduction<F> {
    /// Create a new quadratic reduction
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        outer_variables: usize,
    ) -> Result<Self, HachiError> {
        let inner_variables = num_variables.saturating_sub(outer_variables);
        
        if outer_variables + inner_variables != num_variables {
            return Err(HachiError::InvalidParameters(
                format!("Variable split invalid: {} + {} != {}", 
                    outer_variables, inner_variables, num_variables)
            ));
        }
        
        let ring_dimension = params.ring_dimension();
        let decomposition_base = 2;
        let decomposition_bits = 64; // For Goldilocks field
        
        Ok(Self {
            num_variables,
            outer_variables,
            inner_variables,
            ring_dimension,
            decomposition_base,
            decomposition_bits,
        })
    }
    
    /// Construct outer evaluation vector b
    ///
    /// b = (x_1^{i_1} · ... · x_r^{i_r})_{i∈{0,1}^r}
    pub fn construct_outer_vector(
        &self,
        outer_point: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if outer_point.len() != self.outer_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.outer_variables,
                actual: outer_point.len(),
            });
        }
        
        let num_outer = 1 << self.outer_variables;
        let mut b = Vec::with_capacity(num_outer);
        
        // For each index i ∈ {0,1}^r
        for i in 0..num_outer {
            let mut product = RingElement::one(self.ring_dimension)?;
            
            // Compute x_1^{i_1} · ... · x_r^{i_r}
            for bit_pos in 0..self.outer_variables {
                let bit = (i >> bit_pos) & 1;
                if bit == 1 {
                    product = product.mul(&outer_point[bit_pos])?;
                }
            }
            
            b.push(product);
        }
        
        Ok(b)
    }
    
    /// Construct inner evaluation vector a
    ///
    /// a = (x_{r+1}^{j_1} · ... · x_μ^{j_m})_{j∈{0,1}^m}
    pub fn construct_inner_vector(
        &self,
        inner_point: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if inner_point.len() != self.inner_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.inner_variables,
                actual: inner_point.len(),
            });
        }
        
        let num_inner = 1 << self.inner_variables;
        let mut a = Vec::with_capacity(num_inner);
        
        // For each index j ∈ {0,1}^m
        for j in 0..num_inner {
            let mut product = RingElement::one(self.ring_dimension)?;
            
            // Compute x_{r+1}^{j_1} · ... · x_μ^{j_m}
            for bit_pos in 0..self.inner_variables {
                let bit = (j >> bit_pos) & 1;
                if bit == 1 {
                    product = product.mul(&inner_point[bit_pos])?;
                }
            }
            
            a.push(product);
        }
        
        Ok(a)
    }
    
    /// Construct coefficient matrix F
    ///
    /// F = (f_i)_{i∈{0,1}^r} where f_i = (f_{i||j})_{j∈{0,1}^m}
    pub fn construct_coefficient_matrix(
        &self,
        coefficients: &[RingElement<F>],
    ) -> Result<Vec<Vec<RingElement<F>>>, HachiError> {
        let expected_count = 1 << self.num_variables;
        if coefficients.len() != expected_count {
            return Err(HachiError::InvalidDimension {
                expected: expected_count,
                actual: coefficients.len(),
            });
        }
        
        let num_outer = 1 << self.outer_variables;
        let num_inner = 1 << self.inner_variables;
        let mut F = Vec::with_capacity(num_outer);
        
        // For each outer index i
        for i in 0..num_outer {
            let mut f_i = Vec::with_capacity(num_inner);
            
            // For each inner index j
            for j in 0..num_inner {
                let full_idx = (i << self.inner_variables) | j;
                f_i.push(coefficients[full_idx].clone());
            }
            
            F.push(f_i);
        }
        
        Ok(F)
    }
    
    /// Compute quadratic form evaluation
    ///
    /// f(x) = b^T · (a^T ⊗ I_{2^r}) · F
    pub fn evaluate_quadratic_form(
        &self,
        b: &[RingElement<F>],
        a: &[RingElement<F>],
        F: &[Vec<RingElement<F>>],
    ) -> Result<RingElement<F>, HachiError> {
        if b.len() != (1 << self.outer_variables) {
            return Err(HachiError::InvalidDimension {
                expected: 1 << self.outer_variables,
                actual: b.len(),
            });
        }
        
        if a.len() != (1 << self.inner_variables) {
            return Err(HachiError::InvalidDimension {
                expected: 1 << self.inner_variables,
                actual: a.len(),
            });
        }
        
        let mut result = RingElement::zero(self.ring_dimension)?;
        
        // Compute b^T · (a^T ⊗ I_{2^r}) · F
        // = Σ_i b_i · (Σ_j a_j · F_{i,j})
        
        for i in 0..b.len() {
            let mut inner_sum = RingElement::zero(self.ring_dimension)?;
            
            for j in 0..a.len() {
                let product = a[j].mul(&F[i][j])?;
                inner_sum = inner_sum.add(&product)?;
            }
            
            let term = b[i].mul(&inner_sum)?;
            result = result.add(&term)?;
        }
        
        Ok(result)
    }
    
    /// Construct gadget decomposition
    ///
    /// s = G_{2^μ}^{-1}(f) where f is coefficient vector
    pub fn gadget_decompose(
        &self,
        coefficients: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        let expected_count = 1 << self.num_variables;
        if coefficients.len() != expected_count {
            return Err(HachiError::InvalidDimension {
                expected: expected_count,
                actual: coefficients.len(),
            });
        }
        
        let mut decomposed = Vec::new();
        
        // For each coefficient, decompose into base-2 representation
        for coeff in coefficients {
            let decomp = self.decompose_element(coeff)?;
            decomposed.extend(decomp);
        }
        
        Ok(decomposed)
    }
    
    /// Decompose a single ring element into base-2 representation
    fn decompose_element(&self, element: &RingElement<F>) -> Result<Vec<RingElement<F>>, HachiError> {
        let coeffs = element.coefficients();
        let mut decomposed = Vec::new();
        
        // For each coefficient, decompose into bits
        for &coeff in coeffs {
            let bits = self.decompose_field_element(coeff)?;
            for bit in bits {
                let bit_elem = RingElement::from_coefficients(vec![bit])?;
                decomposed.push(bit_elem);
            }
        }
        
        Ok(decomposed)
    }
    
    /// Decompose a field element into binary representation
    fn decompose_field_element(&self, element: F) -> Result<Vec<F>, HachiError> {
        let mut bits = Vec::with_capacity(self.decomposition_bits);
        
        // Extract bits (simplified - would need proper field element handling)
        for _ in 0..self.decomposition_bits {
            bits.push(F::zero()); // Placeholder for actual bit extraction
        }
        
        Ok(bits)
    }
    
    /// Verify quadratic form relation
    ///
    /// Checks: f(x) = b^T · (a^T ⊗ I_{2^r}) · F
    pub fn verify_quadratic_form(
        &self,
        b: &[RingElement<F>],
        a: &[RingElement<F>],
        F: &[Vec<RingElement<F>>],
        claimed_value: &RingElement<F>,
    ) -> Result<bool, HachiError> {
        let computed = self.evaluate_quadratic_form(b, a, F)?;
        Ok(computed.equals(claimed_value))
    }
    
    /// Get outer variables count
    pub fn outer_variables(&self) -> usize {
        self.outer_variables
    }
    
    /// Get inner variables count
    pub fn inner_variables(&self) -> usize {
        self.inner_variables
    }
    
    /// Get decomposition bits
    pub fn decomposition_bits(&self) -> usize {
        self.decomposition_bits
    }
}

/// Mixed product computation for efficient evaluation
///
/// Implements: b^T · (a^T · (g^T ⊗ I_{2^r}) ⊗ I_{2^r}) · s
pub struct MixedProductComputation<F: Field> {
    reduction: QuadraticReduction<F>,
}

impl<F: Field> MixedProductComputation<F> {
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        outer_variables: usize,
    ) -> Result<Self, HachiError> {
        let reduction = QuadraticReduction::new(params, num_variables, outer_variables)?;
        Ok(Self { reduction })
    }
    
    /// Compute mixed product with gadget matrix
    ///
    /// Efficiently computes: b^T · (a^T · (g^T ⊗ I_{2^r}) ⊗ I_{2^r}) · s
    pub fn compute_mixed_product(
        &self,
        b: &[RingElement<F>],
        a: &[RingElement<F>],
        s: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        // Compute a^T · (g^T ⊗ I_{2^r})
        let intermediate = self.compute_intermediate_product(a, s)?;
        
        // Compute b^T · intermediate
        let mut result = RingElement::zero(self.reduction.ring_dimension)?;
        
        for i in 0..b.len() {
            let term = b[i].mul(&intermediate[i])?;
            result = result.add(&term)?;
        }
        
        Ok(result)
    }
    
    /// Compute intermediate product: a^T · (g^T ⊗ I_{2^r})
    fn compute_intermediate_product(
        &self,
        a: &[RingElement<F>],
        s: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        let num_outer = 1 << self.reduction.outer_variables;
        let mut result = vec![RingElement::zero(self.reduction.ring_dimension)?; num_outer];
        
        // For each outer index
        for i in 0..num_outer {
            let mut sum = RingElement::zero(self.reduction.ring_dimension)?;
            
            // Sum over inner indices
            for j in 0..a.len() {
                let idx = i * a.len() + j;
                if idx < s.len() {
                    let term = a[j].mul(&s[idx])?;
                    sum = sum.add(&term)?;
                }
            }
            
            result[i] = sum;
        }
        
        Ok(result)
    }
}

/// Witness structure for quadratic form
#[derive(Clone, Debug)]
pub struct QuadraticWitness<F: Field> {
    /// Decomposed witness s = G_{2^μ}^{-1}(f)
    pub decomposed: Vec<RingElement<F>>,
    
    /// Outer evaluation vector b
    pub outer_vector: Vec<RingElement<F>>,
    
    /// Inner evaluation vector a
    pub inner_vector: Vec<RingElement<F>>,
    
    /// Coefficient matrix F
    pub coefficient_matrix: Vec<Vec<RingElement<F>>>,
}

impl<F: Field> QuadraticWitness<F> {
    /// Create witness from polynomial evaluation
    pub fn from_evaluation(
        reduction: &QuadraticReduction<F>,
        coefficients: &[RingElement<F>],
        outer_point: &[RingElement<F>],
        inner_point: &[RingElement<F>],
    ) -> Result<Self, HachiError> {
        let decomposed = reduction.gadget_decompose(coefficients)?;
        let outer_vector = reduction.construct_outer_vector(outer_point)?;
        let inner_vector = reduction.construct_inner_vector(inner_point)?;
        let coefficient_matrix = reduction.construct_coefficient_matrix(coefficients)?;
        
        Ok(Self {
            decomposed,
            outer_vector,
            inner_vector,
            coefficient_matrix,
        })
    }
    
    /// Verify witness satisfies quadratic form
    pub fn verify(&self, reduction: &QuadraticReduction<F>, claimed_value: &RingElement<F>) -> Result<bool, HachiError> {
        reduction.verify_quadratic_form(
            &self.outer_vector,
            &self.inner_vector,
            &self.coefficient_matrix,
            claimed_value,
        )
    }
}
