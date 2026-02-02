// Optimized F_q polynomial case (Section 3.2 of paper)
//
// When polynomial coefficients are in F_q but evaluation points are in F_{q^k},
// we can use a more efficient transformation that reduces from (ℓ - α + κ)-variate
// to (ℓ - α)-variate polynomials over R_q.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::primitives::{BijectivePacking, RingFixedSubgroup, ExtensionFieldK};
use crate::ring::RingElement;
use crate::field::Field;

/// Optimized transformation for F_q polynomials evaluated at F_{q^k} points
///
/// Given:
/// - f ∈ F_q[X_1, ..., X_ℓ] (polynomial with F_q coefficients)
/// - x ∈ F_{q^k}^ℓ (evaluation point in extension field)
///
/// Computes:
/// - Partial evaluations y_i ∈ F_{q^k} for i ∈ {0,1}^κ
/// - Aggregated polynomial f' ∈ F_{q^k}[Z, X_{κ+1}, ..., X_ℓ]
/// - Reduces to (ℓ - α)-variate polynomial over R_q
///
/// Advantage: One fewer variable than generic transform (ℓ - α vs ℓ - α + κ)
#[derive(Clone, Debug)]
pub struct OptimizedFqTransform<F: Field> {
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Extension degree k = 2^κ
    extension_degree: usize,
    
    /// κ = log₂(k)
    kappa: usize,
    
    /// α = log₂(d)
    alpha: usize,
    
    /// Number of variables in original polynomial
    num_variables: usize,
    
    /// Output number of variables: ℓ - α
    output_variables: usize,
    
    /// Bijective packing ψ
    packing: BijectivePacking<F>,
    
    /// Fixed subgroup R_q^H
    fixed_subgroup: RingFixedSubgroup<F>,
    
    /// Extension field F_{q^k}
    extension_field: ExtensionFieldK<F>,
}

impl<F: Field> OptimizedFqTransform<F> {
    /// Create a new optimized F_q transformation
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
        
        // Verify ℓ ≥ α
        if num_variables < alpha {
            return Err(HachiError::InvalidParameters(
                format!("Number of variables {} must be at least α={}", num_variables, alpha)
            ));
        }
        
        // Output variables: ℓ - α (one fewer than generic transform)
        let output_variables = num_variables - alpha;
        
        let packing = BijectivePacking::new(params)?;
        let fixed_subgroup = RingFixedSubgroup::new(params)?;
        let extension_field = ExtensionFieldK::new(params)?;
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            kappa,
            alpha,
            num_variables,
            output_variables,
            packing,
            fixed_subgroup,
            extension_field,
        })
    }
    
    /// Compute partial evaluations y_i for i ∈ {0,1}^κ
    ///
    /// For polynomial f ∈ F_q[X_1, ..., X_ℓ] and evaluation point x ∈ F_{q^k}^ℓ:
    /// y_i := f(x_1^{i_1}, ..., x_κ^{i_κ}, x_{κ+1}, ..., x_ℓ)
    ///
    /// where i = (i_1, ..., i_κ) ∈ {0,1}^κ
    pub fn compute_partial_evaluations(
        &self,
        coefficients: &[F],
        evaluation_point: &[ExtensionFieldElement<F>],
    ) -> Result<Vec<ExtensionFieldElement<F>>, HachiError> {
        // Verify dimensions
        let expected_coeff_count = 1 << self.num_variables;
        if coefficients.len() != expected_coeff_count {
            return Err(HachiError::InvalidDimension {
                expected: expected_coeff_count,
                actual: coefficients.len(),
            });
        }
        
        if evaluation_point.len() != self.num_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.num_variables,
                actual: evaluation_point.len(),
            });
        }
        
        let num_partial = 1 << self.kappa;
        let mut partial_evals = Vec::with_capacity(num_partial);
        
        // For each partial index i ∈ {0,1}^κ
        for i in 0..num_partial {
            // Compute y_i = f(x_1^{i_1}, ..., x_κ^{i_κ}, x_{κ+1}, ..., x_ℓ)
            let mut partial_point = Vec::with_capacity(self.num_variables);
            
            // First κ coordinates: x_j^{i_j}
            for j in 0..self.kappa {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    partial_point.push(evaluation_point[j].clone());
                } else {
                    partial_point.push(ExtensionFieldElement::one());
                }
            }
            
            // Remaining coordinates: x_{κ+1}, ..., x_ℓ
            for j in self.kappa..self.num_variables {
                partial_point.push(evaluation_point[j].clone());
            }
            
            // Evaluate polynomial at partial point
            let y_i = self.evaluate_polynomial(coefficients, &partial_point)?;
            partial_evals.push(y_i);
        }
        
        Ok(partial_evals)
    }
    
    /// Evaluate F_q polynomial at given point in F_{q^k}
    fn evaluate_polynomial(
        &self,
        coefficients: &[F],
        point: &[ExtensionFieldElement<F>],
    ) -> Result<ExtensionFieldElement<F>, HachiError> {
        if point.len() != self.num_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.num_variables,
                actual: point.len(),
            });
        }
        
        let mut result = ExtensionFieldElement::zero();
        
        // Evaluate using Horner's method for efficiency
        // Process coefficients in reverse order
        for (index, &coeff) in coefficients.iter().enumerate().rev() {
            // Convert index to binary representation
            let mut binary = Vec::with_capacity(self.num_variables);
            let mut idx = index;
            for _ in 0..self.num_variables {
                binary.push((idx & 1) as u32);
                idx >>= 1;
            }
            
            // Compute monomial: x_1^{b_1} · ... · x_ℓ^{b_ℓ}
            let mut monomial = ExtensionFieldElement::one();
            for j in 0..self.num_variables {
                if binary[j] == 1 {
                    monomial = self.extension_field.mul(&monomial, &point[j])?;
                }
            }
            
            // Scale by coefficient
            let scaled = self.extension_field.scalar_mul(&monomial, coeff)?;
            
            // Add to result
            result = self.extension_field.add(&result, &scaled)?;
        }
        
        Ok(result)
    }
    
    /// Construct aggregated polynomial f' ∈ F_{q^k}[Z, X_{κ+1}, ..., X_ℓ]
    ///
    /// f'(Z, X_{κ+1}, ..., X_ℓ) := Σ_{i∈{0,1}^κ} f_i(X_{κ+1}, ..., X_ℓ) · Z^{Σ_{t=1}^κ i_t·2^{t-1}}
    ///
    /// where f_i(X_{κ+1}, ..., X_ℓ) := f(X_1^{i_1}, ..., X_κ^{i_κ}, X_{κ+1}, ..., X_ℓ)
    pub fn construct_aggregated_polynomial(
        &self,
        coefficients: &[F],
    ) -> Result<Vec<ExtensionFieldElement<F>>, HachiError> {
        let num_partial = 1 << self.kappa;
        let num_remaining = 1 << (self.num_variables - self.kappa);
        let output_size = num_partial * num_remaining;
        
        let mut aggregated = vec![ExtensionFieldElement::zero(); output_size];
        
        // For each coefficient in original polynomial
        for (orig_idx, &coeff) in coefficients.iter().enumerate() {
            // Extract partial index i and remaining index j
            let i = orig_idx & ((1 << self.kappa) - 1);
            let j = orig_idx >> self.kappa;
            
            // Compute power of Z: Z^{Σ_{t=1}^κ i_t·2^{t-1}}
            let z_power = self.compute_z_power(i);
            
            // Position in aggregated polynomial: z_power * num_remaining + j
            let agg_idx = z_power * num_remaining + j;
            
            // Add coefficient to aggregated polynomial
            let coeff_ext = ExtensionFieldElement::from_base_field(coeff);
            aggregated[agg_idx] = self.extension_field.add(
                &aggregated[agg_idx],
                &coeff_ext,
            )?;
        }
        
        Ok(aggregated)
    }
    
    /// Compute Z power: Σ_{t=1}^κ i_t·2^{t-1}
    fn compute_z_power(&self, i: usize) -> usize {
        let mut power = 0;
        for t in 0..self.kappa {
            let bit = (i >> t) & 1;
            power += bit << t;
        }
        power
    }
    
    /// Transform evaluation claim using partial evaluations
    ///
    /// Given:
    /// - Partial evaluations y_i for i ∈ {0,1}^κ
    /// - Evaluation point x ∈ F_{q^k}^ℓ
    ///
    /// Constructs:
    /// - Aggregated polynomial f' ∈ F_{q^k}[Z, X_{κ+1}, ..., X_ℓ]
    /// - Evaluation claim: f'(x_1, ..., x_κ, x_{κ+1}, ..., x_ℓ) = y
    pub fn transform_evaluation_claim(
        &self,
        partial_evals: &[ExtensionFieldElement<F>],
        evaluation_point: &[ExtensionFieldElement<F>],
    ) -> Result<(Vec<ExtensionFieldElement<F>>, ExtensionFieldElement<F>), HachiError> {
        if partial_evals.len() != (1 << self.kappa) {
            return Err(HachiError::InvalidDimension {
                expected: 1 << self.kappa,
                actual: partial_evals.len(),
            });
        }
        
        if evaluation_point.len() != self.num_variables {
            return Err(HachiError::InvalidDimension {
                expected: self.num_variables,
                actual: evaluation_point.len(),
            });
        }
        
        // Compute aggregated evaluation
        let mut aggregated_eval = ExtensionFieldElement::zero();
        
        for i in 0..partial_evals.len() {
            // Compute Z^{Σ_{t=1}^κ i_t·2^{t-1}}
            let z_power = self.compute_z_power(i);
            
            // Compute x_1^{z_power} (where x_1 is first coordinate)
            let mut x_power = ExtensionFieldElement::one();
            for _ in 0..z_power {
                x_power = self.extension_field.mul(&x_power, &evaluation_point[0])?;
            }
            
            // Add y_i · x_1^{z_power}
            let term = self.extension_field.mul(&partial_evals[i], &x_power)?;
            aggregated_eval = self.extension_field.add(&aggregated_eval, &term)?;
        }
        
        // Construct aggregated polynomial coefficients
        let aggregated_poly = self.construct_aggregated_polynomial(&[])?;
        
        Ok((aggregated_poly, aggregated_eval))
    }
    
    /// Reduce to (ℓ - α)-variate polynomial over R_q
    ///
    /// Takes aggregated polynomial f' ∈ F_{q^k}[Z, X_{κ+1}, ..., X_ℓ]
    /// and transforms to (ℓ - α)-variate polynomial over R_q
    pub fn reduce_to_ring_polynomial(
        &self,
        aggregated_coefficients: &[ExtensionFieldElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        let num_output_coeffs = 1 << self.output_variables;
        
        if aggregated_coefficients.len() != (1 << (self.kappa + self.num_variables - self.kappa)) {
            return Err(HachiError::InvalidDimension {
                expected: 1 << (self.kappa + self.num_variables - self.kappa),
                actual: aggregated_coefficients.len(),
            });
        }
        
        let mut ring_coefficients = Vec::with_capacity(num_output_coeffs);
        
        // For each output coefficient
        for out_idx in 0..num_output_coeffs {
            // Collect extension field elements for this output coefficient
            let mut ext_elements = Vec::new();
            
            for z_power in 0..(1 << self.kappa) {
                let agg_idx = z_power * num_output_coeffs + out_idx;
                if agg_idx < aggregated_coefficients.len() {
                    ext_elements.push(aggregated_coefficients[agg_idx].clone());
                }
            }
            
            // Convert to fixed ring element
            let ring_elem = self.fixed_subgroup.from_extension_field_vector(&ext_elements)?;
            ring_coefficients.push(ring_elem);
        }
        
        Ok(ring_coefficients)
    }
    
    /// Get output number of variables
    pub fn output_variables(&self) -> usize {
        self.output_variables
    }
    
    /// Get number of partial evaluations
    pub fn num_partial_evaluations(&self) -> usize {
        1 << self.kappa
    }
}

/// Extension field element wrapper
#[derive(Clone, Debug)]
pub struct ExtensionFieldElement<F: Field> {
    coefficients: Vec<F>,
}

impl<F: Field> ExtensionFieldElement<F> {
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }
    
    pub fn zero() -> Self {
        Self { coefficients: vec![F::zero()] }
    }
    
    pub fn one() -> Self {
        Self { coefficients: vec![F::one()] }
    }
    
    pub fn from_base_field(value: F) -> Self {
        Self { coefficients: vec![value] }
    }
    
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }
    
    pub fn clone(&self) -> Self {
        Self { coefficients: self.coefficients.clone() }
    }
}

/// Extension field operations wrapper
#[derive(Clone, Debug)]
pub struct ExtensionFieldOps<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ExtensionFieldOps<F> {
    pub fn add(
        &self,
        a: &ExtensionFieldElement<F>,
        b: &ExtensionFieldElement<F>,
    ) -> Result<ExtensionFieldElement<F>, HachiError> {
        let max_len = a.coefficients.len().max(b.coefficients.len());
        let mut result = vec![F::zero(); max_len];
        
        for i in 0..a.coefficients.len() {
            result[i] = result[i] + a.coefficients[i];
        }
        
        for i in 0..b.coefficients.len() {
            result[i] = result[i] + b.coefficients[i];
        }
        
        Ok(ExtensionFieldElement::new(result))
    }
    
    pub fn mul(
        &self,
        a: &ExtensionFieldElement<F>,
        b: &ExtensionFieldElement<F>,
    ) -> Result<ExtensionFieldElement<F>, HachiError> {
        let result_len = a.coefficients.len() + b.coefficients.len() - 1;
        let mut result = vec![F::zero(); result_len];
        
        for i in 0..a.coefficients.len() {
            for j in 0..b.coefficients.len() {
                result[i + j] = result[i + j] + (a.coefficients[i] * b.coefficients[j]);
            }
        }
        
        Ok(ExtensionFieldElement::new(result))
    }
    
    pub fn scalar_mul(
        &self,
        a: &ExtensionFieldElement<F>,
        scalar: F,
    ) -> Result<ExtensionFieldElement<F>, HachiError> {
        let result: Vec<F> = a.coefficients.iter().map(|c| *c * scalar).collect();
        Ok(ExtensionFieldElement::new(result))
    }
}
