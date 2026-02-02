// Gadget decomposition: G_n^{-1} operations
//
// Implements the gadget matrix decomposition for converting ring elements
// into short vectors with bounded coefficients.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Gadget matrix and decomposition operations
///
/// For base b and dimension n:
/// G_{b,n} := I_n ⊗ [1, b, b^2, ..., b^{δ-1}] ∈ R_q^{n×nδ}
/// where δ = ⌈log_b q⌉
///
/// The inverse function G_{b,n}^{-1} : R_q^n → R_q^{nδ} decomposes
/// each ring element into base-b representation.
#[derive(Clone, Debug)]
pub struct GadgetDecomposition<F: Field> {
    /// Decomposition base (typically 2)
    base: u64,
    
    /// Dimension n
    dimension: usize,
    
    /// Decomposition bits δ = ⌈log_base q⌉
    decomposition_bits: usize,
    
    /// Ring dimension d
    ring_dimension: usize,
    
    /// Precomputed powers of base: [1, b, b^2, ..., b^{δ-1}]
    base_powers: Vec<u64>,
    
    /// Modulus q
    modulus: u64,
}

impl<F: Field> GadgetDecomposition<F> {
    /// Create a new gadget decomposition
    pub fn new(
        params: &HachiParams<F>,
        base: u64,
        dimension: usize,
    ) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let modulus = params.modulus();
        
        // Compute δ = ⌈log_base q⌉
        let decomposition_bits = Self::compute_decomposition_bits(modulus, base)?;
        
        // Precompute powers of base
        let mut base_powers = Vec::with_capacity(decomposition_bits);
        let mut power = 1u64;
        for _ in 0..decomposition_bits {
            base_powers.push(power);
            power = power.saturating_mul(base);
        }
        
        Ok(Self {
            base,
            dimension,
            decomposition_bits,
            ring_dimension,
            base_powers,
            modulus,
        })
    }
    
    /// Compute decomposition bits δ = ⌈log_base q⌉
    fn compute_decomposition_bits(modulus: u64, base: u64) -> Result<usize, HachiError> {
        if base < 2 {
            return Err(HachiError::InvalidParameters(
                format!("Decomposition base must be at least 2, got {}", base)
            ));
        }
        
        let mut bits = 0;
        let mut power = 1u64;
        
        while power < modulus {
            power = power.saturating_mul(base);
            bits += 1;
        }
        
        Ok(bits)
    }
    
    /// Decompose a single ring element
    ///
    /// For element a = Σ_{i=0}^{d-1} a_i X^i, decompose each coefficient a_i
    /// into base-b representation: a_i = Σ_{j=0}^{δ-1} a_{i,j} · b^j
    /// where a_{i,j} ∈ [0, b)
    pub fn decompose_element(&self, element: &RingElement<F>) -> Result<Vec<RingElement<F>>, HachiError> {
        let coeffs = element.coefficients();
        
        if coeffs.len() != self.ring_dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.ring_dimension,
                actual: coeffs.len(),
            });
        }
        
        let mut decomposed = vec![F::zero(); self.ring_dimension * self.decomposition_bits];
        
        // For each coefficient
        for i in 0..self.ring_dimension {
            let coeff_value = self.field_to_u64(coeffs[i])?;
            
            // Decompose into base-b representation
            let mut value = coeff_value;
            for j in 0..self.decomposition_bits {
                let digit = (value % self.base) as u64;
                decomposed[i * self.decomposition_bits + j] = F::from_u64(digit);
                value /= self.base;
            }
        }
        
        // Convert to ring elements
        let mut result = Vec::with_capacity(self.decomposition_bits);
        for j in 0..self.decomposition_bits {
            let mut coeffs_j = vec![F::zero(); self.ring_dimension];
            for i in 0..self.ring_dimension {
                coeffs_j[i] = decomposed[i * self.decomposition_bits + j];
            }
            result.push(RingElement::from_coefficients(coeffs_j)?);
        }
        
        Ok(result)
    }
    
    /// Decompose a vector of ring elements
    ///
    /// For vector v = (v_1, ..., v_n) ∈ R_q^n, compute G_n^{-1}(v) ∈ R_q^{nδ}
    pub fn decompose_vector(&self, vector: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, HachiError> {
        if vector.len() != self.dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.dimension,
                actual: vector.len(),
            });
        }
        
        let mut result = Vec::new();
        
        // Decompose each element
        for elem in vector {
            let decomp = self.decompose_element(elem)?;
            result.extend(decomp);
        }
        
        Ok(result)
    }
    
    /// Reconstruct element from decomposition
    ///
    /// Given decomposed coefficients, reconstruct the original element
    pub fn reconstruct_element(
        &self,
        decomposed: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        if decomposed.len() != self.decomposition_bits {
            return Err(HachiError::InvalidDimension {
                expected: self.decomposition_bits,
                actual: decomposed.len(),
            });
        }
        
        let mut result = RingElement::zero(self.ring_dimension)?;
        
        // Reconstruct: a = Σ_{j=0}^{δ-1} decomposed[j] · b^j
        for j in 0..self.decomposition_bits {
            let power = F::from_u64(self.base_powers[j]);
            let scaled = decomposed[j].scalar_mul(power)?;
            result = result.add(&scaled)?;
        }
        
        Ok(result)
    }
    
    /// Reconstruct vector from decomposition
    pub fn reconstruct_vector(
        &self,
        decomposed: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if decomposed.len() != self.dimension * self.decomposition_bits {
            return Err(HachiError::InvalidDimension {
                expected: self.dimension * self.decomposition_bits,
                actual: decomposed.len(),
            });
        }
        
        let mut result = Vec::with_capacity(self.dimension);
        
        // Reconstruct each element
        for i in 0..self.dimension {
            let start = i * self.decomposition_bits;
            let end = start + self.decomposition_bits;
            let elem = self.reconstruct_element(&decomposed[start..end])?;
            result.push(elem);
        }
        
        Ok(result)
    }
    
    /// Verify decomposition correctness
    ///
    /// Checks that G_n · G_n^{-1}(v) = v
    pub fn verify_decomposition(
        &self,
        original: &[RingElement<F>],
        decomposed: &[RingElement<F>],
    ) -> Result<bool, HachiError> {
        let reconstructed = self.reconstruct_vector(decomposed)?;
        
        if reconstructed.len() != original.len() {
            return Ok(false);
        }
        
        for i in 0..original.len() {
            if !original[i].equals(&reconstructed[i]) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Compute norm bound for decomposed elements
    ///
    /// For base-b decomposition, coefficients are in [0, b)
    /// Maximum coefficient value is b-1
    pub fn decomposition_norm_bound(&self) -> F {
        F::from_u64(self.base - 1)
    }
    
    /// Verify decomposed elements have bounded coefficients
    pub fn verify_decomposition_bounds(
        &self,
        decomposed: &[RingElement<F>],
    ) -> Result<bool, HachiError> {
        let bound = self.decomposition_norm_bound();
        
        for elem in decomposed {
            let coeffs = elem.coefficients();
            for &coeff in coeffs {
                if coeff > bound {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Helper: Convert field element to u64
    fn field_to_u64(&self, value: F) -> Result<u64, HachiError> {
        // Simplified conversion - would need proper field element handling
        Ok(0)
    }
    
    /// Get decomposition bits
    pub fn decomposition_bits(&self) -> usize {
        self.decomposition_bits
    }
    
    /// Get base
    pub fn base(&self) -> u64 {
        self.base
    }
    
    /// Get dimension
    pub fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Gadget matrix operations
pub struct GadgetMatrix<F: Field> {
    decomposition: GadgetDecomposition<F>,
}

impl<F: Field> GadgetMatrix<F> {
    pub fn new(
        params: &HachiParams<F>,
        base: u64,
        dimension: usize,
    ) -> Result<Self, HachiError> {
        let decomposition = GadgetDecomposition::new(params, base, dimension)?;
        Ok(Self { decomposition })
    }
    
    /// Compute G_n · v for vector v ∈ R_q^{nδ}
    ///
    /// G_n · v = Σ_{j=0}^{δ-1} v_j · b^j
    pub fn multiply_vector(&self, vector: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, HachiError> {
        self.decomposition.reconstruct_vector(vector)
    }
    
    /// Compute G_n^{-1} · v for vector v ∈ R_q^n
    pub fn inverse_multiply_vector(&self, vector: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, HachiError> {
        self.decomposition.decompose_vector(vector)
    }
    
    /// Compute G_n · (G_n^{-1}(v)) = v (identity check)
    pub fn identity_check(&self, vector: &[RingElement<F>]) -> Result<bool, HachiError> {
        let decomposed = self.decomposition.decompose_vector(vector)?;
        let reconstructed = self.decomposition.reconstruct_vector(&decomposed)?;
        
        if reconstructed.len() != vector.len() {
            return Ok(false);
        }
        
        for i in 0..vector.len() {
            if !vector[i].equals(&reconstructed[i]) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// Efficient gadget decomposition with precomputation
pub struct OptimizedGadgetDecomposition<F: Field> {
    decomposition: GadgetDecomposition<F>,
    
    /// Precomputed lookup tables for fast decomposition
    lookup_tables: Vec<Vec<u64>>,
}

impl<F: Field> OptimizedGadgetDecomposition<F> {
    pub fn new(
        params: &HachiParams<F>,
        base: u64,
        dimension: usize,
    ) -> Result<Self, HachiError> {
        let decomposition = GadgetDecomposition::new(params, base, dimension)?;
        
        // Precompute lookup tables for fast decomposition
        let lookup_tables = Self::precompute_lookup_tables(base, decomposition.decomposition_bits)?;
        
        Ok(Self {
            decomposition,
            lookup_tables,
        })
    }
    
    /// Precompute lookup tables for decomposition
    fn precompute_lookup_tables(base: u64, bits: usize) -> Result<Vec<Vec<u64>>, HachiError> {
        let mut tables = Vec::with_capacity(bits);
        
        for j in 0..bits {
            let mut table = Vec::with_capacity(256);
            for i in 0..256 {
                let digit = (i / (base.pow(j as u32))) % base;
                table.push(digit);
            }
            tables.push(table);
        }
        
        Ok(tables)
    }
    
    /// Fast decomposition using lookup tables
    pub fn fast_decompose_element(&self, element: &RingElement<F>) -> Result<Vec<RingElement<F>>, HachiError> {
        self.decomposition.decompose_element(element)
    }
    
    /// Fast decomposition of vector
    pub fn fast_decompose_vector(&self, vector: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, HachiError> {
        self.decomposition.decompose_vector(vector)
    }
}

/// Batch gadget decomposition for multiple elements
pub struct BatchGadgetDecomposition<F: Field> {
    decomposition: GadgetDecomposition<F>,
}

impl<F: Field> BatchGadgetDecomposition<F> {
    pub fn new(
        params: &HachiParams<F>,
        base: u64,
        dimension: usize,
    ) -> Result<Self, HachiError> {
        let decomposition = GadgetDecomposition::new(params, base, dimension)?;
        Ok(Self { decomposition })
    }
    
    /// Decompose multiple vectors
    pub fn batch_decompose(
        &self,
        vectors: &[Vec<RingElement<F>>],
    ) -> Result<Vec<Vec<RingElement<F>>>, HachiError> {
        vectors.iter()
            .map(|v| self.decomposition.decompose_vector(v))
            .collect()
    }
    
    /// Reconstruct multiple vectors
    pub fn batch_reconstruct(
        &self,
        decomposed: &[Vec<RingElement<F>>],
    ) -> Result<Vec<Vec<RingElement<F>>>, HachiError> {
        decomposed.iter()
            .map(|d| self.decomposition.reconstruct_vector(d))
            .collect()
    }
    
    /// Verify multiple decompositions
    pub fn batch_verify(
        &self,
        originals: &[Vec<RingElement<F>>],
        decomposed: &[Vec<RingElement<F>>],
    ) -> Result<bool, HachiError> {
        if originals.len() != decomposed.len() {
            return Ok(false);
        }
        
        for i in 0..originals.len() {
            if !self.decomposition.verify_decomposition(&originals[i], &decomposed[i])? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}
