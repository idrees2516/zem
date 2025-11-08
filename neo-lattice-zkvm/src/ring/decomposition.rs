// Norm decomposition for approximate range proofs
// Implements decomposition H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g)
// Per Symphony paper Eq. (33) and Section 3.4
//
// Also implements HyperWolf gadget matrix decomposition
// Gadget vector: g⃗_a = (1, a, a², ..., a^{ι-1}) where ι = ⌈log_a q⌉
// Gadget matrix: G_{a,m} = I_m ⊗ g⃗_a ∈ Z_q^{m×ιm}
// Decomposition: G^{-1}_{a,m}(A) = Ã such that A = G_{a,m}·Ã

use crate::field::Field;
use super::{RingElement, ExponentialMap};

/// Norm decomposition parameters
#[derive(Clone, Debug)]
pub struct DecompositionParams {
    /// Ring degree d
    pub degree: usize,
    /// Base d' = d - 2
    pub d_prime: usize,
    /// Number of decomposition levels k_g
    pub k_g: usize,
    /// Norm bound B
    pub bound_b: f64,
    /// Decomposition bound B_{d,k_g}
    pub b_decomp: f64,
}

impl DecompositionParams {
    /// Compute k_g as minimal integer s.t. B_{d,k_g} ≥ 9.5B
    /// where B_{d,k_g} := (d'/2)·(1 + d' + ... + d'^{k_g-1})
    pub fn compute_k_g(degree: usize, bound_b: f64) -> usize {
        let d_prime = degree - 2;
        let target = 9.5 * bound_b;
        
        let mut k_g = 1;
        loop {
            let b_decomp = Self::compute_b_decomp(d_prime, k_g);
            if b_decomp >= target {
                return k_g;
            }
            k_g += 1;
            
            // Safety check to prevent infinite loop
            if k_g > 100 {
                panic!("k_g computation did not converge");
            }
        }
    }
    
    /// Compute B_{d,k_g} := (d'/2)·(1 + d' + ... + d'^{k_g-1})
    /// This is a geometric series: (d'/2)·(d'^k_g - 1)/(d' - 1)
    fn compute_b_decomp(d_prime: usize, k_g: usize) -> f64 {
        let d_prime_f = d_prime as f64;
        
        if d_prime == 1 {
            // Special case: geometric series becomes k_g/2
            (k_g as f64) / 2.0
        } else {
            // General case: (d'/2)·(d'^k_g - 1)/(d' - 1)
            let numerator = d_prime_f / 2.0 * (d_prime_f.powi(k_g as i32) - 1.0);
            let denominator = d_prime_f - 1.0;
            numerator / denominator
        }
    }
    
    /// Create decomposition parameters
    pub fn new(degree: usize, bound_b: f64) -> Self {
        let d_prime = degree - 2;
        let k_g = Self::compute_k_g(degree, bound_b);
        let b_decomp = Self::compute_b_decomp(d_prime, k_g);
        
        Self {
            degree,
            d_prime,
            k_g,
            bound_b,
            b_decomp,
        }
    }
    
    /// Verify B_{d,k_g} ≥ 9.5B
    pub fn verify_bound(&self) -> bool {
        self.b_decomp >= 9.5 * self.bound_b
    }
    
    /// Compute relaxed norm bound B' = 16B_{d,k_g}/√30
    /// Per Theorem 3.1 of Symphony paper
    pub fn relaxed_bound(&self) -> f64 {
        16.0 * self.b_decomp / (30.0_f64).sqrt()
    }
}

/// Norm decomposition result
/// H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g)
#[derive(Clone, Debug)]
pub struct NormDecomposition {
    /// Decomposed matrices H^(i) ∈ Z_q^{m×d}
    pub components: Vec<Vec<Vec<i64>>>,
    /// Number of components k_g
    pub k_g: usize,
    /// Decomposition parameters
    pub params: DecompositionParams,
}

impl NormDecomposition {
    /// Decompose projected matrix H into k_g components
    /// Ensures ∥H^(i)∥_∞ ≤ d'/2 for all i ∈ [k_g]
    pub fn decompose(
        projected: &[Vec<i64>],
        params: DecompositionParams,
    ) -> Result<Self, String> {
        let m = projected.len();
        let d = if m > 0 { projected[0].len() } else { 0 };
        
        let mut components = Vec::with_capacity(params.k_g);
        let d_prime = params.d_prime as i64;
        let half_d_prime = d_prime / 2;
        
        // Initialize components
        for _ in 0..params.k_g {
            components.push(vec![vec![0i64; d]; m]);
        }
        
        // Decompose each element of H
        for i in 0..m {
            for j in 0..d {
                let mut value = projected[i][j];
                
                // Decompose value in base d'
                for k in 0..params.k_g {
                    // Extract digit in range [-d'/2, d'/2]
                    let digit = Self::extract_digit(value, d_prime);
                    
                    if digit.abs() > half_d_prime {
                        return Err(format!(
                            "Digit {} exceeds bound d'/2 = {}",
                            digit, half_d_prime
                        ));
                    }
                    
                    components[k][i][j] = digit;
                    
                    // Update value for next digit
                    value = (value - digit) / d_prime;
                }
                
                // Verify complete decomposition
                if value != 0 {
                    return Err(format!(
                        "Incomplete decomposition: residual value {}",
                        value
                    ));
                }
            }
        }
        
        // Verify norm bounds
        for (k, component) in components.iter().enumerate() {
            let norm = Self::infinity_norm(component);
            if norm > half_d_prime {
                return Err(format!(
                    "Component {} has norm {} > d'/2 = {}",
                    k, norm, half_d_prime
                ));
            }
        }
        
        Ok(Self {
            components,
            k_g: params.k_g,
            params,
        })
    }
    
    /// Extract digit in balanced representation
    /// Returns value in range [-d'/2, d'/2]
    fn extract_digit(value: i64, d_prime: i64) -> i64 {
        let remainder = value % d_prime;
        
        // Convert to balanced representation
        if remainder > d_prime / 2 {
            remainder - d_prime
        } else if remainder < -(d_prime / 2) {
            remainder + d_prime
        } else {
            remainder
        }
    }
    
    /// Compute infinity norm of matrix
    fn infinity_norm(matrix: &[Vec<i64>]) -> i64 {
        matrix
            .iter()
            .flat_map(|row| row.iter())
            .map(|&val| val.abs())
            .max()
            .unwrap_or(0)
    }
    
    /// Flatten matrix H^(i) to vector h^(i) := flt(H^(i)) ∈ Z_q^{md}
    pub fn flatten_component(&self, component_idx: usize) -> Vec<i64> {
        assert!(component_idx < self.k_g, "Component index out of range");
        
        self.components[component_idx]
            .iter()
            .flat_map(|row| row.iter().copied())
            .collect()
    }
    
    /// Compute monomial vectors g^(i) := Exp(h^(i)) ∈ M^n
    /// where n = md (flattened dimension)
    pub fn compute_monomial_vectors<F: Field>(&self) -> Vec<Vec<RingElement<F>>> {
        let exp_map = ExponentialMap::<F>::new(self.params.degree);
        
        let mut monomial_vectors = Vec::with_capacity(self.k_g);
        
        for k in 0..self.k_g {
            let flattened = self.flatten_component(k);
            
            // Convert each value to monomial
            let monomials: Vec<RingElement<F>> = flattened
                .iter()
                .map(|&val| exp_map.exp(val))
                .collect();
            
            monomial_vectors.push(monomials);
        }
        
        monomial_vectors
    }
    
    /// Verify decomposition correctness
    /// Check: H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g)
    pub fn verify_decomposition(&self, original: &[Vec<i64>]) -> bool {
        let m = original.len();
        let d = if m > 0 { original[0].len() } else { 0 };
        
        for i in 0..m {
            for j in 0..d {
                let mut reconstructed = 0i64;
                let mut power = 1i64;
                
                for k in 0..self.k_g {
                    reconstructed += self.components[k][i][j] * power;
                    power *= self.params.d_prime as i64;
                }
                
                if reconstructed != original[i][j] {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Get component H^(i)
    pub fn get_component(&self, index: usize) -> &[Vec<i64>] {
        &self.components[index]
    }
    
    /// Get all components
    pub fn get_all_components(&self) -> &[Vec<Vec<i64>>] {
        &self.components
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_compute_k_g() {
        let degree = 64;
        let bound_b = 100.0;
        
        let k_g = DecompositionParams::compute_k_g(degree, bound_b);
        
        // Verify B_{d,k_g} ≥ 9.5B
        let d_prime = degree - 2;
        let b_decomp = DecompositionParams::compute_b_decomp(d_prime, k_g);
        assert!(b_decomp >= 9.5 * bound_b);
        
        // Verify minimality: k_g - 1 should not satisfy the bound
        if k_g > 1 {
            let b_decomp_minus_1 = DecompositionParams::compute_b_decomp(d_prime, k_g - 1);
            assert!(b_decomp_minus_1 < 9.5 * bound_b);
        }
    }
    
    #[test]
    fn test_decomposition_params() {
        let params = DecompositionParams::new(64, 100.0);
        
        assert_eq!(params.degree, 64);
        assert_eq!(params.d_prime, 62);
        assert!(params.k_g > 0);
        assert!(params.verify_bound());
        
        // Verify relaxed bound
        let relaxed = params.relaxed_bound();
        assert!(relaxed > 0.0);
    }
    
    #[test]
    fn test_extract_digit() {
        let d_prime = 62;
        
        // Test positive value
        let digit = NormDecomposition::extract_digit(100, d_prime);
        assert!(digit >= -(d_prime / 2) && digit <= d_prime / 2);
        
        // Test negative value
        let digit = NormDecomposition::extract_digit(-100, d_prime);
        assert!(digit >= -(d_prime / 2) && digit <= d_prime / 2);
        
        // Test zero
        let digit = NormDecomposition::extract_digit(0, d_prime);
        assert_eq!(digit, 0);
    }
    
    #[test]
    fn test_decompose_simple() {
        let projected = vec![
            vec![100, 200, 50],
            vec![-150, 75, -25],
        ];
        
        let params = DecompositionParams::new(64, 100.0);
        let decomp = NormDecomposition::decompose(&projected, params).unwrap();
        
        assert_eq!(decomp.k_g, params.k_g);
        assert_eq!(decomp.components.len(), params.k_g);
        
        // Verify each component has correct dimensions
        for component in &decomp.components {
            assert_eq!(component.len(), 2); // m = 2
            assert_eq!(component[0].len(), 3); // d = 3
        }
        
        // Verify norm bounds
        for component in &decomp.components {
            let norm = NormDecomposition::infinity_norm(component);
            assert!(norm <= params.d_prime as i64 / 2);
        }
    }
    
    #[test]
    fn test_verify_decomposition() {
        let projected = vec![
            vec![50, 100, -75],
        ];
        
        let params = DecompositionParams::new(64, 50.0);
        let decomp = NormDecomposition::decompose(&projected, params).unwrap();
        
        // Verify decomposition is correct
        assert!(decomp.verify_decomposition(&projected));
    }
    
    #[test]
    fn test_flatten_component() {
        let projected = vec![
            vec![10, 20],
            vec![30, 40],
        ];
        
        let params = DecompositionParams::new(64, 50.0);
        let decomp = NormDecomposition::decompose(&projected, params).unwrap();
        
        let flattened = decomp.flatten_component(0);
        
        // Should flatten row by row
        assert_eq!(flattened.len(), 4); // 2 rows × 2 cols
    }
    
    #[test]
    fn test_compute_monomial_vectors() {
        let projected = vec![
            vec![5, -10],
        ];
        
        let params = DecompositionParams::new(64, 50.0);
        let decomp = NormDecomposition::decompose(&projected, params).unwrap();
        
        let monomial_vectors = decomp.compute_monomial_vectors::<GoldilocksField>();
        
        assert_eq!(monomial_vectors.len(), params.k_g);
        
        // Each monomial vector should have md elements
        for monomials in &monomial_vectors {
            assert_eq!(monomials.len(), 2); // m=1, d=2, so md=2
        }
    }
    
    #[test]
    fn test_infinity_norm() {
        let matrix = vec![
            vec![1, -5, 3],
            vec![2, 10, -7],
        ];
        
        let norm = NormDecomposition::infinity_norm(&matrix);
        assert_eq!(norm, 10);
    }
    
    #[test]
    fn test_decomposition_with_large_values() {
        let projected = vec![
            vec![1000, -2000, 500],
        ];
        
        let params = DecompositionParams::new(64, 1000.0);
        let decomp = NormDecomposition::decompose(&projected, params).unwrap();
        
        // Verify decomposition
        assert!(decomp.verify_decomposition(&projected));
        
        // Verify all components have bounded norm
        for component in &decomp.components {
            let norm = NormDecomposition::infinity_norm(component);
            assert!(norm <= params.d_prime as i64 / 2);
        }
    }
    
    #[test]
    fn test_b_decomp_computation() {
        let d_prime = 62;
        let k_g = 3;
        
        let b_decomp = DecompositionParams::compute_b_decomp(d_prime, k_g);
        
        // Manual calculation: (62/2)·(1 + 62 + 62²) = 31·(1 + 62 + 3844) = 31·3907 = 121117
        let expected = 31.0 * (1.0 + 62.0 + 62.0 * 62.0);
        assert!((b_decomp - expected).abs() < 1.0);
    }
}


// ============================================================================
// HyperWolf Gadget Matrix Decomposition
// ============================================================================

/// Gadget decomposition parameters for HyperWolf PCS
/// Implements G^{-1}_{a,m} decomposition where a is the basis
#[derive(Clone, Debug)]
pub struct GadgetParams {
    /// Decomposition basis a ∈ {4, 16} for HyperWolf
    pub basis: u64,
    /// Decomposition length ι = ⌈log_a q⌉
    pub iota: usize,
    /// Field modulus q
    pub modulus: u64,
    /// Dimension m (number of rows)
    pub dimension: usize,
}

impl GadgetParams {
    /// Create gadget parameters for given basis and modulus
    /// 
    /// # Arguments
    /// * `basis` - Decomposition basis a ∈ {4, 16}
    /// * `modulus` - Field modulus q
    /// * `dimension` - Matrix dimension m
    /// 
    /// # Returns
    /// Gadget parameters with computed ι = ⌈log_a q⌉
    pub fn new(basis: u64, modulus: u64, dimension: usize) -> Result<Self, String> {
        if basis != 4 && basis != 16 {
            return Err(format!("Basis must be 4 or 16, got {}", basis));
        }
        
        if modulus == 0 {
            return Err("Modulus must be non-zero".to_string());
        }
        
        // Compute ι = ⌈log_a q⌉
        let iota = Self::compute_iota(basis, modulus);
        
        Ok(Self {
            basis,
            iota,
            modulus,
            dimension,
        })
    }
    
    /// Compute ι = ⌈log_a q⌉
    fn compute_iota(basis: u64, modulus: u64) -> usize {
        let log_a_q = (modulus as f64).log(basis as f64);
        log_a_q.ceil() as usize
    }
    
    /// Generate gadget vector g⃗_a = (1, a, a², ..., a^{ι-1})
    pub fn gadget_vector<F: Field>(&self) -> Vec<F> {
        let mut gadget = Vec::with_capacity(self.iota);
        let mut power = 1u64;
        
        for _ in 0..self.iota {
            gadget.push(F::from_u64(power % self.modulus));
            power = (power * self.basis) % self.modulus;
        }
        
        gadget
    }
    
    /// Generate gadget matrix G_{a,m} = I_m ⊗ g⃗_a ∈ Z_q^{m×ιm}
    /// Returns matrix as Vec<Vec<F>> where outer vec is rows
    pub fn gadget_matrix<F: Field>(&self) -> Vec<Vec<F>> {
        let gadget_vec = self.gadget_vector::<F>();
        let mut matrix = vec![vec![F::zero(); self.iota * self.dimension]; self.dimension];
        
        // Kronecker product I_m ⊗ g⃗_a
        for i in 0..self.dimension {
            for j in 0..self.iota {
                matrix[i][i * self.iota + j] = gadget_vec[j];
            }
        }
        
        matrix
    }
    
    /// Compute norm bound for decomposed elements
    /// For basis a and length ι, ∥Ãᵢ∥ ≤ √(a²ιm)
    pub fn norm_bound(&self) -> f64 {
        let a_squared = (self.basis * self.basis) as f64;
        let iota_m = (self.iota * self.dimension) as f64;
        (a_squared * iota_m).sqrt()
    }
}

/// Gadget decomposition result
/// For matrix A ∈ R_q^{m×n}, computes Ã = G^{-1}_{a,m}(A) ∈ R_q^{ιm×n}
/// such that A = G_{a,m}·Ã
#[derive(Clone, Debug)]
pub struct GadgetDecomposition<F: Field> {
    /// Decomposed matrix Ã ∈ R_q^{ιm×n}
    pub decomposed: Vec<Vec<RingElement<F>>>,
    /// Gadget parameters
    pub params: GadgetParams,
}

impl<F: Field> GadgetDecomposition<F> {
    /// Decompose matrix A ∈ R_q^{m×n} into Ã = G^{-1}_{a,m}(A)
    /// 
    /// # Arguments
    /// * `matrix` - Input matrix A ∈ R_q^{m×n}
    /// * `params` - Gadget parameters
    /// 
    /// # Returns
    /// Decomposed matrix Ã ∈ R_q^{ιm×n} such that A = G_{a,m}·Ã
    pub fn decompose(
        matrix: Vec<Vec<RingElement<F>>>,
        params: GadgetParams,
    ) -> Result<Self, String> {
        let m = matrix.len();
        let n = if m > 0 { matrix[0].len() } else { 0 };
        
        if m != params.dimension {
            return Err(format!(
                "Matrix dimension {} does not match params dimension {}",
                m, params.dimension
            ));
        }
        
        // Decompose each row of A
        let mut decomposed = Vec::with_capacity(params.iota * m);
        
        for row in matrix {
            // Decompose each element in the row
            let decomposed_row = Self::decompose_row(&row, &params)?;
            decomposed.extend(decomposed_row);
        }
        
        Ok(Self {
            decomposed,
            params,
        })
    }
    
    /// Decompose a single row of ring elements
    /// For row (r_0, ..., r_{n-1}), produces ι rows where each element is decomposed
    fn decompose_row(
        row: &[RingElement<F>],
        params: &GadgetParams,
    ) -> Result<Vec<Vec<RingElement<F>>>, String> {
        let n = row.len();
        let mut result = vec![vec![]; params.iota];
        
        // Decompose each ring element in the row
        for ring_elem in row {
            let decomposed_elem = Self::decompose_ring_element(ring_elem, params)?;
            
            // Add decomposed coefficients to corresponding rows
            for (i, coeff_ring) in decomposed_elem.into_iter().enumerate() {
                result[i].push(coeff_ring);
            }
        }
        
        Ok(result)
    }
    
    /// Decompose a single ring element r ∈ R_q into ι ring elements
    /// Each coefficient of r is decomposed in base a
    fn decompose_ring_element(
        ring_elem: &RingElement<F>,
        params: &GadgetParams,
    ) -> Result<Vec<RingElement<F>>, String> {
        let d = ring_elem.coeffs.len();
        let mut decomposed = vec![vec![F::zero(); d]; params.iota];
        
        // Decompose each coefficient
        for (j, coeff) in ring_elem.coeffs.iter().enumerate() {
            let coeff_val = coeff.to_canonical_u64();
            let digits = Self::decompose_coefficient(coeff_val, params)?;
            
            // Assign digits to decomposed ring elements
            for (i, digit) in digits.into_iter().enumerate() {
                decomposed[i][j] = digit;
            }
        }
        
        // Convert to ring elements
        let result: Vec<RingElement<F>> = decomposed
            .into_iter()
            .map(|coeffs| RingElement::from_coeffs(coeffs))
            .collect();
        
        Ok(result)
    }
    
    /// Decompose a single coefficient in base a
    /// Returns ι digits where value = Σᵢ digitsᵢ·a^i
    fn decompose_coefficient(
        value: u64,
        params: &GadgetParams,
    ) -> Result<Vec<F>, String> {
        let mut digits = Vec::with_capacity(params.iota);
        let mut remaining = value;
        
        for _ in 0..params.iota {
            let digit = remaining % params.basis;
            digits.push(F::from_u64(digit));
            remaining /= params.basis;
        }
        
        // Verify complete decomposition
        if remaining != 0 {
            return Err(format!(
                "Incomplete decomposition: residual value {}",
                remaining
            ));
        }
        
        Ok(digits)
    }
    
    /// Verify decomposition: check that A = G_{a,m}·Ã
    pub fn verify(&self, original: &[Vec<RingElement<F>>], ring: &super::CyclotomicRing<F>) -> bool {
        let m = original.len();
        let n = if m > 0 { original[0].len() } else { 0 };
        
        // Compute G_{a,m}·Ã
        let gadget_matrix = self.params.gadget_matrix::<F>();
        
        for i in 0..m {
            for j in 0..n {
                // Compute (G_{a,m}·Ã)[i][j]
                let mut sum = ring.zero();
                
                for k in 0..self.params.iota {
                    let row_idx = i * self.params.iota + k;
                    let gadget_coeff = gadget_matrix[i][row_idx];
                    
                    // Multiply gadget coefficient by decomposed element
                    let term = ring.scalar_mul(&gadget_coeff, &self.decomposed[row_idx][j]);
                    sum = ring.add(&sum, &term);
                }
                
                // Check if sum equals original element
                if sum.coeffs != original[i][j].coeffs {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Get decomposed matrix dimensions (ιm × n)
    pub fn dimensions(&self) -> (usize, usize) {
        let rows = self.decomposed.len();
        let cols = if rows > 0 { self.decomposed[0].len() } else { 0 };
        (rows, cols)
    }
    
    /// Compute norm bound: ∥Ãᵢ∥ ≤ √(a²ιm)
    pub fn norm_bound(&self) -> f64 {
        self.params.norm_bound()
    }
}

/// Decompose a vector of ring elements
/// For vector s⃗ ∈ R_q^n, computes G^{-1}_{a,n}(s⃗) ∈ R_q^{ιn}
pub fn decompose_vector<F: Field>(
    vector: Vec<RingElement<F>>,
    params: &GadgetParams,
) -> Result<Vec<RingElement<F>>, String> {
    let n = vector.len();
    let mut result = Vec::with_capacity(params.iota * n);
    
    // Decompose each ring element
    for ring_elem in vector {
        let decomposed = GadgetDecomposition::decompose_ring_element(&ring_elem, params)?;
        result.extend(decomposed);
    }
    
    Ok(result)
}

#[cfg(test)]
mod gadget_tests {
    use super::*;
    use crate::field::GoldilocksField;
    use super::super::CyclotomicRing;
    
    #[test]
    fn test_gadget_params_creation() {
        let params = GadgetParams::new(4, 1_000_000, 2).unwrap();
        
        assert_eq!(params.basis, 4);
        assert_eq!(params.dimension, 2);
        assert!(params.iota > 0);
        
        // Verify ι = ⌈log_4 1000000⌉
        let expected_iota = (1_000_000f64.log(4.0)).ceil() as usize;
        assert_eq!(params.iota, expected_iota);
    }
    
    #[test]
    fn test_gadget_vector() {
        let params = GadgetParams::new(4, 256, 1).unwrap();
        let gadget: Vec<GoldilocksField> = params.gadget_vector();
        
        // For basis 4 and modulus 256, ι = ⌈log_4 256⌉ = 4
        // Gadget vector should be (1, 4, 16, 64)
        assert_eq!(gadget.len(), 4);
        assert_eq!(gadget[0].to_canonical_u64(), 1);
        assert_eq!(gadget[1].to_canonical_u64(), 4);
        assert_eq!(gadget[2].to_canonical_u64(), 16);
        assert_eq!(gadget[3].to_canonical_u64(), 64);
    }
    
    #[test]
    fn test_gadget_matrix() {
        let params = GadgetParams::new(4, 256, 2).unwrap();
        let matrix: Vec<Vec<GoldilocksField>> = params.gadget_matrix();
        
        // Matrix should be 2 × 8 (m × ιm where m=2, ι=4)
        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].len(), 8);
        
        // First row should be (1, 4, 16, 64, 0, 0, 0, 0)
        assert_eq!(matrix[0][0].to_canonical_u64(), 1);
        assert_eq!(matrix[0][1].to_canonical_u64(), 4);
        assert_eq!(matrix[0][2].to_canonical_u64(), 16);
        assert_eq!(matrix[0][3].to_canonical_u64(), 64);
        assert_eq!(matrix[0][4].to_canonical_u64(), 0);
        
        // Second row should be (0, 0, 0, 0, 1, 4, 16, 64)
        assert_eq!(matrix[1][4].to_canonical_u64(), 1);
        assert_eq!(matrix[1][5].to_canonical_u64(), 4);
        assert_eq!(matrix[1][6].to_canonical_u64(), 16);
        assert_eq!(matrix[1][7].to_canonical_u64(), 64);
    }
    
    #[test]
    fn test_decompose_coefficient() {
        let params = GadgetParams::new(4, 256, 1).unwrap();
        
        // Decompose 100 in base 4
        // 100 = 0·1 + 1·4 + 2·16 + 1·64 = 0 + 4 + 32 + 64 = 100
        let digits: Vec<GoldilocksField> = 
            GadgetDecomposition::decompose_coefficient(100, &params).unwrap();
        
        assert_eq!(digits.len(), 4);
        assert_eq!(digits[0].to_canonical_u64(), 0); // 100 % 4 = 0
        assert_eq!(digits[1].to_canonical_u64(), 1); // 25 % 4 = 1
        assert_eq!(digits[2].to_canonical_u64(), 2); // 6 % 4 = 2
        assert_eq!(digits[3].to_canonical_u64(), 1); // 1 % 4 = 1
        
        // Verify reconstruction
        let reconstructed = digits[0].to_canonical_u64() +
                           digits[1].to_canonical_u64() * 4 +
                           digits[2].to_canonical_u64() * 16 +
                           digits[3].to_canonical_u64() * 64;
        assert_eq!(reconstructed, 100);
    }
    
    #[test]
    fn test_decompose_ring_element() {
        let params = GadgetParams::new(4, 256, 1).unwrap();
        
        // Create ring element with coefficients (5, 10, 0, ...)
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(5);
        coeffs[1] = GoldilocksField::from_u64(10);
        let ring_elem = RingElement::from_coeffs(coeffs);
        
        let decomposed = GadgetDecomposition::decompose_ring_element(&ring_elem, &params).unwrap();
        
        // Should have ι = 4 decomposed ring elements
        assert_eq!(decomposed.len(), 4);
        
        // Each should have 64 coefficients
        for elem in &decomposed {
            assert_eq!(elem.coeffs.len(), 64);
        }
        
        // Verify first coefficient decomposition (5 in base 4 = 1 + 1·4)
        assert_eq!(decomposed[0].coeffs[0].to_canonical_u64(), 1);
        assert_eq!(decomposed[1].coeffs[0].to_canonical_u64(), 1);
        assert_eq!(decomposed[2].coeffs[0].to_canonical_u64(), 0);
        assert_eq!(decomposed[3].coeffs[0].to_canonical_u64(), 0);
    }
    
    #[test]
    fn test_decompose_vector() {
        let params = GadgetParams::new(4, 256, 1).unwrap();
        
        // Create vector of 2 ring elements
        let mut coeffs1 = vec![GoldilocksField::zero(); 64];
        coeffs1[0] = GoldilocksField::from_u64(5);
        let elem1 = RingElement::from_coeffs(coeffs1);
        
        let mut coeffs2 = vec![GoldilocksField::zero(); 64];
        coeffs2[0] = GoldilocksField::from_u64(10);
        let elem2 = RingElement::from_coeffs(coeffs2);
        
        let vector = vec![elem1, elem2];
        
        let decomposed = decompose_vector(vector, &params).unwrap();
        
        // Should have 2 * ι = 2 * 4 = 8 elements
        assert_eq!(decomposed.len(), 8);
    }
    
    #[test]
    fn test_gadget_decomposition_matrix() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let params = GadgetParams::new(4, 256, 2).unwrap();
        
        // Create 2×2 matrix of ring elements
        let mut matrix = Vec::new();
        for i in 0..2 {
            let mut row = Vec::new();
            for j in 0..2 {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64((i * 2 + j + 1) as u64 * 10);
                row.push(RingElement::from_coeffs(coeffs));
            }
            matrix.push(row);
        }
        
        let decomposed = GadgetDecomposition::decompose(matrix.clone(), params).unwrap();
        
        // Decomposed matrix should be 8×2 (ιm × n where ι=4, m=2, n=2)
        let (rows, cols) = decomposed.dimensions();
        assert_eq!(rows, 8);
        assert_eq!(cols, 2);
        
        // Verify decomposition
        assert!(decomposed.verify(&matrix, &ring));
    }
    
    #[test]
    fn test_norm_bound() {
        let params = GadgetParams::new(4, 256, 2).unwrap();
        
        let bound = params.norm_bound();
        
        // For basis 4, ι=4, m=2: √(16 * 4 * 2) = √128 ≈ 11.31
        assert!(bound > 11.0 && bound < 12.0);
    }
    
    #[test]
    fn test_basis_16() {
        let params = GadgetParams::new(16, 65536, 1).unwrap();
        
        // For basis 16 and modulus 65536, ι = ⌈log_16 65536⌉ = 4
        assert_eq!(params.iota, 4);
        
        let gadget: Vec<GoldilocksField> = params.gadget_vector();
        
        // Gadget vector should be (1, 16, 256, 4096)
        assert_eq!(gadget[0].to_canonical_u64(), 1);
        assert_eq!(gadget[1].to_canonical_u64(), 16);
        assert_eq!(gadget[2].to_canonical_u64(), 256);
        assert_eq!(gadget[3].to_canonical_u64(), 4096);
    }
}
