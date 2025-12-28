// Low-Degree Extension (LDE) for SALSAA
//
// Mathematical Background:
// - LDE extends a vector w ∈ K^{d^µ} to a multivariate polynomial LDE[w]: K^µ → K
// - The polynomial has individual degree d-1 in each of µ variables
// - Interpolation property: LDE[w](z) = w_z for all z ∈ [d]^µ (grid points)
// - Uniqueness: LDE[w] is the unique polynomial satisfying interpolation
//
// Construction (Lagrange Interpolation):
// For w^T = (w_z)_{z∈[d]^µ}, define:
// LDE[w](X_0, ..., X_{µ-1}) = Σ_{z∈[d]^µ} w_z · ∏_{j∈[µ]} L_j(X_j, z_j)
// where L_j(X_j, z_j) = ∏_{k∈[d]\{z_j}} (X_j - k)/(z_j - k) is Lagrange basis
//
// Evaluation Formula (Lemma 1):
// For any r ∈ K^µ, we have:
// LDE[w](r) = ⟨r̃, w⟩ = r̃^T · w
// where r̃ ∈ K^{d^µ} is the Lagrange basis vector:
// r̃^T = ⊗_{j∈[µ]} (∏_{k'∈[d]\{k}} (r_j - k')/(k - k'))_{k∈[d]}
//
// Tensor Structure:
// The Lagrange basis r̃ has tensor structure:
// r̃ = r̃_0 ⊗ r̃_1 ⊗ ... ⊗ r̃_{µ-1}
// where r̃_j ∈ K^d is the univariate Lagrange basis for variable j
//
// Matrix Extension:
// For W ∈ K^{d^µ×r} (matrix with r columns), define:
// LDE[W]: K^µ → K^r by LDE[W](r) = (LDE[w_0](r), ..., LDE[w_{r-1}](r))
// where w_i is the i-th column of W
//
// Applications in SALSAA:
// 1. Norm-check: Express ∥w∥²_{σ,2} = Σ_{z∈[d]^µ} |LDE[w](z)|²
// 2. Sumcheck: Verify Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t
// 3. Evaluation claims: Prove LDE[W](r) = s for verifier challenge r
//
// Complexity:
// - Construction: O(d^µ) to store coefficients (not computed explicitly)
// - Evaluation: O(d·µ) ring operations via Lagrange basis
// - Lagrange basis: O(d·µ) field operations
//
// Reference: SALSAA paper Section 2.4, Lemma 1, Requirements 4.1, 4.2

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use std::sync::Arc;

/// Low-degree extension context
/// Manages parameters for LDE construction and evaluation
pub struct LDEContext<F: Field> {
    /// Degree bound per variable (d)
    pub degree: usize,
    
    /// Number of variables (µ)
    pub num_vars: usize,
    
    /// Total witness size (d^µ)
    pub witness_size: usize,
    
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Precomputed Lagrange denominators for efficiency
    /// lagrange_denoms[j][k] = ∏_{k'∈[d]\{k}} (k - k')
    lagrange_denoms: Vec<Vec<F>>,
}

impl<F: Field> LDEContext<F> {
    /// Create new LDE context
    ///
    /// Parameters:
    /// - degree: d, the degree bound per variable (polynomial has degree d-1)
    /// - num_vars: µ, the number of variables
    /// - ring: cyclotomic ring for arithmetic
    ///
    /// Precomputes:
    /// - Lagrange denominators for fast evaluation
    /// - Witness size d^µ
    ///
    /// Complexity: O(d²·µ) preprocessing
    pub fn new(degree: usize, num_vars: usize, ring: Arc<CyclotomicRing<F>>) -> Self {
        assert!(degree > 0, "Degree must be positive");
        assert!(num_vars > 0, "Number of variables must be positive");
        
        let witness_size = degree.pow(num_vars as u32);
        
        // Precompute Lagrange denominators
        // For each variable j and each point k ∈ [d]:
        // denom[j][k] = ∏_{k'∈[d]\{k}} (k - k')
        let lagrange_denoms = Self::precompute_lagrange_denominators(degree, num_vars);
        
        Self {
            degree,
            num_vars,
            witness_size,
            ring,
            lagrange_denoms,
        }
    }
    
    /// Precompute Lagrange denominators for all variables and points
    ///
    /// Mathematical: For variable j and point k ∈ [d]:
    /// denom[j][k] = ∏_{k'∈[d]\{k}} (k - k')
    ///
    /// These are used in Lagrange basis computation:
    /// L_j(X_j, k) = ∏_{k'∈[d]\{k}} (X_j - k')/(k - k')
    ///
    /// Complexity: O(d²·µ)
    fn precompute_lagrange_denominators(degree: usize, num_vars: usize) -> Vec<Vec<F>> {
        let mut denoms = Vec::with_capacity(num_vars);
        
        for _ in 0..num_vars {
            let mut var_denoms = Vec::with_capacity(degree);
            
            for k in 0..degree {
                // Compute ∏_{k'∈[d]\{k}} (k - k')
                let mut denom = F::one();
                
                for k_prime in 0..degree {
                    if k_prime != k {
                        // (k - k') in field
                        let k_field = F::from_u64(k as u64);
                        let k_prime_field = F::from_u64(k_prime as u64);
                        let diff = k_field.sub(&k_prime_field);
                        denom = denom.mul(&diff);
                    }
                }
                
                var_denoms.push(denom);
            }
            
            denoms.push(var_denoms);
        }
        
        denoms
    }
    
    /// Compute Lagrange coefficient for single variable
    ///
    /// Mathematical: L_j(x_j, k) = ∏_{k'∈[d]\{k}} (x_j - k')/(k - k')
    ///
    /// This is the Lagrange basis polynomial for variable j evaluated at x_j,
    /// corresponding to grid point k.
    ///
    /// Properties:
    /// - L_j(k, k) = 1
    /// - L_j(k', k) = 0 for k' ≠ k, k' ∈ [d]
    /// - Σ_{k∈[d]} L_j(x_j, k) = 1 for all x_j (partition of unity)
    ///
    /// Complexity: O(d) field operations
    pub fn lagrange_coefficient(&self, x_j: &RingElement<F>, k: usize) -> RingElement<F> {
        assert!(k < self.degree, "k must be in [0, d)");
        
        // Compute numerator: ∏_{k'∈[d]\{k}} (x_j - k')
        let mut numerator = self.ring.one();
        
        for k_prime in 0..self.degree {
            if k_prime != k {
                // x_j - k'
                let k_prime_elem = self.ring.from_u64(k_prime as u64);
                let diff = self.ring.sub(x_j, &k_prime_elem);
                numerator = self.ring.mul(&numerator, &diff);
            }
        }
        
        // Get precomputed denominator
        // Note: We use variable 0's denominators since they're the same for all variables
        let denom_field = self.lagrange_denoms[0][k];
        let denom_elem = self.ring.from_field_element(denom_field);
        
        // Divide: numerator / denominator
        // In ring, division by field element is multiplication by inverse
        let denom_inv = denom_field.inverse().expect("Denominator should be invertible");
        let denom_inv_elem = self.ring.from_field_element(denom_inv);
        
        self.ring.mul(&numerator, &denom_inv_elem)
    }
    
    /// Compute Lagrange basis vector for evaluation point
    ///
    /// Mathematical: For r = (r_0, ..., r_{µ-1}) ∈ K^µ, computes r̃ ∈ K^{d^µ} where:
    /// r̃^T = ⊗_{j∈[µ]} (L_j(r_j, 0), L_j(r_j, 1), ..., L_j(r_j, d-1))
    ///
    /// The tensor product structure means:
    /// r̃[z_0 + z_1·d + z_2·d² + ... + z_{µ-1}·d^{µ-1}] = ∏_{j∈[µ]} L_j(r_j, z_j)
    ///
    /// This is the key to efficient LDE evaluation:
    /// LDE[w](r) = ⟨r̃, w⟩ = Σ_{z∈[d]^µ} r̃_z · w_z
    ///
    /// Complexity: O(d^µ) to construct full vector, but can be computed on-the-fly
    pub fn lagrange_basis(&self, point: &[RingElement<F>]) -> Vec<RingElement<F>> {
        assert_eq!(point.len(), self.num_vars, 
            "Point must have {} coordinates", self.num_vars);
        
        // Compute univariate Lagrange bases for each variable
        let mut univariate_bases = Vec::with_capacity(self.num_vars);
        
        for j in 0..self.num_vars {
            let mut basis_j = Vec::with_capacity(self.degree);
            
            for k in 0..self.degree {
                let coeff = self.lagrange_coefficient(&point[j], k);
                basis_j.push(coeff);
            }
            
            univariate_bases.push(basis_j);
        }
        
        // Compute tensor product: r̃ = r̃_0 ⊗ r̃_1 ⊗ ... ⊗ r̃_{µ-1}
        let mut result = vec![self.ring.one()];
        
        for basis_j in univariate_bases {
            let mut new_result = Vec::with_capacity(result.len() * self.degree);
            
            for existing_elem in &result {
                for basis_elem in &basis_j {
                    let prod = self.ring.mul(existing_elem, basis_elem);
                    new_result.push(prod);
                }
            }
            
            result = new_result;
        }
        
        assert_eq!(result.len(), self.witness_size);
        result
    }
    
    /// Evaluate LDE at point using Lagrange basis
    ///
    /// Mathematical: LDE[w](r) = ⟨r̃, w⟩ = Σ_{i=0}^{d^µ-1} r̃_i · w_i
    ///
    /// Algorithm:
    /// 1. Compute Lagrange basis r̃ = lagrange_basis(r)
    /// 2. Compute inner product ⟨r̃, w⟩
    ///
    /// Complexity: O(d^µ) ring operations
    ///
    /// Note: This is the direct evaluation method. For sumcheck, we use
    /// dynamic programming to avoid recomputing the full basis.
    pub fn evaluate_lde(
        &self,
        witness: &[RingElement<F>],
        point: &[RingElement<F>],
    ) -> RingElement<F> {
        assert_eq!(witness.len(), self.witness_size,
            "Witness must have size d^µ = {}", self.witness_size);
        
        // Compute Lagrange basis
        let lagrange = self.lagrange_basis(point);
        
        // Compute inner product
        let mut result = self.ring.zero();
        
        for (lag_coeff, wit_elem) in lagrange.iter().zip(witness.iter()) {
            let prod = self.ring.mul(lag_coeff, wit_elem);
            result = self.ring.add(&result, &prod);
        }
        
        result
    }
    
    /// Evaluate LDE for matrix witness (column-wise)
    ///
    /// Mathematical: For W ∈ K^{d^µ×r}, computes LDE[W](r) ∈ K^r where:
    /// LDE[W](r) = (LDE[w_0](r), ..., LDE[w_{r-1}](r))
    /// and w_i is the i-th column of W
    ///
    /// Complexity: O(r·d^µ) ring operations
    pub fn evaluate_matrix_lde(
        &self,
        witness_matrix: &[Vec<RingElement<F>>],
        point: &[RingElement<F>],
    ) -> Vec<RingElement<F>> {
        // Compute Lagrange basis once
        let lagrange = self.lagrange_basis(point);
        
        let num_cols = witness_matrix.len();
        let mut result = Vec::with_capacity(num_cols);
        
        for col in witness_matrix {
            assert_eq!(col.len(), self.witness_size,
                "Each column must have size d^µ = {}", self.witness_size);
            
            // Compute inner product for this column
            let mut col_result = self.ring.zero();
            
            for (lag_coeff, wit_elem) in lagrange.iter().zip(col.iter()) {
                let prod = self.ring.mul(lag_coeff, wit_elem);
                col_result = self.ring.add(&col_result, &prod);
            }
            
            result.push(col_result);
        }
        
        result
    }
    
    /// Verify interpolation property on grid points
    ///
    /// Mathematical: Check that LDE[w](z) = w_z for all z ∈ [d]^µ
    ///
    /// This is a sanity check that the LDE construction is correct.
    /// Should always return true for valid witness.
    ///
    /// Complexity: O(d^{2µ}) - expensive, only for testing
    pub fn verify_interpolation(&self, witness: &[RingElement<F>]) -> bool {
        assert_eq!(witness.len(), self.witness_size);
        
        // Enumerate all grid points z ∈ [d]^µ
        for flat_idx in 0..self.witness_size {
            // Convert flat index to multi-index z = (z_0, ..., z_{µ-1})
            let mut z = Vec::with_capacity(self.num_vars);
            let mut idx = flat_idx;
            
            for _ in 0..self.num_vars {
                let z_j = idx % self.degree;
                z.push(self.ring.from_u64(z_j as u64));
                idx /= self.degree;
            }
            
            // Evaluate LDE at grid point z
            let lde_val = self.evaluate_lde(witness, &z);
            
            // Should equal witness value at this point
            if !self.ring.equal(&lde_val, &witness[flat_idx]) {
                return false;
            }
        }
        
        true
    }
    
    /// Convert multi-index to flat index
    ///
    /// Mathematical: For z = (z_0, ..., z_{µ-1}) ∈ [d]^µ,
    /// computes flat_index = z_0 + z_1·d + z_2·d² + ... + z_{µ-1}·d^{µ-1}
    ///
    /// This is the standard row-major indexing for multi-dimensional arrays.
    pub fn multi_index_to_flat(&self, multi_index: &[usize]) -> usize {
        assert_eq!(multi_index.len(), self.num_vars);
        
        let mut flat_idx = 0;
        let mut stride = 1;
        
        for &z_j in multi_index {
            assert!(z_j < self.degree, "Index {} out of bounds [0, {})", z_j, self.degree);
            flat_idx += z_j * stride;
            stride *= self.degree;
        }
        
        flat_idx
    }
    
    /// Convert flat index to multi-index
    ///
    /// Mathematical: Inverse of multi_index_to_flat
    /// Given flat_index, computes z = (z_0, ..., z_{µ-1}) such that
    /// flat_index = z_0 + z_1·d + z_2·d² + ... + z_{µ-1}·d^{µ-1}
    pub fn flat_to_multi_index(&self, flat_idx: usize) -> Vec<usize> {
        assert!(flat_idx < self.witness_size, 
            "Flat index {} out of bounds [0, {})", flat_idx, self.witness_size);
        
        let mut multi_idx = Vec::with_capacity(self.num_vars);
        let mut idx = flat_idx;
        
        for _ in 0..self.num_vars {
            let z_j = idx % self.degree;
            multi_idx.push(z_j);
            idx /= self.degree;
        }
        
        multi_idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    fn create_test_ring() -> Arc<CyclotomicRing<GoldilocksField>> {
        Arc::new(CyclotomicRing::new(64))
    }
    
    fn create_test_element(val: u64, ring: &CyclotomicRing<GoldilocksField>) -> RingElement<GoldilocksField> {
        ring.from_u64(val)
    }
    
    #[test]
    fn test_lde_context_creation() {
        let ring = create_test_ring();
        let lde = LDEContext::new(4, 2, ring.clone());
        
        assert_eq!(lde.degree, 4);
        assert_eq!(lde.num_vars, 2);
        assert_eq!(lde.witness_size, 16); // 4^2
    }
    
    #[test]
    fn test_lagrange_denominators() {
        let ring = create_test_ring();
        let lde = LDEContext::new(3, 2, ring.clone());
        
        // Check that denominators are precomputed
        assert_eq!(lde.lagrange_denoms.len(), 2); // µ = 2 variables
        assert_eq!(lde.lagrange_denoms[0].len(), 3); // d = 3 points per variable
    }
    
    #[test]
    fn test_lagrange_coefficient_at_grid_point() {
        let ring = create_test_ring();
        let lde = LDEContext::new(3, 1, ring.clone());
        
        // L_0(0, 0) should be 1
        let x_0 = create_test_element(0, &ring);
        let coeff_00 = lde.lagrange_coefficient(&x_0, 0);
        assert_eq!(coeff_00.coeffs[0].to_canonical_u64(), 1);
        
        // L_0(0, 1) should be 0
        let coeff_01 = lde.lagrange_coefficient(&x_0, 1);
        assert_eq!(coeff_01.coeffs[0].to_canonical_u64(), 0);
        
        // L_0(1, 1) should be 1
        let x_1 = create_test_element(1, &ring);
        let coeff_11 = lde.lagrange_coefficient(&x_1, 1);
        assert_eq!(coeff_11.coeffs[0].to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_lagrange_basis_univariate() {
        let ring = create_test_ring();
        let lde = LDEContext::new(3, 1, ring.clone());
        
        // For univariate (µ=1), Lagrange basis at point r should have d elements
        let r = vec![create_test_element(5, &ring)];
        let basis = lde.lagrange_basis(&r);
        
        assert_eq!(basis.len(), 3); // d = 3
    }
    
    #[test]
    fn test_lagrange_basis_bivariate() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        // For bivariate (µ=2, d=2), Lagrange basis should have d^µ = 4 elements
        let r = vec![
            create_test_element(3, &ring),
            create_test_element(7, &ring),
        ];
        let basis = lde.lagrange_basis(&r);
        
        assert_eq!(basis.len(), 4); // 2^2 = 4
    }
    
    #[test]
    fn test_lde_evaluation_constant() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        // Constant witness: all elements are 5
        let witness = vec![create_test_element(5, &ring); 4];
        
        // LDE of constant should be constant everywhere
        let r = vec![
            create_test_element(3, &ring),
            create_test_element(7, &ring),
        ];
        
        let result = lde.evaluate_lde(&witness, &r);
        assert_eq!(result.coeffs[0].to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_lde_interpolation_property() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        // Create witness with distinct values
        let witness = vec![
            create_test_element(1, &ring),
            create_test_element(2, &ring),
            create_test_element(3, &ring),
            create_test_element(4, &ring),
        ];
        
        // Verify interpolation at grid points
        // Grid points for d=2, µ=2: (0,0), (1,0), (0,1), (1,1)
        let grid_points = vec![
            vec![create_test_element(0, &ring), create_test_element(0, &ring)],
            vec![create_test_element(1, &ring), create_test_element(0, &ring)],
            vec![create_test_element(0, &ring), create_test_element(1, &ring)],
            vec![create_test_element(1, &ring), create_test_element(1, &ring)],
        ];
        
        for (i, point) in grid_points.iter().enumerate() {
            let result = lde.evaluate_lde(&witness, point);
            assert_eq!(result.coeffs[0].to_canonical_u64(), (i + 1) as u64);
        }
    }
    
    #[test]
    fn test_verify_interpolation() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        let witness = vec![
            create_test_element(1, &ring),
            create_test_element(2, &ring),
            create_test_element(3, &ring),
            create_test_element(4, &ring),
        ];
        
        assert!(lde.verify_interpolation(&witness));
    }
    
    #[test]
    fn test_matrix_lde_evaluation() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        // Create 2-column witness matrix
        let col0 = vec![
            create_test_element(1, &ring),
            create_test_element(2, &ring),
            create_test_element(3, &ring),
            create_test_element(4, &ring),
        ];
        
        let col1 = vec![
            create_test_element(5, &ring),
            create_test_element(6, &ring),
            create_test_element(7, &ring),
            create_test_element(8, &ring),
        ];
        
        let witness_matrix = vec![col0, col1];
        
        // Evaluate at a point
        let r = vec![
            create_test_element(0, &ring),
            create_test_element(0, &ring),
        ];
        
        let result = lde.evaluate_matrix_lde(&witness_matrix, &r);
        
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].coeffs[0].to_canonical_u64(), 1);
        assert_eq!(result[1].coeffs[0].to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_multi_index_conversion() {
        let ring = create_test_ring();
        let lde = LDEContext::new(3, 2, ring.clone());
        
        // Test round-trip conversion
        for flat_idx in 0..9 { // 3^2 = 9
            let multi_idx = lde.flat_to_multi_index(flat_idx);
            let recovered = lde.multi_index_to_flat(&multi_idx);
            assert_eq!(recovered, flat_idx);
        }
    }
    
    #[test]
    fn test_multi_index_specific_values() {
        let ring = create_test_ring();
        let lde = LDEContext::new(3, 2, ring.clone());
        
        // (0, 0) -> 0
        assert_eq!(lde.multi_index_to_flat(&[0, 0]), 0);
        
        // (1, 0) -> 1
        assert_eq!(lde.multi_index_to_flat(&[1, 0]), 1);
        
        // (2, 0) -> 2
        assert_eq!(lde.multi_index_to_flat(&[2, 0]), 2);
        
        // (0, 1) -> 3
        assert_eq!(lde.multi_index_to_flat(&[0, 1]), 3);
        
        // (2, 2) -> 8
        assert_eq!(lde.multi_index_to_flat(&[2, 2]), 8);
    }
    
    #[test]
    fn test_lde_linearity() {
        let ring = create_test_ring();
        let lde = LDEContext::new(2, 2, ring.clone());
        
        // Create two witnesses
        let w1 = vec![
            create_test_element(1, &ring),
            create_test_element(2, &ring),
            create_test_element(3, &ring),
            create_test_element(4, &ring),
        ];
        
        let w2 = vec![
            create_test_element(5, &ring),
            create_test_element(6, &ring),
            create_test_element(7, &ring),
            create_test_element(8, &ring),
        ];
        
        // Compute w1 + w2
        let mut w_sum = Vec::new();
        for (a, b) in w1.iter().zip(w2.iter()) {
            w_sum.push(ring.add(a, b));
        }
        
        // Evaluation point
        let r = vec![
            create_test_element(3, &ring),
            create_test_element(5, &ring),
        ];
        
        // LDE[w1 + w2](r) should equal LDE[w1](r) + LDE[w2](r)
        let lde_sum = lde.evaluate_lde(&w_sum, &r);
        let lde_w1 = lde.evaluate_lde(&w1, &r);
        let lde_w2 = lde.evaluate_lde(&w2, &r);
        let sum_lde = ring.add(&lde_w1, &lde_w2);
        
        assert!(ring.equal(&lde_sum, &sum_lde));
    }
}
