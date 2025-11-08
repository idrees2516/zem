// Random projection system for approximate range proofs
// Implements structured projection matrix M_J := I_{n/ℓ_h} ⊗ J
// Per Symphony paper Section 3.4

use crate::field::Field;
use super::RingElement;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Distribution χ over {0, ±1} with Pr[χ=0] = 1/2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChiValue {
    Zero,
    PlusOne,
    MinusOne,
}

impl ChiValue {
    /// Sample from χ distribution
    pub fn sample<R: Rng>(rng: &mut R) -> Self {
        let val = rng.gen::<u8>() % 4;
        match val {
            0 | 1 => ChiValue::Zero,      // Pr = 1/2
            2 => ChiValue::PlusOne,        // Pr = 1/4
            3 => ChiValue::MinusOne,       // Pr = 1/4
        }
    }
    
    /// Convert to i8
    pub fn to_i8(self) -> i8 {
        match self {
            ChiValue::Zero => 0,
            ChiValue::PlusOne => 1,
            ChiValue::MinusOne => -1,
        }
    }
    
    /// Convert to field element
    pub fn to_field<F: Field>(self) -> F {
        match self {
            ChiValue::Zero => F::zero(),
            ChiValue::PlusOne => F::one(),
            ChiValue::MinusOne => F::one().neg(),
        }
    }
}

/// Structured projection matrix M_J := I_{n/ℓ_h} ⊗ J
/// where J ∈ {0,±1}^{λ_pj × ℓ_h}
/// Per Section 3.4 of Symphony paper
#[derive(Clone, Debug)]
pub struct ProjectionMatrix {
    /// Inner matrix J ∈ {0,±1}^{λ_pj × ℓ_h}
    pub inner_matrix: Vec<Vec<ChiValue>>,
    /// Projection parameter λ_pj (typically 256)
    pub lambda_pj: usize,
    /// Block size ℓ_h
    pub ell_h: usize,
    /// Number of blocks n/ℓ_h
    pub num_blocks: usize,
}

impl ProjectionMatrix {
    /// Sample projection matrix with λ_pj = 256 for security
    /// J ← χ^{λ_pj × ℓ_h}
    pub fn sample(lambda_pj: usize, ell_h: usize, n: usize, seed: Option<[u8; 32]>) -> Self {
        assert_eq!(n % ell_h, 0, "n must be divisible by ℓ_h");
        
        let num_blocks = n / ell_h;
        let mut rng = if let Some(s) = seed {
            ChaCha20Rng::from_seed(s)
        } else {
            ChaCha20Rng::from_entropy()
        };
        
        // Sample J from χ^{λ_pj × ℓ_h}
        let mut inner_matrix = Vec::with_capacity(lambda_pj);
        for _ in 0..lambda_pj {
            let mut row = Vec::with_capacity(ell_h);
            for _ in 0..ell_h {
                row.push(ChiValue::sample(&mut rng));
            }
            inner_matrix.push(row);
        }
        
        Self {
            inner_matrix,
            lambda_pj,
            ell_h,
            num_blocks,
        }
    }
    
    /// Project witness: H := (I_{n/ℓ_h} ⊗ J) × cf(f) ∈ Z_q^{m×d}
    /// where m = n·λ_pj/ℓ_h
    pub fn project<F: Field>(&self, witness: &[RingElement<F>]) -> Vec<Vec<i64>> {
        let n = witness.len();
        assert_eq!(n, self.num_blocks * self.ell_h, "Witness length mismatch");
        
        let d = witness[0].coeffs.len();
        let m = self.num_blocks * self.lambda_pj;
        
        // Initialize H ∈ Z_q^{m×d}
        let mut h = vec![vec![0i64; d]; m];
        
        // For each block
        for block_idx in 0..self.num_blocks {
            // Extract block of witness elements
            let block_start = block_idx * self.ell_h;
            let block_end = block_start + self.ell_h;
            let block = &witness[block_start..block_end];
            
            // Compute J × block for this block
            for (row_idx, j_row) in self.inner_matrix.iter().enumerate() {
                let output_row = block_idx * self.lambda_pj + row_idx;
                
                // For each coefficient position
                for coeff_idx in 0..d {
                    let mut sum = 0i64;
                    
                    // Compute dot product: J[row] · block_coeffs[coeff_idx]
                    for (local_idx, &chi_val) in j_row.iter().enumerate() {
                        let witness_elem = &block[local_idx];
                        let coeff = witness_elem.coeffs[coeff_idx];
                        
                        // Convert to balanced representation
                        let coeff_val = Self::to_balanced::<F>(coeff);
                        let chi_i8 = chi_val.to_i8() as i64;
                        
                        sum += chi_i8 * coeff_val;
                    }
                    
                    h[output_row][coeff_idx] = sum;
                }
            }
        }
        
        h
    }
    
    /// Convert field element to balanced representation
    fn to_balanced<F: Field>(val: F) -> i64 {
        let u = val.to_canonical_u64();
        let modulus = F::MODULUS;
        
        if u <= modulus / 2 {
            u as i64
        } else {
            -((modulus - u) as i64)
        }
    }
    
    /// Compute infinity norm of projected matrix H
    pub fn projected_infinity_norm(h: &[Vec<i64>]) -> i64 {
        h.iter()
            .flat_map(|row| row.iter())
            .map(|&val| val.abs())
            .max()
            .unwrap_or(0)
    }
    
    /// Verify Lemma 2.2: Pr[|⟨u,v⟩| > 9.5∥v∥_2] ≲ 2^{-141}
    /// For u ← χ^n, this holds with overwhelming probability
    pub fn verify_lemma_2_2_bound(inner_product: f64, v_norm: f64) -> bool {
        inner_product.abs() <= 9.5 * v_norm
    }
    
    /// Verify Eq. (6): For ∥v∥_2 > B, Pr[∥Jv mod q∥_2 ≤ √30B] ≲ 2^{-128}
    /// This ensures norm preservation with high probability
    pub fn verify_norm_preservation(
        projected_norm: f64,
        original_norm: f64,
        bound_b: f64,
    ) -> bool {
        if original_norm > bound_b {
            // If original norm exceeds bound, projected norm should also exceed √30B
            projected_norm > (30.0_f64).sqrt() * bound_b
        } else {
            // If original norm is within bound, no constraint
            true
        }
    }
    
    /// Check if projection preserves L2 norm approximately
    /// Expected: ∥Jv∥_2 ≈ √(λ_pj/ℓ_h) · ∥v∥_2
    pub fn check_norm_preservation(&self, original_norm: f64, projected_norm: f64) -> bool {
        let scale_factor = (self.lambda_pj as f64 / self.ell_h as f64).sqrt();
        let expected_norm = scale_factor * original_norm;
        
        // Allow 20% deviation
        let lower_bound = expected_norm * 0.8;
        let upper_bound = expected_norm * 1.2;
        
        projected_norm >= lower_bound && projected_norm <= upper_bound
    }
}

/// Random projection parameters
#[derive(Clone, Debug)]
pub struct ProjectionParams {
    /// Projection parameter λ_pj = 256 for security
    pub lambda_pj: usize,
    /// Block size ℓ_h
    pub ell_h: usize,
    /// Norm bound B
    pub bound_b: f64,
}

impl ProjectionParams {
    /// Create projection parameters with λ_pj = 256
    pub fn new(ell_h: usize, bound_b: f64) -> Self {
        Self {
            lambda_pj: 256,
            ell_h,
            bound_b,
        }
    }
    
    /// Verify security: λ_pj = 256 ensures 2^{-128} failure probability
    pub fn verify_security(&self) -> bool {
        self.lambda_pj >= 256
    }
    
    /// Compute output dimension m = n·λ_pj/ℓ_h
    pub fn output_dimension(&self, n: usize) -> usize {
        n * self.lambda_pj / self.ell_h
    }
}

/// Projected witness with metadata
#[derive(Clone, Debug)]
pub struct ProjectedWitness {
    /// Projected matrix H ∈ Z_q^{m×d}
    pub matrix: Vec<Vec<i64>>,
    /// Original witness length n
    pub n: usize,
    /// Ring degree d
    pub d: usize,
    /// Projection parameters
    pub params: ProjectionParams,
}

impl ProjectedWitness {
    /// Create new projected witness
    pub fn new(
        matrix: Vec<Vec<i64>>,
        n: usize,
        d: usize,
        params: ProjectionParams,
    ) -> Self {
        Self { matrix, n, d, params }
    }
    
    /// Compute infinity norm of projection
    pub fn infinity_norm(&self) -> i64 {
        ProjectionMatrix::projected_infinity_norm(&self.matrix)
    }
    
    /// Compute L2 norm of projection (treating as flattened vector)
    pub fn l2_norm(&self) -> f64 {
        let sum_squared: i128 = self.matrix
            .iter()
            .flat_map(|row| row.iter())
            .map(|&val| (val as i128) * (val as i128))
            .sum();
        
        (sum_squared as f64).sqrt()
    }
    
    /// Get dimensions (m, d)
    pub fn dimensions(&self) -> (usize, usize) {
        (self.matrix.len(), self.d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_chi_distribution() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut counts = [0, 0, 0]; // [zero, plus_one, minus_one]
        
        for _ in 0..10000 {
            match ChiValue::sample(&mut rng) {
                ChiValue::Zero => counts[0] += 1,
                ChiValue::PlusOne => counts[1] += 1,
                ChiValue::MinusOne => counts[2] += 1,
            }
        }
        
        // Verify approximately: 50% zeros, 25% +1, 25% -1
        assert!(counts[0] > 4500 && counts[0] < 5500); // ~50%
        assert!(counts[1] > 2000 && counts[1] < 3000); // ~25%
        assert!(counts[2] > 2000 && counts[2] < 3000); // ~25%
    }
    
    #[test]
    fn test_projection_matrix_creation() {
        let lambda_pj = 256;
        let ell_h = 4;
        let n = 8;
        let seed = [0u8; 32];
        
        let proj_matrix = ProjectionMatrix::sample(lambda_pj, ell_h, n, Some(seed));
        
        assert_eq!(proj_matrix.lambda_pj, 256);
        assert_eq!(proj_matrix.ell_h, 4);
        assert_eq!(proj_matrix.num_blocks, 2); // n/ℓ_h = 8/4 = 2
        assert_eq!(proj_matrix.inner_matrix.len(), 256);
        assert_eq!(proj_matrix.inner_matrix[0].len(), 4);
    }
    
    #[test]
    fn test_projection() {
        let lambda_pj = 16; // Smaller for testing
        let ell_h = 4;
        let n = 8;
        let d = 64;
        let seed = [1u8; 32];
        
        let proj_matrix = ProjectionMatrix::sample(lambda_pj, ell_h, n, Some(seed));
        
        // Create witness
        let witness: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|i| {
                let mut coeffs = vec![GoldilocksField::zero(); d];
                coeffs[0] = GoldilocksField::from_u64(i as u64 + 1);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let h = proj_matrix.project(&witness);
        
        // Verify dimensions: m = n·λ_pj/ℓ_h = 8·16/4 = 32
        assert_eq!(h.len(), 32);
        assert_eq!(h[0].len(), 64);
    }
    
    #[test]
    fn test_projected_infinity_norm() {
        let h = vec![
            vec![1, -5, 3],
            vec![2, 10, -7],
            vec![-3, 4, 8],
        ];
        
        let norm = ProjectionMatrix::projected_infinity_norm(&h);
        assert_eq!(norm, 10);
    }
    
    #[test]
    fn test_lemma_2_2_bound() {
        // Test case where bound holds
        let inner_product = 9.0;
        let v_norm = 1.0;
        assert!(ProjectionMatrix::verify_lemma_2_2_bound(inner_product, v_norm));
        
        // Test case where bound is violated
        let inner_product = 10.0;
        let v_norm = 1.0;
        assert!(!ProjectionMatrix::verify_lemma_2_2_bound(inner_product, v_norm));
    }
    
    #[test]
    fn test_norm_preservation() {
        let projected_norm = 100.0;
        let original_norm = 50.0;
        let bound_b = 40.0;
        
        // Original norm > bound, so projected should be > √30·B ≈ 219
        // In this case, projected_norm = 100 < 219, so should fail
        assert!(!ProjectionMatrix::verify_norm_preservation(
            projected_norm,
            original_norm,
            bound_b
        ));
        
        // Test case where it passes
        let projected_norm = 250.0;
        assert!(ProjectionMatrix::verify_norm_preservation(
            projected_norm,
            original_norm,
            bound_b
        ));
    }
    
    #[test]
    fn test_projection_params() {
        let params = ProjectionParams::new(4, 100.0);
        
        assert_eq!(params.lambda_pj, 256);
        assert_eq!(params.ell_h, 4);
        assert_eq!(params.bound_b, 100.0);
        assert!(params.verify_security());
        
        // Test output dimension
        let n = 8;
        let m = params.output_dimension(n);
        assert_eq!(m, 8 * 256 / 4); // 512
    }
    
    #[test]
    fn test_projected_witness() {
        let matrix = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        let params = ProjectionParams::new(4, 100.0);
        
        let projected = ProjectedWitness::new(matrix, 8, 3, params);
        
        assert_eq!(projected.dimensions(), (2, 3));
        assert_eq!(projected.infinity_norm(), 6);
        
        // L2 norm = √(1² + 2² + 3² + 4² + 5² + 6²) = √91 ≈ 9.54
        let l2 = projected.l2_norm();
        assert!((l2 - 9.54).abs() < 0.01);
    }
    
    #[test]
    fn test_chi_value_conversion() {
        assert_eq!(ChiValue::Zero.to_i8(), 0);
        assert_eq!(ChiValue::PlusOne.to_i8(), 1);
        assert_eq!(ChiValue::MinusOne.to_i8(), -1);
        
        assert_eq!(ChiValue::Zero.to_field::<GoldilocksField>(), GoldilocksField::zero());
        assert_eq!(ChiValue::PlusOne.to_field::<GoldilocksField>(), GoldilocksField::one());
        assert_eq!(ChiValue::MinusOne.to_field::<GoldilocksField>(), GoldilocksField::one().neg());
    }
}
