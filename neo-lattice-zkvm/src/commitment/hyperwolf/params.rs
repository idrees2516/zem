// HyperWolf PCS Parameters
// Implements parameter generation and validation
// Per HyperWolf paper Requirements 1.1 and 13

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use super::ChallengeSpace;
use rand::{Rng, thread_rng};

/// Public parameters for HyperWolf PCS
/// 
/// Contains matrices A_0, A_1, ..., A_{k-1} for leveled commitment
/// and all security/efficiency parameters
#[derive(Clone, Debug)]
pub struct HyperWolfParams<F: Field> {
    /// Security parameter λ = 128
    pub security_param: usize,
    
    /// Polynomial degree bound N
    pub degree_bound: usize,
    
    /// Ring dimension d = 64 (power of 2)
    pub ring_dim: usize,
    
    /// Number of rounds k = log(N/d)
    pub num_rounds: usize,
    
    /// Matrix height κ = 18
    pub matrix_height: usize,
    
    /// Decomposition basis b ∈ {4, 16}
    pub decomposition_basis: u64,
    
    /// ι = ⌈log_b q⌉
    pub decomposition_length: usize,
    
    /// Prime modulus q ≈ 2^128
    pub modulus: u64,
    
    /// Matrices A_0 ∈ R_q^{κ×2ι}, A_i ∈ R_q^{κ×2κι} for i ∈ [1,k-1]
    pub matrices: Vec<Vec<Vec<RingElement<F>>>>,
    
    /// Challenge space C
    pub challenge_space: ChallengeSpace<F>,
    
    /// Infinity norm bound β_2 = b/2
    pub infinity_bound: f64,
    
    /// ℓ₂-norm bound squared β_1² = β_2² · nd
    pub l2_bound_squared: f64,
    
    /// Cyclotomic ring for operations
    ring: CyclotomicRing<F>,
}


impl<F: Field> HyperWolfParams<F> {
    /// Create new HyperWolf parameters with standard configuration
    /// 
    /// # Arguments
    /// * `security_param` - Security parameter λ (typically 128)
    /// * `degree_bound` - Polynomial degree bound N
    /// * `ring_dim` - Ring dimension d (must be 64 for standard config)
    /// 
    /// # Returns
    /// HyperWolf parameters with:
    /// - κ = 18 (matrix height)
    /// - b = 4 (decomposition basis)
    /// - q ≈ 2^128 (modulus)
    /// - Challenge space with |C| ≈ 2^{128.6}
    pub fn new(
        security_param: usize,
        degree_bound: usize,
        ring_dim: usize,
    ) -> Result<Self, String> {
        if security_param != 128 {
            return Err(format!(
                "Only 128-bit security supported, got {}",
                security_param
            ));
        }
        
        if ring_dim != 64 {
            return Err(format!(
                "Standard configuration requires d=64, got {}",
                ring_dim
            ));
        }
        
        if !degree_bound.is_power_of_two() {
            return Err(format!(
                "Degree bound must be power of 2, got {}",
                degree_bound
            ));
        }
        
        if degree_bound < ring_dim {
            return Err(format!(
                "Degree bound {} must be at least ring dimension {}",
                degree_bound, ring_dim
            ));
        }
        
        // Standard parameters
        let matrix_height = 18;
        let decomposition_basis = 4;
        let modulus = F::MODULUS;
        
        // Compute k = log(N/d)
        let num_rounds = (degree_bound / ring_dim).trailing_zeros() as usize;
        
        // Compute ι = ⌈log_b q⌉
        let decomposition_length = Self::compute_iota(decomposition_basis, modulus);
        
        // Create challenge space
        let challenge_space = ChallengeSpace::new_standard(ring_dim)?;
        
        // Compute norm bounds
        let infinity_bound = (decomposition_basis as f64) / 2.0;
        let n = (degree_bound * decomposition_length) / ring_dim;
        let l2_bound_squared = infinity_bound * infinity_bound * (n * ring_dim) as f64;
        
        // Generate random matrices
        let matrices = Self::generate_matrices(
            matrix_height,
            decomposition_length,
            num_rounds,
            ring_dim,
        )?;
        
        let ring = CyclotomicRing::new(ring_dim);
        
        Ok(Self {
            security_param,
            degree_bound,
            ring_dim,
            num_rounds,
            matrix_height,
            decomposition_basis,
            decomposition_length,
            modulus,
            matrices,
            challenge_space,
            infinity_bound,
            l2_bound_squared,
            ring,
        })
    }

    /// Create custom HyperWolf parameters
    /// 
    /// # Arguments
    /// * `security_param` - Security parameter λ
    /// * `degree_bound` - Polynomial degree bound N
    /// * `ring_dim` - Ring dimension d
    /// * `matrix_height` - Matrix height κ
    /// * `decomposition_basis` - Decomposition basis b ∈ {4, 16}
    pub fn new_custom(
        security_param: usize,
        degree_bound: usize,
        ring_dim: usize,
        matrix_height: usize,
        decomposition_basis: u64,
    ) -> Result<Self, String> {
        if decomposition_basis != 4 && decomposition_basis != 16 {
            return Err(format!(
                "Decomposition basis must be 4 or 16, got {}",
                decomposition_basis
            ));
        }
        
        if !ring_dim.is_power_of_two() {
            return Err(format!(
                "Ring dimension must be power of 2, got {}",
                ring_dim
            ));
        }
        
        let modulus = F::MODULUS;
        let num_rounds = (degree_bound / ring_dim).trailing_zeros() as usize;
        let decomposition_length = Self::compute_iota(decomposition_basis, modulus);
        
        let challenge_space = if ring_dim == 64 {
            ChallengeSpace::new_standard(ring_dim)?
        } else {
            return Err("Custom ring dimensions not yet supported for challenge space".to_string());
        };
        
        let infinity_bound = (decomposition_basis as f64) / 2.0;
        let n = (degree_bound * decomposition_length) / ring_dim;
        let l2_bound_squared = infinity_bound * infinity_bound * (n * ring_dim) as f64;
        
        let matrices = Self::generate_matrices(
            matrix_height,
            decomposition_length,
            num_rounds,
            ring_dim,
        )?;
        
        let ring = CyclotomicRing::new(ring_dim);
        
        Ok(Self {
            security_param,
            degree_bound,
            ring_dim,
            num_rounds,
            matrix_height,
            decomposition_basis,
            decomposition_length,
            modulus,
            matrices,
            challenge_space,
            infinity_bound,
            l2_bound_squared,
            ring,
        })
    }
    
    /// Compute ι = ⌈log_b q⌉
    fn compute_iota(basis: u64, modulus: u64) -> usize {
        let log_b_q = (modulus as f64).log(basis as f64);
        log_b_q.ceil() as usize
    }

    /// Generate random matrices A_0, A_1, ..., A_{k-1}
    /// 
    /// - A_0 ∈ R_q^{κ×2ι}
    /// - A_i ∈ R_q^{κ×2κι} for i ∈ [1, k-1]
    fn generate_matrices(
        matrix_height: usize,
        decomposition_length: usize,
        num_rounds: usize,
        ring_dim: usize,
    ) -> Result<Vec<Vec<Vec<RingElement<F>>>>, String> {
        let mut rng = thread_rng();
        let mut matrices = Vec::with_capacity(num_rounds);
        
        // Generate A_0 ∈ R_q^{κ×2ι}
        let a0_cols = 2 * decomposition_length;
        let a0 = Self::generate_random_matrix(
            matrix_height,
            a0_cols,
            ring_dim,
            &mut rng,
        );
        matrices.push(a0);
        
        // Generate A_i ∈ R_q^{κ×2κι} for i ∈ [1, k-1]
        let ai_cols = 2 * matrix_height * decomposition_length;
        for _ in 1..num_rounds {
            let ai = Self::generate_random_matrix(
                matrix_height,
                ai_cols,
                ring_dim,
                &mut rng,
            );
            matrices.push(ai);
        }
        
        Ok(matrices)
    }
    
    /// Generate random matrix of ring elements
    fn generate_random_matrix<R: Rng>(
        rows: usize,
        cols: usize,
        ring_dim: usize,
        rng: &mut R,
    ) -> Vec<Vec<RingElement<F>>> {
        let mut matrix = Vec::with_capacity(rows);
        
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                let coeffs: Vec<F> = (0..ring_dim)
                    .map(|_| F::from_u64(rng.gen::<u64>() % F::MODULUS))
                    .collect();
                row.push(RingElement::from_coeffs(coeffs));
            }
            matrix.push(row);
        }
        
        matrix
    }
    
    /// Get matrix A_i
    pub fn get_matrix(&self, index: usize) -> Option<&Vec<Vec<RingElement<F>>>> {
        self.matrices.get(index)
    }
    
    /// Get all matrices
    pub fn get_all_matrices(&self) -> &[Vec<Vec<RingElement<F>>>] {
        &self.matrices
    }
    
    /// Get cyclotomic ring
    pub fn ring(&self) -> &CyclotomicRing<F> {
        &self.ring
    }
    
    /// Compute γ = (2T)^{k-1} β_2 for final witness norm bound
    /// where T is the operator norm bound from challenge space
    pub fn compute_gamma(&self) -> f64 {
        let t = self.challenge_space.operator_norm_bound;
        let two_t = 2.0 * t;
        let power = two_t.powi((self.num_rounds - 1) as i32);
        power * self.infinity_bound
    }
    
    /// Get expected witness dimension n = Nι/d
    pub fn witness_dimension(&self) -> usize {
        (self.degree_bound * self.decomposition_length) / self.ring_dim
    }
    
    /// Validate M-SIS hardness
    /// 
    /// Checks that norm bound is below Micciancio-Regev threshold:
    /// β < min(q, 2²√(dκ log q log(1.0045)))
    /// 
    /// Per HyperWolf paper Requirement 13.8
    pub fn validate_msis_hardness(&self) -> Result<(), String> {
        // Compute required norm bound for M-SIS
        let d = self.ring_dim as f64;
        let kappa = self.matrix_height as f64;
        let q = self.modulus as f64;
        
        let log_q = q.ln();
        let log_1_0045 = 1.0045f64.ln();
        
        // Micciancio-Regev threshold: 2²√(dκ log q log(1.0045))
        let mr_threshold = 4.0 * (d * kappa * log_q * log_1_0045).sqrt();
        
        // Our norm bound from extraction: max(√(8Tγ√(2ι)), √(2γ√(2ι)))
        let gamma = self.compute_gamma();
        let iota = self.decomposition_length as f64;
        let t = self.challenge_space.operator_norm_bound;
        
        let bound1 = (8.0 * t * gamma * (2.0 * iota).sqrt()).sqrt();
        let bound2 = (2.0 * gamma * (2.0 * iota).sqrt()).sqrt();
        let our_bound = bound1.max(bound2);
        
        // Check against both q and MR threshold
        let threshold = q.min(mr_threshold);
        
        if our_bound >= threshold {
            return Err(format!(
                "M-SIS hardness violated: norm bound {} ≥ threshold {}",
                our_bound, threshold
            ));
        }
        
        Ok(())
    }
    
    /// Validate wrap-around condition
    /// 
    /// Checks that 2γ < q/√n where γ = (2T)^{k-1} β_2 and n = Nι/d
    /// This ensures no modular wrap-around in inner product computations
    /// 
    /// Per HyperWolf paper Requirement 13.10
    pub fn validate_wraparound_condition(&self) -> Result<(), String> {
        let gamma = self.compute_gamma();
        let n = self.witness_dimension();
        let q = self.modulus as f64;
        
        let two_gamma = 2.0 * gamma;
        let threshold = q / (n as f64).sqrt();
        
        if two_gamma >= threshold {
            return Err(format!(
                "Wrap-around condition violated: 2γ = {} ≥ q/√n = {}",
                two_gamma, threshold
            ));
        }
        
        Ok(())
    }
    
    /// Validate challenge space size
    /// 
    /// Checks that |C| ≈ 2^{128.6} for negligible soundness error
    /// 
    /// Per HyperWolf paper Requirement 13.11
    pub fn validate_challenge_space_size(&self) -> Result<(), String> {
        let log_size = self.challenge_space.log2_space_size();
        
        // Require at least 2^128 for 128-bit security
        if log_size < 128.0 {
            return Err(format!(
                "Challenge space too small: log₂|C| = {} < 128",
                log_size
            ));
        }
        
        Ok(())
    }
    
    /// Validate LaBRADOR constraint
    /// 
    /// Checks that (3k-1)² ≥ max(2κι, 3ι) for witness length requirement
    /// 
    /// Per HyperWolf paper Requirement 13.12
    pub fn validate_labrador_constraint(&self) -> Result<(), String> {
        let k = self.num_rounds;
        let kappa = self.matrix_height;
        let iota = self.decomposition_length;
        
        let lhs = (3 * k - 1) * (3 * k - 1);
        let rhs = (2 * kappa * iota).max(3 * iota);
        
        if lhs < rhs {
            return Err(format!(
                "LaBRADOR constraint violated: (3k-1)² = {} < max(2κι, 3ι) = {}",
                lhs, rhs
            ));
        }
        
        Ok(())
    }
    
    /// Validate soundness error bound
    /// 
    /// Checks that knowledge soundness error is negligible:
    /// 2(k-1)/|C| + 6(k-2)d+6dι/q ≤ 2^{-λ}
    /// 
    /// Per HyperWolf paper Requirement 13.11
    pub fn validate_soundness_error(&self) -> Result<(), String> {
        let k = self.num_rounds;
        let d = self.ring_dim;
        let iota = self.decomposition_length;
        let q = self.modulus as f64;
        let c_size = self.challenge_space.space_size();
        
        // First component: 2(k-1)/|C|
        let error1 = (2.0 * (k - 1) as f64) / c_size;
        
        // Second component: (6(k-2)d + 6dι)/q
        let numerator = (6 * (k - 2) * d + 6 * d * iota) as f64;
        let error2 = numerator / q;
        
        let total_error = error1 + error2;
        let threshold = 2.0_f64.powi(-(self.security_param as i32));
        
        if total_error > threshold {
            return Err(format!(
                "Soundness error too large: {} > 2^{{-{}}}",
                total_error, self.security_param
            ));
        }
        
        Ok(())
    }
    
    /// Validate all parameters
    /// 
    /// Runs all validation checks and returns detailed error if any fail
    pub fn validate_all(&self) -> Result<(), String> {
        self.validate_msis_hardness()?;
        self.validate_wraparound_condition()?;
        self.validate_challenge_space_size()?;
        self.validate_labrador_constraint()?;
        self.validate_soundness_error()?;
        
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_standard_params() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        assert_eq!(params.security_param, 128);
        assert_eq!(params.degree_bound, 1024);
        assert_eq!(params.ring_dim, 64);
        assert_eq!(params.matrix_height, 18);
        assert_eq!(params.decomposition_basis, 4);
        
        // k = log(1024/64) = log(16) = 4
        assert_eq!(params.num_rounds, 4);
    }
    
    #[test]
    fn test_invalid_security_param() {
        let result = HyperWolfParams::<GoldilocksField>::new(256, 1024, 64);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_ring_dim() {
        let result = HyperWolfParams::<GoldilocksField>::new(128, 1024, 32);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_degree_bound() {
        // Not power of 2
        let result = HyperWolfParams::<GoldilocksField>::new(128, 1000, 64);
        assert!(result.is_err());
        
        // Less than ring dimension
        let result = HyperWolfParams::<GoldilocksField>::new(128, 32, 64);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_compute_iota() {
        // For basis 4 and modulus 2^64
        let iota = HyperWolfParams::<GoldilocksField>::compute_iota(4, 1u64 << 32);
        
        // ι = ⌈log_4 2^32⌉ = ⌈32/2⌉ = 16
        assert_eq!(iota, 16);
    }
    
    #[test]
    fn test_matrix_generation() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Should have k = 4 matrices
        assert_eq!(params.matrices.len(), 4);
        
        // A_0 should be κ × 2ι
        let a0 = &params.matrices[0];
        assert_eq!(a0.len(), 18); // κ rows
        assert_eq!(a0[0].len(), 2 * params.decomposition_length); // 2ι cols
        
        // A_1, A_2, A_3 should be κ × 2κι
        for i in 1..4 {
            let ai = &params.matrices[i];
            assert_eq!(ai.len(), 18); // κ rows
            assert_eq!(ai[0].len(), 2 * 18 * params.decomposition_length); // 2κι cols
        }
    }
    
    #[test]
    fn test_get_matrix() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        assert!(params.get_matrix(0).is_some());
        assert!(params.get_matrix(3).is_some());
        assert!(params.get_matrix(4).is_none());
    }
    
    #[test]
    fn test_compute_gamma() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        let gamma = params.compute_gamma();
        
        // γ = (2T)^{k-1} β_2
        // T = 10, k = 4, β_2 = 2
        // γ = (20)^3 * 2 = 8000 * 2 = 16000
        assert!((gamma - 16000.0).abs() < 1.0);
    }
    
    #[test]
    fn test_witness_dimension() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        let n = params.witness_dimension();
        
        // n = Nι/d = 1024 * ι / 64 = 16ι
        assert_eq!(n, 16 * params.decomposition_length);
    }
    
    #[test]
    fn test_norm_bounds() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // β_2 = b/2 = 4/2 = 2
        assert_eq!(params.infinity_bound, 2.0);
        
        // β_1² = β_2² · nd
        let n = params.witness_dimension();
        let expected_l2_squared = 4.0 * (n * 64) as f64;
        assert_eq!(params.l2_bound_squared, expected_l2_squared);
    }
    
    #[test]
    fn test_custom_params() {
        let params = HyperWolfParams::<GoldilocksField>::new_custom(
            128, 2048, 64, 20, 16
        ).unwrap();
        
        assert_eq!(params.matrix_height, 20);
        assert_eq!(params.decomposition_basis, 16);
        assert_eq!(params.degree_bound, 2048);
        
        // k = log(2048/64) = log(32) = 5
        assert_eq!(params.num_rounds, 5);
    }
    
    #[test]
    fn test_invalid_decomposition_basis() {
        let result = HyperWolfParams::<GoldilocksField>::new_custom(
            128, 1024, 64, 18, 8
        );
        assert!(result.is_err());
    }
    
    #[test]
    fn test_different_degree_bounds() {
        // Test various degree bounds
        for log_n in 10..=20 {
            let n = 1 << log_n;
            let params = HyperWolfParams::<GoldilocksField>::new(128, n, 64).unwrap();
            
            assert_eq!(params.degree_bound, n);
            assert_eq!(params.num_rounds, log_n - 6); // log(N/64)
        }
    }
    
    #[test]
    fn test_validate_msis_hardness() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Standard parameters should satisfy M-SIS hardness
        assert!(params.validate_msis_hardness().is_ok());
    }
    
    #[test]
    fn test_validate_wraparound_condition() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Standard parameters should satisfy wrap-around condition
        assert!(params.validate_wraparound_condition().is_ok());
    }
    
    #[test]
    fn test_validate_challenge_space_size() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Standard parameters should have large enough challenge space
        assert!(params.validate_challenge_space_size().is_ok());
    }
    
    #[test]
    fn test_validate_labrador_constraint() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Standard parameters should satisfy LaBRADOR constraint
        assert!(params.validate_labrador_constraint().is_ok());
    }
    
    #[test]
    fn test_validate_soundness_error() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // Standard parameters should have negligible soundness error
        assert!(params.validate_soundness_error().is_ok());
    }
    
    #[test]
    fn test_validate_all() {
        let params = HyperWolfParams::<GoldilocksField>::new(128, 1024, 64).unwrap();
        
        // All validations should pass for standard parameters
        assert!(params.validate_all().is_ok());
    }
    
    #[test]
    fn test_validate_all_different_sizes() {
        // Test validation for various degree bounds
        for log_n in 10..=16 {
            let n = 1 << log_n;
            let params = HyperWolfParams::<GoldilocksField>::new(128, n, 64).unwrap();
            
            // All should pass validation
            assert!(params.validate_all().is_ok(), 
                "Validation failed for N = {}", n);
        }
    }
}
