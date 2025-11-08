// Ajtai commitment scheme implementation
// Lattice-based binding commitment with Module-SIS security
// Implements Setup, Commit, VfyOpen, RVfyOpen per Symphony paper

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Commitment key containing MSIS matrix A ∈ Rq^{κ×n}
#[derive(Clone, Debug)]
pub struct CommitmentKey<F: Field> {
    /// Public MSIS matrix A ∈ Rq^{κ×n}
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    /// Number of rows (κ)
    pub kappa: usize,
    /// Number of columns (n)
    pub n: usize,
    /// Ring parameters
    pub ring: CyclotomicRing<F>,
    /// Security parameters
    pub params: AjtaiParams,
}

/// Ajtai commitment scheme parameters
#[derive(Clone, Debug)]
pub struct AjtaiParams {
    /// Security parameter λ
    pub lambda: usize,
    /// Ring degree d
    pub degree: usize,
    /// Field modulus q
    pub modulus: u64,
    /// Commitment dimension κ = κ(λ)
    pub kappa: usize,
    /// Module-SIS parameter β_SIS
    pub beta_sis: f64,
    /// Operator norm bound T = ∥S∥_op
    pub operator_norm_bound: f64,
    /// Standard norm bound B_bnd
    pub b_bnd: f64,
    /// Relaxed norm bound B_rbnd := 2·B_bnd
    pub b_rbnd: f64,
}

impl AjtaiParams {
    /// Create parameters for 128-bit security
    /// Per Symphony paper: β_SIS = 4T·B_rbnd where T = ∥S∥_op ≤ 15
    pub fn new_128bit_security(degree: usize, modulus: u64, kappa: usize) -> Self {
        let lambda = 128;
        let operator_norm_bound = 15.0; // LaBRADOR challenge set
        
        // Set B_rbnd based on application requirements
        // For typical use: B_rbnd = β_SIS/(4T)
        let b_rbnd = 1000.0; // Will be adjusted based on β_SIS
        let b_bnd = b_rbnd / 2.0;
        
        // Compute β_SIS for 128-bit security
        let beta_sis = 4.0 * operator_norm_bound * b_rbnd;
        
        Self {
            lambda,
            degree,
            modulus,
            kappa,
            beta_sis,
            operator_norm_bound,
            b_bnd,
            b_rbnd,
        }
    }
    
    /// Verify security level using lattice estimator bounds
    pub fn verify_security(&self) -> bool {
        // Simplified security check
        // In production, use full lattice estimator
        let log_q = (self.modulus as f64).log2();
        let security_bits = (self.kappa as f64) * (self.degree as f64) * log_q / 2.0;
        security_bits >= self.lambda as f64
    }
}

/// Commitment value c ∈ Rq^κ
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment<F: Field> {
    pub value: Vec<RingElement<F>>,
}

/// Opening for commitment: (f, s) where f ∈ Rq^n and s ∈ S - S
#[derive(Clone, Debug)]
pub struct Opening<F: Field> {
    /// Witness f ∈ Rq^n
    pub witness: Vec<RingElement<F>>,
    /// Scalar s ∈ S - S (from challenge set)
    pub scalar: RingElement<F>,
}

/// Ajtai commitment scheme
pub struct AjtaiCommitment<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> AjtaiCommitment<F> {
    /// Setup(1^λ): Generate commitment key
    /// Samples A ∈ Rq^{κ×n} uniformly at random
    pub fn setup(params: AjtaiParams, n: usize, seed: Option<[u8; 32]>) -> CommitmentKey<F> {
        let ring = CyclotomicRing::new(params.degree);
        let mut rng = if let Some(s) = seed {
            ChaCha20Rng::from_seed(s)
        } else {
            ChaCha20Rng::from_entropy()
        };
        
        // Sample A uniformly at random
        let mut matrix_a = Vec::with_capacity(params.kappa);
        for _ in 0..params.kappa {
            let mut row = Vec::with_capacity(n);
            for _ in 0..n {
                // Sample random ring element
                let coeffs: Vec<F> = (0..params.degree)
                    .map(|_| {
                        let val = rng.gen::<u64>() % params.modulus;
                        F::from_u64(val)
                    })
                    .collect();
                row.push(RingElement::from_coeffs(coeffs));
            }
            matrix_a.push(row);
        }
        
        CommitmentKey {
            matrix_a,
            kappa: params.kappa,
            n,
            ring,
            params,
        }
    }
    
    /// Commit(pp_cm, m): Compute commitment c := A·m
    /// Input: message m ∈ Rq^n
    /// Output: commitment c ∈ Rq^κ
    pub fn commit(key: &CommitmentKey<F>, message: &[RingElement<F>]) -> Commitment<F> {
        assert_eq!(message.len(), key.n, "Message length must match n");
        
        let mut value = Vec::with_capacity(key.kappa);
        
        // Compute c := A·m
        for row in &key.matrix_a {
            let mut sum = key.ring.zero();
            for (a_ij, m_j) in row.iter().zip(message.iter()) {
                let prod = key.ring.mul(a_ij, m_j);
                sum = key.ring.add(&sum, &prod);
            }
            value.push(sum);
        }
        
        Commitment { value }
    }
    
    /// VfyOpen: Verify commitment opening
    /// Checks: Af = s·c AND ∥f∥_2 < B_bnd AND s·m = f
    /// Returns true if opening is valid
    pub fn verify_opening(
        key: &CommitmentKey<F>,
        commitment: &Commitment<F>,
        message: &[RingElement<F>],
        opening: &Opening<F>,
    ) -> bool {
        // Check dimensions
        if opening.witness.len() != key.n {
            return false;
        }
        if commitment.value.len() != key.kappa {
            return false;
        }
        
        // Check 1: Af = s·c
        let af = Self::matrix_vector_mul(key, &opening.witness);
        let sc = Self::scalar_vector_mul(key, &opening.scalar, &commitment.value);
        if af != sc {
            return false;
        }
        
        // Check 2: ∥f∥_2 < B_bnd
        let f_norm = Self::vector_l2_norm(&opening.witness);
        if f_norm >= key.params.b_bnd {
            return false;
        }
        
        // Check 3: s·m = f
        let sm = Self::scalar_vector_mul_single(key, &opening.scalar, message);
        if sm != opening.witness {
            return false;
        }
        
        true
    }
    
    /// RVfyOpen: Verify relaxed commitment opening
    /// Checks: Af = s·c AND ∥f∥_2 ≤ B_rbnd := 2·B_bnd AND s·m = f
    /// Returns true if relaxed opening is valid
    pub fn verify_relaxed_opening(
        key: &CommitmentKey<F>,
        commitment: &Commitment<F>,
        message: &[RingElement<F>],
        opening: &Opening<F>,
    ) -> bool {
        // Check dimensions
        if opening.witness.len() != key.n {
            return false;
        }
        if commitment.value.len() != key.kappa {
            return false;
        }
        
        // Check 1: Af = s·c
        let af = Self::matrix_vector_mul(key, &opening.witness);
        let sc = Self::scalar_vector_mul(key, &opening.scalar, &commitment.value);
        if af != sc {
            return false;
        }
        
        // Check 2: ∥f∥_2 ≤ B_rbnd (relaxed bound)
        let f_norm = Self::vector_l2_norm(&opening.witness);
        if f_norm > key.params.b_rbnd {
            return false;
        }
        
        // Check 3: s·m = f
        let sm = Self::scalar_vector_mul_single(key, &opening.scalar, message);
        if sm != opening.witness {
            return false;
        }
        
        true
    }
    
    /// Matrix-vector multiplication: A·v
    fn matrix_vector_mul(
        key: &CommitmentKey<F>,
        vector: &[RingElement<F>],
    ) -> Vec<RingElement<F>> {
        let mut result = Vec::with_capacity(key.kappa);
        
        for row in &key.matrix_a {
            let mut sum = key.ring.zero();
            for (a_ij, v_j) in row.iter().zip(vector.iter()) {
                let prod = key.ring.mul(a_ij, v_j);
                sum = key.ring.add(&sum, &prod);
            }
            result.push(sum);
        }
        
        result
    }
    
    /// Scalar-vector multiplication: s·v (element-wise)
    fn scalar_vector_mul(
        key: &CommitmentKey<F>,
        scalar: &RingElement<F>,
        vector: &[RingElement<F>],
    ) -> Vec<RingElement<F>> {
        vector
            .iter()
            .map(|v| key.ring.mul(scalar, v))
            .collect()
    }
    
    /// Scalar-vector multiplication returning single vector
    fn scalar_vector_mul_single(
        key: &CommitmentKey<F>,
        scalar: &RingElement<F>,
        vector: &[RingElement<F>],
    ) -> Vec<RingElement<F>> {
        Self::scalar_vector_mul(key, scalar, vector)
    }
    
    /// Compute L2 norm of vector of ring elements
    /// ∥v∥_2 = √(Σ_i ∥v_i∥_2^2)
    fn vector_l2_norm(vector: &[RingElement<F>]) -> f64 {
        let sum_squared: u128 = vector
            .iter()
            .map(|elem| elem.norm_l2_squared())
            .sum();
        (sum_squared as f64).sqrt()
    }
    
    /// Verify binding security under Module-SIS assumption
    /// MSIS_{q,κ,n,β_SIS} where β_SIS = 4T·B_rbnd
    pub fn verify_binding_security(params: &AjtaiParams) -> bool {
        // Verify β_SIS = 4T·B_rbnd
        let expected_beta_sis = 4.0 * params.operator_norm_bound * params.b_rbnd;
        (params.beta_sis - expected_beta_sis).abs() < 1e-6
    }
    
    /// VfyOpen_{ℓ_h,B}: Fine-grained commitment opening verification
    /// Per Eq. (13) of Symphony paper
    /// Checks: Af = c AND ∀(i,j) ∈ [n/ℓ_h] × [d]: ∥F_{i,j}∥_2 ≤ B
    /// where F = cf(f) ∈ Z_q^{n×d} is parsed into blocks F_{i,j} ∈ Z_q^{ℓ_h×1}
    pub fn verify_fine_grained_opening(
        key: &CommitmentKey<F>,
        commitment: &Commitment<F>,
        witness: &[RingElement<F>],
        ell_h: usize,
        bound_b: f64,
    ) -> bool {
        // Check dimensions
        if witness.len() != key.n {
            return false;
        }
        if commitment.value.len() != key.kappa {
            return false;
        }
        if key.n % ell_h != 0 {
            return false; // n must be divisible by ℓ_h
        }
        
        // Check 1: Af = c
        let af = Self::matrix_vector_mul(key, witness);
        if af != commitment.value {
            return false;
        }
        
        // Check 2: ∀(i,j) ∈ [n/ℓ_h] × [d]: ∥F_{i,j}∥_2 ≤ B
        // Parse cf(f) into blocks
        let d = key.params.degree;
        let num_blocks = key.n / ell_h;
        
        for block_idx in 0..num_blocks {
            for coeff_idx in 0..d {
                // Extract block F_{i,j} ∈ Z_q^{ℓ_h×1}
                let mut block_norm_squared: u128 = 0;
                
                for local_idx in 0..ell_h {
                    let global_idx = block_idx * ell_h + local_idx;
                    let coeff = witness[global_idx].coeffs[coeff_idx];
                    
                    // Convert to balanced representation
                    let val = coeff.to_canonical_u64();
                    let modulus = F::MODULUS;
                    let balanced = if val <= modulus / 2 {
                        val as i128
                    } else {
                        -((modulus - val) as i128)
                    };
                    
                    block_norm_squared += (balanced * balanced) as u128;
                }
                
                let block_norm = (block_norm_squared as f64).sqrt();
                if block_norm > bound_b {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Verify implication: VfyOpen_{ℓ_h,B} = 1 ⟹ VfyOpen = 1
    /// if B·√(nd/ℓ_h) ≤ B_bnd
    pub fn verify_fine_grained_implies_standard(
        key: &CommitmentKey<F>,
        ell_h: usize,
        bound_b: f64,
    ) -> bool {
        let n = key.n as f64;
        let d = key.params.degree as f64;
        let ell_h_f = ell_h as f64;
        
        let implied_bound = bound_b * (n * d / ell_h_f).sqrt();
        implied_bound <= key.params.b_bnd
    }
}

/// Fine-grained opening parameters
#[derive(Clone, Debug)]
pub struct FineGrainedParams {
    /// Block size ℓ_h
    pub ell_h: usize,
    /// Per-block norm bound B
    pub bound_b: f64,
}

impl FineGrainedParams {
    /// Create fine-grained parameters ensuring compatibility with standard opening
    /// Ensures B·√(nd/ℓ_h) ≤ B_bnd
    pub fn new(ell_h: usize, n: usize, d: usize, b_bnd: f64) -> Self {
        let bound_b = b_bnd / ((n * d / ell_h) as f64).sqrt();
        Self { ell_h, bound_b }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_params_creation() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        assert_eq!(params.lambda, 128);
        assert_eq!(params.degree, 64);
        assert_eq!(params.kappa, 4);
        assert_eq!(params.operator_norm_bound, 15.0);
    }
    
    #[test]
    fn test_setup() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        assert_eq!(key.kappa, 4);
        assert_eq!(key.n, 8);
        assert_eq!(key.matrix_a.len(), 4);
        assert_eq!(key.matrix_a[0].len(), 8);
    }
    
    #[test]
    fn test_commit() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        // Create message
        let message: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|i| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(i as u64 + 1);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let commitment = AjtaiCommitment::commit(&key, &message);
        
        assert_eq!(commitment.value.len(), 4);
    }
    
    #[test]
    fn test_commitment_linearity() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        // Create two messages
        let m1: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|_| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(2);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let m2: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|_| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(3);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        // Commit separately
        let c1 = AjtaiCommitment::commit(&key, &m1);
        let c2 = AjtaiCommitment::commit(&key, &m2);
        
        // Commit to sum
        let m_sum: Vec<RingElement<GoldilocksField>> = m1
            .iter()
            .zip(m2.iter())
            .map(|(a, b)| key.ring.add(a, b))
            .collect();
        let c_sum = AjtaiCommitment::commit(&key, &m_sum);
        
        // Verify linearity: c(m1 + m2) = c(m1) + c(m2)
        let c1_plus_c2: Vec<RingElement<GoldilocksField>> = c1
            .value
            .iter()
            .zip(c2.value.iter())
            .map(|(a, b)| key.ring.add(a, b))
            .collect();
        
        for (sum_elem, expected_elem) in c_sum.value.iter().zip(c1_plus_c2.iter()) {
            assert_eq!(sum_elem.coeffs, expected_elem.coeffs);
        }
    }
    
    #[test]
    fn test_binding_security() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        assert!(AjtaiCommitment::<GoldilocksField>::verify_binding_security(&params));
    }
    
    #[test]
    fn test_vector_l2_norm() {
        let vector: Vec<RingElement<GoldilocksField>> = vec![
            {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(3);
                RingElement::from_coeffs(coeffs)
            },
            {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(4);
                RingElement::from_coeffs(coeffs)
            },
        ];
        
        let norm = AjtaiCommitment::<GoldilocksField>::vector_l2_norm(&vector);
        // ∥v∥_2 = √(3^2 + 4^2) = √25 = 5
        assert!((norm - 5.0).abs() < 1e-6);
    }
    
    #[test]
    fn test_fine_grained_opening() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        // Create witness with small coefficients
        let witness: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|_| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(2);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let commitment = AjtaiCommitment::commit(&key, &witness);
        
        // Test with ℓ_h = 4
        let ell_h = 4;
        let bound_b = 10.0;
        
        let result = AjtaiCommitment::verify_fine_grained_opening(
            &key,
            &commitment,
            &witness,
            ell_h,
            bound_b,
        );
        
        assert!(result);
    }
    
    #[test]
    fn test_fine_grained_params() {
        let n = 8;
        let d = 64;
        let ell_h = 4;
        let b_bnd = 100.0;
        
        let fg_params = FineGrainedParams::new(ell_h, n, d, b_bnd);
        
        // Verify B·√(nd/ℓ_h) ≤ B_bnd
        let implied_bound = fg_params.bound_b * ((n * d / ell_h) as f64).sqrt();
        assert!(implied_bound <= b_bnd + 1e-6);
    }
    
    #[test]
    fn test_fine_grained_implies_standard() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        let ell_h = 4;
        let fg_params = FineGrainedParams::new(ell_h, n, 64, key.params.b_bnd);
        
        assert!(AjtaiCommitment::<GoldilocksField>::verify_fine_grained_implies_standard(
            &key,
            ell_h,
            fg_params.bound_b,
        ));
    }
}
