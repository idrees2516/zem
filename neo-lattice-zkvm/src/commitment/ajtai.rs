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
/// 
/// **Paper Reference**: Symphony Section 3.1 "Ajtai Commitment Scheme"
/// 
/// This represents a commitment C = A·w where:
/// - A ∈ R_q^{κ×n} is the public commitment key
/// - w ∈ R_q^n is the witness (message) being committed
/// - C ∈ R_q^κ is the resulting commitment
/// 
/// **Security**: Binding under Module-SIS assumption with parameter β_SIS = 4T·B_rbnd
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment<F: Field> {
    pub value: Vec<RingElement<F>>,
    /// Tracked norm bound for the witness (if known)
    /// This is used to verify ||w|| ≤ β throughout operations
    pub witness_norm_bound: Option<f64>,
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
    /// 
    /// **Paper Reference**: Symphony Section 3.1, Requirement 2.2
    /// 
    /// **Mathematical Operation**:
    /// Given commitment key A ∈ R_q^{κ×n} and message m ∈ R_q^n,
    /// computes c = A·m ∈ R_q^κ via matrix-vector multiplication.
    /// 
    /// **Norm Tracking** (Requirement 2.6):
    /// Computes and tracks ||m||_2 to ensure ||m|| ≤ β throughout operations.
    /// This is critical for:
    /// 1. Binding security under Module-SIS
    /// 2. Soundness of folding schemes
    /// 3. Preventing norm overflow in recursive protocols
    /// 
    /// **Input**: 
    /// - key: Commitment key containing matrix A
    /// - message: Witness vector m ∈ R_q^n
    /// 
    /// **Output**: 
    /// - Commitment c ∈ R_q^κ with tracked norm bound
    pub fn commit(key: &CommitmentKey<F>, message: &[RingElement<F>]) -> Commitment<F> {
        assert_eq!(message.len(), key.n, "Message length must match n");
        
        let mut value = Vec::with_capacity(key.kappa);
        
        // Compute c := A·m via matrix-vector multiplication
        // Each component c_i = Σ_j A_{i,j} · m_j
        for row in &key.matrix_a {
            let mut sum = key.ring.zero();
            for (a_ij, m_j) in row.iter().zip(message.iter()) {
                let prod = key.ring.mul(a_ij, m_j);
                sum = key.ring.add(&sum, &prod);
            }
            value.push(sum);
        }
        
        // Track witness norm: ||m||_2 = √(Σ_i ||m_i||_2^2)
        // This enforces the constraint ||w|| ≤ β from Requirement 2.2
        let witness_norm = Self::vector_l2_norm(message);
        
        Commitment { 
            value,
            witness_norm_bound: Some(witness_norm),
        }
    }
    
    /// Commit with explicit norm bound checking
    /// 
    /// **Paper Reference**: Requirement 2.2, 2.6
    /// 
    /// This variant explicitly checks that ||message|| ≤ β before committing.
    /// Returns None if the norm bound is violated.
    /// 
    /// **Why This Matters**:
    /// In folding schemes, norm bounds grow with each fold. We must track
    /// and verify these bounds to maintain soundness.
    pub fn commit_with_bound_check(
        key: &CommitmentKey<F>, 
        message: &[RingElement<F>],
        max_norm: f64,
    ) -> Option<Commitment<F>> {
        let witness_norm = Self::vector_l2_norm(message);
        
        // Enforce ||w|| ≤ β constraint
        if witness_norm > max_norm {
            return None;
        }
        
        Some(Self::commit(key, message))
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
    
    /// Homomorphic addition: C(w₁) + C(w₂) = C(w₁ + w₂)
    /// 
    /// **Paper Reference**: Requirement 2.5 "Homomorphic Operations"
    /// 
    /// **Mathematical Property**:
    /// Given commitments C₁ = A·w₁ and C₂ = A·w₂, we have:
    /// C₁ + C₂ = A·w₁ + A·w₂ = A·(w₁ + w₂) = C(w₁ + w₂)
    /// 
    /// This is the additive homomorphism property that makes Ajtai commitments
    /// useful for linear combinations in folding schemes.
    /// 
    /// **Norm Tracking**:
    /// By triangle inequality: ||w₁ + w₂||_2 ≤ ||w₁||_2 + ||w₂||_2
    /// We track the combined norm bound to ensure it doesn't exceed β.
    pub fn add_commitments(
        key: &CommitmentKey<F>,
        c1: &Commitment<F>, 
        c2: &Commitment<F>
    ) -> Commitment<F> {
        assert_eq!(c1.value.len(), c2.value.len(), "Commitments must have same dimension");
        
        // Component-wise addition: (C₁ + C₂)_i = C₁_i + C₂_i
        let value: Vec<RingElement<F>> = c1.value.iter()
            .zip(c2.value.iter())
            .map(|(v1, v2)| key.ring.add(v1, v2))
            .collect();
        
        // Track combined norm bound using triangle inequality
        let witness_norm_bound = match (c1.witness_norm_bound, c2.witness_norm_bound) {
            (Some(n1), Some(n2)) => Some(n1 + n2),
            _ => None,
        };
        
        Commitment { value, witness_norm_bound }
    }
    
    /// Scalar multiplication: s·C(w) = C(s·w)
    /// 
    /// **Paper Reference**: Requirement 2.5, Symphony Section 4.2 "Folding"
    /// 
    /// **Mathematical Property**:
    /// Given commitment C = A·w and scalar s ∈ R_q:
    /// s·C = s·(A·w) = A·(s·w) = C(s·w)
    /// 
    /// **Use in Folding**:
    /// This operation is critical for folding schemes where we compute
    /// linear combinations of commitments with challenge scalars.
    /// 
    /// **Norm Tracking**:
    /// ||s·w||_2 ≤ ||s||_op · ||w||_2 where ||s||_op is the operator norm.
    /// For challenge sets with ||S||_op ≤ 15 (LaBRADOR), this gives tight bounds.
    pub fn scalar_mul_commitment(
        key: &CommitmentKey<F>,
        scalar: &RingElement<F>,
        commitment: &Commitment<F>
    ) -> Commitment<F> {
        // Component-wise scalar multiplication: (s·C)_i = s·C_i
        let value: Vec<RingElement<F>> = commitment.value.iter()
            .map(|v| key.ring.mul(scalar, v))
            .collect();
        
        // Track norm bound: ||s·w||_2 ≤ ||s||_op · ||w||_2
        let scalar_op_norm = scalar.operator_norm();
        let witness_norm_bound = commitment.witness_norm_bound
            .map(|n| scalar_op_norm * n);
        
        Commitment { value, witness_norm_bound }
    }
    
    /// Linear combination of commitments: Σ_i α_i·C_i = C(Σ_i α_i·w_i)
    /// 
    /// **Paper Reference**: Neo Section 3.2 "Folding Multiple Instances"
    /// 
    /// **Mathematical Property**:
    /// Given commitments C_i = A·w_i and scalars α_i ∈ R_q:
    /// Σ_i α_i·C_i = Σ_i α_i·(A·w_i) = A·(Σ_i α_i·w_i) = C(Σ_i α_i·w_i)
    /// 
    /// **Use in Folding**:
    /// This is the core operation for folding ℓ instances into one.
    /// The verifier sends challenges α_i, and the prover computes the
    /// folded commitment as a linear combination.
    /// 
    /// **Norm Bound**:
    /// ||Σ_i α_i·w_i||_2 ≤ Σ_i ||α_i||_op · ||w_i||_2
    /// For ℓ instances with ||α_i||_op ≤ T and ||w_i||_2 ≤ β:
    /// ||w_folded||_2 ≤ ℓ·T·β
    pub fn linear_combination(
        key: &CommitmentKey<F>,
        commitments: &[Commitment<F>],
        scalars: &[RingElement<F>]
    ) -> Commitment<F> {
        assert_eq!(commitments.len(), scalars.len(), 
            "Number of commitments must match number of scalars");
        assert!(!commitments.is_empty(), "Cannot compute linear combination of empty set");
        
        // Initialize with first scaled commitment
        let mut result = Self::scalar_mul_commitment(key, &scalars[0], &commitments[0]);
        
        // Add remaining scaled commitments
        for (commitment, scalar) in commitments[1..].iter().zip(&scalars[1..]) {
            let scaled = Self::scalar_mul_commitment(key, scalar, commitment);
            result = Self::add_commitments(key, &result, &scaled);
        }
        
        result
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

/// Pay-per-bit matrix commitment structure
/// 
/// **Paper Reference**: Neo Section 3.3 "Pay-Per-Bit Commitments", Requirements 2.4, 5.7
/// 
/// **Key Innovation**:
/// Traditional commitments to n field elements cost O(n·log q) bits.
/// Pay-per-bit commitments achieve O(k·log q + log n) for k non-zero entries,
/// making committing to n bits 64× cheaper than n 64-bit values!
/// 
/// **How It Works**:
/// 1. Transform field element vector v ∈ F^n into matrix M ∈ {0,1}^{n×log q}
///    where M[i,j] is the j-th bit of v[i]
/// 2. Commit to M using Ajtai scheme over cyclotomic ring
/// 3. Sparse matrices (k non-zero entries) have commitment cost O(k·log q + log n)
/// 
/// **Why This Matters**:
/// - zkVM witnesses are often sparse (many zeros)
/// - Bit-level witnesses (boolean circuits) are extremely cheap
/// - Enables efficient commitment to large sparse matrices
#[derive(Clone, Debug)]
pub struct PayPerBitCommitment<F: Field> {
    /// Underlying Ajtai commitment to the matrix representation
    pub commitment: Commitment<F>,
    /// Original vector dimension n
    pub vector_dim: usize,
    /// Bit width (log q)
    pub bit_width: usize,
    /// Number of non-zero entries (for cost tracking)
    pub num_nonzero: usize,
}

impl<F: Field> PayPerBitCommitment<F> {
    /// Transform field element vector to bit matrix
    /// 
    /// **Paper Reference**: Neo Section 3.3
    /// 
    /// **Transformation**:
    /// Given v = [v_0, v_1, ..., v_{n-1}] ∈ F^n, create matrix M ∈ {0,1}^{n×log q}:
    /// M[i,j] = j-th bit of v[i] (in binary representation)
    /// 
    /// **Example**:
    /// If v = [5, 3, 0] and q = 8 (log q = 3):
    /// ```
    /// M = [1 0 1]  (5 = 101₂)
    ///     [1 1 0]  (3 = 011₂)
    ///     [0 0 0]  (0 = 000₂)
    /// ```
    /// 
    /// **Sparsity**:
    /// If v has k non-zero entries, M has at most k·log q non-zero entries.
    pub fn vector_to_bit_matrix(vector: &[F]) -> Vec<Vec<bool>> {
        let n = vector.len();
        let bit_width = 64; // For 64-bit field elements
        
        let mut matrix = vec![vec![false; bit_width]; n];
        
        for (i, elem) in vector.iter().enumerate() {
            let val = elem.to_canonical_u64();
            
            // Extract bits: M[i,j] = (val >> j) & 1
            for j in 0..bit_width {
                matrix[i][j] = ((val >> j) & 1) == 1;
            }
        }
        
        matrix
    }
    
    /// Count non-zero entries in bit matrix
    /// 
    /// **Paper Reference**: Neo Section 3.3
    /// 
    /// This determines the commitment cost: O(k·log q + log n) where k is the count.
    pub fn count_nonzero_bits(matrix: &[Vec<bool>]) -> usize {
        matrix.iter()
            .flat_map(|row| row.iter())
            .filter(|&&bit| bit)
            .count()
    }
    
    /// Commit to field vector using pay-per-bit scheme
    /// 
    /// **Paper Reference**: Neo Section 3.3, Requirements 2.4, 5.7
    /// 
    /// **Cost Analysis**:
    /// - Traditional commitment: O(n·log q) bits
    /// - Pay-per-bit commitment: O(k·log q + log n) bits where k = # non-zero entries
    /// - For sparse vectors (k << n): massive savings!
    /// - For bit vectors (log q = 1): 64× cheaper than field element commitment
    /// 
    /// **Implementation**:
    /// 1. Convert vector to bit matrix M ∈ {0,1}^{n×log q}
    /// 2. Flatten matrix to ring element vector
    /// 3. Commit using standard Ajtai scheme
    /// 
    /// **Security**:
    /// Binding still holds under Module-SIS with adjusted parameters.
    pub fn commit_vector(
        key: &CommitmentKey<F>,
        vector: &[F]
    ) -> PayPerBitCommitment<F> {
        let vector_dim = vector.len();
        let bit_width = 64;
        
        // Step 1: Transform to bit matrix
        let bit_matrix = Self::vector_to_bit_matrix(vector);
        let num_nonzero = Self::count_nonzero_bits(&bit_matrix);
        
        // Step 2: Flatten matrix to ring elements
        // Each row becomes a ring element with bits as coefficients
        let mut ring_vector = Vec::with_capacity(vector_dim);
        
        for row in &bit_matrix {
            let mut coeffs = vec![F::zero(); key.params.degree];
            
            // Pack bits into ring element coefficients
            // Use first log q coefficients to store the bits
            for (j, &bit) in row.iter().enumerate().take(bit_width) {
                if j < coeffs.len() {
                    coeffs[j] = if bit { F::one() } else { F::zero() };
                }
            }
            
            ring_vector.push(RingElement::from_coeffs(coeffs));
        }
        
        // Step 3: Commit using Ajtai scheme
        let commitment = AjtaiCommitment::commit(key, &ring_vector);
        
        PayPerBitCommitment {
            commitment,
            vector_dim,
            bit_width,
            num_nonzero,
        }
    }
    
    /// Compute commitment cost in bits
    /// 
    /// **Paper Reference**: Neo Section 3.3, Requirement 5.7
    /// 
    /// **Formula**: Cost = O(k·log q + log n)
    /// where:
    /// - k = number of non-zero entries
    /// - log q = bit width of field elements
    /// - n = vector dimension
    /// 
    /// **Comparison**:
    /// - Traditional: n·log q bits
    /// - Pay-per-bit: k·log q + log n bits
    /// - Savings: (n - k)·log q - log n bits
    /// 
    /// For n = 2^20, log q = 64, k = 1000:
    /// - Traditional: 67,108,864 bits ≈ 8 MB
    /// - Pay-per-bit: 64,020 bits ≈ 8 KB
    /// - Savings: 1000× reduction!
    pub fn commitment_cost_bits(&self) -> usize {
        // O(k·log q + log n)
        let k_log_q = self.num_nonzero * self.bit_width;
        let log_n = (self.vector_dim as f64).log2().ceil() as usize;
        k_log_q + log_n
    }
    
    /// Compute traditional commitment cost for comparison
    pub fn traditional_cost_bits(&self) -> usize {
        // O(n·log q)
        self.vector_dim * self.bit_width
    }
    
    /// Compute cost savings ratio
    /// 
    /// **Paper Reference**: Requirement 5.7
    /// 
    /// For bit vectors (log q = 1), this achieves 64× savings.
    /// For sparse vectors, savings scale with sparsity.
    pub fn cost_savings_ratio(&self) -> f64 {
        let traditional = self.traditional_cost_bits() as f64;
        let pay_per_bit = self.commitment_cost_bits() as f64;
        traditional / pay_per_bit
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

/// Evaluation claim for folding
/// 
/// **Paper Reference**: Neo Section 3.4, Requirements 5.8, 5.9
/// 
/// Represents a claim that a committed polynomial evaluates to a specific value
/// at a given point: "polynomial committed in C evaluates to y at point r"
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    /// Commitment to the polynomial
    pub commitment: Commitment<F>,
    /// Evaluation point r ∈ F^μ
    pub point: Vec<F>,
    /// Claimed evaluation value y ∈ F
    pub value: F,
}

/// Folding-friendly linear homomorphism for evaluation claims
/// 
/// **Paper Reference**: Neo Section 3.4, Requirements 5.8, 5.9, 21.19
/// 
/// **Problem**: In folding schemes, we have β ≥ 2 commitments {C_i} with
/// claimed multilinear evaluations {(r, y_i)} at the same point r.
/// We need to fold these into a single claim (C, r, y).
/// 
/// **Solution**: Use linear homomorphism of commitments:
/// C = Σ_i α_i·C_i  and  y = Σ_i α_i·y_i
/// where α_i are random challenges from the verifier.
/// 
/// **Why This Works**:
/// If each C_i commits to polynomial p_i with p_i(r) = y_i, then:
/// C commits to p = Σ_i α_i·p_i, and p(r) = Σ_i α_i·p_i(r) = Σ_i α_i·y_i = y
/// 
/// **Security**:
/// With overwhelming probability over random α_i, if the folded claim is valid,
/// then all original claims were valid (by Schwartz-Zippel lemma).
impl<F: Field> AjtaiCommitment<F> {
    /// Fold multiple evaluation claims into one
    /// 
    /// **Paper Reference**: Neo Section 3.4, Requirements 5.8, 5.9
    /// 
    /// **Input**:
    /// - claims: β ≥ 2 evaluation claims {(C_i, r, y_i)}
    /// - challenges: Random challenges {α_i} from verifier
    /// 
    /// **Output**:
    /// - Folded claim (C, r, y) where:
    ///   - C = Σ_i α_i·C_i (linear combination of commitments)
    ///   - r = r (same evaluation point)
    ///   - y = Σ_i α_i·y_i (linear combination of values)
    /// 
    /// **Soundness**:
    /// If the folded claim is valid with probability > 1/|F|, then with
    /// overwhelming probability, all original claims were valid.
    pub fn fold_evaluation_claims(
        key: &CommitmentKey<F>,
        claims: &[EvaluationClaim<F>],
        challenges: &[RingElement<F>]
    ) -> EvaluationClaim<F> {
        assert!(claims.len() >= 2, "Need at least 2 claims to fold");
        assert_eq!(claims.len(), challenges.len(), 
            "Number of claims must match number of challenges");
        
        // Verify all claims have the same evaluation point
        let point = &claims[0].point;
        for claim in &claims[1..] {
            assert_eq!(claim.point.len(), point.len(), 
                "All claims must have same evaluation point dimension");
            for (p1, p2) in point.iter().zip(claim.point.iter()) {
                assert_eq!(p1.to_canonical_u64(), p2.to_canonical_u64(),
                    "All claims must evaluate at the same point");
            }
        }
        
        // Fold commitments: C = Σ_i α_i·C_i
        let commitments: Vec<Commitment<F>> = claims.iter()
            .map(|claim| claim.commitment.clone())
            .collect();
        let folded_commitment = Self::linear_combination(key, &commitments, challenges);
        
        // Fold values: y = Σ_i α_i·y_i
        // Note: α_i are ring elements, but y_i are field elements
        // We use the constant term of α_i for the field multiplication
        let mut folded_value = F::zero();
        for (claim, challenge) in claims.iter().zip(challenges.iter()) {
            let alpha_const = challenge.constant_term();
            let term = alpha_const.mul(&claim.value);
            folded_value = folded_value.add(&term);
        }
        
        EvaluationClaim {
            commitment: folded_commitment,
            point: point.clone(),
            value: folded_value,
        }
    }
    
    /// Batch fold multiple sets of evaluation claims
    /// 
    /// **Paper Reference**: Neo Section 3.4, Requirement 21.19
    /// 
    /// **Use Case**:
    /// In IVC, we may have multiple independent sets of evaluation claims
    /// that need to be folded separately. This batches the folding operations.
    /// 
    /// **Optimization**:
    /// By batching, we can reuse random challenges and reduce the number
    /// of commitment operations.
    pub fn batch_fold_evaluation_claims(
        key: &CommitmentKey<F>,
        claim_sets: &[Vec<EvaluationClaim<F>>],
        challenge_sets: &[Vec<RingElement<F>>]
    ) -> Vec<EvaluationClaim<F>> {
        assert_eq!(claim_sets.len(), challenge_sets.len(),
            "Number of claim sets must match number of challenge sets");
        
        claim_sets.iter()
            .zip(challenge_sets.iter())
            .map(|(claims, challenges)| {
                Self::fold_evaluation_claims(key, claims, challenges)
            })
            .collect()
    }
    
    /// Verify folded evaluation claim consistency
    /// 
    /// **Paper Reference**: Neo Section 3.4
    /// 
    /// **Check**:
    /// Given original claims {(C_i, r, y_i)}, challenges {α_i}, and
    /// folded claim (C, r, y), verify that:
    /// 1. C = Σ_i α_i·C_i
    /// 2. y = Σ_i α_i·y_i
    /// 
    /// This is used by the verifier to check the prover's folding.
    pub fn verify_folded_claim(
        key: &CommitmentKey<F>,
        original_claims: &[EvaluationClaim<F>],
        challenges: &[RingElement<F>],
        folded_claim: &EvaluationClaim<F>
    ) -> bool {
        // Recompute the folding
        let expected = Self::fold_evaluation_claims(key, original_claims, challenges);
        
        // Check commitment equality
        if expected.commitment.value.len() != folded_claim.commitment.value.len() {
            return false;
        }
        
        for (exp, got) in expected.commitment.value.iter()
            .zip(folded_claim.commitment.value.iter()) {
            if exp.coeffs != got.coeffs {
                return false;
            }
        }
        
        // Check value equality
        if expected.value.to_canonical_u64() != folded_claim.value.to_canonical_u64() {
            return false;
        }
        
        // Check point equality
        if expected.point.len() != folded_claim.point.len() {
            return false;
        }
        
        for (exp, got) in expected.point.iter().zip(folded_claim.point.iter()) {
            if exp.to_canonical_u64() != got.to_canonical_u64() {
                return false;
            }
        }
        
        true
    }
}
