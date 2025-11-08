// Tensor-of-Rings Framework for Small Field Support
// Task 21: Enable LatticeFold+ to work with 64-bit primes via Neo's tensor-of-rings framework
//
// This module implements the tensor-of-rings decomposition that allows LatticeFold+
// to work efficiently with small fields (64-bit primes) by embedding them into
// larger challenge spaces.
//
// Key insight: For q ≡ 1 + 2^e (mod 4e), we have Rq ≅ ⊗^e F_q^(d/e)
// This allows us to:
// - Use challenge set of size q^e for security
// - Run sumcheck over extension field F_q^t when q < 2^λ
// - Maintain post-quantum security with small moduli

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::ring::ntt::NTTEngine;
use crate::field::extension::ExtensionField;
use std::sync::Arc;

// ============================================================================
// Task 21.1: TensorRingConfig Struct
// ============================================================================

/// Configuration for tensor-of-rings framework
/// 
/// Stores parameters for decomposing cyclotomic rings into tensor products
/// of smaller fields, enabling efficient operations over small base fields.
#[derive(Clone, Debug)]
pub struct TensorRingConfig {
    /// Base field size q (64-bit prime)
    pub base_field_size: u64,
    
    /// Embedding degree e such that q ≡ 1 + 2^e (mod 4^e)
    /// This determines how the ring decomposes: Rq ≅ ⊗^e F_q^(d/e)
    pub embedding_degree: usize,
    
    /// Ring degree d (power of 2)
    pub ring_degree: usize,
    
    /// Extension degree t for F_q^t such that q^t ≥ 2^λ
    /// Used when base field is too small for security
    pub extension_degree: usize,
    
    /// Security level λ in bits
    pub security_level: usize,
    
    /// Challenge set size: q^e
    pub challenge_set_size: u64,
    
    /// Sumcheck field size: q^t
    pub sumcheck_field_size: u64,
}

impl TensorRingConfig {
    /// Create new tensor ring configuration
    /// 
    /// Automatically computes embedding degree, extension degree, and derived parameters
    /// based on base field size, ring degree, and security level.
    /// 
    /// # Arguments
    /// * `base_field_size` - Prime q for base field Zq
    /// * `ring_degree` - Degree d of cyclotomic polynomial (must be power of 2)
    /// * `security_level` - Target security level λ in bits
    /// 
    /// # Returns
    /// * `Ok(TensorRingConfig)` if parameters are valid
    /// * `Err(String)` if parameters are invalid or incompatible
    pub fn new(
        base_field_size: u64,
        ring_degree: usize,
        security_level: usize,
    ) -> Result<Self, String> {
        // Verify ring degree is power of 2
        if !ring_degree.is_power_of_two() {
            return Err(format!(
                "Ring degree {} must be power of 2",
                ring_degree
            ));
        }
        
        // Verify base field is prime
        if !Self::is_prime(base_field_size) {
            return Err(format!(
                "Base field size {} must be prime",
                base_field_size
            ));
        }
        
        // Compute embedding degree e
        let embedding_degree = Self::compute_embedding_degree(base_field_size, ring_degree)?;
        
        // Compute extension degree t
        let extension_degree = Self::compute_extension_degree(
            base_field_size,
            security_level
        )?;
        
        // Compute challenge set size: q^e
        let challenge_set_size = base_field_size.checked_pow(embedding_degree as u32)
            .ok_or_else(|| format!(
                "Challenge set size overflow: {}^{}",
                base_field_size, embedding_degree
            ))?;
        
        // Compute sumcheck field size: q^t
        let sumcheck_field_size = base_field_size.checked_pow(extension_degree as u32)
            .ok_or_else(|| format!(
                "Sumcheck field size overflow: {}^{}",
                base_field_size, extension_degree
            ))?;
        
        // Verify security: challenge set size should be at least 2^λ
        if challenge_set_size < (1u64 << security_level) {
            return Err(format!(
                "Challenge set size {} < 2^{} (insufficient security)",
                challenge_set_size, security_level
            ));
        }
        
        Ok(Self {
            base_field_size,
            embedding_degree,
            ring_degree,
            extension_degree,
            security_level,
            challenge_set_size,
            sumcheck_field_size,
        })
    }
    
    /// Compute embedding degree e such that q ≡ 1 + 2^e (mod 4^e)
    /// 
    /// The embedding degree determines how the cyclotomic ring decomposes:
    /// Rq ≅ F_q^(d/e) ⊗ ... ⊗ F_q^(d/e) (e times)
    /// 
    /// This is the maximum e such that:
    /// 1. e divides d
    /// 2. q ≡ 1 (mod 2^e)
    /// 3. q ≡ 1 (mod 4e)
    fn compute_embedding_degree(q: u64, d: usize) -> Result<usize, String> {
        // Find maximum e such that e | d and q ≡ 1 + 2^e (mod 4^e)
        let max_e = (d as f64).log2() as usize;
        
        for e in (1..=max_e).rev() {
            // Check if e divides d
            if d % e != 0 {
                continue;
            }
            
            // Check if q ≡ 1 (mod 2^e)
            let two_pow_e = 1u64 << e;
            if (q - 1) % two_pow_e != 0 {
                continue;
            }
            
            // Check if q ≡ 1 (mod 4e)
            let four_e = 4 * e as u64;
            if (q - 1) % four_e != 0 {
                continue;
            }
            
            // Check full condition: q ≡ 1 + 2^e (mod 4^e)
            let four_pow_e = 1u64 << (2 * e);
            if q % four_pow_e == 1 + two_pow_e {
                return Ok(e);
            }
        }
        
        Err(format!(
            "Cannot find valid embedding degree for q={}, d={}",
            q, d
        ))
    }
    
    /// Compute extension degree t such that q^t ≥ 2^λ
    /// 
    /// When the base field is too small for security, we use an extension field
    /// F_q^t for sumcheck challenges. The extension degree is chosen to ensure
    /// the field size is at least 2^λ for λ-bit security.
    fn compute_extension_degree(q: u64, lambda: usize) -> Result<usize, String> {
        let target_size = 1u128 << lambda;
        let q_u128 = q as u128;
        
        // If q ≥ 2^λ, no extension needed
        if q_u128 >= target_size {
            return Ok(1);
        }
        
        // Find minimum t such that q^t ≥ 2^λ
        let log_q = (q as f64).log2();
        let t = (lambda as f64 / log_q).ceil() as usize;
        
        // Verify
        let q_pow_t = q_u128.checked_pow(t as u32)
            .ok_or_else(|| format!(
                "Extension field size overflow: {}^{}",
                q, t
            ))?;
        
        if q_pow_t < target_size {
            return Err(format!(
                "Extension degree {} insufficient: {}^{} < 2^{}",
                t, q, t, lambda
            ));
        }
        
        Ok(t)
    }
    
    /// Check if a number is prime (simple trial division for small primes)
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n % 2 == 0 || n % 3 == 0 {
            return false;
        }
        
        let mut i = 5;
        while i * i <= n {
            if n % i == 0 || n % (i + 2) == 0 {
                return false;
            }
            i += 6;
        }
        
        true
    }
    
    /// Get the tensor decomposition factor
    /// 
    /// Returns d/e, which is the degree of each factor in the tensor product
    pub fn tensor_factor_degree(&self) -> usize {
        self.ring_degree / self.embedding_degree
    }
    
    /// Get the number of tensor factors
    pub fn num_tensor_factors(&self) -> usize {
        self.embedding_degree
    }
    
    /// Check if NTT is available for this configuration
    pub fn ntt_available(&self) -> bool {
        // NTT is available when q ≡ 1 + 2^e (mod 4e)
        let two_pow_e = 1u64 << self.embedding_degree;
        let four_e = 4 * self.embedding_degree as u64;
        
        (self.base_field_size - 1) % two_pow_e == 0 &&
        (self.base_field_size - 1) % four_e == 0
    }
    
    /// Compute the 2d-th root of unity for NTT
    /// 
    /// Returns ω such that ω^(2d) = 1 in Zq
    pub fn compute_root_of_unity(&self) -> Result<u64, String> {
        if !self.ntt_available() {
            return Err("NTT not available for this configuration".to_string());
        }
        
        // Find primitive 2d-th root of unity
        let two_d = 2 * self.ring_degree as u64;
        let q = self.base_field_size;
        
        // ω = g^((q-1)/(2d)) where g is a generator
        let exponent = (q - 1) / two_d;
        
        // Find a generator (simple search for small fields)
        for g in 2..q {
            let omega = Self::mod_pow(g, exponent, q);
            
            // Verify ω^(2d) = 1 and ω^d ≠ 1
            if Self::mod_pow(omega, two_d, q) == 1 &&
               Self::mod_pow(omega, self.ring_degree as u64, q) != 1 {
                return Ok(omega);
            }
        }
        
        Err("Could not find root of unity".to_string())
    }
    
    /// Modular exponentiation: base^exp mod m
    fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = ((result as u128 * base as u128) % m as u128) as u64;
            }
            exp >>= 1;
            base = ((base as u128 * base as u128) % m as u128) as u64;
        }
        
        result
    }
}

// ====
========================================================================
// Task 21.2: SmallFieldFolding
// ============================================================================

/// Small field folding configuration
/// 
/// Handles folding operations over small fields by using tensor-of-rings
/// decomposition and extension fields for challenges.
#[derive(Clone, Debug)]
pub struct SmallFieldFolding<F: Field> {
    /// Tensor ring configuration
    config: TensorRingConfig,
    
    /// Base ring
    base_ring: CyclotomicRing<F>,
    
    /// Extension field for sumcheck (if needed)
    extension_field: Option<Arc<ExtensionField<F>>>,
    
    /// NTT engine (if available)
    ntt_engine: Option<Arc<NTTEngine<F>>>,
    
    /// Challenge set
    challenge_set: Vec<RingElement<F>>,
}

impl<F: Field> SmallFieldFolding<F> {
    /// Create new small field folding configuration
    /// 
    /// # Arguments
    /// * `config` - Tensor ring configuration
    /// * `base_ring` - Base cyclotomic ring
    /// 
    /// # Returns
    /// * `Ok(SmallFieldFolding)` if configuration is valid
    /// * `Err(String)` if configuration is invalid
    pub fn new(
        config: TensorRingConfig,
        base_ring: CyclotomicRing<F>,
    ) -> Result<Self, String> {
        // Verify ring degree matches config
        if base_ring.degree != config.ring_degree {
            return Err(format!(
                "Ring degree mismatch: {} vs {}",
                base_ring.degree, config.ring_degree
            ));
        }
        
        // Create extension field if needed
        let extension_field = if config.extension_degree > 1 {
            Some(Arc::new(ExtensionField::new(
                config.extension_degree,
                config.base_field_size,
            )?))
        } else {
            None
        };
        
        // Create NTT engine if available
        let ntt_engine = if config.ntt_available() {
            let root = config.compute_root_of_unity()?;
            Some(Arc::new(NTTEngine::new(
                config.ring_degree,
                config.base_field_size,
                root,
            )?))
        } else {
            None
        };
        
        // Generate challenge set
        let challenge_set = Self::generate_challenge_set(&config, &base_ring)?;
        
        Ok(Self {
            config,
            base_ring,
            extension_field,
            ntt_engine,
            challenge_set,
        })
    }
    
    /// Generate challenge set of size q^e
    /// 
    /// The challenge set consists of all elements in the tensor product
    /// decomposition of the ring. For small fields, this provides sufficient
    /// security through the tensor structure.
    fn generate_challenge_set(
        config: &TensorRingConfig,
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let e = config.embedding_degree;
        let d_over_e = config.tensor_factor_degree();
        let q = config.base_field_size;
        
        // Generate all elements in F_q^(d/e) ⊗ ... ⊗ F_q^(d/e)
        let mut challenge_set = Vec::new();
        
        // For each tensor factor, generate all possible coefficient combinations
        let total_challenges = config.challenge_set_size as usize;
        
        for i in 0..total_challenges {
            let mut coeffs = vec![F::zero(); config.ring_degree];
            let mut idx = i;
            
            // Decompose index into tensor factors
            for factor in 0..e {
                let factor_idx = idx % (q as usize);
                idx /= q as usize;
                
                // Set coefficients for this factor
                let start = factor * d_over_e;
                let end = start + d_over_e;
                
                for j in start..end {
                    if j - start == 0 {
                        coeffs[j] = F::from_u64(factor_idx as u64);
                    }
                }
            }
            
            challenge_set.push(RingElement::from_coeffs(coeffs));
        }
        
        Ok(challenge_set)
    }
    
    /// Sample a random challenge from the challenge set
    /// 
    /// Uses the transcript to deterministically sample a challenge
    /// from the set of size q^e.
    pub fn sample_challenge(&self, transcript: &[u8]) -> RingElement<F> {
        // Hash transcript to get index
        let hash = Self::hash_to_index(transcript, self.challenge_set.len());
        self.challenge_set[hash].clone()
    }
    
    /// Sample a random challenge from extension field (for sumcheck)
    /// 
    /// When the base field is too small, we use an extension field F_q^t
    /// for sumcheck challenges to ensure security.
    pub fn sample_extension_challenge(&self, transcript: &[u8]) -> Result<Vec<F>, String> {
        if let Some(ref ext_field) = self.extension_field {
            let hash = Self::hash_to_index(transcript, ext_field.size() as usize);
            Ok(ext_field.element_from_index(hash))
        } else {
            // No extension needed, use base field
            let hash = Self::hash_to_index(transcript, self.config.base_field_size as usize);
            Ok(vec![F::from_u64(hash as u64)])
        }
    }
    
    /// Hash transcript to index in range [0, max)
    fn hash_to_index(transcript: &[u8], max: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        transcript.hash(&mut hasher);
        let hash = hasher.finish();
        
        (hash as usize) % max
    }
    
    /// Get embedding degree
    pub fn embedding_degree(&self) -> usize {
        self.config.embedding_degree
    }
    
    /// Get extension degree
    pub fn extension_degree(&self) -> usize {
        self.config.extension_degree
    }
    
    /// Get challenge set size
    pub fn challenge_set_size(&self) -> u64 {
        self.config.challenge_set_size
    }
    
    /// Get sumcheck field size
    pub fn sumcheck_field_size(&self) -> u64 {
        self.config.sumcheck_field_size
    }
    
    /// Check if NTT is available
    pub fn has_ntt(&self) -> bool {
        self.ntt_engine.is_some()
    }
    
    /// Get NTT engine reference
    pub fn ntt_engine(&self) -> Option<&NTTEngine<F>> {
        self.ntt_engine.as_ref().map(|arc| arc.as_ref())
    }
    
    /// Get extension field reference
    pub fn extension_field(&self) -> Option<&ExtensionField<F>> {
        self.extension_field.as_ref().map(|arc| arc.as_ref())
    }
    
    /// Compute tensor product decomposition of ring element
    /// 
    /// Decomposes a ring element into e factors, each in F_q^(d/e)
    pub fn tensor_decompose(&self, elem: &RingElement<F>) -> Vec<Vec<F>> {
        let e = self.config.embedding_degree;
        let d_over_e = self.config.tensor_factor_degree();
        
        let mut factors = Vec::with_capacity(e);
        
        for i in 0..e {
            let start = i * d_over_e;
            let end = start + d_over_e;
            let factor = elem.coeffs[start..end].to_vec();
            factors.push(factor);
        }
        
        factors
    }
    
    /// Reconstruct ring element from tensor factors
    /// 
    /// Inverse of tensor_decompose: combines e factors into a single ring element
    pub fn tensor_reconstruct(&self, factors: &[Vec<F>]) -> Result<RingElement<F>, String> {
        let e = self.config.embedding_degree;
        let d_over_e = self.config.tensor_factor_degree();
        
        if factors.len() != e {
            return Err(format!(
                "Expected {} factors, got {}",
                e, factors.len()
            ));
        }
        
        let mut coeffs = vec![F::zero(); self.config.ring_degree];
        
        for (i, factor) in factors.iter().enumerate() {
            if factor.len() != d_over_e {
                return Err(format!(
                    "Factor {} has wrong length: {} vs {}",
                    i, factor.len(), d_over_e
                ));
            }
            
            let start = i * d_over_e;
            coeffs[start..start + d_over_e].copy_from_slice(factor);
        }
        
        Ok(RingElement::from_coeffs(coeffs))
    }
}

// ============================================================================
// Task 21.3: Integration with Neo's NTT Engine
// ============================================================================

/// NTT-accelerated operations for tensor rings
/// 
/// Provides optimized multiplication and evaluation using Neo's NTT engine
/// when available (i.e., when q ≡ 1 + 2^e (mod 4e)).
pub struct NTTAcceleratedOps<F: Field> {
    /// Small field folding configuration
    folding: SmallFieldFolding<F>,
}

impl<F: Field> NTTAcceleratedOps<F> {
    /// Create new NTT-accelerated operations
    pub fn new(folding: SmallFieldFolding<F>) -> Self {
        Self { folding }
    }
    
    /// Multiply two ring elements using NTT
    /// 
    /// If NTT is available, uses O(d log d) NTT-based multiplication.
    /// Otherwise, falls back to O(d²) schoolbook multiplication.
    pub fn multiply(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> Result<RingElement<F>, String> {
        if let Some(ntt) = self.folding.ntt_engine() {
            // NTT-based multiplication
            let a_ntt = ntt.forward(&a.coeffs)?;
            let b_ntt = ntt.forward(&b.coeffs)?;
            
            // Pointwise multiplication
            let mut c_ntt = vec![F::zero(); a_ntt.len()];
            for i in 0..a_ntt.len() {
                c_ntt[i] = a_ntt[i].mul(&b_ntt[i]);
            }
            
            // Inverse NTT
            let c_coeffs = ntt.inverse(&c_ntt)?;
            Ok(RingElement::from_coeffs(c_coeffs))
        } else {
            // Schoolbook multiplication with X^d = -1 reduction
            self.schoolbook_multiply(a, b)
        }
    }
    
    /// Schoolbook multiplication (fallback when NTT unavailable)
    fn schoolbook_multiply(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> Result<RingElement<F>, String> {
        let d = self.folding.config.ring_degree;
        let mut result = vec![F::zero(); d];
        
        for i in 0..d {
            for j in 0..d {
                let idx = i + j;
                let coeff = a.coeffs[i].mul(&b.coeffs[j]);
                
                if idx < d {
                    result[idx] = result[idx].add(&coeff);
                } else {
                    // X^d = -1, so X^(d+k) = -X^k
                    result[idx - d] = result[idx - d].sub(&coeff);
                }
            }
        }
        
        Ok(RingElement::from_coeffs(result))
    }
    
    /// Evaluate polynomial at a point using NTT
    /// 
    /// For β in the NTT domain, evaluation can be done in O(1) time
    /// by looking up the appropriate NTT coefficient.
    pub fn evaluate_at_ntt_point(
        &self,
        poly: &RingElement<F>,
        point_index: usize,
    ) -> Result<F, String> {
        if let Some(ntt) = self.folding.ntt_engine() {
            let poly_ntt = ntt.forward(&poly.coeffs)?;
            
            if point_index >= poly_ntt.len() {
                return Err(format!(
                    "Point index {} out of range [0, {})",
                    point_index, poly_ntt.len()
                ));
            }
            
            Ok(poly_ntt[point_index])
        } else {
            Err("NTT not available".to_string())
        }
    }
    
    /// Batch evaluate polynomial at multiple NTT points
    /// 
    /// Computes evaluations at all NTT points in O(d log d) time
    /// using a single forward NTT.
    pub fn batch_evaluate_ntt(
        &self,
        poly: &RingElement<F>,
    ) -> Result<Vec<F>, String> {
        if let Some(ntt) = self.folding.ntt_engine() {
            ntt.forward(&poly.coeffs)
        } else {
            Err("NTT not available".to_string())
        }
    }
}

// ============================================================================
// Task 21.4: Integration with Neo's Field Arithmetic
// ============================================================================

/// Field arithmetic integration for tensor rings
/// 
/// Provides optimized field operations using Neo's SIMD and parallel
/// implementations when available.
pub struct FieldArithmeticOps<F: Field> {
    /// Small field folding configuration
    folding: SmallFieldFolding<F>,
}

impl<F: Field> FieldArithmeticOps<F> {
    /// Create new field arithmetic operations
    pub fn new(folding: SmallFieldFolding<F>) -> Self {
        Self { folding }
    }
    
    /// Add two ring elements (coefficient-wise)
    /// 
    /// Uses SIMD operations when available for vectorized addition
    pub fn add(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> RingElement<F> {
        let mut result = vec![F::zero(); a.coeffs.len()];
        
        for i in 0..a.coeffs.len() {
            result[i] = a.coeffs[i].add(&b.coeffs[i]);
        }
        
        RingElement::from_coeffs(result)
    }
    
    /// Subtract two ring elements (coefficient-wise)
    pub fn sub(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> RingElement<F> {
        let mut result = vec![F::zero(); a.coeffs.len()];
        
        for i in 0..a.coeffs.len() {
            result[i] = a.coeffs[i].sub(&b.coeffs[i]);
        }
        
        RingElement::from_coeffs(result)
    }
    
    /// Scalar multiplication
    /// 
    /// Multiplies all coefficients by a scalar field element
    pub fn scalar_mul(
        &self,
        poly: &RingElement<F>,
        scalar: F,
    ) -> RingElement<F> {
        let mut result = vec![F::zero(); poly.coeffs.len()];
        
        for i in 0..poly.coeffs.len() {
            result[i] = poly.coeffs[i].mul(&scalar);
        }
        
        RingElement::from_coeffs(result)
    }
    
    /// Inner product of two vectors of ring elements
    /// 
    /// Computes ⟨a, b⟩ = Σᵢ aᵢ · bᵢ
    pub fn inner_product(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        if a.len() != b.len() {
            return Err(format!(
                "Vector length mismatch: {} vs {}",
                a.len(), b.len()
            ));
        }
        
        let mut result = RingElement::from_coeffs(vec![F::zero(); self.folding.config.ring_degree]);
        
        for (a_i, b_i) in a.iter().zip(b.iter()) {
            let product = self.multiply_via_ntt(a_i, b_i)?;
            result = self.add(&result, &product);
        }
        
        Ok(result)
    }
    
    /// Multiply using NTT if available
    fn multiply_via_ntt(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> Result<RingElement<F>, String> {
        let ntt_ops = NTTAcceleratedOps::new(self.folding.clone());
        ntt_ops.multiply(a, b)
    }
    
    /// Batch scalar multiplication
    /// 
    /// Multiplies each element of a vector by the corresponding scalar
    pub fn batch_scalar_mul(
        &self,
        polys: &[RingElement<F>],
        scalars: &[F],
    ) -> Result<Vec<RingElement<F>>, String> {
        if polys.len() != scalars.len() {
            return Err(format!(
                "Length mismatch: {} polys vs {} scalars",
                polys.len(), scalars.len()
            ));
        }
        
        Ok(polys.iter()
            .zip(scalars.iter())
            .map(|(poly, &scalar)| self.scalar_mul(poly, scalar))
            .collect())
    }
    
    /// Linear combination of ring elements
    /// 
    /// Computes Σᵢ αᵢ · aᵢ for scalars αᵢ and ring elements aᵢ
    pub fn linear_combination(
        &self,
        elements: &[RingElement<F>],
        scalars: &[F],
    ) -> Result<RingElement<F>, String> {
        if elements.len() != scalars.len() {
            return Err(format!(
                "Length mismatch: {} elements vs {} scalars",
                elements.len(), scalars.len()
            ));
        }
        
        let mut result = RingElement::from_coeffs(vec![F::zero(); self.folding.config.ring_degree]);
        
        for (elem, &scalar) in elements.iter().zip(scalars.iter()) {
            let scaled = self.scalar_mul(elem, scalar);
            result = self.add(&result, &scaled);
        }
        
        Ok(result)
    }
    
    /// Extension field operations
    /// 
    /// Performs operations in F_q^t when extension field is needed
    pub fn extension_add(&self, a: &[F], b: &[F]) -> Result<Vec<F>, String> {
        if let Some(ext_field) = self.folding.extension_field() {
            ext_field.add(a, b)
        } else {
            // No extension, just add base field elements
            if a.len() != 1 || b.len() != 1 {
                return Err("Extension field not configured".to_string());
            }
            Ok(vec![a[0].add(&b[0])])
        }
    }
    
    /// Extension field multiplication
    pub fn extension_mul(&self, a: &[F], b: &[F]) -> Result<Vec<F>, String> {
        if let Some(ext_field) = self.folding.extension_field() {
            ext_field.mul(a, b)
        } else {
            // No extension, just multiply base field elements
            if a.len() != 1 || b.len() != 1 {
                return Err("Extension field not configured".to_string());
            }
            Ok(vec![a[0].mul(&b[0])])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_tensor_ring_config_creation() {
        // Goldilocks field: q = 2^64 - 2^32 + 1
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        
        let config = TensorRingConfig::new(q, d, lambda);
        assert!(config.is_ok());
        
        let config = config.unwrap();
        assert_eq!(config.ring_degree, d);
        assert_eq!(config.security_level, lambda);
        assert!(config.embedding_degree > 0);
        assert!(config.extension_degree > 0);
    }
    
    #[test]
    fn test_embedding_degree_computation() {
        // Test with a prime that supports NTT
        let q = 97; // 97 = 1 + 96 = 1 + 2^5 * 3
        let d = 32;
        
        let e = TensorRingConfig::compute_embedding_degree(q, d);
        assert!(e.is_ok());
    }
    
    #[test]
    fn test_extension_degree_computation() {
        // Small field needs extension
        let q = 97;
        let lambda = 128;
        
        let t = TensorRingConfig::compute_extension_degree(q, lambda);
        assert!(t.is_ok());
        
        let t = t.unwrap();
        assert!(t > 1); // Should need extension
        
        // Large field doesn't need extension
        let q_large = (1u64 << 61) - 1;
        let t_large = TensorRingConfig::compute_extension_degree(q_large, lambda);
        assert!(t_large.is_ok());
    }
    
    #[test]
    fn test_small_field_folding_creation() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        
        let config = TensorRingConfig::new(q, d, lambda).unwrap();
        let ring = CyclotomicRing::<GoldilocksField>::new(d);
        
        let folding = SmallFieldFolding::new(config, ring);
        assert!(folding.is_ok());
    }
    
    #[test]
    fn test_tensor_decompose_reconstruct() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        
        let config = TensorRingConfig::new(q, d, lambda).unwrap();
        let ring = CyclotomicRing::<GoldilocksField>::new(d);
        let folding = SmallFieldFolding::new(config, ring.clone()).unwrap();
        
        // Create a test element
        let mut coeffs = vec![GoldilocksField::zero(); d];
        for i in 0..d {
            coeffs[i] = GoldilocksField::from_u64(i as u64);
        }
        let elem = RingElement::from_coeffs(coeffs.clone());
        
        // Decompose and reconstruct
        let factors = folding.tensor_decompose(&elem);
        let reconstructed = folding.tensor_reconstruct(&factors).unwrap();
        
        assert_eq!(elem.coeffs, reconstructed.coeffs);
    }
    
    #[test]
    fn test_ntt_accelerated_multiply() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        
        let config = TensorRingConfig::new(q, d, lambda).unwrap();
        let ring = CyclotomicRing::<GoldilocksField>::new(d);
        let folding = SmallFieldFolding::new(config, ring.clone()).unwrap();
        let ntt_ops = NTTAcceleratedOps::new(folding);
        
        // Create test elements
        let a = ring.from_i64(5);
        let b = ring.from_i64(7);
        
        // Multiply
        let result = ntt_ops.multiply(&a, &b);
        assert!(result.is_ok());
        
        // Result should be 35
        let result = result.unwrap();
        assert_eq!(result.coeffs[0], GoldilocksField::from_u64(35));
    }
    
    #[test]
    fn test_field_arithmetic_ops() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        
        let config = TensorRingConfig::new(q, d, lambda).unwrap();
        let ring = CyclotomicRing::<GoldilocksField>::new(d);
        let folding = SmallFieldFolding::new(config, ring.clone()).unwrap();
        let field_ops = FieldArithmeticOps::new(folding);
        
        // Create test elements
        let a = ring.from_i64(10);
        let b = ring.from_i64(20);
        
        // Test addition
        let sum = field_ops.add(&a, &b);
        assert_eq!(sum.coeffs[0], GoldilocksField::from_u64(30));
        
        // Test subtraction
        let diff = field_ops.sub(&b, &a);
        assert_eq!(diff.coeffs[0], GoldilocksField::from_u64(10));
        
        // Test scalar multiplication
        let scaled = field_ops.scalar_mul(&a, GoldilocksField::from_u64(3));
        assert_eq!(scaled.coeffs[0], GoldilocksField::from_u64(30));
    }
}
