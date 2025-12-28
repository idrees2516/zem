// Cyclotomic ring implementation
// R = Z[X]/(X^d + 1) for power-of-2 d
// Extended for SALSAA: canonical embedding, trace, balanced representation

use crate::field::Field;
use super::ntt::NTT;
use num_complex::Complex64;
use std::f64::consts::PI;

/// Cyclotomic ring R_q = F_q[X]/(X^d + 1)
/// For SALSAA: K = Q(ζ) where ζ is primitive f-th root of unity
/// R = O_K = Z[ζ] (ring of integers)
/// R_q = R/qR (quotient ring)
#[derive(Clone, Debug)]
pub struct CyclotomicRing<F: Field> {
    pub degree: usize,              // φ = φ(f): Euler's totient
    pub conductor: u64,             // f: conductor of cyclotomic field
    pub modulus: u64,               // q: prime modulus
    pub splitting_degree: usize,    // e: multiplicative order of q mod f
    pub ntt: Option<NTT<F>>,
    
    // Cached values for canonical embedding
    primitive_roots: Vec<Complex64>, // ζ^k for k coprime to f
    galois_automorphisms: Vec<usize>, // Indices of Galois automorphisms
}

/// Ring element: polynomial in R_q
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingElement<F: Field> {
    pub coeffs: Vec<F>,
}

impl<F: Field> CyclotomicRing<F> {
    /// Create new cyclotomic ring R_q = F_q[X]/(X^d + 1)
    /// Requires d to be a power of 2
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be power of 2");
        assert!(degree >= 64, "Degree must be at least 64 for security");
        
        // For X^d + 1, conductor f = 2d (when d is power of 2)
        let conductor = 2 * degree as u64;
        let modulus = F::MODULUS;
        
        // Compute splitting degree e: multiplicative order of q mod f
        let splitting_degree = Self::compute_splitting_degree(modulus, conductor);
        
        // Precompute primitive roots for canonical embedding
        let primitive_roots = Self::compute_primitive_roots(conductor, degree);
        
        // Compute Galois automorphism indices
        let galois_automorphisms = Self::compute_galois_automorphisms(conductor, degree);
        
        // Try to initialize NTT if primitive root exists
        let ntt = NTT::try_new(degree);
        
        Self { 
            degree, 
            conductor,
            modulus,
            splitting_degree,
            ntt,
            primitive_roots,
            galois_automorphisms,
        }
    }
    
    /// Compute multiplicative order of q modulo f
    /// Returns smallest e such that q^e ≡ 1 (mod f)
    fn compute_splitting_degree(q: u64, f: u64) -> usize {
        let mut e = 1;
        let mut power = q % f;
        
        while power != 1 && e < f as usize {
            power = (power * q) % f;
            e += 1;
        }
        
        if power != 1 {
            // q and f are not coprime or order doesn't exist
            return 1;
        }
        
        e
    }
    
    /// Compute primitive f-th roots of unity for canonical embedding
    /// Returns ζ^k for k ∈ (Z/fZ)× (units mod f)
    fn compute_primitive_roots(f: u64, phi: usize) -> Vec<Complex64> {
        let mut roots = Vec::with_capacity(phi);
        
        // ζ = e^{2πi/f}
        let base_angle = 2.0 * PI / (f as f64);
        
        // Collect ζ^k for k coprime to f
        for k in 1..=f {
            if Self::gcd(k, f) == 1 {
                let angle = base_angle * (k as f64);
                roots.push(Complex64::new(angle.cos(), angle.sin()));
            }
        }
        
        assert_eq!(roots.len(), phi, "Number of primitive roots must equal φ(f)");
        roots
    }
    
    /// Compute indices for Galois automorphisms
    /// Gal(K/Q) = {σ_k : ζ ↦ ζ^k | k ∈ (Z/fZ)×}
    fn compute_galois_automorphisms(f: u64, phi: usize) -> Vec<usize> {
        let mut autos = Vec::with_capacity(phi);
        
        for k in 1..=f {
            if Self::gcd(k, f) == 1 {
                autos.push(k as usize);
            }
        }
        
        assert_eq!(autos.len(), phi);
        autos
    }
    
    /// Greatest common divisor
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let temp = b;
            b = a % b;
            a = temp;
        }
        a
    }
    
    /// Euler's totient function φ(n)
    /// Returns count of integers k in [1,n] coprime to n
    pub fn euler_totient(n: u64) -> usize {
        if n == 1 {
            return 1;
        }
        
        let mut result = n;
        let mut n_mut = n;
        let mut p = 2;
        
        // For each prime factor p of n: φ(n) *= (1 - 1/p)
        while p * p <= n_mut {
            if n_mut % p == 0 {
                while n_mut % p == 0 {
                    n_mut /= p;
                }
                result -= result / p;
            }
            p += 1;
        }
        
        if n_mut > 1 {
            result -= result / n_mut;
        }
        
        result as usize
    }
    
    /// Compute set operator norm: ∥S∥_op := max_{a∈S} ∥a∥_op
    /// Per Symphony paper, for LaBRADOR challenge set, ∥S∥_op ≤ 15
    pub fn set_operator_norm(elements: &[RingElement<F>]) -> f64 {
        elements.iter()
            .map(|elem| elem.operator_norm())
            .fold(0.0, f64::max)
    }
    
    /// Verify Lemma 2.3: For a ∈ M (monomial), b ∈ R, ∥a·b∥_∞ ≤ ∥b∥_∞
    /// This holds when a is a monomial (single non-zero coefficient of ±1)
    pub fn verify_lemma_2_3(&self, a: &RingElement<F>, b: &RingElement<F>) -> bool {
        // Check if a is a monomial
        let non_zero_count = a.coeffs.iter()
            .filter(|c| c.to_canonical_u64() != 0)
            .count();
        
        if non_zero_count != 1 {
            return false; // Not a monomial
        }
        
        // Compute a·b
        let product = self.mul(a, b);
        
        // Check ∥a·b∥_∞ ≤ ∥b∥_∞
        product.norm_infinity() <= b.norm_infinity()
    }
    
    /// Verify Lemma 2.4: Invertibility for ∥y∥_∞ < q^{1/e}/√e
    /// Returns true if element is likely invertible based on norm bound
    pub fn verify_lemma_2_4(&self, y: &RingElement<F>) -> bool {
        if let Some(ref ntt) = self.ntt {
            let e = ntt.exponent_e() as f64;
            let q = F::MODULUS as f64;
            
            // Compute bound: q^{1/e}/√e
            let bound = q.powf(1.0 / e) / e.sqrt();
            
            // Check if ∥y∥_∞ < bound
            (y.norm_infinity() as f64) < bound
        } else {
            false
        }
    }
    
    /// Check if NTT is available for this ring
    pub fn has_ntt(&self) -> bool {
        self.ntt.is_some()
    }
    
    /// Compute CRT decomposition R_q ≅ (F_{q^e})^{φ/e}
    /// 
    /// **Paper Reference**: SALSAA Section 2.2 "Ring Splitting and Incomplete NTT"
    /// 
    /// **Mathematical Background**:
    /// When q has multiplicative order e modulo the conductor f (meaning q^e ≡ 1 mod f),
    /// the cyclotomic ring R_q splits into φ/e components over the extension field F_{q^e}.
    /// This is the Chinese Remainder Theorem (CRT) for rings.
    /// 
    /// **Why This Matters**:
    /// - For small e (e.g., e = 2, 4, 8), we can use "incomplete NTT" which is more efficient
    /// - Each CRT slot can be processed independently, enabling parallelization
    /// - Reduces communication in protocols by a factor of e
    /// 
    /// **Implementation**:
    /// We use the NTT's CRT splitting functionality to decompose the ring element
    /// into φ/e slots, where each slot is a polynomial of degree e over F_{q^e}.
    /// 
    /// **Supported Splitting Degrees**: e ∈ {1, 2, 4, 8} as per Requirement 1.3
    pub fn to_crt(&self, elem: &RingElement<F>) -> Vec<Vec<F>> {
        if let Some(ref ntt) = self.ntt {
            // Use NTT's CRT splitting for efficient decomposition
            ntt.apply_crt_splitting(&elem.coeffs)
        } else {
            // Fallback: return single slot containing all coefficients
            vec![elem.coeffs.clone()]
        }
    }
    
    /// Reconstruct ring element from CRT decomposition
    /// 
    /// **Paper Reference**: SALSAA Section 2.2
    /// 
    /// This is the inverse operation of to_crt(). It takes the φ/e CRT slots
    /// and reconstructs the original ring element using the Chinese Remainder Theorem.
    pub fn from_crt(&self, slots: &[Vec<F>]) -> RingElement<F> {
        if let Some(ref ntt) = self.ntt {
            let coeffs = ntt.inverse_crt_splitting(slots);
            RingElement { coeffs }
        } else {
            // Fallback: assume single slot
            RingElement { coeffs: slots[0].clone() }
        }
    }
    
    /// Get the splitting degree e for this ring
    /// 
    /// **Paper Reference**: SALSAA Section 2.2
    /// 
    /// The splitting degree e is the multiplicative order of q modulo f,
    /// i.e., the smallest positive integer such that q^e ≡ 1 (mod f).
    /// 
    /// For Goldilocks field (q = 2^64 - 2^32 + 1), e = 32.
    pub fn get_splitting_degree(&self) -> usize {
        self.splitting_degree
    }
    
    /// Get number of CRT slots: φ/e
    /// 
    /// **Paper Reference**: SALSAA Section 2.2
    /// 
    /// This tells us how many independent components the ring splits into.
    /// Each slot can be processed in parallel.
    pub fn get_num_crt_slots(&self) -> usize {
        if let Some(ref ntt) = self.ntt {
            ntt.num_crt_slots()
        } else {
            1
        }
    }
    
    /// Verify the CRT isomorphism R_q ≅ (F_{q^e})^{φ/e}
    /// 
    /// **Paper Reference**: SALSAA Section 2.2
    /// 
    /// This checks that the ring splitting is valid, which requires:
    /// 1. q^e ≡ 1 (mod f) where f is the conductor
    /// 2. e divides φ (Euler's totient of f)
    pub fn verify_crt_isomorphism(&self) -> bool {
        if let Some(ref ntt) = self.ntt {
            ntt.verify_isomorphism()
        } else {
            true // Trivial case: no splitting
        }
    }
    
    /// Canonical embedding σ: K → C^φ
    /// For x ∈ R, computes σ(x) = (σ_j(x))_{j∈[φ]} where σ_j ∈ Gal(K/Q)
    /// Each σ_j maps ζ ↦ ζ^{k_j} for k_j coprime to f
    pub fn canonical_embedding(&self, elem: &RingElement<F>) -> Vec<Complex64> {
        let mut result = Vec::with_capacity(self.degree);
        
        // For each Galois automorphism σ_j: ζ ↦ ζ^{k_j}
        for &k in &self.galois_automorphisms {
            // Evaluate polynomial at ζ^k
            // x = Σ_i x_i ζ^i → σ_k(x) = Σ_i x_i (ζ^k)^i = Σ_i x_i ζ^{ki}
            let mut value = Complex64::new(0.0, 0.0);
            
            for (i, coeff) in elem.coeffs.iter().enumerate() {
                // Convert coefficient to balanced representation
                let c_val = Self::to_balanced_i64(coeff.to_canonical_u64(), self.modulus);
                let c_complex = Complex64::new(c_val as f64, 0.0);
                
                // Compute ζ^{ki mod f}
                let power_index = (k * i) % (self.conductor as usize);
                let root = self.get_root_power(power_index);
                
                value += c_complex * root;
            }
            
            result.push(value);
        }
        
        result
    }
    
    /// Get ζ^k for any k (handles reduction mod f)
    fn get_root_power(&self, k: usize) -> Complex64 {
        let k_reduced = k % (self.conductor as usize);
        
        // Find which primitive root corresponds to ζ^k_reduced
        // We need to map k_reduced to index in primitive_roots
        let mut idx = 0;
        for (i, &auto_k) in self.galois_automorphisms.iter().enumerate() {
            if auto_k == k_reduced {
                idx = i;
                break;
            }
        }
        
        // If k_reduced is not coprime to f, compute directly
        if idx == 0 && k_reduced != self.galois_automorphisms[0] {
            let angle = 2.0 * PI * (k_reduced as f64) / (self.conductor as f64);
            return Complex64::new(angle.cos(), angle.sin());
        }
        
        self.primitive_roots[idx]
    }
    
    /// Convert canonical u64 to balanced i64 representation
    /// Maps [0, q) to [-(q-1)/2, (q-1)/2] for odd q
    /// Maps [0, q) to [-q/2, q/2-1] for even q
    fn to_balanced_i64(val: u64, q: u64) -> i64 {
        if val <= q / 2 {
            val as i64
        } else {
            -((q - val) as i64)
        }
    }
    
    /// Canonical norm squared: ∥x∥²_{σ,2} = Σ_j |σ_j(x)|²
    /// This equals Trace(⟨x, x̄⟩) where x̄ is complex conjugate
    pub fn canonical_norm_squared(&self, elem: &RingElement<F>) -> f64 {
        let embedding = self.canonical_embedding(elem);
        embedding.iter()
            .map(|z| z.norm_sqr())
            .sum()
    }
    
    /// Field trace Trace_{K/Q}(x) = Σ_{σ_j ∈ Gal(K/Q)} σ_j(x)
    /// Returns trace as integer (sum of all embeddings)
    pub fn trace(&self, elem: &RingElement<F>) -> i64 {
        let embedding = self.canonical_embedding(elem);
        
        // Sum real parts (imaginary parts cancel for elements in K)
        let trace_real: f64 = embedding.iter()
            .map(|z| z.re)
            .sum();
        
        // Round to nearest integer
        trace_real.round() as i64
    }
    
    /// Trace of inner product: Trace(⟨x, y⟩) where ⟨x, y⟩ = Σ_i x_i ȳ_i
    /// For vectors x, y ∈ R^m
    pub fn trace_inner_product(&self, x: &[RingElement<F>], y: &[RingElement<F>]) -> i64 {
        assert_eq!(x.len(), y.len());
        
        let mut total_trace = 0i64;
        
        for (x_i, y_i) in x.iter().zip(y.iter()) {
            // Compute x_i * conjugate(y_i)
            let y_i_conj = self.conjugate_ring_element(y_i);
            let product = self.mul(x_i, &y_i_conj);
            
            // Add trace of product
            total_trace += self.trace(&product);
        }
        
        total_trace
    }
    
    /// Complex conjugation in canonical embedding
    /// For x ∈ K, computes x̄ such that σ(x̄) = conjugate(σ(x))
    /// In polynomial representation: reverses and negates non-constant coefficients
    pub fn conjugate_ring_element(&self, elem: &RingElement<F>) -> RingElement<F> {
        elem.conjugate()
    }
    
    /// Verify identity: ∥x∥²_{σ,2} = Trace(⟨x, x̄⟩)
    /// Used for norm-check protocol correctness
    pub fn verify_norm_trace_identity(&self, elem: &RingElement<F>) -> bool {
        let norm_sq = self.canonical_norm_squared(elem);
        
        let elem_conj = self.conjugate_ring_element(elem);
        let inner_prod = self.mul(elem, &elem_conj);
        let trace_val = self.trace(&inner_prod);
        
        // Check if they're approximately equal (accounting for floating point error)
        (norm_sq - trace_val as f64).abs() < 1e-6
    }
    
    /// Create zero ring element
    pub fn zero(&self) -> RingElement<F> {
        RingElement {
            coeffs: vec![F::zero(); self.degree]
        }
    }
    
    /// Create one ring element
    pub fn one(&self) -> RingElement<F> {
        let mut coeffs = vec![F::zero(); self.degree];
        coeffs[0] = F::one();
        RingElement { coeffs }
    }
    
    /// Add two ring elements
    pub fn add(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        let coeffs = a.coeffs.iter()
            .zip(b.coeffs.iter())
            .map(|(x, y)| x.add(y))
            .collect();
        
        RingElement { coeffs }
    }
    
    /// Subtract two ring elements
    pub fn sub(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        let coeffs = a.coeffs.iter()
            .zip(b.coeffs.iter())
            .map(|(x, y)| x.sub(y))
            .collect();
        
        RingElement { coeffs }
    }
    
    /// Negate ring element
    pub fn neg(&self, a: &RingElement<F>) -> RingElement<F> {
        let coeffs = a.coeffs.iter().map(|x| x.neg()).collect();
        RingElement { coeffs }
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &F, a: &RingElement<F>) -> RingElement<F> {
        let coeffs = a.coeffs.iter().map(|x| scalar.mul(x)).collect();
        RingElement { coeffs }
    }
    
    /// Multiply two ring elements
    pub fn mul(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.coeffs.len(), self.degree);
        assert_eq!(b.coeffs.len(), self.degree);
        
        if let Some(ref ntt) = self.ntt {
            self.mul_ntt(a, b, ntt)
        } else {
            self.mul_schoolbook(a, b)
        }
    }
    
    /// NTT-based multiplication (O(d log d))
    fn mul_ntt(&self, a: &RingElement<F>, b: &RingElement<F>, ntt: &NTT<F>) -> RingElement<F> {
        // Forward NTT
        let a_ntt = ntt.forward(&a.coeffs);
        let b_ntt = ntt.forward(&b.coeffs);
        
        // Pointwise multiplication
        let c_ntt: Vec<F> = a_ntt.iter()
            .zip(b_ntt.iter())
            .map(|(x, y)| x.mul(y))
            .collect();
        
        // Inverse NTT
        let coeffs = ntt.inverse(&c_ntt);
        
        RingElement { coeffs }
    }
    
    /// Schoolbook multiplication (O(d^2)) - fallback when NTT unavailable
    fn mul_schoolbook(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        let d = self.degree;
        let mut result = vec![F::zero(); d];
        
        // Compute polynomial product
        for i in 0..d {
            for j in 0..d {
                let prod = a.coeffs[i].mul(&b.coeffs[j]);
                let idx = i + j;
                
                if idx < d {
                    result[idx] = result[idx].add(&prod);
                } else {
                    // Reduce by X^d = -1
                    let reduced_idx = idx - d;
                    result[reduced_idx] = result[reduced_idx].sub(&prod);
                }
            }
        }
        
        RingElement { coeffs: result }
    }
}

impl<F: Field> RingElement<F> {
    /// Create ring element from coefficient vector
    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }
    
    /// Create ring element from balanced representation
    /// Converts i64 coefficients in [-q/2, q/2] to field elements
    pub fn from_balanced(coeffs: Vec<i64>, modulus: u64) -> Self {
        let field_coeffs = coeffs.iter()
            .map(|&c| {
                if c >= 0 {
                    F::from_u64(c as u64)
                } else {
                    F::from_u64((modulus as i64 + c) as u64)
                }
            })
            .collect();
        
        Self { coeffs: field_coeffs }
    }
    
    /// Convert to balanced representation
    /// Returns coefficients as i64 in range [-(q-1)/2, (q-1)/2]
    pub fn to_balanced(&self, modulus: u64) -> Vec<i64> {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                if val <= modulus / 2 {
                    val as i64
                } else {
                    -((modulus - val) as i64)
                }
            })
            .collect()
    }
    
    /// Coefficient embedding: R_q → F_q^d
    pub fn to_coefficient_vector(&self) -> Vec<F> {
        self.coeffs.clone()
    }
    
    /// Constant term extraction: R_q → F_q
    /// For f = Σᵢ fᵢXⁱ, returns f₀
    /// This is the ct(·) operation from HyperWolf paper
    pub fn constant_term(&self) -> F {
        self.coeffs[0]
    }
    
    /// Conjugation automorphism: σ⁻¹(f) = Σᵢ fᵢX⁻ⁱ
    /// For f = Σᵢ₌₀ᵈ⁻¹ fᵢXⁱ, computes σ⁻¹(f) = f₀ + f_{d-1}X + f_{d-2}X² + ... + f₁X^{d-1}
    /// In cyclotomic ring R = Z[X]/(X^d + 1), X⁻¹ = -X^{d-1}
    /// So σ⁻¹(f) reverses coefficients (except constant term) and negates them
    pub fn conjugate(&self) -> Self {
        let d = self.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Constant term stays the same
        result[0] = self.coeffs[0];
        
        // For i > 0: coefficient of X^i in σ⁻¹(f) is -f_{d-i}
        for i in 1..d {
            result[i] = self.coeffs[d - i].neg();
        }
        
        Self { coeffs: result }
    }
    
    /// Inner product with conjugate: ⟨f, σ⁻¹(g)⟩ in R_q
    /// Used in HyperWolf's guarded IPA for exact ℓ₂-norm computation
    pub fn inner_product_conjugate(&self, other: &Self) -> Self {
        assert_eq!(self.coeffs.len(), other.coeffs.len());
        
        let d = self.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Compute f · σ⁻¹(g) coefficient by coefficient
        // This is polynomial multiplication in R_q
        for i in 0..d {
            for j in 0..d {
                let g_conj_coeff = if j == 0 {
                    other.coeffs[0]
                } else {
                    other.coeffs[d - j].neg()
                };
                
                let prod = self.coeffs[i].mul(&g_conj_coeff);
                let idx = i + j;
                
                if idx < d {
                    result[idx] = result[idx].add(&prod);
                } else {
                    // Reduce by X^d = -1
                    let reduced_idx = idx - d;
                    result[reduced_idx] = result[reduced_idx].sub(&prod);
                }
            }
        }
        
        Self { coeffs: result }
    }
    
    /// Infinity norm of ring element: ∥f∥_∞ = max_i |f_i|
    pub fn norm_infinity(&self) -> u64 {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation: map to [-q/2, q/2]
                if val <= modulus / 2 {
                    val
                } else {
                    modulus - val
                }
            })
            .max()
            .unwrap_or(0)
    }
    
    /// L2 norm of ring element: ∥f∥_2 = √(Σ f_i^2)
    /// Returns the squared norm to avoid floating point
    pub fn norm_l2_squared(&self) -> u128 {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation: map to [-q/2, q/2]
                let balanced = if val <= modulus / 2 {
                    val as i128
                } else {
                    -((modulus - val) as i128)
                };
                (balanced * balanced) as u128
            })
            .sum()
    }
    
    /// L2 norm of ring element (floating point approximation)
    pub fn norm_l2(&self) -> f64 {
        (self.norm_l2_squared() as f64).sqrt()
    }
    
    /// Operator norm: ∥a∥_op := sup_{y∈R} ∥a·y∥_∞ / ∥y∥_∞
    /// For a ∈ M (monomial set), this equals the sum of absolute values of coefficients
    /// Per Eq. (1) of Symphony paper
    pub fn operator_norm(&self) -> f64 {
        // For general ring elements, operator norm is bounded by sum of absolute coefficients
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation
                if val <= modulus / 2 {
                    val as f64
                } else {
                    (modulus - val) as f64
                }
            })
            .sum()
    }
    
    /// Canonical norm: ||x||_{σ,2}
    /// 
    /// **Paper Reference**: SALSAA Section 2.2, Requirement 1.4
    /// 
    /// **Formula**: ||x||²_{σ,2} = Trace(⟨x, x̄⟩)
    /// where:
    /// - σ: R → C^φ is the canonical embedding
    /// - x̄ is the complex conjugate
    /// - Trace is the trace function Trace_{K/Q}
    /// 
    /// **Implementation**:
    /// For cyclotomic ring R = Z[X]/(X^φ + 1), the canonical norm
    /// can be computed via the trace of the inner product with conjugate.
    pub fn canonical_norm(&self) -> f64 {
        // Compute ⟨x, x̄⟩
        let inner_prod = self.inner_product_conjugate(self);
        
        // Take trace
        let trace_val = inner_prod.trace();
        
        // ||x||²_{σ,2} = Trace(⟨x, x̄⟩)
        // Return square root
        let trace_f64 = trace_val.constant_term().to_canonical_u64() as f64;
        trace_f64.sqrt()
    }
    
    /// Trace function: Trace_{K/Q}(x)
    /// 
    /// **Paper Reference**: SALSAA Section 2.2, Requirement 1.6
    /// 
    /// **Formula**: Trace(x) = Σ_{i=0}^{φ-1} σ_i(x)
    /// where σ_i are the φ embeddings of R into C.
    /// 
    /// **Simplified Implementation**:
    /// For cyclotomic rings, Trace(x) = φ · x_0 (constant term)
    /// This is a simplification; full implementation would compute all embeddings.
    pub fn trace(&self) -> Self {
        let d = self.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Simplified: Trace(x) ≈ d · x_0
        // In full implementation, would sum over all Galois conjugates
        result[0] = self.coeffs[0].mul(&F::from_u64(d as u64));
        
        Self { coeffs: result }
    }
    
    /// Scalar multiplication by field element
    /// 
    /// **Formula**: (α · x)_i = α · x_i for all i
    pub fn scalar_mul_field(&self, scalar: &F) -> Self {
        let result = self.coeffs.iter()
            .map(|c| c.mul(scalar))
            .collect();
        
        Self { coeffs: result }
    }
    
    /// Get degree (number of coefficients)
    pub fn degree(&self) -> usize {
        self.coeffs.len()
    }
    
    /// Create zero ring element of given degree
    pub fn zero(degree: usize) -> Self {
        Self {
            coeffs: vec![F::zero(); degree],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_ring_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        assert_eq!(ring.degree, 64);
    }
    
    #[test]
    fn test_ring_addition() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(3);
        a_coeffs[1] = GoldilocksField::from_u64(4);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[1] = GoldilocksField::from_u64(6);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let c = ring.add(&a, &b);
        assert_eq!(c.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(c.coeffs[1].to_canonical_u64(), 10);
    }
    
    #[test]
    fn test_ring_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let c = ring.mul(&a, &b);
        assert_eq!(c.coeffs[0].to_canonical_u64(), 6);
    }
    
    #[test]
    fn test_norm_infinity() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(5);
        coeffs[1] = GoldilocksField::from_u64(10);
        let elem = RingElement::from_coeffs(coeffs);
        
        assert_eq!(elem.norm_infinity(), 10);
    }
    
    #[test]
    fn test_norm_l2() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        let elem = RingElement::from_coeffs(coeffs);
        
        // ∥f∥_2 = √(3^2 + 4^2) = √25 = 5
        assert_eq!(elem.norm_l2_squared(), 25);
        assert!((elem.norm_l2() - 5.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_ntt_vs_schoolbook_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create test polynomials
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        a_coeffs[1] = GoldilocksField::from_u64(3);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[2] = GoldilocksField::from_u64(7);
        let b = RingElement::from_coeffs(b_coeffs);
        
        // Multiply using NTT
        let c_ntt = ring.mul(&a, &b);
        
        // Multiply using schoolbook (temporarily disable NTT)
        let ring_no_ntt = CyclotomicRing {
            degree: ring.degree,
            ntt: None,
        };
        let c_schoolbook = ring_no_ntt.mul(&a, &b);
        
        // Results should match
        assert_eq!(c_ntt.coeffs, c_schoolbook.coeffs);
    }
    
    #[test]
    fn test_ring_axioms() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[0] = GoldilocksField::from_u64(2);
        let a = RingElement::from_coeffs(a_coeffs);
        
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        let mut c_coeffs = vec![GoldilocksField::zero(); 64];
        c_coeffs[0] = GoldilocksField::from_u64(5);
        let c = RingElement::from_coeffs(c_coeffs);
        
        // Test associativity: (a + b) + c = a + (b + c)
        let left = ring.add(&ring.add(&a, &b), &c);
        let right = ring.add(&a, &ring.add(&b, &c));
        assert_eq!(left.coeffs, right.coeffs);
        
        // Test commutativity: a + b = b + a
        let ab = ring.add(&a, &b);
        let ba = ring.add(&b, &a);
        assert_eq!(ab.coeffs, ba.coeffs);
        
        // Test distributivity: a * (b + c) = a*b + a*c
        let left = ring.mul(&a, &ring.add(&b, &c));
        let right = ring.add(&ring.mul(&a, &b), &ring.mul(&a, &c));
        assert_eq!(left.coeffs, right.coeffs);
        
        // Test multiplicative commutativity: a * b = b * a
        let ab = ring.mul(&a, &b);
        let ba = ring.mul(&b, &a);
        assert_eq!(ab.coeffs, ba.coeffs);
    }
    
    #[test]
    fn test_operator_norm() {
        // Test monomial X has operator norm 1
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[1] = GoldilocksField::from_u64(1);
        let monomial = RingElement::from_coeffs(coeffs);
        
        assert_eq!(monomial.operator_norm(), 1.0);
    }
    
    #[test]
    fn test_set_operator_norm() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create LaBRADOR-style challenge set with small coefficients
        let mut elements = Vec::new();
        
        // Element with coefficients {0, ±1, ±2}
        let mut coeffs1 = vec![GoldilocksField::zero(); 64];
        coeffs1[0] = GoldilocksField::from_u64(1);
        coeffs1[1] = GoldilocksField::from_u64(2);
        elements.push(RingElement::from_coeffs(coeffs1));
        
        let mut coeffs2 = vec![GoldilocksField::zero(); 64];
        coeffs2[0] = GoldilocksField::from_u64(2);
        coeffs2[2] = GoldilocksField::from_u64(1);
        elements.push(RingElement::from_coeffs(coeffs2));
        
        let set_norm = CyclotomicRing::<GoldilocksField>::set_operator_norm(&elements);
        
        // For LaBRADOR challenge set, ∥S∥_op ≤ 15
        assert!(set_norm <= 15.0);
    }
    
    #[test]
    fn test_lemma_2_3() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create monomial a = X
        let mut a_coeffs = vec![GoldilocksField::zero(); 64];
        a_coeffs[1] = GoldilocksField::from_u64(1);
        let a = RingElement::from_coeffs(a_coeffs);
        
        // Create arbitrary b
        let mut b_coeffs = vec![GoldilocksField::zero(); 64];
        b_coeffs[0] = GoldilocksField::from_u64(5);
        b_coeffs[1] = GoldilocksField::from_u64(3);
        let b = RingElement::from_coeffs(b_coeffs);
        
        // Verify Lemma 2.3: ∥a·b∥_∞ ≤ ∥b∥_∞
        assert!(ring.verify_lemma_2_3(&a, &b));
    }
    
    #[test]
    fn test_lemma_2_4() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Create element with small norm
        let mut y_coeffs = vec![GoldilocksField::zero(); 64];
        y_coeffs[0] = GoldilocksField::from_u64(10);
        let y = RingElement::from_coeffs(y_coeffs);
        
        // Should be invertible (small norm)
        assert!(ring.verify_lemma_2_4(&y));
    }
    
    #[test]
    fn test_conjugation_automorphism() {
        // Test σ⁻¹(f) for f = 1 + 2X + 3X²
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(1);
        coeffs[1] = GoldilocksField::from_u64(2);
        coeffs[2] = GoldilocksField::from_u64(3);
        let f = RingElement::from_coeffs(coeffs);
        
        let f_conj = f.conjugate();
        
        // σ⁻¹(f) = 1 - 3X - 2X²  (in balanced representation)
        assert_eq!(f_conj.coeffs[0].to_canonical_u64(), 1);
        // -3 and -2 will be represented as q-3 and q-2
        let q = GoldilocksField::MODULUS;
        assert_eq!(f_conj.coeffs[1].to_canonical_u64(), q - 3);
        assert_eq!(f_conj.coeffs[2].to_canonical_u64(), q - 2);
    }
    
    #[test]
    fn test_conjugation_involution() {
        // Test that σ⁻¹(σ⁻¹(f)) = f
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(5);
        coeffs[1] = GoldilocksField::from_u64(7);
        coeffs[5] = GoldilocksField::from_u64(11);
        let f = RingElement::from_coeffs(coeffs);
        
        let f_conj_conj = f.conjugate().conjugate();
        
        // Should get back original
        assert_eq!(f.coeffs, f_conj_conj.coeffs);
    }
    
    #[test]
    fn test_inner_product_conjugate() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Test ⟨f, σ⁻¹(f)⟩ for f = 3 + 4X
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        let f = RingElement::from_coeffs(coeffs);
        
        let inner_prod = f.inner_product_conjugate(&f);
        
        // ⟨f, σ⁻¹(f)⟩ = f · σ⁻¹(f)
        // For f = 3 + 4X, σ⁻¹(f) = 3 - 4X^{63}
        // f · σ⁻¹(f) = (3 + 4X)(3 - 4X^{63})
        //            = 9 - 12X^{63} + 12X - 16X^{64}
        //            = 9 - 12X^{63} + 12X + 16  (since X^{64} = -1)
        //            = 25 + 12X - 12X^{63}
        
        // Constant term should be 25 = 3² + 4²
        assert_eq!(inner_prod.constant_term().to_canonical_u64(), 25);
    }
    
    #[test]
    fn test_constant_term_extraction() {
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(42);
        coeffs[1] = GoldilocksField::from_u64(100);
        let f = RingElement::from_coeffs(coeffs);
        
        assert_eq!(f.constant_term().to_canonical_u64(), 42);
    }
    
    #[test]
    fn test_inner_product_conjugate_property() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        // Test that ct(⟨f, σ⁻¹(f)⟩) = ∥f∥₂² for small coefficients
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(3);
        coeffs[1] = GoldilocksField::from_u64(4);
        coeffs[2] = GoldilocksField::from_u64(5);
        let f = RingElement::from_coeffs(coeffs);
        
        let inner_prod = f.inner_product_conjugate(&f);
        let ct = inner_prod.constant_term().to_canonical_u64();
        
        // ∥f∥₂² = 3² + 4² + 5² = 9 + 16 + 25 = 50
        assert_eq!(ct, 50);
    }
}
