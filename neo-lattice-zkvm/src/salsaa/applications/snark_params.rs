// SNARK Parameter Selection and Configuration
//
// This module implements parameter selection for the SALSAA SNARK construction
// as described in Theorem 1 of the SALSAA paper. It provides:
// - Automatic parameter selection based on witness size and security level
// - Proof size estimation
// - Prover/verifier complexity estimation
// - vSIS hardness verification

use std::sync::Arc;
use crate::ring::cyclotomic::CyclotomicRing;

/// Security levels in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 128-bit security
    Bits128,
    /// 192-bit security  
    Bits192,
    /// 256-bit security
    Bits256,
}

impl SecurityLevel {
    pub fn bits(&self) -> usize {
        match self {
            SecurityLevel::Bits128 => 128,
            SecurityLevel::Bits192 => 192,
            SecurityLevel::Bits256 => 256,
        }
    }
}

/// Challenge set type for folding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeSet {
    /// Subtractive set (from KLNO24)
    Subtractive,
    /// Large set (from KLNO25) - better parameters
    Large,
}

/// SNARK parameters for a specific instance
#[derive(Debug, Clone)]
pub struct SNARKParams {
    /// Security level λ
    pub security_level: SecurityLevel,
    
    /// Cyclotomic ring R = Z[ζ_f]
    pub ring: Arc<CyclotomicRing>,
    
    /// Modulus q
    pub modulus: u64,
    
    /// Witness size m = d^µ
    pub witness_size: usize,
    
    /// Degree bound per variable
    pub d: usize,
    
    /// Number of variables µ = log_d(m)
    pub mu: usize,
    
    /// Number of witness columns r
    pub r: usize,
    
    /// Norm bound β
    pub beta: f64,
    
    /// Number of structured rounds
    pub structured_rounds: usize,
    
    /// Number of unstructured rounds
    pub unstructured_rounds: usize,
    
    /// Random projection dimension m_rp
    pub projection_dim: usize,
    
    /// Base decomposition parameters
    pub decomp_base: u64,
    pub decomp_digits: usize,
    
    /// Challenge set type
    pub challenge_set: ChallengeSet,
    
    /// Knowledge error κ
    pub knowledge_error: f64,
}

impl SNARKParams {
    /// Create SNARK parameters for a given witness size and security level
    ///
    /// This implements the parameter selection strategy from Theorem 1:
    /// - Choose d, µ such that m = d^µ
    /// - Set structured rounds = µ
    /// - Set unstructured rounds = O(log λ)
    /// - Select q, β to ensure vSIS hardness
    pub fn for_witness_size(
        witness_size: usize,
        num_columns: usize,
        security_level: SecurityLevel,
    ) -> Result<Self, String> {
        let lambda = security_level.bits();
        
        // Choose d and µ
        // Strategy: d ≈ λ for good proof size, µ = log_d(m)
        let d = Self::choose_degree_bound(witness_size, lambda);
        let mu = Self::compute_mu(witness_size, d);
        
        // Verify m = d^µ (approximately)
        let actual_m = d.pow(mu as u32);
        if actual_m < witness_size {
            return Err(format!(
                "Computed m = {}^{} = {} < witness_size = {}",
                d, mu, actual_m, witness_size
            ));
        }
        
        // Number of rounds
        let structured_rounds = mu;
        let unstructured_rounds = Self::compute_unstructured_rounds(lambda);
        
        // Random projection dimension: m_rp = O(λ)
        let projection_dim = 2 * lambda;
        
        // Base decomposition parameters
        // Choose base b ≈ √q for good norm reduction
        let (decomp_base, decomp_digits) = Self::choose_decomposition_params(lambda);
        
        // Select cyclotomic ring and modulus
        let (ring, modulus) = Self::select_ring_and_modulus(lambda, d, mu)?;
        
        // Compute norm bound β
        // β should be large enough for honest witness but small enough for security
        let beta = Self::compute_norm_bound(&ring, witness_size, num_columns);
        
        // Verify vSIS hardness
        let vsis_secure = Self::verify_vsis_hardness(
            &ring,
            modulus,
            beta,
            security_level,
        )?;
        
        if !vsis_secure {
            return Err("vSIS assumption does not hold for these parameters".to_string());
        }
        
        // Compute knowledge error
        let knowledge_error = Self::compute_knowledge_error(d, mu, num_columns, &ring);
        
        Ok(SNARKParams {
            security_level,
            ring,
            modulus,
            witness_size: actual_m,
            d,
            mu,
            r: num_columns,
            beta,
            structured_rounds,
            unstructured_rounds,
            projection_dim,
            decomp_base,
            decomp_digits,
            challenge_set: ChallengeSet::Large,
            knowledge_error,
        })
    }
    
    /// Choose degree bound d based on witness size and security level
    ///
    /// Strategy: d ≈ λ gives good proof size O(λ log³ m / log λ)
    fn choose_degree_bound(witness_size: usize, lambda: usize) -> usize {
        // Start with d ≈ λ
        let mut d = lambda;
        
        // Adjust to ensure reasonable µ
        let mu = (witness_size as f64).log(d as f64).ceil() as usize;
        
        // If µ is too small (< 3), increase d
        if mu < 3 {
            d = (witness_size as f64).powf(1.0 / 3.0).ceil() as usize;
        }
        
        // If µ is too large (> 20), decrease d
        if mu > 20 {
            d = (witness_size as f64).powf(1.0 / 20.0).ceil() as usize;
        }
        
        // Ensure d >= 2
        d.max(2)
    }
    
    /// Compute µ = ⌈log_d(m)⌉
    fn compute_mu(witness_size: usize, d: usize) -> usize {
        (witness_size as f64).log(d as f64).ceil() as usize
    }
    
    /// Compute number of unstructured rounds
    ///
    /// After structured rounds reduce witness to size O(λ²),
    /// need O(log λ) more rounds to reach constant size
    fn compute_unstructured_rounds(lambda: usize) -> usize {
        // log₂(λ) rounds
        (lambda as f64).log2().ceil() as usize
    }
    
    /// Choose base decomposition parameters
    ///
    /// Strategy: base b ≈ √q, digits ℓ ≈ log_b(q)
    fn choose_decomposition_params(lambda: usize) -> (u64, usize) {
        // For λ = 128: b ≈ 2^16, ℓ ≈ 4
        // For λ = 192: b ≈ 2^20, ℓ ≈ 5  
        // For λ = 256: b ≈ 2^24, ℓ ≈ 5
        match lambda {
            128 => (1 << 16, 4),
            192 => (1 << 20, 5),
            256 => (1 << 24, 5),
            _ => (1 << 16, 4),
        }
    }
    
    /// Select cyclotomic ring and modulus
    ///
    /// Requirements:
    /// - Ring degree φ = φ(f) should be large enough for security
    /// - Modulus q should be prime with q ≡ 1 (mod f) for CRT splitting
    /// - Splitting degree e should be small (e ≤ 8) for efficiency
    fn select_ring_and_modulus(
        lambda: usize,
        d: usize,
        mu: usize,
    ) -> Result<(Arc<CyclotomicRing>, u64), String> {
        // Choose conductor f
        // Common choices: f = 2^k (power of 2) or f = p (prime)
        let conductor = Self::choose_conductor(lambda);
        
        // Choose modulus q
        // q should be prime with q ≡ 1 (mod f)
        // q ≈ 2^(2λ) for security
        let modulus = Self::choose_modulus(lambda, conductor)?;
        
        // Create ring
        let ring = Arc::new(CyclotomicRing::new(conductor, modulus)?);
        
        Ok((ring, modulus))
    }
    
    /// Choose conductor f for cyclotomic field
    fn choose_conductor(lambda: usize) -> u64 {
        // Use power-of-2 cyclotomic for efficiency
        // φ(2^k) = 2^(k-1)
        match lambda {
            128 => 256,  // φ = 128
            192 => 512,  // φ = 256
            256 => 1024, // φ = 512
            _ => 256,
        }
    }
    
    /// Choose modulus q
    ///
    /// Requirements:
    /// - q prime
    /// - q ≡ 1 (mod f) for CRT splitting
    /// - q ≈ 2^(2λ) for vSIS security
    /// - Splitting degree e = ord_f(q) should be small
    fn choose_modulus(lambda: usize, conductor: u64) -> Result<u64, String> {
        // Target size: q ≈ 2^(2λ)
        let target_bits = 2 * lambda;
        
        // Find prime q ≡ 1 (mod f) near 2^(target_bits)
        let start = 1u64 << target_bits;
        
        for offset in 0..10000 {
            let candidate = start + offset * conductor;
            if Self::is_prime_fast(candidate) && candidate % conductor == 1 {
                // Check splitting degree
                let e = Self::multiplicative_order(candidate, conductor);
                if e <= 8 {
                    return Ok(candidate);
                }
            }
        }
        
        Err(format!(
            "Could not find suitable modulus for λ={}, f={}",
            lambda, conductor
        ))
    }
    
    /// Fast primality test (Miller-Rabin)
    fn is_prime_fast(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        
        // Miller-Rabin with a few witnesses
        let witnesses = [2u64, 3, 5, 7, 11, 13, 17, 19, 23];
        
        // Write n-1 as 2^r * d
        let mut d = n - 1;
        let mut r = 0;
        while d % 2 == 0 {
            d /= 2;
            r += 1;
        }
        
        'witness: for &a in &witnesses {
            if a >= n {
                continue;
            }
            
            let mut x = Self::mod_pow(a, d, n);
            if x == 1 || x == n - 1 {
                continue 'witness;
            }
            
            for _ in 0..r - 1 {
                x = Self::mod_mul(x, x, n);
                if x == n - 1 {
                    continue 'witness;
                }
            }
            
            return false;
        }
        
        true
    }
    
    /// Modular exponentiation: a^b mod n
    fn mod_pow(mut a: u64, mut b: u64, n: u64) -> u64 {
        let mut result = 1u64;
        a %= n;
        
        while b > 0 {
            if b % 2 == 1 {
                result = Self::mod_mul(result, a, n);
            }
            a = Self::mod_mul(a, a, n);
            b /= 2;
        }
        
        result
    }
    
    /// Modular multiplication: (a * b) mod n
    fn mod_mul(a: u64, b: u64, n: u64) -> u64 {
        ((a as u128 * b as u128) % n as u128) as u64
    }
    
    /// Compute multiplicative order of q modulo f
    fn multiplicative_order(q: u64, f: u64) -> usize {
        let mut order = 1;
        let mut power = q % f;
        
        while power != 1 {
            power = (power * q) % f;
            order += 1;
            
            if order > 1000 {
                return order; // Give up if too large
            }
        }
        
        order
    }
    
    /// Compute norm bound β for honest witness
    ///
    /// β should be:
    /// - Large enough that honest witness satisfies ∥W∥_{σ,2} ≤ β
    /// - Small enough that vSIS is hard
    fn compute_norm_bound(ring: &CyclotomicRing, m: usize, r: usize) -> f64 {
        // Honest witness typically has entries from discrete Gaussian
        // with parameter σ ≈ √(φ)
        let phi = ring.degree();
        let sigma = (phi as f64).sqrt();
        
        // Expected norm: ∥W∥_{σ,2} ≈ σ√(mr)
        // Set β = 6σ√(mr) for high probability bound
        6.0 * sigma * ((m * r) as f64).sqrt()
    }
    
    /// Verify vSIS hardness
    ///
    /// vSIS_{n,m,q,β}: Given A ∈ R_q^{n×m}, find x ∈ R^m with Ax = 0 and ∥x∥_{σ,2} ≤ β
    ///
    /// Security requires:
    /// - β < q / (2√n) (for correctness)
    /// - Hermite factor δ ≈ (β√n / q)^(1/n) should be ≥ 1.005 (for hardness)
    fn verify_vsis_hardness(
        ring: &CyclotomicRing,
        q: u64,
        beta: f64,
        security_level: SecurityLevel,
    ) -> Result<bool, String> {
        let phi = ring.degree();
        let lambda = security_level.bits();
        
        // Typical SNARK has n ≈ λ
        let n = lambda;
        
        // Check correctness condition: β < q / (2√n)
        let correctness_bound = (q as f64) / (2.0 * (n as f64).sqrt());
        if beta >= correctness_bound {
            return Err(format!(
                "Norm bound β = {} too large for correctness (need β < {})",
                beta, correctness_bound
            ));
        }
        
        // Check hardness via Hermite factor
        // δ = (β√n / q)^(1/(nφ))
        let hermite_factor = (beta * (n as f64).sqrt() / (q as f64))
            .powf(1.0 / (n * phi) as f64);
        
        // For security, need δ ≥ 1.005
        let min_hermite_factor = 1.005;
        
        if hermite_factor < min_hermite_factor {
            return Err(format!(
                "Hermite factor {} too small for security (need ≥ {})",
                hermite_factor, min_hermite_factor
            ));
        }
        
        // Additional check: q > 2β² for norm-check correctness
        if (q as f64) <= 2.0 * beta * beta {
            return Err(format!(
                "Modulus q = {} too small for norm-check (need q > 2β² = {})",
                q,
                2.0 * beta * beta
            ));
        }
        
        Ok(true)
    }
    
    /// Compute knowledge error κ
    ///
    /// From Corollary 1: κ = (2µ(d-1) + r - 1) / q^e
    fn compute_knowledge_error(d: usize, mu: usize, r: usize, ring: &CyclotomicRing) -> f64 {
        let e = ring.splitting_degree();
        let q = ring.modulus();
        
        let numerator = 2 * mu * (d - 1) + r - 1;
        let denominator = (q as f64).powi(e as i32);
        
        numerator as f64 / denominator
    }
    
    /// Estimate proof size in bits
    ///
    /// From Theorem 1: O(λ log³ m / log λ) bits
    ///
    /// Detailed breakdown:
    /// - Structured rounds: µ rounds × proof per round
    /// - Each round: norm-check + batching + decomp + split + projection + folding
    /// - Norm-check: (2d-1)µe log q + 3r log |R_q| bits
    /// - Other protocols: O(λ log q) bits each
    /// - Unstructured rounds: O(log λ) rounds × O(λ log q) bits
    /// - Final witness: O(λ²) ring elements
    pub fn proof_size_bits(&self) -> usize {
        let lambda = self.security_level.bits();
        let e = self.ring.splitting_degree();
        let log_q = (self.modulus as f64).log2().ceil() as usize;
        let log_rq = self.ring.degree() * log_q;
        
        // Structured rounds
        let mut structured_size = 0;
        for _ in 0..self.structured_rounds {
            // Norm-check (Π^norm+)
            let norm_check_size = (2 * self.d - 1) * self.mu * e * log_q + 3 * self.r * log_rq;
            structured_size += norm_check_size;
            
            // Batching: O(1) challenges
            structured_size += e * log_q;
            
            // Base decomposition: no communication
            
            // Split: y_top matrix
            structured_size += self.r * log_rq;
            
            // Random projection: y_proj matrix
            structured_size += self.projection_dim * self.r * log_rq;
            
            // Folding: O(1) challenges
            structured_size += e * log_q;
        }
        
        // Unstructured rounds
        let unstructured_size = self.unstructured_rounds * lambda * log_q;
        
        // Final witness: O(λ²) ring elements
        let final_witness_size = lambda * lambda * log_rq;
        
        structured_size + unstructured_size + final_witness_size
    }
    
    /// Estimate prover complexity in ring operations
    ///
    /// From Theorem 1: O(m) ring operations
    pub fn prover_ops(&self) -> usize {
        // Dominated by sumcheck in each structured round
        // Each sumcheck: O(mr) ring operations
        // Total: µ rounds × O(mr) = O(µmr) = O(m) since µ = O(log m), r = O(1)
        self.structured_rounds * self.witness_size * self.r
    }
    
    /// Estimate verifier complexity in ring operations
    ///
    /// From Theorem 1: O(log m · λ²) ring operations
    pub fn verifier_ops(&self) -> usize {
        let lambda = self.security_level.bits();
        
        // Each structured round: O(λ²) operations
        // Total: µ rounds × O(λ²) = O(log m · λ²)
        self.structured_rounds * lambda * lambda
    }
    
    /// Get human-readable parameter summary
    pub fn summary(&self) -> String {
        format!(
            "SALSAA SNARK Parameters:\n\
             Security: {} bits\n\
             Witness size: m = {}^{} = {}\n\
             Columns: r = {}\n\
             Norm bound: β = {:.2e}\n\
             Ring: Z[ζ_{}] / {}Z, φ = {}, e = {}\n\
             Structured rounds: {}\n\
             Unstructured rounds: {}\n\
             Proof size: {} bits ({:.2} KB)\n\
             Prover ops: {} ({:.2e})\n\
             Verifier ops: {} ({:.2e})\n\
             Knowledge error: {:.2e}",
            self.security_level.bits(),
            self.d,
            self.mu,
            self.witness_size,
            self.r,
            self.beta,
            self.ring.conductor(),
            self.modulus,
            self.ring.degree(),
            self.ring.splitting_degree(),
            self.structured_rounds,
            self.unstructured_rounds,
            self.proof_size_bits(),
            self.proof_size_bits() as f64 / 8192.0,
            self.prover_ops(),
            self.prover_ops() as f64,
            self.verifier_ops(),
            self.verifier_ops() as f64,
            self.knowledge_error,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parameter_selection_small() {
        let params = SNARKParams::for_witness_size(
            1024,  // m = 1024
            1,     // r = 1
            SecurityLevel::Bits128,
        );
        
        assert!(params.is_ok());
        let params = params.unwrap();
        
        assert_eq!(params.witness_size, 1024);
        assert!(params.d >= 2);
        assert!(params.mu >= 1);
        assert_eq!(params.d.pow(params.mu as u32), params.witness_size);
    }
    
    #[test]
    fn test_parameter_selection_medium() {
        let params = SNARKParams::for_witness_size(
            1 << 20,  // m = 1M
            4,        // r = 4
            SecurityLevel::Bits128,
        );
        
        assert!(params.is_ok());
        let params = params.unwrap();
        
        println!("{}", params.summary());
    }
    
    #[test]
    fn test_primality() {
        assert!(SNARKParams::is_prime_fast(2));
        assert!(SNARKParams::is_prime_fast(3));
        assert!(SNARKParams::is_prime_fast(5));
        assert!(SNARKParams::is_prime_fast(7));
        assert!(SNARKParams::is_prime_fast(11));
        assert!(SNARKParams::is_prime_fast(97));
        
        assert!(!SNARKParams::is_prime_fast(1));
        assert!(!SNARKParams::is_prime_fast(4));
        assert!(!SNARKParams::is_prime_fast(6));
        assert!(!SNARKParams::is_prime_fast(100));
    }
    
    #[test]
    fn test_multiplicative_order() {
        // ord_8(3) = 2 since 3^2 ≡ 1 (mod 8)
        assert_eq!(SNARKParams::multiplicative_order(3, 8), 2);
        
        // ord_7(2) = 3 since 2^3 ≡ 1 (mod 7)
        assert_eq!(SNARKParams::multiplicative_order(2, 7), 3);
    }
}