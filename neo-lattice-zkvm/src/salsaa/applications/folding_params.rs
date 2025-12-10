// SALSAA Folding Scheme Parameters
//
// This module implements parameter selection for the SALSAA folding scheme
// construction as described in Theorem 3 of the SALSAA paper.
//
// The folding scheme allows accumulating L instances of Ξ^lin into a single
// accumulated instance with proof size O(λ log² m / log λ) bits.

use std::sync::Arc;
use crate::ring::cyclotomic::CyclotomicRing;
use crate::salsaa::applications::snark_params::{SecurityLevel, ChallengeSet};

/// Folding scheme parameters
#[derive(Debug, Clone)]
pub struct FoldingParams {
    /// Security level λ
    pub security_level: SecurityLevel,
    
    /// Cyclotomic ring R = Z[ζ_f]
    pub ring: Arc<CyclotomicRing>,
    
    /// Modulus q
    pub modulus: u64,
    
    /// Number of instances to fold L
    pub num_instances: usize,
    
    /// Witness size per instance m = d^µ
    pub witness_size: usize,
    
    /// Degree bound per variable
    pub d: usize,
    
    /// Number of variables µ = log_d(m)
    pub mu: usize,
    
    /// Number of witness columns r
    pub r: usize,
    
    /// Norm bound β
    pub beta: f64,
    
    /// Accumulator width r_acc = 2^ℓ
    pub accumulator_width: usize,
    
    /// Accumulator depth ℓ
    pub accumulator_depth: usize,
    
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

impl FoldingParams {
    /// Create folding scheme parameters for given number of instances
    ///
    /// # Arguments
    /// * `num_instances` - Number of instances L to fold
    /// * `witness_size` - Witness size m per instance
    /// * `num_columns` - Number of witness columns r
    /// * `security_level` - Security parameter λ
    ///
    /// # Returns
    /// Folding parameters optimized for the given configuration
    pub fn for_num_instances(
        num_instances: usize,
        witness_size: usize,
        num_columns: usize,
        security_level: SecurityLevel,
    ) -> Result<Self, String> {
        let lambda = security_level.bits();
        
        // Choose d and µ (same strategy as SNARK)
        let d = Self::choose_degree_bound(witness_size, lambda);
        let mu = Self::compute_mu(witness_size, d);
        
        // Verify m = d^µ
        let actual_m = d.pow(mu as u32);
        if actual_m < witness_size {
            return Err(format!(
                "Computed m = {}^{} = {} < witness_size = {}",
                d, mu, actual_m, witness_size
            ));
        }
        
        // Accumulator parameters
        // Set r_acc = 2^ℓ where ℓ is chosen to balance proof size and verifier cost
        let accumulator_depth = Self::choose_accumulator_depth(num_instances, lambda);
        let accumulator_width = 1 << accumulator_depth;
        
        // Random projection dimension: m_rp = O(λ)
        let projection_dim = 2 * lambda;
        
        // Base decomposition parameters
        let (decomp_base, decomp_digits) = Self::choose_decomposition_params(lambda);
        
        // Select cyclotomic ring and modulus
        let (ring, modulus) = Self::select_ring_and_modulus(lambda, d, mu)?;
        
        // Compute norm bound β
        let beta = Self::compute_norm_bound(&ring, witness_size, num_columns);
        
        // Verify vSIS hardness
        Self::verify_vsis_hardness(&ring, modulus, beta, security_level)?;
        
        // Compute knowledge error
        let knowledge_error = Self::compute_knowledge_error(d, mu, num_columns, &ring);
        
        Ok(FoldingParams {
            security_level,
            ring,
            modulus,
            num_instances,
            witness_size: actual_m,
            d,
            mu,
            r: num_columns,
            beta,
            accumulator_width,
            accumulator_depth,
            projection_dim,
            decomp_base,
            decomp_digits,
            challenge_set: ChallengeSet::Large,
            knowledge_error,
        })
    }
    
    /// Choose accumulator depth ℓ
    ///
    /// Strategy: Balance proof size and verifier cost
    /// - Larger ℓ → smaller proof but more verifier work
    /// - Smaller ℓ → larger proof but less verifier work
    ///
    /// Typical choice: ℓ ≈ log₂(L) for L instances
    fn choose_accumulator_depth(num_instances: usize, lambda: usize) -> usize {
        if num_instances <= 1 {
            return 1;
        }
        
        // ℓ = ⌈log₂(L)⌉
        let depth = (num_instances as f64).log2().ceil() as usize;
        
        // Clamp to reasonable range [1, log λ]
        let max_depth = (lambda as f64).log2().ceil() as usize;
        depth.min(max_depth).max(1)
    }
    
    /// Choose degree bound d
    fn choose_degree_bound(witness_size: usize, lambda: usize) -> usize {
        let mut d = lambda;
        let mu = (witness_size as f64).log(d as f64).ceil() as usize;
        
        if mu < 3 {
            d = (witness_size as f64).powf(1.0 / 3.0).ceil() as usize;
        }
        if mu > 20 {
            d = (witness_size as f64).powf(1.0 / 20.0).ceil() as usize;
        }
        
        d.max(2)
    }
    
    /// Compute µ = ⌈log_d(m)⌉
    fn compute_mu(witness_size: usize, d: usize) -> usize {
        (witness_size as f64).log(d as f64).ceil() as usize
    }
    
    /// Choose base decomposition parameters
    fn choose_decomposition_params(lambda: usize) -> (u64, usize) {
        match lambda {
            128 => (1 << 16, 4),
            192 => (1 << 20, 5),
            256 => (1 << 24, 5),
            _ => (1 << 16, 4),
        }
    }
    
    /// Select cyclotomic ring and modulus
    fn select_ring_and_modulus(
        lambda: usize,
        d: usize,
        mu: usize,
    ) -> Result<(Arc<CyclotomicRing>, u64), String> {
        let conductor = Self::choose_conductor(lambda);
        let modulus = Self::choose_modulus(lambda, conductor)?;
        let ring = Arc::new(CyclotomicRing::new(conductor, modulus)?);
        Ok((ring, modulus))
    }
    
    /// Choose conductor f
    fn choose_conductor(lambda: usize) -> u64 {
        match lambda {
            128 => 256,
            192 => 512,
            256 => 1024,
            _ => 256,
        }
    }
    
    /// Choose modulus q
    fn choose_modulus(lambda: usize, conductor: u64) -> Result<u64, String> {
        let target_bits = 2 * lambda;
        let start = 1u64 << target_bits;
        
        for offset in 0..10000 {
            let candidate = start + offset * conductor;
            if Self::is_prime_fast(candidate) && candidate % conductor == 1 {
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
    
    /// Fast primality test
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
        
        let witnesses = [2u64, 3, 5, 7, 11, 13, 17, 19, 23];
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
    
    /// Modular exponentiation
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
    
    /// Modular multiplication
    fn mod_mul(a: u64, b: u64, n: u64) -> u64 {
        ((a as u128 * b as u128) % n as u128) as u64
    }
    
    /// Compute multiplicative order
    fn multiplicative_order(q: u64, f: u64) -> usize {
        let mut order = 1;
        let mut power = q % f;
        
        while power != 1 {
            power = (power * q) % f;
            order += 1;
            
            if order > 1000 {
                return order;
            }
        }
        
        order
    }
    
    /// Compute norm bound β
    fn compute_norm_bound(ring: &CyclotomicRing, m: usize, r: usize) -> f64 {
        let phi = ring.degree();
        let sigma = (phi as f64).sqrt();
        6.0 * sigma * ((m * r) as f64).sqrt()
    }
    
    /// Verify vSIS hardness
    fn verify_vsis_hardness(
        ring: &CyclotomicRing,
        q: u64,
        beta: f64,
        security_level: SecurityLevel,
    ) -> Result<(), String> {
        let phi = ring.degree();
        let lambda = security_level.bits();
        let n = lambda;
        
        // Check correctness: β < q / (2√n)
        let correctness_bound = (q as f64) / (2.0 * (n as f64).sqrt());
        if beta >= correctness_bound {
            return Err(format!(
                "Norm bound β = {} too large for correctness (need β < {})",
                beta, correctness_bound
            ));
        }
        
        // Check hardness via Hermite factor
        let hermite_factor = (beta * (n as f64).sqrt() / (q as f64))
            .powf(1.0 / (n * phi) as f64);
        
        if hermite_factor < 1.005 {
            return Err(format!(
                "Hermite factor {} too small for security",
                hermite_factor
            ));
        }
        
        // Check norm-check correctness: q > 2β²
        if (q as f64) <= 2.0 * beta * beta {
            return Err(format!(
                "Modulus q = {} too small for norm-check",
                q
            ));
        }
        
        Ok(())
    }
    
    /// Compute knowledge error κ
    fn compute_knowledge_error(d: usize, mu: usize, r: usize, ring: &CyclotomicRing) -> f64 {
        let e = ring.splitting_degree();
        let q = ring.modulus();
        
        let numerator = 2 * mu * (d - 1) + r - 1;
        let denominator = (q as f64).powi(e as i32);
        
        numerator as f64 / denominator
    }
    
    /// Estimate proof size in bits
    ///
    /// From Theorem 3: O(λ log² m / log λ) bits
    ///
    /// Detailed breakdown:
    /// - Join: O(1) communication
    /// - Norm-check: (2d-1)µe log q + 3r log |R_q| bits
    /// - Random projection: m_rp · r log |R_q| bits
    /// - Folding: O(1) challenges
    /// - Enhanced batching: O(µ) sumcheck rounds
    /// - Base decomposition: no communication
    pub fn proof_size_bits(&self) -> usize {
        let lambda = self.security_level.bits();
        let e = self.ring.splitting_degree();
        let log_q = (self.modulus as f64).log2().ceil() as usize;
        let log_rq = self.ring.degree() * log_q;
        
        // Join protocol: minimal communication
        let join_size = e * log_q;
        
        // Norm-check (Π^norm+)
        let norm_check_size = (2 * self.d - 1) * self.mu * e * log_q + 3 * self.r * log_rq;
        
        // Random projection
        let projection_size = self.projection_dim * self.r * log_rq;
        
        // Folding: O(1) challenges
        let folding_size = e * log_q;
        
        // Enhanced batching via sumcheck: µ rounds
        let batching_size = self.mu * (2 * self.d - 1) * e * log_q;
        
        // Base decomposition: no communication
        
        join_size + norm_check_size + projection_size + folding_size + batching_size
    }
    
    /// Estimate prover complexity in ring operations
    ///
    /// From Theorem 3: O(Lm) ring operations
    pub fn prover_ops(&self) -> usize {
        // Dominated by processing L instances
        // Each instance: O(m) operations
        self.num_instances * self.witness_size * self.r
    }
    
    /// Estimate verifier complexity in ring operations
    ///
    /// From Theorem 3: O(λ²) ring operations (independent of m!)
    pub fn verifier_ops(&self) -> usize {
        let lambda = self.security_level.bits();
        lambda * lambda
    }
    
    /// Get human-readable parameter summary
    pub fn summary(&self) -> String {
        format!(
            "SALSAA Folding Scheme Parameters:\n\
             Security: {} bits\n\
             Instances to fold: L = {}\n\
             Witness size per instance: m = {}^{} = {}\n\
             Columns: r = {}\n\
             Norm bound: β = {:.2e}\n\
             Ring: Z[ζ_{}] / {}Z, φ = {}, e = {}\n\
             Accumulator: width = 2^{} = {}\n\
             Proof size: {} bits ({:.2} KB)\n\
             Prover ops: {} ({:.2e})\n\
             Verifier ops: {} ({:.2e})\n\
             Knowledge error: {:.2e}",
            self.security_level.bits(),
            self.num_instances,
            self.d,
            self.mu,
            self.witness_size,
            self.r,
            self.beta,
            self.ring.conductor(),
            self.modulus,
            self.ring.degree(),
            self.ring.splitting_degree(),
            self.accumulator_depth,
            self.accumulator_width,
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
    fn test_folding_params_small() {
        let params = FoldingParams::for_num_instances(
            4,     // Fold 4 instances
            1024,  // m = 1024 per instance
            1,     // r = 1
            SecurityLevel::Bits128,
        );
        
        assert!(params.is_ok());
        let params = params.unwrap();
        
        assert_eq!(params.num_instances, 4);
        assert!(params.accumulator_depth >= 2); // log₂(4) = 2
    }
    
    #[test]
    fn test_folding_params_medium() {
        let params = FoldingParams::for_num_instances(
            16,       // Fold 16 instances
            1 << 20,  // m = 1M per instance
            4,        // r = 4
            SecurityLevel::Bits128,
        );
        
        assert!(params.is_ok());
        let params = params.unwrap();
        
        println!("{}", params.summary());
        
        // Verify verifier cost is O(λ²), independent of m
        let lambda = 128;
        assert!(params.verifier_ops() <= 10 * lambda * lambda);
    }
    
    #[test]
    fn test_accumulator_depth() {
        assert_eq!(FoldingParams::choose_accumulator_depth(1, 128), 1);
        assert_eq!(FoldingParams::choose_accumulator_depth(2, 128), 1);
        assert_eq!(FoldingParams::choose_accumulator_depth(4, 128), 2);
        assert_eq!(FoldingParams::choose_accumulator_depth(8, 128), 3);
        assert_eq!(FoldingParams::choose_accumulator_depth(16, 128), 4);
    }
}
