//! Parameter Selection for Cyclo (Section 6.1 and Appendix C)

use crate::field::FiniteField;
use super::types::*;

/// Parameter set for Cyclo folding scheme
#[derive(Clone, Debug)]
pub struct ParameterSet<F: FiniteField> {
    /// Security level (128, 192, 256 bits)
    pub security_level: usize,
    /// Cyclotomic conductor f
    pub conductor: usize,
    /// Ring degree φ = φ(f)
    pub degree: usize,
    /// Prime modulus q (in bits)
    pub modulus_bits: usize,
    /// Extension degree e
    pub extension_degree: usize,
    /// Decomposition base b
    pub base_b: usize,
    /// Initial norm bound B
    pub norm_bound_B: u64,
    /// Ajtai commitment rank a
    pub rank_a: usize,
    /// Extended rank a'
    pub rank_a_prime: usize,
    /// Witness length m
    pub witness_length: usize,
    /// Maximum folding rounds
    pub max_folding_rounds: usize,
    /// Soundness error target
    pub soundness_error: f64,
}

impl<F: FiniteField> ParameterSet<F> {
    /// Default parameters (similar to Table 2 in paper)
    pub fn default_128bit() -> Self {
        Self {
            security_level: 128,
            conductor: 256,        // f = 2^8, so φ = 128
            degree: 128,
            modulus_bits: 50,      // ~2^50 for efficiency
            extension_degree: 2,   // Splits to quadratic extensions
            base_b: 1,            // Ternary decomposition
            norm_bound_B: 1024,   // 2^10
            rank_a: 13,
            rank_a_prime: 13,
            witness_length: 1 << 20,  // 2^20
            max_folding_rounds: 64,
            soundness_error: 2.0f64.powi(-80),
        }
    }

    /// High security parameters (256-bit)
    pub fn high_security_256bit() -> Self {
        Self {
            security_level: 256,
            conductor: 512,
            degree: 256,
            modulus_bits: 60,
            extension_degree: 2,
            base_b: 1,
            norm_bound_B: 2048,
            rank_a: 26,
            rank_a_prime: 26,
            witness_length: 1 << 20,
            max_folding_rounds: 64,
            soundness_error: 2.0f64.powi(-200),
        }
    }

    /// Compact parameters (smaller proofs)
    pub fn compact() -> Self {
        Self {
            security_level: 128,
            conductor: 128,
            degree: 64,
            modulus_bits: 48,
            extension_degree: 2,
            base_b: 1,
            norm_bound_B: 512,
            rank_a: 10,
            rank_a_prime: 10,
            witness_length: 1 << 18,
            max_folding_rounds: 32,
            soundness_error: 2.0f64.powi(-80),
        }
    }

    /// Validate parameter set
    pub fn validate(&self) -> Result<(), String> {
        // Check conductor is power of 2 for efficient arithmetic
        if !self.conductor.is_power_of_two() {
            return Err("Conductor must be power of 2".to_string());
        }

        // Check degree matches conductor
        let expected_degree = euler_totient(self.conductor);
        if self.degree != expected_degree {
            return Err(format!(
                "Degree mismatch: expected {}, got {}",
                expected_degree, self.degree
            ));
        }

        // Check modulus is sufficient
        if self.modulus_bits < 32 {
            return Err("Modulus too small".to_string());
        }

        // Check rank is positive
        if self.rank_a == 0 || self.rank_a_prime == 0 {
            return Err("Ranks must be positive".to_string());
        }

        // Check base is valid
        if self.base_b == 0 {
            return Err("Base b must be positive".to_string());
        }

        Ok(())
    }

    /// Compute proof size estimate
    pub fn estimate_proof_size(&self) -> ProofSizeEstimate {
        let L = 1; // Number of relations to fold
        let k = 3; // R1CS has 3 matrices
        let n = 1; // Number of evaluation points
        
        // Extension commitment: La' ring elements
        let ext_commitment_size = L * self.rank_a_prime * self.degree * (self.modulus_bits / 8);

        // Range test: sum-check over ℓ rounds with degree 2b+2
        let ell = ((self.witness_length * self.degree) as f64).log2().ceil() as usize;
        let range_sumcheck_size = L * (2 * self.base_b + 2) * ell * self.extension_degree * (self.modulus_bits / 8);

        // Unification sum-check
        let unification_vars = ((2 + k + L * (2 + n + k)) as f64).log2().ceil() as usize;
        let unification_size = 2 * unification_vars * self.extension_degree * (self.modulus_bits / 8);

        // Evaluation claims: (k+2)(L+1) ring elements
        let eval_claims_size = (k + 2) * (L + 1) * self.degree * (self.modulus_bits / 8);

        let total_bytes = ext_commitment_size + range_sumcheck_size + unification_size + eval_claims_size;

        ProofSizeEstimate {
            extension_commitment_kb: (ext_commitment_size / 1024) as f64,
            range_test_kb: (range_sumcheck_size / 1024) as f64,
            unification_kb: (unification_size / 1024) as f64,
            evaluation_claims_kb: (eval_claims_size / 1024) as f64,
            total_kb: (total_bytes / 1024) as f64,
        }
    }

    /// Compute prover time estimate (ring multiplications)
    pub fn estimate_prover_time(&self) -> ProverTimeEstimate {
        let L = 1;
        let ell = ((2.0f64 * self.norm_bound_B as f64).log(2.0 * self.base_b as f64)).ceil() as usize;

        // Extension commitment: La'm'ℓ = La'm log_{2b}(2B)
        let ext_commitment_muls = L * self.rank_a_prime * self.witness_length * ell;

        // Range test: dominated by MLE evaluations
        let range_muls = L * self.witness_length * ell;

        // Unification sum-check
        let unification_muls = (L + 1) * self.witness_length * ell;

        // Folding: linear combination
        let folding_muls = self.witness_length * ell;

        ProverTimeEstimate {
            extension_commitment_muls: ext_commitment_muls,
            range_test_muls: range_muls,
            unification_muls: unification_muls,
            folding_muls,
            total_muls: ext_commitment_muls + range_muls + unification_muls + folding_muls,
        }
    }

    /// Compute verifier time estimate
    pub fn estimate_verifier_time(&self) -> VerifierTimeEstimate {
        let L = 1;

        // Extension commitment verification: La' multiplications
        let ext_verification_muls = L * self.rank_a_prime;

        // Range test verification: sum-check verification
        let ell = ((self.witness_length * self.degree) as f64).log2().ceil() as usize;
        let range_verification_muls = L * ell;

        // Unification verification
        let k = 3;
        let n = 1;
        let unification_vars = ((2 + k + L * (2 + n + k)) as f64).log2().ceil() as usize;
        let unification_verification_muls = unification_vars;

        // Folding computation
        let folding_verification_muls = L * self.rank_a_prime;

        VerifierTimeEstimate {
            extension_verification_muls: ext_verification_muls,
            range_verification_muls: range_verification_muls,
            unification_verification_muls: unification_verification_muls,
            folding_verification_muls: folding_verification_muls,
            total_muls: ext_verification_muls + range_verification_muls + 
                       unification_verification_muls + folding_verification_muls,
        }
    }

    /// Compute memory usage estimate
    pub fn estimate_memory_usage(&self) -> MemoryUsageEstimate {
        let ell = ((2.0f64 * self.norm_bound_B as f64).log(2.0 * self.base_b as f64)).ceil() as usize;
        let m_tilde = self.witness_length * ell;

        // Store witness: (L+1) * m' ring elements
        let L = 1;
        let witness_memory_mb = ((L + 1) * m_tilde * self.degree * (self.modulus_bits / 8)) as f64 / (1024.0 * 1024.0);

        // Store matrices: a × m' for commitment
        let matrix_memory_mb = (self.rank_a * m_tilde * self.degree * (self.modulus_bits / 8)) as f64 / (1024.0 * 1024.0);

        // MLE evaluations for sum-check
        let mle_memory_mb = (m_tilde * self.degree * (self.modulus_bits / 8)) as f64 / (1024.0 * 1024.0);

        MemoryUsageEstimate {
            witness_mb: witness_memory_mb,
            matrices_mb: matrix_memory_mb,
            mle_evaluations_mb: mle_memory_mb,
            total_mb: witness_memory_mb + matrix_memory_mb + mle_memory_mb,
        }
    }

    /// Compute accumulated norm after T folding rounds
    pub fn compute_accumulated_norm(&self, rounds: usize, num_relations: usize) -> u64 {
        // β_T = β_0 + T · L · b · γ
        let gamma = 2; // Approximate expansion factor for ternary
        let per_round_growth = num_relations * self.base_b * gamma;
        self.norm_bound_B + (per_round_growth * rounds) as u64
    }

    /// Convert to CycloParams
    pub fn to_cyclo_params(&self, modulus: F) -> CycloParams<F> {
        CycloParams {
            conductor: self.conductor,
            modulus,
            extension_degree: self.extension_degree,
            base_b: self.base_b,
            norm_bound_B: F::from_u64(self.norm_bound_B),
            rank_a: self.rank_a,
            rank_a_prime: self.rank_a_prime,
            witness_length: self.witness_length,
            max_folding_rounds: self.max_folding_rounds,
            expansion_factor: F::from_u64(2), // For ternary
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofSizeEstimate {
    pub extension_commitment_kb: f64,
    pub range_test_kb: f64,
    pub unification_kb: f64,
    pub evaluation_claims_kb: f64,
    pub total_kb: f64,
}

#[derive(Clone, Debug)]
pub struct ProverTimeEstimate {
    pub extension_commitment_muls: usize,
    pub range_test_muls: usize,
    pub unification_muls: usize,
    pub folding_muls: usize,
    pub total_muls: usize,
}

#[derive(Clone, Debug)]
pub struct VerifierTimeEstimate {
    pub extension_verification_muls: usize,
    pub range_verification_muls: usize,
    pub unification_verification_muls: usize,
    pub folding_verification_muls: usize,
    pub total_muls: usize,
}

#[derive(Clone, Debug)]
pub struct MemoryUsageEstimate {
    pub witness_mb: f64,
    pub matrices_mb: f64,
    pub mle_evaluations_mb: f64,
    pub total_mb: f64,
}

/// Builder for custom parameter sets
pub struct ParameterBuilder<F: FiniteField> {
    params: ParameterSet<F>,
}

impl<F: FiniteField> ParameterBuilder<F> {
    pub fn new() -> Self {
        Self {
            params: ParameterSet::default_128bit(),
        }
    }

    pub fn security_level(mut self, level: usize) -> Self {
        self.params.security_level = level;
        self
    }

    pub fn conductor(mut self, f: usize) -> Self {
        self.params.conductor = f;
        self.params.degree = euler_totient(f);
        self
    }

    pub fn modulus_bits(mut self, bits: usize) -> Self {
        self.params.modulus_bits = bits;
        self
    }

    pub fn base_b(mut self, b: usize) -> Self {
        self.params.base_b = b;
        self
    }

    pub fn witness_length(mut self, m: usize) -> Self {
        self.params.witness_length = m;
        self
    }

    pub fn max_folding_rounds(mut self, rounds: usize) -> Self {
        self.params.max_folding_rounds = rounds;
        self
    }

    pub fn build(self) -> Result<ParameterSet<F>, String> {
        self.params.validate()?;
        Ok(self.params)
    }
}
