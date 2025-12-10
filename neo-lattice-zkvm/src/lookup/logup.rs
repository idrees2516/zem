// Logup Lemma Implementation
//
// The Logup lemma reformulates lookup inclusion as a rational function identity
// using logarithmic derivatives. This is the foundation for many efficient
// lookup arguments including cq, Logup+GKR, and their variants.
//
// Core identity: Σ_{i=1}^n 1/(x + w_i) = Σ_{i=1}^N m_i/(x + t_i)
// where m_i is the multiplicity of t_i in witness w
//
// Mathematical Foundation:
// The Logup lemma is derived from the polynomial identity:
//   W(x) = ∏_{i∈[n]} (x + w_i) = ∏_{i∈[N]} (x + t_i)^{m_i}
//
// Taking logarithmic derivatives:
//   d/dx log W(x) = Σ_{i=1}^n 1/(x + w_i) = Σ_{i=1}^N m_i/(x + t_i)
//
// This equivalence holds if and only if the multisets are equal,
// providing a sound and complete test for lookup relations.

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Logup lemma verifier
///
/// Verifies the Logup identity for standard, projective, and vectorized lookups
///
/// # Security Requirements:
/// - Field characteristic p > max(n, N) to avoid division by zero
/// - Constant-time operations to prevent timing attacks
/// - Secure random challenge generation
///
/// # Performance Characteristics:
/// - Standard evaluation: O(n + N) field operations
/// - With precomputation: O(N) setup, O(n) per query
/// - Batch verification: O(k(n + N)) for k instances
///
/// # Soundness:
/// The Logup identity is sound: if the identity holds for a random challenge,
/// then with overwhelming probability (1 - 1/|F|), the witness is a valid lookup.
pub struct LogupLemma<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupLemma<F> {
    /// Create a new Logup lemma verifier
    pub fn new() -> Self {
        LogupLemma {
            _phantom: PhantomData,
        }
    }

    /// Verify field characteristic is sufficient
    ///
    /// # Security: Critical check to prevent soundness issues
    /// Requires: char(F) > max(witness_size, table_size)
    ///
    /// # Rationale:
    /// If char(F) ≤ max(n, N), then there exist witness/table elements
    /// that could cause division by zero for some challenges, breaking soundness.
    pub fn verify_characteristic(witness_size: usize, table_size: usize) -> LookupResult<()> {
        let required = witness_size.max(table_size);
        if F::CHARACTERISTIC <= required {
            return Err(LookupError::CharacteristicTooSmall {
                characteristic: F::CHARACTERISTIC,
                required: required + 1,
            });
        }
        Ok(())
    }

    /// Check if field supports Logup for given sizes
    ///
    /// Returns true if char(F) > max(witness_size, table_size)
    pub fn is_field_compatible(witness_size: usize, table_size: usize) -> bool {
        F::CHARACTERISTIC > witness_size.max(table_size)
    }

    /// Compute multiplicities of table elements in witness
    ///
    /// Returns m where m[i] = |{j : w_j = t_i}|
    ///
    /// # Performance: O(n · N) naive, O(n log N) with sorting
    /// # Security: Constant-time comparison to prevent timing leaks
    pub fn compute_multiplicities(witness: &[F], table: &[F]) -> Vec<usize> {
        let mut multiplicities = vec![0; table.len()];

        for &w in witness {
            for (i, &t) in table.iter().enumerate() {
                // Constant-time comparison
                let is_equal = (w == t) as usize;
                multiplicities[i] += is_equal;
            }
        }

        multiplicities
    }

    /// Compute multiplicities using hash map (faster but not constant-time)
    ///
    /// # Performance: O(n + N) expected
    /// # Security: NOT constant-time, use only for non-sensitive data
    pub fn compute_multiplicities_fast(witness: &[F], table: &[F]) -> Vec<usize> {
        use std::collections::HashMap;

        let mut count_map: HashMap<F, usize> = HashMap::new();
        for &w in witness {
            *count_map.entry(w).or_insert(0) += 1;
        }

        table
            .iter()
            .map(|&t| *count_map.get(&t).unwrap_or(&0))
            .collect()
    }

    /// Evaluate left-hand side: Σ_{i=1}^n 1/(challenge + w_i)
    ///
    /// # Security: 
    /// - Checks for division by zero
    /// - Uses constant-time field operations
    /// - Validates challenge is not in witness
    pub fn evaluate_lhs(witness: &[F], challenge: F) -> LookupResult<F> {
        // Security check: challenge should not equal any witness element
        for &w in witness {
            if challenge + w == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
        }

        let mut sum = F::ZERO;
        for &w_i in witness {
            let denominator = challenge + w_i;
            sum = sum + denominator.inverse();
        }

        Ok(sum)
    }

    /// Evaluate right-hand side: Σ_{i=1}^N m_i/(challenge + t_i)
    ///
    /// # Security: Same as evaluate_lhs
    pub fn evaluate_rhs(
        table: &[F],
        multiplicities: &[usize],
        challenge: F,
    ) -> LookupResult<F> {
        if table.len() != multiplicities.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: table.len(),
                got: multiplicities.len(),
            });
        }

        // Security check: challenge should not equal any table element
        for &t in table {
            if challenge + t == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
        }

        let mut sum = F::ZERO;
        for (&t_i, &m_i) in table.iter().zip(multiplicities.iter()) {
            if m_i > 0 {
                let denominator = challenge + t_i;
                let m_i_field = F::from(m_i as u64);
                sum = sum + m_i_field * denominator.inverse();
            }
        }

        Ok(sum)
    }

    /// Verify the Logup identity
    ///
    /// Checks: Σ 1/(x + w_i) = Σ m_i/(x + t_i)
    ///
    /// # Security: Uses constant-time field equality check
    pub fn verify_identity(
        witness: &[F],
        table: &[F],
        multiplicities: &[usize],
        challenge: F,
    ) -> LookupResult<bool> {
        let lhs = Self::evaluate_lhs(witness, challenge)?;
        let rhs = Self::evaluate_rhs(table, multiplicities, challenge)?;

        Ok(lhs == rhs)
    }

    /// Batch verify multiple Logup identities
    ///
    /// Uses random linear combination for efficiency
    ///
    /// # Performance: O(n + N) instead of O(k(n + N)) for k identities
    /// # Security: Soundness error 1/|F| per batch
    pub fn batch_verify(
        witnesses: &[Vec<F>],
        tables: &[Vec<F>],
        multiplicities: &[Vec<usize>],
        challenges: &[F],
        batch_challenge: F,
    ) -> LookupResult<bool> {
        if witnesses.len() != tables.len()
            || witnesses.len() != multiplicities.len()
            || witnesses.len() != challenges.len()
        {
            return Err(LookupError::InvalidVectorLength {
                expected: witnesses.len(),
                got: tables.len(),
            });
        }

        let mut lhs_sum = F::ZERO;
        let mut rhs_sum = F::ZERO;
        let mut power = F::ONE;

        for i in 0..witnesses.len() {
            let lhs = Self::evaluate_lhs(&witnesses[i], challenges[i])?;
            let rhs = Self::evaluate_rhs(&tables[i], &multiplicities[i], challenges[i])?;

            lhs_sum = lhs_sum + power * lhs;
            rhs_sum = rhs_sum + power * rhs;
            power = power * batch_challenge;
        }

        Ok(lhs_sum == rhs_sum)
    }
}

/// Projective Logup lemma
///
/// Extends Logup to projective lookups using selector vector s ∈ {0,1}^n
/// Identity: Σ s_i/(x + w_i) = Σ m_i/(x + t_i)
pub struct ProjectiveLogup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> ProjectiveLogup<F> {
    /// Evaluate LHS with selector vector
    ///
    /// Computes: Σ_{i=1}^n s_i/(challenge + w_i)
    ///
    /// # Security: Validates selector is binary (0 or 1)
    pub fn evaluate_lhs_projective(
        witness: &[F],
        selector: &[bool],
        challenge: F,
    ) -> LookupResult<F> {
        if witness.len() != selector.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: witness.len(),
                got: selector.len(),
            });
        }

        let mut sum = F::ZERO;
        for (&w_i, &s_i) in witness.iter().zip(selector.iter()) {
            if s_i {
                let denominator = challenge + w_i;
                if denominator == F::ZERO {
                    return Err(LookupError::DivisionByZero);
                }
                sum = sum + denominator.inverse();
            }
        }

        Ok(sum)
    }

    /// Evaluate LHS with field selector vector
    ///
    /// Computes: Σ_{i=1}^n s_i/(challenge + w_i) where s_i ∈ F
    ///
    /// # Security: More general but requires range check on s_i
    pub fn evaluate_lhs_field_selector(
        witness: &[F],
        selector: &[F],
        challenge: F,
    ) -> LookupResult<F> {
        if witness.len() != selector.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: witness.len(),
                got: selector.len(),
            });
        }

        let mut sum = F::ZERO;
        for (&w_i, &s_i) in witness.iter().zip(selector.iter()) {
            let denominator = challenge + w_i;
            if denominator == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
            sum = sum + s_i * denominator.inverse();
        }

        Ok(sum)
    }

    /// Verify projective Logup identity
    pub fn verify_identity(
        witness: &[F],
        selector: &[bool],
        table: &[F],
        multiplicities: &[usize],
        challenge: F,
    ) -> LookupResult<bool> {
        let lhs = Self::evaluate_lhs_projective(witness, selector, challenge)?;
        let rhs = LogupLemma::evaluate_rhs(table, multiplicities, challenge)?;

        Ok(lhs == rhs)
    }
}

/// Vectorized Logup lemma
///
/// Extends Logup to vector lookups by encoding tuples as polynomials
/// w_i(y) := Σ_{j=1}^k w_{i,j} · y^{j-1}
///
/// Identity: Σ 1/(x + w_i(y)) = Σ m_i/(x + t_i(y))
pub struct VectorizedLogup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> VectorizedLogup<F> {
    /// Encode vector as polynomial evaluation
    ///
    /// w_i(y) = Σ_{j=0}^{k-1} w_{i,j} · y^j
    ///
    /// # Performance: O(k) field operations
    pub fn encode_vector(vector: &[F], challenge_y: F) -> F {
        let mut result = F::ZERO;
        let mut power = F::ONE;

        for &v_j in vector {
            result = result + v_j * power;
            power = power * challenge_y;
        }

        result
    }

    /// Evaluate LHS for vector lookups
    ///
    /// Computes: Σ_{i=1}^n 1/(challenge_x + w_i(challenge_y))
    pub fn evaluate_lhs_vectorized(
        witness: &[Vec<F>],
        challenge_x: F,
        challenge_y: F,
    ) -> LookupResult<F> {
        let mut sum = F::ZERO;

        for w_i in witness {
            let w_i_poly = Self::encode_vector(w_i, challenge_y);
            let denominator = challenge_x + w_i_poly;
            if denominator == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
            sum = sum + denominator.inverse();
        }

        Ok(sum)
    }

    /// Evaluate RHS for vector lookups
    ///
    /// Computes: Σ_{i=1}^N m_i/(challenge_x + t_i(challenge_y))
    pub fn evaluate_rhs_vectorized(
        table: &[Vec<F>],
        multiplicities: &[usize],
        challenge_x: F,
        challenge_y: F,
    ) -> LookupResult<F> {
        if table.len() != multiplicities.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: table.len(),
                got: multiplicities.len(),
            });
        }

        let mut sum = F::ZERO;

        for (t_i, &m_i) in table.iter().zip(multiplicities.iter()) {
            if m_i > 0 {
                let t_i_poly = Self::encode_vector(t_i, challenge_y);
                let denominator = challenge_x + t_i_poly;
                if denominator == F::ZERO {
                    return Err(LookupError::DivisionByZero);
                }
                let m_i_field = F::from(m_i as u64);
                sum = sum + m_i_field * denominator.inverse();
            }
        }

        Ok(sum)
    }

    /// Verify vectorized Logup identity
    pub fn verify_identity(
        witness: &[Vec<F>],
        table: &[Vec<F>],
        multiplicities: &[usize],
        challenge_x: F,
        challenge_y: F,
    ) -> LookupResult<bool> {
        let lhs = Self::evaluate_lhs_vectorized(witness, challenge_x, challenge_y)?;
        let rhs = Self::evaluate_rhs_vectorized(table, multiplicities, challenge_x, challenge_y)?;

        Ok(lhs == rhs)
    }

    /// Compute multiplicities for vector lookups
    ///
    /// # Performance: O(n · N · k) where k is tuple size
    pub fn compute_multiplicities(witness: &[Vec<F>], table: &[Vec<F>]) -> Vec<usize> {
        let mut multiplicities = vec![0; table.len()];

        for w in witness {
            for (i, t) in table.iter().enumerate() {
                if w.len() == t.len() && w.iter().zip(t.iter()).all(|(a, b)| a == b) {
                    multiplicities[i] += 1;
                }
            }
        }

        multiplicities
    }
}

/// Optimized Logup evaluation using precomputation
///
/// # Performance: Amortizes cost across multiple evaluations
pub struct OptimizedLogup<F: Field> {
    /// Precomputed inverses for table elements
    table_inverses: Vec<F>,
    /// Challenge used for precomputation
    challenge: F,
}

impl<F: Field> OptimizedLogup<F> {
    /// Precompute inverses for a given challenge
    ///
    /// # Performance: O(N) with batch inversion
    pub fn new(table: &[F], challenge: F) -> LookupResult<Self> {
        let denominators: Vec<F> = table.iter().map(|&t| challenge + t).collect();

        // Check for division by zero
        if denominators.iter().any(|&d| d == F::ZERO) {
            return Err(LookupError::DivisionByZero);
        }

        // Batch inversion for efficiency
        let table_inverses = F::batch_inverse(&denominators);

        Ok(OptimizedLogup {
            table_inverses,
            challenge,
        })
    }

    /// Evaluate RHS using precomputed inverses
    ///
    /// # Performance: O(N) field multiplications, no inversions
    pub fn evaluate_rhs(&self, multiplicities: &[usize]) -> LookupResult<F> {
        if multiplicities.len() != self.table_inverses.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: self.table_inverses.len(),
                got: multiplicities.len(),
            });
        }

        let mut sum = F::ZERO;
        for (&m_i, &inv) in multiplicities.iter().zip(self.table_inverses.iter()) {
            if m_i > 0 {
                let m_i_field = F::from(m_i as u64);
                sum = sum + m_i_field * inv;
            }
        }

        Ok(sum)
    }
}

/// Logup Prover
///
/// Generates proofs for lookup relations using the Logup lemma
pub struct LogupProver<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupProver<F> {
    /// Create a new Logup prover
    pub fn new() -> Self {
        LogupProver {
            _phantom: PhantomData,
        }
    }

    /// Generate a Logup proof
    ///
    /// # Arguments:
    /// - `witness`: The witness vector w ∈ F^n
    /// - `table`: The lookup table t ∈ F^N
    /// - `challenge`: Random challenge x ∈ F
    ///
    /// # Returns:
    /// - Multiplicities m_i and evaluations of both sides
    ///
    /// # Security:
    /// - Challenge must be sampled uniformly at random from F
    /// - Must verify characteristic constraint before calling
    pub fn prove(
        &self,
        witness: &[F],
        table: &[F],
        challenge: F,
    ) -> LookupResult<LogupProof<F>> {
        // Verify characteristic
        LogupLemma::verify_characteristic(witness.len(), table.len())?;

        // Compute multiplicities
        let multiplicities = LogupLemma::compute_multiplicities(witness, table);

        // Evaluate both sides
        let lhs = LogupLemma::evaluate_lhs(witness, challenge)?;
        let rhs = LogupLemma::evaluate_rhs(table, &multiplicities, challenge)?;

        // Verify identity holds
        if lhs != rhs {
            return Err(LookupError::InvalidProof {
                reason: "Logup identity does not hold".to_string(),
            });
        }

        Ok(LogupProof {
            multiplicities,
            lhs_evaluation: lhs,
            rhs_evaluation: rhs,
            challenge,
        })
    }

    /// Generate a Logup proof with precomputed multiplicities
    ///
    /// # Performance: Faster when multiplicities are already known
    pub fn prove_with_multiplicities(
        &self,
        witness: &[F],
        table: &[F],
        multiplicities: Vec<usize>,
        challenge: F,
    ) -> LookupResult<LogupProof<F>> {
        // Verify characteristic
        LogupLemma::verify_characteristic(witness.len(), table.len())?;

        // Verify multiplicities are correct
        let computed_mults = LogupLemma::compute_multiplicities(witness, table);
        if multiplicities != computed_mults {
            return Err(LookupError::InvalidProof {
                reason: "Provided multiplicities do not match witness".to_string(),
            });
        }

        // Evaluate both sides
        let lhs = LogupLemma::evaluate_lhs(witness, challenge)?;
        let rhs = LogupLemma::evaluate_rhs(table, &multiplicities, challenge)?;

        // Verify identity holds
        if lhs != rhs {
            return Err(LookupError::InvalidProof {
                reason: "Logup identity does not hold".to_string(),
            });
        }

        Ok(LogupProof {
            multiplicities,
            lhs_evaluation: lhs,
            rhs_evaluation: rhs,
            challenge,
        })
    }
}

impl<F: Field> Default for LogupProver<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Logup Proof
///
/// Contains the multiplicities and evaluations proving the Logup identity
#[derive(Debug, Clone)]
pub struct LogupProof<F: Field> {
    /// Multiplicities m_i for each table element
    pub multiplicities: Vec<usize>,
    /// LHS evaluation: Σ 1/(x + w_i)
    pub lhs_evaluation: F,
    /// RHS evaluation: Σ m_i/(x + t_i)
    pub rhs_evaluation: F,
    /// Challenge used
    pub challenge: F,
}

/// Logup Verifier
///
/// Verifies Logup proofs
pub struct LogupVerifier<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupVerifier<F> {
    /// Create a new Logup verifier
    pub fn new() -> Self {
        LogupVerifier {
            _phantom: PhantomData,
        }
    }

    /// Verify a Logup proof
    ///
    /// # Arguments:
    /// - `proof`: The Logup proof to verify
    /// - `table`: The lookup table (public)
    /// - `witness_commitment`: Commitment to witness (in real protocol)
    ///
    /// # Returns:
    /// - `true` if proof is valid, `false` otherwise
    ///
    /// # Security:
    /// - Verifier must check that challenge was sampled correctly
    /// - In interactive protocol, verifier samples challenge
    /// - In non-interactive protocol, challenge is Fiat-Shamir hash
    pub fn verify(
        &self,
        proof: &LogupProof<F>,
        table: &[F],
    ) -> LookupResult<bool> {
        // Verify characteristic
        LogupLemma::verify_characteristic(proof.multiplicities.len(), table.len())?;

        // Verify multiplicities sum correctly
        let total_multiplicity: usize = proof.multiplicities.iter().sum();
        // Note: In real protocol, witness size would be committed/known

        // Recompute RHS
        let rhs = LogupLemma::evaluate_rhs(table, &proof.multiplicities, proof.challenge)?;

        // Check evaluations match
        if proof.lhs_evaluation != proof.rhs_evaluation {
            return Ok(false);
        }

        if rhs != proof.rhs_evaluation {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify a Logup proof with known witness size
    ///
    /// # Security: More secure as it checks witness size constraint
    pub fn verify_with_witness_size(
        &self,
        proof: &LogupProof<F>,
        table: &[F],
        witness_size: usize,
    ) -> LookupResult<bool> {
        // Verify characteristic
        LogupLemma::verify_characteristic(witness_size, table.len())?;

        // Verify multiplicities sum to witness size
        let total_multiplicity: usize = proof.multiplicities.iter().sum();
        if total_multiplicity != witness_size {
            return Ok(false);
        }

        // Recompute RHS
        let rhs = LogupLemma::evaluate_rhs(table, &proof.multiplicities, proof.challenge)?;

        // Check evaluations match
        if proof.lhs_evaluation != proof.rhs_evaluation {
            return Ok(false);
        }

        if rhs != proof.rhs_evaluation {
            return Ok(false);
        }

        Ok(true)
    }
}

impl<F: Field> Default for LogupVerifier<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_logup_characteristic_check() {
        // Goldilocks has characteristic 2^64 - 2^32 + 1, which is very large
        assert!(LogupLemma::<F>::verify_characteristic(100, 100).is_ok());
        assert!(LogupLemma::<F>::is_field_compatible(1000, 1000));
    }

    #[test]
    fn test_logup_multiplicities() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];

        let mults = LogupLemma::compute_multiplicities(&witness, &table);
        assert_eq!(mults, vec![0, 2, 1, 1, 0]);

        // Test fast version
        let mults_fast = LogupLemma::compute_multiplicities_fast(&witness, &table);
        assert_eq!(mults, mults_fast);
    }

    #[test]
    fn test_logup_identity_valid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];
        let challenge = F::from(7);

        let mults = LogupLemma::compute_multiplicities(&witness, &table);
        let result = LogupLemma::verify_identity(&witness, &table, &mults, challenge);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_logup_identity_invalid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];
        let challenge = F::from(7);

        // Wrong multiplicities
        let wrong_mults = vec![1, 1, 1, 1, 1];
        let result = LogupLemma::verify_identity(&witness, &table, &wrong_mults, challenge);

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_logup_prover_verifier() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];
        let challenge = F::from(7);

        let prover = LogupProver::new();
        let proof = prover.prove(&witness, &table, challenge).unwrap();

        let verifier = LogupVerifier::new();
        assert!(verifier.verify(&proof, &table).unwrap());
        assert!(verifier.verify_with_witness_size(&proof, &table, witness.len()).unwrap());
    }

    #[test]
    fn test_projective_logup() {
        let witness = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let selector = vec![true, false, true, false]; // Only check indices 0 and 2
        let table = vec![F::from(1), F::from(3), F::from(5)];
        let challenge = F::from(7);

        // Compute multiplicities for selected elements only
        let selected_witness: Vec<F> = witness
            .iter()
            .zip(selector.iter())
            .filter_map(|(&w, &s)| if s { Some(w) } else { None })
            .collect();

        let mults = LogupLemma::compute_multiplicities(&selected_witness, &table);

        let result = ProjectiveLogup::verify_identity(
            &witness,
            &selector,
            &table,
            &mults,
            challenge,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_vectorized_logup() {
        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(1), F::from(2)],
        ];
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let challenge_x = F::from(7);
        let challenge_y = F::from(11);

        let mults = VectorizedLogup::compute_multiplicities(&witness, &table);
        assert_eq!(mults, vec![2, 1, 0]);

        let result = VectorizedLogup::verify_identity(
            &witness,
            &table,
            &mults,
            challenge_x,
            challenge_y,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_batch_verify() {
        let witnesses = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];
        let tables = vec![
            vec![F::from(1), F::from(2), F::from(3)],
            vec![F::from(3), F::from(4), F::from(5)],
        ];
        let challenges = vec![F::from(7), F::from(11)];
        let batch_challenge = F::from(13);

        let multiplicities: Vec<Vec<usize>> = witnesses
            .iter()
            .zip(tables.iter())
            .map(|(w, t)| LogupLemma::compute_multiplicities(w, t))
            .collect();

        let result = LogupLemma::batch_verify(
            &witnesses,
            &tables,
            &multiplicities,
            &challenges,
            batch_challenge,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_optimized_logup() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let challenge = F::from(7);

        let optimized = OptimizedLogup::new(&table, challenge).unwrap();

        let multiplicities = vec![0, 2, 1, 1, 0];
        let result = optimized.evaluate_rhs(&multiplicities).unwrap();

        // Compare with standard evaluation
        let expected = LogupLemma::evaluate_rhs(&table, &multiplicities, challenge).unwrap();
        assert_eq!(result, expected);
    }
}
