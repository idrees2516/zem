//! Ajtai Commitment Scheme over Cyclotomic Rings

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;

/// Ajtai commitment scheme
/// Commitment: c = Aw mod q for A ∈ R_q^{a×m}
pub struct AjtaiCommitment<F: FiniteField> {
    /// Ring
    pub ring: CyclotomicRing<F>,
    /// Commitment matrix A ∈ R_q^{a×m}
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    /// Rank a
    pub rank: usize,
    /// Witness length m
    pub witness_length: usize,
}

impl<F: FiniteField> AjtaiCommitment<F> {
    /// Create new Ajtai commitment with random matrix
    pub fn new(
        ring: CyclotomicRing<F>,
        rank: usize,
        witness_length: usize,
        rng: &mut impl rand::Rng,
    ) -> Self {
        let matrix_a = Self::generate_random_matrix(&ring, rank, witness_length, rng);
        
        Self {
            ring,
            matrix_a,
            rank,
            witness_length,
        }
    }

    /// Create from existing matrix
    pub fn from_matrix(
        ring: CyclotomicRing<F>,
        matrix_a: Vec<Vec<RingElement<F>>>,
    ) -> Self {
        let rank = matrix_a.len();
        let witness_length = if rank > 0 { matrix_a[0].len() } else { 0 };
        
        Self {
            ring,
            matrix_a,
            rank,
            witness_length,
        }
    }

    /// Commit to witness w
    pub fn commit(&self, witness: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, String> {
        if witness.len() != self.witness_length {
            return Err(format!(
                "Witness length mismatch: expected {}, got {}",
                self.witness_length,
                witness.len()
            ));
        }

        Ok(matrix_vector_mult(&self.ring, &self.matrix_a, witness))
    }

    /// Verify commitment
    pub fn verify(
        &self,
        commitment: &[RingElement<F>],
        witness: &[RingElement<F>],
    ) -> Result<bool, String> {
        if commitment.len() != self.rank {
            return Err("Commitment dimension mismatch".to_string());
        }

        let computed = self.commit(witness)?;
        
        Ok(commitment.iter().zip(computed.iter()).all(|(c1, c2)| c1 == c2))
    }

    /// Verify with norm bound
    pub fn verify_with_norm_bound(
        &self,
        commitment: &[RingElement<F>],
        witness: &[RingElement<F>],
        norm_bound: F,
    ) -> Result<bool, String> {
        // Check norm bound
        for w in witness {
            if w.norm_infinity() > norm_bound {
                return Ok(false);
            }
        }

        self.verify(commitment, witness)
    }

    /// Generate random commitment matrix
    fn generate_random_matrix(
        ring: &CyclotomicRing<F>,
        rank: usize,
        witness_length: usize,
        rng: &mut impl rand::Rng,
    ) -> Vec<Vec<RingElement<F>>> {
        let mut matrix = Vec::with_capacity(rank);
        
        for _ in 0..rank {
            let mut row = Vec::with_capacity(witness_length);
            for _ in 0..witness_length {
                // Sample uniformly from R_q
                let coeffs: Vec<F> = (0..ring.degree)
                    .map(|_| {
                        let val = rng.gen_range(0..ring.modulus.to_u64());
                        F::from_u64(val)
                    })
                    .collect();
                row.push(RingElement::new(coeffs, ring.conductor));
            }
            matrix.push(row);
        }
        
        matrix
    }

    /// Homomorphic addition: Com(w1) + Com(w2) = Com(w1 + w2)
    pub fn add_commitments(
        &self,
        c1: &[RingElement<F>],
        c2: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        if c1.len() != c2.len() {
            return Err("Commitment lengths differ".to_string());
        }

        Ok(c1.iter().zip(c2.iter())
            .map(|(a, b)| self.ring.add(a, b))
            .collect())
    }

    /// Homomorphic scalar multiplication: α·Com(w) = Com(α·w)
    pub fn scalar_mult_commitment(
        &self,
        commitment: &[RingElement<F>],
        scalar: &RingElement<F>,
    ) -> Vec<RingElement<F>> {
        commitment.iter()
            .map(|c| self.ring.multiply(scalar, c))
            .collect()
    }

    /// Linear combination of commitments
    pub fn linear_combination(
        &self,
        commitments: &[Vec<RingElement<F>>],
        scalars: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        if commitments.len() != scalars.len() {
            return Err("Number of commitments and scalars differ".to_string());
        }

        if commitments.is_empty() {
            return Ok(vec![RingElement::zero(self.ring.conductor); self.rank]);
        }

        let mut result = vec![RingElement::zero(self.ring.conductor); self.rank];

        for (commitment, scalar) in commitments.iter().zip(scalars.iter()) {
            let scaled = self.scalar_mult_commitment(commitment, scalar);
            result = self.add_commitments(&result, &scaled)?;
        }

        Ok(result)
    }

    /// Extract SIS solution from two witnesses with same commitment
    pub fn extract_sis_solution(
        &self,
        w1: &[RingElement<F>],
        w2: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        if w1.len() != w2.len() {
            return Err("Witness lengths differ".to_string());
        }

        // SIS solution: w = w1 - w2 such that Aw = 0
        let solution: Vec<RingElement<F>> = w1.iter()
            .zip(w2.iter())
            .map(|(a, b)| self.ring.subtract(a, b))
            .collect();

        // Verify it's a non-trivial solution
        let is_zero = solution.iter().all(|w| {
            w.coeffs.iter().all(|&c| c == F::zero())
        });

        if is_zero {
            return Err("Trivial SIS solution".to_string());
        }

        // Verify Aw = 0
        let result = self.commit(&solution)?;
        let is_valid = result.iter().all(|r| {
            r.coeffs.iter().all(|&c| c == F::zero())
        });

        if !is_valid {
            return Err("Invalid SIS solution".to_string());
        }

        Ok(solution)
    }
}

/// Structured Ajtai commitment (for efficiency)
pub struct StructuredAjtaiCommitment<F: FiniteField> {
    base: AjtaiCommitment<F>,
    /// Use structured matrices (e.g., circulant)
    use_structure: bool,
}

impl<F: FiniteField> StructuredAjtaiCommitment<F> {
    pub fn new(
        ring: CyclotomicRing<F>,
        rank: usize,
        witness_length: usize,
        rng: &mut impl rand::Rng,
    ) -> Self {
        let base = AjtaiCommitment::new(ring, rank, witness_length, rng);
        Self {
            base,
            use_structure: true,
        }
    }

    /// Commit using structured matrix
    pub fn commit(&self, witness: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, String> {
        if self.use_structure {
            self.fast_commit(witness)
        } else {
            self.base.commit(witness)
        }
    }

    /// Fast commitment using NTT (if available)
    fn fast_commit(&self, witness: &[RingElement<F>]) -> Result<Vec<RingElement<F>>, String> {
        // In production, use NTT-based multiplication
        // For now, fall back to standard commit
        self.base.commit(witness)
    }
}

/// Batch commitment for multiple witnesses
pub struct BatchCommitment<F: FiniteField> {
    commitment: AjtaiCommitment<F>,
}

impl<F: FiniteField> BatchCommitment<F> {
    pub fn new(commitment: AjtaiCommitment<F>) -> Self {
        Self { commitment }
    }

    /// Commit to multiple witnesses
    pub fn batch_commit(
        &self,
        witnesses: &[Vec<RingElement<F>>],
    ) -> Result<Vec<Vec<RingElement<F>>>, String> {
        witnesses.iter()
            .map(|w| self.commitment.commit(w))
            .collect()
    }

    /// Verify multiple commitments
    pub fn batch_verify(
        &self,
        commitments: &[Vec<RingElement<F>>],
        witnesses: &[Vec<RingElement<F>>],
    ) -> Result<bool, String> {
        if commitments.len() != witnesses.len() {
            return Err("Number of commitments and witnesses differ".to_string());
        }

        for (c, w) in commitments.iter().zip(witnesses.iter()) {
            if !self.commitment.verify(c, w)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Commitment key generation
pub fn generate_commitment_key<F: FiniteField>(
    ring: &CyclotomicRing<F>,
    rank: usize,
    witness_length: usize,
    seed: &[u8],
) -> Vec<Vec<RingElement<F>>> {
    // Use deterministic randomness from seed
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    let mut rng = ChaCha20Rng::from_seed(
        seed.try_into().unwrap_or([0u8; 32])
    );

    AjtaiCommitment::generate_random_matrix(ring, rank, witness_length, &mut rng)
}

/// Verify commitment matrix is well-formed
pub fn verify_commitment_key<F: FiniteField>(
    matrix: &[Vec<RingElement<F>>],
    rank: usize,
    witness_length: usize,
) -> Result<(), String> {
    if matrix.len() != rank {
        return Err("Matrix rank mismatch".to_string());
    }

    for row in matrix {
        if row.len() != witness_length {
            return Err("Matrix column count mismatch".to_string());
        }
    }

    Ok(())
}
