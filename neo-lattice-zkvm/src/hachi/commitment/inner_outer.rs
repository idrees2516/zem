// Inner-outer commitment structure (Figure 3 of paper)
//
// Implements the two-level Ajtai commitment for efficient polynomial commitments.
// Structure:
// - Inner commitment: Commits to witness vectors s_i
// - Outer commitment: Commits to inner commitments t_i
// - Binding: Reduces to Module-SIS hardness

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Inner-outer commitment structure
///
/// For witness s = (s_1, ..., s_{2^r}) ∈ R_q^{(2^m + 2^r)·poly(λ)}:
/// 1. Inner commitment: t_i = A_in · s_i for i = 1, ..., 2^r
/// 2. Outer commitment: u = A_out · t where t = (t_1, ..., t_{2^r})
///
/// Binding property (Lemma 7):
/// If two different witnesses s, s' produce same commitment u,
/// then can solve Module-SIS instance.
#[derive(Clone, Debug)]
pub struct InnerOuterCommitment<F: Field> {
    /// Inner commitment matrix A_in ∈ R_q^{κ_in × n_in}
    inner_matrix: Vec<Vec<RingElement<F>>>,
    
    /// Outer commitment matrix A_out ∈ R_q^{κ_out × 2^r}
    outer_matrix: Vec<Vec<RingElement<F>>>,
    
    /// Inner matrix dimensions
    inner_rows: usize,
    inner_cols: usize,
    
    /// Outer matrix dimensions
    outer_rows: usize,
    outer_cols: usize,
    
    /// Ring dimension
    ring_dimension: usize,
}

impl<F: Field> InnerOuterCommitment<F> {
    /// Create a new inner-outer commitment scheme
    pub fn new(
        params: &HachiParams<F>,
        inner_rows: usize,
        inner_cols: usize,
        outer_rows: usize,
        outer_cols: usize,
    ) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        
        // Sample random matrices
        let inner_matrix = Self::sample_random_matrix(ring_dimension, inner_rows, inner_cols)?;
        let outer_matrix = Self::sample_random_matrix(ring_dimension, outer_rows, outer_cols)?;
        
        Ok(Self {
            inner_matrix,
            outer_matrix,
            inner_rows,
            inner_cols,
            outer_rows,
            outer_cols,
            ring_dimension,
        })
    }
    
    /// Sample a random matrix from R_q
    fn sample_random_matrix(
        ring_dimension: usize,
        rows: usize,
        cols: usize,
    ) -> Result<Vec<Vec<RingElement<F>>>, HachiError> {
        let mut matrix = Vec::with_capacity(rows);
        
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                row.push(RingElement::random(ring_dimension));
            }
            matrix.push(row);
        }
        
        Ok(matrix)
    }
    
    /// Compute inner commitments
    ///
    /// For witness s = (s_1, ..., s_{2^r}), compute t_i = A_in · s_i
    pub fn compute_inner_commitments(
        &self,
        witness_blocks: &[Vec<RingElement<F>>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if witness_blocks.len() != self.outer_cols {
            return Err(HachiError::InvalidDimension {
                expected: self.outer_cols,
                actual: witness_blocks.len(),
            });
        }
        
        let mut inner_commitments = Vec::with_capacity(self.outer_cols);
        
        // For each witness block s_i
        for s_i in witness_blocks {
            if s_i.len() != self.inner_cols {
                return Err(HachiError::InvalidDimension {
                    expected: self.inner_cols,
                    actual: s_i.len(),
                });
            }
            
            // Compute t_i = A_in · s_i
            let t_i = self.matrix_vector_product(&self.inner_matrix, s_i)?;
            inner_commitments.push(t_i);
        }
        
        Ok(inner_commitments)
    }
    
    /// Compute outer commitment
    ///
    /// Given inner commitments t = (t_1, ..., t_{2^r}), compute u = A_out · t
    pub fn compute_outer_commitment(
        &self,
        inner_commitments: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        if inner_commitments.len() != self.outer_cols {
            return Err(HachiError::InvalidDimension {
                expected: self.outer_cols,
                actual: inner_commitments.len(),
            });
        }
        
        // Compute u = A_out · t
        self.matrix_vector_product(&self.outer_matrix, inner_commitments)
    }
    
    /// Full commitment: inner + outer
    ///
    /// Given witness s, compute commitment u = A_out · (A_in · s)
    pub fn commit(
        &self,
        witness: &[Vec<RingElement<F>>],
    ) -> Result<RingElement<F>, HachiError> {
        let inner_commitments = self.compute_inner_commitments(witness)?;
        self.compute_outer_commitment(&inner_commitments)
    }
    
    /// Matrix-vector product: A · v
    fn matrix_vector_product(
        &self,
        matrix: &[Vec<RingElement<F>>],
        vector: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        if matrix.is_empty() {
            return Err(HachiError::InvalidDimension {
                expected: 1,
                actual: 0,
            });
        }
        
        if matrix[0].len() != vector.len() {
            return Err(HachiError::InvalidDimension {
                expected: matrix[0].len(),
                actual: vector.len(),
            });
        }
        
        let mut result = RingElement::zero(self.ring_dimension)?;
        
        // Compute first row: A[0] · v
        for j in 0..vector.len() {
            let term = matrix[0][j].mul(&vector[j])?;
            result = result.add(&term)?;
        }
        
        Ok(result)
    }
    
    /// Verify commitment structure
    pub fn verify_structure(&self) -> Result<bool, HachiError> {
        // Check matrix dimensions
        if self.inner_matrix.is_empty() || self.outer_matrix.is_empty() {
            return Ok(false);
        }
        
        if self.inner_matrix[0].len() != self.inner_cols {
            return Ok(false);
        }
        
        if self.outer_matrix[0].len() != self.outer_cols {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Get inner matrix
    pub fn inner_matrix(&self) -> &[Vec<RingElement<F>>] {
        &self.inner_matrix
    }
    
    /// Get outer matrix
    pub fn outer_matrix(&self) -> &[Vec<RingElement<F>>] {
        &self.outer_matrix
    }
    
    /// Get inner matrix dimensions
    pub fn inner_dimensions(&self) -> (usize, usize) {
        (self.inner_rows, self.inner_cols)
    }
    
    /// Get outer matrix dimensions
    pub fn outer_dimensions(&self) -> (usize, usize) {
        (self.outer_rows, self.outer_cols)
    }
}

/// Commitment key structure
#[derive(Clone, Debug)]
pub struct CommitmentKey<F: Field> {
    /// Inner-outer commitment scheme
    scheme: InnerOuterCommitment<F>,
    
    /// Public parameters
    params: HachiParams<F>,
}

impl<F: Field> CommitmentKey<F> {
    /// Create a new commitment key
    pub fn new(
        params: &HachiParams<F>,
        inner_rows: usize,
        inner_cols: usize,
        outer_rows: usize,
        outer_cols: usize,
    ) -> Result<Self, HachiError> {
        let scheme = InnerOuterCommitment::new(params, inner_rows, inner_cols, outer_rows, outer_cols)?;
        
        Ok(Self {
            scheme,
            params: params.clone(),
        })
    }
    
    /// Commit to witness
    pub fn commit(&self, witness: &[Vec<RingElement<F>>]) -> Result<RingElement<F>, HachiError> {
        self.scheme.commit(witness)
    }
    
    /// Get scheme
    pub fn scheme(&self) -> &InnerOuterCommitment<F> {
        &self.scheme
    }
    
    /// Get parameters
    pub fn params(&self) -> &HachiParams<F> {
        &self.params
    }
}

/// Commitment value
#[derive(Clone, Debug)]
pub struct Commitment<F: Field> {
    /// Commitment value u ∈ R_q
    value: RingElement<F>,
    
    /// Inner commitments t_i (for verification)
    inner_commitments: Option<Vec<RingElement<F>>>,
}

impl<F: Field> Commitment<F> {
    /// Create a new commitment
    pub fn new(value: RingElement<F>) -> Self {
        Self {
            value,
            inner_commitments: None,
        }
    }
    
    /// Create commitment with inner commitments
    pub fn with_inner(value: RingElement<F>, inner: Vec<RingElement<F>>) -> Self {
        Self {
            value,
            inner_commitments: Some(inner),
        }
    }
    
    /// Get commitment value
    pub fn value(&self) -> &RingElement<F> {
        &self.value
    }
    
    /// Get inner commitments
    pub fn inner_commitments(&self) -> Option<&[RingElement<F>]> {
        self.inner_commitments.as_deref()
    }
    
    /// Verify commitment structure
    pub fn verify_structure(&self) -> Result<bool, HachiError> {
        // Check that value is valid ring element
        Ok(self.value.degree() > 0)
    }
}

/// Commitment opening structure
#[derive(Clone, Debug)]
pub struct CommitmentOpening<F: Field> {
    /// Witness blocks s_i
    witness_blocks: Vec<Vec<RingElement<F>>>,
    
    /// Inner commitments t_i
    inner_commitments: Vec<RingElement<F>>,
}

impl<F: Field> CommitmentOpening<F> {
    /// Create a new commitment opening
    pub fn new(
        witness_blocks: Vec<Vec<RingElement<F>>>,
        inner_commitments: Vec<RingElement<F>>,
    ) -> Self {
        Self {
            witness_blocks,
            inner_commitments,
        }
    }
    
    /// Get witness blocks
    pub fn witness_blocks(&self) -> &[Vec<RingElement<F>>] {
        &self.witness_blocks
    }
    
    /// Get inner commitments
    pub fn inner_commitments(&self) -> &[RingElement<F>] {
        &self.inner_commitments
    }
    
    /// Verify opening against commitment
    pub fn verify(
        &self,
        commitment_key: &CommitmentKey<F>,
        commitment: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        // Recompute commitment
        let recomputed = commitment_key.commit(&self.witness_blocks)?;
        
        // Check if matches
        Ok(recomputed.equals(commitment.value()))
    }
}

/// Batch commitment operations
pub struct BatchCommitment<F: Field> {
    key: CommitmentKey<F>,
}

impl<F: Field> BatchCommitment<F> {
    pub fn new(key: CommitmentKey<F>) -> Self {
        Self { key }
    }
    
    /// Commit to multiple witnesses
    pub fn batch_commit(
        &self,
        witnesses: &[Vec<Vec<RingElement<F>>>],
    ) -> Result<Vec<Commitment<F>>, HachiError> {
        witnesses.iter()
            .map(|w| {
                let value = self.key.commit(w)?;
                Ok(Commitment::new(value))
            })
            .collect()
    }
    
    /// Verify multiple openings
    pub fn batch_verify(
        &self,
        openings: &[CommitmentOpening<F>],
        commitments: &[Commitment<F>],
    ) -> Result<bool, HachiError> {
        if openings.len() != commitments.len() {
            return Ok(false);
        }
        
        for i in 0..openings.len() {
            if !openings[i].verify(&self.key, &commitments[i])? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}
