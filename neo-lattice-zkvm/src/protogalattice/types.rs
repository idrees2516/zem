// Core types for ProtogaLattice folding scheme

use std::fmt;
use serde::{Serialize, Deserialize};
use crate::ring::RingElement;
use crate::field::Field;

/// Instance for ProtogaLattice - represents public inputs to a polynomial relation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtogaInstance<F: Field> {
    /// Committed values representing the instance
    pub commitments: Vec<RingElement>,
    /// Public inputs to the relation
    pub public_inputs: Vec<F>,
    /// Relaxation parameter for the instance
    pub relaxation_factor: F,
    /// Error term for relaxed R1CS
    pub error_commitment: Option<RingElement>,
}

/// Witness for ProtogaLattice - represents secret values satisfying the relation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtogaWitness<F: Field> {
    /// Secret witness values
    pub witness_values: Vec<F>,
    /// Randomness used in commitments
    pub commitment_randomness: Vec<RingElement>,
    /// Error vector for relaxed relation
    pub error_vector: Option<Vec<F>>,
}

/// Proof generated during folding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtogaProof<F: Field> {
    /// Cross-terms from polynomial evaluation
    pub cross_terms: Vec<Vec<F>>,
    /// Commitments to cross-terms
    pub cross_term_commitments: Vec<RingElement>,
    /// Randomness commitments for each round
    pub randomness_commitments: Vec<RingElement>,
    /// Challenge responses
    pub challenge_responses: Vec<F>,
    /// Final opening proofs
    pub opening_proofs: Vec<OpeningProof<F>>,
}

/// Opening proof for a commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpeningProof<F: Field> {
    /// Opened value
    pub value: Vec<F>,
    /// Proof of correct opening
    pub proof: Vec<RingElement>,
    /// Hint for verification
    pub hint: Vec<u8>,
}

/// Folded instance after one round of folding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldedInstance<F: Field> {
    /// The folded instance
    pub instance: ProtogaInstance<F>,
    /// Accumulator for cross-terms
    pub cross_term_accumulator: Vec<F>,
    /// Challenge used in folding
    pub folding_challenge: F,
}

/// Folded witness corresponding to folded instance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldedWitness<F: Field> {
    /// The folded witness
    pub witness: ProtogaWitness<F>,
    /// Accumulated randomness
    pub accumulated_randomness: Vec<RingElement>,
}

/// Proof of correct folding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldingProof<F: Field> {
    /// Proof for each folding round
    pub round_proofs: Vec<RoundProof<F>>,
    /// Final accumulated instance
    pub final_instance: ProtogaInstance<F>,
}

/// Proof for a single folding round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundProof<F: Field> {
    /// Cross-term polynomial commitments
    pub cross_term_commits: Vec<RingElement>,
    /// Evaluation of cross-terms at challenge
    pub cross_term_evals: Vec<F>,
    /// Sum-check proof for this round
    pub sumcheck_proof: SumCheckProof<F>,
}

/// Sum-check proof for polynomial evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumCheckProof<F: Field> {
    /// Univariate polynomials for each round
    pub round_polynomials: Vec<Vec<F>>,
    /// Final evaluation
    pub final_evaluation: F,
}

/// Polynomial relation instance
#[derive(Clone, Debug)]
pub struct RelationInstance<F: Field> {
    /// Number of variables
    pub num_variables: usize,
    /// Number of constraints
    pub num_constraints: usize,
    /// Degree of the polynomial relation
    pub degree: usize,
    /// Structured matrices defining the relation
    pub matrices: Vec<SparseMatrix<F>>,
}

/// Sparse matrix representation for efficient computation
#[derive(Clone, Debug)]
pub struct SparseMatrix<F: Field> {
    /// Number of rows
    pub rows: usize,
    /// Number of columns
    pub cols: usize,
    /// Non-zero entries as (row, col, value)
    pub entries: Vec<(usize, usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    /// Create new sparse matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: Vec::new(),
        }
    }

    /// Add entry to sparse matrix
    pub fn add_entry(&mut self, row: usize, col: usize, value: F) {
        debug_assert!(row < self.rows && col < self.cols);
        self.entries.push((row, col, value));
    }

    /// Compute matrix-vector product
    pub fn mul_vec(&self, vec: &[F]) -> Vec<F> {
        debug_assert_eq!(vec.len(), self.cols);
        let mut result = vec![F::zero(); self.rows];
        
        for &(row, col, ref value) in &self.entries {
            result[row] = result[row].add(&value.mul(&vec[col]));
        }
        
        result
    }

    /// Compute transpose matrix-vector product
    pub fn mul_vec_transpose(&self, vec: &[F]) -> Vec<F> {
        debug_assert_eq!(vec.len(), self.rows);
        let mut result = vec![F::zero(); self.cols];
        
        for &(row, col, ref value) in &self.entries {
            result[col] = result[col].add(&value.mul(&vec[row]));
        }
        
        result
    }
}

/// Polynomial relation defining the computation
#[derive(Clone, Debug)]
pub struct PolynomialRelation<F: Field> {
    /// Multilinear polynomials in the relation
    pub multilinear_polys: Vec<Vec<F>>,
    /// Coefficients combining the polynomials
    pub coefficients: Vec<F>,
    /// Degree of the relation
    pub degree: usize,
    /// Number of variables
    pub num_variables: usize,
}

impl<F: Field> PolynomialRelation<F> {
    /// Evaluate the relation at given point
    pub fn evaluate(&self, point: &[F]) -> F {
        debug_assert_eq!(point.len(), self.num_variables);
        
        let mut result = F::zero();
        for (poly, coeff) in self.multilinear_polys.iter().zip(&self.coefficients) {
            let eval = self.evaluate_multilinear(poly, point);
            result = result.add(&coeff.mul(&eval));
        }
        result
    }

    /// Evaluate multilinear polynomial at point
    fn evaluate_multilinear(&self, poly: &[F], point: &[F]) -> F {
        let n = point.len();
        debug_assert_eq!(poly.len(), 1 << n);
        
        let mut evals = poly.to_vec();
        for i in 0..n {
            let half = 1 << (n - i - 1);
            for j in 0..half {
                let left = evals[j];
                let right = evals[j + half];
                evals[j] = left.mul(&(F::one().sub(&point[i])))
                    .add(&right.mul(&point[i]));
            }
        }
        evals[0]
    }
}

impl<F: Field> ProtogaInstance<F> {
    /// Create a new instance
    pub fn new(
        commitments: Vec<RingElement>,
        public_inputs: Vec<F>,
    ) -> Self {
        Self {
            commitments,
            public_inputs,
            relaxation_factor: F::one(),
            error_commitment: None,
        }
    }

    /// Create relaxed instance with error term
    pub fn relaxed(
        commitments: Vec<RingElement>,
        public_inputs: Vec<F>,
        relaxation_factor: F,
        error_commitment: RingElement,
    ) -> Self {
        Self {
            commitments,
            public_inputs,
            relaxation_factor,
            error_commitment: Some(error_commitment),
        }
    }

    /// Check if instance is relaxed
    pub fn is_relaxed(&self) -> bool {
        self.error_commitment.is_some() || 
        self.relaxation_factor != F::one()
    }
}

impl<F: Field> ProtogaWitness<F> {
    /// Create a new witness
    pub fn new(
        witness_values: Vec<F>,
        commitment_randomness: Vec<RingElement>,
    ) -> Self {
        Self {
            witness_values,
            commitment_randomness,
            error_vector: None,
        }
    }

    /// Create relaxed witness with error vector
    pub fn relaxed(
        witness_values: Vec<F>,
        commitment_randomness: Vec<RingElement>,
        error_vector: Vec<F>,
    ) -> Self {
        Self {
            witness_values,
            commitment_randomness,
            error_vector: Some(error_vector),
        }
    }
}

impl<F: Field> fmt::Display for ProtogaInstance<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtogaInstance(commitments: {}, public_inputs: {}, relaxed: {})",
            self.commitments.len(),
            self.public_inputs.len(),
            self.is_relaxed()
        )
    }
}
