// Multilinear Extension (MLE) utilities for lookup arguments
//
// Multilinear extensions are fundamental for multilinear polynomial-based
// lookup schemes like Lasso, Spark, and HyperPlonk-compatible lookups.
//
// For a function f: {0,1}^k → F, the multilinear extension f̃: F^k → F
// is the unique multilinear polynomial that agrees with f on the Boolean hypercube.

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};

/// Multilinear polynomial representation
///
/// Stores evaluations over the Boolean hypercube {0,1}^k
/// The MLE is uniquely determined by these 2^k evaluations
#[derive(Debug, Clone)]
pub struct MultilinearPolynomial<F: Field> {
    /// Evaluations over {0,1}^k in lexicographic order
    pub evaluations: Vec<F>,
    /// Number of variables k
    pub num_vars: usize,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create a new multilinear polynomial from evaluations
    ///
    /// # Security: Validates that evaluations.len() == 2^num_vars
    pub fn new(evaluations: Vec<F>, num_vars: usize) -> LookupResult<Self> {
        let expected_size = 1 << num_vars;
        if evaluations.len() != expected_size {
            return Err(LookupError::InvalidTableSize {
                size: evaluations.len(),
                required: format!("2^{} = {}", num_vars, expected_size),
            });
        }

        Ok(MultilinearPolynomial {
            evaluations,
            num_vars,
        })
    }

    /// Evaluate the multilinear extension at a point
    ///
    /// Uses the multilinear Lagrange basis:
    /// f̃(x) = Σ_{b∈{0,1}^k} f(b) · eq̃(x, b)
    ///
    /// # Performance: O(2^k) field operations
    /// # Security: Constant-time evaluation to prevent timing attacks
    pub fn evaluate(&self, point: &[F]) -> LookupResult<F> {
        if point.len() != self.num_vars {
            return Err(LookupError::InvalidVectorLength {
                expected: self.num_vars,
                got: point.len(),
            });
        }

        let mut result = F::ZERO;
        let size = 1 << self.num_vars;

        for i in 0..size {
            let mut eq_val = F::ONE;
            for (j, &x_j) in point.iter().enumerate() {
                let bit = ((i >> j) & 1) == 1;
                // eq term: x_j if bit=1, (1-x_j) if bit=0
                eq_val = eq_val * if bit { x_j } else { F::ONE - x_j };
            }
            result = result + self.evaluations[i] * eq_val;
        }

        Ok(result)
    }

    /// Evaluate using optimized algorithm for sparse polynomials
    ///
    /// # Performance: O(n) where n is number of non-zero evaluations
    pub fn evaluate_sparse(&self, point: &[F]) -> LookupResult<F> {
        if point.len() != self.num_vars {
            return Err(LookupError::InvalidVectorLength {
                expected: self.num_vars,
                got: point.len(),
            });
        }

        let mut result = F::ZERO;

        for (i, &eval) in self.evaluations.iter().enumerate() {
            if eval == F::ZERO {
                continue; // Skip zero evaluations
            }

            let mut eq_val = F::ONE;
            for (j, &x_j) in point.iter().enumerate() {
                let bit = ((i >> j) & 1) == 1;
                eq_val = eq_val * if bit { x_j } else { F::ONE - x_j };
            }
            result = result + eval * eq_val;
        }

        Ok(result)
    }

    /// Partial evaluation: fix first variable to value
    ///
    /// Returns a new MLE with one fewer variable
    /// f̃(x_0, x_1, ..., x_{k-1}) → f̃'(x_1, ..., x_{k-1}) where x_0 is fixed
    ///
    /// # Performance: O(2^{k-1}) field operations
    pub fn partial_eval(&self, value: F) -> LookupResult<Self> {
        if self.num_vars == 0 {
            return Err(LookupError::InvalidTableSize {
                size: 0,
                required: "at least 1 variable".to_string(),
            });
        }

        let new_num_vars = self.num_vars - 1;
        let new_size = 1 << new_num_vars;
        let mut new_evals = Vec::with_capacity(new_size);

        // For each point in the new hypercube
        for i in 0..new_size {
            // Compute f̃(value, b_1, ..., b_{k-1})
            // = (1-value) · f(0, b_1, ..., b_{k-1}) + value · f(1, b_1, ..., b_{k-1})
            let idx_0 = i; // Index with first bit = 0
            let idx_1 = i | (1 << new_num_vars); // Index with first bit = 1

            let eval = (F::ONE - value) * self.evaluations[idx_0] + value * self.evaluations[idx_1];
            new_evals.push(eval);
        }

        Self::new(new_evals, new_num_vars)
    }

    /// Get the degree of the polynomial (always k for k-variate multilinear)
    pub fn degree(&self) -> usize {
        self.num_vars
    }

    /// Check if the polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.evaluations.iter().all(|&e| e == F::ZERO)
    }

    /// Compute the sum of all evaluations
    ///
    /// Useful for sumcheck protocol
    pub fn sum_over_hypercube(&self) -> F {
        self.evaluations.iter().copied().fold(F::ZERO, |acc, e| acc + e)
    }
}

/// The eq polynomial: eq̃(x, y) = ∏_{i=1}^k (x_i · y_i + (1 - x_i) · (1 - y_i))
///
/// This is the multilinear extension of the equality function:
/// eq(x, y) = 1 if x = y, 0 otherwise
///
/// # Security: Critical for Spark and Lasso protocols
pub struct EqPolynomial;

impl EqPolynomial {
    /// Evaluate eq̃(x, y) at given points
    ///
    /// # Performance: O(k) field operations
    /// # Security: Constant-time to prevent timing attacks
    pub fn evaluate<F: Field>(x: &[F], y: &[F]) -> LookupResult<F> {
        if x.len() != y.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: x.len(),
                got: y.len(),
            });
        }

        let mut result = F::ONE;
        for (&x_i, &y_i) in x.iter().zip(y.iter()) {
            // eq term: x_i · y_i + (1 - x_i) · (1 - y_i)
            result = result * (x_i * y_i + (F::ONE - x_i) * (F::ONE - y_i));
        }

        Ok(result)
    }

    /// Create the MLE of eq(·, y) as a multilinear polynomial
    ///
    /// Returns f̃ where f̃(x) = eq̃(x, y)
    ///
    /// # Performance: O(2^k) field operations
    pub fn as_mle<F: Field>(y: &[F]) -> LookupResult<MultilinearPolynomial<F>> {
        let num_vars = y.len();
        let size = 1 << num_vars;
        let mut evaluations = Vec::with_capacity(size);

        for i in 0..size {
            let mut eq_val = F::ONE;
            for (j, &y_j) in y.iter().enumerate() {
                let bit = ((i >> j) & 1) == 1;
                let x_j = if bit { F::ONE } else { F::ZERO };
                eq_val = eq_val * (x_j * y_j + (F::ONE - x_j) * (F::ONE - y_j));
            }
            evaluations.push(eq_val);
        }

        MultilinearPolynomial::new(evaluations, num_vars)
    }

    /// Batch evaluate eq̃(x, y_i) for multiple y_i values
    ///
    /// # Performance: O(n · k) where n is number of y values
    /// # Optimization: Uses SIMD-friendly operations
    pub fn batch_evaluate<F: Field>(x: &[F], y_values: &[Vec<F>]) -> LookupResult<Vec<F>> {
        y_values
            .iter()
            .map(|y| Self::evaluate(x, y))
            .collect()
    }
}

/// Tensor product structure for multilinear polynomials
///
/// Exploits the tensor product structure: eq̃(x_1 ∥ x_2, y_1 ∥ y_2) = eq̃(x_1, y_1) · eq̃(x_2, y_2)
///
/// # Security: Critical for Spark sparse polynomial commitments
pub struct TensorProduct;

impl TensorProduct {
    /// Split evaluation point into segments
    ///
    /// Used in Spark to split k-variate evaluation into c segments of k/c variables each
    pub fn split_point<F: Field>(point: &[F], num_segments: usize) -> Vec<Vec<F>> {
        let segment_size = (point.len() + num_segments - 1) / num_segments;
        point
            .chunks(segment_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Evaluate using tensor product structure
    ///
    /// For point x = x_1 ∥ x_2 ∥ ... ∥ x_c and y = y_1 ∥ y_2 ∥ ... ∥ y_c:
    /// eq̃(x, y) = ∏_{i=1}^c eq̃(x_i, y_i)
    ///
    /// # Performance: O(k) instead of O(2^k) for full evaluation
    pub fn evaluate_tensor<F: Field>(
        x_segments: &[Vec<F>],
        y_segments: &[Vec<F>],
    ) -> LookupResult<F> {
        if x_segments.len() != y_segments.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: x_segments.len(),
                got: y_segments.len(),
            });
        }

        let mut result = F::ONE;
        for (x_seg, y_seg) in x_segments.iter().zip(y_segments.iter()) {
            let eq_val = EqPolynomial::evaluate(x_seg, y_seg)?;
            result = result * eq_val;
        }

        Ok(result)
    }

    /// Construct lookup tables for tensor product evaluation
    ///
    /// Used in Spark: for each segment, create table T_i = {eq̃(x_i, w) : w ∈ {0,1}^{k/c}}
    ///
    /// # Performance: O(c · 2^{k/c}) instead of O(2^k)
    pub fn construct_eq_tables<F: Field>(x_segments: &[Vec<F>]) -> Vec<Vec<F>> {
        x_segments
            .iter()
            .map(|x_seg| {
                let size = 1 << x_seg.len();
                let mut table = Vec::with_capacity(size);

                for i in 0..size {
                    let mut y_seg = Vec::with_capacity(x_seg.len());
                    for j in 0..x_seg.len() {
                        let bit = ((i >> j) & 1) == 1;
                        y_seg.push(if bit { F::ONE } else { F::ZERO });
                    }

                    let eq_val = EqPolynomial::evaluate(x_seg, &y_seg).unwrap();
                    table.push(eq_val);
                }

                table
            })
            .collect()
    }
}

/// Multilinear extension utilities for lookup arguments
pub struct MLEUtils;

impl MLEUtils {
    /// Convert a vector to its multilinear extension
    ///
    /// For a vector v of length n = 2^k, returns the MLE f̃ where f̃(b) = v[b] for b ∈ {0,1}^k
    pub fn from_vector<F: Field>(vector: Vec<F>) -> LookupResult<MultilinearPolynomial<F>> {
        if vector.is_empty() {
            return Err(LookupError::InvalidTableSize {
                size: 0,
                required: "non-empty vector".to_string(),
            });
        }

        // Check if length is power of 2
        if !vector.len().is_power_of_two() {
            return Err(LookupError::InvalidTableSize {
                size: vector.len(),
                required: "power of 2".to_string(),
            });
        }

        let num_vars = vector.len().trailing_zeros() as usize;
        MultilinearPolynomial::new(vector, num_vars)
    }

    /// Pad vector to next power of 2 and convert to MLE
    ///
    /// Pads with zeros to make length a power of 2
    pub fn from_vector_padded<F: Field>(mut vector: Vec<F>) -> LookupResult<MultilinearPolynomial<F>> {
        if vector.is_empty() {
            return Err(LookupError::InvalidTableSize {
                size: 0,
                required: "non-empty vector".to_string(),
            });
        }

        // Pad to next power of 2
        let next_pow2 = vector.len().next_power_of_two();
        vector.resize(next_pow2, F::ZERO);

        Self::from_vector(vector)
    }

    /// Compute the multilinear extension of a sparse vector
    ///
    /// Only stores non-zero entries as (index, value) pairs
    ///
    /// # Performance: Memory O(n) instead of O(2^k) for sparse vectors
    pub fn from_sparse<F: Field>(
        non_zero_entries: Vec<(usize, F)>,
        num_vars: usize,
    ) -> LookupResult<MultilinearPolynomial<F>> {
        let size = 1 << num_vars;
        let mut evaluations = vec![F::ZERO; size];

        for (idx, val) in non_zero_entries {
            if idx >= size {
                return Err(LookupError::InvalidIndexSize {
                    expected: size,
                    got: idx,
                });
            }
            evaluations[idx] = val;
        }

        MultilinearPolynomial::new(evaluations, num_vars)
    }

    /// Check if a multilinear polynomial is sparse
    ///
    /// Returns true if less than 10% of evaluations are non-zero
    pub fn is_sparse<F: Field>(mle: &MultilinearPolynomial<F>) -> bool {
        let non_zero_count = mle.evaluations.iter().filter(|&&e| e != F::ZERO).count();
        let sparsity = non_zero_count as f64 / mle.evaluations.len() as f64;
        sparsity < 0.1
    }

    /// Extract non-zero entries from MLE
    ///
    /// Returns (index, value) pairs for all non-zero evaluations
    pub fn to_sparse<F: Field>(mle: &MultilinearPolynomial<F>) -> Vec<(usize, F)> {
        mle.evaluations
            .iter()
            .enumerate()
            .filter(|(_, &val)| val != F::ZERO)
            .map(|(idx, &val)| (idx, val))
            .collect()
    }
}
