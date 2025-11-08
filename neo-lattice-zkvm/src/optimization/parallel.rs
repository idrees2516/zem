// Parallel processing optimizations for Neo
//
// Task 17: Implement parallel processing
// - Parallel commitment computation for multiple witnesses
// - Parallel matrix-vector multiplications
// - Parallel MLE evaluations
// - Work-stealing parallelism using Rayon

use crate::field::Field;
use crate::ring::cyclotomic::RingElement;
use crate::commitment::ajtai::{AjtaiCommitmentScheme, Commitment};
use crate::polynomial::multilinear::MultilinearPolynomial;
use rayon::prelude::*;
use std::sync::Arc;

/// Configuration for parallel processing
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of threads to use (0 = auto-detect)
    pub num_threads: usize,
    
    /// Minimum work size to enable parallelism
    pub min_parallel_size: usize,
    
    /// Chunk size for parallel iteration
    pub chunk_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: 0, // Auto-detect
            min_parallel_size: 1024,
            chunk_size: 256,
        }
    }
}

impl ParallelConfig {
    /// Create a new parallel configuration
    pub fn new(num_threads: usize) -> Self {
        Self {
            num_threads,
            ..Default::default()
        }
    }
    
    /// Set minimum size for enabling parallelism
    pub fn with_min_size(mut self, min_size: usize) -> Self {
        self.min_parallel_size = min_size;
        self
    }
    
    /// Set chunk size for parallel iteration
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }
    
    /// Check if parallelism should be enabled for given work size
    pub fn should_parallelize(&self, work_size: usize) -> bool {
        work_size >= self.min_parallel_size
    }
    
    /// Initialize thread pool
    pub fn init_thread_pool(&self) -> Result<(), rayon::ThreadPoolBuildError> {
        if self.num_threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.num_threads)
                .build_global()
        } else {
            Ok(())
        }
    }
}

/// Parallel commitment computation for multiple witnesses
///
/// Computes commitments for a batch of witnesses in parallel.
/// Each commitment is computed independently, allowing perfect parallelization.
///
/// # Arguments
/// * `scheme` - Commitment scheme to use
/// * `witnesses` - Batch of witnesses to commit to
/// * `config` - Parallel configuration
///
/// # Returns
/// Vector of commitments, one per witness
///
/// # Performance
/// - Sequential: O(batch_size * κ * n * d * log d)
/// - Parallel: O((batch_size * κ * n * d * log d) / num_threads)
pub fn parallel_commitment_batch<F: Field>(
    scheme: &AjtaiCommitmentScheme<F>,
    witnesses: &[Vec<RingElement<F>>],
    config: &ParallelConfig,
) -> Result<Vec<Commitment<F>>, String> {
    if config.should_parallelize(witnesses.len()) {
        // Parallel computation
        witnesses
            .par_iter()
            .map(|witness| scheme.commit(witness))
            .collect()
    } else {
        // Sequential computation for small batches
        witnesses
            .iter()
            .map(|witness| scheme.commit(witness))
            .collect()
    }
}

/// Parallel matrix-vector multiplication
///
/// Computes y = Ax for sparse or dense matrix A in parallel.
/// Rows are processed in parallel chunks.
///
/// # Arguments
/// * `matrix` - Matrix rows (each row is a vector of (index, value) pairs)
/// * `vector` - Input vector
/// * `config` - Parallel configuration
///
/// # Returns
/// Result vector y = Ax
pub fn parallel_matrix_vector_mul<F: Field>(
    matrix: &[Vec<(usize, F)>],
    vector: &[F],
    config: &ParallelConfig,
) -> Vec<F> {
    let num_rows = matrix.len();
    
    if config.should_parallelize(num_rows) {
        // Parallel computation
        matrix
            .par_iter()
            .map(|row| {
                let mut sum = F::zero();
                for &(idx, val) in row {
                    if idx < vector.len() {
                        sum = sum.add(&val.mul(&vector[idx]));
                    }
                }
                sum
            })
            .collect()
    } else {
        // Sequential computation
        matrix
            .iter()
            .map(|row| {
                let mut sum = F::zero();
                for &(idx, val) in row {
                    if idx < vector.len() {
                        sum = sum.add(&val.mul(&vector[idx]));
                    }
                }
                sum
            })
            .collect()
    }
}

/// Parallel MLE evaluations at multiple points
///
/// Evaluates a multilinear polynomial at multiple evaluation points in parallel.
/// Each evaluation is independent and can be computed in parallel.
///
/// # Arguments
/// * `mle` - Multilinear polynomial to evaluate
/// * `points` - Evaluation points (each point is a vector of field elements)
/// * `config` - Parallel configuration
///
/// # Returns
/// Vector of evaluation results
///
/// # Performance
/// - Sequential: O(num_points * 2^ℓ)
/// - Parallel: O((num_points * 2^ℓ) / num_threads)
pub fn parallel_mle_evaluations<F: Field>(
    mle: &MultilinearPolynomial<F>,
    points: &[Vec<F>],
    config: &ParallelConfig,
) -> Vec<F> {
    if config.should_parallelize(points.len()) {
        // Parallel evaluation
        points
            .par_iter()
            .map(|point| mle.evaluate(point))
            .collect()
    } else {
        // Sequential evaluation
        points
            .iter()
            .map(|point| mle.evaluate(point))
            .collect()
    }
}

/// Parallel batch field operations
///
/// Performs batched field additions in parallel.
pub fn parallel_batch_add<F: Field>(
    a: &[F],
    b: &[F],
    config: &ParallelConfig,
) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    
    if config.should_parallelize(a.len()) {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| x.add(y))
            .collect()
    } else {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.add(y))
            .collect()
    }
}

/// Parallel batch field multiplications
pub fn parallel_batch_mul<F: Field>(
    a: &[F],
    b: &[F],
    config: &ParallelConfig,
) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    
    if config.should_parallelize(a.len()) {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| x.mul(y))
            .collect()
    } else {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x.mul(y))
            .collect()
    }
}

/// Parallel linear combination
///
/// Computes Σᵢ coeffs[i] * vectors[i] in parallel.
///
/// # Arguments
/// * `vectors` - Input vectors
/// * `coeffs` - Coefficients for linear combination
/// * `config` - Parallel configuration
///
/// # Returns
/// Result vector
pub fn parallel_linear_combination<F: Field>(
    vectors: &[Vec<F>],
    coeffs: &[F],
    config: &ParallelConfig,
) -> Vec<F> {
    assert_eq!(vectors.len(), coeffs.len());
    
    if vectors.is_empty() {
        return Vec::new();
    }
    
    let len = vectors[0].len();
    
    if config.should_parallelize(len) {
        // Parallel computation by position
        (0..len)
            .into_par_iter()
            .map(|i| {
                let mut sum = F::zero();
                for (vec, coeff) in vectors.iter().zip(coeffs.iter()) {
                    sum = sum.add(&coeff.mul(&vec[i]));
                }
                sum
            })
            .collect()
    } else {
        // Sequential computation
        let mut result = vec![F::zero(); len];
        for (vec, coeff) in vectors.iter().zip(coeffs.iter()) {
            for i in 0..len {
                result[i] = result[i].add(&coeff.mul(&vec[i]));
            }
        }
        result
    }
}

/// Parallel inner product computation
///
/// Computes ⟨a, b⟩ = Σᵢ a[i] * b[i] in parallel using reduction.
pub fn parallel_inner_product<F: Field>(
    a: &[F],
    b: &[F],
    config: &ParallelConfig,
) -> F {
    assert_eq!(a.len(), b.len());
    
    if config.should_parallelize(a.len()) {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| x.mul(y))
            .reduce(|| F::zero(), |acc, x| acc.add(&x))
    } else {
        let mut sum = F::zero();
        for (x, y) in a.iter().zip(b.iter()) {
            sum = sum.add(&x.mul(y));
        }
        sum
    }
}

/// Parallel polynomial evaluation at multiple points
///
/// Evaluates multiple polynomials at the same point in parallel.
pub fn parallel_poly_evaluations<F: Field>(
    polys: &[MultilinearPolynomial<F>],
    point: &[F],
    config: &ParallelConfig,
) -> Vec<F> {
    if config.should_parallelize(polys.len()) {
        polys
            .par_iter()
            .map(|poly| poly.evaluate(point))
            .collect()
    } else {
        polys
            .iter()
            .map(|poly| poly.evaluate(point))
            .collect()
    }
}

/// Parallel Hadamard product (element-wise multiplication)
pub fn parallel_hadamard_product<F: Field>(
    vectors: &[Vec<F>],
    config: &ParallelConfig,
) -> Vec<F> {
    if vectors.is_empty() {
        return Vec::new();
    }
    
    let len = vectors[0].len();
    
    if config.should_parallelize(len) {
        (0..len)
            .into_par_iter()
            .map(|i| {
                let mut prod = F::one();
                for vec in vectors {
                    prod = prod.mul(&vec[i]);
                }
                prod
            })
            .collect()
    } else {
        let mut result = vec![F::one(); len];
        for vec in vectors {
            for i in 0..len {
                result[i] = result[i].mul(&vec[i]);
            }
        }
        result
    }
}

/// Parallel sum computation with reduction
pub fn parallel_sum<F: Field>(
    values: &[F],
    config: &ParallelConfig,
) -> F {
    if config.should_parallelize(values.len()) {
        values
            .par_iter()
            .cloned()
            .reduce(|| F::zero(), |acc, x| acc.add(&x))
    } else {
        let mut sum = F::zero();
        for val in values {
            sum = sum.add(val);
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;
    use crate::ring::cyclotomic::CyclotomicRing;
    
    #[test]
    fn test_parallel_config() {
        let config = ParallelConfig::default();
        
        assert!(!config.should_parallelize(100));
        assert!(config.should_parallelize(2000));
    }
    
    #[test]
    fn test_parallel_batch_add() {
        let config = ParallelConfig::default();
        
        let a: Vec<GoldilocksField> = (0..1000)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect();
        let b: Vec<GoldilocksField> = (0..1000)
            .map(|i| GoldilocksField::from_canonical_u64(i * 2))
            .collect();
        
        let result = parallel_batch_add(&a, &b, &config);
        
        assert_eq!(result.len(), 1000);
        for i in 0..1000 {
            let expected = GoldilocksField::from_canonical_u64(i * 3);
            assert_eq!(result[i].to_canonical_u64(), expected.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_parallel_inner_product() {
        let config = ParallelConfig::default();
        
        let a: Vec<GoldilocksField> = (0..1000)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect();
        let b: Vec<GoldilocksField> = (0..1000)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect();
        
        let result = parallel_inner_product(&a, &b, &config);
        
        // Expected: Σ i^2 for i in 0..1000
        let mut expected = GoldilocksField::zero();
        for i in 0..1000 {
            let val = GoldilocksField::from_canonical_u64(i);
            expected = expected.add(&val.mul(&val));
        }
        
        assert_eq!(result.to_canonical_u64(), expected.to_canonical_u64());
    }
    
    #[test]
    fn test_parallel_linear_combination() {
        let config = ParallelConfig::default();
        
        let v1: Vec<GoldilocksField> = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
        ];
        let v2: Vec<GoldilocksField> = vec![
            GoldilocksField::from_canonical_u64(4),
            GoldilocksField::from_canonical_u64(5),
            GoldilocksField::from_canonical_u64(6),
        ];
        
        let vectors = vec![v1, v2];
        let coeffs = vec![
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
        ];
        
        let result = parallel_linear_combination(&vectors, &coeffs, &config);
        
        // Expected: 2*[1,2,3] + 3*[4,5,6] = [14, 19, 24]
        assert_eq!(result[0].to_canonical_u64(), 14);
        assert_eq!(result[1].to_canonical_u64(), 19);
        assert_eq!(result[2].to_canonical_u64(), 24);
    }
    
    #[test]
    fn test_parallel_hadamard_product() {
        let config = ParallelConfig::default();
        
        let v1: Vec<GoldilocksField> = vec![
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
            GoldilocksField::from_canonical_u64(4),
        ];
        let v2: Vec<GoldilocksField> = vec![
            GoldilocksField::from_canonical_u64(5),
            GoldilocksField::from_canonical_u64(6),
            GoldilocksField::from_canonical_u64(7),
        ];
        
        let vectors = vec![v1, v2];
        let result = parallel_hadamard_product(&vectors, &config);
        
        // Expected: [2*5, 3*6, 4*7] = [10, 18, 28]
        assert_eq!(result[0].to_canonical_u64(), 10);
        assert_eq!(result[1].to_canonical_u64(), 18);
        assert_eq!(result[2].to_canonical_u64(), 28);
    }
}
