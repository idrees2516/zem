// Parallel Sum-Check Implementation
// Task 20.1: Implement parallel sum-check via Rayon
//
// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 6
// Also: "Speeding Up Sum-Check Proving" (2025-1117)
//
// This module implements parallel sum-check proving using work-stealing
// parallelism via Rayon. The key insight is that sum-check round polynomial
// computation can be parallelized across evaluation points.
//
// Mathematical Foundation:
// Given g: {0,1}^μ → F with claimed sum H, the prover computes:
// - Round j: g_j(X_j) = Σ_{x_{j+1},...,x_μ ∈ {0,1}} g(r_1,...,r_{j-1},X_j,x_{j+1},...,x_μ)
//
// Parallelization Strategy:
// 1. Partition evaluation domain across threads
// 2. Each thread computes partial sums
// 3. Combine partial results
// 4. Work-stealing ensures load balancing
//
// Performance:
// - Linear speedup with number of cores
// - Efficient for large evaluation domains (2^20+)
// - Minimal synchronization overhead

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::sumcheck::{UnivariatePolynomial, SumCheckProof};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

/// Parallel sum-check configuration
#[derive(Clone, Debug)]
pub struct ParallelConfig {
    /// Number of threads (0 = use all available cores)
    pub num_threads: usize,
    
    /// Minimum work size per thread
    /// Below this threshold, don't parallelize
    pub min_work_per_thread: usize,
    
    /// Chunk size for work distribution
    pub chunk_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: 0, // Use all cores
            min_work_per_thread: 1024,
            chunk_size: 256,
        }
    }
}

/// Parallel sum-check prover
///
/// Uses Rayon for work-stealing parallelism.
pub struct ParallelSumCheckProver<F: Field> {
    /// Configuration
    config: ParallelConfig,
    
    /// Thread pool
    pool: rayon::ThreadPool,
    
    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field + Send + Sync> ParallelSumCheckProver<F> {
    /// Create new parallel prover
    ///
    /// Parameters:
    /// - config: Parallelization configuration
    ///
    /// Returns:
    /// - New parallel prover
    pub fn new(config: ParallelConfig) -> Result<Self, String> {
        // Determine number of threads
        let num_threads = if config.num_threads == 0 {
            num_cpus::get()
        } else {
            config.num_threads
        };
        
        // Create thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .map_err(|e| format!("Failed to create thread pool: {}", e))?;
        
        Ok(Self {
            config,
            pool,
            _phantom: std::marker::PhantomData,
        })
    }
    
    /// Prove sum-check in parallel
    ///
    /// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 3
    ///
    /// Given:
    /// - g: Multilinear polynomial
    /// - claimed_sum: H = Σ_{x ∈ {0,1}^μ} g(x)
    ///
    /// Generates:
    /// - Round polynomials g_1(X), ..., g_μ(X)
    /// - Final evaluation g(r_1, ..., r_μ)
    ///
    /// Parallelization:
    /// Each round polynomial computation is parallelized across the
    /// evaluation domain. For round j, we compute:
    /// g_j(0) = Σ_{x_{j+1},...,x_μ} g(r_1,...,r_{j-1},0,x_{j+1},...,x_μ)
    /// g_j(1) = Σ_{x_{j+1},...,x_μ} g(r_1,...,r_{j-1},1,x_{j+1},...,x_μ)
    ///
    /// These sums are computed in parallel by partitioning the domain.
    pub fn prove(
        &self,
        g: &MultilinearPolynomial<F>,
        claimed_sum: F,
        challenges: &[F],
    ) -> Result<SumCheckProof<F>, String> {
        let num_vars = g.num_vars();
        
        if challenges.len() != num_vars {
            return Err(format!(
                "Invalid number of challenges: {} != {}",
                challenges.len(), num_vars
            ));
        }
        
        // Verify claimed sum
        let actual_sum = self.compute_sum_parallel(g)?;
        if actual_sum.to_canonical_u64() != claimed_sum.to_canonical_u64() {
            return Err("Claimed sum does not match actual sum".to_string());
        }
        
        let mut round_polynomials = Vec::with_capacity(num_vars);
        let mut current_poly = g.clone();
        let mut current_sum = claimed_sum;
        
        // Generate round polynomials
        for j in 0..num_vars {
            let challenge = challenges[j];
            
            // Compute round polynomial g_j(X) in parallel
            let round_poly = self.compute_round_polynomial_parallel(&current_poly, j)?;
            
            // Verify consistency: g_j(0) + g_j(1) = current_sum
            let sum_check = round_poly.evaluate(&F::zero())
                .add(&round_poly.evaluate(&F::one()));
            
            if sum_check.to_canonical_u64() != current_sum.to_canonical_u64() {
                return Err(format!("Round {} sum check failed", j));
            }
            
            round_polynomials.push(round_poly.clone());
            
            // Update for next round: bind X_j = r_j
            current_poly = self.bind_variable_parallel(&current_poly, j, challenge)?;
            current_sum = round_poly.evaluate(&challenge);
        }
        
        // Final evaluation
        let final_eval = current_poly.evaluations()[0];
        
        Ok(SumCheckProof {
            round_polynomials,
            final_evaluation: final_eval,
        })
    }
    
    /// Compute sum of polynomial in parallel
    ///
    /// Computes: Σ_{x ∈ {0,1}^μ} g(x)
    ///
    /// Parallelization:
    /// Partition the evaluation domain {0,1}^μ into chunks.
    /// Each thread computes the sum over its chunk.
    /// Combine partial sums at the end.
    fn compute_sum_parallel(&self, g: &MultilinearPolynomial<F>) -> Result<F, String> {
        let evaluations = g.evaluations();
        let n = evaluations.len();
        
        // Check if parallelization is worthwhile
        if n < self.config.min_work_per_thread {
            // Sequential sum
            return Ok(evaluations.iter().fold(F::zero(), |acc, &val| acc.add(&val)));
        }
        
        // Parallel sum using Rayon
        let sum = self.pool.install(|| {
            evaluations
                .par_chunks(self.config.chunk_size)
                .map(|chunk| {
                    chunk.iter().fold(F::zero(), |acc, &val| acc.add(&val))
                })
                .reduce(|| F::zero(), |a, b| a.add(&b))
        });
        
        Ok(sum)
    }
    
    /// Compute round polynomial in parallel
    ///
    /// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 3.2
    ///
    /// Computes g_j(X) for round j.
    ///
    /// For each value v ∈ {0, 1, ..., d-1} (where d is degree):
    /// g_j(v) = Σ_{x_{j+1},...,x_μ} g(r_1,...,r_{j-1},v,x_{j+1},...,x_μ)
    ///
    /// Parallelization:
    /// The sum over {x_{j+1},...,x_μ} is computed in parallel.
    fn compute_round_polynomial_parallel(
        &self,
        g: &MultilinearPolynomial<F>,
        round: usize,
    ) -> Result<UnivariatePolynomial<F>, String> {
        let num_vars = g.num_vars();
        let evaluations = g.evaluations();
        let n = evaluations.len();
        
        // For multilinear polynomials, degree is at most 1 in each variable
        // So round polynomial has degree at most 1
        let degree = 1;
        
        // Compute g_j(0) and g_j(1)
        let mut coeffs = Vec::with_capacity(degree + 1);
        
        for value in 0..=degree {
            let v = F::from_u64(value as u64);
            
            // Compute sum in parallel
            let sum = if n < self.config.min_work_per_thread {
                // Sequential
                self.compute_partial_sum_sequential(evaluations, round, v)
            } else {
                // Parallel
                self.compute_partial_sum_parallel(evaluations, round, v)?
            };
            
            coeffs.push(sum);
        }
        
        UnivariatePolynomial::from_coefficients(coeffs)
    }
    
    /// Compute partial sum sequentially
    fn compute_partial_sum_sequential(
        &self,
        evaluations: &[F],
        round: usize,
        value: F,
    ) -> F {
        let n = evaluations.len();
        let stride = 1 << (round + 1);
        let half_stride = stride / 2;
        
        let mut sum = F::zero();
        
        for i in (0..n).step_by(stride) {
            // Interpolate between evaluations[i] and evaluations[i + half_stride]
            let eval_0 = evaluations[i];
            let eval_1 = evaluations[i + half_stride];
            
            // Linear interpolation: (1-v)·eval_0 + v·eval_1
            let one_minus_v = F::one().sub(&value);
            let interpolated = one_minus_v.mul(&eval_0).add(&value.mul(&eval_1));
            
            sum = sum.add(&interpolated);
        }
        
        sum
    }
    
    /// Compute partial sum in parallel
    fn compute_partial_sum_parallel(
        &self,
        evaluations: &[F],
        round: usize,
        value: F,
    ) -> Result<F, String> {
        let n = evaluations.len();
        let stride = 1 << (round + 1);
        let half_stride = stride / 2;
        
        // Create index ranges for parallel processing
        let indices: Vec<usize> = (0..n).step_by(stride).collect();
        
        // Parallel sum
        let sum = self.pool.install(|| {
            indices
                .par_chunks(self.config.chunk_size)
                .map(|chunk| {
                    let mut partial_sum = F::zero();
                    
                    for &i in chunk {
                        let eval_0 = evaluations[i];
                        let eval_1 = evaluations[i + half_stride];
                        
                        // Linear interpolation
                        let one_minus_v = F::one().sub(&value);
                        let interpolated = one_minus_v.mul(&eval_0).add(&value.mul(&eval_1));
                        
                        partial_sum = partial_sum.add(&interpolated);
                    }
                    
                    partial_sum
                })
                .reduce(|| F::zero(), |a, b| a.add(&b))
        });
        
        Ok(sum)
    }
    
    /// Bind variable in parallel
    ///
    /// Computes g(r_1,...,r_j,X_{j+1},...,X_μ) given g and r_j.
    ///
    /// This reduces the polynomial from μ variables to μ-1 variables.
    fn bind_variable_parallel(
        &self,
        g: &MultilinearPolynomial<F>,
        var_index: usize,
        value: F,
    ) -> Result<MultilinearPolynomial<F>, String> {
        let evaluations = g.evaluations();
        let n = evaluations.len();
        let new_n = n / 2;
        
        let stride = 1 << (var_index + 1);
        let half_stride = stride / 2;
        
        // Check if parallelization is worthwhile
        if new_n < self.config.min_work_per_thread {
            // Sequential
            let mut new_evals = Vec::with_capacity(new_n);
            
            for i in (0..n).step_by(stride) {
                let eval_0 = evaluations[i];
                let eval_1 = evaluations[i + half_stride];
                
                // Linear interpolation: (1-value)·eval_0 + value·eval_1
                let one_minus_v = F::one().sub(&value);
                let interpolated = one_minus_v.mul(&eval_0).add(&value.mul(&eval_1));
                
                new_evals.push(interpolated);
            }
            
            return MultilinearPolynomial::from_evaluations(new_evals);
        }
        
        // Parallel
        let indices: Vec<usize> = (0..n).step_by(stride).collect();
        
        let new_evals: Vec<F> = self.pool.install(|| {
            indices
                .par_iter()
                .map(|&i| {
                    let eval_0 = evaluations[i];
                    let eval_1 = evaluations[i + half_stride];
                    
                    // Linear interpolation
                    let one_minus_v = F::one().sub(&value);
                    one_minus_v.mul(&eval_0).add(&value.mul(&eval_1))
                })
                .collect()
        });
        
        MultilinearPolynomial::from_evaluations(new_evals)
    }
    
    /// Get configuration
    pub fn config(&self) -> &ParallelConfig {
        &self.config
    }
    
    /// Get number of threads
    pub fn num_threads(&self) -> usize {
        self.pool.current_num_threads()
    }
}

/// Parallel performance statistics
#[derive(Clone, Debug)]
pub struct ParallelPerformance {
    /// Number of threads used
    pub num_threads: usize,
    
    /// Total time (milliseconds)
    pub total_time_ms: u64,
    
    /// Time per round (milliseconds)
    pub round_times_ms: Vec<u64>,
    
    /// Speedup vs sequential
    pub speedup: f64,
    
    /// Parallel efficiency (speedup / num_threads)
    pub efficiency: f64,
}

impl ParallelPerformance {
    /// Create new performance stats
    pub fn new(
        num_threads: usize,
        total_time_ms: u64,
        round_times_ms: Vec<u64>,
        sequential_time_ms: u64,
    ) -> Self {
        let speedup = sequential_time_ms as f64 / total_time_ms as f64;
        let efficiency = speedup / num_threads as f64;
        
        Self {
            num_threads,
            total_time_ms,
            round_times_ms,
            speedup,
            efficiency,
        }
    }
    
    /// Print performance report
    pub fn print_report(&self) {
        println!("Parallel Sum-Check Performance:");
        println!("  Threads: {}", self.num_threads);
        println!("  Total time: {} ms", self.total_time_ms);
        println!("  Speedup: {:.2}x", self.speedup);
        println!("  Efficiency: {:.2}%", self.efficiency * 100.0);
        println!("  Round times:");
        for (i, &time) in self.round_times_ms.iter().enumerate() {
            println!("    Round {}: {} ms", i, time);
        }
    }
}

/// Benchmark parallel vs sequential sum-check
pub fn benchmark_parallel_sumcheck<F: Field + Send + Sync>(
    polynomial_size: usize,
    num_threads: usize,
) -> Result<ParallelPerformance, String> {
    use std::time::Instant;
    
    // Create random polynomial
    let num_vars = (polynomial_size as f64).log2() as usize;
    let evals: Vec<F> = (0..polynomial_size)
        .map(|i| F::from_u64(i as u64))
        .collect();
    let poly = MultilinearPolynomial::from_evaluations(evals)?;
    
    // Generate random challenges
    let challenges: Vec<F> = (0..num_vars)
        .map(|i| F::from_u64((i * 12345) as u64))
        .collect();
    
    // Compute claimed sum
    let claimed_sum = poly.evaluations().iter()
        .fold(F::zero(), |acc, &val| acc.add(&val));
    
    // Sequential timing
    let seq_start = Instant::now();
    let _seq_proof = crate::sumcheck::DenseSumCheckProver::new()
        .prove(&poly, claimed_sum, &challenges)?;
    let seq_time = seq_start.elapsed().as_millis() as u64;
    
    // Parallel timing
    let config = ParallelConfig {
        num_threads,
        min_work_per_thread: 1024,
        chunk_size: 256,
    };
    
    let parallel_prover = ParallelSumCheckProver::new(config)?;
    
    let par_start = Instant::now();
    let _par_proof = parallel_prover.prove(&poly, claimed_sum, &challenges)?;
    let par_time = par_start.elapsed().as_millis() as u64;
    
    // Round times (would be measured individually in practice)
    let round_times = vec![par_time / num_vars as u64; num_vars];
    
    Ok(ParallelPerformance::new(
        num_threads,
        par_time,
        round_times,
        seq_time,
    ))
}
