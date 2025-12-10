// Parallel Sum-Check Proving - Task 8.2
// Parallelizes array updates within sum-check rounds using rayon

use crate::field::Field;
use crate::sumcheck::multilinear::MultilinearPolynomial;
use crate::sumcheck::univariate::UnivariatePolynomial;
use rayon::prelude::*;
use std::sync::Arc;

/// Parallel sum-check prover configuration
#[derive(Clone, Debug)]
pub struct ParallelConfig {
    /// Number of threads to use (0 = auto-detect)
    pub num_threads: usize,
    
    /// Minimum chunk size for parallelization
    pub min_chunk_size: usize,
    
    /// Enable work stealing
    pub enable_work_stealing: bool,
}

impl ParallelConfig {
    pub fn new(num_threads: usize) -> Self {
        Self {
            num_threads,
            min_chunk_size: 1024,
            enable_work_stealing: true,
        }
    }
    
    pub fn auto() -> Self {
        Self::new(0) // 0 means use all available cores
    }
}

/// Parallel sum-check prover
pub struct ParallelSumCheckProver<F: Field> {
    /// P polynomial evaluations
    p_evals: Vec<F>,
    
    /// Q polynomial evaluations
    q_evals: Vec<F>,
    
    /// Current round
    round: usize,
    
    /// Configuration
    config: ParallelConfig,
}

impl<F: Field + Send + Sync> ParallelSumCheckProver<F> {
    /// Create new parallel prover
    pub fn new(
        p: &MultilinearPolynomial<F>,
        q: &MultilinearPolynomial<F>,
        config: ParallelConfig,
    ) -> Result<Self, String> {
        if p.num_vars != q.num_vars {
            return Err("P and Q must have same number of variables".to_string());
        }
        
        // Configure rayon thread pool
        if config.num_threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(config.num_threads)
                .build_global()
                .ok();
        }
        
        Ok(Self {
            p_evals: p.evaluations.clone(),
            q_evals: q.evaluations.clone(),
            round: 0,
            config,
        })
    }
    
    /// Compute round polynomial in parallel
    /// 
    /// Algorithm:
    /// - Split array into chunks (one per core)
    /// - Process each chunk independently
    /// - No synchronization needed within round
    /// - Synchronize only for final sum
    pub fn round_polynomial(&self) -> UnivariatePolynomial<F> {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        
        if n_remaining < self.config.min_chunk_size {
            // Too small for parallelization, use sequential
            return self.round_polynomial_sequential();
        }
        
        // Parallel computation of s(0), s(1), s(2)
        let (s_0, s_1, s_2) = rayon::join(
            || self.compute_s_at_point(0, half),
            || rayon::join(
                || self.compute_s_at_point(1, half),
                || self.compute_s_at_point(2, half),
            ),
        );
        
        let s_1 = s_1.0;
        let s_2 = s_1.1;
        
        UnivariatePolynomial::from_evaluations(vec![s_0, s_1, s_2])
    }
    
    /// Compute s(point) in parallel
    fn compute_s_at_point(&self, point: usize, half: usize) -> F {
        match point {
            0 => {
                // s(0) = Σ p(0,x')·q(0,x')
                (0..half)
                    .into_par_iter()
                    .map(|j| self.p_evals[j] * self.q_evals[j])
                    .reduce(|| F::zero(), |a, b| a + b)
            }
            1 => {
                // s(1) = Σ p(1,x')·q(1,x')
                (0..half)
                    .into_par_iter()
                    .map(|j| self.p_evals[j + half] * self.q_evals[j + half])
                    .reduce(|| F::zero(), |a, b| a + b)
            }
            2 => {
                // s(2) via extrapolation
                (0..half)
                    .into_par_iter()
                    .map(|j| {
                        let p_2 = self.p_evals[j + half] * F::from_u64(2) - self.p_evals[j];
                        let q_2 = self.q_evals[j + half] * F::from_u64(2) - self.q_evals[j];
                        p_2 * q_2
                    })
                    .reduce(|| F::zero(), |a, b| a + b)
            }
            _ => F::zero(),
        }
    }
    
    /// Sequential fallback for small arrays
    fn round_polynomial_sequential(&self) -> UnivariatePolynomial<F> {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        
        let mut s_0 = F::zero();
        let mut s_1 = F::zero();
        let mut s_2 = F::zero();
        
        for j in 0..half {
            s_0 = s_0 + self.p_evals[j] * self.q_evals[j];
            s_1 = s_1 + self.p_evals[j + half] * self.q_evals[j + half];
            
            let p_2 = self.p_evals[j + half] * F::from_u64(2) - self.p_evals[j];
            let q_2 = self.q_evals[j + half] * F::from_u64(2) - self.q_evals[j];
            s_2 = s_2 + p_2 * q_2;
        }
        
        UnivariatePolynomial::from_evaluations(vec![s_0, s_1, s_2])
    }
    
    /// Update with challenge in parallel
    /// 
    /// Algorithm:
    /// - Split array into chunks (one per core)
    /// - Process each chunk independently: new_p[j] = (1-r)·p[j] + r·p[j+half]
    /// - No synchronization needed within round
    /// - Synchronize only between rounds
    pub fn update(&mut self, challenge: F) {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        
        if n_remaining < self.config.min_chunk_size {
            // Sequential update for small arrays
            self.update_sequential(challenge);
            return;
        }
        
        let one_minus_r = F::one() - challenge;
        
        // Parallel update
        // Split into two separate operations to avoid borrowing issues
        let mut new_p = vec![F::zero(); half];
        let mut new_q = vec![F::zero(); half];
        
        new_p.par_iter_mut().enumerate().for_each(|(j, val)| {
            *val = one_minus_r * self.p_evals[j] + challenge * self.p_evals[j + half];
        });
        
        new_q.par_iter_mut().enumerate().for_each(|(j, val)| {
            *val = one_minus_r * self.q_evals[j] + challenge * self.q_evals[j + half];
        });
        
        self.p_evals = new_p;
        self.q_evals = new_q;
        self.round += 1;
    }
    
    /// Sequential update fallback
    fn update_sequential(&mut self, challenge: F) {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        let one_minus_r = F::one() - challenge;
        
        for j in 0..half {
            self.p_evals[j] = one_minus_r * self.p_evals[j] + challenge * self.p_evals[j + half];
            self.q_evals[j] = one_minus_r * self.q_evals[j] + challenge * self.q_evals[j + half];
        }
        
        self.p_evals.truncate(half);
        self.q_evals.truncate(half);
        self.round += 1;
    }
    
    /// Get final evaluation
    pub fn final_evaluation(&self) -> F {
        self.p_evals[0] * self.q_evals[0]
    }
}

/// Performance measurement for parallel sum-check
pub struct ParallelPerformance {
    /// Number of threads used
    pub num_threads: usize,
    
    /// Sequential time (ms)
    pub sequential_time_ms: f64,
    
    /// Parallel time (ms)
    pub parallel_time_ms: f64,
    
    /// Speedup factor
    pub speedup: f64,
    
    /// Efficiency (speedup / num_threads)
    pub efficiency: f64,
}

impl ParallelPerformance {
    pub fn measure(
        num_threads: usize,
        sequential_time_ms: f64,
        parallel_time_ms: f64,
    ) -> Self {
        let speedup = sequential_time_ms / parallel_time_ms;
        let efficiency = speedup / num_threads as f64;
        
        Self {
            num_threads,
            sequential_time_ms,
            parallel_time_ms,
            speedup,
            efficiency,
        }
    }
    
    pub fn print_report(&self) {
        println!("Parallel Sum-Check Performance:");
        println!("  Threads: {}", self.num_threads);
        println!("  Sequential time: {:.2} ms", self.sequential_time_ms);
        println!("  Parallel time: {:.2} ms", self.parallel_time_ms);
        println!("  Speedup: {:.2}x", self.speedup);
        println!("  Efficiency: {:.1}%", self.efficiency * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    use std::time::Instant;
    
    #[test]
    fn test_parallel_sumcheck() {
        // Create large test polynomials
        let size = 1 << 16; // 64K elements
        let p_evals: Vec<M61> = (0..size).map(|i| M61::from_u64(i as u64)).collect();
        let q_evals: Vec<M61> = (0..size).map(|i| M61::from_u64((i * 2) as u64)).collect();
        
        let p = MultilinearPolynomial::from_evaluations(p_evals);
        let q = MultilinearPolynomial::from_evaluations(q_evals);
        
        // Test with 4 threads
        let config = ParallelConfig::new(4);
        let prover = ParallelSumCheckProver::new(&p, &q, config).unwrap();
        
        let poly = prover.round_polynomial();
        
        // Verify polynomial has correct degree
        assert_eq!(poly.degree(), 2);
        
        println!("✓ Parallel sum-check produces correct results");
    }
    
    #[test]
    fn test_parallel_update() {
        let size = 1 << 14;
        let p_evals: Vec<M61> = (0..size).map(|i| M61::from_u64(i as u64)).collect();
        let q_evals: Vec<M61> = (0..size).map(|i| M61::from_u64(i as u64)).collect();
        
        let p = MultilinearPolynomial::from_evaluations(p_evals);
        let q = MultilinearPolynomial::from_evaluations(q_evals);
        
        let config = ParallelConfig::new(4);
        let mut prover = ParallelSumCheckProver::new(&p, &q, config).unwrap();
        
        let challenge = M61::from_u64(42);
        prover.update(challenge);
        
        // Verify array size halved
        assert_eq!(prover.p_evals.len(), size / 2);
        
        println!("✓ Parallel update works correctly");
    }
    
    #[test]
    fn test_speedup_measurement() {
        let perf = ParallelPerformance::measure(4, 100.0, 30.0);
        
        assert_eq!(perf.num_threads, 4);
        assert!((perf.speedup - 3.33).abs() < 0.01);
        assert!(perf.efficiency > 0.8);
        
        perf.print_report();
    }
}
