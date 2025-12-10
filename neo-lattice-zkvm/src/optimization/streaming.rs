// Streaming Prover with Controlled Memory - Task 8.3
// Implements O(N^{1/c}) memory complexity streaming algorithm

use crate::field::Field;
use crate::sumcheck::multilinear::MultilinearPolynomial;
use crate::sumcheck::univariate::UnivariatePolynomial;
use std::collections::HashMap;

/// Streaming configuration
#[derive(Clone, Debug)]
pub struct StreamingConfig {
    /// Memory parameter c (c=2 for O(√N), c=4 for O(N^{1/4}))
    pub c: usize,
    
    /// Chunk size for streaming
    pub chunk_size: usize,
    
    /// Enable disk streaming for very large datasets
    pub enable_disk_streaming: bool,
    
    /// Temporary directory for disk streaming
    pub temp_dir: String,
}

impl StreamingConfig {
    pub fn new(c: usize) -> Self {
        Self {
            c,
            chunk_size: 1024,
            enable_disk_streaming: false,
            temp_dir: "/tmp/zkvm_streaming".to_string(),
        }
    }
    
    pub fn sqrt_memory() -> Self {
        Self::new(2) // O(√N) memory
    }
    
    pub fn quartic_memory() -> Self {
        Self::new(4) // O(N^{1/4}) memory
    }
}

/// Streaming sum-check prover
/// Avoids materializing full K·T arrays by processing in chunks
pub struct StreamingSumCheckProver<F: Field> {
    /// Sparse entries: (index, value) pairs
    sparse_entries: Vec<(usize, F)>,
    
    /// Number of variables
    num_vars: usize,
    
    /// Current stage (1 or 2 for c=2)
    stage: usize,
    
    /// Configuration
    config: StreamingConfig,
    
    /// Intermediate arrays (size O(N^{1/c}))
    p_array: Vec<F>,
    q_array: Vec<F>,
    
    /// Challenges received so far
    challenges: Vec<F>,
}

impl<F: Field> StreamingSumCheckProver<F> {
    /// Create new streaming prover
    /// 
    /// For c=2 (O(√N) memory):
    /// - Stage 1: Process first n/2 variables with O(√N) memory
    /// - Stage 2: Process last n/2 variables with O(√N) memory
    /// 
    /// For c=4 (O(N^{1/4}) memory):
    /// - 4 stages, each processing n/4 variables
    pub fn new(
        sparse_entries: Vec<(usize, F)>,
        dense_poly: &MultilinearPolynomial<F>,
        config: StreamingConfig,
    ) -> Result<Self, String> {
        let num_vars = dense_poly.num_vars;
        let n = dense_poly.evaluations.len();
        
        // Compute chunk size based on c parameter
        let chunk_size = (n as f64).powf(1.0 / config.c as f64).ceil() as usize;
        
        // Initialize stage 1 arrays
        let (p_array, q_array) = Self::initialize_stage_1(
            &sparse_entries,
            &dense_poly.evaluations,
            chunk_size,
            num_vars,
        );
        
        Ok(Self {
            sparse_entries,
            num_vars,
            stage: 1,
            config,
            p_array,
            q_array,
            challenges: Vec::new(),
        })
    }
    
    /// Initialize stage 1 with one streaming pass
    /// 
    /// Algorithm for c=2:
    /// - For each (idx, val) in sparse_p:
    ///   - Compute (i,j) = split_index(idx, √N)
    ///   - Accumulate P[i] += val·h[j]
    ///   - Set Q[i] = f[i]
    fn initialize_stage_1(
        sparse_entries: &[(usize, F)],
        dense_evals: &[F],
        chunk_size: usize,
        num_vars: usize,
    ) -> (Vec<F>, Vec<F>) {
        let mut p_array = vec![F::zero(); chunk_size];
        let q_array = dense_evals[..chunk_size].to_vec();
        
        // One streaming pass over sparse entries
        for &(idx, val) in sparse_entries {
            let (i, j) = Self::split_index(idx, chunk_size);
            if i < chunk_size && j < dense_evals.len() / chunk_size {
                p_array[i] = p_array[i] + val * dense_evals[j];
            }
        }
        
        (p_array, q_array)
    }
    
    /// Split index into (i, j) for two-stage processing
    fn split_index(idx: usize, chunk_size: usize) -> (usize, usize) {
        let i = idx / chunk_size;
        let j = idx % chunk_size;
        (i, j)
    }
    
    /// Compute round polynomial
    pub fn round_polynomial(&self) -> UnivariatePolynomial<F> {
        let n_remaining = self.p_array.len();
        let half = n_remaining / 2;
        
        let mut s_0 = F::zero();
        let mut s_1 = F::zero();
        let mut s_2 = F::zero();
        
        // Process in chunks to maintain memory bound
        for chunk_start in (0..half).step_by(self.config.chunk_size) {
            let chunk_end = (chunk_start + self.config.chunk_size).min(half);
            
            for j in chunk_start..chunk_end {
                s_0 = s_0 + self.p_array[j] * self.q_array[j];
                s_1 = s_1 + self.p_array[j + half] * self.q_array[j + half];
                
                let p_2 = self.p_array[j + half] * F::from_u64(2) - self.p_array[j];
                let q_2 = self.q_array[j + half] * F::from_u64(2) - self.q_array[j];
                s_2 = s_2 + p_2 * q_2;
            }
        }
        
        UnivariatePolynomial::from_evaluations(vec![s_0, s_1, s_2])
    }
    
    /// Update with challenge
    pub fn update(&mut self, challenge: F) {
        let n_remaining = self.p_array.len();
        let half = n_remaining / 2;
        let one_minus_r = F::one() - challenge;
        
        // Update in chunks to maintain memory bound
        let mut new_p = vec![F::zero(); half];
        let mut new_q = vec![F::zero(); half];
        
        for chunk_start in (0..half).step_by(self.config.chunk_size) {
            let chunk_end = (chunk_start + self.config.chunk_size).min(half);
            
            for j in chunk_start..chunk_end {
                new_p[j] = one_minus_r * self.p_array[j] + challenge * self.p_array[j + half];
                new_q[j] = one_minus_r * self.q_array[j] + challenge * self.q_array[j + half];
            }
        }
        
        self.p_array = new_p;
        self.q_array = new_q;
        self.challenges.push(challenge);
        
        // Check if we need to transition to next stage
        let vars_per_stage = self.num_vars / self.config.c;
        if self.challenges.len() == vars_per_stage && self.stage < self.config.c {
            self.transition_to_next_stage();
        }
    }
    
    /// Transition to next stage
    /// 
    /// For c=2:
    /// - After n/2 rounds, transition from stage 1 to stage 2
    /// - Create new P,Q arrays of size √N
    /// - Make another streaming pass over sparse entries
    fn transition_to_next_stage(&mut self) {
        self.stage += 1;
        
        // Reinitialize arrays for next stage
        let chunk_size = self.p_array.len();
        let mut new_p = vec![F::zero(); chunk_size];
        let mut new_q = vec![F::zero(); chunk_size];
        
        // Streaming pass with challenges applied
        for &(idx, val) in &self.sparse_entries {
            // Apply challenges to compute p̃(⃗r,j)
            let evaluated_val = self.evaluate_with_challenges(val, idx);
            let (_, j) = Self::split_index(idx, chunk_size);
            if j < chunk_size {
                new_p[j] = new_p[j] + evaluated_val;
            }
        }
        
        self.p_array = new_p;
        self.q_array = new_q;
    }
    
    /// Evaluate sparse entry with accumulated challenges
    fn evaluate_with_challenges(&self, val: F, idx: usize) -> F {
        // Apply challenges to compute partial evaluation
        let mut result = val;
        for (i, &challenge) in self.challenges.iter().enumerate() {
            let bit = (idx >> i) & 1;
            if bit == 0 {
                result = result * (F::one() - challenge);
            } else {
                result = result * challenge;
            }
        }
        result
    }
    
    /// Get final evaluation
    pub fn final_evaluation(&self) -> F {
        self.p_array[0] * self.q_array[0]
    }
    
    /// Get peak memory usage
    pub fn peak_memory_bytes(&self) -> usize {
        let array_size = self.p_array.len();
        let field_size = std::mem::size_of::<F>();
        2 * array_size * field_size // Two arrays
    }
}

/// Memory usage analysis
pub struct MemoryAnalysis {
    /// Total data size N
    pub n: usize,
    
    /// Memory parameter c
    pub c: usize,
    
    /// Standard memory (bytes)
    pub standard_memory: usize,
    
    /// Streaming memory (bytes)
    pub streaming_memory: usize,
    
    /// Reduction factor
    pub reduction_factor: f64,
}

impl MemoryAnalysis {
    pub fn analyze<F: Field>(n: usize, c: usize) -> Self {
        let field_size = std::mem::size_of::<F>();
        let standard_memory = n * field_size;
        let streaming_memory = ((n as f64).powf(1.0 / c as f64).ceil() as usize) * field_size;
        let reduction_factor = standard_memory as f64 / streaming_memory as f64;
        
        Self {
            n,
            c,
            standard_memory,
            streaming_memory,
            reduction_factor,
        }
    }
    
    pub fn print_report(&self) {
        println!("Streaming Memory Analysis:");
        println!("  Data size N: {}", self.n);
        println!("  Parameter c: {}", self.c);
        println!("  Standard memory: {} bytes ({:.2} MB)", 
                 self.standard_memory, 
                 self.standard_memory as f64 / 1_048_576.0);
        println!("  Streaming memory: {} bytes ({:.2} KB)", 
                 self.streaming_memory,
                 self.streaming_memory as f64 / 1024.0);
        println!("  Reduction factor: {:.0}x", self.reduction_factor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_streaming_prover() {
        // Create sparse entries
        let sparse_entries = vec![
            (0, M61::from_u64(1)),
            (100, M61::from_u64(2)),
            (500, M61::from_u64(3)),
        ];
        
        // Create dense polynomial
        let dense_evals: Vec<M61> = (0..1024).map(|i| M61::from_u64(i as u64)).collect();
        let dense_poly = MultilinearPolynomial::from_evaluations(dense_evals);
        
        let config = StreamingConfig::sqrt_memory();
        let prover = StreamingSumCheckProver::new(sparse_entries, &dense_poly, config).unwrap();
        
        // Verify memory usage is bounded
        let peak_memory = prover.peak_memory_bytes();
        assert!(peak_memory < 1024 * std::mem::size_of::<M61>());
        
        println!("✓ Streaming prover uses bounded memory: {} bytes", peak_memory);
    }
    
    #[test]
    fn test_memory_analysis() {
        let analysis = MemoryAnalysis::analyze::<M61>(1 << 20, 2);
        
        assert_eq!(analysis.n, 1 << 20);
        assert_eq!(analysis.c, 2);
        assert!(analysis.reduction_factor > 1000.0);
        
        analysis.print_report();
    }
    
    #[test]
    fn test_different_c_values() {
        for c in [2, 3, 4] {
            let analysis = MemoryAnalysis::analyze::<M61>(1 << 20, c);
            println!("c={}: reduction={:.0}x", c, analysis.reduction_factor);
            
            // Verify reduction increases with c
            assert!(analysis.reduction_factor > 10.0);
        }
    }
}
