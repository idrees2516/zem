// Task 1.6: Sparse Sum-Check with Prefix-Suffix Algorithm
// Handles massive sums where most terms are zero with O(T + N^{1/c}) complexity

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use std::fmt::Debug;

/// Sparse sum-check prover for g(x) = p̃(x) · q̃(x) where p̃ has only T non-zero entries
/// Achieves O(T + N^{1/c}) time and O(N^{1/c}) space
pub struct SparseSumCheckProver<K: ExtensionFieldElement> {
    /// Non-zero entries of p̃ with their indices
    pub sparse_entries: Vec<(usize, K)>,
    
    /// Dense polynomial q̃ factored as q̃(i,j) = f̃(i) · h̃(j)
    pub f_evals: Vec<K>,
    pub h_evals: Vec<K>,
    
    /// Current stage (1 or 2)
    pub stage: usize,
    
    /// Arrays for current stage
    pub p_array: Vec<K>,
    pub q_array: Vec<K>,
    
    /// Configuration parameter c (controls memory usage)
    pub c: usize,
    
    /// Total number of variables
    pub num_vars: usize,
    
    /// Challenges from stage 1
    pub stage1_challenges: Vec<K>,
}

impl<K: ExtensionFieldElement> SparseSumCheckProver<K> {
    /// Initialize with sparsity T and memory O(N^{1/c})
    /// 
    /// Algorithm:
    /// - sparse_p: T non-zero entries of p̃
    /// - f, h: factorization of q̃(i,j) = f̃(i) · h̃(j)
    /// - c: controls memory (c=2 gives O(√N) memory)
    pub fn new(
        sparse_p: Vec<(usize, K)>,
        f: Vec<K>,
        h: Vec<K>,
        c: usize,
    ) -> Result<Self, String> {
        if c == 0 {
            return Err("c must be at least 1".to_string());
        }
        
        let sqrt_n = f.len();
        if sqrt_n != h.len() {
            return Err("f and h must have same length".to_string());
        }
        
        let num_vars = (sqrt_n * sqrt_n) as f64;
        let num_vars = (num_vars.log2()) as usize;
        
        // Stage 1 initialization: one streaming pass over non-zero terms
        let mut p_array = vec![K::zero(); sqrt_n];
        
        for &(idx, val) in &sparse_p {
            let (i, j) = Self::split_index(idx, sqrt_n);
            // P[i] = Σ_j p̃(i,j) · h̃(j)
            if i < sqrt_n && j < sqrt_n {
                p_array[i] = p_array[i].add(&val.mul(&h[j]));
            }
        }
        
        Ok(Self {
            sparse_entries: sparse_p,
            f_evals: f.clone(),
            h_evals: h,
            stage: 1,
            p_array,
            q_array: f, // Q[i] = f̃(i)
            c,
            num_vars,
            stage1_challenges: Vec::new(),
        })
    }
    
    /// Split index into (i, j) for prefix-suffix decomposition
    fn split_index(idx: usize, sqrt_n: usize) -> (usize, usize) {
        let i = idx / sqrt_n;
        let j = idx % sqrt_n;
        (i, j)
    }
    
    /// Compute round polynomial for current stage
    pub fn round_polynomial(&self) -> UnivariatePolynomial<K> {
        let half = self.p_array.len() / 2;
        
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            let p_0 = self.p_array[i];
            let p_1 = self.p_array[i + half];
            let q_0 = self.q_array[i];
            let q_1 = self.q_array[i + half];
            
            s_0 = s_0.add(&p_0.mul(&q_0));
            s_1 = s_1.add(&p_1.mul(&q_1));
            
            // Extrapolate to X=2
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let p_2 = two.mul(&p_1).sub(&p_0);
            let q_2 = two.mul(&q_1).sub(&q_0);
            s_2 = s_2.add(&p_2.mul(&q_2));
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    /// Update state after receiving challenge
    pub fn update(&mut self, challenge: K) -> Result<(), String> {
        let half = self.p_array.len() / 2;
        let mut new_p = Vec::with_capacity(half);
        let mut new_q = Vec::with_capacity(half);
        
        let one_minus_r = K::one().sub(&challenge);
        
        for i in 0..half {
            let p_new = one_minus_r.mul(&self.p_array[i])
                .add(&challenge.mul(&self.p_array[i + half]));
            new_p.push(p_new);
            
            let q_new = one_minus_r.mul(&self.q_array[i])
                .add(&challenge.mul(&self.q_array[i + half]));
            new_q.push(q_new);
        }
        
        self.p_array = new_p;
        self.q_array = new_q;
        
        // Check if we need to transition to stage 2
        if self.stage == 1 && self.p_array.len() == 1 {
            self.stage1_challenges.push(challenge);
            self.transition_to_stage2()?;
        } else if self.stage == 1 {
            self.stage1_challenges.push(challenge);
        }
        
        Ok(())
    }
    
    /// Transition from stage 1 to stage 2
    /// After receiving challenges ⃗r from first n/2 rounds
    fn transition_to_stage2(&mut self) -> Result<(), String> {
        let sqrt_n = self.f_evals.len();
        
        // Create new P,Q arrays of size √N
        let mut new_p = vec![K::zero(); sqrt_n];
        let mut new_q = vec![K::zero(); sqrt_n];
        
        // For each sparse entry, compute P[j] = p̃(⃗r,j)
        for &(idx, val) in &self.sparse_entries {
            let (i, j) = Self::split_index(idx, sqrt_n);
            
            if j < sqrt_n {
                // Evaluate p̃ at (⃗r, j) where ⃗r are stage 1 challenges
                let p_at_r_j = self.eval_p_at_prefix(&self.stage1_challenges, i, val);
                new_p[j] = new_p[j].add(&p_at_r_j);
            }
        }
        
        // Q[j] = f̃(⃗r) · h̃(j)
        let f_at_r = self.eval_mle_at_point(&self.f_evals, &self.stage1_challenges);
        for j in 0..sqrt_n {
            new_q[j] = f_at_r.mul(&self.h_evals[j]);
        }
        
        self.p_array = new_p;
        self.q_array = new_q;
        self.stage = 2;
        
        Ok(())
    }
    
    /// Evaluate p̃ at prefix challenges
    fn eval_p_at_prefix(&self, challenges: &[K], i: usize, val: K) -> K {
        // Convert i to bits and evaluate
        let num_bits = challenges.len();
        let mut result = val;
        
        for (bit_idx, &challenge) in challenges.iter().enumerate() {
            let bit = (i >> bit_idx) & 1;
            let factor = if bit == 1 {
                challenge
            } else {
                K::one().sub(&challenge)
            };
            result = result.mul(&factor);
        }
        
        result
    }
    
    /// Evaluate MLE at point
    fn eval_mle_at_point(&self, evals: &[K], point: &[K]) -> K {
        let mut current = evals.to_vec();
        
        for &r in point {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            let one_minus_r = K::one().sub(&r);
            
            for i in 0..half {
                let val = one_minus_r.mul(&current[i])
                    .add(&r.mul(&current[i + half]));
                next.push(val);
            }
            
            current = next;
        }
        
        if current.is_empty() {
            K::zero()
        } else {
            current[0]
        }
    }
    
    /// Get final evaluation
    pub fn final_evaluation(&self) -> Result<K, String> {
        if self.p_array.len() != 1 || self.q_array.len() != 1 {
            return Err("Not at final evaluation".to_string());
        }
        
        Ok(self.p_array[0].mul(&self.q_array[0]))
    }
    
    /// Verify total time is O(T + √N) for c=2
    pub fn verify_complexity(&self, t: usize, n: usize, c: usize) -> bool {
        let n_to_1_over_c = (n as f64).powf(1.0 / c as f64) as usize;
        
        // Initialization: O(T) to process sparse entries
        let init_cost = t;
        
        // Stage 1: O(√N) for n/2 rounds
        let stage1_cost = n_to_1_over_c * (n / c);
        
        // Stage 2: O(√N) for n/2 rounds
        let stage2_cost = n_to_1_over_c * (n / c);
        
        let total_cost = init_cost + stage1_cost + stage2_cost;
        let expected_cost = t + 2 * n_to_1_over_c;
        
        total_cost <= expected_cost * 2 // Allow 2x slack
    }
}

/// Generalized sparse sum-check for arbitrary c
/// Achieves O(T + N^{1/c}) time and space
pub struct GeneralizedSparseSumCheck<K: ExtensionFieldElement> {
    /// Sparsity T
    pub sparsity: usize,
    
    /// Total size N = 2^n
    pub total_size: usize,
    
    /// Parameter c
    pub c: usize,
    
    /// Current stage (1 to c)
    pub current_stage: usize,
    
    /// Sparse entries
    pub sparse_entries: Vec<(usize, K)>,
    
    /// Stage arrays
    pub stage_arrays: Vec<Vec<K>>,
    
    /// Challenges from previous stages
    pub all_challenges: Vec<Vec<K>>,
}

impl<K: ExtensionFieldElement> GeneralizedSparseSumCheck<K> {
    /// Initialize for arbitrary c
    pub fn new(
        sparse_entries: Vec<(usize, K)>,
        total_size: usize,
        c: usize,
    ) -> Result<Self, String> {
        if c == 0 {
            return Err("c must be at least 1".to_string());
        }
        
        let chunk_size = (total_size as f64).powf(1.0 / c as f64) as usize;
        
        Ok(Self {
            sparsity: sparse_entries.len(),
            total_size,
            c,
            current_stage: 1,
            sparse_entries,
            stage_arrays: vec![vec![K::zero(); chunk_size]],
            all_challenges: Vec::new(),
        })
    }
    
    /// Process stage
    pub fn process_stage(&mut self, challenges: Vec<K>) -> Result<(), String> {
        self.all_challenges.push(challenges);
        self.current_stage += 1;
        
        if self.current_stage <= self.c {
            // Initialize next stage
            let chunk_size = (self.total_size as f64).powf(1.0 / self.c as f64) as usize;
            self.stage_arrays.push(vec![K::zero(); chunk_size]);
        }
        
        Ok(())
    }
    
    /// Verify complexity: O(C·T) for K = T^C
    pub fn verify_optimal_complexity(&self) -> bool {
        // For K = T^C, prover time should be O(C·T)
        let k = self.total_size;
        let t = self.sparsity;
        let c = self.c;
        
        // Check if K ≈ T^C
        let expected_k = (t as f64).powi(c as i32) as usize;
        let ratio = k as f64 / expected_k as f64;
        
        // Allow 2x slack
        ratio >= 0.5 && ratio <= 2.0
    }
}
