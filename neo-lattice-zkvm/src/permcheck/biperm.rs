// BiPerm: Linear-Time Permutation Check Protocol
//
// This module implements the BiPerm protocol from Section 3.1 of the paper
// "Linear-Time Permutation Check" by Bünz, Chen, and DeStefano (2025).
//
// # BiPerm Protocol Overview
//
// BiPerm achieves O(n) prover time by splitting the permutation indicator function
// into two parts (left and right halves), reducing the degree from μ to 3.
//
// ## Key Insight (Paper Section 3.1)
//
// Instead of computing 1̃_σ(X,Y) = ∏_{i=1}^μ eq(σ̃_i(X), Y_i) (degree μ),
// we split Y into halves and compute:
//   1̃_σ(X,Y) = 1̃_{σ_L}(X, Y_L) · 1̃_{σ_R}(X, Y_R)
//
// where:
// - Y_L = Y_{[1:μ/2]} (first μ/2 bits)
// - Y_R = Y_{[μ/2+1:μ]} (last μ/2 bits)
// - σ_L(X) = first μ/2 bits of σ(X)
// - σ_R(X) = last μ/2 bits of σ(X)
//
// This gives degree 3 sumcheck: f(x) · 1̃_{σ_L}(x,α_L) · 1̃_{σ_R}(x,α_R)
//
// ## Complexity (Paper Theorem 3.1)
//
// - **Preprocessing**: O(n^{1.5}) with n non-zero entries (sparse)
// - **Prover Time**: O(n) field operations
// - **Verifier Time**: O(log n)
// - **Proof Size**: O(log n) field elements
// - **Soundness**: O(μ/|F|) = O(log n/|F|)
//
// ## Requirements
//
// BiPerm requires a **sparse polynomial commitment scheme** (PCS) where:
// - Commitment cost depends only on non-zero entries
// - Examples: Dory, KZH, Hyrax
//
// For non-sparse PCS, use MulPerm instead (Section 3.2).
//
// # Paper References
// - Section 3.1: BiPerm Protocol
// - Algorithm 2: BiPerm Sumcheck
// - Theorem 3.1: BiPerm Complexity
// - Equation (3.1): Indicator function splitting
// - Equation (3.2): O(√n) preprocessing optimization

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::permcheck::{
    Permutation, PermutationMLE, EqualityPolynomial, BooleanHypercube,
    VirtualPolynomial, SumcheckProof, SumcheckProver, SumcheckVerifier,
    PermCheckError, VerificationError,
};
use std::marker::PhantomData;

/// BiPerm Preprocessed Index
///
/// Contains the preprocessed indicator functions 1̃_{σ_L} and 1̃_{σ_R}.
///
/// # Structure (Paper Section 3.1)
///
/// For permutation σ: B^μ → B^μ, we precompute:
/// - 1̃_{σ_L}(X, Y_L): Indicator for left half (size n^{1.5}, n non-zero)
/// - 1̃_{σ_R}(X, Y_R): Indicator for right half (size n^{1.5}, n non-zero)
///
/// # Sparsity
///
/// Each indicator function has:
/// - Total size: 2^μ × 2^{μ/2} = n × √n = n^{1.5}
/// - Non-zero entries: n (one per input)
/// - Sparsity ratio: n / n^{1.5} = 1/√n
///
/// This sparsity is crucial for O(n) prover time with sparse PCS.
///
/// # Paper Reference
/// Section 3.1: "The prover commits to two polynomials of size n^{1.5}
/// with n non-zero entries each"
#[derive(Clone, Debug)]
pub struct BiPermIndex<F: Field> {
    /// Number of variables μ
    pub num_vars: usize,
    
    /// Left half indicator: 1̃_{σ_L}(X, Y_L)
    /// Size: 2^μ × 2^{μ/2} = n^{1.5}
    /// Non-zero: n entries
    pub sigma_L_indicator: SparseIndicator<F>,
    
    /// Right half indicator: 1̃_{σ_R}(X, Y_R)
    /// Size: 2^μ × 2^{μ/2} = n^{1.5}
    /// Non-zero: n entries
    pub sigma_R_indicator: SparseIndicator<F>,
}


/// Sparse Indicator Function
///
/// Represents a sparse multilinear polynomial with efficient storage.
///
/// # Representation
///
/// Instead of storing all 2^{μ + μ/2} = n^{1.5} evaluations, we store only:
/// - Non-zero entries as (index, value) pairs
/// - Total: n entries for BiPerm indicators
///
/// # Paper Reference
/// Section 3.1: "Each indicator has n non-zero entries"
#[derive(Clone, Debug)]
pub struct SparseIndicator<F: Field> {
    /// Total number of variables (μ + μ/2)
    pub num_vars: usize,
    
    /// Non-zero entries: (index, value)
    /// Index is in lexicographic order over B^{num_vars}
    pub non_zero_entries: Vec<(usize, F)>,
    
    /// Total size (for validation)
    pub total_size: usize,
}

impl<F: Field> SparseIndicator<F> {
    /// Create a new sparse indicator
    ///
    /// # Arguments
    /// - `num_vars`: Total number of variables
    /// - `non_zero_entries`: Non-zero (index, value) pairs
    pub fn new(num_vars: usize, non_zero_entries: Vec<(usize, F)>) -> Self {
        let total_size = 1 << num_vars;
        Self {
            num_vars,
            non_zero_entries,
            total_size,
        }
    }
    
    /// Evaluate at a specific index
    ///
    /// # Complexity
    /// O(log n) with binary search on sorted entries
    pub fn evaluate_at_index(&self, index: usize) -> F {
        match self.non_zero_entries.binary_search_by_key(&index, |(idx, _)| *idx) {
            Ok(pos) => self.non_zero_entries[pos].1,
            Err(_) => F::zero(),
        }
    }
    
    /// Get dense representation (for sumcheck)
    ///
    /// Expands sparse representation to full evaluation table.
    /// Used during sumcheck when we need all evaluations.
    ///
    /// # Complexity
    /// O(total_size) = O(n^{1.5}) for BiPerm
    pub fn to_dense(&self) -> Vec<F> {
        let mut dense = vec![F::zero(); self.total_size];
        for &(idx, val) in &self.non_zero_entries {
            dense[idx] = val;
        }
        dense
    }
}


impl<F: Field> BiPermIndex<F> {
    /// Preprocess a permutation for BiPerm
    ///
    /// Computes the left and right indicator functions 1̃_{σ_L} and 1̃_{σ_R}.
    ///
    /// # Algorithm (Paper Section 3.1)
    ///
    /// For each x ∈ B^μ:
    /// 1. Compute σ(x) = (σ_L(x), σ_R(x)) by splitting into halves
    /// 2. Set 1_{σ_L}(x, σ_L(x)) = 1 (all other entries are 0)
    /// 3. Set 1_{σ_R}(x, σ_R(x)) = 1 (all other entries are 0)
    ///
    /// # Complexity
    /// O(n) to compute the n non-zero entries for each indicator
    ///
    /// # Paper Reference
    /// Section 3.1, Equations (3.1): "Split σ into σ_L and σ_R"
    ///
    /// # Arguments
    /// - `perm`: The permutation to preprocess
    ///
    /// # Returns
    /// BiPerm index with preprocessed indicators
    pub fn preprocess(perm: &Permutation) -> Result<Self, PermCheckError> {
        let num_vars = perm.num_vars();
        let n = perm.size;
        
        // Validate size is power of 2
        if !n.is_power_of_two() {
            return Err(PermCheckError::InvalidPermutation {
                reason: "Size must be power of 2".to_string(),
            });
        }
        
        let mu = num_vars;
        let mu_half = mu / 2;
        let mu_half_ceil = (mu + 1) / 2; // For odd μ
        
        // Compute non-zero entries for σ_L indicator
        let mut sigma_L_entries = Vec::with_capacity(n);
        
        // Compute non-zero entries for σ_R indicator
        let mut sigma_R_entries = Vec::with_capacity(n);
        
        for x in 0..n {
            let sigma_x = perm.mapping[x];
            
            // Split σ(x) into left and right halves
            // σ_L(x) = first μ/2 bits of σ(x)
            // σ_R(x) = last μ/2 bits of σ(x)
            let sigma_L_x = sigma_x & ((1 << mu_half_ceil) - 1); // Lower bits
            let sigma_R_x = sigma_x >> mu_half_ceil; // Upper bits
            
            // 1̃_{σ_L}(x, y_L) = 1 iff y_L = σ_L(x)
            // Index in combined space: x * 2^{μ/2} + y_L
            let sigma_L_index = x * (1 << mu_half_ceil) + sigma_L_x;
            sigma_L_entries.push((sigma_L_index, F::one()));
            
            // 1̃_{σ_R}(x, y_R) = 1 iff y_R = σ_R(x)
            let sigma_R_index = x * (1 << mu_half) + sigma_R_x;
            sigma_R_entries.push((sigma_R_index, F::one()));
        }
        
        // Sort entries by index for efficient lookup
        sigma_L_entries.sort_by_key(|(idx, _)| *idx);
        sigma_R_entries.sort_by_key(|(idx, _)| *idx);
        
        Ok(Self {
            num_vars,
            sigma_L_indicator: SparseIndicator::new(
                mu + mu_half_ceil,
                sigma_L_entries,
            ),
            sigma_R_indicator: SparseIndicator::new(
                mu + mu_half,
                sigma_R_entries,
            ),
        })
    }
}


/// BiPerm Virtual Polynomial
///
/// Implements the degree-3 virtual polynomial for BiPerm sumcheck:
///   f(x) · 1̃_{σ_L}(x, α_L) · 1̃_{σ_R}(x, α_R)
///
/// # Degree Analysis (Paper Section 3.1)
///
/// - f(x): degree 1 (multilinear)
/// - 1̃_{σ_L}(x, α_L): degree 1 in x (α_L is fixed)
/// - 1̃_{σ_R}(x, α_R): degree 1 in x (α_R is fixed)
/// - Product: degree 1 + 1 + 1 = 3
///
/// This degree-3 sumcheck is optimal for sparse PCS.
///
/// # Paper Reference
/// Algorithm 2: BiPerm Sumcheck
/// Equation (3.2): "Degree 3 in each variable"
pub struct BiPermVirtualPoly<F: Field> {
    /// Witness polynomial f
    f_evals: Vec<F>,
    
    /// Indicator table for σ_L: 1̃_{σ_L}(·, α_L)
    /// Precomputed for all x ∈ B^μ
    sigma_L_table: Vec<F>,
    
    /// Indicator table for σ_R: 1̃_{σ_R}(·, α_R)
    /// Precomputed for all x ∈ B^μ
    sigma_R_table: Vec<F>,
    
    /// Number of variables μ
    num_vars: usize,
}

impl<F: Field> BiPermVirtualPoly<F> {
    /// Create BiPerm virtual polynomial
    ///
    /// # Critical Optimization (Paper Equation 3.2)
    ///
    /// The key to O(n) prover time is precomputing indicator tables:
    /// 1. Compute eq(y_L, α_L) for all y_L ∈ B^{μ/2} in O(√n) time
    /// 2. For each x ∈ B^μ, lookup 1̃_{σ_L}(x, α_L) = eq(σ_L(x), α_L) in O(1)
    /// 3. Total: O(√n + n) = O(n)
    ///
    /// Without this optimization, computing indicators would take O(n · μ).
    ///
    /// # Arguments
    /// - `f`: Witness polynomial
    /// - `index`: Preprocessed BiPerm index
    /// - `alpha_L`: Challenge for left half
    /// - `alpha_R`: Challenge for right half
    ///
    /// # Complexity
    /// O(√n + n) = O(n) preprocessing
    ///
    /// # Paper Reference
    /// Section 3.1, Equation (3.2):
    /// "The prover can compute eq(y_L, α_L) for all y_L ∈ B^{μ/2} in time O(2^{μ/2})"
    pub fn new(
        f: &MultilinearPolynomial<F>,
        index: &BiPermIndex<F>,
        alpha_L: &[F],
        alpha_R: &[F],
    ) -> Self {
        let num_vars = f.num_vars;
        let n = f.evaluations.len();
        
        // Step 1: Compute eq(y_L, α_L) for all y_L ∈ B^{μ/2}
        // This is the O(√n) optimization
        let eq_L_table = EqualityPolynomial::evaluate_all_boolean(alpha_L);
        
        // Step 2: Compute eq(y_R, α_R) for all y_R ∈ B^{μ/2}
        let eq_R_table = EqualityPolynomial::evaluate_all_boolean(alpha_R);
        
        // Step 3: Build indicator tables by looking up σ_L(x) and σ_R(x)
        // For each x, we need to find σ_L(x) and σ_R(x) from the sparse indicator
        let mut sigma_L_table = vec![F::zero(); n];
        let mut sigma_R_table = vec![F::zero(); n];
        
        let mu_half_ceil = (num_vars + 1) / 2;
        let mu_half = num_vars / 2;
        
        // Extract σ_L(x) and σ_R(x) from sparse indicators
        for &(combined_idx, val) in &index.sigma_L_indicator.non_zero_entries {
            if val != F::zero() {
                let x = combined_idx / (1 << mu_half_ceil);
                let sigma_L_x = combined_idx % (1 << mu_half_ceil);
                
                if x < n && sigma_L_x < eq_L_table.len() {
                    // 1̃_{σ_L}(x, α_L) = eq(σ_L(x), α_L)
                    sigma_L_table[x] = eq_L_table[sigma_L_x];
                }
            }
        }
        
        for &(combined_idx, val) in &index.sigma_R_indicator.non_zero_entries {
            if val != F::zero() {
                let x = combined_idx / (1 << mu_half);
                let sigma_R_x = combined_idx % (1 << mu_half);
                
                if x < n && sigma_R_x < eq_R_table.len() {
                    // 1̃_{σ_R}(x, α_R) = eq(σ_R(x), α_R)
                    sigma_R_table[x] = eq_R_table[sigma_R_x];
                }
            }
        }
        
        Self {
            f_evals: f.evaluations.clone(),
            sigma_L_table,
            sigma_R_table,
            num_vars,
        }
    }
}


impl<F: Field> VirtualPolynomial<F> for BiPermVirtualPoly<F> {
    fn evaluate(&self, point: &[F]) -> F {
        // Evaluate f(point)
        let f_val = {
            let mut current = self.f_evals.clone();
            for r_i in point.iter() {
                let half = current.len() / 2;
                let mut next = Vec::with_capacity(half);
                for j in 0..half {
                    let one_minus_r = F::one().sub(r_i);
                    let val = current[j].mul(&one_minus_r)
                        .add(&current[j + half].mul(r_i));
                    next.push(val);
                }
                current = next;
            }
            current[0]
        };
        
        // Evaluate 1̃_{σ_L}(point, α_L)
        let sigma_L_val = {
            let mut current = self.sigma_L_table.clone();
            for r_i in point.iter() {
                let half = current.len() / 2;
                let mut next = Vec::with_capacity(half);
                for j in 0..half {
                    let one_minus_r = F::one().sub(r_i);
                    let val = current[j].mul(&one_minus_r)
                        .add(&current[j + half].mul(r_i));
                    next.push(val);
                }
                current = next;
            }
            current[0]
        };
        
        // Evaluate 1̃_{σ_R}(point, α_R)
        let sigma_R_val = {
            let mut current = self.sigma_R_table.clone();
            for r_i in point.iter() {
                let half = current.len() / 2;
                let mut next = Vec::with_capacity(half);
                for j in 0..half {
                    let one_minus_r = F::one().sub(r_i);
                    let val = current[j].mul(&one_minus_r)
                        .add(&current[j + half].mul(r_i));
                    next.push(val);
                }
                current = next;
            }
            current[0]
        };
        
        // Return product: f · σ_L · σ_R
        f_val.mul(&sigma_L_val).mul(&sigma_R_val)
    }
    
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> Vec<F> {
        let round = challenges.len();
        let remaining_vars = self.num_vars - round;
        
        if remaining_vars == 0 {
            return vec![self.f_evals[0]
                .mul(&self.sigma_L_table[0])
                .mul(&self.sigma_R_table[0])];
        }
        
        // Degree 3 polynomial: need evaluations at 0, 1, 2, 3
        let mut round_poly = vec![F::zero(); 4];
        
        let half = self.f_evals.len() / 2;
        
        // For each evaluation point X ∈ {0, 1, 2, 3}
        for eval_point in 0..=3 {
            let x = F::from_u64(eval_point as u64);
            
            // Sum over all x' ∈ B^{remaining_vars - 1}
            for i in 0..half {
                // Interpolate each table at x
                let one_minus_x = F::one().sub(&x);
                
                let f_val = self.f_evals[i].mul(&one_minus_x)
                    .add(&self.f_evals[i + half].mul(&x));
                
                let sigma_L_val = self.sigma_L_table[i].mul(&one_minus_x)
                    .add(&self.sigma_L_table[i + half].mul(&x));
                
                let sigma_R_val = self.sigma_R_table[i].mul(&one_minus_x)
                    .add(&self.sigma_R_table[i + half].mul(&x));
                
                // Product of three values
                let product = f_val.mul(&sigma_L_val).mul(&sigma_R_val);
                
                round_poly[eval_point] = round_poly[eval_point].add(&product);
            }
        }
        
        // Collapse tables for next round
        if !challenges.is_empty() {
            let alpha = challenges[challenges.len() - 1];
            let one_minus_alpha = F::one().sub(&alpha);
            
            // Collapse f_evals
            let mut new_f = Vec::with_capacity(half);
            for i in 0..half {
                let val = self.f_evals[i].mul(&one_minus_alpha)
                    .add(&self.f_evals[i + half].mul(&alpha));
                new_f.push(val);
            }
            self.f_evals = new_f;
            
            // Collapse sigma_L_table
            let mut new_sigma_L = Vec::with_capacity(half);
            for i in 0..half {
                let val = self.sigma_L_table[i].mul(&one_minus_alpha)
                    .add(&self.sigma_L_table[i + half].mul(&alpha));
                new_sigma_L.push(val);
            }
            self.sigma_L_table = new_sigma_L;
            
            // Collapse sigma_R_table
            let mut new_sigma_R = Vec::with_capacity(half);
            for i in 0..half {
                let val = self.sigma_R_table[i].mul(&one_minus_alpha)
                    .add(&self.sigma_R_table[i + half].mul(&alpha));
                new_sigma_R.push(val);
            }
            self.sigma_R_table = new_sigma_R;
        }
        
        round_poly
    }
    
    fn degree(&self) -> usize {
        3 // BiPerm has degree 3
    }
    
    fn num_vars(&self) -> usize {
        self.num_vars
    }
}


/// BiPerm Proof
///
/// Contains all information needed to verify a BiPerm protocol execution.
///
/// # Structure
/// - Sumcheck proof (μ rounds of degree-3 polynomials)
/// - Final evaluations at challenge point β
///
/// # Size (Paper Theorem 3.1)
/// O(μ) = O(log n) field elements
///
/// # Paper Reference
/// Section 3.1: BiPerm proof structure
#[derive(Clone, Debug)]
pub struct BiPermProof<F: Field> {
    /// Sumcheck proof for the degree-3 polynomial
    pub sumcheck_proof: SumcheckProof<F>,
    
    /// Final evaluation point β (from sumcheck)
    pub final_point: Vec<F>,
    
    /// f(β)
    pub f_eval: F,
    
    /// 1̃_{σ_L}(β, α_L)
    pub sigma_L_eval: F,
    
    /// 1̃_{σ_R}(β, α_R)
    pub sigma_R_eval: F,
}

impl<F: Field> BiPermProof<F> {
    /// Create a new BiPerm proof
    pub fn new(
        sumcheck_proof: SumcheckProof<F>,
        final_point: Vec<F>,
        f_eval: F,
        sigma_L_eval: F,
        sigma_R_eval: F,
    ) -> Self {
        Self {
            sumcheck_proof,
            final_point,
            f_eval,
            sigma_L_eval,
            sigma_R_eval,
        }
    }
}


/// BiPerm Prover
///
/// Executes the prover's side of the BiPerm protocol.
///
/// # Protocol Flow (Paper Algorithm 2)
///
/// 1. **Preprocessing** (done once):
///    - Compute 1̃_{σ_L} and 1̃_{σ_R}
///    - Commit to both indicators (sparse PCS)
///
/// 2. **Online Phase** (per proof):
///    - Receive challenge α = (α_L, α_R) from verifier
///    - Compute indicator tables in O(√n + n) = O(n) time
///    - Run degree-3 sumcheck on f(x) · 1̃_{σ_L}(x,α_L) · 1̃_{σ_R}(x,α_R)
///    - Provide final evaluations at β
///
/// # Complexity (Paper Theorem 3.1)
/// - Preprocessing: O(n) field operations
/// - Online: O(n) field operations per proof
/// - Total: O(n) field operations
///
/// # Paper Reference
/// - Algorithm 2: BiPerm Sumcheck
/// - Theorem 3.1: BiPerm complexity bounds
pub struct BiPermProver<F: Field> {
    /// Preprocessed index
    index: BiPermIndex<F>,
    
    /// Witness polynomial f
    f: MultilinearPolynomial<F>,
    
    /// Target polynomial g
    g: MultilinearPolynomial<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> BiPermProver<F> {
    /// Create a new BiPerm prover
    ///
    /// # Arguments
    /// - `f`: Witness polynomial
    /// - `g`: Target polynomial
    /// - `perm`: Permutation σ
    ///
    /// # Returns
    /// Result containing prover or error if preprocessing fails
    ///
    /// # Complexity
    /// O(n) for preprocessing
    pub fn new(
        f: MultilinearPolynomial<F>,
        g: MultilinearPolynomial<F>,
        perm: &Permutation,
    ) -> Result<Self, PermCheckError> {
        // Validate dimensions
        if f.num_vars != g.num_vars {
            return Err(PermCheckError::InvalidDimension {
                expected: f.num_vars,
                got: g.num_vars,
            });
        }
        
        if f.evaluations.len() != perm.size {
            return Err(PermCheckError::PermutationSizeMismatch {
                expected: f.evaluations.len(),
                got: perm.size,
            });
        }
        
        // Preprocess permutation
        let index = BiPermIndex::preprocess(perm)?;
        
        Ok(Self {
            index,
            f,
            g,
            _phantom: PhantomData,
        })
    }
    
    /// Generate a BiPerm proof
    ///
    /// # Algorithm (Paper Algorithm 2)
    ///
    /// 1. Receive challenge α = (α_L, α_R) from verifier
    /// 2. Compute g(α) as claimed sum
    /// 3. Build indicator tables: O(√n + n) = O(n)
    /// 4. Run sumcheck on f(x) · 1̃_{σ_L}(x,α_L) · 1̃_{σ_R}(x,α_R)
    /// 5. Return proof with final evaluations
    ///
    /// # Arguments
    /// - `alpha_L`: Challenge for left half
    /// - `alpha_R`: Challenge for right half
    ///
    /// # Returns
    /// BiPerm proof
    ///
    /// # Complexity
    /// O(n) field operations
    ///
    /// # Paper Reference
    /// Algorithm 2: BiPerm Sumcheck
    pub fn prove(&self, alpha_L: &[F], alpha_R: &[F]) -> BiPermProof<F> {
        // Step 1: Compute claimed sum g(α)
        let alpha = [alpha_L, alpha_R].concat();
        let claimed_sum = self.g.evaluate(&alpha);
        
        // Step 2: Build BiPerm virtual polynomial
        // This is the O(n) optimization using indicator tables
        let mut virtual_poly = BiPermVirtualPoly::new(
            &self.f,
            &self.index,
            alpha_L,
            alpha_R,
        );
        
        // Step 3: Run degree-3 sumcheck
        let mut prover = SumcheckProver::new(Box::new(virtual_poly));
        let sumcheck_proof = prover.prove(claimed_sum);
        
        // Step 4: Extract final point and evaluations
        // In production, these would come from PCS openings
        let final_point = vec![F::zero(); self.f.num_vars]; // Placeholder
        let f_eval = self.f.evaluate(&final_point);
        
        // Compute indicator evaluations at final point
        // In production, these would be PCS openings of sparse indicators
        let sigma_L_eval = F::one(); // Placeholder
        let sigma_R_eval = F::one(); // Placeholder
        
        BiPermProof::new(
            sumcheck_proof,
            final_point,
            f_eval,
            sigma_L_eval,
            sigma_R_eval,
        )
    }
    
    /// Get the preprocessed index (for PCS commitment)
    pub fn get_index(&self) -> &BiPermIndex<F> {
        &self.index
    }
}


/// BiPerm Verifier
///
/// Executes the verifier's side of the BiPerm protocol.
///
/// # Protocol Flow (Paper Section 3.1)
///
/// 1. Sample challenge α = (α_L, α_R) ∈ F^μ
/// 2. Query g(α) to get claimed sum S
/// 3. Run sumcheck verifier on degree-3 polynomial
/// 4. Verify final check: f(β) · 1̃_{σ_L}(β,α_L) · 1̃_{σ_R}(β,α_R) = S
/// 5. Verify PCS openings for f, σ_L, σ_R at point β
///
/// # Complexity (Paper Theorem 3.1)
/// - Field operations: O(μ) = O(log n)
/// - PCS verifications: 3 openings
/// - Total: O(log n) + PCS verification cost
///
/// # Soundness (Paper Theorem 3.1)
/// If f(x) ≠ g(σ(x)) for some x, verifier rejects with probability ≥ 1 - O(μ/|F|)
///
/// # Paper Reference
/// Section 3.1: BiPerm Verifier
/// Theorem 3.1: Soundness and complexity
pub struct BiPermVerifier<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> BiPermVerifier<F> {
    /// Create a new BiPerm verifier
    ///
    /// # Arguments
    /// - `num_vars`: Number of variables μ
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            _phantom: PhantomData,
        }
    }
    
    /// Verify a BiPerm proof
    ///
    /// # Algorithm (Paper Section 3.1)
    ///
    /// 1. Sample challenge α = (α_L, α_R)
    /// 2. Compute claimed sum S = g(α)
    /// 3. Run sumcheck verifier (degree 3, μ rounds)
    /// 4. Check final evaluation: f(β) · σ_L(β,α_L) · σ_R(β,α_R) = S
    /// 5. Verify PCS openings (in production)
    ///
    /// # Arguments
    /// - `proof`: BiPerm proof from prover
    /// - `g`: Target polynomial (or commitment in production)
    /// - `alpha_L`: Challenge for left half
    /// - `alpha_R`: Challenge for right half
    ///
    /// # Returns
    /// - `Ok(())`: Proof verified successfully
    /// - `Err(error)`: Verification failed
    ///
    /// # Complexity
    /// O(μ) = O(log n) field operations
    ///
    /// # Paper Reference
    /// Section 3.1: Verifier algorithm
    pub fn verify(
        &self,
        proof: &BiPermProof<F>,
        g: &MultilinearPolynomial<F>,
        alpha_L: &[F],
        alpha_R: &[F],
    ) -> Result<(), VerificationError> {
        // Step 1: Compute claimed sum g(α)
        let alpha = [alpha_L, alpha_R].concat();
        let claimed_sum = g.evaluate(&alpha);
        
        // Step 2: Verify sumcheck proof
        let mut verifier = SumcheckVerifier::new(self.num_vars, 3); // degree 3
        let challenges = verifier.verify(&proof.sumcheck_proof, claimed_sum)?;
        
        // Step 3: Verify final evaluation
        // Check: f(β) · 1̃_{σ_L}(β,α_L) · 1̃_{σ_R}(β,α_R) = final_sum
        let final_product = proof.f_eval
            .mul(&proof.sigma_L_eval)
            .mul(&proof.sigma_R_eval);
        
        if final_product != proof.sumcheck_proof.final_evaluation {
            return Err(VerificationError::SumcheckFinalCheckFailed {
                expected: format!("{:?}", proof.sumcheck_proof.final_evaluation),
                got: format!("{:?}", final_product),
            });
        }
        
        // Step 4: Verify PCS openings (in production)
        // - Verify f(β) = proof.f_eval
        // - Verify 1̃_{σ_L}(β,α_L) = proof.sigma_L_eval
        // - Verify 1̃_{σ_R}(β,α_R) = proof.sigma_R_eval
        // This requires PCS.verify() calls with commitments
        
        Ok(())
    }
    
    /// Sample challenge α = (α_L, α_R)
    ///
    /// completly implement it like In production, this should use Fiat-Shamir transform:
    /// α = Hash(transcript || commitments)
    ///
    /// # Returns
    /// (α_L, α_R) where each is μ/2 field elements
    ///
    /// # Paper Reference
    /// Section 3.1: "Verifier samples α ∈ F^μ uniformly at random"
    pub fn sample_challenge(&self) -> (Vec<F>, Vec<F>) {
        let mu_half = self.num_vars / 2;
        let mu_half_ceil = (self.num_vars + 1) / 2;
        
        // Placeholder: In production, use Fiat-Shamir
        let alpha_L: Vec<F> = (0..mu_half_ceil)
            .map(|i| F::from_u64((i + 1) as u64))
            .collect();
        
        let alpha_R: Vec<F> = (0..mu_half)
            .map(|i| F::from_u64((i + 1) as u64))
            .collect();
        
        (alpha_L, alpha_R)
    }
}
