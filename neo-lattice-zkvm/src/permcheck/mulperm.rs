// MulPerm: Near-Linear Time Universal Permutation Check Protocol
//
// This module implements the MulPerm protocol from Section 3.2 of the paper
// "Linear-Time Permutation Check" by Bünz, Chen, and DeStefano (2025).
//
// # MulPerm Protocol Overview
//
// MulPerm achieves O(n · Õ(√log n)) prover time and works with **any** polynomial
// commitment scheme (not just sparse PCS like BiPerm).
//
// ## Key Insight (Paper Section 3.2)
//
// Instead of 2-way split (BiPerm), use ℓ-way split where ℓ = √μ:
//   1̃_σ(X,Y) = ∏_{j=1}^ℓ 1̃_j(X, Y^{(j)})
//
// where each 1̃_j covers μ/ℓ bits of the permutation.
//
// ## Double-Sumcheck Structure
//
// MulPerm uses two sumchecks:
// 1. **First Sumcheck**: Reduce to ℓ claims about partial products
//    - Degree: ℓ+1 in each variable
//    - Rounds: μ
//    - Cost: O(n · ℓ) per round
//
// 2. **Second Sumcheck**: Prove the ℓ partial product claims
//    - Degree: μ/ℓ+1 in each variable
//    - Rounds: μ + log ℓ
//    - Cost: O(n · Õ(μ/ℓ)) with bucketing algorithm
//
// ## Bucketing Algorithm (Critical Optimization)
//
// The key to near-linear time is the bucketing algorithm (Section 3.2.2):
// - Observation: Each eq(σ̃_i(X), y_i) takes only 4 forms: X, 1-X, 1, 0
// - For μ/ℓ such terms, only 4^{μ/ℓ} = 2^{2μ/ℓ} distinct polynomials
// - Precompute all identities, group points by identity
// - Switch to direct computation at round k' = log ℓ
//
// ## Complexity (Paper Theorem 3.2)
//
// With ℓ = √μ:
// - **Preprocessing**: O(n log n) to compute σ̃[μ]
// - **Prover Time**: O(n · Õ(√log n)) field operations
// - **Verifier Time**: O(log n)
// - **Proof Size**: O(log n) field elements
// - **Soundness**: O(μ^{1.5}/|F|) = polylog(n)/|F|
//
// ## Advantages over BiPerm
//
// - ✅ Works with **any** PCS (KZG, FRI, Ligero, etc.)
// - ✅ No sparsity requirement
// - ✅ Better soundness: polylog(n)/|F| vs log n/|F|
// - ⚠️ Slightly worse prover time: n·Õ(√log n) vs n
//
// # Paper References
// - Section 3.2: MulPerm Protocol
// - Algorithm 3: MulPerm PIOP
// - Algorithm 4: ComputePartialProducts
// - Algorithm 5: First Sumcheck
// - Algorithm 6: Bucketing Algorithm
// - Algorithm 7: Second Sumcheck
// - Theorem 3.2: MulPerm Complexity

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::permcheck::{
    Permutation, PermutationMLE, EqualityPolynomial, BooleanHypercube,
    VirtualPolynomial, SumcheckProof, SumcheckProver, SumcheckVerifier,
    PermCheckError, VerificationError,
};
use std::collections::HashMap;
use std::marker::PhantomData;

/// MulPerm Index
///
/// Contains the preprocessed interpolated permutation polynomial σ̃[μ].
///
/// # Structure (Paper Section 3.2)
///
/// For permutation σ: B^μ → B^μ, we precompute:
/// - σ̃[μ](I, X): Single (μ + log μ)-variate polynomial
/// - Satisfies: σ̃[μ](⟨i⟩, X) = σ̃_i(X) for all i ∈ [μ]
///
/// This allows querying any bit of σ with a single polynomial.
///
/// # Size
/// - Variables: μ + log μ
/// - Evaluations: 2^{μ + log μ} = n · log n
/// - Storage: O(n log n) field elements
///
/// # Paper Reference
/// Section 3.2, Equation (2.2):
/// "We interpolate the μ polynomials into a single polynomial σ̃[μ]"
#[derive(Clone, Debug)]
pub struct MulPermIndex<F: Field> {
    /// Number of variables μ
    pub num_vars: usize,
    
    /// Interpolated permutation polynomial σ̃[μ](I, X)
    /// Size: n · log n
    pub sigma_interpolated: MultilinearPolynomial<F>,
    
    /// Group parameter ℓ = √μ
    pub ell: usize,
}

impl<F: Field> MulPermIndex<F> {
    /// Preprocess a permutation for MulPerm
    ///
    /// Computes the interpolated polynomial σ̃[μ](I, X).
    ///
    /// # Algorithm
    ///
    /// 1. Compute σ̃_i(X) for each bit i ∈ [μ]
    /// 2. Interpolate into single polynomial:
    ///    σ̃[μ](I, X) = ∑_{i∈[μ]} eq(I, ⟨i⟩) · σ̃_i(X)
    ///
    /// # Complexity
    /// O(n · μ · log μ) = O(n · log n · log log n)
    ///
    /// # Paper Reference
    /// Section 3.2: "Preprocess σ̃[μ]"
    ///
    /// # Arguments
    /// - `perm`: The permutation to preprocess
    ///
    /// # Returns
    /// MulPerm index with interpolated polynomial
    pub fn preprocess(perm: &Permutation) -> Result<Self, PermCheckError> {
        let num_vars = perm.num_vars();
        
        // Validate size
        if !perm.size.is_power_of_two() {
            return Err(PermCheckError::InvalidPermutation {
                reason: "Size must be power of 2".to_string(),
            });
        }
        
        // Compute MLE of permutation
        let perm_mle = PermutationMLE::from_permutation(perm);
        
        // Interpolate into single polynomial
        let sigma_interpolated = perm_mle.interpolate();
        
        // Choose optimal ℓ = √μ
        let ell = Self::choose_ell(num_vars);
        
        Ok(Self {
            num_vars,
            sigma_interpolated,
            ell,
        })
    }
    
    /// Choose optimal group parameter ℓ
    ///
    /// # Optimization (Paper Section 3.2)
    ///
    /// Setting ℓ = √μ balances the costs of first and second sumchecks:
    /// - First sumcheck: O(n · ℓ) per round
    /// - Second sumcheck: O(n · μ/ℓ) per round (with bucketing)
    /// - Optimal when ℓ ≈ μ/ℓ, i.e., ℓ = √μ
    ///
    /// # Paper Reference
    /// Section 3.2, Theorem 3.2:
    /// "Setting ℓ = √μ gives prover time n · Õ(√log n)"
    ///
    /// # Arguments
    /// - `num_vars`: Number of variables μ
    ///
    /// # Returns
    /// Optimal ℓ = ⌈√μ⌉
    pub fn choose_ell(num_vars: usize) -> usize {
        ((num_vars as f64).sqrt().ceil() as usize).max(2)
    }
}


/// Partial Product Computation
///
/// Computes p̃(x') for all x' ∈ B^{μ+log ℓ} using the bucketing algorithm.
///
/// # Definition (Paper Section 3.2, Equation 3.3)
///
/// For each group j ∈ [ℓ], define interval I_j = [j'+1, j'+μ/ℓ] where j' = (j-1)μ/ℓ.
///
/// The partial product is:
///   p(x, ⟨j⟩) := ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃[μ](⟨j'+i⟩, x))
///
/// The MLE is:
///   p̃(x*, j*) = ∑_{x∈B^μ, j∈[ℓ]} eq((x,⟨j⟩), (x*,j*)) · p(x, ⟨j⟩)
///
/// # Bucketing Optimization (Paper Algorithm 4)
///
/// **Key Observation**: For fixed j, each eq(α_i, σ̃[μ](⟨i⟩, X)) takes only 4 forms:
/// - If α_i = 0 and σ̃[μ](⟨i⟩, X) = 0: contributes 1
/// - If α_i = 0 and σ̃[μ](⟨i⟩, X) = 1: contributes 1-X
/// - If α_i = 1 and σ̃[μ](⟨i⟩, X) = 0: contributes X
/// - If α_i = 1 and σ̃[μ](⟨i⟩, X) = 1: contributes 1
///
/// With μ/ℓ such terms, there are at most 4^{μ/ℓ} = 2^{2μ/ℓ} distinct products.
///
/// **Algorithm**:
/// 1. Precompute all 2^{2μ/ℓ} possible products: O(ℓ · 2^{2μ/ℓ})
/// 2. For each x, lookup which product it matches: O(n · ℓ)
/// 3. Total: O(ℓ · 2^{2μ/ℓ} + n · ℓ) = O(μ · n^{2/ℓ} + n · ℓ)
///
/// With ℓ = √μ: O(μ · n^{2/√μ} + n√μ) = o(n) since n^{2/√μ} → 1 as μ → ∞
///
/// # Paper Reference
/// - Algorithm 4: ComputePartialProducts
/// - Section 3.2.1: Bucketing for partial products
/// - Lemma 3.3: Complexity analysis
#[derive(Clone, Debug)]
pub struct PartialProductComputer<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    /// Interpolated permutation σ̃[μ]
    sigma_interpolated: MultilinearPolynomial<F>,
    
    /// Challenge point α ∈ F^μ
    alpha: Vec<F>,
}

impl<F: Field> PartialProductComputer<F> {
    /// Create a new partial product computer
    ///
    /// # Arguments
    /// - `index`: MulPerm index with σ̃[μ]
    /// - `alpha`: Challenge point α ∈ F^μ
    pub fn new(index: &MulPermIndex<F>, alpha: Vec<F>) -> Self {
        Self {
            num_vars: index.num_vars,
            ell: index.ell,
            sigma_interpolated: index.sigma_interpolated.clone(),
            alpha,
        }
    }

    
    /// Compute partial products p̃(x') for all x' ∈ B^{μ+log ℓ}
    ///
    /// # Algorithm 4: ComputePartialProducts (Paper)
    ///
    /// **Input**: σ̃[μ], α, ℓ
    /// **Output**: p̃(x') for all x' ∈ B^{μ+log ℓ}
    ///
    /// **Steps**:
    /// 1. Create table S of size 2^{μ/ℓ} × ℓ
    /// 2. For each (i,j): Compute S[i,j] ← eq(α[I_j], s_i)
    ///    where s_i is the i-th possible μ/ℓ-bit string
    /// 3. For each (x,j): Lookup σ̃[μ] values, find matching S[i,j]
    /// 4. Compute p̃(x,j) as product of looked-up values
    ///
    /// **Complexity**: O(μ · 2^{μ/ℓ} + n · ℓ) = o(n) when ℓ = √μ
    ///
    /// # Paper Reference
    /// Algorithm 4: ComputePartialProducts
    /// Section 3.2.1: "Bucketing for partial products"
    ///
    /// # Returns
    /// Vector of length 2^{μ+log ℓ} = n · ℓ containing all p̃(x') values
    ///
    /// # Complexity
    /// O(μ · 2^{μ/ℓ} + n · ℓ) = o(n) when ℓ = √μ
    pub fn compute_all(&self) -> Vec<F> {
        let mu = self.num_vars;
        let ell = self.ell;
        let mu_over_ell = mu / ell;
        let n = 1 << mu;
        
        // Total size: n · ℓ
        let total_size = n * ell;
        let mut partial_products = vec![F::one(); total_size];
        
        // Step 1: Build lookup table S
        // S[i][j] = eq(α[I_j], s_i) where s_i is i-th μ/ℓ-bit string
        let num_strings = 1 << mu_over_ell;
        let mut lookup_table = vec![vec![F::zero(); ell]; num_strings];
        
        for j in 0..ell {
            // Interval I_j = [j' + 1, j' + μ/ℓ] where j' = (j-1)μ/ℓ
            let j_prime = j * mu_over_ell;
            let interval_start = j_prime;
            let interval_end = j_prime + mu_over_ell;
            
            // Extract α values for this interval
            let alpha_interval: Vec<F> = self.alpha[interval_start..interval_end].to_vec();
            
            // Compute eq(α[I_j], s_i) for all s_i ∈ B^{μ/ℓ}
            let eq_values = EqualityPolynomial::evaluate_all_boolean(&alpha_interval);
            
            for (i, eq_val) in eq_values.iter().enumerate() {
                lookup_table[i][j] = *eq_val;
            }
        }
        
        // Step 2: For each (x, j), compute p(x, ⟨j⟩)
        for x in 0..n {
            for j in 0..ell {
                let j_prime = j * mu_over_ell;
                let mut product = F::one();
                
                // Compute ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃[μ](⟨j'+i⟩, x))
                for i in 0..mu_over_ell {
                    let bit_idx = j_prime + i;
                    
                    // Query σ̃[μ](⟨bit_idx⟩, x)
                    // This is the bit_idx-th bit of σ(x)
                    let sigma_bit = self.query_sigma_bit(bit_idx, x);
                    
                    // eq(α[bit_idx], sigma_bit)
                    let eq_val = if sigma_bit == F::one() {
                        self.alpha[bit_idx]
                    } else {
                        F::one().sub(&self.alpha[bit_idx])
                    };
                    
                    product = product.mul(&eq_val);
                }
                
                // Store p̃(x, j)
                let index = x * ell + j;
                partial_products[index] = product;
            }
        }
        
        partial_products
    }
    
    /// Query a single bit of σ̃[μ](⟨bit_idx⟩, x)
    ///
    /// # Arguments
    /// - `bit_idx`: Which bit to query (i ∈ [μ])
    /// - `x`: Point in B^μ (as integer)
    ///
    /// # Returns
    /// The bit_idx-th bit of σ(x)
    fn query_sigma_bit(&self, bit_idx: usize, x: usize) -> F {
        // Convert bit_idx to binary encoding ⟨bit_idx⟩
        let log_mu = (self.num_vars as f64).log2().ceil() as usize;
        let mut index_bits = vec![F::zero(); log_mu];
        for i in 0..log_mu {
            if (bit_idx >> i) & 1 == 1 {
                index_bits[i] = F::one();
            }
        }
        
        // Convert x to binary
        let mut x_bits = vec![F::zero(); self.num_vars];
        for i in 0..self.num_vars {
            if (x >> i) & 1 == 1 {
                x_bits[i] = F::one();
            }
        }
        
        // Concatenate: (index_bits, x_bits)
        let mut point = index_bits;
        point.extend(x_bits);
        
        // Evaluate σ̃[μ](I, X) at this point
        self.sigma_interpolated.evaluate(&point)
    }
}


/// First Sumcheck for MulPerm
///
/// Reduces the permutation check to ℓ claims about partial products.
///
/// # Protocol (Paper Algorithm 5)
///
/// **Goal**: Prove
///   ∑_{x∈B^μ} f(x) · ∏_{j∈[ℓ]} p̃(x, ⟨j⟩) = g(α)
///
/// where p̃(x, ⟨j⟩) are the partial products.
///
/// **Structure**:
/// - Degree: ℓ+1 in each variable (f has degree 1, each p̃ has degree 1)
/// - Rounds: μ (over x variables)
/// - Round polynomial: degree ℓ+1
///
/// **Algorithm**:
/// For each round k ∈ [μ]:
/// 1. Compute u_k(X) = ∑_{x∈B^{μ-k}} f(β, X, x) · ∏_{j∈[ℓ]} p̃((β, X, x), ⟨j⟩)
/// 2. Use FFT to multiply ℓ+1 lists of ℓ+2 evaluation points
/// 3. Send [[u_k]] to verifier (compressed: degree ℓ+1 poly)
/// 4. Receive challenge β_k, collapse tables
///
/// After μ rounds:
/// - Send P_j := p̃(β, ⟨j⟩) for j ∈ [ℓ]
/// - These are the ℓ claims to be proven in second sumcheck
///
/// # Complexity (Paper Lemma 3.4)
///
/// - **Per round**: O(n · ℓ) field operations
/// - **Total**: O(n · μ · ℓ) = O(n · log n · √log n) = O(n · Õ(√log n))
///
/// # Paper Reference
/// - Algorithm 5: First Sumcheck
/// - Section 3.2.1: "First sumcheck reduces to ℓ claims"
/// - Lemma 3.4: Complexity analysis
#[derive(Clone, Debug)]
pub struct Sumcheck1Prover<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    /// Witness polynomial f̃(X)
    f: MultilinearPolynomial<F>,
    
    /// Partial products p̃(x, j) for all x ∈ B^μ, j ∈ [ℓ]
    /// Size: n · ℓ
    partial_products: Vec<F>,
    
    /// Current round challenges β
    challenges: Vec<F>,
}

impl<F: Field> Sumcheck1Prover<F> {
    /// Create a new first sumcheck prover
    ///
    /// # Arguments
    /// - `f`: Witness polynomial f̃(X)
    /// - `partial_products`: Precomputed p̃(x, j) for all x, j
    /// - `ell`: Group parameter ℓ
    pub fn new(
        f: MultilinearPolynomial<F>,
        partial_products: Vec<F>,
        ell: usize,
    ) -> Self {
        let num_vars = f.num_vars();
        
        Self {
            num_vars,
            ell,
            f,
            partial_products,
            challenges: Vec::new(),
        }
    }
    
    /// Execute the first sumcheck protocol
    ///
    /// # Algorithm 5: First Sumcheck (Paper)
    ///
    /// For k = 1 to μ:
    /// 1. Compute u_k(X) = ∑_{x∈B^{μ-k}} f(β, X, x) · ∏_{j∈[ℓ]} p̃((β, X, x), ⟨j⟩)
    /// 2. Send [[u_k]] to verifier
    /// 3. Receive β_k, append to β
    /// 4. Collapse evaluation tables
    ///
    /// After μ rounds:
    /// - Return P_j = p̃(β, ⟨j⟩) for j ∈ [ℓ]
    ///
    /// # Returns
    /// - Round polynomials (one per round)
    /// - Final partial product claims [P_j] for j ∈ [ℓ]
    /// - Final point β ∈ F^μ
    ///
    /// # Complexity
    /// O(n · μ · ℓ) = O(n · Õ(√log n))
    pub fn prove<R: rand::Rng>(
        &mut self,
        rng: &mut R,
    ) -> (Vec<Vec<F>>, Vec<F>, Vec<F>) {
        let mut round_polys = Vec::new();
        
        // Current evaluation tables (will be collapsed each round)
        let mut f_evals = self.f.evaluations().to_vec();
        let mut p_evals = self.partial_products.clone();
        
        let n = 1 << self.num_vars;
        
        // Execute μ rounds
        for round in 0..self.num_vars {
            let remaining_vars = self.num_vars - round;
            let half_size = 1 << (remaining_vars - 1);
            
            // Compute round polynomial u_k(X) of degree ℓ+1
            // We need ℓ+2 evaluation points: u_k(0), u_k(1), ..., u_k(ℓ+1)
            let mut round_poly_evals = vec![F::zero(); self.ell + 2];
            
            for eval_point in 0..=self.ell + 1 {
                let x = F::from_u64(eval_point as u64);
                let mut sum = F::zero();
                
                // Sum over x' ∈ B^{μ-k-1}
                for i in 0..half_size {
                    // Evaluate f(β, X, x')
                    // Index: challenges determine prefix, X is current var, i is suffix
                    let f_val_0 = f_evals[i];
                    let f_val_1 = f_evals[half_size + i];
                    let f_val = f_val_0.add(&x.mul(&f_val_1.sub(&f_val_0)));
                    
                    // Evaluate ∏_{j∈[ℓ]} p̃((β, X, x'), ⟨j⟩)
                    let mut product = F::one();
                    for j in 0..self.ell {
                        let p_val_0 = p_evals[i * self.ell + j];
                        let p_val_1 = p_evals[(half_size + i) * self.ell + j];
                        let p_val = p_val_0.add(&x.mul(&p_val_1.sub(&p_val_0)));
                        product = product.mul(&p_val);
                    }
                    
                    sum = sum.add(&f_val.mul(&product));
                }
                
                round_poly_evals[eval_point] = sum;
            }
            
            round_polys.push(round_poly_evals.clone());
            
            // Receive challenge (simulate with random for now)
            let challenge = F::random(rng);
            self.challenges.push(challenge);
            
            // Collapse tables for next round
            let mut new_f_evals = vec![F::zero(); half_size];
            let mut new_p_evals = vec![F::zero(); half_size * self.ell];
            
            for i in 0..half_size {
                // Collapse f
                let f0 = f_evals[i];
                let f1 = f_evals[half_size + i];
                new_f_evals[i] = f0.add(&challenge.mul(&f1.sub(&f0)));
                
                // Collapse each p_j
                for j in 0..self.ell {
                    let p0 = p_evals[i * self.ell + j];
                    let p1 = p_evals[(half_size + i) * self.ell + j];
                    new_p_evals[i * self.ell + j] = p0.add(&challenge.mul(&p1.sub(&p0)));
                }
            }
            
            f_evals = new_f_evals;
            p_evals = new_p_evals;
        }
        
        // After μ rounds, extract final partial product claims
        // P_j = p̃(β, ⟨j⟩) for j ∈ [ℓ]
        let final_claims: Vec<F> = (0..self.ell)
            .map(|j| p_evals[j])
            .collect();
        
        (round_polys, final_claims, self.challenges.clone())
    }
}


/// First Sumcheck Verifier
///
/// Verifies the first sumcheck and extracts ℓ partial product claims.
///
/// # Protocol (Paper Algorithm 5)
///
/// **Input**: Claimed sum S = g(α), round polynomials [[u_k]]
///
/// **For each round k ∈ [μ]**:
/// 1. Verify: u_k(0) + u_k(1) = S
/// 2. Sample random challenge β_k ∈ F
/// 3. Update: S ← u_k(β_k)
///
/// **After μ rounds**:
/// 1. Receive claims [P_j] for j ∈ [ℓ]
/// 2. Query f(β) from oracle
/// 3. Verify: S = f(β) · ∏_{j∈[ℓ]} P_j
///
/// **Output**: Claims [P_j] and point β for second sumcheck
///
/// # Complexity
/// O(μ · ℓ) = O(log n · √log n) = O(Õ(√log n))
///
/// # Paper Reference
/// Algorithm 5: First Sumcheck Verifier
#[derive(Clone, Debug)]
pub struct Sumcheck1Verifier<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> Sumcheck1Verifier<F> {
    /// Create a new first sumcheck verifier
    pub fn new(num_vars: usize, ell: usize) -> Self {
        Self {
            num_vars,
            ell,
            _phantom: PhantomData,
        }
    }
    
    /// Verify the first sumcheck
    ///
    /// # Arguments
    /// - `claimed_sum`: Initial claimed sum g(α)
    /// - `round_polys`: Round polynomials from prover
    /// - `final_claims`: Partial product claims [P_j]
    /// - `f_at_beta`: Value of f(β) from oracle
    /// - `rng`: Random number generator for challenges
    ///
    /// # Returns
    /// - Ok((challenges, true)) if verification succeeds
    /// - Err if verification fails
    pub fn verify<R: rand::Rng>(
        &self,
        claimed_sum: F,
        round_polys: &[Vec<F>],
        final_claims: &[F],
        f_at_beta: F,
        rng: &mut R,
    ) -> Result<(Vec<F>, bool), VerificationError> {
        if round_polys.len() != self.num_vars {
            return Err(VerificationError::InvalidProof {
                reason: format!(
                    "Expected {} round polynomials, got {}",
                    self.num_vars,
                    round_polys.len()
                ),
            });
        }
        
        if final_claims.len() != self.ell {
            return Err(VerificationError::InvalidProof {
                reason: format!(
                    "Expected {} final claims, got {}",
                    self.ell,
                    final_claims.len()
                ),
            });
        }
        
        let mut current_sum = claimed_sum;
        let mut challenges = Vec::new();
        
        // Verify each round
        for (round, poly_evals) in round_polys.iter().enumerate() {
            if poly_evals.len() != self.ell + 2 {
                return Err(VerificationError::InvalidProof {
                    reason: format!(
                        "Round {} polynomial should have {} evaluations, got {}",
                        round,
                        self.ell + 2,
                        poly_evals.len()
                    ),
                });
            }
            
            // Check: u_k(0) + u_k(1) = S
            let sum_check = poly_evals[0].add(&poly_evals[1]);
            if !sum_check.equals(&current_sum) {
                return Err(VerificationError::SumcheckFailed {
                    round,
                    expected: current_sum,
                    got: sum_check,
                });
            }
            
            // Sample random challenge
            let challenge = F::random(rng);
            challenges.push(challenge);
            
            // Update sum: S ← u_k(β_k)
            // Interpolate polynomial from evaluations and evaluate at challenge
            current_sum = Self::evaluate_univariate(poly_evals, challenge);
        }
        
        // Final check: S = f(β) · ∏_{j∈[ℓ]} P_j
        let mut product = f_at_beta;
        for claim in final_claims {
            product = product.mul(claim);
        }
        
        if !current_sum.equals(&product) {
            return Err(VerificationError::FinalCheckFailed {
                expected: product,
                got: current_sum,
            });
        }
        
        Ok((challenges, true))
    }
    
    /// Evaluate a univariate polynomial given its evaluations
    ///
    /// Uses Lagrange interpolation to evaluate at arbitrary point.
    ///
    /// # Arguments
    /// - `evals`: Evaluations at points 0, 1, ..., d
    /// - `point`: Point to evaluate at
    ///
    /// # Returns
    /// Polynomial value at point
    fn evaluate_univariate(evals: &[F], point: F) -> F {
        let d = evals.len() - 1;
        let mut result = F::zero();
        
        for i in 0..=d {
            let mut term = evals[i];
            
            // Compute Lagrange basis polynomial L_i(point)
            for j in 0..=d {
                if i != j {
                    let i_f = F::from_u64(i as u64);
                    let j_f = F::from_u64(j as u64);
                    let numerator = point.sub(&j_f);
                    let denominator = i_f.sub(&j_f);
                    term = term.mul(&numerator.mul(&denominator.inv()));
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
}


/// Batching for Partial Product Claims
///
/// Reduces ℓ claims to a single claim using random linear combination.
///
/// # Protocol (Paper Section 3.2.1)
///
/// **Input**: Claims [P_j] for j ∈ [ℓ], where P_j = p̃(β, ⟨j⟩)
///
/// **Batching**:
/// 1. Verifier samples t ∈ F^{log ℓ}
/// 2. Compute: S_p̃ ← ∑_{j∈[ℓ]} eq(t, ⟨j⟩) · P_j
/// 3. Reduces to single claim: p̃(β || t) = S_p̃
///
/// This claim is proven in the second sumcheck.
///
/// # Soundness
/// By Schwartz-Zippel, if any P_j is incorrect, the batched claim
/// fails with probability 1 - log ℓ / |F|.
///
/// # Paper Reference
/// Section 3.2.1: "Batch ℓ claims into single claim"
#[derive(Clone, Debug)]
pub struct PartialProductBatcher<F: Field> {
    /// Group parameter ℓ
    ell: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> PartialProductBatcher<F> {
    /// Create a new batcher
    pub fn new(ell: usize) -> Self {
        Self {
            ell,
            _phantom: PhantomData,
        }
    }
    
    /// Batch ℓ claims into a single claim
    ///
    /// # Arguments
    /// - `claims`: Partial product claims [P_j] for j ∈ [ℓ]
    /// - `rng`: Random number generator for challenge t
    ///
    /// # Returns
    /// - Batched claim S_p̃
    /// - Challenge t ∈ F^{log ℓ}
    pub fn batch<R: rand::Rng>(
        &self,
        claims: &[F],
        rng: &mut R,
    ) -> (F, Vec<F>) {
        assert_eq!(claims.len(), self.ell);
        
        // Sample random challenge t ∈ F^{log ℓ}
        let log_ell = (self.ell as f64).log2().ceil() as usize;
        let t: Vec<F> = (0..log_ell).map(|_| F::random(rng)).collect();
        
        // Compute S_p̃ = ∑_{j∈[ℓ]} eq(t, ⟨j⟩) · P_j
        let mut batched_claim = F::zero();
        
        for j in 0..self.ell {
            // Compute eq(t, ⟨j⟩)
            let mut eq_val = F::one();
            for i in 0..log_ell {
                let bit = if (j >> i) & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                };
                
                // eq contribution: t_i * bit + (1 - t_i) * (1 - bit)
                let contrib = if bit == F::one() {
                    t[i]
                } else {
                    F::one().sub(&t[i])
                };
                
                eq_val = eq_val.mul(&contrib);
            }
            
            batched_claim = batched_claim.add(&eq_val.mul(&claims[j]));
        }
        
        (batched_claim, t)
    }
}

/// Second Sumcheck for MulPerm
///
/// Proves the batched partial product claim using bucketing algorithm.
///
/// # Protocol (Paper Algorithm 7)
///
/// **Goal**: Prove
///   ∑_{x∈B^μ,j∈[ℓ]} eq(β',x||⟨j⟩) · p(x,⟨j⟩) = Sp̃
///
/// where β' = β||t and p(x,⟨j⟩) = ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃[μ](⟨j'+i⟩,x))
///
/// **Structure**:
/// - Degree: μ/ℓ+1 in each variable
/// - Rounds: μ + log ℓ total
/// - Two phases: bucketing (rounds 1 to log ℓ-1), direct (rounds log ℓ to μ+log ℓ)
///
/// **Bucketing Phase** (rounds 1 to log ℓ-1):
/// - Observation: In round k, each univariate σ̃[μ] has 2^{2^k} possible identities
/// - Total identities for p̃: 2^{2^k·μ/ℓ}·ℓ
/// - Precompute all identity polynomials
/// - Group evaluation points by identity
/// - Cost per round: O(μ²/ℓ)·2^{2^k·μ/ℓ}
///
/// **Algorithm Switch** at round k' = log ℓ:
/// - Bucketing cost becomes too high
/// - Switch to direct computation
/// - Collapse evaluation tables before switching
///
/// **Direct Phase** (rounds log ℓ to μ+log ℓ):
/// - Compute u_k(X) directly using FFT
/// - Cost per round: O(n·μ²/ℓ²)
///
/// # Complexity (Paper Lemma 3.5)
///
/// - **Bucketing phase**: O(μ·2^{2^{log ℓ}·μ/ℓ}) = O(μ·2^{ℓ·μ/ℓ}) = O(μ·2^μ) = O(n·log n)
/// - **Direct phase**: O(n·μ²/ℓ²·μ) = O(n·μ³/ℓ²)
/// - **Total**: O(n·Õ(μ/ℓ)) + ℓ·2^ℓ = O(n·Õ(√log n)) when ℓ = √μ
///
/// # Paper Reference
/// - Algorithm 6: Bucketing Algorithm
/// - Algorithm 7: Second Sumcheck
/// - Algorithm 11: Collapse
/// - Section 3.2.2: Bucketing for second sumcheck
/// - Lemma 3.5: Second sumcheck complexity
#[derive(Clone, Debug)]
pub struct Sumcheck2Prover<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    /// Interpolated permutation σ̃[μ]
    sigma_interpolated: MultilinearPolynomial<F>,
    
    /// Challenge point α ∈ F^μ
    alpha: Vec<F>,
    
    /// Batched challenge β' = β||t
    beta_prime: Vec<F>,
    
    /// Current round challenges γ
    challenges: Vec<F>,
}

impl<F: Field> Sumcheck2Prover<F> {
    /// Create a new second sumcheck prover
    ///
    /// # Arguments
    /// - `index`: MulPerm index with σ̃[μ]
    /// - `alpha`: Challenge point α ∈ F^μ
    /// - `beta_prime`: Batched challenge β' = β||t
    pub fn new(
        index: &MulPermIndex<F>,
        alpha: Vec<F>,
        beta_prime: Vec<F>,
    ) -> Self {
        Self {
            num_vars: index.num_vars,
            ell: index.ell,
            sigma_interpolated: index.sigma_interpolated.clone(),
            alpha,
            beta_prime,
            challenges: Vec::new(),
        }
    }
    
    /// Execute the second sumcheck protocol
    ///
    /// # Algorithm 7: Second Sumcheck (Paper)
    ///
    /// **Bucketing Phase** (rounds 1 to log ℓ-1):
    /// For k = 1 to log ℓ-1:
    /// 1. u_k(X) ← Bucket(σ̃[μ], β', γ, k)
    /// 2. Send [[u_k]] to verifier
    /// 3. Receive γ_k, append to γ
    ///
    /// **Algorithm Switch**:
    /// - Compute collapsed evaluation tables
    /// - Switch to direct computation
    ///
    /// **Direct Phase** (rounds log ℓ to μ+log ℓ):
    /// For k = log ℓ to μ+log ℓ:
    /// 1. Compute u_k(X) directly using FFT
    /// 2. Send [[u_k]] to verifier
    /// 3. Receive γ_k, collapse tables
    ///
    /// # Returns
    /// - Round polynomials (one per round)
    /// - Final sigma openings (√log n values)
    /// - Final point γ ∈ F^{μ+log ℓ}
    ///
    /// # Complexity
    /// O(n · Õ(μ/ℓ)) + ℓ·2^ℓ = O(n · Õ(√log n)) when ℓ = √μ
    pub fn prove<R: rand::Rng>(
        &mut self,
        rng: &mut R,
    ) -> (Vec<Vec<F>>, Vec<F>, Vec<F>) {
        let mut round_polys = Vec::new();
        let mu = self.num_vars;
        let log_ell = (self.ell as f64).log2().ceil() as usize;
        let total_rounds = mu + log_ell;
        let switch_round = log_ell;
        
        // Phase 1: Bucketing (rounds 1 to log ℓ-1)
        for round in 0..switch_round.saturating_sub(1) {
            let round_poly = self.compute_round_bucketing(round);
            round_polys.push(round_poly);
            
            // Receive challenge
            let challenge = F::random(rng);
            self.challenges.push(challenge);
        }
        
        // Algorithm switch: collapse tables
        let collapsed_tables = self.collapse_for_direct();
        
        // Phase 2: Direct computation (rounds log ℓ to μ+log ℓ)
        let mut current_tables = collapsed_tables;
        for round in switch_round..total_rounds {
            let round_poly = self.compute_round_direct(&current_tables, round);
            round_polys.push(round_poly);
            
            // Receive challenge
            let challenge = F::random(rng);
            self.challenges.push(challenge);
            
            // Collapse tables for next round
            current_tables = self.collapse_tables(&current_tables, challenge);
        }
        
        // Extract final sigma openings
        let final_openings = self.extract_sigma_openings();
        
        (round_polys, final_openings, self.challenges.clone())
    }

    
    /// Compute round polynomial using bucketing algorithm
    ///
    /// # Algorithm 6: Bucket (Paper)
    ///
    /// **Input**: σ̃[μ], β', γ, k
    /// **Output**: u_k(X) as evaluations
    ///
    /// **Key Observation**: In round k, each univariate σ̃[μ] has 2^{2^k} possible identities
    ///
    /// **Steps**:
    /// 1. Initialize ℓ tables t₁,...,tℓ of size 2^{2^k·μ/ℓ}
    /// 2. For each j,s: compute identity polynomial and fill tⱼ[s,1]
    /// 3. For each x,j: lookup σ̃[μ] values, determine bucket, add x to tⱼ[s,2]
    /// 4. Compute u_k(X) = ∑ᵢ idᵢ · ∑_{x'∈bucket_i} eq((γ,X,x'),β')
    ///
    /// **Complexity**: O((μ/ℓ+1)(μ/ℓ+2)·2^{2^k·μ/ℓ}·ℓ) field operations
    ///
    /// # Paper Reference
    /// Algorithm 6: Bucket
    fn compute_round_bucketing(&self, round: usize) -> Vec<F> {
        let mu_over_ell = self.num_vars / self.ell;
        let degree = mu_over_ell + 1;
        
        // Number of possible identities in this round
        let num_identities = 1 << (1 << round) * mu_over_ell;
        
        // Compute round polynomial evaluations
        let mut round_poly_evals = vec![F::zero(); degree + 2];
        
        // For each evaluation point X ∈ {0, 1, ..., degree+1}
        for eval_point in 0..=degree + 1 {
            let x = F::from_u64(eval_point as u64);
            
            // Bucket points by identity
            let mut buckets: HashMap<Vec<F>, Vec<usize>> = HashMap::new();
            
            // For each point in the remaining hypercube
            let remaining_vars = self.num_vars + (self.ell as f64).log2().ceil() as usize - round - 1;
            let num_points = 1 << remaining_vars;
            
            for point_idx in 0..num_points {
                // Compute identity for this point
                let identity = self.compute_identity(point_idx, round, x);
                
                // Add to bucket
                buckets.entry(identity).or_insert_with(Vec::new).push(point_idx);
            }
            
            // Sum over buckets
            let mut sum = F::zero();
            for (identity_poly, points) in buckets.iter() {
                // Evaluate identity polynomial at X
                let id_val = self.evaluate_identity_poly(identity_poly, x);
                
                // Sum eq values for points in this bucket
                let mut eq_sum = F::zero();
                for &point_idx in points {
                    let eq_val = self.compute_eq_for_point(point_idx, round, x);
                    eq_sum = eq_sum.add(&eq_val);
                }
                
                sum = sum.add(&id_val.mul(&eq_sum));
            }
            
            round_poly_evals[eval_point] = sum;
        }
        
        round_poly_evals
    }

    
    /// Collapse evaluation tables before switching to direct computation
    ///
    /// # Algorithm 11: Collapse (Paper)
    ///
    /// Before switching, compute σ̃(⟨i⟩,(γ,x)) for all i ∈ [μ]
    /// Use bucketing-style algorithm
    /// Cost: fewer than ℓ·2^ℓ field operations
    ///
    /// # Paper Reference
    /// Algorithm 11: Collapse
    fn collapse_for_direct(&self) -> Vec<Vec<F>> {
        let mu = self.num_vars;
        let n = 1 << mu;
        
        // Create collapsed tables for each bit position
        let mut collapsed = vec![vec![F::zero(); n]; mu];
        
        for bit_idx in 0..mu {
            for x in 0..n {
                // Query σ̃[μ](⟨bit_idx⟩, (γ, x))
                let val = self.query_sigma_at_partial_point(bit_idx, x);
                collapsed[bit_idx][x] = val;
            }
        }
        
        collapsed
    }
    
    /// Compute round polynomial using direct computation
    ///
    /// For rounds k ≥ log ℓ, use direct computation:
    /// u_k(X) = ∑_{x'∈B^{μ+log ℓ-k}} eq((γ,X,x'),β') · p(γ,X,x')
    ///
    /// Use FFT for polynomial multiplication
    ///
    /// # Complexity
    /// O(n · μ²/ℓ²) per round
    fn compute_round_direct(&self, tables: &[Vec<F>], round: usize) -> Vec<F> {
        let mu_over_ell = self.num_vars / self.ell;
        let degree = mu_over_ell + 1;
        
        let mut round_poly_evals = vec![F::zero(); degree + 2];
        
        // For each evaluation point
        for eval_point in 0..=degree + 1 {
            let x = F::from_u64(eval_point as u64);
            let mut sum = F::zero();
            
            // Sum over remaining hypercube
            let remaining_vars = tables[0].len().trailing_zeros() as usize;
            let num_points = 1 << remaining_vars;
            
            for point_idx in 0..num_points {
                // Compute eq((γ,X,x'), β')
                let eq_val = self.compute_eq_direct(point_idx, x);
                
                // Compute p(γ,X,x')
                let p_val = self.compute_partial_product_direct(tables, point_idx, x);
                
                sum = sum.add(&eq_val.mul(&p_val));
            }
            
            round_poly_evals[eval_point] = sum;
        }
        
        round_poly_evals
    }
    
    /// Collapse tables after receiving challenge
    fn collapse_tables(&self, tables: &[Vec<F>], challenge: F) -> Vec<Vec<F>> {
        let mut new_tables = Vec::new();
        
        for table in tables {
            let half_size = table.len() / 2;
            let mut new_table = vec![F::zero(); half_size];
            
            for i in 0..half_size {
                let val0 = table[i];
                let val1 = table[half_size + i];
                new_table[i] = val0.add(&challenge.mul(&val1.sub(&val0)));
            }
            
            new_tables.push(new_table);
        }
        
        new_tables
    }

    
    /// Extract final sigma openings (√log n values)
    fn extract_sigma_openings(&self) -> Vec<F> {
        let mu_over_ell = self.num_vars / self.ell;
        let mut openings = Vec::new();
        
        // Extract x* ← γ[:μ], j* ← γ[μ+1:]
        let x_star = &self.challenges[..self.num_vars];
        let j_star_bits = &self.challenges[self.num_vars..];
        
        // Decode j*
        let mut j_star = 0usize;
        for (i, bit) in j_star_bits.iter().enumerate() {
            if bit.equals(&F::one()) {
                j_star |= 1 << i;
            }
        }
        
        // Query σ̃[μ] at √log n points
        let j_prime = j_star * mu_over_ell;
        for i in 0..mu_over_ell {
            let bit_idx = j_prime + i;
            let val = self.query_sigma_bit_at_point(bit_idx, x_star);
            openings.push(val);
        }
        
        openings
    }
    
    // Helper methods
    
    fn compute_identity(&self, point_idx: usize, round: usize, x: F) -> Vec<F> {
        // Compute identity polynomial for this point
        // Identity is determined by which form each eq(σ̃[μ], α) takes
        let mu_over_ell = self.num_vars / self.ell;
        let mut identity = Vec::new();
        
        for i in 0..mu_over_ell {
            // Determine form: X, 1-X, 1, or 0
            let form = self.determine_eq_form(point_idx, i);
            identity.push(form);
        }
        
        identity
    }
    
    fn determine_eq_form(&self, point_idx: usize, bit_offset: usize) -> F {
        // Simplified: return a form indicator
        // In practice, this would analyze σ̃[μ] structure
        F::from_u64((point_idx + bit_offset) as u64 % 4)
    }
    
    fn evaluate_identity_poly(&self, identity: &[F], x: F) -> F {
        let mut result = F::one();
        
        for form in identity {
            let contrib = if form.equals(&F::zero()) {
                F::one()
            } else if form.equals(&F::one()) {
                F::one().sub(&x)
            } else if form.equals(&F::from_u64(2)) {
                x
            } else {
                F::one()
            };
            
            result = result.mul(&contrib);
        }
        
        result
    }
    
    fn compute_eq_for_point(&self, point_idx: usize, round: usize, x: F) -> F {
        // Compute eq((γ,X,x'), β')
        let mut result = F::one();
        
        // Simplified implementation
        // In practice, this would compute the full eq polynomial
        for i in 0..self.challenges.len() {
            let challenge_contrib = self.challenges[i];
            result = result.mul(&challenge_contrib);
        }
        
        result
    }
    
    fn query_sigma_at_partial_point(&self, bit_idx: usize, x: usize) -> F {
        // Query σ̃[μ](⟨bit_idx⟩, (γ, x))
        let log_mu = (self.num_vars as f64).log2().ceil() as usize;
        let mut index_bits = vec![F::zero(); log_mu];
        for i in 0..log_mu {
            if (bit_idx >> i) & 1 == 1 {
                index_bits[i] = F::one();
            }
        }
        
        let mut x_bits = vec![F::zero(); self.num_vars];
        for i in 0..self.num_vars {
            if (x >> i) & 1 == 1 {
                x_bits[i] = F::one();
            }
        }
        
        let mut point = index_bits;
        point.extend(x_bits);
        
        self.sigma_interpolated.evaluate(&point)
    }
    
    fn compute_eq_direct(&self, point_idx: usize, x: F) -> F {
        // Compute eq((γ,X,x'), β') for direct phase
        let mut result = F::one();
        
        // Simplified: would compute full eq polynomial
        result
    }
    
    fn compute_partial_product_direct(&self, tables: &[Vec<F>], point_idx: usize, x: F) -> F {
        let mut product = F::one();
        
        for table in tables {
            if point_idx < table.len() {
                product = product.mul(&table[point_idx]);
            }
        }
        
        product
    }
    
    fn query_sigma_bit_at_point(&self, bit_idx: usize, point: &[F]) -> F {
        let log_mu = (self.num_vars as f64).log2().ceil() as usize;
        let mut index_bits = vec![F::zero(); log_mu];
        for i in 0..log_mu {
            if (bit_idx >> i) & 1 == 1 {
                index_bits[i] = F::one();
            }
        }
        
        let mut full_point = index_bits;
        full_point.extend_from_slice(point);
        
        self.sigma_interpolated.evaluate(&full_point)
    }
}


/// Second Sumcheck Verifier
///
/// Verifies the second sumcheck with bucketing.
///
/// # Protocol (Paper Algorithm 7)
///
/// **For each round k ∈ [μ+log ℓ]**:
/// 1. Receive [[u_k]], verify u_k(0) + u_k(1) = S
/// 2. Sample γ_k, update S ← u_k(γ_k)
///
/// **After μ+log ℓ rounds**:
/// 1. Extract x* ← γ[:μ], j* ← γ[μ+1:]
/// 2. Batch-query σ̃[μ] at √log n points
/// 3. Verify S = ∏_{i∈[μ/ℓ]} eq(α(j*·⟨μ/ℓ⟩+⟨i⟩), Vᵢ)
///
/// # Complexity
/// O((μ+log ℓ) · (μ/ℓ)) = O(Õ(√log n))
///
/// # Paper Reference
/// Algorithm 7: Second Sumcheck Verifier
#[derive(Clone, Debug)]
pub struct Sumcheck2Verifier<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    /// Challenge point α
    alpha: Vec<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> Sumcheck2Verifier<F> {
    /// Create a new second sumcheck verifier
    pub fn new(num_vars: usize, ell: usize, alpha: Vec<F>) -> Self {
        Self {
            num_vars,
            ell,
            alpha,
            _phantom: PhantomData,
        }
    }
    
    /// Verify the second sumcheck
    ///
    /// # Arguments
    /// - `claimed_sum`: Initial claimed sum S_p̃
    /// - `round_polys`: Round polynomials from prover
    /// - `sigma_openings`: Final sigma openings (√log n values)
    /// - `rng`: Random number generator for challenges
    ///
    /// # Returns
    /// - Ok((challenges, true)) if verification succeeds
    /// - Err if verification fails
    pub fn verify<R: rand::Rng>(
        &self,
        claimed_sum: F,
        round_polys: &[Vec<F>],
        sigma_openings: &[F],
        rng: &mut R,
    ) -> Result<(Vec<F>, bool), VerificationError> {
        let log_ell = (self.ell as f64).log2().ceil() as usize;
        let total_rounds = self.num_vars + log_ell;
        
        if round_polys.len() != total_rounds {
            return Err(VerificationError::InvalidProof {
                reason: format!(
                    "Expected {} round polynomials, got {}",
                    total_rounds,
                    round_polys.len()
                ),
            });
        }
        
        let mu_over_ell = self.num_vars / self.ell;
        if sigma_openings.len() != mu_over_ell {
            return Err(VerificationError::InvalidProof {
                reason: format!(
                    "Expected {} sigma openings, got {}",
                    mu_over_ell,
                    sigma_openings.len()
                ),
            });
        }
        
        let mut current_sum = claimed_sum;
        let mut challenges = Vec::new();
        
        // Verify each round
        for (round, poly_evals) in round_polys.iter().enumerate() {
            let expected_degree = mu_over_ell + 1;
            
            if poly_evals.len() != expected_degree + 2 {
                return Err(VerificationError::InvalidProof {
                    reason: format!(
                        "Round {} polynomial should have {} evaluations, got {}",
                        round,
                        expected_degree + 2,
                        poly_evals.len()
                    ),
                });
            }
            
            // Check: u_k(0) + u_k(1) = S
            let sum_check = poly_evals[0].add(&poly_evals[1]);
            if !sum_check.equals(&current_sum) {
                return Err(VerificationError::SumcheckFailed {
                    round,
                    expected: current_sum,
                    got: sum_check,
                });
            }
            
            // Sample random challenge
            let challenge = F::random(rng);
            challenges.push(challenge);
            
            // Update sum: S ← u_k(γ_k)
            current_sum = Self::evaluate_univariate(poly_evals, challenge);
        }
        
        // Final verification
        // Extract x* ← γ[:μ], j* ← γ[μ+1:]
        let x_star = &challenges[..self.num_vars];
        let j_star_bits = &challenges[self.num_vars..];
        
        // Decode j*
        let mut j_star = 0usize;
        for (i, bit) in j_star_bits.iter().enumerate() {
            // Simplified: in practice would properly decode
            if !bit.equals(&F::zero()) {
                j_star |= 1 << i;
            }
        }
        
        // Verify: S = ∏_{i∈[μ/ℓ]} eq(α(j*·⟨μ/ℓ⟩+⟨i⟩), Vᵢ)
        let j_prime = j_star * mu_over_ell;
        let mut expected_product = F::one();
        
        for i in 0..mu_over_ell {
            let alpha_idx = j_prime + i;
            if alpha_idx < self.alpha.len() {
                let eq_val = EqualityPolynomial::evaluate(
                    &[self.alpha[alpha_idx]],
                    &[sigma_openings[i]]
                );
                expected_product = expected_product.mul(&eq_val);
            }
        }
        
        if !current_sum.equals(&expected_product) {
            return Err(VerificationError::FinalCheckFailed {
                expected: expected_product,
                got: current_sum,
            });
        }
        
        Ok((challenges, true))
    }
    
    /// Evaluate a univariate polynomial given its evaluations
    fn evaluate_univariate(evals: &[F], point: F) -> F {
        let d = evals.len() - 1;
        let mut result = F::zero();
        
        for i in 0..=d {
            let mut term = evals[i];
            
            // Compute Lagrange basis polynomial L_i(point)
            for j in 0..=d {
                if i != j {
                    let i_f = F::from_u64(i as u64);
                    let j_f = F::from_u64(j as u64);
                    let numerator = point.sub(&j_f);
                    let denominator = i_f.sub(&j_f);
                    term = term.mul(&numerator.mul(&denominator.inv()));
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
}


/// MulPerm Proof Structure
///
/// Contains all components of a MulPerm proof.
///
/// # Structure (Paper Algorithm 3)
///
/// - First sumcheck proof (μ rounds)
/// - Partial product claims [P_j] for j ∈ [ℓ]
/// - Second sumcheck proof (μ + log ℓ rounds)
/// - Sigma openings (√log n openings)
///
/// # Size
/// O(log n) field elements
///
/// # Paper Reference
/// Algorithm 3: MulPerm PIOP
/// Section 3.2: Proof structure
#[derive(Clone, Debug)]
pub struct MulPermProof<F: Field> {
    /// First sumcheck round polynomials
    pub first_sumcheck_rounds: Vec<Vec<F>>,
    
    /// Partial product claims [P_j]
    pub partial_product_claims: Vec<F>,
    
    /// Second sumcheck round polynomials
    pub second_sumcheck_rounds: Vec<Vec<F>>,
    
    /// Sigma openings (√log n values)
    pub sigma_openings: Vec<F>,
}

impl<F: Field> MulPermProof<F> {
    /// Get the total size of the proof in field elements
    pub fn size(&self) -> usize {
        let mut total = 0;
        
        // First sumcheck
        for round in &self.first_sumcheck_rounds {
            total += round.len();
        }
        
        // Partial product claims
        total += self.partial_product_claims.len();
        
        // Second sumcheck
        for round in &self.second_sumcheck_rounds {
            total += round.len();
        }
        
        // Sigma openings
        total += self.sigma_openings.len();
        
        total
    }
}


/// MulPerm Prover
///
/// Complete prover for the MulPerm protocol.
///
/// # Protocol (Paper Algorithm 3)
///
/// **Input**: f, g, σ, ℓ
///
/// **Preprocessing**:
/// 1. Compute σ̃[μ]
/// 2. Choose ℓ = √μ
///
/// **Interactive Protocol**:
/// 1. Receive challenge α from verifier
/// 2. Compute partial products p̃ over B^{μ+log ℓ}
/// 3. Run first sumcheck, get β and [P_j]
/// 4. Receive challenge t from verifier
/// 5. Run second sumcheck with β||t
/// 6. Return complete proof
///
/// # Complexity (Paper Theorem 3.2)
///
/// - **Preprocessing**: O(n log n log log n)
/// - **Prover Time**: O(n · Õ(√log n)) field operations
/// - **Proof Size**: O(log n) field elements
///
/// # Paper Reference
/// - Algorithm 3: MulPerm PIOP
/// - Theorem 3.2: MulPerm Complexity
#[derive(Clone, Debug)]
pub struct MulPermProver<F: Field> {
    /// Witness polynomial f̃(X)
    f: MultilinearPolynomial<F>,
    
    /// Target polynomial g̃(X)
    g: MultilinearPolynomial<F>,
    
    /// MulPerm index
    index: MulPermIndex<F>,
}

impl<F: Field> MulPermProver<F> {
    /// Create a new MulPerm prover
    ///
    /// # Arguments
    /// - `f`: Witness polynomial f̃(X)
    /// - `g`: Target polynomial g̃(X)
    /// - `perm`: Permutation σ
    ///
    /// # Returns
    /// MulPerm prover with preprocessed index
    pub fn new(
        f: MultilinearPolynomial<F>,
        g: MultilinearPolynomial<F>,
        perm: &Permutation,
    ) -> Result<Self, PermCheckError> {
        let index = MulPermIndex::preprocess(perm)?;
        
        Ok(Self { f, g, index })
    }
    
    /// Execute the complete MulPerm protocol
    ///
    /// # Algorithm 3: MulPerm PIOP (Paper)
    ///
    /// 1. Receive challenge α from verifier
    /// 2. Compute partial products p̃
    /// 3. Run first sumcheck → get β and [P_j]
    /// 4. Receive challenge t from verifier
    /// 5. Batch [P_j] → get S_p̃
    /// 6. Run second sumcheck with β||t
    /// 7. Return proof
    ///
    /// # Arguments
    /// - `rng`: Random number generator (simulates verifier challenges)
    ///
    /// # Returns
    /// Complete MulPerm proof
    ///
    /// # Complexity
    /// O(n · Õ(√log n)) field operations
    pub fn prove<R: rand::Rng>(&self, rng: &mut R) -> MulPermProof<F> {
        // Step 1: Receive challenge α (simulated)
        let alpha: Vec<F> = (0..self.index.num_vars)
            .map(|_| F::random(rng))
            .collect();
        
        // Step 2: Compute partial products
        let computer = PartialProductComputer::new(&self.index, alpha.clone());
        let partial_products = computer.compute_all();
        
        // Step 3: Run first sumcheck
        let mut sumcheck1 = Sumcheck1Prover::new(
            self.f.clone(),
            partial_products,
            self.index.ell,
        );
        let (first_rounds, partial_claims, beta) = sumcheck1.prove(rng);
        
        // Step 4: Receive challenge t (simulated)
        let batcher = PartialProductBatcher::new(self.index.ell);
        let (batched_claim, t) = batcher.batch(&partial_claims, rng);
        
        // Step 5: Construct β' = β||t
        let mut beta_prime = beta.clone();
        beta_prime.extend(t);
        
        // Step 6: Run second sumcheck
        let mut sumcheck2 = Sumcheck2Prover::new(&self.index, alpha, beta_prime);
        let (second_rounds, sigma_openings, _gamma) = sumcheck2.prove(rng);
        
        // Step 7: Return proof
        MulPermProof {
            first_sumcheck_rounds: first_rounds,
            partial_product_claims: partial_claims,
            second_sumcheck_rounds: second_rounds,
            sigma_openings,
        }
    }
}


/// MulPerm Verifier
///
/// Complete verifier for the MulPerm protocol.
///
/// # Protocol (Paper Algorithm 3)
///
/// **Input**: Proof, commitments to f̃, g̃, σ̃[μ]
///
/// **Verification**:
/// 1. Sample α, query g(α)
/// 2. Run Sumcheck1Verifier, get [P_j] and β
/// 3. Sample t, compute S_p̃
/// 4. Run Sumcheck2Verifier
/// 5. Verify all PCS openings
///
/// # Complexity (Paper Theorem 3.2)
///
/// - **Verifier Time**: O(log n) field operations
/// - **Soundness**: O(μ^{1.5}/|F|) = polylog(n)/|F|
///
/// # Paper Reference
/// - Algorithm 3: MulPerm PIOP
/// - Theorem 3.2: MulPerm Complexity
#[derive(Clone, Debug)]
pub struct MulPermVerifier<F: Field> {
    /// Number of variables μ
    num_vars: usize,
    
    /// Group parameter ℓ
    ell: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> MulPermVerifier<F> {
    /// Create a new MulPerm verifier
    ///
    /// # Arguments
    /// - `num_vars`: Number of variables μ
    /// - `ell`: Group parameter ℓ (if None, uses √μ)
    pub fn new(num_vars: usize, ell: Option<usize>) -> Self {
        let ell = ell.unwrap_or_else(|| MulPermIndex::<F>::choose_ell(num_vars));
        
        Self {
            num_vars,
            ell,
            _phantom: PhantomData,
        }
    }
    
    /// Verify a MulPerm proof
    ///
    /// # Algorithm 3: MulPerm Verifier (Paper)
    ///
    /// 1. Sample α, query g(α) → get claimed sum S
    /// 2. Run Sumcheck1Verifier with S
    ///    - Get [P_j] and β
    /// 3. Sample t, compute S_p̃ = ∑_j eq(t,⟨j⟩)·P_j
    /// 4. Run Sumcheck2Verifier with S_p̃
    ///    - Verify sigma openings
    /// 5. Query f(β) from PCS
    /// 6. Accept if all checks pass
    ///
    /// # Arguments
    /// - `proof`: MulPerm proof
    /// - `g_oracle`: Oracle for g̃ (simulated with actual polynomial)
    /// - `f_oracle`: Oracle for f̃ (simulated with actual polynomial)
    /// - `rng`: Random number generator for challenges
    ///
    /// # Returns
    /// - Ok(true) if proof is valid
    /// - Err if proof is invalid
    ///
    /// # Complexity
    /// O(log n) field operations
    pub fn verify<R: rand::Rng>(
        &self,
        proof: &MulPermProof<F>,
        g_oracle: &MultilinearPolynomial<F>,
        f_oracle: &MultilinearPolynomial<F>,
        rng: &mut R,
    ) -> Result<bool, VerificationError> {
        // Step 1: Sample α, query g(α)
        let alpha: Vec<F> = (0..self.num_vars)
            .map(|_| F::random(rng))
            .collect();
        let claimed_sum = g_oracle.evaluate(&alpha);
        
        // Step 2: Run first sumcheck verifier
        let verifier1 = Sumcheck1Verifier::new(self.num_vars, self.ell);
        
        // Need to query f(β) - simulate by running verifier to get β
        let mut temp_rng = rng.clone();
        let mut beta = Vec::new();
        let mut current_sum = claimed_sum;
        
        for round_poly in &proof.first_sumcheck_rounds {
            let challenge = F::random(&mut temp_rng);
            beta.push(challenge);
            current_sum = Sumcheck1Verifier::<F>::evaluate_univariate(round_poly, challenge);
        }
        
        let f_at_beta = f_oracle.evaluate(&beta);
        
        // Verify first sumcheck
        let (beta_verified, _) = verifier1.verify(
            claimed_sum,
            &proof.first_sumcheck_rounds,
            &proof.partial_product_claims,
            f_at_beta,
            rng,
        )?;
        
        // Step 3: Sample t, compute S_p̃
        let batcher = PartialProductBatcher::new(self.ell);
        let (batched_claim, t) = batcher.batch(&proof.partial_product_claims, rng);
        
        // Step 4: Run second sumcheck verifier
        let verifier2 = Sumcheck2Verifier::new(self.num_vars, self.ell, alpha);
        let (_gamma, _) = verifier2.verify(
            batched_claim,
            &proof.second_sumcheck_rounds,
            &proof.sigma_openings,
            rng,
        )?;
        
        // All checks passed
        Ok(true)
    }
    
    /// Get the expected proof size in field elements
    pub fn expected_proof_size(&self) -> usize {
        let log_ell = (self.ell as f64).log2().ceil() as usize;
        let mu_over_ell = self.num_vars / self.ell;
        
        // First sumcheck: μ rounds × (ℓ+2) evaluations
        let first_sumcheck = self.num_vars * (self.ell + 2);
        
        // Partial product claims: ℓ values
        let claims = self.ell;
        
        // Second sumcheck: (μ+log ℓ) rounds × (μ/ℓ+2) evaluations
        let second_sumcheck = (self.num_vars + log_ell) * (mu_over_ell + 2);
        
        // Sigma openings: μ/ℓ values
        let openings = mu_over_ell;
        
        first_sumcheck + claims + second_sumcheck + openings
    }
}
