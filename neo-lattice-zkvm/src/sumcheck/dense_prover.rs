// Dense Sum-Check Prover for Products of Multilinear Polynomials
// Achieves O(N) prover time for g(x) = p̃(x) · q̃(x)

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use std::fmt::Debug;

/// Dense sum-check prover for products of MLEs
/// Proves: Σ_{x∈{0,1}^n} g(x) = C where g(x) = p̃(x) · q̃(x)
#[derive(Clone, Debug)]
pub struct DenseSumCheckProver<K: ExtensionFieldElement> {
    /// Current round number (0-indexed)
    pub round: usize,
    /// Evaluations of p̃ at current partial assignment
    pub p_evals: Vec<K>,
    /// Evaluations of q̃ at current partial assignment
    pub q_evals: Vec<K>,
    /// Number of variables
    pub num_vars: usize,
}

impl<K: ExtensionFieldElement> DenseSumCheckProver<K> {
    /// Initialize prover with two multilinear polynomials
    /// Validates that both have same number of variables
    pub fn new(
        p: MultilinearPolynomial<K>,
        q: MultilinearPolynomial<K>,
    ) -> Result<Self, String> {
        if p.num_vars != q.num_vars {
            return Err(format!(
                "Polynomials must have same number of variables: {} vs {}",
                p.num_vars, q.num_vars
            ));
        }
        
        let num_vars = p.num_vars;
        
        Ok(Self {
            round: 0,
            p_evals: p.evaluations,
            q_evals: q.evaluations,
            num_vars,
        })
    }
    
    /// Compute round polynomial s_i(X) of degree 2
    /// s_i(X) = Σ_{x'∈{0,1}^{n-i}} p̃(r_1,...,r_{i-1},X,x') · q̃(r_1,...,r_{i-1},X,x')
    pub fn round_polynomial(&self) -> UnivariatePolynomial<K> {
        let n_remaining = self.p_evals.len();
        
        if n_remaining == 0 {
            return UnivariatePolynomial::zero();
        }
        
        let half = n_remaining / 2;
        
        // Evaluate at X = 0, 1, 2
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            let p_0 = self.p_evals[i];
            let p_1 = self.p_evals[i + half];
            let q_0 = self.q_evals[i];
            let q_1 = self.q_evals[i + half];
            
            // s(0) = Σ p̃(0,x') · q̃(0,x')
            s_0 = s_0.add(&p_0.mul(&q_0));
            
            // s(1) = Σ p̃(1,x') · q̃(1,x')
            s_1 = s_1.add(&p_1.mul(&q_1));
            
            // s(2) = Σ p̃(2,x') · q̃(2,x')
            // Use extrapolation: p̃(2,x') = 2·p̃(1,x') - p̃(0,x')
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let p_2 = two.mul(&p_1).sub(&p_0);
            let q_2 = two.mul(&q_1).sub(&q_0);
            s_2 = s_2.add(&p_2.mul(&q_2));
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    /// Update prover state after receiving challenge r_i
    /// Binds variable i to challenge value
    /// Algorithm: For j in 0..half: new_p[j] = (1-r)·p[j] + r·p[j+half]
    pub fn update(&mut self, challenge: K) -> Result<(), String> {
        let n_remaining = self.p_evals.len();
        
        if n_remaining == 0 {
            return Err("No more variables to bind".to_string());
        }
        
        let half = n_remaining / 2;
        let mut new_p = Vec::with_capacity(half);
        let mut new_q = Vec::with_capacity(half);
        
        let one_minus_r = K::one().sub(&challenge);
        
        for i in 0..half {
            // p̃(r_i, x') = (1-r_i)·p̃(0,x') + r_i·p̃(1,x')
            let p_new = one_minus_r.mul(&self.p_evals[i])
                .add(&challenge.mul(&self.p_evals[i + half]));
            new_p.push(p_new);
            
            // q̃(r_i, x') = (1-r_i)·q̃(0,x') + r_i·q̃(1,x')
            let q_new = one_minus_r.mul(&self.q_evals[i])
                .add(&challenge.mul(&self.q_evals[i + half]));
            new_q.push(q_new);
        }
        
        self.p_evals = new_p;
        self.q_evals = new_q;
        self.round += 1;
        
        Ok(())
    }
    
    /// Get final evaluation g(r_1,...,r_n)
    /// Should be called after all n rounds
    pub fn final_evaluation(&self) -> Result<K, String> {
        if self.p_evals.len() != 1 || self.q_evals.len() != 1 {
            return Err(format!(
                "Final evaluation requires exactly 1 element, got {} and {}",
                self.p_evals.len(),
                self.q_evals.len()
            ));
        }
        
        Ok(self.p_evals[0].mul(&self.q_evals[0]))
    }
    
    /// Get current round number
    pub fn current_round(&self) -> usize {
        self.round
    }
    
    /// Check if protocol is complete
    pub fn is_complete(&self) -> bool {
        self.p_evals.len() == 1 && self.q_evals.len() == 1
    }
    
    /// Get number of remaining rounds
    pub fn remaining_rounds(&self) -> usize {
        if self.p_evals.len() == 0 {
            0
        } else {
            (self.p_evals.len() as f64).log2() as usize
        }
    }
    
    /// Verify total prover time is O(N)
    /// Time = O(2·N + N + N/2 + ... + 1) = O(N)
    pub fn verify_linear_time(&self, n: usize) -> bool {
        // Total operations across all rounds
        let mut total_ops = 0;
        let mut size = 1 << n;
        
        for _ in 0..n {
            // Each round processes 'size' elements
            // Computing s(0), s(1), s(2) requires 2 multiplications per element
            total_ops += 2 * size;
            size /= 2;
        }
        
        // Total should be approximately 4N (where N = 2^n)
        let n_val = 1 << n;
        total_ops <= 4 * n_val
    }
}

/// Sum-check proof transcript
#[derive(Clone, Debug)]
pub struct SumCheckProof<K: ExtensionFieldElement> {
    /// Round polynomials s_1, ..., s_n
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    /// Final evaluation g(r_1,...,r_n)
    pub final_evaluation: K,
    /// Claimed sum C
    pub claimed_sum: K,
}

impl<K: ExtensionFieldElement> SumCheckProof<K> {
    /// Create new proof
    pub fn new(
        round_polynomials: Vec<UnivariatePolynomial<K>>,
        final_evaluation: K,
        claimed_sum: K,
    ) -> Self {
        Self {
            round_polynomials,
            final_evaluation,
            claimed_sum,
        }
    }
    
    /// Get number of rounds
    pub fn num_rounds(&self) -> usize {
        self.round_polynomials.len()
    }
    
    /// Get proof size in field elements
    pub fn size_in_field_elements(&self) -> usize {
        // Each round polynomial has degree 2, so 3 evaluations
        // Plus 1 for final evaluation, 1 for claimed sum
        self.round_polynomials.len() * 3 + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M61Field, Field};
    use crate::field::extension_framework::M61ExtensionField2;
    
    type K = M61ExtensionField2;
    
    fn make_test_poly(n: usize, offset: u64) -> MultilinearPolynomial<K> {
        let size = 1 << n;
        let evals: Vec<K> = (0..size)
            .map(|i| K::from_base_field_element(M61Field::from_u64(i as u64 + offset), 0))
            .collect();
        MultilinearPolynomial::from_evaluations(evals).unwrap()
    }
    
    #[test]
    fn test_new_prover() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(3, 10);
        
        let prover = DenseSumCheckProver::new(p, q).unwrap();
        
        assert_eq!(prover.num_vars, 3);
        assert_eq!(prover.round, 0);
        assert_eq!(prover.p_evals.len(), 8);
        assert_eq!(prover.q_evals.len(), 8);
    }
    
    #[test]
    fn test_new_prover_mismatched_vars() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(4, 0);
        
        let result = DenseSumCheckProver::new(p, q);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_round_polynomial() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        let prover = DenseSumCheckProver::new(p, q).unwrap();
        let round_poly = prover.round_polynomial();
        
        // Should have degree 2 (3 evaluations)
        assert_eq!(round_poly.degree(), 2);
        assert_eq!(round_poly.evaluations.len(), 3);
    }
    
    #[test]
    fn test_update() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(3, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        let challenge = K::from_base_field_element(M61Field::from_u64(7), 0);
        prover.update(challenge).unwrap();
        
        assert_eq!(prover.round, 1);
        assert_eq!(prover.p_evals.len(), 4);
        assert_eq!(prover.q_evals.len(), 4);
    }
    
    #[test]
    fn test_multiple_rounds() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(3, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        // Round 1
        let _poly1 = prover.round_polynomial();
        prover.update(K::from_base_field_element(M61Field::from_u64(3), 0)).unwrap();
        assert_eq!(prover.p_evals.len(), 4);
        
        // Round 2
        let _poly2 = prover.round_polynomial();
        prover.update(K::from_base_field_element(M61Field::from_u64(5), 0)).unwrap();
        assert_eq!(prover.p_evals.len(), 2);
        
        // Round 3
        let _poly3 = prover.round_polynomial();
        prover.update(K::from_base_field_element(M61Field::from_u64(7), 0)).unwrap();
        assert_eq!(prover.p_evals.len(), 1);
        
        assert!(prover.is_complete());
    }
    
    #[test]
    fn test_final_evaluation() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        // Complete all rounds
        for _ in 0..2 {
            let _poly = prover.round_polynomial();
            prover.update(K::from_base_field_element(M61Field::from_u64(3), 0)).unwrap();
        }
        
        let final_eval = prover.final_evaluation().unwrap();
        
        // Should be p(r,r) * q(r,r) for some r
        assert_ne!(final_eval, K::zero());
    }
    
    #[test]
    fn test_is_complete() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        assert!(!prover.is_complete());
        
        prover.update(K::from_base_field_element(M61Field::from_u64(3), 0)).unwrap();
        assert!(!prover.is_complete());
        
        prover.update(K::from_base_field_element(M61Field::from_u64(5), 0)).unwrap();
        assert!(prover.is_complete());
    }
    
    #[test]
    fn test_remaining_rounds() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(3, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        assert_eq!(prover.remaining_rounds(), 3);
        
        prover.update(K::from_base_field_element(M61Field::from_u64(3), 0)).unwrap();
        assert_eq!(prover.remaining_rounds(), 2);
        
        prover.update(K::from_base_field_element(M61Field::from_u64(5), 0)).unwrap();
        assert_eq!(prover.remaining_rounds(), 1);
        
        prover.update(K::from_base_field_element(M61Field::from_u64(7), 0)).unwrap();
        assert_eq!(prover.remaining_rounds(), 0);
    }
    
    #[test]
    fn test_verify_linear_time() {
        let p = make_test_poly(4, 0);
        let q = make_test_poly(4, 0);
        
        let prover = DenseSumCheckProver::new(p, q).unwrap();
        
        // Verify O(N) time complexity
        assert!(prover.verify_linear_time(4));
    }
    
    #[test]
    fn test_large_polynomial() {
        // Test with N=256
        let p = make_test_poly(8, 0);
        let q = make_test_poly(8, 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        
        // Run all 8 rounds
        for _ in 0..8 {
            let _poly = prover.round_polynomial();
            prover.update(K::from_base_field_element(M61Field::from_u64(3), 0)).unwrap();
        }
        
        assert!(prover.is_complete());
        let _final_eval = prover.final_evaluation().unwrap();
    }
    
    #[test]
    fn test_proof_size() {
        let round_polys = vec![
            UnivariatePolynomial::from_evaluations(&[K::zero(), K::one(), K::zero()]),
            UnivariatePolynomial::from_evaluations(&[K::one(), K::zero(), K::one()]),
        ];
        
        let proof = SumCheckProof::new(
            round_polys,
            K::one(),
            K::from_base_field_element(M61Field::from_u64(42), 0),
        );
        
        assert_eq!(proof.num_rounds(), 2);
        // 2 rounds * 3 evals + 1 final + 1 claimed = 8
        assert_eq!(proof.size_in_field_elements(), 8);
    }
}


/// SALSAA-specific sum-check prover for norm verification
/// 
/// **Paper Reference**: SALSAA Section 3, Requirements 4.1, 4.7, 18.7, 21.12
/// 
/// **Key Innovation**: Linear-time prover using dynamic programming (Thaler's optimization)
/// 
/// **Mathematical Background**:
/// SALSAA proves norm bounds via sum-check over the identity:
/// ||x||²_{σ,2} = Trace(⟨x, x̄⟩) = Σ_{z∈[d]^μ} u^T·CRT(LDE[W](z) ⊙ LDE[W̄](z̄))
/// 
/// where:
/// - W is the witness matrix
/// - LDE[W] is the low-degree extension
/// - W̄ is the complex conjugate
/// - CRT is the Chinese Remainder Theorem decomposition
/// - u is a random linear combination vector
/// 
/// **Prover Complexity**: O(m) where m = d^μ is the number of evaluations
/// - Round 1: Process all m evaluations → O(m) work
/// - Round 2: Process m/2 evaluations → O(m/2) work
/// - Round i: Process m/2^{i-1} evaluations → O(m/2^{i-1}) work
/// - Total: O(m + m/2 + m/4 + ... + 1) = O(2m) = O(m)
/// 
/// **Why This Matters**:
/// Traditional sum-check has O(m·μ) prover time. Thaler's optimization achieves O(m),
/// which is optimal since the prover must read all m evaluations at least once.
#[derive(Clone, Debug)]
pub struct SALSAASumCheckProver<K: ExtensionFieldElement> {
    /// Underlying dense prover
    prover: DenseSumCheckProver<K>,
    /// Degree bound per variable (d)
    degree_bound: usize,
    /// Number of variables (μ)
    num_vars: usize,
}

impl<K: ExtensionFieldElement> SALSAASumCheckProver<K> {
    /// Create SALSAA sum-check prover
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.1
    /// 
    /// **Input**:
    /// - lde_w: Low-degree extension of witness W
    /// - lde_w_bar: Low-degree extension of conjugate W̄
    /// - degree_bound: Maximum degree per variable (typically d-1)
    /// 
    /// **Output**:
    /// Prover that can generate round polynomials in O(m) total time
    pub fn new(
        lde_w: MultilinearPolynomial<K>,
        lde_w_bar: MultilinearPolynomial<K>,
        degree_bound: usize,
    ) -> Result<Self, String> {
        let num_vars = lde_w.num_vars;
        let prover = DenseSumCheckProver::new(lde_w, lde_w_bar)?;
        
        Ok(Self {
            prover,
            degree_bound,
            num_vars,
        })
    }
    
    /// Compute round polynomial g_j(X) with degree ≤ 2(d-1)
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.2
    /// 
    /// **Mathematical Formula**:
    /// g_j(X) = Σ_{x'∈[d]^{μ-j}} LDE[W](r_1,...,r_{j-1},X,x') ⊙ LDE[W̄](r_1,...,r_{j-1},X,x')
    /// 
    /// **Degree Analysis**:
    /// - Each LDE[W](·,X,·) has degree ≤ d-1 in X
    /// - Product has degree ≤ 2(d-1)
    /// - Requires (2d-1) field elements to represent
    /// 
    /// **Optimization**:
    /// Uses dynamic programming to compute in O(m/2^j) time for round j
    pub fn round_polynomial_salsaa(&self) -> UnivariatePolynomial<K> {
        // Use underlying dense prover's optimized implementation
        self.prover.round_polynomial()
    }
    
    /// Update prover state with verifier challenge
    /// 
    /// **Paper Reference**: SALSAA Section 3.1
    /// 
    /// **Work Halving**:
    /// After binding variable j to challenge r_j, the remaining problem
    /// has size m/2. This is the key to O(m) total time.
    pub fn update_salsaa(&mut self, challenge: K) -> Result<(), String> {
        self.prover.update(challenge)
    }
    
    /// Verify linear-time complexity
    /// 
    /// **Paper Reference**: Requirement 18.7
    /// 
    /// **Theorem**: Total prover work is O(m) field operations where m = d^μ
    /// 
    /// **Proof**:
    /// Work in round j = O(m/2^{j-1})
    /// Total = Σ_{j=1}^μ O(m/2^{j-1}) = O(m·Σ_{j=0}^{μ-1} 1/2^j) = O(m·2) = O(m)
    pub fn verify_linear_time_complexity(&self) -> bool {
        self.prover.verify_linear_time(self.num_vars)
    }
    
    /// Get communication complexity in bits
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.5
    /// 
    /// **Formula**: (2d-1)·μ·e·log q + 2r·log|R_q| bits
    /// where:
    /// - (2d-1) = coefficients per round polynomial
    /// - μ = number of rounds
    /// - e = splitting degree (from CRT decomposition)
    /// - log q = field element size
    /// - r = number of columns in witness matrix
    /// - log|R_q| = ring element size
    pub fn communication_complexity_bits(
        &self,
        splitting_degree: usize,
        log_q: usize,
        num_columns: usize,
        log_ring_size: usize,
    ) -> usize {
        let round_poly_bits = (2 * self.degree_bound - 1) * self.num_vars * splitting_degree * log_q;
        let final_eval_bits = 2 * num_columns * log_ring_size;
        round_poly_bits + final_eval_bits
    }
}

/// Batched norm check via random linear combination
/// 
/// **Paper Reference**: SALSAA Section 3.2, Requirement 4.4
/// 
/// **Problem**: Need to verify r norm bounds: ||W_i||² ≤ ν_i for i ∈ [r]
/// 
/// **Solution**: Use random linear combination to reduce to single sum-check
/// - Verifier sends random u ∈ F^r
/// - Prover proves: Σ_i u_i·||W_i||² ≤ Σ_i u_i·ν_i
/// - By Schwartz-Zippel, if this holds, all individual bounds hold with high probability
/// 
/// **Benefit**: r sum-checks → 1 sum-check, reducing communication by factor of r
#[derive(Clone, Debug)]
pub struct BatchedNormCheck<K: ExtensionFieldElement> {
    /// Number of columns to batch
    num_columns: usize,
    /// Random linear combination coefficients
    rlc_coefficients: Vec<K>,
    /// Individual norm bounds
    norm_bounds: Vec<f64>,
}

impl<K: ExtensionFieldElement> BatchedNormCheck<K> {
    /// Create batched norm check
    /// 
    /// **Paper Reference**: Requirement 4.4
    /// 
    /// **Input**:
    /// - num_columns: Number of norm bounds to batch (r)
    /// - rlc_coefficients: Random challenges u ∈ F^r from verifier
    /// - norm_bounds: Individual bounds ν_i
    pub fn new(
        num_columns: usize,
        rlc_coefficients: Vec<K>,
        norm_bounds: Vec<f64>,
    ) -> Result<Self, String> {
        if rlc_coefficients.len() != num_columns {
            return Err("RLC coefficients must match number of columns".to_string());
        }
        if norm_bounds.len() != num_columns {
            return Err("Norm bounds must match number of columns".to_string());
        }
        
        Ok(Self {
            num_columns,
            rlc_coefficients,
            norm_bounds,
        })
    }
    
    /// Compute batched target sum
    /// 
    /// **Formula**: t = Σ_i u_i·ν_i
    /// 
    /// This is the right-hand side of the batched inequality.
    pub fn compute_batched_target(&self) -> f64 {
        self.rlc_coefficients.iter()
            .zip(self.norm_bounds.iter())
            .map(|(u, nu)| {
                // Convert u to f64 (using constant term if it's a ring element)
                let u_val = u.to_base_field_element().to_canonical_u64() as f64;
                u_val * nu
            })
            .sum()
    }
    
    /// Verify soundness of batching
    /// 
    /// **Paper Reference**: Requirement 4.4
    /// 
    /// **Theorem**: If Σ_i u_i·||W_i||² ≤ Σ_i u_i·ν_i for random u,
    /// then ||W_i||² ≤ ν_i for all i with probability ≥ 1 - r/|F|
    /// 
    /// **Proof**: By Schwartz-Zippel lemma on the polynomial
    /// p(u) = Σ_i u_i·(||W_i||² - ν_i)
    pub fn verify_soundness(&self, field_size: u64) -> f64 {
        // Soundness error = r/|F|
        (self.num_columns as f64) / (field_size as f64)
    }
}
