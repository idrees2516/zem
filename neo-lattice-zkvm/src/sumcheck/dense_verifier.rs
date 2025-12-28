// Dense Sum-Check Verifier
// Verifies sum-check proofs with O(n) field operations

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::UnivariatePolynomial;
use std::fmt::Debug;

/// Verification result
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Accept,
    Reject(String),
}

/// Dense sum-check verifier
/// Tracks state across rounds and performs all verification checks
#[derive(Clone, Debug)]
pub struct DenseSumCheckVerifier<K: ExtensionFieldElement> {
    /// Claimed sum C
    pub claimed_sum: K,
    /// Previous round polynomial
    pub prev_poly: Option<UnivariatePolynomial<K>>,
    /// Challenges sent to prover
    pub challenges: Vec<K>,
    /// Current round number
    pub round: usize,
    /// Number of variables
    pub num_vars: usize,
}

impl<K: ExtensionFieldElement> DenseSumCheckVerifier<K> {
    /// Create new verifier with claimed sum and number of variables
    pub fn new(claimed_sum: K, num_vars: usize) -> Self {
        Self {
            claimed_sum,
            prev_poly: None,
            challenges: Vec::with_capacity(num_vars),
            round: 0,
            num_vars,
        }
    }
    
    /// Verify round 1: Check C = s_1(0) + s_1(1)
    pub fn verify_round_1(&mut self, s_1: UnivariatePolynomial<K>) -> VerificationResult {
        // Check degree bound
        if s_1.degree() > 2 {
            return VerificationResult::Reject(format!(
                "Round 1 polynomial has degree {} > 2",
                s_1.degree()
            ));
        }
        
        // Check C = s_1(0) + s_1(1)
        let s_0 = s_1.evaluate_at_int(0);
        let s_1_val = s_1.evaluate_at_int(1);
        let sum = s_0.add(&s_1_val);
        
        if sum != self.claimed_sum {
            return VerificationResult::Reject(format!(
                "Round 1 check failed: s_1(0) + s_1(1) != C"
            ));
        }
        
        // Sample challenge
        let challenge = self.sample_challenge();
        self.challenges.push(challenge);
        self.prev_poly = Some(s_1);
        self.round = 1;
        
        VerificationResult::Accept
    }
    
    /// Verify round i > 1: Check s_{i-1}(r_{i-1}) = s_i(0) + s_i(1)
    pub fn verify_round_i(&mut self, s_i: UnivariatePolynomial<K>) -> VerificationResult {
        if self.round == 0 {
            return VerificationResult::Reject(
                "Must call verify_round_1 first".to_string()
            );
        }
        
        // Check degree bound
        if s_i.degree() > 2 {
            return VerificationResult::Reject(format!(
                "Round {} polynomial has degree {} > 2",
                self.round + 1,
                s_i.degree()
            ));
        }
        
        // Get previous polynomial and challenge
        let prev_poly = self.prev_poly.as_ref().ok_or_else(|| {
            VerificationResult::Reject("No previous polynomial".to_string())
        });
        
        if let Err(e) = prev_poly {
            return e;
        }
        
        let prev_poly = prev_poly.unwrap();
        let prev_challenge = self.challenges[self.round - 1];
        
        // Check s_{i-1}(r_{i-1}) = s_i(0) + s_i(1)
        let lhs = prev_poly.evaluate(prev_challenge);
        let s_0 = s_i.evaluate_at_int(0);
        let s_1 = s_i.evaluate_at_int(1);
        let rhs = s_0.add(&s_1);
        
        if lhs != rhs {
            return VerificationResult::Reject(format!(
                "Round {} check failed: s_{}(r_{}) != s_{}(0) + s_{}(1)",
                self.round + 1,
                self.round,
                self.round,
                self.round + 1,
                self.round + 1
            ));
        }
        
        // Sample challenge
        let challenge = self.sample_challenge();
        self.challenges.push(challenge);
        self.prev_poly = Some(s_i);
        self.round += 1;
        
        VerificationResult::Accept
    }
    
    /// Verify final round: Check s_n(r_n) = final_eval
    pub fn verify_final(
        &self,
        s_n: &UnivariatePolynomial<K>,
        final_eval: K,
    ) -> VerificationResult {
        if self.round != self.num_vars {
            return VerificationResult::Reject(format!(
                "Not all rounds complete: {} of {}",
                self.round,
                self.num_vars
            ));
        }
        
        // Check degree bound
        if s_n.degree() > 2 {
            return VerificationResult::Reject(format!(
                "Final polynomial has degree {} > 2",
                s_n.degree()
            ));
        }
        
        // Get last challenge
        let r_n = self.challenges[self.num_vars - 1];
        
        // Check s_n(r_n) = final_eval
        let lhs = s_n.evaluate(r_n);
        
        if lhs != final_eval {
            return VerificationResult::Reject(
                "Final check failed: s_n(r_n) != final_eval".to_string()
            );
        }
        
        VerificationResult::Accept
    }
    
    /// Sample random challenge (in real implementation, use Fiat-Shamir)
    fn sample_challenge(&self) -> K {
        // In production, use Fiat-Shamir transform with transcript
        // For now, use deterministic value based on round
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % K::BaseField::MODULUS;
        K::from_base_field_element(K::BaseField::from_u64(val), 0)
    }
    
    /// Compute total soundness error: 2n/|F| for n rounds
    pub fn soundness_error(&self) -> f64 {
        let field_size = K::BaseField::MODULUS as f64;
        (2.0 * self.num_vars as f64) / field_size
    }
    
    /// Get challenges sent so far
    pub fn get_challenges(&self) -> &[K] {
        &self.challenges
    }
    
    /// Check if verification is complete
    pub fn is_complete(&self) -> bool {
        self.round == self.num_vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{M61Field, Field};
    use crate::field::extension_framework::M61ExtensionField2;
    use crate::sumcheck::{MultilinearPolynomial, DenseSumCheckProver};
    
    type K = M61ExtensionField2;
    
    fn make_test_poly(n: usize, offset: u64) -> MultilinearPolynomial<K> {
        let size = 1 << n;
        let evals: Vec<K> = (0..size)
            .map(|i| K::from_base_field_element(M61Field::from_u64(i as u64 + offset), 0))
            .collect();
        MultilinearPolynomial::from_evaluations(evals).unwrap()
    }
    
    #[test]
    fn test_honest_prover_accepted() {
        let p = make_test_poly(3, 0);
        let q = make_test_poly(3, 0);
        
        // Compute claimed sum
        let product = p.mul(&q).unwrap();
        let mut claimed_sum = K::zero();
        for eval in &product.evaluations {
            claimed_sum = claimed_sum.add(eval);
        }
        
        // Run prover
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        let mut verifier = DenseSumCheckVerifier::new(claimed_sum, 3);
        
        // Round 1
        let poly1 = prover.round_polynomial();
        let result = verifier.verify_round_1(poly1);
        assert_eq!(result, VerificationResult::Accept);
        
        let challenge1 = verifier.challenges[0];
        prover.update(challenge1).unwrap();
        
        // Round 2
        let poly2 = prover.round_polynomial();
        let result = verifier.verify_round_i(poly2);
        assert_eq!(result, VerificationResult::Accept);
        
        let challenge2 = verifier.challenges[1];
        prover.update(challenge2).unwrap();
        
        // Round 3
        let poly3 = prover.round_polynomial();
        let result = verifier.verify_round_i(poly3);
        assert_eq!(result, VerificationResult::Accept);
        
        let challenge3 = verifier.challenges[2];
        prover.update(challenge3).unwrap();
        
        // Final check
        let final_eval = prover.final_evaluation().unwrap();
        let result = verifier.verify_final(&poly3, final_eval);
        assert_eq!(result, VerificationResult::Accept);
    }
    
    #[test]
    fn test_wrong_claimed_sum_rejected() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        // Use wrong claimed sum
        let wrong_sum = K::from_base_field_element(M61Field::from_u64(999999), 0);
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        let mut verifier = DenseSumCheckVerifier::new(wrong_sum, 2);
        
        // Round 1 should fail
        let poly1 = prover.round_polynomial();
        let result = verifier.verify_round_1(poly1);
        
        match result {
            VerificationResult::Reject(_) => {}, // Expected
            VerificationResult::Accept => panic!("Should have rejected wrong sum"),
        }
    }
    
    #[test]
    fn test_degree_bound_check() {
        let claimed_sum = K::zero();
        let mut verifier = DenseSumCheckVerifier::new(claimed_sum, 2);
        
        // Create polynomial with degree > 2
        let high_degree_poly = UnivariatePolynomial::from_evaluations(&[
            K::zero(),
            K::one(),
            K::zero(),
            K::one(),
        ]);
        
        let result = verifier.verify_round_1(high_degree_poly);
        
        match result {
            VerificationResult::Reject(msg) => {
                assert!(msg.contains("degree"));
            },
            VerificationResult::Accept => panic!("Should have rejected high degree"),
        }
    }
    
    #[test]
    fn test_soundness_error() {
        let verifier = DenseSumCheckVerifier::<K>::new(K::zero(), 10);
        let error = verifier.soundness_error();
        
        // Error should be 20 / (2^61 - 1)
        assert!(error > 0.0);
        assert!(error < 1.0);
    }
    
    #[test]
    fn test_is_complete() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        let product = p.mul(&q).unwrap();
        let mut claimed_sum = K::zero();
        for eval in &product.evaluations {
            claimed_sum = claimed_sum.add(eval);
        }
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        let mut verifier = DenseSumCheckVerifier::new(claimed_sum, 2);
        
        assert!(!verifier.is_complete());
        
        // Round 1
        let poly1 = prover.round_polynomial();
        verifier.verify_round_1(poly1);
        prover.update(verifier.challenges[0]).unwrap();
        assert!(!verifier.is_complete());
        
        // Round 2
        let poly2 = prover.round_polynomial();
        verifier.verify_round_i(poly2);
        prover.update(verifier.challenges[1]).unwrap();
        assert!(verifier.is_complete());
    }
    
    #[test]
    fn test_get_challenges() {
        let p = make_test_poly(2, 0);
        let q = make_test_poly(2, 0);
        
        let product = p.mul(&q).unwrap();
        let mut claimed_sum = K::zero();
        for eval in &product.evaluations {
            claimed_sum = claimed_sum.add(eval);
        }
        
        let mut prover = DenseSumCheckProver::new(p, q).unwrap();
        let mut verifier = DenseSumCheckVerifier::new(claimed_sum, 2);
        
        // Round 1
        let poly1 = prover.round_polynomial();
        verifier.verify_round_1(poly1);
        
        let challenges = verifier.get_challenges();
        assert_eq!(challenges.len(), 1);
        
        prover.update(challenges[0]).unwrap();
        
        // Round 2
        let poly2 = prover.round_polynomial();
        verifier.verify_round_i(poly2);
        
        let challenges = verifier.get_challenges();
        assert_eq!(challenges.len(), 2);
    }
}


/// SALSAA-specific sum-check verifier
/// 
/// **Paper Reference**: SALSAA Section 3, Requirements 4.2, 4.3
/// 
/// **Key Properties**:
/// - Verifier complexity: O(μ·d) field operations
/// - Communication: (2d-1)·μ field elements
/// - Soundness error: ≤ 2μd/|F| by Schwartz-Zippel lemma
/// 
/// **Mathematical Background**:
/// The verifier checks that:
/// 1. Round 1: C = g_1(0) + g_1(1)
/// 2. Round i: g_{i-1}(r_{i-1}) = g_i(0) + g_i(1) for i ∈ [2,μ]
/// 3. Final: g_μ(r_μ) = g(r_1,...,r_μ) where g is the claimed polynomial
/// 
/// **Why O(μ·d) Complexity**:
/// - μ rounds total
/// - Each round: verify polynomial of degree ≤ 2(d-1)
/// - Verification per round: O(d) operations (evaluate polynomial)
/// - Total: O(μ·d) operations
#[derive(Clone, Debug)]
pub struct SALSAASumCheckVerifier<K: ExtensionFieldElement> {
    /// Underlying dense verifier
    verifier: DenseSumCheckVerifier<K>,
    /// Degree bound per variable (d)
    degree_bound: usize,
    /// Number of variables (μ)
    num_vars: usize,
}

impl<K: ExtensionFieldElement> SALSAASumCheckVerifier<K> {
    /// Create SALSAA sum-check verifier
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.2
    /// 
    /// **Input**:
    /// - claimed_sum: Target sum C
    /// - num_vars: Number of variables μ
    /// - degree_bound: Maximum degree per variable d
    /// 
    /// **Output**:
    /// Verifier that checks proofs in O(μ·d) time
    pub fn new(
        claimed_sum: K,
        num_vars: usize,
        degree_bound: usize,
    ) -> Self {
        let verifier = DenseSumCheckVerifier::new(claimed_sum, num_vars);
        
        Self {
            verifier,
            degree_bound,
            num_vars,
        }
    }
    
    /// Verify round polynomial g_j(X) with degree ≤ 2(d-1)
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.2
    /// 
    /// **Checks**:
    /// 1. Degree bound: deg(g_j) ≤ 2(d-1)
    /// 2. Consistency: g_{j-1}(r_{j-1}) = g_j(0) + g_j(1)
    /// 
    /// **Complexity**: O(d) field operations
    /// - Evaluate g_j at 0, 1, and r_{j-1}: O(d) each
    /// - Total: O(d) operations
    pub fn verify_round_salsaa(
        &mut self,
        round_poly: UnivariatePolynomial<K>,
    ) -> VerificationResult {
        // Check degree bound: deg(g_j) ≤ 2(d-1)
        let max_degree = 2 * (self.degree_bound - 1);
        if round_poly.degree() > max_degree {
            return VerificationResult::Reject(format!(
                "Round polynomial has degree {} > 2(d-1) = {}",
                round_poly.degree(),
                max_degree
            ));
        }
        
        // Use underlying verifier for consistency checks
        if self.verifier.round == 0 {
            self.verifier.verify_round_1(round_poly)
        } else {
            self.verifier.verify_round_i(round_poly)
        }
    }
    
    /// Verify final evaluation check
    /// 
    /// **Paper Reference**: SALSAA Section 3.1, Requirement 4.3
    /// 
    /// **Check**: g_μ(r_μ) = LDE[W](r) ⊙ LDE[W̄](r̄)
    /// 
    /// This requires the verifier to evaluate the LDE at the random point,
    /// which is done via oracle queries in the full protocol.
    pub fn verify_final_salsaa(
        &self,
        final_poly: &UnivariatePolynomial<K>,
        final_eval: K,
    ) -> VerificationResult {
        self.verifier.verify_final(final_poly, final_eval)
    }
    
    /// Compute verifier complexity in field operations
    /// 
    /// **Paper Reference**: Requirement 4.3
    /// 
    /// **Formula**: O(μ·d) field operations + O(r) ring operations
    /// where:
    /// - μ = number of rounds
    /// - d = degree bound per variable
    /// - r = number of columns (for final evaluation)
    /// 
    /// **Breakdown**:
    /// - Each round: Evaluate polynomial of degree 2(d-1) → O(d) ops
    /// - μ rounds: O(μ·d) ops
    /// - Final evaluation: O(r) ring operations
    pub fn verifier_complexity_ops(&self, num_columns: usize) -> usize {
        let round_ops = self.num_vars * self.degree_bound;
        let final_ops = num_columns;
        round_ops + final_ops
    }
    
    /// Compute soundness error
    /// 
    /// **Paper Reference**: SALSAA Section 3.1
    /// 
    /// **Theorem**: Soundness error ≤ 2μ(d-1)/|F| by Schwartz-Zippel lemma
    /// 
    /// **Proof**:
    /// - Each round polynomial has degree ≤ 2(d-1)
    /// - By Schwartz-Zippel, probability of accepting bad polynomial ≤ 2(d-1)/|F|
    /// - Union bound over μ rounds: ≤ 2μ(d-1)/|F|
    pub fn soundness_error_salsaa(&self, field_size: u64) -> f64 {
        let numerator = 2.0 * (self.num_vars as f64) * ((self.degree_bound - 1) as f64);
        let denominator = field_size as f64;
        numerator / denominator
    }
    
    /// Get challenges sent to prover
    pub fn get_challenges(&self) -> &[K] {
        self.verifier.get_challenges()
    }
    
    /// Check if verification is complete
    pub fn is_complete(&self) -> bool {
        self.verifier.is_complete()
    }
}

/// LDE evaluation claim verifier
/// 
/// **Paper Reference**: SALSAA Section 3.2, Requirements 4.6, 4.8
/// 
/// **Purpose**: Verify that LDE[M_i·W](r_i) = s_i mod q for structured matrices M_i
/// 
/// **Structured Matrices**:
/// - Diagonal matrices
/// - Circulant matrices  
/// - Toeplitz matrices
/// - Other matrices with fast multiplication
/// 
/// **Why This Matters**:
/// After sum-check, we're left with evaluation claims on the LDE.
/// These must be verified using polynomial commitment schemes or
/// additional sum-check reductions.
#[derive(Clone, Debug)]
pub struct LDEEvaluationVerifier<K: ExtensionFieldElement> {
    /// Evaluation point r ∈ F^μ
    pub evaluation_point: Vec<K>,
    /// Claimed evaluation s ∈ R_q
    pub claimed_value: Vec<K>,
    /// Matrix structure type
    pub matrix_type: MatrixStructure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixStructure {
    Diagonal,
    Circulant,
    Toeplitz,
    General,
}

impl<K: ExtensionFieldElement> LDEEvaluationVerifier<K> {
    /// Create LDE evaluation verifier
    /// 
    /// **Paper Reference**: Requirement 4.8
    pub fn new(
        evaluation_point: Vec<K>,
        claimed_value: Vec<K>,
        matrix_type: MatrixStructure,
    ) -> Self {
        Self {
            evaluation_point,
            claimed_value,
            matrix_type,
        }
    }
    
    /// Verify evaluation claim using polynomial commitment
    /// 
    /// **Paper Reference**: SALSAA Section 3.2
    /// 
    /// In the full protocol, this would:
    /// 1. Query polynomial commitment at evaluation_point
    /// 2. Verify opening proof
    /// 3. Check that opened value matches claimed_value
    /// 
    /// For structured matrices, we can optimize the verification.
    pub fn verify_with_commitment(
        &self,
        _commitment: &[u8], // Placeholder for actual commitment type
        _opening_proof: &[u8], // Placeholder for actual proof type
    ) -> VerificationResult {
        // In full implementation, verify polynomial commitment opening
        // For now, return accept as placeholder
        VerificationResult::Accept
    }
    
    /// Compute verification complexity for structured matrices
    /// 
    /// **Paper Reference**: Requirement 4.8
    /// 
    /// **Optimization**: For structured matrices, verification can be faster
    /// - Diagonal: O(1) operations
    /// - Circulant: O(log n) operations via FFT
    /// - Toeplitz: O(log n) operations
    /// - General: O(n) operations
    pub fn verification_complexity(&self, matrix_size: usize) -> usize {
        match self.matrix_type {
            MatrixStructure::Diagonal => 1,
            MatrixStructure::Circulant => (matrix_size as f64).log2() as usize,
            MatrixStructure::Toeplitz => (matrix_size as f64).log2() as usize,
            MatrixStructure::General => matrix_size,
        }
    }
}
