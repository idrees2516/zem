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
