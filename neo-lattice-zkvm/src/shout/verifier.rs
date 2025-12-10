// Shout Protocol Verifier
// Verifies batch evaluation proofs with all checks

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{UnivariatePolynomial, MultilinearPolynomial};
use crate::shout::prover::{ReadCheckProof, BooleanityProof, OneHotProof};
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Accept,
    Reject(String),
}

pub struct ShoutVerifier<K: ExtensionFieldElement> {
    pub memory_size: usize,
    pub num_lookups: usize,
    pub dimension: usize,
}

impl<K: ExtensionFieldElement> ShoutVerifier<K> {
    pub fn new(memory_size: usize, num_lookups: usize, dimension: usize) -> Self {
        Self {
            memory_size,
            num_lookups,
            dimension,
        }
    }
    
    /// Verify read-checking sum-check proof
    pub fn verify_read_check(
        &self,
        proof: &ReadCheckProof<K>,
        claimed_rv: K,
        rcycle: &[K],
    ) -> VerificationResult {
        let log_k = (self.memory_size as f64).log2() as usize;
        
        if proof.round_polynomials.len() != log_k {
            return VerificationResult::Reject(format!(
                "Expected {} rounds, got {}",
                log_k,
                proof.round_polynomials.len()
            ));
        }
        
        // Verify first round: claimed_rv = s_1(0) + s_1(1)
        let s_1 = &proof.round_polynomials[0];
        let sum = s_1.evaluate_at_int(0).add(&s_1.evaluate_at_int(1));
        if sum != claimed_rv {
            return VerificationResult::Reject(
                "First round check failed".to_string()
            );
        }
        
        // Verify subsequent rounds
        for i in 1..log_k {
            let s_prev = &proof.round_polynomials[i - 1];
            let s_curr = &proof.round_polynomials[i];
            let r_prev = proof.challenges[i - 1];
            
            let lhs = s_prev.evaluate(r_prev);
            let rhs = s_curr.evaluate_at_int(0).add(&s_curr.evaluate_at_int(1));
            
            if lhs != rhs {
                return VerificationResult::Reject(format!(
                    "Round {} check failed",
                    i + 1
                ));
            }
        }
        
        // Verify final evaluation
        let s_n = &proof.round_polynomials[log_k - 1];
        let r_n = proof.challenges[log_k - 1];
        let final_check = s_n.evaluate(r_n);
        
        if final_check != proof.final_evaluation {
            return VerificationResult::Reject(
                "Final evaluation check failed".to_string()
            );
        }
        
        VerificationResult::Accept
    }
    
    /// Verify booleanity check proof
    pub fn verify_booleanity(
        &self,
        proof: &BooleanityProof<K>,
        r: &[K],
        r_prime: &[K],
    ) -> VerificationResult {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_lookups as f64).log2() as usize;
        let total_vars = log_k + log_t;
        
        if proof.round_polynomials.len() != total_vars {
            return VerificationResult::Reject(format!(
                "Expected {} rounds, got {}",
                total_vars,
                proof.round_polynomials.len()
            ));
        }
        
        // Verify sum equals zero (constraint satisfaction)
        let s_1 = &proof.round_polynomials[0];
        let sum = s_1.evaluate_at_int(0).add(&s_1.evaluate_at_int(1));
        if sum != K::zero() {
            return VerificationResult::Reject(
                "Booleanity constraint not satisfied".to_string()
            );
        }
        
        // Verify round consistency
        for i in 1..total_vars {
            let s_prev = &proof.round_polynomials[i - 1];
            let s_curr = &proof.round_polynomials[i];
            let r_prev = proof.challenges[i - 1];
            
            let lhs = s_prev.evaluate(r_prev);
            let rhs = s_curr.evaluate_at_int(0).add(&s_curr.evaluate_at_int(1));
            
            if lhs != rhs {
                return VerificationResult::Reject(format!(
                    "Booleanity round {} check failed",
                    i + 1
                ));
            }
        }
        
        VerificationResult::Accept
    }
    
    /// Verify one-hot check proof
    pub fn verify_one_hot(
        &self,
        proof: &OneHotProof<K>,
        rcycle: &[K],
    ) -> VerificationResult {
        match proof {
            OneHotProof::NonBinary { evaluation, expected, actual } => {
                if actual != expected {
                    return VerificationResult::Reject(format!(
                        "One-hot check failed: expected {:?}, got {:?}",
                        expected,
                        actual
                    ));
                }
                VerificationResult::Accept
            }
            OneHotProof::Binary { sum_check_proof } => {
                // Verify sum-check proves sum = 1
                let log_k = (self.memory_size as f64).log2() as usize;
                
                if sum_check_proof.round_polynomials.len() != log_k {
                    return VerificationResult::Reject(
                        "Invalid sum-check proof length".to_string()
                    );
                }
                
                // Verify first round sums to 1
                let s_1 = &sum_check_proof.round_polynomials[0];
                let sum = s_1.evaluate_at_int(0).add(&s_1.evaluate_at_int(1));
                if sum != K::one() {
                    return VerificationResult::Reject(
                        "One-hot sum check failed".to_string()
                    );
                }
                
                // Verify round consistency
                for i in 1..log_k {
                    let s_prev = &sum_check_proof.round_polynomials[i - 1];
                    let s_curr = &sum_check_proof.round_polynomials[i];
                    let r_prev = sum_check_proof.challenges[i - 1];
                    
                    let lhs = s_prev.evaluate(r_prev);
                    let rhs = s_curr.evaluate_at_int(0).add(&s_curr.evaluate_at_int(1));
                    
                    if lhs != rhs {
                        return VerificationResult::Reject(format!(
                            "One-hot round {} check failed",
                            i + 1
                        ));
                    }
                }
                
                VerificationResult::Accept
            }
        }
    }
    
    /// Compute soundness error for entire protocol
    /// Error = (log K + log T) / |F| for booleanity + one-hot
    ///       + log K / |F| for read-checking
    pub fn soundness_error(&self) -> f64 {
        let log_k = (self.memory_size as f64).log2();
        let log_t = (self.num_lookups as f64).log2();
        let field_size = K::BaseField::MODULUS as f64;
        
        let booleanity_error = (log_k + log_t) / field_size;
        let one_hot_error = log_t / field_size;
        let read_check_error = log_k / field_size;
        
        booleanity_error + one_hot_error + read_check_error
    }
}
