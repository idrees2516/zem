// Task 3.3: Less-Than Predicate for Twist
// LT(j',j) = 1 iff j' < j

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::MultilinearPolynomial;

/// Less-than predicate for time ordering
pub struct LessThanPredicate;

impl LessThanPredicate {
    /// Create MLE of LT(j',j) = 1 iff j' < j
    /// 
    /// Algorithm:
    /// - Create evaluation table of size 2^{2·log T}
    /// - For each (j', j) pair: set LT(j',j) = 1 if j' < j as integers, else 0
    pub fn create_mle<K: ExtensionFieldElement>(
        log_t: usize,
    ) -> Result<MultilinearPolynomial<K>, String> {
        let t = 1 << log_t;
        let size = t * t;  // 2^{2·log T}
        
        let mut evaluations = Vec::with_capacity(size);
        
        // For each (j', j) pair
        for idx in 0..size {
            let j_prime = idx >> log_t;  // First log_t bits
            let j = idx & ((1 << log_t) - 1);  // Last log_t bits
            
            // LT(j',j) = 1 iff j' < j
            let value = if j_prime < j {
                K::one()
            } else {
                K::zero()
            };
            
            evaluations.push(value);
        }
        
        MultilinearPolynomial::from_evaluations(evaluations)
    }
    
    /// Evaluate LT̃(r',r) at random points
    /// Verifier can compute this in O(log T) time
    /// 
    /// Algorithm:
    /// result = 0, prefix_prod = 1
    /// For i=0 to n-1:
    ///   term = prefix_prod·(1-r'_i)·r_i  (bit i is first difference with r'_i < r_i)
    ///   result += term
    ///   prefix_prod *= r'_i·r_i + (1-r'_i)·(1-r_i)  (bits 0..i-1 equal)
    /// Return result
    pub fn evaluate_less_than<K: ExtensionFieldElement>(
        r_prime: &[K],
        r: &[K],
    ) -> Result<K, String> {
        if r_prime.len() != r.len() {
            return Err("Dimension mismatch".to_string());
        }
        
        let n = r.len();
        let mut result = K::zero();
        let mut prefix_prod = K::one();
        
        for i in 0..n {
            // Contribution when bit i is first difference (r'_i < r_i)
            // This means: r'_i = 0, r_i = 1, and all previous bits equal
            let one_minus_r_prime_i = K::one().sub(&r_prime[i]);
            let term = prefix_prod.mul(&one_minus_r_prime_i).mul(&r[i]);
            result = result.add(&term);
            
            // Update prefix: all bits 0..i equal
            // Equal when both 0 or both 1:
            // r'_i·r_i (both 1) + (1-r'_i)·(1-r_i) (both 0)
            let both_one = r_prime[i].mul(&r[i]);
            let both_zero = one_minus_r_prime_i.mul(&K::one().sub(&r[i]));
            prefix_prod = prefix_prod.mul(&both_one.add(&both_zero));
        }
        
        Ok(result)
    }
}

/// Less-than MLE wrapper
pub struct LessThanMLE<K: ExtensionFieldElement> {
    pub mle: MultilinearPolynomial<K>,
    pub log_t: usize,
}

impl<K: ExtensionFieldElement> LessThanMLE<K> {
    pub fn new(log_t: usize) -> Result<Self, String> {
        let mle = LessThanPredicate::create_mle(log_t)?;
        Ok(Self { mle, log_t })
    }
    
    /// Evaluate at (j', j) on Boolean hypercube
    pub fn eval_at_boolean(&self, j_prime: usize, j: usize) -> Result<K, String> {
        let t = 1 << self.log_t;
        if j_prime >= t || j >= t {
            return Err("Index out of bounds".to_string());
        }
        
        let idx = (j_prime << self.log_t) | j;
        Ok(self.mle.evaluations[idx])
    }
    
    /// Evaluate at random point (r', r)
    pub fn eval_at_random(&self, r_prime: &[K], r: &[K]) -> Result<K, String> {
        if r_prime.len() != self.log_t || r.len() != self.log_t {
            return Err("Dimension mismatch".to_string());
        }
        
        LessThanPredicate::evaluate_less_than(r_prime, r)
    }
}
