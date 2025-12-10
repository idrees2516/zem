// Task 3.8: Virtual Memory Values
// Val(k,j) computed via sum-check, never explicitly committed

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::MultilinearPolynomial;
use crate::shout::virtual_polynomials::{VirtualPolynomial, SumCheckClaim};
use crate::twist::{ValEvaluationSumCheck, LessThanPredicate};

/// Virtual memory values for Twist protocol
/// Val(k,j) = Σ_{j'<j} Inc(k,j')
/// Never explicitly committed - computed via sum-check
pub struct VirtualMemoryValues<K: ExtensionFieldElement> {
    /// Increment MLE: Inc(k,j)
    pub increment_mle: MultilinearPolynomial<K>,
    
    /// Memory size K
    pub memory_size: usize,
    
    /// Number of cycles T
    pub num_cycles: usize,
}

impl<K: ExtensionFieldElement> VirtualMemoryValues<K> {
    pub fn new(
        increment_mle: MultilinearPolynomial<K>,
        memory_size: usize,
        num_cycles: usize,
    ) -> Result<Self, String> {
        let log_k = (memory_size as f64).log2() as usize;
        let log_t = (num_cycles as f64).log2() as usize;
        let expected_size = 1 << (log_k + log_t);
        
        if increment_mle.evaluations.len() != expected_size {
            return Err(format!(
                "Increment MLE size {} doesn't match K×T = {}",
                increment_mle.evaluations.len(),
                expected_size
            ));
        }
        
        Ok(Self {
            increment_mle,
            memory_size,
            num_cycles,
        })
    }
    
    /// Evaluate Val(raddress, rcycle) via sum-check
    /// 
    /// Algorithm:
    /// - Split point into raddress and rcycle
    /// - Apply sum-check: Val(raddress,rcycle) = Σ_{j'} Inc(raddress,j')·LT(j',rcycle)
    /// - Return result from sum-check
    pub fn evaluate_at_point(&self, point: &[K]) -> Result<K, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        if point.len() != log_k + log_t {
            return Err(format!(
                "Point dimension {} doesn't match log K + log T = {}",
                point.len(),
                log_k + log_t
            ));
        }
        
        // Split point into (raddress, rcycle)
        let raddress = &point[..log_k];
        let rcycle = &point[log_k..];
        
        // Compute Val(raddress, rcycle) via sum-check
        let val_eval = ValEvaluationSumCheck::new(log_t);
        let proof = val_eval.compute_val(raddress, rcycle, &self.increment_mle)?;
        
        Ok(proof.val_at_point)
    }
    
    /// Evaluate Val(k, j) on Boolean hypercube
    pub fn evaluate_at_boolean(&self, k: usize, j: usize) -> Result<K, String> {
        if k >= self.memory_size || j >= self.num_cycles {
            return Err("Index out of bounds".to_string());
        }
        
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        // Convert to field elements
        let k_bits: Vec<K> = (0..log_k)
            .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
            .collect();
        let j_bits: Vec<K> = (0..log_t)
            .map(|i| if (j >> i) & 1 == 1 { K::one() } else { K::zero() })
            .collect();
        
        let mut point = k_bits;
        point.extend_from_slice(&j_bits);
        
        self.evaluate_at_point(&point)
    }
    
    /// Compute Val directly from increments (for verification)
    /// Val(k,j) = Σ_{j'<j} Inc(k,j')
    pub fn compute_val_direct(&self, k: usize, j: usize) -> Result<K, String> {
        if k >= self.memory_size || j >= self.num_cycles {
            return Err("Index out of bounds".to_string());
        }
        
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        let mut val = K::zero();
        
        // Sum over all j' < j
        for j_prime in 0..j {
            let k_bits: Vec<K> = (0..log_k)
                .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            let j_prime_bits: Vec<K> = (0..log_t)
                .map(|i| if (j_prime >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            
            let mut point = k_bits;
            point.extend_from_slice(&j_prime_bits);
            
            let inc_val = self.increment_mle.evaluate(&point)?;
            val = val.add(&inc_val);
        }
        
        Ok(val)
    }
}

impl<K: ExtensionFieldElement> VirtualPolynomial<K> for VirtualMemoryValues<K> {
    fn evaluate_via_sumcheck(&self, point: &[K]) -> Result<K, String> {
        self.evaluate_at_point(point)
    }
    
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K> {
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        SumCheckClaim {
            claimed_value: K::zero(),  // Will be computed
            evaluation_point: point.to_vec(),
            num_variables: log_t,
        }
    }
}

/// Comparison: Virtual vs Explicit Val Commitment
/// 
/// EXPLICIT COMMITMENT:
/// - Commit to Val ∈ F^{K×T} explicitly
/// - Commitment size: K·T field elements
/// - Prover time: O(K·T) for commitment
/// - Verifier time: O(1) for evaluation query
/// - Total cost: O(K·T)
/// 
/// VIRTUAL POLYNOMIAL:
/// - Never commit to Val
/// - Commitment size: T (only increments)
/// - Prover time: O(T) for increment commitment + O(T·log T) for sum-check
/// - Verifier time: O(log T) for sum-check verification
/// - Total cost: O(T·log T)
/// 
/// SAVINGS:
/// Virtual wins when: T·log T < K·T
/// Simplifies to: log T < K
/// For typical zkVM: K=32, T=2^20 → 20 < 32 ✓
/// Savings: K·T / (T·log T) = K / log T = 32/20 = 1.6x
/// 
/// But the real win is avoiding K·T commitments:
/// - For K=32, T=2^20: 32·2^20 = 33,554,432 vs 2^20 = 1,048,576
/// - 32x reduction in commitment size!
