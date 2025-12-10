// Task 2.7: Virtual Read Values for Shout
// Virtual polynomial that avoids explicit commitment to read values

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use std::fmt::Debug;

/// Virtual polynomial trait
/// Represents polynomials not directly committed but computed via sum-check
pub trait VirtualPolynomial<K: ExtensionFieldElement> {
    /// Evaluate via sum-check at given point
    fn evaluate_via_sumcheck(&self, point: &[K]) -> Result<K, String>;
    
    /// Generate sum-check claim for evaluation
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K>;
}

/// Sum-check claim for virtual polynomial evaluation
#[derive(Clone, Debug)]
pub struct SumCheckClaim<K: ExtensionFieldElement> {
    pub claimed_value: K,
    pub evaluation_point: Vec<K>,
    pub num_variables: usize,
}

/// Task 2.7: Virtual read values
/// rv(rcycle) = Σ_k ra(k,rcycle)·Val(k)
/// Never explicitly committed - always computed via sum-check
/// Saves commitment costs: no commitment to T read values
pub struct VirtualReadValues<K: ExtensionFieldElement> {
    /// Access matrix MLE: ra(k,j)
    pub access_mle: MultilinearPolynomial<K>,
    
    /// Lookup table MLE: Val(k)
    pub table_mle: MultilinearPolynomial<K>,
    
    /// Memory size K
    pub memory_size: usize,
    
    /// Number of lookups T
    pub num_lookups: usize,
}

impl<K: ExtensionFieldElement> VirtualReadValues<K> {
    pub fn new(
        access_mle: MultilinearPolynomial<K>,
        table_mle: MultilinearPolynomial<K>,
        memory_size: usize,
        num_lookups: usize,
    ) -> Result<Self, String> {
        // Verify dimensions
        let expected_access_size = memory_size * num_lookups;
        if access_mle.evaluations.len() != expected_access_size {
            return Err(format!(
                "Access MLE size {} doesn't match K×T = {}",
                access_mle.evaluations.len(),
                expected_access_size
            ));
        }
        
        if table_mle.evaluations.len() != memory_size {
            return Err(format!(
                "Table MLE size {} doesn't match K = {}",
                table_mle.evaluations.len(),
                memory_size
            ));
        }
        
        Ok(Self {
            access_mle,
            table_mle,
            memory_size,
            num_lookups,
        })
    }
    
    /// Evaluate rv(rcycle) via sum-check
    /// Algorithm:
    /// 1. Apply sum-check over k ∈ {0,1}^{log K}
    /// 2. Each round: compute s_i(X) = Σ_{x'} ra(r_1,...,r_{i-1},X,x',rcycle)·Val(r_1,...,r_{i-1},X,x')
    /// 3. Final: evaluate ra(raddress,rcycle) from commitment, Val(raddress) by verifier
    pub fn evaluate_at_cycle(&self, rcycle: &[K]) -> Result<VirtualEvaluation<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_lookups as f64).log2() as usize;
        
        if rcycle.len() != log_t {
            return Err(format!(
                "rcycle dimension {} doesn't match log T = {}",
                rcycle.len(),
                log_t
            ));
        }
        
        // Initialize: compute ra(k, rcycle) and Val(k) for all k
        let mut ra_at_rcycle = Vec::with_capacity(self.memory_size);
        
        for k in 0..self.memory_size {
            // Extract ra(k, rcycle) from access_mle
            // access_mle is structured as ra(k,j) where index = k * T + j
            let ra_val = self.eval_ra_at_k_rcycle(k, rcycle)?;
            ra_at_rcycle.push(ra_val);
        }
        
        let val_evals = self.table_mle.evaluations.clone();
        
        // Run sum-check
        let mut round_polynomials = Vec::with_capacity(log_k);
        let mut challenges = Vec::new();
        
        let mut current_ra = ra_at_rcycle;
        let mut current_val = val_evals;
        
        for round in 0..log_k {
            // Compute round polynomial
            let round_poly = self.compute_round_poly(&current_ra, &current_val);
            round_polynomials.push(round_poly.clone());
            
            // Sample challenge (Fiat-Shamir in production)
            let challenge = self.sample_challenge(round);
            challenges.push(challenge);
            
            // Update arrays
            current_ra = self.partial_eval(&current_ra, challenge);
            current_val = self.partial_eval(&current_val, challenge);
        }
        
        // Final evaluation
        let ra_final = if !current_ra.is_empty() { current_ra[0] } else { K::zero() };
        let val_final = if !current_val.is_empty() { current_val[0] } else { K::zero() };
        let final_eval = ra_final.mul(&val_final);
        
        Ok(VirtualEvaluation {
            value: final_eval,
            round_polynomials,
            challenges,
            ra_at_raddress: ra_final,
            val_at_raddress: val_final,
        })
    }
    
    // Helper: evaluate ra(k, rcycle) from access_mle
    fn eval_ra_at_k_rcycle(&self, k: usize, rcycle: &[K]) -> Result<K, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_lookups as f64).log2() as usize;
        
        // Convert k to bits
        let k_bits: Vec<K> = (0..log_k)
            .map(|i| {
                if (k >> i) & 1 == 1 {
                    K::one()
                } else {
                    K::zero()
                }
            })
            .collect();
        
        // Evaluation point: [k_bits, rcycle]
        let mut eval_point = k_bits;
        eval_point.extend_from_slice(rcycle);
        
        self.access_mle.evaluate(&eval_point)
    }
    
    fn compute_round_poly(&self, ra_evals: &[K], val_evals: &[K]) -> UnivariatePolynomial<K> {
        let half = ra_evals.len() / 2;
        
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            let ra_0 = ra_evals[i];
            let ra_1 = ra_evals[i + half];
            let val_0 = val_evals[i];
            let val_1 = val_evals[i + half];
            
            s_0 = s_0.add(&ra_0.mul(&val_0));
            s_1 = s_1.add(&ra_1.mul(&val_1));
            
            // Extrapolate to X=2
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let ra_2 = two.mul(&ra_1).sub(&ra_0);
            let val_2 = two.mul(&val_1).sub(&val_0);
            s_2 = s_2.add(&ra_2.mul(&val_2));
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    fn partial_eval(&self, evals: &[K], challenge: K) -> Vec<K> {
        let half = evals.len() / 2;
        let mut result = Vec::with_capacity(half);
        
        let one_minus_r = K::one().sub(&challenge);
        
        for i in 0..half {
            let new_val = one_minus_r.mul(&evals[i])
                .add(&challenge.mul(&evals[i + half]));
            result.push(new_val);
        }
        
        result
    }
    
    fn sample_challenge(&self, round: usize) -> K {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % K::BaseField::MODULUS;
        K::from_base_field_element(K::BaseField::from_u64(val), 0)
    }
}

impl<K: ExtensionFieldElement> VirtualPolynomial<K> for VirtualReadValues<K> {
    fn evaluate_via_sumcheck(&self, point: &[K]) -> Result<K, String> {
        let eval = self.evaluate_at_cycle(point)?;
        Ok(eval.value)
    }
    
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K> {
        let log_k = (self.memory_size as f64).log2() as usize;
        
        SumCheckClaim {
            claimed_value: K::zero(), // Will be computed
            evaluation_point: point.to_vec(),
            num_variables: log_k,
        }
    }
}

/// Result of virtual evaluation
#[derive(Clone, Debug)]
pub struct VirtualEvaluation<K: ExtensionFieldElement> {
    /// Computed value rv(rcycle)
    pub value: K,
    
    /// Sum-check round polynomials
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    
    /// Challenges used
    pub challenges: Vec<K>,
    
    /// Final ra evaluation at random point
    pub ra_at_raddress: K,
    
    /// Final Val evaluation at random point
    pub val_at_raddress: K,
}

/// Comparison: Virtual vs Explicit Commitment
/// 
/// EXPLICIT COMMITMENT:
/// - Commit to rv ∈ F^T explicitly
/// - Commitment size: T field elements
/// - Prover time: O(T) for commitment
/// - Verifier time: O(1) for evaluation query
/// 
/// VIRTUAL POLYNOMIAL:
/// - Never commit to rv
/// - Commitment size: 0 (only commit to ra)
/// - Prover time: O(K + T·log K) for sum-check
/// - Verifier time: O(log K) for sum-check verification
/// 
/// TRADE-OFF:
/// - Virtual saves commitment costs (crucial for large T)
/// - Virtual adds sum-check rounds (log K rounds)
/// - For K << T: virtual is much better
/// - For K >> T: explicit might be competitive
/// 
/// TYPICAL PARAMETERS:
/// - zkVM: K=32 (registers), T=2^20 (cycles) → virtual wins massively
/// - Lookup tables: K=2^16, T=2^20 → virtual still better
/// - Small tables: K=256, T=100 → explicit might be simpler
