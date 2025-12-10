// Task 4.3: Virtual Write Values
// wv(j) = Σ_k wa(k,j)·(Val(k,j) + Inc(j))

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use crate::virtual_poly::framework::{VirtualPolyTrait, VirtualEvaluation, VirtualProof};
use crate::shout::virtual_polynomials::SumCheckClaim;
use crate::twist::ValEvaluationSumCheck;
use std::collections::HashMap;

/// Virtual write values
/// wv(j) = Σ_k wa(k,j)·(Val(k,j) + Inc(j))
/// Never committed - computed via sum-check
pub struct VirtualWriteValues<K: ExtensionFieldElement> {
    /// Write address MLE: wa(k,j)
    pub write_address_mle: MultilinearPolynomial<K>,
    
    /// Increment MLE: Inc(k,j)
    pub increment_mle: MultilinearPolynomial<K>,
    
    /// Memory size K
    pub memory_size: usize,
    
    /// Number of cycles T
    pub num_cycles: usize,
}

impl<K: ExtensionFieldElement> VirtualWriteValues<K> {
    pub fn new(
        write_address_mle: MultilinearPolynomial<K>,
        increment_mle: MultilinearPolynomial<K>,
        memory_size: usize,
        num_cycles: usize,
    ) -> Result<Self, String> {
        let log_k = (memory_size as f64).log2() as usize;
        let log_t = (num_cycles as f64).log2() as usize;
        let expected_size = 1 << (log_k + log_t);
        
        if write_address_mle.evaluations.len() != expected_size {
            return Err("Write address MLE size mismatch".to_string());
        }
        
        if increment_mle.evaluations.len() != expected_size {
            return Err("Increment MLE size mismatch".to_string());
        }
        
        Ok(Self {
            write_address_mle,
            increment_mle,
            memory_size,
            num_cycles,
        })
    }
    
    /// Evaluate wv(j) via sum-check
    /// 
    /// Algorithm:
    /// 1. Apply sum-check over k ∈ {0,1}^{log K}
    /// 2. For each k: compute wa(k,j)·(Val(k,j) + Inc(j))
    /// 3. Val(k,j) itself is virtual, computed via increment aggregation
    /// 4. Sum over all k
    pub fn evaluate_at_cycle(&self, j_point: &[K]) -> Result<VirtualEvaluation<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        if j_point.len() != log_t {
            return Err("j_point dimension mismatch".to_string());
        }
        
        // Compute wa(k, j) and Val(k, j) + Inc(j) for all k
        let val_eval = ValEvaluationSumCheck::new(log_t);
        
        let mut wa_at_j = Vec::with_capacity(self.memory_size);
        let mut val_plus_inc = Vec::with_capacity(self.memory_size);
        
        for k in 0..self.memory_size {
            let k_bits: Vec<K> = (0..log_k)
                .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            
            // Evaluate wa(k, j)
            let mut wa_point = k_bits.clone();
            wa_point.extend_from_slice(j_point);
            let wa_val = self.write_address_mle.evaluate(&wa_point)?;
            wa_at_j.push(wa_val);
            
            // Compute Val(k, j) via sum-check
            let val_proof = val_eval.compute_val(&k_bits, j_point, &self.increment_mle)?;
            let val_kj = val_proof.val_at_point;
            
            // Get Inc(j) - same for all k
            let j_bits: Vec<K> = (0..log_t)
                .map(|i| if (j_point.len() > i && j_point[i] == K::one()) { K::one() } else { K::zero() })
                .collect();
            
            let mut inc_point = k_bits;
            inc_point.extend_from_slice(&j_bits);
            let inc_j = self.increment_mle.evaluate(&inc_point)?;
            
            // Val(k,j) + Inc(j)
            val_plus_inc.push(val_kj.add(&inc_j));
        }
        
        // Run sum-check: Σ_k wa(k,j)·(Val(k,j) + Inc(j))
        let mut round_polynomials = Vec::with_capacity(log_k);
        let mut challenges = Vec::new();
        
        let mut current_wa = wa_at_j;
        let mut current_val_inc = val_plus_inc;
        
        for _ in 0..log_k {
            let round_poly = self.compute_round_poly(&current_wa, &current_val_inc);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge();
            challenges.push(challenge);
            
            current_wa = self.partial_eval(&current_wa, challenge);
            current_val_inc = self.partial_eval(&current_val_inc, challenge);
        }
        
        let final_wa = if !current_wa.is_empty() { current_wa[0] } else { K::zero() };
        let final_val_inc = if !current_val_inc.is_empty() { current_val_inc[0] } else { K::zero() };
        let value = final_wa.mul(&final_val_inc);
        
        Ok(VirtualEvaluation {
            value,
            proof: VirtualProof {
                round_polynomials,
                challenges,
                final_evals: HashMap::new(),
            },
            intermediates: HashMap::new(),
        })
    }
    
    fn compute_round_poly(&self, wa_vals: &[K], val_inc_vals: &[K]) -> UnivariatePolynomial<K> {
        let half = wa_vals.len() / 2;
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            s_0 = s_0.add(&wa_vals[i].mul(&val_inc_vals[i]));
            s_1 = s_1.add(&wa_vals[i + half].mul(&val_inc_vals[i + half]));
            
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let wa_2 = two.mul(&wa_vals[i + half]).sub(&wa_vals[i]);
            let val_inc_2 = two.mul(&val_inc_vals[i + half]).sub(&val_inc_vals[i]);
            s_2 = s_2.add(&wa_2.mul(&val_inc_2));
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    fn partial_eval(&self, evals: &[K], challenge: K) -> Vec<K> {
        let half = evals.len() / 2;
        let mut result = Vec::with_capacity(half);
        let one_minus_r = K::one().sub(&challenge);
        
        for i in 0..half {
            let new_val = one_minus_r.mul(&evals[i]).add(&challenge.mul(&evals[i + half]));
            result.push(new_val);
        }
        
        result
    }
    
    fn sample_challenge(&self) -> K {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % K::BaseField::MODULUS;
        K::from_base_field_element(K::BaseField::from_u64(val), 0)
    }
}

impl<K: ExtensionFieldElement> Clone for VirtualWriteValues<K> {
    fn clone(&self) -> Self {
        Self {
            write_address_mle: self.write_address_mle.clone(),
            increment_mle: self.increment_mle.clone(),
            memory_size: self.memory_size,
            num_cycles: self.num_cycles,
        }
    }
}

impl<K: ExtensionFieldElement> VirtualPolyTrait<K> for VirtualWriteValues<K> {
    fn evaluate_via_sumcheck(
        &self,
        point: &[K],
        _committed_polys: &HashMap<String, MultilinearPolynomial<K>>,
    ) -> Result<VirtualEvaluation<K>, String> {
        self.evaluate_at_cycle(point)
    }
    
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K> {
        let log_k = (self.memory_size as f64).log2() as usize;
        
        SumCheckClaim {
            claimed_value: K::zero(),
            evaluation_point: point.to_vec(),
            num_variables: log_k,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec!["wa".to_string(), "Inc".to_string(), "Val".to_string()]
    }
}
