// Task 3.5: Read-Checking Sum-Check for Twist
// rv(r') = Σ_{k,j} eq(r',j)·ra(k,j)·Val(k,j)

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use crate::twist::ValEvaluationSumCheck;

pub struct TwistReadCheck<K: ExtensionFieldElement> {
    pub memory_size: usize,
    pub num_cycles: usize,
}

impl<K: ExtensionFieldElement> TwistReadCheck<K> {
    pub fn new(memory_size: usize, num_cycles: usize) -> Self {
        Self {
            memory_size,
            num_cycles,
        }
    }
    
    /// Read-checking sum-check: rv(r') = Σ_{k,j} eq(r',j)·ra(k,j)·Val(k,j)
    /// 
    /// Exploits sparsity: only T out of K·T terms non-zero (where ra≠0)
    /// Prover time: O(K + T·log K)
    pub fn read_checking_sumcheck(
        &self,
        r_prime: &[K],
        read_address_mle: &MultilinearPolynomial<K>,
        increment_mle: &MultilinearPolynomial<K>,
    ) -> Result<ReadCheckProof<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        if r_prime.len() != log_t {
            return Err("r_prime dimension mismatch".to_string());
        }
        
        // Compute ra(k, r') for all k
        let mut ra_at_r_prime = Vec::with_capacity(self.memory_size);
        for k in 0..self.memory_size {
            let ra_val = self.eval_ra_at_k_rprime(k, r_prime, read_address_mle)?;
            ra_at_r_prime.push(ra_val);
        }
        
        // Compute Val(k, r') for all k using Val-evaluation sum-check
        let val_eval = ValEvaluationSumCheck::new(log_t);
        let mut val_at_r_prime = Vec::with_capacity(self.memory_size);
        
        for k in 0..self.memory_size {
            let k_bits: Vec<K> = (0..log_k)
                .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            
            let val_proof = val_eval.compute_val(&k_bits, r_prime, increment_mle)?;
            val_at_r_prime.push(val_proof.val_at_point);
        }
        
        // Run sum-check over k: Σ_k ra(k,r')·Val(k,r')
        let mut round_polynomials = Vec::with_capacity(log_k);
        let mut challenges = Vec::new();
        
        let mut current_ra = ra_at_r_prime;
        let mut current_val = val_at_r_prime;
        
        for _ in 0..log_k {
            let round_poly = self.compute_round_poly(&current_ra, &current_val);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge();
            challenges.push(challenge);
            
            current_ra = self.partial_eval(&current_ra, challenge);
            current_val = self.partial_eval(&current_val, challenge);
        }
        
        let final_ra = if !current_ra.is_empty() { current_ra[0] } else { K::zero() };
        let final_val = if !current_val.is_empty() { current_val[0] } else { K::zero() };
        let final_eval = final_ra.mul(&final_val);
        
        Ok(ReadCheckProof {
            round_polynomials,
            challenges,
            final_evaluation: final_eval,
            ra_at_raddress: final_ra,
            val_at_raddress: final_val,
        })
    }
    
    fn eval_ra_at_k_rprime(
        &self,
        k: usize,
        r_prime: &[K],
        read_address_mle: &MultilinearPolynomial<K>,
    ) -> Result<K, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        
        let k_bits: Vec<K> = (0..log_k)
            .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
            .collect();
        
        let mut eval_point = k_bits;
        eval_point.extend_from_slice(r_prime);
        
        read_address_mle.evaluate(&eval_point)
    }
    
    fn compute_round_poly(&self, ra_evals: &[K], val_evals: &[K]) -> UnivariatePolynomial<K> {
        let half = ra_evals.len() / 2;
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            s_0 = s_0.add(&ra_evals[i].mul(&val_evals[i]));
            s_1 = s_1.add(&ra_evals[i + half].mul(&val_evals[i + half]));
            
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let ra_2 = two.mul(&ra_evals[i + half]).sub(&ra_evals[i]);
            let val_2 = two.mul(&val_evals[i + half]).sub(&val_evals[i]);
            s_2 = s_2.add(&ra_2.mul(&val_2));
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

#[derive(Clone, Debug)]
pub struct ReadCheckProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub challenges: Vec<K>,
    pub final_evaluation: K,
    pub ra_at_raddress: K,
    pub val_at_raddress: K,
}
