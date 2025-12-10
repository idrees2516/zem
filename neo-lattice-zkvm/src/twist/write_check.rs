// Task 3.6: Write-Checking Sum-Check for Twist
// Inc(r',r'') = Σ_{k,j} eq(r',k)·eq(r'',j)·wa(k,j)·(wv(j) - Val(k,j))

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use crate::twist::ValEvaluationSumCheck;

pub struct TwistWriteCheck<K: ExtensionFieldElement> {
    pub memory_size: usize,
    pub num_cycles: usize,
}

impl<K: ExtensionFieldElement> TwistWriteCheck<K> {
    pub fn new(memory_size: usize, num_cycles: usize) -> Self {
        Self {
            memory_size,
            num_cycles,
        }
    }
    
    /// Write-checking sum-check
    /// Inc(r',r'') = Σ_{k,j} eq(r',k)·eq(r'',j)·wa(k,j)·(wv(j) - Val(k,j))
    pub fn write_checking_sumcheck(
        &self,
        r_prime: &[K],
        r_double_prime: &[K],
        write_address_mle: &MultilinearPolynomial<K>,
        write_value_mle: &MultilinearPolynomial<K>,
        increment_mle: &MultilinearPolynomial<K>,
    ) -> Result<WriteCheckProof<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_cycles as f64).log2() as usize;
        
        if r_prime.len() != log_k {
            return Err("r_prime dimension mismatch".to_string());
        }
        if r_double_prime.len() != log_t {
            return Err("r_double_prime dimension mismatch".to_string());
        }
        
        // Compute constraint polynomial evaluations
        // g(k,j) = wa(k,j)·(wv(j) - Val(k,j))
        let mut constraint_evals = Vec::with_capacity(self.memory_size * self.num_cycles);
        
        let val_eval = ValEvaluationSumCheck::new(log_t);
        
        for idx in 0..(self.memory_size * self.num_cycles) {
            let k = idx / self.num_cycles;
            let j = idx % self.num_cycles;
            
            let k_bits: Vec<K> = (0..log_k)
                .map(|i| if (k >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            let j_bits: Vec<K> = (0..log_t)
                .map(|i| if (j >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            
            // wa(k,j)
            let mut wa_point = k_bits.clone();
            wa_point.extend_from_slice(&j_bits);
            let wa_val = write_address_mle.evaluate(&wa_point)?;
            
            // wv(j)
            let wv_val = write_value_mle.evaluate(&j_bits)?;
            
            // Val(k,j)
            let val_proof = val_eval.compute_val(&k_bits, &j_bits, increment_mle)?;
            let val_kj = val_proof.val_at_point;
            
            // g(k,j) = wa(k,j)·(wv(j) - Val(k,j))
            let constraint = wa_val.mul(&wv_val.sub(&val_kj));
            constraint_evals.push(constraint);
        }
        
        // Multiply by eq(r',k)·eq(r'',j)
        let eq_vals = self.compute_eq_product(r_prime, r_double_prime, log_k, log_t);
        for i in 0..constraint_evals.len() {
            constraint_evals[i] = constraint_evals[i].mul(&eq_vals[i]);
        }
        
        // Run sum-check
        let total_vars = log_k + log_t;
        let mut round_polynomials = Vec::with_capacity(total_vars);
        let mut challenges = Vec::new();
        let mut current_evals = constraint_evals;
        
        for _ in 0..total_vars {
            let round_poly = self.compute_round_poly(&current_evals);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge();
            challenges.push(challenge);
            
            current_evals = self.partial_eval(&current_evals, challenge);
        }
        
        let final_eval = if !current_evals.is_empty() { current_evals[0] } else { K::zero() };
        
        Ok(WriteCheckProof {
            round_polynomials,
            challenges,
            final_evaluation: final_eval,
        })
    }
    
    fn compute_eq_product(&self, r: &[K], r_prime: &[K], log_k: usize, log_t: usize) -> Vec<K> {
        let total_size = (1 << log_k) * (1 << log_t);
        let mut result = Vec::with_capacity(total_size);
        
        for idx in 0..total_size {
            let k = idx >> log_t;
            let j = idx & ((1 << log_t) - 1);
            
            let k_bits: Vec<bool> = (0..log_k).map(|i| (k >> i) & 1 == 1).collect();
            let j_bits: Vec<bool> = (0..log_t).map(|i| (j >> i) & 1 == 1).collect();
            
            let eq_k = Self::eq_polynomial(r, &k_bits);
            let eq_j = Self::eq_polynomial(r_prime, &j_bits);
            
            result.push(eq_k.mul(&eq_j));
        }
        
        result
    }
    
    fn eq_polynomial(r: &[K], x: &[bool]) -> K {
        let mut result = K::one();
        for (r_i, &x_i) in r.iter().zip(x.iter()) {
            let term = if x_i { *r_i } else { K::one().sub(r_i) };
            result = result.mul(&term);
        }
        result
    }
    
    fn compute_round_poly(&self, evals: &[K]) -> UnivariatePolynomial<K> {
        let half = evals.len() / 2;
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        
        for i in 0..half {
            s_0 = s_0.add(&evals[i]);
            s_1 = s_1.add(&evals[i + half]);
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1])
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
pub struct WriteCheckProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub challenges: Vec<K>,
    pub final_evaluation: K,
}
