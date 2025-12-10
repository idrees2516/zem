// Task 3.4: Val-Evaluation Sum-Check
// Val(raddress, rcycle) = Σ_{j'} Inc(raddress,j')·LT(j',rcycle)

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial, DenseSumCheckProver};
use crate::twist::LessThanPredicate;

pub struct ValEvaluationSumCheck<K: ExtensionFieldElement> {
    pub log_t: usize,
}

impl<K: ExtensionFieldElement> ValEvaluationSumCheck<K> {
    pub fn new(log_t: usize) -> Self {
        Self { log_t }
    }
    
    /// Compute Val(raddress, rcycle) via sum-check
    /// Val(raddress, rcycle) = Σ_{j'} Inc(raddress,j')·LT(j',rcycle)
    pub fn compute_val(
        &self,
        raddress: &[K],
        rcycle: &[K],
        increment_mle: &MultilinearPolynomial<K>,
    ) -> Result<ValEvaluationProof<K>, String> {
        if rcycle.len() != self.log_t {
            return Err("rcycle dimension mismatch".to_string());
        }
        
        // Create less-than MLE
        let lt_mle = LessThanPredicate::create_mle(self.log_t)?;
        
        // Extract Inc(raddress, j') for all j'
        let inc_at_raddress = self.extract_inc_at_raddress(increment_mle, raddress)?;
        
        // Create MLE for Inc(raddress, ·)
        let inc_mle = MultilinearPolynomial::from_evaluations(inc_at_raddress)?;
        
        // Run dense sum-check: Σ_{j'} Inc(raddress,j')·LT(j',rcycle)
        let mut prover = DenseSumCheckProver::new(inc_mle, lt_mle)?;
        
        let mut round_polynomials = Vec::with_capacity(self.log_t);
        let mut challenges = Vec::new();
        
        for _ in 0..self.log_t {
            let round_poly = prover.round_polynomial();
            round_polynomials.push(round_poly.clone());
            
            let challenge = self.sample_challenge();
            challenges.push(challenge);
            
            prover.update(challenge)?;
        }
        
        let final_eval = prover.final_evaluation()?;
        
        Ok(ValEvaluationProof {
            round_polynomials,
            challenges,
            final_evaluation: final_eval,
            val_at_point: final_eval,
        })
    }
    
    fn extract_inc_at_raddress(
        &self,
        increment_mle: &MultilinearPolynomial<K>,
        raddress: &[K],
    ) -> Result<Vec<K>, String> {
        let t = 1 << self.log_t;
        let mut result = Vec::with_capacity(t);
        
        // For each j', evaluate Inc(raddress, j')
        for j_prime in 0..t {
            let j_prime_bits: Vec<K> = (0..self.log_t)
                .map(|i| {
                    if (j_prime >> i) & 1 == 1 {
                        K::one()
                    } else {
                        K::zero()
                    }
                })
                .collect();
            
            let mut eval_point = raddress.to_vec();
            eval_point.extend_from_slice(&j_prime_bits);
            
            let inc_val = increment_mle.evaluate(&eval_point)?;
            result.push(inc_val);
        }
        
        Ok(result)
    }
    
    fn sample_challenge(&self) -> K {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % K::BaseField::MODULUS;
        K::from_base_field_element(K::BaseField::from_u64(val), 0)
    }
}

#[derive(Clone, Debug)]
pub struct ValEvaluationProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub challenges: Vec<K>,
    pub final_evaluation: K,
    pub val_at_point: K,
}
