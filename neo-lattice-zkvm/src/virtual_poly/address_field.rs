// Task 4.2: Virtual Address Field Conversion
// Convert one-hot encoding to field element via sum-check

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use crate::virtual_poly::framework::{VirtualPolyTrait, VirtualEvaluation, VirtualProof};
use crate::shout::virtual_polynomials::SumCheckClaim;
use std::collections::HashMap;

/// Virtual address field conversion
/// raf(rcycle) = Σ_k (Σ_i 2^i·k_i)·Π_ℓ ra_ℓ(k_ℓ,rcycle)
/// Converts one-hot address to single field element
pub struct VirtualAddressField<K: ExtensionFieldElement> {
    /// One-hot chunk MLEs: ra_ℓ(k_ℓ, j)
    pub one_hot_chunks: Vec<MultilinearPolynomial<K>>,
    
    /// Chunk size K^{1/d}
    pub chunk_size: usize,
    
    /// Memory size K
    pub memory_size: usize,
    
    /// Dimension d
    pub dimension: usize,
}

impl<K: ExtensionFieldElement> VirtualAddressField<K> {
    pub fn new(
        one_hot_chunks: Vec<MultilinearPolynomial<K>>,
        memory_size: usize,
    ) -> Result<Self, String> {
        let dimension = one_hot_chunks.len();
        if dimension == 0 {
            return Err("Must have at least one chunk".to_string());
        }
        
        let chunk_size = ((memory_size as f64).powf(1.0 / dimension as f64).ceil()) as usize;
        
        Ok(Self {
            one_hot_chunks,
            chunk_size,
            memory_size,
            dimension,
        })
    }
    
    /// Evaluate raf(rcycle) via sum-check
    /// 
    /// Algorithm:
    /// 1. Apply sum-check over k ∈ {0,1}^{log K}
    /// 2. For each k: compute address_value = Σ_i 2^{i·log(chunk_size)}·k_i
    /// 3. Multiply by product of one-hot indicators: Π_ℓ ra_ℓ(k_ℓ,rcycle)
    /// 4. Sum over all k
    pub fn evaluate_at_cycle(&self, rcycle: &[K]) -> Result<VirtualEvaluation<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        
        // Compute address values and one-hot products for all k
        let mut address_values = Vec::with_capacity(self.memory_size);
        let mut one_hot_products = Vec::with_capacity(self.memory_size);
        
        for k in 0..self.memory_size {
            // Compute address value: Σ_i 2^{i·log(chunk_size)}·k_i
            let addr_val = self.compute_address_value(k);
            address_values.push(addr_val);
            
            // Compute one-hot product: Π_ℓ ra_ℓ(k_ℓ,rcycle)
            let one_hot_prod = self.compute_one_hot_product(k, rcycle)?;
            one_hot_products.push(one_hot_prod);
        }
        
        // Run sum-check: Σ_k address_value(k) · one_hot_product(k)
        let mut round_polynomials = Vec::with_capacity(log_k);
        let mut challenges = Vec::new();
        
        let mut current_addr = address_values;
        let mut current_one_hot = one_hot_products;
        
        for _ in 0..log_k {
            let round_poly = self.compute_round_poly(&current_addr, &current_one_hot);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge();
            challenges.push(challenge);
            
            current_addr = self.partial_eval(&current_addr, challenge);
            current_one_hot = self.partial_eval(&current_one_hot, challenge);
        }
        
        let final_addr = if !current_addr.is_empty() { current_addr[0] } else { K::zero() };
        let final_one_hot = if !current_one_hot.is_empty() { current_one_hot[0] } else { K::zero() };
        let value = final_addr.mul(&final_one_hot);
        
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
    
    /// Compute address value for k
    /// address_value(k) = Σ_i 2^{i·log(chunk_size)}·k_i
    fn compute_address_value(&self, k: usize) -> K {
        let mut value = K::zero();
        let mut remaining_k = k;
        let mut multiplier = K::one();
        
        let chunk_size_field = K::from_base_field_element(
            K::BaseField::from_u64(self.chunk_size as u64),
            0
        );
        
        for _ in 0..self.dimension {
            let k_digit = remaining_k % self.chunk_size;
            remaining_k /= self.chunk_size;
            
            let k_digit_field = K::from_base_field_element(
                K::BaseField::from_u64(k_digit as u64),
                0
            );
            
            value = value.add(&multiplier.mul(&k_digit_field));
            multiplier = multiplier.mul(&chunk_size_field);
        }
        
        value
    }
    
    /// Compute one-hot product: Π_ℓ ra_ℓ(k_ℓ,rcycle)
    fn compute_one_hot_product(&self, k: usize, rcycle: &[K]) -> Result<K, String> {
        let mut product = K::one();
        let mut remaining_k = k;
        
        for dim in 0..self.dimension {
            let k_digit = remaining_k % self.chunk_size;
            remaining_k /= self.chunk_size;
            
            // Evaluate ra_ℓ(k_digit, rcycle)
            let log_chunk = (self.chunk_size as f64).log2() as usize;
            let k_digit_bits: Vec<K> = (0..log_chunk)
                .map(|i| if (k_digit >> i) & 1 == 1 { K::one() } else { K::zero() })
                .collect();
            
            let mut eval_point = k_digit_bits;
            eval_point.extend_from_slice(rcycle);
            
            let ra_val = self.one_hot_chunks[dim].evaluate(&eval_point)?;
            product = product.mul(&ra_val);
        }
        
        Ok(product)
    }
    
    fn compute_round_poly(&self, addr_vals: &[K], one_hot_vals: &[K]) -> UnivariatePolynomial<K> {
        let half = addr_vals.len() / 2;
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            s_0 = s_0.add(&addr_vals[i].mul(&one_hot_vals[i]));
            s_1 = s_1.add(&addr_vals[i + half].mul(&one_hot_vals[i + half]));
            
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let addr_2 = two.mul(&addr_vals[i + half]).sub(&addr_vals[i]);
            let one_hot_2 = two.mul(&one_hot_vals[i + half]).sub(&one_hot_vals[i]);
            s_2 = s_2.add(&addr_2.mul(&one_hot_2));
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

impl<K: ExtensionFieldElement> Clone for VirtualAddressField<K> {
    fn clone(&self) -> Self {
        Self {
            one_hot_chunks: self.one_hot_chunks.clone(),
            chunk_size: self.chunk_size,
            memory_size: self.memory_size,
            dimension: self.dimension,
        }
    }
}

impl<K: ExtensionFieldElement> VirtualPolyTrait<K> for VirtualAddressField<K> {
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
        (0..self.dimension)
            .map(|i| format!("ra_{}", i))
            .collect()
    }
}
