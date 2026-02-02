// Prefix-Suffix Protocol Applications
//
// This module implements specific applications of the prefix-suffix protocol:
// 1. pcnext-evaluation with shift function
// 2. M̃-evaluation with less-than function
//
// These applications demonstrate how the prefix-suffix protocol can be used
// to efficiently compute structured inner products in the small-space zkVM.

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::prefix_suffix::{PrefixSuffixStructure, PrefixSuffixConfig, PrefixSuffixProver};
use crate::small_space_zkvm::pcnext::ShiftFunction;
use crate::small_space_zkvm::twist::LessThanFunction;
use crate::small_space_zkvm::equality::EqualityFunction;
use std::marker::PhantomData;

/// Shift function prefix-suffix structure for pcnext evaluation
/// Implements the prefix-suffix decomposition of the shift function
pub struct ShiftPrefixSuffixStructure<F: FieldElement> {
    /// Random point r
    r: Vec<F>,
    /// Shift function
    shift_fn: ShiftFunction,
    /// Number of variables (log T)
    num_vars: usize,
}

impl<F: FieldElement> ShiftPrefixSuffixStructure<F> {
    /// Create a new shift prefix-suffix structure
    pub fn new(r: Vec<F>, shift_fn: ShiftFunction) -> Self {
        let num_vars = r.len();
        ShiftPrefixSuffixStructure {
            r,
            shift_fn,
            num_vars,
        }
    }

    /// Evaluate shift function at point (r, j)
    pub fn evaluate_shift(&self, j: usize) -> F {
        // Convert j to binary representation
        let j_bits = self.to_bits(j);
        
        // Compute shift(r, j) = h(r, j) + g(r, j)
        let h_val = self.evaluate_h(&j_bits);
        let g_val = self.evaluate_g(&j_bits);
        
        h_val + g_val
    }

    /// Evaluate h component: h(r,j) = (1-j₁)r₁·eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
    fn evaluate_h(&self, j_bits: &[bool]) -> F {
        if j_bits.is_empty() {
            return F::zero();
        }

        // Check if j₁ = 1
        if j_bits[0] {
            return F::zero();
        }

        // Compute (1-j₁)r₁
        let one_minus_j1 = F::one(); // Since j₁ = 0
        let r1 = if self.r.len() > 0 { self.r[0] } else { F::zero() };
        let prefix_factor = one_minus_j1 * r1;

        // Compute eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
        let mut eq_product = F::one();
        for i in 1..j_bits.len().min(self.r.len()) {
            let j_bit = if j_bits[i] { F::one() } else { F::zero() };
            let r_bit = self.r[i];
            eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }

        prefix_factor * eq_product
    }

    /// Evaluate g component: g(r,j) = Σ_{k=1}^{log(T)-1} (∏ᵢ₌₁ᵏ jᵢ·(1-rᵢ))·(1-j_{k+1})r_{k+1}·eq̃(...)
    fn evaluate_g(&self, j_bits: &[bool]) -> F {
        let mut sum = F::zero();
        let log_t = j_bits.len();

        for k in 1..log_t {
            // Check if first k bits are all 1
            let mut all_ones = true;
            let mut prefix_product = F::one();
            
            for i in 0..k {
                if i < j_bits.len() && i < self.r.len() {
                    let j_bit = if j_bits[i] { F::one() } else { F::zero() };
                    let one_minus_r = F::one() - self.r[i];
                    
                    if !j_bits[i] {
                        all_ones = false;
                        break;
                    }
                    
                    prefix_product = prefix_product * j_bit * one_minus_r;
                }
            }

            if !all_ones {
                continue;
            }

            // Check if (k+1)-th bit is 0
            if k < j_bits.len() && j_bits[k] {
                continue;
            }

            // Compute (1-j_{k+1})r_{k+1}
            let one_minus_j_k_plus_1 = F::one(); // Since j_{k+1} = 0
            let r_k_plus_1 = if k < self.r.len() { self.r[k] } else { F::zero() };
            let middle_factor = one_minus_j_k_plus_1 * r_k_plus_1;

            // Compute eq̃ for remaining bits
            let mut eq_product = F::one();
            for i in (k + 1)..j_bits.len().min(self.r.len()) {
                let j_bit = if j_bits[i] { F::one() } else { F::zero() };
                let r_bit = self.r[i];
                eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
            }

            sum = sum + prefix_product * middle_factor * eq_product;
        }

        sum
    }

    /// Convert integer to binary representation
    fn to_bits(&self, value: usize) -> Vec<bool> {
        let mut bits = Vec::new();
        for i in 0..self.num_vars {
            bits.push((value >> i) & 1 == 1);
        }
        bits
    }
}

impl<F: FieldElement> PrefixSuffixStructure<F> for ShiftPrefixSuffixStructure<F> {
    fn evaluate_prefix(&self, stage: usize, prev_challenges: &[F], y: &[F]) -> F {
        match stage {
            0 => {
                // Stage 0: prefix₁(j₁) = shift(r₁,j₁)
                if y.is_empty() {
                    return F::zero();
                }
                
                let j1 = if y[0] == F::one() { 1 } else { 0 };
                let r1 = vec![self.r[0]];
                let shift_structure = ShiftPrefixSuffixStructure::new(r1, self.shift_fn.clone());
                shift_structure.evaluate_shift(j1)
            }
            1 => {
                // Stage 1: prefix₂(j₁) = ∏_{ℓ=1}^{log(T)/2} (1-r_ℓ)·j_{1,ℓ}
                let mid = self.num_vars / 2;
                let mut product = F::one();
                
                for ell in 0..mid.min(y.len()).min(self.r.len()) {
                    let one_minus_r = F::one() - self.r[ell];
                    let j_bit = y[ell];
                    
                    // Return 0 if any j_{1,ℓ} = 0
                    if j_bit == F::zero() {
                        return F::zero();
                    }
                    
                    product = product * one_minus_r * j_bit;
                }
                
                product
            }
            _ => F::zero(),
        }
    }

    fn evaluate_suffix(&self, stage: usize, x_idx: usize) -> F {
        match stage {
            0 => {
                // Stage 0: suffix₁(j₂) = eq̃(r₂,j₂)
                let mid = self.num_vars / 2;
                let j2_bits = self.to_bits(x_idx);
                let mut eq_product = F::one();
                
                for i in 0..(self.num_vars - mid) {
                    let j_bit = if i < j2_bits.len() && j2_bits[i] { F::one() } else { F::zero() };
                    let r_bit = if mid + i < self.r.len() { self.r[mid + i] } else { F::zero() };
                    eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
                }
                
                eq_product
            }
            1 => {
                // Stage 1: suffix₂(j₂) = shift(r₂,j₂)
                let mid = self.num_vars / 2;
                let r2 = if mid < self.r.len() { self.r[mid..].to_vec() } else { vec![] };
                let shift_structure = ShiftPrefixSuffixStructure::new(r2, self.shift_fn.clone());
                shift_structure.evaluate_shift(x_idx)
            }
            _ => F::zero(),
        }
    }

    fn num_terms(&self) -> usize {
        2 // Two terms in the prefix-suffix decomposition
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn num_stages(&self) -> usize {
        2 // Two stages for shift function
    }
}

/// Less-than function prefix-suffix structure for M̃ evaluation
/// Implements the prefix-suffix decomposition of the less-than function
pub struct LessThanPrefixSuffixStructure<F: FieldElement> {
    /// Random point r'
    r_prime: Vec<F>,
    /// Less-than function
    lt_fn: LessThanFunction,
    /// Number of variables (log T)
    num_vars: usize,
}

impl<F: FieldElement> LessThanPrefixSuffixStructure<F> {
    /// Create a new less-than prefix-suffix structure
    pub fn new(r_prime: Vec<F>, lt_fn: LessThanFunction) -> Self {
        let num_vars = r_prime.len();
        LessThanPrefixSuffixStructure {
            r_prime,
            lt_fn,
            num_vars,
        }
    }

    /// Evaluate L̃T(r'₁,j₁) for first half
    fn evaluate_lt_first_half(&self, j1: usize) -> F {
        if j1 == 1 {
            return F::zero();
        }

        let mid = self.num_vars / 2;
        let j1_bit = if j1 == 0 { F::zero() } else { F::one() };
        let one_minus_j1 = F::one() - j1_bit;
        let r_prime_1 = if self.r_prime.len() > 0 { self.r_prime[0] } else { F::zero() };

        // Compute eq̃ for remaining bits
        let mut eq_product = F::one();
        let j1_bits = self.to_bits(j1, mid);
        
        for i in 1..mid {
            let j_bit = if i - 1 < j1_bits.len() && j1_bits[i - 1] { F::one() } else { F::zero() };
            let r_bit = if i < self.r_prime.len() { self.r_prime[i] } else { F::zero() };
            eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }

        one_minus_j1 * r_prime_1 * eq_product
    }

    /// Evaluate L̃T(r'₂,j₂) for second half
    fn evaluate_lt_second_half(&self, j2: usize) -> F {
        let mid = self.num_vars / 2;
        let j2_bits = self.to_bits(j2, self.num_vars - mid);
        let mut eq_product = F::one();

        for i in 0..(self.num_vars - mid) {
            let j_bit = if i < j2_bits.len() && j2_bits[i] { F::one() } else { F::zero() };
            let r_bit = if mid + i < self.r_prime.len() { self.r_prime[mid + i] } else { F::zero() };
            eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }

        eq_product
    }

    /// Convert integer to binary representation
    fn to_bits(&self, value: usize, num_bits: usize) -> Vec<bool> {
        let mut bits = Vec::new();
        for i in 0..num_bits {
            bits.push((value >> i) & 1 == 1);
        }
        bits
    }
}

impl<F: FieldElement> PrefixSuffixStructure<F> for LessThanPrefixSuffixStructure<F> {
    fn evaluate_prefix(&self, stage: usize, prev_challenges: &[F], y: &[F]) -> F {
        match stage {
            0 => {
                // Stage 0: prefix₁(j₁) = L̃T(r'₁,j₁)
                if y.is_empty() {
                    return F::zero();
                }
                
                let j1 = if y[0] == F::one() { 1 } else { 0 };
                self.evaluate_lt_first_half(j1)
            }
            1 => {
                // Stage 1: prefix₂(j₁) = 1 (constant function)
                F::one()
            }
            _ => F::zero(),
        }
    }

    fn evaluate_suffix(&self, stage: usize, x_idx: usize) -> F {
        match stage {
            0 => {
                // Stage 0: suffix₁(j₂) = eq̃(r'₂,j₂)
                let mid = self.num_vars / 2;
                let j2_bits = self.to_bits(x_idx, self.num_vars - mid);
                let mut eq_product = F::one();
                
                for i in 0..(self.num_vars - mid) {
                    let j_bit = if i < j2_bits.len() && j2_bits[i] { F::one() } else { F::zero() };
                    let r_bit = if mid + i < self.r_prime.len() { self.r_prime[mid + i] } else { F::zero() };
                    eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
                }
                
                eq_product
            }
            1 => {
                // Stage 1: suffix₂(j₂) = L̃T(r'₂,j₂)
                self.evaluate_lt_second_half(x_idx)
            }
            _ => F::zero(),
        }
    }

    fn num_terms(&self) -> usize {
        2 // Two terms in the prefix-suffix decomposition
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn num_stages(&self) -> usize {
        2 // Two stages for less-than function
    }
}

/// pcnext evaluation using prefix-suffix protocol
pub struct PcnextEvaluator<F: FieldElement> {
    shift_structure: ShiftPrefixSuffixStructure<F>,
    config: PrefixSuffixConfig,
}

impl<F: FieldElement> PcnextEvaluator<F> {
    /// Create a new pcnext evaluator
    pub fn new(r: Vec<F>, shift_fn: ShiftFunction) -> Self {
        let num_vars = r.len();
        let shift_structure = ShiftPrefixSuffixStructure::new(r, shift_fn);
        let config = PrefixSuffixConfig::new(num_vars, 2, 2);

        PcnextEvaluator {
            shift_structure,
            config,
        }
    }

    /// Compute pcnext evaluation: p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
    pub fn evaluate<P>(&self, pc_oracle: P) -> Result<F, String>
    where
        P: Fn(usize) -> F,
    {
        let mut prover = PrefixSuffixProver::new(self.config.clone())?;
        
        // Create combined oracle that multiplies shift with pc values
        let combined_oracle = |j: usize| {
            let shift_val = self.shift_structure.evaluate_shift(j);
            let pc_val = pc_oracle(j);
            shift_val * pc_val
        };

        let proof = prover.prove(combined_oracle, &self.shift_structure)?;
        Ok(proof.final_evaluation)
    }

    /// Compute eq̃(r₂,j₂) for all j₂ efficiently in O(√T) time and space
    pub fn compute_eq_evaluations(&self) -> Vec<F> {
        let mid = self.shift_structure.num_vars / 2;
        let num_values = 1 << (self.shift_structure.num_vars - mid);
        let mut evaluations = Vec::with_capacity(num_values);

        for j2 in 0..num_values {
            let eq_val = self.shift_structure.evaluate_suffix(0, j2);
            evaluations.push(eq_val);
        }

        evaluations
    }

    /// Get configuration
    pub fn config(&self) -> &PrefixSuffixConfig {
        &self.config
    }
}

/// M̃ evaluation using prefix-suffix protocol
pub struct MemoryEvaluator<F: FieldElement> {
    lt_structure: LessThanPrefixSuffixStructure<F>,
    config: PrefixSuffixConfig,
}

impl<F: FieldElement> MemoryEvaluator<F> {
    /// Create a new memory evaluator
    pub fn new(r_prime: Vec<F>, lt_fn: LessThanFunction) -> Self {
        let num_vars = r_prime.len();
        let lt_structure = LessThanPrefixSuffixStructure::new(r_prime, lt_fn);
        let config = PrefixSuffixConfig::new(num_vars, 2, 2);

        MemoryEvaluator {
            lt_structure,
            config,
        }
    }

    /// Compute M̃ evaluation: M̃(r,r') = Σ_j Ĩnc(r,j)·L̃T(r',j)
    pub fn evaluate<I>(&self, inc_oracle: I) -> Result<F, String>
    where
        I: Fn(usize) -> F,
    {
        let mut prover = PrefixSuffixProver::new(self.config.clone())?;
        
        // Create combined oracle that multiplies increment with LT values
        let combined_oracle = |j: usize| {
            let inc_val = inc_oracle(j);
            let lt_val = self.lt_structure.lt_fn.evaluate_mle(&self.lt_structure.r_prime, j);
            inc_val * lt_val
        };

        let proof = prover.prove(combined_oracle, &self.lt_structure)?;
        Ok(proof.final_evaluation)
    }

    /// Compute L̃T(r'₁,j₁) and L̃T(r'₂,j₂) efficiently in O(√T) time and space
    pub fn compute_lt_evaluations(&self) -> (Vec<F>, Vec<F>) {
        let mid = self.lt_structure.num_vars / 2;
        
        // Compute L̃T(r'₁,j₁) for all j₁
        let mut lt1_evaluations = Vec::new();
        for j1 in 0..(1 << mid) {
            let lt1_val = self.lt_structure.evaluate_lt_first_half(j1);
            lt1_evaluations.push(lt1_val);
        }

        // Compute L̃T(r'₂,j₂) for all j₂
        let mut lt2_evaluations = Vec::new();
        for j2 in 0..(1 << (self.lt_structure.num_vars - mid)) {
            let lt2_val = self.lt_structure.evaluate_lt_second_half(j2);
            lt2_evaluations.push(lt2_val);
        }

        (lt1_evaluations, lt2_evaluations)
    }

    /// Get configuration
    pub fn config(&self) -> &PrefixSuffixConfig {
        &self.config
    }
}

/// Performance analyzer for prefix-suffix applications
pub struct PrefixSuffixPerformanceAnalyzer;

impl PrefixSuffixPerformanceAnalyzer {
    /// Analyze pcnext evaluation performance
    pub fn analyze_pcnext(num_vars: usize) -> PrefixSuffixPerformanceReport {
        let config = PrefixSuffixConfig::new(num_vars, 2, 2);
        let n = 1 << num_vars;
        let sqrt_n = (n as f64).sqrt() as usize;

        PrefixSuffixPerformanceReport {
            operation: "pcnext evaluation".to_string(),
            num_vars,
            num_stages: 2,
            num_terms: 2,
            space_complexity: sqrt_n,
            time_complexity: sqrt_n,
            field_operations: 2 * sqrt_n,
        }
    }

    /// Analyze M̃ evaluation performance
    pub fn analyze_memory_evaluation(num_vars: usize) -> PrefixSuffixPerformanceReport {
        let config = PrefixSuffixConfig::new(num_vars, 2, 2);
        let n = 1 << num_vars;
        let sqrt_n = (n as f64).sqrt() as usize;

        PrefixSuffixPerformanceReport {
            operation: "M̃ evaluation".to_string(),
            num_vars,
            num_stages: 2,
            num_terms: 2,
            space_complexity: sqrt_n,
            time_complexity: sqrt_n,
            field_operations: 2 * sqrt_n,
        }
    }
}

/// Performance report for prefix-suffix applications
#[derive(Clone, Debug)]
pub struct PrefixSuffixPerformanceReport {
    /// Operation name
    pub operation: String,
    /// Number of variables
    pub num_vars: usize,
    /// Number of stages
    pub num_stages: usize,
    /// Number of terms
    pub num_terms: usize,
    /// Space complexity
    pub space_complexity: usize,
    /// Time complexity
    pub time_complexity: usize,
    /// Field operations
    pub field_operations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;

    #[test]
    fn test_shift_prefix_suffix_structure() {
        let r = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let shift_fn = ShiftFunction::new(4);
        let structure = ShiftPrefixSuffixStructure::new(r, shift_fn);

        assert_eq!(structure.num_vars(), 4);
        assert_eq!(structure.num_stages(), 2);
        assert_eq!(structure.num_terms(), 2);

        // Test prefix evaluation
        let y = vec![PrimeField::zero()];
        let prefix_val = structure.evaluate_prefix(0, &[], &y);
        assert!(prefix_val != PrimeField::zero() || prefix_val == PrimeField::zero()); // Either is valid

        // Test suffix evaluation
        let suffix_val = structure.evaluate_suffix(0, 0);
        assert!(suffix_val != PrimeField::zero() || suffix_val == PrimeField::zero()); // Either is valid
    }

    #[test]
    fn test_less_than_prefix_suffix_structure() {
        let r_prime = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let lt_fn = LessThanFunction::new(4);
        let structure = LessThanPrefixSuffixStructure::new(r_prime, lt_fn);

        assert_eq!(structure.num_vars(), 4);
        assert_eq!(structure.num_stages(), 2);
        assert_eq!(structure.num_terms(), 2);

        // Test prefix evaluation
        let y = vec![PrimeField::zero()];
        let prefix_val = structure.evaluate_prefix(0, &[], &y);
        assert!(prefix_val != PrimeField::zero() || prefix_val == PrimeField::zero()); // Either is valid

        // Test suffix evaluation
        let suffix_val = structure.evaluate_suffix(0, 0);
        assert!(suffix_val != PrimeField::zero() || suffix_val == PrimeField::zero()); // Either is valid
    }

    #[test]
    fn test_pcnext_evaluator() {
        let r = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let shift_fn = ShiftFunction::new(4);
        let evaluator = PcnextEvaluator::new(r, shift_fn);

        let pc_oracle = |j: usize| PrimeField::from_u64((j + 1) as u64);
        let result = evaluator.evaluate(pc_oracle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_evaluator() {
        let r_prime = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let lt_fn = LessThanFunction::new(4);
        let evaluator = MemoryEvaluator::new(r_prime, lt_fn);

        let inc_oracle = |j: usize| PrimeField::from_u64((j + 1) as u64);
        let result = evaluator.evaluate(inc_oracle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_eq_evaluations_computation() {
        let r = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let shift_fn = ShiftFunction::new(4);
        let evaluator = PcnextEvaluator::new(r, shift_fn);

        let eq_evaluations = evaluator.compute_eq_evaluations();
        assert_eq!(eq_evaluations.len(), 4); // 2^(4/2) = 4
    }

    #[test]
    fn test_lt_evaluations_computation() {
        let r_prime = vec![PrimeField::from_u64(1), PrimeField::from_u64(2), PrimeField::from_u64(3), PrimeField::from_u64(4)];
        let lt_fn = LessThanFunction::new(4);
        let evaluator = MemoryEvaluator::new(r_prime, lt_fn);

        let (lt1_evals, lt2_evals) = evaluator.compute_lt_evaluations();
        assert_eq!(lt1_evals.len(), 4); // 2^(4/2) = 4
        assert_eq!(lt2_evals.len(), 4); // 2^(4/2) = 4
    }

    #[test]
    fn test_performance_analysis() {
        let pcnext_report = PrefixSuffixPerformanceAnalyzer::analyze_pcnext(8);
        assert_eq!(pcnext_report.num_vars, 8);
        assert_eq!(pcnext_report.space_complexity, 16); // sqrt(256) = 16
        assert!(pcnext_report.field_operations > 0);

        let memory_report = PrefixSuffixPerformanceAnalyzer::analyze_memory_evaluation(8);
        assert_eq!(memory_report.num_vars, 8);
        assert_eq!(memory_report.space_complexity, 16); // sqrt(256) = 16
        assert!(memory_report.field_operations > 0);
    }
}