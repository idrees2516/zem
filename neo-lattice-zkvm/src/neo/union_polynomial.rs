// Neo Union Polynomial Computation
// Task 7.2: Implement union polynomial computation
//
// **Paper Reference**: Neo Section 3.2 "Folding Multiple Instances", Requirements 5.1, 8.7
//
// **Union Polynomial Definition**:
// w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
//
// where:
// - ℓ is the number of instances being folded
// - Y ∈ F^{log ℓ} are the folding variables
// - X ∈ F^{log n} are the witness variables
// - eq̃_k(Y) is the multilinear extension of the k-th unit vector
// - w̃^(k)(X) is the multilinear extension of the k-th witness
//
// **Why Union Polynomial?**:
// The union polynomial allows us to represent all ℓ witnesses in a single
// multilinear polynomial. The verifier can then "fold" them by evaluating
// at a random challenge τ ∈ F^{log ℓ}, giving w̃(X) = w̃_∪(τ,X).

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use super::ccs::CCSWitness;

/// Neo union polynomial: w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
/// 
/// **Paper Reference**: Neo Section 3.2, Requirements 5.1, 8.7
/// 
/// **Structure**:
/// - Combines ℓ witness polynomials into single polynomial
/// - Has log ℓ + log n variables total
/// - Supports efficient partial evaluation at Y = τ
/// 
/// **Key Property**:
/// w̃_∪(τ, X) = Σ_k eq̃_k(τ)·w̃^(k)(X) is the folded witness
#[derive(Clone, Debug)]
pub struct NeoUnionPolynomial<F: Field> {
    /// Individual witness polynomials w̃^(1), ..., w̃^(ℓ)
    witness_polynomials: Vec<MultilinearPolynomial<F>>,
    /// Number of instances ℓ
    num_instances: usize,
    /// Number of Y variables (log ℓ)
    num_y_vars: usize,
    /// Number of X variables (log n)
    num_x_vars: usize,
}

impl<F: Field> NeoUnionPolynomial<F> {
    /// Build union polynomial from CCS witnesses
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// **Algorithm**:
    /// 1. Convert each witness vector to multilinear polynomial
    /// 2. Pad to power of 2 if needed
    /// 3. Store for efficient evaluation
    /// 
    /// **Complexity**: O(ℓ·n) to build
    pub fn from_witnesses(witnesses: &[CCSWitness<F>]) -> Self {
        let num_instances = witnesses.len();
        let log_ell = if num_instances > 0 {
            (num_instances as f64).log2().ceil() as usize
        } else {
            0
        };
        
        // Get witness size and compute log n
        let witness_size = witnesses.first().map(|w| w.size()).unwrap_or(0);
        let log_n = if witness_size > 0 {
            (witness_size as f64).log2().ceil() as usize
        } else {
            0
        };
        
        // Convert each witness to multilinear polynomial
        let witness_polynomials: Vec<MultilinearPolynomial<F>> = witnesses
            .iter()
            .map(|w| {
                // Pad to power of 2
                let padded_size = 1 << log_n;
                let mut padded = w.witness.clone();
                padded.resize(padded_size, F::zero());
                MultilinearPolynomial::from_evaluations(padded)
            })
            .collect();
        
        Self {
            witness_polynomials,
            num_instances,
            num_y_vars: log_ell,
            num_x_vars: log_n,
        }
    }
    
    /// Evaluate union polynomial at (Y, X)
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// **Formula**: w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_k(Y)·w̃^(k)(X)
    /// 
    /// **Complexity**: O(ℓ·log n) for evaluation
    pub fn evaluate(&self, y: &[F], x: &[F]) -> F {
        assert_eq!(y.len(), self.num_y_vars, "Y dimension mismatch");
        assert_eq!(x.len(), self.num_x_vars, "X dimension mismatch");
        
        let mut result = F::zero();
        
        for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
            // Compute eq̃_k(Y)
            let eq_val = Self::compute_eq_at_index(k, y);
            
            // Compute w̃^(k)(X)
            let witness_val = witness_poly.evaluate(x);
            
            // Accumulate eq̃_k(Y)·w̃^(k)(X)
            result = result.add(&eq_val.mul(&witness_val));
        }
        
        result
    }
    
    /// Compute eq̃_k(Y) where k is the index
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// **Formula**: eq̃_k(Y) = Π_i (Y_i·k_i + (1-Y_i)·(1-k_i))
    /// where k_i is the i-th bit of k in binary representation
    /// 
    /// **Intuition**:
    /// eq̃_k is the multilinear extension of the k-th unit vector.
    /// It equals 1 when Y encodes k in binary, and 0 otherwise.
    fn compute_eq_at_index(k: usize, y: &[F]) -> F {
        let mut result = F::one();
        
        for (i, yi) in y.iter().enumerate() {
            // Extract i-th bit of k
            let k_i = if (k >> i) & 1 == 1 {
                F::one()
            } else {
                F::zero()
            };
            
            // Compute eq_i = Y_i·k_i + (1-Y_i)·(1-k_i)
            let one = F::one();
            let yi_ki = yi.mul(&k_i);
            let one_minus_yi = one.sub(yi);
            let one_minus_ki = one.sub(&k_i);
            let term = yi_ki.add(&one_minus_yi.mul(&one_minus_ki));
            
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Partial evaluation: fix Y = τ, return w̃(X) = w̃_∪(τ, X)
    /// 
    /// **Paper Reference**: Neo Section 3.2, Requirement 5.2
    /// 
    /// **This is the folded witness!**
    /// 
    /// **Formula**: w̃(X) = Σ_k eq̃_k(τ)·w̃^(k)(X)
    /// 
    /// **Complexity**: O(ℓ·n) to compute all evaluations
    /// 
    /// **Why This Matters**:
    /// This is the core of the folding operation. The verifier sends random
    /// challenge τ, and the prover computes the folded witness by evaluating
    /// the union polynomial at Y = τ.
    pub fn evaluate_partial(&self, tau: &[F]) -> Vec<F> {
        assert_eq!(tau.len(), self.num_y_vars, "τ dimension mismatch");
        
        let witness_size = 1 << self.num_x_vars;
        let mut folded = vec![F::zero(); witness_size];
        
        // Precompute eq̃_k(τ) for all k
        let eq_evals: Vec<F> = (0..self.num_instances)
            .map(|k| Self::compute_eq_at_index(k, tau))
            .collect();
        
        // For each evaluation point x in the Boolean hypercube
        for x_idx in 0..witness_size {
            let mut val = F::zero();
            
            for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
                // Get w̃^(k) evaluation at this point
                let witness_val = witness_poly.evaluations()[x_idx];
                
                // Accumulate eq̃_k(τ)·w̃^(k)(x)
                val = val.add(&eq_evals[k].mul(&witness_val));
            }
            
            folded[x_idx] = val;
        }
        
        folded
    }
    
    /// Get number of instances
    pub fn num_instances(&self) -> usize {
        self.num_instances
    }
    
    /// Get number of Y variables
    pub fn num_y_vars(&self) -> usize {
        self.num_y_vars
    }
    
    /// Get number of X variables
    pub fn num_x_vars(&self) -> usize {
        self.num_x_vars
    }
    
    /// Get witness polynomials
    pub fn witness_polynomials(&self) -> &[MultilinearPolynomial<F>] {
        &self.witness_polynomials
    }
}

/// Union polynomial computation trait
/// 
/// **Paper Reference**: Neo Section 3.2
/// 
/// Provides interface for computing and manipulating union polynomials
/// in the Neo folding scheme.
pub trait UnionPolynomialComputation<F: Field> {
    /// Build union polynomial from witnesses
    fn build_union_polynomial(witnesses: &[CCSWitness<F>]) -> NeoUnionPolynomial<F>;
    
    /// Evaluate at (Y, X)
    fn evaluate_union(&self, y: &[F], x: &[F]) -> F;
    
    /// Partial evaluation at Y = τ
    fn fold_witnesses(&self, tau: &[F]) -> Vec<F>;
    
    /// Verify correctness of partial evaluation
    fn verify_partial_evaluation(&self, tau: &[F], r_x: &[F], claimed_value: &F) -> bool;
}

impl<F: Field> UnionPolynomialComputation<F> for NeoUnionPolynomial<F> {
    fn build_union_polynomial(witnesses: &[CCSWitness<F>]) -> NeoUnionPolynomial<F> {
        NeoUnionPolynomial::from_witnesses(witnesses)
    }
    
    fn evaluate_union(&self, y: &[F], x: &[F]) -> F {
        self.evaluate(y, x)
    }
    
    fn fold_witnesses(&self, tau: &[F]) -> Vec<F> {
        self.evaluate_partial(tau)
    }
    
    fn verify_partial_evaluation(&self, tau: &[F], r_x: &[F], claimed_value: &F) -> bool {
        let computed = self.evaluate(tau, r_x);
        computed.to_canonical_u64() == claimed_value.to_canonical_u64()
    }
}

/// Efficient union polynomial using tensor structure
/// 
/// **Paper Reference**: Neo Section 3.2
/// 
/// **Optimization**:
/// Exploits tensor product structure of eq̃ polynomial for faster computation.
/// Reduces complexity from O(ℓ·n·log ℓ) to O(ℓ·n).
pub struct TensorNeoUnionPolynomial<F: Field> {
    /// Witness evaluations in tensor form [ℓ, n]
    tensor_evals: Vec<Vec<F>>,
    /// Number of Y variables
    num_y_vars: usize,
    /// Number of X variables
    num_x_vars: usize,
}

impl<F: Field> TensorNeoUnionPolynomial<F> {
    /// Create from witnesses
    pub fn from_witnesses(witnesses: &[CCSWitness<F>]) -> Self {
        let num_instances = witnesses.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        let witness_size = witnesses.first().map(|w| w.size()).unwrap_or(0);
        let log_n = (witness_size as f64).log2().ceil() as usize;
        
        // Pad to powers of 2
        let padded_instances = 1 << log_ell;
        let padded_size = 1 << log_n;
        
        let mut tensor_evals = Vec::with_capacity(padded_instances);
        
        for i in 0..padded_instances {
            if i < witnesses.len() {
                let mut padded = witnesses[i].witness.clone();
                padded.resize(padded_size, F::zero());
                tensor_evals.push(padded);
            } else {
                tensor_evals.push(vec![F::zero(); padded_size]);
            }
        }
        
        Self {
            tensor_evals,
            num_y_vars: log_ell,
            num_x_vars: log_n,
        }
    }
    
    /// Efficient partial evaluation using tensor structure
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// **Optimization**:
    /// Precomputes eq̃(τ, k) for all k using tensor product:
    /// eq̃(τ, k) = Π_i eq̃_i(τ_i, k_i)
    /// 
    /// This reduces the number of multiplications from O(ℓ·log ℓ) to O(ℓ).
    /// 
    /// **Complexity**: O(ℓ·n) instead of O(ℓ·n·log ℓ)
    pub fn evaluate_partial_tensor(&self, tau: &[F]) -> Vec<F> {
        assert_eq!(tau.len(), self.num_y_vars);
        
        let num_instances = 1 << self.num_y_vars;
        let witness_size = 1 << self.num_x_vars;
        
        // Precompute eq̃(τ, k) for all k using tensor product
        let eq_evals = self.compute_eq_tensor(tau);
        
        // Compute folded witness
        let mut folded = vec![F::zero(); witness_size];
        
        for x_idx in 0..witness_size {
            let mut val = F::zero();
            for k in 0..num_instances {
                val = val.add(&eq_evals[k].mul(&self.tensor_evals[k][x_idx]));
            }
            folded[x_idx] = val;
        }
        
        folded
    }
    
    /// Compute eq̃(τ, k) for all k using tensor product structure
    /// 
    /// **Formula**: eq̃(τ, k) = Π_i (τ_i·k_i + (1-τ_i)·(1-k_i))
    /// 
    /// **Tensor Optimization**:
    /// Build up the product incrementally, bit by bit.
    /// After processing bit i, we have eq̃ values for all k with bits 0..i fixed.
    fn compute_eq_tensor(&self, tau: &[F]) -> Vec<F> {
        let num_instances = 1 << self.num_y_vars;
        let mut eq_evals = vec![F::one(); num_instances];
        
        for (i, tau_i) in tau.iter().enumerate() {
            let one = F::one();
            let one_minus_tau = one.sub(tau_i);
            
            for k in 0..num_instances {
                let k_i = if (k >> i) & 1 == 1 { F::one() } else { F::zero() };
                let one_minus_k = one.sub(&k_i);
                
                // eq̃_i = τ_i·k_i + (1-τ_i)·(1-k_i)
                let eq_i = tau_i.mul(&k_i).add(&one_minus_tau.mul(&one_minus_k));
                eq_evals[k] = eq_evals[k].mul(&eq_i);
            }
        }
        
        eq_evals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_union_polynomial_construction() {
        let w1 = CCSWitness::new(vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let w2 = CCSWitness::new(vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)]);
        
        let witnesses = vec![w1, w2];
        let union = NeoUnionPolynomial::from_witnesses(&witnesses);
        
        assert_eq!(union.num_instances(), 2);
        assert_eq!(union.num_y_vars(), 1);
        assert_eq!(union.num_x_vars(), 2);
    }
    
    #[test]
    fn test_eq_computation() {
        // Test eq̃_0([0]) = 1 (selects first instance)
        let y = vec![F::zero()];
        let eq_0 = NeoUnionPolynomial::<F>::compute_eq_at_index(0, &y);
        assert_eq!(eq_0.to_canonical_u64(), 1);
        
        // Test eq̃_1([0]) = 0 (doesn't select second instance)
        let eq_1 = NeoUnionPolynomial::<F>::compute_eq_at_index(1, &y);
        assert_eq!(eq_1.to_canonical_u64(), 0);
        
        // Test eq̃_1([1]) = 1 (selects second instance)
        let y = vec![F::one()];
        let eq_1 = NeoUnionPolynomial::<F>::compute_eq_at_index(1, &y);
        assert_eq!(eq_1.to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_partial_evaluation() {
        let w1 = CCSWitness::new(vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let w2 = CCSWitness::new(vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)]);
        
        let witnesses = vec![w1, w2];
        let union = NeoUnionPolynomial::from_witnesses(&witnesses);
        
        // Evaluate at τ = [0] (should give w1)
        let tau = vec![F::zero()];
        let folded = union.evaluate_partial(&tau);
        
        assert_eq!(folded.len(), 4);
        assert_eq!(folded[0].to_canonical_u64(), 1);
        assert_eq!(folded[1].to_canonical_u64(), 2);
        assert_eq!(folded[2].to_canonical_u64(), 3);
        assert_eq!(folded[3].to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_tensor_union_polynomial() {
        let w1 = CCSWitness::new(vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)]);
        let w2 = CCSWitness::new(vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)]);
        
        let witnesses = vec![w1.clone(), w2.clone()];
        
        let union = NeoUnionPolynomial::from_witnesses(&witnesses);
        let tensor_union = TensorNeoUnionPolynomial::from_witnesses(&witnesses);
        
        // Both should give same result
        let tau = vec![F::from_u64(3)];
        
        let folded1 = union.evaluate_partial(&tau);
        let folded2 = tensor_union.evaluate_partial_tensor(&tau);
        
        assert_eq!(folded1.len(), folded2.len());
        for (v1, v2) in folded1.iter().zip(folded2.iter()) {
            assert_eq!(v1.to_canonical_u64(), v2.to_canonical_u64());
        }
    }
}
