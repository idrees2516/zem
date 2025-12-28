// pcnext Virtual Polynomial Module
//
// This module implements the pcnext virtual polynomial used in Spartan
// to verify program counter transitions. The pcnext polynomial encodes
// the shift operation that maps each cycle to the next cycle.
//
// Key Features:
// 1. Shift function for program counter transitions
// 2. Efficient streaming evaluation
// 3. Depth-first traversal for O(T) time, O(log T) space
// 4. Integration with sum-check protocol
//
// References:
// - Paper Section 4.6-4.7: pcnext Virtual Polynomial (Requirements 4.6-4.7)
// - Tasks 17.1-17.7: pcnext implementation

use crate::field::Field;
use super::equality::EqualityFunction;

/// Shift Function
///
/// Encodes the shift operation for program counter transitions.
/// shift(r,j) = 1 if j is the next cycle after some cycle with PC=r
///
/// Reference: Requirements 4.6-4.7, Task 17.1
#[derive(Clone, Debug)]
pub struct ShiftFunction<F: Field> {
    /// Number of variables (log T)
    pub num_vars: usize,
    
    /// Field type marker
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ShiftFunction<F> {
    /// Create new shift function
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Evaluate shift function at point (r, j)
    ///
    /// Computes shift(r,j) = h(r,j) + g(r,j)
    ///
    /// Reference: Requirements 4.6-4.7, Task 17.4
    pub fn eval(&self, r: &[F], j: &[F]) -> F {
        let h_val = self.eval_h(r, j);
        let g_val = self.eval_g(r, j);
        h_val + g_val
    }
    
    /// Evaluate h(r,j) component
    ///
    /// h(r,j) = (1-j₁)r₁·eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
    /// Returns 0 if j₁ = 1
    ///
    /// Reference: Requirements 4.7, 17.14, Task 17.2
    fn eval_h(&self, r: &[F], j: &[F]) -> F {
        if j.is_empty() {
            return F::zero();
        }
        
        // Check if j₁ = 1
        if j[0] == F::one() {
            return F::zero();
        }
        
        // Compute (1-j₁)r₁
        let factor = (F::one() - j[0]) * r[0];
        
        // Compute eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
        let j_rest = &j[1..];
        let r_rest = &r[1..];
        
        let eq_val = self.eval_eq(j_rest, r_rest);
        
        factor * eq_val
    }
    
    /// Evaluate g(r,j) component
    ///
    /// g(r,j) = Σ_{k=1}^{log(T)-1} (∏ᵢ₌₁ᵏ jᵢ·(1-rᵢ))·(1-j_{k+1})r_{k+1}·eq̃(...)
    /// Checks first k bits are all 1 and (k+1)-th bit is 0
    ///
    /// Reference: Requirements 4.7, 17.14, Task 17.3
    fn eval_g(&self, r: &[F], j: &[F]) -> F {
        let mut result = F::zero();
        
        for k in 1..self.num_vars {
            // Check if first k bits of j are all 1
            let mut prefix_product = F::one();
            for i in 0..k {
                if i < j.len() {
                    prefix_product = prefix_product * j[i] * (F::one() - r[i]);
                }
            }
            
            // Check if (k+1)-th bit of j is 0
            if k < j.len() {
                let factor = (F::one() - j[k]) * r[k];
                
                // Compute eq̃ for remaining bits
                let j_rest = if k + 1 < j.len() { &j[k+1..] } else { &[] };
                let r_rest = if k + 1 < r.len() { &r[k+1..] } else { &[] };
                
                let eq_val = self.eval_eq(j_rest, r_rest);
                
                result = result + prefix_product * factor * eq_val;
            }
        }
        
        result
    }
    
    /// Evaluate equality function
    ///
    /// Computes eq̃(j, r) = ∏ᵢ ((1-jᵢ)(1-rᵢ) + jᵢ·rᵢ)
    fn eval_eq(&self, j: &[F], r: &[F]) -> F {
        let mut result = F::one();
        
        let len = std::cmp::min(j.len(), r.len());
        for i in 0..len {
            let component = (F::one() - j[i]) * (F::one() - r[i]) + j[i] * r[i];
            result = result * component;
        }
        
        result
    }
}

/// Streaming Shift Evaluator
///
/// Evaluates shift function in streaming fashion using depth-first traversal.
/// Achieves O(T) time and O(log T) space.
///
/// Reference: Requirements 4.7, 17.14, 17.18, Task 17.5
pub struct StreamingShiftEvaluator<F: Field> {
    /// Shift function
    shift_fn: ShiftFunction<F>,
    
    /// Random point r
    r: Vec<F>,
}

impl<F: Field> StreamingShiftEvaluator<F> {
    /// Create new streaming evaluator
    pub fn new(shift_fn: ShiftFunction<F>, r: Vec<F>) -> Self {
        Self { shift_fn, r }
    }
    
    /// Evaluate all shift values in streaming fashion
    ///
    /// Computes shift(r, j) for all j ∈ {0,1}^(log T)
    /// Time: O(T), Space: O(log T)
    ///
    /// Reference: Requirements 4.7, 17.14, 17.18, Task 17.5
    pub fn eval_all_streaming<Callback>(&self, mut callback: Callback)
    where
        Callback: FnMut(usize, F),
    {
        let num_vars = self.shift_fn.num_vars;
        let mut j = vec![F::zero(); num_vars];
        
        // Depth-first traversal
        self.dfs_traverse(0, &mut j, &mut callback);
    }
    
    /// Depth-first traversal helper
    fn dfs_traverse<Callback>(&self, depth: usize, j: &mut Vec<F>, callback: &mut Callback)
    where
        Callback: FnMut(usize, F),
    {
        if depth == self.shift_fn.num_vars {
            // Leaf node: compute shift value
            let idx = self.bits_to_index(j);
            let shift_val = self.shift_fn.eval(&self.r, j);
            callback(idx, shift_val);
            return;
        }
        
        // Try j[depth] = 0
        j[depth] = F::zero();
        self.dfs_traverse(depth + 1, j, callback);
        
        // Try j[depth] = 1
        j[depth] = F::one();
        self.dfs_traverse(depth + 1, j, callback);
    }
    
    /// Convert binary vector to index
    fn bits_to_index(&self, bits: &[F]) -> usize {
        let mut idx = 0usize;
        for (i, &bit) in bits.iter().enumerate() {
            if bit == F::one() {
                idx |= 1 << i;
            }
        }
        idx
    }
}

/// pcnext Oracle
///
/// Oracle for pcnext polynomial:
/// p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
///
/// Reference: Requirements 4.6-4.7, Task 17.6
pub struct PcnextOracle<F: Field> {
    /// Shift function
    shift_fn: ShiftFunction<F>,
    
    /// Program counter values (indexed by cycle)
    pc_values: Vec<F>,
}

impl<F: Field> PcnextOracle<F> {
    /// Create new pcnext oracle
    pub fn new(shift_fn: ShiftFunction<F>, pc_values: Vec<F>) -> Self {
        Self {
            shift_fn,
            pc_values,
        }
    }
    
    /// Evaluate pcnext at point r
    ///
    /// Computes p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
    pub fn eval_at(&self, r: &[F]) -> F {
        let mut result = F::zero();
        
        for (j_idx, &pc_val) in self.pc_values.iter().enumerate() {
            // Convert index to binary
            let mut j = vec![F::zero(); self.shift_fn.num_vars];
            for i in 0..self.shift_fn.num_vars {
                if (j_idx >> i) & 1 == 1 {
                    j[i] = F::one();
                }
            }
            
            // Compute shift(r, j)
            let shift_val = self.shift_fn.eval(r, &j);
            
            // Add contribution
            result = result + shift_val * pc_val;
        }
        
        result
    }
}

/// Shift Prefix-Suffix Structure
///
/// Decomposes shift function into prefix and suffix parts
/// for efficient evaluation with prefix-suffix protocol.
///
/// Reference: Requirements 7.14, Task 28.1
pub struct ShiftPrefixSuffixStructure<F: Field> {
    /// Random point r
    r: Vec<F>,
    
    /// Shift function
    shift_fn: ShiftFunction<F>,
    
    /// Number of stages
    num_stages: usize,
}

impl<F: Field> ShiftPrefixSuffixStructure<F> {
    /// Create new structure
    pub fn new(r: Vec<F>, shift_fn: ShiftFunction<F>, num_stages: usize) -> Self {
        Self {
            r,
            shift_fn,
            num_stages,
        }
    }
    
    /// Evaluate prefix for stage 0
    ///
    /// prefix₁(j₁) = shift(r₁,j₁)
    /// Evaluate shift function on first half of variables
    ///
    /// Reference: Requirements 7.14, Task 28.2
    pub fn eval_prefix_stage0(&self, j1: &[F]) -> F {
        let mut j = j1.to_vec();
        j.resize(self.shift_fn.num_vars, F::zero());
        self.shift_fn.eval(&self.r, &j)
    }
    
    /// Evaluate suffix for stage 0
    ///
    /// suffix₁(j₂) = eq̃(r₂,j₂)
    /// Evaluate equality function on second half
    ///
    /// Reference: Requirements 7.14, Task 28.3
    pub fn eval_suffix_stage0(&self, j2: &[F]) -> F {
        let eq_fn = EqualityFunction::new(j2.len());
        let r2 = if self.r.len() > j2.len() {
            &self.r[j2.len()..]
        } else {
            &[]
        };
        eq_fn.eval(r2, j2)
    }
    
    /// Evaluate prefix for stage 1
    ///
    /// prefix₂(j₁) = ∏_{ℓ=1}^{log(T)/2} (1-r_ℓ)·j_{1,ℓ}
    /// Return 0 if any j_{1,ℓ} = 0
    ///
    /// Reference: Requirements 7.14, Task 28.4
    pub fn eval_prefix_stage1(&self, j1: &[F]) -> F {
        let mut result = F::one();
        
        for (i, &j_bit) in j1.iter().enumerate() {
            if i < self.r.len() {
                result = result * (F::one() - self.r[i]) * j_bit;
            }
        }
        
        result
    }
    
    /// Evaluate suffix for stage 1
    ///
    /// suffix₂(j₂) = shift(r₂,j₂)
    /// Evaluate shift function on second half
    ///
    /// Reference: Requirements 7.14, Task 28.5
    pub fn eval_suffix_stage1(&self, j2: &[F]) -> F {
        let r2 = if self.r.len() > j2.len() {
            &self.r[j2.len()..]
        } else {
            &[]
        };
        
        let mut j = j2.to_vec();
        j.resize(self.shift_fn.num_vars, F::zero());
        self.shift_fn.eval(r2, &j)
    }
}

/// pcnext Evaluation with Prefix-Suffix
///
/// Computes pcnext evaluation using prefix-suffix protocol.
///
/// Reference: Requirements 7.14, 17.14, Task 28.6
pub struct PcnextPrefixSuffixEvaluator<F: Field> {
    /// Prefix-suffix structure
    ps_structure: ShiftPrefixSuffixStructure<F>,
    
    /// Program counter values
    pc_values: Vec<F>,
}

impl<F: Field> PcnextPrefixSuffixEvaluator<F> {
    /// Create new evaluator
    pub fn new(
        ps_structure: ShiftPrefixSuffixStructure<F>,
        pc_values: Vec<F>,
    ) -> Self {
        Self {
            ps_structure,
            pc_values,
        }
    }
    
    /// Evaluate pcnext using prefix-suffix protocol
    ///
    /// Computes p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
    /// using prefix-suffix decomposition
    pub fn eval(&self, r: &[F]) -> F {
        let mut result = F::zero();
        
        for (j_idx, &pc_val) in self.pc_values.iter().enumerate() {
            // Convert index to binary
            let mut j = vec![F::zero(); self.ps_structure.shift_fn.num_vars];
            for i in 0..self.ps_structure.shift_fn.num_vars {
                if (j_idx >> i) & 1 == 1 {
                    j[i] = F::one();
                }
            }
            
            // Split j into two halves
            let mid = j.len() / 2;
            let j1 = &j[..mid];
            let j2 = &j[mid..];
            
            // Compute prefix and suffix
            let prefix = self.ps_structure.eval_prefix_stage0(j1);
            let suffix = self.ps_structure.eval_suffix_stage0(j2);
            
            // Combine
            let shift_val = prefix * suffix;
            result = result + shift_val * pc_val;
        }
        
        result
    }
}
