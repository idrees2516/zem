// Equality Function Module for Small-Space zkVM
//
// This module implements the equality function eq̃(X,Y) and its efficient evaluation.
// The equality function is fundamental to sum-check protocols and multilinear extensions.
//
// The equality function eq: {0,1}^n × {0,1}^n → {0,1} is defined as:
//   eq(x,y) = 1 if x = y, 0 otherwise
//
// Its multilinear extension eq̃: F^n × F^n → F is:
//   eq̃(X,Y) = ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
//
// Key Features:
// 1. Direct evaluation: O(n) time, O(1) space
// 2. Precomputation table: O(2^n) time and space
// 3. Efficient streaming using depth-first traversal: O(2^n) time, O(n) space
// 4. Evaluation at specific index: O(n) time, O(1) space
//
// References:
// - Paper Section 2: Mathematical Preliminaries (Requirement 0.12)
// - Paper Section 3.1: Algorithm 1 (Requirements 1.5, 1.9, 1.12)
// - Paper [CFFZE24, Rot24]: Efficient streaming via binary tree traversal (Requirement 17.17)

use crate::field::Field;
use super::field_arithmetic::index_to_bits;

/// Equality Function
///
/// Represents the multilinear extension of the equality function.
///
/// The equality function is central to many zkSNARK protocols:
/// - Used in sum-check to weight terms by eq̃(r, x)
/// - Used in GKR protocol for wiring predicates
/// - Used in Spartan for constraint satisfaction
///
/// Reference: Paper Section 2, Requirement 0.12
#[derive(Clone, Debug)]
pub struct EqualityFunction<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    
    /// Phantom data for field type
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> EqualityFunction<F> {
    /// Create new equality function
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Evaluate eq̃(X,Y) at two points
    ///
    /// Computes: eq̃(X,Y) = ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
    ///
    /// This formula can be rewritten as:
    ///   ∏ᵢ (Xᵢ·Yᵢ + (1-Xᵢ)·(1-Yᵢ))
    ///
    /// Which equals 1 if X = Y (on Boolean hypercube), 0 otherwise.
    ///
    /// Time: O(n) field operations
    /// Space: O(1)
    ///
    /// Reference: Requirements 0.12, 1.5, 1.9, Task 3.2
    pub fn evaluate(&self, x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), self.num_vars, "X dimension mismatch");
        assert_eq!(y.len(), self.num_vars, "Y dimension mismatch");
        
        let mut result = F::one();
        
        for i in 0..self.num_vars {
            // Compute: (1-Xᵢ)(1-Yᵢ) + XᵢYᵢ
            let one_minus_xi = F::one().sub(&x[i]);
            let one_minus_yi = F::one().sub(&y[i]);
            
            let term = one_minus_xi.mul(&one_minus_yi).add(&x[i].mul(&y[i]));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Precompute table of all eq̃(r, y) for y ∈ {0,1}^n
    ///
    /// Given a fixed point r ∈ F^n, precomputes eq̃(r, y) for all
    /// y ∈ {0,1}^n and stores in a table of size 2^n.
    ///
    /// This is useful when eq̃(r, y) needs to be accessed many times
    /// for the same r but different y values.
    ///
    /// Algorithm:
    /// For each y ∈ {0,1}^n:
    ///   table[val(y)] = ∏ᵢ ((1-rᵢ)(1-yᵢ) + rᵢ·yᵢ)
    ///
    /// Time: O(n·2^n) field operations
    /// Space: O(2^n)
    ///
    /// Reference: Requirement 0.12, Task 3.3
    pub fn precompute_table(&self, r: &[F]) -> Vec<F> {
        assert_eq!(r.len(), self.num_vars, "Point dimension mismatch");
        
        let size = 1 << self.num_vars;
        let mut table = Vec::with_capacity(size);
        
        for i in 0..size {
            let bits = index_to_bits(i, self.num_vars);
            let y: Vec<F> = bits.iter()
                .map(|&b| if b { F::one() } else { F::zero() })
                .collect();
            
            table.push(self.evaluate(r, &y));
        }
        
        table
    }
    
    /// Stream eq̃(r, y) evaluations in lexicographic order
    ///
    /// Efficiently computes eq̃(r, y) for all y ∈ {0,1}^n using
    /// depth-first traversal of the binary tree.
    ///
    /// This avoids storing the full table while still computing
    /// all values efficiently.
    ///
    /// The callback is invoked with (index, value) where:
    /// - index = val(y) is the integer representation of y
    /// - value = eq̃(r, y)
    ///
    /// Time: O(2^n) field operations
    /// Space: O(n) for recursion stack
    ///
    /// This is a key optimization from [CFFZE24, Rot24] that enables
    /// small-space sum-check proving.
    ///
    /// Reference: Requirements 0.12, 17.17, Task 3.4
    pub fn stream_evaluations<G>(&self, r: &[F], mut callback: G)
    where
        G: FnMut(usize, F),
    {
        assert_eq!(r.len(), self.num_vars, "Point dimension mismatch");
        
        self.stream_recursive(r, 0, 0, F::one(), &mut callback);
    }
    
    /// Recursive helper for streaming evaluations
    ///
    /// Performs depth-first traversal of the binary tree representing
    /// the Boolean hypercube {0,1}^n.
    ///
    /// At each node:
    /// - Left child (bit = 0): multiply by (1 - r[depth])
    /// - Right child (bit = 1): multiply by r[depth]
    ///
    /// This incrementally builds up the product:
    ///   eq̃(r, y) = ∏ᵢ ((1-rᵢ)(1-yᵢ) + rᵢ·yᵢ)
    ///
    /// Parameters:
    /// - r: Fixed point in F^n
    /// - depth: Current recursion depth (0 to num_vars)
    /// - index: Current index being built (val(y₁,...,y_depth))
    /// - current_val: Product accumulated so far
    /// - callback: Function to call with (index, value)
    ///
    /// Reference: Requirements 0.12, 17.17, Task 3.5
    fn stream_recursive<G>(
        &self,
        r: &[F],
        depth: usize,
        index: usize,
        current_val: F,
        callback: &mut G,
    ) where
        G: FnMut(usize, F),
    {
        if depth == self.num_vars {
            // Reached a leaf: output the value
            callback(index, current_val);
            return;
        }
        
        // Left child: y[depth] = 0
        // Multiply by (1 - r[depth])
        let left_val = current_val.mul(&F::one().sub(&r[depth]));
        self.stream_recursive(r, depth + 1, index, left_val, callback);
        
        // Right child: y[depth] = 1
        // Multiply by r[depth]
        // Index gets bit set at position depth
        let right_val = current_val.mul(&r[depth]);
        let right_index = index | (1 << depth);
        self.stream_recursive(r, depth + 1, right_index, right_val, callback);
    }
    
    /// Compute eq̃(r, tobits(i)) at specific index
    ///
    /// Given index i and point r, computes eq̃(r, tobits(i))
    /// without precomputing the full table.
    ///
    /// This is used in streaming MLE evaluation and small-space sum-check.
    ///
    /// Algorithm:
    /// 1. Convert i to binary: y = tobits(i)
    /// 2. Compute: ∏ⱼ ((1-rⱼ)(1-yⱼ) + rⱼ·yⱼ)
    ///
    /// Time: O(n) field operations
    /// Space: O(1) (excluding bit conversion)
    ///
    /// Reference: Requirement 0.12, Task 3.6
    pub fn evaluate_at_index(&self, r: &[F], index: usize) -> F {
        assert_eq!(r.len(), self.num_vars, "Point dimension mismatch");
        assert!(index < (1 << self.num_vars), "Index out of range");
        
        let bits = index_to_bits(index, self.num_vars);
        let mut result = F::one();
        
        for (j, &bit) in bits.iter().enumerate() {
            let term = if bit {
                r[j]
            } else {
                F::one().sub(&r[j])
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Batch evaluate eq̃(r, y) for multiple y values
    ///
    /// Given r and a list of y values, computes eq̃(r, y) for each y.
    ///
    /// This is more efficient than calling evaluate() multiple times
    /// when there are many y values.
    pub fn batch_evaluate(&self, r: &[F], ys: &[Vec<F>]) -> Vec<F> {
        ys.iter().map(|y| self.evaluate(r, y)).collect()
    }
    
    /// Verify equality function property
    ///
    /// Checks that eq̃(x, y) = 1 when x = y (on Boolean hypercube)
    /// and eq̃(x, y) = 0 when x ≠ y.
    ///
    /// This is used for testing to ensure correctness.
    pub fn verify_property(&self) -> bool {
        let size = 1 << self.num_vars;
        
        for i in 0..size {
            for j in 0..size {
                let bits_i = index_to_bits(i, self.num_vars);
                let bits_j = index_to_bits(j, self.num_vars);
                
                let x: Vec<F> = bits_i.iter()
                    .map(|&b| if b { F::one() } else { F::zero() })
                    .collect();
                let y: Vec<F> = bits_j.iter()
                    .map(|&b| if b { F::one() } else { F::zero() })
                    .collect();
                
                let result = self.evaluate(&x, &y);
                let expected = if i == j { F::one() } else { F::zero() };
                
                if result != expected {
                    return false;
                }
            }
        }
        
        true
    }
}

/// Efficient Equality Evaluator
///
/// Optimized structure for repeated evaluations of eq̃(r, ·)
/// for a fixed point r.
///
/// Precomputes intermediate values to speed up evaluations.
pub struct EqualityEvaluator<F: Field> {
    /// Fixed point r
    r: Vec<F>,
    
    /// Precomputed (1 - r[i]) values
    one_minus_r: Vec<F>,
    
    /// Number of variables
    num_vars: usize,
}

impl<F: Field> EqualityEvaluator<F> {
    /// Create evaluator for fixed point r
    pub fn new(r: Vec<F>) -> Self {
        let num_vars = r.len();
        let one_minus_r: Vec<F> = r.iter()
            .map(|ri| F::one().sub(ri))
            .collect();
        
        Self {
            r,
            one_minus_r,
            num_vars,
        }
    }
    
    /// Evaluate eq̃(r, y) using precomputed values
    pub fn evaluate(&self, y: &[F]) -> F {
        assert_eq!(y.len(), self.num_vars, "Y dimension mismatch");
        
        let mut result = F::one();
        
        for i in 0..self.num_vars {
            // (1-rᵢ)(1-yᵢ) + rᵢ·yᵢ
            let one_minus_yi = F::one().sub(&y[i]);
            let term = self.one_minus_r[i].mul(&one_minus_yi)
                .add(&self.r[i].mul(&y[i]));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Evaluate at Boolean point (more efficient)
    pub fn evaluate_at_bits(&self, bits: &[bool]) -> F {
        assert_eq!(bits.len(), self.num_vars, "Bits length mismatch");
        
        let mut result = F::one();
        
        for i in 0..self.num_vars {
            let term = if bits[i] {
                self.r[i]
            } else {
                self.one_minus_r[i]
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Evaluate at index
    pub fn evaluate_at_index(&self, index: usize) -> F {
        let bits = index_to_bits(index, self.num_vars);
        self.evaluate_at_bits(&bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_equality_at_boolean() {
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        // Test eq̃(x, x) = 1 for all x ∈ {0,1}^2
        for i in 0..4 {
            let bits = index_to_bits(i, 2);
            let x: Vec<GoldilocksField> = bits.iter()
                .map(|&b| if b { GoldilocksField::one() } else { GoldilocksField::zero() })
                .collect();
            
            let result = eq.evaluate(&x, &x);
            assert_eq!(result, GoldilocksField::one(), "eq(x,x) should be 1");
        }
    }
    
    #[test]
    fn test_equality_different_points() {
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        let x = vec![GoldilocksField::zero(), GoldilocksField::zero()];
        let y = vec![GoldilocksField::one(), GoldilocksField::zero()];
        
        let result = eq.evaluate(&x, &y);
        assert_eq!(result, GoldilocksField::zero(), "eq(x,y) should be 0 when x≠y");
    }
    
    #[test]
    fn test_equality_property() {
        let eq = EqualityFunction::<GoldilocksField>::new(3);
        assert!(eq.verify_property(), "Equality property should hold");
    }
    
    #[test]
    fn test_precompute_table() {
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        let r = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let table = eq.precompute_table(&r);
        assert_eq!(table.len(), 4);
        
        // Verify table values match direct evaluation
        for i in 0..4 {
            let bits = index_to_bits(i, 2);
            let y: Vec<GoldilocksField> = bits.iter()
                .map(|&b| if b { GoldilocksField::one() } else { GoldilocksField::zero() })
                .collect();
            
            let direct = eq.evaluate(&r, &y);
            assert_eq!(table[i], direct, "Table value mismatch at index {}", i);
        }
    }
    
    #[test]
    fn test_stream_evaluations() {
        let eq = EqualityFunction::<GoldilocksField>::new(3);
        
        let r = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let mut streamed = vec![GoldilocksField::zero(); 8];
        
        eq.stream_evaluations(&r, |index, value| {
            streamed[index] = value;
        });
        
        // Verify streamed values match precomputed table
        let table = eq.precompute_table(&r);
        for i in 0..8 {
            assert_eq!(streamed[i], table[i], "Streamed value mismatch at index {}", i);
        }
    }
    
    #[test]
    fn test_evaluate_at_index() {
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        let r = vec![
            GoldilocksField::from_u64(7),
            GoldilocksField::from_u64(11),
        ];
        
        // Test all indices
        for i in 0..4 {
            let result = eq.evaluate_at_index(&r, i);
            
            // Compare with direct evaluation
            let bits = index_to_bits(i, 2);
            let y: Vec<GoldilocksField> = bits.iter()
                .map(|&b| if b { GoldilocksField::one() } else { GoldilocksField::zero() })
                .collect();
            let expected = eq.evaluate(&r, &y);
            
            assert_eq!(result, expected, "Index evaluation mismatch at {}", i);
        }
    }
    
    #[test]
    fn test_equality_evaluator() {
        let r = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let evaluator = EqualityEvaluator::new(r.clone());
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        // Test evaluation at various points
        for i in 0..4 {
            let bits = index_to_bits(i, 2);
            let y: Vec<GoldilocksField> = bits.iter()
                .map(|&b| if b { GoldilocksField::one() } else { GoldilocksField::zero() })
                .collect();
            
            let result = evaluator.evaluate(&y);
            let expected = eq.evaluate(&r, &y);
            
            assert_eq!(result, expected, "Evaluator mismatch at index {}", i);
        }
    }
    
    #[test]
    fn test_evaluator_at_bits() {
        let r = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let evaluator = EqualityEvaluator::new(r.clone());
        
        let bits = vec![true, false];
        let result = evaluator.evaluate_at_bits(&bits);
        
        // Compare with standard evaluation
        let y = vec![GoldilocksField::one(), GoldilocksField::zero()];
        let expected = evaluator.evaluate(&y);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_batch_evaluate() {
        let eq = EqualityFunction::<GoldilocksField>::new(2);
        
        let r = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
        ];
        
        let ys = vec![
            vec![GoldilocksField::zero(), GoldilocksField::zero()],
            vec![GoldilocksField::one(), GoldilocksField::zero()],
            vec![GoldilocksField::zero(), GoldilocksField::one()],
        ];
        
        let results = eq.batch_evaluate(&r, &ys);
        
        assert_eq!(results.len(), 3);
        for (i, y) in ys.iter().enumerate() {
            let expected = eq.evaluate(&r, y);
            assert_eq!(results[i], expected, "Batch result mismatch at {}", i);
        }
    }
}
