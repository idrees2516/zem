// Multilinear Extension (MLE) Module for Small-Space zkVM
//
// This module implements multilinear extensions with both standard and streaming evaluation.
// A multilinear extension f̃ of a function f: {0,1}^n → F is the unique multilinear polynomial
// such that f̃(y) = f(y) for all y ∈ {0,1}^n.
//
// Key Features:
// 1. Standard MLE evaluation: O(2^n) time, O(2^n) space
// 2. Streaming MLE evaluation: O(2^n) time, O(n) space
// 3. Partial evaluation (fix first k variables)
// 4. Fact 2.1 interpolation: ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
//
// References:
// - Paper Section 2: Mathematical Preliminaries (Requirements 0.8-0.11)
// - Paper Section 3.1: Streaming Witness Generation (Requirements 3.1-3.5)
// - Paper Fact 2.1: Interpolation formula (Requirement 0.11, 17.4)

use crate::field::Field;
use super::field_arithmetic::{index_to_bits, FieldOpCounter};

/// Multilinear Extension
///
/// Represents the multilinear extension f̃: F^n → F of a function f: {0,1}^n → F.
///
/// The MLE is defined by the formula:
/// f̃(X₁,...,Xₙ) = Σ_{x∈{0,1}^n} f(x) · ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-xᵢ) + Xᵢ·xᵢ)
///
/// This is the unique multilinear polynomial that agrees with f on the Boolean hypercube.
///
/// Reference: Paper Section 2, Requirements 0.8-0.11
#[derive(Clone, Debug)]
pub struct MultilinearExtension<F: Field> {
    /// Number of variables
    pub num_vars: usize,
    
    /// Evaluations over Boolean hypercube {0,1}^n
    /// Only stored when needed (for standard evaluation)
    /// For streaming evaluation, this is None
    pub evaluations: Option<Vec<F>>,
}

impl<F: Field> MultilinearExtension<F> {
    /// Create MLE from evaluations
    ///
    /// Given evaluations f(x) for all x ∈ {0,1}^n,
    /// creates the MLE f̃ that extends f to all of F^n.
    ///
    /// The evaluations vector must have length 2^n.
    ///
    /// Reference: Requirement 0.10
    pub fn from_evaluations(evaluations: Vec<F>) -> Self {
        let len = evaluations.len();
        assert!(len.is_power_of_two(), "Length must be power of 2");
        let num_vars = len.trailing_zeros() as usize;
        
        Self {
            num_vars,
            evaluations: Some(evaluations),
        }
    }
    
    /// Create MLE structure without storing evaluations
    ///
    /// Used for streaming evaluation where evaluations are generated on-demand.
    ///
    /// Reference: Requirements 0.8-0.11, Task 2.4
    pub fn new_streaming(num_vars: usize) -> Self {
        Self {
            num_vars,
            evaluations: None,
        }
    }
    
    /// Standard MLE evaluation
    ///
    /// Evaluates f̃ at point r ∈ F^n using the stored evaluations.
    ///
    /// Algorithm:
    /// 1. Start with evaluations vector of size 2^n
    /// 2. For each variable i from 1 to n:
    ///    - Halve the size by interpolating:
    ///      evals[j] = (1-r[i])·evals[2j] + r[i]·evals[2j+1]
    /// 3. Return the final single value
    ///
    /// Time: O(2^n) field operations
    /// Space: O(2^n) for evaluations storage
    ///
    /// Reference: Paper Section 2, Requirements 0.8-0.11, Task 2.3
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");
        assert!(self.evaluations.is_some(), "No evaluations stored");
        
        let mut current = self.evaluations.as_ref().unwrap().clone();
        
        // For each variable, interpolate between 0 and 1 evaluations
        // This implements Fact 2.1: ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
        for r_i in point.iter() {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                // Interpolate: (1 - r_i) · current[2j] + r_i · current[2j+1]
                let interpolated = Self::interpolate_bit(
                    current[2 * j],
                    current[2 * j + 1],
                    *r_i
                );
                next.push(interpolated);
            }
            
            current = next;
        }
        
        assert_eq!(current.len(), 1, "Should reduce to single value");
        current[0]
    }
    
    /// Streaming MLE evaluation
    ///
    /// Evaluates f̃ at point r ∈ F^n without storing the full evaluations vector.
    /// Instead, uses an oracle to generate evaluations on-demand.
    ///
    /// Formula:
    /// f̃(r) = Σ_{i=0}^{2^n-1} oracle(i) · eq̃(r, tobits(i))
    ///
    /// where eq̃(r, y) = ∏ⱼ ((1-rⱼ)(1-yⱼ) + rⱼ·yⱼ)
    ///
    /// Time: O(2^n) field operations
    /// Space: O(n) for point storage and bit conversion
    ///
    /// This is crucial for small-space proving as it avoids storing
    /// the entire witness vector.
    ///
    /// Reference: Requirements 0.8-0.11, Task 2.4
    pub fn evaluate_streaming<G>(&self, point: &[F], oracle: G) -> F
    where
        G: Fn(usize) -> F,
    {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");
        
        let mut result = F::zero();
        let size = 1 << self.num_vars;
        
        // Sum over all Boolean hypercube points
        for i in 0..size {
            let eval = oracle(i);
            let eq_eval = self.compute_eq_at_index(i, point);
            result = result.add(&eval.mul(&eq_eval));
        }
        
        result
    }
    
    /// Compute eq̃(r, tobits(i))
    ///
    /// Given index i and point r, computes the equality function:
    /// eq̃(r, tobits(i)) = ∏ⱼ ((1-rⱼ)(1-yⱼ) + rⱼ·yⱼ)
    ///
    /// where y = tobits(i) is the binary representation of i.
    ///
    /// Time: O(n) field operations
    /// Space: O(1) (excluding bit conversion)
    ///
    /// Reference: Requirement 0.12, Task 3.6
    fn compute_eq_at_index(&self, index: usize, point: &[F]) -> F {
        let bits = index_to_bits(index, self.num_vars);
        let mut result = F::one();
        
        for (j, &bit) in bits.iter().enumerate() {
            let term = if bit {
                point[j]
            } else {
                F::one().sub(&point[j])
            };
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Fact 2.1: Interpolation formula
    ///
    /// Given evaluations at 0 and 1, interpolates at arbitrary point c:
    /// ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
    ///
    /// This is the fundamental interpolation used throughout the protocol.
    ///
    /// Reference: Paper Fact 2.1, Requirements 0.11, 17.4, Task 2.5
    pub fn interpolate_bit(eval_0: F, eval_1: F, challenge: F) -> F {
        let one_minus_c = F::one().sub(&challenge);
        eval_0.mul(&one_minus_c).add(&eval_1.mul(&challenge))
    }
    
    /// Partial MLE evaluation
    ///
    /// Fixes the first k variables to specific values and returns
    /// the MLE over the remaining n-k variables.
    ///
    /// Given f̃: F^n → F and values v₁,...,vₖ ∈ F,
    /// returns g̃: F^(n-k) → F where g̃(x) = f̃(v₁,...,vₖ,x).
    ///
    /// Algorithm:
    /// For each fixed variable vᵢ:
    ///   - Halve the evaluations using interpolation
    ///   - evals[j] = (1-vᵢ)·evals[2j] + vᵢ·evals[2j+1]
    ///
    /// Time: O(2^n) field operations
    /// Space: O(2^(n-k)) for result
    ///
    /// Reference: Requirements 0.8-0.11, Task 2.6
    pub fn partial_eval(&self, prefix: &[F]) -> Self {
        let k = prefix.len();
        assert!(k <= self.num_vars, "Too many variables to fix");
        assert!(self.evaluations.is_some(), "No evaluations stored");
        
        let mut current = self.evaluations.as_ref().unwrap().clone();
        
        // Fix each variable in sequence
        for val in prefix {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                let interpolated = Self::interpolate_bit(
                    current[2 * j],
                    current[2 * j + 1],
                    *val
                );
                next.push(interpolated);
            }
            
            current = next;
        }
        
        Self {
            num_vars: self.num_vars - k,
            evaluations: Some(current),
        }
    }
    
    /// Create MLE from vector
    ///
    /// Given w ∈ F^(2^n), creates the MLE w̃ such that:
    /// w̃(tobits(i)) = wᵢ for all i ∈ {0,...,2^n-1}
    ///
    /// This is the standard way to create an MLE from a witness vector.
    ///
    /// Reference: Requirement 0.10, Task 2.7
    pub fn from_vector(w: Vec<F>) -> Self {
        Self::from_evaluations(w)
    }
    
    /// Verify MLE property
    ///
    /// Checks that f̃(y) = f(y) for all y ∈ {0,1}^n.
    ///
    /// This is used for testing to ensure the MLE is computed correctly.
    ///
    /// Reference: Requirement 0.9, Task 2.2
    pub fn verify_mle_property(&self) -> bool {
        if self.evaluations.is_none() {
            return true; // Cannot verify without evaluations
        }
        
        let evals = self.evaluations.as_ref().unwrap();
        let size = 1 << self.num_vars;
        
        // Check each Boolean point
        for i in 0..size {
            let bits = index_to_bits(i, self.num_vars);
            let point: Vec<F> = bits.iter()
                .map(|&b| if b { F::one() } else { F::zero() })
                .collect();
            
            let mle_eval = self.evaluate(&point);
            if mle_eval != evals[i] {
                return false;
            }
        }
        
        true
    }
    
    /// Linear combination of MLEs
    ///
    /// Given MLEs f̃₁,...,f̃ₖ and coefficients α₁,...,αₖ,
    /// computes the MLE of Σᵢ αᵢ·fᵢ.
    ///
    /// Property: (Σᵢ αᵢ·fᵢ)~(r) = Σᵢ αᵢ·f̃ᵢ(r)
    ///
    /// This is used in various protocols for combining multiple polynomials.
    pub fn linear_combination(mles: &[Self], coeffs: &[F]) -> Self {
        assert_eq!(mles.len(), coeffs.len(), "Length mismatch");
        assert!(!mles.is_empty(), "Empty MLE list");
        
        let num_vars = mles[0].num_vars;
        let size = 1 << num_vars;
        
        // Verify all MLEs have same size
        for mle in mles {
            assert_eq!(mle.num_vars, num_vars, "MLE size mismatch");
            assert!(mle.evaluations.is_some(), "MLE has no evaluations");
        }
        
        let mut result = vec![F::zero(); size];
        
        // Compute linear combination of evaluations
        for (mle, coeff) in mles.iter().zip(coeffs.iter()) {
            let evals = mle.evaluations.as_ref().unwrap();
            for (i, eval) in evals.iter().enumerate() {
                result[i] = result[i].add(&eval.mul(coeff));
            }
        }
        
        Self::from_evaluations(result)
    }
}

/// Polynomial Oracle Trait
///
/// Provides oracle access to polynomial evaluations without storing them.
/// This is the key abstraction for small-space proving.
///
/// The oracle can generate evaluations on-demand, typically by:
/// - Re-executing the VM from a checkpoint
/// - Computing from a compressed representation
/// - Streaming from disk or network
///
/// Reference: Requirements 1.7, 17.1, Task 6.1
pub trait PolynomialOracle<F: Field> {
    /// Query polynomial k at index i
    ///
    /// Returns the value of the k-th polynomial at the i-th point
    /// of the Boolean hypercube.
    ///
    /// For witness vectors, this typically means:
    /// - i is the cycle number
    /// - k is the witness component (register, memory, etc.)
    fn query(&self, poly_index: usize, index: usize) -> F;
    
    /// Get number of polynomials
    ///
    /// Returns ℓ, the number of polynomials in the product.
    fn num_polynomials(&self) -> usize;
    
    /// Get number of variables
    ///
    /// Returns n, where each polynomial is defined over {0,1}^n.
    fn num_variables(&self) -> usize;
}

/// Simple Vector Oracle
///
/// Oracle backed by in-memory vectors.
/// Used for testing and when memory is not a constraint.
pub struct VectorOracle<F: Field> {
    polynomials: Vec<Vec<F>>,
    num_vars: usize,
}

impl<F: Field> VectorOracle<F> {
    /// Create oracle from vectors
    pub fn new(polynomials: Vec<Vec<F>>) -> Self {
        assert!(!polynomials.is_empty(), "Empty polynomial list");
        
        let len = polynomials[0].len();
        assert!(len.is_power_of_two(), "Length must be power of 2");
        
        // Verify all polynomials have same length
        for poly in &polynomials {
            assert_eq!(poly.len(), len, "Polynomial length mismatch");
        }
        
        let num_vars = len.trailing_zeros() as usize;
        
        Self {
            polynomials,
            num_vars,
        }
    }
}

impl<F: Field> PolynomialOracle<F> for VectorOracle<F> {
    fn query(&self, poly_index: usize, index: usize) -> F {
        self.polynomials[poly_index][index]
    }
    
    fn num_polynomials(&self) -> usize {
        self.polynomials.len()
    }
    
    fn num_variables(&self) -> usize {
        self.num_vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_mle_creation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearExtension::from_evaluations(evals);
        assert_eq!(mle.num_vars, 2);
    }
    
    #[test]
    fn test_mle_evaluation_at_boolean() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearExtension::from_evaluations(evals.clone());
        
        // Evaluate at Boolean points
        let point00 = vec![GoldilocksField::zero(), GoldilocksField::zero()];
        assert_eq!(mle.evaluate(&point00), evals[0]);
        
        let point01 = vec![GoldilocksField::zero(), GoldilocksField::one()];
        assert_eq!(mle.evaluate(&point01), evals[1]);
        
        let point10 = vec![GoldilocksField::one(), GoldilocksField::zero()];
        assert_eq!(mle.evaluate(&point10), evals[2]);
        
        let point11 = vec![GoldilocksField::one(), GoldilocksField::one()];
        assert_eq!(mle.evaluate(&point11), evals[3]);
    }
    
    #[test]
    fn test_mle_property() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearExtension::from_evaluations(evals);
        assert!(mle.verify_mle_property());
    }
    
    #[test]
    fn test_interpolate_bit() {
        let eval_0 = GoldilocksField::from_u64(10);
        let eval_1 = GoldilocksField::from_u64(20);
        let challenge = GoldilocksField::from_u64(3);
        
        // (1-3)*10 + 3*20 = -2*10 + 60 = -20 + 60 = 40 (in field)
        let result = MultilinearExtension::<GoldilocksField>::interpolate_bit(
            eval_0, eval_1, challenge
        );
        
        // Verify formula: (1-c)*eval_0 + c*eval_1
        let expected = GoldilocksField::one().sub(&challenge).mul(&eval_0)
            .add(&challenge.mul(&eval_1));
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_partial_eval() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearExtension::from_evaluations(evals);
        
        // Fix first variable to 0
        let partial = mle.partial_eval(&[GoldilocksField::zero()]);
        assert_eq!(partial.num_vars, 1);
        assert_eq!(partial.evaluations.as_ref().unwrap().len(), 2);
        
        // Should get [1, 2] (first half)
        assert_eq!(partial.evaluations.as_ref().unwrap()[0].to_canonical_u64(), 1);
        assert_eq!(partial.evaluations.as_ref().unwrap()[1].to_canonical_u64(), 2);
    }
    
    #[test]
    fn test_streaming_evaluation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearExtension::new_streaming(2);
        
        // Oracle that returns the evaluations
        let oracle = |i: usize| evals[i];
        
        // Evaluate at a random point
        let point = vec![
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(7),
        ];
        
        let result = mle.evaluate_streaming(&point, oracle);
        
        // Compare with standard evaluation
        let mle_standard = MultilinearExtension::from_evaluations(evals);
        let expected = mle_standard.evaluate(&point);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_linear_combination() {
        let evals1 = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        let evals2 = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle1 = MultilinearExtension::from_evaluations(evals1);
        let mle2 = MultilinearExtension::from_evaluations(evals2);
        
        let coeffs = vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
        ];
        
        let combined = MultilinearExtension::linear_combination(
            &[mle1, mle2],
            &coeffs
        );
        
        // 2*1 + 3*3 = 11
        assert_eq!(combined.evaluations.as_ref().unwrap()[0].to_canonical_u64(), 11);
        // 2*2 + 3*4 = 16
        assert_eq!(combined.evaluations.as_ref().unwrap()[1].to_canonical_u64(), 16);
    }
    
    #[test]
    fn test_vector_oracle() {
        let poly1 = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
        ];
        let poly2 = vec![
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let oracle = VectorOracle::new(vec![poly1, poly2]);
        
        assert_eq!(oracle.num_polynomials(), 2);
        assert_eq!(oracle.num_variables(), 1);
        assert_eq!(oracle.query(0, 0).to_canonical_u64(), 1);
        assert_eq!(oracle.query(1, 1).to_canonical_u64(), 4);
    }
}
