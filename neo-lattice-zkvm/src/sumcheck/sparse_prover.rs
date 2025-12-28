// Sparse Sum-Check Prover
// Implements O(T) prover for T non-zero terms
//
// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 4.2 "Sparse Sum-check"
//
// This module implements a critical optimization for sum-check when the polynomial
// being summed has sparse structure - i.e., most evaluations are zero.
//
// Key Idea:
// Traditional sum-check prover processes all 2^n evaluations, even if most are zero.
// Sparse sum-check only processes the T non-zero terms, achieving O(T) complexity
// instead of O(2^n), which is exponentially better when T << 2^n.
//
// Mathematical Background:
// Given a polynomial g(x) with only T non-zero evaluations out of 2^n total,
// we want to prove: Σ_{x∈{0,1}^n} g(x) = C
//
// Instead of iterating over all 2^n points, we maintain a sparse representation:
// - Store only the T non-zero terms as (index, value) pairs
// - For each round, compute the round polynomial by iterating only over non-zero terms
// - Update the sparse representation by evaluating at the challenge point
//
// Algorithm Overview:
// 1. Initialize with sparse representation: {(x_i, g(x_i)) : g(x_i) ≠ 0}
// 2. For each round j:
//    a. Compute s_j(X) by summing over non-zero terms
//    b. Receive challenge r_j
//    c. Update sparse representation by binding variable j to r_j
// 3. Return final evaluation
//
// Structured Sparsity:
// When the polynomial has structured sparsity (e.g., block-sparse, low-rank),
// we can use prefix-suffix algorithms for even better performance.
//
// Paper Reference: Section 4.2.1 "Prefix-Suffix Algorithm"
//
// For polynomials of the form g(x,y) = p(x)·q(y), we can compute round polynomials
// in O(√T) time using:
// s_j(X) = Σ_x p(x)·[Σ_y q(y) where x_j = X]
//
// This exploits the tensor product structure to avoid redundant computation.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Sparse term in a multilinear polynomial
/// Represents a single non-zero evaluation point
#[derive(Clone, Debug)]
pub struct SparseTerm<F: Field> {
    /// Binary index of the evaluation point
    /// For n variables, this is a value in [0, 2^n)
    pub index: usize,
    
    /// Value at this point: g(index) ≠ 0
    pub value: F,
}

impl<F: Field> SparseTerm<F> {
    /// Create new sparse term
    pub fn new(index: usize, value: F) -> Self {
        Self { index, value }
    }
    
    /// Get bit at position i in the binary representation
    /// Used to determine which "side" of a variable binding this term falls on
    ///
    /// Example: For index = 5 = 0b101:
    /// - get_bit(0) = 1 (least significant bit)
    /// - get_bit(1) = 0
    /// - get_bit(2) = 1 (most significant bit)
    pub fn get_bit(&self, position: usize) -> bool {
        (self.index >> position) & 1 == 1
    }
    
    /// Update index after binding variable at position
    /// When we bind variable i to a challenge, we need to update the index
    /// by removing bit i and shifting higher bits down
    ///
    /// Paper Reference: Section 4.2, "Index Update"
    ///
    /// Example: If we bind variable 1 in index 0b1011 (11):
    /// - Bits 0 and 2-3 remain: 0b1_1 → 0b101 (5)
    pub fn update_index(&mut self, bound_position: usize) {
        // Extract bits below bound_position
        let lower_mask = (1 << bound_position) - 1;
        let lower_bits = self.index & lower_mask;
        
        // Extract bits above bound_position and shift down
        let upper_bits = (self.index >> (bound_position + 1)) << bound_position;
        
        // Combine
        self.index = upper_bits | lower_bits;
    }
}

/// Sparse sum-check prover
///
/// Paper Reference: "Sum-check Is All You Need", Section 4.2
///
/// Maintains a sparse representation of the polynomial and processes
/// only non-zero terms in each round.
pub struct SparseSumCheckProver<F: Field> {
    /// Current sparse terms (only non-zero evaluations)
    terms: Vec<SparseTerm<F>>,
    
    /// Number of variables in the original polynomial
    num_vars: usize,
    
    /// Current round (0-indexed)
    current_round: usize,
    
    /// Degree of the polynomial (typically 2 for products)
    degree: usize,
}

impl<F: Field> SparseSumCheckProver<F> {
    /// Create sparse sum-check prover from sparse representation
    ///
    /// Paper Reference: Section 4.2, "Sparse Representation"
    ///
    /// # Arguments
    /// * `terms` - Non-zero terms as (index, value) pairs
    /// * `num_vars` - Number of variables in the polynomial
    /// * `degree` - Maximum degree of the polynomial
    ///
    /// # Returns
    /// Prover that processes only T non-zero terms per round
    pub fn new(terms: Vec<SparseTerm<F>>, num_vars: usize, degree: usize) -> Self {
        Self {
            terms,
            num_vars,
            current_round: 0,
            degree,
        }
    }
    
    /// Create from dense polynomial by extracting non-zero terms
    ///
    /// This is useful when you have a dense representation but know
    /// the polynomial is sparse. The conversion is O(2^n) but only
    /// done once at setup.
    pub fn from_dense(poly: &MultilinearPolynomial<F>, degree: usize) -> Self {
        let mut terms = Vec::new();
        
        for (index, value) in poly.evaluations().iter().enumerate() {
            if value.to_canonical_u64() != 0 {
                terms.push(SparseTerm::new(index, *value));
            }
        }
        
        Self::new(terms, poly.num_vars(), degree)
    }
    
    /// Compute round polynomial s_j(X)
    ///
    /// Paper Reference: Section 4.2, Algorithm 4.1
    ///
    /// For round j, we compute:
    /// s_j(X) = Σ_{x'∈{0,1}^{n-j}} g(r_1,...,r_{j-1}, X, x')
    ///
    /// Key Optimization:
    /// We only sum over the T non-zero terms, not all 2^{n-j} terms.
    ///
    /// Algorithm:
    /// 1. Group terms by their bit at position j
    /// 2. For X=0: sum terms where bit j = 0
    /// 3. For X=1: sum terms where bit j = 1
    /// 4. Interpolate to get polynomial of degree ≤ d
    ///
    /// Complexity: O(T) where T is number of non-zero terms
    pub fn round_polynomial(&self) -> Vec<F> {
        if self.terms.is_empty() {
            return vec![F::zero(); self.degree + 1];
        }
        
        // Compute evaluations at X = 0, 1, ..., degree
        let mut evaluations = vec![F::zero(); self.degree + 1];
        
        for eval_point in 0..=self.degree {
            let mut sum = F::zero();
            
            for term in &self.terms {
                // Determine contribution of this term to s_j(eval_point)
                // This depends on the bit at position current_round
                let bit = term.get_bit(self.current_round);
                
                // Compute the contribution using linear interpolation
                // If bit = 0: contributes when X = 0
                // If bit = 1: contributes when X = 1
                // For general X: use (1-X)·term[bit=0] + X·term[bit=1]
                
                if eval_point == 0 && !bit {
                    sum = sum.add(&term.value);
                } else if eval_point == 1 && bit {
                    sum = sum.add(&term.value);
                } else if eval_point > 1 {
                    // For higher degree evaluations, use extrapolation
                    // This is needed when degree > 1 (e.g., for products)
                    let contribution = if bit {
                        // Term contributes at X=1, extrapolate to eval_point
                        term.value.mul(&F::from_u64(eval_point as u64))
                    } else {
                        // Term contributes at X=0, no contribution for eval_point > 0
                        F::zero()
                    };
                    sum = sum.add(&contribution);
                }
            }
            
            evaluations[eval_point] = sum;
        }
        
        evaluations
    }
    
    /// Update prover state with verifier challenge
    ///
    /// Paper Reference: Section 4.2, "Challenge Binding"
    ///
    /// After receiving challenge r_j, we:
    /// 1. Evaluate each term at r_j: term' = (1-r_j)·term[bit=0] + r_j·term[bit=1]
    /// 2. Update indices by removing bit j
    /// 3. Remove any terms that become zero
    ///
    /// Key Property:
    /// The number of non-zero terms can only decrease, maintaining sparsity.
    ///
    /// Complexity: O(T) where T is current number of non-zero terms
    pub fn update(&mut self, challenge: F) -> Result<(), String> {
        if self.current_round >= self.num_vars {
            return Err("No more rounds remaining".to_string());
        }
        
        let mut new_terms = Vec::new();
        let one_minus_r = F::one().sub(&challenge);
        
        // Group terms by their index after removing the current bit
        let mut grouped: HashMap<usize, F> = HashMap::new();
        
        for term in &self.terms {
            let bit = term.get_bit(self.current_round);
            
            // Compute new value: (1-r)·value[bit=0] + r·value[bit=1]
            let new_value = if bit {
                challenge.mul(&term.value)
            } else {
                one_minus_r.mul(&term.value)
            };
            
            // Compute new index (remove current bit)
            let mut new_term = SparseTerm::new(term.index, new_value);
            new_term.update_index(self.current_round);
            
            // Accumulate terms with same new index
            let entry = grouped.entry(new_term.index).or_insert(F::zero());
            *entry = entry.add(&new_value);
        }
        
        // Convert back to sparse terms, filtering zeros
        for (index, value) in grouped {
            if value.to_canonical_u64() != 0 {
                new_terms.push(SparseTerm::new(index, value));
            }
        }
        
        self.terms = new_terms;
        self.current_round += 1;
        
        Ok(())
    }
    
    /// Get final evaluation after all rounds
    ///
    /// After n rounds, we should have at most one non-zero term left,
    /// which is the evaluation g(r_1, ..., r_n).
    pub fn final_evaluation(&self) -> Result<F, String> {
        if self.current_round != self.num_vars {
            return Err(format!(
                "Not all rounds complete: {}/{}",
                self.current_round, self.num_vars
            ));
        }
        
        // Sum all remaining terms (should be at most 1)
        let mut sum = F::zero();
        for term in &self.terms {
            sum = sum.add(&term.value);
        }
        
        Ok(sum)
    }
    
    /// Get number of non-zero terms
    ///
    /// This is the key metric for sparse sum-check performance.
    /// Prover work per round is O(T) where T is this value.
    pub fn num_nonzero_terms(&self) -> usize {
        self.terms.len()
    }
    
    /// Check if prover is complete
    pub fn is_complete(&self) -> bool {
        self.current_round == self.num_vars
    }
}

/// Prefix-Suffix Sparse Prover
///
/// Paper Reference: Section 4.2.1 "Prefix-Suffix Algorithm"
///
/// For polynomials with tensor product structure g(x,y) = p(x)·q(y),
/// we can exploit this structure for even better performance.
///
/// Key Idea:
/// Instead of storing all T = |supp(p)| × |supp(q)| non-zero terms,
/// we store only the |supp(p)| + |supp(q)| non-zero terms of p and q.
///
/// Round Polynomial Computation:
/// s_j(X) = [Σ_x p(x) where x_j = X] · [Σ_y q(y)]
///
/// This reduces work from O(T) to O(√T) when |supp(p)| ≈ |supp(q)| ≈ √T.
pub struct PrefixSuffixProver<F: Field> {
    /// Sparse terms for prefix polynomial p(x)
    prefix_terms: Vec<SparseTerm<F>>,
    
    /// Sparse terms for suffix polynomial q(y)
    suffix_terms: Vec<SparseTerm<F>>,
    
    /// Number of variables in prefix
    prefix_vars: usize,
    
    /// Number of variables in suffix
    suffix_vars: usize,
    
    /// Current round
    current_round: usize,
}

impl<F: Field> PrefixSuffixProver<F> {
    /// Create prefix-suffix prover
    ///
    /// Paper Reference: Section 4.2.1
    ///
    /// # Arguments
    /// * `prefix_terms` - Non-zero terms of p(x)
    /// * `suffix_terms` - Non-zero terms of q(y)
    /// * `prefix_vars` - Number of variables in x
    /// * `suffix_vars` - Number of variables in y
    ///
    /// # Complexity
    /// Setup: O(|supp(p)| + |supp(q)|) instead of O(|supp(p)| × |supp(q)|)
    pub fn new(
        prefix_terms: Vec<SparseTerm<F>>,
        suffix_terms: Vec<SparseTerm<F>>,
        prefix_vars: usize,
        suffix_vars: usize,
    ) -> Self {
        Self {
            prefix_terms,
            suffix_terms,
            prefix_vars,
            suffix_vars,
            current_round: 0,
        }
    }
    
    /// Compute round polynomial using tensor structure
    ///
    /// Paper Reference: Section 4.2.1, Algorithm 4.2
    ///
    /// For round j:
    /// - If j < prefix_vars: s_j(X) = [Σ_x p(x) where x_j = X] · [Σ_y q(y)]
    /// - If j >= prefix_vars: s_j(X) = [Σ_x p(x)] · [Σ_y q(y) where y_{j-prefix_vars} = X]
    ///
    /// Complexity: O(|supp(p)| + |supp(q)|) instead of O(|supp(p)| × |supp(q)|)
    pub fn round_polynomial(&self) -> Vec<F> {
        let degree = 2; // For products
        let mut evaluations = vec![F::zero(); degree + 1];
        
        if self.current_round < self.prefix_vars {
            // Processing prefix variable
            for eval_point in 0..=degree {
                // Sum prefix terms where bit at current_round matches eval_point
                let mut prefix_sum = F::zero();
                for term in &self.prefix_terms {
                    let bit = term.get_bit(self.current_round);
                    if (eval_point == 0 && !bit) || (eval_point == 1 && bit) {
                        prefix_sum = prefix_sum.add(&term.value);
                    }
                }
                
                // Sum all suffix terms (independent of current variable)
                let mut suffix_sum = F::zero();
                for term in &self.suffix_terms {
                    suffix_sum = suffix_sum.add(&term.value);
                }
                
                evaluations[eval_point] = prefix_sum.mul(&suffix_sum);
            }
        } else {
            // Processing suffix variable
            let suffix_round = self.current_round - self.prefix_vars;
            
            for eval_point in 0..=degree {
                // Sum all prefix terms (independent of current variable)
                let mut prefix_sum = F::zero();
                for term in &self.prefix_terms {
                    prefix_sum = prefix_sum.add(&term.value);
                }
                
                // Sum suffix terms where bit at suffix_round matches eval_point
                let mut suffix_sum = F::zero();
                for term in &self.suffix_terms {
                    let bit = term.get_bit(suffix_round);
                    if (eval_point == 0 && !bit) || (eval_point == 1 && bit) {
                        suffix_sum = suffix_sum.add(&term.value);
                    }
                }
                
                evaluations[eval_point] = prefix_sum.mul(&suffix_sum);
            }
        }
        
        evaluations
    }
    
    /// Update with challenge
    ///
    /// Updates either prefix or suffix terms depending on current round.
    pub fn update(&mut self, challenge: F) -> Result<(), String> {
        let total_vars = self.prefix_vars + self.suffix_vars;
        if self.current_round >= total_vars {
            return Err("No more rounds remaining".to_string());
        }
        
        let one_minus_r = F::one().sub(&challenge);
        
        if self.current_round < self.prefix_vars {
            // Update prefix terms
            let mut new_prefix = Vec::new();
            let mut grouped: HashMap<usize, F> = HashMap::new();
            
            for term in &self.prefix_terms {
                let bit = term.get_bit(self.current_round);
                let new_value = if bit {
                    challenge.mul(&term.value)
                } else {
                    one_minus_r.mul(&term.value)
                };
                
                let mut new_term = SparseTerm::new(term.index, new_value);
                new_term.update_index(self.current_round);
                
                let entry = grouped.entry(new_term.index).or_insert(F::zero());
                *entry = entry.add(&new_value);
            }
            
            for (index, value) in grouped {
                if value.to_canonical_u64() != 0 {
                    new_prefix.push(SparseTerm::new(index, value));
                }
            }
            
            self.prefix_terms = new_prefix;
        } else {
            // Update suffix terms
            let suffix_round = self.current_round - self.prefix_vars;
            let mut new_suffix = Vec::new();
            let mut grouped: HashMap<usize, F> = HashMap::new();
            
            for term in &self.suffix_terms {
                let bit = term.get_bit(suffix_round);
                let new_value = if bit {
                    challenge.mul(&term.value)
                } else {
                    one_minus_r.mul(&term.value)
                };
                
                let mut new_term = SparseTerm::new(term.index, new_value);
                new_term.update_index(suffix_round);
                
                let entry = grouped.entry(new_term.index).or_insert(F::zero());
                *entry = entry.add(&new_value);
            }
            
            for (index, value) in grouped {
                if value.to_canonical_u64() != 0 {
                    new_suffix.push(SparseTerm::new(index, value));
                }
            }
            
            self.suffix_terms = new_suffix;
        }
        
        self.current_round += 1;
        Ok(())
    }
    
    /// Get final evaluation
    pub fn final_evaluation(&self) -> Result<F, String> {
        let total_vars = self.prefix_vars + self.suffix_vars;
        if self.current_round != total_vars {
            return Err("Not all rounds complete".to_string());
        }
        
        // Final value is product of remaining prefix and suffix sums
        let mut prefix_sum = F::zero();
        for term in &self.prefix_terms {
            prefix_sum = prefix_sum.add(&term.value);
        }
        
        let mut suffix_sum = F::zero();
        for term in &self.suffix_terms {
            suffix_sum = suffix_sum.add(&term.value);
        }
        
        Ok(prefix_sum.mul(&suffix_sum))
    }
    
    /// Get total number of stored terms
    ///
    /// This is |supp(p)| + |supp(q)|, which is much smaller than
    /// |supp(p)| × |supp(q)| when both are sparse.
    pub fn num_stored_terms(&self) -> usize {
        self.prefix_terms.len() + self.suffix_terms.len()
    }
}

/// Sparse sum-check proof
#[derive(Clone, Debug)]
pub struct SparseSumCheckProof<F: Field> {
    /// Round polynomials (one per variable)
    pub round_polynomials: Vec<Vec<F>>,
    
    /// Final evaluation
    pub final_evaluation: F,
    
    /// Claimed sum
    pub claimed_sum: F,
}

impl<F: Field> SparseSumCheckProof<F> {
    /// Create new sparse proof
    pub fn new(
        round_polynomials: Vec<Vec<F>>,
        final_evaluation: F,
        claimed_sum: F,
    ) -> Self {
        Self {
            round_polynomials,
            final_evaluation,
            claimed_sum,
        }
    }
    
    /// Get proof size in field elements
    pub fn size_in_field_elements(&self) -> usize {
        let round_poly_size: usize = self.round_polynomials.iter()
            .map(|poly| poly.len())
            .sum();
        round_poly_size + 2 // +2 for final_evaluation and claimed_sum
    }
}
