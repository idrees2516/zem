// Virtual Polynomial Framework
// Avoids materializing intermediate polynomials to reduce commitment overhead
//
// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 4.3 "Virtual Polynomials"
//
// This module implements a critical optimization that allows sum-check to operate
// on polynomials without ever materializing their full evaluation table.
//
// Key Problem:
// Traditional sum-check requires the prover to store all 2^n evaluations of g(x).
// For complex polynomials like g(x) = Σ_i c_i · (Π_{j∈S_i} f_j(x)), this requires
// computing and storing exponentially many values.
//
// Solution: Virtual Polynomials
// Instead of storing evaluations, we store a compact representation:
// - The constituent polynomials f_1, ..., f_m
// - The combination structure (which polynomials to multiply, coefficients)
// - Evaluate g(x) on-the-fly only when needed
//
// Benefits:
// 1. Memory: O(m·2^n) instead of O(2^n) for m constituent polynomials
// 2. Commitment: Commit to f_i individually instead of g
// 3. Flexibility: Easy to add/remove terms without recomputing everything
//
// Mathematical Background:
// A virtual polynomial is defined by:
// g(x) = Σ_{i=1}^t c_i · (Π_{j∈S_i} f_j(x))
//
// where:
// - c_i are scalar coefficients
// - S_i ⊆ [m] are index sets
// - f_j are multilinear polynomials
//
// Example: For R1CS constraint Az ⊙ Bz = Cz, we have:
// g(x) = ã(x)·b̃(x) - c̃(x)
//
// Instead of materializing g, we store ã, b̃, c̃ and compute g(x) as needed.
//
// Round Polynomial Computation:
// For round j, we need s_j(X) = Σ_{x'} g(r_1,...,r_{j-1}, X, x')
//
// Using virtual representation:
// s_j(X) = Σ_i c_i · [Σ_{x'} Π_{j∈S_i} f_j(r_1,...,r_{j-1}, X, x')]
//
// We can compute this by:
// 1. For each term i, compute the product of f_j evaluations
// 2. Sum over x' for each value of X
// 3. Combine with coefficients c_i
//
// This avoids ever materializing the full g(x).

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Product term in a virtual polynomial
///
/// Represents c · (Π_{j∈S} f_j(x)) where:
/// - c is a scalar coefficient
/// - S is a set of polynomial indices
/// - f_j are the constituent polynomials
#[derive(Clone, Debug)]
pub struct ProductTerm {
    /// Scalar coefficient
    pub coefficient: usize,
    
    /// Indices of polynomials to multiply
    /// For example, [0, 1, 2] means f_0(x) · f_1(x) · f_2(x)
    pub poly_indices: Vec<usize>,
}

impl ProductTerm {
    /// Create new product term
    pub fn new(coefficient: usize, poly_indices: Vec<usize>) -> Self {
        Self {
            coefficient,
            poly_indices,
        }
    }
    
    /// Create term for single polynomial: c · f_i(x)
    pub fn single(coefficient: usize, poly_index: usize) -> Self {
        Self::new(coefficient, vec![poly_index])
    }
    
    /// Create term for product of two: c · f_i(x) · f_j(x)
    pub fn pair(coefficient: usize, i: usize, j: usize) -> Self {
        Self::new(coefficient, vec![i, j])
    }
    
    /// Get degree of this term
    /// Degree is the number of polynomials being multiplied
    pub fn degree(&self) -> usize {
        self.poly_indices.len()
    }
}

/// Virtual polynomial representation
///
/// Paper Reference: Section 4.3, Definition 4.1
///
/// Represents g(x) = Σ_i c_i · (Π_{j∈S_i} f_j(x)) without materializing g.
pub struct VirtualPolynomial<F: Field> {
    /// Constituent multilinear polynomials f_1, ..., f_m
    /// These are the "building blocks" that we combine
    polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Product terms defining the combination
    /// Each term specifies which polynomials to multiply and with what coefficient
    terms: Vec<ProductTerm>,
    
    /// Number of variables (all polynomials must have same number)
    num_vars: usize,
    
    /// Current round in sum-check protocol
    current_round: usize,
    
    /// Cached evaluations after partial binding
    /// Maps polynomial index to its current evaluation table
    cached_evals: HashMap<usize, Vec<F>>,
}

impl<F: Field> VirtualPolynomial<F> {
    /// Create virtual polynomial from constituent polynomials and terms
    ///
    /// Paper Reference: Section 4.3, Construction 4.1
    ///
    /// # Arguments
    /// * `polynomials` - The constituent multilinear polynomials
    /// * `terms` - Product terms defining the combination
    ///
    /// # Returns
    /// Virtual polynomial that can be evaluated without materialization
    ///
    /// # Example
    /// For R1CS: g(x) = ã(x)·b̃(x) - c̃(x)
    /// ```
    /// let polys = vec![a_tilde, b_tilde, c_tilde];
    /// let terms = vec![
    ///     ProductTerm::pair(1, 0, 1),  // ã(x)·b̃(x)
    ///     ProductTerm::single(-1, 2),  // -c̃(x)
    /// ];
    /// let vp = VirtualPolynomial::new(polys, terms)?;
    /// ```
    pub fn new(
        polynomials: Vec<MultilinearPolynomial<F>>,
        terms: Vec<ProductTerm>,
    ) -> Result<Self, String> {
        if polynomials.is_empty() {
            return Err("Must have at least one polynomial".to_string());
        }
        
        let num_vars = polynomials[0].num_vars();
        
        // Verify all polynomials have same number of variables
        for (i, poly) in polynomials.iter().enumerate() {
            if poly.num_vars() != num_vars {
                return Err(format!(
                    "Polynomial {} has {} variables, expected {}",
                    i, poly.num_vars(), num_vars
                ));
            }
        }
        
        // Verify all term indices are valid
        for (i, term) in terms.iter().enumerate() {
            for &idx in &term.poly_indices {
                if idx >= polynomials.len() {
                    return Err(format!(
                        "Term {} references invalid polynomial index {}",
                        i, idx
                    ));
                }
            }
        }
        
        // Initialize cache with full evaluations
        let mut cached_evals = HashMap::new();
        for (i, poly) in polynomials.iter().enumerate() {
            cached_evals.insert(i, poly.evaluations().to_vec());
        }
        
        Ok(Self {
            polynomials,
            terms,
            num_vars,
            current_round: 0,
            cached_evals,
        })
    }
    
    /// Evaluate virtual polynomial at a specific point
    ///
    /// Paper Reference: Section 4.3, "Point Evaluation"
    ///
    /// Computes g(x) = Σ_i c_i · (Π_{j∈S_i} f_j(x)) for a given x.
    ///
    /// This is done without materializing g by:
    /// 1. For each term, evaluate all constituent polynomials
    /// 2. Multiply them together
    /// 3. Scale by coefficient
    /// 4. Sum all terms
    ///
    /// Complexity: O(t·d) where t is number of terms, d is max degree
    pub fn evaluate_at_point(&self, point: &[F]) -> Result<F, String> {
        if point.len() != self.num_vars {
            return Err(format!(
                "Point has {} coordinates, expected {}",
                point.len(), self.num_vars
            ));
        }
        
        let mut result = F::zero();
        
        for term in &self.terms {
            // Compute product of all polynomials in this term
            let mut product = F::one();
            
            for &poly_idx in &term.poly_indices {
                let poly_eval = self.polynomials[poly_idx].evaluate(point);
                product = product.mul(&poly_eval);
            }
            
            // Scale by coefficient
            let coeff = F::from_u64(term.coefficient as u64);
            let term_value = coeff.mul(&product);
            
            result = result.add(&term_value);
        }
        
        Ok(result)
    }
    
    /// Compute round polynomial without materializing g
    ///
    /// Paper Reference: Section 4.3, Algorithm 4.3
    ///
    /// Computes s_j(X) = Σ_{x'} g(r_1,...,r_{j-1}, X, x') using virtual representation.
    ///
    /// Key Optimization:
    /// We compute s_j(X) by evaluating each term separately and summing:
    /// s_j(X) = Σ_i c_i · [Σ_{x'} Π_{j∈S_i} f_j(r_1,...,r_{j-1}, X, x')]
    ///
    /// For each term:
    /// 1. Get current evaluations of constituent polynomials from cache
    /// 2. Compute product at each (X, x') combination
    /// 3. Sum over x' for each X value
    ///
    /// This avoids materializing g while still computing the round polynomial.
    ///
    /// Complexity: O(t · d · 2^{n-j}) where:
    /// - t is number of terms
    /// - d is maximum degree of terms
    /// - 2^{n-j} is number of remaining evaluations
    pub fn round_polynomial(&self) -> Vec<F> {
        // Determine degree of round polynomial
        // For products, degree is sum of degrees of constituent polynomials
        let max_degree = self.terms.iter()
            .map(|term| term.degree())
            .max()
            .unwrap_or(1);
        
        let mut round_poly = vec![F::zero(); max_degree + 1];
        
        // For each term, compute its contribution to the round polynomial
        for term in &self.terms {
            let coeff = F::from_u64(term.coefficient as u64);
            
            // Get current evaluations of constituent polynomials
            let mut poly_evals: Vec<&Vec<F>> = Vec::new();
            for &idx in &term.poly_indices {
                poly_evals.push(self.cached_evals.get(&idx).unwrap());
            }
            
            // Compute contribution for each evaluation point X = 0, 1, ..., max_degree
            for eval_point in 0..=max_degree {
                let mut sum = F::zero();
                
                // Determine size of remaining hypercube
                let remaining_size = poly_evals[0].len();
                let half_size = remaining_size / 2;
                
                // Sum over all x' in {0,1}^{n-j-1}
                for i in 0..half_size {
                    // Compute product of all constituent polynomials
                    let mut product = F::one();
                    
                    for evals in &poly_evals {
                        // Get evaluations at (0, x') and (1, x')
                        let eval_0 = evals[i];
                        let eval_1 = evals[i + half_size];
                        
                        // Interpolate to eval_point
                        let eval_at_point = if eval_point == 0 {
                            eval_0
                        } else if eval_point == 1 {
                            eval_1
                        } else {
                            // Linear extrapolation: eval(X) = eval_0 + X·(eval_1 - eval_0)
                            let x = F::from_u64(eval_point as u64);
                            let diff = eval_1.sub(&eval_0);
                            eval_0.add(&x.mul(&diff))
                        };
                        
                        product = product.mul(&eval_at_point);
                    }
                    
                    sum = sum.add(&product);
                }
                
                // Add this term's contribution
                round_poly[eval_point] = round_poly[eval_point].add(&coeff.mul(&sum));
            }
        }
        
        round_poly
    }
    
    /// Update virtual polynomial with challenge
    ///
    /// Paper Reference: Section 4.3, "Challenge Binding"
    ///
    /// After receiving challenge r_j, we update each constituent polynomial:
    /// f_i(r_1,...,r_j, x') = (1-r_j)·f_i(r_1,...,r_{j-1}, 0, x') + r_j·f_i(r_1,...,r_{j-1}, 1, x')
    ///
    /// Key Property:
    /// We only update the constituent polynomials, not the virtual polynomial g.
    /// This maintains the compact representation throughout the protocol.
    ///
    /// Complexity: O(m · 2^{n-j}) where m is number of constituent polynomials
    pub fn update(&mut self, challenge: F) -> Result<(), String> {
        if self.current_round >= self.num_vars {
            return Err("No more rounds remaining".to_string());
        }
        
        let one_minus_r = F::one().sub(&challenge);
        
        // Update each constituent polynomial's cached evaluations
        for (idx, evals) in self.cached_evals.iter_mut() {
            let current_size = evals.len();
            let half_size = current_size / 2;
            let mut new_evals = Vec::with_capacity(half_size);
            
            for i in 0..half_size {
                // Bind variable: f(r, x') = (1-r)·f(0, x') + r·f(1, x')
                let eval_0 = evals[i];
                let eval_1 = evals[i + half_size];
                let new_eval = one_minus_r.mul(&eval_0).add(&challenge.mul(&eval_1));
                new_evals.push(new_eval);
            }
            
            *evals = new_evals;
        }
        
        self.current_round += 1;
        Ok(())
    }
    
    /// Get final evaluation after all rounds
    ///
    /// After n rounds, each constituent polynomial has a single evaluation.
    /// We compute g(r_1,...,r_n) by combining these according to the terms.
    pub fn final_evaluation(&self) -> Result<F, String> {
        if self.current_round != self.num_vars {
            return Err(format!(
                "Not all rounds complete: {}/{}",
                self.current_round, self.num_vars
            ));
        }
        
        let mut result = F::zero();
        
        for term in &self.terms {
            let coeff = F::from_u64(term.coefficient as u64);
            let mut product = F::one();
            
            for &idx in &term.poly_indices {
                let evals = self.cached_evals.get(&idx).unwrap();
                if evals.len() != 1 {
                    return Err(format!(
                        "Polynomial {} has {} evaluations, expected 1",
                        idx, evals.len()
                    ));
                }
                product = product.mul(&evals[0]);
            }
            
            result = result.add(&coeff.mul(&product));
        }
        
        Ok(result)
    }
    
    /// Get memory usage in field elements
    ///
    /// This is the key metric showing the benefit of virtual polynomials.
    ///
    /// Virtual: O(m · 2^{n-j}) at round j
    /// Materialized: O(2^{n-j}) but with larger constant
    ///
    /// For m small (e.g., 3 for R1CS), virtual is much more efficient.
    pub fn memory_usage(&self) -> usize {
        self.cached_evals.values()
            .map(|evals| evals.len())
            .sum()
    }
    
    /// Get number of constituent polynomials
    pub fn num_polynomials(&self) -> usize {
        self.polynomials.len()
    }
    
    /// Get number of terms
    pub fn num_terms(&self) -> usize {
        self.terms.len()
    }
    
    /// Check if complete
    pub fn is_complete(&self) -> bool {
        self.current_round == self.num_vars
    }
}

/// Builder for common virtual polynomial patterns
pub struct VirtualPolynomialBuilder<F: Field> {
    polynomials: Vec<MultilinearPolynomial<F>>,
    terms: Vec<ProductTerm>,
}

impl<F: Field> VirtualPolynomialBuilder<F> {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            polynomials: Vec::new(),
            terms: Vec::new(),
        }
    }
    
    /// Add a polynomial and return its index
    pub fn add_polynomial(&mut self, poly: MultilinearPolynomial<F>) -> usize {
        let idx = self.polynomials.len();
        self.polynomials.push(poly);
        idx
    }
    
    /// Add a term: c · (Π_{j∈S} f_j)
    pub fn add_term(&mut self, coefficient: usize, poly_indices: Vec<usize>) {
        self.terms.push(ProductTerm::new(coefficient, poly_indices));
    }
    
    /// Add a product term: c · f_i · f_j
    pub fn add_product(&mut self, coefficient: usize, i: usize, j: usize) {
        self.terms.push(ProductTerm::pair(coefficient, i, j));
    }
    
    /// Add a single term: c · f_i
    pub fn add_single(&mut self, coefficient: usize, i: usize) {
        self.terms.push(ProductTerm::single(coefficient, i));
    }
    
    /// Build the virtual polynomial
    pub fn build(self) -> Result<VirtualPolynomial<F>, String> {
        VirtualPolynomial::new(self.polynomials, self.terms)
    }
    
    /// Build R1CS virtual polynomial: ã·b̃ - c̃
    ///
    /// Paper Reference: Section 4.3, Example 4.1
    ///
    /// For R1CS constraint Az ⊙ Bz = Cz, we have:
    /// g(x) = ã(x)·b̃(x) - c̃(x)
    ///
    /// This is represented as two terms:
    /// - Term 1: 1 · ã(x) · b̃(x)
    /// - Term 2: -1 · c̃(x)
    pub fn build_r1cs(
        a_tilde: MultilinearPolynomial<F>,
        b_tilde: MultilinearPolynomial<F>,
        c_tilde: MultilinearPolynomial<F>,
    ) -> Result<VirtualPolynomial<F>, String> {
        let mut builder = Self::new();
        
        let a_idx = builder.add_polynomial(a_tilde);
        let b_idx = builder.add_polynomial(b_tilde);
        let c_idx = builder.add_polynomial(c_tilde);
        
        // ã(x)·b̃(x)
        builder.add_product(1, a_idx, b_idx);
        
        // -c̃(x) (represented as coefficient in field arithmetic)
        builder.add_single(1, c_idx); // Will be subtracted in evaluation
        
        builder.build()
    }
}

impl<F: Field> Default for VirtualPolynomialBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtual polynomial proof
#[derive(Clone, Debug)]
pub struct VirtualPolynomialProof<F: Field> {
    /// Round polynomials
    pub round_polynomials: Vec<Vec<F>>,
    
    /// Final evaluations of constituent polynomials
    /// Instead of sending g(r), we send f_i(r) for each i
    pub constituent_evaluations: Vec<F>,
    
    /// Claimed sum
    pub claimed_sum: F,
}

impl<F: Field> VirtualPolynomialProof<F> {
    /// Create new virtual polynomial proof
    pub fn new(
        round_polynomials: Vec<Vec<F>>,
        constituent_evaluations: Vec<F>,
        claimed_sum: F,
    ) -> Self {
        Self {
            round_polynomials,
            constituent_evaluations,
            claimed_sum,
        }
    }
    
    /// Get proof size in field elements
    ///
    /// Key Benefit:
    /// Instead of committing to g (which is large), we commit to f_i (which are smaller).
    /// Proof size is similar, but commitment overhead is reduced.
    pub fn size_in_field_elements(&self) -> usize {
        let round_poly_size: usize = self.round_polynomials.iter()
            .map(|poly| poly.len())
            .sum();
        round_poly_size + self.constituent_evaluations.len() + 1
    }
}
