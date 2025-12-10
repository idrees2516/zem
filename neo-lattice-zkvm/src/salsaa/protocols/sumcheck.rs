// Π^sum: Sumcheck Protocol with Dynamic Programming
//
// Mathematical Background:
// Reduces sumcheck relation Σ_{z∈[d]^µ} g(z) = t to LDE evaluation claims.
// Uses dynamic programming to achieve O(m) prover complexity where m = d^µ.
//
// Protocol (Figure 2, Lemma 3):
// For polynomial g(X) = u^T · CRT(LDE[W](X) ⊙ LDE[W̄](X)):
//
// Round j ∈ [µ]:
// 1. Prover computes univariate g_j(X) = Σ_{z_{j+1},...,z_{µ-1}∈[d]} g(r_0,...,r_{j-1},X,z_{j+1},...,z_{µ-1})
// 2. Prover sends g_j (degree ≤ 2(d-1))
// 3. Verifier checks a_j = Σ_{k∈[d]} g_j(k) where a_0 = t, a_j = g_{j-1}(r_{j-1})
// 4. Verifier samples challenge r_j ∈ F_{q^e}^×
//
// After µ rounds:
// - Verifier has random point r = (r_0, ..., r_{µ-1})
// - Prover sends s_0 = LDE[W](r), s_1 = LDE[W̄](r̄)
// - Verifier checks a_µ = u^T · CRT(s_0 ⊙ s_1)
//
// Dynamic Programming Optimization:
// Instead of recomputing sums from scratch each round, maintain partial sums:
// - Precompute: For each prefix (z_0,...,z_j), store Σ_{z_{j+1},...} g(z_0,...,z_j,z_{j+1},...)
// - Update: When r_j is received, interpolate to get values at (r_0,...,r_j,z_{j+1},...)
// - Complexity: O(d^{j+1}) work per round j, total O(µ·d^µ) = O(m·log m)
//
// Communication: (2d-1)µe log q + 2r log |R_q| bits
// - µ rounds × (2d-1) coefficients × e × log q bits per round
// - 2 final evaluations × r columns × log |R_q| bits
//
// Reference: SALSAA paper Figure 2, Lemma 3, Requirements 6.1, 6.2, 6.3

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::{CRTContext, ExtFieldElement, ModulusType};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::lde::LDEContext;
use crate::salsaa::relations::{
    SumcheckStatement, SumcheckWitness, LDEStatement, LDEWitness,
};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Sumcheck protocol with dynamic programming
pub struct SumcheckReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// LDE context for polynomial evaluation
    pub lde_context: Arc<LDEContext<F>>,
    
    /// CRT context for slot-wise operations
    pub crt_context: Arc<CRTContext<F>>,
    
    /// Degree bound per variable
    pub degree: usize,
    
    /// Number of variables
    pub num_vars: usize,
}

/// Sumcheck round polynomial
///
/// Represents g_j(X) sent by prover in round j
#[derive(Clone, Debug)]
pub struct RoundPolynomial<F: Field> {
    /// Coefficients of g_j(X) in monomial basis
    /// Degree is at most 2(d-1)
    pub coeffs: Vec<ExtFieldElement<F>>,
}

/// Sumcheck proof
///
/// Contains all round polynomials and final evaluations
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials g_0, g_1, ..., g_{µ-1}
    pub round_polynomials: Vec<RoundPolynomial<F>>,
    
    /// Final evaluation s_0 = LDE[W](r)
    pub final_eval_w: Vec<RingElement<F>>,
    
    /// Final evaluation s_1 = LDE[W̄](r̄)
    pub final_eval_w_conj: Vec<RingElement<F>>,
    
    /// Challenge point r = (r_0, ..., r_{µ-1})
    pub challenge_point: Vec<ExtFieldElement<F>>,
}

impl<F: Field> SumcheckReduction<F> {
    /// Create new sumcheck reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        lde_context: Arc<LDEContext<F>>,
        crt_context: Arc<CRTContext<F>>,
    ) -> Self {
        let degree = lde_context.degree;
        let num_vars = lde_context.num_vars;
        
        Self {
            ring,
            lde_context,
            crt_context,
            degree,
            num_vars,
        }
    }
    
    /// Prover sumcheck with O(m) complexity using dynamic programming
    ///
    /// Algorithm:
    /// 1. Initialize: Compute g(z) for all z ∈ [d]^µ
    /// 2. For each round j:
    ///    a. Compute g_j(X) using partial sums
    ///    b. Send g_j to verifier (via transcript)
    ///    c. Receive challenge r_j
    ///    d. Update partial sums for next round
    /// 3. Compute final evaluations s_0, s_1
    ///
    /// Complexity: O(d^µ) = O(m) ring operations
    pub fn prover_sumcheck(
        &self,
        statement: &SumcheckStatement<F>,
        witness: &SumcheckWitness<F>,
        transcript: &mut Transcript,
    ) -> SumcheckProof<F> {
        let d = self.degree;
        let mu = self.num_vars;
        let num_cols = statement.num_columns;
        
        // Step 1: Precompute g(z) = u^T · CRT(LDE[W](z) ⊙ LDE[W̄](z)) for all z ∈ [d]^µ
        let g_values = self.compute_g_values(
            &witness.w_matrix,
            &witness.w_conjugate,
            &statement.batching_vector,
        );
        
        // Initialize partial sums table
        // partial_sums[level][index] = sum over remaining variables
        let mut partial_sums = vec![g_values.clone()];
        
        let mut round_polynomials = Vec::with_capacity(mu);
        let mut challenges = Vec::with_capacity(mu);
        
        // Sumcheck rounds
        for round in 0..mu {
            // Compute round polynomial g_j(X)
            let round_poly = self.compute_round_polynomial(
                &partial_sums[round],
                round,
                d,
            );
            
            // Send round polynomial to transcript
            transcript.append_ext_field_vector(
                format!("sumcheck-round-{}", round).as_bytes(),
                &round_poly.coeffs,
            );
            
            round_polynomials.push(round_poly.clone());
            
            // Receive challenge r_j from verifier
            let challenge = transcript.challenge_ext_field(
                format!("sumcheck-challenge-{}", round).as_bytes(),
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            
            challenges.push(challenge.clone());
            
            // Update partial sums for next round
            if round < mu - 1 {
                let next_partial_sums = self.update_partial_sums(
                    &partial_sums[round],
                    &challenge,
                    round,
                    d,
                );
                partial_sums.push(next_partial_sums);
            }
        }
        
        // Step 3: Compute final evaluations
        // Lift challenges to ring elements
        let lifted_challenges = self.crt_context.lift_challenge_vector(&challenges);
        
        // Evaluate LDE[W](r)
        let final_eval_w = self.evaluate_matrix_lde(
            &witness.w_matrix,
            &lifted_challenges,
        );
        
        // Evaluate LDE[W̄](r̄)
        let conjugate_challenges: Vec<RingElement<F>> = lifted_challenges.iter()
            .map(|r| self.ring.conjugate(r))
            .collect();
        
        let final_eval_w_conj = self.evaluate_matrix_lde(
            &witness.w_conjugate,
            &conjugate_challenges,
        );
        
        // Send final evaluations to transcript
        transcript.append_ring_vector(b"sumcheck-final-w", &final_eval_w);
        transcript.append_ring_vector(b"sumcheck-final-w-conj", &final_eval_w_conj);
        
        SumcheckProof {
            round_polynomials,
            final_eval_w,
            final_eval_w_conj,
            challenge_point: challenges,
        }
    }
    
    /// Verifier sumcheck
    ///
    /// Verifies:
    /// 1. Round consistency: a_j = Σ_{k∈[d]} g_j(k)
    /// 2. Final check: a_µ = u^T · CRT(s_0 ⊙ s_1)
    ///
    /// Returns LDE statement for final evaluation claims
    pub fn verifier_sumcheck(
        &self,
        statement: &SumcheckStatement<F>,
        proof: &SumcheckProof<F>,
        transcript: &mut Transcript,
    ) -> Result<LDEStatement<F>, String> {
        let d = self.degree;
        let mu = self.num_vars;
        
        if proof.round_polynomials.len() != mu {
            return Err(format!("Expected {} round polynomials, got {}", 
                mu, proof.round_polynomials.len()));
        }
        
        let mut current_sum = statement.claimed_sum.clone();
        let mut challenges = Vec::with_capacity(mu);
        
        // Verify each round
        for (round, round_poly) in proof.round_polynomials.iter().enumerate() {
            // Add round polynomial to transcript
            transcript.append_ext_field_vector(
                format!("sumcheck-round-{}", round).as_bytes(),
                &round_poly.coeffs,
            );
            
            // Check: Σ_{k∈[d]} g_j(k) = current_sum
            let poly_sum = self.sum_polynomial_over_domain(round_poly, d);
            
            if !self.ext_field_equal(&poly_sum, &current_sum) {
                return Err(format!("Round {} sum check failed", round));
            }
            
            // Sample challenge
            let challenge = transcript.challenge_ext_field(
                format!("sumcheck-challenge-{}", round).as_bytes(),
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            
            challenges.push(challenge.clone());
            
            // Update current_sum = g_j(r_j)
            current_sum = self.evaluate_polynomial(round_poly, &challenge);
        }
        
        // Verify final evaluations are in transcript
        transcript.append_ring_vector(b"sumcheck-final-w", &proof.final_eval_w);
        transcript.append_ring_vector(b"sumcheck-final-w-conj", &proof.final_eval_w_conj);
        
        // Final check: a_µ = u^T · CRT(s_0 ⊙ s_1)
        let final_check = self.compute_final_check(
            &proof.final_eval_w,
            &proof.final_eval_w_conj,
            &statement.batching_vector,
        );
        
        if !self.ext_field_equal(&final_check, &current_sum) {
            return Err("Final sumcheck verification failed".to_string());
        }
        
        // Create LDE statement for evaluation claims
        let lde_statement = LDEStatement {
            eval_points: vec![
                challenges.clone(),
                challenges.iter().map(|c| self.conjugate_ext_field(c)).collect(),
            ],
            claimed_values: vec![
                proof.final_eval_w.clone(),
                proof.final_eval_w_conj.clone(),
            ],
            tensor_matrices: vec![],
        };
        
        Ok(lde_statement)
    }
    
    /// Compute g(z) = u^T · CRT(LDE[W](z) ⊙ LDE[W̄](z)) for all z ∈ [d]^µ
    ///
    /// This is the polynomial we're summing over in the sumcheck.
    /// Precomputing all values enables O(m) prover complexity.
    fn compute_g_values(
        &self,
        w_matrix: &Matrix<F>,
        w_conjugate: &Matrix<F>,
        batching_vector: &[ExtFieldElement<F>],
    ) -> Vec<ExtFieldElement<F>> {
        let d = self.degree;
        let mu = self.num_vars;
        let total_points = d.pow(mu as u32);
        
        let mut g_values = Vec::with_capacity(total_points);
        
        // For each grid point z ∈ [d]^µ
        for flat_idx in 0..total_points {
            // Convert flat index to multi-index
            let multi_idx = self.lde_context.flat_to_multi_index(flat_idx);
            
            // Convert to ring elements
            let z_point: Vec<RingElement<F>> = multi_idx.iter()
                .map(|&idx| self.ring.from_u64(idx as u64))
                .collect();
            
            // Evaluate LDE[W](z) for each column
            let w_eval = self.evaluate_matrix_lde(w_matrix, &z_point);
            
            // Evaluate LDE[W̄](z) for each column
            let w_conj_eval = self.evaluate_matrix_lde(w_conjugate, &z_point);
            
            // Compute Hadamard product in CRT domain
            let w_crt = self.crt_context.vector_to_crt(&w_eval);
            let w_conj_crt = self.crt_context.vector_to_crt(&w_conj_eval);
            let hadamard_crt = self.crt_context.hadamard_product_crt(&w_crt, &w_conj_crt);
            
            // Compute inner product with batching vector
            let g_z = self.inner_product_ext_field(&batching_vector, &hadamard_crt);
            
            g_values.push(g_z);
        }
        
        g_values
    }
    
    /// Compute round polynomial g_j(X) using partial sums
    ///
    /// g_j(X) = Σ_{z_{j+1},...,z_{µ-1}∈[d]} g(r_0,...,r_{j-1},X,z_{j+1},...,z_{µ-1})
    ///
    /// Uses Lagrange interpolation over points {0, 1, ..., d-1}
    fn compute_round_polynomial(
        &self,
        partial_sums: &[ExtFieldElement<F>],
        round: usize,
        d: usize,
    ) -> RoundPolynomial<F> {
        let degree_bound = 2 * (d - 1);
        
        // Compute evaluations at points 0, 1, ..., 2(d-1)
        let mut evaluations = Vec::with_capacity(degree_bound + 1);
        
        for x in 0..=degree_bound {
            let mut sum = ExtFieldElement::zero(
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            
            // Sum over all assignments to remaining variables
            let stride = d.pow((self.num_vars - round - 1) as u32);
            
            for base_idx in 0..(partial_sums.len() / d) {
                for k in 0..d {
                    let idx = base_idx * d + k;
                    if idx < partial_sums.len() {
                        // Lagrange basis: L_k(x) = ∏_{j≠k} (x-j)/(k-j)
                        let lagrange_coeff = self.lagrange_basis_eval(x, k, d);
                        let term = partial_sums[idx].scalar_mul(&lagrange_coeff);
                        sum = sum.add(&term);
                    }
                }
            }
            
            evaluations.push(sum);
        }
        
        // Interpolate to get polynomial coefficients
        let coeffs = self.interpolate_polynomial(&evaluations);
        
        RoundPolynomial { coeffs }
    }
    
    /// Update partial sums after receiving challenge r_j
    ///
    /// For each prefix (z_0,...,z_j,r_j), compute sum over (z_{j+2},...,z_{µ-1})
    fn update_partial_sums(
        &self,
        current_sums: &[ExtFieldElement<F>],
        challenge: &ExtFieldElement<F>,
        round: usize,
        d: usize,
    ) -> Vec<ExtFieldElement<F>> {
        let next_size = current_sums.len() / d;
        let mut next_sums = Vec::with_capacity(next_size);
        
        for base_idx in 0..next_size {
            // Interpolate at challenge point
            let mut interpolated = ExtFieldElement::zero(
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            
            for k in 0..d {
                let idx = base_idx * d + k;
                if idx < current_sums.len() {
                    let lagrange_coeff = self.lagrange_basis_eval_ext(challenge, k, d);
                    let term = current_sums[idx].mul(&lagrange_coeff);
                    interpolated = interpolated.add(&term);
                }
            }
            
            next_sums.push(interpolated);
        }
        
        next_sums
    }
    
    /// Evaluate matrix LDE at point
    fn evaluate_matrix_lde(
        &self,
        matrix: &Matrix<F>,
        point: &[RingElement<F>],
    ) -> Vec<RingElement<F>> {
        let num_cols = matrix.cols;
        let mut result = Vec::with_capacity(num_cols);
        
        for col_idx in 0..num_cols {
            let column = matrix.get_col(col_idx);
            let eval = self.lde_context.evaluate_lde(&column, point);
            result.push(eval);
        }
        
        result
    }
    
    /// Lagrange basis evaluation at integer point
    fn lagrange_basis_eval(&self, x: usize, k: usize, d: usize) -> F {
        if x == k {
            return F::one();
        }
        
        let mut numerator = F::one();
        let mut denominator = F::one();
        
        for j in 0..d {
            if j != k {
                let x_minus_j = if x >= j {
                    F::from_u64((x - j) as u64)
                } else {
                    F::from_u64((j - x) as u64).neg()
                };
                
                let k_minus_j = if k >= j {
                    F::from_u64((k - j) as u64)
                } else {
                    F::from_u64((j - k) as u64).neg()
                };
                
                numerator = numerator.mul(&x_minus_j);
                denominator = denominator.mul(&k_minus_j);
            }
        }
        
        let denom_inv = denominator.inverse().unwrap_or(F::one());
        numerator.mul(&denom_inv)
    }
    
    /// Lagrange basis evaluation at extension field point
    fn lagrange_basis_eval_ext(
        &self,
        x: &ExtFieldElement<F>,
        k: usize,
        d: usize,
    ) -> ExtFieldElement<F> {
        let mut numerator = ExtFieldElement::one(x.degree, x.modulus_type.clone());
        let mut denominator = F::one();
        
        for j in 0..d {
            if j != k {
                let j_elem = ExtFieldElement::from_base(
                    F::from_u64(j as u64),
                    x.degree,
                    x.modulus_type.clone(),
                );
                let x_minus_j = x.sub(&j_elem);
                numerator = numerator.mul(&x_minus_j);
                
                let k_minus_j = if k >= j {
                    F::from_u64((k - j) as u64)
                } else {
                    F::from_u64((j - k) as u64).neg()
                };
                denominator = denominator.mul(&k_minus_j);
            }
        }
        
        let denom_inv = denominator.inverse().unwrap_or(F::one());
        numerator.scalar_mul(&denom_inv)
    }
    
    /// Interpolate polynomial from evaluations
    fn interpolate_polynomial(
        &self,
        evaluations: &[ExtFieldElement<F>],
    ) -> Vec<ExtFieldElement<F>> {
        // Use Lagrange interpolation
        let n = evaluations.len();
        let mut coeffs = vec![
            ExtFieldElement::zero(
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            n
        ];
        
        for i in 0..n {
            let mut basis_poly = vec![F::one()];
            
            for j in 0..n {
                if i != j {
                    // Multiply by (X - j) / (i - j)
                    let denom = if i >= j {
                        F::from_u64((i - j) as u64)
                    } else {
                        F::from_u64((j - i) as u64).neg()
                    };
                    let denom_inv = denom.inverse().unwrap_or(F::one());
                    
                    // Multiply polynomial by (X - j)
                    let mut new_poly = vec![F::zero(); basis_poly.len() + 1];
                    for (k, &coeff) in basis_poly.iter().enumerate() {
                        new_poly[k] = new_poly[k].add(&coeff.mul(&F::from_u64(j as u64).neg()));
                        new_poly[k + 1] = new_poly[k + 1].add(&coeff);
                    }
                    
                    // Scale by 1/(i-j)
                    for coeff in &mut new_poly {
                        *coeff = coeff.mul(&denom_inv);
                    }
                    
                    basis_poly = new_poly;
                }
            }
            
            // Add evaluations[i] * basis_poly to coeffs
            for (k, &base_coeff) in basis_poly.iter().enumerate() {
                if k < coeffs.len() {
                    let term = evaluations[i].scalar_mul(&base_coeff);
                    coeffs[k] = coeffs[k].add(&term);
                }
            }
        }
        
        coeffs
    }
    
    /// Sum polynomial over domain [d]
    fn sum_polynomial_over_domain(
        &self,
        poly: &RoundPolynomial<F>,
        d: usize,
    ) -> ExtFieldElement<F> {
        let mut sum = ExtFieldElement::zero(
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        for k in 0..d {
            let k_elem = ExtFieldElement::from_base(
                F::from_u64(k as u64),
                self.crt_context.slot_degree,
                self.crt_context.modulus_type.clone(),
            );
            let eval = self.evaluate_polynomial(poly, &k_elem);
            sum = sum.add(&eval);
        }
        
        sum
    }
    
    /// Evaluate polynomial at point
    fn evaluate_polynomial(
        &self,
        poly: &RoundPolynomial<F>,
        point: &ExtFieldElement<F>,
    ) -> ExtFieldElement<F> {
        if poly.coeffs.is_empty() {
            return ExtFieldElement::zero(point.degree, point.modulus_type.clone());
        }
        
        // Horner's method
        let mut result = poly.coeffs[poly.coeffs.len() - 1].clone();
        
        for i in (0..poly.coeffs.len() - 1).rev() {
            result = result.mul(point);
            result = result.add(&poly.coeffs[i]);
        }
        
        result
    }
    
    /// Compute final check value
    fn compute_final_check(
        &self,
        s0: &[RingElement<F>],
        s1: &[RingElement<F>],
        batching_vector: &[ExtFieldElement<F>],
    ) -> ExtFieldElement<F> {
        // Convert to CRT
        let s0_crt = self.crt_context.vector_to_crt(s0);
        let s1_crt = self.crt_context.vector_to_crt(s1);
        
        // Hadamard product
        let hadamard = self.crt_context.hadamard_product_crt(&s0_crt, &s1_crt);
        
        // Inner product with batching vector
        self.inner_product_ext_field(batching_vector, &hadamard)
    }
    
    /// Inner product in extension field
    fn inner_product_ext_field(
        &self,
        a: &[ExtFieldElement<F>],
        b: &[ExtFieldElement<F>],
    ) -> ExtFieldElement<F> {
        assert_eq!(a.len(), b.len());
        
        let mut result = ExtFieldElement::zero(
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        for (ai, bi) in a.iter().zip(b.iter()) {
            let prod = ai.mul(bi);
            result = result.add(&prod);
        }
        
        result
    }
    
    /// Check extension field equality
    fn ext_field_equal(&self, a: &ExtFieldElement<F>, b: &ExtFieldElement<F>) -> bool {
        if a.degree != b.degree {
            return false;
        }
        
        for (ac, bc) in a.coeffs.iter().zip(b.coeffs.iter()) {
            if ac.to_canonical_u64() != bc.to_canonical_u64() {
                return false;
            }
        }
        
        true
    }
    
    /// Conjugate extension field element
    ///
    /// For F_{q^e} represented as F_q[X]/(m(X)), conjugation is the Frobenius automorphism:
    /// σ(a) = a^q for a ∈ F_{q^e}
    ///
    /// For power-of-2 cyclotomics with m(X) = X^e + 1:
    /// - If e is even, conjugation negates odd-power coefficients
    /// - This corresponds to the complex conjugation in the canonical embedding
    ///
    /// For general extensions:
    /// - Apply Frobenius: (a_0 + a_1·α + ... + a_{e-1}·α^{e-1})^q
    /// - This requires computing α^q in the quotient ring
    fn conjugate_ext_field(&self, elem: &ExtFieldElement<F>) -> ExtFieldElement<F> {
        match &elem.modulus_type {
            crate::ring::crt::ModulusType::PowerOfTwoCyclotomic => {
                // For X^e + 1, conjugation negates odd-power coefficients
                let mut conj_coeffs = elem.coeffs.clone();
                for i in (1..conj_coeffs.len()).step_by(2) {
                    conj_coeffs[i] = conj_coeffs[i].neg();
                }
                
                ExtFieldElement {
                    coeffs: conj_coeffs,
                    degree: elem.degree,
                    modulus_type: elem.modulus_type.clone(),
                }
            }
            crate::ring::crt::ModulusType::CyclotomicMinusOne => {
                // For X^e - 1, conjugation is more complex
                // Apply Frobenius automorphism: a ↦ a^q
                let q = F::characteristic();
                elem.pow(q)
            }
            crate::ring::crt::ModulusType::General(_) => {
                // For general minimal polynomial, apply Frobenius
                let q = F::characteristic();
                elem.pow(q)
            }
        }
    }
}
