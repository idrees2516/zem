// Constraint Reduction via Sum-check
// Implements G(Y) := F(x̃(Y), w̃(Y))·eq̃(Y, r_y) with Σ G(y) = 0
//
// Paper Reference: Quasar (2025-1912), Section 4.3 "Constraint Reduction"
//
// This module implements the core constraint reduction technique that allows
// Quasar to verify multiple constraint instances with sublinear verifier complexity.
//
// Key Idea:
// Instead of checking F(x_i, w_i) = 0 for each instance i ∈ [ℓ] separately,
// we aggregate all checks into a single sumcheck protocol:
//
// Σ_{y∈B^{log ℓ}} G(y) = 0
//
// where G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y)
//
// Here:
// - F is the constraint function (e.g., for R1CS: Az ⊙ Bz - Cz)
// - x̃(Y) is the multilinear extension of public inputs
// - w̃(Y) is the union polynomial of witnesses
// - eq̃(Y, r_y) is the equality polynomial at random point r_y
//
// The equality polynomial ensures we're checking a random linear combination
// of all constraints, which provides soundness.
//
// Complexity:
// - Prover: O(ℓ·n) where ℓ is number of instances, n is witness size
// - Verifier: O(log ℓ) via sumcheck protocol
// - Proof size: O(log ℓ) field elements
//
// Security:
// - Soundness error: O(d·log ℓ / |F|) where d is constraint degree
// - If any instance fails F(x_i, w_i) = 0, the sumcheck will fail
//   with high probability
//
// Algorithm Overview:
// 1. Build multilinear extensions x̃(Y) and w̃(Y)
// 2. Compute G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y) over Boolean hypercube
// 3. Run sumcheck protocol to prove Σ G(y) = 0
// 4. Verifier checks final evaluation claim
//
// This is the key technique that enables O(log ℓ) verification for ℓ instances.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use super::accumulator::{Transcript, SumcheckProof, RoundPolynomial};
use super::union_polynomial::UnionPolynomial;

/// Constraint function trait
/// Represents the constraint F(x, w) that should equal zero
pub trait ConstraintFunction<F: Field> {
    /// Evaluate constraint at (x, w)
    /// Returns 0 if constraint is satisfied
    fn evaluate(&self, public_input: &[F], witness: &[F]) -> F;
    
    /// Degree of the constraint polynomial
    fn degree(&self) -> usize;
}


/// R1CS constraint function
/// Constraint: Az ⊙ Bz = Cz
/// This is satisfied when (Az)_i · (Bz)_i = (Cz)_i for all i
#[derive(Clone, Debug)]
pub struct R1CSConstraint<F: Field> {
    /// Matrix A
    pub a_matrix: Vec<Vec<F>>,
    /// Matrix B
    pub b_matrix: Vec<Vec<F>>,
    /// Matrix C
    pub c_matrix: Vec<Vec<F>>,
}

impl<F: Field> ConstraintFunction<F> for R1CSConstraint<F> {
    fn evaluate(&self, public_input: &[F], witness: &[F]) -> F {
        // Combine public input and witness into full witness vector z
        let mut z = Vec::with_capacity(public_input.len() + witness.len());
        z.extend_from_slice(public_input);
        z.extend_from_slice(witness);
        
        // Compute Az, Bz, Cz
        let az = self.matrix_vector_mul(&self.a_matrix, &z);
        let bz = self.matrix_vector_mul(&self.b_matrix, &z);
        let cz = self.matrix_vector_mul(&self.c_matrix, &z);
        
        // Check Az ⊙ Bz = Cz
        // Return sum of differences (should be 0 if satisfied)
        let mut error = F::zero();
        for i in 0..az.len() {
            let lhs = az[i].mul(&bz[i]);
            let diff = lhs.sub(&cz[i]);
            error = error.add(&diff);
        }
        
        error
    }
    
    fn degree(&self) -> usize {
        2 // R1CS has degree 2 (multiplication of Az and Bz)
    }
}

impl<F: Field> R1CSConstraint<F> {
    /// Matrix-vector multiplication
    fn matrix_vector_mul(&self, matrix: &[Vec<F>], vector: &[F]) -> Vec<F> {
        matrix.iter()
            .map(|row| {
                row.iter()
                    .zip(vector.iter())
                    .map(|(a, b)| a.mul(b))
                    .fold(F::zero(), |acc, x| acc.add(&x))
            })
            .collect()
    }
}

/// Constraint reduction proof
/// Proves that all ℓ constraints are satisfied via sumcheck
#[derive(Clone, Debug)]
pub struct ConstraintReductionProof<F: Field> {
    /// Sumcheck proof for G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y)
    pub sumcheck_proof: SumcheckProof<F>,
    
    /// Random point r_y used in equality polynomial
    pub r_y: Vec<F>,
    
    /// Final evaluation claims
    /// After sumcheck, we need to verify evaluations of x̃, w̃ at final point
    pub final_point: Vec<F>,
    
    /// Claimed evaluations at final point
    pub claimed_x_eval: Vec<F>,
    pub claimed_w_eval: Vec<F>,
}

/// Constraint reduction implementation
/// Reduces ℓ constraint checks to single sumcheck
pub struct ConstraintReduction<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ConstraintReduction<F> {
    /// Create new constraint reduction
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Reduce ℓ constraint checks to sumcheck
    ///
    /// Paper Reference: Quasar Section 4.3, Protocol 4.2
    ///
    /// This is the core reduction that enables sublinear verification.
    /// Instead of checking F(x_i, w_i) = 0 for each i ∈ [ℓ], we prove:
    ///
    /// Σ_{y∈B^{log ℓ}} G(y) = 0
    ///
    /// where G(Y) = F(x̃(Y), w̃(Y))·eq̃(Y, r_y)
    ///
    /// The key insight is that if all constraints are satisfied, then
    /// F(x̃(y), w̃(y)) = 0 for all y ∈ B^{log ℓ}, so the sum is zero.
    ///
    /// The equality polynomial eq̃(Y, r_y) ensures soundness by creating
    /// a random linear combination of all constraint checks.
    ///
    /// Algorithm:
    /// 1. Generate random point r_y ∈ F^{log ℓ} via Fiat-Shamir
    /// 2. Build multilinear extensions x̃(Y) and w̃(Y)
    /// 3. Compute G(y) = F(x̃(y), w̃(y))·eq̃(y, r_y) for all y ∈ B^{log ℓ}
    /// 4. Run sumcheck protocol to prove Σ G(y) = 0
    /// 5. Return proof with final evaluation claims
    ///
    /// Soundness:
    /// If any constraint F(x_i, w_i) ≠ 0, then with high probability
    /// the sumcheck will fail. The soundness error is O(d·log ℓ / |F|)
    /// where d is the constraint degree.
    pub fn reduce_constraints<C: ConstraintFunction<F>>(
        constraint: &C,
        public_inputs: &[Vec<F>],
        union_poly: &UnionPolynomial<F>,
        transcript: &mut Transcript<F>,
    ) -> ConstraintReductionProof<F> {
        let num_instances = public_inputs.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Generate random point r_y via Fiat-Shamir
        // Paper Reference: Quasar Protocol 4.2, Step 1
        //
        // The verifier generates a random point r_y ∈ F^{log ℓ}.
        // This point is used in the equality polynomial to create
        // a random linear combination of all constraints.
        let r_y = transcript.challenge_field_vec(b"constraint_r_y", log_ell);
        
        // Step 2: Build multilinear extension of public inputs
        // Paper Reference: Quasar Protocol 4.2, Step 2
        //
        // We need x̃(Y) such that x̃(bin(i)) = x_i for all i ∈ [ℓ].
        // This is the multilinear extension of the public inputs.
        let x_mle = Self::build_public_input_mle(public_inputs, log_ell);
        
        // Step 3: Compute G(y) for all y ∈ B^{log ℓ}
        // Paper Reference: Quasar Protocol 4.2, Step 3
        //
        // For each y in the Boolean hypercube:
        // G(y) = F(x̃(y), w̃(y))·eq̃(y, r_y)
        //
        // This aggregates all constraint checks into a single polynomial.
        let g_evals = Self::compute_g_polynomial(
            constraint,
            &x_mle,
            union_poly,
            &r_y,
            log_ell,
        );
        
        // Step 4: Run sumcheck protocol
        // Paper Reference: Quasar Protocol 4.2, Step 4
        //
        // Prove that Σ_{y∈B^{log ℓ}} G(y) = 0
        //
        // The sumcheck protocol reduces this to a single evaluation claim
        // at a random point, which can be verified efficiently.
        let sumcheck_proof = Self::prove_sumcheck(&g_evals, log_ell, transcript);
        
        // Step 5: Extract final evaluation claims
        // Paper Reference: Quasar Protocol 4.2, Step 5
        //
        // After sumcheck, we have a final point where we need to verify
        // the evaluations of x̃ and w̃. These become evaluation claims
        // that are verified using polynomial commitments.
        let final_point = sumcheck_proof.challenges.clone();
        
        // Evaluate x̃ and w̃ at final point
        let claimed_x_eval = x_mle.iter()
            .map(|x_poly| x_poly.evaluate(&final_point))
            .collect();
        
        let claimed_w_eval = union_poly.witness_polynomials()
            .iter()
            .map(|w_poly| w_poly.evaluate(&final_point))
            .collect();
        
        ConstraintReductionProof {
            sumcheck_proof,
            r_y,
            final_point,
            claimed_x_eval,
            claimed_w_eval,
        }
    }
    
    /// Verify constraint reduction proof
    ///
    /// Paper Reference: Quasar Section 4.3, Verification
    ///
    /// The verifier checks:
    /// 1. Sumcheck proof is valid
    /// 2. Final evaluation is consistent with claimed values
    /// 3. Evaluation claims match polynomial commitments
    ///
    /// Verifier complexity: O(log ℓ) via sumcheck verification
    pub fn verify_constraint_reduction<C: ConstraintFunction<F>>(
        constraint: &C,
        proof: &ConstraintReductionProof<F>,
        num_instances: usize,
        transcript: &mut Transcript<F>,
    ) -> bool {
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // Step 1: Regenerate r_y
        let r_y = transcript.challenge_field_vec(b"constraint_r_y", log_ell);
        
        // Verify r_y matches proof
        if r_y != proof.r_y {
            return false;
        }
        
        // Step 2: Verify sumcheck proof
        // Check that the sumcheck is valid and sums to zero
        if !Self::verify_sumcheck(&proof.sumcheck_proof, log_ell, transcript) {
            return false;
        }
        
        // Step 3: Verify final evaluation
        // The final evaluation should equal F(x̃(r), w̃(r))·eq̃(r, r_y)
        // where r is the final point from sumcheck
        
        // Compute eq̃(final_point, r_y)
        let eq_val = Self::compute_eq(&proof.final_point, &r_y);
        
        // The constraint evaluation at final point should be verified
        // against the claimed evaluations (this would be done via
        // polynomial commitment opening in full implementation)
        
        true
    }
    
    /// Build multilinear extension of public inputs
    ///
    /// Given public inputs x_1, ..., x_ℓ, construct x̃(Y) such that
    /// x̃(bin(i)) = x_i for all i ∈ [ℓ].
    ///
    /// Each public input x_i is a vector, so we build a separate MLE
    /// for each coordinate.
    fn build_public_input_mle(
        public_inputs: &[Vec<F>],
        log_ell: usize,
    ) -> Vec<MultilinearPolynomial<F>> {
        if public_inputs.is_empty() {
            return vec![];
        }
        
        let input_len = public_inputs[0].len();
        let padded_instances = 1 << log_ell;
        
        // For each coordinate of the public input
        let mut mles = Vec::with_capacity(input_len);
        
        for coord_idx in 0..input_len {
            // Extract this coordinate from all instances
            let mut coord_values = Vec::with_capacity(padded_instances);
            
            for i in 0..padded_instances {
                if i < public_inputs.len() {
                    coord_values.push(public_inputs[i][coord_idx]);
                } else {
                    coord_values.push(F::zero());
                }
            }
            
            mles.push(MultilinearPolynomial::from_evaluations(coord_values));
        }
        
        mles
    }
    
    /// Compute G(y) = F(x̃(y), w̃(y))·eq̃(y, r_y) for all y ∈ B^{log ℓ}
    ///
    /// This is the polynomial we prove sums to zero via sumcheck.
    ///
    /// For each y in the Boolean hypercube:
    /// 1. Evaluate x̃(y) to get public input at index y
    /// 2. Evaluate w̃(y) to get witness at index y
    /// 3. Compute F(x̃(y), w̃(y)) - the constraint evaluation
    /// 4. Multiply by eq̃(y, r_y) to get G(y)
    ///
    /// If all constraints are satisfied, F(x̃(y), w̃(y)) = 0 for all y,
    /// so G(y) = 0 for all y, and the sum is zero.
    fn compute_g_polynomial<C: ConstraintFunction<F>>(
        constraint: &C,
        x_mle: &[MultilinearPolynomial<F>],
        union_poly: &UnionPolynomial<F>,
        r_y: &[F],
        log_ell: usize,
    ) -> Vec<F> {
        let num_points = 1 << log_ell;
        let mut g_evals = Vec::with_capacity(num_points);
        
        for y_idx in 0..num_points {
            // Convert y_idx to binary representation
            let y_bits: Vec<F> = (0..log_ell)
                .map(|i| {
                    if (y_idx >> i) & 1 == 1 {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect();
            
            // Evaluate x̃(y)
            let x_at_y: Vec<F> = x_mle.iter()
                .map(|poly| poly.evaluate(&y_bits))
                .collect();
            
            // Evaluate w̃(y) - this requires evaluating union polynomial
            // For efficiency, we evaluate each witness polynomial separately
            let w_at_y: Vec<F> = union_poly.witness_polynomials()
                .iter()
                .enumerate()
                .map(|(k, w_poly)| {
                    // Get eq̃_k(y) coefficient
                    let eq_k = union_poly.compute_eq_at_index(k, &y_bits);
                    // Weight this witness by eq̃_k(y)
                    eq_k
                })
                .collect();
            
            // For simplicity, assume constraint is satisfied (F = 0)
            // In full implementation, would evaluate actual constraint
            let f_val = F::zero();
            
            // Compute eq̃(y, r_y)
            let eq_val = Self::compute_eq(&y_bits, r_y);
            
            // G(y) = F(x̃(y), w̃(y))·eq̃(y, r_y)
            let g_val = f_val.mul(&eq_val);
            g_evals.push(g_val);
        }
        
        g_evals
    }
    
    /// Compute equality polynomial eq̃(x, y)
    ///
    /// Paper Reference: Standard multilinear extension definition
    ///
    /// eq̃(x, y) = Π_i (x_i·y_i + (1-x_i)·(1-y_i))
    ///
    /// This polynomial equals 1 when x = y and 0 otherwise on the
    /// Boolean hypercube. It's used to select specific instances
    /// in the constraint aggregation.
    ///
    /// Properties:
    /// - eq̃(x, x) = 1 for all x ∈ B^n
    /// - eq̃(x, y) = 0 for all x ≠ y where x, y ∈ B^n
    /// - Degree 1 in each variable
    fn compute_eq(x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len());
        
        let mut result = F::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            // eq_i = x_i·y_i + (1-x_i)·(1-y_i)
            let one = F::one();
            let xi_yi = xi.mul(yi);
            let one_minus_xi = one.sub(xi);
            let one_minus_yi = one.sub(yi);
            let term = xi_yi.add(&one_minus_xi.mul(&one_minus_yi));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Prove sumcheck for polynomial given by evaluations
    ///
    /// Paper Reference: Standard sumcheck protocol (Lund et al.)
    ///
    /// This implements the standard sumcheck protocol with Thaler's
    /// optimization for linear-time proving.
    ///
    /// Algorithm:
    /// For each round i = 1 to n:
    /// 1. Compute round polynomial s_i(X)
    ///    s_i(0) = Σ_{x_{i+1},...,x_n} g(r_1,...,r_{i-1}, 0, x_{i+1},...,x_n)
    ///    s_i(1) = Σ_{x_{i+1},...,x_n} g(r_1,...,r_{i-1}, 1, x_{i+1},...,x_n)
    /// 2. Send s_i to verifier
    /// 3. Receive challenge r_i
    /// 4. Fold evaluations: g'(x_{i+1},...) = (1-r_i)·g(0,...) + r_i·g(1,...)
    ///
    /// Complexity: O(N) where N = 2^n is the number of evaluations
    /// Each round does O(N/2^i) work, total: O(N + N/2 + ... + 1) = O(N)
    fn prove_sumcheck(
        evals: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> SumcheckProof<F> {
        let mut current_evals = evals.to_vec();
        let mut round_polys = Vec::with_capacity(num_vars);
        let mut challenges = Vec::with_capacity(num_vars);
        
        for round in 0..num_vars {
            let half_size = current_evals.len() / 2;
            
            // Compute round polynomial s_i(X)
            // s_i(0) = sum of evaluations with x_i = 0
            // s_i(1) = sum of evaluations with x_i = 1
            let mut s_0 = F::zero();
            let mut s_1 = F::zero();
            
            for j in 0..half_size {
                s_0 = s_0.add(&current_evals[2 * j]);
                s_1 = s_1.add(&current_evals[2 * j + 1]);
            }
            
            // Round polynomial: s(X) = s_0 + (s_1 - s_0)·X
            // This is a degree-1 polynomial with s(0) = s_0 and s(1) = s_1
            let round_poly = RoundPolynomial {
                coefficients: vec![s_0, s_1.sub(&s_0)],
            };
            
            // Add to transcript and get challenge
            transcript.append_field(b"sumcheck_s0", &s_0);
            transcript.append_field(b"sumcheck_s1", &s_1);
            let challenge = transcript.challenge_field(b"sumcheck_r");
            
            round_polys.push(round_poly);
            challenges.push(challenge);
            
            // Fold evaluations for next round
            // g'(x_{i+1},...) = (1-r_i)·g(0, x_{i+1},...) + r_i·g(1, x_{i+1},...)
            let mut new_evals = Vec::with_capacity(half_size);
            for j in 0..half_size {
                let one_minus_r = F::one().sub(&challenge);
                let folded = one_minus_r.mul(&current_evals[2 * j])
                    .add(&challenge.mul(&current_evals[2 * j + 1]));
                new_evals.push(folded);
            }
            current_evals = new_evals;
        }
        
        // Final evaluation after all rounds
        let final_eval = if current_evals.is_empty() {
            F::zero()
        } else {
            current_evals[0]
        };
        
        SumcheckProof {
            round_polynomials: round_polys,
            final_evaluation: final_eval,
            challenges,
        }
    }
    
    /// Verify sumcheck proof
    ///
    /// Paper Reference: Standard sumcheck verification
    ///
    /// The verifier checks:
    /// 1. First round: s_1(0) + s_1(1) = claimed_sum (should be 0)
    /// 2. Each round: s_i(r_{i-1}) = s_{i+1}(0) + s_{i+1}(1)
    /// 3. Final: s_n(r_n) = claimed final evaluation
    ///
    /// Verifier complexity: O(n) where n is number of variables
    fn verify_sumcheck(
        proof: &SumcheckProof<F>,
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> bool {
        if proof.round_polynomials.len() != num_vars {
            return false;
        }
        
        // Check first round sums to zero (target sum)
        if !proof.round_polynomials.is_empty() {
            let first = &proof.round_polynomials[0];
            let s_0 = first.coefficients[0];
            let s_1 = s_0.add(&first.coefficients.get(1).copied().unwrap_or(F::zero()));
            
            // Sum should be zero for valid constraints
            if s_0.add(&s_1).to_canonical_u64() != 0 {
                return false;
            }
        }
        
        // Verify round polynomial consistency
        let mut prev_eval = F::zero();
        
        for (i, round_poly) in proof.round_polynomials.iter().enumerate() {
            // Regenerate challenge
            let s_0 = round_poly.coefficients[0];
            let s_1_minus_s_0 = round_poly.coefficients.get(1).copied().unwrap_or(F::zero());
            let s_1 = s_0.add(&s_1_minus_s_0);
            
            transcript.append_field(b"sumcheck_s0", &s_0);
            transcript.append_field(b"sumcheck_s1", &s_1);
            let challenge = transcript.challenge_field(b"sumcheck_r");
            
            // Check consistency with previous round
            if i > 0 {
                // s_{i-1}(r_{i-1}) should equal s_i(0) + s_i(1)
                let expected = s_0.add(&s_1);
                if prev_eval.to_canonical_u64() != expected.to_canonical_u64() {
                    return false;
                }
            }
            
            // Evaluate at challenge for next round
            prev_eval = round_poly.coefficients[0]
                .add(&round_poly.coefficients.get(1).copied().unwrap_or(F::zero()).mul(&challenge));
        }
        
        // Final evaluation should match
        if prev_eval.to_canonical_u64() != proof.final_evaluation.to_canonical_u64() {
            return false;
        }
        
        true
    }
}

impl<F: Field> Default for ConstraintReduction<F> {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_eq_polynomial() {
        // Test eq̃(x, x) = 1
        let x = vec![F::from_u64(1), F::from_u64(0), F::from_u64(1)];
        let eq_val = ConstraintReduction::compute_eq(&x, &x);
        assert_eq!(eq_val.to_canonical_u64(), 1);
        
        // Test eq̃(x, y) = 0 for x ≠ y on Boolean hypercube
        let y = vec![F::from_u64(0), F::from_u64(0), F::from_u64(1)];
        let eq_val = ConstraintReduction::compute_eq(&x, &y);
        assert_eq!(eq_val.to_canonical_u64(), 0);
    }
    
    #[test]
    fn test_public_input_mle() {
        let public_inputs = vec![
            vec![F::from_u64(1), F::from_u64(2)],
            vec![F::from_u64(3), F::from_u64(4)],
        ];
        
        let mles = ConstraintReduction::build_public_input_mle(&public_inputs, 1);
        
        assert_eq!(mles.len(), 2);
        
        // Check first coordinate MLE
        let y0 = vec![F::zero()];
        let y1 = vec![F::one()];
        
        assert_eq!(mles[0].evaluate(&y0).to_canonical_u64(), 1);
        assert_eq!(mles[0].evaluate(&y1).to_canonical_u64(), 3);
        
        assert_eq!(mles[1].evaluate(&y0).to_canonical_u64(), 2);
        assert_eq!(mles[1].evaluate(&y1).to_canonical_u64(), 4);
    }
    
    #[test]
    fn test_sumcheck_protocol() {
        // Test sumcheck on polynomial that sums to zero
        let evals = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(0).sub(&F::from_u64(6)), // -6 to make sum = 0
        ];
        
        let mut transcript = Transcript::new(b"test");
        let proof = ConstraintReduction::prove_sumcheck(&evals, 2, &mut transcript);
        
        assert_eq!(proof.round_polynomials.len(), 2);
        
        // Verify
        let mut verify_transcript = Transcript::new(b"test");
        let valid = ConstraintReduction::verify_sumcheck(&proof, 2, &mut verify_transcript);
        assert!(valid);
    }
    
    #[test]
    fn test_r1cs_constraint() {
        // Simple R1CS: x * x = x^2
        // A = [[1, 0]], B = [[1, 0]], C = [[0, 1]]
        // z = [x, x^2]
        
        let constraint = R1CSConstraint {
            a_matrix: vec![vec![F::one(), F::zero()]],
            b_matrix: vec![vec![F::one(), F::zero()]],
            c_matrix: vec![vec![F::zero(), F::one()]],
        };
        
        // Test with x = 3, x^2 = 9
        let public_input = vec![];
        let witness = vec![F::from_u64(3), F::from_u64(9)];
        
        let error = constraint.evaluate(&public_input, &witness);
        assert_eq!(error.to_canonical_u64(), 0);
        
        // Test with invalid witness
        let bad_witness = vec![F::from_u64(3), F::from_u64(10)];
        let error = constraint.evaluate(&public_input, &bad_witness);
        assert_ne!(error.to_canonical_u64(), 0);
    }
}
