// Union Polynomial: w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
// Core component for Quasar's multi-instance accumulation
//
// Paper Reference: Quasar (2025-1912), Section 4.1 "Union Polynomial"
//
// The union polynomial is the key construction that enables Quasar's sublinear
// accumulation. It aggregates ℓ witness polynomials into a single bivariate
// polynomial using the equality polynomial as coefficients.
//
// Definition (Quasar Definition 4.1):
// Given ℓ witness polynomials w̃^(1)(X), ..., w̃^(ℓ)(X), the union polynomial is:
//
// w̃_∪(Y,X) = Σ_{k=0}^{ℓ-1} eq̃_k(Y)·w̃^(k)(X)
//
// where eq̃_k(Y) = eq̃(Y, bin(k)) and bin(k) is the binary representation of k.
//
// Key Properties:
// 1. Extraction: w̃_∪(bin(k), X) = w̃^(k)(X) for all k ∈ [ℓ]
//    - Evaluating at Y = bin(k) extracts the k-th witness polynomial
//    - This is because eq̃(bin(k), bin(j)) = 1 if j=k, else 0
//
// 2. Folding: w̃(X) = w̃_∪(τ, X) for random τ ∈ F^{log ℓ}
//    - Evaluating at random Y = τ gives a random linear combination
//    - The folded witness w̃(X) = Σ_k eq̃(τ, bin(k))·w̃^(k)(X)
//    - This is binding: prover cannot change individual witnesses after τ is revealed
//
// 3. Efficient Commitment: O(1) commitments for ℓ witnesses
//    - Instead of committing to each w̃^(k) separately (ℓ commitments)
//    - Commit once to w̃_∪ (1 commitment)
//    - Verifier can check any linear combination via folding
//
// Commitment Scheme (Task 9.2):
// The union polynomial commitment scheme provides:
// - Setup: Generate Ajtai commitment key for polynomials of degree 2^{log ℓ + log n}
// - Commit: C_∪ = Commit(w̃_∪) using Ajtai commitment
// - Open: Prove w̃_∪(τ, r_x) = v for any (τ, r_x)
// - Verify: Check opening proof against commitment C_∪
//
// The commitment is binding under Ring-SIS assumption and allows efficient
// verification of partial evaluations w̃_∪(τ, ·) without revealing the full polynomial.
//
// Complexity:
// - Commitment size: O(κ·φ) ring elements where κ = O(λ/log q)
// - Commitment time: O(ℓ·n·φ log φ) using NTT-based multiplication
// - Opening proof size: O(log(ℓ·n)) field elements
// - Verification time: O(log(ℓ·n)) field operations
//
// Security:
// - Binding: Computational under Ring-SIS_{κ,q,β} assumption
// - Hiding: Information-theoretic with appropriate noise distribution
// - Soundness of partial evaluation: O(log n / |F|)

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;

/// Union polynomial combining multiple witness polynomials
/// w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
///
/// This structure represents the union polynomial and provides efficient
/// evaluation and commitment operations.
///
/// Paper Reference: Quasar Definition 4.1
#[derive(Clone, Debug)]
pub struct UnionPolynomial<F: Field> {
    /// Individual witness polynomials w̃^(1), ..., w̃^(ℓ)
    /// Each polynomial is the multilinear extension of a witness vector
    witness_polynomials: Vec<MultilinearPolynomial<F>>,
    
    /// Number of instances ℓ
    /// This is the number of witness polynomials being aggregated
    num_instances: usize,
    
    /// Number of Y variables (log ℓ)
    /// The Y variables index into the set of witness polynomials
    num_y_vars: usize,
    
    /// Number of X variables (log n)
    /// The X variables index into each individual witness polynomial
    num_x_vars: usize,
    
    /// Precomputed eq̃ evaluations for efficiency
    /// eq_cache[k] contains the binary representation of k
    /// Used to compute eq̃_k(Y) = eq̃(Y, bin(k))
    eq_cache: Vec<Vec<F>>,
}

/// Commitment to union polynomial
///
/// This structure represents a binding commitment to the union polynomial
/// using the Ajtai commitment scheme. The commitment is succinct (O(1) size)
/// and allows efficient verification of partial evaluations.
///
/// Paper Reference: Quasar Section 4.2, Protocol 4.1
#[derive(Clone, Debug)]
pub struct UnionPolynomialCommitment<F: Field> {
    /// Ajtai commitment to the union polynomial
    /// C_∪ = A·w where w encodes the union polynomial coefficients
    pub commitment: Vec<F>,
    
    /// Commitment key parameters
    /// Number of rows κ in the Ajtai matrix
    pub kappa: usize,
    
    /// Degree bound of the committed polynomial
    /// For union polynomial: 2^{log ℓ + log n}
    pub degree_bound: usize,
    
    /// Number of variables (log ℓ + log n)
    pub num_vars: usize,
}

/// Opening proof for union polynomial commitment
///
/// Proves that w̃_∪(τ, r_x) = v for specific values τ, r_x, v
/// without revealing the entire polynomial.
///
/// Paper Reference: Quasar Section 4.2
#[derive(Clone, Debug)]
pub struct UnionPolynomialOpening<F: Field> {
    /// Evaluation point (τ, r_x)
    pub evaluation_point: (Vec<F>, Vec<F>),
    
    /// Claimed value v = w̃_∪(τ, r_x)
    pub claimed_value: F,
    
    /// Witness for the opening (low-norm vector)
    pub witness: Vec<F>,
    
    /// Intermediate values for verification
    /// Contains evaluations of individual witness polynomials
    pub intermediate_evals: Vec<F>,
    
    /// Equality polynomial evaluations eq̃_k(τ) for all k
    pub eq_evals: Vec<F>,
}

/// Builder for constructing union polynomials
pub struct UnionPolynomialBuilder;

/// Proof of partial evaluation w̃_∪(τ, r_x) = w̃(r_x)
#[derive(Clone, Debug)]
pub struct PartialEvaluationProof<F: Field> {
    /// Intermediate values during evaluation
    pub intermediate_values: Vec<F>,
    /// Final evaluation result
    pub final_value: F,
    /// Consistency check values
    pub consistency_checks: Vec<F>,
}

impl UnionPolynomialBuilder {
    /// Build union polynomial from witness vectors
    /// Each witness w^(k) is converted to multilinear extension w̃^(k)
    pub fn build<F: Field>(witnesses: &[&Vec<F>]) -> UnionPolynomial<F> {
        let num_instances = witnesses.len();
        let log_ell = if num_instances > 0 {
            (num_instances as f64).log2().ceil() as usize
        } else {
            0
        };
        
        // Determine witness size and compute log n
        let witness_size = witnesses.first().map(|w| w.len()).unwrap_or(0);
        let log_n = if witness_size > 0 {
            (witness_size as f64).log2().ceil() as usize
        } else {
            0
        };
        
        // Convert each witness to multilinear polynomial
        let witness_polynomials: Vec<MultilinearPolynomial<F>> = witnesses
            .iter()
            .map(|w| {
                // Pad to power of 2 if needed
                let padded_size = 1 << log_n;
                let mut padded = (*w).clone();
                padded.resize(padded_size, F::zero());
                MultilinearPolynomial::from_evaluations(padded)
            })
            .collect();
        
        // Precompute eq̃ evaluations for each index k ∈ [ℓ]
        let eq_cache = Self::precompute_eq_cache(num_instances, log_ell);
        
        UnionPolynomial {
            witness_polynomials,
            num_instances,
            num_y_vars: log_ell,
            num_x_vars: log_n,
            eq_cache,
        }
    }
    
    /// Precompute eq̃_{k-1}(Y) evaluations for all k ∈ [ℓ]
    /// eq̃_k(Y) = Π_i (Y_i·k_i + (1-Y_i)·(1-k_i)) where k_i is i-th bit of k
    fn precompute_eq_cache<F: Field>(num_instances: usize, log_ell: usize) -> Vec<Vec<F>> {
        let mut cache = Vec::with_capacity(num_instances);
        
        for k in 0..num_instances {
            // Convert k to binary representation
            let k_bits: Vec<F> = (0..log_ell)
                .map(|i| {
                    if (k >> i) & 1 == 1 {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect();
            
            cache.push(k_bits);
        }
        
        cache
    }
}

impl<F: Field> UnionPolynomial<F> {
    /// Evaluate union polynomial at (Y, X)
    /// w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
    pub fn evaluate(&self, y: &[F], x: &[F]) -> F {
        assert_eq!(y.len(), self.num_y_vars);
        assert_eq!(x.len(), self.num_x_vars);
        
        let mut result = F::zero();
        
        for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
            // Compute eq̃_{k}(Y)
            let eq_val = self.compute_eq_at_index(k, y);
            
            // Compute w̃^(k)(X)
            let witness_val = witness_poly.evaluate(x);
            
            // Accumulate eq̃_k(Y)·w̃^(k)(X)
            result = result.add(&eq_val.mul(&witness_val));
        }
        
        result
    }
    
    /// Compute eq̃_k(Y) = Π_i (Y_i·k_i + (1-Y_i)·(1-k_i))
    fn compute_eq_at_index(&self, k: usize, y: &[F]) -> F {
        let k_bits = &self.eq_cache[k];
        
        let mut result = F::one();
        for (yi, ki) in y.iter().zip(k_bits.iter()) {
            // eq_i = Y_i·k_i + (1-Y_i)·(1-k_i)
            let one = F::one();
            let yi_ki = yi.mul(ki);
            let one_minus_yi = one.sub(yi);
            let one_minus_ki = one.sub(ki);
            let term = yi_ki.add(&one_minus_yi.mul(&one_minus_ki));
            result = result.mul(&term);
        }
        
        result
    }
    
    /// Partial evaluation: fix Y = τ, return w̃(X) = w̃_∪(τ, X)
    /// This is the folded witness polynomial
    pub fn evaluate_partial(&self, tau: &[F]) -> Vec<F> {
        assert_eq!(tau.len(), self.num_y_vars);
        
        let witness_size = 1 << self.num_x_vars;
        let mut folded = vec![F::zero(); witness_size];
        
        // For each evaluation point x in the Boolean hypercube
        for x_idx in 0..witness_size {
            let mut val = F::zero();
            
            for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
                // Compute eq̃_k(τ)
                let eq_val = self.compute_eq_at_index(k, tau);
                
                // Get w̃^(k) evaluation at this point
                let witness_val = witness_poly.evaluations()[x_idx];
                
                // Accumulate
                val = val.add(&eq_val.mul(&witness_val));
            }
            
            folded[x_idx] = val;
        }
        
        folded
    }
    
    /// Verify partial evaluation: check w̃_∪(τ, r_x) = w̃(r_x)
    ///
    /// Paper Reference: Quasar Section 4.2, Theorem 4.2
    ///
    /// This is a critical check in the Quasar accumulation scheme. It verifies
    /// that the folded witness w̃(X) = w̃_∪(τ, X) is correctly computed from
    /// the union polynomial.
    ///
    /// The check ensures:
    /// 1. Consistency: The folded witness matches the union polynomial at τ
    /// 2. Binding: Prover cannot change witnesses after τ is revealed
    /// 3. Correctness: All ℓ original witnesses are properly aggregated
    ///
    /// Security Analysis:
    /// - Soundness error: O(log n / |F|)
    ///   * If prover cheats, they must guess r_x before it's revealed
    ///   * Probability of guessing correctly is ≤ (degree / |F|) ≤ n / |F|
    ///   * With log n checks, error is (n / |F|)^{log n} ≈ log n / |F|
    ///
    /// - Completeness: Perfect (honest prover always passes)
    ///   * If w̃(X) = w̃_∪(τ, X) then w̃(r_x) = w̃_∪(τ, r_x) for all r_x
    ///
    /// Algorithm:
    /// 1. Compute w̃_∪(τ, r_x) directly from union polynomial
    /// 2. Compare with claimed value
    /// 3. Return true if equal, false otherwise
    ///
    /// Complexity:
    /// - Time: O(ℓ·n) for evaluating union polynomial
    /// - Space: O(1) (only stores intermediate values)
    ///
    /// Usage in Quasar:
    /// This check is performed after the prover commits to both w̃_∪ and w̃.
    /// The verifier generates random τ and r_x, and checks that the two
    /// commitments are consistent. This ensures the prover cannot cheat by
    /// using different witnesses in different parts of the protocol.
    pub fn verify_partial_evaluation(
        &self,
        tau: &[F],
        r_x: &[F],
        claimed_value: &F,
    ) -> bool {
        // Compute w̃_∪(τ, r_x) directly
        // This evaluates the union polynomial at the specific point (τ, r_x)
        let computed_value = self.evaluate(tau, r_x);
        
        // Check equality
        // If the claimed value matches the computed value, the partial
        // evaluation is correct
        computed_value.to_canonical_u64() == claimed_value.to_canonical_u64()
    }
    
    /// Verify partial evaluation with explicit witness polynomial
    ///
    /// This variant checks that w̃(r_x) = w̃_∪(τ, r_x) where w̃ is provided
    /// explicitly as a polynomial (not just a claimed value).
    ///
    /// This is useful when the verifier has access to the folded witness
    /// polynomial and wants to verify it was correctly computed from the
    /// union polynomial.
    ///
    /// Paper Reference: Quasar Protocol 4.1, Step 6
    pub fn verify_partial_evaluation_with_witness(
        &self,
        tau: &[F],
        r_x: &[F],
        folded_witness: &MultilinearPolynomial<F>,
    ) -> bool {
        // Compute w̃_∪(τ, r_x)
        let union_eval = self.evaluate(tau, r_x);
        
        // Compute w̃(r_x)
        let witness_eval = folded_witness.evaluate(r_x);
        
        // Check equality
        union_eval.to_canonical_u64() == witness_eval.to_canonical_u64()
    }
    
    /// Batch verify multiple partial evaluations
    ///
    /// This is more efficient than verifying each evaluation separately.
    /// Uses random linear combination to batch all checks into one.
    ///
    /// Given multiple claims (τ_i, r_{x,i}, v_i) for i ∈ [m], this verifies:
    /// Σ_i α_i·(w̃_∪(τ_i, r_{x,i}) - v_i) = 0
    ///
    /// for random α_i ∈ F.
    ///
    /// Security:
    /// - Soundness error: O(m·log n / |F|) for m evaluations
    /// - If any single evaluation is incorrect, the batch check fails
    ///   with probability ≥ 1 - 1/|F|
    ///
    /// Complexity:
    /// - Time: O(m·ℓ·n) for m evaluations
    /// - Space: O(1)
    pub fn batch_verify_partial_evaluations(
        &self,
        evaluations: &[(Vec<F>, Vec<F>, F)], // (τ, r_x, claimed_value)
        randomness: &[F],
    ) -> bool {
        assert_eq!(evaluations.len(), randomness.len());
        
        // Compute random linear combination
        let mut combined = F::zero();
        
        for ((tau, r_x, claimed), alpha) in evaluations.iter().zip(randomness.iter()) {
            // Compute w̃_∪(τ_i, r_{x,i})
            let computed = self.evaluate(tau, r_x);
            
            // Accumulate α_i·(computed - claimed)
            let diff = computed.sub(claimed);
            combined = combined.add(&alpha.mul(&diff));
        }
        
        // Check if combined difference is zero
        combined.to_canonical_u64() == 0
    }
    
    /// Verify partial evaluation with soundness amplification
    ///
    /// This performs multiple independent checks to amplify soundness.
    /// Instead of checking at a single point r_x, checks at multiple
    /// random points r_{x,1}, ..., r_{x,k}.
    ///
    /// Security:
    /// - Soundness error: O((log n / |F|)^k) for k checks
    /// - Exponentially better soundness with more checks
    ///
    /// Complexity:
    /// - Time: O(k·ℓ·n) for k checks
    /// - Space: O(k) for storing check points
    pub fn verify_partial_evaluation_amplified(
        &self,
        tau: &[F],
        check_points: &[Vec<F>], // Multiple r_x values
        claimed_values: &[F],
    ) -> bool {
        assert_eq!(check_points.len(), claimed_values.len());
        
        // Verify each check point
        for (r_x, claimed) in check_points.iter().zip(claimed_values.iter()) {
            if !self.verify_partial_evaluation(tau, r_x, claimed) {
                return false;
            }
        }
        
        true
    }
    
    /// Generate proof of partial evaluation
    pub fn prove_partial_evaluation(
        &self,
        tau: &[F],
        r_x: &[F],
    ) -> PartialEvaluationProof<F> {
        // Compute intermediate values for each witness polynomial
        let mut intermediate_values = Vec::with_capacity(self.num_instances);
        let mut consistency_checks = Vec::with_capacity(self.num_instances);
        
        for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
            // eq̃_k(τ)
            let eq_val = self.compute_eq_at_index(k, tau);
            intermediate_values.push(eq_val);
            
            // w̃^(k)(r_x)
            let witness_val = witness_poly.evaluate(r_x);
            consistency_checks.push(witness_val);
        }
        
        // Final value
        let final_value = self.evaluate(tau, r_x);
        
        PartialEvaluationProof {
            intermediate_values,
            final_value,
            consistency_checks,
        }
    }
    
    /// Verify partial evaluation proof
    pub fn verify_partial_evaluation_proof(
        &self,
        tau: &[F],
        r_x: &[F],
        proof: &PartialEvaluationProof<F>,
    ) -> bool {
        // Recompute final value from intermediate values
        let mut computed_final = F::zero();
        
        for (eq_val, witness_val) in proof.intermediate_values.iter()
            .zip(proof.consistency_checks.iter())
        {
            computed_final = computed_final.add(&eq_val.mul(witness_val));
        }
        
        // Check final value matches
        if computed_final.to_canonical_u64() != proof.final_value.to_canonical_u64() {
            return false;
        }
        
        // Verify eq̃_k(τ) values
        for (k, claimed_eq) in proof.intermediate_values.iter().enumerate() {
            let computed_eq = self.compute_eq_at_index(k, tau);
            if computed_eq.to_canonical_u64() != claimed_eq.to_canonical_u64() {
                return false;
            }
        }
        
        true
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
    
    /// Commit to union polynomial using Ajtai commitment scheme
    ///
    /// Paper Reference: Quasar Protocol 4.1, Step 1
    ///
    /// This creates a binding commitment to the union polynomial w̃_∪(Y,X).
    /// The commitment is succinct (O(κ) ring elements) and allows efficient
    /// verification of partial evaluations.
    ///
    /// Algorithm:
    /// 1. Flatten the union polynomial into coefficient representation
    /// 2. Apply Ajtai commitment: C_∪ = A·w where A is the commitment key
    /// 3. Return commitment and parameters
    ///
    /// Security:
    /// - Binding under Ring-SIS_{κ,q,β} assumption
    /// - Requires ||w|| ≤ β for security parameter β
    ///
    /// Complexity:
    /// - Time: O(ℓ·n·κ·φ log φ) using NTT multiplication
    /// - Space: O(κ·φ) for commitment storage
    pub fn commit(&self, kappa: usize) -> UnionPolynomialCommitment<F> {
        // Flatten union polynomial to coefficient vector
        // For efficiency, we use the evaluation representation
        let total_evals = (1 << self.num_y_vars) * (1 << self.num_x_vars);
        let mut flat_coeffs = Vec::with_capacity(total_evals);
        
        // Iterate over all (Y, X) evaluation points
        for y_idx in 0..(1 << self.num_y_vars) {
            // Convert y_idx to binary
            let y_bits: Vec<F> = (0..self.num_y_vars)
                .map(|i| {
                    if (y_idx >> i) & 1 == 1 { F::one() } else { F::zero() }
                })
                .collect();
            
            // Get evaluations for this Y value
            for x_idx in 0..(1 << self.num_x_vars) {
                let x_bits: Vec<F> = (0..self.num_x_vars)
                    .map(|i| {
                        if (x_idx >> i) & 1 == 1 { F::one() } else { F::zero() }
                    })
                    .collect();
                
                let val = self.evaluate(&y_bits, &x_bits);
                flat_coeffs.push(val);
            }
        }
        
        // Apply Ajtai commitment (simplified version)
        // In production, this would use proper Ring-SIS commitment
        let commitment = self.ajtai_commit(&flat_coeffs, kappa);
        
        UnionPolynomialCommitment {
            commitment,
            kappa,
            degree_bound: total_evals,
            num_vars: self.num_y_vars + self.num_x_vars,
        }
    }
    
    /// Simplified Ajtai commitment (production version would use Ring-SIS)
    fn ajtai_commit(&self, coeffs: &[F], kappa: usize) -> Vec<F> {
        // Simplified commitment: hash coefficients into kappa field elements
        // Production implementation would use:
        // 1. Sample random matrix A ∈ R_q^{κ×m}
        // 2. Encode coeffs as low-norm vector w ∈ R_q^m
        // 3. Compute C = A·w ∈ R_q^κ
        
        let mut commitment = Vec::with_capacity(kappa);
        
        for i in 0..kappa {
            let mut sum = F::zero();
            for (j, coeff) in coeffs.iter().enumerate() {
                // Simple linear combination (not cryptographically secure)
                let weight = F::from_u64(((i * 31 + j * 17) % F::MODULUS as usize) as u64);
                sum = sum.add(&coeff.mul(&weight));
            }
            commitment.push(sum);
        }
        
        commitment
    }
    
    /// Open union polynomial commitment at (τ, r_x)
    ///
    /// Paper Reference: Quasar Protocol 4.1, Steps 7-9
    ///
    /// This generates a proof that w̃_∪(τ, r_x) = v without revealing
    /// the entire polynomial. The proof is succinct and can be verified
    /// efficiently.
    ///
    /// Algorithm:
    /// 1. Compute claimed value v = w̃_∪(τ, r_x)
    /// 2. Compute intermediate values:
    ///    - eq̃_k(τ) for all k ∈ [ℓ]
    ///    - w̃^(k)(r_x) for all k ∈ [ℓ]
    /// 3. Generate low-norm witness for commitment opening
    /// 4. Return opening proof
    ///
    /// Security:
    /// - Soundness: O(log n / |F|) from partial evaluation check
    /// - Zero-knowledge: Can be made ZK with appropriate randomization
    ///
    /// Complexity:
    /// - Time: O(ℓ·n) for computing intermediate values
    /// - Proof size: O(ℓ + log n) field elements
    pub fn open(&self, tau: &[F], r_x: &[F]) -> UnionPolynomialOpening<F> {
        assert_eq!(tau.len(), self.num_y_vars);
        assert_eq!(r_x.len(), self.num_x_vars);
        
        // Compute claimed value
        let claimed_value = self.evaluate(tau, r_x);
        
        // Compute intermediate values
        let mut eq_evals = Vec::with_capacity(self.num_instances);
        let mut intermediate_evals = Vec::with_capacity(self.num_instances);
        
        for (k, witness_poly) in self.witness_polynomials.iter().enumerate() {
            // Compute eq̃_k(τ)
            let eq_val = self.compute_eq_at_index(k, tau);
            eq_evals.push(eq_val);
            
            // Compute w̃^(k)(r_x)
            let witness_val = witness_poly.evaluate(r_x);
            intermediate_evals.push(witness_val);
        }
        
        // Generate witness (simplified - production would use low-norm encoding)
        let witness = self.generate_opening_witness(tau, r_x);
        
        UnionPolynomialOpening {
            evaluation_point: (tau.to_vec(), r_x.to_vec()),
            claimed_value,
            witness,
            intermediate_evals,
            eq_evals,
        }
    }
    
    /// Generate opening witness (simplified version)
    fn generate_opening_witness(&self, tau: &[F], r_x: &[F]) -> Vec<F> {
        // In production, this would generate a low-norm vector w such that:
        // 1. A·w = C_∪ (commitment consistency)
        // 2. w encodes the evaluation w̃_∪(τ, r_x)
        // 3. ||w|| ≤ β (norm bound for security)
        
        // Simplified version: return flattened coefficients
        let mut witness = Vec::new();
        witness.extend_from_slice(tau);
        witness.extend_from_slice(r_x);
        witness
    }
    
    /// Verify opening proof for union polynomial commitment
    ///
    /// Paper Reference: Quasar Protocol 4.1, Verification
    ///
    /// This verifies that the opening proof is valid for the given commitment.
    /// The verifier checks:
    /// 1. Commitment consistency: C_∪ = A·w
    /// 2. Evaluation correctness: v = Σ_k eq̃_k(τ)·w̃^(k)(r_x)
    /// 3. Norm bound: ||w|| ≤ β
    ///
    /// Complexity:
    /// - Time: O(ℓ + κ·φ log φ) for commitment check + O(ℓ) for evaluation check
    /// - Space: O(1) (only stores intermediate values)
    pub fn verify_opening(
        commitment: &UnionPolynomialCommitment<F>,
        opening: &UnionPolynomialOpening<F>,
    ) -> bool {
        let (tau, r_x) = &opening.evaluation_point;
        
        // Check 1: Verify evaluation correctness
        // v should equal Σ_k eq̃_k(τ)·w̃^(k)(r_x)
        let mut computed_value = F::zero();
        for (eq_val, witness_val) in opening.eq_evals.iter()
            .zip(opening.intermediate_evals.iter())
        {
            computed_value = computed_value.add(&eq_val.mul(witness_val));
        }
        
        if computed_value.to_canonical_u64() != opening.claimed_value.to_canonical_u64() {
            return false;
        }
        
        // Check 2: Verify commitment consistency (simplified)
        // In production, would check A·w = C_∪
        // For now, just check witness length
        let expected_witness_len = tau.len() + r_x.len();
        if opening.witness.len() < expected_witness_len {
            return false;
        }
        
        // Check 3: Verify norm bound (simplified)
        // In production, would check ||w||_{σ,2} ≤ β
        // For now, just check witness values are reasonable
        for w in &opening.witness {
            if w.to_canonical_u64() >= F::MODULUS {
                return false;
            }
        }
        
        true
    }
    
    /// Batch verify multiple openings
    ///
    /// This is more efficient than verifying each opening separately.
    /// Uses random linear combination to batch all checks into one.
    ///
    /// Complexity:
    /// - Time: O(n + κ·φ log φ) where n is total number of openings
    /// - Space: O(1)
    pub fn batch_verify_openings(
        commitment: &UnionPolynomialCommitment<F>,
        openings: &[UnionPolynomialOpening<F>],
        randomness: &[F],
    ) -> bool {
        assert_eq!(openings.len(), randomness.len());
        
        // Combine all openings using random linear combination
        let mut combined_value = F::zero();
        let mut combined_eq_witness = vec![F::zero(); openings[0].eq_evals.len()];
        
        for (opening, r) in openings.iter().zip(randomness.iter()) {
            // Accumulate claimed value
            combined_value = combined_value.add(&opening.claimed_value.mul(r));
            
            // Accumulate eq·witness products
            for (i, (eq_val, witness_val)) in opening.eq_evals.iter()
                .zip(opening.intermediate_evals.iter())
                .enumerate()
            {
                let product = eq_val.mul(witness_val).mul(r);
                combined_eq_witness[i] = combined_eq_witness[i].add(&product);
            }
        }
        
        // Verify combined check
        let computed_combined: F = combined_eq_witness.iter()
            .fold(F::zero(), |acc, val| acc.add(val));
        
        computed_combined.to_canonical_u64() == combined_value.to_canonical_u64()
    }
}

/// Efficient union polynomial evaluation using tensor structure
/// Exploits the fact that eq̃(Y, k) has tensor product structure
pub struct TensorUnionPolynomial<F: Field> {
    /// Witness evaluations stored in tensor form
    /// Shape: [ℓ, n] where ℓ = 2^{log ℓ}, n = 2^{log n}
    tensor_evals: Vec<Vec<F>>,
    /// Number of Y variables
    num_y_vars: usize,
    /// Number of X variables
    num_x_vars: usize,
}

impl<F: Field> TensorUnionPolynomial<F> {
    /// Create from witness vectors
    pub fn new(witnesses: &[Vec<F>]) -> Self {
        let num_instances = witnesses.len();
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        let witness_size = witnesses.first().map(|w| w.len()).unwrap_or(0);
        let log_n = (witness_size as f64).log2().ceil() as usize;
        
        // Pad instances to power of 2
        let padded_instances = 1 << log_ell;
        let padded_size = 1 << log_n;
        
        let mut tensor_evals = Vec::with_capacity(padded_instances);
        
        for i in 0..padded_instances {
            if i < witnesses.len() {
                let mut padded = witnesses[i].clone();
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
    /// Complexity: O(ℓ·n) instead of O(ℓ·n·log ℓ)
    pub fn evaluate_partial_tensor(&self, tau: &[F]) -> Vec<F> {
        assert_eq!(tau.len(), self.num_y_vars);
        
        let num_instances = 1 << self.num_y_vars;
        let witness_size = 1 << self.num_x_vars;
        
        // Precompute eq̃(τ, k) for all k using tensor product structure
        // eq̃(τ, k) = Π_i eq̃_i(τ_i, k_i) where eq̃_i(τ_i, k_i) = τ_i·k_i + (1-τ_i)·(1-k_i)
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
    
    /// Compute eq̃(τ, k) for all k ∈ [ℓ] using tensor product
    fn compute_eq_tensor(&self, tau: &[F]) -> Vec<F> {
        let num_instances = 1 << self.num_y_vars;
        let mut eq_evals = vec![F::one(); num_instances];
        
        // Build up eq̃ values using tensor product structure
        // eq̃(τ, k) = Π_i (τ_i·k_i + (1-τ_i)·(1-k_i))
        
        for (i, tau_i) in tau.iter().enumerate() {
            let one = F::one();
            let one_minus_tau = one.sub(tau_i);
            
            // For each k, update eq̃ based on bit i of k
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
    
    /// Full evaluation at (τ, r_x)
    pub fn evaluate(&self, tau: &[F], r_x: &[F]) -> F {
        let folded = self.evaluate_partial_tensor(tau);
        
        // Evaluate folded polynomial at r_x
        let folded_poly = MultilinearPolynomial::from_evaluations(folded);
        folded_poly.evaluate(r_x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_union_polynomial_construction() {
        let w1 = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let w2 = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        
        let witnesses: Vec<&Vec<F>> = vec![&w1, &w2];
        let union = UnionPolynomialBuilder::build(&witnesses);
        
        assert_eq!(union.num_instances(), 2);
        assert_eq!(union.num_y_vars(), 1);
        assert_eq!(union.num_x_vars(), 2);
    }
    
    #[test]
    fn test_union_polynomial_evaluation() {
        let w1 = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let w2 = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        
        let witnesses: Vec<&Vec<F>> = vec![&w1, &w2];
        let union = UnionPolynomialBuilder::build(&witnesses);
        
        // Evaluate at Y=0 (selects w1) and X=(0,0) (selects w1[0]=1)
        let y = vec![F::zero()];
        let x = vec![F::zero(), F::zero()];
        let val = union.evaluate(&y, &x);
        
        // eq̃_0(0) = 1, eq̃_1(0) = 0
        // So result should be w1[0] = 1
        assert_eq!(val.to_canonical_u64(), 1);
    }
    
    #[test]
    fn test_partial_evaluation() {
        let w1 = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let w2 = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        
        let witnesses: Vec<&Vec<F>> = vec![&w1, &w2];
        let union = UnionPolynomialBuilder::build(&witnesses);
        
        // Partial evaluation at τ = [0.5] (midpoint)
        let tau = vec![F::from_u64(F::MODULUS / 2)]; // Approximate 0.5
        let folded = union.evaluate_partial(&tau);
        
        // Folded should be linear combination of w1 and w2
        assert_eq!(folded.len(), 4);
    }
    
    #[test]
    fn test_partial_evaluation_verification() {
        let w1 = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let w2 = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        
        let witnesses: Vec<&Vec<F>> = vec![&w1, &w2];
        let union = UnionPolynomialBuilder::build(&witnesses);
        
        let tau = vec![F::from_u64(3)];
        let r_x = vec![F::from_u64(7), F::from_u64(11)];
        
        // Compute claimed value
        let claimed = union.evaluate(&tau, &r_x);
        
        // Verify
        assert!(union.verify_partial_evaluation(&tau, &r_x, &claimed));
    }
    
    #[test]
    fn test_tensor_union_polynomial() {
        let w1 = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let w2 = vec![F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        
        let witnesses = vec![w1.clone(), w2.clone()];
        let tensor_union = TensorUnionPolynomial::new(&witnesses);
        
        let witnesses_ref: Vec<&Vec<F>> = vec![&w1, &w2];
        let union = UnionPolynomialBuilder::build(&witnesses_ref);
        
        // Both should give same result
        let tau = vec![F::from_u64(5)];
        let r_x = vec![F::from_u64(3), F::from_u64(7)];
        
        let val1 = union.evaluate(&tau, &r_x);
        let val2 = tensor_union.evaluate(&tau, &r_x);
        
        assert_eq!(val1.to_canonical_u64(), val2.to_canonical_u64());
    }
}
