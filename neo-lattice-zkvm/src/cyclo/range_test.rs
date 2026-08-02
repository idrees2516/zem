//! Range Test Protocol (Figure 1 from the paper)
//! 
//! Tests that a committed vector w ∈ R_q^m satisfies ||w||_∞ ≤ b

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;
use super::utils::*;

/// Range Test Protocol Π^range_b
pub struct RangeTest<F: FiniteField> {
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
    /// Bound b
    pub bound_b: usize,
    /// Extension degree e
    pub extension_degree: usize,
}

impl<F: FiniteField> RangeTest<F> {
    pub fn new(
        ring: CyclotomicRing<F>,
        bound_b: usize,
        extension_degree: usize,
    ) -> Self {
        Self {
            ring,
            bound_b,
            extension_degree,
        }
    }

    /// Prover side of range test
    /// Input: ((r_i)_i, (b_i)_i, y), w ∈ Ξ^lin_{n,b}
    /// Output: ((r_i)_i, ((b_i)_i, u'), ỹ, ṫ), w ∈ Ξ^lin_{n+1,b}
    pub fn prove(
        &self,
        instance: &LinearInstance<F>,
        witness: &LinearWitness<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(LinearInstance<F>, RangeTestProof<F>), String> {
        let m = witness.witness.len();
        let phi = self.ring.degree;
        let ell = ((m * phi) as f64).log2().ceil() as usize;

        // Step 1: Prover defines f := MLE[cf(w)]
        let cf_w = self.coefficient_embedding(&witness.witness);
        let f = MLE::new(cf_w.clone());

        // Step 2: Verifier samples η ∈ F_{q^e}^ell
        let eta = transcript.challenge_vector(ell, self.extension_degree);
        
        // Step 3: Prover sets f̂(X) := ∏_{j=-b}^{b} (f(X) - j) · ω(X)
        // where ω(X) := eq(X; η)
        
        // Step 4: Run sum-check over F_{q^e}
        // Reduce ∑_{z∈{0,1}^ell} f̂(z) = 0 to f̂(u) = s
        let sumcheck_proof = self.run_range_sumcheck(
            &f,
            &eta,
            ell,
            transcript,
        )?;

        let u = sumcheck_proof.challenge_point.clone();
        let s = sumcheck_proof.claimed_sum;

        // Step 5: Prover sets t̃ := ⟨u', w⟩ where u' := cf^{-1}_∨(tensor(u))
        let tensor_u = tensor(&u);
        let u_prime = self.inverse_cf_dual(&tensor_u);
        
        let t_tilde = self.inner_product_ring(&u_prime, &witness.witness);

        // Step 6: Verifier computes t := Trace(t̃) and checks
        let t = self.ring.trace(&t_tilde);
        
        // Verify: s ?= ω(u) · ∏_{j=-b}^{b} (t - j)
        let omega_u = eq_polynomial(&u, &eta);
        let mut product = F::one();
        for j in -(self.bound_b as i64)..=(self.bound_b as i64) {
            let j_field = F::from_i64(j);
            product = product * (t - j_field);
        }
        
        if s != omega_u * product {
            return Err("Range test verification failed".to_string());
        }

        // Step 7: Output augmented instance
        let mut new_eval_points = instance.eval_points.clone();
        new_eval_points.push(u_prime.clone());

        let mut new_image = instance.image.clone();
        new_image.push(t_tilde.clone());

        let new_instance = LinearInstance {
            challenge_points: instance.challenge_points.clone(),
            eval_points: new_eval_points,
            image: new_image,
        };

        let proof = RangeTestProof {
            sumcheck_proof: sumcheck_proof.round_polynomials,
            final_eval: t_tilde,
        };

        Ok((new_instance, proof))
    }

    /// Verifier side of range test
    pub fn verify(
        &self,
        instance: &LinearInstance<F>,
        proof: &RangeTestProof<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<LinearInstance<F>, String> {
        let m = instance.image.len() - instance.challenge_points.len() - instance.eval_points.len();
        let phi = self.ring.degree;
        let ell = ((m * phi) as f64).log2().ceil() as usize;

        // Sample η
        let eta = transcript.challenge_vector(ell, self.extension_degree);

        // Verify sum-check
        let verification = self.verify_range_sumcheck(
            &proof.sumcheck_proof,
            &eta,
            ell,
            transcript,
        )?;

        let u = verification.challenge_point;
        let s = verification.claimed_sum;

        // Compute t := Trace(t̃)
        let t = self.ring.trace(&proof.final_eval);

        // Verify: s ?= ω(u) · ∏_{j=-b}^{b} (t - j)
        let omega_u = eq_polynomial(&u, &eta);
        let mut product = F::one();
        for j in -(self.bound_b as i64)..=(self.bound_b as i64) {
            let j_field = F::from_i64(j);
            product = product * (t - j_field);
        }

        if s != omega_u * product {
            return Err("Range test verification failed".to_string());
        }

        // Construct output instance
        let tensor_u = tensor(&u);
        let u_prime = self.inverse_cf_dual(&tensor_u);

        let mut new_eval_points = instance.eval_points.clone();
        new_eval_points.push(u_prime);

        let mut new_image = instance.image.clone();
        new_image.push(proof.final_eval.clone());

        Ok(LinearInstance {
            challenge_points: instance.challenge_points.clone(),
            eval_points: new_eval_points,
            image: new_image,
        })
    }

    /// Run sum-check for range test
    fn run_range_sumcheck(
        &self,
        f: &MLE<F>,
        eta: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<SumCheckProof<F>, String> {
        // f̂(X) = ω(X) · ∏_{j=-b}^{b} (f(X) - j)
        // where ω(X) = eq(X; η)
        
        let mut round_polynomials = Vec::new();
        let mut current_evals = f.evaluations.clone();
        let mut challenges = Vec::new();

        for round in 0..num_vars {
            // Compute univariate polynomial for this round
            let univariate = self.compute_range_round_polynomial(
                &current_evals,
                eta,
                &challenges,
                round,
                num_vars,
            );

            round_polynomials.push(univariate.clone());
            
            // Get challenge
            let challenge = transcript.challenge_scalar(self.extension_degree);
            challenges.push(challenge);

            // Fold evaluations
            current_evals = self.fold_evaluations(&current_evals, challenge);
        }

        // Final claimed sum should be 0 for valid range
        let final_eval = current_evals[0];
        
        Ok(SumCheckProof {
            round_polynomials,
            challenge_point: challenges,
            claimed_sum: final_eval,
        })
    }

    /// Compute round polynomial for range sum-check
    fn compute_range_round_polynomial(
        &self,
        evals: &[F],
        eta: &[F],
        prev_challenges: &[F],
        round: usize,
        num_vars: usize,
    ) -> Vec<F> {
        let degree = 2 * self.bound_b + 2;
        let mut poly = vec![F::zero(); degree + 1];

        let half_size = evals.len() / 2;

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];

            // Compute eq contribution for both points
            let mut point_0 = prev_challenges.to_vec();
            point_0.push(F::zero());
            let mut point_1 = prev_challenges.to_vec();
            point_1.push(F::one());

            // Pad to full dimension
            while point_0.len() < num_vars {
                point_0.push(F::zero());
            }
            while point_1.len() < num_vars {
                point_1.push(F::zero());
            }

            let eq_0 = eq_polynomial(&point_0, eta);
            let eq_1 = eq_polynomial(&point_1, eta);

            // Compute product terms
            let prod_0 = self.compute_product_term(eval_0);
            let prod_1 = self.compute_product_term(eval_1);

            // Combine: g(X) = eq(0, ...) · prod(f(0)) + eq(1, ...) · prod(f(1))
            let contribution_0 = eq_0 * prod_0;
            let contribution_1 = eq_1 * prod_1;

            // Add to polynomial (interpolated on X)
            poly[0] = poly[0] + contribution_0;
            poly[1] = poly[1] + (contribution_1 - contribution_0);
        }

        poly
    }

    /// Compute ∏_{j=-b}^{b} (value - j)
    fn compute_product_term(&self, value: F) -> F {
        let mut result = F::one();
        for j in -(self.bound_b as i64)..=(self.bound_b as i64) {
            let j_field = F::from_i64(j);
            result = result * (value - j_field);
        }
        result
    }

    /// Verify sum-check for range test
    fn verify_range_sumcheck(
        &self,
        round_polys: &[Vec<F>],
        eta: &[F],
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<SumCheckVerification<F>, String> {
        let mut claimed_sum = F::zero();
        let mut challenges = Vec::new();

        for (round, poly) in round_polys.iter().enumerate() {
            // Check that g(0) + g(1) = claimed_sum for this round
            if round > 0 {
                let g_0 = poly[0];
                let g_1: F = poly.iter().fold(F::zero(), |acc, &c| acc + c);
                if g_0 + g_1 != claimed_sum {
                    return Err(format!("Sum-check failed at round {}", round));
                }
            }

            // Get challenge
            let challenge = transcript.challenge_scalar(self.extension_degree);
            challenges.push(challenge);

            // Evaluate polynomial at challenge
            claimed_sum = evaluate_polynomial(poly, challenge);
        }

        Ok(SumCheckVerification {
            challenge_point: challenges,
            claimed_sum,
        })
    }

    /// Fold evaluations with challenge
    fn fold_evaluations(&self, evals: &[F], challenge: F) -> Vec<F> {
        let half_size = evals.len() / 2;
        let mut folded = Vec::with_capacity(half_size);

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];
            // Linear interpolation: (1 - r) * f(0) + r * f(1)
            folded.push(eval_0 * (F::one() - challenge) + eval_1 * challenge);
        }

        folded
    }

    /// Coefficient embedding for witness
    fn coefficient_embedding(&self, witness: &[RingElement<F>]) -> Vec<F> {
        witness.iter()
            .flat_map(|elem| elem.cf())
            .collect()
    }

    /// Inverse dual coefficient embedding
    fn inverse_cf_dual(&self, tensor: &[F]) -> Vec<ExtensionRingElement<F>> {
        let phi = self.ring.degree;
        let num_elements = tensor.len() / phi;
        
        let mut result = Vec::with_capacity(num_elements);
        
        for i in 0..num_elements {
            let start = i * phi;
            let end = start + phi;
            let coeffs = tensor[start..end].to_vec();
            
            // Apply dual basis transformation
            let mut dual_coeffs = vec![F::zero(); phi];
            dual_coeffs[0] = coeffs[0];
            for j in 1..phi {
                dual_coeffs[j] = F::zero() - coeffs[phi - j];
            }
            
            result.push(RingElement::new(dual_coeffs, self.ring.conductor));
        }
        
        result
    }

    /// Inner product in ring elements
    fn inner_product_ring(
        &self,
        a: &[ExtensionRingElement<F>],
        b: &[RingElement<F>],
    ) -> ExtensionRingElement<F> {
        assert_eq!(a.len(), b.len());
        
        let mut result = RingElement::zero(self.ring.conductor);
        
        for (ai, bi) in a.iter().zip(b.iter()) {
            let prod = self.ring.multiply(ai, bi);
            result = self.ring.add(&result, &prod);
        }
        
        result
    }
}

/// Sum-check proof structure
#[derive(Clone, Debug)]
pub struct SumCheckProof<F: FiniteField> {
    pub round_polynomials: Vec<Vec<F>>,
    pub challenge_point: Vec<F>,
    pub claimed_sum: F,
}

/// Sum-check verification result
#[derive(Clone, Debug)]
pub struct SumCheckVerification<F: FiniteField> {
    pub challenge_point: Vec<F>,
    pub claimed_sum: F,
}

/// Evaluate polynomial at a point
fn evaluate_polynomial<F: FiniteField>(coeffs: &[F], point: F) -> F {
    let mut result = F::zero();
    let mut power = F::one();
    
    for &coeff in coeffs {
        result = result + coeff * power;
        power = power * point;
    }
    
    result
}
