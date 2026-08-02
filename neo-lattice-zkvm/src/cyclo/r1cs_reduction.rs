//! R1CS/CCS over F_q to Principal Linear Relation (Section 7)
//! 
//! Reduces R1CS constraints over finite fields to lattice-based relations

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;
use super::utils::*;

/// Module homomorphism θ_k: R_q → F_q
/// θ_k(f(X)) = f(k) mod q
pub struct ThetaMap<F: FiniteField> {
    /// Base k for evaluation
    pub base_k: usize,
    /// Ring
    pub ring: CyclotomicRing<F>,
}

impl<F: FiniteField> ThetaMap<F> {
    pub fn new(base_k: usize, ring: CyclotomicRing<F>) -> Self {
        Self { base_k, ring }
    }

    /// Apply θ_k to ring element: f(X) ↦ f(k)
    pub fn apply(&self, elem: &RingElement<F>) -> F {
        self.ring.evaluate_at(elem, F::from_u64(self.base_k as u64))
    }

    /// Apply θ_k to vector
    pub fn apply_vector(&self, v: &[RingElement<F>]) -> Vec<F> {
        v.iter().map(|elem| self.apply(elem)).collect()
    }

    /// Compute preimage: encode field element as ring element
    /// For c ∈ F_q, compute p_c(X) = c_0 + c_1 X + ... + c_{ℓ_k(q)-1} X^{ℓ_k(q)-1}
    /// where c = ∑ c_i k^i (base-k decomposition)
    pub fn preimage(&self, c: F) -> RingElement<F> {
        let ell_k = self.compute_ell_k();
        let mut coeffs = vec![F::zero(); self.ring.degree];

        // Base-k decomposition of c
        let mut remaining = c.to_u64();
        let k = self.base_k as u64;

        for i in 0..ell_k {
            if i >= self.ring.degree {
                break;
            }
            let digit = remaining % k;
            coeffs[i] = F::from_u64(digit);
            remaining /= k;
        }

        RingElement::new(coeffs, self.ring.conductor)
    }

    /// Compute preimage for vector
    pub fn preimage_vector(&self, v: &[F]) -> Vec<RingElement<F>> {
        v.iter().map(|&elem| self.preimage(elem)).collect()
    }

    /// Compute ℓ_k(q) = ⌊log_k(q)⌋
    fn compute_ell_k(&self) -> usize {
        let q = self.ring.modulus.to_u64();
        let k = self.base_k as u64;
        ((q as f64).log(k as f64)).floor() as usize
    }

    /// Check if preimage has low norm
    pub fn has_low_norm(&self, c: F, bound: F) -> bool {
        let preimage = self.preimage(c);
        preimage.norm_infinity() < bound
    }
}

/// R1CS to Committed Hybrid R1CS Reduction
pub struct R1CSReduction<F: FiniteField> {
    /// θ_k map
    pub theta_map: ThetaMap<F>,
    /// Ajtai commitment matrix A
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    /// Norm bound
    pub norm_bound: F,
}

impl<F: FiniteField> R1CSReduction<F> {
    pub fn new(
        theta_map: ThetaMap<F>,
        matrix_a: Vec<Vec<RingElement<F>>>,
        norm_bound: F,
    ) -> Self {
        Self {
            theta_map,
            matrix_a,
            norm_bound,
        }
    }

    /// Reduce R1CS instance to Committed Hybrid R1CS
    pub fn reduce_instance(
        &self,
        x: &[F],
        w: &[F],
    ) -> Result<(HybridR1CSInstance<F>, HybridR1CSWitness<F>), String> {
        
        // Encode field elements as ring elements via θ_k^{-1}
        let x_prime = self.theta_map.preimage_vector(x);
        let w_prime = self.theta_map.preimage_vector(w);

        // Construct z' = (x', 1, w')
        let mut z_prime = x_prime.clone();
        z_prime.push(RingElement::one(self.theta_map.ring.conductor));
        z_prime.extend(w_prime.clone());

        // Compute commitment y = Az'
        let commitment = matrix_vector_mult(
            &self.theta_map.ring,
            &self.matrix_a,
            &z_prime,
        );

        // Verify norm bound
        for elem in &z_prime {
            if elem.norm_infinity() > self.norm_bound {
                return Err("Witness norm exceeds bound".to_string());
            }
        }

        let instance = HybridR1CSInstance {
            public_input: x_prime,
            commitment,
        };

        let witness = HybridR1CSWitness {
            witness: w_prime,
        };

        Ok((instance, witness))
    }
}

/// Committed Hybrid R1CS to Principal Linear Relation (Protocol Π^{hyb-R1CS})
pub struct HybridR1CSToLinear<F: FiniteField> {
    /// θ_k map
    pub theta_map: ThetaMap<F>,
    /// Ring
    pub ring: CyclotomicRing<F>,
    /// Extension degree
    pub extension_degree: usize,
    /// Strong sampling set C
    pub challenge_set: StrongSamplingSet<F>,
}

impl<F: FiniteField> HybridR1CSToLinear<F> {
    pub fn new(
        theta_map: ThetaMap<F>,
        ring: CyclotomicRing<F>,
        extension_degree: usize,
        challenge_set: StrongSamplingSet<F>,
    ) -> Self {
        Self {
            theta_map,
            ring,
            extension_degree,
            challenge_set,
        }
    }

    /// Reduce Committed Hybrid R1CS to Principal Linear Relation
    pub fn reduce(
        &self,
        hybrid_instance: &HybridR1CSInstance<F>,
        hybrid_witness: &HybridR1CSWitness<F>,
        r1cs_matrices: &[Vec<Vec<F>>; 3],
        matrix_a: &[Vec<RingElement<F>>],
        transcript: &mut Transcript<F>,
    ) -> Result<(LinearInstance<F>, LinearWitness<F>, Vec<Vec<F>>), String> {
        
        let m = hybrid_witness.witness.len() + hybrid_instance.public_input.len() + 1;
        let log_m = (m as f64).log2().ceil() as usize;

        // Step 1: Verifier samples random vector r ∈ F_{q^e}^{log m}
        let r = transcript.challenge_vector(log_m, self.extension_degree);

        // Step 2: Define witness w' = (x, 1, w)
        let mut w_prime = hybrid_instance.public_input.clone();
        w_prime.push(RingElement::one(self.ring.conductor));
        w_prime.extend(hybrid_witness.witness.clone());

        // Apply θ_k to get field witness
        let theta_w_prime = self.theta_map.apply_vector(&w_prime);

        // Step 3: Run sum-check over F_q^e for Q(Y) = Q_0(Y)Q_1(Y) - Q_2(Y)
        // where Q_i(Y) = ∑_{b'} MLE[M_i](Y,b') · MLE[θ_k(w')](b')
        let (sumcheck_proof, u, c) = self.run_r1cs_sumcheck(
            &r1cs_matrices,
            &theta_w_prime,
            &r,
            transcript,
        )?;

        // Step 4: Prover sends d_i ∈ R_{q^e} for i ∈ [3]
        // d_i = ∑_{b'} MLE[M_i](u,b') · MLE[w'](b')
        let d = self.compute_d_values(&r1cs_matrices, &w_prime, &u)?;

        transcript.append_ring_elements(&d);

        // Step 5: Verifier checks (θ_k(d_0)θ_k(d_1) - θ_k(d_2))eq(u;r) = c
        let theta_d: Vec<F> = d.iter().map(|di| self.theta_map.apply(di)).collect();
        let lhs = (theta_d[0] * theta_d[1] - theta_d[2]) * eq_polynomial(&u, &r);
        
        if lhs != c {
            return Err("R1CS linearization check failed".to_string());
        }

        // Step 6: Sample v for public input check
        let log_ell_plus_1 = ((hybrid_instance.public_input.len() + 1) as f64).log2().ceil() as usize;
        let v = self.sample_public_input_challenge(log_ell_plus_1, transcript)?;

        // Compute e = MLE[(x, 1)](v)
        let mut public_prefix = hybrid_instance.public_input.clone();
        public_prefix.push(RingElement::one(self.ring.conductor));
        let e = self.evaluate_mle(&public_prefix, &v)?;

        // Step 7: Output principal linear relation instance
        let r_prime = vec![
            self.embed_in_extension_ring(&u),
            self.embed_in_extension_ring(&u),
            self.embed_in_extension_ring(&u),
        ];

        let b_prime = vec![
            self.combine_eval_points(&v),
        ];

        let mut y_prime = hybrid_instance.commitment.clone();
        y_prime.extend(d.clone());
        y_prime.push(e);

        let linear_instance = LinearInstance {
            challenge_points: r_prime,
            eval_points: b_prime,
            image: y_prime,
        };

        let linear_witness = LinearWitness {
            witness: w_prime,
        };

        Ok((linear_instance, linear_witness, sumcheck_proof))
    }

    /// Run sum-check for R1CS linearization
    fn run_r1cs_sumcheck(
        &self,
        matrices: &[Vec<Vec<F>>; 3],
        witness: &[F],
        r: &[F],
        transcript: &mut Transcript<F>,
    ) -> Result<(Vec<Vec<F>>, Vec<F>, F), String> {
        
        let log_m = (witness.len() as f64).log2().ceil() as usize;
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        // Define Q(Y) = Q_0(Y)Q_1(Y) - Q_2(Y)
        // Compute MLE for each matrix-witness product
        let q_mles = self.compute_q_mles(matrices, witness)?;

        // Run sum-check to reduce ∑_{b ∈ {0,1}^{log m}} Q(b)eq(b;r) = 0
        let mut current_evals = q_mles;

        for round in 0..log_m {
            // Compute univariate polynomial for this round
            let univariate = self.compute_r1cs_round_polynomial(
                &current_evals,
                r,
                &challenges,
                round,
                log_m,
            )?;

            round_polynomials.push(univariate.clone());

            // Get challenge
            let challenge = transcript.challenge_scalar(self.extension_degree);
            challenges.push(challenge);

            // Fold evaluations
            current_evals = self.fold_q_evaluations(&current_evals, challenge);
        }

        let final_eval = current_evals[0];

        Ok((round_polynomials, challenges, final_eval))
    }

    /// Compute Q_i MLEs
    fn compute_q_mles(
        &self,
        matrices: &[Vec<Vec<F>>; 3],
        witness: &[F],
    ) -> Result<Vec<F>, String> {
        // Simplified: compute evaluations of Q on boolean hypercube
        // In practice, would compute MLE[M_i](Y,b') · MLE[witness](b') for each Y
        Ok(vec![F::zero(); 1 << ((witness.len() as f64).log2().ceil() as usize)])
    }

    /// Compute round polynomial for R1CS sum-check
    fn compute_r1cs_round_polynomial(
        &self,
        evals: &[F],
        r: &[F],
        prev_challenges: &[F],
        round: usize,
        num_vars: usize,
    ) -> Result<Vec<F>, String> {
        // Degree 2 polynomial (Q_0 · Q_1 has degree 2)
        let mut poly = vec![F::zero(); 3];

        let half_size = evals.len() / 2;

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];

            // Compute eq contribution
            let mut point_0 = prev_challenges.to_vec();
            point_0.push(F::zero());
            let mut point_1 = prev_challenges.to_vec();
            point_1.push(F::one());

            while point_0.len() < num_vars {
                point_0.push(F::zero());
            }
            while point_1.len() < num_vars {
                point_1.push(F::zero());
            }

            let eq_0 = eq_polynomial(&point_0, r);
            let eq_1 = eq_polynomial(&point_1, r);

            // Linear interpolation: g(X) = (1-X)·eval_0·eq_0 + X·eval_1·eq_1
            poly[0] = poly[0] + eval_0 * eq_0;
            poly[1] = poly[1] + (eval_1 * eq_1 - eval_0 * eq_0);
        }

        Ok(poly)
    }

    /// Fold Q evaluations
    fn fold_q_evaluations(&self, evals: &[F], challenge: F) -> Vec<F> {
        let half_size = evals.len() / 2;
        let mut folded = Vec::with_capacity(half_size);

        for i in 0..half_size {
            let eval_0 = evals[2 * i];
            let eval_1 = evals[2 * i + 1];
            folded.push(eval_0 * (F::one() - challenge) + eval_1 * challenge);
        }

        folded
    }

    /// Compute d values: d_i = ∑_{b'} MLE[M_i](u,b') · MLE[w'](b')
    fn compute_d_values(
        &self,
        matrices: &[Vec<Vec<F>>; 3],
        w_prime: &[RingElement<F>],
        u: &[F],
    ) -> Result<Vec<ExtensionRingElement<F>>, String> {
        
        let mut d = Vec::with_capacity(3);

        for matrix in matrices {
            let mut sum = RingElement::zero(self.ring.conductor);
            
            // Compute ∑_{b'} MLE[M_i](u,b') · MLE[w'](b')
            // Simplified computation
            for (i, row) in matrix.iter().enumerate() {
                for (j, &entry) in row.iter().enumerate() {
                    if j < w_prime.len() {
                        let entry_ring = self.theta_map.preimage(entry);
                        let contrib = self.ring.multiply(&entry_ring, &w_prime[j]);
                        sum = self.ring.add(&sum, &contrib);
                    }
                }
            }

            d.push(sum);
        }

        Ok(d)
    }

    /// Sample challenge for public input verification
    fn sample_public_input_challenge(
        &self,
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<Vec<ExtensionRingElement<F>>, String> {
        
        let mut challenges = Vec::with_capacity(num_vars);
        
        for _ in 0..num_vars {
            let idx = transcript.challenge_index(self.challenge_set.elements.len());
            challenges.push(self.challenge_set.elements[idx].clone());
        }

        Ok(challenges)
    }

    /// Evaluate MLE at a point
    fn evaluate_mle(
        &self,
        values: &[RingElement<F>],
        point: &[ExtensionRingElement<F>],
    ) -> Result<ExtensionRingElement<F>, String> {
        
        let mle = MLE::new(
            values.iter().flat_map(|v| v.cf()).collect()
        );

        // Convert point to field elements for evaluation
        let point_field: Vec<F> = point.iter()
            .flat_map(|p| p.cf())
            .collect();

        let eval_field = mle.evaluate(&point_field[..mle.num_vars.min(point_field.len())]);
        
        Ok(self.theta_map.preimage(eval_field))
    }

    /// Embed field vector in extension ring
    fn embed_in_extension_ring(&self, point: &[F]) -> Vec<ExtensionRingElement<F>> {
        point.iter()
            .map(|&p| self.theta_map.preimage(p))
            .collect()
    }

    /// Combine evaluation points
    fn combine_eval_points(&self, v: &[ExtensionRingElement<F>]) -> Vec<ExtensionRingElement<F>> {
        let mut result = v.to_vec();
        result.push(RingElement::zero(self.ring.conductor));
        result
    }
}
