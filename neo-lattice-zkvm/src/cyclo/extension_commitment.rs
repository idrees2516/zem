//! Extension Commitment Protocol (Figure 2 from the paper)
//! 
//! Commits to the decomposition of the witness "vertically"

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;
use super::utils::*;

/// Extension Commitment Protocol Π^ext_{b,C}
pub struct ExtensionCommitment<F: FiniteField> {
    /// Cyclotomic ring
    pub ring: CyclotomicRing<F>,
    /// Decomposition base b
    pub base_b: usize,
    /// Challenge set C (strong sampling set)
    pub challenge_set: StrongSamplingSet<F>,
    /// Commitment matrix R ∈ R_q^{a'×mℓ}
    pub matrix_r: Vec<Vec<RingElement<F>>>,
}

impl<F: FiniteField> ExtensionCommitment<F> {
    pub fn new(
        ring: CyclotomicRing<F>,
        base_b: usize,
        challenge_set: StrongSamplingSet<F>,
        matrix_r: Vec<Vec<RingElement<F>>>,
    ) -> Self {
        Self {
            ring,
            base_b,
            challenge_set,
            matrix_r,
        }
    }

    /// Prover side of extension commitment
    /// Input: ((r_i)_i, (b_i)_i, y), w ∈ Ξ^lin_{A,(M_i)_i,a,n,m,B}
    /// Output: ((r_i)_i, (b̃_i)_i, ỹ), v ∈ Ξ^lin_{R,(M̃_i)_i,a',n,mℓ,b}
    pub fn prove(
        &self,
        instance: &LinearInstance<F>,
        witness: &LinearWitness<F>,
        norm_bound_B: F,
        matrices_M: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        transcript: &mut Transcript<F>,
    ) -> Result<(LinearInstance<F>, LinearWitness<F>, ExtensionCommitmentProof<F>), String> {
        
        let m = witness.witness.len();
        let ell = self.compute_ell(norm_bound_B);
        let ell_C = (matrices_M[0].len() as f64).log2().ceil() as usize;

        // Step 1: Decompose witness into base-2b digits
        let v = self.decompose_witness(&witness.witness, ell)?;

        // Step 2: Compute extended commitment t := Rv
        let t = self.compute_commitment(&v)?;

        transcript.append_commitment(&t);

        // Step 3: Verifier samples c̃ ← C^{ℓ_C} and sets c := tensor(c̃)
        let c_tilde = self.sample_challenges(ell_C, transcript)?;
        let c = self.compute_tensor_challenges(&c_tilde)?;

        // Step 4: Construct augmented relation
        let (new_instance, new_witness) = self.construct_augmented_relation(
            instance,
            &v,
            &t,
            &c,
            &c_tilde,
            matrices_M,
            matrix_A,
            ell,
        )?;

        let proof = ExtensionCommitmentProof {
            commitment: t,
        };

        Ok((new_instance, new_witness, proof))
    }

    /// Verifier side of extension commitment
    pub fn verify(
        &self,
        instance: &LinearInstance<F>,
        proof: &ExtensionCommitmentProof<F>,
        norm_bound_B: F,
        matrices_M: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        transcript: &mut Transcript<F>,
    ) -> Result<LinearInstance<F>, String> {
        
        let ell = self.compute_ell(norm_bound_B);
        let ell_C = (matrices_M[0].len() as f64).log2().ceil() as usize;

        transcript.append_commitment(&proof.commitment);

        // Sample challenges
        let c_tilde = self.sample_challenges(ell_C, transcript)?;
        let c = self.compute_tensor_challenges(&c_tilde)?;

        // Construct augmented instance (verifier side)
        self.construct_augmented_instance(
            instance,
            &proof.commitment,
            &c,
            &c_tilde,
            matrices_M,
            matrix_A,
            ell,
        )
    }

    /// Decompose witness into base-(2b) digits
    /// w = ∑_{i=0}^{ℓ-1} (2b)^i w_i where ||w_i||_∞ < b
    fn decompose_witness(
        &self,
        witness: &[RingElement<F>],
        ell: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        
        let m = witness.len();
        let mut v = Vec::with_capacity(m * ell);

        for w_elem in witness {
            // Decompose each coefficient of the ring element
            let decomposed = self.decompose_ring_element(w_elem, ell)?;
            v.extend(decomposed);
        }

        Ok(v)
    }

    /// Decompose single ring element into ℓ elements
    fn decompose_ring_element(
        &self,
        elem: &RingElement<F>,
        ell: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        
        let phi = self.ring.degree;
        let base_2b = 2 * self.base_b;
        let mut result = vec![RingElement::zero(self.ring.conductor); ell];

        for coeff_idx in 0..phi {
            let coeff = elem.coeffs[coeff_idx];
            let coeff_int = coeff.to_i64();

            // Decompose coefficient into base-(2b) representation
            let mut remaining = coeff_int.abs();
            let sign = if coeff_int < 0 { -1 } else { 1 };

            for digit_idx in 0..ell {
                let digit = (remaining % base_2b as i64) as i64;
                remaining /= base_2b as i64;

                // Store signed digit
                let signed_digit = sign * digit;
                result[digit_idx].coeffs[coeff_idx] = F::from_i64(signed_digit);

                // Verify bound
                if result[digit_idx].coeffs[coeff_idx].abs().to_u64() >= self.base_b as u64 {
                    return Err("Decomposed digit exceeds bound".to_string());
                }
            }

            if remaining != 0 {
                return Err("Decomposition overflow".to_string());
            }
        }

        Ok(result)
    }

    /// Compute commitment t = Rv
    fn compute_commitment(
        &self,
        v: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        
        if self.matrix_r[0].len() != v.len() {
            return Err("Dimension mismatch in commitment".to_string());
        }

        let commitment = matrix_vector_mult(&self.ring, &self.matrix_r, v);
        Ok(commitment)
    }

    /// Sample challenges from strong sampling set
    fn sample_challenges(
        &self,
        ell_C: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        
        let mut challenges = Vec::with_capacity(ell_C);
        
        for _ in 0..ell_C {
            let idx = transcript.challenge_index(self.challenge_set.elements.len());
            challenges.push(self.challenge_set.elements[idx].clone());
        }

        Ok(challenges)
    }

    /// Compute tensor challenges c = tensor(c̃)
    fn compute_tensor_challenges(
        &self,
        c_tilde: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, String> {
        
        let ell_C = c_tilde.len();
        let size = 1 << ell_C;
        let mut result = Vec::with_capacity(size);

        for i in 0..size {
            let mut elem = RingElement::one(self.ring.conductor);
            
            for j in 0..ell_C {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    elem = self.ring.multiply(&elem, &c_tilde[j]);
                }
            }
            
            result.push(elem);
        }

        Ok(result)
    }

    /// Construct augmented relation (prover side)
    fn construct_augmented_relation(
        &self,
        instance: &LinearInstance<F>,
        v: &[RingElement<F>],
        t: &[RingElement<F>],
        c: &[RingElement<F>],
        c_tilde: &[RingElement<F>],
        matrices_M: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        ell: usize,
    ) -> Result<(LinearInstance<F>, LinearWitness<F>), String> {
        
        // Construct M̃_i = ((2b)^0, (2b)^1, ..., (2b)^{ℓ-1}) ⊗ M_i
        let mut tilde_matrices = Vec::new();
        let base_2b = 2 * self.base_b;

        for M_i in matrices_M {
            let tilde_M_i = self.tensor_with_powers(M_i, base_2b, ell)?;
            tilde_matrices.push(tilde_M_i);
        }

        // Add M̃_k = ((2b)^0, (2b)^1, ..., (2b)^{ℓ-1}) ⊗ A
        let tilde_M_k = self.tensor_with_powers(matrix_A, base_2b, ell)?;
        tilde_matrices.push(tilde_M_k);

        // Construct b̃_i = ((2b)^0, (2b)^1, ..., (2b)^{ℓ-1}) ⊗ b_i
        let mut tilde_b = Vec::new();
        for b_i in &instance.eval_points {
            let tilde_b_i = self.tensor_eval_point_with_powers(b_i, base_2b, ell)?;
            tilde_b.push(tilde_b_i);
        }

        // Augment challenge points with c
        let mut new_challenge_points = instance.challenge_points.clone();
        // The tensor c acts as a batching challenge
        // In practice, we use c̃ directly in the extended instance

        // Construct ỹ
        let mut new_image = t.clone();
        new_image.extend(instance.image.iter().skip(t.len()).cloned());
        
        // Add inner product constraint ⟨c, y⟩
        let inner_prod = self.compute_image_inner_product(c, &instance.image)?;
        new_image.push(inner_prod);

        let new_instance = LinearInstance {
            challenge_points: new_challenge_points,
            eval_points: tilde_b,
            image: new_image,
        };

        let new_witness = LinearWitness {
            witness: v.to_vec(),
        };

        Ok((new_instance, new_witness))
    }

    /// Construct augmented instance (verifier side)
    fn construct_augmented_instance(
        &self,
        instance: &LinearInstance<F>,
        t: &[RingElement<F>],
        c: &[RingElement<F>],
        c_tilde: &[RingElement<F>],
        matrices_M: &[Vec<Vec<RingElement<F>>>],
        matrix_A: &[Vec<RingElement<F>>],
        ell: usize,
    ) -> Result<LinearInstance<F>, String> {
        
        // Similar to prover side but without witness
        let base_2b = 2 * self.base_b;

        let mut tilde_b = Vec::new();
        for b_i in &instance.eval_points {
            let tilde_b_i = self.tensor_eval_point_with_powers(b_i, base_2b, ell)?;
            tilde_b.push(tilde_b_i);
        }

        let mut new_image = t.clone();
        new_image.extend(instance.image.iter().skip(t.len()).cloned());
        
        let inner_prod = self.compute_image_inner_product(c, &instance.image)?;
        new_image.push(inner_prod);

        Ok(LinearInstance {
            challenge_points: instance.challenge_points.clone(),
            eval_points: tilde_b,
            image: new_image,
        })
    }

    /// Tensor matrix with powers
    fn tensor_with_powers(
        &self,
        matrix: &[Vec<RingElement<F>>],
        base: usize,
        ell: usize,
    ) -> Result<Vec<Vec<RingElement<F>>>, String> {
        
        let rows = matrix.len();
        let cols = matrix[0].len();
        let new_cols = cols * ell;

        let mut result = vec![vec![RingElement::zero(self.ring.conductor); new_cols]; rows];

        for i in 0..rows {
            for j in 0..cols {
                for k in 0..ell {
                    let power = base.pow(k as u32);
                    let power_field = F::from_u64(power as u64);
                    result[i][j * ell + k] = matrix[i][j].scalar_mul(power_field);
                }
            }
        }

        Ok(result)
    }

    /// Tensor evaluation point with powers
    fn tensor_eval_point_with_powers(
        &self,
        b_i: &[ExtensionRingElement<F>],
        base: usize,
        ell: usize,
    ) -> Result<Vec<ExtensionRingElement<F>>, String> {
        
        let len = b_i.len();
        let mut result = Vec::with_capacity(len * ell);

        for elem in b_i {
            for k in 0..ell {
                let power = base.pow(k as u32);
                let power_field = F::from_u64(power as u64);
                result.push(elem.scalar_mul(power_field));
            }
        }

        Ok(result)
    }

    /// Compute inner product of challenge with image
    fn compute_image_inner_product(
        &self,
        c: &[RingElement<F>],
        image: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        
        let len = c.len().min(image.len());
        let mut result = RingElement::zero(self.ring.conductor);

        for i in 0..len {
            let prod = self.ring.multiply(&c[i], &image[i]);
            result = self.ring.add(&result, &prod);
        }

        Ok(result)
    }

    /// Compute ℓ = ⌈log_{2b}(2B)⌉
    fn compute_ell(&self, norm_bound_B: F) -> usize {
        let two_B = 2 * norm_bound_B.to_u64();
        let base_2b = 2 * self.base_b as u64;
        ((two_B as f64).log(base_2b as f64)).ceil() as usize
    }
}
