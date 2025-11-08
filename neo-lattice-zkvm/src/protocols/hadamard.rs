// Hadamard Product Reduction Protocol (Π_had)
// Figure 1 from Symphony paper
// Reduces R_had^aux (Hadamard product check) to R_lin^aux (linear evaluation check)

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::field::symphony_extension::SymphonyExtensionField;
use crate::ring::tensor::TensorElement;
use crate::commitment::ajtai::Commitment;
use crate::folding::transcript::Transcript;
use crate::folding::sumcheck::{SumcheckProver, SumcheckVerifier, SumcheckProof};
use crate::polynomial::multilinear::MultilinearExtension;
use super::rok_traits::{
    ReductionOfKnowledge, LinearInstance, LinearWitness, LinearAuxData,
    SparseMatrix, MultilinearPolynomial, compute_tensor_product, compute_eq_polynomial,
};
use std::marker::PhantomData;

/// Hadamard product relation R_had^aux
/// Instance: (c, X_in, (M_1, M_2, M_3))
/// Witness: W
/// Check: (M_1 × F) ◦ (M_2 × F) = M_3 × F
/// where F^⊤ = [X_in^⊤, W^⊤] and ◦ is Hadamard (element-wise) product
#[derive(Clone, Debug)]
pub struct HadamardInstance<F: Field> {
    /// Commitment to witness
    pub commitment: Commitment<F>,
    
    /// Public input X_in ∈ Z_q^{n_in×d}
    pub public_input: Vec<Vec<F>>,
    
    /// R1CS matrices (M_1, M_2, M_3) ∈ Z_q^{m×n}
    pub matrices: (SparseMatrix<F>, SparseMatrix<F>, SparseMatrix<F>),
    
    /// Number of constraints m
    pub num_constraints: usize,
    
    /// Number of variables n = n_in + n_w
    pub num_variables: usize,
    
    /// Number of columns d (batch size)
    pub num_columns: usize,
    
    /// Auxiliary data
    pub aux_data: LinearAuxData<F>,
}

/// Hadamard witness
#[derive(Clone, Debug)]
pub struct HadamardWitness<F: Field> {
    /// Witness matrix W ∈ Z_q^{n_w×d}
    pub witness_matrix: Vec<Vec<F>>,
    
    /// Opening scalar s ∈ S - S
    pub opening_scalar: RingElement<F>,
}

/// Hadamard reduction proof
#[derive(Clone, Debug)]
pub struct HadamardProof<F: Field> {
    /// Sumcheck proof for batched Hadamard claims
    pub sumcheck_proof: SumcheckProof<F>,
    
    /// Evaluation matrix U ∈ K^{3×d}
    /// U_{i,j} = g_{i,j}(r) where g_{i,j} is MLE of (M_i × F)_{*,j}
    pub evaluation_matrix: Vec<Vec<SymphonyExtensionField<F>>>,
}

/// Hadamard product reduction protocol
pub struct HadamardReductionProtocol<F: Field> {
    /// Ring parameters
    ring: CyclotomicRing<F>,
    
    /// Challenge set size |S|
    challenge_set_size: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> HadamardReductionProtocol<F> {
    /// Create new Hadamard reduction protocol
    pub fn new(ring: CyclotomicRing<F>, challenge_set_size: usize) -> Self {
        Self {
            ring,
            challenge_set_size,
            _phantom: PhantomData,
        }
    }
    
    /// Prover: reduce Hadamard instance to linear instance
    /// 
    /// Protocol (Figure 1):
    /// 1. V → P: s ← K^{log m}, α ← K
    /// 2. P ↔ V: Sumcheck for Σ_{b,j} α^{j-1}·f_j(b) = 0
    ///    where f_j(X) = eq(s,X)·(g_{1,j}(X)·g_{2,j}(X) - g_{3,j}(X))
    /// 3. P → V: U ∈ K^{3×d} where U_{i,j} = g_{i,j}(r)
    /// 4. V: Check Σ_j α^{j-1}·eq(s,r)·(U_{1,j}·U_{2,j} - U_{3,j}) = e
    /// 5. Output: v_i = Σ_j (X^{j-1})·U_{i,j} ∈ E for i ∈ [3]
    pub fn prove(
        &self,
        instance: &HadamardInstance<F>,
        witness: &HadamardWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<(LinearInstance<F>, LinearWitness<F>, HadamardProof<F>), String> {
        // Step 1: Receive challenges from transcript
        let log_m = (instance.num_constraints as f64).log2().ceil() as usize;
        let s = self.receive_challenge_vector(transcript, "hadamard_s", log_m)?;
        let alpha = self.receive_challenge_scalar(transcript, "hadamard_alpha")?;
        
        // Step 2: Construct full witness matrix F^⊤ = [X_in^⊤, W^⊤]
        let f_matrix = self.construct_full_witness(instance, witness)?;
        
        // Step 3: Compute M_i × F for i ∈ [3]
        let m1_f = self.matrix_multiply(&instance.matrices.0, &f_matrix)?;
        let m2_f = self.matrix_multiply(&instance.matrices.1, &f_matrix)?;
        let m3_f = self.matrix_multiply(&instance.matrices.2, &f_matrix)?;
        
        // Step 4: Prepare sumcheck claims
        // For each column j: Σ_{b∈{0,1}^{log m}} eq(s,b)·(g_{1,j}(b)·g_{2,j}(b) - g_{3,j}(b)) = 0
        let sumcheck_claim = self.prepare_batched_sumcheck_claim(
            &s,
            &alpha,
            &m1_f,
            &m2_f,
            &m3_f,
        )?;
        
        // Step 5: Run degree-3 sumcheck protocol
        let mut sumcheck_prover = SumcheckProver::new(
            sumcheck_claim,
            3, // degree
            self.ring.clone(),
        );
        let sumcheck_proof = sumcheck_prover.prove(transcript)?;
        let r = sumcheck_proof.final_challenge.clone();
        
        // Step 6: Compute evaluation matrix U ∈ K^{3×d}
        let evaluation_matrix = self.compute_evaluation_matrix(
            &r,
            &m1_f,
            &m2_f,
            &m3_f,
        )?;
        
        // Append evaluation matrix to transcript
        for (i, row) in evaluation_matrix.iter().enumerate() {
            for (j, eval) in row.iter().enumerate() {
                transcript.append_extension_field(&format!("hadamard_U_{}_{}", i, j), eval);
            }
        }
        
        // Step 7: Compute output evaluations v_i ∈ E for i ∈ [3]
        let output_evaluations = self.compute_output_evaluations(&evaluation_matrix)?;
        
        // Step 8: Construct linear instance and witness
        let linear_instance = LinearInstance {
            commitment: instance.commitment.clone(),
            public_input: vec![], // Will be filled by caller
            evaluation_point: r.clone(),
            evaluation: output_evaluations[0].clone(), // v_1 for first matrix
            aux_data: instance.aux_data.clone(),
        };
        
        let linear_witness = LinearWitness {
            witness: self.flatten_witness_matrix(&f_matrix)?,
            opening_scalar: witness.opening_scalar.clone(),
            norm: self.compute_witness_norm(&f_matrix)?,
        };
        
        let proof = HadamardProof {
            sumcheck_proof,
            evaluation_matrix,
        };
        
        Ok((linear_instance, linear_witness, proof))
    }
    
    /// Verifier: verify Hadamard reduction
    pub fn verify(
        &self,
        instance: &HadamardInstance<F>,
        proof: &HadamardProof<F>,
        transcript: &mut Transcript,
    ) -> Result<LinearInstance<F>, String> {
        // Step 1: Regenerate challenges
        let log_m = (instance.num_constraints as f64).log2().ceil() as usize;
        let s = self.receive_challenge_vector(transcript, "hadamard_s", log_m)?;
        let alpha = self.receive_challenge_scalar(transcript, "hadamard_alpha")?;
        
        // Step 2: Verify sumcheck proof
        let mut sumcheck_verifier = SumcheckVerifier::new(3, self.ring.clone());
        let r = sumcheck_verifier.verify(&proof.sumcheck_proof, transcript)?;
        
        // Step 3: Regenerate evaluation matrix from transcript
        let mut evaluation_matrix = vec![vec![SymphonyExtensionField::zero(); instance.num_columns]; 3];
        for (i, row) in evaluation_matrix.iter_mut().enumerate() {
            for (j, eval) in row.iter_mut().enumerate() {
                *eval = transcript.challenge_extension_field(&format!("hadamard_U_{}_{}", i, j));
            }
        }
        
        // Step 4: Verify final check (Equation in Step 4 of protocol)
        // Check: Σ_j α^{j-1}·eq(s,r)·(U_{1,j}·U_{2,j} - U_{3,j}) = e
        self.verify_final_check(
            &s,
            &r,
            &alpha,
            &evaluation_matrix,
            &proof.sumcheck_proof,
        )?;
        
        // Step 5: Compute output evaluations
        let output_evaluations = self.compute_output_evaluations(&evaluation_matrix)?;
        
        // Step 6: Construct linear instance
        Ok(LinearInstance {
            commitment: instance.commitment.clone(),
            public_input: vec![],
            evaluation_point: r,
            evaluation: output_evaluations[0].clone(),
            aux_data: instance.aux_data.clone(),
        })
    }
    
    /// Construct full witness matrix F^⊤ = [X_in^⊤, W^⊤]
    fn construct_full_witness(
        &self,
        instance: &HadamardInstance<F>,
        witness: &HadamardWitness<F>,
    ) -> Result<Vec<Vec<F>>, String> {
        let n_in = instance.public_input.len();
        let n_w = witness.witness_matrix.len();
        let d = instance.num_columns;
        
        if n_in + n_w != instance.num_variables {
            return Err(format!(
                "Dimension mismatch: n_in={} + n_w={} != n={}",
                n_in, n_w, instance.num_variables
            ));
        }
        
        let mut f_matrix = Vec::with_capacity(instance.num_variables);
        
        // Add public input rows
        for row in &instance.public_input {
            if row.len() != d {
                return Err(format!("Public input row length {} != d={}", row.len(), d));
            }
            f_matrix.push(row.clone());
        }
        
        // Add witness rows
        for row in &witness.witness_matrix {
            if row.len() != d {
                return Err(format!("Witness row length {} != d={}", row.len(), d));
            }
            f_matrix.push(row.clone());
        }
        
        Ok(f_matrix)
    }
    
    /// Matrix multiplication: M × F where M is m×n and F is n×d
    fn matrix_multiply(
        &self,
        matrix: &SparseMatrix<F>,
        f: &[Vec<F>],
    ) -> Result<Vec<Vec<F>>, String> {
        let m = matrix.rows;
        let n = matrix.cols;
        let d = f[0].len();
        
        if f.len() != n {
            return Err(format!("Matrix dimension mismatch: {} != {}", f.len(), n));
        }
        
        let mut result = vec![vec![F::zero(); d]; m];
        
        // Sparse matrix multiplication
        for &(row, col, ref value) in &matrix.entries {
            for j in 0..d {
                result[row][j] = result[row][j].add(&value.mul(&f[col][j]));
            }
        }
        
        Ok(result)
    }
    
    /// Prepare batched sumcheck claim
    /// Claim: Σ_{b∈{0,1}^{log m}} Σ_j α^{j-1}·f_j(b) = 0
    /// where f_j(X) = eq(s,X)·(g_{1,j}(X)·g_{2,j}(X) - g_{3,j}(X))
    fn prepare_batched_sumcheck_claim(
        &self,
        s: &[SymphonyExtensionField<F>],
        alpha: &SymphonyExtensionField<F>,
        m1_f: &[Vec<F>],
        m2_f: &[Vec<F>],
        m3_f: &[Vec<F>],
    ) -> Result<MultilinearPolynomial<F>, String> {
        let m = m1_f.len();
        let d = m1_f[0].len();
        let log_m = (m as f64).log2().ceil() as usize;
        
        // Compute evaluations at Boolean hypercube {0,1}^{log m}
        let mut evaluations = vec![SymphonyExtensionField::zero(); 1 << log_m];
        
        for b_idx in 0..m {
            // Convert index to binary vector
            let b = self.index_to_binary(b_idx, log_m);
            
            // Compute eq(s, b)
            let eq_s_b = compute_eq_polynomial(s, &b);
            
            // Compute Σ_j α^{j-1}·(g_{1,j}(b)·g_{2,j}(b) - g_{3,j}(b))
            let mut sum = SymphonyExtensionField::zero();
            let mut alpha_power = SymphonyExtensionField::one();
            
            for j in 0..d {
                // g_{i,j}(b) = (M_i × F)_{b,j}
                let g1_j_b = SymphonyExtensionField::from_base_field(m1_f[b_idx][j]);
                let g2_j_b = SymphonyExtensionField::from_base_field(m2_f[b_idx][j]);
                let g3_j_b = SymphonyExtensionField::from_base_field(m3_f[b_idx][j]);
                
                // g_{1,j}(b)·g_{2,j}(b) - g_{3,j}(b)
                let product = g1_j_b.mul(&g2_j_b);
                let diff = product.sub(&g3_j_b);
                
                // α^{j-1}·diff
                let scaled = alpha_power.mul(&diff);
                sum = sum.add(&scaled);
                
                alpha_power = alpha_power.mul(alpha);
            }
            
            // eq(s, b)·sum
            evaluations[b_idx] = eq_s_b.mul(&sum);
        }
        
        // Pad to power of 2
        while evaluations.len() < (1 << log_m) {
            evaluations.push(SymphonyExtensionField::zero());
        }
        
        Ok(MultilinearPolynomial::from_evaluations(evaluations))
    }
    
    /// Compute evaluation matrix U ∈ K^{3×d}
    /// U_{i,j} = g_{i,j}(r) where g_{i,j} is MLE of (M_i × F)_{*,j}
    fn compute_evaluation_matrix(
        &self,
        r: &[SymphonyExtensionField<F>],
        m1_f: &[Vec<F>],
        m2_f: &[Vec<F>],
        m3_f: &[Vec<F>],
    ) -> Result<Vec<Vec<SymphonyExtensionField<F>>>, String> {
        let d = m1_f[0].len();
        let mut evaluation_matrix = vec![vec![SymphonyExtensionField::zero(); d]; 3];
        
        // For each column j and each matrix i
        for j in 0..d {
            // Extract column j from each M_i × F
            let col1_j: Vec<_> = m1_f.iter().map(|row| row[j]).collect();
            let col2_j: Vec<_> = m2_f.iter().map(|row| row[j]).collect();
            let col3_j: Vec<_> = m3_f.iter().map(|row| row[j]).collect();
            
            // Compute MLE evaluations
            evaluation_matrix[0][j] = self.evaluate_mle(&col1_j, r)?;
            evaluation_matrix[1][j] = self.evaluate_mle(&col2_j, r)?;
            evaluation_matrix[2][j] = self.evaluate_mle(&col3_j, r)?;
        }
        
        Ok(evaluation_matrix)
    }
    
    /// Evaluate multilinear extension at point r
    fn evaluate_mle(
        &self,
        values: &[F],
        r: &[SymphonyExtensionField<F>],
    ) -> Result<SymphonyExtensionField<F>, String> {
        // Compute tensor product ts(r)
        let tensor = compute_tensor_product(r);
        
        // Compute inner product ⟨values, tensor⟩
        let mut result = SymphonyExtensionField::zero();
        for (i, &value) in values.iter().enumerate() {
            if i >= tensor.len() {
                break;
            }
            let value_ext = SymphonyExtensionField::from_base_field(value);
            result = result.add(&value_ext.mul(&tensor[i]));
        }
        
        Ok(result)
    }
    
    /// Compute output evaluations v_i = Σ_j (X^{j-1})·U_{i,j} ∈ E
    fn compute_output_evaluations(
        &self,
        evaluation_matrix: &[Vec<SymphonyExtensionField<F>>],
    ) -> Result<Vec<TensorElement<F>>, String> {
        let d = evaluation_matrix[0].len();
        let mut output_evals = Vec::with_capacity(3);
        
        for i in 0..3 {
            // Compute Σ_j (X^{j-1})·U_{i,j}
            let mut tensor_elem = TensorElement::zero(&self.ring);
            
            for j in 0..d {
                // Create monomial X^{j-1}
                let mut monomial_coeffs = vec![F::zero(); self.ring.degree];
                if j > 0 {
                    monomial_coeffs[j - 1] = F::one();
                } else {
                    monomial_coeffs[0] = F::one(); // X^0 = 1
                }
                let monomial = RingElement::from_coeffs(monomial_coeffs);
                
                // Multiply by U_{i,j} and add to sum
                let scaled = tensor_elem.scalar_mul_extension(&evaluation_matrix[i][j]);
                tensor_elem = tensor_elem.add(&scaled);
            }
            
            output_evals.push(tensor_elem);
        }
        
        Ok(output_evals)
    }
    
    /// Verify final check
    fn verify_final_check(
        &self,
        s: &[SymphonyExtensionField<F>],
        r: &[SymphonyExtensionField<F>],
        alpha: &SymphonyExtensionField<F>,
        evaluation_matrix: &[Vec<SymphonyExtensionField<F>>],
        sumcheck_proof: &SumcheckProof<F>,
    ) -> Result<(), String> {
        // Compute eq(s, r)
        let eq_s_r = compute_eq_polynomial(s, r);
        
        // Compute Σ_j α^{j-1}·(U_{1,j}·U_{2,j} - U_{3,j})
        let d = evaluation_matrix[0].len();
        let mut sum = SymphonyExtensionField::zero();
        let mut alpha_power = SymphonyExtensionField::one();
        
        for j in 0..d {
            let u1_j = &evaluation_matrix[0][j];
            let u2_j = &evaluation_matrix[1][j];
            let u3_j = &evaluation_matrix[2][j];
            
            // U_{1,j}·U_{2,j} - U_{3,j}
            let product = u1_j.mul(u2_j);
            let diff = product.sub(u3_j);
            
            // α^{j-1}·diff
            let scaled = alpha_power.mul(&diff);
            sum = sum.add(&scaled);
            
            alpha_power = alpha_power.mul(alpha);
        }
        
        // eq(s, r)·sum
        let expected = eq_s_r.mul(&sum);
        
        // Get claimed value from sumcheck
        let claimed = &sumcheck_proof.claimed_value;
        
        // Verify equality
        if expected != *claimed {
            return Err("Final check failed: expected != claimed".to_string());
        }
        
        Ok(())
    }
    
    /// Helper: receive challenge vector from transcript
    fn receive_challenge_vector(
        &self,
        transcript: &mut Transcript,
        label: &str,
        length: usize,
    ) -> Result<Vec<SymphonyExtensionField<F>>, String> {
        let mut challenges = Vec::with_capacity(length);
        for i in 0..length {
            let challenge = transcript.challenge_extension_field(&format!("{}_{}", label, i));
            challenges.push(challenge);
        }
        Ok(challenges)
    }
    
    /// Helper: receive challenge scalar from transcript
    fn receive_challenge_scalar(
        &self,
        transcript: &mut Transcript,
        label: &str,
    ) -> Result<SymphonyExtensionField<F>, String> {
        Ok(transcript.challenge_extension_field(label))
    }
    
    /// Helper: convert index to binary vector
    fn index_to_binary(&self, index: usize, length: usize) -> Vec<SymphonyExtensionField<F>> {
        let mut binary = Vec::with_capacity(length);
        for i in 0..length {
            let bit = (index >> i) & 1;
            binary.push(if bit == 1 {
                SymphonyExtensionField::one()
            } else {
                SymphonyExtensionField::zero()
            });
        }
        binary
    }
    
    /// Helper: flatten witness matrix to vector
    fn flatten_witness_matrix(&self, matrix: &[Vec<F>]) -> Result<Vec<RingElement<F>>, String> {
        let mut flattened = Vec::new();
        
        for row in matrix {
            // Convert row to ring element
            let ring_elem = RingElement::from_coeffs(row.clone());
            flattened.push(ring_elem);
        }
        
        Ok(flattened)
    }
    
    /// Helper: compute witness norm
    fn compute_witness_norm(&self, matrix: &[Vec<F>]) -> Result<f64, String> {
        let mut max_norm = 0.0;
        
        for row in matrix {
            for &value in row {
                let val_u64 = value.to_canonical_u64();
                let norm = val_u64 as f64;
                if norm > max_norm {
                    max_norm = norm;
                }
            }
        }
        
        Ok(max_norm)
    }
}

impl<F: Field> ReductionOfKnowledge for HadamardReductionProtocol<F> {
    type InputInstance = HadamardInstance<F>;
    type InputWitness = HadamardWitness<F>;
    type OutputInstance = LinearInstance<F>;
    type OutputWitness = LinearWitness<F>;
    type Proof = HadamardProof<F>;
    type Error = String;
    
    fn reduce(
        &self,
        instance: &Self::InputInstance,
        witness: &Self::InputWitness,
        transcript: &mut Transcript,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness, Self::Proof), Self::Error> {
        self.prove(instance, witness, transcript)
    }
    
    fn verify(
        &self,
        instance: &Self::InputInstance,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<Self::OutputInstance, Self::Error> {
        self.verify(instance, proof, transcript)
    }
    
    fn protocol_name(&self) -> &'static str {
        "Hadamard_Reduction"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_hadamard_protocol_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let protocol = HadamardReductionProtocol::new(ring, 256);
        assert_eq!(protocol.protocol_name(), "Hadamard_Reduction");
    }
    
    // Additional tests would go here
}
