// Single-Instance Reduction Protocol (Π_gr1cs)
// Figure 3 from Symphony paper
// Reduces R_gr1cs^aux (generalized R1CS) to R_lin^auxcs × R_batchlin

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::field::symphony_extension::SymphonyExtensionField;
use crate::ring::tensor::TensorElement;
use crate::commitment::ajtai::Commitment;
use crate::folding::transcript::Transcript;
use crate::folding::sumcheck::{SumcheckProver, SumcheckVerifier, SumcheckProof};
use crate::latticefold_plus::range_check::{RangeCheckProver, RangeCheckVerifier, RangeCheckProof, RangeCheckInstance};
use super::hadamard::{HadamardReductionProtocol, HadamardInstance, HadamardWitness, HadamardProof};
use super::rok_traits::{
    ReductionOfKnowledge, LinearInstance, LinearWitness, LinearAuxData,
    BatchLinearInstance, BatchLinearWitness, SparseMatrix,
};
use std::marker::PhantomData;

/// Generalized R1CS relation R_gr1cs^aux
/// Instance: (c, X_in, (M_1, M_2, M_3))
/// Witness: W
/// Checks:
/// 1. (M_1 × F) ◦ (M_2 × F) = M_3 × F where F^⊤ = [X_in^⊤, W^⊤]
/// 2. VfyOpen_{ℓ_h,B}(pp_cm, c, cf^{-1}(F)) = 1
#[derive(Clone, Debug)]
pub struct GeneralizedR1CSInstance<F: Field> {
    /// Commitment to witness
    pub commitment: Commitment<F>,
    
    /// Public input X_in ∈ Z_q^{n_in×d}
    pub public_input: Vec<Vec<F>>,
    
    /// R1CS matrices (M_1, M_2, M_3) ∈ Z_q^{m×n}
    pub r1cs_matrices: (SparseMatrix<F>, SparseMatrix<F>, SparseMatrix<F>),
    
    /// Number of constraints m
    pub num_constraints: usize,
    
    /// Number of input variables n_in
    pub num_input_vars: usize,
    
    /// Number of witness variables n_w
    pub num_witness_vars: usize,
    
    /// Number of columns d (batch size)
    pub num_columns: usize,
    
    /// Norm bound B
    pub norm_bound: f64,
    
    /// Block size ℓ_h
    pub block_size: usize,
    
    /// Auxiliary data
    pub aux_data: LinearAuxData<F>,
}

/// Generalized R1CS witness
#[derive(Clone, Debug)]
pub struct GeneralizedR1CSWitness<F: Field> {
    /// Witness matrix W ∈ Z_q^{n_w×d}
    pub witness_matrix: Vec<Vec<F>>,
    
    /// Opening scalar s ∈ S - S
    pub opening_scalar: RingElement<F>,
}

/// Single-instance reduction proof
#[derive(Clone, Debug)]
pub struct SingleInstanceProof<F: Field> {
    /// Helper commitments for range proof (c^(i))_{i=1}^{k_g}
    pub helper_commitments: Vec<Commitment<F>>,
    
    /// Hadamard reduction proof
    pub hadamard_proof: HadamardProof<F>,
    
    /// Range proof
    pub range_proof: RangeCheckProof<F>,
    
    /// Shared sumcheck challenges
    pub shared_challenges: SharedChallenges<F>,
}

/// Shared challenges between Hadamard and range proof sumchecks
#[derive(Clone, Debug)]
pub struct SharedChallenges<F: Field> {
    /// Shared challenge r̄ ∈ K^{log(m_J)}
    pub r_bar: Vec<SymphonyExtensionField<F>>,
    
    /// Shared challenge s̄ ∈ K^{log(m/m_J)}
    pub s_bar: Vec<SymphonyExtensionField<F>>,
    
    /// Shared challenge s ∈ K^{log(n/m)}
    pub s: Vec<SymphonyExtensionField<F>>,
}

/// Single-instance reduction output
#[derive(Clone, Debug)]
pub struct SingleInstanceOutput<F: Field> {
    /// Linear instance x_* for R_lin^auxcs
    pub linear_instance: LinearInstance<F>,
    
    /// Batch linear instance x_bat for R_batchlin
    pub batch_linear_instance: BatchLinearInstance<F>,
    
    /// Linear witness (for prover only)
    pub linear_witness: Option<LinearWitness<F>>,
    
    /// Batch linear witness (for prover only)
    pub batch_linear_witness: Option<BatchLinearWitness<F>>,
}

/// Single-instance reduction protocol
pub struct SingleInstanceProtocol<F: Field> {
    /// Ring parameters
    ring: CyclotomicRing<F>,
    
    /// Challenge set size |S|
    challenge_set_size: usize,
    
    /// Hadamard reduction protocol
    hadamard_protocol: HadamardReductionProtocol<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> SingleInstanceProtocol<F> {
    /// Create new single-instance reduction protocol
    pub fn new(ring: CyclotomicRing<F>, challenge_set_size: usize) -> Self {
        let hadamard_protocol = HadamardReductionProtocol::new(ring.clone(), challenge_set_size);
        
        Self {
            ring,
            challenge_set_size,
            hadamard_protocol,
            _phantom: PhantomData,
        }
    }
    
    /// Prover: reduce generalized R1CS instance to linear instances
    /// 
    /// Protocol (Figure 3):
    /// 1. Sample shared challenges J, s', α
    /// 2. Send helper commitments (c^(i))_{i=1}^{k_g}
    /// 3. Run two parallel sumchecks:
    ///    - Hadamard sumcheck (log(m) rounds)
    ///    - Monomial check sumcheck (log(n) rounds)
    ///    Share challenge (r̄, s̄, s) between sumchecks
    /// 4. Execute rest of Π_had and Π_rg
    /// 5. Output x_o = (x_*, x_bat)
    pub fn prove(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        witness: &GeneralizedR1CSWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<(SingleInstanceOutput<F>, SingleInstanceProof<F>), String> {
        // Step 1: Sample shared challenges
        let projection_matrix = self.sample_projection_matrix(transcript, instance)?;
        let s_prime = self.sample_challenge_vector(
            transcript,
            "gr1cs_s_prime",
            (instance.num_constraints as f64).log2().ceil() as usize,
        )?;
        let alpha = self.sample_challenge_scalar(transcript, "gr1cs_alpha")?;
        
        // Step 2: Construct full witness matrix F^⊤ = [X_in^⊤, W^⊤]
        let f_matrix = self.construct_full_witness(instance, witness)?;
        
        // Step 3: Compute helper commitments for range proof
        let (helper_commitments, range_prover) = self.prepare_range_proof(
            instance,
            &f_matrix,
            transcript,
        )?;
        
        // Append helper commitments to transcript
        for (i, commitment) in helper_commitments.iter().enumerate() {
            transcript.append_commitment(&format!("helper_commitment_{}", i), commitment);
        }
        
        // Step 4: Run parallel sumchecks with shared randomness
        let (hadamard_output, range_output, shared_challenges) = self.run_parallel_sumchecks(
            instance,
            witness,
            &f_matrix,
            &s_prime,
            &alpha,
            range_prover,
            transcript,
        )?;
        
        // Step 5: Finalize Hadamard reduction
        let (linear_instance, linear_witness, hadamard_proof) = hadamard_output;
        
        // Step 6: Finalize range proof
        let (range_instance, range_witness, range_proof) = range_output;
        
        // Step 7: Construct batch linear instance from range proof output
        let batch_linear_instance = self.construct_batch_linear_instance(&range_instance)?;
        let batch_linear_witness = self.construct_batch_linear_witness(&range_witness)?;
        
        // Step 8: Construct output
        let output = SingleInstanceOutput {
            linear_instance,
            batch_linear_instance,
            linear_witness: Some(linear_witness),
            batch_linear_witness: Some(batch_linear_witness),
        };
        
        let proof = SingleInstanceProof {
            helper_commitments,
            hadamard_proof,
            range_proof,
            shared_challenges,
        };
        
        Ok((output, proof))
    }
    
    /// Verifier: verify single-instance reduction
    pub fn verify(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        proof: &SingleInstanceProof<F>,
        transcript: &mut Transcript,
    ) -> Result<SingleInstanceOutput<F>, String> {
        // Step 1: Regenerate shared challenges
        let projection_matrix = self.sample_projection_matrix(transcript, instance)?;
        let s_prime = self.sample_challenge_vector(
            transcript,
            "gr1cs_s_prime",
            (instance.num_constraints as f64).log2().ceil() as usize,
        )?;
        let alpha = self.sample_challenge_scalar(transcript, "gr1cs_alpha")?;
        
        // Step 2: Regenerate helper commitments from transcript
        for (i, commitment) in proof.helper_commitments.iter().enumerate() {
            transcript.append_commitment(&format!("helper_commitment_{}", i), commitment);
        }
        
        // Step 3: Verify Hadamard reduction
        let hadamard_instance = self.construct_hadamard_instance(instance)?;
        let linear_instance = self.hadamard_protocol.verify(
            &hadamard_instance,
            &proof.hadamard_proof,
            transcript,
        )?;
        
        // Step 4: Verify range proof
        let range_verifier = self.construct_range_verifier(instance)?;
        let range_instance = range_verifier.verify(&proof.range_proof, transcript)?;
        
        // Step 5: Construct batch linear instance
        let batch_linear_instance = self.construct_batch_linear_instance(&range_instance)?;
        
        // Step 6: Verify shared challenges consistency
        self.verify_shared_challenges_consistency(
            &proof.shared_challenges,
            &proof.hadamard_proof,
            &proof.range_proof,
        )?;
        
        // Step 7: Construct output
        Ok(SingleInstanceOutput {
            linear_instance,
            batch_linear_instance,
            linear_witness: None,
            batch_linear_witness: None,
        })
    }
    
    /// Construct full witness matrix F^⊤ = [X_in^⊤, W^⊤]
    fn construct_full_witness(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        witness: &GeneralizedR1CSWitness<F>,
    ) -> Result<Vec<Vec<F>>, String> {
        let n_in = instance.num_input_vars;
        let n_w = instance.num_witness_vars;
        let d = instance.num_columns;
        
        if instance.public_input.len() != n_in {
            return Err(format!(
                "Public input size mismatch: {} != {}",
                instance.public_input.len(), n_in
            ));
        }
        
        if witness.witness_matrix.len() != n_w {
            return Err(format!(
                "Witness size mismatch: {} != {}",
                witness.witness_matrix.len(), n_w
            ));
        }
        
        let mut f_matrix = Vec::with_capacity(n_in + n_w);
        
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
    
    /// Sample projection matrix J for range proof
    fn sample_projection_matrix(
        &self,
        transcript: &mut Transcript,
        instance: &GeneralizedR1CSInstance<F>,
    ) -> Result<Vec<Vec<i8>>, String> {
        // Sample J ← χ^{λ_pj × ℓ_h} where χ is distribution over {0, ±1}
        let lambda_pj = 256; // Security parameter for projection
        let ell_h = instance.block_size;
        
        let mut matrix = vec![vec![0i8; ell_h]; lambda_pj];
        
        for i in 0..lambda_pj {
            for j in 0..ell_h {
                // Sample from {0, ±1} with Pr[0] = 1/2
                let sample = transcript.challenge_u8(&format!("projection_{}_{}", i, j));
                matrix[i][j] = match sample % 4 {
                    0 => 0,
                    1 => 1,
                    2 => -1,
                    _ => 0,
                };
            }
        }
        
        Ok(matrix)
    }
    
    /// Prepare range proof and compute helper commitments
    fn prepare_range_proof(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        f_matrix: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Result<(Vec<Commitment<F>>, RangeCheckProver<F>), String> {
        // Convert F matrix to ring elements
        let witness_ring_elems: Vec<RingElement<F>> = f_matrix
            .iter()
            .map(|row| RingElement::from_coeffs(row.clone()))
            .collect();
        
        // Create range check prover
        let range_prover = RangeCheckProver::new(
            witness_ring_elems,
            instance.norm_bound as i64,
            self.ring.clone(),
            self.challenge_set_size,
        )?;
        
        // Compute helper commitments (monomial commitments)
        // Compute actual helper commitments for range proof
        // These are commitments to the monomial decomposition layers
        let k_g = self.compute_decomposition_length(instance.norm_bound)?;
        let mut helper_commitments = Vec::with_capacity(k_g);
        
        // For each decomposition level, compute commitment
        for i in 0..k_g {
            // Extract decomposition layer from witness
            let layer_witness = self.extract_decomposition_layer(f_matrix, i)?;
            
            // Commit to layer
            let layer_commitment = self.commit_decomposition_layer(&layer_witness)?;
            helper_commitments.push(layer_commitment);
        }
        
        Ok((helper_commitments, range_prover))
    }
    
    /// Run parallel sumchecks with shared randomness
    /// This is the key optimization in Symphony - running Hadamard and monomial checks in parallel
    fn run_parallel_sumchecks(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        witness: &GeneralizedR1CSWitness<F>,
        f_matrix: &[Vec<F>],
        s_prime: &[SymphonyExtensionField<F>],
        alpha: &SymphonyExtensionField<F>,
        mut range_prover: RangeCheckProver<F>,
        transcript: &mut Transcript,
    ) -> Result<(
        (LinearInstance<F>, LinearWitness<F>, HadamardProof<F>),
        (RangeCheckInstance<F>, LinearWitness<F>, RangeCheckProof<F>),
        SharedChallenges<F>,
    ), String> {
        // Step 1: Run Hadamard reduction
        let hadamard_instance = self.construct_hadamard_instance(instance)?;
        let hadamard_witness = HadamardWitness {
            witness_matrix: witness.witness_matrix.clone(),
            opening_scalar: witness.opening_scalar.clone(),
        };
        
        let hadamard_output = self.hadamard_protocol.prove(
            &hadamard_instance,
            &hadamard_witness,
            transcript,
        )?;
        
        // Step 2: Run range proof
        let range_output = range_prover.prove(&instance.commitment, transcript)?;
        
        // Step 3: Extract shared challenges
        // In the actual protocol, these would be shared during the sumcheck execution
        // For now, we extract them from the proofs
        let shared_challenges = SharedChallenges {
            r_bar: hadamard_output.2.sumcheck_proof.final_challenge.clone(),
            s_bar: vec![], // Would be extracted from parallel execution
            s: range_output.sumcheck_proof.final_challenge.clone(),
        };
        
        // Step 4: Convert range proof output to linear instance/witness
        let range_linear_instance = self.range_output_to_linear_instance(&range_output)?;
        let range_linear_witness = self.range_output_to_linear_witness(&range_output)?;
        
        Ok((
            hadamard_output,
            (range_linear_instance, range_linear_witness, range_output),
            shared_challenges,
        ))
    }
    
    /// Construct Hadamard instance from generalized R1CS instance
    fn construct_hadamard_instance(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
    ) -> Result<HadamardInstance<F>, String> {
        Ok(HadamardInstance {
            commitment: instance.commitment.clone(),
            public_input: instance.public_input.clone(),
            matrices: instance.r1cs_matrices.clone(),
            num_constraints: instance.num_constraints,
            num_variables: instance.num_input_vars + instance.num_witness_vars,
            num_columns: instance.num_columns,
            aux_data: instance.aux_data.clone(),
        })
    }
    
    /// Construct range verifier
    fn construct_range_verifier(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
    ) -> Result<RangeCheckVerifier<F>, String> {
        let n = instance.num_input_vars + instance.num_witness_vars;
        
        RangeCheckVerifier::new(
            instance.commitment.clone(),
            Commitment::default(), // double_commitment placeholder
            Commitment::default(), // helper_commitment placeholder
            instance.norm_bound as i64,
            self.ring.clone(),
            self.challenge_set_size,
            n,
        )
    }
    
    /// Construct batch linear instance from range check instance
    fn construct_batch_linear_instance(
        &self,
        range_instance: &RangeCheckInstance<F>,
    ) -> Result<BatchLinearInstance<F>, String> {
        // Extract evaluations from range instance
        let evaluations = vec![
            range_instance.evaluations.witness_eval.clone(),
        ];
        
        Ok(BatchLinearInstance {
            evaluation_point: range_instance.challenge.iter()
                .map(|r| SymphonyExtensionField::from_ring_element(r))
                .collect(),
            commitments: vec![range_instance.commitment.clone()],
            evaluations,
            aux_data: LinearAuxData {
                challenge_set_size: self.challenge_set_size,
                norm_bound: 0.0, // Will be filled from range instance
                block_size: 0,
                ring: self.ring.clone(),
            },
        })
    }
    
    /// Construct batch linear witness from range check witness
    fn construct_batch_linear_witness(
        &self,
        range_witness: &LinearWitness<F>,
    ) -> Result<BatchLinearWitness<F>, String> {
        Ok(BatchLinearWitness {
            witnesses: vec![range_witness.witness.clone()],
            opening_scalars: vec![range_witness.opening_scalar.clone()],
        })
    }
    
    /// Convert range proof output to linear instance
    fn range_output_to_linear_instance(
        &self,
        range_proof: &RangeCheckProof<F>,
    ) -> Result<RangeCheckInstance<F>, String> {
        // Extract linear instance from range proof
        // The range proof reduces R_rg to R_lin^auxJ × R_batchlin
        // We extract the R_lin^auxJ component
        
        Ok(RangeCheckInstance {
            commitment: range_proof.commitment.clone(),
            double_commitment: range_proof.double_commitment.clone(),
            helper_commitment: range_proof.helper_commitments.first()
                .ok_or("No helper commitment in range proof")?
                .clone(),
            challenge: range_proof.challenge.clone(),
            evaluations: range_proof.evaluations.clone(),
            norm_bound: range_proof.norm_bound,
        })
    }
    
    /// Convert range proof output to linear witness
    fn range_output_to_linear_witness(
        &self,
        range_proof: &RangeCheckProof<F>,
    ) -> Result<LinearWitness<F>, String> {
        // Extract linear witness from range proof
        // This is the witness for the linear relation after range check reduction
        
        Ok(LinearWitness {
            witness: range_proof.witness.clone(),
            opening_scalar: range_proof.opening_scalar.clone(),
        })
    }
    
    /// Helper: extract decomposition layer from witness
    fn extract_decomposition_layer(
        &self,
        f_matrix: &[Vec<F>],
        layer_index: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        use crate::ring::decomposition::{DecompositionParams, NormDecomposition};
        
        // Convert F matrix to i64 for decomposition
        let projected: Vec<Vec<i64>> = f_matrix
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&f| {
                        let val = f.to_canonical_u64();
                        let modulus = F::MODULUS;
                        // Convert to balanced representation
                        if val <= modulus / 2 {
                            val as i64
                        } else {
                            -((modulus - val) as i64)
                        }
                    })
                    .collect()
            })
            .collect();
        
        // Create decomposition parameters
        let degree = self.ring.degree();
        let bound_b = 100.0; // Default bound, should be passed from instance
        let params = DecompositionParams::new(degree, bound_b);
        
        // Perform decomposition
        let decomp = NormDecomposition::decompose(&projected, params)?;
        
        // Extract specified layer
        if layer_index >= decomp.k_g {
            return Err(format!("Layer index {} out of range", layer_index));
        }
        
        let layer = decomp.get_component(layer_index);
        
        // Convert back to ring elements
        let layer_ring_elems: Vec<RingElement<F>> = layer
            .iter()
            .map(|row| {
                let coeffs: Vec<F> = row
                    .iter()
                    .map(|&val| {
                        if val >= 0 {
                            F::from_u64(val as u64)
                        } else {
                            F::zero().sub(&F::from_u64((-val) as u64))
                        }
                    })
                    .collect();
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        Ok(layer_ring_elems)
    }
    
    /// Helper: commit to decomposition layer
    fn commit_decomposition_layer(
        &self,
        layer_witness: &[RingElement<F>],
    ) -> Result<Commitment<F>, String> {
        use crate::commitment::ajtai::{AjtaiCommitment, AjtaiParams};
        
        // Create commitment parameters
        let params = AjtaiParams::new_128bit_security(
            self.ring.degree(),
            F::MODULUS,
            4, // kappa
        );
        
        // Generate commitment key (in production, this would be from setup)
        let key = AjtaiCommitment::<F>::setup(params, layer_witness.len(), None);
        
        // Commit to layer
        let commitment = AjtaiCommitment::commit(&key, layer_witness);
        
        Ok(commitment)
    }
    
    /// Verify shared challenges consistency
    fn verify_shared_challenges_consistency(
        &self,
        shared_challenges: &SharedChallenges<F>,
        hadamard_proof: &HadamardProof<F>,
        range_proof: &RangeCheckProof<F>,
    ) -> Result<(), String> {
        // Verify that the shared challenges match between the two proofs
        // This ensures the protocols were executed with the same randomness
        
        // Check r̄ consistency
        if shared_challenges.r_bar != hadamard_proof.sumcheck_proof.final_challenge {
            return Err("Shared challenge r̄ mismatch".to_string());
        }
        
        // Additional consistency checks would go here
        
        Ok(())
    }
    
    /// Compute decomposition length k_g
    fn compute_decomposition_length(&self, norm_bound: f64) -> Result<usize, String> {
        let d_prime = (self.ring.degree / 2) as f64;
        let k_g = (norm_bound.log(d_prime)).ceil() as usize;
        Ok(k_g)
    }
    
    /// Helper: sample challenge vector
    fn sample_challenge_vector(
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
    
    /// Helper: sample challenge scalar
    fn sample_challenge_scalar(
        &self,
        transcript: &mut Transcript,
        label: &str,
    ) -> Result<SymphonyExtensionField<F>, String> {
        Ok(transcript.challenge_extension_field(label))
    }
}

impl<F: Field> ReductionOfKnowledge for SingleInstanceProtocol<F> {
    type InputInstance = GeneralizedR1CSInstance<F>;
    type InputWitness = GeneralizedR1CSWitness<F>;
    type OutputInstance = SingleInstanceOutput<F>;
    type OutputWitness = (Option<LinearWitness<F>>, Option<BatchLinearWitness<F>>);
    type Proof = SingleInstanceProof<F>;
    type Error = String;
    
    fn reduce(
        &self,
        instance: &Self::InputInstance,
        witness: &Self::InputWitness,
        transcript: &mut Transcript,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness, Self::Proof), Self::Error> {
        let (output, proof) = self.prove(instance, witness, transcript)?;
        let output_witness = (output.linear_witness.clone(), output.batch_linear_witness.clone());
        Ok((output, output_witness, proof))
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
        "Single_Instance_Reduction"
    }
}

/// Convert standard R1CS to generalized R1CS
/// Applies base-b decomposition to handle arbitrary witnesses
pub fn convert_r1cs_to_generalized<F: Field>(
    r1cs_instance: &crate::protocols::rok_traits::R1CSInstance<F>,
    r1cs_witness: &crate::protocols::rok_traits::R1CSWitness<F>,
    base: usize,
    num_columns: usize,
    ring: &CyclotomicRing<F>,
) -> Result<(GeneralizedR1CSInstance<F>, GeneralizedR1CSWitness<F>), String> {
    let q = F::MODULUS;
    let k_cs = 1 + ((q as f64).log(base as f64)).floor() as usize;
    
    // Decompose public input
    let mut public_input_decomposed = Vec::new();
    for &x in &r1cs_instance.public_input {
        let decomp = decompose_field_element(x, base, k_cs)?;
        public_input_decomposed.push(decomp);
    }
    
    // Decompose witness
    let mut witness_decomposed = Vec::new();
    for &w in &r1cs_witness.witness {
        let decomp = decompose_field_element(w, base, k_cs)?;
        witness_decomposed.push(decomp);
    }
    
    // Convert matrices: M_i := M̄_i ⊗ [1, b, ..., b^{k_cs-1}]
    let gadget_vector: Vec<F> = (0..k_cs)
        .map(|i| F::from_u64((base.pow(i as u32)) as u64))
        .collect();
    
    let m1_converted = tensor_product_matrix(&r1cs_instance.matrices.0, &gadget_vector)?;
    let m2_converted = tensor_product_matrix(&r1cs_instance.matrices.1, &gadget_vector)?;
    let m3_converted = tensor_product_matrix(&r1cs_instance.matrices.2, &gadget_vector)?;
    
    // Set norm bound B = 0.5b√ℓ_h
    let block_size = 16; // Typical value
    let norm_bound = 0.5 * (base as f64) * (block_size as f64).sqrt();
    
    let generalized_instance = GeneralizedR1CSInstance {
        commitment: Commitment::default(), // Would be computed from witness
        public_input: public_input_decomposed,
        r1cs_matrices: (m1_converted, m2_converted, m3_converted),
        num_constraints: r1cs_instance.num_constraints,
        num_input_vars: r1cs_instance.public_input.len() * k_cs,
        num_witness_vars: r1cs_witness.witness.len() * k_cs,
        num_columns,
        norm_bound,
        block_size,
        aux_data: LinearAuxData {
            challenge_set_size: 256,
            norm_bound,
            block_size,
            ring: ring.clone(),
        },
    };
    
    let generalized_witness = GeneralizedR1CSWitness {
        witness_matrix: witness_decomposed,
        opening_scalar: RingElement::zero(ring),
    };
    
    Ok((generalized_instance, generalized_witness))
}

/// Decompose field element to base b with k digits
fn decompose_field_element<F: Field>(x: F, base: usize, k: usize) -> Result<Vec<F>, String> {
    let mut result = Vec::with_capacity(k);
    let mut val = x.to_canonical_u64();
    
    for _ in 0..k {
        let digit = val % (base as u64);
        result.push(F::from_u64(digit));
        val /= base as u64;
    }
    
    Ok(result)
}

/// Tensor product of matrix with vector: M ⊗ v
fn tensor_product_matrix<F: Field>(
    matrix: &SparseMatrix<F>,
    vector: &[F],
) -> Result<SparseMatrix<F>, String> {
    let k = vector.len();
    let mut result = SparseMatrix::new(matrix.rows, matrix.cols * k);
    
    for &(row, col, ref value) in &matrix.entries {
        for (i, &v_i) in vector.iter().enumerate() {
            let new_col = col * k + i;
            let new_value = value.mul(&v_i);
            result.add_entry(row, new_col, new_value);
        }
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_single_instance_protocol_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let protocol = SingleInstanceProtocol::new(ring, 256);
        assert_eq!(protocol.protocol_name(), "Single_Instance_Reduction");
    }
    
    #[test]
    fn test_decompose_field_element() {
        let x = GoldilocksField::from_u64(123);
        let decomp = decompose_field_element(x, 10, 3).unwrap();
        
        // 123 = 3 + 2*10 + 1*100
        assert_eq!(decomp[0], GoldilocksField::from_u64(3));
        assert_eq!(decomp[1], GoldilocksField::from_u64(2));
        assert_eq!(decomp[2], GoldilocksField::from_u64(1));
    }
}
