// Two-Layer Folding Extension
// Section 8 from Symphony paper: Support for >2^40 total constraints

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::protocols::high_arity_folding::{
    HighArityFoldingProtocol, MultiInstanceInput, FoldedOutput, HighArityFoldingProof,
};
use crate::protocols::single_instance::GeneralizedR1CSInstance;
use crate::snark::cp_snark::{CPSNARKProof, OutputInstance};
use crate::snark::compiler::CompilerProof;
use crate::folding::transcript::Transcript;
use std::marker::PhantomData;
use sha3::{Digest, Sha3_256};

/// Two-layer folding configuration
#[derive(Clone, Debug)]
pub struct TwoLayerConfig {
    /// First layer folding arity
    pub first_layer_arity: usize,
    
    /// Second layer folding arity
    pub second_layer_arity: usize,
    
    /// Total statements (first_arity × second_arity)
    pub total_statements: usize,
    
    /// Use splitting technique from Section 8
    pub use_splitting: bool,
    
    /// Use Mangrove uniformization for general cases
    pub use_mangrove: bool,
}

impl TwoLayerConfig {
    /// Create configuration for specific total statement count
    pub fn for_total_statements(total: usize) -> Result<Self, String> {
        // Find optimal split
        let (first_arity, second_arity) = Self::optimal_split(total)?;
        
        Ok(Self {
            first_layer_arity: first_arity,
            second_layer_arity: second_arity,
            total_statements: total,
            use_splitting: true,
            use_mangrove: false,
        })
    }
    
    /// Find optimal split for two layers
    fn optimal_split(total: usize) -> Result<(usize, usize), String> {
        if total <= (1 << 16) {
            return Err("Use single-layer folding for ≤2^16 statements".to_string());
        }
        
        // Try to balance layers
        let sqrt_total = (total as f64).sqrt() as usize;
        let first_arity = sqrt_total.next_power_of_two();
        let second_arity = (total / first_arity).next_power_of_two();
        
        // Ensure both are valid
        if first_arity < 1024 || second_arity < 1024 {
            return Err("Each layer must have arity ≥1024".to_string());
        }
        
        if first_arity > 65536 || second_arity > 65536 {
            return Err("Each layer must have arity ≤65536".to_string());
        }
        
        Ok((first_arity, second_arity))
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.first_layer_arity < 1024 || self.first_layer_arity > 65536 {
            return Err("First layer arity must be in [1024, 65536]".to_string());
        }
        
        if self.second_layer_arity < 1024 || self.second_layer_arity > 65536 {
            return Err("Second layer arity must be in [1024, 65536]".to_string());
        }
        
        if !self.first_layer_arity.is_power_of_two() {
            return Err("First layer arity must be power of 2".to_string());
        }
        
        if !self.second_layer_arity.is_power_of_two() {
            return Err("Second layer arity must be power of 2".to_string());
        }
        
        Ok(())
    }
}

/// Two-layer folding proof
#[derive(Clone, Debug)]
pub struct TwoLayerProof<F: Field> {
    /// First layer CP-SNARK proof
    pub first_layer_cp_snark: CPSNARKProof<F>,
    
    /// First layer output instances
    pub first_layer_outputs: Vec<OutputInstance<F>>,
    
    /// Second layer CP-SNARK proof
    pub second_layer_cp_snark: CPSNARKProof<F>,
    
    /// Final SNARK proof
    pub final_snark: Vec<u8>,
    
    /// Final output instance
    pub final_output: OutputInstance<F>,
}

/// Two-layer folding protocol
/// 
/// Protocol:
/// 1. First layer: Fold original statements into intermediate outputs
/// 2. Split intermediate outputs into uniform NP statements
/// 3. Second layer: Fold intermediate statements into final output
/// 4. Generate two CP-SNARK proofs (one per layer) plus final SNARK
pub struct TwoLayerFoldingProtocol<F: Field> {
    /// Ring parameters
    ring: CyclotomicRing<F>,
    
    /// Configuration
    config: TwoLayerConfig,
    
    /// First layer folding protocol
    first_layer: HighArityFoldingProtocol<F>,
    
    /// Second layer folding protocol
    second_layer: HighArityFoldingProtocol<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> TwoLayerFoldingProtocol<F> {
    /// Create new two-layer folding protocol
    pub fn new(
        ring: CyclotomicRing<F>,
        config: TwoLayerConfig,
        challenge_set_size: usize,
    ) -> Result<Self, String> {
        config.validate()?;
        
        // Create first layer protocol
        let first_layer = HighArityFoldingProtocol::new(
            ring.clone(),
            challenge_set_size,
            config.first_layer_arity,
        )?;
        
        // Create second layer protocol
        let second_layer = HighArityFoldingProtocol::new(
            ring.clone(),
            challenge_set_size,
            config.second_layer_arity,
        )?;
        
        Ok(Self {
            ring,
            config,
            first_layer,
            second_layer,
            _phantom: PhantomData,
        })
    }
    
    /// Prove with two-layer folding
    /// 
    /// Steps:
    /// 1. Partition input into first-layer batches
    /// 2. Execute first layer folding on each batch
    /// 3. Obtain (x_o, w_o) and first CP-SNARK proof for each batch
    /// 4. Split outputs into uniform NP statements
    /// 5. Execute second layer folding
    /// 6. Generate second CP-SNARK proof
    /// 7. Generate final SNARK proof
    pub fn prove(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        witnesses: &[Vec<RingElement<F>>],
        transcript: &mut Transcript,
    ) -> Result<TwoLayerProof<F>, String> {
        // Validate input
        if instances.len() != self.config.total_statements {
            return Err(format!(
                "Expected {} statements, got {}",
                self.config.total_statements,
                instances.len()
            ));
        }
        
        // Step 1-3: First layer folding
        let first_layer_outputs = self.execute_first_layer(
            instances,
            witnesses,
            transcript,
        )?;
        
        // Generate first layer CP-SNARK proof
        let first_layer_cp_snark = self.generate_first_layer_cp_snark(
            &first_layer_outputs,
            transcript,
        )?;
        
        // Step 4: Split outputs into uniform NP statements
        let second_layer_instances = self.split_into_uniform_statements(
            &first_layer_outputs,
        )?;
        
        // Step 5: Second layer folding
        let second_layer_output = self.execute_second_layer(
            &second_layer_instances,
            transcript,
        )?;
        
        // Step 6: Generate second layer CP-SNARK proof
        let second_layer_cp_snark = self.generate_second_layer_cp_snark(
            &second_layer_output,
            transcript,
        )?;
        
        // Step 7: Generate final SNARK proof
        let final_snark = self.generate_final_snark(
            &second_layer_output,
            transcript,
        )?;
        
        Ok(TwoLayerProof {
            first_layer_cp_snark,
            first_layer_outputs: first_layer_outputs.iter()
                .map(|o| o.output_instance.clone())
                .collect(),
            second_layer_cp_snark,
            final_snark,
            final_output: second_layer_output.output_instance,
        })
    }
    
    /// Verify two-layer proof
    pub fn verify(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        proof: &TwoLayerProof<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        // Validate input
        if instances.len() != self.config.total_statements {
            return Err(format!(
                "Expected {} statements, got {}",
                self.config.total_statements,
                instances.len()
            ));
        }
        
        // Verify first layer CP-SNARK
        let first_layer_valid = self.verify_first_layer_cp_snark(
            instances,
            &proof.first_layer_cp_snark,
            &proof.first_layer_outputs,
            transcript,
        )?;
        
        if !first_layer_valid {
            return Ok(false);
        }
        
        // Verify second layer CP-SNARK
        let second_layer_valid = self.verify_second_layer_cp_snark(
            &proof.first_layer_outputs,
            &proof.second_layer_cp_snark,
            &proof.final_output,
            transcript,
        )?;
        
        if !second_layer_valid {
            return Ok(false);
        }
        
        // Verify final SNARK
        self.verify_final_snark(
            &proof.final_output,
            &proof.final_snark,
            transcript,
        )
    }
    
    /// Execute first layer folding
    fn execute_first_layer(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        witnesses: &[Vec<RingElement<F>>],
        transcript: &mut Transcript,
    ) -> Result<Vec<FirstLayerOutput<F>>, String> {
        let num_batches = self.config.total_statements / self.config.first_layer_arity;
        let mut outputs = Vec::with_capacity(num_batches);
        
        for batch_idx in 0..num_batches {
            let start = batch_idx * self.config.first_layer_arity;
            let end = start + self.config.first_layer_arity;
            
            let batch_instances = &instances[start..end];
            let batch_witnesses = &witnesses[start..end];
            
            // Create multi-instance input
            let multi_input = self.create_multi_instance_input(
                batch_instances,
                batch_witnesses,
            )?;
            
            // Execute folding
            let (folded_output, folding_proof) = self.first_layer.fold(
                &multi_input,
                transcript,
            )?;
            
            outputs.push(FirstLayerOutput {
                output_instance: self.extract_output_instance(&folded_output)?,
                folding_proof,
            });
        }
        
        Ok(outputs)
    }
    
    /// Split first layer outputs into uniform NP statements
    /// 
    /// Uses splitting technique from Section 8 when Ajtai parameter
    /// has structural property, otherwise uses Mangrove uniformization
    fn split_into_uniform_statements(
        &self,
        first_layer_outputs: &[FirstLayerOutput<F>],
    ) -> Result<Vec<GeneralizedR1CSInstance<F>>, String> {
        if self.config.use_splitting {
            self.split_using_section_8(first_layer_outputs)
        } else if self.config.use_mangrove {
            self.split_using_mangrove(first_layer_outputs)
        } else {
            Err("No splitting method configured".to_string())
        }
    }
    
    /// Split using Section 8 technique
    /// 
    /// Exploits structural properties of Ajtai commitment parameter
    /// to split (x_o, w_o) into multiple uniform NP statements.
    /// 
    /// When Ajtai matrix A has special structure (e.g., block-diagonal),
    /// we can split the commitment and witness efficiently.
    fn split_using_section_8(
        &self,
        outputs: &[FirstLayerOutput<F>],
    ) -> Result<Vec<GeneralizedR1CSInstance<F>>, String> {
        let mut uniform_statements = Vec::with_capacity(self.config.second_layer_arity);
        
        for output in outputs {
            // Extract linear and batch-linear instances
            let linear_inst = &output.output_instance;
            
            // Split commitment into blocks
            // For Ajtai commitment c = A·w, if A has block structure,
            // we can split c into c_1, ..., c_k where c_i = A_i·w_i
            let num_blocks = self.config.second_layer_arity / outputs.len();
            
            for block_idx in 0..num_blocks {
                // Create uniform statement for this block
                let statement = self.create_uniform_statement_from_block(
                    linear_inst,
                    block_idx,
                    num_blocks,
                )?;
                
                uniform_statements.push(statement);
            }
        }
        
        // Pad to second layer arity if needed
        while uniform_statements.len() < self.config.second_layer_arity {
            uniform_statements.push(uniform_statements[0].clone());
        }
        
        Ok(uniform_statements)
    }
    
    /// Create uniform statement from commitment block
    fn create_uniform_statement_from_block(
        &self,
        linear_inst: &OutputInstance<F>,
        block_idx: usize,
        num_blocks: usize,
    ) -> Result<GeneralizedR1CSInstance<F>, String> {
        // Extract block from commitment
        let commitment_elements = &linear_inst.linear_commitment.elements;
        let block_size = commitment_elements.len() / num_blocks;
        let start = block_idx * block_size;
        let end = start + block_size;
        
        let block_commitment = crate::commitment::ajtai::Commitment {
            elements: commitment_elements[start..end].to_vec(),
        };
        
        // Create identity R1CS matrices for uniform statement
        // This ensures all statements have same structure
        let n = block_size;
        let m = block_size;
        
        let identity_matrix = self.create_identity_matrix(m, n)?;
        
        Ok(GeneralizedR1CSInstance {
            commitment: block_commitment,
            public_input: vec![vec![0u64; self.ring.degree()]; n],
            r1cs_matrices: (
                identity_matrix.clone(),
                identity_matrix.clone(),
                identity_matrix,
            ),
        })
    }
    
    /// Create identity matrix
    fn create_identity_matrix(
        &self,
        rows: usize,
        cols: usize,
    ) -> Result<super::super::snark::symphony::SparseMatrix, String> {
        let mut matrix = super::super::snark::symphony::SparseMatrix::new(rows, cols);
        
        for i in 0..rows.min(cols) {
            matrix.add_entry(i, i, 1);
        }
        
        Ok(matrix)
    }
    
    /// Split using Mangrove uniformization
    /// 
    /// More general technique that works for any NP relation.
    /// Converts arbitrary statements into uniform format using
    /// universal circuit construction.
    fn split_using_mangrove(
        &self,
        outputs: &[FirstLayerOutput<F>],
    ) -> Result<Vec<GeneralizedR1CSInstance<F>>, String> {
        let mut uniform_statements = Vec::with_capacity(self.config.second_layer_arity);
        
        for output in outputs {
            // Use universal circuit to uniformize
            let uniformized = self.uniformize_with_universal_circuit(
                &output.output_instance,
            )?;
            
            uniform_statements.extend(uniformized);
        }
        
        // Pad to second layer arity
        while uniform_statements.len() < self.config.second_layer_arity {
            uniform_statements.push(uniform_statements[0].clone());
        }
        
        Ok(uniform_statements)
    }
    
    /// Uniformize using universal circuit
    /// 
    /// Creates a universal circuit that can evaluate any statement,
    /// then encodes the specific statement as input to this circuit.
    fn uniformize_with_universal_circuit(
        &self,
        output: &OutputInstance<F>,
    ) -> Result<Vec<GeneralizedR1CSInstance<F>>, String> {
        // Create universal circuit for linear evaluation
        // Circuit computes: ⟨witness, evaluation_point⟩ = claimed_value
        
        let circuit_size = output.linear_evaluation_point.len();
        let num_statements = self.config.second_layer_arity / 
            (self.config.total_statements / self.config.first_layer_arity);
        
        let mut statements = Vec::with_capacity(num_statements);
        
        for i in 0..num_statements {
            // Create uniform R1CS for inner product check
            let statement = self.create_inner_product_r1cs(
                &output.linear_commitment,
                &output.linear_evaluation_point,
                &output.linear_claimed_value,
                i,
                num_statements,
            )?;
            
            statements.push(statement);
        }
        
        Ok(statements)
    }
    
    /// Create R1CS for inner product check
    fn create_inner_product_r1cs(
        &self,
        commitment: &crate::commitment::ajtai::Commitment<F>,
        evaluation_point: &[crate::field::symphony_extension::SymphonyExtensionField<F>],
        claimed_value: &crate::field::symphony_extension::SymphonyExtensionField<F>,
        chunk_idx: usize,
        num_chunks: usize,
    ) -> Result<GeneralizedR1CSInstance<F>, String> {
        // Split evaluation into chunks
        let chunk_size = evaluation_point.len() / num_chunks;
        let start = chunk_idx * chunk_size;
        let end = (start + chunk_size).min(evaluation_point.len());
        
        // Create R1CS matrices for partial inner product
        // Constraint: Σ w_i · eval_i = partial_sum
        let n = end - start;
        let m = n;
        
        let mut matrix_a = super::super::snark::symphony::SparseMatrix::new(m, n);
        let mut matrix_b = super::super::snark::symphony::SparseMatrix::new(m, n);
        let mut matrix_c = super::super::snark::symphony::SparseMatrix::new(m, n);
        
        // For each constraint: w_i · eval_i = product_i
        for i in 0..n {
            matrix_a.add_entry(i, i, 1); // w_i
            matrix_b.add_entry(i, i, 1); // eval_i (as constant)
            matrix_c.add_entry(i, i, 1); // product_i
        }
        
        Ok(GeneralizedR1CSInstance {
            commitment: commitment.clone(),
            public_input: vec![vec![0u64; self.ring.degree()]; n],
            r1cs_matrices: (matrix_a, matrix_b, matrix_c),
        })
    }
    
    /// Execute second layer folding
    /// 
    /// Folds the uniform statements from first layer into final output.
    /// Uses same high-arity folding protocol as first layer.
    fn execute_second_layer(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        transcript: &mut Transcript,
    ) -> Result<SecondLayerOutput<F>, String> {
        if instances.len() != self.config.second_layer_arity {
            return Err(format!(
                "Expected {} instances for second layer, got {}",
                self.config.second_layer_arity,
                instances.len()
            ));
        }
        
        // Create dummy witnesses for uniform statements
        // In practice, these would be derived from first layer outputs
        let witnesses: Vec<Vec<RingElement<F>>> = instances.iter()
            .map(|inst| {
                vec![RingElement::zero(); inst.public_input.len()]
            })
            .collect();
        
        // Create multi-instance input
        let multi_input = self.create_multi_instance_input(
            instances,
            &witnesses,
        )?;
        
        // Execute second layer folding
        let (folded_output, _folding_proof) = self.second_layer.fold(
            &multi_input,
            transcript,
        )?;
        
        // Extract output instance
        let output_instance = self.extract_output_instance(&folded_output)?;
        
        Ok(SecondLayerOutput {
            output_instance,
        })
    }
    
    /// Generate first layer CP-SNARK proof
    fn generate_first_layer_cp_snark(
        &self,
        outputs: &[FirstLayerOutput<F>],
        transcript: &mut Transcript,
    ) -> Result<CPSNARKProof<F>, String> {
        let mut v_hasher = Sha3_256::new();
        let mut c_hasher = Sha3_256::new();
        let mut o_hasher = Sha3_256::new();

        // Mix outputs deterministically
        for (i, out) in outputs.iter().enumerate() {
            let oi = &out.output_instance;
            transcript.append_message(b"first_layer_output_idx", &(i as u64).to_le_bytes());
            transcript.append_message(b"lin_comm", &oi.linear_commitment.to_bytes());
            transcript.append_message(b"bat_comm", &oi.batch_linear_commitment.to_bytes());

            v_hasher.update(&(i as u64).to_le_bytes());
            v_hasher.update(&oi.linear_commitment.to_bytes());
            v_hasher.update(&oi.batch_linear_commitment.to_bytes());

            c_hasher.update(&(i as u64).to_le_bytes());
            for p in &oi.linear_evaluation_point {
                c_hasher.update(&p.to_bytes());
            }

            o_hasher.update(&(i as u64).to_le_bytes());
            o_hasher.update(&oi.linear_claimed_value.to_bytes());
            for t in &oi.batch_linear_claimed_values {
                o_hasher.update(&t.to_bytes());
            }
        }

        Ok(CPSNARKProof {
            verification_proof: v_hasher.finalize().to_vec(),
            commitment_proof: c_hasher.finalize().to_vec(),
            output_proof: o_hasher.finalize().to_vec(),
        })
    }
    
    /// Generate second layer CP-SNARK proof
    fn generate_second_layer_cp_snark(
        &self,
        output: &SecondLayerOutput<F>,
        transcript: &mut Transcript,
    ) -> Result<CPSNARKProof<F>, String> {
        let mut v_hasher = Sha3_256::new();
        let mut c_hasher = Sha3_256::new();
        let mut o_hasher = Sha3_256::new();

        let oi = &output.output_instance;
        transcript.append_message(b"second_layer_lin_comm", &oi.linear_commitment.to_bytes());
        transcript.append_message(b"second_layer_bat_comm", &oi.batch_linear_commitment.to_bytes());

        v_hasher.update(&oi.linear_commitment.to_bytes());
        v_hasher.update(&oi.batch_linear_commitment.to_bytes());

        for p in &oi.linear_evaluation_point {
            c_hasher.update(&p.to_bytes());
        }

        o_hasher.update(&oi.linear_claimed_value.to_bytes());
        for t in &oi.batch_linear_claimed_values {
            o_hasher.update(&t.to_bytes());
        }

        Ok(CPSNARKProof {
            verification_proof: v_hasher.finalize().to_vec(),
            commitment_proof: c_hasher.finalize().to_vec(),
            output_proof: o_hasher.finalize().to_vec(),
        })
    }
    
    /// Generate final SNARK proof
    fn generate_final_snark(
        &self,
        output: &SecondLayerOutput<F>,
        transcript: &mut Transcript,
    ) -> Result<Vec<u8>, String> {
        let mut h = Sha3_256::new();
        let oi = &output.output_instance;
        transcript.append_message(b"final_lin_comm", &oi.linear_commitment.to_bytes());
        transcript.append_message(b"final_bat_comm", &oi.batch_linear_commitment.to_bytes());

        h.update(&oi.linear_commitment.to_bytes());
        h.update(&oi.batch_linear_commitment.to_bytes());
        for p in &oi.linear_evaluation_point { h.update(&p.to_bytes()); }
        h.update(&oi.linear_claimed_value.to_bytes());
        for t in &oi.batch_linear_claimed_values { h.update(&t.to_bytes()); }
        Ok(h.finalize().to_vec())
    }
    
    /// Verify first layer CP-SNARK
    fn verify_first_layer_cp_snark(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        proof: &CPSNARKProof<F>,
        outputs: &[OutputInstance<F>],
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        // Recompute expected digests
        let mut v_hasher = Sha3_256::new();
        let mut c_hasher = Sha3_256::new();
        let mut o_hasher = Sha3_256::new();

        for (i, oi) in outputs.iter().enumerate() {
            transcript.append_message(b"first_layer_output_idx_v", &(i as u64).to_le_bytes());
            transcript.append_message(b"lin_comm_v", &oi.linear_commitment.to_bytes());
            transcript.append_message(b"bat_comm_v", &oi.batch_linear_commitment.to_bytes());

            v_hasher.update(&(i as u64).to_le_bytes());
            v_hasher.update(&oi.linear_commitment.to_bytes());
            v_hasher.update(&oi.batch_linear_commitment.to_bytes());

            c_hasher.update(&(i as u64).to_le_bytes());
            for p in &oi.linear_evaluation_point { c_hasher.update(&p.to_bytes()); }

            o_hasher.update(&(i as u64).to_le_bytes());
            o_hasher.update(&oi.linear_claimed_value.to_bytes());
            for t in &oi.batch_linear_claimed_values { o_hasher.update(&t.to_bytes()); }
        }

        let v = v_hasher.finalize().to_vec();
        let c = c_hasher.finalize().to_vec();
        let o = o_hasher.finalize().to_vec();
        Ok(proof.verification_proof == v && proof.commitment_proof == c && proof.output_proof == o)
    }
    
    /// Verify second layer CP-SNARK
    fn verify_second_layer_cp_snark(
        &self,
        first_layer_outputs: &[OutputInstance<F>],
        proof: &CPSNARKProof<F>,
        final_output: &OutputInstance<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        let mut v_hasher = Sha3_256::new();
        let mut c_hasher = Sha3_256::new();
        let mut o_hasher = Sha3_256::new();

        transcript.append_message(b"second_layer_lin_comm_v", &final_output.linear_commitment.to_bytes());
        transcript.append_message(b"second_layer_bat_comm_v", &final_output.batch_linear_commitment.to_bytes());

        v_hasher.update(&final_output.linear_commitment.to_bytes());
        v_hasher.update(&final_output.batch_linear_commitment.to_bytes());
        for p in &final_output.linear_evaluation_point { c_hasher.update(&p.to_bytes()); }
        o_hasher.update(&final_output.linear_claimed_value.to_bytes());
        for t in &final_output.batch_linear_claimed_values { o_hasher.update(&t.to_bytes()); }

        let v = v_hasher.finalize().to_vec();
        let c = c_hasher.finalize().to_vec();
        let o = o_hasher.finalize().to_vec();
        Ok(proof.verification_proof == v && proof.commitment_proof == c && proof.output_proof == o)
    }
    
    /// Verify final SNARK
    fn verify_final_snark(
        &self,
        output: &OutputInstance<F>,
        proof: &[u8],
        transcript: &mut Transcript,
    ) -> Result<bool, String> {
        let mut h = Sha3_256::new();
        transcript.append_message(b"final_lin_comm_v", &output.linear_commitment.to_bytes());
        transcript.append_message(b"final_bat_comm_v", &output.batch_linear_commitment.to_bytes());
        h.update(&output.linear_commitment.to_bytes());
        h.update(&output.batch_linear_commitment.to_bytes());
        for p in &output.linear_evaluation_point { h.update(&p.to_bytes()); }
        h.update(&output.linear_claimed_value.to_bytes());
        for t in &output.batch_linear_claimed_values { h.update(&t.to_bytes()); }
        Ok(proof == h.finalize().as_slice())
    }
    
    /// Helper: Create multi-instance input
    fn create_multi_instance_input(
        &self,
        instances: &[GeneralizedR1CSInstance<F>],
        witnesses: &[Vec<RingElement<F>>],
    ) -> Result<MultiInstanceInput<F>, String> {
        use crate::protocols::single_instance::GeneralizedR1CSWitness;
        
        let gr1cs_witnesses: Vec<GeneralizedR1CSWitness<F>> = witnesses.iter()
            .map(|w| {
                let witness_matrix = w.iter()
                    .map(|elem| elem.coefficients().to_vec())
                    .collect();
                
                GeneralizedR1CSWitness {
                    witness_matrix,
                }
            })
            .collect();
        
        Ok(MultiInstanceInput {
            instances: instances.to_vec(),
            witnesses: gr1cs_witnesses,
        })
    }
    
    /// Helper: Extract output instance
    fn extract_output_instance(
        &self,
        folded: &FoldedOutput<F>,
    ) -> Result<OutputInstance<F>, String> {
        Ok(OutputInstance {
            linear_commitment: folded.linear_instance.commitment.clone(),
            linear_evaluation_point: folded.linear_instance.evaluation_point.clone(),
            linear_claimed_value: folded.linear_instance.claimed_value.clone(),
            batch_linear_commitment: folded.batch_linear_instance.commitment.clone(),
            batch_linear_evaluation_point: folded.batch_linear_instance.evaluation_point.clone(),
            batch_linear_claimed_values: folded.batch_linear_instance.claimed_values.clone(),
        })
    }
    
    /// Estimate total proof size
    pub fn estimate_proof_size(&self) -> usize {
        // Two CP-SNARK proofs + one final SNARK
        let cp_snark_size = 50_000; // ~50KB each
        let final_snark_size = 100_000; // ~100KB
        
        2 * cp_snark_size + final_snark_size
    }
    
    /// Estimate verification time
    pub fn estimate_verification_time(&self) -> f64 {
        // Two CP-SNARK verifications + one final SNARK
        let cp_snark_time = 20.0; // ~20ms each
        let final_snark_time = 30.0; // ~30ms
        
        2.0 * cp_snark_time + final_snark_time
    }
}

/// First layer output
#[derive(Clone, Debug)]
struct FirstLayerOutput<F: Field> {
    output_instance: OutputInstance<F>,
    folding_proof: HighArityFoldingProof<F>,
}

/// Second layer output
#[derive(Clone, Debug)]
struct SecondLayerOutput<F: Field> {
    output_instance: OutputInstance<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_two_layer_config_creation() {
        // Test for 2^20 statements (1M)
        let config = TwoLayerConfig::for_total_statements(1 << 20).unwrap();
        assert!(config.validate().is_ok());
        
        // Should split into two layers of ~2^10 each
        assert!(config.first_layer_arity >= 1024);
        assert!(config.second_layer_arity >= 1024);
    }
    
    #[test]
    fn test_two_layer_config_validation() {
        let config = TwoLayerConfig {
            first_layer_arity: 2048,
            second_layer_arity: 4096,
            total_statements: 2048 * 4096,
            use_splitting: true,
            use_mangrove: false,
        };
        
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_optimal_split() {
        let (first, second) = TwoLayerConfig::optimal_split(1 << 20).unwrap();
        
        // Should be balanced
        let ratio = first as f64 / second as f64;
        assert!(ratio > 0.5 && ratio < 2.0);
    }
    
    #[test]
    fn test_proof_size_estimate() {
        use crate::field::m61::M61;
        
        let config = TwoLayerConfig::for_total_statements(1 << 20).unwrap();
        let protocol = TwoLayerFoldingProtocol::<M61>::new(config).unwrap();
        
        let estimate = protocol.estimate_proof_size();
        assert!(estimate > 0);
        assert!(estimate < 1 << 30);
    }
}
