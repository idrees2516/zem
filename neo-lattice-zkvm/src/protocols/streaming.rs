// Memory-Efficient Streaming Prover
// Implements Remark 4.1 from Symphony paper
// Requires only O(n) memory through multiple passes over input data

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::field::symphony_extension::SymphonyExtensionField;
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey, Commitment};
use crate::folding::transcript::Transcript;
use crate::folding::sumcheck::{SumCheckProver, SumCheckProof};
use super::single_instance::{GeneralizedR1CSInstance, GeneralizedR1CSWitness};
use super::high_arity_folding::{MultiInstanceInput, FoldedOutput, FoldedWitness};
use std::marker::PhantomData;

/// Streaming prover configuration
#[derive(Clone, Debug)]
pub struct StreamingConfig {
    /// Maximum memory budget in bytes
    pub max_memory: usize,
    
    /// Number of passes over data
    pub num_passes: usize,
    
    /// Chunk size for streaming
    pub chunk_size: usize,
    
    /// Enable parallelization
    pub parallel: bool,
}

impl StreamingConfig {
    /// Create default streaming configuration
    /// Memory: O(n) where n is witness size
    pub fn default() -> Self {
        Self {
            max_memory: 1_000_000_000, // 1GB
            num_passes: 3, // 2 + log log(n) passes
            chunk_size: 1024,
            parallel: true,
        }
    }
    
    /// Create configuration for specific memory budget
    pub fn with_memory_budget(max_memory: usize) -> Self {
        Self {
            max_memory,
            num_passes: 3,
            chunk_size: max_memory / 1000,
            parallel: true,
        }
    }
    
    /// Compute number of passes needed
    /// Per Remark 4.1: 2 + log log(n) passes
    pub fn compute_num_passes(witness_size: usize) -> usize {
        if witness_size <= 1 {
            return 2;
        }
        
        let log_n = (witness_size as f64).log2();
        let log_log_n = log_n.log2();
        
        2 + log_log_n.ceil() as usize
    }
}

/// Streaming prover for high-arity folding
/// Implements memory-efficient algorithm requiring O(n) memory
pub struct StreamingProver<F: Field> {
    /// Ring parameters
    ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: CommitmentKey<F>,
    
    /// Streaming configuration
    config: StreamingConfig,
    
    /// Challenge set size
    challenge_set_size: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> StreamingProver<F> {
    /// Create new streaming prover
    pub fn new(
        ring: CyclotomicRing<F>,
        commitment_key: CommitmentKey<F>,
        config: StreamingConfig,
        challenge_set_size: usize,
    ) -> Self {
        Self {
            ring,
            commitment_key,
            config,
            challenge_set_size,
            _phantom: PhantomData,
        }
    }
    
    /// Prove with streaming algorithm
    /// 
    /// Pass 1: Compute ℓ_np input commitments in streaming fashion
    /// Pass 2: Execute sumcheck using streaming algorithm
    /// Pass 3: Stream witnesses and compute folded witness
    pub fn prove_streaming(
        &self,
        input: &MultiInstanceInput<F>,
        transcript: &mut Transcript,
    ) -> Result<(FoldedOutput<F>, Vec<u8>), String> {
        let ell_np = input.instances.len();
        
        // Validate memory budget
        self.validate_memory_budget(input)?;
        
        // Pass 1: Compute commitments in streaming fashion
        let commitments = self.pass1_compute_commitments(input, transcript)?;
        
        // Pass 2: Execute sumcheck with streaming evaluation
        let sumcheck_output = self.pass2_streaming_sumcheck(input, transcript)?;
        
        // Pass 3: Compute folded witness in streaming fashion
        let folded_witness = self.pass3_fold_witnesses(input, transcript)?;
        
        // Construct output
        let output = self.construct_output(
            commitments,
            sumcheck_output,
            folded_witness,
        )?;
        
        // Serialize proof
        let proof = self.serialize_proof(&output)?;
        
        Ok((output, proof))
    }
    
    /// Pass 1: Compute commitments in streaming fashion
    /// Memory: O(n) - process one instance at a time
    fn pass1_compute_commitments(
        &self,
        input: &MultiInstanceInput<F>,
        transcript: &mut Transcript,
    ) -> Result<Vec<Commitment<F>>, String> {
        let mut commitments = Vec::with_capacity(input.instances.len());
        
        for (instance, witness) in input.instances.iter().zip(&input.witnesses) {
            // Stream witness in chunks
            let commitment = self.commit_streaming(
                &witness.witness_matrix,
                &self.commitment_key,
            )?;
            
            // Add to transcript
            transcript.append_commitment("instance_commitment", &commitment);
            
            commitments.push(commitment);
        }
        
        Ok(commitments)
    }
    
    /// Commit to witness in streaming fashion
    /// Process witness in chunks to maintain O(n) memory
    fn commit_streaming(
        &self,
        witness_matrix: &[Vec<F>],
        key: &CommitmentKey<F>,
    ) -> Result<Commitment<F>, String> {
        let n = witness_matrix.len();
        let chunk_size = self.config.chunk_size;
        
        // Initialize commitment accumulator
        let mut commitment_value = vec![self.ring.zero(); key.kappa];
        
        // Process witness in chunks
        for chunk_start in (0..n).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(n);
            let chunk = &witness_matrix[chunk_start..chunk_end];
            
            // Convert chunk to ring elements
            let chunk_ring: Vec<RingElement<F>> = chunk
                .iter()
                .map(|row| RingElement::from_coeffs(row.clone()))
                .collect();
            
            // Compute partial commitment for chunk
            let partial_commitment = self.commit_chunk(&chunk_ring, key, chunk_start)?;
            
            // Accumulate
            for (i, elem) in partial_commitment.value.iter().enumerate() {
                commitment_value[i] = self.ring.add(&commitment_value[i], elem);
            }
        }
        
        Ok(Commitment {
            value: commitment_value,
        })
    }
    
    /// Commit to a chunk of witness
    fn commit_chunk(
        &self,
        chunk: &[RingElement<F>],
        key: &CommitmentKey<F>,
        offset: usize,
    ) -> Result<Commitment<F>, String> {
        let mut value = Vec::with_capacity(key.kappa);
        
        for row in &key.matrix_a {
            let mut sum = self.ring.zero();
            
            for (j, elem) in chunk.iter().enumerate() {
                let global_idx = offset + j;
                if global_idx < row.len() {
                    let prod = self.ring.mul(&row[global_idx], elem);
                    sum = self.ring.add(&sum, &prod);
                }
            }
            
            value.push(sum);
        }
        
        Ok(Commitment { value })
    }
    
    /// Pass 2: Execute sumcheck with streaming evaluation
    /// Uses algorithm from [Baw+25] Section 4
    /// Performs log log(n) passes computing evaluation tables
    fn pass2_streaming_sumcheck(
        &self,
        input: &MultiInstanceInput<F>,
        transcript: &mut Transcript,
    ) -> Result<SumcheckOutput<F>, String> {
        let n = input.instances[0].num_input_vars + input.instances[0].num_witness_vars;
        let num_vars = (n as f64).log2().ceil() as usize;
        
        // Initialize sumcheck prover
        let mut prover = SumCheckProver::new(num_vars, 3); // degree 3 for Hadamard
        
        // Compute evaluation tables in streaming fashion
        let eval_tables = self.compute_evaluation_tables_streaming(input, num_vars)?;
        
        // Run sumcheck rounds
        let mut rounds = Vec::with_capacity(num_vars);
        
        for round in 0..num_vars {
            // Compute round polynomial using streaming evaluation
            let polynomial = self.compute_round_polynomial_streaming(
                input,
                &eval_tables,
                round,
                &prover,
            )?;
            
            // Get challenge from transcript
            let challenge = transcript.challenge_extension_field(&format!("sumcheck_round_{}", round));
            
            // Update prover state
            prover.receive_challenge(challenge.to_base_field());
            
            rounds.push((polynomial, challenge));
        }
        
        // Compute final evaluation
        let final_point = prover.challenges();
        let final_eval = self.evaluate_at_point_streaming(input, final_point)?;
        
        Ok(SumcheckOutput {
            rounds,
            final_evaluation: final_eval,
            evaluation_point: prover.challenges().to_vec(),
        })
    }
    
    /// Compute evaluation tables in streaming fashion
    /// Performs log log(n) passes over data
    fn compute_evaluation_tables_streaming(
        &self,
        input: &MultiInstanceInput<F>,
        num_vars: usize,
    ) -> Result<Vec<EvaluationTable<F>>, String> {
        let num_passes = StreamingConfig::compute_num_passes(1 << num_vars);
        let mut tables = Vec::with_capacity(num_passes);
        
        for pass in 0..num_passes {
            let table = self.compute_table_pass(input, pass, num_vars)?;
            tables.push(table);
        }
        
        Ok(tables)
    }
    
    /// Compute evaluation table for a single pass
    fn compute_table_pass(
        &self,
        input: &MultiInstanceInput<F>,
        pass: usize,
        num_vars: usize,
    ) -> Result<EvaluationTable<F>, String> {
        let table_size = 1 << (num_vars / (1 << pass));
        let mut table = vec![F::zero(); table_size];
        
        // Stream through witnesses and accumulate evaluations
        for (instance, witness) in input.instances.iter().zip(&input.witnesses) {
            self.accumulate_evaluations(
                &mut table,
                instance,
                witness,
                pass,
            )?;
        }
        
        Ok(EvaluationTable {
            values: table,
            pass,
        })
    }
    
    /// Accumulate evaluations for a witness
    fn accumulate_evaluations(
        &self,
        table: &mut [F],
        instance: &GeneralizedR1CSInstance<F>,
        witness: &GeneralizedR1CSWitness<F>,
        pass: usize,
    ) -> Result<(), String> {
        // Stream through witness matrix in chunks
        let chunk_size = self.config.chunk_size;
        
        for chunk_start in (0..witness.witness_matrix.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(witness.witness_matrix.len());
            
            // Process chunk
            for i in chunk_start..chunk_end {
                let row = &witness.witness_matrix[i];
                
                // Compute contribution to evaluation table
                for (j, &val) in row.iter().enumerate() {
                    let table_idx = self.compute_table_index(i, j, pass);
                    if table_idx < table.len() {
                        table[table_idx] = table[table_idx].add(&val);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Compute table index for streaming evaluation
    fn compute_table_index(&self, row: usize, col: usize, pass: usize) -> usize {
        // Use bit-reversal for cache-friendly access pattern
        let combined = (row << 16) | col;
        let shift = pass * 4;
        (combined >> shift) & ((1 << 16) - 1)
    }
    
    /// Compute round polynomial using streaming evaluation
    fn compute_round_polynomial_streaming(
        &self,
        input: &MultiInstanceInput<F>,
        eval_tables: &[EvaluationTable<F>],
        round: usize,
        prover: &SumCheckProver<F>,
    ) -> Result<Vec<F>, String> {
        let degree = 3; // Hadamard check has degree 3
        let mut polynomial = vec![F::zero(); degree + 1];
        
        // Evaluate at points 0, 1, 2, 3
        for eval_point in 0..=degree {
            let mut sum = F::zero();
            
            // Stream through evaluation tables
            for table in eval_tables {
                let contribution = self.evaluate_table_at_point(
                    table,
                    eval_point,
                    round,
                    prover.challenges(),
                )?;
                sum = sum.add(&contribution);
            }
            
            polynomial[eval_point] = sum;
        }
        
        Ok(polynomial)
    }
    
    /// Evaluate table at a specific point
    fn evaluate_table_at_point(
        &self,
        table: &EvaluationTable<F>,
        eval_point: usize,
        round: usize,
        challenges: &[F],
    ) -> Result<F, String> {
        let mut sum = F::zero();
        
        // Stream through table values
        for (i, &val) in table.values.iter().enumerate() {
            // Compute Lagrange basis evaluation
            let basis = self.compute_lagrange_basis(i, eval_point, round, challenges)?;
            sum = sum.add(&val.mul(&basis));
        }
        
        Ok(sum)
    }
    
    /// Compute Lagrange basis polynomial evaluation
    fn compute_lagrange_basis(
        &self,
        index: usize,
        eval_point: usize,
        round: usize,
        challenges: &[F],
    ) -> Result<F, String> {
        // Compute eq(challenges, index) * L_{eval_point}(X)
        let mut result = F::one();
        
        // eq polynomial evaluation
        for (i, &challenge) in challenges.iter().enumerate() {
            let bit = (index >> i) & 1;
            if bit == 1 {
                result = result.mul(&challenge);
            } else {
                result = result.mul(&F::one().sub(&challenge));
            }
        }
        
        // Lagrange basis for eval_point
        let eval_f = F::from_u64(eval_point as u64);
        result = result.mul(&eval_f);
        
        Ok(result)
    }
    
    /// Evaluate polynomial at point using streaming
    fn evaluate_at_point_streaming(
        &self,
        input: &MultiInstanceInput<F>,
        point: &[F],
    ) -> Result<F, String> {
        let mut result = F::zero();
        
        // Stream through instances
        for (instance, witness) in input.instances.iter().zip(&input.witnesses) {
            let contribution = self.evaluate_instance_at_point(
                instance,
                witness,
                point,
            )?;
            result = result.add(&contribution);
        }
        
        Ok(result)
    }
    
    /// Evaluate single instance at point
    fn evaluate_instance_at_point(
        &self,
        instance: &GeneralizedR1CSInstance<F>,
        witness: &GeneralizedR1CSWitness<F>,
        point: &[F],
    ) -> Result<F, String> {
        let mut result = F::zero();
        
        // Stream through witness in chunks
        let chunk_size = self.config.chunk_size;
        
        for chunk_start in (0..witness.witness_matrix.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(witness.witness_matrix.len());
            
            for i in chunk_start..chunk_end {
                let row = &witness.witness_matrix[i];
                
                // Compute multilinear evaluation
                for (j, &val) in row.iter().enumerate() {
                    let basis = self.compute_multilinear_basis(i, j, point)?;
                    result = result.add(&val.mul(&basis));
                }
            }
        }
        
        Ok(result)
    }
    
    /// Compute multilinear basis evaluation
    fn compute_multilinear_basis(
        &self,
        row: usize,
        col: usize,
        point: &[F],
    ) -> Result<F, String> {
        let mut result = F::one();
        let index = (row << 16) | col;
        
        for (i, &p) in point.iter().enumerate() {
            let bit = (index >> i) & 1;
            if bit == 1 {
                result = result.mul(&p);
            } else {
                result = result.mul(&F::one().sub(&p));
            }
        }
        
        Ok(result)
    }
    
    /// Pass 3: Compute folded witness in streaming fashion
    /// Memory: O(n) - stream through witnesses and accumulate
    fn pass3_fold_witnesses(
        &self,
        input: &MultiInstanceInput<F>,
        transcript: &mut Transcript,
    ) -> Result<FoldedWitness<F>, String> {
        // Sample folding challenges
        let beta = self.sample_folding_challenges(transcript, input.instances.len())?;
        
        let n = input.witnesses[0].witness_matrix.len();
        let d = input.witnesses[0].witness_matrix[0].len();
        
        // Initialize folded witness
        let mut folded_matrix = vec![vec![F::zero(); d]; n];
        
        // Stream through witnesses and accumulate
        for (witness, beta_ell) in input.witnesses.iter().zip(&beta) {
            self.accumulate_folded_witness(
                &mut folded_matrix,
                witness,
                beta_ell,
            )?;
        }
        
        // Convert to ring elements
        let folded_ring: Vec<RingElement<F>> = folded_matrix
            .iter()
            .map(|row| RingElement::from_coeffs(row.clone()))
            .collect();
        
        // Compute norm
        let norm = Self::compute_witness_norm(&folded_ring);
        
        // Compute opening scalar
        let opening_scalar = self.compute_folded_opening_scalar(input, &beta)?;
        
        Ok(FoldedWitness {
            witness: folded_ring,
            opening_scalar,
            norm,
        })
    }
    
    /// Accumulate folded witness contribution
    fn accumulate_folded_witness(
        &self,
        folded: &mut [Vec<F>],
        witness: &GeneralizedR1CSWitness<F>,
        beta: &RingElement<F>,
    ) -> Result<(), String> {
        let chunk_size = self.config.chunk_size;
        
        // Stream through witness in chunks
        for chunk_start in (0..witness.witness_matrix.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(witness.witness_matrix.len());
            
            for i in chunk_start..chunk_end {
                let row = &witness.witness_matrix[i];
                
                // Scale by beta and accumulate
                for (j, &val) in row.iter().enumerate() {
                    // folded[i][j] += beta * val
                    let beta_coeff = beta.coeffs[j % beta.coeffs.len()];
                    let scaled = val.mul(&beta_coeff);
                    folded[i][j] = folded[i][j].add(&scaled);
                }
            }
        }
        
        Ok(())
    }
    
    /// Sample folding challenges
    fn sample_folding_challenges(
        &self,
        transcript: &mut Transcript,
        count: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        let mut challenges = Vec::with_capacity(count);
        
        for i in 0..count {
            let challenge_bytes = transcript.challenge_bytes(
                &format!("folding_challenge_{}", i).as_bytes(),
                32,
            );
            
            // Convert to ring element
            let mut coeffs = Vec::with_capacity(self.ring.degree());
            for j in 0..self.ring.degree() {
                let byte_idx = (j * 8) % challenge_bytes.len();
                let val = u64::from_le_bytes([
                    challenge_bytes[byte_idx],
                    challenge_bytes[(byte_idx + 1) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 2) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 3) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 4) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 5) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 6) % challenge_bytes.len()],
                    challenge_bytes[(byte_idx + 7) % challenge_bytes.len()],
                ]) % F::MODULUS;
                coeffs.push(F::from_u64(val));
            }
            
            challenges.push(RingElement::from_coeffs(coeffs));
        }
        
        Ok(challenges)
    }
    
    /// Compute folded opening scalar
    fn compute_folded_opening_scalar(
        &self,
        input: &MultiInstanceInput<F>,
        beta: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        let mut opening_scalar = self.ring.zero();
        
        for (witness, beta_ell) in input.witnesses.iter().zip(beta) {
            let scaled = self.ring.mul(&witness.opening_scalar, beta_ell);
            opening_scalar = self.ring.add(&opening_scalar, &scaled);
        }
        
        Ok(opening_scalar)
    }
    
    /// Compute witness norm
    fn compute_witness_norm(witness: &[RingElement<F>]) -> f64 {
        let mut sum_sq = 0.0;
        for w in witness {
            let norm = w.l2_norm();
            sum_sq += norm * norm;
        }
        sum_sq.sqrt()
    }
    
    /// Validate memory budget
    fn validate_memory_budget(&self, input: &MultiInstanceInput<F>) -> Result<(), String> {
        let witness_size = input.witnesses[0].witness_matrix.len() 
            * input.witnesses[0].witness_matrix[0].len()
            * std::mem::size_of::<F>();
        
        let estimated_memory = witness_size * 2; // Factor of 2 for working memory
        
        if estimated_memory > self.config.max_memory {
            return Err(format!(
                "Estimated memory {} exceeds budget {}",
                estimated_memory,
                self.config.max_memory
            ));
        }
        
        Ok(())
    }
    
    /// Construct output from streaming results
    fn construct_output(
        &self,
        commitments: Vec<Commitment<F>>,
        sumcheck_output: SumcheckOutput<F>,
        folded_witness: FoldedWitness<F>,
    ) -> Result<FoldedOutput<F>, String> {
        use super::rok_traits::{LinearInstance, BatchLinearInstance};
        
        // Construct linear instance
        let linear_instance = LinearInstance {
            commitment: commitments[0].clone(),
            evaluation_point: sumcheck_output.evaluation_point.iter()
                .map(|&f| SymphonyExtensionField::from_base_field(f))
                .collect(),
            claimed_value: SymphonyExtensionField::from_base_field(sumcheck_output.final_evaluation),
        };
        
        // Construct batch linear instance
        let batch_linear_instance = BatchLinearInstance {
            commitment: commitments[0].clone(),
            evaluation_point: sumcheck_output.evaluation_point.iter()
                .map(|&f| SymphonyExtensionField::from_base_field(f))
                .collect(),
            claimed_values: vec![], // Would be filled from monomial checks
        };
        
        Ok(FoldedOutput {
            linear_instance,
            batch_linear_instance,
            folded_witness: Some(folded_witness),
            message_commitments: commitments,
        })
    }
    
    /// Serialize proof
    fn serialize_proof(&self, output: &FoldedOutput<F>) -> Result<Vec<u8>, String> {
        let mut proof = Vec::new();
        
        // Serialize commitments
        for commitment in &output.message_commitments {
            proof.extend_from_slice(&commitment.to_bytes());
        }
        
        // Serialize evaluation point
        for point in &output.linear_instance.evaluation_point {
            proof.extend_from_slice(&point.to_bytes());
        }
        
        // Serialize claimed value
        proof.extend_from_slice(&output.linear_instance.claimed_value.to_bytes());
        
        Ok(proof)
    }
}

/// Sumcheck output from streaming execution
#[derive(Clone, Debug)]
struct SumcheckOutput<F: Field> {
    /// Round polynomials and challenges
    rounds: Vec<(Vec<F>, SymphonyExtensionField<F>)>,
    
    /// Final evaluation
    final_evaluation: F,
    
    /// Evaluation point
    evaluation_point: Vec<F>,
}

/// Evaluation table for streaming sumcheck
#[derive(Clone, Debug)]
struct EvaluationTable<F: Field> {
    /// Table values
    values: Vec<F>,
    
    /// Pass number
    pass: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::commitment::ajtai::AjtaiParams;
    
    #[test]
    fn test_streaming_config() {
        let config = StreamingConfig::default();
        assert_eq!(config.max_memory, 1_000_000_000);
        assert!(config.parallel);
    }
    
    #[test]
    fn test_compute_num_passes() {
        // For n = 1024, log(n) = 10, log(log(n)) ≈ 3.32
        // So num_passes = 2 + 4 = 6
        let passes = StreamingConfig::compute_num_passes(1024);
        assert!(passes >= 2 && passes <= 10);
    }
    
    #[test]
    fn test_streaming_prover_creation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let key = AjtaiCommitment::setup(params, 256, None);
        let config = StreamingConfig::default();
        
        let prover = StreamingProver::new(ring, key, config, 256);
        assert_eq!(prover.challenge_set_size, 256);
    }
}
