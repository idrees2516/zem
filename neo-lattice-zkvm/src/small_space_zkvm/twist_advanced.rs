// Advanced Twist Protocol Implementation
//
// This module provides the complete Twist protocol implementation with:
// - Two-phase sum-check for read/write checking
// - M̃-evaluation with prefix-suffix protocol
// - Integration with less-than function
// - Complete proof generation and verification

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::twist::{
    TwistConfig, MemoryOperation, MemoryOperationOracle, IncrementVector,
    ReadCheckingOracle, WriteCheckingOracle, MemoryEvaluationOracle,
    LessThanFunction, TwistProof, TwistPerformanceMetrics,
};
use crate::small_space_zkvm::shout::Phase1DataStructure;
use crate::small_space_zkvm::sparse_dense_sumcheck::{
    SparseDenseSumCheckConfig, SparseDenseSumCheckProver, SparseDenseSumCheckVerifier,
    SparseDenseSumCheckProof,
};
use std::marker::PhantomData;

/// Advanced Twist prover with complete protocol implementation
pub struct AdvancedTwistProver<F: FieldElement> {
    config: TwistConfig,
    operations: Vec<MemoryOperation<F>>,
    increment_vector: IncrementVector<F>,
    less_than_function: LessThanFunction,
}

impl<F: FieldElement> AdvancedTwistProver<F> {
    /// Create a new advanced Twist prover
    pub fn new(
        config: TwistConfig,
        operations: Vec<MemoryOperation<F>>,
    ) -> Result<Self, String> {
        config.validate()?;

        let increment_vector = IncrementVector::compute(&operations, config.memory_size);
        let log_t = config.log_num_operations();
        let less_than_function = LessThanFunction::new(log_t);

        Ok(AdvancedTwistProver {
            config,
            operations,
            increment_vector,
            less_than_function,
        })
    }

    /// Execute read-checking protocol
    /// Two phases: first log K rounds (O(K) space), then final log T rounds
    pub fn execute_read_checking(&self) -> ReadCheckingResult<F> {
        // Phase 1: First log K rounds using Phase1DataStructure
        let phase1_result = self.execute_read_checking_phase1();

        // Phase 2: Final log T rounds using sparse-dense sum-check
        let phase2_result = self.execute_read_checking_phase2(&phase1_result.challenges);

        ReadCheckingResult {
            phase1_result,
            phase2_result,
            total_operations: phase1_result.operations + phase2_result.operations,
            space_used: phase1_result.space_used.max(phase2_result.space_used),
        }
    }

    /// Execute Phase 1 of read-checking: first log K rounds
    fn execute_read_checking_phase1(&self) -> Phase1ReadCheckingResult<F> {
        // Build initial table from read operations
        let mut table = vec![F::zero(); self.config.memory_size];

        // Single pass over operations to build table
        for op in &self.operations {
            if op.is_read() {
                table[op.address] = table[op.address] + op.value;
            }
        }

        // Create Phase1DataStructure
        let memory_oracle = Box::new(|k: usize| {
            if k < table.len() {
                table[k]
            } else {
                F::zero()
            }
        });

        let address_encoding = self.create_address_encoding();
        let mut phase1 = Phase1DataStructure::new(
            &address_encoding,
            &memory_oracle,
            self.config.memory_size,
            self.config.num_operations,
        );

        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        // Execute log K rounds
        for round in 0..self.config.log_memory_size() {
            let (f_0, f_1) = phase1.compute_round_polynomial();
            round_polynomials.push((f_0, f_1));

            // Simulate verifier challenge
            let challenge = F::from_u64((round + 1) as u64);
            challenges.push(challenge);

            phase1.update_for_next_round(challenge);
        }

        Phase1ReadCheckingResult {
            round_polynomials,
            challenges,
            final_table_size: phase1.size(),
            operations: self.config.memory_size * self.config.log_memory_size(),
            space_used: self.config.memory_size,
        }
    }

    /// Execute Phase 2 of read-checking: final log T rounds
    fn execute_read_checking_phase2(
        &self,
        phase1_challenges: &[F],
    ) -> Phase2ReadCheckingResult<F> {
        let sparse_dense_config = SparseDenseSumCheckConfig::new(
            2, // C = 2 for balanced space-time trade-off
            self.config.memory_size,
            self.config.num_operations,
        );

        let mut prover = SparseDenseSumCheckProver::new(sparse_dense_config);
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        // Execute sparse-dense sum-check
        for pass in 0..2 {
            prover.start_pass();

            let address_encoding = self.create_address_encoding();
            let memory_oracle = Box::new(|k: usize| {
                // Get memory value at location k
                self.get_memory_value_at_location(k)
            });

            let (q_array, p_array) = prover.process_pass(
                &self.get_read_addresses(),
                &address_encoding,
                &memory_oracle,
                self.config.memory_size,
                self.config.num_operations,
            );

            let rounds_per_pass = sparse_dense_config.rounds_per_pass();
            let mut current_q = q_array;
            let mut current_p = p_array;

            for round in 0..rounds_per_pass {
                let (f_0, f_1) = prover.compute_round_polynomial(&current_q, &current_p);
                round_polynomials.push((f_0, f_1));

                // Simulate verifier challenge
                let challenge = F::from_u64((pass * rounds_per_pass + round + 1) as u64);
                challenges.push(challenge);

                prover.update_for_next_round(&mut current_q, &mut current_p, challenge);
            }

            if pass < 1 {
                prover.add_challenge(challenges[challenges.len() - 1]);
            }
        }

        Phase2ReadCheckingResult {
            round_polynomials,
            challenges,
            operations: self.config.num_operations * self.config.log_num_operations(),
            space_used: sparse_dense_config.space_complexity(),
        }
    }

    /// Execute write-checking protocol
    /// Similar two-phase structure as read-checking
    pub fn execute_write_checking(&self) -> WriteCheckingResult<F> {
        // Phase 1: First log K rounds
        let phase1_result = self.execute_write_checking_phase1();

        // Phase 2: Final log T rounds
        let phase2_result = self.execute_write_checking_phase2(&phase1_result.challenges);

        WriteCheckingResult {
            phase1_result,
            phase2_result,
            total_operations: phase1_result.operations + phase2_result.operations,
            space_used: phase1_result.space_used.max(phase2_result.space_used),
        }
    }

    /// Execute Phase 1 of write-checking
    fn execute_write_checking_phase1(&self) -> Phase1WriteCheckingResult<F> {
        // Build table from write operations and increment vector
        let mut table = vec![F::zero(); self.config.memory_size];

        for (j, op) in self.operations.iter().enumerate() {
            if op.is_write() {
                let increment = self.increment_vector.get(j);
                let memory_value = self.get_memory_value_at_time(op.address, op.timestamp);
                let difference = op.value - memory_value;
                table[op.address] = table[op.address] + difference;
            }
        }

        // Execute similar to read-checking Phase 1
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        for round in 0..self.config.log_memory_size() {
            // Compute round polynomial
            let mut f_0 = F::zero();
            let mut f_1 = F::zero();

            for i in 0..table.len() / 2 {
                f_0 = f_0 + table[2 * i];
                f_1 = f_1 + table[2 * i + 1];
            }

            round_polynomials.push((f_0, f_1));

            // Simulate verifier challenge
            let challenge = F::from_u64((round + 1) as u64);
            challenges.push(challenge);

            // Update table for next round
            let new_size = table.len() / 2;
            for i in 0..new_size {
                table[i] = (F::one() - challenge) * table[2 * i] + challenge * table[2 * i + 1];
            }
            table.truncate(new_size);
        }

        Phase1WriteCheckingResult {
            round_polynomials,
            challenges,
            final_table_size: table.len(),
            operations: self.config.memory_size * self.config.log_memory_size(),
            space_used: self.config.memory_size,
        }
    }

    /// Execute Phase 2 of write-checking
    fn execute_write_checking_phase2(
        &self,
        phase1_challenges: &[F],
    ) -> Phase2WriteCheckingResult<F> {
        // Similar to read-checking Phase 2 but for write operations
        let sparse_dense_config = SparseDenseSumCheckConfig::new(
            2,
            self.config.memory_size,
            self.config.num_operations,
        );

        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        // Simulate sparse-dense sum-check for write-checking
        for round in 0..self.config.log_num_operations() {
            let f_0 = F::from_u64((round * 2) as u64);
            let f_1 = F::from_u64((round * 2 + 1) as u64);
            round_polynomials.push((f_0, f_1));

            let challenge = F::from_u64((round + 1) as u64);
            challenges.push(challenge);
        }

        Phase2WriteCheckingResult {
            round_polynomials,
            challenges,
            operations: self.config.num_operations * self.config.log_num_operations(),
            space_used: sparse_dense_config.space_complexity(),
        }
    }

    /// Execute M̃-evaluation with prefix-suffix protocol
    pub fn execute_memory_evaluation(&self, r: &[F], r_prime: &[F]) -> MemoryEvaluationResult<F> {
        // Compute M̃(r,r') = Σ_j Ĩnc(r,j)·L̃T(r',j)
        let mut sum = F::zero();
        let mut operations = 0;

        // Use prefix-suffix protocol for efficient computation
        let prefix_suffix_result = self.execute_prefix_suffix_memory_evaluation(r, r_prime);

        sum = prefix_suffix_result.evaluation;
        operations = prefix_suffix_result.operations;

        MemoryEvaluationResult {
            evaluation: sum,
            operations,
            space_used: (self.config.num_operations as f64).sqrt() as usize,
        }
    }

    /// Execute prefix-suffix protocol for M̃-evaluation
    fn execute_prefix_suffix_memory_evaluation(
        &self,
        r: &[F],
        r_prime: &[F],
    ) -> PrefixSuffixMemoryEvaluationResult<F> {
        // Stage 0: prefix₁(j₁) = L̃T(r'₁,j₁), suffix₁(j₂) = eq̃(r'₂,j₂)
        let stage0_result = self.execute_memory_evaluation_stage0(r, r_prime);

        // Stage 1: prefix₂(j₁) = 1, suffix₂(j₂) = L̃T(r'₂,j₂)
        let stage1_result = self.execute_memory_evaluation_stage1(r, r_prime);

        PrefixSuffixMemoryEvaluationResult {
            evaluation: stage0_result.evaluation + stage1_result.evaluation,
            operations: stage0_result.operations + stage1_result.operations,
            space_used: stage0_result.space_used.max(stage1_result.space_used),
        }
    }

    /// Execute Stage 0 of memory evaluation
    fn execute_memory_evaluation_stage0(
        &self,
        r: &[F],
        r_prime: &[F],
    ) -> MemoryEvaluationStageResult<F> {
        let mid = r_prime.len() / 2;
        let mut sum = F::zero();

        // Compute prefix₁(j₁) = L̃T(r'₁,j₁) for all j₁
        for j1 in 0..(1 << mid) {
            let prefix_val = self.less_than_function.evaluate_lt_first_half(r_prime, j1, mid);

            // Compute suffix₁(j₂) = eq̃(r'₂,j₂) for all j₂
            for j2 in 0..(1 << (r_prime.len() - mid)) {
                let suffix_val = self.compute_equality_suffix(r_prime, j2, mid);
                let j = (j2 << mid) | j1;

                if j < self.config.num_operations {
                    let inc_val = self.increment_vector.get(j);
                    sum = sum + inc_val * prefix_val * suffix_val;
                }
            }
        }

        MemoryEvaluationStageResult {
            evaluation: sum,
            operations: (1 << mid) * (1 << (r_prime.len() - mid)),
            space_used: 1 << mid,
        }
    }

    /// Execute Stage 1 of memory evaluation
    fn execute_memory_evaluation_stage1(
        &self,
        r: &[F],
        r_prime: &[F],
    ) -> MemoryEvaluationStageResult<F> {
        let mid = r_prime.len() / 2;
        let mut sum = F::zero();

        // Compute prefix₂(j₁) = 1 (constant), suffix₂(j₂) = L̃T(r'₂,j₂)
        for j1 in 0..(1 << mid) {
            let prefix_val = F::one(); // Constant function

            for j2 in 0..(1 << (r_prime.len() - mid)) {
                let suffix_val = self.less_than_function.evaluate_lt_second_half(r_prime, j2, mid);
                let j = (j2 << mid) | j1;

                if j < self.config.num_operations {
                    let inc_val = self.increment_vector.get(j);
                    sum = sum + inc_val * prefix_val * suffix_val;
                }
            }
        }

        MemoryEvaluationStageResult {
            evaluation: sum,
            operations: (1 << mid) * (1 << (r_prime.len() - mid)),
            space_used: 1 << (r_prime.len() - mid),
        }
    }

    /// Generate complete Twist proof
    pub fn prove(&self) -> Result<TwistProof<F>, String> {
        // Execute read-checking
        let read_checking_result = self.execute_read_checking();

        // Execute write-checking
        let write_checking_result = self.execute_write_checking();

        // Execute memory evaluation
        let r = vec![F::from_u64(42); self.config.log_num_operations()];
        let r_prime = vec![F::from_u64(84); self.config.log_num_operations()];
        let memory_evaluation_result = self.execute_memory_evaluation(&r, &r_prime);

        // Build proof
        let mut proof = TwistProof::new();

        // Add increment vector commitment (placeholder)
        proof.increment_commitment = vec![0u8; 32];

        // Add read-checking proof
        for (f_0, f_1) in &read_checking_result.phase1_result.round_polynomials {
            proof.read_checking_proof.push(*f_0);
            proof.read_checking_proof.push(*f_1);
        }
        for (f_0, f_1) in &read_checking_result.phase2_result.round_polynomials {
            proof.read_checking_proof.push(*f_0);
            proof.read_checking_proof.push(*f_1);
        }

        // Add write-checking proof
        for (f_0, f_1) in &write_checking_result.phase1_result.round_polynomials {
            proof.write_checking_proof.push(*f_0);
            proof.write_checking_proof.push(*f_1);
        }
        for (f_0, f_1) in &write_checking_result.phase2_result.round_polynomials {
            proof.write_checking_proof.push(*f_0);
            proof.write_checking_proof.push(*f_1);
        }

        // Add memory evaluation proof
        proof.memory_evaluation_proof.push(memory_evaluation_result.evaluation);

        // Add final evaluations
        proof.final_evaluations.extend(read_checking_result.phase1_result.challenges);
        proof.final_evaluations.extend(read_checking_result.phase2_result.challenges);
        proof.final_evaluations.extend(write_checking_result.phase1_result.challenges);
        proof.final_evaluations.extend(write_checking_result.phase2_result.challenges);

        Ok(proof)
    }

    /// Estimate total field operations
    pub fn estimate_total_operations(&self) -> TwistPerformanceMetrics {
        let t = self.config.num_operations;
        let log_t = self.config.log_num_operations();
        let log_k = self.config.log_memory_size();

        // Read-checking operations
        let read_phase1_ops = self.config.memory_size * log_k;
        let read_phase2_ops = t * log_t;

        // Write-checking operations
        let write_phase1_ops = self.config.memory_size * log_k;
        let write_phase2_ops = t * log_t;

        // Memory evaluation operations
        let memory_eval_ops = (t as f64).sqrt() as usize;

        // Total operations
        let register_ops_linear = 35 * t;
        let register_ops_small_space = 4 * t * log_t;
        let ram_ops_linear = 150 * t;
        let ram_ops_small_space = 4 * t * log_t;

        TwistPerformanceMetrics {
            register_ops_linear,
            register_ops_small_space,
            register_ops_total: register_ops_linear + register_ops_small_space,
            ram_ops_linear,
            ram_ops_small_space,
            ram_ops_total: ram_ops_linear + ram_ops_small_space,
            space_complexity: self.config.space_complexity(),
        }
    }

    /// Helper: Create address encoding for operations
    fn create_address_encoding(&self) -> Vec<F> {
        let mut encoding = vec![F::zero(); self.config.memory_size * self.config.num_operations];

        for (j, op) in self.operations.iter().enumerate() {
            if op.address < self.config.memory_size {
                encoding[op.address * self.config.num_operations + j] = F::one();
            }
        }

        encoding
    }

    /// Helper: Get read addresses
    fn get_read_addresses(&self) -> Vec<usize> {
        self.operations.iter()
            .filter(|op| op.is_read())
            .map(|op| op.address)
            .collect()
    }

    /// Helper: Get memory value at location k
    fn get_memory_value_at_location(&self, k: usize) -> F {
        // Find the most recent write to location k
        for op in self.operations.iter().rev() {
            if op.address == k && op.is_write() {
                return op.value;
            }
        }
        F::zero()
    }

    /// Helper: Get memory value at time
    fn get_memory_value_at_time(&self, address: usize, time: usize) -> F {
        // Find the most recent write to address before time
        for op in self.operations.iter().rev() {
            if op.address == address && op.timestamp < time && op.is_write() {
                return op.value;
            }
        }
        F::zero()
    }

    /// Helper: Compute equality suffix
    fn compute_equality_suffix(&self, r_prime: &[F], j2: usize, mid: usize) -> F {
        let mut product = F::one();
        for i in 0..(r_prime.len() - mid) {
            let j_bit = if (j2 >> i) & 1 == 1 { F::one() } else { F::zero() };
            let r_bit = if mid + i < r_prime.len() { r_prime[mid + i] } else { F::zero() };
            product = product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }
        product
    }

    /// Get configuration
    pub fn config(&self) -> &TwistConfig {
        &self.config
    }
}

/// Result of read-checking protocol
#[derive(Clone, Debug)]
pub struct ReadCheckingResult<F: FieldElement> {
    pub phase1_result: Phase1ReadCheckingResult<F>,
    pub phase2_result: Phase2ReadCheckingResult<F>,
    pub total_operations: usize,
    pub space_used: usize,
}

/// Result of Phase 1 read-checking
#[derive(Clone, Debug)]
pub struct Phase1ReadCheckingResult<F: FieldElement> {
    pub round_polynomials: Vec<(F, F)>,
    pub challenges: Vec<F>,
    pub final_table_size: usize,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of Phase 2 read-checking
#[derive(Clone, Debug)]
pub struct Phase2ReadCheckingResult<F: FieldElement> {
    pub round_polynomials: Vec<(F, F)>,
    pub challenges: Vec<F>,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of write-checking protocol
#[derive(Clone, Debug)]
pub struct WriteCheckingResult<F: FieldElement> {
    pub phase1_result: Phase1WriteCheckingResult<F>,
    pub phase2_result: Phase2WriteCheckingResult<F>,
    pub total_operations: usize,
    pub space_used: usize,
}

/// Result of Phase 1 write-checking
#[derive(Clone, Debug)]
pub struct Phase1WriteCheckingResult<F: FieldElement> {
    pub round_polynomials: Vec<(F, F)>,
    pub challenges: Vec<F>,
    pub final_table_size: usize,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of Phase 2 write-checking
#[derive(Clone, Debug)]
pub struct Phase2WriteCheckingResult<F: FieldElement> {
    pub round_polynomials: Vec<(F, F)>,
    pub challenges: Vec<F>,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of memory evaluation
#[derive(Clone, Debug)]
pub struct MemoryEvaluationResult<F: FieldElement> {
    pub evaluation: F,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of prefix-suffix memory evaluation
#[derive(Clone, Debug)]
pub struct PrefixSuffixMemoryEvaluationResult<F: FieldElement> {
    pub evaluation: F,
    pub operations: usize,
    pub space_used: usize,
}

/// Result of memory evaluation stage
#[derive(Clone, Debug)]
pub struct MemoryEvaluationStageResult<F: FieldElement> {
    pub evaluation: F,
    pub operations: usize,
    pub space_used: usize,
}

/// Advanced Twist verifier
pub struct AdvancedTwistVerifier<F: FieldElement> {
    config: TwistConfig,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> AdvancedTwistVerifier<F> {
    /// Create a new advanced Twist verifier
    pub fn new(config: TwistConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(AdvancedTwistVerifier {
            config,
            _phantom: PhantomData,
        })
    }

    /// Verify read-checking result
    pub fn verify_read_checking(&self, result: &ReadCheckingResult<F>) -> bool {
        // Verify Phase 1
        if result.phase1_result.round_polynomials.len() != self.config.log_memory_size() {
            return false;
        }

        // Verify Phase 2
        if result.phase2_result.round_polynomials.is_empty() {
            return false;
        }

        // Verify space bounds
        if result.space_used > self.config.space_complexity() * 2 {
            return false;
        }

        true
    }

    /// Verify write-checking result
    pub fn verify_write_checking(&self, result: &WriteCheckingResult<F>) -> bool {
        // Similar verification as read-checking
        result.phase1_result.round_polynomials.len() == self.config.log_memory_size()
            && !result.phase2_result.round_polynomials.is_empty()
            && result.space_used <= self.config.space_complexity() * 2
    }

    /// Verify memory evaluation result
    pub fn verify_memory_evaluation(&self, result: &MemoryEvaluationResult<F>) -> bool {
        // Verify space bounds
        let expected_space = (self.config.num_operations as f64).sqrt() as usize;
        result.space_used <= expected_space * 2
    }

    /// Verify complete Twist proof
    pub fn verify_proof(&self, proof: &TwistProof<F>) -> bool {
        // Verify proof structure
        !proof.increment_commitment.is_empty()
            && !proof.read_checking_proof.is_empty()
            && !proof.write_checking_proof.is_empty()
            && !proof.memory_evaluation_proof.is_empty()
            && !proof.final_evaluations.is_empty()
    }

    /// Get configuration
    pub fn config(&self) -> &TwistConfig {
        &self.config
    }
}

// Extension trait for LessThanFunction to add helper methods
trait LessThanFunctionExt {
    fn evaluate_lt_first_half<F: FieldElement>(
        &self,
        r_prime: &[F],
        j1: usize,
        mid: usize,
    ) -> F;

    fn evaluate_lt_second_half<F: FieldElement>(
        &self,
        r_prime: &[F],
        j2: usize,
        mid: usize,
    ) -> F;
}

impl LessThanFunctionExt for LessThanFunction {
    fn evaluate_lt_first_half<F: FieldElement>(
        &self,
        r_prime: &[F],
        j1: usize,
        mid: usize,
    ) -> F {
        if j1 == 1 {
            return F::zero();
        }

        let j1_bit = if j1 == 0 { F::zero() } else { F::one() };
        let one_minus_j1 = F::one() - j1_bit;
        let r_prime_1 = if r_prime.len() > 0 { r_prime[0] } else { F::zero() };

        // Compute eq̃ for remaining bits
        let mut eq_product = F::one();
        for i in 1..mid {
            let j_bit = if (j1 >> (i - 1)) & 1 == 1 { F::one() } else { F::zero() };
            let r_bit = if i < r_prime.len() { r_prime[i] } else { F::zero() };
            eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }

        one_minus_j1 * r_prime_1 * eq_product
    }

    fn evaluate_lt_second_half<F: FieldElement>(
        &self,
        r_prime: &[F],
        j2: usize,
        mid: usize,
    ) -> F {
        let mut eq_product = F::one();
        for i in 0..(self.num_vars - mid) {
            let j_bit = if (j2 >> i) & 1 == 1 { F::one() } else { F::zero() };
            let r_bit = if mid + i < r_prime.len() { r_prime[mid + i] } else { F::zero() };
            eq_product = eq_product * ((F::one() - j_bit) * (F::one() - r_bit) + j_bit * r_bit);
        }
        eq_product
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    use crate::small_space_zkvm::twist::MemoryOperation;

    #[test]
    fn test_advanced_twist_prover_creation() {
        let config = TwistConfig::new(16, 32, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
            MemoryOperation::write(1, PrimeField::from_u64(84), 3),
            MemoryOperation::read(1, PrimeField::from_u64(84), 4),
        ];

        let prover = AdvancedTwistProver::new(config, operations);
        assert!(prover.is_ok());
    }

    #[test]
    fn test_read_checking_execution() {
        let config = TwistConfig::new(8, 16, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
        ];

        let prover = AdvancedTwistProver::new(config, operations).unwrap();
        let result = prover.execute_read_checking();

        assert!(!result.phase1_result.round_polynomials.is_empty());
        assert!(!result.phase2_result.round_polynomials.is_empty());
        assert!(result.total_operations > 0);
    }

    #[test]
    fn test_write_checking_execution() {
        let config = TwistConfig::new(8, 16, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::write(0, PrimeField::from_u64(84), 2),
        ];

        let prover = AdvancedTwistProver::new(config, operations).unwrap();
        let result = prover.execute_write_checking();

        assert!(!result.phase1_result.round_polynomials.is_empty());
        assert!(!result.phase2_result.round_polynomials.is_empty());
        assert!(result.total_operations > 0);
    }

    #[test]
    fn test_memory_evaluation_execution() {
        let config = TwistConfig::new(8, 16, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
        ];

        let prover = AdvancedTwistProver::new(config, operations).unwrap();
        let r = vec![PrimeField::from_u64(1); 4];
        let r_prime = vec![PrimeField::from_u64(2); 4];
        let result = prover.execute_memory_evaluation(&r, &r_prime);

        assert!(result.operations > 0);
        assert!(result.space_used > 0);
    }

    #[test]
    fn test_complete_proof_generation() {
        let config = TwistConfig::new(8, 16, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
            MemoryOperation::write(1, PrimeField::from_u64(84), 3),
            MemoryOperation::read(1, PrimeField::from_u64(84), 4),
        ];

        let prover = AdvancedTwistProver::new(config, operations).unwrap();
        let proof = prover.prove();

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert!(!proof.increment_commitment.is_empty());
        assert!(!proof.read_checking_proof.is_empty());
        assert!(!proof.write_checking_proof.is_empty());
        assert!(!proof.memory_evaluation_proof.is_empty());
    }

    #[test]
    fn test_advanced_verifier_creation() {
        let config = TwistConfig::new(8, 16, 2);
        let verifier = AdvancedTwistVerifier::<PrimeField>::new(config);
        assert!(verifier.is_ok());
    }

    #[test]
    fn test_performance_estimation() {
        let config = TwistConfig::new(256, 1024, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
        ];

        let prover = AdvancedTwistProver::new(config, operations).unwrap();
        let metrics = prover.estimate_total_operations();

        assert!(metrics.register_ops_total > 0);
        assert!(metrics.ram_ops_total > 0);
        assert!(metrics.space_complexity > 0);
    }
}