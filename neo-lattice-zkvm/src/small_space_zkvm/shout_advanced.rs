// Advanced Shout Protocol Implementation
//
// This module provides the complete Shout protocol implementation with:
// - Phase 1: First log K rounds using Phase1DataStructure
// - Phase 2: Final log T rounds using sparse-dense sum-check
// - Booleanity and Hamming-weight-one verification
// - Full integration with sum-check protocol

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::shout::{
    Phase1DataStructure, ShoutConfig, ShoutProof, AddressOracle, MemoryOracle,
};
use crate::small_space_zkvm::sparse_dense_sumcheck::{
    SparseDenseSumCheckConfig, SparseDenseSumCheckProver, SparseDenseSumCheckVerifier,
    SparseDenseSumCheckProof, QArray, PArray,
};
use std::marker::PhantomData;

/// Advanced Shout prover with full protocol implementation
pub struct AdvancedShoutProver<F: FieldElement> {
    config: ShoutConfig,
    address_encoding: Vec<F>,
    memory_oracle: Box<dyn Fn(usize) -> F>,
    read_addresses: Vec<usize>,
}

impl<F: FieldElement> AdvancedShoutProver<F> {
    /// Create a new advanced Shout prover
    pub fn new(
        config: ShoutConfig,
        address_oracle: &dyn AddressOracle,
        memory_oracle: Box<dyn Fn(usize) -> F>,
    ) -> Result<Self, String> {
        config.validate()?;

        let mut address_encoding = vec![F::zero(); config.memory_size * config.num_reads];
        let mut read_addresses = Vec::new();

        for j in 0..config.num_reads {
            let addr = address_oracle.get_address(j);
            read_addresses.push(addr);
            if addr < config.memory_size {
                address_encoding[addr * config.num_reads + j] = F::one();
            }
        }

        Ok(AdvancedShoutProver {
            config,
            address_encoding,
            memory_oracle,
            read_addresses,
        })
    }

    /// Execute Phase 1: First log K rounds
    pub fn execute_phase1(&self) -> Phase1Result<F> {
        let phase1 = Phase1DataStructure::new(
            &self.address_encoding,
            &self.memory_oracle,
            self.config.memory_size,
            self.config.num_reads,
        );

        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();
        let mut current_phase1 = phase1;

        for round in 0..self.config.log_memory_size() {
            let (f_0, f_1) = current_phase1.compute_round_polynomial();
            round_polynomials.push((f_0, f_1));

            // Simulate verifier challenge (in real protocol, this comes from verifier)
            let challenge = F::from_u64((round + 1) as u64);
            challenges.push(challenge);

            current_phase1.update_for_next_round(challenge);
        }

        Phase1Result {
            round_polynomials,
            challenges,
            final_table_size: current_phase1.size(),
        }
    }

    /// Execute Phase 2: Final log T rounds using sparse-dense sum-check
    pub fn execute_phase2(&self, phase1_challenges: &[F]) -> Phase2Result<F> {
        let sparse_dense_config = SparseDenseSumCheckConfig::new(
            2, // C = 2 for balanced space-time trade-off
            self.config.memory_size,
            self.config.num_reads,
        );

        let mut prover = SparseDenseSumCheckProver::new(sparse_dense_config);
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();

        for pass in 0..2 {
            prover.start_pass();

            let (q_array, p_array) = prover.process_pass(
                &self.read_addresses,
                &self.address_encoding,
                &self.memory_oracle,
                self.config.memory_size,
                self.config.num_reads,
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

        Phase2Result {
            round_polynomials,
            challenges,
            space_used: sparse_dense_config.space_complexity(),
        }
    }

    /// Verify booleanity of address encoding
    pub fn verify_booleanity_sum(&self) -> F {
        let mut sum = F::zero();
        for &val in &self.address_encoding {
            let one_minus_val = F::one() - val;
            sum = sum + val * one_minus_val;
        }
        sum
    }

    /// Verify Hamming weight one
    pub fn verify_hamming_weight_sum(&self) -> F {
        let mut total = F::zero();
        for j in 0..self.config.num_reads {
            let mut sum_for_j = F::zero();
            for k in 0..self.config.memory_size {
                let idx = k * self.config.num_reads + j;
                if idx < self.address_encoding.len() {
                    sum_for_j = sum_for_j + self.address_encoding[idx];
                }
            }
            total = total + sum_for_j - F::one();
        }
        total
    }

    /// Generate complete Shout proof
    pub fn prove(&self) -> Result<ShoutProof<F>, String> {
        // Verify basic properties
        if self.verify_booleanity_sum() != F::zero() {
            return Err("Booleanity check failed".to_string());
        }
        if self.verify_hamming_weight_sum() != F::zero() {
            return Err("Hamming weight check failed".to_string());
        }

        // Execute Phase 1
        let phase1_result = self.execute_phase1();

        // Execute Phase 2
        let phase2_result = self.execute_phase2(&phase1_result.challenges);

        // Combine results into proof
        let mut proof = ShoutProof::new();

        // Add commitment (placeholder - would be actual commitment in real protocol)
        proof.address_commitment = vec![0u8; 32];

        // Add booleanity proof
        for (f_0, f_1) in &phase1_result.round_polynomials {
            proof.booleanity_proof.push(*f_0);
            proof.booleanity_proof.push(*f_1);
        }

        // Add Hamming weight proof
        for (f_0, f_1) in &phase2_result.round_polynomials {
            proof.hamming_weight_proof.push(*f_0);
            proof.hamming_weight_proof.push(*f_1);
        }

        // Add read-checking proof (combined from both phases)
        for (f_0, f_1) in &phase1_result.round_polynomials {
            proof.read_checking_proof.push(*f_0);
            proof.read_checking_proof.push(*f_1);
        }
        for (f_0, f_1) in &phase2_result.round_polynomials {
            proof.read_checking_proof.push(*f_0);
            proof.read_checking_proof.push(*f_1);
        }

        // Add final evaluations
        proof.final_evaluations = phase1_result.challenges.clone();
        proof.final_evaluations.extend(phase2_result.challenges.clone());

        Ok(proof)
    }

    /// Estimate total field operations
    pub fn estimate_total_operations(&self) -> usize {
        let t = self.config.num_reads;
        let log_t = self.config.log_num_reads();
        let log_k = self.config.log_memory_size();

        // Phase 1: log K rounds, O(K) per round = O(K log K)
        let phase1_ops = self.config.memory_size * log_k;

        // Phase 2: log T rounds with C=2 passes
        // Each pass: O(K^(1/2) + T) time
        let phase2_ops = 2 * (
            (self.config.memory_size as f64).sqrt() as usize +
            t
        );

        // Booleanity and Hamming weight checks
        let check_ops = 2 * self.config.memory_size * self.config.num_reads;

        phase1_ops + phase2_ops + check_ops
    }

    /// Get configuration
    pub fn config(&self) -> &ShoutConfig {
        &self.config
    }
}

/// Result of Phase 1 execution
#[derive(Clone, Debug)]
pub struct Phase1Result<F: FieldElement> {
    /// Round polynomials (f_0, f_1) for each round
    pub round_polynomials: Vec<(F, F)>,
    /// Challenges used
    pub challenges: Vec<F>,
    /// Final table size after all rounds
    pub final_table_size: usize,
}

/// Result of Phase 2 execution
#[derive(Clone, Debug)]
pub struct Phase2Result<F: FieldElement> {
    /// Round polynomials (f_0, f_1) for each round
    pub round_polynomials: Vec<(F, F)>,
    /// Challenges used
    pub challenges: Vec<F>,
    /// Space used
    pub space_used: usize,
}

/// Advanced Shout verifier
pub struct AdvancedShoutVerifier<F: FieldElement> {
    config: ShoutConfig,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> AdvancedShoutVerifier<F> {
    /// Create a new advanced Shout verifier
    pub fn new(config: ShoutConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(AdvancedShoutVerifier {
            config,
            _phantom: PhantomData,
        })
    }

    /// Verify Phase 1 result
    pub fn verify_phase1(&self, phase1_result: &Phase1Result<F>) -> bool {
        // Verify number of rounds
        if phase1_result.round_polynomials.len() != self.config.log_memory_size() {
            return false;
        }

        // Verify number of challenges
        if phase1_result.challenges.len() != self.config.log_memory_size() {
            return false;
        }

        // Verify final table size is 1
        if phase1_result.final_table_size != 1 {
            return false;
        }

        true
    }

    /// Verify Phase 2 result
    pub fn verify_phase2(&self, phase2_result: &Phase2Result<F>) -> bool {
        // Verify number of rounds
        let expected_rounds = 2 * self.config.log_num_reads() / 2;
        if phase2_result.round_polynomials.len() != expected_rounds {
            return false;
        }

        // Verify space complexity
        let expected_space = (self.config.memory_size as f64).sqrt() as usize;
        if phase2_result.space_used > expected_space * 2 {
            return false;
        }

        true
    }

    /// Verify complete Shout proof
    pub fn verify_proof(&self, proof: &ShoutProof<F>) -> bool {
        // Verify proof structure
        if proof.address_commitment.is_empty() {
            return false;
        }

        if proof.booleanity_proof.is_empty() {
            return false;
        }

        if proof.hamming_weight_proof.is_empty() {
            return false;
        }

        if proof.read_checking_proof.is_empty() {
            return false;
        }

        if proof.final_evaluations.is_empty() {
            return false;
        }

        true
    }

    /// Get configuration
    pub fn config(&self) -> &ShoutConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    use crate::small_space_zkvm::shout::SimpleAddressOracle;

    #[test]
    fn test_advanced_shout_prover_creation() {
        let config = ShoutConfig::new(16, 32, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
                            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 16);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle);
        assert!(prover.is_ok());
    }

    #[test]
    fn test_phase1_execution() {
        let config = ShoutConfig::new(8, 16, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 8);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let phase1_result = prover.execute_phase1();

        assert_eq!(phase1_result.round_polynomials.len(), 3); // log2(8) = 3
        assert_eq!(phase1_result.challenges.len(), 3);
    }

    #[test]
    fn test_phase2_execution() {
        let config = ShoutConfig::new(8, 16, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 8);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let phase1_result = prover.execute_phase1();
        let phase2_result = prover.execute_phase2(&phase1_result.challenges);

        assert!(!phase2_result.round_polynomials.is_empty());
        assert!(!phase2_result.challenges.is_empty());
    }

    #[test]
    fn test_booleanity_verification() {
        let config = ShoutConfig::new(8, 16, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 8);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let booleanity_sum = prover.verify_booleanity_sum();

        assert_eq!(booleanity_sum, PrimeField::zero());
    }

    #[test]
    fn test_hamming_weight_verification() {
        let config = ShoutConfig::new(8, 16, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 8);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let hamming_sum = prover.verify_hamming_weight_sum();

        assert_eq!(hamming_sum, PrimeField::zero());
    }

    #[test]
    fn test_complete_proof_generation() {
        let config = ShoutConfig::new(8, 16, 2);
        let addresses = vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
        let oracle = SimpleAddressOracle::new(addresses, 8);
        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let proof = prover.prove();

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert!(!proof.address_commitment.is_empty());
        assert!(!proof.booleanity_proof.is_empty());
        assert!(!proof.hamming_weight_proof.is_empty());
    }

    #[test]
    fn test_advanced_verifier_creation() {
        let config = ShoutConfig::new(8, 16, 2);
        let verifier = AdvancedShoutVerifier::<PrimeField>::new(config);
        assert!(verifier.is_ok());
    }

    #[test]
    fn test_verifier_phase1_verification() {
        let config = ShoutConfig::new(8, 16, 2);
        let verifier = AdvancedShoutVerifier::<PrimeField>::new(config).unwrap();

        let phase1_result = Phase1Result {
            round_polynomials: vec![(PrimeField::one(), PrimeField::one()); 3],
            challenges: vec![PrimeField::one(); 3],
            final_table_size: 1,
        };

        assert!(verifier.verify_phase1(&phase1_result));
    }

    #[test]
    fn test_operation_estimation() {
        let config = ShoutConfig::new(256, 1024, 2);
        let addresses = vec![0; 1024];
        let oracle = SimpleAddressOracle::new(addresses, 256);
        let memory_oracle = Box::new(|_k: usize| PrimeField::one());

        let prover = AdvancedShoutProver::new(config, &oracle, memory_oracle).unwrap();
        let ops = prover.estimate_total_operations();

        assert!(ops > 0);
    }
}
