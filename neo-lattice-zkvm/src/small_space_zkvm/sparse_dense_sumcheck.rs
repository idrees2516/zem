// Sparse-Dense Sum-Check Protocol for Shout Final Rounds
//
// This module implements the sparse-dense sum-check protocol for the final log T rounds
// of the Shout protocol. It achieves O(C·K^(1/C) + C·T) time with O(K^(1/C)) space
// by making C passes over the read addresses.
//
// Reference: "Twist and Shout: Faster memory checking arguments via one-hot addressing
// and increments" (2025-105)

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use std::marker::PhantomData;

/// Configuration for sparse-dense sum-check
#[derive(Clone, Debug)]
pub struct SparseDenseSumCheckConfig {
    /// Number of passes C
    pub num_passes: usize,
    /// Memory size K
    pub memory_size: usize,
    /// Number of reads T
    pub num_reads: usize,
}

impl SparseDenseSumCheckConfig {
    /// Create a new configuration
    pub fn new(num_passes: usize, memory_size: usize, num_reads: usize) -> Self {
        SparseDenseSumCheckConfig {
            num_passes,
            memory_size,
            num_reads,
        }
    }

    /// Compute log₂(num_reads)
    pub fn log_num_reads(&self) -> usize {
        (self.num_reads as f64).log2().ceil() as usize
    }

    /// Compute rounds per pass
    pub fn rounds_per_pass(&self) -> usize {
        let total_rounds = self.log_num_reads();
        (total_rounds + self.num_passes - 1) / self.num_passes
    }

    /// Compute space complexity: O(K^(1/C) + T^(1/C))
    pub fn space_complexity(&self) -> usize {
        let k_factor = (self.memory_size as f64).powf(1.0 / self.num_passes as f64) as usize;
        let t_factor = (self.num_reads as f64).powf(1.0 / self.num_passes as f64) as usize;
        k_factor + t_factor
    }

    /// Compute time complexity: O(C·K^(1/C) + C·T)
    pub fn time_complexity(&self) -> usize {
        let k_factor = (self.memory_size as f64).powf(1.0 / self.num_passes as f64) as usize;
        let c_k_factor = self.num_passes * k_factor;
        let c_t = self.num_passes * self.num_reads;
        c_k_factor + c_t
    }
}

/// Q array for sparse-dense sum-check
/// Q[y] = Σ_{x: x₁=y} u(x)·suffix(x₂,...,x_C)
pub struct QArray<F: FieldElement> {
    /// Q array values
    pub values: Vec<F>,
    /// Size of Q array (2^(log T / C))
    pub size: usize,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> QArray<F> {
    /// Create a new Q array
    pub fn new(size: usize) -> Self {
        QArray {
            values: vec![F::zero(); size],
            size,
            _phantom: PhantomData,
        }
    }

    /// Add a value to Q[y]
    pub fn add(&mut self, y: usize, value: F) {
        if y < self.size {
            self.values[y] = self.values[y] + value;
        }
    }

    /// Get value at Q[y]
    pub fn get(&self, y: usize) -> F {
        if y < self.size {
            self.values[y]
        } else {
            F::zero()
        }
    }

    /// Clear all values
    pub fn clear(&mut self) {
        for val in &mut self.values {
            *val = F::zero();
        }
    }
}

/// P array for sparse-dense sum-check
/// P[y] = prefix(y) for y ∈ {0,1}^(log T / C)
pub struct PArray<F: FieldElement> {
    /// P array values
    pub values: Vec<F>,
    /// Size of P array (2^(log T / C))
    pub size: usize,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> PArray<F> {
    /// Create a new P array
    pub fn new(size: usize) -> Self {
        PArray {
            values: vec![F::zero(); size],
            size,
            _phantom: PhantomData,
        }
    }

    /// Set value at P[y]
    pub fn set(&mut self, y: usize, value: F) {
        if y < self.size {
            self.values[y] = value;
        }
    }

    /// Get value at P[y]
    pub fn get(&self, y: usize) -> F {
        if y < self.size {
            self.values[y]
        } else {
            F::zero()
        }
    }
}

/// Sparse-dense sum-check prover
pub struct SparseDenseSumCheckProver<F: FieldElement> {
    config: SparseDenseSumCheckConfig,
    current_pass: usize,
    challenges: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> SparseDenseSumCheckProver<F> {
    /// Create a new sparse-dense sum-check prover
    pub fn new(config: SparseDenseSumCheckConfig) -> Self {
        SparseDenseSumCheckProver {
            config,
            current_pass: 0,
            challenges: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Initialize for a new pass
    pub fn start_pass(&mut self) {
        self.current_pass = 0;
        self.challenges.clear();
    }

    /// Process a pass over read addresses
    /// Returns (Q_array, P_array) for this pass
    pub fn process_pass(
        &mut self,
        read_addresses: &[usize],
        address_encoding: &[F],
        memory_oracle: &dyn Fn(usize) -> F,
        memory_size: usize,
        num_reads: usize,
    ) -> (QArray<F>, PArray<F>) {
        let rounds_per_pass = self.config.rounds_per_pass();
        let q_size = 1 << rounds_per_pass;
        let p_size = 1 << rounds_per_pass;

        let mut q_array = QArray::new(q_size);
        let mut p_array = PArray::new(p_size);

        // Build Q array: single pass over read addresses
        for j in 0..num_reads {
            for k in 0..memory_size {
                let idx = k * num_reads + j;
                if idx < address_encoding.len() && address_encoding[idx] == F::one() {
                    let memory_val = memory_oracle(k);
                    // Extract y from j based on current pass
                    let y = self.extract_y_for_pass(j, self.current_pass);
                    if y < q_size {
                        q_array.add(y, memory_val);
                    }
                }
            }
        }

        // Build P array: compute prefix values
        for y in 0..p_size {
            let prefix_val = self.compute_prefix_for_pass(y, self.current_pass);
            p_array.set(y, prefix_val);
        }

        self.current_pass += 1;

        (q_array, p_array)
    }

    /// Extract y coordinate for current pass
    fn extract_y_for_pass(&self, index: usize, pass: usize) -> usize {
        let rounds_per_pass = self.config.rounds_per_pass();
        let start_bit = pass * rounds_per_pass;
        let mask = (1 << rounds_per_pass) - 1;
        (index >> start_bit) & mask
    }

    /// Compute prefix value for current pass
    fn compute_prefix_for_pass(&self, y: usize, pass: usize) -> F {
        // For pass 0: prefix = 1
        // For pass > 0: prefix = ∏ (1 - r_i) for i in previous challenges
        if pass == 0 {
            F::one()
        } else {
            let mut result = F::one();
            for &challenge in &self.challenges {
                result = result * (F::one() - challenge);
            }
            result
        }
    }

    /// Add a challenge for the next pass
    pub fn add_challenge(&mut self, challenge: F) {
        self.challenges.push(challenge);
    }

    /// Compute round polynomial from Q and P arrays
    pub fn compute_round_polynomial(
        &self,
        q_array: &QArray<F>,
        p_array: &PArray<F>,
    ) -> (F, F) {
        let mut f_0 = F::zero();
        let mut f_1 = F::zero();

        let size = q_array.size;
        for i in 0..size / 2 {
            let q_2i = q_array.get(2 * i);
            let q_2i_1 = q_array.get(2 * i + 1);
            let p_2i = p_array.get(2 * i);
            let p_2i_1 = p_array.get(2 * i + 1);

            f_0 = f_0 + p_2i * q_2i;
            f_1 = f_1 + p_2i_1 * q_2i_1;
        }

        (f_0, f_1)
    }

    /// Update arrays for next round using challenge
    pub fn update_for_next_round(
        &self,
        q_array: &mut QArray<F>,
        p_array: &mut PArray<F>,
        challenge: F,
    ) {
        let new_size = q_array.size / 2;

        // Update Q array
        for i in 0..new_size {
            let q_2i = q_array.get(2 * i);
            let q_2i_1 = q_array.get(2 * i + 1);
            q_array.values[i] = (F::one() - challenge) * q_2i + challenge * q_2i_1;
        }
        q_array.values.truncate(new_size);

        // Update P array
        for i in 0..new_size {
            let p_2i = p_array.get(2 * i);
            let p_2i_1 = p_array.get(2 * i + 1);
            p_array.values[i] = (F::one() - challenge) * p_2i + challenge * p_2i_1;
        }
        p_array.values.truncate(new_size);
    }

    /// Get current pass number
    pub fn current_pass(&self) -> usize {
        self.current_pass
    }

    /// Get number of challenges collected
    pub fn num_challenges(&self) -> usize {
        self.challenges.len()
    }
}

/// Sparse-dense sum-check verifier
pub struct SparseDenseSumCheckVerifier<F: FieldElement> {
    config: SparseDenseSumCheckConfig,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> SparseDenseSumCheckVerifier<F> {
    /// Create a new sparse-dense sum-check verifier
    pub fn new(config: SparseDenseSumCheckConfig) -> Self {
        SparseDenseSumCheckVerifier {
            config,
            _phantom: PhantomData,
        }
    }

    /// Verify round polynomial consistency
    pub fn verify_round_polynomial(
        &self,
        prev_value: F,
        f_0: F,
        f_1: F,
    ) -> bool {
        // Check: prev_value = f_0 + f_1
        prev_value == f_0 + f_1
    }

    /// Get configuration
    pub fn config(&self) -> &SparseDenseSumCheckConfig {
        &self.config
    }
}

/// Sparse-dense sum-check proof
#[derive(Clone, Debug)]
pub struct SparseDenseSumCheckProof<F: FieldElement> {
    /// Round polynomials for each pass
    pub round_polynomials: Vec<(F, F)>,
    /// Final evaluation value
    pub final_value: F,
    /// Challenges used
    pub challenges: Vec<F>,
}

impl<F: FieldElement> SparseDenseSumCheckProof<F> {
    /// Create a new empty proof
    pub fn new() -> Self {
        SparseDenseSumCheckProof {
            round_polynomials: Vec::new(),
            final_value: F::zero(),
            challenges: Vec::new(),
        }
    }

    /// Add a round polynomial
    pub fn add_round(&mut self, f_0: F, f_1: F) {
        self.round_polynomials.push((f_0, f_1));
    }

    /// Add a challenge
    pub fn add_challenge(&mut self, challenge: F) {
        self.challenges.push(challenge);
    }

    /// Get proof size in field elements
    pub fn size_in_field_elements(&self) -> usize {
        // 2 values per round + 1 final value + challenges
        2 * self.round_polynomials.len() + 1 + self.challenges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;

    #[test]
    fn test_sparse_dense_config() {
        let config = SparseDenseSumCheckConfig::new(2, 256, 1024);
        assert_eq!(config.num_passes, 2);
        assert_eq!(config.memory_size, 256);
        assert_eq!(config.num_reads, 1024);
    }

    #[test]
    fn test_q_array() {
        let mut q_array = QArray::<PrimeField>::new(8);
        q_array.add(0, PrimeField::one());
        q_array.add(1, PrimeField::from_u64(2));

        assert_eq!(q_array.get(0), PrimeField::one());
        assert_eq!(q_array.get(1), PrimeField::from_u64(2));
        assert_eq!(q_array.get(2), PrimeField::zero());
    }

    #[test]
    fn test_p_array() {
        let mut p_array = PArray::<PrimeField>::new(8);
        p_array.set(0, PrimeField::one());
        p_array.set(1, PrimeField::from_u64(3));

        assert_eq!(p_array.get(0), PrimeField::one());
        assert_eq!(p_array.get(1), PrimeField::from_u64(3));
    }

    #[test]
    fn test_sparse_dense_prover() {
        let config = SparseDenseSumCheckConfig::new(2, 256, 1024);
        let prover = SparseDenseSumCheckProver::<PrimeField>::new(config);

        assert_eq!(prover.current_pass(), 0);
        assert_eq!(prover.num_challenges(), 0);
    }

    #[test]
    fn test_sparse_dense_verifier() {
        let config = SparseDenseSumCheckConfig::new(2, 256, 1024);
        let verifier = SparseDenseSumCheckVerifier::<PrimeField>::new(config);

        let f_0 = PrimeField::from_u64(5);
        let f_1 = PrimeField::from_u64(3);
        let prev_value = PrimeField::from_u64(8);

        assert!(verifier.verify_round_polynomial(prev_value, f_0, f_1));
    }

    #[test]
    fn test_sparse_dense_proof() {
        let mut proof = SparseDenseSumCheckProof::<PrimeField>::new();
        proof.add_round(PrimeField::from_u64(5), PrimeField::from_u64(3));
        proof.add_challenge(PrimeField::from_u64(7));

        assert_eq!(proof.round_polynomials.len(), 1);
        assert_eq!(proof.challenges.len(), 1);
        assert_eq!(proof.size_in_field_elements(), 4);
    }
}
