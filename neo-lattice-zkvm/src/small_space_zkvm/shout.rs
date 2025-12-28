// Shout Protocol: Read-Only Memory Checking
//
// This module implements the Shout protocol for verifying read-only memory access patterns.
// The protocol uses one-hot address encoding and sum-check to verify that:
// 1. All addresses are valid (one-hot encoded)
// 2. All reads return correct values from memory
// 3. All addresses have exactly one 1 bit (Hamming weight one)
//
// Reference: "Twist and Shout: Faster memory checking arguments via one-hot addressing
// and increments" (2025-105)

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::mle::MultilinearExtension;
use crate::small_space_zkvm::equality::EqualityFunction;
use crate::small_space_zkvm::sum_check::{PolynomialOracle, SumCheckProver, SumCheckVerifier};
use std::collections::HashMap;
use std::marker::PhantomData;

/// Configuration for the Shout protocol
#[derive(Clone, Debug)]
pub struct ShoutConfig {
    /// Memory size K (number of addressable locations)
    pub memory_size: usize,
    /// Number of read operations T
    pub num_reads: usize,
    /// Dimension parameter d for commitment scheme
    pub dimension: usize,
}

impl ShoutConfig {
    /// Create a new Shout configuration
    pub fn new(memory_size: usize, num_reads: usize, dimension: usize) -> Self {
        ShoutConfig {
            memory_size,
            num_reads,
            dimension,
        }
    }

    /// Compute log₂(memory_size)
    pub fn log_memory_size(&self) -> usize {
        (self.memory_size as f64).log2().ceil() as usize
    }

    /// Compute log₂(num_reads)
    pub fn log_num_reads(&self) -> usize {
        (self.num_reads as f64).log2().ceil() as usize
    }

    /// Compute key size in group elements for elliptic curves
    /// Key size = 2√(K^(1/d)·T)
    pub fn elliptic_curve_key_size(&self) -> usize {
        let k_factor = (self.memory_size as f64).powf(1.0 / self.dimension as f64);
        let t_factor = self.num_reads as f64;
        let product = k_factor * t_factor;
        (2.0 * product.sqrt()) as usize
    }

    /// Validate configuration parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.memory_size == 0 {
            return Err("Memory size must be positive".to_string());
        }
        if self.num_reads == 0 {
            return Err("Number of reads must be positive".to_string());
        }
        if self.dimension == 0 {
            return Err("Dimension must be positive".to_string());
        }
        if self.dimension > 10 {
            return Err("Dimension too large (> 10)".to_string());
        }
        Ok(())
    }
}

/// Trait for providing read addresses
pub trait AddressOracle {
    /// Get the address for read j
    fn get_address(&self, j: usize) -> usize;

    /// Get the k-th bit of the address for read j
    fn get_address_bit(&self, j: usize, k: usize) -> bool;

    /// Get memory size
    fn memory_size(&self) -> usize;

    /// Get number of reads
    fn num_reads(&self) -> usize;
}

/// Trait for providing memory values
pub trait MemoryOracle<F: FieldElement> {
    /// Get the value stored at memory location k
    fn get_memory_value(&self, k: usize) -> F;

    /// Get memory size
    fn memory_size(&self) -> usize;
}

/// Simple in-memory implementation of AddressOracle
pub struct SimpleAddressOracle {
    addresses: Vec<usize>,
    memory_size: usize,
}

impl SimpleAddressOracle {
    /// Create a new simple address oracle
    pub fn new(addresses: Vec<usize>, memory_size: usize) -> Self {
        SimpleAddressOracle {
            addresses,
            memory_size,
        }
    }
}

impl AddressOracle for SimpleAddressOracle {
    fn get_address(&self, j: usize) -> usize {
        self.addresses[j]
    }

    fn get_address_bit(&self, j: usize, k: usize) -> bool {
        let addr = self.addresses[j];
        (addr >> k) & 1 == 1
    }

    fn memory_size(&self) -> usize {
        self.memory_size
    }

    fn num_reads(&self) -> usize {
        self.addresses.len()
    }
}

/// Simple in-memory implementation of MemoryOracle
pub struct SimpleMemoryOracle<F: FieldElement> {
    values: Vec<F>,
}

impl<F: FieldElement> SimpleMemoryOracle<F> {
    /// Create a new simple memory oracle
    pub fn new(values: Vec<F>) -> Self {
        SimpleMemoryOracle { values }
    }
}

impl<F: FieldElement> MemoryOracle<F> for SimpleMemoryOracle<F> {
    fn get_memory_value(&self, k: usize) -> F {
        self.values[k]
    }

    fn memory_size(&self) -> usize {
        self.values.len()
    }
}

/// One-hot address encoding
/// For address k, the one-hot encoding is a vector where position k is 1 and all others are 0
pub struct OneHotAddressEncoding<F: FieldElement> {
    /// Multilinear extension of read addresses in one-hot form
    /// r̃a: F^(T·K) where r̃a(k,j) = 1 if address j reads from location k, 0 otherwise
    pub encoding: Vec<F>,
    memory_size: usize,
    num_reads: usize,
}

impl<F: FieldElement> OneHotAddressEncoding<F> {
    /// Create one-hot encoding from addresses
    pub fn new(
        address_oracle: &dyn AddressOracle,
        memory_size: usize,
        num_reads: usize,
    ) -> Self {
        let mut encoding = vec![F::zero(); memory_size * num_reads];

        for j in 0..num_reads {
            let addr = address_oracle.get_address(j);
            if addr < memory_size {
                encoding[addr * num_reads + j] = F::one();
            }
        }

        OneHotAddressEncoding {
            encoding,
            memory_size,
            num_reads,
        }
    }

    /// Get the one-hot encoding value at position (k, j)
    pub fn get(&self, k: usize, j: usize) -> F {
        if k < self.memory_size && j < self.num_reads {
            self.encoding[k * self.num_reads + j]
        } else {
            F::zero()
        }
    }

    /// Verify that all entries are in {0, 1}
    pub fn verify_booleanity(&self) -> bool {
        for &val in &self.encoding {
            if val != F::zero() && val != F::one() {
                return false;
            }
        }
        true
    }

    /// Verify that each read has exactly one 1 (Hamming weight one)
    pub fn verify_hamming_weight_one(&self) -> bool {
        for j in 0..self.num_reads {
            let mut count = 0;
            for k in 0..self.memory_size {
                if self.get(k, j) == F::one() {
                    count += 1;
                }
            }
            if count != 1 {
                return false;
            }
        }
        true
    }
}

/// Read-checking oracle for Shout protocol
/// Computes r̃v(r) = Σ_{(k,j)} eq̃(r,j)·r̃a(k,j)·M̃(k)
pub struct ReadCheckingOracle<F: FieldElement> {
    address_encoding: Vec<F>,
    memory_oracle: Box<dyn Fn(usize) -> F>,
    memory_size: usize,
    num_reads: usize,
    log_memory_size: usize,
    log_num_reads: usize,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> ReadCheckingOracle<F> {
    /// Create a new read-checking oracle
    pub fn new(
        address_encoding: Vec<F>,
        memory_oracle: Box<dyn Fn(usize) -> F>,
        memory_size: usize,
        num_reads: usize,
    ) -> Self {
        let log_memory_size = (memory_size as f64).log2().ceil() as usize;
        let log_num_reads = (num_reads as f64).log2().ceil() as usize;

        ReadCheckingOracle {
            address_encoding,
            memory_oracle,
            memory_size,
            num_reads,
            log_memory_size,
            log_num_reads,
            _phantom: PhantomData,
        }
    }

    /// Compute the read-checking polynomial at a point
    /// This is used internally by the sum-check protocol
    pub fn evaluate_at_point(&self, point: &[F]) -> F {
        // This would be called by the sum-check oracle
        // For now, return zero as placeholder
        F::zero()
    }
}

/// Booleanity-checking oracle for Shout protocol
/// Verifies that all address encoding entries are in {0, 1}
pub struct BooleanityCheckingOracle<F: FieldElement> {
    address_encoding: Vec<F>,
    memory_size: usize,
    num_reads: usize,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> BooleanityCheckingOracle<F> {
    /// Create a new booleanity-checking oracle
    pub fn new(address_encoding: Vec<F>, memory_size: usize, num_reads: usize) -> Self {
        BooleanityCheckingOracle {
            address_encoding,
            memory_size,
            num_reads,
            _phantom: PhantomData,
        }
    }

    /// Compute the booleanity-checking polynomial
    /// Σ_{(k,j)} r̃a(k,j)·(1 - r̃a(k,j))
    /// This should equal 0 if all entries are in {0, 1}
    pub fn compute_sum(&self) -> F {
        let mut sum = F::zero();
        for &val in &self.address_encoding {
            let one_minus_val = F::one() - val;
            sum = sum + val * one_minus_val;
        }
        sum
    }
}

/// Hamming-weight-one checking oracle for Shout protocol
/// Verifies that each read address has exactly one 1 bit
pub struct HammingWeightOneOracle<F: FieldElement> {
    address_encoding: Vec<F>,
    memory_size: usize,
    num_reads: usize,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> HammingWeightOneOracle<F> {
    /// Create a new Hamming-weight-one oracle
    pub fn new(address_encoding: Vec<F>, memory_size: usize, num_reads: usize) -> Self {
        HammingWeightOneOracle {
            address_encoding,
            memory_size,
            num_reads,
            _phantom: PhantomData,
        }
    }

    /// Compute the Hamming-weight-one polynomial for a specific read j
    /// Σ_k r̃a(k,j) should equal 1 for all j
    pub fn compute_sum_for_read(&self, j: usize) -> F {
        let mut sum = F::zero();
        for k in 0..self.memory_size {
            let idx = k * self.num_reads + j;
            if idx < self.address_encoding.len() {
                sum = sum + self.address_encoding[idx];
            }
        }
        sum
    }

    /// Compute total sum: Σ_j (Σ_k r̃a(k,j) - 1)
    /// This should equal 0 if all reads have Hamming weight one
    pub fn compute_total_sum(&self) -> F {
        let mut total = F::zero();
        for j in 0..self.num_reads {
            let sum_for_j = self.compute_sum_for_read(j);
            total = total + sum_for_j - F::one();
        }
        total
    }
}

/// Phase 1 data structure for first log K rounds of read-checking
/// Maintains a table of size O(K) that is halved each round
pub struct Phase1DataStructure<F: FieldElement> {
    table: Vec<F>,
    memory_size: usize,
    num_reads: usize,
}

impl<F: FieldElement> Phase1DataStructure<F> {
    /// Create Phase1DataStructure from address encoding and memory oracle
    pub fn new(
        address_encoding: &[F],
        memory_oracle: &dyn Fn(usize) -> F,
        memory_size: usize,
        num_reads: usize,
    ) -> Self {
        let mut table = vec![F::zero(); memory_size];

        // Single pass over read addresses
        for j in 0..num_reads {
            for k in 0..memory_size {
                let idx = k * num_reads + j;
                if idx < address_encoding.len() && address_encoding[idx] == F::one() {
                    table[k] = table[k] + memory_oracle(k);
                }
            }
        }

        Phase1DataStructure {
            table,
            memory_size,
            num_reads,
        }
    }

    /// Get current table size
    pub fn size(&self) -> usize {
        self.table.len()
    }

    /// Compute round polynomial from current table
    /// For round 1: f(0) = Σ table[2i], f(1) = Σ table[2i+1]
    pub fn compute_round_polynomial(&self) -> (F, F) {
        let mut f_0 = F::zero();
        let mut f_1 = F::zero();

        for i in 0..self.table.len() / 2 {
            f_0 = f_0 + self.table[2 * i];
            f_1 = f_1 + self.table[2 * i + 1];
        }

        (f_0, f_1)
    }

    /// Update table for next round using challenge r
    pub fn update_for_next_round(&mut self, challenge: F) {
        let new_size = self.table.len() / 2;
        for i in 0..new_size {
            self.table[i] = (F::one() - challenge) * self.table[2 * i]
                + challenge * self.table[2 * i + 1];
        }
        self.table.truncate(new_size);
    }
}

/// Shout prover for read-only memory checking
pub struct ShoutProver<F: FieldElement> {
    config: ShoutConfig,
    address_encoding: Vec<F>,
    memory_oracle: Box<dyn Fn(usize) -> F>,
}

impl<F: FieldElement> ShoutProver<F> {
    /// Create a new Shout prover
    pub fn new(
        config: ShoutConfig,
        address_oracle: &dyn AddressOracle,
        memory_oracle: Box<dyn Fn(usize) -> F>,
    ) -> Result<Self, String> {
        config.validate()?;

        let address_encoding = {
            let mut enc = vec![F::zero(); config.memory_size * config.num_reads];
            for j in 0..config.num_reads {
                let addr = address_oracle.get_address(j);
                if addr < config.memory_size {
                    enc[addr * config.num_reads + j] = F::one();
                }
            }
            enc
        };

        Ok(ShoutProver {
            config,
            address_encoding,
            memory_oracle,
        })
    }

    /// Verify booleanity of address encoding
    pub fn verify_booleanity(&self) -> bool {
        for &val in &self.address_encoding {
            if val != F::zero() && val != F::one() {
                return false;
            }
        }
        true
    }

    /// Verify Hamming weight one for all reads
    pub fn verify_hamming_weight_one(&self) -> bool {
        for j in 0..self.config.num_reads {
            let mut count = 0;
            for k in 0..self.config.memory_size {
                let idx = k * self.config.num_reads + j;
                if idx < self.address_encoding.len() && self.address_encoding[idx] == F::one() {
                    count += 1;
                }
            }
            if count != 1 {
                return false;
            }
        }
        true
    }

    /// Get configuration
    pub fn config(&self) -> &ShoutConfig {
        &self.config
    }

    /// Get address encoding
    pub fn address_encoding(&self) -> &[F] {
        &self.address_encoding
    }

    /// Compute field operation count for Shout protocol
    /// Linear-time version: ~40T operations for instruction execution
    /// Small-space version: ~2T log T additional operations
    pub fn estimate_field_operations(&self) -> usize {
        let t = self.config.num_reads;
        let log_t = self.config.log_num_reads();

        // Linear-time: 40T
        let linear_ops = 40 * t;

        // Small-space: 2T log T
        let small_space_ops = 2 * t * log_t;

        linear_ops + small_space_ops
    }
}

/// Shout verifier for read-only memory checking
pub struct ShoutVerifier<F: FieldElement> {
    config: ShoutConfig,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> ShoutVerifier<F> {
    /// Create a new Shout verifier
    pub fn new(config: ShoutConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(ShoutVerifier {
            config,
            _phantom: PhantomData,
        })
    }

    /// Verify booleanity checking proof
    pub fn verify_booleanity_proof(&self, booleanity_sum: F) -> bool {
        // Booleanity sum should be 0 if all entries are in {0, 1}
        booleanity_sum == F::zero()
    }

    /// Verify Hamming weight one proof
    pub fn verify_hamming_weight_one_proof(&self, hamming_sum: F) -> bool {
        // Hamming weight sum should be 0 if all reads have weight one
        hamming_sum == F::zero()
    }

    /// Get configuration
    pub fn config(&self) -> &ShoutConfig {
        &self.config
    }
}

/// Shout proof structure
#[derive(Clone, Debug)]
pub struct ShoutProof<F: FieldElement> {
    /// Commitment to one-hot address encoding
    pub address_commitment: Vec<u8>,
    /// Booleanity checking sum-check proof
    pub booleanity_proof: Vec<F>,
    /// Hamming weight one sum-check proof
    pub hamming_weight_proof: Vec<F>,
    /// Read-checking sum-check proof
    pub read_checking_proof: Vec<F>,
    /// Final evaluation values
    pub final_evaluations: Vec<F>,
}

impl<F: FieldElement> ShoutProof<F> {
    /// Create a new empty Shout proof
    pub fn new() -> Self {
        ShoutProof {
            address_commitment: Vec::new(),
            booleanity_proof: Vec::new(),
            hamming_weight_proof: Vec::new(),
            read_checking_proof: Vec::new(),
            final_evaluations: Vec::new(),
        }
    }

    /// Get proof size in bytes (approximate)
    pub fn size_bytes(&self) -> usize {
        let field_size = 32; // Assuming 256-bit field elements
        self.address_commitment.len()
            + self.booleanity_proof.len() * field_size
            + self.hamming_weight_proof.len() * field_size
            + self.read_checking_proof.len() * field_size
            + self.final_evaluations.len() * field_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;

    #[test]
    fn test_shout_config_validation() {
        let config = ShoutConfig::new(256, 1000, 2);
        assert!(config.validate().is_ok());

        let invalid_config = ShoutConfig::new(0, 1000, 2);
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_one_hot_encoding() {
        let addresses = vec![0, 1, 2, 1, 0];
        let oracle = SimpleAddressOracle::new(addresses, 4);

        let encoding = OneHotAddressEncoding::<PrimeField>::new(&oracle, 4, 5);

        // Verify booleanity
        assert!(encoding.verify_booleanity());

        // Verify Hamming weight one
        assert!(encoding.verify_hamming_weight_one());
    }

    #[test]
    fn test_phase1_data_structure() {
        let addresses = vec![0, 1, 2, 1, 0];
        let oracle = SimpleAddressOracle::new(addresses, 4);

        let address_encoding = {
            let mut enc = vec![PrimeField::zero(); 4 * 5];
            for j in 0..5 {
                let addr = oracle.get_address(j);
                enc[addr * 5 + j] = PrimeField::one();
            }
            enc
        };

        let memory_oracle = Box::new(|k: usize| PrimeField::from_u64((k + 1) as u64));

        let phase1 = Phase1DataStructure::new(&address_encoding, &memory_oracle, 4, 5);

        assert_eq!(phase1.size(), 4);

        let (f_0, f_1) = phase1.compute_round_polynomial();
        assert!(f_0 != PrimeField::zero() || f_1 != PrimeField::zero());
    }

    #[test]
    fn test_booleanity_oracle() {
        let address_encoding = vec![
            PrimeField::one(),
            PrimeField::zero(),
            PrimeField::one(),
            PrimeField::zero(),
        ];

        let oracle = BooleanityCheckingOracle::new(address_encoding, 2, 2);
        let sum = oracle.compute_sum();

        assert_eq!(sum, PrimeField::zero());
    }

    #[test]
    fn test_hamming_weight_oracle() {
        let address_encoding = vec![
            PrimeField::one(),
            PrimeField::zero(),
            PrimeField::zero(),
            PrimeField::one(),
        ];

        let oracle = HammingWeightOneOracle::new(address_encoding, 2, 2);

        let sum_0 = oracle.compute_sum_for_read(0);
        let sum_1 = oracle.compute_sum_for_read(1);

        assert_eq!(sum_0, PrimeField::one());
        assert_eq!(sum_1, PrimeField::one());
    }

    #[test]
    fn test_shout_prover_creation() {
        let config = ShoutConfig::new(256, 1000, 2);
        let addresses = vec![0; 1000];
        let oracle = SimpleAddressOracle::new(addresses, 256);
        let memory_oracle = Box::new(|_k: usize| PrimeField::one());

        let prover = ShoutProver::new(config, &oracle, memory_oracle);
        assert!(prover.is_ok());
    }

    #[test]
    fn test_shout_verifier_creation() {
        let config = ShoutConfig::new(256, 1000, 2);
        let verifier = ShoutVerifier::<PrimeField>::new(config);
        assert!(verifier.is_ok());
    }
}
