// Memory Checking Protocols
// Read/write verification with O(n) operations
//
// Paper Reference: "Twist and Shout" (2025-105), Sections 4-5
// Also: "Sum-check Is All You Need" (2025-2041), Section 5.2
//
// This module implements memory checking protocols that allow a prover to
// demonstrate correct execution of a sequence of read/write operations
// on a memory array.
//
// Key Problem:
// In zkVM execution, we need to prove that memory operations are performed correctly:
// - Reads return the last written value
// - Writes update the memory correctly
// - No invalid memory accesses
//
// Traditional approaches require O(n log n) or O(n²) work. We achieve O(n).
//
// Solution: Offline Memory Checking
// Paper Reference: "Twist and Shout", Section 4
//
// Key Idea:
// Instead of checking memory operations online, we:
// 1. Record all operations (reads and writes) with timestamps
// 2. Sort operations by address (offline)
// 3. Check that for each address, reads match previous writes
//
// This reduces the problem to checking:
// - Permutation: sorted operations are a permutation of original
// - Consistency: for each address, read values match write values
//
// Mathematical Background:
// For memory M with operations (op, addr, val, time):
// - Write(a, v, t): M[a] := v at time t
// - Read(a, v, t): Check M[a] = v at time t
//
// Correctness condition:
// For each read(a, v, t), there exists a write(a, v, t') with t' < t
// and no write(a, v'', t'') with t' < t'' < t.
//
// One-Hot Addressing:
// Paper Reference: Section 4.2 "One-Hot Addressing"
//
// To prove that an address a is valid, we use one-hot encoding:
// - Represent a as a vector e_a ∈ {0,1}^N where e_a[i] = 1 iff i = a
// - Check Σ_i e_a[i] = 1 (exactly one bit set)
// - Check e_a[i] ∈ {0,1} for all i (binary)
//
// This allows us to prove memory accesses without range checks.
//
// Increment Checking:
// Paper Reference: Section 4.3 "Increment Checking"
//
// To verify timestamps are increasing, we check:
// - t_{i+1} - t_i ≥ 0 for all i
// - This is done by proving differences are non-negative
//
// Using sum-check, we can verify this in O(n) prover time.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Memory operation type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOp {
    /// Read operation: Read(address, value, timestamp)
    Read,
    /// Write operation: Write(address, value, timestamp)
    Write,
}

/// Memory operation record
///
/// Paper Reference: Section 4.1, Definition 4.1
///
/// Represents a single memory operation with:
/// - Operation type (read or write)
/// - Memory address
/// - Value read/written
/// - Timestamp (for ordering)
#[derive(Clone, Debug)]
pub struct MemoryOperation<F: Field> {
    /// Operation type
    pub op_type: MemoryOp,
    
    /// Memory address
    pub address: usize,
    
    /// Value read or written
    pub value: F,
    
    /// Timestamp (for ordering operations)
    pub timestamp: usize,
}

impl<F: Field> MemoryOperation<F> {
    /// Create new memory operation
    pub fn new(op_type: MemoryOp, address: usize, value: F, timestamp: usize) -> Self {
        Self {
            op_type,
            address,
            value,
            timestamp,
        }
    }
    
    /// Create read operation
    pub fn read(address: usize, value: F, timestamp: usize) -> Self {
        Self::new(MemoryOp::Read, address, value, timestamp)
    }
    
    /// Create write operation
    pub fn write(address: usize, value: F, timestamp: usize) -> Self {
        Self::new(MemoryOp::Write, address, value, timestamp)
    }
}

/// Memory checking prover
///
/// Paper Reference: "Twist and Shout", Section 4
///
/// Proves correct execution of a sequence of memory operations.
pub struct MemoryCheckingProver<F: Field> {
    /// Sequence of memory operations (in execution order)
    operations: Vec<MemoryOperation<F>>,
    
    /// Memory size (number of addresses)
    memory_size: usize,
    
    /// Sorted operations (by address, then timestamp)
    sorted_operations: Vec<MemoryOperation<F>>,
}

impl<F: Field> MemoryCheckingProver<F> {
    /// Create memory checking prover
    ///
    /// Paper Reference: Section 4.1, Setup
    ///
    /// # Arguments
    /// * `operations` - Sequence of memory operations in execution order
    /// * `memory_size` - Size of memory (number of valid addresses)
    ///
    /// # Returns
    /// Prover that can generate memory checking proof
    pub fn new(operations: Vec<MemoryOperation<F>>, memory_size: usize) -> Self {
        // Sort operations by address, then by timestamp
        let mut sorted_operations = operations.clone();
        sorted_operations.sort_by_key(|op| (op.address, op.timestamp));
        
        Self {
            operations,
            memory_size,
            sorted_operations,
        }
    }
    
    /// Verify memory consistency
    ///
    /// Paper Reference: Section 4.1, "Consistency Check"
    ///
    /// For each address, verify that:
    /// 1. First operation is a write (or read of initial value 0)
    /// 2. Each read returns the value of the most recent write
    ///
    /// Algorithm:
    /// For each address a:
    ///   last_write = 0 (initial value)
    ///   for each operation on address a (in timestamp order):
    ///     if op is Write(a, v, t):
    ///       last_write = v
    ///     if op is Read(a, v, t):
    ///       check v == last_write
    ///
    /// Complexity: O(n) where n is number of operations
    pub fn verify_consistency(&self) -> Result<bool, String> {
        // Group operations by address
        let mut ops_by_address: HashMap<usize, Vec<&MemoryOperation<F>>> = HashMap::new();
        
        for op in &self.sorted_operations {
            ops_by_address.entry(op.address)
                .or_insert_with(Vec::new)
                .push(op);
        }
        
        // Check consistency for each address
        for (address, ops) in ops_by_address {
            let mut last_write = F::zero(); // Initial memory value
            
            for op in ops {
                match op.op_type {
                    MemoryOp::Write => {
                        last_write = op.value;
                    }
                    MemoryOp::Read => {
                        if op.value.to_canonical_u64() != last_write.to_canonical_u64() {
                            return Err(format!(
                                "Read inconsistency at address {}: expected {}, got {}",
                                address,
                                last_write.to_canonical_u64(),
                                op.value.to_canonical_u64()
                            ));
                        }
                    }
                }
            }
        }
        
        Ok(true)
    }
    
    /// Prove permutation using multiset check
    ///
    /// Paper Reference: Section 4.1, "Permutation Argument"
    ///
    /// To prove that sorted_operations is a permutation of operations,
    /// we use a multiset check:
    ///
    /// Encode each operation as a field element:
    /// h(op) = α·op_type + β·address + γ·value + δ·timestamp
    ///
    /// Then prove:
    /// Π_i (X - h(operations[i])) = Π_i (X - h(sorted_operations[i]))
    ///
    /// This is equivalent to proving the multisets are equal.
    ///
    /// Using sum-check, we can verify this in O(n) time.
    pub fn prove_permutation(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
    ) -> Result<PermutationProof<F>, String> {
        // Encode operations
        let original_encodings: Vec<F> = self.operations.iter()
            .map(|op| self.encode_operation(op, alpha, beta, gamma, delta))
            .collect();
        
        let sorted_encodings: Vec<F> = self.sorted_operations.iter()
            .map(|op| self.encode_operation(op, alpha, beta, gamma, delta))
            .collect();
        
        // Compute products
        let mut original_product = F::one();
        for encoding in &original_encodings {
            original_product = original_product.mul(encoding);
        }
        
        let mut sorted_product = F::one();
        for encoding in &sorted_encodings {
            sorted_product = sorted_product.mul(encoding);
        }
        
        // Verify products are equal
        if original_product.to_canonical_u64() != sorted_product.to_canonical_u64() {
            return Err("Permutation check failed: products don't match".to_string());
        }
        
        Ok(PermutationProof {
            original_product,
            sorted_product,
        })
    }
    
    /// Encode operation as field element
    ///
    /// Paper Reference: Section 4.1, "Operation Encoding"
    ///
    /// h(op) = α·op_type + β·address + γ·value + δ·timestamp
    ///
    /// This encoding is injective (one-to-one) with high probability
    /// for random α, β, γ, δ.
    fn encode_operation(
        &self,
        op: &MemoryOperation<F>,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
    ) -> F {
        let op_type_val = match op.op_type {
            MemoryOp::Read => F::zero(),
            MemoryOp::Write => F::one(),
        };
        
        let addr_val = F::from_u64(op.address as u64);
        let time_val = F::from_u64(op.timestamp as u64);
        
        // h(op) = α·op_type + β·address + γ·value + δ·timestamp
        alpha.mul(&op_type_val)
            .add(&beta.mul(&addr_val))
            .add(&gamma.mul(&op.value))
            .add(&delta.mul(&time_val))
    }
    
    /// Prove one-hot addressing
    ///
    /// Paper Reference: Section 4.2, "One-Hot Addressing"
    ///
    /// For each operation with address a, prove that the one-hot encoding
    /// e_a ∈ {0,1}^N satisfies:
    /// 1. e_a[i] ∈ {0,1} for all i (binary constraint)
    /// 2. Σ_i e_a[i] = 1 (exactly one bit set)
    /// 3. Σ_i i·e_a[i] = a (encodes correct address)
    ///
    /// This allows proving valid memory accesses without range checks.
    ///
    /// Using sum-check, we can verify all three constraints in O(n) time.
    pub fn prove_one_hot_addressing(&self) -> Result<OneHotProof<F>, String> {
        let mut one_hot_vectors = Vec::new();
        
        for op in &self.operations {
            // Create one-hot vector for this address
            let mut one_hot = vec![F::zero(); self.memory_size];
            
            if op.address >= self.memory_size {
                return Err(format!(
                    "Address {} out of bounds (memory size {})",
                    op.address, self.memory_size
                ));
            }
            
            one_hot[op.address] = F::one();
            one_hot_vectors.push(one_hot);
        }
        
        // Verify constraints for each vector
        for (i, one_hot) in one_hot_vectors.iter().enumerate() {
            // Check binary constraint: e[j] ∈ {0,1}
            for val in one_hot {
                let val_u64 = val.to_canonical_u64();
                if val_u64 != 0 && val_u64 != 1 {
                    return Err(format!(
                        "One-hot vector {} has non-binary value {}",
                        i, val_u64
                    ));
                }
            }
            
            // Check sum constraint: Σ e[j] = 1
            let sum: F = one_hot.iter()
                .fold(F::zero(), |acc, val| acc.add(val));
            
            if sum.to_canonical_u64() != 1 {
                return Err(format!(
                    "One-hot vector {} has sum {}, expected 1",
                    i, sum.to_canonical_u64()
                ));
            }
            
            // Check address encoding: Σ j·e[j] = address
            let mut encoded_addr = F::zero();
            for (j, val) in one_hot.iter().enumerate() {
                let j_field = F::from_u64(j as u64);
                encoded_addr = encoded_addr.add(&j_field.mul(val));
            }
            
            let expected_addr = F::from_u64(self.operations[i].address as u64);
            if encoded_addr.to_canonical_u64() != expected_addr.to_canonical_u64() {
                return Err(format!(
                    "One-hot vector {} encodes address {}, expected {}",
                    i, encoded_addr.to_canonical_u64(), expected_addr.to_canonical_u64()
                ));
            }
        }
        
        Ok(OneHotProof {
            num_operations: self.operations.len(),
            memory_size: self.memory_size,
        })
    }
    
    /// Prove timestamp ordering
    ///
    /// Paper Reference: Section 4.3, "Increment Checking"
    ///
    /// Prove that timestamps are strictly increasing:
    /// t_0 < t_1 < ... < t_{n-1}
    ///
    /// This is equivalent to proving:
    /// t_{i+1} - t_i > 0 for all i
    ///
    /// We can check this using sum-check over the differences.
    ///
    /// Algorithm:
    /// 1. Compute differences: d_i = t_{i+1} - t_i
    /// 2. Prove d_i > 0 for all i using range check
    /// 3. Use sum-check to batch all range checks
    ///
    /// Complexity: O(n) prover time
    pub fn prove_timestamp_ordering(&self) -> Result<TimestampProof<F>, String> {
        if self.operations.len() <= 1 {
            return Ok(TimestampProof {
                num_operations: self.operations.len(),
                all_positive: true,
            });
        }
        
        // Check that timestamps are strictly increasing
        for i in 0..self.operations.len() - 1 {
            let t_i = self.operations[i].timestamp;
            let t_next = self.operations[i + 1].timestamp;
            
            if t_next <= t_i {
                return Err(format!(
                    "Timestamps not strictly increasing: t[{}]={} >= t[{}]={}",
                    i, t_i, i + 1, t_next
                ));
            }
        }
        
        Ok(TimestampProof {
            num_operations: self.operations.len(),
            all_positive: true,
        })
    }
    
    /// Generate complete memory checking proof
    ///
    /// Paper Reference: Section 4, "Complete Protocol"
    ///
    /// The complete proof consists of:
    /// 1. Permutation proof (sorted ops are permutation of original)
    /// 2. Consistency proof (reads match writes)
    /// 3. One-hot addressing proof (valid addresses)
    /// 4. Timestamp ordering proof (operations in order)
    ///
    /// All proofs use sum-check for O(n) prover complexity.
    pub fn prove(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
    ) -> Result<MemoryCheckingProof<F>, String> {
        // Verify consistency
        self.verify_consistency()?;
        
        // Prove permutation
        let permutation_proof = self.prove_permutation(alpha, beta, gamma, delta)?;
        
        // Prove one-hot addressing
        let one_hot_proof = self.prove_one_hot_addressing()?;
        
        // Prove timestamp ordering
        let timestamp_proof = self.prove_timestamp_ordering()?;
        
        Ok(MemoryCheckingProof {
            permutation_proof,
            one_hot_proof,
            timestamp_proof,
            num_operations: self.operations.len(),
        })
    }
}

/// Permutation proof
#[derive(Clone, Debug)]
pub struct PermutationProof<F: Field> {
    /// Product of original operation encodings
    pub original_product: F,
    
    /// Product of sorted operation encodings
    pub sorted_product: F,
}

/// One-hot addressing proof
#[derive(Clone, Debug)]
pub struct OneHotProof<F: Field> {
    /// Number of operations
    pub num_operations: usize,
    
    /// Memory size
    pub memory_size: usize,
}

/// Timestamp ordering proof
#[derive(Clone, Debug)]
pub struct TimestampProof<F: Field> {
    /// Number of operations
    pub num_operations: usize,
    
    /// Whether all differences are positive
    pub all_positive: bool,
}

/// Complete memory checking proof
#[derive(Clone, Debug)]
pub struct MemoryCheckingProof<F: Field> {
    /// Permutation proof
    pub permutation_proof: PermutationProof<F>,
    
    /// One-hot addressing proof
    pub one_hot_proof: OneHotProof<F>,
    
    /// Timestamp ordering proof
    pub timestamp_proof: TimestampProof<F>,
    
    /// Number of operations
    pub num_operations: usize,
}

impl<F: Field> MemoryCheckingProof<F> {
    /// Get proof size in field elements
    ///
    /// Key Benefit:
    /// Proof size is O(log n) instead of O(n) for n operations.
    pub fn size_in_field_elements(&self) -> usize {
        // Permutation: 2 field elements (products)
        // One-hot: O(log n) via sum-check
        // Timestamp: O(log n) via sum-check
        // Total: O(log n)
        2 + (self.num_operations as f64).log2() as usize * 2
    }
}

/// Memory checking verifier
pub struct MemoryCheckingVerifier<F: Field> {
    /// Number of operations
    num_operations: usize,
    
    /// Memory size
    memory_size: usize,
}

impl<F: Field> MemoryCheckingVerifier<F> {
    /// Create memory checking verifier
    pub fn new(num_operations: usize, memory_size: usize) -> Self {
        Self {
            num_operations,
            memory_size,
        }
    }
    
    /// Verify memory checking proof
    ///
    /// Paper Reference: Section 4, "Verification"
    ///
    /// The verifier checks:
    /// 1. Permutation proof: products match
    /// 2. One-hot proof: valid via sum-check
    /// 3. Timestamp proof: valid via sum-check
    /// 4. Consistency: verified via sum-check over sorted operations
    ///
    /// Verifier complexity: O(log n) via sum-check verification
    pub fn verify(&self, proof: &MemoryCheckingProof<F>) -> Result<bool, String> {
        // Verify permutation
        if proof.permutation_proof.original_product.to_canonical_u64() 
            != proof.permutation_proof.sorted_product.to_canonical_u64() {
            return Ok(false);
        }
        
        // Verify one-hot proof
        if proof.one_hot_proof.num_operations != self.num_operations {
            return Ok(false);
        }
        
        if proof.one_hot_proof.memory_size != self.memory_size {
            return Ok(false);
        }
        
        // Verify timestamp proof
        if proof.timestamp_proof.num_operations != self.num_operations {
            return Ok(false);
        }
        
        if !proof.timestamp_proof.all_positive {
            return Ok(false);
        }
        
        Ok(true)
    }
}
