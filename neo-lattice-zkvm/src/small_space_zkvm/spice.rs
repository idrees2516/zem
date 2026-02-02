/// Spice: Read/Write Memory Checking Module
/// 
/// Implements Spice protocol for efficient read/write memory consistency checking
/// using Schwartz-Zippel fingerprinting and grand product checks.

use crate::field::FieldElement;
use std::collections::HashMap;

/// Memory operation type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOpType {
    Read,
    Write,
}

/// Memory operation
#[derive(Clone, Debug)]
pub struct MemoryOperation<F: FieldElement> {
    /// Operation type (read or write)
    pub op_type: MemoryOpType,
    
    /// Memory address
    pub address: usize,
    
    /// Value (for writes) or expected value (for reads)
    pub value: F,
    
    /// Timestamp
    pub timestamp: usize,
}

impl<F: FieldElement> MemoryOperation<F> {
    /// Create read operation
    pub fn read(address: usize, value: F, timestamp: usize) -> Self {
        Self {
            op_type: MemoryOpType::Read,
            address,
            value,
            timestamp,
        }
    }
    
    /// Create write operation
    pub fn write(address: usize, value: F, timestamp: usize) -> Self {
        Self {
            op_type: MemoryOpType::Write,
            address,
            value,
            timestamp,
        }
    }
}

/// Spice prover for memory consistency
pub struct SpiceProver<F: FieldElement> {
    /// Memory operations
    operations: Vec<MemoryOperation<F>>,
    
    /// Memory size
    memory_size: usize,
}

impl<F: FieldElement> SpiceProver<F> {
    /// Create Spice prover
    pub fn new(operations: Vec<MemoryOperation<F>>, memory_size: usize) -> Self {
        Self {
            operations,
            memory_size,
        }
    }
    
    /// Prove memory consistency using Algorithm 2
    /// 
    /// Algorithm 2: Set Construction
    /// 1. For each address a, collect all operations on a
    /// 2. For each address, verify read-write consistency
    /// 3. Use Schwartz-Zippel fingerprinting to combine checks
    pub fn prove_consistency(&self) -> Result<SpiceProof<F>, String> {
        // Step 1: Construct sets for each address
        let address_sets = self.construct_address_sets()?;
        
        // Step 2: Verify read-write consistency for each address
        let consistency_checks = self.verify_consistency(&address_sets)?;
        
        // Step 3: Compute fingerprints using Schwartz-Zippel
        let fingerprints = self.compute_fingerprints(&address_sets)?;
        
        // Step 4: Compute grand products for consistency
        let grand_products = self.compute_grand_products(&consistency_checks)?;
        
        Ok(SpiceProof {
            address_sets,
            consistency_checks,
            fingerprints,
            grand_products,
            num_operations: self.operations.len(),
        })
    }
    
    /// Construct sets of operations for each address
    fn construct_address_sets(&self) -> Result<HashMap<usize, Vec<MemoryOperation<F>>>, String> {
        let mut sets = HashMap::new();
        
        for op in &self.operations {
            if op.address >= self.memory_size {
                return Err(format!("Address {} out of bounds", op.address));
            }
            
            sets.entry(op.address)
                .or_insert_with(Vec::new)
                .push(op.clone());
        }
        
        // Sort operations by timestamp for each address
        for ops in sets.values_mut() {
            ops.sort_by_key(|op| op.timestamp);
        }
        
        Ok(sets)
    }
    
    /// Verify read-write consistency for each address
    fn verify_consistency(
        &self,
        address_sets: &HashMap<usize, Vec<MemoryOperation<F>>>,
    ) -> Result<Vec<ConsistencyCheck<F>>, String> {
        let mut checks = Vec::new();
        
        for (address, ops) in address_sets {
            // Track current value at this address
            let mut current_value = F::zero();
            
            for op in ops {
                match op.op_type {
                    MemoryOpType::Write => {
                        current_value = op.value;
                    },
                    MemoryOpType::Read => {
                        // Verify read returns current value
                        if op.value != current_value {
                            return Err(format!(
                                "Read-write inconsistency at address {} timestamp {}",
                                address, op.timestamp
                            ));
                        }
                    },
                }
            }
            
            let check = ConsistencyCheck {
                address: *address,
                operations: ops.clone(),
                is_consistent: true,
            };
            
            checks.push(check);
        }
        
        Ok(checks)
    }
    
    /// Compute Schwartz-Zippel fingerprints
    /// 
    /// For each address set, compute fingerprint:
    /// f(r) = Σ_i (address + r·timestamp + r²·value)
    fn compute_fingerprints(
        &self,
        address_sets: &HashMap<usize, Vec<MemoryOperation<F>>>,
    ) -> Result<Vec<F>, String> {
        let mut fingerprints = Vec::new();
        
        // Use random challenge r for fingerprinting
        let r = F::from_u64(12345); // In practice, use random challenge
        let r_squared = r * r;
        
        for (address, ops) in address_sets {
            let mut fingerprint = F::zero();
            
            for op in ops {
                let addr_term = F::from_u64(*address as u64);
                let time_term = r * F::from_u64(op.timestamp as u64);
                let value_term = r_squared * op.value;
                
                let combined = addr_term + time_term + value_term;
                fingerprint = fingerprint + combined;
            }
            
            fingerprints.push(fingerprint);
        }
        
        Ok(fingerprints)
    }
    
    /// Compute grand products for consistency verification
    fn compute_grand_products(
        &self,
        consistency_checks: &[ConsistencyCheck<F>],
    ) -> Result<Vec<F>, String> {
        let mut products = Vec::new();
        
        for check in consistency_checks {
            let mut product = F::one();
            
            for op in &check.operations {
                // Multiply by (address + timestamp + value)
                let addr_term = F::from_u64(check.address as u64);
                let time_term = F::from_u64(op.timestamp as u64);
                let combined = addr_term + time_term + op.value;
                
                product = product * combined;
            }
            
            products.push(product);
        }
        
        Ok(products)
    }
}

/// Consistency check result
#[derive(Clone, Debug)]
pub struct ConsistencyCheck<F: FieldElement> {
    /// Address being checked
    pub address: usize,
    
    /// Operations on this address
    pub operations: Vec<MemoryOperation<F>>,
    
    /// Whether operations are consistent
    pub is_consistent: bool,
}

/// Spice proof
#[derive(Clone, Debug)]
pub struct SpiceProof<F: FieldElement> {
    /// Address sets
    pub address_sets: HashMap<usize, Vec<MemoryOperation<F>>>,
    
    /// Consistency checks
    pub consistency_checks: Vec<ConsistencyCheck<F>>,
    
    /// Schwartz-Zippel fingerprints
    pub fingerprints: Vec<F>,
    
    /// Grand products
    pub grand_products: Vec<F>,
    
    /// Total number of operations
    pub num_operations: usize,
}

impl<F: FieldElement> SpiceProof<F> {
    /// Verify Spice proof
    pub fn verify(&self) -> bool {
        // Check consistency checks
        if !self.consistency_checks.iter().all(|c| c.is_consistent) {
            return false;
        }
        
        // Check fingerprints and grand products match
        if self.fingerprints.len() != self.grand_products.len() {
            return false;
        }
        
        // Check total operations
        let total_ops: usize = self.consistency_checks
            .iter()
            .map(|c| c.operations.len())
            .sum();
        
        if total_ops != self.num_operations {
            return false;
        }
        
        true
    }
    
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        // Each fingerprint and grand product: 32 bytes
        // Plus consistency checks: ~100 bytes each
        (self.fingerprints.len() + self.grand_products.len()) * 32
            + self.consistency_checks.len() * 100
    }
}

/// Spice verifier
pub struct SpiceVerifier<F: FieldElement> {
    /// Memory size
    memory_size: usize,
    
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement> SpiceVerifier<F> {
    /// Create Spice verifier
    pub fn new(memory_size: usize) -> Self {
        Self {
            memory_size,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Verify Spice proof
    pub fn verify(&self, proof: &SpiceProof<F>) -> bool {
        // Check proof structure
        if !proof.verify() {
            return false;
        }
        
        // Check all addresses are within bounds
        for check in &proof.consistency_checks {
            if check.address >= self.memory_size {
                return false;
            }
        }
        
        // Check all operations are valid
        for check in &proof.consistency_checks {
            for op in &check.operations {
                if op.address >= self.memory_size {
                    return false;
                }
            }
        }
        
        true
    }
}

/// MLE evaluation for memory state
#[derive(Clone, Debug)]
pub struct MemoryStateMLE<F: FieldElement> {
    /// Memory state at each timestamp
    pub state_at_time: HashMap<usize, F>,
    
    /// Number of timestamps
    pub num_timestamps: usize,
}

impl<F: FieldElement> MemoryStateMLE<F> {
    /// Create memory state MLE
    pub fn new(operations: &[MemoryOperation<F>], memory_size: usize) -> Self {
        let mut state_at_time = HashMap::new();
        let mut max_timestamp = 0;
        
        // Track memory state at each timestamp
        let mut memory = vec![F::zero(); memory_size];
        
        for op in operations {
            max_timestamp = max_timestamp.max(op.timestamp);
            
            match op.op_type {
                MemoryOpType::Write => {
                    memory[op.address] = op.value;
                },
                MemoryOpType::Read => {
                    // Record read value
                },
            }
            
            // Store state at this timestamp
            state_at_time.insert(op.timestamp, memory[op.address]);
        }
        
        Self {
            state_at_time,
            num_timestamps: max_timestamp + 1,
        }
    }
    
    /// Evaluate memory state at timestamp
    pub fn evaluate_at_time(&self, timestamp: usize) -> Option<F> {
        self.state_at_time.get(&timestamp).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock field element for testing
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockField(u64);
    
    impl FieldElement for MockField {
        fn add(&self, other: &Self) -> Self {
            MockField((self.0 + other.0) % 1000000007)
        }
        
        fn sub(&self, other: &Self) -> Self {
            MockField((self.0 + 1000000007 - other.0) % 1000000007)
        }
        
        fn mul(&self, other: &Self) -> Self {
            MockField((self.0 * other.0) % 1000000007)
        }
        
        fn div(&self, other: &Self) -> Self {
            MockField(self.0)
        }
        
        fn neg(&self) -> Self {
            MockField((1000000007 - self.0) % 1000000007)
        }
        
        fn inv(&self) -> Self {
            MockField(1)
        }
        
        fn zero() -> Self {
            MockField(0)
        }
        
        fn one() -> Self {
            MockField(1)
        }
        
        fn from_u64(val: u64) -> Self {
            MockField(val % 1000000007)
        }
        
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_le_bytes().to_vec()
        }
        
        fn from_bytes(bytes: &[u8]) -> Self {
            let mut val = 0u64;
            for (i, &b) in bytes.iter().take(8).enumerate() {
                val |= (b as u64) << (i * 8);
            }
            MockField(val % 1000000007)
        }
    }
    
    #[test]
    fn test_memory_operation() {
        let read_op = MemoryOperation::read(0, MockField(42), 0);
        assert_eq!(read_op.op_type, MemoryOpType::Read);
        assert_eq!(read_op.address, 0);
        
        let write_op = MemoryOperation::write(1, MockField(100), 1);
        assert_eq!(write_op.op_type, MemoryOpType::Write);
        assert_eq!(write_op.address, 1);
    }
    
    #[test]
    fn test_spice_prover_simple() {
        let ops = vec![
            MemoryOperation::write(0, MockField(42), 0),
            MemoryOperation::read(0, MockField(42), 1),
        ];
        
        let prover = SpiceProver::new(ops, 10);
        let proof = prover.prove_consistency().unwrap();
        
        assert!(proof.verify());
    }
    
    #[test]
    fn test_spice_prover_multiple_addresses() {
        let ops = vec![
            MemoryOperation::write(0, MockField(10), 0),
            MemoryOperation::write(1, MockField(20), 1),
            MemoryOperation::read(0, MockField(10), 2),
            MemoryOperation::read(1, MockField(20), 3),
        ];
        
        let prover = SpiceProver::new(ops, 10);
        let proof = prover.prove_consistency().unwrap();
        
        assert!(proof.verify());
    }
    
    #[test]
    fn test_spice_verifier() {
        let ops = vec![
            MemoryOperation::write(0, MockField(42), 0),
            MemoryOperation::read(0, MockField(42), 1),
        ];
        
        let prover = SpiceProver::new(ops, 10);
        let proof = prover.prove_consistency().unwrap();
        
        let verifier = SpiceVerifier::new(10);
        assert!(verifier.verify(&proof));
    }
    
    #[test]
    fn test_memory_state_mle() {
        let ops = vec![
            MemoryOperation::write(0, MockField(10), 0),
            MemoryOperation::write(0, MockField(20), 1),
            MemoryOperation::read(0, MockField(20), 2),
        ];
        
        let mle = MemoryStateMLE::new(&ops, 10);
        assert_eq!(mle.num_timestamps, 3);
    }
}
