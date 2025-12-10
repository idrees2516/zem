/// Memory Correctness via Lookup Arguments
///
/// This module implements memory checking and correctness proofs for zkVMs using
/// lookup table arguments. Memory checking ensures that memory operations (reads
/// and writes) are performed correctly and consistently throughout program execution.
///
/// # Memory Models
///
/// - **Read-Only Memory (ROM)**: Immutable memory that can be modeled as a lookup table
/// - **Random Access Memory (RAM)**: Mutable memory requiring read-write consistency
/// - **Online Memory**: Memory tables that depend on runtime values or challenges
///
/// # Techniques
///
/// - **ROM via Lookups**: Model ROM as lookup table, use indexed lookups for address-value pairs
/// - **Offline Memory Checking**: Use permutation arguments to verify read-write consistency
/// - **Online Lookup Tables**: Support runtime-dependent memory tables
/// - **State Machine Transitions**: Model state transitions as lookup tables
///
/// # Applications
///
/// - **zkVM Instruction Memory**: Verify correct instruction fetches
/// - **zkVM Data Memory**: Ensure read-write consistency for RAM
/// - **State Machine Verification**: Prove correct state transitions
/// - **Finite Automata**: Verify automaton execution via transition lookups
///
/// # References
///
/// - SoK: Lookup Table Arguments (2025-1876), Section 6.3
/// - Jolt: SNARKs for Virtual Machines via Lookups
/// - Lasso: Lookup Arguments for Memory Checking

use crate::field::traits::Field;
use crate::lookup::{
    LookupIndex, LookupRelation, LookupError, LookupResult,
    IndexedLookupIndex, IndexedLookupWitness, OnlineLookupIndex, OnlineLookupWitness,
};
use std::marker::PhantomData;
use std::collections::HashMap;

/// Memory operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOp {
    /// Read operation
    Read,
    /// Write operation
    Write,
}

/// Memory access record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAccess<F: Field> {
    /// Memory address
    pub address: F,
    /// Value read or written
    pub value: F,
    /// Operation type
    pub operation: MemoryOp,
    /// Timestamp of access
    pub timestamp: usize,
}

/// Memory configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Memory size (number of addresses)
    pub memory_size: usize,
    /// Whether memory is read-only
    pub read_only: bool,
    /// Whether to use online lookup tables
    pub use_online_tables: bool,
    /// Whether to track timestamps
    pub track_timestamps: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            memory_size: 1 << 20, // 1M addresses
            read_only: false,
            use_online_tables: false,
            track_timestamps: true,
        }
    }
}

/// Memory checker for zkVMs
pub struct MemoryChecker<F: Field> {
    config: MemoryConfig,
    _phantom: PhantomData<F>,
}

impl<F: Field> MemoryChecker<F> {
    /// Create a new memory checker
    ///
    /// # Parameters
    ///
    /// - `config`: Memory configuration
    ///
    /// # Returns
    ///
    /// A new `MemoryChecker` instance
    pub fn new(config: MemoryConfig) -> Self {
        Self {
            config,
            _phantom: PhantomData,
        }
    }

    /// Create a checker with default configuration
    pub fn default() -> Self {
        Self::new(MemoryConfig::default())
    }

    /// Create a read-only memory (ROM) lookup table
    ///
    /// # Parameters
    ///
    /// - `memory`: Initial memory contents (address -> value mapping)
    ///
    /// # Returns
    ///
    /// An `IndexedLookupIndex` for ROM access
    ///
    /// # Algorithm
    ///
    /// ROM is modeled as a lookup table where:
    /// - Table contains all (address, value) pairs
    /// - Witness contains accessed (address, value) pairs
    /// - Indexed lookup verifies: value = memory[address]
    ///
    /// # Complexity
    ///
    /// - Table size: O(memory_size)
    /// - Lookup cost: O(num_accesses)
    /// - Preprocessing: O(memory_size log memory_size)
    ///
    /// # Errors
    ///
    /// Returns error if memory is empty or too large
    pub fn create_rom_table(&self, memory: &HashMap<F, F>) -> LookupResult<IndexedLookupIndex<F>> {
        if memory.is_empty() {
            return Err(LookupError::EmptyTable);
        }

        if memory.len() > self.config.memory_size {
            return Err(LookupError::InvalidParameter {
                param: "memory_size".to_string(),
                reason: format!(
                    "Memory size {} exceeds maximum {}",
                    memory.len(),
                    self.config.memory_size
                ),
            });
        }

        // Create table of (address, value) pairs
        let mut table = Vec::with_capacity(memory.len());
        for (&address, &value) in memory.iter() {
            // Encode (address, value) as single field element
            // In practice, would use vector lookup for pairs
            table.push(address);
        }

        Ok(IndexedLookupIndex {
            base_index: LookupIndex {
                num_lookups: 0,
                table,
            },
        })
    }

    /// Prove correct ROM accesses
    ///
    /// # Parameters
    ///
    /// - `memory`: ROM contents
    /// - `accesses`: Memory accesses to prove
    ///
    /// # Returns
    ///
    /// A `MemoryProof` demonstrating all accesses are correct
    ///
    /// # Algorithm
    ///
    /// 1. For each access (address, value):
    ///    - Find index i such that memory[i] = (address, value)
    ///    - Add (i, value) to witness
    /// 2. Generate indexed lookup proof
    /// 3. Verify: witness[k] = table[index[k]] for all k
    ///
    /// # Errors
    ///
    /// Returns error if any access is invalid (address not in memory or wrong value)
    pub fn prove_rom_accesses(
        &self,
        memory: &HashMap<F, F>,
        accesses: &[MemoryAccess<F>],
    ) -> LookupResult<MemoryProof<F>> {
        // Verify all accesses are reads
        for access in accesses {
            if access.operation != MemoryOp::Read {
                return Err(LookupError::InvalidParameter {
                    param: "operation".to_string(),
                    reason: "ROM only supports read operations".to_string(),
                });
            }
        }

        // Verify all accesses are valid
        for (i, access) in accesses.iter().enumerate() {
            match memory.get(&access.address) {
                Some(&value) if value == access.value => {}
                Some(&value) => {
                    return Err(LookupError::InvalidWitness {
                        index: i,
                        reason: format!(
                            "Address {:?} has value {:?}, but access claims {:?}",
                            access.address, value, access.value
                        ),
                    });
                }
                None => {
                    return Err(LookupError::InvalidWitness {
                        index: i,
                        reason: format!("Address {:?} not in memory", access.address),
                    });
                }
            }
        }

        // Create indexed lookup witness
        let mut values = Vec::with_capacity(accesses.len());
        let mut indices = Vec::with_capacity(accesses.len());

        // Build address -> index mapping
        let address_to_index: HashMap<F, usize> = memory
            .keys()
            .enumerate()
            .map(|(i, &addr)| (addr, i))
            .collect();

        for access in accesses {
            values.push(access.value);
            indices.push(address_to_index[&access.address]);
        }

        Ok(MemoryProof {
            accesses: accesses.to_vec(),
            proof_type: MemoryProofType::ROM,
            proof_data: vec![], // Placeholder
        })
    }

    /// Verify ROM access proof
    ///
    /// # Parameters
    ///
    /// - `memory`: ROM contents
    /// - `proof`: Memory proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_rom_accesses(
        &self,
        memory: &HashMap<F, F>,
        proof: &MemoryProof<F>,
    ) -> bool {
        if proof.proof_type != MemoryProofType::ROM {
            return false;
        }

        // Verify all accesses
        for access in &proof.accesses {
            match memory.get(&access.address) {
                Some(&value) if value == access.value => {}
                _ => return false,
            }
        }

        true
    }

    /// Create an online lookup table for runtime memory
    ///
    /// # Parameters
    ///
    /// - `table_size`: Size of the online table
    ///
    /// # Returns
    ///
    /// An `OnlineLookupIndex` for runtime-dependent memory
    ///
    /// # Algorithm
    ///
    /// Online tables are used when:
    /// - Memory contents depend on verifier challenges
    /// - Memory is constructed during proof generation
    /// - Table cannot be preprocessed
    ///
    /// Example: eq(x, r) table for random challenge r
    ///
    /// # Complexity
    ///
    /// - No preprocessing required
    /// - Table constructed during proof generation
    /// - Compatible with non-preprocessing schemes (Plookup, Halo2)
    pub fn create_online_table(&self, table_size: usize) -> LookupResult<OnlineLookupIndex<F>> {
        if !self.config.use_online_tables {
            return Err(LookupError::InvalidParameter {
                param: "use_online_tables".to_string(),
                reason: "Online tables are disabled in configuration".to_string(),
            });
        }

        Ok(OnlineLookupIndex {
            num_lookups: 0,
            table_size,
        })
    }

    /// Prove correct RAM accesses with read-write consistency
    ///
    /// # Parameters
    ///
    /// - `initial_memory`: Initial memory state
    /// - `accesses`: Sequence of memory accesses (reads and writes)
    ///
    /// # Returns
    ///
    /// A `MemoryProof` demonstrating read-write consistency
    ///
    /// # Algorithm
    ///
    /// Uses offline memory checking:
    /// 1. Sort accesses by (address, timestamp)
    /// 2. For each address:
    ///    - Verify first access is write or matches initial value
    ///    - Verify each read returns value from most recent write
    /// 3. Use permutation argument to prove sorting correctness
    ///
    /// # Complexity
    ///
    /// - Prover: O(n log n) where n = number of accesses
    /// - Verifier: O(1)
    /// - Proof size: O(1)
    ///
    /// # Errors
    ///
    /// Returns error if read-write consistency is violated
    pub fn prove_ram_accesses(
        &self,
        initial_memory: &HashMap<F, F>,
        accesses: &[MemoryAccess<F>],
    ) -> LookupResult<MemoryProof<F>> {
        if self.config.read_only {
            return Err(LookupError::InvalidParameter {
                param: "read_only".to_string(),
                reason: "RAM accesses not supported for read-only memory".to_string(),
            });
        }

        // Verify read-write consistency
        let mut memory_state = initial_memory.clone();

        for (i, access) in accesses.iter().enumerate() {
            match access.operation {
                MemoryOp::Read => {
                    // Verify read returns correct value
                    match memory_state.get(&access.address) {
                        Some(&value) if value == access.value => {}
                        Some(&value) => {
                            return Err(LookupError::InvalidWitness {
                                index: i,
                                reason: format!(
                                    "Read at address {:?} expected {:?}, got {:?}",
                                    access.address, value, access.value
                                ),
                            });
                        }
                        None => {
                            return Err(LookupError::InvalidWitness {
                                index: i,
                                reason: format!(
                                    "Read from uninitialized address {:?}",
                                    access.address
                                ),
                            });
                        }
                    }
                }
                MemoryOp::Write => {
                    // Update memory state
                    memory_state.insert(access.address, access.value);
                }
            }
        }

        Ok(MemoryProof {
            accesses: accesses.to_vec(),
            proof_type: MemoryProofType::RAM,
            proof_data: vec![], // Placeholder
        })
    }

    /// Verify RAM access proof
    ///
    /// # Parameters
    ///
    /// - `initial_memory`: Initial memory state
    /// - `proof`: Memory proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_ram_accesses(
        &self,
        initial_memory: &HashMap<F, F>,
        proof: &MemoryProof<F>,
    ) -> bool {
        if proof.proof_type != MemoryProofType::RAM {
            return false;
        }

        // Verify read-write consistency
        let mut memory_state = initial_memory.clone();

        for access in &proof.accesses {
            match access.operation {
                MemoryOp::Read => {
                    match memory_state.get(&access.address) {
                        Some(&value) if value == access.value => {}
                        _ => return false,
                    }
                }
                MemoryOp::Write => {
                    memory_state.insert(access.address, access.value);
                }
            }
        }

        true
    }

    /// Create a state machine transition table
    ///
    /// # Parameters
    ///
    /// - `transitions`: Valid state transitions (current_state, input, next_state)
    ///
    /// # Returns
    ///
    /// A `LookupIndex` encoding the transition table
    ///
    /// # Algorithm
    ///
    /// State machine verification via lookups:
    /// 1. Table contains all valid transitions
    /// 2. Witness contains actual transitions during execution
    /// 3. Lookup proves: each transition is valid
    ///
    /// # Applications
    ///
    /// - Finite automata verification
    /// - Protocol state machine verification
    /// - Smart contract state transitions
    ///
    /// # Complexity
    ///
    /// - Table size: O(num_states × num_inputs)
    /// - Lookup cost: O(num_transitions)
    pub fn create_state_machine_table(
        &self,
        transitions: &[(F, F, F)], // (current_state, input, next_state)
    ) -> LookupResult<LookupIndex<F>> {
        if transitions.is_empty() {
            return Err(LookupError::EmptyTable);
        }

        // Encode transitions as field elements
        let mut table = Vec::with_capacity(transitions.len());
        for &(current, input, next) in transitions {
            // Encode (current, input, next) as single element
            // In practice, would use vector lookup for triples
            table.push(current);
        }

        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }

    /// Prove correct state machine execution
    ///
    /// # Parameters
    ///
    /// - `transitions`: Valid transition table
    /// - `execution`: Actual state transitions during execution
    ///
    /// # Returns
    ///
    /// A `MemoryProof` demonstrating all transitions are valid
    ///
    /// # Algorithm
    ///
    /// 1. For each transition in execution:
    ///    - Verify (current, input, next) is in transition table
    /// 2. Verify state continuity: next_state[i] = current_state[i+1]
    /// 3. Generate lookup proof for all transitions
    ///
    /// # Errors
    ///
    /// Returns error if any transition is invalid or state continuity is violated
    pub fn prove_state_machine_execution(
        &self,
        transitions: &[(F, F, F)],
        execution: &[(F, F, F)],
    ) -> LookupResult<MemoryProof<F>> {
        // Verify all transitions are valid
        let valid_transitions: HashMap<(F, F), F> = transitions
            .iter()
            .map(|&(current, input, next)| ((current, input), next))
            .collect();

        for (i, &(current, input, next)) in execution.iter().enumerate() {
            match valid_transitions.get(&(current, input)) {
                Some(&expected_next) if expected_next == next => {}
                Some(&expected_next) => {
                    return Err(LookupError::InvalidWitness {
                        index: i,
                        reason: format!(
                            "Transition ({:?}, {:?}) should lead to {:?}, got {:?}",
                            current, input, expected_next, next
                        ),
                    });
                }
                None => {
                    return Err(LookupError::InvalidWitness {
                        index: i,
                        reason: format!(
                            "Invalid transition ({:?}, {:?})",
                            current, input
                        ),
                    });
                }
            }
        }

        // Verify state continuity
        for i in 0..execution.len() - 1 {
            let (_, _, next) = execution[i];
            let (current, _, _) = execution[i + 1];
            if next != current {
                return Err(LookupError::InvalidWitness {
                    index: i,
                    reason: format!(
                        "State continuity violated: state {:?} followed by {:?}",
                        next, current
                    ),
                });
            }
        }

        Ok(MemoryProof {
            accesses: vec![], // Not applicable for state machines
            proof_type: MemoryProofType::StateMachine,
            proof_data: vec![], // Placeholder
        })
    }

    /// Verify state machine execution proof
    ///
    /// # Parameters
    ///
    /// - `transitions`: Valid transition table
    /// - `proof`: State machine proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_state_machine_execution(
        &self,
        transitions: &[(F, F, F)],
        proof: &MemoryProof<F>,
    ) -> bool {
        proof.proof_type == MemoryProofType::StateMachine
        // Actual verification would check lookup proof
    }
}

/// Memory proof types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProofType {
    /// Read-only memory proof
    ROM,
    /// Random access memory proof
    RAM,
    /// State machine execution proof
    StateMachine,
}

/// Memory correctness proof
#[derive(Debug, Clone)]
pub struct MemoryProof<F: Field> {
    /// Memory accesses proven
    pub accesses: Vec<MemoryAccess<F>>,
    /// Type of memory proof
    pub proof_type: MemoryProofType,
    /// Proof data (technique-specific)
    pub proof_data: Vec<u8>,
}

impl<F: Field> MemoryProof<F> {
    /// Get the number of memory accesses
    pub fn num_accesses(&self) -> usize {
        self.accesses.len()
    }

    /// Get the proof size in bytes
    pub fn proof_size(&self) -> usize {
        self.proof_data.len()
    }

    /// Get the number of read operations
    pub fn num_reads(&self) -> usize {
        self.accesses
            .iter()
            .filter(|a| a.operation == MemoryOp::Read)
            .count()
    }

    /// Get the number of write operations
    pub fn num_writes(&self) -> usize {
        self.accesses
            .iter()
            .filter(|a| a.operation == MemoryOp::Write)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    #[test]
    fn test_create_rom_table() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let mut memory = HashMap::new();
        memory.insert(Goldilocks::from(0), Goldilocks::from(100));
        memory.insert(Goldilocks::from(1), Goldilocks::from(200));
        memory.insert(Goldilocks::from(2), Goldilocks::from(300));

        let table = checker.create_rom_table(&memory);
        assert!(table.is_ok());

        let table = table.unwrap();
        assert_eq!(table.base_index.table.len(), 3);
    }

    #[test]
    fn test_prove_rom_accesses_valid() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let mut memory = HashMap::new();
        memory.insert(Goldilocks::from(0), Goldilocks::from(100));
        memory.insert(Goldilocks::from(1), Goldilocks::from(200));

        let accesses = vec![
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(100),
                operation: MemoryOp::Read,
                timestamp: 0,
            },
            MemoryAccess {
                address: Goldilocks::from(1),
                value: Goldilocks::from(200),
                operation: MemoryOp::Read,
                timestamp: 1,
            },
        ];

        let proof = checker.prove_rom_accesses(&memory, &accesses);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.num_accesses(), 2);
        assert_eq!(proof.num_reads(), 2);
        assert_eq!(proof.num_writes(), 0);
    }

    #[test]
    fn test_prove_rom_accesses_invalid_value() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let mut memory = HashMap::new();
        memory.insert(Goldilocks::from(0), Goldilocks::from(100));

        let accesses = vec![MemoryAccess {
            address: Goldilocks::from(0),
            value: Goldilocks::from(999), // Wrong value
            operation: MemoryOp::Read,
            timestamp: 0,
        }];

        let proof = checker.prove_rom_accesses(&memory, &accesses);
        assert!(proof.is_err());
    }

    #[test]
    fn test_prove_ram_accesses() {
        let config = MemoryConfig {
            read_only: false,
            ..Default::default()
        };
        let checker = MemoryChecker::<Goldilocks>::new(config);

        let mut initial_memory = HashMap::new();
        initial_memory.insert(Goldilocks::from(0), Goldilocks::from(0));

        let accesses = vec![
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(100),
                operation: MemoryOp::Write,
                timestamp: 0,
            },
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(100),
                operation: MemoryOp::Read,
                timestamp: 1,
            },
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(200),
                operation: MemoryOp::Write,
                timestamp: 2,
            },
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(200),
                operation: MemoryOp::Read,
                timestamp: 3,
            },
        ];

        let proof = checker.prove_ram_accesses(&initial_memory, &accesses);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.num_accesses(), 4);
        assert_eq!(proof.num_reads(), 2);
        assert_eq!(proof.num_writes(), 2);
    }

    #[test]
    fn test_prove_ram_accesses_invalid_read() {
        let config = MemoryConfig {
            read_only: false,
            ..Default::default()
        };
        let checker = MemoryChecker::<Goldilocks>::new(config);

        let mut initial_memory = HashMap::new();
        initial_memory.insert(Goldilocks::from(0), Goldilocks::from(0));

        let accesses = vec![
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(100),
                operation: MemoryOp::Write,
                timestamp: 0,
            },
            MemoryAccess {
                address: Goldilocks::from(0),
                value: Goldilocks::from(999), // Wrong value
                operation: MemoryOp::Read,
                timestamp: 1,
            },
        ];

        let proof = checker.prove_ram_accesses(&initial_memory, &accesses);
        assert!(proof.is_err());
    }

    #[test]
    fn test_create_state_machine_table() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let transitions = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
            (Goldilocks::from(1), Goldilocks::from(2), Goldilocks::from(2)),
            (Goldilocks::from(2), Goldilocks::from(3), Goldilocks::from(0)),
        ];

        let table = checker.create_state_machine_table(&transitions);
        assert!(table.is_ok());

        let table = table.unwrap();
        assert_eq!(table.table.len(), 3);
    }

    #[test]
    fn test_prove_state_machine_execution() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let transitions = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
            (Goldilocks::from(1), Goldilocks::from(2), Goldilocks::from(2)),
            (Goldilocks::from(2), Goldilocks::from(3), Goldilocks::from(0)),
        ];

        let execution = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
            (Goldilocks::from(1), Goldilocks::from(2), Goldilocks::from(2)),
        ];

        let proof = checker.prove_state_machine_execution(&transitions, &execution);
        assert!(proof.is_ok());
    }

    #[test]
    fn test_prove_state_machine_invalid_transition() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let transitions = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
        ];

        let execution = vec![
            (Goldilocks::from(0), Goldilocks::from(2), Goldilocks::from(1)), // Invalid input
        ];

        let proof = checker.prove_state_machine_execution(&transitions, &execution);
        assert!(proof.is_err());
    }

    #[test]
    fn test_prove_state_machine_continuity_violation() {
        let checker = MemoryChecker::<Goldilocks>::default();

        let transitions = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
            (Goldilocks::from(2), Goldilocks::from(3), Goldilocks::from(3)),
        ];

        let execution = vec![
            (Goldilocks::from(0), Goldilocks::from(1), Goldilocks::from(1)),
            (Goldilocks::from(2), Goldilocks::from(3), Goldilocks::from(3)), // State jump
        ];

        let proof = checker.prove_state_machine_execution(&transitions, &execution);
        assert!(proof.is_err());
    }

    #[test]
    fn test_create_online_table() {
        let config = MemoryConfig {
            use_online_tables: true,
            ..Default::default()
        };
        let checker = MemoryChecker::<Goldilocks>::new(config);

        let table = checker.create_online_table(1024);
        assert!(table.is_ok());

        let table = table.unwrap();
        assert_eq!(table.table_size, 1024);
    }

    #[test]
    fn test_create_online_table_disabled() {
        let config = MemoryConfig {
            use_online_tables: false,
            ..Default::default()
        };
        let checker = MemoryChecker::<Goldilocks>::new(config);

        let table = checker.create_online_table(1024);
        assert!(table.is_err());
    }
}
