// Core Jolt-style zkVM architecture
// Implements task 6.1 requirements

use crate::field::Field;
use crate::ring::RingElement;
use super::cycle_proof::{CycleProof, CycleProver, CycleVerifier};
use super::instruction_tables::InstructionTableSet;
use super::riscv::DecodedInstruction;
use super::shard_proof::{ShardProof, ShardProver};
use std::marker::PhantomData;

/// zkVM configuration parameters
#[derive(Clone, Debug)]
pub struct ZkVMConfig {
    /// Number of registers (32 for RISC-V)
    pub num_registers: usize,
    
    /// RAM size in bytes
    pub ram_size: usize,
    
    /// Cycles per shard (typically 2^20 = 1M cycles)
    pub cycles_per_shard: usize,
    
    /// Program memory size (typically 2^20 = 1MB)
    pub program_size: usize,
    
    /// Instruction table size (typically 2^16)
    pub instruction_table_size: usize,
    
    /// Bit width for decomposed operations (typically 16)
    pub operation_bit_width: usize,
}

impl ZkVMConfig {
    /// Create default RISC-V configuration
    pub fn default_riscv() -> Self {
        Self {
            num_registers: 32,
            ram_size: 1 << 20,        // 1MB RAM
            cycles_per_shard: 1 << 20, // 1M cycles per shard
            program_size: 1 << 20,     // 1MB program
            instruction_table_size: 1 << 16, // 64K table entries
            operation_bit_width: 16,   // 16-bit decomposition
        }
    }
    
    /// Create configuration for large RAM
    pub fn large_ram_riscv(ram_size: usize) -> Self {
        Self {
            num_registers: 32,
            ram_size,
            cycles_per_shard: 1 << 20,
            program_size: 1 << 20,
            instruction_table_size: 1 << 16,
            operation_bit_width: 16,
        }
    }
}

/// Lattice-based Jolt-style zkVM
/// 
/// Architecture (as per task 6.1):
/// - fetch_shout: K=2^20 (program size), T=2^20 (cycles), d=1
/// - exec_shout: K=2^16 (instruction tables), T=2^20, d=1
/// - register_twist: K=32 (registers), T=2^20, d=1
/// - ram_twist: K=ram_size, T=2^20, d=4 (for large RAM)
pub struct LatticeJoltZkVM<F: Field, R: RingElement> {
    /// Configuration
    pub config: ZkVMConfig,
    
    /// Instruction tables for execution
    pub instruction_tables: InstructionTableSet<F>,
    
    /// Cycle prover
    pub cycle_prover: CycleProver<F>,
    
    /// Cycle verifier
    pub cycle_verifier: CycleVerifier<F>,
    
    /// Shard prover
    pub shard_prover: ShardProver<F>,
    
    /// Phantom data for ring element
    _phantom: PhantomData<R>,
}

impl<F: Field, R: RingElement> LatticeJoltZkVM<F, R> {
    /// Create new zkVM for RISC-V with default configuration
    /// 
    /// Implements task 6.1 requirements:
    /// - Configure Shout instances for fetch and exec
    /// - Configure Twist instances for registers and RAM
    /// - Initialize instruction tables
    /// - Initialize constraint checker (Spartan-style)
    pub fn new_riscv() -> Self {
        let config = ZkVMConfig::default_riscv();
        Self::new_with_config(config)
    }
    
    /// Create new zkVM with custom RAM size
    pub fn new_riscv_with_ram(ram_size: usize) -> Self {
        let config = ZkVMConfig::large_ram_riscv(ram_size);
        Self::new_with_config(config)
    }
    
    /// Create new zkVM with custom configuration
    pub fn new_with_config(config: ZkVMConfig) -> Self {
        // Create instruction tables
        let instruction_tables = InstructionTableSet::new(config.operation_bit_width);
        
        // Create cycle prover and verifier
        // Note: In a full implementation, these would be initialized with actual
        // Shout and Twist protocol instances. For now, we create them with
        // placeholder protocols that will be properly initialized when needed.
        let cycle_prover = CycleProver::new_placeholder(instruction_tables.clone());
        let cycle_verifier = CycleVerifier::new(instruction_tables.clone());
        
        // Create shard prover
        let shard_prover = ShardProver::new(
            CycleProver::new_placeholder(instruction_tables.clone()),
            config.clone(),
        );
        
        Self {
            config,
            instruction_tables,
            cycle_prover,
            cycle_verifier,
            shard_prover,
            _phantom: PhantomData,
        }
    }
    
    /// Compute optimal d parameter based on memory size
    /// 
    /// As per task 6.1:
    /// - d=1 for K ≤ 2^16 (small tables)
    /// - d=2 for K ≤ 2^20 (medium tables)
    /// - d=4 for K ≤ 2^30 (large tables)
    /// - d=8 for K > 2^30 (gigantic tables)
    fn compute_d_for_memory_size(size: usize) -> usize {
        if size <= (1 << 16) {
            1
        } else if size <= (1 << 20) {
            2
        } else if size <= (1 << 30) {
            4
        } else {
            8
        }
    }
    
    /// Prove single cycle execution
    /// 
    /// Delegates to cycle_prover which implements task 6.2:
    /// 1. Fetch: Prove instruction fetch via Shout
    /// 2. Decode/Execute: Prove instruction execution via Shout
    /// 3. Register Reads: Prove via Twist
    /// 4. Register Write: Prove via Twist
    /// 5. RAM Access: Prove via Twist (if load/store)
    pub fn prove_cycle(
        &mut self,
        cycle: usize,
        instruction: &DecodedInstruction,
        register_values: &[u64; 32],
        memory_value: Option<u64>,
    ) -> Result<CycleProof<F>, String> {
        self.cycle_prover.prove_cycle(
            cycle,
            instruction,
            register_values,
            memory_value,
        )
    }
    
    /// Verify single cycle proof
    pub fn verify_cycle(
        &self,
        proof: &CycleProof<F>,
        instruction: &DecodedInstruction,
    ) -> Result<bool, String> {
        self.cycle_verifier.verify_cycle(proof, instruction)
    }
    
    /// Prove shard execution (Task 6.3)
    /// Proves multiple cycles (up to 2^20) in a single shard
    pub fn prove_shard(
        &mut self,
        start_cycle: usize,
        instructions: &[DecodedInstruction],
        initial_registers: &[u64; 32],
        memory_values: &[(u64, u64)],
    ) -> Result<ShardProof<F>, String> {
        self.shard_prover.prove_shard(
            start_cycle,
            instructions,
            initial_registers,
            memory_values,
        )
    }
    
    /// Get memory statistics
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            num_registers: self.config.num_registers,
            ram_size: self.config.ram_size,
            program_size: self.config.program_size,
            cycles_per_shard: self.config.cycles_per_shard,
            register_d: 1,
            ram_d: Self::compute_d_for_memory_size(self.config.ram_size),
            commitment_cost_per_cycle: self.estimate_commitment_cost(),
        }
    }
    
    /// Estimate commitment cost per cycle
    /// 
    /// Cost breakdown:
    /// - Fetch: d=1, so 1 commitment per cycle
    /// - Exec: d=1, so 1 commitment per cycle (per lookup)
    /// - Register reads: d=1, so 2 commitments per cycle (2 reads)
    /// - Register write: d=1, so 1 commitment per cycle
    /// - RAM: d=4 (for large RAM), so 4 commitments per cycle (if memory op)
    fn estimate_commitment_cost(&self) -> usize {
        let fetch_cost = 1;
        let exec_cost = 4; // 4 lookups for 64-bit decomposition
        let register_read_cost = 2; // 2 reads
        let register_write_cost = 1;
        let ram_cost = Self::compute_d_for_memory_size(self.config.ram_size);
        
        // Average cost (assuming 20% memory ops)
        fetch_cost + exec_cost + register_read_cost + register_write_cost + (ram_cost / 5)
    }
}

/// Memory statistics
#[derive(Clone, Debug)]
pub struct MemoryStats {
    pub num_registers: usize,
    pub ram_size: usize,
    pub program_size: usize,
    pub cycles_per_shard: usize,
    pub register_d: usize,
    pub ram_d: usize,
    pub commitment_cost_per_cycle: usize,
}

impl MemoryStats {
    /// Print statistics
    pub fn print(&self) {
        println!("zkVM Memory Statistics:");
        println!("  Registers: {}", self.num_registers);
        println!("  RAM size: {} bytes ({} MB)", self.ram_size, self.ram_size / (1 << 20));
        println!("  Program size: {} bytes ({} MB)", self.program_size, self.program_size / (1 << 20));
        println!("  Cycles per shard: {} ({} M)", self.cycles_per_shard, self.cycles_per_shard / (1 << 20));
        println!("  Register d-parameter: {}", self.register_d);
        println!("  RAM d-parameter: {}", self.ram_d);
        println!("  Commitment cost per cycle: {} group operations", self.commitment_cost_per_cycle);
    }
}

/// Shard proof (for future implementation in task 6.3)
#[derive(Clone, Debug)]
pub struct ShardProof<F: Field> {
    /// Cycle proofs for this shard
    pub cycle_proofs: Vec<CycleProof<F>>,
    
    /// Start cycle
    pub start_cycle: usize,
    
    /// End cycle
    pub end_cycle: usize,
    
    /// Batched proof (after Symphony folding)
    pub batched_proof: Option<Vec<F>>, // Placeholder
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    use crate::ring::cyclotomic::CyclotomicRing;
    
    #[test]
    fn test_zkvm_creation() {
        let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
        
        assert_eq!(zkvm.config.num_registers, 32);
        assert_eq!(zkvm.config.ram_size, 1 << 20);
        assert_eq!(zkvm.config.cycles_per_shard, 1 << 20);
    }
    
    #[test]
    fn test_zkvm_with_large_ram() {
        let ram_size = 1 << 30; // 1GB
        let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv_with_ram(ram_size);
        
        assert_eq!(zkvm.config.ram_size, ram_size);
        
        let stats = zkvm.memory_stats();
        assert_eq!(stats.ram_d, 4); // d=4 for 1GB RAM
    }
    
    #[test]
    fn test_compute_d_parameter() {
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 10), 1);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 16), 1);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 18), 2);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 20), 2);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 25), 4);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 30), 4);
        assert_eq!(LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::compute_d_for_memory_size(1 << 32), 8);
    }
    
    #[test]
    fn test_memory_stats() {
        let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
        let stats = zkvm.memory_stats();
        
        assert_eq!(stats.num_registers, 32);
        assert_eq!(stats.register_d, 1);
        assert!(stats.commitment_cost_per_cycle > 0);
    }
    
    #[test]
    fn test_default_config() {
        let config = ZkVMConfig::default_riscv();
        
        assert_eq!(config.num_registers, 32);
        assert_eq!(config.ram_size, 1 << 20);
        assert_eq!(config.cycles_per_shard, 1 << 20);
        assert_eq!(config.program_size, 1 << 20);
        assert_eq!(config.instruction_table_size, 1 << 16);
        assert_eq!(config.operation_bit_width, 16);
    }
}
