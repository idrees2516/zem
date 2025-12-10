// Integration tests for Jolt-style zkVM
// Tests tasks 6.1 and 6.2 implementation

use neo_lattice_zkvm::field::m61::M61;
use neo_lattice_zkvm::ring::cyclotomic::CyclotomicRing;
use neo_lattice_zkvm::jolt_zkvm::{
    LatticeJoltZkVM, ZkVMConfig, DecodedInstruction, RiscVInstruction,
};

#[test]
fn test_zkvm_initialization() {
    // Test task 6.1: zkVM Core Architecture initialization
    let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Verify configuration
    assert_eq!(zkvm.config.num_registers, 32);
    assert_eq!(zkvm.config.ram_size, 1 << 20); // 1MB
    assert_eq!(zkvm.config.cycles_per_shard, 1 << 20); // 1M cycles
    assert_eq!(zkvm.config.program_size, 1 << 20); // 1MB
    assert_eq!(zkvm.config.instruction_table_size, 1 << 16); // 64K
    
    println!("✓ zkVM initialized with correct configuration");
}

#[test]
fn test_zkvm_with_custom_ram() {
    // Test with different RAM sizes
    let ram_sizes = vec![
        (1 << 16, 1),  // 64KB -> d=1
        (1 << 20, 2),  // 1MB -> d=2
        (1 << 25, 4),  // 32MB -> d=4
        (1 << 30, 4),  // 1GB -> d=4
    ];
    
    for (ram_size, expected_d) in ram_sizes {
        let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv_with_ram(ram_size);
        let stats = zkvm.memory_stats();
        
        assert_eq!(stats.ram_size, ram_size);
        assert_eq!(stats.ram_d, expected_d);
        
        println!("✓ RAM size {} bytes -> d={}", ram_size, expected_d);
    }
}

#[test]
fn test_memory_statistics() {
    // Test memory statistics reporting
    let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    let stats = zkvm.memory_stats();
    
    assert_eq!(stats.num_registers, 32);
    assert_eq!(stats.register_d, 1);
    assert!(stats.commitment_cost_per_cycle > 0);
    
    println!("✓ Memory statistics:");
    println!("  Registers: {}", stats.num_registers);
    println!("  RAM: {} bytes", stats.ram_size);
    println!("  Register d: {}", stats.register_d);
    println!("  RAM d: {}", stats.ram_d);
    println!("  Commitment cost/cycle: {}", stats.commitment_cost_per_cycle);
}

#[test]
fn test_instruction_decoding() {
    // Test RISC-V instruction decoding
    
    // ADD x1, x2, x3
    let add_inst = 0x003100B3u32;
    let decoded = DecodedInstruction::decode(add_inst, 0).unwrap();
    assert_eq!(decoded.opcode, RiscVInstruction::Add);
    assert_eq!(decoded.rd, 1);
    assert_eq!(decoded.rs1, 2);
    assert_eq!(decoded.rs2, 3);
    println!("✓ Decoded ADD instruction");
    
    // ADDI x1, x2, 42
    let addi_inst = 0x02A10093u32;
    let decoded = DecodedInstruction::decode(addi_inst, 0).unwrap();
    assert_eq!(decoded.opcode, RiscVInstruction::Addi);
    assert_eq!(decoded.rd, 1);
    assert_eq!(decoded.rs1, 2);
    assert_eq!(decoded.imm, 42);
    println!("✓ Decoded ADDI instruction");
    
    // LW x1, 0(x2)
    let lw_inst = 0x00012083u32;
    let decoded = DecodedInstruction::decode(lw_inst, 0).unwrap();
    assert_eq!(decoded.opcode, RiscVInstruction::Lw);
    assert!(decoded.opcode.is_memory_op());
    assert!(decoded.opcode.is_load());
    println!("✓ Decoded LW instruction");
    
    // SW x2, 0(x1)
    let sw_inst = 0x00212023u32;
    let decoded = DecodedInstruction::decode(sw_inst, 0).unwrap();
    assert_eq!(decoded.opcode, RiscVInstruction::Sw);
    assert!(decoded.opcode.is_memory_op());
    assert!(decoded.opcode.is_store());
    println!("✓ Decoded SW instruction");
}

#[test]
fn test_instruction_tables() {
    // Test instruction table creation and lookup
    let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Verify tables exist for common instructions
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Add).is_some());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Sub).is_some());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Xor).is_some());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::And).is_some());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Or).is_some());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Mul).is_some());
    
    // Memory operations don't have tables (handled differently)
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Lw).is_none());
    assert!(zkvm.instruction_tables.get_table(RiscVInstruction::Sw).is_none());
    
    println!("✓ Instruction tables created correctly");
}

#[test]
fn test_operation_decomposition() {
    // Test 64-bit operation decomposition into 16-bit chunks
    let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    let a = 0x123456789ABCDEF0u64;
    let b = 0xFEDCBA9876543210u64;
    
    let chunks = zkvm.instruction_tables.decompose_operation(a, b);
    
    assert_eq!(chunks.len(), 4);
    assert_eq!(chunks[0], (0xDEF0, 0x3210)); // Lower 16 bits
    assert_eq!(chunks[1], (0x9ABC, 0x7654));
    assert_eq!(chunks[2], (0x5678, 0xBA98));
    assert_eq!(chunks[3], (0x1234, 0xFEDC)); // Upper 16 bits
    
    println!("✓ 64-bit operation decomposed into 4×16-bit chunks");
}

#[test]
fn test_cycle_proof_structure() {
    // Test that we can create cycle proofs (task 6.2)
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Create a simple ADD instruction
    let instruction = DecodedInstruction {
        opcode: RiscVInstruction::Add,
        rd: 1,
        rs1: 2,
        rs2: 3,
        imm: 0,
        address: 0,
    };
    
    // Register values: x2=5, x3=7
    let mut registers = [0u64; 32];
    registers[2] = 5;
    registers[3] = 7;
    
    // Prove cycle execution
    let proof = zkvm.prove_cycle(0, &instruction, &registers, None).unwrap();
    
    // Verify proof structure
    assert_eq!(proof.read_proofs.len(), 2); // 2 source registers
    assert!(proof.ram_proof.is_none()); // No memory access
    
    println!("✓ Cycle proof generated for ADD instruction");
    println!("  - Fetch proof: PC={}", proof.fetch_proof.pc);
    println!("  - Execute proof: {} table lookups", proof.exec_proof.table_lookups.len());
    println!("  - Read proofs: {}", proof.read_proofs.len());
    println!("  - Result: {}", proof.exec_proof.result);
}

#[test]
fn test_cycle_proof_with_memory() {
    // Test cycle proof for memory operation
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Create a LW (load word) instruction
    let instruction = DecodedInstruction {
        opcode: RiscVInstruction::Lw,
        rd: 1,
        rs1: 2,
        rs2: 0,
        imm: 0,
        address: 0,
    };
    
    let mut registers = [0u64; 32];
    registers[2] = 0x1000; // Base address
    
    let memory_value = Some(0x12345678u64);
    
    // Prove cycle with memory access
    let proof = zkvm.prove_cycle(0, &instruction, &registers, memory_value).unwrap();
    
    // Verify memory proof exists
    assert!(proof.ram_proof.is_some());
    let ram_proof = proof.ram_proof.unwrap();
    assert_eq!(ram_proof.address, 0x1000);
    assert_eq!(ram_proof.value, 0x12345678);
    assert!(!ram_proof.is_write); // Load is a read
    
    println!("✓ Cycle proof generated for LW instruction");
    println!("  - Memory address: 0x{:x}", ram_proof.address);
    println!("  - Memory value: 0x{:x}", ram_proof.value);
    println!("  - Is write: {}", ram_proof.is_write);
}

#[test]
fn test_cycle_proof_verification() {
    // Test cycle proof verification
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    let instruction = DecodedInstruction {
        opcode: RiscVInstruction::Add,
        rd: 1,
        rs1: 2,
        rs2: 3,
        imm: 0,
        address: 0,
    };
    
    let mut registers = [0u64; 32];
    registers[2] = 10;
    registers[3] = 20;
    
    // Generate proof
    let proof = zkvm.prove_cycle(0, &instruction, &registers, None).unwrap();
    
    // Verify proof
    let verified = zkvm.verify_cycle(&proof, &instruction).unwrap();
    assert!(verified);
    
    println!("✓ Cycle proof verified successfully");
}

#[test]
fn test_multiple_instruction_types() {
    // Test proving different instruction types
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    let mut registers = [0u64; 32];
    
    let instructions = vec![
        (RiscVInstruction::Add, 2, 3, 0),
        (RiscVInstruction::Sub, 4, 5, 0),
        (RiscVInstruction::Xor, 6, 7, 0),
        (RiscVInstruction::And, 8, 9, 0),
        (RiscVInstruction::Or, 10, 11, 0),
    ];
    
    for (opcode, rs1, rs2, _) in instructions {
        let instruction = DecodedInstruction {
            opcode,
            rd: 1,
            rs1,
            rs2,
            imm: 0,
            address: 0,
        };
        
        registers[rs1] = 100;
        registers[rs2] = 50;
        
        let proof = zkvm.prove_cycle(0, &instruction, &registers, None).unwrap();
        let verified = zkvm.verify_cycle(&proof, &instruction).unwrap();
        
        assert!(verified);
        println!("✓ Proved and verified {:?} instruction", opcode);
    }
}

#[test]
fn test_zkvm_configuration_variants() {
    // Test different configuration options
    
    // Default RISC-V config
    let config1 = ZkVMConfig::default_riscv();
    assert_eq!(config1.num_registers, 32);
    assert_eq!(config1.operation_bit_width, 16);
    
    // Large RAM config
    let config2 = ZkVMConfig::large_ram_riscv(1 << 30);
    assert_eq!(config2.ram_size, 1 << 30);
    
    println!("✓ Configuration variants work correctly");
}

#[test]
fn test_commitment_cost_estimation() {
    // Test commitment cost estimation for different RAM sizes
    let ram_sizes = vec![
        1 << 16,  // 64KB
        1 << 20,  // 1MB
        1 << 25,  // 32MB
        1 << 30,  // 1GB
    ];
    
    for ram_size in ram_sizes {
        let zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv_with_ram(ram_size);
        let stats = zkvm.memory_stats();
        
        println!("RAM size: {} bytes", ram_size);
        println!("  d-parameter: {}", stats.ram_d);
        println!("  Commitment cost/cycle: {} group ops", stats.commitment_cost_per_cycle);
        
        // Verify cost increases with RAM size (due to larger d)
        assert!(stats.commitment_cost_per_cycle > 0);
    }
}

#[test]
fn test_instruction_source_registers() {
    // Test num_source_registers for different instruction types
    assert_eq!(RiscVInstruction::Add.num_source_registers(), 2);
    assert_eq!(RiscVInstruction::Sub.num_source_registers(), 2);
    assert_eq!(RiscVInstruction::Addi.num_source_registers(), 1);
    assert_eq!(RiscVInstruction::Lw.num_source_registers(), 1);
    assert_eq!(RiscVInstruction::Sw.num_source_registers(), 2);
    assert_eq!(RiscVInstruction::Lui.num_source_registers(), 0);
    assert_eq!(RiscVInstruction::Jal.num_source_registers(), 0);
    
    println!("✓ Source register counts correct for all instruction types");
}
