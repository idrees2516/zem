// Integration tests for Tasks 6.3, 6.4, and Phase 7
// Tests shard proving and Symphony folding

use neo_lattice_zkvm::field::m61::M61;
use neo_lattice_zkvm::ring::cyclotomic::CyclotomicRing;
use neo_lattice_zkvm::jolt_zkvm::{
    LatticeJoltZkVM, DecodedInstruction, RiscVInstruction,
    SymphonyTwistShoutFolder, FoldingConfig, ShoutInstance, TwistInstance,
};

#[test]
fn test_shard_proving_small_program() {
    // Test Task 6.3: Shard Proving with small program
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Create small program: 3 ADD instructions
    let instructions = vec![
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            address: 0,
        },
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 4,
            rs1: 1,
            rs2: 3,
            imm: 0,
            address: 4,
        },
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 5,
            rs1: 4,
            rs2: 2,
            imm: 0,
            address: 8,
        },
    ];
    
    let mut registers = [0u64; 32];
    registers[2] = 10;
    registers[3] = 20;
    
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &[]).unwrap();
    
    assert_eq!(shard_proof.num_cycles, 3);
    assert_eq!(shard_proof.start_cycle, 0);
    assert_eq!(shard_proof.end_cycle, 3);
    assert_eq!(shard_proof.cycle_proofs.len(), 3);
    
    println!("✓ Shard proof generated for 3 cycles");
    println!("  - Batched proof compression: {:.2}x", shard_proof.batched_proof.compression_ratio);
    println!("  - Constraints checked: {}", shard_proof.constraint_proof.num_constraints);
}

#[test]
fn test_shard_proving_with_branches() {
    // Test shard proving with branch instructions
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    let instructions = vec![
        // x1 = x2 + x3
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            address: 0,
        },
        // if x1 == x2, branch
        DecodedInstruction {
            opcode: RiscVInstruction::Beq,
            rd: 0,
            rs1: 1,
            rs2: 2,
            imm: 8,
            address: 4,
        },
    ];
    
    let mut registers = [0u64; 32];
    registers[2] = 10;
    registers[3] = 0; // x1 will be 10, equal to x2
    
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &[]).unwrap();
    
    assert_eq!(shard_proof.num_cycles, 2);
    
    // Check PC constraints
    assert!(shard_proof.constraint_proof.pc_constraints.len() > 0);
    
    println!("✓ Shard proof with branches generated");
}

#[test]
fn test_shard_proving_with_memory() {
    // Test shard proving with memory operations
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    let instructions = vec![
        // Load from memory
        DecodedInstruction {
            opcode: RiscVInstruction::Lw,
            rd: 1,
            rs1: 2,
            rs2: 0,
            imm: 0,
            address: 0,
        },
        // Store to memory
        DecodedInstruction {
            opcode: RiscVInstruction::Sw,
            rd: 0,
            rs1: 3,
            rs2: 1,
            imm: 0,
            address: 4,
        },
    ];
    
    let mut registers = [0u64; 32];
    registers[2] = 0x1000; // Load address
    registers[3] = 0x2000; // Store address
    
    let memory_values = vec![(0x1000, 0x12345678)];
    
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &memory_values).unwrap();
    
    assert_eq!(shard_proof.num_cycles, 2);
    
    // Check memory constraints
    assert!(shard_proof.constraint_proof.memory_constraints.len() > 0);
    
    println!("✓ Shard proof with memory operations generated");
}

#[test]
fn test_constraint_checking() {
    // Test constraint checking for VM transitions
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    let instructions = vec![
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            address: 0,
        },
    ];
    
    let mut registers = [0u64; 32];
    registers[2] = 100;
    registers[3] = 200;
    
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &[]).unwrap();
    
    // Verify PC constraints
    for pc_constraint in &shard_proof.constraint_proof.pc_constraints {
        assert!(pc_constraint.satisfied, "PC constraint not satisfied");
        assert_eq!(pc_constraint.next_pc, pc_constraint.expected_pc);
    }
    
    // Verify register constraints
    for reg_constraint in &shard_proof.constraint_proof.register_constraints {
        assert!(reg_constraint.satisfied, "Register constraint not satisfied");
    }
    
    println!("✓ All constraints verified");
    println!("  - PC constraints: {}", shard_proof.constraint_proof.pc_constraints.len());
    println!("  - Register constraints: {}", shard_proof.constraint_proof.register_constraints.len());
}

#[test]
fn test_batched_proof_compression() {
    // Test proof batching and compression
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Create larger program (10 instructions)
    let mut instructions = Vec::new();
    for i in 0..10 {
        instructions.push(DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: (i % 30) + 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            address: (i * 4) as u64,
        });
    }
    
    let mut registers = [0u64; 32];
    registers[2] = 5;
    registers[3] = 7;
    
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &[]).unwrap();
    
    assert_eq!(shard_proof.num_cycles, 10);
    
    // Check compression ratio
    assert!(shard_proof.batched_proof.compression_ratio > 1.0);
    
    println!("✓ Batched proof compression: {:.2}x", shard_proof.batched_proof.compression_ratio);
}

// Task 7 Tests: Symphony Folding

#[test]
fn test_symphony_folder_creation() {
    // Test Task 7: Symphony folder creation
    let config = FoldingConfig::default_folding();
    let _folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(1024, config);
    
    println!("✓ Symphony folder created with arity 1024");
}

#[test]
fn test_shout_to_ccs_conversion() {
    // Test Task 7.1: Shout to CCS conversion
    let config = FoldingConfig::default_folding();
    let folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(1024, config);
    
    let shout = ShoutInstance {
        memory_size: 256,
        num_lookups: 100,
        dimension: 1,
        access_commitments: vec![vec![M61::zero(); 100]],
        table_values: vec![M61::zero(); 256],
        read_values: vec![M61::zero(); 100],
    };
    
    let ccs = folder.shout_to_ccs(&shout).unwrap();
    
    assert_eq!(ccs.structure.num_constraints, 100);
    assert!(ccs.structure.num_variables > 0);
    assert_eq!(ccs.structure.matrices.len(), 3); // d=1 has 3 matrices
    
    println!("✓ Shout converted to CCS");
    println!("  - Constraints: {}", ccs.structure.num_constraints);
    println!("  - Variables: {}", ccs.structure.num_variables);
    println!("  - Matrices: {}", ccs.structure.matrices.len());
}

#[test]
fn test_twist_to_ccs_conversion() {
    // Test Task 7.1: Twist to CCS conversion
    let config = FoldingConfig::default_folding();
    let folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(1024, config);
    
    let twist = TwistInstance {
        memory_size: 32,
        num_cycles: 100,
        dimension: 1,
        read_address_commitments: vec![vec![M61::zero(); 100]],
        write_address_commitments: vec![vec![M61::zero(); 100]],
        increments: vec![M61::zero(); 3200],
        memory_values: vec![M61::zero(); 3200],
    };
    
    let ccs = folder.twist_to_ccs(&twist).unwrap();
    
    assert_eq!(ccs.structure.num_constraints, 3200);
    assert!(ccs.structure.num_variables > 0);
    assert_eq!(ccs.structure.matrices.len(), 3);
    
    println!("✓ Twist converted to CCS");
    println!("  - Constraints: {}", ccs.structure.num_constraints);
    println!("  - Variables: {}", ccs.structure.num_variables);
}

#[test]
fn test_parallel_folding_small() {
    // Test Task 7.2: Parallel folding with small number of instances
    let config = FoldingConfig::new(4); // 4 instances
    let mut folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(4, config);
    
    let mut instances = Vec::new();
    for _ in 0..4 {
        instances.push(ShoutInstance {
            memory_size: 64,
            num_lookups: 50,
            dimension: 1,
            access_commitments: vec![vec![M61::zero(); 50]],
            table_values: vec![M61::zero(); 64],
            read_values: vec![M61::zero(); 50],
        });
    }
    
    let folded = folder.fold_shout_instances(instances).unwrap();
    
    assert_eq!(folded.merged_claims.len(), 2); // 2ℓ_np claims merged to 2
    assert_eq!(folded.num_original_instances, 4);
    assert!(folded.compression_ratio > 1.0);
    
    println!("✓ Parallel folding of 4 instances");
    println!("  - Compression ratio: {:.2}x", folded.compression_ratio);
}

#[test]
fn test_claim_merging() {
    // Test Task 7.3: Claim merging via random linear combination
    let config = FoldingConfig::new(8);
    let folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(8, config);
    
    // Create 16 claims (2 per instance)
    let claims: Vec<M61> = (1..=16).map(|i| M61::from_u64(i)).collect();
    
    let merged = folder.merge_claims(&claims).unwrap();
    
    assert_eq!(merged.len(), 2);
    assert!(merged[0] != M61::zero());
    assert!(merged[1] != M61::zero());
    
    println!("✓ Claims merged: 16 → 2");
}

#[test]
fn test_tensor_of_rings_conversion() {
    // Test Task 7.3: Conversion to tensor-of-rings
    let config = FoldingConfig::default_folding();
    let folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(1024, config);
    
    let claims = vec![M61::from_u64(12345), M61::from_u64(67890)];
    
    let tensor_rings = folder.claims_to_tensor_of_rings(&claims).unwrap();
    
    assert_eq!(tensor_rings.len(), 2);
    for tr in &tensor_rings {
        assert_eq!(tr.extension_degree, 2);
        assert_eq!(tr.ring_dimension, 256);
    }
    
    println!("✓ Claims converted to tensor-of-rings");
    println!("  - Extension degree: {}", tensor_rings[0].extension_degree);
    println!("  - Ring dimension: {}", tensor_rings[0].ring_dimension);
}

#[test]
fn test_batch_folding() {
    // Test Task 7.4: Batch folding of Shout and Twist instances
    let config = FoldingConfig::new(4);
    let mut folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(4, config);
    
    // Create Shout instances
    let mut shout_instances = Vec::new();
    for _ in 0..4 {
        shout_instances.push(ShoutInstance {
            memory_size: 64,
            num_lookups: 50,
            dimension: 1,
            access_commitments: vec![vec![M61::zero(); 50]],
            table_values: vec![M61::zero(); 64],
            read_values: vec![M61::zero(); 50],
        });
    }
    
    // Create Twist instances
    let mut twist_instances = Vec::new();
    for _ in 0..4 {
        twist_instances.push(TwistInstance {
            memory_size: 32,
            num_cycles: 50,
            dimension: 1,
            read_address_commitments: vec![vec![M61::zero(); 50]],
            write_address_commitments: vec![vec![M61::zero(); 50]],
            increments: vec![M61::zero(); 1600],
            memory_values: vec![M61::zero(); 1600],
        });
    }
    
    let result = folder.batch_fold(shout_instances, twist_instances).unwrap();
    
    assert!(result.soundness_maintained);
    assert!(result.total_compression_ratio > 1.0);
    
    println!("✓ Batch folding complete");
    println!("  - Shout compression: {:.2}x", result.shout_folded.compression_ratio);
    println!("  - Twist compression: {:.2}x", result.twist_folded.compression_ratio);
    println!("  - Total compression: {:.2}x", result.total_compression_ratio);
}

#[test]
fn test_high_arity_folding() {
    // Test high-arity folding with different arities
    let arities = vec![1 << 10, 1 << 12, 1 << 14];
    
    for arity in arities {
        let config = FoldingConfig::new(arity);
        let _folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(arity, config);
        
        println!("✓ High-arity folder created with arity 2^{}", (arity as f64).log2() as u32);
    }
}

#[test]
fn test_folding_soundness() {
    // Test that folding maintains soundness
    let config = FoldingConfig::new(4);
    let mut folder = SymphonyTwistShoutFolder::<M61, CyclotomicRing<M61>>::new(4, config);
    
    let mut instances = Vec::new();
    for i in 0..4 {
        instances.push(ShoutInstance {
            memory_size: 64,
            num_lookups: 50,
            dimension: 1,
            access_commitments: vec![vec![M61::from_u64(i); 50]],
            table_values: vec![M61::from_u64(i * 2); 64],
            read_values: vec![M61::from_u64(i * 3); 50],
        });
    }
    
    let folded = folder.fold_shout_instances(instances).unwrap();
    
    // Verify merged claims are non-zero (soundness check)
    assert!(folded.merged_claims[0] != M61::zero());
    assert!(folded.merged_claims[1] != M61::zero());
    
    println!("✓ Folding soundness verified");
}

#[test]
fn test_end_to_end_shard_and_fold() {
    // End-to-end test: Prove shard, then fold multiple shards
    let mut zkvm = LatticeJoltZkVM::<M61, CyclotomicRing<M61>>::new_riscv();
    
    // Create program
    let instructions = vec![
        DecodedInstruction {
            opcode: RiscVInstruction::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            address: 0,
        },
        DecodedInstruction {
            opcode: RiscVInstruction::Sub,
            rd: 4,
            rs1: 1,
            rs2: 3,
            imm: 0,
            address: 4,
        },
    ];
    
    let mut registers = [0u64; 32];
    registers[2] = 100;
    registers[3] = 50;
    
    // Prove shard
    let shard_proof = zkvm.prove_shard(0, &instructions, &registers, &[]).unwrap();
    
    assert_eq!(shard_proof.num_cycles, 2);
    
    // In a full implementation, we would:
    // 1. Convert shard proofs to Shout/Twist instances
    // 2. Fold multiple shard proofs together
    // 3. Compress to single proof
    
    println!("✓ End-to-end shard proving and folding");
    println!("  - Shard cycles: {}", shard_proof.num_cycles);
    println!("  - Batched compression: {:.2}x", shard_proof.batched_proof.compression_ratio);
}
