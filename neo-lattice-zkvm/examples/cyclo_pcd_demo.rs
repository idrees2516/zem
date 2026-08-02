//! Cyclo PCD and Recursive Verification Demo
//! 
//! Demonstrates proof-carrying data construction and recursive verification

use neo_lattice_zkvm::field::{FiniteField, GoldilocksField};
use neo_lattice_zkvm::cyclo::*;

type F = GoldilocksField;

fn main() -> Result<(), String> {
    println!("=== Cyclo PCD and Recursive Verification Demo ===\n");

    // Setup parameters
    let params = setup_parameters();
    println!("Parameters:");
    println!("  Conductor f = {}", params.conductor);
    println!("  Ring degree φ(f) = {}", euler_totient(params.conductor));
    println!("  Modulus q = {}", params.modulus.to_u64());
    println!("  Extension degree e = {}", params.extension_degree);
    println!("  Decomposition base b = {}", params.base_b);
    println!("  Norm bound B = {}", params.norm_bound_B.to_u64());
    println!();

    // Initialize ring and protocols
    let ring = CyclotomicRing::new(params.conductor);
    
    let commitment_scheme = AjtaiCommitment::new(
        ring.clone(),
        params.rank_a,
        params.witness_length,
        params.modulus,
    );

    let range_test = RangeTest::new(
        ring.clone(),
        params.extension_degree,
        params.base_b,
    );

    let extension_commitment = ExtensionCommitment::new(
        ring.clone(),
        params.extension_degree,
        params.base_b,
    );

    let strong_sampling = create_strong_sampling_set(&ring);

    let folding = CycloFolding::new(
        ring.clone(),
        params.clone(),
        range_test,
        extension_commitment,
        strong_sampling,
    );

    println!("=== Part 1: Recursive Verification Circuit ===\n");
    demonstrate_recursive_circuit(&folding, &ring)?;

    println!("\n=== Part 2: PCD Construction ===\n");
    demonstrate_pcd_construction(&folding, &ring)?;

    println!("\n=== Part 3: Incremental PCD ===\n");
    demonstrate_incremental_pcd(&folding)?;

    println!("\n=== Part 4: Recursive PCD with Circuit ===\n");
    demonstrate_recursive_pcd(&ring)?;

    println!("\n=== Demo Complete ===");
    Ok(())
}

fn demonstrate_recursive_circuit(
    folding: &CycloFolding<F>,
    ring: &CyclotomicRing<F>,
) -> Result<(), String> {
    println!("Building recursive verification circuit...");

    let mut circuit_builder = RecursiveVerifierCircuit::new(ring.clone());

    // Build circuit for verifying 2 input instances
    let num_inputs = 2;
    circuit_builder.build_verifier_circuit(folding, num_inputs)?;

    println!("Circuit built successfully!");
    println!("  Number of gates: {}", circuit_builder.circuit_size());
    println!("  Number of wires: {}", circuit_builder.circuit.num_wires);
    println!("  Circuit depth: {}", circuit_builder.circuit_depth());

    // Convert to R1CS
    println!("\nConverting to R1CS representation...");
    let r1cs = circuit_builder.to_r1cs()?;
    println!("  Matrix A: {}x{}", r1cs[0].len(), r1cs[0][0].len());
    println!("  Matrix B: {}x{}", r1cs[1].len(), r1cs[1][0].len());
    println!("  Matrix C: {}x{}", r1cs[2].len(), r1cs[2][0].len());

    // Create and verify a witness
    println!("\nCreating circuit witness...");
    let mut witness = CircuitWitness::new(circuit_builder.circuit.num_wires);
    
    // Set some example values
    for i in 0..witness.wire_values.len() {
        witness.set_wire(i, F::from_u64((i % 100) as u64));
    }

    println!("  Witness size: {} field elements", witness.wire_values.len());

    // Apply circuit optimizations
    println!("\nApplying circuit optimizations...");
    optimization::remove_redundant_gates(&mut circuit_builder.circuit);
    optimization::merge_linear_combinations(&mut circuit_builder.circuit);
    optimization::constant_propagation(&mut circuit_builder.circuit, &mut witness);
    
    println!("  Optimized gates: {}", circuit_builder.circuit_size());

    Ok(())
}

fn demonstrate_pcd_construction(
    folding: &CycloFolding<F>,
    ring: &CyclotomicRing<F>,
) -> Result<(), String> {
    println!("Constructing PCD tree...");

    let config = PCDConfig {
        max_depth: 5,
        branching_factor: 2,
        enable_compression: true,
        target_norm_bound: 1 << 20,
    };

    let mut tree = PCDTree::new(config.clone());

    // Create several leaf instances
    println!("Creating {} leaf instances...", 8);
    let mut leaf_ids = Vec::new();

    for i in 0..8 {
        let instance = create_example_accumulator(ring, i);
        let leaf_id = tree.create_leaf(instance);
        leaf_ids.push(leaf_id);
        println!("  Created leaf {}", leaf_id);
    }

    // Merge leaves into tree structure
    println!("\nMerging accumulators into tree...");
    let mut current_level = leaf_ids.clone();
    let mut level = 0;

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(config.branching_factor) {
            let mut transcript = Transcript::new(b"pcd_demo");
            let parent_id = tree.merge_accumulators(
                chunk,
                folding,
                &mut transcript,
            )?;
            next_level.push(parent_id);
            println!("  Level {}: Merged {:?} -> {}", level, chunk, parent_id);
        }

        current_level = next_level;
        level += 1;
    }

    let root_id = current_level[0];
    println!("\nTree construction complete! Root ID: {}", root_id);

    // Get tree statistics
    let stats = tree.statistics();
    println!("\nTree Statistics:");
    println!("  Total nodes: {}", stats.total_nodes);
    println!("  Leaf nodes: {}", stats.leaf_nodes);
    println!("  Internal nodes: {}", stats.internal_nodes);
    println!("  Max depth: {}", stats.max_depth);
    println!("  Branching factor: {}", stats.branching_factor);

    // Build PCD proof
    println!("\nBuilding PCD proof...");
    let pcd_proof = tree.build_pcd_proof(root_id, folding)?;
    
    println!("  Proof tree depth: {}", pcd_proof.tree_depth);
    println!("  Number of layers: {}", pcd_proof.layer_proofs.len());
    
    for (i, layer) in pcd_proof.layer_proofs.iter().enumerate() {
        println!("    Layer {}: {} proofs", i, layer.len());
    }

    // Compress proof
    if config.enable_compression {
        println!("\nCompressing PCD proof...");
        let compressed = tree.compress_proof(&pcd_proof)?;
        
        println!("  Compressed layers: {}", compressed.compressed_layers.len());
        
        let mut total_proofs = 0;
        for (i, layer) in compressed.compressed_layers.iter().enumerate() {
            println!("    Layer {}: {} batched proofs", i, layer.num_proofs);
            total_proofs += layer.num_proofs;
        }
        println!("  Total proofs batched: {}", total_proofs);
    }

    // Verify PCD proof
    println!("\nVerifying PCD proof...");
    let relation_matrices = vec![vec![vec![]]];
    let matrix_a = vec![vec![]];
    
    let verified = PCDTree::verify_pcd_proof(
        &pcd_proof,
        folding,
        &relation_matrices,
        &matrix_a,
    )?;

    println!("  Verification result: {}", if verified { "PASSED ✓" } else { "FAILED ✗" });

    Ok(())
}

fn demonstrate_incremental_pcd(
    folding: &CycloFolding<F>,
) -> Result<(), String> {
    println!("Building incremental PCD...");

    let config = PCDConfig {
        max_depth: 10,
        branching_factor: 2,
        enable_compression: true,
        target_norm_bound: 1 << 20,
    };

    let mut incremental = IncrementalPCD::new(config, folding.clone());

    // Add instances incrementally
    let num_instances = 16;
    println!("Adding {} instances incrementally...", num_instances);

    for i in 0..num_instances {
        let instance = create_example_accumulator(&folding.ring, i);
        incremental.add_instance(instance)?;
        
        if (i + 1) % 4 == 0 {
            let stats = incremental.statistics();
            println!("  After {} instances:", i + 1);
            println!("    Total nodes: {}", stats.total_nodes);
            println!("    Max depth: {}", stats.max_depth);
        }
    }

    // Finalize and get proof
    println!("\nFinalizing incremental PCD...");
    let final_proof = incremental.finalize()?;

    println!("  Final proof depth: {}", final_proof.tree_depth);
    println!("  Final proof layers: {}", final_proof.layer_proofs.len());

    Ok(())
}

fn demonstrate_recursive_pcd(
    ring: &CyclotomicRing<F>,
) -> Result<(), String> {
    println!("Building recursive PCD with verification circuit...");

    let config = PCDConfig {
        max_depth: 4,
        branching_factor: 2,
        enable_compression: false,
        target_norm_bound: 1 << 20,
    };

    let mut recursive_pcd = RecursivePCD::new(config, ring.clone());

    // Create some leaf instances
    let num_leaves = 4;
    println!("Creating {} leaf instances...", num_leaves);
    
    for i in 0..num_leaves {
        let instance = create_example_accumulator(ring, i);
        recursive_pcd.tree.create_leaf(instance);
    }

    // Get circuit metrics before building
    println!("\nInitial circuit metrics:");
    let metrics = recursive_pcd.circuit_metrics();
    println!("  Gates: {}", metrics.num_gates);
    println!("  Wires: {}", metrics.num_wires);
    println!("  Depth: {}", metrics.depth);

    println!("\nRecursive PCD construction complete!");

    Ok(())
}

fn setup_parameters() -> CycloParams<F> {
    let conductor = 8; // X^4 + 1, degree φ(8) = 4
    let degree = euler_totient(conductor);
    
    CycloParams {
        conductor,
        modulus: F::from_u64(0xFFFFFFFF00000001u64), // Goldilocks
        extension_degree: 2,
        base_b: 16,
        norm_bound_B: F::from_u64(1 << 16),
        rank_a: 10,
        rank_a_prime: 15,
        witness_length: 32,
        max_folding_rounds: 10,
        expansion_factor: F::from_u64(2),
    }
}

fn create_strong_sampling_set(ring: &CyclotomicRing<F>) -> StrongSamplingSet<F> {
    let mut elements = Vec::new();
    
    // Create ternary set {-1, 0, 1}
    for val in [-1i64, 0, 1] {
        let mut coeffs = vec![F::zero(); ring.degree];
        if val == -1 {
            coeffs[0] = F::zero() - F::one();
        } else if val == 1 {
            coeffs[0] = F::one();
        }
        elements.push(RingElement::new(coeffs, ring.conductor));
    }

    StrongSamplingSet {
        elements,
        norm_bound: F::from_u64(1),
        non_unit_prob: 0.33,
    }
}

fn create_example_accumulator(
    ring: &CyclotomicRing<F>,
    index: usize,
) -> AccumulatorInstance<F> {
    let seed = F::from_u64((index + 1) as u64);
    
    // Create challenge points
    let challenge_point = vec![RingElement::new(
        vec![seed; ring.degree],
        ring.conductor,
    )];

    // Create eval points
    let eval_point = vec![RingElement::new(
        vec![seed * F::from_u64(2); ring.degree],
        ring.conductor,
    )];

    // Create image
    let image = vec![
        RingElement::new(
            vec![seed * F::from_u64(3); ring.degree],
            ring.conductor,
        );
        3
    ];

    AccumulatorInstance {
        linear_instance: LinearInstance {
            challenge_points: vec![challenge_point],
            eval_points: vec![eval_point],
            image,
        },
    }
}
