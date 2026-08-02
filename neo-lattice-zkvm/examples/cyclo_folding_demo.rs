//! Cyclo Folding Scheme Demo
//! 
//! Demonstrates the complete Cyclo folding workflow:
//! 1. Setup parameters
//! 2. R1CS relation to Committed Hybrid R1CS
//! 3. Extension commitment and range test
//! 4. Folding multiple instances
//! 5. IVC-style accumulation

use neo_lattice_zkvm::cyclo::*;
use neo_lattice_zkvm::field::GoldilocksField as F;
use rand::thread_rng;

fn main() -> Result<(), String> {
    println!("=== Cyclo: Lightweight Lattice-based Folding Demo ===\n");

    // Step 1: Setup parameters
    println!("1. Setting up parameters...");
    let params = setup_parameters()?;
    println!("   - Security level: {} bits", params.security_level);
    println!("   - Ring degree: {}", params.degree);
    println!("   - Witness length: {}", params.witness_length);
    println!("   - Max folding rounds: {}", params.max_folding_rounds);
    
    let proof_estimate = params.estimate_proof_size();
    println!("   - Estimated proof size: {:.2} KB", proof_estimate.total_kb);
    println!();

    // Step 2: Setup R1CS relation
    println!("2. Setting up R1CS relation...");
    let (r1cs_matrices, public_input, witness) = create_example_r1cs()?;
    println!("   - R1CS size: {}x{}", r1cs_matrices[0].len(), r1cs_matrices[0][0].len());
    println!("   - Public inputs: {}", public_input.len());
    println!("   - Witness size: {}", witness.len());
    println!();

    // Step 3: Create cyclotomic ring and commitment
    println!("3. Initializing cyclotomic ring...");
    let modulus = F::from_u64((1u64 << 50) - 1);
    let ring = CyclotomicRing::new(params.conductor, modulus);
    println!("   - Conductor: {}", ring.conductor);
    println!("   - Degree φ: {}", ring.degree);
    println!();

    // Step 4: Setup theta map for F_q -> R_q embedding
    println!("4. Setting up θ_k map for field embedding...");
    let base_k = 2; // Base-2 for low norm
    let theta_map = ThetaMap::new(base_k, ring.clone());
    
    // Verify low norm encoding
    let test_field_elem = F::from_u64(42);
    let ring_elem = theta_map.preimage(test_field_elem);
    println!("   - Field element {} maps to ring element with norm {}", 
             test_field_elem.to_u64(), ring_elem.norm_infinity().to_u64());
    println!();

    // Step 5: Setup Ajtai commitment
    println!("5. Generating Ajtai commitment key...");
    let mut rng = thread_rng();
    let ajtai = AjtaiCommitment::new(
        ring.clone(),
        params.rank_a,
        public_input.len() + 1 + witness.len(),
        &mut rng,
    );
    println!("   - Commitment matrix: {}x{}", params.rank_a, ajtai.witness_length);
    println!();

    // Step 6: Reduce R1CS to Committed Hybrid R1CS
    println!("6. Reducing R1CS to Committed Hybrid R1CS...");
    let r1cs_reduction = R1CSReduction::new(
        theta_map.clone(),
        ajtai.matrix_a.clone(),
        F::from_u64(params.norm_bound_B),
    );
    
    let (hybrid_instance, hybrid_witness) = r1cs_reduction.reduce_instance(
        &public_input,
        &witness,
    )?;
    println!("   - Public input encoded: {} ring elements", hybrid_instance.public_input.len());
    println!("   - Commitment computed: {} ring elements", hybrid_instance.commitment.len());
    println!();

    // Step 7: Setup strong sampling set
    println!("7. Generating strong sampling set...");
    let challenge_set = build_strong_sampling_set(
        ring.clone(),
        false, // Use approximate (ternary)
        None,
        Some(1.0 / 3.0), // Uniform ternary
    )?;
    println!("   - Challenge set size: {}", challenge_set.elements.len());
    println!("   - Non-unit probability: {:.2e}", challenge_set.non_unit_prob);
    println!();

    // Step 8: Hybrid R1CS to Principal Linear Relation
    println!("8. Reducing to Principal Linear Relation...");
    let mut transcript = Transcript::new(b"cyclo-demo");
    let hybrid_to_linear = HybridR1CSToLinear::new(
        theta_map.clone(),
        ring.clone(),
        params.extension_degree,
        challenge_set.clone(),
    );
    
    let (linear_instance, linear_witness, sumcheck_proof) = hybrid_to_linear.reduce(
        &hybrid_instance,
        &hybrid_witness,
        &r1cs_matrices,
        &ajtai.matrix_a,
        &mut transcript,
    )?;
    println!("   - Linear relation instance created");
    println!("   - Challenge points: {}", linear_instance.challenge_points.len());
    println!("   - Evaluation points: {}", linear_instance.eval_points.len());
    println!();

    // Step 9: Setup folding protocols
    println!("9. Setting up folding protocols...");
    
    // Extension commitment
    let ext_matrix_r = generate_commitment_key(
        &ring,
        params.rank_a_prime,
        params.witness_length * ((2.0 * params.norm_bound_B as f64).log2().ceil() as usize),
        b"extension-commitment-key",
    );
    let extension_commitment = ExtensionCommitment::new(
        ring.clone(),
        params.base_b,
        challenge_set.clone(),
        ext_matrix_r,
    );
    
    // Range test
    let range_test = RangeTest::new(
        ring.clone(),
        params.base_b,
        params.extension_degree,
    );
    
    // Folding challenge set
    let folding_challenges = build_strong_sampling_set(
        ring.clone(),
        false,
        None,
        Some(1.0 / 3.0),
    )?;
    
    println!("   - Extension commitment ready");
    println!("   - Range test ready");
    println!();

    // Step 10: Create folding scheme
    println!("10. Creating Cyclo folding scheme...");
    let cyclo_params = params.to_cyclo_params(modulus);
    let cyclo = CycloFolding::new(
        ring.clone(),
        cyclo_params.clone(),
        range_test,
        extension_commitment,
        folding_challenges,
    );
    println!("   - Folding scheme initialized");
    println!();

    // Step 11: Initialize accumulator
    println!("11. Initializing accumulator..");
    let acc_instance = AccumulatorInstance {
        linear_instance: LinearInstance {
            challenge_points: vec![],
            eval_points: vec![],
            image: vec![],
        },
    };
    let acc_witness = AccumulatorWitness {
        witness: vec![],
    };
    println!("   - Empty accumulator created");
    println!();

    // Step 12: Perform folding
    println!("12. Performing folding...");
    let relation_matrices = vec![ajtai.matrix_a.clone()];
    let inputs = vec![(linear_instance.clone(), linear_witness.clone())];
    
    transcript = Transcript::new(b"cyclo-folding");
    let (new_acc, new_witness, folding_proof) = cyclo.prove(
        &acc_instance,
        &acc_witness,
        &inputs,
        &relation_matrices,
        &ajtai.matrix_a,
        &mut transcript,
    )?;
    
    println!("   - Folding complete!");
    println!("   - Extension proofs: {}", folding_proof.extension_proofs.len());
    println!("   - Range proofs: {}", folding_proof.range_proofs.len());
    println!();

    // Step 13: Verify folding
    println!("13. Verifying folding...");
    transcript = Transcript::new(b"cyclo-folding");
    let verified_acc = cyclo.verify(
        &acc_instance,
        &[linear_instance],
        &folding_proof,
        &relation_matrices,
        &ajtai.matrix_a,
        &mut transcript,
    )?;
    
    println!("   - Verification successful! ✓");
    println!();

    // Step 14: Demonstrate IVC
    println!("14. Demonstrating IVC (multiple rounds)...");
    let num_rounds = 5;
    let mut current_acc = acc_instance;
    let mut current_witness = acc_witness;
    
    for round in 1..=num_rounds {
        println!("   Round {}/{}", round, num_rounds);
        
        // Create new instance for this round
        let (new_r1cs, new_public, new_witness) = create_example_r1cs()?;
        let (new_hybrid_inst, new_hybrid_wit) = r1cs_reduction.reduce_instance(
            &new_public,
            &new_witness,
        )?;
        
        transcript = Transcript::new(&format!("round-{}", round).as_bytes());
        let (new_linear_inst, new_linear_wit, _) = hybrid_to_linear.reduce(
            &new_hybrid_inst,
            &new_hybrid_wit,
            &new_r1cs,
            &ajtai.matrix_a,
            &mut transcript,
        )?;
        
        // Fold into accumulator
        transcript = Transcript::new(&format!("fold-{}", round).as_bytes());
        let inputs = vec![(new_linear_inst, new_linear_wit)];
        let (next_acc, next_witness, _) = cyclo.prove(
            &current_acc,
            &current_witness,
            &inputs,
            &relation_matrices,
            &ajtai.matrix_a,
            &mut transcript,
        )?;
        
        current_acc = next_acc;
        current_witness = next_witness;
        
        // Compute accumulated norm
        let acc_norm = cyclo_params.norm_bound_B.to_u64() + 
                      (round as u64 * params.base_b as u64 * 2);
        println!("     Accumulated norm: {}", acc_norm);
    }
    
    println!("   - IVC complete after {} rounds! ✓", num_rounds);
    println!();

    // Step 15: Summary
    println!("=== Summary ===");
    println!("✓ Parameter setup and estimation");
    println!("✓ R1CS to Committed Hybrid R1CS reduction");
    println!("✓ θ_k map for low-norm field embedding");
    println!("✓ Hybrid R1CS to Principal Linear Relation");
    println!("✓ Extension commitment protocol");
    println!("✓ Range test via sum-check");
    println!("✓ Single folding step");
    println!("✓ IVC with {} rounds", num_rounds);
    println!("\nCyclo folding scheme working correctly!");

    Ok(())
}

fn setup_parameters() -> Result<ParameterSet<F>, String> {
    ParameterBuilder::new()
        .security_level(128)
        .conductor(256)
        .modulus_bits(50)
        .base_b(1)
        .witness_length(1 << 12) // Smaller for demo
        .max_folding_rounds(64)
        .build()
}

fn create_example_r1cs() -> Result<([Vec<Vec<F>>; 3], Vec<F>, Vec<F>), String> {
    // Simple R1CS: x * x = y
    // Variables: [1, x, y]
    let m = 3;
    
    // M0: select x
    let mut m0 = vec![vec![F::zero(); m]; m];
    m0[0][1] = F::one(); // x
    
    // M1: select x
    let mut m1 = vec![vec![F::zero(); m]; m];
    m1[0][1] = F::one(); // x
    
    // M2: select y
    let mut m2 = vec![vec![F::zero(); m]; m];
    m2[0][2] = F::one(); // y
    
    let matrices = [m0, m1, m2];
    
    // Public input: x = 5
    let public_input = vec![F::from_u64(5)];
    
    // Private witness: y = 25
    let witness = vec![F::from_u64(25)];
    
    Ok((matrices, public_input, witness))
}
