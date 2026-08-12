// ProtogaLattice demonstration
//
// This example shows how to use the ProtogaLattice constant-round folding scheme
// for general polynomial relations with post-quantum security.

use neo_lattice_zkvm::protogalattice::*;
use neo_lattice_zkvm::field::GoldilocksField;
use neo_lattice_zkvm::protogalattice::{
    prover::*,
    verifier::*,
    polynomial_relations::*,
    lattice_params::*,
    transcript::Transcript,
    optimization::*,
};
use rand::thread_rng;

fn main() -> Result<()> {
    println!("=== ProtogaLattice Demonstration ===\n");

    // Example 1: Basic polynomial constraint
    basic_polynomial_example()?;

    // Example 2: Multiple constraint folding
    multiple_constraint_folding()?;

    // Example 3: Incremental Verifiable Computation
    incremental_computation_example()?;

    // Example 4: Parallel proving
    parallel_proving_example()?;

    // Example 5: Batch verification
    batch_verification_example()?;

    println!("\n=== All Examples Completed Successfully ===");
    Ok(())
}

/// Example 1: Basic polynomial constraint proving
fn basic_polynomial_example() -> Result<()> {
    println!("--- Example 1: Basic Polynomial Constraint ---");

    let mut rng = thread_rng();
    let params = LatticeParams::new_128();
    
    // Define relation: x² + 2y = z
    let mut relation = GeneralPolynomialRelation::new(3);
    let mut constraint = PolynomialConstraint::new("quadratic_relation");
    
    // Add x²
    constraint.add_term(ConstraintTerm::new(
        GoldilocksField::from(1u64),
        vec![0],
        vec![2],
    ));
    
    // Add 2y
    constraint.add_term(ConstraintTerm::linear(
        GoldilocksField::from(2u64),
        1,
    ));
    
    // Add -z
    constraint.add_term(ConstraintTerm::linear(
        GoldilocksField::from(1u64).neg(),
        2,
    ));
    
    constraint.set_rhs(GoldilocksField::zero());
    relation.add_constraint(constraint);

    println!("  Relation: x² + 2y - z = 0");

    // Setup prover
    let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng)?;
    println!("  Prover setup complete");

    // Create satisfying witness: x=3, y=5, z=19 (9 + 10 = 19)
    let witness = vec![
        GoldilocksField::from(3u64),  // x
        GoldilocksField::from(5u64),  // y
        GoldilocksField::from(19u64), // z
    ];

    // Check witness satisfies relation
    assert!(relation.is_satisfied(&witness));
    println!("  Witness: x=3, y=5, z=19 ✓");

    // Generate proof
    let start = std::time::Instant::now();
    let (instance, _witness_struct, proof) = prover.prove(&witness, &[], &mut rng)?;
    let prove_time = start.elapsed();
    println!("  Proof generated in {:?}", prove_time);
    println!("  Instance has {} commitments", instance.commitments.len());

    // Setup verifier
    let verifier = ProtogaVerifier::from_proving_key(
        prover.proving_key.commitment_key.clone(),
        params,
        &relation,
    );

    // Verify proof
    let start = std::time::Instant::now();
    let valid = verifier.verify(&instance, &proof)?;
    let verify_time = start.elapsed();
    
    println!("  Proof verified in {:?}", verify_time);
    println!("  Verification result: {}", if valid { "VALID ✓" } else { "INVALID ✗" });
    assert!(valid);

    println!();
    Ok(())
}

/// Example 2: Folding multiple constraints
fn multiple_constraint_folding() -> Result<()> {
    println!("--- Example 2: Multiple Constraint Folding ---");

    let mut rng = thread_rng();
    let params = LatticeParams::new_128();
    
    // Define relation with multiple constraints
    let mut relation = GeneralPolynomialRelation::new(4);
    
    // Constraint 1: x + y = z
    let mut c1 = PolynomialConstraint::new("linear_sum");
    c1.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 0));
    c1.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 1));
    c1.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64).neg(), 2));
    c1.set_rhs(GoldilocksField::zero());
    relation.add_constraint(c1);

    // Constraint 2: x * y = w
    let mut c2 = PolynomialConstraint::new("product");
    c2.add_term(ConstraintTerm::new(
        GoldilocksField::from(1u64),
        vec![0, 1],
        vec![1, 1],
    ));
    c2.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64).neg(), 3));
    c2.set_rhs(GoldilocksField::zero());
    relation.add_constraint(c2);

    println!("  Relation:");
    println!("    Constraint 1: x + y = z");
    println!("    Constraint 2: x * y = w");

    let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng)?;
    let verifier = ProtogaVerifier::from_proving_key(
        prover.proving_key.commitment_key.clone(),
        params,
        &relation,
    );

    // Create multiple instances
    let witnesses = vec![
        vec![
            GoldilocksField::from(2u64),  // x
            GoldilocksField::from(3u64),  // y
            GoldilocksField::from(5u64),  // z = 2+3
            GoldilocksField::from(6u64),  // w = 2*3
        ],
        vec![
            GoldilocksField::from(4u64),  // x
            GoldilocksField::from(5u64),  // y
            GoldilocksField::from(9u64),  // z = 4+5
            GoldilocksField::from(20u64), // w = 4*5
        ],
        vec![
            GoldilocksField::from(7u64),  // x
            GoldilocksField::from(2u64),  // y
            GoldilocksField::from(9u64),  // z = 7+2
            GoldilocksField::from(14u64), // w = 7*2
        ],
    ];

    println!("  Generating {} proofs...", witnesses.len());

    // Generate proofs
    let proofs: Vec<_> = witnesses.iter()
        .map(|w| {
            assert!(relation.is_satisfied(w));
            prover.prove(w, &[], &mut rng).unwrap()
        })
        .collect();

    println!("  All witnesses valid ✓");

    let instances: Vec<_> = proofs.iter().map(|(inst, _, _)| inst.clone()).collect();
    let witness_structs: Vec<_> = proofs.iter().map(|(_, wit, _)| wit.clone()).collect();

    // Fold instances
    println!("  Folding {} instances...", instances.len());
    let start = std::time::Instant::now();
    
    let mut transcript = Transcript::new(b"multi_fold");
    let folding_proof = prover.prove_folding(&instances, &witness_structs, &mut transcript)?;
    
    let fold_time = start.elapsed();
    println!("  Folding completed in {:?}", fold_time);
    println!("  Folding proof has {} rounds", folding_proof.round_proofs.len());

    // Verify folding
    let start = std::time::Instant::now();
    let valid = verifier.verify_folding(&instances, &folding_proof)?;
    let verify_time = start.elapsed();

    println!("  Folding verified in {:?}", verify_time);
    println!("  Verification result: {}", if valid { "VALID ✓" } else { "INVALID ✗" });
    assert!(valid);

    println!();
    Ok(())
}

/// Example 3: Incremental Verifiable Computation
fn incremental_computation_example() -> Result<()> {
    println!("--- Example 3: Incremental Verifiable Computation ---");

    let mut rng = thread_rng();
    let params = LatticeParams::new_128();
    
    // Simple fibonacci-like relation: z = x + y
    let mut relation = GeneralPolynomialRelation::new(3);
    let mut constraint = PolynomialConstraint::new("fibonacci_step");
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 0));
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 1));
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64).neg(), 2));
    constraint.set_rhs(GoldilocksField::zero());
    relation.add_constraint(constraint);

    println!("  Relation: z = x + y (Fibonacci step)");

    let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng)?;
    let mut inc_prover = IncrementalProver::new(prover);

    // Prove multiple steps
    let num_steps = 10;
    println!("  Computing {} Fibonacci-like steps...", num_steps);

    let mut a = 1u64;
    let mut b = 1u64;

    for i in 0..num_steps {
        let c = a + b;
        let witness = vec![
            GoldilocksField::from(a),
            GoldilocksField::from(b),
            GoldilocksField::from(c),
        ];

        let mut transcript = Transcript::new(&format!("step_{}", i).as_bytes());
        let _proof = inc_prover.prove_step(&witness, &[], &mut transcript, &mut rng)?;

        println!("  Step {}: {} + {} = {}", i + 1, a, b, c);

        a = b;
        b = c;
    }

    let final_instance = inc_prover.get_accumulated().unwrap();
    println!("\n  Successfully accumulated {} steps into single instance", num_steps);
    println!("  Final instance has {} commitments", final_instance.commitments.len());
    println!("  Relaxation factor: {}", final_instance.relaxation_factor.to_canonical_u64());

    println!();
    Ok(())
}

/// Example 4: Parallel proving
fn parallel_proving_example() -> Result<()> {
    println!("--- Example 4: Parallel Proving ---");

    let mut rng = thread_rng();
    let params = LatticeParams::new_128();
    
    // Simple linear relation
    let mut relation = GeneralPolynomialRelation::new(2);
    let mut constraint = PolynomialConstraint::new("identity");
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64), 0));
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64).neg(), 1));
    constraint.set_rhs(GoldilocksField::zero());
    relation.add_constraint(constraint);

    let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng)?;

    // Create parallel prover
    let num_threads = 4;
    let parallel_prover = ParallelProver::new(prover, num_threads);
    println!("  Using {} threads for parallel proving", num_threads);

    // Generate many witnesses
    let num_proofs = 50;
    let witnesses: Vec<_> = (0..num_proofs)
        .map(|i| {
            let val = GoldilocksField::from((i + 1) as u64);
            vec![val, val]
        })
        .collect();

    let public_inputs = vec![vec![]; num_proofs];

    println!("  Generating {} proofs in parallel...", num_proofs);

    // Prove in parallel
    let start = std::time::Instant::now();
    let proofs = parallel_prover.parallel_prove(witnesses, public_inputs)?;
    let total_time = start.elapsed();

    println!("  Generated {} proofs in {:?}", proofs.len(), total_time);
    println!("  Average time per proof: {:?}", total_time / num_proofs as u32);

    // Verify one proof to check correctness
    let verifier = ProtogaVerifier::from_proving_key(
        parallel_prover.prover.proving_key.commitment_key.clone(),
        params,
        &relation,
    );

    let (instance, _, proof) = &proofs[0];
    let valid = verifier.verify(instance, proof)?;
    println!("  Sample proof verification: {}", if valid { "VALID ✓" } else { "INVALID ✗" });

    println!();
    Ok(())
}

/// Example 5: Batch verification
fn batch_verification_example() -> Result<()> {
    println!("--- Example 5: Batch Verification ---");

    let mut rng = thread_rng();
    let params = LatticeParams::new_128();
    
    // Linear relation for batch verification
    let mut relation = GeneralPolynomialRelation::new(2);
    let mut constraint = PolynomialConstraint::new("linear");
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(2u64), 0));
    constraint.add_term(ConstraintTerm::linear(GoldilocksField::from(1u64).neg(), 1));
    constraint.set_rhs(GoldilocksField::zero());
    relation.add_constraint(constraint);

    println!("  Relation: 2x = y");

    let prover = ProtogaProver::setup(params.clone(), relation.clone(), &mut rng)?;
    let verifier = ProtogaVerifier::from_proving_key(
        prover.proving_key.commitment_key.clone(),
        params,
        &relation,
    );

    // Generate multiple proofs
    let num_proofs = 20;
    let witnesses: Vec<_> = (1..=num_proofs)
        .map(|i| {
            let x = GoldilocksField::from(i as u64);
            let y = GoldilocksField::from((2 * i) as u64);
            vec![x, y]
        })
        .collect();

    println!("  Generating {} proofs...", num_proofs);

    let proofs: Vec<_> = witnesses.iter()
        .map(|w| prover.prove(w, &[], &mut rng).unwrap())
        .collect();

    let instances: Vec<_> = proofs.iter().map(|(inst, _, _)| inst.clone()).collect();
    let proof_vec: Vec<_> = proofs.iter().map(|(_, _, proof)| proof.clone()).collect();

    // Individual verification
    println!("  Individual verification...");
    let start = std::time::Instant::now();
    for (instance, proof) in instances.iter().zip(proof_vec.iter()) {
        let valid = verifier.verify(instance, proof)?;
        assert!(valid);
    }
    let individual_time = start.elapsed();
    println!("    Time: {:?}", individual_time);
    println!("    Per proof: {:?}", individual_time / num_proofs as u32);

    // Batch verification
    println!("  Batch verification...");
    let start = std::time::Instant::now();
    let valid = verifier.batch_verify(&instances, &proof_vec)?;
    let batch_time = start.elapsed();

    println!("    Time: {:?}", batch_time);
    println!("    Speedup: {:.2}x", individual_time.as_secs_f64() / batch_time.as_secs_f64());
    println!("    Result: {}", if valid { "ALL VALID ✓" } else { "INVALID ✗" });
    assert!(valid);

    println!();
    Ok(())
}
