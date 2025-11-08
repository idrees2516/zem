// Multilinear Polynomial Commitment Example
// Demonstrates HyperWolf PCS usage for multilinear polynomials
//
// This example shows:
// 1. Creating multilinear polynomial from evaluations
// 2. Committing and proving evaluation
// 3. Multilinear-specific features

use neo_lattice_zkvm::commitment::hyperwolf::{
    HyperWolfPCS, Polynomial, EvalPoint,
};
use neo_lattice_zkvm::field::GoldilocksField;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HyperWolf Multilinear Polynomial Example ===\n");
    
    // Step 1: Setup
    println!("1. Setting up HyperWolf PCS...");
    let security_param = 128;
    let num_vars = 3; // 3-variable multilinear polynomial
    let degree_bound = 1 << num_vars; // 2^3 = 8 evaluations
    let ring_dim = 64;
    
    let params = HyperWolfPCS::setup::<GoldilocksField>(
        security_param,
        degree_bound,
        ring_dim,
    )?;
    
    println!("   ✓ Parameters generated for {} variables", num_vars);
    println!();
    
    // Step 2: Create multilinear polynomial
    // f(X₀, X₁, X₂) with evaluations on Boolean hypercube {0,1}³
    println!("2. Creating multilinear polynomial...");
    println!("   Evaluations on Boolean hypercube:");
    
    let evaluations = vec![
        GoldilocksField::from_u64(1),  // f(0,0,0) = 1
        GoldilocksField::from_u64(2),  // f(1,0,0) = 2
        GoldilocksField::from_u64(3),  // f(0,1,0) = 3
        GoldilocksField::from_u64(4),  // f(1,1,0) = 4
        GoldilocksField::from_u64(5),  // f(0,0,1) = 5
        GoldilocksField::from_u64(6),  // f(1,0,1) = 6
        GoldilocksField::from_u64(7),  // f(0,1,1) = 7
        GoldilocksField::from_u64(8),  // f(1,1,1) = 8
    ];
    
    for (i, &val) in evaluations.iter().enumerate() {
        let x0 = i & 1;
        let x1 = (i >> 1) & 1;
        let x2 = (i >> 2) & 1;
        println!("   f({},{},{}) = {}", x0, x1, x2, val.to_canonical_u64());
    }
    
    let polynomial = Polynomial::new_multilinear(evaluations, num_vars)?;
    println!("   ✓ Multilinear polynomial created");
    println!();
    
    // Step 3: Commit to polynomial
    println!("3. Committing to polynomial...");
    let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial)?;
    println!("   ✓ Commitment generated");
    println!();
    
    // Step 4: Evaluate at a random point
    println!("4. Evaluating at point (2, 3, 4)...");
    let eval_point = EvalPoint::Multilinear(vec![
        GoldilocksField::from_u64(2),
        GoldilocksField::from_u64(3),
        GoldilocksField::from_u64(4),
    ]);
    
    let eval_value = polynomial.evaluate(&eval_point)?;
    println!("   ✓ f(2,3,4) = {}", eval_value.to_canonical_u64());
    println!();
    
    // Step 5: Generate proof
    println!("5. Generating evaluation proof...");
    let proof = HyperWolfPCS::prove_eval(
        &params,
        &commitment,
        &polynomial,
        &eval_point,
        eval_value,
        &state,
    )?;
    println!("   ✓ Proof generated");
    println!();
    
    // Step 6: Verify proof
    println!("6. Verifying evaluation proof...");
    let is_valid = HyperWolfPCS::verify_eval(
        &params,
        &commitment,
        &eval_point,
        eval_value,
        &proof,
    )?;
    
    if is_valid {
        println!("   ✓ Proof verified successfully!");
    } else {
        return Err("Verification failed".into());
    }
    println!();
    
    // Step 7: Demonstrate evaluation at Boolean point
    println!("7. Verifying evaluation at Boolean point (1,0,1)...");
    let bool_point = EvalPoint::Multilinear(vec![
        GoldilocksField::from_u64(1),
        GoldilocksField::from_u64(0),
        GoldilocksField::from_u64(1),
    ]);
    
    let bool_value = polynomial.evaluate(&bool_point)?;
    println!("   f(1,0,1) = {} (should be 6)", bool_value.to_canonical_u64());
    
    let bool_proof = HyperWolfPCS::prove_eval(
        &params,
        &commitment,
        &polynomial,
        &bool_point,
        bool_value,
        &state,
    )?;
    
    let is_valid_bool = HyperWolfPCS::verify_eval(
        &params,
        &commitment,
        &bool_point,
        bool_value,
        &bool_proof,
    )?;
    
    if is_valid_bool {
        println!("   ✓ Boolean point proof verified!");
    }
    println!();
    
    println!("=== Example completed successfully! ===");
    
    Ok(())
}
