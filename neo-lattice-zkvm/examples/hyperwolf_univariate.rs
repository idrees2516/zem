// Simple Univariate Polynomial Commitment Example
// Demonstrates basic HyperWolf PCS usage for univariate polynomials
//
// This example shows:
// 1. Setup with standard parameters
// 2. Committing to a univariate polynomial
// 3. Proving evaluation at a point
// 4. Verifying the evaluation proof

use neo_lattice_zkvm::commitment::hyperwolf::{
    HyperWolfPCS, Polynomial, EvalPoint,
};
use neo_lattice_zkvm::field::GoldilocksField;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HyperWolf Univariate Polynomial Example ===\n");
    
    // Step 1: Setup
    println!("1. Setting up HyperWolf PCS...");
    let security_param = 128;
    let degree_bound = 1 << 10; // Support polynomials up to degree 1024
    let ring_dim = 64;
    
    let params = HyperWolfPCS::setup::<GoldilocksField>(
        security_param,
        degree_bound,
        ring_dim,
    )?;
    
    println!("   ✓ Parameters generated");
    println!("   - Security: {} bits", security_param);
    println!("   - Degree bound: {}", degree_bound);
    println!("   - Ring dimension: {}", ring_dim);
    println!();
    
    // Step 2: Create polynomial f(X) = 1 + 2X + 3X² + 4X³
    println!("2. Creating polynomial f(X) = 1 + 2X + 3X² + 4X³...");
    let coeffs = vec![
        GoldilocksField::from_u64(1),
        GoldilocksField::from_u64(2),
        GoldilocksField::from_u64(3),
        GoldilocksField::from_u64(4),
    ];
    
    let polynomial = Polynomial::new_univariate(coeffs, degree_bound)?;
    println!("   ✓ Polynomial created");
    println!();
    
    // Step 3: Commit to polynomial
    println!("3. Committing to polynomial...");
    let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial)?;
    println!("   ✓ Commitment generated");
    println!("   - Commitment size: {} ring elements", commitment.value.len());
    println!();
    
    // Step 4: Evaluate polynomial at point u = 5
    println!("4. Evaluating polynomial at u = 5...");
    let eval_point = EvalPoint::Univariate(GoldilocksField::from_u64(5));
    let eval_value = polynomial.evaluate(&eval_point)?;
    
    // f(5) = 1 + 2*5 + 3*25 + 4*125 = 1 + 10 + 75 + 500 = 586
    println!("   ✓ f(5) = {}", eval_value.to_canonical_u64());
    println!();
    
    // Step 5: Generate evaluation proof
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
    println!("   - Number of rounds: {}", proof.eval_proofs.len());
    println!();
    
    // Step 6: Verify evaluation proof
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
        println!("   ✗ Proof verification failed!");
        return Err("Verification failed".into());
    }
    println!();
    
    // Step 7: Try verifying with wrong value (should fail)
    println!("7. Testing soundness with wrong value...");
    let wrong_value = GoldilocksField::from_u64(999);
    let is_valid_wrong = HyperWolfPCS::verify_eval(
        &params,
        &commitment,
        &eval_point,
        wrong_value,
        &proof,
    )?;
    
    if !is_valid_wrong {
        println!("   ✓ Correctly rejected wrong value!");
    } else {
        println!("   ✗ Incorrectly accepted wrong value!");
        return Err("Soundness check failed".into());
    }
    println!();
    
    println!("=== Example completed successfully! ===");
    
    Ok(())
}
