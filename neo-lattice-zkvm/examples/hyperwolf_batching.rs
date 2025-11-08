// Batching Example for HyperWolf PCS
// Demonstrates efficient batching of multiple evaluation proofs
//
// This example shows:
// 1. Batching multiple polynomials at a single point
// 2. Batching single polynomial at multiple points
// 3. Performance comparison with individual proofs

use neo_lattice_zkvm::commitment::hyperwolf::{
    HyperWolfPCS, Polynomial, EvalPoint,
    BatchingCoordinator, PolyEvalClaim,
};
use neo_lattice_zkvm::field::GoldilocksField;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HyperWolf Batching Example ===\n");
    
    // Setup
    println!("Setting up HyperWolf PCS...");
    let params = HyperWolfPCS::setup::<GoldilocksField>(128, 1 << 10, 64)?;
    let coordinator = BatchingCoordinator::new(params.clone());
    println!("✓ Setup complete\n");
    
    // Example 1: Multiple polynomials at single point
    println!("=== Example 1: Multiple Polynomials at Single Point ===\n");
    
    // Create 5 different polynomials
    let polynomials: Vec<_> = (0..5)
        .map(|i| {
            let coeffs = vec![
                GoldilocksField::from_u64(i + 1),
                GoldilocksField::from_u64(i + 2),
                GoldilocksField::from_u64(i + 3),
            ];
            Polynomial::new_univariate(coeffs, 1 << 10).unwrap()
        })
        .collect();
    
    // Commit to all polynomials
    let commitments_and_states: Vec<_> = polynomials.iter()
        .map(|poly| HyperWolfPCS::commit(&params, poly).unwrap())
        .collect();
    
    // Evaluate all at same point u = 10
    let eval_point = EvalPoint::Univariate(GoldilocksField::from_u64(10));
    
    // Create evaluation claims
    let claims: Vec<_> = polynomials.iter()
        .zip(commitments_and_states.iter())
        .map(|(poly, (commitment, _))| {
            let eval_value = poly.evaluate(&eval_point).unwrap();
            PolyEvalClaim {
                commitment: commitment.clone(),
                polynomial: Some(poly.clone()),
                eval_point: eval_point.clone(),
                eval_value,
            }
        })
        .collect();
    
    println!("Created {} evaluation claims at same point", claims.len());
    
    // Batch prove
    println!("\nGenerating batched proof...");
    let start = Instant::now();
    let batched_proof = coordinator.batch_multiple_polys_single_point(&claims)?;
    let batch_time = start.elapsed();
    println!("✓ Batched proof generated in {:?}", batch_time);
    
    // Verify batched proof
    println!("Verifying batched proof...");
    let start = Instant::now();
    let is_valid = batched_proof.verify(&claims)?;
    let verify_time = start.elapsed();
    
    if is_valid {
        println!("✓ Batched proof verified in {:?}", verify_time);
    } else {
        return Err("Batched verification failed".into());
    }
    
    // Compare with individual proofs
    println!("\nComparing with individual proofs...");
    let start = Instant::now();
    for (poly, (commitment, state)) in polynomials.iter().zip(commitments_and_states.iter()) {
        let eval_value = poly.evaluate(&eval_point)?;
        let _proof = HyperWolfPCS::prove_eval(
            &params,
            commitment,
            poly,
            &eval_point,
            eval_value,
            state,
        )?;
    }
    let individual_time = start.elapsed();
    println!("Individual proofs took: {:?}", individual_time);
    println!("Speedup: {:.2}x", individual_time.as_secs_f64() / batch_time.as_secs_f64());
    println!();
    
    // Example 2: Single multilinear polynomial at multiple points
    println!("=== Example 2: Single Polynomial at Multiple Points ===\n");
    
    // Create multilinear polynomial
    let num_vars = 4;
    let evaluations: Vec<_> = (0..16)
        .map(|i| GoldilocksField::from_u64(i + 1))
        .collect();
    let ml_polynomial = Polynomial::new_multilinear(evaluations, num_vars)?;
    
    let (ml_commitment, ml_state) = HyperWolfPCS::commit(&params, &ml_polynomial)?;
    
    // Multiple evaluation points
    let eval_points = vec![
        vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ],
        vec![
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(6),
            GoldilocksField::from_u64(7),
            GoldilocksField::from_u64(8),
        ],
        vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
            GoldilocksField::from_u64(5),
        ],
    ];
    
    let eval_values: Vec<_> = eval_points.iter()
        .map(|point| {
            let ep = EvalPoint::Multilinear(point.clone());
            ml_polynomial.evaluate(&ep).unwrap()
        })
        .collect();
    
    println!("Evaluating at {} different points", eval_points.len());
    
    // Batch prove multiple points
    println!("\nGenerating batched proof for multiple points...");
    let start = Instant::now();
    let batched_multipoint_proof = coordinator.batch_single_poly_multiple_points(
        &ml_polynomial,
        &ml_commitment,
        &eval_points,
        &eval_values,
    )?;
    let batch_multipoint_time = start.elapsed();
    println!("✓ Batched proof generated in {:?}", batch_multipoint_time);
    
    // Verify
    println!("Verifying batched multipoint proof...");
    let start = Instant::now();
    let is_valid_multipoint = batched_multipoint_proof.verify(
        &ml_commitment,
        &eval_points,
        &eval_values,
    )?;
    let verify_multipoint_time = start.elapsed();
    
    if is_valid_multipoint {
        println!("✓ Batched multipoint proof verified in {:?}", verify_multipoint_time);
    } else {
        return Err("Multipoint verification failed".into());
    }
    
    // Compare with individual proofs
    println!("\nComparing with individual proofs...");
    let start = Instant::now();
    for (point, value) in eval_points.iter().zip(eval_values.iter()) {
        let ep = EvalPoint::Multilinear(point.clone());
        let _proof = HyperWolfPCS::prove_eval(
            &params,
            &ml_commitment,
            &ml_polynomial,
            &ep,
            *value,
            &ml_state,
        )?;
    }
    let individual_multipoint_time = start.elapsed();
    println!("Individual proofs took: {:?}", individual_multipoint_time);
    println!("Speedup: {:.2}x", 
        individual_multipoint_time.as_secs_f64() / batch_multipoint_time.as_secs_f64());
    println!();
    
    println!("=== Batching Example Completed Successfully! ===");
    println!("\nKey Takeaways:");
    println!("- Batching multiple polynomials at same point: ~{}x faster", 
        (individual_time.as_secs_f64() / batch_time.as_secs_f64()) as usize);
    println!("- Batching single polynomial at multiple points: ~{}x faster",
        (individual_multipoint_time.as_secs_f64() / batch_multipoint_time.as_secs_f64()) as usize);
    println!("- Single proof instead of {} individual proofs", claims.len() + eval_points.len());
    
    Ok(())
}
