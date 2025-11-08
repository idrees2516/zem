// Simple example demonstrating Neo folding scheme components

use neo_lattice_zkvm::{
    GoldilocksField, Field,
    CCSStructure, CCSInstance, SparseMatrix,
    EvaluationClaim, SumCheckProof, WitnessDecomposition,
};

fn main() {
    println!("Neo Lattice-based Folding Scheme Example\n");
    
    // Example 1: Simple R1CS as CCS
    example_r1cs();
    
    // Example 2: Witness Decomposition
    example_decomposition();
    
    // Example 3: Evaluation Claims
    example_evaluation_claims();
}

fn example_r1cs() {
    println!("=== Example 1: R1CS as CCS ===");
    
    type F = GoldilocksField;
    
    // Create simple R1CS: x * x = x (for x = 1)
    // This represents the constraint that x is either 0 or 1
    
    let mut a = SparseMatrix::new(1, 3);
    a.add_entry(0, 1, F::one()); // x
    
    let mut b = SparseMatrix::new(1, 3);
    b.add_entry(0, 1, F::one()); // x
    
    let mut c = SparseMatrix::new(1, 3);
    c.add_entry(0, 1, F::one()); // x
    
    let ccs = CCSStructure::from_r1cs(1, 3, a, b, c).unwrap();
    
    println!("CCS Structure:");
    println!("  - Constraints (m): {}", ccs.m);
    println!("  - Variables (n): {}", ccs.n);
    println!("  - Matrices (t): {}", ccs.t);
    println!("  - Terms (q): {}", ccs.q);
    
    // Test with x = 1
    let public_input = vec![F::one()];
    let witness = vec![];
    
    let instance = CCSInstance::new(ccs.clone(), public_input.clone(), witness.clone());
    
    if instance.verify() {
        println!("✓ CCS instance verified successfully for x = 1");
    } else {
        println!("✗ CCS verification failed");
    }
    
    // Test with x = 0
    let public_input_zero = vec![F::zero()];
    let instance_zero = CCSInstance::new(ccs, public_input_zero, vec![]);
    
    if instance_zero.verify() {
        println!("✓ CCS instance verified successfully for x = 0");
    } else {
        println!("✗ CCS verification failed");
    }
    
    println!();
}

fn example_decomposition() {
    println!("=== Example 2: Witness Decomposition ===");
    
    type F = GoldilocksField;
    
    // Create a witness with some values
    let witness = vec![
        F::from_u64(100),
        F::from_u64(200),
        F::from_u64(50),
        F::from_u64(150),
    ];
    
    let norm_bound = 200;
    
    println!("Original witness: {:?}", witness.iter().map(|f| f.to_canonical_u64()).collect::<Vec<_>>());
    println!("Norm bound: {}", norm_bound);
    
    // Decompose witness
    let decomposition = WitnessDecomposition::new(&witness, norm_bound).unwrap();
    
    println!("Decomposition:");
    println!("  - Base: {}", decomposition.base);
    println!("  - Number of digits: {}", decomposition.num_digits);
    
    // Verify decomposition
    if decomposition.verify_decomposition(&witness) {
        println!("✓ Decomposition correctness verified");
    } else {
        println!("✗ Decomposition verification failed");
    }
    
    if decomposition.verify_norm_bounds() {
        println!("✓ Norm bounds verified");
    } else {
        println!("✗ Norm bound verification failed");
    }
    
    println!();
}

fn example_evaluation_claims() {
    println!("=== Example 3: Evaluation Claims ===");
    
    type F = GoldilocksField;
    
    // Create a simple witness vector
    let witness = vec![
        F::from_u64(1),
        F::from_u64(2),
        F::from_u64(3),
        F::from_u64(4),
    ];
    
    println!("Witness: {:?}", witness.iter().map(|f| f.to_canonical_u64()).collect::<Vec<_>>());
    
    // Evaluation point (2 variables for 4 elements)
    let point = vec![F::zero(), F::zero()];
    
    println!("Evaluation point: [0, 0]");
    
    // Create MLE and evaluate
    use neo_lattice_zkvm::polynomial::MultilinearPolynomial;
    let mle = MultilinearPolynomial::new(witness.clone());
    let value = mle.evaluate(&point);
    
    println!("MLE evaluation at [0, 0]: {}", value.to_canonical_u64());
    println!("(Should equal first element: {})", witness[0].to_canonical_u64());
    
    if value == witness[0] {
        println!("✓ MLE evaluation correct");
    } else {
        println!("✗ MLE evaluation incorrect");
    }
    
    println!();
}
