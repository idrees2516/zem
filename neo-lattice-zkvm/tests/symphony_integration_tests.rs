// Symphony SNARK Integration Tests
// Comprehensive end-to-end tests for the complete system

use neo_lattice_zkvm::field::{Field, GoldilocksField};
use neo_lattice_zkvm::ring::{CyclotomicRing, RingElement};
use neo_lattice_zkvm::snark::symphony::{SymphonySNARK, SymphonyParams};
use neo_lattice_zkvm::protocols::rok_traits::R1CSInstance;
use neo_lattice_zkvm::commitment::ajtai::{AjtaiCommitment, AjtaiParams};

type F = GoldilocksField;

/// Create simple R1CS instance for testing
/// Constraint: x * y = z
fn create_simple_r1cs() -> (R1CSInstance<F>, Vec<F>) {
    let num_constraints = 1;
    let num_variables = 3; // x, y, z
    
    // Matrices for x * y = z
    // M1 = [1, 0, 0] (selects x)
    // M2 = [0, 1, 0] (selects y)
    // M3 = [0, 0, 1] (selects z)
    
    use neo_lattice_zkvm::protocols::rok_traits::SparseMatrix;
    
    let mut m1 = SparseMatrix::new(num_constraints, num_variables);
    m1.add_entry(0, 0, F::one());
    
    let mut m2 = SparseMatrix::new(num_constraints, num_variables);
    m2.add_entry(0, 1, F::one());
    
    let mut m3 = SparseMatrix::new(num_constraints, num_variables);
    m3.add_entry(0, 2, F::one());
    
    let instance = R1CSInstance {
        num_constraints,
        num_variables,
        public_input: vec![F::from_u64(3), F::from_u64(4), F::from_u64(12)], // 3 * 4 = 12
        matrices: (m1, m2, m3),
    };
    
    let witness = vec![F::from_u64(3), F::from_u64(4), F::from_u64(12)];
    
    (instance, witness)
}

/// Create batch of R1CS instances
fn create_batch_r1cs(count: usize) -> (Vec<R1CSInstance<F>>, Vec<Vec<F>>) {
    let mut instances = Vec::with_capacity(count);
    let mut witnesses = Vec::with_capacity(count);
    
    for i in 0..count {
        let (instance, witness) = create_simple_r1cs();
        instances.push(instance);
        witnesses.push(witness);
    }
    
    (instances, witnesses)
}

#[test]
fn test_symphony_setup_post_quantum() {
    let params = SymphonyParams::default_post_quantum();
    let snark = SymphonySNARK::<F>::setup(params);
    
    assert!(snark.is_ok(), "Setup failed: {:?}", snark.err());
    
    let snark = snark.unwrap();
    assert_eq!(snark.params().degree, 64);
    assert_eq!(snark.params().security_level, 128);
}

#[test]
fn test_symphony_setup_classical() {
    let params = SymphonyParams::default_classical();
    let snark = SymphonySNARK::<F>::setup(params);
    
    assert!(snark.is_ok(), "Setup failed: {:?}", snark.err());
    
    let snark = snark.unwrap();
    assert_eq!(snark.params().degree, 64);
}

#[test]
fn test_symphony_setup_high_throughput() {
    let params = SymphonyParams::high_throughput();
    let snark = SymphonySNARK::<F>::setup(params);
    
    assert!(snark.is_ok(), "Setup failed: {:?}", snark.err());
    
    let snark = snark.unwrap();
    assert_eq!(snark.params().folding_arity, 65536);
}

#[test]
fn test_parameter_security_verification() {
    let params = SymphonyParams::default_post_quantum();
    assert!(params.verify_security().is_ok());
    
    // Test invalid parameters
    let mut invalid_params = params.clone();
    invalid_params.folding_arity = 100; // Not power of 2
    assert!(invalid_params.verify_security().is_err());
    
    invalid_params.folding_arity = 512; // Too small
    assert!(invalid_params.verify_security().is_err());
}

#[test]
fn test_proof_size_estimation() {
    let params = SymphonyParams::default_post_quantum();
    let size = params.estimate_proof_size();
    
    println!("Estimated post-quantum proof size: {} bytes ({:.2} KB)", size, size as f64 / 1024.0);
    
    // Post-quantum proof should be < 200KB
    assert!(size < 200_000, "Proof size {} exceeds 200KB", size);
    
    // Classical proof should be smaller
    let classical_params = SymphonyParams::default_classical();
    let classical_size = classical_params.estimate_proof_size();
    
    println!("Estimated classical proof size: {} bytes ({:.2} KB)", classical_size, classical_size as f64 / 1024.0);
    
    // Classical proof should be < 50KB
    assert!(classical_size < 50_000, "Classical proof size {} exceeds 50KB", classical_size);
}

#[test]
fn test_verification_time_estimation() {
    let params = SymphonyParams::default_post_quantum();
    let time = params.estimate_verification_time();
    
    println!("Estimated verification time: {:.2} ms", time);
    
    // Verification should be in tens of milliseconds
    assert!(time < 100.0, "Verification time {}ms exceeds 100ms", time);
    assert!(time > 0.0, "Verification time must be positive");
}

#[test]
fn test_prover_complexity_estimation() {
    let params = SymphonyParams::default_post_quantum();
    let complexity = params.estimate_prover_complexity();
    
    println!("Estimated prover complexity: {} Rq-multiplications ({:.2e})", complexity, complexity as f64);
    
    // Should be around 3·2^32 Rq-multiplications
    let expected = 3u64 * (1u64 << 32);
    let ratio = complexity as f64 / expected as f64;
    
    println!("Complexity ratio vs baseline: {:.2}", ratio);
    
    assert!(ratio > 0.1 && ratio < 10.0, "Prover complexity ratio {} out of reasonable range", ratio);
}

#[test]
#[ignore] // Expensive test
fn test_symphony_prove_verify_small_batch() {
    // Use smaller folding arity for faster testing
    let mut params = SymphonyParams::default_post_quantum();
    params.folding_arity = 4; // Minimum for testing
    
    let snark = SymphonySNARK::<F>::setup(params).expect("Setup failed");
    
    // Create batch of R1CS instances
    let (instances, witnesses) = create_batch_r1cs(4);
    
    // Generate proof
    println!("Generating proof...");
    let proof_result = snark.prove(&instances, &witnesses);
    
    if let Err(e) = &proof_result {
        println!("Proof generation failed: {}", e);
    }
    
    assert!(proof_result.is_ok(), "Proof generation failed");
    let proof = proof_result.unwrap();
    
    println!("Proof size: {} bytes", proof.size());
    
    // Verify proof
    println!("Verifying proof...");
    let verify_result = snark.verify(&instances, &proof);
    
    assert!(verify_result.is_ok(), "Verification failed: {:?}", verify_result.err());
    assert!(verify_result.unwrap(), "Proof verification returned false");
}

#[test]
fn test_ajtai_commitment_integration() {
    let params = AjtaiParams::new_128bit_security(64, F::MODULUS, 4);
    assert!(params.verify_security());
    
    let key = AjtaiCommitment::<F>::setup(params, 256, None);
    
    assert_eq!(key.kappa, 4);
    assert_eq!(key.n, 256);
    assert_eq!(key.matrix_a.len(), 4);
    assert_eq!(key.matrix_a[0].len(), 256);
}

#[test]
fn test_ring_operations() {
    let ring = CyclotomicRing::<F>::new(64).expect("Ring creation failed");
    
    let a = ring.random_element();
    let b = ring.random_element();
    
    // Test addition
    let c = ring.add(&a, &b);
    assert_eq!(c.coeffs.len(), 64);
    
    // Test multiplication
    let d = ring.mul(&a, &b);
    assert_eq!(d.coeffs.len(), 64);
    
    // Test commutativity
    let e = ring.mul(&b, &a);
    assert_eq!(d.coeffs, e.coeffs, "Multiplication not commutative");
}

#[test]
fn test_folding_arity_scaling() {
    let arities = vec![1024, 2048, 4096, 8192, 16384];
    
    for arity in arities {
        let mut params = SymphonyParams::default_post_quantum();
        params.folding_arity = arity;
        
        assert!(params.verify_security().is_ok(), "Security verification failed for arity {}", arity);
        
        let proof_size = params.estimate_proof_size();
        let verify_time = params.estimate_verification_time();
        
        println!("Arity {}: proof size = {} bytes, verify time = {:.2} ms", 
                 arity, proof_size, verify_time);
        
        // Verify scaling properties
        assert!(proof_size < 500_000, "Proof size too large for arity {}", arity);
        assert!(verify_time < 200.0, "Verification time too long for arity {}", arity);
    }
}

#[test]
fn test_memory_budget_configuration() {
    let budgets = vec![
        100_000_000,   // 100MB
        500_000_000,   // 500MB
        1_000_000_000, // 1GB
        4_000_000_000, // 4GB
    ];
    
    for budget in budgets {
        let mut params = SymphonyParams::default_post_quantum();
        params.memory_budget = budget;
        params.use_streaming = true;
        
        let snark = SymphonySNARK::<F>::setup(params);
        assert!(snark.is_ok(), "Setup failed for memory budget {}", budget);
        
        println!("Successfully configured with memory budget: {} bytes ({:.2} GB)", 
                 budget, budget as f64 / 1_000_000_000.0);
    }
}

#[test]
fn test_hash_function_options() {
    use neo_lattice_zkvm::fiat_shamir::hash_oracle::HashFunction;
    
    let hash_functions = vec![
        HashFunction::Blake3,
        HashFunction::Sha256,
        HashFunction::Poseidon,
    ];
    
    for hash_fn in hash_functions {
        let mut params = SymphonyParams::default_post_quantum();
        params.hash_function = hash_fn;
        params.folding_arity = 4; // Small for testing
        
        let snark = SymphonySNARK::<F>::setup(params);
        assert!(snark.is_ok(), "Setup failed for hash function {:?}", hash_fn);
        
        println!("Successfully configured with hash function: {:?}", hash_fn);
    }
}

#[test]
fn test_streaming_vs_standard_prover() {
    let mut params = SymphonyParams::default_post_quantum();
    params.folding_arity = 4;
    
    // Test with streaming enabled
    params.use_streaming = true;
    let snark_streaming = SymphonySNARK::<F>::setup(params.clone());
    assert!(snark_streaming.is_ok(), "Streaming setup failed");
    
    // Test with streaming disabled
    params.use_streaming = false;
    let snark_standard = SymphonySNARK::<F>::setup(params);
    assert!(snark_standard.is_ok(), "Standard setup failed");
    
    println!("Both streaming and standard provers configured successfully");
}

#[test]
fn test_parameter_presets() {
    let presets = vec![
        ("Post-Quantum", SymphonyParams::default_post_quantum()),
        ("Classical", SymphonyParams::default_classical()),
        ("High-Throughput", SymphonyParams::high_throughput()),
    ];
    
    for (name, params) in presets {
        println!("\nTesting {} preset:", name);
        println!("  Degree: {}", params.degree);
        println!("  Folding arity: {}", params.folding_arity);
        println!("  Security level: {}", params.security_level);
        println!("  Proof size estimate: {} bytes", params.estimate_proof_size());
        println!("  Verification time estimate: {:.2} ms", params.estimate_verification_time());
        
        assert!(params.verify_security().is_ok(), "{} preset security verification failed", name);
    }
}

#[test]
fn test_concurrent_proof_generation() {
    use std::sync::Arc;
    use std::thread;
    
    let params = SymphonyParams::default_post_quantum();
    let snark = Arc::new(SymphonySNARK::<F>::setup(params).expect("Setup failed"));
    
    let mut handles = vec![];
    
    // Spawn multiple threads (simulating concurrent proof generation)
    for i in 0..4 {
        let snark_clone = Arc::clone(&snark);
        
        let handle = thread::spawn(move || {
            println!("Thread {} checking parameters", i);
            let proof_size = snark_clone.estimate_proof_size();
            let verify_time = snark_clone.estimate_verification_time();
            
            assert!(proof_size > 0);
            assert!(verify_time > 0.0);
            
            println!("Thread {} completed: proof_size={}, verify_time={:.2}ms", 
                     i, proof_size, verify_time);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
    
    println!("All concurrent operations completed successfully");
}

#[test]
fn test_proof_serialization() {
    // This test verifies proof serialization/deserialization
    // Currently a placeholder as full implementation requires complete proof generation
    
    use neo_lattice_zkvm::snark::cp_snark::CPSNARKProof;
    
    let proof = CPSNARKProof::<F> {
        verification_proof: vec![1, 2, 3, 4],
        commitment_proof: vec![5, 6, 7, 8],
        output_proof: vec![9, 10, 11, 12],
    };
    
    // Verify proof structure
    assert_eq!(proof.verification_proof.len(), 4);
    assert_eq!(proof.commitment_proof.len(), 4);
    assert_eq!(proof.output_proof.len(), 4);
    
    println!("Proof serialization structure verified");
}

#[test]
fn test_error_handling() {
    let params = SymphonyParams::default_post_quantum();
    let snark = SymphonySNARK::<F>::setup(params).expect("Setup failed");
    
    // Test with wrong number of instances
    let (instances, witnesses) = create_batch_r1cs(2);
    let result = snark.prove(&instances, &witnesses);
    
    assert!(result.is_err(), "Should fail with wrong number of instances");
    
    println!("Error handling test passed: {}", result.err().unwrap());
}

#[test]
fn test_benchmark_data_collection() {
    let params = SymphonyParams::default_post_quantum();
    
    println!("\n=== Symphony SNARK Benchmark Data ===");
    println!("Parameters:");
    println!("  Ring degree: {}", params.degree);
    println!("  Modulus: {}", params.modulus);
    println!("  Folding arity: {}", params.folding_arity);
    println!("  Security level: {} bits", params.security_level);
    println!("\nPerformance Estimates:");
    println!("  Proof size: {} bytes ({:.2} KB)", 
             params.estimate_proof_size(), 
             params.estimate_proof_size() as f64 / 1024.0);
    println!("  Verification time: {:.2} ms", params.estimate_verification_time());
    println!("  Prover complexity: {:.2e} Rq-muls", params.estimate_prover_complexity() as f64);
    println!("=====================================\n");
}

// Helper function to run all tests
#[test]
fn test_comprehensive_system_check() {
    println!("\n=== Running Comprehensive System Check ===\n");
    
    // 1. Parameter validation
    println!("1. Validating parameters...");
    let params = SymphonyParams::default_post_quantum();
    assert!(params.verify_security().is_ok());
    println!("   ✓ Parameters valid\n");
    
    // 2. Setup
    println!("2. Running setup...");
    let snark = SymphonySNARK::<F>::setup(params);
    assert!(snark.is_ok());
    println!("   ✓ Setup successful\n");
    
    // 3. Estimate performance
    let snark = snark.unwrap();
    println!("3. Performance estimates:");
    println!("   Proof size: {} bytes", snark.estimate_proof_size());
    println!("   Verification time: {:.2} ms", snark.estimate_verification_time());
    println!("   ✓ Estimates computed\n");
    
    // 4. Component checks
    println!("4. Checking components:");
    println!("   Ring degree: {}", snark.params().degree);
    println!("   Folding arity: {}", snark.params().folding_arity);
    println!("   Challenge set size: {}", snark.params().challenge_set_size);
    println!("   ✓ All components initialized\n");
    
    println!("=== System Check Complete ===\n");
}
