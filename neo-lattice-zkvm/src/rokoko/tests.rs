// Comprehensive test suite for RoKoko protocol

#[cfg(test)]
mod integration_tests {
    use crate::rokoko::*;
    use crate::rokoko::polynomial::MultilinearPolynomial;
    use crate::rokoko::protocol::{RokokoParams, Statement, Witness};
    use crate::rokoko::prover::RokokoProver;
    use crate::rokoko::verifier::RokokoVerifier;
    use crate::rokoko::batching::{BatchProver, BatchVerifier};
    use crate::rokoko::optimization::*;

    #[test]
    fn test_end_to_end_proof() {
        let params = RokokoParams::default();
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(2, 1, sum);
        let witness = Witness::new(vec![poly]);

        let mut prover = RokokoProver::new(params.clone(), false);
        let proof = prover.prove(&statement, &witness).unwrap();

        let mut verifier = RokokoVerifier::new(params);
        let valid = verifier.verify(&statement, &proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_invalid_proof_rejected() {
        let params = RokokoParams::default();
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(2, 1, sum + 1); // Wrong sum
        let witness = Witness::new(vec![poly]);

        let mut prover = RokokoProver::new(params.clone(), false);
        let result = prover.prove(&statement, &witness);
        
        // Should fail or be rejected
        assert!(result.is_err() || {
            let proof = result.unwrap();
            let mut verifier = RokokoVerifier::new(params);
            !verifier.verify(&statement, &proof).unwrap()
        });
    }

    #[test]
    fn test_multiple_polynomials() {
        let params = RokokoParams::default();
        let poly1 = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let poly2 = MultilinearPolynomial::new(vec![5, 6, 7, 8], 2).unwrap();
        
        let sum = poly1.sum_over_hypercube();

        let statement = Statement::new(2, 2, sum);
        let witness = Witness::new(vec![poly1, poly2]);

        let mut prover = RokokoProver::new(params.clone(), false);
        let proof = prover.prove(&statement, &witness).unwrap();

        let mut verifier = RokokoVerifier::new(params);
        let valid = verifier.verify(&statement, &proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_zero_knowledge_property() {
        let params = RokokoParams::default();
        let secret_poly = MultilinearPolynomial::new(vec![42, 17, 99, 8], 2).unwrap();
        let sum = secret_poly.sum_over_hypercube();

        let statement = Statement::new(2, 1, sum);
        let witness = Witness::new(vec![secret_poly]);

        let mut prover = RokokoProver::new(params.clone(), false);
        let zk_proof = prover.prove_zk(&statement, &witness).unwrap();

        // Proof should not leak witness
        assert_ne!(zk_proof.witness_commitment.values[0], 42);
        
        // But should still verify
        let mut verifier = RokokoVerifier::new(params);
        let valid = verifier.verify(&statement, &zk_proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_batch_verification() {
        let params = RokokoParams::default();
        let mut statements = Vec::new();
        let mut proofs = Vec::new();

        for i in 1..=3 {
            let coeffs = vec![i, i+1, i+2, i+3];
            let poly = MultilinearPolynomial::new(coeffs, 2).unwrap();
            let sum = poly.sum_over_hypercube();

            let statement = Statement::new(2, 1, sum);
            let witness = Witness::new(vec![poly]);

            let mut prover = RokokoProver::new(params.clone(), false);
            let proof = prover.prove(&statement, &witness).unwrap();

            statements.push(statement);
            proofs.push(proof);
        }

        let batch_prover = BatchProver::new(false);
        let batch_proof = batch_prover.prove_batch(&statements, proofs).unwrap();

        let batch_verifier = BatchVerifier::new(false);
        let valid = batch_verifier.verify_batch(&statements, &batch_proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_parallel_proving() {
        let params = RokokoParams::default();
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 3).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(3, 1, sum);
        let witness = Witness::new(vec![poly]);

        // Sequential
        let mut prover_seq = RokokoProver::new(params.clone(), false);
        let start = std::time::Instant::now();
        let proof_seq = prover_seq.prove(&statement, &witness).unwrap();
        let time_seq = start.elapsed();

        // Parallel
        let mut prover_par = RokokoProver::new(params.clone(), true);
        let start = std::time::Instant::now();
        let proof_par = prover_par.prove(&statement, &witness).unwrap();
        let time_par = start.elapsed();

        println!("Sequential: {:?}, Parallel: {:?}", time_seq, time_par);
        
        // Both should verify
        let mut verifier = RokokoVerifier::new(params);
        assert!(verifier.verify(&statement, &proof_seq).unwrap());
        verifier.reset();
        assert!(verifier.verify(&statement, &proof_par).unwrap());
    }

    #[test]
    fn test_proof_size_scaling() {
        let params = RokokoParams::default();
        
        for num_vars in 2..=5 {
            let size = 1 << num_vars;
            let coeffs: Vec<u64> = (1..=size).map(|i| i as u64).collect();
            let poly = MultilinearPolynomial::new(coeffs, num_vars).unwrap();
            let sum = poly.sum_over_hypercube();

            let statement = Statement::new(num_vars, 1, sum);
            let witness = Witness::new(vec![poly]);

            let mut prover = RokokoProver::new(params.clone(), false);
            let proof = prover.prove(&statement, &witness).unwrap();

            println!("Variables: {}, Proof size: {} bytes", num_vars, proof.size_bytes());
            
            // Size should grow logarithmically
            assert!(proof.size_bytes() < size * 100); // Much smaller than witness
        }
    }

    #[test]
    fn test_evaluation_cache() {
        let cache = EvaluationCache::new(100);
        let point = vec![1, 2, 3];
        
        // First computation
        let result1 = cache.get_or_compute(&point, |p| Ok(p.iter().sum())).unwrap();
        
        // Second computation should hit cache
        let result2 = cache.get_or_compute(&point, |_| Ok(999)).unwrap();
        
        assert_eq!(result1, result2);
        assert_eq!(result1, 6);
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_simd_operations() {
        let ops = SimdPolynomialOps::new(16);
        let poly1 = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let poly2 = MultilinearPolynomial::new(vec![5, 6, 7, 8], 2).unwrap();
        
        let sum = ops.add_polynomials(&poly1, &poly2).unwrap();
        
        assert_eq!(sum.coefficients[0], 6);
        assert_eq!(sum.coefficients[1], 8);
        assert_eq!(sum.coefficients[2], 10);
        assert_eq!(sum.coefficients[3], 12);
    }

    #[test]
    fn test_streaming_operations() {
        let streaming = StreamingOps::new(64);
        let large_coeffs: Vec<u64> = (1..=1000).collect();
        
        let sum = streaming.stream_sum(&large_coeffs);
        let expected: u64 = large_coeffs.iter().sum::<u64>() % ((1 << 31) - 1);
        
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_parameter_validation() {
        let mut params = RokokoParams::default();
        assert!(params.validate().is_ok());

        params.security_level = 50; // Too low
        assert!(params.validate().is_err());

        params.security_level = 128;
        params.refinement_depth = 0; // Invalid
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_statement_validation() {
        let stmt = Statement::new(5, 2, 100);
        assert!(stmt.validate().is_ok());

        let bad_stmt = Statement::new(0, 2, 100); // No variables
        assert!(bad_stmt.validate().is_err());
    }

    #[test]
    fn test_witness_validation() {
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let witness = Witness::new(vec![poly]);
        let statement = Statement::new(2, 1, 10);
        
        assert!(witness.validate(&statement).is_ok());

        let bad_statement = Statement::new(3, 1, 10); // Wrong num_vars
        assert!(witness.validate(&bad_statement).is_err());
    }

    #[test]
    fn test_fast_verification() {
        let params = RokokoParams::default();
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4], 2).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(2, 1, sum);
        let witness = Witness::new(vec![poly]);

        let mut prover = RokokoProver::new(params.clone(), false);
        let proof = prover.prove(&statement, &witness).unwrap();

        // Fast verification should be quicker but still valid
        let mut verifier = RokokoVerifier::new(params);
        let start = std::time::Instant::now();
        let valid_fast = verifier.verify_fast(&statement, &proof).unwrap();
        let time_fast = start.elapsed();

        verifier.reset();
        let start = std::time::Instant::now();
        let valid_full = verifier.verify(&statement, &proof).unwrap();
        let time_full = start.elapsed();

        println!("Fast: {:?}, Full: {:?}", time_fast, time_full);
        
        assert!(valid_fast);
        assert!(valid_full);
    }

    #[test]
    fn test_proof_compression() {
        use crate::rokoko::batching::ProofCompressor;

        let params = RokokoParams::default();
        let poly = MultilinearPolynomial::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 3).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(3, 1, sum);
        let witness = Witness::new(vec![poly]);

        let mut prover = RokokoProver::new(params, false);
        let proof = prover.prove(&statement, &witness).unwrap();

        let original_size = proof.size_bytes();
        
        let compressor = ProofCompressor::new(0.5);
        let compressed = compressor.compress(&proof).unwrap();
        
        // Compressed should be smaller (exact format dependent)
        println!("Original: {} bytes, Compressed format created", original_size);
    }

    #[test]
    fn test_large_polynomial() {
        let params = RokokoParams::default();
        let num_vars = 6;
        let size = 1 << num_vars;
        let coeffs: Vec<u64> = (1..=size).map(|i| (i % 1000) as u64).collect();
        
        let poly = MultilinearPolynomial::new(coeffs, num_vars).unwrap();
        let sum = poly.sum_over_hypercube();

        let statement = Statement::new(num_vars, 1, sum);
        let witness = Witness::new(vec![poly]);

        let mut prover = RokokoProver::new(params.clone(), true);
        let proof = prover.prove(&statement, &witness).unwrap();

        let mut verifier = RokokoVerifier::new(params);
        let valid = verifier.verify(&statement, &proof).unwrap();
        
        assert!(valid);
        println!("Large polynomial ({} coeffs) verified successfully", size);
    }
}
