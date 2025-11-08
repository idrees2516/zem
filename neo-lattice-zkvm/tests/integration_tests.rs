// Comprehensive Integration Tests for Symphony SNARK
// Tests all components working together

use neo_lattice_zkvm::*;

#[cfg(test)]
mod symphony_integration_tests {
    use super::*;
    
    #[test]
    fn test_symphony_setup_post_quantum() {
        let params = SymphonyParams::default_post_quantum();
        assert!(params.validate().is_ok());
        
        // Verify parameters
        assert_eq!(params.ring_degree, 64);
        assert_eq!(params.extension_degree, 2);
        assert_eq!(params.folding_arity, 1024);
        assert_eq!(params.security_parameter, 128);
    }
    
    #[test]
    fn test_symphony_setup_classical() {
        let params = SymphonyParams::default_classical();
        assert!(params.validate().is_ok());
        
        assert_eq!(params.folding_arity, 2048);
    }
    
    #[test]
    fn test_symphony_setup_high_arity() {
        let params = SymphonyParams::high_arity();
        assert!(params.validate().is_ok());
        
        assert_eq!(params.folding_arity, 65536);
    }
    
    #[test]
    fn test_proof_size_estimates() {
        let pq_params = SymphonyParams::default_post_quantum();
        let pq_size = pq_params.estimate_proof_size();
        assert!(pq_size < 200_000, "Post-quantum proof should be <200KB");
        
        let classical_params = SymphonyParams::default_classical();
        let classical_size = classical_params.estimate_proof_size();
        assert!(classical_size < 50_000, "Classical proof should be <50KB");
    }
    
    #[test]
    fn test_verification_time_estimates() {
        let params = SymphonyParams::default_post_quantum();
        let time = params.estimate_verification_time();
        assert!(time < 100.0, "Verification should be <100ms");
    }
    
    #[test]
    fn test_prover_operations_estimate() {
        let params = SymphonyParams::default_post_quantum();
        let ops = params.estimate_prover_operations();
        
        let target = 3u64 * (1u64 << 32);
        let ratio = ops as f64 / target as f64;
        assert!(ratio > 0.5 && ratio < 2.0, "Prover ops should be ~3·2^32");
    }
}

#[cfg(test)]
mod folding_protocol_tests {
    use super::*;
    
    #[test]
    fn test_high_arity_folding_structure() {
        // Test that high-arity folding protocol can be created
        // TODO: Implement with actual ring and parameters
    }
    
    #[test]
    fn test_challenge_set_generation() {
        // Test challenge set has operator norm ≤ 15
        // TODO: Implement
    }
    
    #[test]
    fn test_witness_folding() {
        // Test witness folding preserves correctness
        // TODO: Implement
    }
    
    #[test]
    fn test_norm_bounds() {
        // Test folded witness satisfies norm bounds
        // TODO: Implement
    }
}

#[cfg(test)]
mod fiat_shamir_tests {
    use super::*;
    
    #[test]
    fn test_hash_oracle_sha256() {
        use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
        
        let mut oracle = StandardHashOracle::new(HashFunction::Sha256);
        oracle.update(b"test message");
        let output = oracle.finalize(32);
        
        assert_eq!(output.len(), 32);
    }
    
    #[test]
    fn test_hash_oracle_blake3() {
        use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
        
        let mut oracle = StandardHashOracle::new(HashFunction::Blake3);
        oracle.update(b"test message");
        let output = oracle.finalize(64);
        
        assert_eq!(output.len(), 64);
    }
    
    #[test]
    fn test_challenge_derivation_deterministic() {
        use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
        
        let mut oracle1 = StandardHashOracle::new(HashFunction::Blake3);
        oracle1.update(b"test");
        let output1 = oracle1.finalize(32);
        
        let mut oracle2 = StandardHashOracle::new(HashFunction::Blake3);
        oracle2.update(b"test");
        let output2 = oracle2.finalize(32);
        
        assert_eq!(output1, output2, "Challenge derivation should be deterministic");
    }
    
    #[test]
    fn test_challenge_derivation_different_inputs() {
        use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
        
        let mut oracle1 = StandardHashOracle::new(HashFunction::Blake3);
        oracle1.update(b"test1");
        let output1 = oracle1.finalize(32);
        
        let mut oracle2 = StandardHashOracle::new(HashFunction::Blake3);
        oracle2.update(b"test2");
        let output2 = oracle2.finalize(32);
        
        assert_ne!(output1, output2, "Different inputs should produce different challenges");
    }
}

#[cfg(test)]
mod cp_snark_tests {
    use super::*;
    
    #[test]
    fn test_cp_snark_relation_creation() {
        use neo_lattice_zkvm::snark::cp_snark::CPSNARKRelation;
        use neo_lattice_zkvm::field::m61::M61;
        
        let relation = CPSNARKRelation::<M61>::new(10, 1024, 64);
        assert_eq!(relation.num_rounds, 10);
        assert_eq!(relation.folding_arity, 1024);
        assert_eq!(relation.ring_degree, 64);
    }
    
    #[test]
    fn test_proof_size_compression() {
        use neo_lattice_zkvm::snark::cp_snark::CPSNARKRelation;
        use neo_lattice_zkvm::field::m61::M61;
        
        let relation = CPSNARKRelation::<M61>::new(10, 1024, 64);
        let size = relation.estimate_proof_size();
        
        // Should compress >30MB folding proof to <1KB
        assert!(size < 100_000, "CP-SNARK proof should be <100KB");
    }
}

#[cfg(test)]
mod witness_extraction_tests {
    use super::*;
    
    #[test]
    fn test_extraction_probability() {
        use neo_lattice_zkvm::snark::extraction::WitnessExtractor;
        use neo_lattice_zkvm::field::m61::M61;
        
        let extractor = WitnessExtractor::<M61>::new(1024, vec![]);
        
        let prob = extractor.extraction_probability(0.9);
        assert!(prob > 0.8, "Extraction probability should be high");
    }
    
    #[test]
    fn test_expected_adversary_calls() {
        use neo_lattice_zkvm::snark::extraction::expected_adversary_calls;
        
        assert_eq!(expected_adversary_calls(1024), 1025);
        assert_eq!(expected_adversary_calls(2048), 2049);
    }
    
    #[test]
    fn test_knowledge_error_bound() {
        use neo_lattice_zkvm::snark::extraction::knowledge_error_bound;
        
        let error = knowledge_error_bound(2.0_f64.powi(-128), 1024, 1 << 20);
        assert!(error < 2.0_f64.powi(-100), "Knowledge error should be small");
    }
}

#[cfg(test)]
mod streaming_prover_tests {
    use super::*;
    
    #[test]
    fn test_streaming_config_default() {
        use neo_lattice_zkvm::protocols::streaming::StreamingConfig;
        
        let config = StreamingConfig::default();
        assert_eq!(config.max_memory_bytes, 1 << 30);
        assert!(!config.use_disk_streaming);
    }
    
    #[test]
    fn test_streaming_config_low_memory() {
        use neo_lattice_zkvm::protocols::streaming::StreamingConfig;
        
        let config = StreamingConfig::low_memory();
        assert_eq!(config.max_memory_bytes, 1 << 28);
        assert!(config.use_disk_streaming);
    }
    
    #[test]
    fn test_streaming_config_high_performance() {
        use neo_lattice_zkvm::protocols::streaming::StreamingConfig;
        
        let config = StreamingConfig::high_performance();
        assert_eq!(config.max_memory_bytes, 1 << 32);
        assert!(!config.use_disk_streaming);
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_soundness_error() {
        use neo_lattice_zkvm::fiat_shamir::transform::FiatShamirSecurity;
        
        let error = FiatShamirSecurity::soundness_error(10, 128);
        assert!(error < 2.0_f64.powi(-120), "Soundness error should be negligible");
    }
    
    #[test]
    fn test_knowledge_error_with_queries() {
        use neo_lattice_zkvm::fiat_shamir::transform::FiatShamirSecurity;
        
        let base = 2.0_f64.powi(-128);
        let soundness = 2.0_f64.powi(-120);
        let error = FiatShamirSecurity::knowledge_error(base, soundness, 1000);
        
        assert!(error < 2.0_f64.powi(-100), "Knowledge error should remain small");
    }
    
    #[test]
    fn test_security_level_verification() {
        use neo_lattice_zkvm::fiat_shamir::transform::FiatShamirSecurity;
        
        let error = 2.0_f64.powi(-130);
        assert!(FiatShamirSecurity::verify_security_level(error, 128));
        assert!(!FiatShamirSecurity::verify_security_level(error, 140));
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    
    #[test]
    fn test_parameter_scaling() {
        let params_1k = SymphonyParams {
            folding_arity: 1024,
            ..SymphonyParams::default_post_quantum()
        };
        
        let params_4k = SymphonyParams {
            folding_arity: 4096,
            ..SymphonyParams::default_post_quantum()
        };
        
        let size_1k = params_1k.estimate_proof_size();
        let size_4k = params_4k.estimate_proof_size();
        
        // Proof size should scale sublinearly
        let ratio = size_4k as f64 / size_1k as f64;
        assert!(ratio < 4.0, "Proof size should scale sublinearly with arity");
    }
    
    #[test]
    fn test_verification_time_scaling() {
        let params_1k = SymphonyParams {
            folding_arity: 1024,
            ..SymphonyParams::default_post_quantum()
        };
        
        let params_4k = SymphonyParams {
            folding_arity: 4096,
            ..SymphonyParams::default_post_quantum()
        };
        
        let time_1k = params_1k.estimate_verification_time();
        let time_4k = params_4k.estimate_verification_time();
        
        // Verification time should scale logarithmically
        let ratio = time_4k / time_1k;
        assert!(ratio < 2.0, "Verification time should scale logarithmically");
    }
}

#[cfg(test)]
mod end_to_end_tests {
    use super::*;
    
    #[test]
    #[ignore] // Requires full implementation
    fn test_end_to_end_small_batch() {
        // Test proving and verifying small batch of R1CS statements
        // TODO: Implement when R1CS conversion is complete
    }
    
    #[test]
    #[ignore] // Requires full implementation
    fn test_end_to_end_large_batch() {
        // Test proving and verifying large batch
        // TODO: Implement
    }
    
    #[test]
    #[ignore] // Requires full implementation
    fn test_end_to_end_streaming() {
        // Test streaming prover with large input
        // TODO: Implement
    }
}
