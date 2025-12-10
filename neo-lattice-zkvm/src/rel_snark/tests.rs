// Integration tests for Relativized SNARK module

#[cfg(test)]
mod integration_tests {
    use crate::rel_snark::*;
    
    #[test]
    fn test_types_creation() {
        let pp = PublicParameters::new(128, vec![1, 2, 3]);
        assert_eq!(pp.lambda, 128);
        
        let ipk = IndexerKey::new(vec![4, 5, 6]);
        assert!(!ipk.data.is_empty());
        
        let ivk = VerifierKey::new(vec![7, 8, 9]);
        assert!(!ivk.data.is_empty());
        
        let proof = Proof::new(vec![10, 11, 12]);
        assert!(!proof.data.is_empty());
        assert!(proof.oracle_responses.is_none());
        
        let proof_with_oracle = Proof::with_oracle_responses(
            vec![13, 14, 15],
            vec![vec![16, 17, 18]]
        );
        assert!(proof_with_oracle.oracle_responses.is_some());
    }
    
    #[test]
    fn test_circuit_creation() {
        let circuit = Circuit::new(vec![1, 2, 3], 100, 50);
        assert_eq!(circuit.num_constraints, 100);
        assert_eq!(circuit.num_variables, 50);
    }
    
    #[test]
    fn test_statement_witness() {
        let statement = Statement::new(vec![1, 2, 3]);
        assert!(!statement.data.is_empty());
        
        let witness = Witness::new(vec![4, 5, 6]);
        assert!(!witness.data.is_empty());
    }
    
    #[test]
    fn test_extraction_result() {
        let witness = Witness::new(vec![1, 2, 3]);
        let result = ExtractionResult::success(witness);
        assert!(result.success);
        assert!(result.info.is_none());
        
        let failure = ExtractionResult::failure("Test failure".to_string());
        assert!(!failure.success);
        assert!(failure.info.is_some());
    }
}
