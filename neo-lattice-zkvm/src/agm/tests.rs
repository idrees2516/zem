// Integration tests for AGM module

#[cfg(test)]
mod integration_tests {
    use crate::agm::*;
    use serde::{Serialize, Deserialize};
    use rand::thread_rng;
    
    // Mock implementations for integration testing
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct TestField(i64);
    
    impl std::ops::Add for TestField {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            TestField(self.0 + other.0)
        }
    }
    
    impl std::ops::Sub for TestField {
        type Output = Self;
        fn sub(self, other: Self) -> Self {
            TestField(self.0 - other.0)
        }
    }
    
    impl std::ops::Mul for TestField {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            TestField(self.0 * other.0)
        }
    }
    
    impl std::ops::Neg for TestField {
        type Output = Self;
        fn neg(self) -> Self {
            TestField(-self.0)
        }
    }
    
    impl Field for TestField {
        fn zero() -> Self { TestField(0) }
        fn one() -> Self { TestField(1) }
        fn is_zero(&self) -> bool { self.0 == 0 }
        fn inverse(&self) -> Option<Self> {
            if self.0 == 0 { None } else { Some(TestField(1)) }
        }
        fn random<R: rand::Rng>(_rng: &mut R) -> Self {
            TestField(42)
        }
    }
    
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct TestGroup(i64);
    
    impl std::ops::Add for TestGroup {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            TestGroup(self.0 + other.0)
        }
    }
    
    impl std::ops::Neg for TestGroup {
        type Output = Self;
        fn neg(self) -> Self {
            TestGroup(-self.0)
        }
    }
    
    impl Group for TestGroup {
        type Scalar = TestField;
        
        fn identity() -> Self { TestGroup(0) }
        fn generator() -> Self { TestGroup(1) }
        fn is_identity(&self) -> bool { self.0 == 0 }
        
        fn scalar_mul(&self, scalar: &Self::Scalar) -> Self {
            TestGroup(self.0 * scalar.0)
        }
        
        fn multi_scalar_mul(points: &[Self], scalars: &[Self::Scalar]) -> Self {
            let mut result = Self::identity();
            for (point, scalar) in points.iter().zip(scalars.iter()) {
                result = result + point.scalar_mul(scalar);
            }
            result
        }
        
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_le_bytes().to_vec()
        }
        
        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() != 8 {
                return Err("Invalid length".to_string());
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Ok(TestGroup(i64::from_le_bytes(arr)))
        }
        
        fn random<R: rand::Rng>(_rng: &mut R) -> Self {
            TestGroup(42)
        }
    }
    
    #[test]
    fn test_complete_agm_workflow() {
        // Setup basis
        let g1 = TestGroup(2);
        let g2 = TestGroup(3);
        let g3 = TestGroup(5);
        let basis = vec![g1.clone(), g2.clone(), g3.clone()];
        
        // Create algebraic output using builder
        let y1 = TestGroup(31); // 5*2 + 7*3 + 0*5
        let y2 = TestGroup(23); // 2*2 + 3*3 + 2*5
        
        let output = AlgebraicOutputBuilder::new(basis.clone())
            .unwrap()
            .add_output(y1, vec![TestField(5), TestField(7), TestField(0)])
            .unwrap()
            .add_output(y2, vec![TestField(2), TestField(3), TestField(2)])
            .unwrap()
            .build();
        
        // Verify algebraic property
        assert!(output.verify_algebraic().is_ok());
        assert_eq!(output.num_outputs(), 2);
    }
    
    #[test]
    fn test_agm_with_oracle_queries() {
        // Setup basis
        let g1 = TestGroup(2);
        let g2 = TestGroup(3);
        let basis = vec![g1.clone(), g2.clone()];
        
        // Create output with oracle queries
        let y_out = TestGroup(31); // 5*2 + 7*3
        let y_oracle1 = TestGroup(13); // 2*2 + 3*3
        let y_oracle2 = TestGroup(8);  // 1*2 + 2*3
        
        let output = AlgebraicOutputBuilder::new(basis)
            .unwrap()
            .add_output(y_out, vec![TestField(5), TestField(7)])
            .unwrap()
            .add_oracle_query(y_oracle1, vec![TestField(2), TestField(3)])
            .unwrap()
            .add_oracle_query(y_oracle2, vec![TestField(1), TestField(2)])
            .unwrap()
            .build();
        
        assert_eq!(output.num_outputs(), 1);
        assert_eq!(output.num_oracle_queries(), 2);
        assert_eq!(output.num_total_elements(), 3);
        assert!(output.verify_algebraic().is_ok());
    }
    
    #[test]
    fn test_group_parser_integration() {
        // Create parser
        let mut config = GroupParserConfig::new(8);
        config.add_consecutive_positions(0, 3);
        let parser = GroupParser::<TestGroup>::new(config);
        
        // Create statement and proof with group elements
        let g1 = TestGroup(5);
        let g2 = TestGroup(7);
        let g3 = TestGroup(11);
        
        let mut statement = Vec::new();
        statement.extend_from_slice(&g1.to_bytes());
        statement.extend_from_slice(&g2.to_bytes());
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&g3.to_bytes());
        
        // Extract elements
        let elements = parser.extract_from_statement_proof(&statement, &proof).unwrap();
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0], g1);
        assert_eq!(elements[1], g2);
        assert_eq!(elements[2], g3);
    }
    
    #[test]
    fn test_oracle_forcing_computation() {
        let parser = GroupParser::<TestGroup>::with_element_size(8);
        
        let g1 = TestGroup(5);
        let g2 = TestGroup(7);
        let g3 = TestGroup(11);
        let g4 = TestGroup(13);
        let g5 = TestGroup(17);
        
        // All elements in statement/proof
        let all_elements = vec![g1.clone(), g2.clone(), g3.clone(), g4.clone(), g5.clone()];
        
        // Verifier already queried some elements
        let verifier_elements = vec![g1, g3, g5];
        
        // Compute forcing set
        let forcing_set = parser.compute_oracle_forcing_set(all_elements, verifier_elements);
        
        // Should only need to force g2 and g4
        assert_eq!(forcing_set.len(), 2);
        assert!(forcing_set.contains(&g2));
        assert!(forcing_set.contains(&g4));
    }
    
    #[test]
    fn test_group_representation_manager() {
        let g1 = TestGroup(2);
        let g2 = TestGroup(3);
        let g3 = TestGroup(5);
        
        let mut manager = GroupRepresentationManager::with_basis(vec![g1, g2, g3]).unwrap();
        
        // Add output representation
        let y_out = TestGroup(31); // 5*2 + 7*3 + 0*5
        manager.provide_output_representation(
            y_out,
            vec![TestField(5), TestField(7), TestField(0)]
        ).unwrap();
        
        // Add oracle representation
        let y_oracle = TestGroup(23); // 2*2 + 3*3 + 2*5
        manager.provide_oracle_representation(
            y_oracle,
            vec![TestField(2), TestField(3), TestField(2)]
        ).unwrap();
        
        // Verify extended AGM
        assert!(manager.verify_extended_agm().is_ok());
    }
    
    #[test]
    fn test_invalid_representation_rejected() {
        let g1 = TestGroup(2);
        let g2 = TestGroup(3);
        
        let mut repr = GroupRepresentation::with_basis(vec![g1, g2]).unwrap();
        
        // Try to provide invalid representation
        let wrong_element = TestGroup(100);
        let coeffs = vec![TestField(5), TestField(7)]; // Would give 31, not 100
        
        let result = repr.provide_representation(wrong_element, coeffs);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AGMError::InvalidRepresentation);
    }
}
