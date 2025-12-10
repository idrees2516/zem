// Oracle Forcing Logic
//
// Implements oracle forcing for AGM-secure SNARKs.
// Ensures all group elements are queried to oracle for extraction.
//
// Mathematical Foundation:
// - Compute g = group(z || π) \ group(tr_V)
// - Force oracle queries: θ(g) = r
// - For Fiat-Shamir: g = ∅ (zero overhead)

use std::collections::HashSet;
use serde::{Serialize, Deserialize};

use crate::agm::{Group, GroupParser};
use crate::oracle::{Oracle, OracleTranscript};

use super::errors::{RelSNARKError, RelSNARKResult};

/// Strategy for oracle forcing
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForcingStrategy {
    /// Minimal forcing: only force elements not in verifier transcript
    Minimal,
    
    /// Full forcing: force all group elements
    Full,
    
    /// Fiat-Shamir: no forcing needed (g = ∅)
    FiatShamir,
    
    /// Custom forcing with specified elements
    Custom(Vec<Vec<u8>>),
}

/// Oracle forcing implementation
pub struct OracleForcing<G: Group> {
    /// Group parser for extracting elements
    parser: GroupParser<G>,
    
    /// Forcing strategy
    strategy: ForcingStrategy,
}

impl<G: Group> OracleForcing<G> {
    /// Create a new oracle forcing instance
    pub fn new(parser: GroupParser<G>, strategy: ForcingStrategy) -> Self {
        Self { parser, strategy }
    }
    
    /// Create with minimal forcing strategy
    pub fn minimal(parser: GroupParser<G>) -> Self {
        Self::new(parser, ForcingStrategy::Minimal)
    }
    
    /// Create with Fiat-Shamir strategy (zero overhead)
    pub fn fiat_shamir(parser: GroupParser<G>) -> Self {
        Self::new(parser, ForcingStrategy::FiatShamir)
    }
    
    /// Compute oracle forcing set: g = group(z || π) \ group(tr_V)
    ///
    /// # Arguments
    /// * `statement` - Serialized statement
    /// * `proof` - Serialized proof
    /// * `verifier_transcript` - Verifier's oracle transcript
    ///
    /// # Returns
    /// Set of group elements that need to be queried
    pub fn compute_forcing_set(
        &self,
        statement: &[u8],
        proof: &[u8],
        verifier_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> RelSNARKResult<Vec<G>> {
        match &self.strategy {
            ForcingStrategy::FiatShamir => {
                // Fiat-Shamir: verifier queries entire (statement, proof)
                // So g = ∅ (zero overhead)
                Ok(Vec::new())
            }
            
            ForcingStrategy::Minimal => {
                // Extract all group elements from statement and proof
                let all_elements = self.parser
                    .extract_from_statement_proof(statement, proof)
                    .map_err(|e| RelSNARKError::AGMError(e.to_string()))?;
                
                // Extract group elements from verifier transcript
                let verifier_elements = self.extract_from_transcript(verifier_transcript)?;
                
                // Compute set difference
                Ok(self.parser.compute_oracle_forcing_set(all_elements, verifier_elements))
            }
            
            ForcingStrategy::Full => {
                // Force all group elements
                self.parser
                    .extract_from_statement_proof(statement, proof)
                    .map_err(|e| RelSNARKError::AGMError(e.to_string()))
            }
            
            ForcingStrategy::Custom(elements) => {
                // Force custom set of elements
                elements.iter()
                    .map(|bytes| G::from_bytes(bytes)
                        .map_err(|e| RelSNARKError::AGMError(e)))
                    .collect()
            }
        }
    }
    
    /// Force oracle queries for group elements
    ///
    /// # Arguments
    /// * `elements` - Group elements to query
    /// * `oracle` - Oracle to query
    ///
    /// # Returns
    /// Oracle responses for each element
    pub fn force_queries<O>(
        &self,
        elements: &[G],
        oracle: &mut O,
    ) -> RelSNARKResult<Vec<Vec<u8>>>
    where
        O: Oracle<Vec<u8>, Vec<u8>>,
    {
        let mut responses = Vec::with_capacity(elements.len());
        
        for element in elements {
            let query = self.parser.serialize_group_element(element);
            let response = oracle.query(query)
                .map_err(|e| RelSNARKError::OracleError(e.to_string()))?;
            responses.push(response);
        }
        
        Ok(responses)
    }
    
    /// Extract group elements from oracle transcript
    fn extract_from_transcript(
        &self,
        transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> RelSNARKResult<Vec<G>> {
        let mut elements = Vec::new();
        
        for query in transcript.queries() {
            // Try to parse query as group element
            if let Ok(element) = G::from_bytes(&query.query) {
                elements.push(element);
            }
        }
        
        Ok(elements)
    }
    
    /// Get forcing strategy
    pub fn strategy(&self) -> &ForcingStrategy {
        &self.strategy
    }
    
    /// Check if forcing is needed
    pub fn is_forcing_needed(&self) -> bool {
        !matches!(self.strategy, ForcingStrategy::FiatShamir)
    }
}

/// Helper functions for oracle forcing
pub mod utils {
    use super::*;
    
    /// Compute forcing set for Fiat-Shamir transformed SNARK
    ///
    /// Returns empty set (zero overhead)
    pub fn fiat_shamir_forcing<G: Group>() -> Vec<G> {
        Vec::new()
    }
    
    /// Compute forcing set for interactive protocol
    ///
    /// Returns g = group(statement || proof) \ group(tr_V)
    pub fn interactive_forcing<G: Group>(
        parser: &GroupParser<G>,
        statement: &[u8],
        proof: &[u8],
        verifier_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> RelSNARKResult<Vec<G>> {
        let forcing = OracleForcing::minimal(parser.clone());
        forcing.compute_forcing_set(statement, proof, verifier_transcript)
    }
    
    /// Serialize group element for oracle query
    pub fn serialize_for_query<G: Group>(element: &G) -> Vec<u8> {
        element.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agm::GroupParserConfig;
    use serde::{Serialize, Deserialize};
    
    // Mock implementations for testing
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct MockField(i64);
    
    impl std::ops::Add for MockField {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            MockField(self.0 + other.0)
        }
    }
    
    impl std::ops::Sub for MockField {
        type Output = Self;
        fn sub(self, other: Self) -> Self {
            MockField(self.0 - other.0)
        }
    }
    
    impl std::ops::Mul for MockField {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            MockField(self.0 * other.0)
        }
    }
    
    impl std::ops::Neg for MockField {
        type Output = Self;
        fn neg(self) -> Self {
            MockField(-self.0)
        }
    }
    
    impl crate::agm::Field for MockField {
        fn zero() -> Self { MockField(0) }
        fn one() -> Self { MockField(1) }
        fn is_zero(&self) -> bool { self.0 == 0 }
        fn inverse(&self) -> Option<Self> {
            if self.0 == 0 { None } else { Some(MockField(1)) }
        }
        fn random<R: rand::Rng>(_rng: &mut R) -> Self {
            MockField(42)
        }
    }
    
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct MockGroup(i64);
    
    impl std::ops::Add for MockGroup {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            MockGroup(self.0 + other.0)
        }
    }
    
    impl std::ops::Neg for MockGroup {
        type Output = Self;
        fn neg(self) -> Self {
            MockGroup(-self.0)
        }
    }
    
    impl Group for MockGroup {
        type Scalar = MockField;
        
        fn identity() -> Self { MockGroup(0) }
        fn generator() -> Self { MockGroup(1) }
        fn is_identity(&self) -> bool { self.0 == 0 }
        
        fn scalar_mul(&self, scalar: &Self::Scalar) -> Self {
            MockGroup(self.0 * scalar.0)
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
            Ok(MockGroup(i64::from_le_bytes(arr)))
        }
        
        fn random<R: rand::Rng>(_rng: &mut R) -> Self {
            MockGroup(42)
        }
    }
    
    #[test]
    fn test_fiat_shamir_forcing() {
        let config = GroupParserConfig::new(8);
        let parser = GroupParser::<MockGroup>::new(config);
        let forcing = OracleForcing::fiat_shamir(parser);
        
        assert_eq!(forcing.strategy(), &ForcingStrategy::FiatShamir);
        assert!(!forcing.is_forcing_needed());
    }
    
    #[test]
    fn test_minimal_forcing() {
        let config = GroupParserConfig::new(8);
        let parser = GroupParser::<MockGroup>::new(config);
        let forcing = OracleForcing::minimal(parser);
        
        assert_eq!(forcing.strategy(), &ForcingStrategy::Minimal);
        assert!(forcing.is_forcing_needed());
    }
    
    #[test]
    fn test_fiat_shamir_zero_overhead() {
        let elements: Vec<MockGroup> = utils::fiat_shamir_forcing();
        assert_eq!(elements.len(), 0);
    }
}
