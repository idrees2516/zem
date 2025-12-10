// Group Element Parser
//
// Extracts group elements from mixed data structures for oracle forcing.
// For lst ∈ G^ℓ_G × F^ℓ_F, group(lst) extracts ℓ_G group elements.
//
// Mathematical Foundation:
// - Ordering must be publicly known and deterministic
// - Used to identify which elements need oracle queries
// - For oracle forcing: g = group(z || π) \ group(tr_V)

use std::collections::HashSet;
use serde::{Serialize, Deserialize};

use super::types::{Field, Group};
use super::errors::{AGMError, AGMResult};

/// Configuration for parsing group elements from data structures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupParserConfig {
    /// Positions of group elements in serialized data
    /// Each entry is (start_offset, length) in bytes
    pub group_positions: Vec<(usize, usize)>,
    
    /// Expected size of each group element in bytes
    pub group_element_size: usize,
}

impl GroupParserConfig {
    /// Create a new parser configuration
    pub fn new(group_element_size: usize) -> Self {
        Self {
            group_positions: Vec::new(),
            group_element_size,
        }
    }
    
    /// Add a group element position
    pub fn add_position(&mut self, start_offset: usize, length: usize) {
        self.group_positions.push((start_offset, length));
    }
    
    /// Add multiple consecutive group elements
    pub fn add_consecutive_positions(&mut self, start_offset: usize, count: usize) {
        for i in 0..count {
            let offset = start_offset + i * self.group_element_size;
            self.group_positions.push((offset, self.group_element_size));
        }
    }
}

/// Parser for extracting group elements from mixed data structures
///
/// Handles extraction of group elements from statements, proofs, and transcripts.
pub struct GroupParser<G: Group> {
    /// Configuration for parsing
    config: GroupParserConfig,
    
    /// Phantom data for group type
    _phantom: std::marker::PhantomData<G>,
}

impl<G: Group> GroupParser<G> {
    /// Create a new group parser with configuration
    pub fn new(config: GroupParserConfig) -> Self {
        Self {
            config,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Create a parser with automatic detection
    ///
    /// Assumes all group elements are consecutive and of the same size
    pub fn with_element_size(element_size: usize) -> Self {
        Self::new(GroupParserConfig::new(element_size))
    }
    
    /// Parse group elements from byte array
    ///
    /// # Arguments
    /// * `data` - Serialized data containing group elements
    ///
    /// # Returns
    /// Vector of extracted group elements in order
    pub fn parse(&self, data: &[u8]) -> AGMResult<Vec<G>> {
        let mut elements = Vec::new();
        
        for (start, length) in &self.config.group_positions {
            if *start + *length > data.len() {
                return Err(AGMError::DeserializationError(
                    format!("Position {}+{} exceeds data length {}", start, length, data.len())
                ));
            }
            
            let element_bytes = &data[*start..*start + *length];
            let element = G::from_bytes(element_bytes)
                .map_err(|e| AGMError::DeserializationError(e))?;
            
            elements.push(element);
        }
        
        Ok(elements)
    }
    
    /// Extract group elements from statement and proof
    ///
    /// # Arguments
    /// * `statement` - Serialized statement
    /// * `proof` - Serialized proof
    ///
    /// # Returns
    /// All group elements from both statement and proof
    pub fn extract_from_statement_proof(
        &self,
        statement: &[u8],
        proof: &[u8],
    ) -> AGMResult<Vec<G>> {
        let mut elements = self.parse(statement)?;
        elements.extend(self.parse(proof)?);
        Ok(elements)
    }
    
    /// Compute oracle forcing set: g = group(z || π) \ group(tr_V)
    ///
    /// Returns group elements that need to be queried to oracle.
    ///
    /// # Arguments
    /// * `statement_proof_elements` - Group elements from statement and proof
    /// * `verifier_transcript_elements` - Group elements already queried by verifier
    ///
    /// # Returns
    /// Set difference: elements in (statement, proof) but not in verifier transcript
    pub fn compute_oracle_forcing_set(
        &self,
        statement_proof_elements: Vec<G>,
        verifier_transcript_elements: Vec<G>,
    ) -> Vec<G> {
        // Convert verifier transcript to set for efficient lookup
        let verifier_set: HashSet<Vec<u8>> = verifier_transcript_elements
            .iter()
            .map(|g| g.to_bytes())
            .collect();
        
        // Filter elements not in verifier transcript
        statement_proof_elements
            .into_iter()
            .filter(|g| !verifier_set.contains(&g.to_bytes()))
            .collect()
    }
    
    /// Serialize a group element for oracle query
    pub fn serialize_group_element(&self, element: &G) -> Vec<u8> {
        element.to_bytes()
    }
    
    /// Deserialize a group element from oracle response
    pub fn deserialize_group_element(&self, bytes: &[u8]) -> AGMResult<G> {
        G::from_bytes(bytes).map_err(|e| AGMError::DeserializationError(e))
    }
    
    /// Extract group elements from multiple data structures
    pub fn extract_from_multiple(&self, data_list: &[&[u8]]) -> AGMResult<Vec<G>> {
        let mut all_elements = Vec::new();
        
        for data in data_list {
            all_elements.extend(self.parse(data)?);
        }
        
        Ok(all_elements)
    }
    
    /// Check if data contains any group elements
    pub fn contains_group_elements(&self, data: &[u8]) -> bool {
        self.config.group_positions.iter().any(|(start, length)| {
            *start + *length <= data.len()
        })
    }
    
    /// Get number of group elements that would be extracted
    pub fn count_group_elements(&self, data: &[u8]) -> usize {
        self.config.group_positions.iter().filter(|(start, length)| {
            *start + *length <= data.len()
        }).count()
    }
}

/// Builder for constructing group parser configurations
pub struct GroupParserBuilder {
    config: GroupParserConfig,
}

impl GroupParserBuilder {
    /// Create a new builder
    pub fn new(group_element_size: usize) -> Self {
        Self {
            config: GroupParserConfig::new(group_element_size),
        }
    }
    
    /// Add a single group element position
    pub fn add_position(mut self, start_offset: usize, length: usize) -> Self {
        self.config.add_position(start_offset, length);
        self
    }
    
    /// Add multiple consecutive group elements
    pub fn add_consecutive(mut self, start_offset: usize, count: usize) -> Self {
        self.config.add_consecutive_positions(start_offset, count);
        self
    }
    
    /// Build the parser
    pub fn build<G: Group>(self) -> GroupParser<G> {
        GroupParser::new(self.config)
    }
}

/// Helper trait for types that can be parsed for group elements
pub trait GroupElementParseable<G: Group> {
    /// Extract group elements from self
    fn extract_group_elements(&self, parser: &GroupParser<G>) -> AGMResult<Vec<G>>;
}

impl<G: Group> GroupElementParseable<G> for Vec<u8> {
    fn extract_group_elements(&self, parser: &GroupParser<G>) -> AGMResult<Vec<G>> {
        parser.parse(self)
    }
}

impl<G: Group> GroupElementParseable<G> for &[u8] {
    fn extract_group_elements(&self, parser: &GroupParser<G>) -> AGMResult<Vec<G>> {
        parser.parse(self)
    }
}

/// Utility functions for common parsing patterns
pub mod utils {
    use super::*;
    
    /// Parse group elements from Fiat-Shamir transcript
    ///
    /// In Fiat-Shamir, verifier queries entire (statement, proof) to ROM,
    /// so oracle forcing set g = ∅ (zero overhead).
    pub fn parse_fiat_shamir<G: Group>(
        parser: &GroupParser<G>,
        statement: &[u8],
        proof: &[u8],
    ) -> AGMResult<(Vec<G>, Vec<G>)> {
        let all_elements = parser.extract_from_statement_proof(statement, proof)?;
        
        // In Fiat-Shamir, all elements are queried by verifier
        // So oracle forcing set is empty
        let forcing_set = Vec::new();
        
        Ok((all_elements, forcing_set))
    }
    
    /// Parse group elements with oracle forcing
    ///
    /// For interactive protocols, compute g = group(z || π) \ group(tr_V)
    pub fn parse_with_forcing<G: Group>(
        parser: &GroupParser<G>,
        statement: &[u8],
        proof: &[u8],
        verifier_transcript: &[G],
    ) -> AGMResult<(Vec<G>, Vec<G>)> {
        let all_elements = parser.extract_from_statement_proof(statement, proof)?;
        let forcing_set = parser.compute_oracle_forcing_set(
            all_elements.clone(),
            verifier_transcript.to_vec(),
        );
        
        Ok((all_elements, forcing_set))
    }
    
    /// Remove duplicate group elements
    pub fn deduplicate<G: Group>(elements: Vec<G>) -> Vec<G> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        
        for element in elements {
            let bytes = element.to_bytes();
            if seen.insert(bytes) {
                result.push(element);
            }
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    
    impl Field for MockField {
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
    fn test_group_parser_creation() {
        let parser = GroupParser::<MockGroup>::with_element_size(8);
        assert_eq!(parser.config.group_element_size, 8);
    }
    
    #[test]
    fn test_parse_group_elements() {
        let mut config = GroupParserConfig::new(8);
        config.add_consecutive_positions(0, 3);
        
        let parser = GroupParser::<MockGroup>::new(config);
        
        // Create data with 3 group elements
        let g1 = MockGroup(5);
        let g2 = MockGroup(7);
        let g3 = MockGroup(11);
        
        let mut data = Vec::new();
        data.extend_from_slice(&g1.to_bytes());
        data.extend_from_slice(&g2.to_bytes());
        data.extend_from_slice(&g3.to_bytes());
        
        let elements = parser.parse(&data).unwrap();
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0], g1);
        assert_eq!(elements[1], g2);
        assert_eq!(elements[2], g3);
    }
    
    #[test]
    fn test_compute_oracle_forcing_set() {
        let parser = GroupParser::<MockGroup>::with_element_size(8);
        
        let g1 = MockGroup(5);
        let g2 = MockGroup(7);
        let g3 = MockGroup(11);
        let g4 = MockGroup(13);
        
        // Statement/proof contains g1, g2, g3, g4
        let statement_proof = vec![g1.clone(), g2.clone(), g3.clone(), g4.clone()];
        
        // Verifier transcript contains g1, g3
        let verifier_transcript = vec![g1, g3];
        
        // Forcing set should be g2, g4
        let forcing_set = parser.compute_oracle_forcing_set(
            statement_proof,
            verifier_transcript,
        );
        
        assert_eq!(forcing_set.len(), 2);
        assert!(forcing_set.contains(&g2));
        assert!(forcing_set.contains(&g4));
    }
    
    #[test]
    fn test_fiat_shamir_zero_overhead() {
        let mut config = GroupParserConfig::new(8);
        config.add_consecutive_positions(0, 2);
        let parser = GroupParser::<MockGroup>::new(config);
        
        let g1 = MockGroup(5);
        let g2 = MockGroup(7);
        
        let mut statement = Vec::new();
        statement.extend_from_slice(&g1.to_bytes());
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&g2.to_bytes());
        
        let (all_elements, forcing_set) = utils::parse_fiat_shamir(
            &parser,
            &statement,
            &proof,
        ).unwrap();
        
        assert_eq!(all_elements.len(), 2);
        assert_eq!(forcing_set.len(), 0); // Zero overhead for Fiat-Shamir
    }
    
    #[test]
    fn test_group_parser_builder() {
        let parser = GroupParserBuilder::new(8)
            .add_consecutive(0, 3)
            .add_position(32, 8)
            .build::<MockGroup>();
        
        assert_eq!(parser.config.group_positions.len(), 4);
    }
}
