// Algebraic Adversary Interface
//
// Defines interfaces for algebraic adversaries that provide group representations
// for all group elements they output.
//
// Mathematical Foundation:
// - Algebraic adversary A^alg must provide representations for:
//   1. Explicit output group elements (y)
//   2. Group elements in oracle transcript (y^θ)
// - Constraint: y||y^θ = Γ^T x

use serde::{Serialize, Deserialize};

use super::types::{Field, Group};
use super::group_representation::GroupRepresentation;
use super::errors::{AGMError, AGMResult};

/// Output from an algebraic adversary
///
/// Contains both the explicit outputs and the group representations
/// required by the AGM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlgebraicOutput<G: Group> {
    /// Explicit output group elements (y)
    pub output_elements: Vec<G>,
    
    /// Group elements queried to oracle (y^θ)
    pub oracle_queried_elements: Vec<G>,
    
    /// Group representations for output || oracle_queried
    /// Must satisfy: (output || oracle_queried) = Γ^T · basis
    pub representations: GroupRepresentation<G>,
}

impl<G: Group> AlgebraicOutput<G> {
    /// Create a new algebraic output
    pub fn new(
        output_elements: Vec<G>,
        oracle_queried_elements: Vec<G>,
        representations: GroupRepresentation<G>,
    ) -> Self {
        Self {
            output_elements,
            oracle_queried_elements,
            representations,
        }
    }
    
    /// Verify that the output is algebraic
    ///
    /// Checks that:
    /// 1. All output elements have representations
    /// 2. All oracle-queried elements have representations
    /// 3. All representations are valid
    pub fn verify_algebraic(&self) -> AGMResult<()> {
        // Check that we have representations for all output elements
        let total_elements = self.output_elements.len() + self.oracle_queried_elements.len();
        if self.representations.num_outputs() != total_elements {
            return Err(AGMError::NonAlgebraicOutput);
        }
        
        // Verify all output elements have valid representations
        for element in &self.output_elements {
            if !self.representations.has_representation(element) {
                return Err(AGMError::MissingRepresentation);
            }
            
            if let Some(coeffs) = self.representations.get_representation(element) {
                self.representations.verify_representation(element, &coeffs)?;
            }
        }
        
        // Verify all oracle-queried elements have valid representations
        for element in &self.oracle_queried_elements {
            if !self.representations.has_representation(element) {
                return Err(AGMError::MissingRepresentation);
            }
            
            if let Some(coeffs) = self.representations.get_representation(element) {
                self.representations.verify_representation(element, &coeffs)?;
            }
        }
        
        // Verify all representations in the matrix
        self.representations.verify_all()?;
        
        Ok(())
    }
    
    /// Get all group elements (output + oracle-queried)
    pub fn all_elements(&self) -> Vec<G> {
        let mut all = self.output_elements.clone();
        all.extend(self.oracle_queried_elements.clone());
        all
    }
    
    /// Get number of output elements
    pub fn num_outputs(&self) -> usize {
        self.output_elements.len()
    }
    
    /// Get number of oracle-queried elements
    pub fn num_oracle_queries(&self) -> usize {
        self.oracle_queried_elements.len()
    }
    
    /// Get total number of elements
    pub fn num_total_elements(&self) -> usize {
        self.output_elements.len() + self.oracle_queried_elements.len()
    }
}

/// Trait for algebraic adversaries in the extended AGM
///
/// An algebraic adversary must provide group representations for all
/// group elements it outputs, including those in oracle transcripts.
pub trait AlgebraicAdversary<G: Group, O> {
    /// Run the adversary with oracle access
    ///
    /// # Arguments
    /// * `public_parameters` - Public parameters for the system
    /// * `oracle` - Oracle that the adversary can query
    ///
    /// # Returns
    /// Algebraic output containing elements and their representations
    fn run(
        &mut self,
        public_parameters: &[u8],
        oracle: &mut O,
    ) -> AGMResult<AlgebraicOutput<G>>;
    
    /// Verify that the adversary is algebraic
    ///
    /// Checks that all outputs have valid group representations.
    fn verify_algebraic(&self, output: &AlgebraicOutput<G>) -> AGMResult<()> {
        output.verify_algebraic()
    }
}

/// Builder for constructing algebraic outputs
///
/// Provides a convenient interface for building algebraic outputs
/// with proper representation tracking.
pub struct AlgebraicOutputBuilder<G: Group> {
    output_elements: Vec<G>,
    oracle_queried_elements: Vec<G>,
    representations: GroupRepresentation<G>,
}

impl<G: Group> AlgebraicOutputBuilder<G> {
    /// Create a new builder with a given basis
    pub fn new(basis: Vec<G>) -> AGMResult<Self> {
        Ok(Self {
            output_elements: Vec::new(),
            oracle_queried_elements: Vec::new(),
            representations: GroupRepresentation::with_basis(basis)?,
        })
    }
    
    /// Add an output element with its representation
    pub fn add_output(
        mut self,
        element: G,
        coefficients: Vec<G::Scalar>,
    ) -> AGMResult<Self> {
        self.representations.provide_representation(element.clone(), coefficients)?;
        self.output_elements.push(element);
        Ok(self)
    }
    
    /// Add an oracle-queried element with its representation
    pub fn add_oracle_query(
        mut self,
        element: G,
        coefficients: Vec<G::Scalar>,
    ) -> AGMResult<Self> {
        self.representations.provide_representation(element.clone(), coefficients)?;
        self.oracle_queried_elements.push(element);
        Ok(self)
    }
    
    /// Add a basis element
    pub fn add_basis_element(mut self, element: G) -> AGMResult<Self> {
        self.representations.add_basis_element(element)?;
        Ok(self)
    }
    
    /// Build the algebraic output
    pub fn build(self) -> AlgebraicOutput<G> {
        AlgebraicOutput::new(
            self.output_elements,
            self.oracle_queried_elements,
            self.representations,
        )
    }
}

/// Helper trait for extracting group elements from various data structures
pub trait GroupElementExtractor<G: Group> {
    /// Extract all group elements from the data structure
    fn extract_group_elements(&self) -> Vec<G>;
}

/// Implement for common types
impl<G: Group> GroupElementExtractor<G> for Vec<G> {
    fn extract_group_elements(&self) -> Vec<G> {
        self.clone()
    }
}

impl<G: Group> GroupElementExtractor<G> for &[G] {
    fn extract_group_elements(&self) -> Vec<G> {
        self.to_vec()
    }
}

impl<G: Group> GroupElementExtractor<G> for (Vec<G>, Vec<u8>) {
    fn extract_group_elements(&self) -> Vec<G> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agm::group_representation::GroupRepresentation;
    
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
    fn test_algebraic_output_creation() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        // Add basis
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        repr.add_basis_element(g1.clone()).unwrap();
        repr.add_basis_element(g2.clone()).unwrap();
        
        // Add output element
        let y = MockGroup(31); // 5*2 + 7*3
        let coeffs = vec![MockField(5), MockField(7)];
        repr.provide_representation(y.clone(), coeffs).unwrap();
        
        let output = AlgebraicOutput::new(
            vec![y],
            vec![],
            repr,
        );
        
        assert_eq!(output.num_outputs(), 1);
        assert_eq!(output.num_oracle_queries(), 0);
        assert!(output.verify_algebraic().is_ok());
    }
    
    #[test]
    fn test_algebraic_output_with_oracle_queries() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        // Add basis
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        repr.add_basis_element(g1.clone()).unwrap();
        repr.add_basis_element(g2.clone()).unwrap();
        
        // Add output element
        let y_out = MockGroup(31); // 5*2 + 7*3
        repr.provide_representation(y_out.clone(), vec![MockField(5), MockField(7)]).unwrap();
        
        // Add oracle-queried element
        let y_oracle = MockGroup(13); // 2*2 + 3*3
        repr.provide_representation(y_oracle.clone(), vec![MockField(2), MockField(3)]).unwrap();
        
        let output = AlgebraicOutput::new(
            vec![y_out],
            vec![y_oracle],
            repr,
        );
        
        assert_eq!(output.num_outputs(), 1);
        assert_eq!(output.num_oracle_queries(), 1);
        assert_eq!(output.num_total_elements(), 2);
        assert!(output.verify_algebraic().is_ok());
    }
    
    #[test]
    fn test_non_algebraic_output() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        // Add basis
        let g1 = MockGroup(2);
        repr.add_basis_element(g1).unwrap();
        
        // Create output with element but no representation
        let y = MockGroup(10);
        let output = AlgebraicOutput::new(
            vec![y],
            vec![],
            repr,
        );
        
        // Should fail verification
        assert!(output.verify_algebraic().is_err());
    }
    
    #[test]
    fn test_algebraic_output_builder() {
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        
        let output = AlgebraicOutputBuilder::new(vec![g1, g2])
            .unwrap()
            .add_output(MockGroup(31), vec![MockField(5), MockField(7)])
            .unwrap()
            .add_oracle_query(MockGroup(13), vec![MockField(2), MockField(3)])
            .unwrap()
            .build();
        
        assert_eq!(output.num_outputs(), 1);
        assert_eq!(output.num_oracle_queries(), 1);
        assert!(output.verify_algebraic().is_ok());
    }
}
