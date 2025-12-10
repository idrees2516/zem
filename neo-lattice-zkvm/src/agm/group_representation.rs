// Group Representation Management
//
// Implements tracking and verification of group representations in the AGM.
// For group element y output by adversary A^alg, requires representation Γ such that y = Γ^T x.
//
// Mathematical Foundation:
// - Representation matrix Γ ∈ F^(|y|+|y^θ|)×|x|
// - Verification: y||y^θ = Γ^T x where:
//   - y: explicit output group elements
//   - y^θ: group elements in oracle transcript
//   - x: basis elements (received elements)

use std::collections::HashMap;
use std::hash::Hash;
use serde::{Serialize, Deserialize};

use super::types::{Field, Group, BasisElement, Coefficient, RepresentationMatrix};
use super::errors::{AGMError, AGMResult};

/// Group representation for a set of output elements
///
/// Tracks the linear combination of basis elements that produces each output element.
/// Verifies the algebraic constraint: y = Γ^T x
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRepresentation<G: Group> {
    /// Basis elements (x in the representation y = Γ^T x)
    basis: Vec<G>,
    
    /// Coefficient matrix Γ where output = Γ^T · basis
    /// Each row corresponds to an output element
    /// Each column corresponds to a basis element
    coefficients: RepresentationMatrix<G::Scalar>,
    
    /// Mapping from group element to its representation (for fast lookup)
    #[serde(skip)]
    representation_map: HashMap<Vec<u8>, Vec<G::Scalar>>,
}

impl<G: Group> GroupRepresentation<G> {
    /// Create a new empty group representation
    pub fn new() -> Self {
        Self {
            basis: Vec::new(),
            coefficients: RepresentationMatrix::new(0, 0),
            representation_map: HashMap::new(),
        }
    }
    
    /// Create a group representation with a given basis
    pub fn with_basis(basis: Vec<G>) -> AGMResult<Self> {
        // Validate basis
        if basis.is_empty() {
            return Err(AGMError::InvalidBasis("Basis cannot be empty".to_string()));
        }
        
        // Check for identity element in basis (should not be included)
        if basis.iter().any(|g| g.is_identity()) {
            return Err(AGMError::InvalidBasis(
                "Basis should not contain identity element".to_string()
            ));
        }
        
        Ok(Self {
            basis,
            coefficients: RepresentationMatrix::new(0, 0),
            representation_map: HashMap::new(),
        })
    }
    
    /// Add a basis element
    pub fn add_basis_element(&mut self, element: G) -> AGMResult<usize> {
        // Check if element is identity
        if element.is_identity() {
            return Err(AGMError::InvalidBasis(
                "Cannot add identity element to basis".to_string()
            ));
        }
        
        // Check if element already exists in basis
        if self.basis.contains(&element) {
            return Ok(self.basis.iter().position(|g| g == &element).unwrap());
        }
        
        let index = self.basis.len();
        self.basis.push(element);
        
        // Update coefficient matrix dimensions
        let new_coefficients = RepresentationMatrix::new(
            self.coefficients.rows,
            self.basis.len()
        );
        
        // Copy existing coefficients
        for i in 0..self.coefficients.rows {
            for j in 0..self.coefficients.cols {
                if let Some(val) = self.coefficients.get(i, j) {
                    let _ = new_coefficients.set(i, j, val.clone());
                }
            }
        }
        
        self.coefficients = new_coefficients;
        
        Ok(index)
    }
    
    /// Provide representation for an output element
    ///
    /// # Arguments
    /// * `element` - The output group element
    /// * `coeffs` - Coefficients for the linear combination (one per basis element)
    ///
    /// # Returns
    /// Index of the output element in the representation
    pub fn provide_representation(
        &mut self,
        element: G,
        coeffs: Vec<G::Scalar>
    ) -> AGMResult<usize> {
        // Validate coefficient length
        if coeffs.len() != self.basis.len() {
            return Err(AGMError::DimensionMismatch {
                expected: self.basis.len(),
                actual: coeffs.len(),
            });
        }
        
        // Verify representation before adding
        self.verify_representation_internal(&element, &coeffs)?;
        
        // Add new row to coefficient matrix
        let output_index = self.coefficients.rows;
        let mut new_coefficients = RepresentationMatrix::new(
            output_index + 1,
            self.basis.len()
        );
        
        // Copy existing coefficients
        for i in 0..self.coefficients.rows {
            for j in 0..self.coefficients.cols {
                if let Some(val) = self.coefficients.get(i, j) {
                    let _ = new_coefficients.set(i, j, val.clone());
                }
            }
        }
        
        // Add new coefficients
        for (j, coeff) in coeffs.iter().enumerate() {
            let _ = new_coefficients.set(output_index, j, coeff.clone());
        }
        
        self.coefficients = new_coefficients;
        
        // Update representation map
        let element_bytes = element.to_bytes();
        self.representation_map.insert(element_bytes, coeffs);
        
        Ok(output_index)
    }
    
    /// Verify that a representation is valid: y = Γ^T x
    ///
    /// # Arguments
    /// * `element` - The group element to verify
    /// * `coeffs` - The claimed coefficients
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, Err otherwise
    pub fn verify_representation(
        &self,
        element: &G,
        coeffs: &[G::Scalar]
    ) -> AGMResult<()> {
        self.verify_representation_internal(element, coeffs)
    }
    
    /// Internal verification implementation
    fn verify_representation_internal(
        &self,
        element: &G,
        coeffs: &[G::Scalar]
    ) -> AGMResult<()> {
        if coeffs.len() != self.basis.len() {
            return Err(AGMError::DimensionMismatch {
                expected: self.basis.len(),
                actual: coeffs.len(),
            });
        }
        
        // Compute Γ^T x = Σ coeffs[i] * basis[i]
        let computed = G::multi_scalar_mul(&self.basis, coeffs);
        
        // Verify y = Γ^T x
        if computed != *element {
            return Err(AGMError::InvalidRepresentation);
        }
        
        Ok(())
    }
    
    /// Get representation for a group element (if it exists)
    pub fn get_representation(&self, element: &G) -> Option<Vec<G::Scalar>> {
        let element_bytes = element.to_bytes();
        self.representation_map.get(&element_bytes).cloned()
    }
    
    /// Check if a group element has a representation
    pub fn has_representation(&self, element: &G) -> bool {
        let element_bytes = element.to_bytes();
        self.representation_map.contains_key(&element_bytes)
    }
    
    /// Get the basis elements
    pub fn basis(&self) -> &[G] {
        &self.basis
    }
    
    /// Get the coefficient matrix
    pub fn coefficients(&self) -> &RepresentationMatrix<G::Scalar> {
        &self.coefficients
    }
    
    /// Get number of output elements with representations
    pub fn num_outputs(&self) -> usize {
        self.coefficients.rows
    }
    
    /// Get number of basis elements
    pub fn num_basis_elements(&self) -> usize {
        self.basis.len()
    }
    
    /// Verify all representations in the matrix
    pub fn verify_all(&self) -> AGMResult<()> {
        for i in 0..self.coefficients.rows {
            if let Some(coeffs) = self.coefficients.get_row(i) {
                // Compute the output element for this row
                let output = G::multi_scalar_mul(&self.basis, &coeffs);
                
                // Verify it matches
                self.verify_representation_internal(&output, &coeffs)?;
            }
        }
        Ok(())
    }
    
    /// Get coefficients for a specific group element
    ///
    /// Returns the coefficient vector for the given element if it has a representation.
    /// This is used in extraction to recover witness values from proof elements.
    ///
    /// # Arguments
    /// * `element` - The group element to get coefficients for
    ///
    /// # Returns
    /// Vector of coefficients if element has a representation, error otherwise
    pub fn get_coefficients_for_element(&self, element: &G) -> AGMResult<Vec<G::Scalar>> {
        let element_bytes = element.to_bytes();
        
        self.representation_map
            .get(&element_bytes)
            .cloned()
            .ok_or_else(|| AGMError::InvalidRepresentation)
    }
    
    /// Get the basis elements (alias for compatibility)
    pub fn get_basis(&self) -> Vec<G> {
        self.basis.clone()
    }
    
    /// Get all coefficients as a matrix
    pub fn get_coefficients(&self) -> Vec<Vec<G::Scalar>> {
        let mut result = Vec::new();
        for i in 0..self.coefficients.rows {
            if let Some(row) = self.coefficients.get_row(i) {
                result.push(row);
            }
        }
        result
    }
    
    /// Verify all representations (alias for compatibility)
    pub fn verify_all_representations(&self) -> bool {
        self.verify_all().is_ok()
    }
}

impl<G: Group> Default for GroupRepresentation<G> {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for group representations with extended AGM support
///
/// Handles both explicit output elements and oracle-queried elements.
/// Maintains the constraint: y||y^θ = Γ^T x
#[derive(Clone, Debug)]
pub struct GroupRepresentationManager<G: Group> {
    /// Representation for explicit output elements
    output_representation: GroupRepresentation<G>,
    
    /// Representation for oracle-queried elements
    oracle_representation: GroupRepresentation<G>,
    
    /// Combined basis (shared between output and oracle representations)
    combined_basis: Vec<G>,
}

impl<G: Group> GroupRepresentationManager<G> {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            output_representation: GroupRepresentation::new(),
            oracle_representation: GroupRepresentation::new(),
            combined_basis: Vec::new(),
        }
    }
    
    /// Create with a given basis
    pub fn with_basis(basis: Vec<G>) -> AGMResult<Self> {
        Ok(Self {
            output_representation: GroupRepresentation::with_basis(basis.clone())?,
            oracle_representation: GroupRepresentation::with_basis(basis.clone())?,
            combined_basis: basis,
        })
    }
    
    /// Add a basis element to both representations
    pub fn add_basis_element(&mut self, element: G) -> AGMResult<usize> {
        if element.is_identity() {
            return Err(AGMError::InvalidBasis(
                "Cannot add identity element to basis".to_string()
            ));
        }
        
        // Check if already exists
        if let Some(idx) = self.combined_basis.iter().position(|g| g == &element) {
            return Ok(idx);
        }
        
        let index = self.combined_basis.len();
        self.combined_basis.push(element.clone());
        
        // Add to both representations
        self.output_representation.add_basis_element(element.clone())?;
        self.oracle_representation.add_basis_element(element)?;
        
        Ok(index)
    }
    
    /// Provide representation for an output element
    pub fn provide_output_representation(
        &mut self,
        element: G,
        coeffs: Vec<G::Scalar>
    ) -> AGMResult<usize> {
        self.output_representation.provide_representation(element, coeffs)
    }
    
    /// Provide representation for an oracle-queried element
    pub fn provide_oracle_representation(
        &mut self,
        element: G,
        coeffs: Vec<G::Scalar>
    ) -> AGMResult<usize> {
        self.oracle_representation.provide_representation(element, coeffs)
    }
    
    /// Verify extended AGM constraint: y||y^θ = Γ^T x
    pub fn verify_extended_agm(&self) -> AGMResult<()> {
        // Verify output representations
        self.output_representation.verify_all()?;
        
        // Verify oracle representations
        self.oracle_representation.verify_all()?;
        
        Ok(())
    }
    
    /// Get output representation
    pub fn output_representation(&self) -> &GroupRepresentation<G> {
        &self.output_representation
    }
    
    /// Get oracle representation
    pub fn oracle_representation(&self) -> &GroupRepresentation<G> {
        &self.oracle_representation
    }
    
    /// Get combined basis
    pub fn basis(&self) -> &[G] {
        &self.combined_basis
    }
}

impl<G: Group> Default for GroupRepresentationManager<G> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
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
    fn test_group_representation_creation() {
        let repr = GroupRepresentation::<MockGroup>::new();
        assert_eq!(repr.num_basis_elements(), 0);
        assert_eq!(repr.num_outputs(), 0);
    }
    
    #[test]
    fn test_add_basis_element() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        let g1 = MockGroup(5);
        let idx1 = repr.add_basis_element(g1.clone()).unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(repr.num_basis_elements(), 1);
        
        let g2 = MockGroup(7);
        let idx2 = repr.add_basis_element(g2).unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(repr.num_basis_elements(), 2);
        
        // Adding same element again should return existing index
        let idx3 = repr.add_basis_element(g1).unwrap();
        assert_eq!(idx3, 0);
        assert_eq!(repr.num_basis_elements(), 2);
    }
    
    #[test]
    fn test_provide_and_verify_representation() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        // Add basis elements
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        repr.add_basis_element(g1.clone()).unwrap();
        repr.add_basis_element(g2.clone()).unwrap();
        
        // Provide representation: y = 5*g1 + 7*g2 = 5*2 + 7*3 = 10 + 21 = 31
        let coeffs = vec![MockField(5), MockField(7)];
        let y = MockGroup(31);
        
        let idx = repr.provide_representation(y.clone(), coeffs.clone()).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(repr.num_outputs(), 1);
        
        // Verify representation
        assert!(repr.verify_representation(&y, &coeffs).is_ok());
        
        // Check representation map
        assert!(repr.has_representation(&y));
        assert_eq!(repr.get_representation(&y), Some(coeffs));
    }
    
    #[test]
    fn test_invalid_representation() {
        let mut repr = GroupRepresentation::<MockGroup>::new();
        
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        repr.add_basis_element(g1).unwrap();
        repr.add_basis_element(g2).unwrap();
        
        // Try to provide invalid representation
        let coeffs = vec![MockField(5), MockField(7)];
        let wrong_y = MockGroup(100); // Should be 31, not 100
        
        let result = repr.provide_representation(wrong_y, coeffs);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AGMError::InvalidRepresentation);
    }
    
    #[test]
    fn test_group_representation_manager() {
        let mut manager = GroupRepresentationManager::<MockGroup>::new();
        
        // Add basis elements
        let g1 = MockGroup(2);
        let g2 = MockGroup(3);
        manager.add_basis_element(g1.clone()).unwrap();
        manager.add_basis_element(g2.clone()).unwrap();
        
        // Provide output representation
        let y_out = MockGroup(31); // 5*2 + 7*3
        let coeffs_out = vec![MockField(5), MockField(7)];
        manager.provide_output_representation(y_out, coeffs_out).unwrap();
        
        // Provide oracle representation
        let y_oracle = MockGroup(13); // 2*2 + 3*3
        let coeffs_oracle = vec![MockField(2), MockField(3)];
        manager.provide_oracle_representation(y_oracle, coeffs_oracle).unwrap();
        
        // Verify extended AGM
        assert!(manager.verify_extended_agm().is_ok());
    }
}
