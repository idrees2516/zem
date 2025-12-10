// Core types for AGM module

use std::hash::Hash;
use serde::{Serialize, Deserialize};

/// Trait for field elements used in group representations
pub trait Field: 
    Clone + 
    PartialEq + 
    Eq + 
    std::ops::Add<Output = Self> + 
    std::ops::Sub<Output = Self> + 
    std::ops::Mul<Output = Self> + 
    std::ops::Neg<Output = Self> +
    Serialize +
    for<'de> Deserialize<'de>
{
    /// Zero element
    fn zero() -> Self;
    
    /// One element
    fn one() -> Self;
    
    /// Check if element is zero
    fn is_zero(&self) -> bool;
    
    /// Multiplicative inverse (if exists)
    fn inverse(&self) -> Option<Self>;
    
    /// Generate random field element
    fn random<R: rand::Rng>(rng: &mut R) -> Self;
}

/// Trait for group elements in AGM
pub trait Group: 
    Clone + 
    PartialEq + 
    Eq + 
    Hash +
    std::ops::Add<Output = Self> + 
    std::ops::Neg<Output = Self> +
    Serialize +
    for<'de> Deserialize<'de>
{
    /// Associated field type for scalars
    type Scalar: Field;
    
    /// Identity element
    fn identity() -> Self;
    
    /// Generator element
    fn generator() -> Self;
    
    /// Check if element is identity
    fn is_identity(&self) -> bool;
    
    /// Scalar multiplication
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
    
    /// Multi-scalar multiplication: Σ scalars[i] * points[i]
    fn multi_scalar_mul(points: &[Self], scalars: &[Self::Scalar]) -> Self;
    
    /// Serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>;
    
    /// Generate random group element
    fn random<R: rand::Rng>(rng: &mut R) -> Self;
}

/// Basis element in group representation
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BasisElement<G: Group> {
    /// The group element
    pub element: G,
    
    /// Index in the basis
    pub index: usize,
}

impl<G: Group> BasisElement<G> {
    /// Create a new basis element
    pub fn new(element: G, index: usize) -> Self {
        Self { element, index }
    }
}

/// Coefficient in group representation
pub type Coefficient<F> = F;

/// Representation matrix Γ where y = Γ^T x
/// Matrix is stored in column-major order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepresentationMatrix<F: Field> {
    /// Number of rows (output elements)
    pub rows: usize,
    
    /// Number of columns (basis elements)
    pub cols: usize,
    
    /// Matrix entries in column-major order
    /// Entry at (i, j) is at index i + j * rows
    pub entries: Vec<F>,
}

impl<F: Field> RepresentationMatrix<F> {
    /// Create a new representation matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: vec![F::zero(); rows * cols],
        }
    }
    
    /// Create from coefficient vectors (one per output element)
    pub fn from_coefficients(coefficients: Vec<Vec<F>>) -> Self {
        if coefficients.is_empty() {
            return Self::new(0, 0);
        }
        
        let rows = coefficients.len();
        let cols = coefficients[0].len();
        let mut entries = Vec::with_capacity(rows * cols);
        
        // Convert to column-major order
        for j in 0..cols {
            for i in 0..rows {
                entries.push(coefficients[i][j].clone());
            }
        }
        
        Self { rows, cols, entries }
    }
    
    /// Get entry at (row, col)
    pub fn get(&self, row: usize, col: usize) -> Option<&F> {
        if row >= self.rows || col >= self.cols {
            return None;
        }
        Some(&self.entries[row + col * self.rows])
    }
    
    /// Set entry at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: F) -> Result<(), String> {
        if row >= self.rows || col >= self.cols {
            return Err(format!("Index out of bounds: ({}, {})", row, col));
        }
        self.entries[row + col * self.rows] = value;
        Ok(())
    }
    
    /// Get row as vector
    pub fn get_row(&self, row: usize) -> Option<Vec<F>> {
        if row >= self.rows {
            return None;
        }
        
        let mut result = Vec::with_capacity(self.cols);
        for col in 0..self.cols {
            result.push(self.entries[row + col * self.rows].clone());
        }
        Some(result)
    }
    
    /// Multiply matrix by vector: Γ^T x
    pub fn multiply_transpose(&self, x: &[F]) -> Result<Vec<F>, String> {
        if x.len() != self.cols {
            return Err(format!(
                "Vector length {} does not match matrix columns {}",
                x.len(),
                self.cols
            ));
        }
        
        let mut result = vec![F::zero(); self.rows];
        
        for i in 0..self.rows {
            for j in 0..self.cols {
                let coeff = self.entries[i + j * self.rows].clone();
                result[i] = result[i].clone() + coeff * x[j].clone();
            }
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock field for testing
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    
    #[test]
    fn test_representation_matrix_creation() {
        let matrix = RepresentationMatrix::<MockField>::new(3, 2);
        assert_eq!(matrix.rows, 3);
        assert_eq!(matrix.cols, 2);
        assert_eq!(matrix.entries.len(), 6);
    }
    
    #[test]
    fn test_representation_matrix_from_coefficients() {
        let coeffs = vec![
            vec![MockField(1), MockField(2)],
            vec![MockField(3), MockField(4)],
        ];
        let matrix = RepresentationMatrix::from_coefficients(coeffs);
        
        assert_eq!(matrix.rows, 2);
        assert_eq!(matrix.cols, 2);
        assert_eq!(matrix.get(0, 0), Some(&MockField(1)));
        assert_eq!(matrix.get(0, 1), Some(&MockField(2)));
        assert_eq!(matrix.get(1, 0), Some(&MockField(3)));
        assert_eq!(matrix.get(1, 1), Some(&MockField(4)));
    }
    
    #[test]
    fn test_representation_matrix_multiply_transpose() {
        let coeffs = vec![
            vec![MockField(1), MockField(2)],
            vec![MockField(3), MockField(4)],
        ];
        let matrix = RepresentationMatrix::from_coefficients(coeffs);
        
        let x = vec![MockField(5), MockField(6)];
        let result = matrix.multiply_transpose(&x).unwrap();
        
        // Result should be [1*5 + 2*6, 3*5 + 4*6] = [17, 39]
        assert_eq!(result, vec![MockField(17), MockField(39)]);
    }
}
