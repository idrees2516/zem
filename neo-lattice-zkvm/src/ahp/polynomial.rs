// Polynomial Operations for AHP
//
// Implements polynomial arithmetic needed for AHP protocols.

use std::ops::{Add, Sub, Mul};
use crate::field::Field;

/// Univariate Polynomial
///
/// Represents a polynomial p(X) = Σ c_i X^i
#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial<F> {
    /// Coefficients [c_0, c_1, ..., c_d] where c_i is coefficient of X^i
    pub coefficients: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    /// Create a new polynomial from coefficients
    pub fn new(coefficients: Vec<F>) -> Self {
        let mut poly = Self { coefficients };
        poly.trim();
        poly
    }
    
    /// Create zero polynomial
    pub fn zero() -> Self {
        Self {
            coefficients: vec![F::zero()],
        }
    }
    
    /// Create constant polynomial
    pub fn constant(value: F) -> Self {
        Self {
            coefficients: vec![value],
        }
    }
    
    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            self.coefficients.len() - 1
        }
    }
    
    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|c| c.is_zero())
    }
    
    /// Evaluate polynomial at a point
    ///
    /// Uses Horner's method: p(x) = c_0 + x(c_1 + x(c_2 + ... + x*c_d))
    pub fn evaluate(&self, point: &F) -> F {
        if self.coefficients.is_empty() {
            return F::zero();
        }
        
        let mut result = self.coefficients[self.coefficients.len() - 1].clone();
        
        for i in (0..self.coefficients.len() - 1).rev() {
            result = result * point.clone() + self.coefficients[i].clone();
        }
        
        result
    }
    
    /// Trim leading zero coefficients
    fn trim(&mut self) {
        while self.coefficients.len() > 1 && self.coefficients.last().unwrap().is_zero() {
            self.coefficients.pop();
        }
        
        if self.coefficients.is_empty() {
            self.coefficients.push(F::zero());
        }
    }
    
    /// Multiply by scalar
    pub fn scale(&self, scalar: &F) -> Self {
        let coefficients = self.coefficients.iter()
            .map(|c| c.clone() * scalar.clone())
            .collect();
        Self::new(coefficients)
    }
    
    /// Divide polynomial by (X - point), returning quotient and remainder
    ///
    /// Uses synthetic division.
    /// If p(point) = 0, then remainder is 0 and quotient is p(X)/(X-point)
    pub fn divide_by_linear(&self, point: &F) -> (Self, F) {
        if self.coefficients.is_empty() {
            return (Self::zero(), F::zero());
        }
        
        let mut quotient = Vec::with_capacity(self.coefficients.len().saturating_sub(1));
        let mut remainder = F::zero();
        
        for i in (0..self.coefficients.len()).rev() {
            let coeff = self.coefficients[i].clone() + remainder.clone();
            if i > 0 {
                quotient.push(coeff.clone());
                remainder = coeff * point.clone();
            } else {
                remainder = coeff;
            }
        }
        
        quotient.reverse();
        (Self::new(quotient), remainder)
    }
    
    /// Compute derivative
    pub fn derivative(&self) -> Self {
        if self.degree() == 0 {
            return Self::zero();
        }
        
        let coefficients: Vec<F> = (1..self.coefficients.len())
            .map(|i| {
                let i_field = F::from_u64(i as u64);
                self.coefficients[i].clone() * i_field
            })
            .collect();
        
        Self::new(coefficients)
    }
    
    /// Interpolate polynomial through points using Lagrange interpolation
    ///
    /// Given points (x_i, y_i), finds unique polynomial of degree < n
    /// such that p(x_i) = y_i for all i.
    pub fn interpolate(points: &[(F, F)]) -> Self {
        if points.is_empty() {
            return Self::zero();
        }
        
        if points.len() == 1 {
            return Self::constant(points[0].1.clone());
        }
        
        let n = points.len();
        let mut result = Self::zero();
        
        for i in 0..n {
            let (x_i, y_i) = &points[i];
            
            let mut basis = Self::constant(F::one());
            let mut denominator = F::one();
            
            for j in 0..n {
                if i != j {
                    let (x_j, _) = &points[j];
                    
                    let numerator_poly = Self::new(vec![
                        x_j.clone().neg(),
                        F::one(),
                    ]);
                    basis = basis * numerator_poly;
                    
                    denominator = denominator * (x_i.clone() - x_j.clone());
                }
            }
            
            let denominator_inv = denominator.inverse();
            basis = basis.scale(&(y_i.clone() * denominator_inv));
            
            result = result + basis;
        }
        
        result
    }
}

impl<F: Field> Add for Polynomial<F> {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut coefficients = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let a = self.coefficients.get(i).cloned().unwrap_or_else(F::zero);
            let b = other.coefficients.get(i).cloned().unwrap_or_else(F::zero);
            coefficients.push(a + b);
        }
        
        Self::new(coefficients)
    }
}

impl<F: Field> Sub for Polynomial<F> {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut coefficients = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let a = self.coefficients.get(i).cloned().unwrap_or_else(F::zero);
            let b = other.coefficients.get(i).cloned().unwrap_or_else(F::zero);
            coefficients.push(a - b);
        }
        
        Self::new(coefficients)
    }
}

impl<F: Field> Mul for Polynomial<F> {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        
        let result_len = self.coefficients.len() + other.coefficients.len() - 1;
        let mut coefficients = vec![F::zero(); result_len];
        
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                coefficients[i + j] = coefficients[i + j].clone() 
                    + self.coefficients[i].clone() * other.coefficients[j].clone();
            }
        }
        
        Self::new(coefficients)
    }
}

/// Multilinear Polynomial
///
/// Represents a multilinear polynomial in n variables.
/// A polynomial is multilinear if each variable appears with degree at most 1.
///
/// Representation: Evaluations on the boolean hypercube {0,1}^n
#[derive(Clone, Debug)]
pub struct MultilinearPolynomial<F> {
    /// Evaluations on {0,1}^n in lexicographic order
    /// For n=2: [f(0,0), f(0,1), f(1,0), f(1,1)]
    pub evaluations: Vec<F>,
    
    /// Number of variables
    pub num_vars: usize,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create from evaluations
    pub fn new(evaluations: Vec<F>) -> Self {
        let num_vars = (evaluations.len() as f64).log2() as usize;
        assert_eq!(evaluations.len(), 1 << num_vars, "Evaluations must be power of 2");
        
        Self {
            evaluations,
            num_vars,
        }
    }
    
    /// Evaluate at a point
    ///
    /// Uses multilinear extension formula.
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");
        
        let mut evals = self.evaluations.clone();
        
        for (i, x_i) in point.iter().enumerate() {
            let step = 1 << (self.num_vars - 1 - i);
            for j in 0..step {
                let zero_eval = evals[j].clone();
                let one_eval = evals[j + step].clone();
                evals[j] = zero_eval.clone() * (F::one() - x_i.clone()) 
                    + one_eval * x_i.clone();
            }
        }
        
        evals[0].clone()
    }
    
    /// Get degree (always 1 for each variable in multilinear)
    pub fn degree(&self) -> usize {
        self.num_vars
    }
}
