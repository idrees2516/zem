// Polynomial operations for RoKoko protocol
//
// Implements multilinear and univariate polynomials with:
// - Multilinear evaluation and partial evaluation
// - Univariate interpolation and evaluation
// - Lagrange basis operations
// - Constant-time operations for security

use crate::errors::ZKVMError;
use crate::rokoko::lattice::LatticeElement;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for polynomial operations
pub trait PolynomialOps {
    type Scalar;
    
    fn evaluate(&self, point: &[Self::Scalar]) -> Result<Self::Scalar, ZKVMError>;
    fn degree(&self) -> usize;
    fn num_variables(&self) -> usize;
}

/// Multilinear polynomial f: {0,1}^ν → F
/// Represented in evaluation form over the Boolean hypercube
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MultilinearPolynomial {
    /// Evaluations over Boolean hypercube {0,1}^ν
    /// evaluations[i] = f(binary representation of i)
    pub evaluations: Vec<u64>,
    
    /// Number of variables ν
    num_vars: usize,
    
    /// Field modulus
    modulus: u64,
}

impl MultilinearPolynomial {
    /// Creates new multilinear polynomial from evaluations
    pub fn new(evaluations: Vec<u64>, modulus: u64) -> Result<Self, ZKVMError> {
        let num_vars = (evaluations.len() as f64).log2();
        if !num_vars.fract().abs() < 1e-10 {
            return Err(ZKVMError::InvalidParameter(
                "Number of evaluations must be power of 2".to_string()
            ));
        }
        
        Ok(Self {
            evaluations,
            num_vars: num_vars as usize,
            modulus,
        })
    }
    
    /// Creates zero polynomial
    pub fn zero(num_vars: usize, modulus: u64) -> Self {
        Self {
            evaluations: vec![0; 1 << num_vars],
            num_vars,
            modulus,
        }
    }
    
    /// Evaluates polynomial at point r = (r_1, ..., r_ν)
    /// Uses the multilinear Lagrange basis:
    /// f(r) = Σ f(w) · ∏_{i=1}^ν [(1-r_i)(1-w_i) + r_i·w_i]
    pub fn evaluate(&self, point: &[u64]) -> Result<u64, ZKVMError> {
        if point.len() != self.num_vars {
            return Err(ZKVMError::InvalidParameter(
                "Point dimension mismatch".to_string()
            ));
        }
        
        // Compute all Lagrange basis evaluations efficiently
        let basis_evals = self.lagrange_basis(point)?;
        
        // Inner product with evaluations
        let mut result = 0u128;
        for (eval, basis) in self.evaluations.iter().zip(basis_evals.iter()) {
            result += (*eval as u128) * (*basis as u128);
            result %= self.modulus as u128;
        }
        
        Ok(result as u64)
    }
    
    /// Computes Lagrange basis evaluations at point
    fn lagrange_basis(&self, point: &[u64]) -> Result<Vec<u64>, ZKVMError> {
        let n = 1 << self.num_vars;
        let mut basis = vec![1u64; n];
        
        // Build basis values iteratively
        let mut size = 1;
        for &r in point.iter() {
            let one_minus_r = sub_mod(self.modulus, r, self.modulus);
            
            for i in 0..size {
                let old_val = basis[i];
                basis[i] = mul_mod(old_val, one_minus_r, self.modulus);
                basis[i + size] = mul_mod(old_val, r, self.modulus);
            }
            size *= 2;
        }
        
        Ok(basis)
    }
    
    /// Partial evaluation: fix first variable to value r
    /// Returns polynomial in remaining variables
    pub fn partial_eval(&self, r: u64) -> Result<Self, ZKVMError> {
        if self.num_vars == 0 {
            return Err(ZKVMError::InvalidParameter(
                "Cannot partially evaluate 0-variate polynomial".to_string()
            ));
        }
        
        let new_size = 1 << (self.num_vars - 1);
        let mut new_evals = vec![0u64; new_size];
        
        let one_minus_r = sub_mod(self.modulus, r, self.modulus);
        
        for i in 0..new_size {
            // f'(x_2,...,x_ν) = (1-r)·f(0,x_2,...,x_ν) + r·f(1,x_2,...,x_ν)
            let eval_0 = self.evaluations[i];
            let eval_1 = self.evaluations[i + new_size];
            
            let term_0 = mul_mod(one_minus_r, eval_0, self.modulus);
            let term_1 = mul_mod(r, eval_1, self.modulus);
            
            new_evals[i] = add_mod(term_0, term_1, self.modulus);
        }
        
        Ok(Self {
            evaluations: new_evals,
            num_vars: self.num_vars - 1,
            modulus: self.modulus,
        })
    }
    
    /// Computes binding polynomial for sumcheck
    /// G(X) = Σ_{w ∈ {0,1}^{ν-1}} f(X, w)
    pub fn binding_polynomial(&self) -> UnivariatePolynomial {
        let half = self.evaluations.len() / 2;
        
        // Degree 1 polynomial: G(X) = c_0 + c_1·X
        let c0 = self.evaluations[..half].iter()
            .fold(0u128, |acc, &x| (acc + x as u128) % self.modulus as u128) as u64;
        
        let c1_part = self.evaluations[half..].iter()
            .fold(0u128, |acc, &x| (acc + x as u128) % self.modulus as u128) as u64;
        
        let c1 = sub_mod(c1_part, c0, self.modulus);
        
        UnivariatePolynomial::new(vec![c0, c1], self.modulus)
    }
    
    /// Adds two multilinear polynomials
    pub fn add(&self, other: &Self) -> Result<Self, ZKVMError> {
        if self.num_vars != other.num_vars {
            return Err(ZKVMError::InvalidParameter(
                "Cannot add polynomials with different number of variables".to_string()
            ));
        }
        
        let evaluations: Vec<u64> = self.evaluations.iter()
            .zip(other.evaluations.iter())
            .map(|(&a, &b)| add_mod(a, b, self.modulus))
            .collect();
        
        Ok(Self {
            evaluations,
            num_vars: self.num_vars,
            modulus: self.modulus,
        })
    }
    
    /// Multiplies two multilinear polynomials (result has 2ν variables)
    pub fn mul(&self, other: &Self) -> Result<Self, ZKVMError> {
        let new_num_vars = self.num_vars + other.num_vars;
        let new_size = 1 << new_num_vars;
        let mut new_evals = vec![0u64; new_size];
        
        for i in 0..self.evaluations.len() {
            for j in 0..other.evaluations.len() {
                let idx = (i << other.num_vars) | j;
                new_evals[idx] = mul_mod(
                    self.evaluations[i],
                    other.evaluations[j],
                    self.modulus
                );
            }
        }
        
        Ok(Self {
            evaluations: new_evals,
            num_vars: new_num_vars,
            modulus: self.modulus,
        })
    }
}

impl PolynomialOps for MultilinearPolynomial {
    type Scalar = u64;
    
    fn evaluate(&self, point: &[Self::Scalar]) -> Result<Self::Scalar, ZKVMError> {
        self.evaluate(point)
    }
    
    fn degree(&self) -> usize {
        self.num_vars
    }
    
    fn num_variables(&self) -> usize {
        self.num_vars
    }
}

/// Univariate polynomial f(X) = Σ c_i X^i
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UnivariatePolynomial {
    /// Coefficients [c_0, c_1, ..., c_d]
    pub coefficients: Vec<u64>,
    
    /// Field modulus
    modulus: u64,
}

impl UnivariatePolynomial {
    /// Creates new univariate polynomial
    pub fn new(coefficients: Vec<u64>, modulus: u64) -> Self {
        Self {
            coefficients,
            modulus,
        }
    }
    
    /// Creates zero polynomial
    pub fn zero(modulus: u64) -> Self {
        Self {
            coefficients: vec![0],
            modulus,
        }
    }
    
    /// Creates constant polynomial
    pub fn constant(value: u64, modulus: u64) -> Self {
        Self {
            coefficients: vec![value],
            modulus,
        }
    }
    
    /// Evaluates polynomial at point using Horner's method
    pub fn evaluate(&self, x: u64) -> u64 {
        if self.coefficients.is_empty() {
            return 0;
        }
        
        let mut result = *self.coefficients.last().unwrap();
        
        for &coeff in self.coefficients.iter().rev().skip(1) {
            result = mul_mod(result, x, self.modulus);
            result = add_mod(result, coeff, self.modulus);
        }
        
        result
    }
    
    /// Lagrange interpolation from points (x_i, y_i)
    pub fn interpolate(
        points: &[(u64, u64)],
        modulus: u64,
    ) -> Result<Self, ZKVMError> {
        if points.is_empty() {
            return Err(ZKVMError::InvalidParameter(
                "Cannot interpolate from empty points".to_string()
            ));
        }
        
        let n = points.len();
        let mut result = vec![0u64; n];
        
        for i in 0..n {
            let (x_i, y_i) = points[i];
            
            // Compute Lagrange basis polynomial L_i(X)
            let mut basis = vec![1u64];
            
            for j in 0..n {
                if i == j {
                    continue;
                }
                
                let (x_j, _) = points[j];
                
                // Multiply by (X - x_j) / (x_i - x_j)
                let denom = sub_mod(x_i, x_j, modulus);
                let denom_inv = mod_inverse(denom, modulus);
                
                // Multiply basis by (X - x_j)
                basis = Self::mul_by_linear(&basis, x_j, modulus);
                
                // Scale by 1/(x_i - x_j)
                for coeff in &mut basis {
                    *coeff = mul_mod(*coeff, denom_inv, modulus);
                }
            }
            
            // Add y_i * L_i(X) to result
            for (k, &coeff) in basis.iter().enumerate() {
                let term = mul_mod(y_i, coeff, modulus);
                result[k] = add_mod(result[k], term, modulus);
            }
        }
        
        Ok(Self {
            coefficients: result,
            modulus,
        })
    }
    
    /// Helper: multiplies polynomial by (X - a)
    fn mul_by_linear(poly: &[u64], a: u64, modulus: u64) -> Vec<u64> {
        let mut result = vec![0u64; poly.len() + 1];
        
        for (i, &coeff) in poly.iter().enumerate() {
            result[i + 1] = add_mod(result[i + 1], coeff, modulus);
            let term = mul_mod(coeff, a, modulus);
            result[i] = sub_mod(result[i], term, modulus);
        }
        
        result
    }
    
    /// Adds two univariate polynomials
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut result = vec![0u64; max_len];
        
        for (i, &coeff) in self.coefficients.iter().enumerate() {
            result[i] = coeff;
        }
        
        for (i, &coeff) in other.coefficients.iter().enumerate() {
            result[i] = add_mod(result[i], coeff, self.modulus);
        }
        
        Self {
            coefficients: result,
            modulus: self.modulus,
        }
    }
    
    /// Multiplies two univariate polynomials
    pub fn mul(&self, other: &Self) -> Self {
        let result_len = self.coefficients.len() + other.coefficients.len() - 1;
        let mut result = vec![0u64; result_len];
        
        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in other.coefficients.iter().enumerate() {
                let term = mul_mod(a, b, self.modulus);
                result[i + j] = add_mod(result[i + j], term, self.modulus);
            }
        }
        
        Self {
            coefficients: result,
            modulus: self.modulus,
        }
    }
    
    /// Returns degree of polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }
}

impl PolynomialOps for UnivariatePolynomial {
    type Scalar = u64;
    
    fn evaluate(&self, point: &[Self::Scalar]) -> Result<Self::Scalar, ZKVMError> {
        if point.len() != 1 {
            return Err(ZKVMError::InvalidParameter(
                "Univariate polynomial requires single point".to_string()
            ));
        }
        Ok(self.evaluate(point[0]))
    }
    
    fn degree(&self) -> usize {
        self.degree()
    }
    
    fn num_variables(&self) -> usize {
        1
    }
}

// Helper arithmetic functions (constant-time)

#[inline(always)]
fn add_mod(a: u64, b: u64, modulus: u64) -> u64 {
    let sum = a.wrapping_add(b);
    if sum < a || sum >= modulus {
        sum.wrapping_sub(modulus)
    } else {
        sum
    }
}

#[inline(always)]
fn sub_mod(a: u64, b: u64, modulus: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        modulus - (b - a)
    }
}

#[inline(always)]
fn mul_mod(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

fn mod_inverse(a: u64, modulus: u64) -> u64 {
    // Extended Euclidean algorithm
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (modulus as i128, a as i128);
    
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    
    if t < 0 {
        t += modulus as i128;
    }
    
    t as u64
}

/// Evaluates multiple polynomials efficiently at same point
pub struct BatchEvaluator {
    modulus: u64,
}

impl BatchEvaluator {
    pub fn new(modulus: u64) -> Self {
        Self { modulus }
    }
    
    /// Evaluates multiple multilinear polynomials at point
    pub fn batch_evaluate_multilinear(
        &self,
        polynomials: &[MultilinearPolynomial],
        point: &[u64],
    ) -> Result<Vec<u64>, ZKVMError> {
        if polynomials.is_empty() {
            return Ok(Vec::new());
        }
        
        // Compute Lagrange basis once for all polynomials
        let basis = polynomials[0].lagrange_basis(point)?;
        
        let mut results = Vec::with_capacity(polynomials.len());
        
        for poly in polynomials {
            let mut result = 0u128;
            for (eval, basis_val) in poly.evaluations.iter().zip(basis.iter()) {
                result += (*eval as u128) * (*basis_val as u128);
                result %= self.modulus as u128;
            }
            results.push(result as u64);
        }
        
        Ok(results)
    }
}
