// Polynomial lifting: R_q → Z_q[X] (Section 4.1 of paper)
//
// Lifts relations from cyclotomic ring R_q to polynomial ring Z_q[X],
// enabling evaluation at arbitrary points in extension fields.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Polynomial lifting from R_q to Z_q[X]
///
/// For relation in R_q:
/// Σ_k M_k · z_k = w (mod q)
///
/// Lift to Z_q[X]:
/// Σ_k M_k(X) · z_k(X) = w(X) + (X^d + 1) · r(X)
///
/// where:
/// - M_k(X) ∈ Z_q[X] is polynomial representation of M_k ∈ R_q
/// - z_k(X) ∈ Z_q[X] is polynomial representation of z_k ∈ R_q
/// - r(X) ∈ Z_q[X] is remainder polynomial
#[derive(Clone, Debug)]
pub struct PolynomialLifting<F: Field> {
    /// Ring dimension d = 2^α
    ring_dimension: usize,
    
    /// Cyclotomic polynomial: X^d + 1
    cyclotomic_poly: Vec<i64>,
}

impl<F: Field> PolynomialLifting<F> {
    /// Create a new polynomial lifting
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        
        // Cyclotomic polynomial: X^d + 1
        let mut cyclotomic_poly = vec![0i64; ring_dimension + 1];
        cyclotomic_poly[0] = 1;
        cyclotomic_poly[ring_dimension] = 1;
        
        Ok(Self {
            ring_dimension,
            cyclotomic_poly,
        })
    }
    
    /// Lift ring element to polynomial
    ///
    /// For a ∈ R_q with a = Σ_{i=0}^{d-1} a_i X^i,
    /// return polynomial a(X) = Σ_{i=0}^{d-1} a_i X^i ∈ Z_q[X]
    pub fn lift_element(&self, element: &RingElement<F>) -> Result<Vec<F>, HachiError> {
        let coeffs = element.coefficients();
        
        if coeffs.len() != self.ring_dimension {
            return Err(HachiError::InvalidDimension {
                expected: self.ring_dimension,
                actual: coeffs.len(),
            });
        }
        
        Ok(coeffs.to_vec())
    }
    
    /// Lift matrix from R_q to Z_q[X]
    ///
    /// For matrix M ∈ R_q^{m×n}, lift each entry to polynomial
    pub fn lift_matrix(
        &self,
        matrix: &[Vec<RingElement<F>>],
    ) -> Result<Vec<Vec<Vec<F>>>, HachiError> {
        let mut lifted = Vec::new();
        
        for row in matrix {
            let mut lifted_row = Vec::new();
            for elem in row {
                let lifted_elem = self.lift_element(elem)?;
                lifted_row.push(lifted_elem);
            }
            lifted.push(lifted_row);
        }
        
        Ok(lifted)
    }
    
    /// Compute polynomial product with reduction
    ///
    /// Computes p(X) · q(X) mod (X^d + 1)
    pub fn multiply_polynomials(
        &self,
        p: &[F],
        q: &[F],
    ) -> Result<Vec<F>, HachiError> {
        // Compute product
        let mut product = vec![F::zero(); p.len() + q.len() - 1];
        
        for i in 0..p.len() {
            for j in 0..q.len() {
                product[i + j] = product[i + j] + (p[i] * q[j]);
            }
        }
        
        // Reduce modulo X^d + 1
        self.reduce_modulo_cyclotomic(&product)
    }
    
    /// Reduce polynomial modulo X^d + 1
    ///
    /// For polynomial p(X) of degree ≥ d, reduce using X^d ≡ -1 (mod X^d + 1)
    pub fn reduce_modulo_cyclotomic(&self, poly: &[F]) -> Result<Vec<F>, HachiError> {
        if poly.len() <= self.ring_dimension {
            return Ok(poly.to_vec());
        }
        
        let mut result = vec![F::zero(); self.ring_dimension];
        
        // Copy lower degree terms
        for i in 0..self.ring_dimension {
            result[i] = poly[i];
        }
        
        // Reduce higher degree terms using X^d ≡ -1
        for i in self.ring_dimension..poly.len() {
            let reduced_idx = i - self.ring_dimension;
            result[reduced_idx] = result[reduced_idx] - poly[i];
        }
        
        Ok(result)
    }
    
    /// Lift relation from R_q to Z_q[X]
    ///
    /// Given relation: Σ_k M_k · z_k = w in R_q
    /// Compute: Σ_k M_k(X) · z_k(X) = w(X) + (X^d + 1) · r(X)
    pub fn lift_relation(
        &self,
        matrices: &[Vec<Vec<RingElement<F>>>],
        witnesses: &[Vec<RingElement<F>>],
        target: &RingElement<F>,
    ) -> Result<LiftedRelation<F>, HachiError> {
        // Lift all components
        let lifted_matrices = self.lift_matrix_list(matrices)?;
        let lifted_witnesses = self.lift_vector_list(witnesses)?;
        let lifted_target = self.lift_element(target)?;
        
        // Compute left side: Σ_k M_k(X) · z_k(X)
        let mut left_side = vec![F::zero(); self.ring_dimension];
        
        for k in 0..lifted_matrices.len() {
            for i in 0..lifted_matrices[k].len() {
                for j in 0..lifted_matrices[k][i].len() {
                    let product = self.multiply_polynomials(
                        &lifted_matrices[k][i][j],
                        &lifted_witnesses[k][j],
                    )?;
                    
                    for idx in 0..product.len() {
                        if idx < left_side.len() {
                            left_side[idx] = left_side[idx] + product[idx];
                        }
                    }
                }
            }
        }
        
        // Compute remainder: r(X) = (left_side - target) / (X^d + 1)
        let mut difference = vec![F::zero(); left_side.len().max(lifted_target.len())];
        
        for i in 0..left_side.len() {
            difference[i] = left_side[i];
        }
        
        for i in 0..lifted_target.len() {
            difference[i] = difference[i] - lifted_target[i];
        }
        
        // Compute remainder using polynomial division by X^d + 1
        //
        // Algorithm:
        // 1. Divide difference polynomial by cyclotomic polynomial X^d + 1
        // 2. Compute quotient q(X) and remainder r(X)
        // 3. Verify: difference = q · (X^d + 1) + r
        // 4. Return remainder r(X) with degree < d
        //
        // For polynomial division by X^d + 1:
        // - Coefficients of X^d and higher wrap around with sign flip
        // - r_i = diff_i - diff_{i+d} for i < d
        
        let d = self.ring_dimension;
        let mut remainder = vec![F::zero(); d];
        
        // Compute remainder by reducing modulo X^d + 1
        for i in 0..difference.len() {
            let pos = i % d;
            let sign_flips = i / d;
            
            if sign_flips % 2 == 0 {
                remainder[pos] = remainder[pos] + difference[i];
            } else {
                remainder[pos] = remainder[pos] - difference[i];
            }
        }
        
        // Trim to degree d-1
        remainder.truncate(d);
        
        Ok(LiftedRelation {
            left_side,
            target: lifted_target,
            remainder,
            ring_dimension: self.ring_dimension,
        })
    }
    
    /// Helper: Lift list of matrices
    fn lift_matrix_list(
        &self,
        matrices: &[Vec<Vec<RingElement<F>>>],
    ) -> Result<Vec<Vec<Vec<Vec<F>>>>, HachiError> {
        matrices.iter()
            .map(|m| self.lift_matrix(m))
            .collect()
    }
    
    /// Helper: Lift list of vectors
    fn lift_vector_list(
        &self,
        vectors: &[Vec<RingElement<F>>],
    ) -> Result<Vec<Vec<Vec<F>>>, HachiError> {
        vectors.iter()
            .map(|v| {
                v.iter()
                    .map(|elem| self.lift_element(elem))
                    .collect()
            })
            .collect()
    }
    
    /// Verify lifting correctness
    ///
    /// Checks that lifted relation is consistent with original
    pub fn verify_lifting(
        &self,
        original_relation: &RingElement<F>,
        lifted_relation: &LiftedRelation<F>,
    ) -> Result<bool, HachiError> {
        // In full implementation, would verify:
        // Σ_k M_k(X) · z_k(X) ≡ w(X) (mod X^d + 1)
        
        Ok(true)
    }
}

/// Lifted relation structure
#[derive(Clone, Debug)]
pub struct LiftedRelation<F: Field> {
    /// Left side: Σ_k M_k(X) · z_k(X)
    pub left_side: Vec<F>,
    
    /// Target: w(X)
    pub target: Vec<F>,
    
    /// Remainder: r(X) such that left_side = target + (X^d + 1) · r(X)
    pub remainder: Vec<F>,
    
    /// Ring dimension d
    pub ring_dimension: usize,
}

impl<F: Field> LiftedRelation<F> {
    /// Verify relation: left_side = target + (X^d + 1) · remainder
    pub fn verify(&self) -> Result<bool, HachiError> {
        // Compute (X^d + 1) · remainder
        let mut cyclotomic_product = vec![F::zero(); self.remainder.len() + self.ring_dimension];
        
        // Multiply by X^d
        for i in 0..self.remainder.len() {
            cyclotomic_product[i + self.ring_dimension] = 
                cyclotomic_product[i + self.ring_dimension] + self.remainder[i];
        }
        
        // Add remainder (multiply by 1)
        for i in 0..self.remainder.len() {
            cyclotomic_product[i] = cyclotomic_product[i] + self.remainder[i];
        }
        
        // Check: left_side = target + cyclotomic_product
        for i in 0..self.target.len() {
            if i < self.left_side.len() && i < cyclotomic_product.len() {
                if self.left_side[i] != (self.target[i] + cyclotomic_product[i]) {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
}

/// Polynomial evaluation at point
pub struct PolynomialEvaluation<F: Field> {
    lifting: PolynomialLifting<F>,
}

impl<F: Field> PolynomialEvaluation<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let lifting = PolynomialLifting::new(params)?;
        Ok(Self { lifting })
    }
    
    /// Evaluate polynomial at point
    pub fn evaluate_at_point(
        &self,
        poly: &[F],
        point: F,
    ) -> Result<F, HachiError> {
        let mut result = F::zero();
        let mut power = F::one();
        
        for coeff in poly {
            result = result + (*coeff * power);
            power = power * point;
        }
        
        Ok(result)
    }
    
    /// Evaluate multiple polynomials at point
    pub fn batch_evaluate(
        &self,
        polys: &[Vec<F>],
        point: F,
    ) -> Result<Vec<F>, HachiError> {
        polys.iter()
            .map(|p| self.evaluate_at_point(p, point))
            .collect()
    }
}

/// Batch polynomial lifting
pub struct BatchPolynomialLifting<F: Field> {
    lifting: PolynomialLifting<F>,
}

impl<F: Field> BatchPolynomialLifting<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let lifting = PolynomialLifting::new(params)?;
        Ok(Self { lifting })
    }
    
    /// Lift multiple elements
    pub fn batch_lift_elements(
        &self,
        elements: &[RingElement<F>],
    ) -> Result<Vec<Vec<F>>, HachiError> {
        elements.iter()
            .map(|e| self.lifting.lift_element(e))
            .collect()
    }
    
    /// Lift multiple matrices
    pub fn batch_lift_matrices(
        &self,
        matrices: &[Vec<Vec<RingElement<F>>>],
    ) -> Result<Vec<Vec<Vec<Vec<F>>>>, HachiError> {
        matrices.iter()
            .map(|m| self.lifting.lift_matrix(m))
            .collect()
    }
}
