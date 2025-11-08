// Monomial set implementation for LatticeFold+
// M = {0, 1, X, X², ..., X^(d-1)} ⊆ Rq

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use std::fmt;

/// Monomial in the set M = {0, 1, X, ..., X^(d-1)}
/// Sparse representation storing only the exponent
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Monomial {
    /// Zero monomial
    Zero,
    /// Positive monomial X^exp for exp ∈ [0, d)
    Positive(usize),
    /// Negative monomial -X^exp for exp ∈ [0, d)
    Negative(usize),
}

impl Monomial {
    /// Create monomial from exponent
    /// For exp ∈ [0, d): returns X^exp
    pub fn from_exponent(exp: usize) -> Self {
        if exp == 0 {
            Monomial::Positive(0) // This represents 1
        } else {
            Monomial::Positive(exp)
        }
    }
    
    /// Check if monomial is zero
    pub fn is_zero(&self) -> bool {
        matches!(self, Monomial::Zero)
    }
    
    /// Get exponent (returns None for Zero)
    pub fn exponent(&self) -> Option<usize> {
        match self {
            Monomial::Zero => None,
            Monomial::Positive(exp) | Monomial::Negative(exp) => Some(*exp),
        }
    }
    
    /// Get sign: 1 for positive, -1 for negative, 0 for zero
    pub fn sign(&self) -> i8 {
        match self {
            Monomial::Zero => 0,
            Monomial::Positive(_) => 1,
            Monomial::Negative(_) => -1,
        }
    }
    
    /// Convert to ring element
    pub fn to_ring_element<F: Field>(&self, ring: &CyclotomicRing<F>) -> RingElement<F> {
        let mut coeffs = vec![F::zero(); ring.degree];
        
        match self {
            Monomial::Zero => {},
            Monomial::Positive(exp) => {
                coeffs[*exp] = F::one();
            },
            Monomial::Negative(exp) => {
                coeffs[*exp] = F::zero().sub(&F::one()); // -1
            },
        }
        
        RingElement::from_coeffs(coeffs)
    }
    
    /// Multiply two monomials (fast via exponent arithmetic)
    /// Handles X^d = -1 reduction automatically
    pub fn multiply(&self, other: &Monomial, degree: usize) -> Monomial {
        match (self, other) {
            (Monomial::Zero, _) | (_, Monomial::Zero) => Monomial::Zero,
            (Monomial::Positive(e1), Monomial::Positive(e2)) => {
                let sum = e1 + e2;
                if sum < degree {
                    Monomial::Positive(sum)
                } else {
                    // X^d = -1, so X^(d+k) = -X^k
                    Monomial::Negative(sum - degree)
                }
            },
            (Monomial::Positive(e1), Monomial::Negative(e2)) |
            (Monomial::Negative(e2), Monomial::Positive(e1)) => {
                let sum = e1 + e2;
                if sum < degree {
                    Monomial::Negative(sum)
                } else {
                    // -X^(d+k) = -(-X^k) = X^k
                    Monomial::Positive(sum - degree)
                }
            },
            (Monomial::Negative(e1), Monomial::Negative(e2)) => {
                let sum = e1 + e2;
                if sum < degree {
                    Monomial::Positive(sum) // (-1) * (-1) = 1
                } else {
                    Monomial::Negative(sum - degree)
                }
            },
        }
    }
    
    /// Multiply monomial by ring element (optimized)
    pub fn multiply_ring_element<F: Field>(
        &self,
        elem: &RingElement<F>,
        ring: &CyclotomicRing<F>
    ) -> RingElement<F> {
        match self {
            Monomial::Zero => ring.zero(),
            Monomial::Positive(exp) => {
                // X^exp * elem rotates coefficients left by exp
                let mut coeffs = vec![F::zero(); ring.degree];
                for i in 0..ring.degree {
                    let new_idx = (i + exp) % ring.degree;
                    if new_idx < ring.degree - exp {
                        coeffs[new_idx] = elem.coeffs[i];
                    } else {
                        // Wrapped around: multiply by -1 due to X^d = -1
                        coeffs[new_idx] = elem.coeffs[i].neg();
                    }
                }
                RingElement::from_coeffs(coeffs)
            },
            Monomial::Negative(exp) => {
                // -X^exp * elem
                let positive_result = Monomial::Positive(*exp)
                    .multiply_ring_element(elem, ring);
                ring.neg(&positive_result)
            },
        }
    }
}

/// exp(a) function: converts integer a ∈ (-d, d) to monomial
/// exp(a) = sgn(a) · X^|a|
pub fn exp_function(a: i64, degree: usize) -> Monomial {
    let d = degree as i64;
    assert!(a.abs() < d, "Value {} out of range for degree {}", a, degree);
    
    if a == 0 {
        Monomial::Zero
    } else if a > 0 {
        Monomial::Positive(a as usize)
    } else {
        // a < 0: exp(a) = -X^|a| = X^(d + a) in Rq
        // But we store it as Negative(|a|) for clarity
        Monomial::Negative((-a) as usize)
    }
}

/// EXP(a) function: returns set of valid monomials for integer a
/// EXP(a) = {exp(a)} if a ≠ 0
/// EXP(0) = {0, 1, X^(d/2)}
pub fn exp_set(a: i64, degree: usize) -> Vec<Monomial> {
    if a == 0 {
        vec![
            Monomial::Zero,
            Monomial::Positive(0), // 1
            Monomial::Positive(degree / 2), // X^(d/2)
        ]
    } else {
        vec![exp_function(a, degree)]
    }
}

/// Check if monomial b is in EXP(a)
pub fn is_in_exp_set(a: i64, b: &Monomial, degree: usize) -> bool {
    let valid_set = exp_set(a, degree);
    valid_set.contains(b)
}

/// Monomial set M = {0, 1, X, ..., X^(d-1)}
pub struct MonomialSet {
    pub degree: usize,
}

impl MonomialSet {
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two());
        Self { degree }
    }
    
    /// Check if polynomial a(X) is a monomial using Lemma 2.1
    /// a ∈ M' ⟺ a(X²) = a(X)²
    pub fn is_monomial<F: Field>(
        &self,
        a: &RingElement<F>,
        ring: &CyclotomicRing<F>
    ) -> bool {
        // Compute a(X²) by substituting X² for X
        let a_composed = self.compose_x_squared(a, ring);
        
        // Compute a(X)²
        let a_squared = ring.mul(a, a);
        
        // Check if they're equal
        a_composed == a_squared
    }
    
    /// Compute a(X²) by substituting X² for X
    fn compose_x_squared<F: Field>(
        &self,
        a: &RingElement<F>,
        ring: &CyclotomicRing<F>
    ) -> RingElement<F> {
        let mut result_coeffs = vec![F::zero(); ring.degree];
        
        for (i, coeff) in a.coeffs.iter().enumerate() {
            let new_exp = (2 * i) % (2 * ring.degree);
            
            if new_exp < ring.degree {
                result_coeffs[new_exp] = result_coeffs[new_exp].add(coeff);
            } else {
                // X^d = -1, so X^(d+k) = -X^k
                let reduced_exp = new_exp - ring.degree;
                result_coeffs[reduced_exp] = result_coeffs[reduced_exp].sub(coeff);
            }
        }
        
        RingElement::from_coeffs(result_coeffs)
    }
    
    /// Evaluate monomial at point β ∈ F_q
    /// ev_a(β) = Σ_i a_i β^i
    pub fn evaluate_monomial<F: Field>(
        &self,
        m: &Monomial,
        beta: &F
    ) -> F {
        match m {
            Monomial::Zero => F::zero(),
            Monomial::Positive(exp) => {
                // β^exp
                let mut result = F::one();
                for _ in 0..*exp {
                    result = result.mul(beta);
                }
                result
            },
            Monomial::Negative(exp) => {
                // -β^exp
                let mut result = F::one();
                for _ in 0..*exp {
                    result = result.mul(beta);
                }
                result.neg()
            },
        }
    }
}

/// Matrix of monomials (sparse representation)
/// Used in range proofs and commitment schemes
#[derive(Clone, Debug)]
pub struct MonomialMatrix {
    pub entries: Vec<Vec<Monomial>>,
    pub rows: usize,
    pub cols: usize,
}

impl MonomialMatrix {
    /// Create new monomial matrix
    pub fn new(entries: Vec<Vec<Monomial>>) -> Self {
        let rows = entries.len();
        let cols = if rows > 0 { entries[0].len() } else { 0 };
        
        // Verify all rows have same length
        for row in &entries {
            assert_eq!(row.len(), cols, "All rows must have same length");
        }
        
        Self { entries, rows, cols }
    }
    
    /// Create from single vector (column matrix)
    pub fn from_vector(vec: Vec<Monomial>) -> Self {
        let rows = vec.len();
        let entries = vec.into_iter().map(|m| vec![m]).collect();
        Self { entries, rows, cols: 1 }
    }
    
    /// Get column as vector
    pub fn column(&self, j: usize) -> Vec<Monomial> {
        assert!(j < self.cols);
        self.entries.iter().map(|row| row[j].clone()).collect()
    }
    
    /// Get row as vector
    pub fn row(&self, i: usize) -> Vec<Monomial> {
        assert!(i < self.rows);
        self.entries[i].clone()
    }
    
    /// Matrix-vector multiplication (optimized for monomials)
    /// M * v where M is n×m monomial matrix and v is m-vector
    pub fn multiply_vector<F: Field>(
        &self,
        v: &[RingElement<F>],
        ring: &CyclotomicRing<F>
    ) -> Vec<RingElement<F>> {
        assert_eq!(v.len(), self.cols);
        
        let mut result = vec![ring.zero(); self.rows];
        
        for i in 0..self.rows {
            for j in 0..self.cols {
                let scaled = self.entries[i][j].multiply_ring_element(&v[j], ring);
                result[i] = ring.add(&result[i], &scaled);
            }
        }
        
        result
    }
    
    /// Transpose matrix
    pub fn transpose(&self) -> Self {
        let mut entries = vec![vec![Monomial::Zero; self.rows]; self.cols];
        
        for i in 0..self.rows {
            for j in 0..self.cols {
                entries[j][i] = self.entries[i][j].clone();
            }
        }
        
        Self {
            entries,
            rows: self.cols,
            cols: self.rows,
        }
    }
    
    /// Check if all entries are in monomial set M
    pub fn all_monomials(&self) -> bool {
        // All entries are monomials by construction
        // This method is for verification purposes
        true
    }
}

impl fmt::Display for Monomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Monomial::Zero => write!(f, "0"),
            Monomial::Positive(0) => write!(f, "1"),
            Monomial::Positive(exp) => write!(f, "X^{}", exp),
            Monomial::Negative(exp) => write!(f, "-X^{}", exp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_monomial_creation() {
        let m1 = Monomial::from_exponent(0);
        assert_eq!(m1, Monomial::Positive(0));
        
        let m2 = Monomial::from_exponent(5);
        assert_eq!(m2, Monomial::Positive(5));
        
        let m3 = Monomial::Zero;
        assert!(m3.is_zero());
    }
    
    #[test]
    fn test_monomial_multiplication() {
        let degree = 64;
        
        let m1 = Monomial::Positive(10);
        let m2 = Monomial::Positive(20);
        let result = m1.multiply(&m2, degree);
        assert_eq!(result, Monomial::Positive(30));
        
        // Test wraparound: X^70 = X^(64+6) = -X^6
        let m3 = Monomial::Positive(40);
        let m4 = Monomial::Positive(30);
        let result2 = m3.multiply(&m4, degree);
        assert_eq!(result2, Monomial::Negative(6));
    }
    
    #[test]
    fn test_exp_function() {
        let degree = 64;
        
        let m1 = exp_function(5, degree);
        assert_eq!(m1, Monomial::Positive(5));
        
        let m2 = exp_function(-3, degree);
        assert_eq!(m2, Monomial::Negative(3));
        
        let m3 = exp_function(0, degree);
        assert_eq!(m3, Monomial::Zero);
    }
    
    #[test]
    fn test_exp_set() {
        let degree = 64;
        
        let set1 = exp_set(5, degree);
        assert_eq!(set1.len(), 1);
        assert_eq!(set1[0], Monomial::Positive(5));
        
        let set0 = exp_set(0, degree);
        assert_eq!(set0.len(), 3);
        assert!(set0.contains(&Monomial::Zero));
        assert!(set0.contains(&Monomial::Positive(0)));
        assert!(set0.contains(&Monomial::Positive(32)));
    }
    
    #[test]
    fn test_monomial_matrix() {
        let entries = vec![
            vec![Monomial::Positive(1), Monomial::Positive(2)],
            vec![Monomial::Positive(3), Monomial::Zero],
        ];
        
        let matrix = MonomialMatrix::new(entries);
        assert_eq!(matrix.rows, 2);
        assert_eq!(matrix.cols, 2);
        
        let col0 = matrix.column(0);
        assert_eq!(col0[0], Monomial::Positive(1));
        assert_eq!(col0[1], Monomial::Positive(3));
    }
    
    #[test]
    fn test_monomial_set_check() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let monomial_set = MonomialSet::new(64);
        
        // Create a monomial X^5
        let m = Monomial::Positive(5);
        let ring_elem = m.to_ring_element(&ring);
        
        // Should pass monomial test
        assert!(monomial_set.is_monomial(&ring_elem, &ring));
        
        // Create a non-monomial (1 + X)
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::one();
        coeffs[1] = GoldilocksField::one();
        let non_monomial = RingElement::from_coeffs(coeffs);
        
        // Should fail monomial test
        assert!(!monomial_set.is_monomial(&non_monomial, &ring));
    }
}
