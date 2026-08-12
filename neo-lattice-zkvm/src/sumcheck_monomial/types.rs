// Core types for monomial sumcheck protocol
//
// This module defines the fundamental data structures used throughout
// the monomial-basis sumcheck implementation.

use crate::field::Field;
use super::MonomialSumcheckError;

/// Monomial polynomial representation
///
/// Stores a polynomial in monomial basis:
/// f(x₁,...,xₙ) = ∑ c_{i₁,...,iₙ} · x₁^{i₁} · ... · xₙ^{iₙ}
///
/// # Storage Format
/// Coefficients are stored in row-major order, where the last variable
/// varies fastest. For example, with 2 variables and degrees [2,2]:
/// Index 0: c_{0,0}  (coefficient of x₁⁰·x₂⁰)
/// Index 1: c_{0,1}  (coefficient of x₁⁰·x₂¹)
/// Index 2: c_{0,2}  (coefficient of x₁⁰·x₂²)
/// Index 3: c_{1,0}  (coefficient of x₁¹·x₂⁰)
/// ...and so on
///
/// # Paper Reference
/// Section 2: "Monomial Basis Representation"
#[derive(Clone, Debug)]
pub struct MonomialPolynomial<F: Field> {
    /// Polynomial coefficients in row-major order
    pub coefficients: Vec<F>,
    
    /// Degree in each variable [d₁, d₂, ..., dₙ]
    pub degrees: Vec<usize>,
    
    /// Number of variables
    pub num_vars: usize,
    
    /// Total number of coefficients (product of (dᵢ+1))
    pub num_coeffs: usize,
    
    /// Strides for indexing (precomputed for efficiency)
    strides: Vec<usize>,
}

impl<F: Field> MonomialPolynomial<F> {
    /// Create a new monomial polynomial
    ///
    /// # Arguments
    /// * `coefficients` - Coefficient vector in row-major order
    /// * `degrees` - Degree in each variable
    ///
    /// # Returns
    /// Result containing the polynomial or an error if dimensions don't match
    pub fn new(coefficients: Vec<F>, degrees: Vec<usize>) -> Result<Self, MonomialSumcheckError> {
        let num_vars = degrees.len();
        
        // Compute expected number of coefficients
        let num_coeffs: usize = degrees.iter().map(|&d| d + 1).product();
        
        if coefficients.len() != num_coeffs {
            return Err(MonomialSumcheckError::EvaluationError {
                reason: format!(
                    "Coefficient count mismatch: expected {}, got {}",
                    num_coeffs,
                    coefficients.len()
                ),
            });
        }
        
        // Precompute strides for efficient indexing
        let strides = Self::compute_strides(&degrees);
        
        Ok(Self {
            coefficients,
            degrees,
            num_vars,
            num_coeffs,
            strides,
        })
    }
    
    /// Compute strides for row-major indexing
    ///
    /// For degrees [d₁, d₂, ..., dₙ], stride for variable i is:
    /// stride[i] = ∏_{j=i+1}^{n} (d_j + 1)
    fn compute_strides(degrees: &[usize]) -> Vec<usize> {
        let n = degrees.len();
        let mut strides = vec![1; n];
        
        for i in (0..n-1).rev() {
            strides[i] = strides[i + 1] * (degrees[i + 1] + 1);
        }
        
        strides
    }
    
    /// Convert multi-index to linear index
    ///
    /// Given powers [i₁, i₂, ..., iₙ], compute linear index
    #[inline]
    pub fn multi_index_to_linear(&self, powers: &[usize]) -> usize {
        debug_assert_eq!(powers.len(), self.num_vars);
        
        powers.iter()
            .zip(self.strides.iter())
            .map(|(&p, &s)| p * s)
            .sum()
    }
    
    /// Convert linear index to multi-index
    ///
    /// Inverse of multi_index_to_linear
    pub fn linear_to_multi_index(&self, mut index: usize) -> Vec<usize> {
        let mut powers = vec![0; self.num_vars];
        
        for i in 0..self.num_vars {
            powers[i] = index / self.strides[i];
            index %= self.strides[i];
        }
        
        powers
    }
    
    /// Evaluate polynomial at a point
    ///
    /// # Arguments
    /// * `point` - Evaluation point [x₁, x₂, ..., xₙ]
    ///
    /// # Returns
    /// f(x₁, ..., xₙ)
    ///
    /// # Complexity
    /// O(N) where N is the number of coefficients
    ///
    /// # Algorithm
    /// Direct evaluation: f(x) = ∑ cᵢ · ∏ xⱼ^{iⱼ}
    pub fn evaluate(&self, point: &[F]) -> F {
        debug_assert_eq!(point.len(), self.num_vars);
        
        // Precompute all powers of each variable
        let powers = self.compute_all_powers(point);
        
        let mut result = F::zero();
        
        for (idx, &coeff) in self.coefficients.iter().enumerate() {
            if coeff.is_zero() {
                continue;  // Skip zero coefficients
            }
            
            let multi_idx = self.linear_to_multi_index(idx);
            
            // Compute product of powers: x₁^{i₁} · x₂^{i₂} · ...
            let mut monomial = coeff;
            for (var_idx, &power_idx) in multi_idx.iter().enumerate() {
                monomial = monomial.mul(&powers[var_idx][power_idx]);
            }
            
            result = result.add(&monomial);
        }
        
        result
    }
    
    /// Compute all powers for evaluation
    ///
    /// Returns powers[i][j] = xᵢ^j for all variables and powers
    ///
    /// # Optimization
    /// Uses iterative multiplication: x^{j+1} = x^j · x
    /// This is more cache-friendly than repeated multiplication
    fn compute_all_powers(&self, point: &[F]) -> Vec<Vec<F>> {
        point.iter()
            .zip(self.degrees.iter())
            .map(|(&x, &deg)| {
                let mut powers = Vec::with_capacity(deg + 1);
                powers.push(F::one());
                
                for _ in 1..=deg {
                    let next = powers.last().unwrap().mul(&x);
                    powers.push(next);
                }
                
                powers
            })
            .collect()
    }
    
    /// Get coefficient at multi-index
    #[inline]
    pub fn get_coeff(&self, powers: &[usize]) -> F {
        let idx = self.multi_index_to_linear(powers);
        self.coefficients[idx]
    }
    
    /// Set coefficient at multi-index
    #[inline]
    pub fn set_coeff(&mut self, powers: &[usize], value: F) {
        let idx = self.multi_index_to_linear(powers);
        self.coefficients[idx] = value;
    }
    
    /// Get maximum degree across all variables
    pub fn max_degree(&self) -> usize {
        self.degrees.iter().copied().max().unwrap_or(0)
    }
}

/// Round polynomial in monomial sumcheck
///
/// Represents the univariate polynomial sent in each round:
/// u_k(X) = ∑_{s=0}^{D} c_s · X^s
///
/// Stored as evaluations at points 0, 1, ..., D for efficient verification
///
/// # Paper Reference
/// Section 3: "Incremental Round Polynomial Computation"
#[derive(Clone, Debug)]
pub struct RoundPolynomial<F: Field> {
    /// Evaluations at 0, 1, ..., degree
    pub evaluations: Vec<F>,
    
    /// Degree of the polynomial
    pub degree: usize,
}

impl<F: Field> RoundPolynomial<F> {
    /// Create from evaluations
    pub fn from_evaluations(evaluations: Vec<F>) -> Self {
        let degree = evaluations.len().saturating_sub(1);
        Self { evaluations, degree }
    }
    
    /// Create from coefficients
    ///
    /// Converts monomial representation to evaluation form
    pub fn from_coefficients(coefficients: Vec<F>) -> Self {
        let degree = coefficients.len().saturating_sub(1);
        let mut evaluations = Vec::with_capacity(degree + 1);
        
        // Evaluate at 0, 1, ..., degree
        for i in 0..=degree {
            let x = F::from_u64(i as u64);
            let mut eval = F::zero();
            
            // Horner's method: more efficient than naive evaluation
            for (j, &coeff) in coefficients.iter().enumerate() {
                let power = x.pow(j as u64);
                eval = eval.add(&coeff.mul(&power));
            }
            
            evaluations.push(eval);
        }
        
        Self { evaluations, degree }
    }
    
    /// Evaluate at a point using Lagrange interpolation
    ///
    /// Given evaluations at 0, 1, ..., D, compute p(x) for arbitrary x
    ///
    /// # Complexity
    /// O(D²) field operations
    /// Can be optimized to O(D log² D) using FFT-based methods
    ///
    /// # Algorithm
    /// Lagrange interpolation:
    /// p(x) = ∑ᵢ p(i) · Lᵢ(x)
    /// where Lᵢ(x) = ∏_{j≠i} (x-j)/(i-j)
    pub fn evaluate(&self, point: F) -> F {
        if self.evaluations.is_empty() {
            return F::zero();
        }
        
        if self.evaluations.len() == 1 {
            return self.evaluations[0];
        }
        
        // Barycentric form for better numerical stability
        self.evaluate_barycentric(point)
    }
    
    /// Barycentric Lagrange interpolation
    ///
    /// More efficient than standard form for multiple evaluations
    ///
    /// # Formula
    /// p(x) = ∑ᵢ wᵢ·yᵢ/(x-xᵢ) / ∑ᵢ wᵢ/(x-xᵢ)
    /// where wᵢ = ∏_{j≠i} 1/(xᵢ-xⱼ) are barycentric weights
    fn evaluate_barycentric(&self, point: F) -> F {
        let n = self.evaluations.len();
        
        // Precompute barycentric weights
        let mut weights = vec![F::one(); n];
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let xi = F::from_u64(i as u64);
                    let xj = F::from_u64(j as u64);
                    weights[i] = weights[i].mul(&xi.sub(&xj).inverse());
                }
            }
        }
        
        let mut numerator = F::zero();
        let mut denominator = F::zero();
        
        for i in 0..n {
            let xi = F::from_u64(i as u64);
            
            // Check if point equals a node
            if point == xi {
                return self.evaluations[i];
            }
            
            let term = weights[i].mul(&point.sub(&xi).inverse());
            numerator = numerator.add(&term.mul(&self.evaluations[i]));
            denominator = denominator.add(&term);
        }
        
        numerator.mul(&denominator.inverse())
    }
    
    /// Check consistency: u(0) + u(1) = expected_sum
    ///
    /// This is the key check in each round of sumcheck
    pub fn check_consistency(&self, expected_sum: F) -> bool {
        if self.evaluations.len() < 2 {
            return false;
        }
        
        let sum = self.evaluations[0].add(&self.evaluations[1]);
        sum == expected_sum
    }
}

/// Sumcheck proof for monomial basis
///
/// Contains all prover messages for verification
///
/// # Structure
/// - One round polynomial per variable
/// - Final evaluation at challenge point
///
/// # Size
/// O(n·D) field elements where n=#variables, D=max degree
#[derive(Clone, Debug)]
pub struct MonomialSumcheckProof<F: Field> {
    /// Round polynomials u₁, u₂, ..., uₙ
    pub round_polynomials: Vec<RoundPolynomial<F>>,
    
    /// Final evaluation f(r₁, ..., rₙ) at challenge point
    pub final_evaluation: F,
    
    /// Optional: proof metadata for debugging
    pub metadata: ProofMetadata,
}

impl<F: Field> MonomialSumcheckProof<F> {
    /// Create a new proof
    pub fn new(
        round_polynomials: Vec<RoundPolynomial<F>>,
        final_evaluation: F,
    ) -> Self {
        Self {
            round_polynomials,
            final_evaluation,
            metadata: ProofMetadata::default(),
        }
    }
    
    /// Get number of rounds
    pub fn num_rounds(&self) -> usize {
        self.round_polynomials.len()
    }
    
    /// Get total size in field elements
    pub fn size(&self) -> usize {
        let rounds_size: usize = self.round_polynomials
            .iter()
            .map(|p| p.evaluations.len())
            .sum();
        rounds_size + 1  // +1 for final evaluation
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Number of rounds
        bytes.extend_from_slice(&(self.num_rounds() as u32).to_le_bytes());
        
        // Each round polynomial
        for poly in &self.round_polynomials {
            bytes.extend_from_slice(&(poly.degree as u32).to_le_bytes());
            for eval in &poly.evaluations {
                bytes.extend_from_slice(&eval.to_bytes());
            }
        }
        
        // Final evaluation
        bytes.extend_from_slice(&self.final_evaluation.to_bytes());
        
        bytes
    }
}

/// Proof metadata for debugging and analysis
#[derive(Clone, Debug, Default)]
pub struct ProofMetadata {
    /// Time taken to generate proof (nanoseconds)
    pub prover_time_ns: u64,
    
    /// Time taken to verify proof (nanoseconds)
    pub verifier_time_ns: u64,
    
    /// Number of field operations (prover)
    pub prover_field_ops: u64,
    
    /// Number of field operations (verifier)
    pub verifier_field_ops: u64,
}

/// Challenge point sampled during protocol
///
/// Represents the random point r = (r₁, r₂, ..., rₙ) where
/// each rᵢ is sampled by the verifier in round i
#[derive(Clone, Debug)]
pub struct ChallengePoint<F: Field> {
    /// Challenge values [r₁, r₂, ..., rₙ]
    pub values: Vec<F>,
    
    /// Precomputed powers for optimization
    /// powers[i][j] = rᵢ^j for j = 0, 1, ..., max_degree
    pub powers: Vec<Vec<F>>,
}

impl<F: Field> ChallengePoint<F> {
    /// Create a new challenge point with precomputed powers
    ///
    /// # Arguments
    /// * `values` - Challenge values [r₁, r₂, ..., rₙ]
    /// * `max_degrees` - Maximum degree for each variable
    pub fn new(values: Vec<F>, max_degrees: &[usize]) -> Self {
        debug_assert_eq!(values.len(), max_degrees.len());
        
        let powers = values.iter()
            .zip(max_degrees.iter())
            .map(|(&r, &max_deg)| {
                let mut pows = Vec::with_capacity(max_deg + 1);
                pows.push(F::one());
                
                for _ in 1..=max_deg {
                    let next = pows.last().unwrap().mul(&r);
                    pows.push(next);
                }
                
                pows
            })
            .collect();
        
        Self { values, powers }
    }
    
    /// Get power: rᵢ^j
    #[inline]
    pub fn get_power(&self, var_idx: usize, power: usize) -> F {
        self.powers[var_idx][power]
    }
    
    /// Number of variables
    pub fn num_vars(&self) -> usize {
        self.values.len()
    }
}

/// Transcript for Fiat-Shamir transformation
///
/// Maintains cryptographic hash of all protocol messages for
/// non-interactive challenge generation
///
/// # Security
/// Uses collision-resistant hash function (e.g., SHA-3, BLAKE3)
/// to ensure soundness in non-interactive setting
pub struct Transcript {
    /// Internal hash state
    state: blake3::Hasher,
    
    /// Domain separation tag
    domain_separator: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with domain separation
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain_separator);
        
        Self {
            state: hasher,
            domain_separator: domain_separator.to_vec(),
        }
    }
    
    /// Append message to transcript
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.update(label);
        self.state.update(&(message.len() as u64).to_le_bytes());
        self.state.update(message);
    }
    
    /// Append field element to transcript
    pub fn append_field_element<F: Field>(&mut self, label: &[u8], element: &F) {
        self.append_message(label, &element.to_bytes());
    }
    
    /// Challenge field element from transcript
    ///
    /// Uses rejection sampling to ensure uniform distribution
    pub fn challenge_field_element<F: Field>(&mut self, label: &[u8]) -> F {
        self.append_message(label, b"challenge");
        
        // Rejection sampling for uniform distribution
        loop {
            let hash = self.state.finalize();
            let bytes = hash.as_bytes();
            
            if let Some(element) = F::from_bytes_uniform(bytes) {
                // Update state for next challenge
                self.state = blake3::Hasher::new();
                self.state.update(&self.domain_separator);
                self.state.update(hash.as_bytes());
                
                return element;
            }
            
            // Rejection: hash again
            self.state = blake3::Hasher::new();
            self.state.update(hash.as_bytes());
        }
    }
    
    /// Challenge multiple field elements
    pub fn challenge_field_elements<F: Field>(&mut self, label: &[u8], count: usize) -> Vec<F> {
        (0..count)
            .map(|i| {
                let label_i = format!("{}_{}", String::from_utf8_lossy(label), i);
                self.challenge_field_element(label_i.as_bytes())
            })
            .collect()
    }
}

impl Clone for Transcript {
    fn clone(&self) -> Self {
        Self::new(&self.domain_separator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::MockField;
    
    #[test]
    fn test_monomial_polynomial_indexing() {
        // 2 variables, degrees [2, 3]
        let degrees = vec![2, 3];
        let num_coeffs = 3 * 4; // (2+1) * (3+1) = 12
        let coeffs = (0..num_coeffs).map(|i| MockField::from(i as u64)).collect();
        
        let poly = MonomialPolynomial::new(coeffs, degrees).unwrap();
        
        // Test round-trip conversion
        for i in 0..num_coeffs {
            let multi = poly.linear_to_multi_index(i);
            let linear = poly.multi_index_to_linear(&multi);
            assert_eq!(i, linear);
        }
    }
    
    #[test]
    fn test_round_polynomial_evaluation() {
        let evals = vec![
            MockField::from(1),
            MockField::from(4),
            MockField::from(9),
        ];
        let poly = RoundPolynomial::from_evaluations(evals);
        
        // Should interpolate correctly at nodes
        assert_eq!(poly.evaluate(MockField::from(0)), MockField::from(1));
        assert_eq!(poly.evaluate(MockField::from(1)), MockField::from(4));
        assert_eq!(poly.evaluate(MockField::from(2)), MockField::from(9));
    }
    
    #[test]
    fn test_challenge_point_powers() {
        let values = vec![MockField::from(2), MockField::from(3)];
        let max_degrees = vec![3, 2];
        
        let challenge = ChallengePoint::new(values, &max_degrees);
        
        // Check powers are computed correctly
        assert_eq!(challenge.get_power(0, 0), MockField::from(1));
        assert_eq!(challenge.get_power(0, 1), MockField::from(2));
        assert_eq!(challenge.get_power(0, 2), MockField::from(4));
        assert_eq!(challenge.get_power(0, 3), MockField::from(8));
        
        assert_eq!(challenge.get_power(1, 0), MockField::from(1));
        assert_eq!(challenge.get_power(1, 1), MockField::from(3));
        assert_eq!(challenge.get_power(1, 2), MockField::from(9));
    }
}
