//! Utility functions for Cyclo

use crate::field::FiniteField;
use super::types::*;
use sha2::{Sha256, Digest};

/// Fiat-Shamir transcript for non-interactive proofs
pub struct Transcript<F: FiniteField> {
    hasher: Sha256,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FiniteField> Transcript<F> {
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(label);
        Self {
            hasher,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Append a message to transcript
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }

    /// Append field element
    pub fn append_scalar(&mut self, label: &[u8], scalar: F) {
        self.append_message(label, &scalar.to_bytes());
    }

    /// Append ring element
    pub fn append_ring_element(&mut self, label: &[u8], elem: &RingElement<F>) {
        self.append_message(label, b"ring_element");
        for coeff in &elem.coeffs {
            self.append_scalar(b"coeff", *coeff);
        }
    }

    /// Append commitment (vector of ring elements)
    pub fn append_commitment(&mut self, commitment: &[RingElement<F>]) {
        self.append_message(b"commitment", &commitment.len().to_le_bytes());
        for elem in commitment {
            self.append_ring_element(b"elem", elem);
        }
    }

    /// Append ring elements vector
    pub fn append_ring_elements(&mut self, elements: &[RingElement<F>]) {
        for elem in elements {
            self.append_ring_element(b"elem", elem);
        }
    }

    /// Challenge scalar in base field
    pub fn challenge_scalar(&mut self, _extension_degree: usize) -> F {
        let hash = self.hasher.clone().finalize();
        self.hasher.update(&hash);
        F::from_bytes(&hash[..16])
    }

    /// Challenge vector
    pub fn challenge_vector(&mut self, length: usize, extension_degree: usize) -> Vec<F> {
        (0..length)
            .map(|_| self.challenge_scalar(extension_degree))
            .collect()
    }

    /// Challenge index for sampling from a set
    pub fn challenge_index(&mut self, set_size: usize) -> usize {
        let hash = self.hasher.clone().finalize();
        self.hasher.update(&hash);
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        (val % set_size as u64) as usize
    }

    /// Challenge indices
    pub fn challenge_indices(&mut self, count: usize, set_size: usize) -> Vec<usize> {
        (0..count)
            .map(|_| self.challenge_index(set_size))
            .collect()
    }
}

/// Polynomial operations
pub mod polynomial {
    use super::*;

    /// Evaluate univariate polynomial at a point
    pub fn evaluate<F: FiniteField>(coeffs: &[F], point: F) -> F {
        let mut result = F::zero();
        let mut power = F::one();
        
        for &coeff in coeffs {
            result = result + coeff * power;
            power = power * point;
        }
        
        result
    }

    /// Interpolate polynomial from points
    pub fn interpolate<F: FiniteField>(points: &[(F, F)]) -> Vec<F> {
        let n = points.len();
        let mut coeffs = vec![F::zero(); n];

        for i in 0..n {
            let (xi, yi) = points[i];
            let mut li = vec![yi];

            for j in 0..n {
                if i != j {
                    let (xj, _) = points[j];
                    let denom = xi - xj;
                    let denom_inv = denom.inverse();

                    // Multiply li by (X - xj) / (xi - xj)
                    let mut new_li = vec![F::zero(); li.len() + 1];
                    for (k, &c) in li.iter().enumerate() {
                        new_li[k] = new_li[k] + c * (F::zero() - xj) * denom_inv;
                        new_li[k + 1] = new_li[k + 1] + c * denom_inv;
                    }
                    li = new_li;
                }
            }

            for (k, &c) in li.iter().enumerate() {
                if k < coeffs.len() {
                    coeffs[k] = coeffs[k] + c;
                }
            }
        }

        coeffs
    }

    /// Add two polynomials
    pub fn add<F: FiniteField>(a: &[F], b: &[F]) -> Vec<F> {
        let max_len = a.len().max(b.len());
        let mut result = vec![F::zero(); max_len];

        for (i, &coeff) in a.iter().enumerate() {
            result[i] = result[i] + coeff;
        }

        for (i, &coeff) in b.iter().enumerate() {
            result[i] = result[i] + coeff;
        }

        result
    }

    /// Multiply two polynomials
    pub fn multiply<F: FiniteField>(a: &[F], b: &[F]) -> Vec<F> {
        if a.is_empty() || b.is_empty() {
            return vec![];
        }

        let mut result = vec![F::zero(); a.len() + b.len() - 1];

        for (i, &coeff_a) in a.iter().enumerate() {
            for (j, &coeff_b) in b.iter().enumerate() {
                result[i + j] = result[i + j] + coeff_a * coeff_b;
            }
        }

        result
    }
}

/// Matrix operations
pub mod matrix {
    use super::*;

    /// Transpose matrix
    pub fn transpose<T: Clone>(matrix: &[Vec<T>]) -> Vec<Vec<T>> {
        if matrix.is_empty() {
            return vec![];
        }

        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut result = vec![vec![]; cols];

        for row in matrix {
            for (j, elem) in row.iter().enumerate() {
                result[j].push(elem.clone());
            }
        }

        result
    }

    /// Matrix-matrix multiplication
    pub fn matrix_mult<F: FiniteField>(
        ring: &super::CyclotomicRing<F>,
        a: &[Vec<RingElement<F>>],
        b: &[Vec<RingElement<F>>],
    ) -> Vec<Vec<RingElement<F>>> {
        let rows_a = a.len();
        let cols_a = if rows_a > 0 { a[0].len() } else { 0 };
        let cols_b = if !b.is_empty() { b[0].len() } else { 0 };

        assert_eq!(cols_a, b.len(), "Matrix dimension mismatch");

        let mut result = vec![vec![RingElement::zero(ring.conductor); cols_b]; rows_a];

        for i in 0..rows_a {
            for j in 0..cols_b {
                let mut sum = RingElement::zero(ring.conductor);
                for k in 0..cols_a {
                    let prod = ring.multiply(&a[i][k], &b[k][j]);
                    sum = ring.add(&sum, &prod);
                }
                result[i][j] = sum;
            }
        }

        result
    }
}

/// Batch operations
pub mod batch {
    use super::*;

    /// Batch verify multiple statements
    pub fn batch_verify<F: FiniteField, T>(
        statements: &[T],
        verifier: impl Fn(&T) -> Result<(), String>,
    ) -> Result<(), String> {
        for (i, statement) in statements.iter().enumerate() {
            verifier(statement)
                .map_err(|e| format!("Statement {} failed: {}", i, e))?;
        }
        Ok(())
    }

    /// Random linear combination
    pub fn random_linear_combination<F: FiniteField>(
        ring: &super::CyclotomicRing<F>,
        elements: &[RingElement<F>],
        challenges: &[RingElement<F>],
    ) -> RingElement<F> {
        assert_eq!(elements.len(), challenges.len());

        let mut result = RingElement::zero(ring.conductor);

        for (elem, challenge) in elements.iter().zip(challenges.iter()) {
            let prod = ring.multiply(elem, challenge);
            result = ring.add(&result, &prod);
        }

        result
    }
}

/// Bit manipulation utilities
pub mod bits {
    /// Convert integer to binary representation
    pub fn to_binary(mut n: usize, length: usize) -> Vec<bool> {
        let mut result = vec![false; length];
        for i in 0..length {
            result[i] = (n & 1) == 1;
            n >>= 1;
        }
        result
    }

    /// Convert binary to integer
    pub fn from_binary(bits: &[bool]) -> usize {
        let mut result = 0;
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                result |= 1 << i;
            }
        }
        result
    }

    /// Hamming weight
    pub fn hamming_weight(bits: &[bool]) -> usize {
        bits.iter().filter(|&&b| b).count()
    }
}

/// Norm computations
pub fn compute_accumulated_norm<F: FiniteField>(
    initial_norm: F,
    num_rounds: usize,
    base_b: F,
    expansion_factor: F,
    num_relations: usize,
) -> F {
    // β + L·b·γ per round (additive growth)
    let per_round_growth = F::from_u64(num_relations as u64) * base_b * expansion_factor;
    initial_norm + per_round_growth * F::from_u64(num_rounds as u64)
}

/// Security parameter computation
pub fn compute_security_parameter(
    ring_degree: usize,
    modulus_bits: usize,
    norm_bound: u64,
) -> usize {
    // Simplified LWE/SIS security estimate
    // In production, use lattice estimator
    let n = ring_degree;
    let log_q = modulus_bits as f64;
    let log_beta = (norm_bound as f64).log2();

    // Rough estimate: λ ≈ n * log(q/β) / log(n)
    let security = (n as f64) * (log_q - log_beta) / (n as f64).log2();
    security.floor() as usize
}

/// Knowledge error computation
pub fn compute_knowledge_error<F: FiniteField>(
    soundness_errors: &[f64],
) -> f64 {
    // Union bound over all error sources
    soundness_errors.iter().sum()
}
