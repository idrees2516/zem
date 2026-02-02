// Multilinear extension commitment (Section 4.2 of paper)
//
// Commits to multilinear extension of coefficient vectors,
// enabling efficient recursive evaluation.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::commitment::inner_outer::CommitmentKey;
use crate::ring::RingElement;
use crate::field::Field;

/// Multilinear extension commitment
///
/// For vectors z', r' ∈ Z_q^*, commit to multilinear extension:
/// P := mle[(z', r')] ∈ F_{q^k}^{≤1}[X_1, ..., X_μ]
///
/// where μ = log₂(|z'| + |r'|)
#[derive(Clone, Debug)]
pub struct MLECommitment<F: Field> {
    /// Commitment key
    key: CommitmentKey<F>,
    
    /// Ring dimension
    ring_dimension: usize,
    
    /// Number of variables in MLE
    num_variables: usize,
}

impl<F: Field> MLECommitment<F> {
    /// Create MLE commitment
    pub fn new(
        key: CommitmentKey<F>,
        num_variables: usize,
    ) -> Result<Self, HachiError> {
        let ring_dimension = key.params().ring_dimension();
        
        Ok(Self {
            key,
            ring_dimension,
            num_variables,
        })
    }
    
    /// Commit to coefficient vectors
    ///
    /// Given z' ∈ Z_q^{2^m} and r' ∈ Z_q^{2^n},
    /// commit to mle[(z', r')] ∈ F_{q^k}^{≤1}[X_1, ..., X_{m+n}]
    pub fn commit_to_vectors(
        &self,
        z_prime: &[RingElement<F>],
        r_prime: &[RingElement<F>],
    ) -> Result<MLECommitmentValue<F>, HachiError> {
        // Combine vectors
        let mut combined = Vec::new();
        combined.extend_from_slice(z_prime);
        combined.extend_from_slice(r_prime);
        
        // Verify size is power of 2
        let total_size = combined.len();
        if total_size & (total_size - 1) != 0 {
            return Err(HachiError::InvalidDimension {
                expected: 1 << self.num_variables,
                actual: total_size,
            });
        }
        
        // Create witness blocks for commitment
        let witness_blocks = vec![combined];
        
        // Commit
        let commitment_value = self.key.commit(&witness_blocks)?;
        
        Ok(MLECommitmentValue {
            value: commitment_value,
            num_variables: self.num_variables,
            z_prime_size: z_prime.len(),
            r_prime_size: r_prime.len(),
        })
    }
    
    /// Evaluate MLE at point
    ///
    /// Given evaluation point x ∈ F_{q^k}^μ, compute mle[(z', r')](x)
    pub fn evaluate_mle(
        &self,
        z_prime: &[RingElement<F>],
        r_prime: &[RingElement<F>],
        evaluation_point: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        // Combine vectors
        let mut combined = Vec::new();
        combined.extend_from_slice(z_prime);
        combined.extend_from_slice(r_prime);
        
        // Compute multilinear extension evaluation
        self.evaluate_multilinear_extension(&combined, evaluation_point)
    }
    
    /// Compute multilinear extension evaluation
    ///
    /// For function f : {0,1}^μ → R_q with values f_i,
    /// compute mle[f](x) = Σ_{i∈{0,1}^μ} f_i · eq(i, x)
    fn evaluate_multilinear_extension(
        &self,
        values: &[RingElement<F>],
        point: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        let num_vars = point.len();
        let num_values = 1 << num_vars;
        
        if values.len() != num_values {
            return Err(HachiError::InvalidDimension {
                expected: num_values,
                actual: values.len(),
            });
        }
        
        let mut result = RingElement::zero(self.ring_dimension)?;
        
        // For each index i ∈ {0,1}^μ
        for i in 0..num_values {
            // Compute equality polynomial eq(i, x)
            let eq_value = self.compute_equality_polynomial(i, point)?;
            
            // Multiply by value and add
            let term = values[i].mul(&eq_value)?;
            result = result.add(&term)?;
        }
        
        Ok(result)
    }
    
    /// Compute equality polynomial eq(i, x)
    ///
    /// eq(i, x) = ∏_{j=1}^μ ((1-i_j)·(1-x_j) + i_j·x_j)
    fn compute_equality_polynomial(
        &self,
        index: usize,
        point: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        let mut result = RingElement::one(self.ring_dimension)?;
        
        for j in 0..point.len() {
            let bit = (index >> j) & 1;
            
            if bit == 0 {
                // (1 - x_j)
                let one = RingElement::one(self.ring_dimension)?;
                let factor = one.sub(&point[j])?;
                result = result.mul(&factor)?;
            } else {
                // x_j
                result = result.mul(&point[j])?;
            }
        }
        
        Ok(result)
    }
    
    /// Verify MLE commitment
    pub fn verify_mle_commitment(
        &self,
        commitment: &MLECommitmentValue<F>,
        z_prime: &[RingElement<F>],
        r_prime: &[RingElement<F>],
    ) -> Result<bool, HachiError> {
        if z_prime.len() != commitment.z_prime_size || r_prime.len() != commitment.r_prime_size {
            return Ok(false);
        }
        
        // Recompute commitment
        let recomputed = self.commit_to_vectors(z_prime, r_prime)?;
        
        Ok(recomputed.value.equals(&commitment.value))
    }
}

/// MLE commitment value
#[derive(Clone, Debug)]
pub struct MLECommitmentValue<F: Field> {
    /// Commitment value
    pub value: RingElement<F>,
    
    /// Number of variables
    pub num_variables: usize,
    
    /// Size of z' vector
    pub z_prime_size: usize,
    
    /// Size of r' vector
    pub r_prime_size: usize,
}

impl<F: Field> MLECommitmentValue<F> {
    /// Get commitment value
    pub fn value(&self) -> &RingElement<F> {
        &self.value
    }
    
    /// Get number of variables
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }
}

/// Recursive MLE evaluation
///
/// Enables efficient recursive evaluation of MLE
pub struct RecursiveMLEEvaluation<F: Field> {
    mle: MLECommitment<F>,
}

impl<F: Field> RecursiveMLEEvaluation<F> {
    pub fn new(key: CommitmentKey<F>, num_variables: usize) -> Result<Self, HachiError> {
        let mle = MLECommitment::new(key, num_variables)?;
        Ok(Self { mle })
    }
    
    /// Evaluate MLE recursively
    ///
    /// For MLE with μ variables, evaluate at point (r_1, ..., r_μ)
    /// using recursive structure
    pub fn recursive_evaluate(
        &self,
        values: &[RingElement<F>],
        point: &[RingElement<F>],
    ) -> Result<RingElement<F>, HachiError> {
        if point.is_empty() {
            // Base case: single value
            if values.len() != 1 {
                return Err(HachiError::InvalidDimension {
                    expected: 1,
                    actual: values.len(),
                });
            }
            return Ok(values[0].clone());
        }
        
        // Recursive case
        let r = &point[0];
        let remaining_point = &point[1..];
        
        let half_size = values.len() / 2;
        
        // Evaluate left and right halves
        let left_eval = self.recursive_evaluate(&values[..half_size], remaining_point)?;
        let right_eval = self.recursive_evaluate(&values[half_size..], remaining_point)?;
        
        // Combine: (1-r) · left + r · right
        let one = RingElement::one(self.mle.ring_dimension)?;
        let one_minus_r = one.sub(r)?;
        
        let left_term = one_minus_r.mul(&left_eval)?;
        let right_term = r.mul(&right_eval)?;
        
        left_term.add(&right_term)
    }
}

/// Batch MLE commitment
pub struct BatchMLECommitment<F: Field> {
    mle: MLECommitment<F>,
}

impl<F: Field> BatchMLECommitment<F> {
    pub fn new(key: CommitmentKey<F>, num_variables: usize) -> Result<Self, HachiError> {
        let mle = MLECommitment::new(key, num_variables)?;
        Ok(Self { mle })
    }
    
    /// Commit to multiple vector pairs
    pub fn batch_commit(
        &self,
        z_primes: &[Vec<RingElement<F>>],
        r_primes: &[Vec<RingElement<F>>],
    ) -> Result<Vec<MLECommitmentValue<F>>, HachiError> {
        if z_primes.len() != r_primes.len() {
            return Err(HachiError::InvalidDimension {
                expected: z_primes.len(),
                actual: r_primes.len(),
            });
        }
        
        let mut commitments = Vec::new();
        
        for i in 0..z_primes.len() {
            let commitment = self.mle.commit_to_vectors(&z_primes[i], &r_primes[i])?;
            commitments.push(commitment);
        }
        
        Ok(commitments)
    }
    
    /// Evaluate multiple MLEs
    pub fn batch_evaluate(
        &self,
        z_primes: &[Vec<RingElement<F>>],
        r_primes: &[Vec<RingElement<F>>],
        evaluation_point: &[RingElement<F>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if z_primes.len() != r_primes.len() {
            return Err(HachiError::InvalidDimension {
                expected: z_primes.len(),
                actual: r_primes.len(),
            });
        }
        
        let mut evaluations = Vec::new();
        
        for i in 0..z_primes.len() {
            let eval = self.mle.evaluate_mle(&z_primes[i], &r_primes[i], evaluation_point)?;
            evaluations.push(eval);
        }
        
        Ok(evaluations)
    }
}

/// MLE homomorphic properties
pub struct MLEHomomorphic<F: Field> {
    mle: MLECommitment<F>,
}

impl<F: Field> MLEHomomorphic<F> {
    pub fn new(key: CommitmentKey<F>, num_variables: usize) -> Result<Self, HachiError> {
        let mle = MLECommitment::new(key, num_variables)?;
        Ok(Self { mle })
    }
    
    /// Verify homomorphic property of MLE
    ///
    /// mle[f + g] = mle[f] + mle[g]
    pub fn verify_additivity(
        &self,
        f: &[RingElement<F>],
        g: &[RingElement<F>],
        point: &[RingElement<F>],
    ) -> Result<bool, HachiError> {
        if f.len() != g.len() {
            return Ok(false);
        }
        
        // Compute mle[f](x)
        let mle_f = self.mle.evaluate_multilinear_extension(f, point)?;
        
        // Compute mle[g](x)
        let mle_g = self.mle.evaluate_multilinear_extension(g, point)?;
        
        // Compute mle[f+g](x)
        let mut f_plus_g = Vec::new();
        for i in 0..f.len() {
            f_plus_g.push(f[i].add(&g[i])?);
        }
        let mle_f_plus_g = self.mle.evaluate_multilinear_extension(&f_plus_g, point)?;
        
        // Check: mle[f+g] = mle[f] + mle[g]
        let sum = mle_f.add(&mle_g)?;
        Ok(sum.equals(&mle_f_plus_g))
    }
}
