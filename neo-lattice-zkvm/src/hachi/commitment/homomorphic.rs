// Homomorphic operations on commitments
//
// Implements homomorphic properties of the commitment scheme,
// enabling efficient operations on committed values.

use crate::hachi::errors::HachiError;
use crate::hachi::commitment::inner_outer::{CommitmentKey, Commitment};
use crate::ring::RingElement;
use crate::field::Field;

/// Homomorphic commitment operations
///
/// The inner-outer commitment scheme is additively homomorphic:
/// commit(s + s') = commit(s) + commit(s')
///
/// This enables efficient operations on committed values.
#[derive(Clone, Debug)]
pub struct HomomorphicCommitment<F: Field> {
    /// Commitment key
    key: CommitmentKey<F>,
    
    /// Ring dimension
    ring_dimension: usize,
}

impl<F: Field> HomomorphicCommitment<F> {
    /// Create homomorphic commitment operations
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let ring_dimension = key.params().ring_dimension();
        
        Ok(Self {
            key,
            ring_dimension,
        })
    }
    
    /// Add two commitments
    ///
    /// commit(s) + commit(s') = commit(s + s')
    pub fn add_commitments(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
    ) -> Result<Commitment<F>, HachiError> {
        let sum = c1.value().add(c2.value())?;
        Ok(Commitment::new(sum))
    }
    
    /// Subtract two commitments
    ///
    /// commit(s) - commit(s') = commit(s - s')
    pub fn sub_commitments(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
    ) -> Result<Commitment<F>, HachiError> {
        let diff = c1.value().sub(c2.value())?;
        Ok(Commitment::new(diff))
    }
    
    /// Scalar multiply commitment
    ///
    /// α · commit(s) = commit(α · s)
    pub fn scalar_multiply_commitment(
        &self,
        commitment: &Commitment<F>,
        scalar: F,
    ) -> Result<Commitment<F>, HachiError> {
        let scaled = commitment.value().scalar_mul(scalar)?;
        Ok(Commitment::new(scaled))
    }
    
    /// Linear combination of commitments
    ///
    /// Σ_i α_i · commit(s_i) = commit(Σ_i α_i · s_i)
    pub fn linear_combination(
        &self,
        commitments: &[Commitment<F>],
        scalars: &[F],
    ) -> Result<Commitment<F>, HachiError> {
        if commitments.len() != scalars.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: scalars.len(),
            });
        }
        
        let mut result = RingElement::zero(self.ring_dimension)?;
        
        for i in 0..commitments.len() {
            let scaled = commitments[i].value().scalar_mul(scalars[i])?;
            result = result.add(&scaled)?;
        }
        
        Ok(Commitment::new(result))
    }
    
    /// Verify homomorphic property
    ///
    /// Checks: commit(s + s') = commit(s) + commit(s')
    pub fn verify_homomorphic_property(
        &self,
        witness1: &[Vec<RingElement<F>>],
        witness2: &[Vec<RingElement<F>>],
    ) -> Result<bool, HachiError> {
        // Compute commitments
        let c1 = self.key.commit(witness1)?;
        let c2 = self.key.commit(witness2)?;
        
        // Compute sum of commitments
        let c_sum = self.add_commitments(&Commitment::new(c1), &Commitment::new(c2))?;
        
        // Compute sum of witnesses
        if witness1.len() != witness2.len() {
            return Ok(false);
        }
        
        let mut sum_witness = Vec::new();
        for i in 0..witness1.len() {
            if witness1[i].len() != witness2[i].len() {
                return Ok(false);
            }
            
            let mut sum_block = Vec::new();
            for j in 0..witness1[i].len() {
                let sum = witness1[i][j].add(&witness2[i][j])?;
                sum_block.push(sum);
            }
            sum_witness.push(sum_block);
        }
        
        // Compute commitment of sum
        let c_witness_sum = self.key.commit(&sum_witness)?;
        
        // Check equality
        Ok(c_sum.value().equals(&c_witness_sum))
    }
}

/// Batch homomorphic operations
pub struct BatchHomomorphicCommitment<F: Field> {
    homo: HomomorphicCommitment<F>,
}

impl<F: Field> BatchHomomorphicCommitment<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let homo = HomomorphicCommitment::new(key)?;
        Ok(Self { homo })
    }
    
    /// Add multiple commitments
    pub fn batch_add(
        &self,
        commitments: &[Commitment<F>],
    ) -> Result<Commitment<F>, HachiError> {
        if commitments.is_empty() {
            return Err(HachiError::InvalidDimension {
                expected: 1,
                actual: 0,
            });
        }
        
        let mut result = commitments[0].clone();
        
        for i in 1..commitments.len() {
            result = self.homo.add_commitments(&result, &commitments[i])?;
        }
        
        Ok(result)
    }
    
    /// Compute linear combinations
    pub fn batch_linear_combination(
        &self,
        commitments: &[Vec<Commitment<F>>],
        scalars: &[Vec<F>],
    ) -> Result<Vec<Commitment<F>>, HachiError> {
        if commitments.len() != scalars.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: scalars.len(),
            });
        }
        
        let mut results = Vec::new();
        
        for i in 0..commitments.len() {
            let lc = self.homo.linear_combination(&commitments[i], &scalars[i])?;
            results.push(lc);
        }
        
        Ok(results)
    }
}

/// Commitment arithmetic
pub struct CommitmentArithmetic<F: Field> {
    homo: HomomorphicCommitment<F>,
}

impl<F: Field> CommitmentArithmetic<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let homo = HomomorphicCommitment::new(key)?;
        Ok(Self { homo })
    }
    
    /// Compute commitment to sum
    pub fn commitment_sum(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
    ) -> Result<Commitment<F>, HachiError> {
        self.homo.add_commitments(c1, c2)
    }
    
    /// Compute commitment to difference
    pub fn commitment_difference(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
    ) -> Result<Commitment<F>, HachiError> {
        self.homo.sub_commitments(c1, c2)
    }
    
    /// Compute commitment to scalar multiple
    pub fn commitment_scalar_multiple(
        &self,
        commitment: &Commitment<F>,
        scalar: F,
    ) -> Result<Commitment<F>, HachiError> {
        self.homo.scalar_multiply_commitment(commitment, scalar)
    }
    
    /// Compute commitment to linear combination
    pub fn commitment_linear_combination(
        &self,
        commitments: &[Commitment<F>],
        scalars: &[F],
    ) -> Result<Commitment<F>, HachiError> {
        self.homo.linear_combination(commitments, scalars)
    }
}

/// Commitment evaluation
///
/// Evaluates committed polynomials at given points
pub struct CommitmentEvaluation<F: Field> {
    key: CommitmentKey<F>,
    ring_dimension: usize,
}

impl<F: Field> CommitmentEvaluation<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let ring_dimension = key.params().ring_dimension();
        Ok(Self { key, ring_dimension })
    }
    
    /// Evaluate committed polynomial at point
    ///
    /// Given commitment to polynomial f and evaluation point x,
    /// compute commitment to f(x)
    pub fn evaluate_at_point(
        &self,
        commitment: &Commitment<F>,
        evaluation_point: &RingElement<F>,
    ) -> Result<Commitment<F>, HachiError> {
        // Multiply commitment by evaluation point
        let evaluated = commitment.value().mul(evaluation_point)?;
        Ok(Commitment::new(evaluated))
    }
    
    /// Batch evaluate at multiple points
    pub fn batch_evaluate(
        &self,
        commitment: &Commitment<F>,
        points: &[RingElement<F>],
    ) -> Result<Vec<Commitment<F>>, HachiError> {
        let mut results = Vec::new();
        
        for point in points {
            let evaluated = self.evaluate_at_point(commitment, point)?;
            results.push(evaluated);
        }
        
        Ok(results)
    }
}

/// Commitment composition
///
/// Composes commitments to create new commitments
pub struct CommitmentComposition<F: Field> {
    homo: HomomorphicCommitment<F>,
}

impl<F: Field> CommitmentComposition<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let homo = HomomorphicCommitment::new(key)?;
        Ok(Self { homo })
    }
    
    /// Compose two commitments
    ///
    /// Given commitments c1, c2 and scalars a, b,
    /// compute a·c1 + b·c2
    pub fn compose(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
        a: F,
        b: F,
    ) -> Result<Commitment<F>, HachiError> {
        let scaled1 = self.homo.scalar_multiply_commitment(c1, a)?;
        let scaled2 = self.homo.scalar_multiply_commitment(c2, b)?;
        self.homo.add_commitments(&scaled1, &scaled2)
    }
    
    /// Compose multiple commitments
    pub fn compose_multiple(
        &self,
        commitments: &[Commitment<F>],
        scalars: &[F],
    ) -> Result<Commitment<F>, HachiError> {
        self.homo.linear_combination(commitments, scalars)
    }
}

/// Commitment verification with homomorphic properties
pub struct HomomorphicVerifier<F: Field> {
    homo: HomomorphicCommitment<F>,
}

impl<F: Field> HomomorphicVerifier<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let homo = HomomorphicCommitment::new(key)?;
        Ok(Self { homo })
    }
    
    /// Verify homomorphic addition
    pub fn verify_addition(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
        c_sum: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        let computed_sum = self.homo.add_commitments(c1, c2)?;
        Ok(computed_sum.value().equals(c_sum.value()))
    }
    
    /// Verify homomorphic subtraction
    pub fn verify_subtraction(
        &self,
        c1: &Commitment<F>,
        c2: &Commitment<F>,
        c_diff: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        let computed_diff = self.homo.sub_commitments(c1, c2)?;
        Ok(computed_diff.value().equals(c_diff.value()))
    }
    
    /// Verify homomorphic scalar multiplication
    pub fn verify_scalar_multiplication(
        &self,
        commitment: &Commitment<F>,
        scalar: F,
        c_scaled: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        let computed_scaled = self.homo.scalar_multiply_commitment(commitment, scalar)?;
        Ok(computed_scaled.value().equals(c_scaled.value()))
    }
    
    /// Verify homomorphic linear combination
    pub fn verify_linear_combination(
        &self,
        commitments: &[Commitment<F>],
        scalars: &[F],
        c_lc: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        let computed_lc = self.homo.linear_combination(commitments, scalars)?;
        Ok(computed_lc.value().equals(c_lc.value()))
    }
}
