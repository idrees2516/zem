// Error correction and relaxation for ProtogaLattice
//
// Implements:
// - Error term computation
// - Relaxation factor management
// - Error bound checking

use crate::field::Field;
use crate::ring::RingElement;
use crate::protogalattice::{
    types::*,
    lattice_params::LatticeParams,
    Result,
};
use crate::errors::ProtogaError;

/// Error correction manager
pub struct ErrorCorrector {
    params: LatticeParams,
    error_bound: f64,
}

impl ErrorCorrector {
    /// Create new error corrector
    pub fn new(params: LatticeParams) -> Self {
        let error_bound = params.sis_beta / 2.0;
        Self {
            params,
            error_bound,
        }
    }

    /// Compute error term for folding
    pub fn compute_folding_error<F: Field>(
        &self,
        instance1: &ProtogaInstance<F>,
        instance2: &ProtogaInstance<F>,
        folded: &ProtogaInstance<F>,
        challenge: &F,
    ) -> Result<Vec<F>> {
        // Error = folded - (instance1 + r * instance2)
        let mut errors = Vec::new();

        for i in 0..folded.public_inputs.len() {
            let expected = instance1.public_inputs[i]
                .add(&challenge.mul(&instance2.public_inputs[i]));
            let error = folded.public_inputs[i].sub(&expected);
            errors.push(error);
        }

        Ok(errors)
    }

    /// Check if error is within bound
    pub fn check_error_bound(&self, error_vec: &[RingElement]) -> bool {
        for error in error_vec {
            let norm = self.compute_norm(error);
            if norm > self.error_bound {
                return false;
            }
        }
        true
    }

    /// Compute L2 norm of ring element
    fn compute_norm(&self, element: &RingElement) -> f64 {
        let coeffs = element.coefficients();
        let norm_squared: u128 = coeffs.iter()
            .map(|&c| (c as u128) * (c as u128))
            .sum();
        (norm_squared as f64).sqrt()
    }

    /// Relax instance with error term
    pub fn relax_instance<F: Field>(
        &self,
        instance: &ProtogaInstance<F>,
        error_vec: Vec<F>,
        error_commit: RingElement,
    ) -> Result<ProtogaInstance<F>> {
        // Check error bound
        if !self.check_error_bound(&[error_commit.clone()]) {
            return Err(ProtogaError::InvalidWitness(
                "Error exceeds bound".into()
            ));
        }

        Ok(ProtogaInstance::relaxed(
            instance.commitments.clone(),
            instance.public_inputs.clone(),
            instance.relaxation_factor,
            error_commit,
        ))
    }

    /// Update relaxation factor
    pub fn update_relaxation<F: Field>(
        &self,
        current: F,
        challenge: F,
    ) -> F {
        // u_new = u_old + r
        current.add(&challenge)
    }

    /// Accumulate error terms
    pub fn accumulate_errors<F: Field>(
        &self,
        error1: &[F],
        error2: &[F],
        challenge: &F,
    ) -> Vec<F> {
        let mut accumulated = Vec::new();
        
        for i in 0..error1.len() {
            let e1 = error1[i];
            let e2 = if i < error2.len() {
                error2[i]
            } else {
                F::zero()
            };
            
            // e = e1 + r * e2
            let acc = e1.add(&challenge.mul(&e2));
            accumulated.push(acc);
        }

        accumulated
    }

    /// Estimate total accumulated error
    pub fn estimate_accumulated_error(&self, rounds: usize) -> f64 {
        // Error grows with each folding round
        let per_round_error = self.params.gaussian_stddev;
        let total_error = per_round_error * (rounds as f64).sqrt();
        
        total_error
    }

    /// Check if system can handle more rounds
    pub fn can_handle_rounds(&self, current_rounds: usize, additional: usize) -> bool {
        let total_rounds = current_rounds + additional;
        let estimated_error = self.estimate_accumulated_error(total_rounds);
        
        estimated_error < self.error_bound
    }
}

/// Error witness for relaxed instances
#[derive(Clone, Debug)]
pub struct ErrorWitness<F: Field> {
    /// Error vector
    pub error_vector: Vec<F>,
    /// Randomness for error commitment
    pub error_randomness: Vec<RingElement>,
    /// Accumulated rounds
    pub rounds: usize,
}

impl<F: Field> ErrorWitness<F> {
    /// Create new error witness
    pub fn new(
        error_vector: Vec<F>,
        error_randomness: Vec<RingElement>,
    ) -> Self {
        Self {
            error_vector,
            error_randomness,
            rounds: 1,
        }
    }

    /// Accumulate with another error witness
    pub fn accumulate(
        &mut self,
        other: &Self,
        challenge: &F,
    ) {
        // Accumulate error vectors
        for i in 0..self.error_vector.len() {
            if i < other.error_vector.len() {
                let acc = self.error_vector[i]
                    .add(&challenge.mul(&other.error_vector[i]));
                self.error_vector[i] = acc;
            }
        }

        // Accumulate randomness
        for i in 0..self.error_randomness.len() {
            if i < other.error_randomness.len() {
                let r_scaled = other.error_randomness[i]
                    .scalar_mul(challenge.to_canonical_u64());
                self.error_randomness[i] = self.error_randomness[i]
                    .add(&r_scaled);
            }
        }

        self.rounds += other.rounds;
    }

    /// Check if within bounds
    pub fn is_within_bounds(&self, params: &LatticeParams) -> bool {
        let corrector = ErrorCorrector::new(params.clone());
        corrector.check_error_bound(&self.error_randomness)
    }
}

/// Relaxation manager for IVC
pub struct RelaxationManager {
    corrector: ErrorCorrector,
    max_relaxation: u64,
}

impl RelaxationManager {
    /// Create new relaxation manager
    pub fn new(params: LatticeParams, max_relaxation: u64) -> Self {
        Self {
            corrector: ErrorCorrector::new(params),
            max_relaxation,
        }
    }

    /// Check if relaxation is acceptable
    pub fn is_acceptable_relaxation<F: Field>(&self, factor: &F) -> bool {
        let canonical = factor.to_canonical_u64();
        canonical <= self.max_relaxation
    }

    /// Compute optimal relaxation for folding
    pub fn compute_optimal_relaxation<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
    ) -> F {
        // Find maximum relaxation factor among instances
        let mut max_factor = F::one();
        
        for instance in instances {
            if instance.relaxation_factor.to_canonical_u64() > 
               max_factor.to_canonical_u64() {
                max_factor = instance.relaxation_factor;
            }
        }

        max_factor
    }

    /// Merge relaxed instances
    pub fn merge_relaxed<F: Field>(
        &self,
        instances: &[ProtogaInstance<F>],
        challenges: &[F],
    ) -> Result<ProtogaInstance<F>> {
        if instances.is_empty() {
            return Err(ProtogaError::InvalidParameters(
                "Empty instance list".into()
            ));
        }

        if instances.len() != challenges.len() {
            return Err(ProtogaError::InvalidParameters(
                "Instance and challenge count mismatch".into()
            ));
        }

        // Merge using linear combination
        let mut merged_commitments = instances[0].commitments.clone();
        let mut merged_inputs = instances[0].public_inputs.clone();
        let mut merged_relaxation = instances[0].relaxation_factor;

        for i in 1..instances.len() {
            let challenge = challenges[i];
            
            // Merge commitments
            for j in 0..merged_commitments.len() {
                if j < instances[i].commitments.len() {
                    let scaled = instances[i].commitments[j]
                        .scalar_mul(challenge.to_canonical_u64());
                    merged_commitments[j] = merged_commitments[j].add(&scaled);
                }
            }

            // Merge inputs
            for j in 0..merged_inputs.len() {
                if j < instances[i].public_inputs.len() {
                    let scaled = challenge.mul(&instances[i].public_inputs[j]);
                    merged_inputs[j] = merged_inputs[j].add(&scaled);
                }
            }

            // Merge relaxation
            merged_relaxation = merged_relaxation
                .add(&challenge.mul(&instances[i].relaxation_factor));
        }

        Ok(ProtogaInstance {
            commitments: merged_commitments,
            public_inputs: merged_inputs,
            relaxation_factor: merged_relaxation,
            error_commitment: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_error_corrector() {
        let params = LatticeParams::new_128();
        let corrector = ErrorCorrector::new(params);

        assert!(corrector.error_bound > 0.0);
        assert!(corrector.can_handle_rounds(0, 3));
    }

    #[test]
    fn test_error_accumulation() {
        let params = LatticeParams::new_128();
        let corrector = ErrorCorrector::new(params);

        let error1 = vec![GoldilocksField::from(1u64)];
        let error2 = vec![GoldilocksField::from(2u64)];
        let challenge = GoldilocksField::from(3u64);

        let accumulated = corrector.accumulate_errors(&error1, &error2, &challenge);
        
        // e = 1 + 3 * 2 = 7
        assert_eq!(accumulated[0], GoldilocksField::from(7u64));
    }

    #[test]
    fn test_relaxation_manager() {
        let params = LatticeParams::new_128();
        let manager = RelaxationManager::new(params, 1000);

        let factor = GoldilocksField::from(500u64);
        assert!(manager.is_acceptable_relaxation(&factor));

        let too_large = GoldilocksField::from(2000u64);
        assert!(!manager.is_acceptable_relaxation(&too_large));
    }
}
