// Batch verification for monomial sumcheck
//
// This module implements efficient batch verification techniques
// that allow verifying multiple sumcheck proofs simultaneously
// with reduced computational cost.
//
// # Paper Reference
// Section 4.5: "Batch Verification via Random Linear Combination"
//
// # Key Idea
// Instead of verifying k proofs separately (cost: k·C),
// verify their random linear combination (cost: C + k·overhead)
//
// # Security
// Soundness error increases by factor k, but remains negligible

use crate::field::Field;
use super::types::*;
use super::{MonomialSumcheckError, MonomialSumcheckConfig};
use super::verifier::MonomialSumcheckVerifier;
use std::marker::PhantomData;

/// Batch verification manager
///
/// Coordinates verification of multiple proofs using random linear combination
///
/// # Algorithm
///
/// Given proofs π₁,...,πₖ for claims v₁,...,vₖ:
/// 1. Sample random coefficients r₁,...,rₖ ← F
/// 2. Compute batched claim: V = ∑ᵢ rᵢ·vᵢ
/// 3. Compute batched round polynomials: Uⱼ(X) = ∑ᵢ rᵢ·uᵢ,ⱼ(X)
/// 4. Verify single sumcheck for (V, {Uⱼ})
///
/// # Complexity
/// - Individual: O(k·n·D²) field operations
/// - Batched: O(n·D² + k·n·D) field operations
/// - Savings: ~k× for large k
///
/// # Soundness
/// If any proof is invalid, batch verification fails with probability ≥ 1 - ε
/// where ε ≈ k·D·n/|F| (still negligible for cryptographic fields)
pub struct BatchVerificationManager<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Transcript for challenge generation
    transcript: Transcript,
    
    /// Random coefficients for batching
    batch_coefficients: Vec<F>,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: Field> BatchVerificationManager<F> {
    /// Create a new batch verification manager
    ///
    /// # Arguments
    /// * `config` - Configuration parameters
    /// * `num_instances` - Number of proofs to batch
    pub fn new(config: MonomialSumcheckConfig, num_instances: usize) -> Self {
        Self {
            config,
            transcript: Transcript::new(b"monomial-sumcheck-batch-v1.0"),
            batch_coefficients: Vec::with_capacity(num_instances),
            _phantom: PhantomData,
        }
    }
    
    /// Verify multiple proofs in batch
    ///
    /// # Arguments
    /// * `proofs` - Vector of proofs to verify
    /// * `claimed_sums` - Vector of claimed sums
    ///
    /// # Returns
    /// * `Ok(challenges)` - All proofs verified successfully
    /// * `Err(error)` - Batch verification failed
    ///
    /// # Security Note
    /// This provides soundness for the batch, not individual proofs.
    /// If verification passes, all proofs are correct with high probability.
    /// If verification fails, at least one proof is incorrect.
    pub fn verify_batch(
        &mut self,
        proofs: &[MonomialSumcheckProof<F>],
        claimed_sums: &[F],
    ) -> Result<Vec<F>, MonomialSumcheckError> {
        let num_instances = proofs.len();
        
        if claimed_sums.len() != num_instances {
            return Err(MonomialSumcheckError::EvaluationError {
                reason: format!(
                    "Proof/sum count mismatch: {} proofs, {} sums",
                    num_instances,
                    claimed_sums.len()
                ),
            });
        }
        
        // Sample random batch coefficients
        self.sample_batch_coefficients(num_instances)?;
        
        // Compute batched claimed sum: V = ∑ᵢ rᵢ·vᵢ
        let batched_sum = self.compute_batched_sum(claimed_sums);
        
        // Compute batched proof
        let batched_proof = self.compute_batched_proof(proofs)?;
        
        // Verify batched proof using standard verifier
        let mut verifier = MonomialSumcheckVerifier::new(self.config.clone());
        verifier.verify(&batched_proof, batched_sum)
    }
    
    /// Sample random coefficients for batching
    ///
    /// Uses Fiat-Shamir to generate coefficients deterministically
    /// from public data (for non-interactive proofs)
    ///
    /// # Security
    /// Coefficients must be unpredictable to malicious prover
    fn sample_batch_coefficients(
        &mut self,
        num_instances: usize,
    ) -> Result<(), MonomialSumcheckError> {
        self.batch_coefficients.clear();
        
        // Add context to transcript
        self.transcript.append_message(
            b"batch_size",
            &(num_instances as u64).to_le_bytes(),
        );
        
        // Sample coefficients
        for i in 0..num_instances {
            let coeff = self.transcript.challenge_field_element(
                format!("batch_coeff_{}", i).as_bytes()
            );
            self.batch_coefficients.push(coeff);
        }
        
        Ok(())
    }
    
    /// Compute batched sum: ∑ᵢ rᵢ·vᵢ
    fn compute_batched_sum(&self, sums: &[F]) -> F {
        self.batch_coefficients.iter()
            .zip(sums.iter())
            .map(|(r, v)| r.mul(v))
            .fold(F::zero(), |acc, x| acc.add(&x))
    }
    
    /// Compute batched proof
    ///
    /// For each round j, compute: Uⱼ(X) = ∑ᵢ rᵢ·uᵢ,ⱼ(X)
    ///
    /// # Complexity
    /// O(k·n·D) field operations
    fn compute_batched_proof(
        &self,
        proofs: &[MonomialSumcheckProof<F>],
    ) -> Result<MonomialSumcheckProof<F>, MonomialSumcheckError> {
        let num_rounds = self.config.num_vars;
        
        // Validate all proofs have correct structure
        for (i, proof) in proofs.iter().enumerate() {
            if proof.num_rounds() != num_rounds {
                return Err(MonomialSumcheckError::BatchVerificationFailed {
                    instance: i,
                    reason: format!(
                        "Invalid round count: expected {}, got {}",
                        num_rounds,
                        proof.num_rounds()
                    ),
                });
            }
        }
        
        // Compute batched round polynomials
        let mut batched_round_polys = Vec::with_capacity(num_rounds);
        
        for round in 0..num_rounds {
            let batched_poly = self.compute_batched_round_poly(proofs, round)?;
            batched_round_polys.push(batched_poly);
        }
        
        // Compute batched final evaluation
        let batched_final_eval = self.batch_coefficients.iter()
            .zip(proofs.iter())
            .map(|(r, p)| r.mul(&p.final_evaluation))
            .fold(F::zero(), |acc, x| acc.add(&x));
        
        Ok(MonomialSumcheckProof::new(
            batched_round_polys,
            batched_final_eval,
        ))
    }
    
    /// Compute batched round polynomial for a specific round
    ///
    /// Uⱼ(X) = ∑ᵢ rᵢ·uᵢ,ⱼ(X)
    fn compute_batched_round_poly(
        &self,
        proofs: &[MonomialSumcheckProof<F>],
        round: usize,
    ) -> Result<RoundPolynomial<F>, MonomialSumcheckError> {
        // Find maximum degree across all proofs for this round
        let max_degree = proofs.iter()
            .map(|p| p.round_polynomials[round].degree)
            .max()
            .unwrap_or(0);
        
        // Compute batched evaluations
        let mut batched_evals = vec![F::zero(); max_degree + 1];
        
        for (coeff, proof) in self.batch_coefficients.iter().zip(proofs.iter()) {
            let round_poly = &proof.round_polynomials[round];
            
            for (eval_point, batched_eval) in batched_evals.iter_mut().enumerate() {
                if eval_point < round_poly.evaluations.len() {
                    let contribution = coeff.mul(&round_poly.evaluations[eval_point]);
                    *batched_eval = batched_eval.add(&contribution);
                } else {
                    // Extrapolate if needed
                    let point = F::from_u64(eval_point as u64);
                    let eval = round_poly.evaluate(point);
                    let contribution = coeff.mul(&eval);
                    *batched_eval = batched_eval.add(&contribution);
                }
            }
        }
        
        Ok(RoundPolynomial::from_evaluations(batched_evals))
    }
}

/// Adaptive batching strategy
///
/// Dynamically adjusts batch size based on proof characteristics
/// to optimize verification cost
///
/// # Strategy
/// - Small proofs: Larger batches (more amortization)
/// - Large proofs: Smaller batches (less overhead)
/// - Different degrees: Separate into groups
pub struct AdaptiveBatchStrategy<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Maximum batch size
    max_batch_size: usize,
    
    /// Minimum batch size
    min_batch_size: usize,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> AdaptiveBatchStrategy<F> {
    /// Create a new adaptive strategy
    pub fn new(
        config: MonomialSumcheckConfig,
        min_batch_size: usize,
        max_batch_size: usize,
    ) -> Self {
        Self {
            config,
            max_batch_size,
            min_batch_size,
            _phantom: PhantomData,
        }
    }
    
    /// Determine optimal batch size for given proofs
    ///
    /// # Heuristics
    /// - Group proofs by degree
    /// - Larger degree → smaller batch
    /// - Balance verification cost vs. batching overhead
    pub fn compute_optimal_batch_size(&self, proofs: &[MonomialSumcheckProof<F>]) -> usize {
        if proofs.is_empty() {
            return self.min_batch_size;
        }
        
        // Compute average proof size
        let avg_size: usize = proofs.iter().map(|p| p.size()).sum::<usize>() / proofs.len();
        
        // Larger proofs → smaller batches
        let batch_size = if avg_size < 100 {
            self.max_batch_size
        } else if avg_size < 1000 {
            self.max_batch_size / 2
        } else {
            self.min_batch_size
        };
        
        batch_size.max(self.min_batch_size).min(self.max_batch_size)
    }
    
    /// Partition proofs into optimal batches
    ///
    /// # Returns
    /// Vector of batches, each with proofs and their claimed sums
    pub fn partition_into_batches<'a>(
        &self,
        proofs: &'a [MonomialSumcheckProof<F>],
        claimed_sums: &'a [F],
    ) -> Vec<(&'a [MonomialSumcheckProof<F>], &'a [F])> {
        let batch_size = self.compute_optimal_batch_size(proofs);
        
        proofs.chunks(batch_size)
            .zip(claimed_sums.chunks(batch_size))
            .collect()
    }
}

/// Incremental batch verification
///
/// Allows adding proofs incrementally and verifying in batches
/// when threshold is reached
///
/// # Use Case
/// Streaming verification where proofs arrive over time
pub struct IncrementalBatchVerifier<F: Field> {
    /// Configuration
    config: MonomialSumcheckConfig,
    
    /// Accumulated proofs
    pending_proofs: Vec<MonomialSumcheckProof<F>>,
    
    /// Corresponding claimed sums
    pending_sums: Vec<F>,
    
    /// Batch threshold
    batch_threshold: usize,
    
    /// Verification statistics
    total_verified: usize,
    total_batches: usize,
}

impl<F: Field> IncrementalBatchVerifier<F> {
    /// Create a new incremental verifier
    ///
    /// # Arguments
    /// * `config` - Configuration parameters
    /// * `batch_threshold` - Verify when this many proofs accumulated
    pub fn new(config: MonomialSumcheckConfig, batch_threshold: usize) -> Self {
        Self {
            config,
            pending_proofs: Vec::new(),
            pending_sums: Vec::new(),
            batch_threshold,
            total_verified: 0,
            total_batches: 0,
        }
    }
    
    /// Add a proof to the pending batch
    ///
    /// If threshold reached, automatically triggers batch verification
    ///
    /// # Returns
    /// * `Ok(None)` - Proof added, threshold not reached
    /// * `Ok(Some(challenges))` - Batch verified successfully
    /// * `Err(error)` - Batch verification failed
    pub fn add_proof(
        &mut self,
        proof: MonomialSumcheckProof<F>,
        claimed_sum: F,
    ) -> Result<Option<Vec<F>>, MonomialSumcheckError> {
        self.pending_proofs.push(proof);
        self.pending_sums.push(claimed_sum);
        
        if self.pending_proofs.len() >= self.batch_threshold {
            self.flush()
        } else {
            Ok(None)
        }
    }
    
    /// Force verification of pending proofs
    ///
    /// # Returns
    /// * `Ok(Some(challenges))` - Batch verified
    /// * `Ok(None)` - No pending proofs
    /// * `Err(error)` - Verification failed
    pub fn flush(&mut self) -> Result<Option<Vec<F>>, MonomialSumcheckError> {
        if self.pending_proofs.is_empty() {
            return Ok(None);
        }
        
        // Verify batch
        let mut manager = BatchVerificationManager::new(
            self.config.clone(),
            self.pending_proofs.len(),
        );
        
        let challenges = manager.verify_batch(&self.pending_proofs, &self.pending_sums)?;
        
        // Update statistics
        self.total_verified += self.pending_proofs.len();
        self.total_batches += 1;
        
        // Clear pending
        self.pending_proofs.clear();
        self.pending_sums.clear();
        
        Ok(Some(challenges))
    }
    
    /// Get verification statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.total_verified, self.total_batches, self.pending_proofs.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::MockField;
    use super::super::prover::MonomialSumcheckProver;
    use super::super::polynomial::MonomialVirtualPolynomial;
    use std::sync::Arc;
    
    #[test]
    fn test_batch_verification() {
        let config = MonomialSumcheckConfig {
            num_vars: 2,
            max_degree: 1,
            ..Default::default()
        };
        
        // Create multiple proofs
        let mut proofs = Vec::new();
        let mut sums = Vec::new();
        
        for _ in 0..3 {
            // Create simple polynomial
            let coeffs = vec![
                MockField::zero(),
                MockField::one(),
                MockField::one(),
                MockField::zero(),
            ];
            let poly = Arc::new(
                super::super::types::MonomialPolynomial::new(coeffs, vec![1, 1]).unwrap()
            );
            
            let mut prover = MonomialSumcheckProver::new(
                poly.clone() as Arc<dyn MonomialVirtualPolynomial<MockField>>,
                config.clone(),
            );
            
            let sum = MockField::from(2);
            let proof = prover.prove(sum).unwrap();
            
            proofs.push(proof);
            sums.push(sum);
        }
        
        // Batch verify
        let mut manager = BatchVerificationManager::new(config, 3);
        let result = manager.verify_batch(&proofs, &sums);
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_incremental_verifier() {
        let config = MonomialSumcheckConfig {
            num_vars: 2,
            max_degree: 1,
            ..Default::default()
        };
        
        let mut verifier = IncrementalBatchVerifier::new(config.clone(), 2);
        
        // Add first proof - should not verify yet
        let coeffs = vec![MockField::zero(), MockField::one(), MockField::one(), MockField::zero()];
        let poly = Arc::new(
            super::super::types::MonomialPolynomial::new(coeffs.clone(), vec![1, 1]).unwrap()
        );
        let mut prover = MonomialSumcheckProver::new(
            poly as Arc<dyn MonomialVirtualPolynomial<MockField>>,
            config.clone(),
        );
        let proof1 = prover.prove(MockField::from(2)).unwrap();
        
        let result1 = verifier.add_proof(proof1, MockField::from(2)).unwrap();
        assert!(result1.is_none()); // Threshold not reached
        
        // Add second proof - should trigger batch verification
        let poly2 = Arc::new(
            super::super::types::MonomialPolynomial::new(coeffs, vec![1, 1]).unwrap()
        );
        let mut prover2 = MonomialSumcheckProver::new(
            poly2 as Arc<dyn MonomialVirtualPolynomial<MockField>>,
            config,
        );
        let proof2 = prover2.prove(MockField::from(2)).unwrap();
        
        let result2 = verifier.add_proof(proof2, MockField::from(2)).unwrap();
        assert!(result2.is_some()); // Batch verified
        
        // Check statistics
        let (verified, batches, pending) = verifier.stats();
        assert_eq!(verified, 2);
        assert_eq!(batches, 1);
        assert_eq!(pending, 0);
    }
}
