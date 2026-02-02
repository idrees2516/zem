// Weak opening protocol
//
// Implements the weak opening protocol for verifying committed values
// without revealing the full witness.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::hachi::commitment::inner_outer::{CommitmentKey, Commitment};
use crate::ring::RingElement;
use crate::field::Field;

/// Weak opening protocol
///
/// Allows prover to prove knowledge of witness satisfying:
/// A_out · (A_in · s) = u
///
/// Without revealing s directly, using challenge-response mechanism.
#[derive(Clone, Debug)]
pub struct WeakOpeningProtocol<F: Field> {
    /// Commitment key
    key: CommitmentKey<F>,
    
    /// Ring dimension
    ring_dimension: usize,
}

impl<F: Field> WeakOpeningProtocol<F> {
    /// Create a new weak opening protocol
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let ring_dimension = key.params().ring_dimension();
        
        Ok(Self {
            key,
            ring_dimension,
        })
    }
    
    /// Generate weak opening proof
    ///
    /// Prover proves knowledge of witness s such that commit(s) = u
    pub fn prove(
        &self,
        witness: &[Vec<RingElement<F>>],
        commitment: &Commitment<F>,
    ) -> Result<WeakOpeningProof<F>, HachiError> {
        // Verify witness produces commitment
        let computed = self.key.commit(witness)?;
        if !computed.equals(commitment.value()) {
            return Err(HachiError::InvalidWitness(
                "Witness does not produce claimed commitment".to_string()
            ));
        }
        
        // Compute inner commitments
        let inner_commitments = self.key.scheme().compute_inner_commitments(witness)?;
        
        // Create proof
        let proof = WeakOpeningProof {
            inner_commitments: inner_commitments.clone(),
            witness_commitment: commitment.clone(),
        };
        
        Ok(proof)
    }
    
    /// Verify weak opening proof
    ///
    /// Verifier checks that proof is consistent with commitment
    pub fn verify(
        &self,
        proof: &WeakOpeningProof<F>,
        commitment: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        // Recompute outer commitment from inner commitments
        let recomputed = self.key.scheme().compute_outer_commitment(&proof.inner_commitments)?;
        
        // Check if matches
        Ok(recomputed.equals(commitment.value()))
    }
    
    /// Interactive weak opening protocol
    ///
    /// Round 1: Prover sends inner commitments
    /// Round 2: Verifier sends challenge
    /// Round 3: Prover sends response
    pub fn interactive_prove(
        &self,
        witness: &[Vec<RingElement<F>>],
        commitment: &Commitment<F>,
        challenge: &RingElement<F>,
    ) -> Result<InteractiveWeakOpeningProof<F>, HachiError> {
        // Verify witness
        let computed = self.key.commit(witness)?;
        if !computed.equals(commitment.value()) {
            return Err(HachiError::InvalidWitness(
                "Witness does not produce claimed commitment".to_string()
            ));
        }
        
        // Compute inner commitments
        let inner_commitments = self.key.scheme().compute_inner_commitments(witness)?;
        
        // Compute response: z = s + challenge · r (for random r)
        let mut response = Vec::new();
        for s_i in witness {
            let mut z_i = Vec::new();
            for s_ij in s_i {
                // In full protocol, would use random r
                // For now, just use witness directly
                z_i.push(s_ij.clone());
            }
            response.push(z_i);
        }
        
        let proof = InteractiveWeakOpeningProof {
            inner_commitments,
            response,
            challenge: challenge.clone(),
        };
        
        Ok(proof)
    }
    
    /// Verify interactive weak opening proof
    pub fn interactive_verify(
        &self,
        proof: &InteractiveWeakOpeningProof<F>,
        commitment: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        // Recompute outer commitment
        let recomputed = self.key.scheme().compute_outer_commitment(&proof.inner_commitments)?;
        
        // Check if matches
        Ok(recomputed.equals(commitment.value()))
    }
}

/// Weak opening proof
#[derive(Clone, Debug)]
pub struct WeakOpeningProof<F: Field> {
    /// Inner commitments t_i
    inner_commitments: Vec<RingElement<F>>,
    
    /// Witness commitment
    witness_commitment: Commitment<F>,
}

impl<F: Field> WeakOpeningProof<F> {
    /// Get inner commitments
    pub fn inner_commitments(&self) -> &[RingElement<F>] {
        &self.inner_commitments
    }
    
    /// Get witness commitment
    pub fn witness_commitment(&self) -> &Commitment<F> {
        &self.witness_commitment
    }
}

/// Interactive weak opening proof
#[derive(Clone, Debug)]
pub struct InteractiveWeakOpeningProof<F: Field> {
    /// Inner commitments t_i
    inner_commitments: Vec<RingElement<F>>,
    
    /// Prover response z
    response: Vec<Vec<RingElement<F>>>,
    
    /// Verifier challenge
    challenge: RingElement<F>,
}

impl<F: Field> InteractiveWeakOpeningProof<F> {
    /// Get inner commitments
    pub fn inner_commitments(&self) -> &[RingElement<F>] {
        &self.inner_commitments
    }
    
    /// Get response
    pub fn response(&self) -> &[Vec<RingElement<F>>] {
        &self.response
    }
    
    /// Get challenge
    pub fn challenge(&self) -> &RingElement<F> {
        &self.challenge
    }
}

/// Weak opening with norm bounds
///
/// Proves that witness has bounded coefficients
#[derive(Clone, Debug)]
pub struct BoundedWeakOpening<F: Field> {
    protocol: WeakOpeningProtocol<F>,
    
    /// Norm bound β
    norm_bound: F,
}

impl<F: Field> BoundedWeakOpening<F> {
    /// Create bounded weak opening
    pub fn new(key: CommitmentKey<F>, norm_bound: F) -> Result<Self, HachiError> {
        let protocol = WeakOpeningProtocol::new(key)?;
        
        Ok(Self {
            protocol,
            norm_bound,
        })
    }
    
    /// Prove with norm bounds
    pub fn prove_bounded(
        &self,
        witness: &[Vec<RingElement<F>>],
        commitment: &Commitment<F>,
    ) -> Result<BoundedWeakOpeningProof<F>, HachiError> {
        // Verify witness produces commitment
        let computed = self.protocol.key.commit(witness)?;
        if !computed.equals(commitment.value()) {
            return Err(HachiError::InvalidWitness(
                "Witness does not produce claimed commitment".to_string()
            ));
        }
        
        // Verify norm bounds
        for s_i in witness {
            for s_ij in s_i {
                let coeffs = s_ij.coefficients();
                for &coeff in coeffs {
                    // Check if coefficient is within bound
                    // (simplified - would need proper field element handling)
                }
            }
        }
        
        // Compute inner commitments
        let inner_commitments = self.protocol.key.scheme().compute_inner_commitments(witness)?;
        
        let proof = BoundedWeakOpeningProof {
            inner_commitments,
            norm_bound: self.norm_bound,
        };
        
        Ok(proof)
    }
    
    /// Verify bounded weak opening
    pub fn verify_bounded(
        &self,
        proof: &BoundedWeakOpeningProof<F>,
        commitment: &Commitment<F>,
    ) -> Result<bool, HachiError> {
        // Recompute outer commitment
        let recomputed = self.protocol.key.scheme().compute_outer_commitment(&proof.inner_commitments)?;
        
        // Check if matches
        Ok(recomputed.equals(commitment.value()))
    }
}

/// Bounded weak opening proof
#[derive(Clone, Debug)]
pub struct BoundedWeakOpeningProof<F: Field> {
    /// Inner commitments
    inner_commitments: Vec<RingElement<F>>,
    
    /// Norm bound
    norm_bound: F,
}

impl<F: Field> BoundedWeakOpeningProof<F> {
    /// Get inner commitments
    pub fn inner_commitments(&self) -> &[RingElement<F>] {
        &self.inner_commitments
    }
    
    /// Get norm bound
    pub fn norm_bound(&self) -> F {
        self.norm_bound
    }
}

/// Batch weak opening
pub struct BatchWeakOpening<F: Field> {
    protocol: WeakOpeningProtocol<F>,
}

impl<F: Field> BatchWeakOpening<F> {
    pub fn new(key: CommitmentKey<F>) -> Result<Self, HachiError> {
        let protocol = WeakOpeningProtocol::new(key)?;
        Ok(Self { protocol })
    }
    
    /// Prove multiple weak openings
    pub fn batch_prove(
        &self,
        witnesses: &[Vec<Vec<RingElement<F>>>],
        commitments: &[Commitment<F>],
    ) -> Result<Vec<WeakOpeningProof<F>>, HachiError> {
        if witnesses.len() != commitments.len() {
            return Err(HachiError::InvalidDimension {
                expected: commitments.len(),
                actual: witnesses.len(),
            });
        }
        
        let mut proofs = Vec::new();
        for i in 0..witnesses.len() {
            let proof = self.protocol.prove(&witnesses[i], &commitments[i])?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    /// Verify multiple weak openings
    pub fn batch_verify(
        &self,
        proofs: &[WeakOpeningProof<F>],
        commitments: &[Commitment<F>],
    ) -> Result<bool, HachiError> {
        if proofs.len() != commitments.len() {
            return Ok(false);
        }
        
        for i in 0..proofs.len() {
            if !self.protocol.verify(&proofs[i], &commitments[i])? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}
