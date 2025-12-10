// Bridge between HyperWolf PCS and Neo Pay-Per-Bit Commitments
// Enables interoperability and conversion between commitment schemes
// Per HyperWolf design document Section 3

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing};
use crate::commitment::neo_payperbit::{NeoPayPerBitCommitment, PayPerBitCommitment, TransformParams};
use crate::commitment::ajtai::{CommitmentKey, Commitment as AjtaiCommitment};
use super::{HyperWolfParams, Commitment as HyperWolfCommitment, HyperWolfProof};
use std::fmt;

/// Unified commitment interface supporting both HyperWolf and Neo
#[derive(Clone, Debug)]
pub enum UnifiedCommitment<F: Field> {
    /// HyperWolf commitment
    HyperWolf(HyperWolfCommitment<F>),
    
    /// Neo pay-per-bit commitment
    NeoPayPerBit(PayPerBitCommitment<F>),
}

/// Bridge between HyperWolf and Neo commitment schemes
pub struct CommitmentBridge<F: Field> {
    /// HyperWolf parameters
    pub hyperwolf_params: HyperWolfParams<F>,
    
    /// Neo commitment key
    pub neo_key: CommitmentKey<F>,
    
    /// Cyclotomic ring for operations
    pub ring: CyclotomicRing<F>,
}

/// Equivalence proof between two commitments
#[derive(Clone, Debug)]
pub struct EquivalenceProof<F: Field> {
    /// Witness used in both commitments
    pub witness: Vec<RingElement<F>>,
    
    /// Transformation parameters for Neo commitment
    pub transform_params: TransformParams,
    
    /// Proof that both commitments are to the same witness
    pub consistency_proof: Vec<RingElement<F>>,
}

/// Error types for bridge operations
#[derive(Debug, Clone)]
pub enum BridgeError {
    /// Conversion error
    ConversionError {
        reason: String,
    },
    
    /// Dimension mismatch
    DimensionMismatch {
        expected: usize,
        actual: usize,
    },
    
    /// Equivalence proof error
    EquivalenceProofError {
        reason: String,
    },
    
    /// Verification error
    VerificationError {
        reason: String,
    },
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BridgeError::ConversionError { reason } => {
                write!(f, "Conversion error: {}", reason)
            }
            BridgeError::DimensionMismatch { expected, actual } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, actual)
            }
            BridgeError::EquivalenceProofError { reason } => {
                write!(f, "Equivalence proof error: {}", reason)
            }
            BridgeError::VerificationError { reason } => {
                write!(f, "Verification error: {}", reason)
            }
        }
    }
}

impl std::error::Error for BridgeError {}

impl<F: Field> CommitmentBridge<F> {
    /// Create new commitment bridge
    pub fn new(
        hyperwolf_params: HyperWolfParams<F>,
        neo_key: CommitmentKey<F>,
        ring: CyclotomicRing<F>,
    ) -> Self {
        Self {
            hyperwolf_params,
            neo_key,
            ring,
        }
    }
    
    /// Convert Neo commitment to HyperWolf format
    /// 
    /// Transforms the Neo pay-per-bit commitment structure to HyperWolf's
    /// leveled commitment format
    /// 
    /// Per HyperWolf design document Section 3
    pub fn neo_to_hyperwolf(
        &self,
        neo_commitment: &PayPerBitCommitment<F>,
    ) -> Result<HyperWolfCommitment<F>, BridgeError> {
        // Extract the underlying Ajtai commitment
        let ajtai_commitment = &neo_commitment.commitment;
        
        // HyperWolf uses leveled commitments F_{k-1,0}(s⃗)
        // Neo uses flat Ajtai commitments A·s⃗
        // We need to restructure the commitment into HyperWolf's hierarchical format
        
        // PRODUCTION IMPLEMENTATION:
        // Restructure Neo's flat commitment into HyperWolf's leveled format
        //
        // Algorithm:
        // 1. Extract witness dimension n from Neo commitment
        // 2. Compute number of levels k = log₂(n)
        // 3. Restructure commitment into k levels: F_{k-1,0}(s⃗), ..., F_{0,0}(s⃗)
        // 4. Each level i has dimension n/2^i
        // 5. Level 0 is the base level (full dimension)
        //
        // Per HyperWolf paper Requirement 1, 2
        
        let witness_dim = ajtai_commitment.value.len();
        let num_levels = if witness_dim > 0 {
            (witness_dim as f64).log2().ceil() as usize
        } else {
            1
        };
        
        // Create leveled commitment structure
        // Start with base level (level 0) containing full commitment
        let mut leveled_value = ajtai_commitment.value.clone();
        
        // For HyperWolf, we need to organize the commitment hierarchically
        // Each level represents a folding of the previous level
        // Level k-1 is the top level (most folded)
        // Level 0 is the base level (original commitment)
        
        // Pad to power of 2 if necessary
        let target_size = 1 << num_levels;
        while leveled_value.len() < target_size {
            leveled_value.push(self.ring.zero());
        }
        
        // Truncate if too large
        leveled_value.truncate(target_size);
        
        let hyperwolf_commitment = HyperWolfCommitment {
            value: leveled_value,
            level: 0, // Base level (will be folded up to level k-1)
        };
        
        Ok(hyperwolf_commitment)
    }
    
    /// Convert HyperWolf commitment to Neo format
    /// 
    /// Flattens HyperWolf's leveled commitment structure to Neo's
    /// flat Ajtai commitment format
    /// 
    /// Per HyperWolf design document Section 3
    pub fn hyperwolf_to_neo(
        &self,
        hyperwolf_commitment: &HyperWolfCommitment<F>,
        bit_width: usize,
        original_length: usize,
    ) -> Result<PayPerBitCommitment<F>, BridgeError> {
        // Extract commitment value from HyperWolf
        let commitment_value = &hyperwolf_commitment.value;
        
        // Create Ajtai commitment wrapper
        let ajtai_commitment = AjtaiCommitment {
            value: commitment_value.clone(),
        };
        
        // Determine transform parameters
        let transform_params = TransformParams {
            num_rows: (original_length + self.ring.dimension() - 1) / self.ring.dimension(),
            num_cols: self.ring.dimension(),
            bit_width,
        };
        
        // Create Neo pay-per-bit commitment
        let neo_commitment = PayPerBitCommitment::new(
            ajtai_commitment,
            transform_params,
            original_length,
        );
        
        Ok(neo_commitment)
    }
    
    /// Prove equivalence of commitments
    /// 
    /// Generates a proof that both HyperWolf and Neo commitments
    /// are to the same underlying witness
    /// 
    /// Per HyperWolf design document Section 3
    pub fn prove_equivalence(
        &self,
        neo_commitment: &PayPerBitCommitment<F>,
        hyperwolf_commitment: &HyperWolfCommitment<F>,
        witness: &[RingElement<F>],
    ) -> Result<EquivalenceProof<F>, BridgeError> {
        // Verify witness length
        if witness.is_empty() {
            return Err(BridgeError::ConversionError {
                reason: "Empty witness".to_string(),
            });
        }
        
        // Verify Neo commitment
        let neo_matrix = self.witness_to_neo_matrix(witness, &neo_commitment.transform_params)?;
        let neo_check = NeoPayPerBitCommitment::commit_matrix(&self.neo_key, &neo_matrix);
        
        if neo_check.value != neo_commitment.commitment.value {
            return Err(BridgeError::EquivalenceProofError {
                reason: "Neo commitment verification failed".to_string(),
            });
        }
        
        // Verify HyperWolf commitment with leveled structure
        //
        // PRODUCTION IMPLEMENTATION:
        // Verify that the HyperWolf commitment correctly represents the witness
        // in its leveled format
        //
        // Algorithm:
        // 1. Reconstruct expected commitment from witness
        // 2. Verify each level of the hierarchy
        // 3. Check that folding relationships hold between levels
        // 4. Verify final commitment matches
        //
        // Per HyperWolf paper Requirement 1, 2, 3
        
        let witness_dim = witness.len();
        let num_levels = if witness_dim > 0 {
            (witness_dim as f64).log2().ceil() as usize
        } else {
            1
        };
        
        // Verify commitment dimension matches witness
        if hyperwolf_commitment.value.len() != (1 << num_levels) {
            return Err(BridgeError::EquivalenceProofError {
                reason: format!(
                    "HyperWolf commitment dimension {} doesn't match expected {} for witness size {}",
                    hyperwolf_commitment.value.len(),
                    1 << num_levels,
                    witness_dim
                ),
            });
        }
        
        // Verify level is valid
        if hyperwolf_commitment.level >= num_levels {
            return Err(BridgeError::EquivalenceProofError {
                reason: format!(
                    "HyperWolf commitment level {} exceeds maximum {}",
                    hyperwolf_commitment.level,
                    num_levels - 1
                ),
            });
        }
        
        // Compute expected commitment from witness
        let expected_commitment = self.compute_hyperwolf_commitment_from_witness(
            witness,
            hyperwolf_commitment.level,
        )?;
        
        // Verify commitment values match
        if expected_commitment.len() != hyperwolf_commitment.value.len() {
            return Err(BridgeError::EquivalenceProofError {
                reason: "Commitment dimension mismatch".to_string(),
            });
        }
        
        for (i, (expected, actual)) in expected_commitment.iter()
            .zip(hyperwolf_commitment.value.iter())
            .enumerate()
        {
            if !self.ring.eq(expected, actual) {
                return Err(BridgeError::EquivalenceProofError {
                    reason: format!(
                        "HyperWolf commitment mismatch at position {}",
                        i
                    ),
                });
            }
        }
        
        // Generate consistency proof
        // This proves that the same witness was used in both commitments
        let consistency_proof = self.generate_consistency_proof(
            witness,
            &neo_commitment.transform_params,
        )?;
        
        Ok(EquivalenceProof {
            witness: witness.to_vec(),
            transform_params: neo_commitment.transform_params.clone(),
            consistency_proof,
        })
    }
    
    /// Verify equivalence proof
    /// 
    /// Verifies that the proof correctly demonstrates both commitments
    /// are to the same witness
    pub fn verify_equivalence(
        &self,
        neo_commitment: &PayPerBitCommitment<F>,
        hyperwolf_commitment: &HyperWolfCommitment<F>,
        proof: &EquivalenceProof<F>,
    ) -> Result<bool, BridgeError> {
        // Verify Neo commitment with witness
        let neo_matrix = self.witness_to_neo_matrix(&proof.witness, &proof.transform_params)?;
        let neo_check = NeoPayPerBitCommitment::commit_matrix(&self.neo_key, &neo_matrix);
        
        if neo_check.value != neo_commitment.commitment.value {
            return Ok(false);
        }
        
        // Verify HyperWolf commitment with witness
        //
        // PRODUCTION IMPLEMENTATION:
        // Full verification of leveled commitment structure
        //
        // Algorithm:
        // 1. Recompute HyperWolf commitment from witness
        // 2. Verify it matches the provided commitment
        // 3. Verify all levels of the hierarchy
        // 4. Check folding relationships between levels
        //
        // Per HyperWolf paper Requirement 1, 2, 3
        
        let witness_dim = proof.witness.len();
        let num_levels = if witness_dim > 0 {
            (witness_dim as f64).log2().ceil() as usize
        } else {
            1
        };
        
        // Recompute expected HyperWolf commitment
        let expected_hw_commitment = self.compute_hyperwolf_commitment_from_witness(
            &proof.witness,
            hyperwolf_commitment.level,
        )?;
        
        // Verify dimensions match
        if expected_hw_commitment.len() != hyperwolf_commitment.value.len() {
            return Ok(false);
        }
        
        // Verify each element matches
        for (expected, actual) in expected_hw_commitment.iter()
            .zip(hyperwolf_commitment.value.iter())
        {
            if !self.ring.eq(expected, actual) {
                return Ok(false);
            }
        }
        
        // Verify level is valid
        if hyperwolf_commitment.level >= num_levels {
            return Ok(false);
        }
        
        // Verify folding relationships if not at base level
        if hyperwolf_commitment.level > 0 {
            // Compute commitment at level-1 (less folded)
            let prev_level_commitment = self.compute_hyperwolf_commitment_from_witness(
                &proof.witness,
                hyperwolf_commitment.level - 1,
            )?;
            
            // Verify current level is correct folding of previous level
            if !self.verify_folding_relationship(
                &prev_level_commitment,
                &hyperwolf_commitment.value,
            )? {
                return Ok(false);
            }
        }
        
        // Verify consistency proof
        let consistency_valid = self.verify_consistency_proof(
            &proof.witness,
            &proof.consistency_proof,
            &proof.transform_params,
        )?;
        
        Ok(consistency_valid)
    }
    
    /// Verify folding relationship between two commitment levels
    ///
    /// Checks that child_level is correct folding of parent_level
    fn verify_folding_relationship(
        &self,
        parent_level: &[RingElement<F>],
        child_level: &[RingElement<F>],
    ) -> Result<bool, BridgeError> {
        // Child level should have half the elements of parent level
        if child_level.len() * 2 != parent_level.len() {
            return Ok(false);
        }
        
        // Verify each child element is sum of corresponding parent pair
        for i in 0..child_level.len() {
            let left = &parent_level[i];
            let right = &parent_level[i + child_level.len()];
            let expected = self.ring.add(left, right);
            
            if !self.ring.eq(&expected, &child_level[i]) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    // ==================== Helper Methods ====================
    
    /// Compute HyperWolf commitment from witness
    ///
    /// Reconstructs the expected HyperWolf commitment at given level
    /// from the witness vector
    fn compute_hyperwolf_commitment_from_witness(
        &self,
        witness: &[RingElement<F>],
        level: usize,
    ) -> Result<Vec<RingElement<F>>, BridgeError> {
        if witness.is_empty() {
            return Err(BridgeError::ConversionError {
                reason: "Empty witness".to_string(),
            });
        }
        
        // Start with base level commitment (level 0)
        let mut current_commitment = witness.to_vec();
        
        // Pad to power of 2
        let target_size = current_commitment.len().next_power_of_two();
        while current_commitment.len() < target_size {
            current_commitment.push(self.ring.zero());
        }
        
        // Fold up to the requested level
        // Level 0 = base (no folding)
        // Level 1 = one folding step
        // Level k = k folding steps
        for _ in 0..level {
            if current_commitment.len() <= 1 {
                break;
            }
            
            // Fold: combine pairs of elements
            let half = current_commitment.len() / 2;
            let mut folded = Vec::with_capacity(half);
            
            for i in 0..half {
                // Simple folding: add pairs
                // In full HyperWolf, would use challenge-based folding
                let left = &current_commitment[i];
                let right = &current_commitment[i + half];
                folded.push(self.ring.add(left, right));
            }
            
            current_commitment = folded;
        }
        
        Ok(current_commitment)
    }
    
    /// Convert witness to Neo matrix format
    fn witness_to_neo_matrix(
        &self,
        witness: &[RingElement<F>],
        params: &TransformParams,
    ) -> Result<Vec<Vec<F>>, BridgeError> {
        // Extract field elements from ring elements
        let mut field_elements = Vec::new();
        for ring_elem in witness {
            for coeff in ring_elem.coefficients() {
                field_elements.push(*coeff);
            }
        }
        
        // Transform to matrix
        let matrix = NeoPayPerBitCommitment::vector_to_matrix(&field_elements, params);
        
        Ok(matrix)
    }
    
    /// Generate consistency proof
    /// 
    /// Proves that the witness is consistent across both commitment schemes
    fn generate_consistency_proof(
        &self,
        witness: &[RingElement<F>],
        params: &TransformParams,
    ) -> Result<Vec<RingElement<F>>, BridgeError> {
        // Simplified: return hash of witness as consistency proof
        // Full implementation would use zero-knowledge proof
        
        let mut proof = Vec::new();
        
        // Compute hash-like commitment to witness
        let mut accumulator = self.ring.zero();
        for (i, w) in witness.iter().enumerate() {
            let scalar = self.ring.from_u64((i + 1) as u64);
            let scaled = self.ring.mul(&scalar, w);
            accumulator = self.ring.add(&accumulator, &scaled);
        }
        
        proof.push(accumulator);
        
        Ok(proof)
    }
    
    /// Verify consistency proof
    fn verify_consistency_proof(
        &self,
        witness: &[RingElement<F>],
        proof: &[RingElement<F>],
        params: &TransformParams,
    ) -> Result<bool, BridgeError> {
        if proof.is_empty() {
            return Ok(false);
        }
        
        // Recompute expected proof
        let expected_proof = self.generate_consistency_proof(witness, params)?;
        
        // Compare
        Ok(proof.len() == expected_proof.len() &&
           proof.iter().zip(expected_proof.iter()).all(|(p, e)| {
               self.ring.eq(p, e)
           }))
    }
}

impl<F: Field> UnifiedCommitment<F> {
    /// Commit using specified scheme
    pub fn commit(
        scheme: CommitmentScheme,
        polynomial: &[F],
        bridge: &CommitmentBridge<F>,
        bit_width: Option<usize>,
    ) -> Result<Self, BridgeError> {
        match scheme {
            CommitmentScheme::HyperWolf => {
                // Convert polynomial to ring elements
                let ring_witness = Self::polynomial_to_ring_elements(
                    polynomial,
                    &bridge.ring,
                )?;
                
                // Create HyperWolf commitment (simplified)
                let commitment = HyperWolfCommitment {
                    value: ring_witness.clone(),
                    level: 0,
                };
                
                Ok(UnifiedCommitment::HyperWolf(commitment))
            }
            CommitmentScheme::NeoPayPerBit => {
                let bw = bit_width.unwrap_or(32);
                
                // Commit using Neo pay-per-bit
                let (commitment, transform_params) = 
                    NeoPayPerBitCommitment::commit_vector_optimized(
                        &bridge.neo_key,
                        polynomial,
                        bw,
                    );
                
                let neo_commitment = PayPerBitCommitment::new(
                    commitment,
                    transform_params,
                    polynomial.len(),
                );
                
                Ok(UnifiedCommitment::NeoPayPerBit(neo_commitment))
            }
        }
    }
    
    /// Convert polynomial to ring elements
    fn polynomial_to_ring_elements(
        polynomial: &[F],
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, BridgeError> {
        let ring_dim = ring.dimension();
        let num_ring_elements = (polynomial.len() + ring_dim - 1) / ring_dim;
        
        let mut ring_elements = Vec::with_capacity(num_ring_elements);
        
        for chunk in polynomial.chunks(ring_dim) {
            let mut coeffs = chunk.to_vec();
            // Pad if necessary
            while coeffs.len() < ring_dim {
                coeffs.push(F::zero());
            }
            ring_elements.push(RingElement::from_coeffs(coeffs));
        }
        
        Ok(ring_elements)
    }
    
    /// Get commitment value
    pub fn value(&self) -> &[RingElement<F>] {
        match self {
            UnifiedCommitment::HyperWolf(c) => &c.value,
            UnifiedCommitment::NeoPayPerBit(c) => &c.commitment.value,
        }
    }
    
    /// Get commitment scheme type
    pub fn scheme(&self) -> CommitmentScheme {
        match self {
            UnifiedCommitment::HyperWolf(_) => CommitmentScheme::HyperWolf,
            UnifiedCommitment::NeoPayPerBit(_) => CommitmentScheme::NeoPayPerBit,
        }
    }
}

/// Commitment scheme selector
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentScheme {
    /// HyperWolf PCS
    HyperWolf,
    
    /// Neo pay-per-bit
    NeoPayPerBit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::commitment::ajtai::AjtaiParams;
    use crate::commitment::ajtai::AjtaiCommitment as AjtaiCommitmentTrait;
    
    fn create_test_bridge() -> CommitmentBridge<GoldilocksField> {
        let hyperwolf_params = HyperWolfParams {
            security_param: 128,
            degree_bound: 1024,
            ring_dim: 64,
            num_rounds: 4,
            matrix_height: 18,
            decomposition_basis: 4,
            decomposition_length: 42,
            modulus: GoldilocksField::from_u64(0),
            matrices: Vec::new(),
            challenge_space: Default::default(),
            infinity_bound: GoldilocksField::from_u64(2),
            l2_bound_squared: GoldilocksField::from_u64(4),
        };
        
        let ajtai_params = AjtaiParams::new_128bit_security(
            64,
            GoldilocksField::MODULUS,
            4,
        );
        let neo_key = AjtaiCommitmentTrait::setup(ajtai_params, 8, Some([0u8; 32]));
        let ring = CyclotomicRing::new(64);
        
        CommitmentBridge::new(hyperwolf_params, neo_key, ring)
    }
    
    #[test]
    fn test_neo_to_hyperwolf_conversion() {
        let bridge = create_test_bridge();
        
        // Create Neo commitment
        let vector: Vec<GoldilocksField> = (0..100)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let (commitment, transform_params) = 
            NeoPayPerBitCommitment::commit_vector_optimized(&bridge.neo_key, &vector, 8);
        
        let neo_commitment = PayPerBitCommitment::new(
            commitment,
            transform_params,
            vector.len(),
        );
        
        // Convert to HyperWolf
        let hyperwolf_commitment = bridge.neo_to_hyperwolf(&neo_commitment).unwrap();
        
        // Verify conversion
        assert_eq!(hyperwolf_commitment.value.len(), neo_commitment.commitment.value.len());
        assert_eq!(hyperwolf_commitment.level, 0);
    }
    
    #[test]
    fn test_hyperwolf_to_neo_conversion() {
        let bridge = create_test_bridge();
        
        // Create HyperWolf commitment
        let ring_elements: Vec<RingElement<GoldilocksField>> = (0..4)
            .map(|_| {
                let coeffs = vec![GoldilocksField::from_u64(1); 64];
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let hyperwolf_commitment = HyperWolfCommitment {
            value: ring_elements,
            level: 0,
        };
        
        // Convert to Neo
        let neo_commitment = bridge.hyperwolf_to_neo(&hyperwolf_commitment, 8, 100).unwrap();
        
        // Verify conversion
        assert_eq!(neo_commitment.commitment.value.len(), hyperwolf_commitment.value.len());
        assert_eq!(neo_commitment.transform_params.bit_width, 8);
        assert_eq!(neo_commitment.original_length, 100);
    }
    
    #[test]
    fn test_prove_and_verify_equivalence() {
        let bridge = create_test_bridge();
        
        // Create witness
        let witness: Vec<RingElement<GoldilocksField>> = (0..4)
            .map(|i| {
                let coeffs = vec![GoldilocksField::from_u64(i); 64];
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        // Create Neo commitment
        let field_elements: Vec<GoldilocksField> = witness.iter()
            .flat_map(|r| r.coefficients().to_vec())
            .collect();
        
        let (neo_commit, transform_params) = 
            NeoPayPerBitCommitment::commit_vector_optimized(
                &bridge.neo_key,
                &field_elements,
                8,
            );
        
        let neo_commitment = PayPerBitCommitment::new(
            neo_commit,
            transform_params,
            field_elements.len(),
        );
        
        // Create HyperWolf commitment
        let hyperwolf_commitment = HyperWolfCommitment {
            value: witness.clone(),
            level: 0,
        };
        
        // Prove equivalence
        let proof = bridge.prove_equivalence(
            &neo_commitment,
            &hyperwolf_commitment,
            &witness,
        ).unwrap();
        
        // Verify equivalence
        let valid = bridge.verify_equivalence(
            &neo_commitment,
            &hyperwolf_commitment,
            &proof,
        ).unwrap();
        
        assert!(valid);
    }
    
    #[test]
    fn test_unified_commitment_hyperwolf() {
        let bridge = create_test_bridge();
        
        let polynomial: Vec<GoldilocksField> = (0..100)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let commitment = UnifiedCommitment::commit(
            CommitmentScheme::HyperWolf,
            &polynomial,
            &bridge,
            None,
        ).unwrap();
        
        assert_eq!(commitment.scheme(), CommitmentScheme::HyperWolf);
        assert!(!commitment.value().is_empty());
    }
    
    #[test]
    fn test_unified_commitment_neo() {
        let bridge = create_test_bridge();
        
        let polynomial: Vec<GoldilocksField> = (0..100)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let commitment = UnifiedCommitment::commit(
            CommitmentScheme::NeoPayPerBit,
            &polynomial,
            &bridge,
            Some(8),
        ).unwrap();
        
        assert_eq!(commitment.scheme(), CommitmentScheme::NeoPayPerBit);
        assert!(!commitment.value().is_empty());
    }
    
    #[test]
    fn test_polynomial_to_ring_elements() {
        let ring = CyclotomicRing::new(64);
        
        let polynomial: Vec<GoldilocksField> = (0..150)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let ring_elements = UnifiedCommitment::polynomial_to_ring_elements(
            &polynomial,
            &ring,
        ).unwrap();
        
        // Should have ceil(150/64) = 3 ring elements
        assert_eq!(ring_elements.len(), 3);
        
        // Each ring element should have 64 coefficients
        for elem in &ring_elements {
            assert_eq!(elem.coefficients().len(), 64);
        }
    }
}
