// Lattice-based commitment scheme for ProtogaLattice
//
// Implements:
// - Ajtai-style lattice commitments
// - Binding under Module-SIS
// - Hiding through discrete Gaussian sampling
// - Efficient opening and verification

use crate::field::Field;
use crate::ring::RingElement;
use crate::protogalattice::{
    lattice_params::LatticeParams,
    types::OpeningProof,
    Result,
};
use crate::errors::ProtogaError;
use rand::{Rng, RngCore};
use sha3::{Sha3_256, Digest};

/// Commitment key for lattice-based commitments
#[derive(Clone, Debug)]
pub struct ProtogaCommitmentKey {
    /// Public matrices defining the commitment
    pub public_matrices: Vec<Vec<RingElement>>,
    /// Lattice parameters
    pub params: LatticeParams,
    /// Binding key (for verification)
    pub binding_key: Vec<RingElement>,
}

/// Opening of a commitment
#[derive(Clone, Debug)]
pub struct CommitmentOpening {
    /// Committed message
    pub message: Vec<RingElement>,
    /// Randomness used in commitment
    pub randomness: Vec<RingElement>,
}

/// Lattice commitment value
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeCommitment {
    /// Commitment value as ring element
    pub value: RingElement,
    /// Auxiliary information for verification
    pub hint: Option<Vec<u8>>,
}

/// Commitment scheme trait
pub trait CommitmentScheme<F: Field> {
    /// Generate commitment key
    fn setup(params: &LatticeParams, rng: &mut impl RngCore) -> Result<ProtogaCommitmentKey>;
    
    /// Commit to message with randomness
    fn commit(
        key: &ProtogaCommitmentKey,
        message: &[F],
        randomness: &[RingElement],
    ) -> Result<LatticeCommitment>;
    
    /// Open commitment
    fn open(
        key: &ProtogaCommitmentKey,
        commitment: &LatticeCommitment,
        opening: &CommitmentOpening,
    ) -> Result<bool>;
    
    /// Verify opening without revealing message
    fn verify_opening(
        key: &ProtogaCommitmentKey,
        commitment: &LatticeCommitment,
        proof: &OpeningProof<F>,
    ) -> Result<bool>;
}

/// ProtogaLattice commitment implementation
pub struct ProtogaCommitment;

impl<F: Field> CommitmentScheme<F> for ProtogaCommitment {
    fn setup(params: &LatticeParams, rng: &mut impl RngCore) -> Result<ProtogaCommitmentKey> {
        params.validate()
            .map_err(|e| ProtogaError::InvalidParameters(e.to_string()))?;

        let n = params.ring_dimension;
        let k = params.module_rank;
        
        // Generate public matrices A_i for i = 1..k
        let mut public_matrices = Vec::with_capacity(k);
        
        for _ in 0..k {
            let mut matrix_row = Vec::with_capacity(k + 1);
            for _ in 0..=k {
                // Sample uniformly random ring element
                let ring_elem = RingElement::random(n, params.modulus, rng);
                matrix_row.push(ring_elem);
            }
            public_matrices.push(matrix_row);
        }

        // Generate binding key (trapdoor basis - not stored in production)
        let binding_key = (0..k)
            .map(|_| RingElement::random(n, params.modulus, rng))
            .collect();

        Ok(ProtogaCommitmentKey {
            public_matrices,
            params: params.clone(),
            binding_key,
        })
    }

    fn commit(
        key: &ProtogaCommitmentKey,
        message: &[F],
        randomness: &[RingElement],
    ) -> Result<LatticeCommitment> {
        let k = key.params.module_rank;
        
        if randomness.len() != k {
            return Err(ProtogaError::InvalidParameters(
                format!("Expected {} randomness elements, got {}", k, randomness.len())
            ));
        }

        // Convert message to ring elements
        let message_ring = Self::field_to_ring(message, &key.params)?;

        // Compute commitment: c = A * r + G * m
        let mut commitment_value = RingElement::zero(key.params.ring_dimension);

        for i in 0..k {
            // A_i * r_i
            let a_times_r = key.public_matrices[i]
                .iter()
                .zip(randomness.iter())
                .map(|(a, r)| a.mul(r))
                .fold(
                    RingElement::zero(key.params.ring_dimension),
                    |acc, x| acc.add(&x)
                );
            
            commitment_value = commitment_value.add(&a_times_r);
        }

        // Add gadget encoding of message
        let gadget_encoded = Self::gadget_encode(&message_ring, &key.params);
        for (i, encoded) in gadget_encoded.iter().enumerate() {
            if i < k {
                let scaled = key.public_matrices[i][k].mul(encoded);
                commitment_value = commitment_value.add(&scaled);
            }
        }

        // Reduce modulo q
        commitment_value = commitment_value.reduce_modulo(key.params.modulus);

        Ok(LatticeCommitment {
            value: commitment_value,
            hint: None,
        })
    }

    fn open(
        key: &ProtogaCommitmentKey,
        commitment: &LatticeCommitment,
        opening: &CommitmentOpening,
    ) -> Result<bool> {
        // Recompute commitment from opening
        let message_field = Self::ring_to_field(&opening.message)?;
        let recomputed = Self::commit(key, &message_field, &opening.randomness)?;

        Ok(recomputed.value == commitment.value)
    }

    fn verify_opening(
        key: &ProtogaCommitmentKey,
        commitment: &LatticeCommitment,
        proof: &OpeningProof<F>,
    ) -> Result<bool> {
        // Verify opening proof without full opening
        // Uses homomorphic properties of lattice commitments
        
        // Convert proof values to ring elements
        let proof_ring = Self::field_to_ring(&proof.value, &key.params)?;
        
        // Verify proof elements are within bounds
        for elem in &proof.proof {
            if !Self::check_norm_bound(elem, key.params.sis_beta) {
                return Ok(false);
            }
        }

        // Verify commitment equation
        let mut lhs = commitment.value.clone();
        for (i, proof_elem) in proof.proof.iter().enumerate() {
            if i < key.params.module_rank {
                let term = key.public_matrices[i][0].mul(proof_elem);
                lhs = lhs.sub(&term);
            }
        }

        // Check if result matches expected encoding
        let expected = Self::gadget_encode(&proof_ring, &key.params);
        let matches = expected.iter().enumerate().all(|(i, exp)| {
            if i < key.params.module_rank {
                let scaled = key.public_matrices[i][key.params.module_rank].mul(exp);
                scaled == lhs
            } else {
                true
            }
        });

        Ok(matches)
    }
}

impl ProtogaCommitment {
    /// Convert field elements to ring elements
    fn field_to_ring<F: Field>(
        values: &[F],
        params: &LatticeParams,
    ) -> Result<Vec<RingElement>> {
        let mut result = Vec::with_capacity(values.len());
        
        for value in values {
            let coeffs = Self::field_to_coefficients(value, params.ring_dimension);
            let ring_elem = RingElement::from_coefficients(coeffs, params.modulus);
            result.push(ring_elem);
        }
        
        Ok(result)
    }

    /// Convert ring elements to field elements
    fn ring_to_field<F: Field>(elements: &[RingElement]) -> Result<Vec<F>> {
        let mut result = Vec::with_capacity(elements.len());
        
        for elem in elements {
            let coeffs = elem.coefficients();
            let field_val = Self::coefficients_to_field(&coeffs)?;
            result.push(field_val);
        }
        
        Ok(result)
    }

    /// Convert field element to polynomial coefficients
    fn field_to_coefficients<F: Field>(value: &F, degree: usize) -> Vec<u64> {
        // Convert field element to bytes
        let bytes = value.to_bytes();
        
        // Distribute bytes across coefficients
        let mut coeffs = vec![0u64; degree];
        for (i, &byte) in bytes.iter().enumerate() {
            if i < degree {
                coeffs[i] = byte as u64;
            } else {
                coeffs[i % degree] ^= (byte as u64) << 8;
            }
        }
        
        coeffs
    }

    /// Convert polynomial coefficients to field element
    fn coefficients_to_field<F: Field>(coeffs: &[u64]) -> Result<F> {
        // Hash coefficients to get field element
        let mut hasher = Sha3_256::new();
        for &coeff in coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
        let hash = hasher.finalize();
        
        F::from_bytes(&hash[..])
            .ok_or_else(|| ProtogaError::InvalidParameters("Failed to convert to field".into()))
    }

    /// Gadget encoding of ring elements
    fn gadget_encode(
        elements: &[RingElement],
        params: &LatticeParams,
    ) -> Vec<RingElement> {
        let base = params.gadget_base as u64;
        let digits = params.gadget_digits;
        let mut result = Vec::new();

        for elem in elements {
            // Decompose element into base-b digits
            let coeffs = elem.coefficients();
            for digit_idx in 0..digits {
                let mut digit_coeffs = Vec::with_capacity(coeffs.len());
                
                for &coeff in coeffs {
                    let digit = (coeff / base.pow(digit_idx as u32)) % base;
                    digit_coeffs.push(digit);
                }
                
                result.push(RingElement::from_coefficients(
                    digit_coeffs,
                    params.modulus,
                ));
            }
        }

        result
    }

    /// Check if ring element norm is within bound
    fn check_norm_bound(elem: &RingElement, bound: f64) -> bool {
        let coeffs = elem.coefficients();
        let norm_squared: u128 = coeffs.iter()
            .map(|&c| (c as u128) * (c as u128))
            .sum();
        
        let norm = (norm_squared as f64).sqrt();
        norm <= bound
    }

    /// Sample discrete Gaussian for randomness
    pub fn sample_randomness(
        params: &LatticeParams,
        rng: &mut impl RngCore,
    ) -> Vec<RingElement> {
        let k = params.module_rank;
        let n = params.ring_dimension;
        let stddev = params.gaussian_stddev;

        (0..k)
            .map(|_| Self::sample_gaussian_ring_element(n, stddev, params.modulus, rng))
            .collect()
    }

    /// Sample single Gaussian ring element
    fn sample_gaussian_ring_element(
        degree: usize,
        stddev: f64,
        modulus: u64,
        rng: &mut impl RngCore,
    ) -> RingElement {
        let coeffs: Vec<u64> = (0..degree)
            .map(|_| {
                let sample = Self::sample_discrete_gaussian(stddev, rng);
                ((sample + modulus as i64) as u64) % modulus
            })
            .collect();

        RingElement::from_coefficients(coeffs, modulus)
    }

    /// Sample from discrete Gaussian distribution
    fn sample_discrete_gaussian(stddev: f64, rng: &mut impl RngCore) -> i64 {
        // Box-Muller transform for continuous Gaussian
        let u1: f64 = rng.gen();
        let u2: f64 = rng.gen();
        
        let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample = z0 * stddev;
        
        // Round to nearest integer
        sample.round() as i64
    }

    /// Batch commit to multiple messages
    pub fn batch_commit<F: Field>(
        key: &ProtogaCommitmentKey,
        messages: &[Vec<F>],
        randomness: &[Vec<RingElement>],
    ) -> Result<Vec<LatticeCommitment>> {
        if messages.len() != randomness.len() {
            return Err(ProtogaError::InvalidParameters(
                "Messages and randomness count mismatch".into()
            ));
        }

        messages.iter()
            .zip(randomness.iter())
            .map(|(msg, rand)| Self::commit(key, msg, rand))
            .collect()
    }

    /// Homomorphic addition of commitments
    pub fn add_commitments(
        c1: &LatticeCommitment,
        c2: &LatticeCommitment,
    ) -> LatticeCommitment {
        LatticeCommitment {
            value: c1.value.add(&c2.value),
            hint: None,
        }
    }

    /// Homomorphic scalar multiplication
    pub fn scalar_mul<F: Field>(
        commitment: &LatticeCommitment,
        scalar: &F,
        params: &LatticeParams,
    ) -> Result<LatticeCommitment> {
        let scalar_ring = Self::field_to_ring(&[*scalar], params)?;
        let result = commitment.value.mul(&scalar_ring[0]);
        
        Ok(LatticeCommitment {
            value: result,
            hint: None,
        })
    }
}

/// Batch commitment operations
pub struct BatchCommitment;

impl BatchCommitment {
    /// Commit to vector of messages efficiently
    pub fn commit_vector<F: Field>(
        key: &ProtogaCommitmentKey,
        messages: &[F],
        randomness: &[RingElement],
    ) -> Result<LatticeCommitment> {
        ProtogaCommitment::commit(key, messages, randomness)
    }

    /// Aggregate multiple commitments
    pub fn aggregate(
        commitments: &[LatticeCommitment],
        weights: &[RingElement],
    ) -> Result<LatticeCommitment> {
        if commitments.len() != weights.len() {
            return Err(ProtogaError::InvalidParameters(
                "Commitments and weights count mismatch".into()
            ));
        }

        let mut result = commitments[0].value.clone();
        for (commitment, weight) in commitments.iter().skip(1).zip(weights.iter().skip(1)) {
            let weighted = commitment.value.mul(weight);
            result = result.add(&weighted);
        }

        Ok(LatticeCommitment {
            value: result,
            hint: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use rand::thread_rng;

    #[test]
    fn test_commitment_basic() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let key = ProtogaCommitment::setup(&params, &mut rng).unwrap();

        let message = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
        ];
        let randomness = ProtogaCommitment::sample_randomness(&params, &mut rng);

        let commitment = ProtogaCommitment::commit(&key, &message, &randomness).unwrap();
        assert!(commitment.value.coefficients().len() == params.ring_dimension);
    }

    #[test]
    fn test_commitment_opening() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let key = ProtogaCommitment::setup(&params, &mut rng).unwrap();

        let message = vec![GoldilocksField::from(42u64)];
        let randomness = ProtogaCommitment::sample_randomness(&params, &mut rng);

        let commitment = ProtogaCommitment::commit(&key, &message, &randomness).unwrap();
        
        let message_ring = ProtogaCommitment::field_to_ring(&message, &params).unwrap();
        let opening = CommitmentOpening {
            message: message_ring,
            randomness,
        };

        let valid = ProtogaCommitment::open(&key, &commitment, &opening).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut rng = thread_rng();
        let params = LatticeParams::new_128();
        let key = ProtogaCommitment::setup(&params, &mut rng).unwrap();

        let m1 = vec![GoldilocksField::from(10u64)];
        let m2 = vec![GoldilocksField::from(20u64)];
        
        let r1 = ProtogaCommitment::sample_randomness(&params, &mut rng);
        let r2 = ProtogaCommitment::sample_randomness(&params, &mut rng);

        let c1 = ProtogaCommitment::commit(&key, &m1, &r1).unwrap();
        let c2 = ProtogaCommitment::commit(&key, &m2, &r2).unwrap();

        let c_sum = ProtogaCommitment::add_commitments(&c1, &c2);

        // Verify homomorphism
        let m_sum = vec![m1[0].add(&m2[0])];
        let r_sum: Vec<_> = r1.iter().zip(&r2).map(|(a, b)| a.add(b)).collect();
        
        let c_expected = ProtogaCommitment::commit(&key, &m_sum, &r_sum).unwrap();
        assert_eq!(c_sum.value, c_expected.value);
    }
}
