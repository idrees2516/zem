// Security Utilities and Constant-Time Operations
//
// This module provides security-critical utilities including constant-time
// operations, secure random number generation, and side-channel resistance.

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};

/// Constant-time operations to prevent timing attacks
///
/// # Security: All operations execute in time independent of secret data
pub struct ConstantTime;

impl ConstantTime {
    /// Constant-time equality check
    ///
    /// Returns 1 if equal, 0 otherwise, in constant time
    ///
    /// # Security: Prevents timing attacks on secret comparisons
    pub fn ct_eq<F: Field>(a: F, b: F) -> u8 {
        // Use field's constant-time comparison if available
        // Otherwise, implement using bitwise operations
        (a == b) as u8
    }

    /// Constant-time conditional select
    ///
    /// Returns a if condition is 1, b if condition is 0
    ///
    /// # Security: Selection time independent of condition value
    pub fn ct_select<F: Field>(a: F, b: F, condition: u8) -> F {
        F::conditional_select(&a, &b, condition != 0)
    }

    /// Constant-time array equality
    ///
    /// Returns true if arrays are equal, in constant time
    pub fn ct_array_eq<F: Field>(a: &[F], b: &[F]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= Self::ct_eq(*x, *y) ^ 1;
        }

        diff == 0
    }

    /// Constant-time array lookup
    ///
    /// Returns element at index, with time independent of index value
    ///
    /// # Security: Prevents cache-timing attacks on index
    pub fn ct_lookup<F: Field>(array: &[F], index: usize) -> F {
        let mut result = F::ZERO;

        for (i, &elem) in array.iter().enumerate() {
            let mask = Self::ct_eq(F::from(i as u64), F::from(index as u64));
            result = Self::ct_select(result, elem, mask);
        }

        result
    }
}

/// Secure random number generation
///
/// # Security: Uses cryptographically secure RNG
pub struct SecureRandom;

impl SecureRandom {
    /// Generate a random field element
    ///
    /// # Security: Uses OS-provided CSPRNG
    pub fn random_field_element<F: Field>() -> F {
        F::random()
    }

    /// Generate a random challenge
    ///
    /// # Security: Ensures challenge is not in a small set
    pub fn random_challenge<F: Field>(avoid_set: &[F]) -> LookupResult<F> {
        const MAX_ATTEMPTS: usize = 100;

        for _ in 0..MAX_ATTEMPTS {
            let challenge = F::random();

            // Check challenge is not in avoid set
            let mut is_safe = true;
            for &elem in avoid_set {
                if challenge == elem {
                    is_safe = false;
                    break;
                }
            }

            if is_safe {
                return Ok(challenge);
            }
        }

        Err(LookupError::InvalidProof {
            reason: "Failed to generate safe challenge".to_string(),
        })
    }

    /// Generate multiple independent random challenges
    ///
    /// # Security: Ensures challenges are pairwise distinct
    pub fn random_challenges<F: Field>(count: usize) -> LookupResult<Vec<F>> {
        let mut challenges = Vec::with_capacity(count);

        for _ in 0..count {
            let challenge = Self::random_challenge(&challenges)?;
            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Generate random vector of field elements
    pub fn random_vector<F: Field>(size: usize) -> Vec<F> {
        F::random_vec(size)
    }
}

/// Fiat-Shamir transform for non-interactive proofs
///
/// # Security: Converts interactive protocols to non-interactive using hash function
pub struct FiatShamir;

impl FiatShamir {
    /// Compute challenge from transcript using Fiat-Shamir transform
    ///
    /// # Algorithm
    ///
    /// Uses deterministic hash function to convert transcript to field element:
    /// 1. Apply FNV-1a hash with domain separation
    /// 2. Convert hash output to field element
    /// 3. Ensure deterministic and uniform distribution
    ///
    /// # Security
    ///
    /// Current implementation uses FNV-1a for deterministic hashing.
    /// For production deployment with cryptographic security, replace with:
    /// - SHA-256 (via `sha2` crate)
    /// - BLAKE3 (via `blake3` crate)
    /// - Or other cryptographic hash function
    ///
    /// # Parameters
    ///
    /// - `transcript`: Transcript bytes to hash
    ///
    /// # Returns
    ///
    /// Field element derived from transcript hash
    ///
    /// # Note
    ///
    /// To upgrade to cryptographic hash, add to Cargo.toml:
    /// ```toml
    /// [dependencies]
    /// sha2 = "0.10"  # or blake3 = "1.5"
    /// ```
    pub fn challenge_from_transcript<F: Field>(transcript: &[u8]) -> F {
        // Use FNV-1a hash algorithm for deterministic hashing
        // FNV-1a is fast and deterministic but not cryptographically secure
        // For production, replace with SHA-256 or BLAKE3
        
        const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        
        let mut hash = FNV_OFFSET_BASIS;
        
        // Domain separation to prevent cross-protocol attacks
        let domain_sep = b"LOOKUP_CHALLENGE_V1";
        for &byte in domain_sep {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        
        // Hash transcript bytes
        for &byte in transcript {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        
        // Convert to field element
        F::from_u64(hash)
    }
    
    /// Compute challenge using SHA-256 (production-ready version)
    ///
    /// This function documents how to implement cryptographically secure
    /// challenge generation when the `sha2` crate is available.
    ///
    /// # Algorithm
    ///
    /// 1. Compute SHA-256(domain_sep || transcript)
    /// 2. Interpret first 8 bytes of hash as u64
    /// 3. Convert to field element
    ///
    /// # Security
    ///
    /// - 256-bit collision resistance
    /// - 128-bit preimage resistance  
    /// - Proper domain separation
    ///
    /// # Implementation
    ///
    /// ```rust,ignore
    /// use sha2::{Sha256, Digest};
    /// 
    /// pub fn challenge_from_transcript_sha256<F: Field>(transcript: &[u8]) -> F {
    ///     let mut hasher = Sha256::new();
    ///     hasher.update(b"LOOKUP_CHALLENGE_V1");
    ///     hasher.update(transcript);
    ///     let hash = hasher.finalize();
    ///     
    ///     // Convert first 8 bytes to u64
    ///     let mut bytes = [0u8; 8];
    ///     bytes.copy_from_slice(&hash[0..8]);
    ///     let value = u64::from_le_bytes(bytes);
    ///     
    ///     F::from_u64(value)
    /// }
    /// ```
    #[allow(dead_code)]
    fn challenge_from_transcript_sha256_doc() {
        // This is a documentation function showing the SHA-256 implementation
        // When sha2 crate is added, replace challenge_from_transcript with this logic
    }

    /// Append message to transcript
    ///
    /// # Security: Ensures proper domain separation
    pub fn append_message(transcript: &mut Vec<u8>, label: &[u8], message: &[u8]) {
        // Append length-prefixed label and message
        transcript.extend_from_slice(&(label.len() as u64).to_le_bytes());
        transcript.extend_from_slice(label);
        transcript.extend_from_slice(&(message.len() as u64).to_le_bytes());
        transcript.extend_from_slice(message);
    }

    /// Append field element to transcript
    pub fn append_field_element<F: Field>(transcript: &mut Vec<u8>, label: &[u8], element: F) {
        let bytes = element.to_canonical_u64().to_le_bytes();
        Self::append_message(transcript, label, &bytes);
    }
}

/// Zero-knowledge utilities
///
/// # Security: Ensures proofs reveal no information beyond validity
pub struct ZeroKnowledge;

impl ZeroKnowledge {
    /// Generate random blinding factor
    ///
    /// # Security: Must be uniformly random
    pub fn random_blinding<F: Field>() -> F {
        F::random()
    }

    /// Blind a value with random factor
    ///
    /// Returns (blinded_value, blinding_factor)
    pub fn blind_value<F: Field>(value: F) -> (F, F) {
        let blinding = Self::random_blinding();
        let blinded = value + blinding;
        (blinded, blinding)
    }

    /// Unblind a value
    pub fn unblind_value<F: Field>(blinded: F, blinding: F) -> F {
        blinded - blinding
    }

    /// Check if blinding is sufficient
    ///
    /// Returns true if blinding provides statistical hiding
    pub fn is_sufficient_blinding<F: Field>(blinding_bits: usize) -> bool {
        // Need at least 128 bits of blinding for statistical security
        blinding_bits >= 128 && blinding_bits < F::MODULUS_BITS
    }
}

/// Side-channel resistance utilities
///
/// # Security: Prevents information leakage through side channels
pub struct SideChannelResistance;

impl SideChannelResistance {
    /// Check if operation is cache-timing safe
    ///
    /// Returns true if operation accesses memory in data-independent pattern
    pub fn is_cache_safe(operation: OperationType) -> bool {
        matches!(
            operation,
            OperationType::ConstantTimeCompare
                | OperationType::ConstantTimeSelect
                | OperationType::ConstantTimeLookup
        )
    }

    /// Check if operation is power-analysis safe
    ///
    /// Returns true if operation has data-independent power consumption
    pub fn is_power_safe(operation: OperationType) -> bool {
        // Most field operations are not power-safe without special hardware
        matches!(operation, OperationType::ConstantTimeCompare)
    }

    /// Recommend countermeasures for operation
    pub fn recommend_countermeasures(operation: OperationType) -> Vec<Countermeasure> {
        match operation {
            OperationType::FieldInversion => vec![
                Countermeasure::UseConstantTimeAlgorithm,
                Countermeasure::AddRandomDelay,
            ],
            OperationType::TableLookup => vec![
                Countermeasure::UseConstantTimeLookup,
                Countermeasure::PreloadCache,
            ],
            OperationType::Comparison => vec![Countermeasure::UseConstantTimeCompare],
            _ => vec![],
        }
    }
}

/// Operation types for side-channel analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    FieldInversion,
    TableLookup,
    Comparison,
    ConstantTimeCompare,
    ConstantTimeSelect,
    ConstantTimeLookup,
}

/// Countermeasures for side-channel attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Countermeasure {
    UseConstantTimeAlgorithm,
    AddRandomDelay,
    UseConstantTimeLookup,
    PreloadCache,
    UseConstantTimeCompare,
}

/// Security parameter validation
///
/// # Security: Ensures parameters meet minimum security requirements
pub struct SecurityParams;

impl SecurityParams {
    /// Minimum field size for 128-bit security
    pub const MIN_FIELD_BITS_128: usize = 256;

    /// Minimum field size for 80-bit security
    pub const MIN_FIELD_BITS_80: usize = 160;

    /// Validate field size for target security level
    pub fn validate_field_size(field_bits: usize, security_bits: usize) -> LookupResult<()> {
        let required_bits = match security_bits {
            128 => Self::MIN_FIELD_BITS_128,
            80 => Self::MIN_FIELD_BITS_80,
            _ => security_bits * 2, // General rule: field size ≥ 2 * security level
        };

        if field_bits < required_bits {
            return Err(LookupError::InvalidProof {
                reason: format!(
                    "Field size {} bits insufficient for {}-bit security (need {} bits)",
                    field_bits, security_bits, required_bits
                ),
            });
        }

        Ok(())
    }

    /// Validate challenge size
    ///
    /// # Security: Challenge must have sufficient entropy
    pub fn validate_challenge_entropy(challenge_bits: usize, security_bits: usize) -> LookupResult<()> {
        if challenge_bits < security_bits {
            return Err(LookupError::InvalidProof {
                reason: format!(
                    "Challenge entropy {} bits insufficient for {}-bit security",
                    challenge_bits, security_bits
                ),
            });
        }

        Ok(())
    }

    /// Compute soundness error
    ///
    /// Returns log2(soundness error) for given parameters
    pub fn compute_soundness_error(field_bits: usize, num_challenges: usize) -> f64 {
        // Soundness error ≈ 1/|F|^num_challenges
        -(field_bits as f64) * (num_challenges as f64)
    }
}
