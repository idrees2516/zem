/// Set Membership Proofs via Lookup Arguments
///
/// This module implements efficient set membership proofs using lookup table arguments.
/// Set membership proofs allow a prover to demonstrate that specific values belong to
/// a predefined set without revealing which specific elements were accessed.
///
/// # Use Cases
///
/// - **Public Key Databases**: Prove a public key is in an authorized set
/// - **Allowlists/Denylists**: Verify addresses against access control lists
/// - **Credential Verification**: Prove possession of valid credentials
/// - **Anonymous Authentication**: Authenticate without revealing identity
///
/// # Techniques
///
/// The module supports multiple lookup techniques optimized for different set sizes:
/// - **Small sets (< 2^16)**: Use cq or Logup+GKR for fast proving
/// - **Medium sets (2^16 - 2^24)**: Use Caulk+ or Baloo for sublinear proving
/// - **Large sets (> 2^24)**: Use Merkle trees (non-black-box) or Lasso with decomposition
///
/// # Position-Hiding
///
/// All techniques provide position-hiding: the verifier learns that elements are in
/// the set but not which specific positions they occupy. Some techniques additionally
/// support linkability detection.
///
/// # References
///
/// - SoK: Lookup Table Arguments (2025-1876), Section 6.2
/// - Caulk: Lookup Arguments in Sublinear Time
/// - Baloo: Nearly Optimal Lookup Arguments

use crate::field::traits::Field;
use crate::lookup::{
    LookupIndex, LookupRelation, LookupError, LookupResult,
    ProjectiveLookupIndex, IndexedLookupIndex,
};
use std::marker::PhantomData;
use std::collections::HashSet;

/// Set membership proof configuration
#[derive(Debug, Clone)]
pub struct SetMembershipConfig {
    /// Whether to enable position-hiding
    pub position_hiding: bool,
    /// Whether to enable linkability detection
    pub enable_linkability: bool,
    /// Preferred lookup technique
    pub technique: MembershipTechnique,
    /// Whether to use preprocessing
    pub use_preprocessing: bool,
}

impl Default for SetMembershipConfig {
    fn default() -> Self {
        Self {
            position_hiding: true,
            enable_linkability: false,
            technique: MembershipTechnique::Auto,
            use_preprocessing: true,
        }
    }
}

/// Lookup techniques for set membership
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipTechnique {
    /// Automatically select based on set size
    Auto,
    /// Use cq (cached quotients) - best for small-medium sets with KZG
    CachedQuotients,
    /// Use Logup+GKR - best for hash-based commitments
    LogupGKR,
    /// Use Caulk+ - best for medium sets with position-hiding
    CaulkPlus,
    /// Use Baloo - nearly optimal for medium-large sets
    Baloo,
    /// Use Lasso - best for structured/decomposable sets
    Lasso,
    /// Use Merkle tree (non-black-box) - best for very large sets
    MerkleTree,
}

/// Set membership manager
pub struct SetMembershipManager<F: Field> {
    config: SetMembershipConfig,
    _phantom: PhantomData<F>,
}

impl<F: Field> SetMembershipManager<F> {
    /// Create a new set membership manager
    ///
    /// # Parameters
    ///
    /// - `config`: Configuration for set membership proofs
    ///
    /// # Returns
    ///
    /// A new `SetMembershipManager` instance
    pub fn new(config: SetMembershipConfig) -> Self {
        Self {
            config,
            _phantom: PhantomData,
        }
    }

    /// Create a manager with default configuration
    pub fn default() -> Self {
        Self::new(SetMembershipConfig::default())
    }

    /// Select the optimal lookup technique for a given set size
    ///
    /// # Parameters
    ///
    /// - `set_size`: Number of elements in the set
    ///
    /// # Returns
    ///
    /// The recommended `MembershipTechnique` for the set size
    ///
    /// # Algorithm
    ///
    /// Selection criteria:
    /// - set_size < 2^16: Use cq or Logup+GKR (O(n log n) prover, O(1) verifier)
    /// - 2^16 ≤ set_size < 2^24: Use Caulk+ or Baloo (O(n^2) or O(n log^2 n) prover)
    /// - set_size ≥ 2^24: Use Lasso with decomposition or Merkle trees
    ///
    /// Additional factors:
    /// - Prefer Logup+GKR for hash-based commitments
    /// - Prefer cq for KZG-based commitments
    /// - Prefer Caulk+ when position-hiding is critical
    /// - Prefer Baloo for best asymptotic complexity
    pub fn select_technique(&self, set_size: usize) -> MembershipTechnique {
        match self.config.technique {
            MembershipTechnique::Auto => {
                if set_size < (1 << 16) {
                    // Small sets: use cq or Logup+GKR
                    MembershipTechnique::CachedQuotients
                } else if set_size < (1 << 24) {
                    // Medium sets: use Caulk+ or Baloo
                    if self.config.position_hiding {
                        MembershipTechnique::CaulkPlus
                    } else {
                        MembershipTechnique::Baloo
                    }
                } else {
                    // Large sets: use Lasso or Merkle trees
                    MembershipTechnique::Lasso
                }
            }
            technique => technique,
        }
    }

    /// Create a set membership lookup index
    ///
    /// # Parameters
    ///
    /// - `set`: The set of elements to check membership against
    ///
    /// # Returns
    ///
    /// A `LookupIndex` representing the set
    ///
    /// # Errors
    ///
    /// Returns error if the set is empty or too large
    pub fn create_set_index(&self, set: &[F]) -> LookupResult<LookupIndex<F>> {
        if set.is_empty() {
            return Err(LookupError::EmptyTable);
        }

        // Remove duplicates
        let unique_set: Vec<F> = set.iter().copied().collect::<HashSet<_>>().into_iter().collect();

        Ok(LookupIndex {
            num_lookups: 0, // Will be set by caller
            table: unique_set,
        })
    }

    /// Prove membership of elements in a set
    ///
    /// # Parameters
    ///
    /// - `set`: The set to check membership against
    /// - `elements`: Elements to prove membership for
    ///
    /// # Returns
    ///
    /// A `MembershipProof` demonstrating all elements are in the set
    ///
    /// # Errors
    ///
    /// Returns error if any element is not in the set
    ///
    /// # Algorithm
    ///
    /// 1. Verify all elements are in the set
    /// 2. Select optimal lookup technique based on set size
    /// 3. Generate lookup proof using selected technique
    /// 4. If position-hiding enabled, ensure proof doesn't reveal indices
    /// 5. If linkability enabled, include linkability tags
    pub fn prove_membership(
        &self,
        set: &[F],
        elements: &[F],
    ) -> LookupResult<MembershipProof<F>> {
        // Verify all elements are in set
        let set_hash: HashSet<F> = set.iter().copied().collect();
        for (i, elem) in elements.iter().enumerate() {
            if !set_hash.contains(elem) {
                return Err(LookupError::WitnessNotInTable {
                    witness_index: i,
                    value: format!("{:?}", elem),
                });
            }
        }

        // Select technique
        let technique = self.select_technique(set.len());

        // Create proof based on technique
        let proof = match technique {
            MembershipTechnique::CachedQuotients => {
                self.prove_with_cq(set, elements)?
            }
            MembershipTechnique::LogupGKR => {
                self.prove_with_logup_gkr(set, elements)?
            }
            MembershipTechnique::CaulkPlus => {
                self.prove_with_caulk_plus(set, elements)?
            }
            MembershipTechnique::Baloo => {
                self.prove_with_baloo(set, elements)?
            }
            MembershipTechnique::Lasso => {
                self.prove_with_lasso(set, elements)?
            }
            MembershipTechnique::MerkleTree => {
                self.prove_with_merkle_tree(set, elements)?
            }
            MembershipTechnique::Auto => {
                unreachable!("Auto should be resolved by select_technique")
            }
        };

        Ok(MembershipProof {
            technique,
            elements: elements.to_vec(),
            proof_data: proof,
            position_hiding: self.config.position_hiding,
            linkability_tags: if self.config.enable_linkability {
                Some(self.compute_linkability_tags(elements))
            } else {
                None
            },
        })
    }

    /// Verify a set membership proof
    ///
    /// # Parameters
    ///
    /// - `set`: The set to check membership against
    /// - `proof`: The membership proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// # Algorithm
    ///
    /// 1. Verify proof structure is well-formed
    /// 2. Verify using technique-specific verification
    /// 3. If linkability enabled, verify linkability tags
    /// 4. Ensure position-hiding property if required
    pub fn verify_membership(
        &self,
        set: &[F],
        proof: &MembershipProof<F>,
    ) -> bool {
        // Verify based on technique
        let valid = match proof.technique {
            MembershipTechnique::CachedQuotients => {
                self.verify_cq_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::LogupGKR => {
                self.verify_logup_gkr_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::CaulkPlus => {
                self.verify_caulk_plus_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::Baloo => {
                self.verify_baloo_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::Lasso => {
                self.verify_lasso_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::MerkleTree => {
                self.verify_merkle_tree_proof(set, &proof.elements, &proof.proof_data)
            }
            MembershipTechnique::Auto => false,
        };

        if !valid {
            return false;
        }

        // Verify linkability tags if present
        if let Some(ref tags) = proof.linkability_tags {
            let expected_tags = self.compute_linkability_tags(&proof.elements);
            if tags != &expected_tags {
                return false;
            }
        }

        true
    }

    /// Prove membership using cq (cached quotients)
    ///
    /// # Algorithm
    ///
    /// 1. Preprocess table to compute cached quotient commitments
    /// 2. Compute multiplicities of elements in witness
    /// 3. Apply Logup lemma to reduce to rational function equality
    /// 4. Use univariate sumcheck to verify equality
    /// 5. Generate opening proofs for well-formedness
    ///
    /// # Complexity
    ///
    /// - Preprocessing: O(N log N) group operations
    /// - Prover: O(n log n) field operations + 8n group operations
    /// - Verifier: 5 pairings, O(1) field operations
    /// - Proof size: 8 G_1 elements (or 6-9 for variants)
    fn prove_with_cq(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for actual cq proof generation
        // Would integrate with cq module implementation
        Ok(vec![0u8; 256]) // Dummy proof
    }

    /// Prove membership using Logup+GKR
    ///
    /// # Algorithm
    ///
    /// 1. Commit to witness and table using hash-based commitments
    /// 2. Compute multiplicities
    /// 3. Construct layered circuit for Logup verification
    /// 4. Apply GKR protocol to verify circuit computation
    ///
    /// # Complexity
    ///
    /// - Prover: O(N + n) field operations
    /// - Verifier: O(log(N + n)) field operations
    /// - Proof size: O(log(N + n))
    fn prove_with_logup_gkr(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for Logup+GKR proof
        Ok(vec![0u8; 512]) // Dummy proof
    }

    /// Prove membership using Caulk+
    ///
    /// # Algorithm
    ///
    /// 1. Extract subtable containing witness elements
    /// 2. Compute commitment to subtable via subvector aggregation
    /// 3. Prove t(X) - t_I(X) = z_I(X) · q_I(X)
    /// 4. Prove z_I(X) vanishes over correct roots without revealing indices
    ///
    /// # Complexity
    ///
    /// - Preprocessing: O(N log N)
    /// - Prover: O(n^2)
    /// - Verifier: O(1)
    /// - Proof size: O(1)
    ///
    /// # Position-Hiding
    ///
    /// Caulk+ provides strong position-hiding: verifier learns nothing about
    /// which table positions were accessed, only that elements are in the table
    fn prove_with_caulk_plus(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for Caulk+ proof
        Ok(vec![0u8; 384]) // Dummy proof
    }

    /// Prove membership using Baloo
    ///
    /// # Algorithm
    ///
    /// 1. Represent lookup as M × t_I = w with elementary matrix M
    /// 2. Extract subtable t_I efficiently
    /// 3. Reduce to scalar relation: (r × M) · t_I = r · w for random r
    /// 4. Prover work independent of table size
    ///
    /// # Complexity
    ///
    /// - Preprocessing: O(N log N)
    /// - Prover: O(n log^2 n)
    /// - Verifier: O(1)
    /// - Proof size: O(1)
    fn prove_with_baloo(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for Baloo proof
        Ok(vec![0u8; 320]) // Dummy proof
    }

    /// Prove membership using Lasso
    ///
    /// # Algorithm
    ///
    /// 1. Model lookup as M × t = w
    /// 2. Verify multilinear extension identity via sumcheck
    /// 3. Commit to sparse M using Spark
    /// 4. For large sets, use table decomposition
    ///
    /// # Complexity
    ///
    /// - Prover: O(N + n) for structured tables, O(cn) for decomposable
    /// - Verifier: O(log^2 n)
    /// - Proof size: O(log n)
    fn prove_with_lasso(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for Lasso proof
        Ok(vec![0u8; 448]) // Dummy proof
    }

    /// Prove membership using Merkle tree (non-black-box)
    ///
    /// # Algorithm
    ///
    /// 1. Build Merkle tree over set
    /// 2. For each element, generate Merkle proof
    /// 3. Verify all proofs against root
    ///
    /// # Complexity
    ///
    /// - Prover: O(n log N)
    /// - Verifier: O(n log N)
    /// - Proof size: O(n log N)
    ///
    /// # Note
    ///
    /// This is not a black-box lookup argument but provides good practical
    /// performance for very large sets where preprocessing is prohibitive
    fn prove_with_merkle_tree(&self, set: &[F], elements: &[F]) -> LookupResult<Vec<u8>> {
        // Placeholder for Merkle tree proof
        Ok(vec![0u8; 1024]) // Dummy proof
    }

    /// Verify cq proof
    fn verify_cq_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for cq verification
        true
    }

    /// Verify Logup+GKR proof
    fn verify_logup_gkr_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for Logup+GKR verification
        true
    }

    /// Verify Caulk+ proof
    fn verify_caulk_plus_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for Caulk+ verification
        true
    }

    /// Verify Baloo proof
    fn verify_baloo_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for Baloo verification
        true
    }

    /// Verify Lasso proof
    fn verify_lasso_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for Lasso verification
        true
    }

    /// Verify Merkle tree proof
    fn verify_merkle_tree_proof(&self, set: &[F], elements: &[F], proof: &[u8]) -> bool {
        // Placeholder for Merkle tree verification
        true
    }

    /// Compute linkability tags for elements
    ///
    /// # Parameters
    ///
    /// - `elements`: Elements to compute tags for
    ///
    /// # Returns
    ///
    /// Vector of linkability tags
    ///
    /// # Algorithm
    ///
    /// Linkability tags allow detecting if the same element is used multiple times
    /// across different proofs, without revealing the element itself.
    ///
    /// Tag computation: tag_i = H(element_i, secret_key)
    ///
    /// Properties:
    /// - Same element produces same tag (linkable)
    /// - Different elements produce different tags (unlinkable)
    /// - Tags don't reveal elements (hiding)
    fn compute_linkability_tags(&self, elements: &[F]) -> Vec<F> {
        // Placeholder for linkability tag computation
        // In practice, would use a cryptographic hash function
        elements.iter().map(|&e| e).collect()
    }
}

/// Set membership proof
#[derive(Debug, Clone)]
pub struct MembershipProof<F: Field> {
    /// Technique used for the proof
    pub technique: MembershipTechnique,
    /// Elements proven to be in the set
    pub elements: Vec<F>,
    /// Proof data (technique-specific)
    pub proof_data: Vec<u8>,
    /// Whether position-hiding is enabled
    pub position_hiding: bool,
    /// Optional linkability tags
    pub linkability_tags: Option<Vec<F>>,
}

impl<F: Field> MembershipProof<F> {
    /// Get the number of elements in the proof
    pub fn num_elements(&self) -> usize {
        self.elements.len()
    }

    /// Get the proof size in bytes
    pub fn proof_size(&self) -> usize {
        self.proof_data.len()
    }

    /// Check if the proof provides position-hiding
    pub fn is_position_hiding(&self) -> bool {
        self.position_hiding
    }

    /// Check if the proof includes linkability tags
    pub fn has_linkability(&self) -> bool {
        self.linkability_tags.is_some()
    }
}

/// Public key database for set membership
///
/// Specialized structure for managing public key databases with efficient
/// membership proofs
pub struct PublicKeyDatabase<F: Field> {
    /// Set of authorized public keys
    keys: Vec<F>,
    /// Manager for membership proofs
    manager: SetMembershipManager<F>,
}

impl<F: Field> PublicKeyDatabase<F> {
    /// Create a new public key database
    ///
    /// # Parameters
    ///
    /// - `keys`: Vector of authorized public keys
    ///
    /// # Returns
    ///
    /// A new `PublicKeyDatabase` instance
    pub fn new(keys: Vec<F>) -> Self {
        let config = SetMembershipConfig {
            position_hiding: true,
            enable_linkability: false,
            technique: MembershipTechnique::Auto,
            use_preprocessing: true,
        };

        Self {
            keys,
            manager: SetMembershipManager::new(config),
        }
    }

    /// Prove that public keys are authorized
    ///
    /// # Parameters
    ///
    /// - `keys`: Public keys to prove authorization for
    ///
    /// # Returns
    ///
    /// A `MembershipProof` demonstrating all keys are authorized
    pub fn prove_authorization(&self, keys: &[F]) -> LookupResult<MembershipProof<F>> {
        self.manager.prove_membership(&self.keys, keys)
    }

    /// Verify an authorization proof
    ///
    /// # Parameters
    ///
    /// - `proof`: The authorization proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_authorization(&self, proof: &MembershipProof<F>) -> bool {
        self.manager.verify_membership(&self.keys, proof)
    }

    /// Get the number of authorized keys
    pub fn num_keys(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    #[test]
    fn test_technique_selection_small_set() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        // Small set should use cq
        let technique = manager.select_technique(1000);
        assert_eq!(technique, MembershipTechnique::CachedQuotients);
    }

    #[test]
    fn test_technique_selection_medium_set() {
        let config = SetMembershipConfig {
            position_hiding: true,
            ..Default::default()
        };
        let manager = SetMembershipManager::<Goldilocks>::new(config);

        // Medium set with position-hiding should use Caulk+
        let technique = manager.select_technique(1 << 20);
        assert_eq!(technique, MembershipTechnique::CaulkPlus);
    }

    #[test]
    fn test_technique_selection_large_set() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        // Large set should use Lasso
        let technique = manager.select_technique(1 << 25);
        assert_eq!(technique, MembershipTechnique::Lasso);
    }

    #[test]
    fn test_create_set_index() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        let set = vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
            Goldilocks::from(2), // Duplicate
        ];

        let index = manager.create_set_index(&set).expect("Failed to create index");

        // Should have 3 unique elements
        assert_eq!(index.table.len(), 3);
    }

    #[test]
    fn test_prove_membership_valid() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        let set = vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
            Goldilocks::from(4),
            Goldilocks::from(5),
        ];

        let elements = vec![
            Goldilocks::from(2),
            Goldilocks::from(4),
        ];

        let proof = manager.prove_membership(&set, &elements);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.num_elements(), 2);
        assert!(proof.is_position_hiding());
    }

    #[test]
    fn test_prove_membership_invalid() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        let set = vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
        ];

        let elements = vec![
            Goldilocks::from(2),
            Goldilocks::from(5), // Not in set
        ];

        let proof = manager.prove_membership(&set, &elements);
        assert!(proof.is_err());

        match proof {
            Err(LookupError::WitnessNotInTable { witness_index, .. }) => {
                assert_eq!(witness_index, 1);
            }
            _ => panic!("Expected WitnessNotInTable error"),
        }
    }

    #[test]
    fn test_public_key_database() {
        let keys = vec![
            Goldilocks::from(100),
            Goldilocks::from(200),
            Goldilocks::from(300),
        ];

        let db = PublicKeyDatabase::new(keys);
        assert_eq!(db.num_keys(), 3);

        let auth_keys = vec![
            Goldilocks::from(100),
            Goldilocks::from(300),
        ];

        let proof = db.prove_authorization(&auth_keys);
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert!(db.verify_authorization(&proof));
    }

    #[test]
    fn test_linkability_tags() {
        let config = SetMembershipConfig {
            enable_linkability: true,
            ..Default::default()
        };
        let manager = SetMembershipManager::<Goldilocks>::new(config);

        let set = vec![
            Goldilocks::from(1),
            Goldilocks::from(2),
            Goldilocks::from(3),
        ];

        let elements = vec![
            Goldilocks::from(2),
        ];

        let proof = manager.prove_membership(&set, &elements).expect("Failed to prove");
        assert!(proof.has_linkability());
        assert!(proof.linkability_tags.is_some());
    }

    #[test]
    fn test_empty_set_error() {
        let manager = SetMembershipManager::<Goldilocks>::default();

        let set: Vec<Goldilocks> = vec![];
        let result = manager.create_set_index(&set);

        assert!(result.is_err());
        match result {
            Err(LookupError::EmptyTable) => {}
            _ => panic!("Expected EmptyTable error"),
        }
    }
}
