// Lookup Table Arguments Module
//
// This module implements comprehensive lookup table arguments based on the SoK paper
// "Lookup Table Arguments" (2025-1876). Lookup arguments are cryptographic protocols
// that enable efficient enforcement of non-native operations in zero-knowledge proof
// systems by proving that witness elements belong to predefined tables.
//
// The module supports multiple lookup variants:
// - Standard lookups: w ⊆ t (witness elements in table)
// - Projective lookups: only specific witness indices checked
// - Indexed lookups: witness-index pairs verified
// - Vector lookups: tuple-based table entries
// - Online lookups: runtime-dependent tables
// - Decomposable lookups: large tables split into smaller subtables

use crate::field::traits::Field;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

// Submodules
pub mod projective;
pub mod indexed;
pub mod vector;
pub mod online;
pub mod decomposition;
pub mod committed;
pub mod oracle;
pub mod mle;
pub mod logup;
pub mod logup_gkr;
pub mod cq;
pub mod spark;
pub mod lasso;
pub mod shout;
pub mod accumulation;
pub mod composition;
pub mod optimization;
pub mod security;
pub mod applications;
pub mod pcs;
pub mod plookup;
pub mod halo2;
pub mod cq_extensions;
pub mod caulk;
pub mod baloo;
pub mod flookup;
pub mod duplex;
pub mod sumcheck;
pub mod gkr;
pub mod protostar;
pub mod nlookup;
pub mod fli;
pub mod table_management;
pub mod non_native;
pub mod set_membership;
pub mod memory;

// Re-exports for convenience
pub use projective::{ProjectiveLookup, ProjectiveLookupIndex};
pub use indexed::{IndexedLookup, IndexedLookupIndex, IndexedLookupWitness};
pub use vector::{VectorLookup, VectorLookupIndex};
pub use online::{OnlineLookup, OnlineLookupIndex, OnlineLookupWitness};
pub use decomposition::{DecomposableTable, DecompositionManager};
pub use non_native::{NonNativeOpsManager, NonNativeOp, NonNativeConfig};
pub use set_membership::{SetMembershipManager, SetMembershipConfig, MembershipProof};
pub use memory::{MemoryChecker, MemoryConfig, MemoryProof, MemoryAccess, MemoryOp};

/// Error types for lookup operations
#[derive(Debug, Clone, PartialEq)]
pub enum LookupError {
    /// Witness element not found in table
    WitnessNotInTable {
        witness_index: usize,
        value: String,
    },
    /// Invalid index size
    InvalidIndexSize {
        expected: usize,
        got: usize,
    },
    /// Invalid projection indices
    InvalidProjectionIndices {
        indices: Vec<usize>,
    },
    /// Invalid vector length
    InvalidVectorLength {
        expected: usize,
        got: usize,
    },
    /// Commitment mismatch
    CommitmentMismatch {
        expected: String,
        got: String,
    },
    /// Invalid opening proof
    InvalidOpening,
    /// Invalid proof
    InvalidProof {
        reason: String,
    },
    /// Sumcheck failed
    SumcheckFailed {
        round: usize,
    },
    /// Pairing check failed
    PairingCheckFailed,
    /// Preprocessing failed
    PreprocessingFailed {
        reason: String,
    },
    /// Invalid table size
    InvalidTableSize {
        size: usize,
        required: String,
    },
    /// Field characteristic too small
    CharacteristicTooSmall {
        characteristic: usize,
        required: usize,
    },
    /// Division by zero
    DivisionByZero,
    /// Invalid field element
    InvalidFieldElement,
    /// Decomposition failed
    DecompositionFailed {
        value: String,
    },
    /// Invalid decomposition
    InvalidDecomposition {
        expected: String,
        got: String,
    },
    /// Accumulation failed
    AccumulationFailed {
        reason: String,
    },
    /// Invalid accumulator
    InvalidAccumulator,
    /// Empty witness
    EmptyWitness,
    /// Table too large
    TableTooLarge {
        table_size: usize,
        max_size: usize,
    },
    /// Proof size mismatch
    ProofSizeMismatch {
        expected: usize,
        got: usize,
    },
    /// Invalid proof format
    InvalidProofFormat {
        reason: String,
    },
    /// Invalid polynomial size
    InvalidPolynomialSize {
        expected: usize,
        got: usize,
    },
    /// Invalid point size
    InvalidPointSize {
        expected: usize,
        got: usize,
    },
    /// Invalid challenge size
    InvalidChallengeSize {
        expected: usize,
        got: usize,
    },
    /// Invalid polynomial degree
    InvalidPolynomialDegree {
        expected: usize,
        got: usize,
    },
    /// Invalid proof size
    InvalidProofSize {
        expected: usize,
        got: usize,
    },
    /// Batch size mismatch
    BatchSizeMismatch,
    /// Empty batch
    EmptyBatch,
    /// Inconsistent polynomial sizes
    InconsistentPolynomialSizes,
    /// Invalid layer size
    InvalidLayerSize {
        expected: usize,
        got: usize,
    },
    /// Missing gate input
    MissingGateInput,
    /// Missing constant
    MissingConstant,
    /// Invalid input size
    InvalidInputSize {
        expected: usize,
        got: usize,
    },
    /// Empty table
    EmptyTable,
    /// Invalid parameter
    InvalidParameter {
        param: String,
        reason: String,
    },
    /// Unsupported operation
    UnsupportedOperation {
        operation: String,
        reason: String,
    },
    /// Invalid witness
    InvalidWitness {
        index: usize,
        reason: String,
    },
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupError::WitnessNotInTable { witness_index, value } => {
                write!(
                    f,
                    "Witness element at index {} with value {} not found in table",
                    witness_index, value
                )
            }
            LookupError::InvalidProof { reason } => {
                write!(f, "Invalid proof: {}", reason)
            }
            LookupError::CharacteristicTooSmall {
                characteristic,
                required,
            } => {
                write!(
                    f,
                    "Field characteristic {} is too small, required at least {}",
                    characteristic, required
                )
            }
            LookupError::InvalidIndexSize { expected, got } => {
                write!(
                    f,
                    "Invalid index size: expected {}, got {}",
                    expected, got
                )
            }
            LookupError::InvalidProjectionIndices { indices } => {
                write!(f, "Invalid projection indices: {:?}", indices)
            }
            LookupError::InvalidVectorLength { expected, got } => {
                write!(
                    f,
                    "Invalid vector length: expected {}, got {}",
                    expected, got
                )
            }
            LookupError::EmptyTable => {
                write!(f, "Table is empty")
            }
            LookupError::InvalidParameter { param, reason } => {
                write!(f, "Invalid parameter '{}': {}", param, reason)
            }
            LookupError::UnsupportedOperation { operation, reason } => {
                write!(f, "Unsupported operation '{}': {}", operation, reason)
            }
            LookupError::InvalidWitness { index, reason } => {
                write!(f, "Invalid witness at index {}: {}", index, reason)
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for LookupError {}

/// Result type for lookup operations
pub type LookupResult<T> = Result<T, LookupError>;

/// Finite set representation for lookup indices
#[derive(Debug, Clone)]
pub struct FiniteSet<F: Field> {
    elements: HashSet<F>,
}

impl<F: Field> FiniteSet<F> {
    /// Create a new finite set from a vector
    pub fn from_vec(elements: Vec<F>) -> Self {
        FiniteSet {
            elements: elements.into_iter().collect(),
        }
    }

    /// Check if an element is in the set
    pub fn contains(&self, element: F) -> bool {
        self.elements.contains(&element)
    }

    /// Get the size of the set
    pub fn size(&self) -> usize {
        self.elements.len()
    }

    /// Get all elements as a vector
    pub fn to_vec(&self) -> Vec<F> {
        self.elements.iter().copied().collect()
    }
}

/// Lookup index defining the lookup relation
///
/// A lookup index I := (S, n, t) consists of:
/// - S: finite set of elements
/// - n: number of lookups (witness size)
/// - t: table vector of N elements from S
///
/// The lookup relation LK_I is the set of witness vectors w ∈ S^n
/// such that w_i ∈ t for all i ∈ [n]
#[derive(Debug, Clone)]
pub struct LookupIndex<F: Field> {
    /// Finite set S
    pub finite_set: FiniteSet<F>,
    /// Number of lookups n
    pub num_lookups: usize,
    /// Table vector t ∈ S^N
    pub table: Vec<F>,
}

impl<F: Field> LookupIndex<F> {
    /// Create a new lookup index
    pub fn new(finite_set: FiniteSet<F>, num_lookups: usize, table: Vec<F>) -> Self {
        LookupIndex {
            finite_set,
            num_lookups,
            table,
        }
    }

    /// Validate the lookup index
    ///
    /// An index is valid if and only if:
    /// - 0 < n (at least one lookup)
    /// - 0 < N (non-empty table)
    /// - t ∈ S^N (all table elements in finite set)
    pub fn is_valid(&self) -> bool {
        self.num_lookups > 0
            && !self.table.is_empty()
            && self.table.iter().all(|&elem| self.finite_set.contains(elem))
    }

    /// Get the table size N
    pub fn table_size(&self) -> usize {
        self.table.len()
    }

    /// Get the witness size n
    pub fn witness_size(&self) -> usize {
        self.num_lookups
    }

    /// Check if a value is in the table
    pub fn contains(&self, value: F) -> bool {
        self.table.contains(&value)
    }

    /// Find the index of a value in the table
    pub fn find_index(&self, value: F) -> Option<usize> {
        self.table.iter().position(|&t| t == value)
    }

    /// Get all indices where a value appears in the table
    pub fn find_all_indices(&self, value: F) -> Vec<usize> {
        self.table
            .iter()
            .enumerate()
            .filter_map(|(i, &t)| if t == value { Some(i) } else { None })
            .collect()
    }
}

/// Trait for lookup relations
///
/// A lookup relation defines the set of valid witness vectors
/// for a given lookup index.
pub trait LookupRelation<F: Field> {
    /// The index type for this lookup relation
    type Index;
    /// The witness type for this lookup relation
    type Witness;

    /// Verify that a witness satisfies the lookup relation
    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool;

    /// Verify and return detailed error if verification fails
    fn verify_detailed(
        &self,
        index: &Self::Index,
        witness: &Self::Witness,
    ) -> LookupResult<()>;
}

/// Standard lookup relation
///
/// The standard lookup relation LK_I is the set of witness vectors w ∈ S^n
/// such that w_i ∈ t for all i ∈ [n].
///
/// This is the most basic form of lookup: every element in the witness
/// must appear somewhere in the table (multiset inclusion).
#[derive(Debug, Clone)]
pub struct StandardLookup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> StandardLookup<F> {
    /// Create a new standard lookup relation
    pub fn new() -> Self {
        StandardLookup {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for StandardLookup<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> LookupRelation<F> for StandardLookup<F> {
    type Index = LookupIndex<F>;
    type Witness = Vec<F>;

    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool {
        // Check witness size matches expected size
        if witness.len() != index.num_lookups {
            return false;
        }

        // Check all witness elements are in table
        witness.iter().all(|&w_i| index.contains(w_i))
    }

    fn verify_detailed(
        &self,
        index: &Self::Index,
        witness: &Self::Witness,
    ) -> LookupResult<()> {
        // Check witness size
        if witness.len() != index.num_lookups {
            return Err(LookupError::InvalidIndexSize {
                expected: index.num_lookups,
                got: witness.len(),
            });
        }

        // Check each witness element
        for (i, &w_i) in witness.iter().enumerate() {
            if !index.contains(w_i) {
                return Err(LookupError::WitnessNotInTable {
                    witness_index: i,
                    value: format!("{:?}", w_i),
                });
            }
        }

        Ok(())
    }
}

/// Multiset operations for lookup relations
///
/// Lookup relations treat both table t and witness w as ordered vectors
/// (multisets) rather than unordered sets. This allows duplicate elements.
pub struct MultisetOps;

impl MultisetOps {
    /// Check if witness is a multiset subset of table
    ///
    /// Returns true if every element in witness appears in table
    /// (counting multiplicities)
    pub fn is_subset<F: Field>(witness: &[F], table: &[F]) -> bool {
        // Count multiplicities in witness
        let mut witness_counts = std::collections::HashMap::new();
        for &w in witness {
            *witness_counts.entry(w).or_insert(0) += 1;
        }

        // Count multiplicities in table
        let mut table_counts = std::collections::HashMap::new();
        for &t in table {
            *table_counts.entry(t).or_insert(0) += 1;
        }

        // Check witness multiplicities ≤ table multiplicities
        witness_counts.iter().all(|(elem, &w_count)| {
            table_counts.get(elem).map_or(false, |&t_count| w_count <= t_count)
        })
    }

    /// Compute multiplicities of table elements in witness
    ///
    /// Returns a vector m where m[i] is the number of times
    /// table[i] appears in witness
    pub fn compute_multiplicities<F: Field>(witness: &[F], table: &[F]) -> Vec<usize> {
        let mut multiplicities = vec![0; table.len()];

        for &w in witness {
            // Find all occurrences of w in table
            for (i, &t) in table.iter().enumerate() {
                if w == t {
                    multiplicities[i] += 1;
                }
            }
        }

        multiplicities
    }

    /// Check multiset equality
    ///
    /// Returns true if witness and table contain the same elements
    /// with the same multiplicities (possibly in different order)
    pub fn is_equal<F: Field>(witness: &[F], table: &[F]) -> bool {
        if witness.len() != table.len() {
            return false;
        }

        let mut witness_counts = std::collections::HashMap::new();
        for &w in witness {
            *witness_counts.entry(w).or_insert(0) += 1;
        }

        let mut table_counts = std::collections::HashMap::new();
        for &t in table {
            *table_counts.entry(t).or_insert(0) += 1;
        }

        witness_counts == table_counts
    }
}

/// Error recovery utilities
pub struct ErrorRecovery<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> ErrorRecovery<F> {
    /// Identify all witness elements not in table
    pub fn find_invalid_witness_elements(
        witness: &[F],
        table: &[F],
    ) -> Vec<(usize, F)> {
        witness
            .iter()
            .enumerate()
            .filter(|(_, &w)| !table.contains(&w))
            .map(|(i, &w)| (i, w))
            .collect()
    }

    /// Validate field characteristic for Logup-based schemes
    ///
    /// Logup requires characteristic p > max(n, N)
    pub fn validate_field_characteristic(
        witness_size: usize,
        table_size: usize,
    ) -> LookupResult<()> {
        let required = witness_size.max(table_size);
        let characteristic = F::CHARACTERISTIC;

        if characteristic <= required {
            Err(LookupError::CharacteristicTooSmall {
                characteristic,
                required: required + 1,
            })
        } else {
            Ok(())
        }
    }

    /// Check if table size is a power of two (required for some schemes)
    pub fn validate_power_of_two_table(table_size: usize) -> LookupResult<()> {
        if table_size == 0 || (table_size & (table_size - 1)) != 0 {
            Err(LookupError::InvalidTableSize {
                size: table_size,
                required: "power of two".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_finite_set() {
        let elements = vec![F::from(1), F::from(2), F::from(3)];
        let set = FiniteSet::from_vec(elements.clone());

        assert_eq!(set.size(), 3);
        assert!(set.contains(F::from(1)));
        assert!(set.contains(F::from(2)));
        assert!(set.contains(F::from(3)));
        assert!(!set.contains(F::from(4)));
    }

    #[test]
    fn test_lookup_index_validation() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());

        let index = LookupIndex::new(finite_set, 3, table);
        assert!(index.is_valid());

        // Invalid: empty table
        let empty_table = vec![];
        let finite_set2 = FiniteSet::from_vec(vec![F::from(1)]);
        let invalid_index = LookupIndex::new(finite_set2, 3, empty_table);
        assert!(!invalid_index.is_valid());

        // Invalid: zero lookups
        let table2 = vec![F::from(1), F::from(2)];
        let finite_set3 = FiniteSet::from_vec(table2.clone());
        let invalid_index2 = LookupIndex::new(finite_set3, 0, table2);
        assert!(!invalid_index2.is_valid());
    }

    #[test]
    fn test_standard_lookup_valid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(1)];

        let finite_set = FiniteSet::from_vec(table.clone());
        let index = LookupIndex::new(finite_set, witness.len(), table);

        let lookup = StandardLookup::new();
        assert!(lookup.verify(&index, &witness));
        assert!(lookup.verify_detailed(&index, &witness).is_ok());
    }

    #[test]
    fn test_standard_lookup_invalid_witness() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(6), F::from(1)]; // 6 not in table

        let finite_set = FiniteSet::from_vec(table.clone());
        let index = LookupIndex::new(finite_set, witness.len(), table);

        let lookup = StandardLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
        match result {
            Err(LookupError::WitnessNotInTable { witness_index, .. }) => {
                assert_eq!(witness_index, 1);
            }
            _ => panic!("Expected WitnessNotInTable error"),
        }
    }

    #[test]
    fn test_standard_lookup_invalid_size() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let witness = vec![F::from(1), F::from(2)]; // Wrong size

        let finite_set = FiniteSet::from_vec(table.clone());
        let index = LookupIndex::new(finite_set, 3, table); // Expects 3 lookups

        let lookup = StandardLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
        match result {
            Err(LookupError::InvalidIndexSize { expected, got }) => {
                assert_eq!(expected, 3);
                assert_eq!(got, 2);
            }
            _ => panic!("Expected InvalidIndexSize error"),
        }
    }

    #[test]
    fn test_multiset_subset() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(2)];
        let witness1 = vec![F::from(2), F::from(1)];
        let witness2 = vec![F::from(2), F::from(2), F::from(1)]; // Two 2s, one in table
        let witness3 = vec![F::from(4)]; // Not in table

        assert!(MultisetOps::is_subset(&witness1, &table));
        assert!(MultisetOps::is_subset(&witness2, &table));
        assert!(!MultisetOps::is_subset(&witness3, &table));
    }

    #[test]
    fn test_compute_multiplicities() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];

        let multiplicities = MultisetOps::compute_multiplicities(&witness, &table);
        assert_eq!(multiplicities, vec![0, 2, 1, 1, 0]);
    }

    #[test]
    fn test_multiset_equality() {
        let set1 = vec![F::from(1), F::from(2), F::from(3)];
        let set2 = vec![F::from(3), F::from(1), F::from(2)]; // Same, different order
        let set3 = vec![F::from(1), F::from(2), F::from(2)]; // Different multiplicities

        assert!(MultisetOps::is_equal(&set1, &set2));
        assert!(!MultisetOps::is_equal(&set1, &set3));
    }

    #[test]
    fn test_find_invalid_witness_elements() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let witness = vec![F::from(1), F::from(4), F::from(2), F::from(5)];

        let invalid = ErrorRecovery::<F>::find_invalid_witness_elements(&witness, &table);
        assert_eq!(invalid.len(), 2);
        assert_eq!(invalid[0], (1, F::from(4)));
        assert_eq!(invalid[1], (3, F::from(5)));
    }

    #[test]
    fn test_lookup_index_find_operations() {
        let table = vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(2),
            F::from(4),
        ];
        let finite_set = FiniteSet::from_vec(table.clone());
        let index = LookupIndex::new(finite_set, 3, table);

        // Test find_index (returns first occurrence)
        assert_eq!(index.find_index(F::from(2)), Some(1));
        assert_eq!(index.find_index(F::from(4)), Some(4));
        assert_eq!(index.find_index(F::from(5)), None);

        // Test find_all_indices (returns all occurrences)
        assert_eq!(index.find_all_indices(F::from(2)), vec![1, 3]);
        assert_eq!(index.find_all_indices(F::from(4)), vec![4]);
        assert_eq!(index.find_all_indices(F::from(5)), vec![]);
    }

    #[test]
    fn test_duplicate_witness_elements() {
        // Test that lookup supports duplicate elements in witness
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let witness = vec![F::from(2), F::from(2), F::from(1), F::from(2)];

        let finite_set = FiniteSet::from_vec(table.clone());
        let index = LookupIndex::new(finite_set, witness.len(), table);

        let lookup = StandardLookup::new();
        assert!(lookup.verify(&index, &witness));
    }
}
