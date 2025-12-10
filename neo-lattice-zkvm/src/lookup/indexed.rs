// Indexed Lookup Relations
//
// Indexed lookups are used in systems like Jolt zkVM where the verifier receives
// commitments to both the witness values and their corresponding table indices.
// This allows external representation of arbitrary functions via tables without
// encoding function logic in circuits.
//
// An indexed lookup consists of:
// - Witness values w = {w_1, ..., w_n}
// - Index vector i = {i_1, ..., i_n} where i_k ∈ [N]
// - Constraint: w_k = t_{i_k} for all k ∈ [n]
//
// This is more expressive than standard lookups as it explicitly tracks which
// table entry corresponds to each witness element.

use crate::field::traits::Field;
use crate::lookup::{FiniteSet, LookupError, LookupIndex, LookupRelation, LookupResult};
use std::marker::PhantomData;

/// Indexed lookup index
///
/// Uses the same base lookup index but interprets it differently:
/// the witness now consists of (value, index) pairs
#[derive(Debug, Clone)]
pub struct IndexedLookupIndex<F: Field> {
    /// Base lookup index
    pub base_index: LookupIndex<F>,
}

impl<F: Field> IndexedLookupIndex<F> {
    /// Create a new indexed lookup index
    pub fn new(base_index: LookupIndex<F>) -> Self {
        IndexedLookupIndex { base_index }
    }

    /// Validate the indexed lookup index
    pub fn is_valid(&self) -> bool {
        self.base_index.is_valid()
    }

    /// Get the table size N
    pub fn table_size(&self) -> usize {
        self.base_index.table_size()
    }

    /// Get the number of lookups n
    pub fn num_lookups(&self) -> usize {
        self.base_index.num_lookups
    }

    /// Get the table
    pub fn table(&self) -> &[F] {
        &self.base_index.table
    }
}

/// Indexed lookup witness
///
/// Contains both values and their corresponding table indices
#[derive(Debug, Clone)]
pub struct IndexedLookupWitness<F: Field> {
    /// Witness values w ∈ S^n
    pub values: Vec<F>,
    /// Table indices i ∈ [N]^n
    pub indices: Vec<usize>,
}

impl<F: Field> IndexedLookupWitness<F> {
    /// Create a new indexed lookup witness
    pub fn new(values: Vec<F>, indices: Vec<usize>) -> Self {
        IndexedLookupWitness { values, indices }
    }

    /// Get the number of lookups
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the witness is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Validate that values and indices have the same length
    pub fn is_well_formed(&self) -> bool {
        self.values.len() == self.indices.len()
    }

    /// Get a specific (value, index) pair
    pub fn get(&self, k: usize) -> Option<(F, usize)> {
        if k < self.len() {
            Some((self.values[k], self.indices[k]))
        } else {
            None
        }
    }

    /// Create from a table and index vector
    ///
    /// Automatically fills in values from table using indices
    pub fn from_indices(table: &[F], indices: Vec<usize>) -> LookupResult<Self> {
        let values: Result<Vec<F>, _> = indices
            .iter()
            .map(|&i| {
                table.get(i).copied().ok_or(LookupError::InvalidIndexSize {
                    expected: table.len(),
                    got: i,
                })
            })
            .collect();

        Ok(IndexedLookupWitness {
            values: values?,
            indices,
        })
    }
}

/// Indexed lookup relation
///
/// Verifies that for each k ∈ [n]:
/// - Index i_k is within table bounds: i_k < N
/// - Value matches table entry: w_k = t_{i_k}
#[derive(Debug, Clone)]
pub struct IndexedLookup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> IndexedLookup<F> {
    /// Create a new indexed lookup relation
    pub fn new() -> Self {
        IndexedLookup {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for IndexedLookup<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> LookupRelation<F> for IndexedLookup<F> {
    type Index = IndexedLookupIndex<F>;
    type Witness = IndexedLookupWitness<F>;

    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool {
        // Check witness is well-formed
        if !witness.is_well_formed() {
            return false;
        }

        // Check witness size matches expected size
        if witness.len() != index.num_lookups() {
            return false;
        }

        let table = index.table();

        // Check each (value, index) pair
        witness
            .indices
            .iter()
            .zip(witness.values.iter())
            .all(|(&i_k, &w_k)| {
                // Check index is within bounds
                i_k < table.len() &&
                // Check value matches table entry
                w_k == table[i_k]
            })
    }

    fn verify_detailed(
        &self,
        index: &Self::Index,
        witness: &Self::Witness,
    ) -> LookupResult<()> {
        // Check witness is well-formed
        if !witness.is_well_formed() {
            return Err(LookupError::InvalidVectorLength {
                expected: witness.values.len(),
                got: witness.indices.len(),
            });
        }

        // Check witness size
        if witness.len() != index.num_lookups() {
            return Err(LookupError::InvalidIndexSize {
                expected: index.num_lookups(),
                got: witness.len(),
            });
        }

        let table = index.table();

        // Check each (value, index) pair
        for k in 0..witness.len() {
            let i_k = witness.indices[k];
            let w_k = witness.values[k];

            // Check index is within bounds
            if i_k >= table.len() {
                return Err(LookupError::InvalidIndexSize {
                    expected: table.len(),
                    got: i_k,
                });
            }

            // Check value matches table entry
            if w_k != table[i_k] {
                return Err(LookupError::WitnessNotInTable {
                    witness_index: k,
                    value: format!("value={:?}, index={}, table[{}]={:?}", w_k, i_k, i_k, table[i_k]),
                });
            }
        }

        Ok(())
    }
}

/// Compiler from standard to indexed lookup
///
/// When S = F and the field characteristic is large enough, we can compile
/// a standard lookup into an indexed lookup using encoding:
/// - t*_i = i · r + t_i
/// - a*_j = b_j · r + a_j
/// where m · N < char(F) and r is a random challenge
pub struct StandardToIndexedCompiler<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> StandardToIndexedCompiler<F> {
    /// Check if compilation is possible
    ///
    /// Requires: m · N < char(F) where m is max witness value and N is table size
    pub fn can_compile(max_witness_value: usize, table_size: usize) -> bool {
        let required = max_witness_value * table_size;
        F::CHARACTERISTIC > required
    }

    /// Encode table with indices
    ///
    /// Returns t*_i = i · r + t_i for each table entry
    pub fn encode_table(table: &[F], challenge: F) -> Vec<F> {
        table
            .iter()
            .enumerate()
            .map(|(i, &t_i)| {
                let i_field = F::from(i as u64);
                i_field * challenge + t_i
            })
            .collect()
    }

    /// Encode witness with indices
    ///
    /// Returns a*_j = b_j · r + a_j where b_j is the index
    pub fn encode_witness(witness: &IndexedLookupWitness<F>, challenge: F) -> Vec<F> {
        witness
            .indices
            .iter()
            .zip(witness.values.iter())
            .map(|(&b_j, &a_j)| {
                let b_j_field = F::from(b_j as u64);
                b_j_field * challenge + a_j
            })
            .collect()
    }

    /// Perform range check on witness values
    ///
    /// Ensures a_j ∈ [r] for each lookup (required for soundness)
    pub fn range_check_witness(witness: &[F], range: F) -> bool {
        witness.iter().all(|&w| w < range)
    }
}

/// Vector lookup conversion
///
/// Indexed lookups can be expressed as vector lookups by treating the table
/// as a vector of pairs (i, t_i)
pub struct IndexedToVectorConverter;

impl IndexedToVectorConverter {
    /// Convert indexed table to vector table
    ///
    /// Each entry becomes a tuple (index, value)
    pub fn convert_table<F: Field>(table: &[F]) -> Vec<(F, F)> {
        table
            .iter()
            .enumerate()
            .map(|(i, &t_i)| (F::from(i as u64), t_i))
            .collect()
    }

    /// Convert indexed witness to vector witness
    ///
    /// Each (value, index) pair becomes a tuple (index, value)
    pub fn convert_witness<F: Field>(witness: &IndexedLookupWitness<F>) -> Vec<(F, F)> {
        witness
            .indices
            .iter()
            .zip(witness.values.iter())
            .map(|(&i, &v)| (F::from(i as u64), v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_indexed_lookup_witness_creation() {
        let values = vec![F::from(2), F::from(4), F::from(1)];
        let indices = vec![1, 3, 0];

        let witness = IndexedLookupWitness::new(values.clone(), indices.clone());
        assert_eq!(witness.len(), 3);
        assert!(!witness.is_empty());
        assert!(witness.is_well_formed());
        assert_eq!(witness.get(0), Some((F::from(2), 1)));
        assert_eq!(witness.get(1), Some((F::from(4), 3)));
        assert_eq!(witness.get(2), Some((F::from(1), 0)));
        assert_eq!(witness.get(3), None);
    }

    #[test]
    fn test_indexed_lookup_witness_from_indices() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let indices = vec![1, 3, 0];

        let witness = IndexedLookupWitness::from_indices(&table, indices).unwrap();
        assert_eq!(witness.values, vec![F::from(2), F::from(4), F::from(1)]);
        assert_eq!(witness.indices, vec![1, 3, 0]);
    }

    #[test]
    fn test_indexed_lookup_witness_from_indices_out_of_bounds() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let indices = vec![1, 5, 0]; // Index 5 is out of bounds

        let result = IndexedLookupWitness::from_indices(&table, indices);
        assert!(result.is_err());
    }

    #[test]
    fn test_indexed_lookup_valid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 3, table.clone());
        let index = IndexedLookupIndex::new(base_index);

        let witness = IndexedLookupWitness::new(
            vec![F::from(2), F::from(4), F::from(1)],
            vec![1, 3, 0],
        );

        let lookup = IndexedLookup::new();
        assert!(lookup.verify(&index, &witness));
        assert!(lookup.verify_detailed(&index, &witness).is_ok());
    }

    #[test]
    fn test_indexed_lookup_invalid_value() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 3, table);
        let index = IndexedLookupIndex::new(base_index);

        // Value doesn't match table entry at index
        let witness = IndexedLookupWitness::new(
            vec![F::from(2), F::from(5), F::from(1)], // Should be 4 at index 1
            vec![1, 3, 0],
        );

        let lookup = IndexedLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_indexed_lookup_invalid_index() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);
        let index = IndexedLookupIndex::new(base_index);

        // Index out of bounds
        let witness = IndexedLookupWitness::new(vec![F::from(2), F::from(1)], vec![1, 5]);

        let lookup = IndexedLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_indexed_lookup_malformed_witness() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);
        let index = IndexedLookupIndex::new(base_index);

        // Mismatched lengths
        let witness = IndexedLookupWitness::new(vec![F::from(2), F::from(1)], vec![1]);

        let lookup = IndexedLookup::new();
        assert!(!lookup.verify(&index, &witness));
    }

    #[test]
    fn test_standard_to_indexed_compiler_can_compile() {
        // Small values and table size
        assert!(StandardToIndexedCompiler::<F>::can_compile(100, 1000));

        // Would overflow for small fields
        // (This test depends on field characteristic)
    }

    #[test]
    fn test_encode_table() {
        let table = vec![F::from(10), F::from(20), F::from(30)];
        let challenge = F::from(1000);

        let encoded = StandardToIndexedCompiler::encode_table(&table, challenge);

        // t*_0 = 0 * 1000 + 10 = 10
        // t*_1 = 1 * 1000 + 20 = 1020
        // t*_2 = 2 * 1000 + 30 = 2030
        assert_eq!(encoded[0], F::from(10));
        assert_eq!(encoded[1], F::from(1020));
        assert_eq!(encoded[2], F::from(2030));
    }

    #[test]
    fn test_encode_witness() {
        let witness = IndexedLookupWitness::new(
            vec![F::from(10), F::from(20)],
            vec![0, 1],
        );
        let challenge = F::from(1000);

        let encoded = StandardToIndexedCompiler::encode_witness(&witness, challenge);

        // a*_0 = 0 * 1000 + 10 = 10
        // a*_1 = 1 * 1000 + 20 = 1020
        assert_eq!(encoded[0], F::from(10));
        assert_eq!(encoded[1], F::from(1020));
    }

    #[test]
    fn test_range_check_witness() {
        let witness = vec![F::from(10), F::from(20), F::from(30)];
        let range = F::from(100);

        assert!(StandardToIndexedCompiler::range_check_witness(&witness, range));

        let range_small = F::from(25);
        assert!(!StandardToIndexedCompiler::range_check_witness(&witness, range_small));
    }

    #[test]
    fn test_indexed_to_vector_conversion() {
        let table = vec![F::from(10), F::from(20), F::from(30)];
        let vector_table = IndexedToVectorConverter::convert_table(&table);

        assert_eq!(vector_table.len(), 3);
        assert_eq!(vector_table[0], (F::from(0), F::from(10)));
        assert_eq!(vector_table[1], (F::from(1), F::from(20)));
        assert_eq!(vector_table[2], (F::from(2), F::from(30)));

        let witness = IndexedLookupWitness::new(
            vec![F::from(20), F::from(10)],
            vec![1, 0],
        );
        let vector_witness = IndexedToVectorConverter::convert_witness(&witness);

        assert_eq!(vector_witness.len(), 2);
        assert_eq!(vector_witness[0], (F::from(1), F::from(20)));
        assert_eq!(vector_witness[1], (F::from(0), F::from(10)));
    }

    #[test]
    fn test_indexed_lookup_duplicate_indices() {
        // Test that same index can be used multiple times
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 4, table);
        let index = IndexedLookupIndex::new(base_index);

        let witness = IndexedLookupWitness::new(
            vec![F::from(2), F::from(2), F::from(1), F::from(2)],
            vec![1, 1, 0, 1],
        );

        let lookup = IndexedLookup::new();
        assert!(lookup.verify(&index, &witness));
    }
}
