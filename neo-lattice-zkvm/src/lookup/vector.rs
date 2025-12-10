// Vector Lookup Relations
//
// Vector lookups handle tables where each entry is a tuple of elements rather
// than a single element. This is useful for operations that naturally work with
// tuples, such as:
// - Multi-input functions (e.g., addition, multiplication)
// - State transitions (current_state, input) → next_state
// - Memory operations (address, value) pairs
//
// A vector lookup index I := (S, n, k, t) consists of:
// - S: finite set
// - n: number of lookups
// - k: tuple size (vector length)
// - t ∈ S^{(k)N}: table of N tuples, each of length k
//
// The vector lookup relation is: w ∈ S^{(k)n} such that ∀i ∈ [n], w_i ∈ t

use crate::field::traits::Field;
use crate::lookup::{FiniteSet, LookupError, LookupRelation, LookupResult};
use std::marker::PhantomData;

/// Vector lookup index
///
/// Extends lookup to handle tuple-based table entries
#[derive(Debug, Clone)]
pub struct VectorLookupIndex<F: Field> {
    /// Finite set S
    pub finite_set: FiniteSet<F>,
    /// Number of lookups n
    pub num_lookups: usize,
    /// Tuple size k (vector length)
    pub tuple_size: usize,
    /// Table t ∈ S^{(k)N}: N tuples of length k
    pub table: Vec<Vec<F>>,
}

impl<F: Field> VectorLookupIndex<F> {
    /// Create a new vector lookup index
    pub fn new(
        finite_set: FiniteSet<F>,
        num_lookups: usize,
        tuple_size: usize,
        table: Vec<Vec<F>>,
    ) -> Self {
        VectorLookupIndex {
            finite_set,
            num_lookups,
            tuple_size,
            table,
        }
    }

    /// Validate the vector lookup index
    ///
    /// Valid if:
    /// - 0 < n (at least one lookup)
    /// - 0 < k (non-zero tuple size)
    /// - 0 < N (non-empty table)
    /// - All table entries have length k
    /// - All table elements are in finite set
    pub fn is_valid(&self) -> bool {
        self.num_lookups > 0
            && self.tuple_size > 0
            && !self.table.is_empty()
            && self.table.iter().all(|tuple| {
                tuple.len() == self.tuple_size
                    && tuple.iter().all(|&elem| self.finite_set.contains(elem))
            })
    }

    /// Get the table size N
    pub fn table_size(&self) -> usize {
        self.table.len()
    }

    /// Check if a tuple is in the table
    pub fn contains(&self, tuple: &[F]) -> bool {
        if tuple.len() != self.tuple_size {
            return false;
        }
        self.table.iter().any(|t| t.as_slice() == tuple)
    }

    /// Find the index of a tuple in the table
    pub fn find_index(&self, tuple: &[F]) -> Option<usize> {
        if tuple.len() != self.tuple_size {
            return None;
        }
        self.table.iter().position(|t| t.as_slice() == tuple)
    }
}

/// Vector lookup relation
///
/// Verifies that each witness tuple appears in the table
#[derive(Debug, Clone)]
pub struct VectorLookup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> VectorLookup<F> {
    /// Create a new vector lookup relation
    pub fn new() -> Self {
        VectorLookup {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for VectorLookup<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> LookupRelation<F> for VectorLookup<F> {
    type Index = VectorLookupIndex<F>;
    type Witness = Vec<Vec<F>>;

    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool {
        // Check witness size matches expected size
        if witness.len() != index.num_lookups {
            return false;
        }

        // Check all witness tuples are in table
        witness.iter().all(|w_i| index.contains(w_i))
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

        // Check each witness tuple
        for (i, w_i) in witness.iter().enumerate() {
            // Check tuple length
            if w_i.len() != index.tuple_size {
                return Err(LookupError::InvalidVectorLength {
                    expected: index.tuple_size,
                    got: w_i.len(),
                });
            }

            // Check tuple is in table
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

/// Vectorized Logup lemma utilities
///
/// Extends Logup to handle vector lookups by encoding tuples as polynomials
pub struct VectorizedLogup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> VectorizedLogup<F> {
    /// Encode a vector as a polynomial
    ///
    /// w_i(y) := Σ_{j=1}^k w_{i,j} · y^{j-1}
    pub fn vector_to_polynomial(vector: &[F], challenge_y: F) -> F {
        vector
            .iter()
            .enumerate()
            .map(|(j, &w_ij)| w_ij * challenge_y.pow(j as u64))
            .fold(F::ZERO, |acc, x| acc + x)
    }

    /// Evaluate rational sum for witness vectors
    ///
    /// Σ_{i=1}^n 1/(x + w_i(y))
    pub fn evaluate_rational_sum_witness(
        witness: &[Vec<F>],
        challenge_x: F,
        challenge_y: F,
    ) -> F {
        witness
            .iter()
            .map(|w_i| {
                let w_i_poly = Self::vector_to_polynomial(w_i, challenge_y);
                (challenge_x + w_i_poly).inverse()
            })
            .fold(F::ZERO, |acc, x| acc + x)
    }

    /// Evaluate rational sum for table vectors
    ///
    /// Σ_{i=1}^N m_i/(x + t_i(y))
    pub fn evaluate_rational_sum_table(
        table: &[Vec<F>],
        multiplicities: &[usize],
        challenge_x: F,
        challenge_y: F,
    ) -> F {
        table
            .iter()
            .zip(multiplicities.iter())
            .map(|(t_i, &m_i)| {
                let t_i_poly = Self::vector_to_polynomial(t_i, challenge_y);
                let m_i_field = F::from(m_i as u64);
                m_i_field * (challenge_x + t_i_poly).inverse()
            })
            .fold(F::ZERO, |acc, x| acc + x)
    }

    /// Compute multiplicities for vector lookups
    pub fn compute_multiplicities(witness: &[Vec<F>], table: &[Vec<F>]) -> Vec<usize> {
        let mut multiplicities = vec![0; table.len()];

        for w in witness {
            for (i, t) in table.iter().enumerate() {
                if w.as_slice() == t.as_slice() {
                    multiplicities[i] += 1;
                }
            }
        }

        multiplicities
    }
}

/// Homomorphic vector lookup utilities
///
/// Supports k separate lookup tables with proof aggregation
pub struct HomomorphicVectorLookup;

impl HomomorphicVectorLookup {
    /// Linearize k-tuples into 3-tuples
    ///
    /// Transforms k-tuple lookups into 3-tuple lookups for efficiency
    /// Each k-tuple (v_1, ..., v_k) becomes k 3-tuples: {(i, j, v_i)}_{i∈[k], j∈[N]}
    pub fn linearize_tuples<F: Field>(
        tuples: &[Vec<F>],
        tuple_size: usize,
    ) -> Vec<(F, F, F)> {
        let mut linearized = Vec::new();

        for (j, tuple) in tuples.iter().enumerate() {
            for (i, &v_i) in tuple.iter().enumerate() {
                linearized.push((
                    F::from(i as u64),
                    F::from(j as u64),
                    v_i,
                ));
            }
        }

        linearized
    }

    /// Check consistency of linearized vectors
    ///
    /// Verifies that all x_i values are equal across each tuple
    pub fn check_consistency<F: Field>(linearized: &[(F, F, F)], tuple_size: usize) -> bool {
        if linearized.is_empty() {
            return true;
        }

        let num_tuples = linearized.len() / tuple_size;

        for j in 0..num_tuples {
            let start = j * tuple_size;
            let end = start + tuple_size;
            let tuple_entries = &linearized[start..end];

            // Check all entries have same j value
            let expected_j = tuple_entries[0].1;
            if !tuple_entries.iter().all(|(_, j_val, _)| *j_val == expected_j) {
                return false;
            }

            // Check i values are sequential
            for (idx, (i_val, _, _)) in tuple_entries.iter().enumerate() {
                if *i_val != F::from(idx as u64) {
                    return false;
                }
            }
        }

        true
    }
}

/// Partial tuple matching for generalized vector lookups
///
/// Allows matching only specific positions within tuples
pub struct PartialTupleMatch;

impl PartialTupleMatch {
    /// Check if witness tuple matches table tuple at specified positions
    pub fn matches_at_positions<F: Field>(
        witness_tuple: &[F],
        table_tuple: &[F],
        positions: &[usize],
    ) -> bool {
        positions.iter().all(|&pos| {
            pos < witness_tuple.len()
                && pos < table_tuple.len()
                && witness_tuple[pos] == table_tuple[pos]
        })
    }

    /// Find all table tuples matching witness at specified positions
    pub fn find_matches<F: Field>(
        witness_tuple: &[F],
        table: &[Vec<F>],
        positions: &[usize],
    ) -> Vec<usize> {
        table
            .iter()
            .enumerate()
            .filter(|(_, t)| Self::matches_at_positions(witness_tuple, t, positions))
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_vector_lookup_index_validation() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            F::from(6),
        ]);

        let index = VectorLookupIndex::new(finite_set, 2, 2, table);
        assert!(index.is_valid());

        // Invalid: inconsistent tuple sizes
        let bad_table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3)], // Wrong size
        ];
        let finite_set2 = FiniteSet::from_vec(vec![F::from(1), F::from(2), F::from(3)]);
        let invalid_index = VectorLookupIndex::new(finite_set2, 2, 2, bad_table);
        assert!(!invalid_index.is_valid());
    }

    #[test]
    fn test_vector_lookup_valid() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            F::from(6),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        let witness = vec![
            vec![F::from(3), F::from(4)],
            vec![F::from(1), F::from(2)],
        ];

        let lookup = VectorLookup::new();
        assert!(lookup.verify(&index, &witness));
        assert!(lookup.verify_detailed(&index, &witness).is_ok());
    }

    #[test]
    fn test_vector_lookup_invalid_tuple() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(5), F::from(6)], // Not in table
        ];

        let lookup = VectorLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_to_polynomial() {
        let vector = vec![F::from(1), F::from(2), F::from(3)];
        let challenge = F::from(10);

        // w(y) = 1 + 2*10 + 3*100 = 1 + 20 + 300 = 321
        let result = VectorizedLogup::vector_to_polynomial(&vector, challenge);
        assert_eq!(result, F::from(321));
    }

    #[test]
    fn test_compute_multiplicities_vector() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(1), F::from(2)],
        ];

        let multiplicities = VectorizedLogup::compute_multiplicities(&witness, &table);
        assert_eq!(multiplicities, vec![2, 1, 0]);
    }

    #[test]
    fn test_linearize_tuples() {
        let tuples = vec![
            vec![F::from(1), F::from(2), F::from(3)],
            vec![F::from(4), F::from(5), F::from(6)],
        ];

        let linearized = HomomorphicVectorLookup::linearize_tuples(&tuples, 3);

        assert_eq!(linearized.len(), 6);
        // First tuple
        assert_eq!(linearized[0], (F::from(0), F::from(0), F::from(1)));
        assert_eq!(linearized[1], (F::from(1), F::from(0), F::from(2)));
        assert_eq!(linearized[2], (F::from(2), F::from(0), F::from(3)));
        // Second tuple
        assert_eq!(linearized[3], (F::from(0), F::from(1), F::from(4)));
        assert_eq!(linearized[4], (F::from(1), F::from(1), F::from(5)));
        assert_eq!(linearized[5], (F::from(2), F::from(1), F::from(6)));
    }

    #[test]
    fn test_check_consistency() {
        let consistent = vec![
            (F::from(0), F::from(0), F::from(1)),
            (F::from(1), F::from(0), F::from(2)),
            (F::from(0), F::from(1), F::from(3)),
            (F::from(1), F::from(1), F::from(4)),
        ];

        assert!(HomomorphicVectorLookup::check_consistency(&consistent, 2));

        let inconsistent = vec![
            (F::from(0), F::from(0), F::from(1)),
            (F::from(1), F::from(1), F::from(2)), // Wrong j value
        ];

        assert!(!HomomorphicVectorLookup::check_consistency(&inconsistent, 2));
    }

    #[test]
    fn test_partial_tuple_match() {
        let witness = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let table_entry1 = vec![F::from(1), F::from(99), F::from(3), F::from(4)];
        let table_entry2 = vec![F::from(1), F::from(2), F::from(99), F::from(4)];

        // Match at positions 0, 2, 3
        let positions = vec![0, 2, 3];
        assert!(PartialTupleMatch::matches_at_positions(
            &witness,
            &table_entry1,
            &positions
        ));
        assert!(!PartialTupleMatch::matches_at_positions(
            &witness,
            &table_entry2,
            &positions
        ));
    }

    #[test]
    fn test_find_matches() {
        let witness = vec![F::from(1), F::from(2), F::from(3)];
        let table = vec![
            vec![F::from(1), F::from(99), F::from(3)],
            vec![F::from(1), F::from(2), F::from(99)],
            vec![F::from(1), F::from(88), F::from(3)],
        ];

        // Match at positions 0 and 2
        let positions = vec![0, 2];
        let matches = PartialTupleMatch::find_matches(&witness, &table, &positions);
        assert_eq!(matches, vec![0, 2]);
    }

    #[test]
    fn test_vector_lookup_duplicate_tuples() {
        // Test that same tuple can appear multiple times in witness
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ]);
        let index = VectorLookupIndex::new(finite_set, 3, 2, table);

        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];

        let lookup = VectorLookup::new();
        assert!(lookup.verify(&index, &witness));
    }
}


impl<F: Field> VectorLookup<F> {
    /// Create a new vector lookup relation
    pub fn new() -> Self {
        VectorLookup {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for VectorLookup<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> LookupRelation<F> for VectorLookup<F> {
    type Index = VectorLookupIndex<F>;
    type Witness = Vec<Vec<F>>;

    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool {
        // Check witness size matches expected size
        if witness.len() != index.num_lookups {
            return false;
        }

        // Check all witness tuples are in table
        witness.iter().all(|w_i| {
            w_i.len() == index.tuple_size && index.contains(w_i)
        })
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

        // Check each witness tuple
        for (i, w_i) in witness.iter().enumerate() {
            // Check tuple length
            if w_i.len() != index.tuple_size {
                return Err(LookupError::InvalidVectorLength {
                    expected: index.tuple_size,
                    got: w_i.len(),
                });
            }

            // Check tuple is in table
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

/// Vectorized Logup lemma support
///
/// For vector lookups, the Logup lemma is extended using polynomials:
/// w_i(y) := Σ_{j=1}^k w_{i,j} · y^{j-1}
///
/// The vectorized Logup identity becomes:
/// Σ_{i=1}^n 1/(x + w_i(y)) = Σ_{i=1}^N m_i/(x + t_i(y))
pub struct VectorizedLogupSupport;

impl VectorizedLogupSupport {
    /// Encode a tuple as a polynomial evaluation
    ///
    /// w_i(y) = Σ_{j=1}^k w_{i,j} · y^{j-1}
    pub fn tuple_to_polynomial<F: Field>(tuple: &[F], challenge_y: F) -> F {
        tuple
            .iter()
            .enumerate()
            .map(|(j, &w_ij)| w_ij * challenge_y.pow(j as u64))
            .fold(F::ZERO, |acc, x| acc + x)
    }

    /// Evaluate rational sum for witness side
    ///
    /// Σ_{i=1}^n 1/(x + w_i(y))
    pub fn evaluate_rational_sum_witness<F: Field>(
        witness: &[Vec<F>],
        challenge_x: F,
        challenge_y: F,
    ) -> F {
        witness
            .iter()
            .map(|w_i| {
                let w_i_poly = Self::tuple_to_polynomial(w_i, challenge_y);
                (challenge_x + w_i_poly).invert().unwrap()
            })
            .fold(F::ZERO, |acc, x| acc + x)
    }

    /// Evaluate rational sum for table side
    ///
    /// Σ_{i=1}^N m_i/(x + t_i(y))
    pub fn evaluate_rational_sum_table<F: Field>(
        table: &[Vec<F>],
        multiplicities: &[usize],
        challenge_x: F,
        challenge_y: F,
    ) -> F {
        table
            .iter()
            .zip(multiplicities.iter())
            .map(|(t_i, &m_i)| {
                let t_i_poly = Self::tuple_to_polynomial(t_i, challenge_y);
                let m_i_field = F::from(m_i as u64);
                m_i_field * (challenge_x + t_i_poly).invert().unwrap()
            })
            .fold(F::ZERO, |acc, x| acc + x)
    }
}

/// Linearization technique for vector lookups
///
/// Transforms k-tuples into 3-tuples {(x_i, y_j, r_i)}_{i∈[k], j∈[N]}
/// This can reduce the tuple size at the cost of more lookups
pub struct VectorLinearization;

impl VectorLinearization {
    /// Linearize a k-tuple table into 3-tuple table
    ///
    /// Each k-tuple becomes k 3-tuples with consistency checks
    pub fn linearize_table<F: Field>(table: &[Vec<F>]) -> Vec<(F, F, F)> {
        let mut linearized = Vec::new();

        for (j, tuple) in table.iter().enumerate() {
            let j_field = F::from(j as u64);
            for (i, &value) in tuple.iter().enumerate() {
                let i_field = F::from(i as u64);
                linearized.push((i_field, j_field, value));
            }
        }

        linearized
    }

    /// Linearize a witness tuple
    pub fn linearize_witness<F: Field>(witness: &[Vec<F>]) -> Vec<(F, F, F)> {
        let mut linearized = Vec::new();

        for tuple in witness {
            for (i, &value) in tuple.iter().enumerate() {
                let i_field = F::from(i as u64);
                // y_j would be determined by which table entry this came from
                // For now, we just include the position and value
                linearized.push((i_field, F::ZERO, value));
            }
        }

        linearized
    }

    /// Verify consistency of linearized tuples
    ///
    /// All x_i values must be equal across each original tuple
    pub fn verify_consistency<F: Field>(linearized: &[(F, F, F)], tuple_size: usize) -> bool {
        if linearized.len() % tuple_size != 0 {
            return false;
        }

        for chunk in linearized.chunks(tuple_size) {
            // Check that x_i values form sequence 0, 1, 2, ..., k-1
            for (i, &(x_i, _, _)) in chunk.iter().enumerate() {
                if x_i != F::from(i as u64) {
                    return false;
                }
            }
        }

        true
    }
}

/// Homomorphic proof aggregation for vector lookups
///
/// Vector lookups can be constructed from k separate lookup proofs
/// (one for each component) using homomorphic properties
pub struct HomomorphicVectorAggregation;

impl HomomorphicVectorAggregation {
    /// Split vector table into k component tables
    ///
    /// table[i] = (t_{i,1}, t_{i,2}, ..., t_{i,k})
    /// becomes k tables: T_j = {t_{i,j} : i ∈ [N]} for j ∈ [k]
    pub fn split_table<F: Field>(table: &[Vec<F>]) -> Vec<Vec<F>> {
        if table.is_empty() {
            return vec![];
        }

        let tuple_size = table[0].len();
        let mut component_tables = vec![Vec::new(); tuple_size];

        for tuple in table {
            for (j, &value) in tuple.iter().enumerate() {
                component_tables[j].push(value);
            }
        }

        component_tables
    }

    /// Split vector witness into k component witnesses
    pub fn split_witness<F: Field>(witness: &[Vec<F>]) -> Vec<Vec<F>> {
        if witness.is_empty() {
            return vec![];
        }

        let tuple_size = witness[0].len();
        let mut component_witnesses = vec![Vec::new(); tuple_size];

        for tuple in witness {
            for (j, &value) in tuple.iter().enumerate() {
                component_witnesses[j].push(value);
            }
        }

        component_witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_vector_lookup_index_validation() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            F::from(6),
        ]);

        let index = VectorLookupIndex::new(finite_set, 2, 2, table);
        assert!(index.is_valid());

        // Invalid: inconsistent tuple lengths
        let bad_table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3)], // Wrong length
        ];
        let finite_set2 = FiniteSet::from_vec(vec![F::from(1), F::from(2), F::from(3)]);
        let invalid_index = VectorLookupIndex::new(finite_set2, 2, 2, bad_table);
        assert!(!invalid_index.is_valid());
    }

    #[test]
    fn test_vector_lookup_valid() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            F::from(6),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        let witness = vec![vec![F::from(3), F::from(4)], vec![F::from(1), F::from(2)]];

        let lookup = VectorLookup::new();
        assert!(lookup.verify(&index, &witness));
        assert!(lookup.verify_detailed(&index, &witness).is_ok());
    }

    #[test]
    fn test_vector_lookup_invalid_tuple() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        // Tuple not in table
        let witness = vec![vec![F::from(1), F::from(2)], vec![F::from(5), F::from(6)]];

        let lookup = VectorLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_lookup_invalid_tuple_length() {
        let table = vec![vec![F::from(1), F::from(2)], vec![F::from(3), F::from(4)]];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        // Wrong tuple length
        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3)], // Too short
        ];

        let lookup = VectorLookup::new();
        assert!(!lookup.verify(&index, &witness));

        let result = lookup.verify_detailed(&index, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_tuple_to_polynomial() {
        let tuple = vec![F::from(1), F::from(2), F::from(3)];
        let challenge_y = F::from(10);

        // w(y) = 1 + 2*10 + 3*100 = 1 + 20 + 300 = 321
        let result = VectorizedLogupSupport::tuple_to_polynomial(&tuple, challenge_y);
        assert_eq!(result, F::from(321));
    }

    #[test]
    fn test_vectorized_logup_rational_sums() {
        let witness = vec![vec![F::from(1), F::from(2)], vec![F::from(3), F::from(4)]];

        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(5), F::from(6)],
        ];

        let multiplicities = vec![1, 1, 0]; // Each witness tuple appears once

        let challenge_x = F::from(7);
        let challenge_y = F::from(10);

        let witness_sum = VectorizedLogupSupport::evaluate_rational_sum_witness(
            &witness,
            challenge_x,
            challenge_y,
        );

        let table_sum = VectorizedLogupSupport::evaluate_rational_sum_table(
            &table,
            &multiplicities,
            challenge_x,
            challenge_y,
        );

        // Sums should be equal for valid lookup
        assert_eq!(witness_sum, table_sum);
    }

    #[test]
    fn test_linearize_table() {
        let table = vec![
            vec![F::from(1), F::from(2), F::from(3)],
            vec![F::from(4), F::from(5), F::from(6)],
        ];

        let linearized = VectorLinearization::linearize_table(&table);

        assert_eq!(linearized.len(), 6); // 2 tuples * 3 elements each

        // First tuple: (0, 0, 1), (1, 0, 2), (2, 0, 3)
        assert_eq!(linearized[0], (F::from(0), F::from(0), F::from(1)));
        assert_eq!(linearized[1], (F::from(1), F::from(0), F::from(2)));
        assert_eq!(linearized[2], (F::from(2), F::from(0), F::from(3)));

        // Second tuple: (0, 1, 4), (1, 1, 5), (2, 1, 6)
        assert_eq!(linearized[3], (F::from(0), F::from(1), F::from(4)));
        assert_eq!(linearized[4], (F::from(1), F::from(1), F::from(5)));
        assert_eq!(linearized[5], (F::from(2), F::from(1), F::from(6)));
    }

    #[test]
    fn test_verify_consistency() {
        let consistent = vec![
            (F::from(0), F::from(0), F::from(1)),
            (F::from(1), F::from(0), F::from(2)),
            (F::from(2), F::from(0), F::from(3)),
        ];

        assert!(VectorLinearization::verify_consistency(&consistent, 3));

        let inconsistent = vec![
            (F::from(0), F::from(0), F::from(1)),
            (F::from(2), F::from(0), F::from(2)), // Should be 1, not 2
            (F::from(2), F::from(0), F::from(3)),
        ];

        assert!(!VectorLinearization::verify_consistency(&inconsistent, 3));
    }

    #[test]
    fn test_split_table() {
        let table = vec![
            vec![F::from(1), F::from(2), F::from(3)],
            vec![F::from(4), F::from(5), F::from(6)],
            vec![F::from(7), F::from(8), F::from(9)],
        ];

        let component_tables = HomomorphicVectorAggregation::split_table(&table);

        assert_eq!(component_tables.len(), 3);
        assert_eq!(component_tables[0], vec![F::from(1), F::from(4), F::from(7)]);
        assert_eq!(component_tables[1], vec![F::from(2), F::from(5), F::from(8)]);
        assert_eq!(component_tables[2], vec![F::from(3), F::from(6), F::from(9)]);
    }

    #[test]
    fn test_split_witness() {
        let witness = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
        ];

        let component_witnesses = HomomorphicVectorAggregation::split_witness(&witness);

        assert_eq!(component_witnesses.len(), 2);
        assert_eq!(component_witnesses[0], vec![F::from(1), F::from(3)]);
        assert_eq!(component_witnesses[1], vec![F::from(2), F::from(4)]);
    }

    #[test]
    fn test_vector_lookup_find_operations() {
        let table = vec![
            vec![F::from(1), F::from(2)],
            vec![F::from(3), F::from(4)],
            vec![F::from(1), F::from(2)], // Duplicate
        ];
        let finite_set = FiniteSet::from_vec(vec![
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
        ]);
        let index = VectorLookupIndex::new(finite_set, 2, 2, table);

        assert!(index.contains(&[F::from(1), F::from(2)]));
        assert!(index.contains(&[F::from(3), F::from(4)]));
        assert!(!index.contains(&[F::from(5), F::from(6)]));

        // find_index returns first occurrence
        assert_eq!(index.find_index(&[F::from(1), F::from(2)]), Some(0));
        assert_eq!(index.find_index(&[F::from(3), F::from(4)]), Some(1));
        assert_eq!(index.find_index(&[F::from(5), F::from(6)]), None);
    }
}
