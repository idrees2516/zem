// Projective Lookup Relations
//
// Projective lookups are a generalization where only specific indices of the witness
// are checked against the table. This is useful in zkVMs where only certain witness
// elements need verification without checking the entire witness.
//
// A projective lookup index I = ((S, n, t), m, i) consists of:
// - Base lookup index (S, n, t)
// - Witness size m (total witness length)
// - Projection indices i = {i_1, ..., i_n} where 0 ≤ i_1 < ... < i_n < m
//
// The projective lookup relation PLK_I is the set of witnesses w ∈ S^m
// such that w_i ⊆ t (only elements at projection indices must be in table)

use crate::field::traits::Field;
use crate::lookup::{FiniteSet, LookupError, LookupIndex, LookupRelation, LookupResult};
use std::marker::PhantomData;

/// Projective lookup index
///
/// Extends the standard lookup index with projection information:
/// - base_index: The underlying lookup index (S, n, t)
/// - witness_size: Total size m of the witness vector
/// - projection_indices: Ordered indices i = {i_1, ..., i_n} to check
#[derive(Debug, Clone)]
pub struct ProjectiveLookupIndex<F: Field> {
    /// Base lookup index
    pub base_index: LookupIndex<F>,
    /// Total witness size m
    pub witness_size: usize,
    /// Projection indices i (must be sorted and < witness_size)
    pub projection_indices: Vec<usize>,
}

impl<F: Field> ProjectiveLookupIndex<F> {
    /// Create a new projective lookup index
    pub fn new(
        base_index: LookupIndex<F>,
        witness_size: usize,
        projection_indices: Vec<usize>,
    ) -> Self {
        ProjectiveLookupIndex {
            base_index,
            witness_size,
            projection_indices,
        }
    }

    /// Validate the projective lookup index
    ///
    /// Valid if:
    /// - Base index is valid
    /// - Projection indices length matches base index num_lookups
    /// - Projection indices are sorted: 0 ≤ i_1 < i_2 < ... < i_n < m
    /// - All projection indices are within witness bounds
    pub fn is_valid(&self) -> bool {
        // Check base index validity
        if !self.base_index.is_valid() {
            return false;
        }

        // Check projection indices count matches expected lookups
        if self.projection_indices.len() != self.base_index.num_lookups {
            return false;
        }

        // Check projection indices are sorted and within bounds
        if self.projection_indices.is_empty() {
            return false;
        }

        // Check first index is non-negative (always true for usize, but explicit)
        if self.projection_indices[0] >= self.witness_size {
            return false;
        }

        // Check indices are strictly increasing and within bounds
        for window in self.projection_indices.windows(2) {
            if window[0] >= window[1] || window[1] >= self.witness_size {
                return false;
            }
        }

        // Check last index is within bounds
        self.projection_indices
            .last()
            .map_or(false, |&last| last < self.witness_size)
    }

    /// Get the number of projected lookups
    pub fn num_projections(&self) -> usize {
        self.projection_indices.len()
    }

    /// Check if an index is in the projection set
    pub fn is_projected(&self, index: usize) -> bool {
        self.projection_indices.binary_search(&index).is_ok()
    }

    /// Extract the projected subvector from a witness
    pub fn extract_projected_witness(&self, witness: &[F]) -> Vec<F> {
        self.projection_indices
            .iter()
            .map(|&i| witness[i])
            .collect()
    }

    /// Create a selector vector for the witness
    ///
    /// Returns a boolean vector s where s[i] = true if i is in projection_indices
    /// This is used in projective Logup lemma
    pub fn create_selector_vector(&self) -> Vec<bool> {
        let mut selector = vec![false; self.witness_size];
        for &i in &self.projection_indices {
            selector[i] = true;
        }
        selector
    }

    /// Create a field selector vector (0/1 instead of false/true)
    pub fn create_field_selector_vector(&self) -> Vec<F> {
        self.create_selector_vector()
            .into_iter()
            .map(|b| if b { F::ONE } else { F::ZERO })
            .collect()
    }
}

/// Projective lookup relation
///
/// Verifies that only the projected indices of the witness are in the table.
/// Non-projected indices can contain arbitrary values.
#[derive(Debug, Clone)]
pub struct ProjectiveLookup<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> ProjectiveLookup<F> {
    /// Create a new projective lookup relation
    pub fn new() -> Self {
        ProjectiveLookup {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> Default for ProjectiveLookup<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> LookupRelation<F> for ProjectiveLookup<F> {
    type Index = ProjectiveLookupIndex<F>;
    type Witness = Vec<F>;

    fn verify(&self, index: &Self::Index, witness: &Self::Witness) -> bool {
        // Check witness size matches expected size
        if witness.len() != index.witness_size {
            return false;
        }

        // Check only projected indices are in table
        index
            .projection_indices
            .iter()
            .all(|&i| index.base_index.contains(witness[i]))
    }

    fn verify_detailed(
        &self,
        index: &Self::Index,
        witness: &Self::Witness,
    ) -> LookupResult<()> {
        // Check witness size
        if witness.len() != index.witness_size {
            return Err(LookupError::InvalidIndexSize {
                expected: index.witness_size,
                got: witness.len(),
            });
        }

        // Check each projected index
        for &i in &index.projection_indices {
            let w_i = witness[i];
            if !index.base_index.contains(w_i) {
                return Err(LookupError::WitnessNotInTable {
                    witness_index: i,
                    value: format!("{:?}", w_i),
                });
            }
        }

        Ok(())
    }
}

/// Utilities for projective lookups
pub struct ProjectiveUtils;

impl ProjectiveUtils {
    /// Compute the projective ratio
    ///
    /// The projective ratio is the proportion of witness elements that are checked.
    /// This is important for determining if lookup arguments provide efficiency gains.
    /// For very small projective ratios, the overhead may exceed the benefit.
    pub fn compute_projective_ratio(num_projections: usize, witness_size: usize) -> f64 {
        if witness_size == 0 {
            0.0
        } else {
            num_projections as f64 / witness_size as f64
        }
    }

    /// Check if projective lookup is worthwhile
    ///
    /// Returns true if the projective ratio is substantial enough to justify
    /// the overhead of lookup arguments
    pub fn is_worthwhile(num_projections: usize, witness_size: usize) -> bool {
        let ratio = Self::compute_projective_ratio(num_projections, witness_size);
        // Heuristic: worthwhile if at least 10% of witness is checked
        ratio >= 0.1
    }

    /// Validate projection indices ordering
    pub fn validate_projection_indices(indices: &[usize], witness_size: usize) -> LookupResult<()> {
        if indices.is_empty() {
            return Err(LookupError::InvalidProjectionIndices {
                indices: indices.to_vec(),
            });
        }

        // Check all indices are within bounds
        for &i in indices {
            if i >= witness_size {
                return Err(LookupError::InvalidProjectionIndices {
                    indices: indices.to_vec(),
                });
            }
        }

        // Check indices are strictly increasing
        for window in indices.windows(2) {
            if window[0] >= window[1] {
                return Err(LookupError::InvalidProjectionIndices {
                    indices: indices.to_vec(),
                });
            }
        }

        Ok(())
    }

    /// Merge multiple projection index sets
    ///
    /// Useful when composing multiple projective lookups
    pub fn merge_projection_indices(indices_sets: &[Vec<usize>]) -> Vec<usize> {
        let mut merged: Vec<usize> = indices_sets.iter().flatten().copied().collect();
        merged.sort_unstable();
        merged.dedup();
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_projective_index_validation() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);

        // Valid projective index
        let proj_index = ProjectiveLookupIndex::new(base_index.clone(), 5, vec![1, 3]);
        assert!(proj_index.is_valid());

        // Invalid: projection indices not sorted
        let invalid_proj1 = ProjectiveLookupIndex::new(base_index.clone(), 5, vec![3, 1]);
        assert!(!invalid_proj1.is_valid());

        // Invalid: projection index out of bounds
        let invalid_proj2 = ProjectiveLookupIndex::new(base_index.clone(), 5, vec![1, 5]);
        assert!(!invalid_proj2.is_valid());

        // Invalid: wrong number of projection indices
        let invalid_proj3 = ProjectiveLookupIndex::new(base_index.clone(), 5, vec![1, 2, 3]);
        assert!(!invalid_proj3.is_valid());
    }

    #[test]
    fn test_projective_lookup_valid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);

        // Witness: [10, 2, 20, 4, 30]
        // Only indices 1 and 3 should be checked (values 2 and 4)
        let witness = vec![
            F::from(10),
            F::from(2),
            F::from(20),
            F::from(4),
            F::from(30),
        ];
        let proj_index = ProjectiveLookupIndex::new(base_index, 5, vec![1, 3]);

        let lookup = ProjectiveLookup::new();
        assert!(lookup.verify(&proj_index, &witness));
        assert!(lookup.verify_detailed(&proj_index, &witness).is_ok());
    }

    #[test]
    fn test_projective_lookup_invalid() {
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);

        // Witness: [10, 6, 20, 4, 30]
        // Index 1 has value 6 which is not in table
        let witness = vec![
            F::from(10),
            F::from(6),
            F::from(20),
            F::from(4),
            F::from(30),
        ];
        let proj_index = ProjectiveLookupIndex::new(base_index, 5, vec![1, 3]);

        let lookup = ProjectiveLookup::new();
        assert!(!lookup.verify(&proj_index, &witness));

        let result = lookup.verify_detailed(&proj_index, &witness);
        assert!(result.is_err());
        match result {
            Err(LookupError::WitnessNotInTable { witness_index, .. }) => {
                assert_eq!(witness_index, 1);
            }
            _ => panic!("Expected WitnessNotInTable error"),
        }
    }

    #[test]
    fn test_extract_projected_witness() {
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 3, table);

        let witness = vec![
            F::from(10),
            F::from(1),
            F::from(20),
            F::from(2),
            F::from(30),
            F::from(3),
        ];
        let proj_index = ProjectiveLookupIndex::new(base_index, 6, vec![1, 3, 5]);

        let projected = proj_index.extract_projected_witness(&witness);
        assert_eq!(projected, vec![F::from(1), F::from(2), F::from(3)]);
    }

    #[test]
    fn test_selector_vector() {
        let table = vec![F::from(1), F::from(2)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);

        let proj_index = ProjectiveLookupIndex::new(base_index, 5, vec![1, 3]);

        let selector = proj_index.create_selector_vector();
        assert_eq!(selector, vec![false, true, false, true, false]);

        let field_selector = proj_index.create_field_selector_vector();
        assert_eq!(
            field_selector,
            vec![F::ZERO, F::ONE, F::ZERO, F::ONE, F::ZERO]
        );
    }

    #[test]
    fn test_is_projected() {
        let table = vec![F::from(1), F::from(2)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 2, table);

        let proj_index = ProjectiveLookupIndex::new(base_index, 5, vec![1, 3]);

        assert!(!proj_index.is_projected(0));
        assert!(proj_index.is_projected(1));
        assert!(!proj_index.is_projected(2));
        assert!(proj_index.is_projected(3));
        assert!(!proj_index.is_projected(4));
    }

    #[test]
    fn test_projective_ratio() {
        assert_eq!(ProjectiveUtils::compute_projective_ratio(2, 10), 0.2);
        assert_eq!(ProjectiveUtils::compute_projective_ratio(5, 10), 0.5);
        assert_eq!(ProjectiveUtils::compute_projective_ratio(0, 10), 0.0);
        assert_eq!(ProjectiveUtils::compute_projective_ratio(10, 10), 1.0);
    }

    #[test]
    fn test_is_worthwhile() {
        assert!(ProjectiveUtils::is_worthwhile(2, 10)); // 20% ratio
        assert!(!ProjectiveUtils::is_worthwhile(1, 100)); // 1% ratio
        assert!(ProjectiveUtils::is_worthwhile(10, 100)); // 10% ratio (boundary)
    }

    #[test]
    fn test_validate_projection_indices() {
        // Valid
        assert!(ProjectiveUtils::validate_projection_indices(&[0, 2, 4], 10).is_ok());

        // Invalid: empty
        assert!(ProjectiveUtils::validate_projection_indices(&[], 10).is_err());

        // Invalid: out of bounds
        assert!(ProjectiveUtils::validate_projection_indices(&[0, 2, 10], 10).is_err());

        // Invalid: not sorted
        assert!(ProjectiveUtils::validate_projection_indices(&[2, 0, 4], 10).is_err());

        // Invalid: duplicates
        assert!(ProjectiveUtils::validate_projection_indices(&[0, 2, 2, 4], 10).is_err());
    }

    #[test]
    fn test_merge_projection_indices() {
        let set1 = vec![1, 3, 5];
        let set2 = vec![2, 3, 6];
        let set3 = vec![0, 5, 7];

        let merged = ProjectiveUtils::merge_projection_indices(&[set1, set2, set3]);
        assert_eq!(merged, vec![0, 1, 2, 3, 5, 6, 7]);
    }

    #[test]
    fn test_projective_lookup_all_indices() {
        // Edge case: project all indices (equivalent to standard lookup)
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 3, table);

        let witness = vec![F::from(2), F::from(1), F::from(3)];
        let proj_index = ProjectiveLookupIndex::new(base_index, 3, vec![0, 1, 2]);

        let lookup = ProjectiveLookup::new();
        assert!(lookup.verify(&proj_index, &witness));
    }

    #[test]
    fn test_projective_lookup_single_index() {
        // Edge case: project single index
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let finite_set = FiniteSet::from_vec(table.clone());
        let base_index = LookupIndex::new(finite_set, 1, table);

        let witness = vec![F::from(99), F::from(2), F::from(88)];
        let proj_index = ProjectiveLookupIndex::new(base_index, 3, vec![1]);

        let lookup = ProjectiveLookup::new();
        assert!(lookup.verify(&proj_index, &witness));
    }
}
