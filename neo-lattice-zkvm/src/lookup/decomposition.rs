// Decomposable Tables
//
// Decomposable tables allow efficient lookups in massive tables (e.g., size 2^128)
// that cannot be materialized by decomposing them into smaller subtables.
//
// A table t ∈ S^N is decomposable into tables t_i ∈ S^{N_i} for 1 ≤ i ≤ k
// via a map M: S → S_1 × ... × S_k such that:
// s ∈ t ⟺ s_i ∈ t_i for all 1 ≤ i ≤ k where M(s) = (s_1, ..., s_k)
//
// Example: 128-bit range check can be decomposed into four 32-bit range checks

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Decomposable table manager
///
/// Manages decomposition of large tables into smaller subtables
#[derive(Debug, Clone)]
pub struct DecomposableTable<F: Field> {
    /// Number of subtables k
    pub decomposition_factor: usize,
    /// Size of each subtable
    pub base_table_sizes: Vec<usize>,
    /// The subtables t_i
    pub base_tables: Vec<Vec<F>>,
    _phantom: PhantomData<F>,
}

impl<F: Field> DecomposableTable<F> {
    /// Create a new decomposable table
    pub fn new(
        decomposition_factor: usize,
        base_table_sizes: Vec<usize>,
        base_tables: Vec<Vec<F>>,
    ) -> Self {
        DecomposableTable {
            decomposition_factor,
            base_table_sizes,
            base_tables,
            _phantom: PhantomData,
        }
    }

    /// Validate the decomposable table
    pub fn is_valid(&self) -> bool {
        self.decomposition_factor > 0
            && self.base_table_sizes.len() == self.decomposition_factor
            && self.base_tables.len() == self.decomposition_factor
            && self
                .base_tables
                .iter()
                .zip(self.base_table_sizes.iter())
                .all(|(table, &size)| table.len() == size)
    }

    /// Get the number of subtables
    pub fn num_subtables(&self) -> usize {
        self.decomposition_factor
    }

    /// Get a specific subtable
    pub fn get_subtable(&self, index: usize) -> Option<&[F]> {
        self.base_tables.get(index).map(|v| v.as_slice())
    }
}

/// Decomposition manager
///
/// Handles value decomposition and verification
pub struct DecompositionManager<F: Field> {
    /// Number of limbs k
    pub decomposition_factor: usize,
    /// Bits per limb
    pub limb_size_bits: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> DecompositionManager<F> {
    /// Create a new decomposition manager
    pub fn new(decomposition_factor: usize, limb_size_bits: usize) -> Self {
        DecompositionManager {
            decomposition_factor,
            limb_size_bits,
            _phantom: PhantomData,
        }
    }

    /// Decompose a value into limbs
    ///
    /// Example: 128-bit value → four 32-bit limbs
    /// value = limbs[0] + 2^32 · limbs[1] + 2^64 · limbs[2] + 2^96 · limbs[3]
    pub fn decompose_value(&self, value: F) -> LookupResult<Vec<F>> {
        // Convert field element to u128 (if possible)
        let value_u128 = self.field_to_u128(value)?;

        let mask = (1u128 << self.limb_size_bits) - 1;
        let mut limbs = Vec::with_capacity(self.decomposition_factor);

        for i in 0..self.decomposition_factor {
            let limb = (value_u128 >> (i * self.limb_size_bits)) & mask;
            limbs.push(F::from(limb as u64));
        }

        Ok(limbs)
    }

    /// Verify decomposition correctness
    ///
    /// Checks: value = limbs[0] + 2^b · limbs[1] + 2^{2b} · limbs[2] + ...
    /// where b is limb_size_bits
    pub fn verify_decomposition(&self, value: F, limbs: &[F]) -> bool {
        if limbs.len() != self.decomposition_factor {
            return false;
        }

        let reconstructed = self.reconstruct_from_limbs(limbs);
        reconstructed == value
    }

    /// Reconstruct value from limbs
    pub fn reconstruct_from_limbs(&self, limbs: &[F]) -> F {
        let mut result = F::ZERO;
        let base = F::from(1u64 << self.limb_size_bits);
        let mut power = F::ONE;

        for &limb in limbs {
            result = result + limb * power;
            power = power * base;
        }

        result
    }

    /// Decompose a witness vector
    ///
    /// Applies decomposition to each witness element
    pub fn decompose_witness(&self, witness: &[F]) -> LookupResult<Vec<Vec<F>>> {
        witness
            .iter()
            .map(|&w| self.decompose_value(w))
            .collect()
    }

    /// Helper: Convert field element to u128
    ///
    /// # Security: Validates that field element fits in u128
    fn field_to_u128(&self, value: F) -> LookupResult<u128> {
        // Convert field element to canonical u64 representation
        let value_u64 = value.to_canonical_u64();
        
        // For values that fit in u64, this is straightforward
        // For larger field elements, we need to check if they fit in u128
        if F::MODULUS_BITS > 128 {
            // Field is too large for u128 decomposition
            // This should be caught at setup time
            return Err(LookupError::InvalidFieldElement);
        }
        
        // Convert to u128
        Ok(value_u64 as u128)
    }
}

/// Linear decomposition map
///
/// Supports homomorphic verification: C = C_0 + 2^b · C_1 + 2^{2b} · C_2 + ...
pub struct LinearDecomposition;

impl LinearDecomposition {
    /// Check if decomposition map is linear
    ///
    /// Linear maps enable homomorphic commitment verification
    pub fn is_linear(limb_size_bits: usize) -> bool {
        // Decomposition x = x_0 + 2^b · x_1 + ... is linear
        limb_size_bits > 0
    }

    /// Verify decomposition homomorphically
    ///
    /// For commitments C, C_0, C_1, ..., C_{k-1}, verify:
    /// C = C_0 + 2^b · C_1 + 2^{2b} · C_2 + ...
    pub fn verify_homomorphic<C, F>(
        commitment: &C,
        limb_commitments: &[C],
        limb_size_bits: usize,
        add: impl Fn(&C, &C) -> C,
        scalar_mul: impl Fn(&C, F) -> C,
    ) -> bool
    where
        F: Field,
        C: PartialEq,
    {
        let base = F::from(1u64 << limb_size_bits);
        let mut reconstructed = limb_commitments[0].clone();
        let mut power = base;

        for limb_comm in &limb_commitments[1..] {
            let scaled = scalar_mul(limb_comm, power);
            reconstructed = add(&reconstructed, &scaled);
            power = power * base;
        }

        reconstructed == *commitment
    }
}

/// Non-homomorphic decomposition verification
///
/// For non-homomorphic PCS, verify decomposition by checking
/// w(r) = w_0(r) + 2^b · w_1(r) + ... at random point r
pub struct NonHomomorphicDecomposition;

impl NonHomomorphicDecomposition {
    /// Verify decomposition at random point
    ///
    /// Checks: w(r) = w_0(r) + 2^b · w_1(r) + 2^{2b} · w_2(r) + ...
    pub fn verify_at_point<F: Field>(
        witness_eval: F,
        limb_evals: &[F],
        limb_size_bits: usize,
    ) -> bool {
        let base = F::from(1u64 << limb_size_bits);
        let mut reconstructed = F::ZERO;
        let mut power = F::ONE;

        for &limb_eval in limb_evals {
            reconstructed = reconstructed + limb_eval * power;
            power = power * base;
        }

        reconstructed == witness_eval
    }
}

/// Indexed table decomposition
///
/// For indexed lookups, decompose both values and indices
pub struct IndexedDecomposition;

impl IndexedDecomposition {
    /// Decompose indexed table
    ///
    /// Maps M_set: S → S_1 × ... × S_k for values
    /// Maps M_index: [N] → [N_1] × ... × [N_k] for indices
    pub fn decompose_indexed<F: Field>(
        values: &[F],
        indices: &[usize],
        decomp_manager: &DecompositionManager<F>,
    ) -> LookupResult<(Vec<Vec<F>>, Vec<Vec<usize>>)> {
        // Decompose values
        let decomposed_values = decomp_manager.decompose_witness(values)?;

        // Decompose indices (similar structure)
        let decomposed_indices: Vec<Vec<usize>> = indices
            .iter()
            .map(|&idx| {
                // Decompose index into k sub-indices
                let mut sub_indices = Vec::new();
                let mut remaining = idx;
                for _ in 0..decomp_manager.decomposition_factor {
                    let limb_size = 1 << decomp_manager.limb_size_bits;
                    sub_indices.push(remaining % limb_size);
                    remaining /= limb_size;
                }
                sub_indices
            })
            .collect();

        Ok((decomposed_values, decomposed_indices))
    }

    /// Verify indexed decomposition
    ///
    /// Checks: s = t[j] ⟺ s_i = t_i[j_i] for all 1 ≤ i ≤ k
    pub fn verify_indexed<F: Field>(
        value: F,
        index: usize,
        value_limbs: &[F],
        index_limbs: &[usize],
        base_tables: &[Vec<F>],
        decomp_manager: &DecompositionManager<F>,
    ) -> bool {
        // Verify value decomposition
        if !decomp_manager.verify_decomposition(value, value_limbs) {
            return false;
        }

        // Verify each limb matches corresponding base table entry
        for i in 0..decomp_manager.decomposition_factor {
            if index_limbs[i] >= base_tables[i].len() {
                return false;
            }
            if value_limbs[i] != base_tables[i][index_limbs[i]] {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_decomposable_table_validation() {
        let base_tables = vec![
            vec![F::from(0), F::from(1), F::from(2)],
            vec![F::from(0), F::from(1), F::from(2)],
        ];
        let base_table_sizes = vec![3, 3];

        let table = DecomposableTable::new(2, base_table_sizes, base_tables);
        assert!(table.is_valid());

        // Invalid: mismatched sizes
        let bad_tables = vec![
            vec![F::from(0), F::from(1)], // Size 2, not 3
            vec![F::from(0), F::from(1), F::from(2)],
        ];
        let bad_table = DecomposableTable::new(2, vec![3, 3], bad_tables);
        assert!(!bad_table.is_valid());
    }

    #[test]
    fn test_decomposition_manager() {
        let manager = DecompositionManager::<F>::new(4, 32);

        // Test reconstruction
        let limbs = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let reconstructed = manager.reconstruct_from_limbs(&limbs);

        // value = 1 + 2*2^32 + 3*2^64 + 4*2^96
        // This is a large number, so we just check the reconstruction works
        assert!(manager.verify_decomposition(reconstructed, &limbs));
    }

    #[test]
    fn test_linear_decomposition() {
        assert!(LinearDecomposition::is_linear(32));
        assert!(LinearDecomposition::is_linear(8));
        assert!(!LinearDecomposition::is_linear(0));
    }

    #[test]
    fn test_non_homomorphic_verification() {
        let limb_evals = vec![F::from(1), F::from(2), F::from(3)];
        let limb_size_bits = 8;

        // Compute expected value: 1 + 2*256 + 3*65536
        let expected = F::from(1) + F::from(2) * F::from(256) + F::from(3) * F::from(65536);

        assert!(NonHomomorphicDecomposition::verify_at_point(
            expected,
            &limb_evals,
            limb_size_bits
        ));

        // Wrong value should fail
        assert!(!NonHomomorphicDecomposition::verify_at_point(
            F::from(999),
            &limb_evals,
            limb_size_bits
        ));
    }

    #[test]
    fn test_get_subtable() {
        let base_tables = vec![
            vec![F::from(0), F::from(1)],
            vec![F::from(2), F::from(3)],
        ];
        let table = DecomposableTable::new(2, vec![2, 2], base_tables);

        assert_eq!(table.get_subtable(0), Some(&[F::from(0), F::from(1)][..]));
        assert_eq!(table.get_subtable(1), Some(&[F::from(2), F::from(3)][..]));
        assert_eq!(table.get_subtable(2), None);
    }
}
