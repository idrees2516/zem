// Lasso: Lookup Arguments for Structured and Decomposable Tables
//
// This module implements Lasso, a highly efficient lookup argument that achieves
// prover complexity O(N+n) for structured tables and O(cn) for decomposable tables,
// where c is the decomposition factor. Lasso is particularly powerful for massive
// tables (e.g., 2^128) that cannot be materialized.
//
// Core Idea:
// Model lookup as matrix-vector multiplication: M_{n×N} × t_{N×1} = w_{n×1}
// where M is an elementary matrix. Use multilinear extension (MLE) and sumcheck
// to verify the identity efficiently.
//
// Mathematical Foundation:
// - Lookup relation: w ⊆ t
// - Matrix representation: M[i,j] = 1 if w_i = t_j, else 0
// - MLE identity: Σ_{y∈{0,1}^{log N}} M̃(r, y) · t̃(y) = w̃(r) for random r
// - Sumcheck protocol: Reduce to evaluations of M̃, t̃, w̃
// - Spark commitment: Commit to sparse M̃ in O(n) time
//
// Key Innovations:
// 1. Structured tables: Tables with efficiently computable MLEs
//    - Verifier can evaluate t̃ directly without commitment
//    - Prover cost: O(N+n) independent of table complexity
//
// 2. Decomposable tables: Large tables split into smaller subtables
//    - Reduce 2^128 table to multiple 2^32 tables
//    - Prover cost: O(cn) where c is decomposition factor
//    - Enables massive table support
//
// 3. Sparse matrix commitment: Use Spark for M̃
//    - Only n non-zero entries in n×N matrix
//    - Commitment time: O(n) independent of N
//
// Performance:
// - Structured tables: O(N+n) prover, O(log^2 n) verifier
// - Decomposable tables: O(cn) prover, O(c log^2 n) verifier
// - No preprocessing required
// - Supports non-homomorphic PCS (hash-based, FRI)
//
// Comparison:
// - cq: O(n log n) prover, requires preprocessing
// - Lasso: O(N+n) or O(cn) prover, no preprocessing
// - Lasso ideal for structured/decomposable tables
//
// References:
// - Lasso paper: Section 7.2 of SoK
// - Structured tables: Section 7.2.3
// - Decomposable tables: Section 7.2.4
// - Spark integration: Section 7.1

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use crate::lookup::mle::MultilinearPolynomial;
use crate::lookup::spark::{SparseMultilinearPolynomial, SparseEntry, SparkCommitmentScheme, SparkCommitment};
use crate::lookup::decomposition::DecomposableTable;
use std::marker::PhantomData;

/// Elementary Matrix for Lasso
///
/// Represents the n×N matrix M where M[i,j] = 1 if w_i = t_j, else 0.
/// Stored in sparse format as {(row_i, col_i, val_i)} for non-zero entries.
///
/// # Properties:
/// - Elementary: each row has exactly one 1
/// - Sparse: only n non-zero entries
/// - Row indices: [0, n) (consecutive)
/// - Column indices: arbitrary in [0, N)
/// - Values: all 1
#[derive(Debug, Clone)]
pub struct LassoElementaryMatrix<F: Field> {
    /// Number of rows (witness size)
    pub num_rows: usize,
    /// Number of columns (table size)
    pub num_cols: usize,
    /// Sparse entries: (row, col, value)
    pub entries: Vec<(usize, usize, F)>,
}

impl<F: Field> LassoElementaryMatrix<F> {
    /// Create elementary matrix from witness and table
    ///
    /// # Arguments:
    /// - `witness`: Witness vector w
    /// - `table`: Table vector t
    ///
    /// # Returns:
    /// Elementary matrix M where M × t = w
    ///
    /// # Complexity: O(n log N) with hash table
    pub fn from_witness_and_table(witness: &[F], table: &[F]) -> LookupResult<Self> {
        let num_rows = witness.len();
        let num_cols = table.len();

        // Build hash map for O(1) lookup
        let mut table_map = std::collections::HashMap::new();
        for (idx, &val) in table.iter().enumerate() {
            table_map.entry(val).or_insert_with(Vec::new).push(idx);
        }

        // Construct sparse entries
        let mut entries = Vec::with_capacity(num_rows);

        for (row, &w_i) in witness.iter().enumerate() {
            let col_indices = table_map.get(&w_i)
                .ok_or_else(|| LookupError::WitnessNotInTable {
                    witness_index: row,
                    value: format!("{:?}", w_i),
                })?;

            // Use first occurrence (any would work)
            let col = col_indices[0];
            entries.push((row, col, F::ONE));
        }

        Ok(LassoElementaryMatrix {
            num_rows,
            num_cols,
            entries,
        })
    }

    /// Verify matrix is elementary
    ///
    /// Checks:
    /// 1. Row indices are [0, n)
    /// 2. Each row appears exactly once
    /// 3. All values are 1
    pub fn is_elementary(&self) -> bool {
        // Check all values are 1
        if !self.entries.iter().all(|(_, _, v)| *v == F::ONE) {
            return false;
        }

        // Check row indices are [0, n) and each appears once
        let mut row_seen = vec![false; self.num_rows];
        for &(row, _, _) in &self.entries {
            if row >= self.num_rows || row_seen[row] {
                return false;
            }
            row_seen[row] = true;
        }

        row_seen.iter().all(|&seen| seen)
    }

    /// Convert to sparse multilinear polynomial
    ///
    /// Represents M̃ as sparse MLE over {0,1}^{log n + log N}
    ///
    /// # Complexity: O(n)
    pub fn to_sparse_mle(&self) -> LookupResult<SparseMultilinearPolynomial<F>> {
        let log_rows = (self.num_rows as f64).log2().ceil() as usize;
        let log_cols = (self.num_cols as f64).log2().ceil() as usize;
        let num_vars = log_rows + log_cols;

        let mut sparse_entries = Vec::with_capacity(self.entries.len());

        for &(row, col, val) in &self.entries {
            // Convert (row, col) to binary position
            let mut position = Vec::with_capacity(num_vars);
            
            // Row bits
            for i in 0..log_rows {
                position.push((row >> i) & 1 == 1);
            }
            
            // Column bits
            for i in 0..log_cols {
                position.push((col >> i) & 1 == 1);
            }

            sparse_entries.push(SparseEntry::new(position, val));
        }

        SparseMultilinearPolynomial::new(sparse_entries, num_vars)
    }
}

