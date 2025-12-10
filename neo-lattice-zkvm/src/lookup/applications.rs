// Lookup Argument Applications
//
// This module implements common applications of lookup arguments for zkVMs:
// - Non-native operations (bit decomposition, range proofs, comparisons)
// - Set membership proofs
// - Memory correctness checking
// - Hash function optimizations
//
// # Design Philosophy
//
// Lookup arguments enable efficient enforcement of non-native operations by:
// 1. Precomputing operation results in lookup tables
// 2. Proving witness values match table entries
// 3. Avoiding expensive circuit constraints
//
// # Performance Considerations
//
// - Small tables (< 2^16): Use any lookup scheme
// - Medium tables (2^16 - 2^24): Prefer table-efficient schemes (cq, Lasso)
// - Large tables (> 2^24): Use decomposition or st

impl<F: Field> Default for Applications<F> {
    fn default() -> Self {
        Self::new()
    }
}
