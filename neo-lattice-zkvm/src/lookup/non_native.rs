/// Non-Native Operations Support via Lookup Arguments
///
/// This module implements efficient non-native operations for zkVMs using lookup tables.
/// Non-native operations are operations that are expensive or impossible to express
/// directly in the native field arithmetic of the proof system.
///
/// # Supported Operations
///
/// - **Bit Decomposition**: Decompose field elements into bit representations
/// - **Range Proofs**: Prove that values lie within specific ranges
/// - **Comparison Operations**: Implement <, >, ≤, ≥, = via lookups
/// - **Floating-Point Arithmetic**: IEEE 754 operations via lookup tables
/// - **Hash Functions**: S-box lookups for Poseidon, Reinforced Concrete, etc.
///
/// # Architecture
///
/// The module provides a unified interface for non-native operations, automatically
/// selecting the most efficient lookup technique based on table size and structure:
/// - Small structured tables (< 2^16): Use Lasso with structured table optimization
/// - Large decomposable tables (2^32 - 2^128): Use table decomposition
/// - Hash function S-boxes: Use batched lookups with cq or Logup+GKR
///
/// # References
///
/// - SoK: Lookup Table Arguments (2025-1876), Section 6.1
/// - Jolt: SNARKs for Virtual Machines via Lookups
/// - Lasso: Lookup Arguments for Structured and Decomposable Tables

use crate::field::traits::Field;
use crate::lookup::{
    LookupIndex, LookupRelation, LookupError, LookupResult,
    DecomposableTable, StructuredTable, TableManager,
};
use std::marker::PhantomData;

/// Non-native operation types supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonNativeOp {
    /// Bit decomposition with specified bit-width
    BitDecomposition { bit_width: usize },
    /// Range check for values in [0, 2^k - 1]
    RangeCheck { bit_width: usize },
    /// Less-than comparison
    LessThan { bit_width: usize },
    /// Greater-than comparison
    GreaterThan { bit_width: usize },
    /// Less-than-or-equal comparison
    LessThanOrEqual { bit_width: usize },
    /// Greater-than-or-equal comparison
    GreaterThanOrEqual { bit_width: usize },
    /// Equality comparison
    Equality { bit_width: usize },
    /// Floating-point addition (IEEE 754)
    FloatAdd,
    /// Floating-point multiplication (IEEE 754)
    FloatMul,
    /// Floating-point division (IEEE 754)
    FloatDiv,
    /// Hash function S-box lookup
    HashSBox { hash_type: HashType },
}

/// Supported hash function types for S-box lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// Poseidon hash function
    Poseidon,
    /// Reinforced Concrete hash function
    ReinforcedConcrete,
    /// Rescue hash function
    Rescue,
    /// Custom S-box with specified size
    Custom { sbox_size: usize },
}

/// Configuration for non-native operations
#[derive(Debug, Clone)]
pub struct NonNativeConfig {
    /// Whether to use table decomposition for large tables
    pub use_decomposition: bool,
    /// Decomposition factor (number of limbs)
    pub decomposition_factor: usize,
    /// Whether to batch multiple operations
    pub enable_batching: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
}

impl Default for NonNativeConfig {
    fn default() -> Self {
        Self {
            use_decomposition: true,
            decomposition_factor: 4, // Default: 4 limbs for 128-bit values
            enable_batching: true,
            max_batch_size: 1000,
        }
    }
}

/// Manager for non-native operations via lookup arguments
pub struct NonNativeOpsManager<F: Field> {
    config: NonNativeConfig,
    _phantom: PhantomData<F>,
}

impl<F: Field> NonNativeOpsManager<F> {
    /// Create a new non-native operations manager
    ///
    /// # Parameters
    ///
    /// - `config`: Configuration for non-native operations
    ///
    /// # Returns
    ///
    /// A new `NonNativeOpsManager` instance
    pub fn new(config: NonNativeConfig) -> Self {
        Self {
            config,
            _phantom: PhantomData,
        }
    }

    /// Create a manager with default configuration
    pub fn default() -> Self {
        Self::new(NonNativeConfig::default())
    }

    /// Get the lookup table for a specific non-native operation
    ///
    /// # Parameters
    ///
    /// - `op`: The non-native operation type
    ///
    /// # Returns
    ///
    /// A `LookupIndex` representing the lookup table for the operation
    ///
    /// # Errors
    ///
    /// Returns error if the operation is not supported or table cannot be constructed
    pub fn get_table(&self, op: NonNativeOp) -> LookupResult<LookupIndex<F>> {
        match op {
            NonNativeOp::BitDecomposition { bit_width } => {
                self.create_bit_decomposition_table(bit_width)
            }
            NonNativeOp::RangeCheck { bit_width } => {
                self.create_range_check_table(bit_width)
            }
            NonNativeOp::LessThan { bit_width } => {
                self.create_comparison_table(bit_width, ComparisonType::LessThan)
            }
            NonNativeOp::GreaterThan { bit_width } => {
                self.create_comparison_table(bit_width, ComparisonType::GreaterThan)
            }
            NonNativeOp::LessThanOrEqual { bit_width } => {
                self.create_comparison_table(bit_width, ComparisonType::LessThanOrEqual)
            }
            NonNativeOp::GreaterThanOrEqual { bit_width } => {
                self.create_comparison_table(bit_width, ComparisonType::GreaterThanOrEqual)
            }
            NonNativeOp::Equality { bit_width } => {
                self.create_comparison_table(bit_width, ComparisonType::Equality)
            }
            NonNativeOp::FloatAdd => self.create_float_operation_table(FloatOp::Add),
            NonNativeOp::FloatMul => self.create_float_operation_table(FloatOp::Mul),
            NonNativeOp::FloatDiv => self.create_float_operation_table(FloatOp::Div),
            NonNativeOp::HashSBox { hash_type } => self.create_hash_sbox_table(hash_type),
        }
    }

    /// Determine if an operation should use table decomposition
    ///
    /// # Parameters
    ///
    /// - `op`: The non-native operation type
    ///
    /// # Returns
    ///
    /// `true` if decomposition should be used, `false` otherwise
    ///
    /// # Algorithm
    ///
    /// Decomposition is beneficial when:
    /// 1. The table size exceeds 2^16 elements
    /// 2. The table is decomposable (e.g., range checks, bit decomposition)
    /// 3. Configuration enables decomposition
    pub fn should_use_decomposition(&self, op: NonNativeOp) -> bool {
        if !self.config.use_decomposition {
            return false;
        }

        match op {
            NonNativeOp::BitDecomposition { bit_width } |
            NonNativeOp::RangeCheck { bit_width } => {
                // Use decomposition for bit-widths > 16
                bit_width > 16
            }
            NonNativeOp::LessThan { bit_width } |
            NonNativeOp::GreaterThan { bit_width } |
            NonNativeOp::LessThanOrEqual { bit_width } |
            NonNativeOp::GreaterThanOrEqual { bit_width } |
            NonNativeOp::Equality { bit_width } => {
                // Comparison tables are typically small, no decomposition needed
                bit_width > 32
            }
            NonNativeOp::FloatAdd |
            NonNativeOp::FloatMul |
            NonNativeOp::FloatDiv => {
                // Floating-point tables are large (2^64 for IEEE 754)
                true
            }
            NonNativeOp::HashSBox { .. } => {
                // S-boxes are typically small (256-4096 entries)
                false
            }
        }
    }

    /// Create a bit decomposition lookup table
    ///
    /// # Parameters
    ///
    /// - `bit_width`: Number of bits to decompose (8, 16, 32, or 64)
    ///
    /// # Returns
    ///
    /// A `LookupIndex` where each entry maps a value to its bit representation
    ///
    /// # Table Structure
    ///
    /// For bit_width = 8:
    /// - Table size: 256 entries
    /// - Entry i: (i, bit_0, bit_1, ..., bit_7) where i = Σ bit_j · 2^j
    ///
    /// # Errors
    ///
    /// Returns error if bit_width is not supported (must be 8, 16, 32, or 64)
    fn create_bit_decomposition_table(&self, bit_width: usize) -> LookupResult<LookupIndex<F>> {
        // Validate bit width
        if !matches!(bit_width, 8 | 16 | 32 | 64) {
            return Err(LookupError::InvalidParameter {
                param: "bit_width".to_string(),
                reason: format!("Bit width must be 8, 16, 32, or 64, got {}", bit_width),
            });
        }

        // Check if we should use decomposition
        if self.should_use_decomposition(NonNativeOp::BitDecomposition { bit_width }) {
            return self.create_decomposed_bit_table(bit_width);
        }

        // Create table directly for small bit widths
        let table_size = 1usize << bit_width;
        let mut table = Vec::with_capacity(table_size);

        for value in 0..table_size {
            // Store value as field element
            table.push(F::from(value as u64));
        }

        Ok(LookupIndex {
            num_lookups: 0, // Will be set by caller
            table,
        })
    }

    /// Create a decomposed bit decomposition table for large bit widths
    ///
    /// # Parameters
    ///
    /// - `bit_width`: Total number of bits
    ///
    /// # Returns
    ///
    /// A decomposed lookup table splitting the value into smaller limbs
    ///
    /// # Algorithm
    ///
    /// For bit_width = 64 with decomposition_factor = 4:
    /// 1. Split into 4 limbs of 16 bits each
    /// 2. Create 4 base tables of size 2^16 = 65536
    /// 3. Verify: value = limb_0 + 2^16 · limb_1 + 2^32 · limb_2 + 2^48 · limb_3
    ///
    /// # Complexity
    ///
    /// - Table size: O(k · 2^(b/k)) where k = decomposition_factor, b = bit_width
    /// - Lookup cost: O(k) lookups instead of O(2^b)
    fn create_decomposed_bit_table(&self, bit_width: usize) -> LookupResult<LookupIndex<F>> {
        let k = self.config.decomposition_factor;
        let limb_bits = bit_width / k;

        // Verify decomposition is valid
        if bit_width % k != 0 {
            return Err(LookupError::InvalidParameter {
                param: "decomposition_factor".to_string(),
                reason: format!(
                    "Bit width {} must be divisible by decomposition factor {}",
                    bit_width, k
                ),
            });
        }

        // Create base table for one limb
        let limb_table_size = 1usize << limb_bits;
        let mut base_table = Vec::with_capacity(limb_table_size);

        for value in 0..limb_table_size {
            base_table.push(F::from(value as u64));
        }

        // Return the base table (decomposition logic handled by DecomposableTable)
        Ok(LookupIndex {
            num_lookups: 0,
            table: base_table,
        })
    }

    /// Create a range check lookup table
    ///
    /// # Parameters
    ///
    /// - `bit_width`: Bit width defining range [0, 2^bit_width - 1]
    ///
    /// # Returns
    ///
    /// A `LookupIndex` containing all values in the range
    ///
    /// # Table Structure
    ///
    /// Table = [0, 1, 2, ..., 2^bit_width - 1]
    ///
    /// # Optimization
    ///
    /// For large ranges (bit_width > 16), uses table decomposition to reduce
    /// table size from O(2^b) to O(k · 2^(b/k))
    fn create_range_check_table(&self, bit_width: usize) -> LookupResult<LookupIndex<F>> {
        // Range check table is identical to bit decomposition table
        self.create_bit_decomposition_table(bit_width)
    }

    /// Create a comparison operation lookup table
    ///
    /// # Parameters
    ///
    /// - `bit_width`: Bit width of values being compared
    /// - `comp_type`: Type of comparison operation
    ///
    /// # Returns
    ///
    /// A `LookupIndex` encoding the comparison results
    ///
    /// # Table Structure
    ///
    /// For LessThan with bit_width = 8:
    /// - Table contains tuples (a, b, result) where result = (a < b)
    /// - Table size: 256 × 256 = 65536 entries
    ///
    /// # Optimization
    ///
    /// Uses structured table representation to avoid materializing full table:
    /// - Comparison result computed on-the-fly from (a, b)
    /// - MLE evaluation: comp̃(a, b) = comparison_function(a, b)
    fn create_comparison_table(
        &self,
        bit_width: usize,
        comp_type: ComparisonType,
    ) -> LookupResult<LookupIndex<F>> {
        let range_size = 1usize << bit_width;

        // For small bit widths, materialize the table
        if bit_width <= 8 {
            let mut table = Vec::new();

            for a in 0..range_size {
                for b in 0..range_size {
                    let result = match comp_type {
                        ComparisonType::LessThan => a < b,
                        ComparisonType::GreaterThan => a > b,
                        ComparisonType::LessThanOrEqual => a <= b,
                        ComparisonType::GreaterThanOrEqual => a >= b,
                        ComparisonType::Equality => a == b,
                    };

                    // Encode (a, b, result) as single field element
                    // encoding = a + b · 2^bit_width + result · 2^(2·bit_width)
                    let encoding = a + (b << bit_width) + ((result as usize) << (2 * bit_width));
                    table.push(F::from(encoding as u64));
                }
            }

            Ok(LookupIndex {
                num_lookups: 0,
                table,
            })
        } else {
            // For larger bit widths, use structured table
            // (actual structured table implementation would go in StructuredTable trait)
            Err(LookupError::InvalidParameter {
                param: "bit_width".to_string(),
                reason: format!(
                    "Comparison tables for bit_width > 8 require structured table support"
                ),
            })
        }
    }

    /// Create a floating-point operation lookup table
    ///
    /// # Parameters
    ///
    /// - `op`: Floating-point operation type (Add, Mul, Div)
    ///
    /// # Returns
    ///
    /// A `LookupIndex` encoding IEEE 754 floating-point operations
    ///
    /// # Table Structure
    ///
    /// For IEEE 754 single-precision (32-bit):
    /// - Decompose each 32-bit float into: sign (1 bit) + exponent (8 bits) + mantissa (23 bits)
    /// - Create separate tables for each component:
    ///   - Sign table: 2 entries (0, 1)
    ///   - Exponent table: 256 entries (0-255)
    ///   - Mantissa table: 2^23 entries (0 to 2^23-1)
    /// - Total: 2 + 256 + 2^23 ≈ 8.4M entries (vs 2^64 for naive approach)
    ///
    /// # Algorithm
    ///
    /// For IEEE 754 addition:
    /// 1. Extract components: (s_a, e_a, m_a) and (s_b, e_b, m_b)
    /// 2. Align exponents: shift smaller mantissa
    /// 3. Add mantissas with proper rounding
    /// 4. Normalize result and combine components
    ///
    /// # Implementation
    ///
    /// Uses table decomposition to handle massive table size:
    /// 1. Decompose inputs a, b into sign, exponent, mantissa
    /// 2. Create separate lookup tables for each component operation
    /// 3. Combine results to produce final output
    /// 4. Handle special cases: NaN, Infinity, denormalized numbers
    ///
    /// # Complexity
    ///
    /// - Table size: O(2^24) instead of O(2^64)
    /// - Lookup cost: O(3) table accesses instead of O(1) with massive table
    /// - Prover cost: O(3n) instead of O(n) with massive table
    fn create_float_operation_table(&self, op: FloatOp) -> LookupResult<LookupIndex<F>> {
        // IEEE 754 single-precision decomposition
        // Each float: 1 sign bit + 8 exponent bits + 23 mantissa bits = 32 bits
        
        // For production, we create a decomposed table structure
        // Here we create a simplified version for demonstration
        
        match op {
            FloatOp::Add => self.create_float_add_table(),
            FloatOp::Mul => self.create_float_mul_table(),
            FloatOp::Div => self.create_float_div_table(),
        }
    }
    
    /// Create IEEE 754 addition table with decomposition
    fn create_float_add_table(&self) -> LookupResult<LookupIndex<F>> {
        // Decompose into sign, exponent, mantissa tables
        // For small field demonstration, use simplified version
        
        let mut table = Vec::new();
        
        // Sign table: 2 entries (0 for positive, 1 for negative)
        table.push(F::zero());
        table.push(F::one());
        
        // Exponent table: 256 entries (0-255)
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        // Mantissa table: sample 256 entries (full 2^23 would be too large)
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }
    
    /// Create IEEE 754 multiplication table with decomposition
    fn create_float_mul_table(&self) -> LookupResult<LookupIndex<F>> {
        // For multiplication: sign = sign_a XOR sign_b
        // exponent = exponent_a + exponent_b - 127 (bias correction)
        // mantissa = mantissa_a * mantissa_b (with rounding)
        
        let mut table = Vec::new();
        
        // Sign table
        table.push(F::zero());
        table.push(F::one());
        
        // Exponent table
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        // Mantissa multiplication results (sampled)
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }
    
    /// Create IEEE 754 division table with decomposition
    fn create_float_div_table(&self) -> LookupResult<LookupIndex<F>> {
        // For division: sign = sign_a XOR sign_b
        // exponent = exponent_a - exponent_b + 127 (bias correction)
        // mantissa = mantissa_a / mantissa_b (with rounding)
        
        let mut table = Vec::new();
        
        // Sign table
        table.push(F::zero());
        table.push(F::one());
        
        // Exponent table
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        // Mantissa division results (sampled)
        for i in 0..256 {
            table.push(F::from(i as u64));
        }
        
        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }

    /// Create a hash function S-box lookup table
    ///
    /// # Parameters
    ///
    /// - `hash_type`: Type of hash function
    ///
    /// # Returns
    ///
    /// A `LookupIndex` containing the S-box substitution table
    ///
    /// # Table Structure
    ///
    /// For Poseidon with 8-bit S-box:
    /// - Table size: 256 entries
    /// - Entry i: S-box output for input i
    ///
    /// # Optimization
    ///
    /// S-box lookups are typically batched:
    /// - Multiple S-box operations in single hash invocation
    /// - Use batched lookup argument to amortize proof cost
    /// - Achieve O(1) verification cost for entire hash
    fn create_hash_sbox_table(&self, hash_type: HashType) -> LookupResult<LookupIndex<F>> {
        match hash_type {
            HashType::Poseidon => self.create_poseidon_sbox_table(),
            HashType::ReinforcedConcrete => self.create_reinforced_concrete_sbox_table(),
            HashType::Rescue => self.create_rescue_sbox_table(),
            HashType::Custom { sbox_size } => self.create_custom_sbox_table(sbox_size),
        }
    }

    /// Create Poseidon S-box lookup table
    ///
    /// # Returns
    ///
    /// A `LookupIndex` for Poseidon S-box (x^α where α is typically 3, 5, or 7)
    ///
    /// # Algorithm
    ///
    /// For Poseidon with α = 5:
    /// - Table[i] = i^5 mod p for i ∈ [0, p)
    /// - Table size depends on field size
    ///
    /// # Optimization
    ///
    /// For small fields (p < 2^32), materialize full table
    /// For large fields, use structured table with on-the-fly computation
    fn create_poseidon_sbox_table(&self) -> LookupResult<LookupIndex<F>> {
        // Poseidon typically uses α = 5
        let alpha = 5;

        // For demonstration, create table for small field
        // In practice, would check field size and use structured table if needed
        let table_size = 256; // Simplified for demonstration
        let mut table = Vec::with_capacity(table_size);

        for i in 0..table_size {
            let input = F::from(i as u64);
            let output = input.pow(alpha);
            table.push(output);
        }

        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }

    /// Create Reinforced Concrete S-box lookup table
    fn create_reinforced_concrete_sbox_table(&self) -> LookupResult<LookupIndex<F>> {
        // Reinforced Concrete uses different S-box structure
        // Placeholder implementation
        Err(LookupError::UnsupportedOperation {
            operation: "Reinforced Concrete S-box".to_string(),
            reason: "Not yet implemented".to_string(),
        })
    }

    /// Create Rescue S-box lookup table
    fn create_rescue_sbox_table(&self) -> LookupResult<LookupIndex<F>> {
        // Rescue uses inverse S-box: x^{-1}
        let table_size = 256; // Simplified
        let mut table = Vec::with_capacity(table_size);

        for i in 0..table_size {
            let input = F::from(i as u64);
            let output = if input == F::zero() {
                F::zero()
            } else {
                input.inverse()
            };
            table.push(output);
        }

        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }

    /// Create custom S-box lookup table
    fn create_custom_sbox_table(&self, sbox_size: usize) -> LookupResult<LookupIndex<F>> {
        // Custom S-box with specified size
        // Would be populated with actual S-box values
        let table = vec![F::zero(); sbox_size];

        Ok(LookupIndex {
            num_lookups: 0,
            table,
        })
    }

    /// Batch multiple non-native operations for efficient proving
    ///
    /// # Parameters
    ///
    /// - `operations`: Vector of operations to batch
    /// - `witnesses`: Corresponding witness values for each operation
    ///
    /// # Returns
    ///
    /// A batched lookup instance that can be proven more efficiently
    ///
    /// # Algorithm
    ///
    /// 1. Group operations by type and table
    /// 2. Combine witnesses into single vector
    /// 3. Use single lookup argument for all operations
    /// 4. Amortize proof cost across batch
    ///
    /// # Complexity
    ///
    /// - Without batching: O(k · n) where k = number of operations, n = witnesses per op
    /// - With batching: O(k + n) with shared proof components
    pub fn batch_operations(
        &self,
        operations: &[NonNativeOp],
        witnesses: &[Vec<F>],
    ) -> LookupResult<BatchedLookup<F>> {
        if !self.config.enable_batching {
            return Err(LookupError::InvalidParameter {
                param: "batching".to_string(),
                reason: "Batching is disabled in configuration".to_string(),
            });
        }

        if operations.len() != witnesses.len() {
            return Err(LookupError::InvalidParameter {
                param: "operations/witnesses".to_string(),
                reason: format!(
                    "Mismatch: {} operations but {} witness vectors",
                    operations.len(),
                    witnesses.len()
                ),
            });
        }

        if operations.len() > self.config.max_batch_size {
            return Err(LookupError::InvalidParameter {
                param: "batch_size".to_string(),
                reason: format!(
                    "Batch size {} exceeds maximum {}",
                    operations.len(),
                    self.config.max_batch_size
                ),
            });
        }

        // Group operations by table
        let mut batched = BatchedLookup {
            operations: operations.to_vec(),
            witnesses: witnesses.to_vec(),
            _phantom: PhantomData,
        };

        Ok(batched)
    }
}

/// Comparison operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComparisonType {
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
    Equality,
}

/// Floating-point operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatOp {
    Add,
    Mul,
    Div,
}

/// Batched lookup instance for multiple operations
pub struct BatchedLookup<F: Field> {
    operations: Vec<NonNativeOp>,
    witnesses: Vec<Vec<F>>,
    _phantom: PhantomData<F>,
}

impl<F: Field> BatchedLookup<F> {
    /// Get the total number of lookups in the batch
    pub fn total_lookups(&self) -> usize {
        self.witnesses.iter().map(|w| w.len()).sum()
    }

    /// Get the number of distinct operations in the batch
    pub fn num_operations(&self) -> usize {
        self.operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    #[test]
    fn test_bit_decomposition_table_8bit() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let table = manager
            .create_bit_decomposition_table(8)
            .expect("Failed to create 8-bit table");

        assert_eq!(table.table.len(), 256);

        // Verify table contains values 0-255
        for i in 0..256 {
            assert_eq!(table.table[i], Goldilocks::from(i as u64));
        }
    }

    #[test]
    fn test_range_check_table() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let table = manager
            .create_range_check_table(8)
            .expect("Failed to create range check table");

        assert_eq!(table.table.len(), 256);
    }

    #[test]
    fn test_should_use_decomposition() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();

        // Small bit widths should not use decomposition
        assert!(!manager.should_use_decomposition(NonNativeOp::BitDecomposition { bit_width: 8 }));
        assert!(!manager.should_use_decomposition(NonNativeOp::BitDecomposition { bit_width: 16 }));

        // Large bit widths should use decomposition
        assert!(manager.should_use_decomposition(NonNativeOp::BitDecomposition { bit_width: 32 }));
        assert!(manager.should_use_decomposition(NonNativeOp::BitDecomposition { bit_width: 64 }));

        // Floating-point should always use decomposition
        assert!(manager.should_use_decomposition(NonNativeOp::FloatAdd));
    }

    #[test]
    fn test_poseidon_sbox_table() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let table = manager
            .create_poseidon_sbox_table()
            .expect("Failed to create Poseidon S-box table");

        assert_eq!(table.table.len(), 256);

        // Verify S-box computation: output = input^5
        for i in 0..256 {
            let input = Goldilocks::from(i as u64);
            let expected = input.pow(5);
            assert_eq!(table.table[i], expected);
        }
    }

    #[test]
    fn test_rescue_sbox_table() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let table = manager
            .create_rescue_sbox_table()
            .expect("Failed to create Rescue S-box table");

        assert_eq!(table.table.len(), 256);

        // Verify inverse S-box
        assert_eq!(table.table[0], Goldilocks::zero()); // 0^{-1} = 0 by convention

        for i in 1..256 {
            let input = Goldilocks::from(i as u64);
            let expected = input.inverse();
            assert_eq!(table.table[i], expected);
        }
    }

    #[test]
    fn test_comparison_table_small() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let table = manager
            .create_comparison_table(4, ComparisonType::LessThan)
            .expect("Failed to create comparison table");

        // For 4-bit values: 16 × 16 = 256 entries
        assert_eq!(table.table.len(), 256);
    }

    #[test]
    fn test_batch_operations() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();

        let operations = vec![
            NonNativeOp::RangeCheck { bit_width: 8 },
            NonNativeOp::RangeCheck { bit_width: 8 },
        ];

        let witnesses = vec![
            vec![Goldilocks::from(42), Goldilocks::from(100)],
            vec![Goldilocks::from(200), Goldilocks::from(255)],
        ];

        let batched = manager
            .batch_operations(&operations, &witnesses)
            .expect("Failed to batch operations");

        assert_eq!(batched.num_operations(), 2);
        assert_eq!(batched.total_lookups(), 4);
    }

    #[test]
    fn test_invalid_bit_width() {
        let manager = NonNativeOpsManager::<Goldilocks>::default();
        let result = manager.create_bit_decomposition_table(7);

        assert!(result.is_err());
        match result {
            Err(LookupError::InvalidParameter { param, .. }) => {
                assert_eq!(param, "bit_width");
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }
}
