// Table Preprocessing and Management
//
// This module implements table preprocessing infrastructure for various lookup schemes.
// It provides:
// - Table preprocessing for different schemes (cq, Caulk, Baloo, Flookup, Duplex)
// - Structured table detection and optimization
// - Table size classification (table-efficient vs super-sublinear)
// - Performance guidance based on table characteristics
//
// # Table Size Classification
//
// - **Table-Efficient**: Prover cost sublinear in |t| (e.g., cq, Caulk+, Baloo)
// - **Super-Sublinear**: Prover cost independent of |t| (e.g., cq with preprocessing)
//
// # Structured Tables
//
// Structured tables have efficiently computable MLEs, enabling:
// - O(log N) evaluation instead of O(N)
// - No need to materialize full table
// - Examples: range tables, XOR tables, multiplication tables
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876), Section on Table Management

use crate::field::traits::Field;
use crate::lookup::mle::MultilinearExtension;
use crate::lookup::{LookupError, LookupResult};
use std::collections::HashMap;
use std::marker::PhantomData;

/// Table preprocessing trait
///
/// Defines interface for scheme-specific table preprocessing
pub trait TablePreprocessor<F: Field> {
    /// Preprocess a table for efficient lookup proving
    ///
    /// # Parameters
    ///
    /// - table: The lookup table to preprocess
    ///
    /// # Returns
    ///
    /// Preprocessed table data
    fn preprocess(&self, table: &[F]) -> LookupResult<PreprocessedTable<F>>;
    
    /// Get preprocessing complexity
    ///
    /// # Returns
    ///
    /// (time_complexity, space_complexity) as strings
    fn preprocessing_complexity(&self) -> (String, String);
    
    /// Check if scheme is table-efficient
    ///
    /// # Returns
    ///
    /// true if prover cost is sublinear in table size
    fn is_table_efficient(&self) -> bool;
}


/// Preprocessed table
///
/// Contains preprocessed data for efficient lookup proving
#[derive(Debug, Clone)]
pub struct PreprocessedTable<F: Field> {
    /// Original table
    pub table: Vec<F>,
    /// Table size N
    pub size: usize,
    /// Scheme-specific auxiliary data
    pub auxiliary_data: Vec<u8>,
    /// Cached commitments (for schemes like cq)
    pub cached_commitments: Vec<Vec<u8>>,
    /// Multilinear extension (if applicable)
    pub mle: Option<MultilinearExtension<F>>,
    /// Is table structured?
    pub is_structured: bool,
    /// Preprocessing time (milliseconds)
    pub preprocessing_time_ms: u64,
}

impl<F: Field> PreprocessedTable<F> {
    /// Create a new preprocessed table
    pub fn new(table: Vec<F>) -> Self {
        let size = table.len();
        Self {
            table,
            size,
            auxiliary_data: Vec::new(),
            cached_commitments: Vec::new(),
            mle: None,
            is_structured: false,
            preprocessing_time_ms: 0,
        }
    }
    
    /// Check if table is power of two size
    pub fn is_power_of_two(&self) -> bool {
        self.size > 0 && (self.size & (self.size - 1)) == 0
    }
    
    /// Get number of variables for MLE (log N)
    pub fn num_vars(&self) -> usize {
        if self.is_power_of_two() {
            (self.size as f64).log2() as usize
        } else {
            0
        }
    }
}

/// Structured table trait
///
/// Defines interface for tables with efficiently computable MLEs
pub trait StructuredTable<F: Field> {
    /// Evaluate table MLE at a point
    ///
    /// # Algorithm
    ///
    /// For structured tables, this can be done in O(log N) or O(k) time
    /// instead of O(N) for general tables.
    ///
    /// # Parameters
    ///
    /// - point: Evaluation point in F^k
    ///
    /// # Returns
    ///
    /// t̃(point)
    fn evaluate_mle(&self, point: &[F]) -> LookupResult<F>;
    
    /// Get table size
    fn size(&self) -> usize;
    
    /// Check if table is structured
    fn is_structured(&self) -> bool {
        true
    }
}


/// Range table
///
/// Table containing [0, 1, 2, ..., N-1]
/// MLE can be evaluated efficiently without materializing table
#[derive(Debug, Clone)]
pub struct RangeTable {
    /// Table size N
    pub size: usize,
}

impl RangeTable {
    /// Create a new range table
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<F: Field> StructuredTable<F> for RangeTable {
    /// Evaluate range table MLE
    ///
    /// # Algorithm
    ///
    /// For range table [0, 1, ..., 2^k - 1], the MLE is:
    /// t̃(x) = Σ_{i=0}^{k-1} x_i · 2^i
    ///
    /// This is just the binary representation interpreted as a number.
    ///
    /// # Complexity
    ///
    /// O(k) = O(log N) field operations
    fn evaluate_mle(&self, point: &[F]) -> LookupResult<F> {
        if !self.size.is_power_of_two() {
            return Err(LookupError::InvalidTableSize {
                expected: self.size.next_power_of_two(),
                got: self.size,
            });
        }
        
        let k = (self.size as f64).log2() as usize;
        if point.len() != k {
            return Err(LookupError::InvalidIndexSize {
                expected: k,
                got: point.len(),
            });
        }
        
        let mut result = F::zero();
        let mut power = F::one();
        let two = F::from(2u64);
        
        for &x_i in point {
            result = result + x_i * power;
            power = power * two;
        }
        
        Ok(result)
    }
    
    fn size(&self) -> usize {
        self.size
    }
}

/// XOR table
///
/// Table where t[i] = i XOR constant
/// MLE can be evaluated efficiently
#[derive(Debug, Clone)]
pub struct XorTable<F: Field> {
    /// Table size N = 2^k
    pub size: usize,
    /// XOR constant
    pub constant: u64,
    _phantom: PhantomData<F>,
}

impl<F: Field> XorTable<F> {
    /// Create a new XOR table
    pub fn new(size: usize, constant: u64) -> Self {
        Self {
            size,
            constant,
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> StructuredTable<F> for XorTable<F> {
    /// Evaluate XOR table MLE
    ///
    /// # Algorithm
    ///
    /// For XOR table, t[i] = i ⊕ c
    /// The MLE can be computed by:
    /// 1. Interpret point as binary number
    /// 2. XOR with constant
    /// 3. Convert back to field element
    ///
    /// # Complexity
    ///
    /// O(k) = O(log N) field operations
    fn evaluate_mle(&self, point: &[F]) -> LookupResult<F> {
        if !self.size.is_power_of_two() {
            return Err(LookupError::InvalidTableSize {
                expected: self.size.next_power_of_two(),
                got: self.size,
            });
        }
        
        let k = (self.size as f64).log2() as usize;
        if point.len() != k {
            return Err(LookupError::InvalidIndexSize {
                expected: k,
                got: point.len(),
            });
        }
        
        // Convert point to index
        let mut index = 0u64;
        for (i, &x_i) in point.iter().enumerate() {
            // In a real implementation, would check if x_i is 0 or 1
            // For now, assume x_i represents a bit
            let bit = x_i.to_canonical_u64() & 1;
            index |= bit << i;
        }
        
        // Apply XOR
        let result_index = index ^ self.constant;
        
        Ok(F::from(result_index))
    }
    
    fn size(&self) -> usize {
        self.size
    }
}


/// Table manager
///
/// Central manager for table preprocessing and optimization
#[derive(Debug)]
pub struct TableManager<F: Field> {
    /// Cache of preprocessed tables
    preprocessed_cache: HashMap<Vec<u8>, PreprocessedTable<F>>,
    /// Structured table registry
    structured_tables: HashMap<String, Box<dyn StructuredTable<F>>>,
}

impl<F: Field> TableManager<F> {
    /// Create a new table manager
    pub fn new() -> Self {
        Self {
            preprocessed_cache: HashMap::new(),
            structured_tables: HashMap::new(),
        }
    }
    
    /// Register a structured table
    ///
    /// # Parameters
    ///
    /// - name: Unique identifier for the table
    /// - table: Structured table implementation
    pub fn register_structured_table(
        &mut self,
        name: String,
        table: Box<dyn StructuredTable<F>>,
    ) {
        self.structured_tables.insert(name, table);
    }
    
    /// Detect if a table is structured
    ///
    /// # Algorithm
    ///
    /// Check if table matches known structured patterns:
    /// - Range table: [0, 1, 2, ..., N-1]
    /// - XOR table: [i ⊕ c for i in 0..N]
    /// - Multiplication table: [i * c for i in 0..N]
    /// - Power table: [i^p for i in 0..N]
    ///
    /// # Complexity
    ///
    /// O(N) to scan table
    pub fn detect_structured(&self, table: &[F]) -> Option<String> {
        // Check if range table
        if self.is_range_table(table) {
            return Some("range".to_string());
        }
        
        // Check if XOR table
        if let Some(constant) = self.is_xor_table(table) {
            return Some(format!("xor_{}", constant));
        }
        
        None
    }
    
    /// Check if table is a range table
    fn is_range_table(&self, table: &[F]) -> bool {
        for (i, &val) in table.iter().enumerate() {
            if val != F::from(i as u64) {
                return false;
            }
        }
        true
    }
    
    /// Check if table is an XOR table
    ///
    /// Returns the XOR constant if it is
    fn is_xor_table(&self, table: &[F]) -> Option<u64> {
        if table.len() < 2 {
            return None;
        }
        
        // Try to find XOR constant
        let first = table[0].to_canonical_u64();
        let second = table[1].to_canonical_u64();
        let candidate_constant = first ^ 0 ^ (second ^ 1);
        
        // Verify all entries match
        for (i, &val) in table.iter().enumerate() {
            let expected = (i as u64) ^ candidate_constant;
            if val.to_canonical_u64() != expected {
                return None;
            }
        }
        
        Some(candidate_constant)
    }
    
    /// Classify table size
    ///
    /// # Returns
    ///
    /// - "small": N ≤ 2^16 (use any scheme)
    /// - "medium": 2^16 < N ≤ 2^24 (prefer table-efficient schemes)
    /// - "large": 2^24 < N ≤ 2^32 (require table-efficient schemes)
    /// - "massive": N > 2^32 (require decomposition)
    pub fn classify_table_size(&self, size: usize) -> String {
        if size <= (1 << 16) {
            "small".to_string()
        } else if size <= (1 << 24) {
            "medium".to_string()
        } else if size <= (1u64 << 32) as usize {
            "large".to_string()
        } else {
            "massive".to_string()
        }
    }
    
    /// Recommend lookup scheme based on table characteristics
    ///
    /// # Algorithm
    ///
    /// Consider:
    /// 1. Table size (small, medium, large, massive)
    /// 2. Is table structured?
    /// 3. Preprocessing budget
    /// 4. Prover cost requirements
    /// 5. Verifier cost requirements
    /// 6. Proof size requirements
    ///
    /// # Returns
    ///
    /// Recommended scheme name and rationale
    pub fn recommend_scheme(
        &self,
        table_size: usize,
        is_structured: bool,
        allow_preprocessing: bool,
    ) -> (String, String) {
        let size_class = self.classify_table_size(table_size);
        
        match size_class.as_str() {
            "small" => {
                if allow_preprocessing {
                    ("cq".to_string(), "Small table with preprocessing: cq offers constant proof size and O(n log n) prover".to_string())
                } else {
                    ("Plookup".to_string(), "Small table without preprocessing: Plookup is simple and efficient".to_string())
                }
            }
            "medium" => {
                if allow_preprocessing {
                    ("cq".to_string(), "Medium table with preprocessing: cq is super-sublinear in table size".to_string())
                } else if is_structured {
                    ("Lasso".to_string(), "Medium structured table: Lasso exploits structure for efficiency".to_string())
                } else {
                    ("Logup+GKR".to_string(), "Medium table without preprocessing: Logup+GKR is transparent".to_string())
                }
            }
            "large" => {
                if allow_preprocessing {
                    ("cq".to_string(), "Large table with preprocessing: cq prover cost independent of table size".to_string())
                } else if is_structured {
                    ("Lasso".to_string(), "Large structured table: Lasso with structured table evaluation".to_string())
                } else {
                    ("Baloo".to_string(), "Large table: Baloo offers O(n log^2 n) prover independent of table size".to_string())
                }
            }
            "massive" => {
                ("Lasso+Decomposition".to_string(), "Massive table: Use Lasso with table decomposition".to_string())
            }
            _ => {
                ("Plookup".to_string(), "Default: Plookup for general use".to_string())
            }
        }
    }
    
    /// Preprocess table with caching
    ///
    /// # Algorithm
    ///
    /// 1. Check cache for existing preprocessing
    /// 2. If not cached, preprocess table
    /// 3. Store in cache for reuse
    /// 4. Return preprocessed table
    ///
    /// # Complexity
    ///
    /// O(1) if cached, O(preprocessing) otherwise
    pub fn preprocess_with_cache(
        &mut self,
        table: &[F],
        preprocessor: &dyn TablePreprocessor<F>,
    ) -> LookupResult<PreprocessedTable<F>> {
        // Compute cache key (hash of table)
        let cache_key = self.compute_table_hash(table);
        
        // Check cache
        if let Some(cached) = self.preprocessed_cache.get(&cache_key) {
            return Ok(cached.clone());
        }
        
        // Preprocess table
        let preprocessed = preprocessor.preprocess(table)?;
        
        // Store in cache
        self.preprocessed_cache.insert(cache_key, preprocessed.clone());
        
        Ok(preprocessed)
    }
    
    /// Compute hash of table for caching
    fn compute_table_hash(&self, table: &[F]) -> Vec<u8> {
        // In a real implementation, use a proper hash function
        let mut hash = vec![0u8; 32];
        for (i, &val) in table.iter().enumerate() {
            let val_bytes = val.to_bytes();
            for j in 0..32.min(val_bytes.len()) {
                hash[j] ^= val_bytes[j].wrapping_add(i as u8);
            }
        }
        hash
    }
    
    /// Clear preprocessing cache
    pub fn clear_cache(&mut self) {
        self.preprocessed_cache.clear();
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let num_entries = self.preprocessed_cache.len();
        let total_size: usize = self.preprocessed_cache.values()
            .map(|p| p.table.len() + p.auxiliary_data.len())
            .sum();
        (num_entries, total_size)
    }
}

impl<F: Field> Default for TableManager<F> {
    fn default() -> Self {
        Self::new()
    }
}


/// cq preprocessor
///
/// Implements preprocessing for cq lookup scheme
#[derive(Debug)]
pub struct CqPreprocessor {
    /// Subgroup size N
    pub subgroup_size: usize,
}

impl CqPreprocessor {
    /// Create a new cq preprocessor
    pub fn new(subgroup_size: usize) -> Self {
        Self { subgroup_size }
    }
}

impl<F: Field> TablePreprocessor<F> for CqPreprocessor {
    fn preprocess(&self, table: &[F]) -> LookupResult<PreprocessedTable<F>> {
        if table.len() != self.subgroup_size {
            return Err(LookupError::InvalidTableSize {
                expected: self.subgroup_size,
                got: table.len(),
            });
        }
        
        let start_time = std::time::Instant::now();
        
        // Precompute cached quotient commitments
        // In a real implementation, this would use FK23 batch techniques
        let num_commitments = (table.len() as f64).log2() as usize;
        let cached_commitments: Vec<Vec<u8>> = (0..num_commitments)
            .map(|i| vec![i as u8; 32])
            .collect();
        
        let preprocessing_time_ms = start_time.elapsed().as_millis() as u64;
        
        let mut preprocessed = PreprocessedTable::new(table.to_vec());
        preprocessed.cached_commitments = cached_commitments;
        preprocessed.preprocessing_time_ms = preprocessing_time_ms;
        
        Ok(preprocessed)
    }
    
    fn preprocessing_complexity(&self) -> (String, String) {
        ("O(N log N)".to_string(), "O(N log N)".to_string())
    }
    
    fn is_table_efficient(&self) -> bool {
        true // cq is super-sublinear
    }
}

/// Lasso preprocessor
///
/// Implements preprocessing for Lasso lookup scheme
#[derive(Debug)]
pub struct LassoPreprocessor {
    /// Table size N
    pub table_size: usize,
}

impl LassoPreprocessor {
    /// Create a new Lasso preprocessor
    pub fn new(table_size: usize) -> Self {
        Self { table_size }
    }
}

impl<F: Field> TablePreprocessor<F> for LassoPreprocessor {
    fn preprocess(&self, table: &[F]) -> LookupResult<PreprocessedTable<F>> {
        if table.len() != self.table_size {
            return Err(LookupError::InvalidTableSize {
                expected: self.table_size,
                got: table.len(),
            });
        }
        
        let start_time = std::time::Instant::now();
        
        // Compute multilinear extension
        let mle = if table.len().is_power_of_two() {
            Some(MultilinearExtension::new(table.to_vec())?)
        } else {
            None
        };
        
        let preprocessing_time_ms = start_time.elapsed().as_millis() as u64;
        
        let mut preprocessed = PreprocessedTable::new(table.to_vec());
        preprocessed.mle = mle;
        preprocessed.preprocessing_time_ms = preprocessing_time_ms;
        
        Ok(preprocessed)
    }
    
    fn preprocessing_complexity(&self) -> (String, String) {
        ("O(N)".to_string(), "O(N)".to_string())
    }
    
    fn is_table_efficient(&self) -> bool {
        false // Lasso prover cost depends on table structure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    type F = Goldilocks;
    
    #[test]
    fn test_range_table() {
        let range_table = RangeTable::new(8);
        
        // Evaluate at point [0, 0, 0] should give 0
        let point = vec![F::zero(), F::zero(), F::zero()];
        let result = range_table.evaluate_mle(&point).unwrap();
        assert_eq!(result, F::zero());
        
        // Evaluate at point [1, 0, 0] should give 1
        let point = vec![F::one(), F::zero(), F::zero()];
        let result = range_table.evaluate_mle(&point).unwrap();
        assert_eq!(result, F::one());
        
        // Evaluate at point [1, 1, 0] should give 3
        let point = vec![F::one(), F::one(), F::zero()];
        let result = range_table.evaluate_mle(&point).unwrap();
        assert_eq!(result, F::from(3u64));
    }
    
    #[test]
    fn test_xor_table() {
        let xor_table = XorTable::<F>::new(8, 5);
        
        // Evaluate at point [0, 0, 0] should give 0 XOR 5 = 5
        let point = vec![F::zero(), F::zero(), F::zero()];
        let result = xor_table.evaluate_mle(&point).unwrap();
        assert_eq!(result, F::from(5u64));
        
        // Evaluate at point [1, 0, 0] should give 1 XOR 5 = 4
        let point = vec![F::one(), F::zero(), F::zero()];
        let result = xor_table.evaluate_mle(&point).unwrap();
        assert_eq!(result, F::from(4u64));
    }
    
    #[test]
    fn test_table_manager_detection() {
        let manager = TableManager::<F>::new();
        
        // Test range table detection
        let range_table = vec![
            F::from(0u64),
            F::from(1u64),
            F::from(2u64),
            F::from(3u64),
        ];
        assert_eq!(manager.detect_structured(&range_table), Some("range".to_string()));
        
        // Test non-structured table
        let random_table = vec![
            F::from(5u64),
            F::from(3u64),
            F::from(7u64),
            F::from(1u64),
        ];
        assert_eq!(manager.detect_structured(&random_table), None);
    }
    
    #[test]
    fn test_table_size_classification() {
        let manager = TableManager::<F>::new();
        
        assert_eq!(manager.classify_table_size(1000), "small");
        assert_eq!(manager.classify_table_size(1 << 20), "medium");
        assert_eq!(manager.classify_table_size(1 << 28), "large");
        assert_eq!(manager.classify_table_size((1u64 << 40) as usize), "massive");
    }
    
    #[test]
    fn test_scheme_recommendation() {
        let manager = TableManager::<F>::new();
        
        // Small table with preprocessing
        let (scheme, _) = manager.recommend_scheme(1000, false, true);
        assert_eq!(scheme, "cq");
        
        // Large structured table without preprocessing
        let (scheme, _) = manager.recommend_scheme(1 << 28, true, false);
        assert_eq!(scheme, "Lasso");
        
        // Massive table
        let (scheme, _) = manager.recommend_scheme((1u64 << 40) as usize, false, true);
        assert_eq!(scheme, "Lasso+Decomposition");
    }
    
    #[test]
    fn test_cq_preprocessor() {
        let preprocessor = CqPreprocessor::new(8);
        let table = vec![
            F::from(0u64),
            F::from(1u64),
            F::from(2u64),
            F::from(3u64),
            F::from(4u64),
            F::from(5u64),
            F::from(6u64),
            F::from(7u64),
        ];
        
        let preprocessed = preprocessor.preprocess(&table).unwrap();
        assert_eq!(preprocessed.size, 8);
        assert!(!preprocessed.cached_commitments.is_empty());
        assert!(preprocessor.is_table_efficient());
    }
    
    #[test]
    fn test_preprocessed_table() {
        let table = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
        let preprocessed = PreprocessedTable::new(table);
        
        assert_eq!(preprocessed.size, 4);
        assert!(preprocessed.is_power_of_two());
        assert_eq!(preprocessed.num_vars(), 2);
    }
}

</content>
</file>