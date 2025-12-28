// Dimension Parameter Selection for Shout Protocol
//
// This module implements the dimension parameter selection logic for the Shout protocol.
// The dimension parameter d controls the space-time trade-off in the commitment scheme.
//
// For elliptic curves: key size = 2√(K^(1/d)·T)
// For hash-based: commit time depends on d
//
// Reference: "Twist and Shout: Faster memory checking arguments via one-hot addressing
// and increments" (2025-105)

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use std::marker::PhantomData;

/// Commitment scheme type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentScheme {
    /// Elliptic curve based (e.g., Hyrax, Dory)
    EllipticCurve,
    /// Hash-based (e.g., Ligero, Brakedown)
    HashBased,
}

/// Dimension selection configuration
#[derive(Clone, Debug)]
pub struct DimensionSelectionConfig {
    /// Memory size K
    pub memory_size: usize,
    /// Number of reads T
    pub num_reads: usize,
    /// Commitment scheme type
    pub scheme: CommitmentScheme,
    /// Maximum key size in GB (for elliptic curves)
    pub max_key_size_gb: f64,
    /// Maximum commit time in seconds (for hash-based)
    pub max_commit_time_seconds: f64,
}

impl DimensionSelectionConfig {
    /// Create a new dimension selection configuration
    pub fn new(
        memory_size: usize,
        num_reads: usize,
        scheme: CommitmentScheme,
    ) -> Self {
        DimensionSelectionConfig {
            memory_size,
            num_reads,
            scheme,
            max_key_size_gb: 10.0,
            max_commit_time_seconds: 60.0,
        }
    }

    /// Set maximum key size for elliptic curves
    pub fn with_max_key_size(mut self, size_gb: f64) -> Self {
        self.max_key_size_gb = size_gb;
        self
    }

    /// Set maximum commit time for hash-based schemes
    pub fn with_max_commit_time(mut self, time_seconds: f64) -> Self {
        self.max_commit_time_seconds = time_seconds;
        self
    }
}

/// Dimension selection result
#[derive(Clone, Debug)]
pub struct DimensionSelectionResult {
    /// Selected dimension d
    pub dimension: usize,
    /// Key size in group elements (for elliptic curves)
    pub key_size_elements: usize,
    /// Key size in GB (for elliptic curves)
    pub key_size_gb: f64,
    /// Space complexity O(K^(1/d)·T^(1/2))
    pub space_complexity: usize,
    /// Time complexity O(d·K^(1/d)·T^(1/2))
    pub time_complexity: usize,
    /// Commit time estimate in seconds (for hash-based)
    pub commit_time_seconds: f64,
}

/// Dimension selector for Shout protocol
pub struct DimensionSelector;

impl DimensionSelector {
    /// Select optimal dimension for elliptic curve commitment
    pub fn select_for_elliptic_curve(config: &DimensionSelectionConfig) -> DimensionSelectionResult {
        let mut best_dimension = 1;
        let mut best_key_size = f64::INFINITY;

        // Try dimensions from 1 to 10
        for d in 1..=10 {
            let key_size = Self::compute_elliptic_curve_key_size(
                config.memory_size,
                config.num_reads,
                d,
            );

            if key_size < best_key_size && key_size <= config.max_key_size_gb {
                best_key_size = key_size;
                best_dimension = d;
            }
        }

        let key_size_elements = Self::compute_elliptic_curve_key_size_elements(
            config.memory_size,
            config.num_reads,
            best_dimension,
        );

        let space_complexity = Self::compute_space_complexity(
            config.memory_size,
            config.num_reads,
            best_dimension,
        );

        let time_complexity = Self::compute_time_complexity(
            config.memory_size,
            config.num_reads,
            best_dimension,
        );

        DimensionSelectionResult {
            dimension: best_dimension,
            key_size_elements,
            key_size_gb: best_key_size,
            space_complexity,
            time_complexity,
            commit_time_seconds: 0.0,
        }
    }

    /// Select optimal dimension for hash-based commitment
    pub fn select_for_hash_based(config: &DimensionSelectionConfig) -> DimensionSelectionResult {
        let mut best_dimension = 1;
        let mut best_commit_time = f64::INFINITY;

        // Try dimensions from 1 to 10
        for d in 1..=10 {
            let commit_time = Self::estimate_hash_based_commit_time(
                config.memory_size,
                config.num_reads,
                d,
            );

            if commit_time < best_commit_time && commit_time <= config.max_commit_time_seconds {
                best_commit_time = commit_time;
                best_dimension = d;
            }
        }

        let space_complexity = Self::compute_space_complexity(
            config.memory_size,
            config.num_reads,
            best_dimension,
        );

        let time_complexity = Self::compute_time_complexity(
            config.memory_size,
            config.num_reads,
            best_dimension,
        );

        DimensionSelectionResult {
            dimension: best_dimension,
            key_size_elements: 0,
            key_size_gb: 0.0,
            space_complexity,
            time_complexity,
            commit_time_seconds: best_commit_time,
        }
    }

    /// Select optimal dimension based on scheme type
    pub fn select(config: &DimensionSelectionConfig) -> DimensionSelectionResult {
        match config.scheme {
            CommitmentScheme::EllipticCurve => Self::select_for_elliptic_curve(config),
            CommitmentScheme::HashBased => Self::select_for_hash_based(config),
        }
    }

    /// Compute elliptic curve key size in group elements
    /// Key size = 2√(K^(1/d)·T)
    fn compute_elliptic_curve_key_size_elements(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> usize {
        let k_factor = (memory_size as f64).powf(1.0 / dimension as f64);
        let t_factor = num_reads as f64;
        let product = k_factor * t_factor;
        (2.0 * product.sqrt()) as usize
    }

    /// Compute elliptic curve key size in GB
    /// Assuming 48 bytes per group element (compressed point on BN254)
    fn compute_elliptic_curve_key_size(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> f64 {
        let elements = Self::compute_elliptic_curve_key_size_elements(
            memory_size,
            num_reads,
            dimension,
        );
        let bytes = elements * 48;
        bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Compute space complexity: O(K^(1/d)·T^(1/2))
    fn compute_space_complexity(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> usize {
        let k_factor = (memory_size as f64).powf(1.0 / dimension as f64) as usize;
        let t_factor = (num_reads as f64).sqrt() as usize;
        k_factor * t_factor
    }

    /// Compute time complexity: O(d·K^(1/d)·T^(1/2))
    fn compute_time_complexity(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> usize {
        let space = Self::compute_space_complexity(memory_size, num_reads, dimension);
        dimension * space
    }

    /// Estimate hash-based commit time in seconds
    /// Assuming 1 million hashes per second
    fn estimate_hash_based_commit_time(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> f64 {
        let space = Self::compute_space_complexity(memory_size, num_reads, dimension);
        let hashes_per_second = 1_000_000.0;
        space as f64 / hashes_per_second
    }

    /// Validate dimension parameter
    pub fn validate_dimension(
        memory_size: usize,
        num_reads: usize,
        dimension: usize,
    ) -> Result<(), String> {
        if dimension == 0 {
            return Err("Dimension must be positive".to_string());
        }
        if dimension > 10 {
            return Err("Dimension too large (> 10)".to_string());
        }
        if memory_size == 0 {
            return Err("Memory size must be positive".to_string());
        }
        if num_reads == 0 {
            return Err("Number of reads must be positive".to_string());
        }
        Ok(())
    }
}

/// Dimension parameter optimizer
pub struct DimensionOptimizer;

impl DimensionOptimizer {
    /// Find dimension that minimizes key size for elliptic curves
    pub fn minimize_key_size(
        memory_size: usize,
        num_reads: usize,
    ) -> (usize, f64) {
        let mut best_dimension = 1;
        let mut best_key_size = f64::INFINITY;

        for d in 1..=10 {
            let key_size = DimensionSelector::compute_elliptic_curve_key_size(
                memory_size,
                num_reads,
                d,
            );

            if key_size < best_key_size {
                best_key_size = key_size;
                best_dimension = d;
            }
        }

        (best_dimension, best_key_size)
    }

    /// Find dimension that minimizes space complexity
    pub fn minimize_space(
        memory_size: usize,
        num_reads: usize,
    ) -> (usize, usize) {
        let mut best_dimension = 1;
        let mut best_space = usize::MAX;

        for d in 1..=10 {
            let space = DimensionSelector::compute_space_complexity(
                memory_size,
                num_reads,
                d,
            );

            if space < best_space {
                best_space = space;
                best_dimension = d;
            }
        }

        (best_dimension, best_space)
    }

    /// Find dimension that minimizes time complexity
    pub fn minimize_time(
        memory_size: usize,
        num_reads: usize,
    ) -> (usize, usize) {
        let mut best_dimension = 1;
        let mut best_time = usize::MAX;

        for d in 1..=10 {
            let time = DimensionSelector::compute_time_complexity(
                memory_size,
                num_reads,
                d,
            );

            if time < best_time {
                best_time = time;
                best_dimension = d;
            }
        }

        (best_dimension, best_time)
    }

    /// Find dimension that balances space and time
    pub fn balance_space_time(
        memory_size: usize,
        num_reads: usize,
    ) -> (usize, usize, usize) {
        let mut best_dimension = 1;
        let mut best_ratio = f64::INFINITY;

        for d in 1..=10 {
            let space = DimensionSelector::compute_space_complexity(
                memory_size,
                num_reads,
                d,
            ) as f64;
            let time = DimensionSelector::compute_time_complexity(
                memory_size,
                num_reads,
                d,
            ) as f64;

            // Minimize time/space ratio
            let ratio = time / space;
            if ratio < best_ratio {
                best_ratio = ratio;
                best_dimension = d;
            }
        }

        let space = DimensionSelector::compute_space_complexity(
            memory_size,
            num_reads,
            best_dimension,
        );
        let time = DimensionSelector::compute_time_complexity(
            memory_size,
            num_reads,
            best_dimension,
        );

        (best_dimension, space, time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dimension_selection_config() {
        let config = DimensionSelectionConfig::new(256, 1024, CommitmentScheme::EllipticCurve);
        assert_eq!(config.memory_size, 256);
        assert_eq!(config.num_reads, 1024);
        assert_eq!(config.scheme, CommitmentScheme::EllipticCurve);
    }

    #[test]
    fn test_elliptic_curve_key_size_computation() {
        let key_size = DimensionSelector::compute_elliptic_curve_key_size(256, 1024, 2);
        assert!(key_size > 0.0);
    }

    #[test]
    fn test_space_complexity_computation() {
        let space = DimensionSelector::compute_space_complexity(256, 1024, 2);
        assert!(space > 0);
    }

    #[test]
    fn test_time_complexity_computation() {
        let time = DimensionSelector::compute_time_complexity(256, 1024, 2);
        assert!(time > 0);
    }

    #[test]
    fn test_dimension_selection_elliptic_curve() {
        let config = DimensionSelectionConfig::new(256, 1024, CommitmentScheme::EllipticCurve);
        let result = DimensionSelector::select_for_elliptic_curve(&config);

        assert!(result.dimension > 0);
        assert!(result.dimension <= 10);
        assert!(result.key_size_gb > 0.0);
    }

    #[test]
    fn test_dimension_selection_hash_based() {
        let config = DimensionSelectionConfig::new(256, 1024, CommitmentScheme::HashBased);
        let result = DimensionSelector::select_for_hash_based(&config);

        assert!(result.dimension > 0);
        assert!(result.dimension <= 10);
        assert!(result.commit_time_seconds > 0.0);
    }

    #[test]
    fn test_dimension_validation() {
        assert!(DimensionSelector::validate_dimension(256, 1024, 2).is_ok());
        assert!(DimensionSelector::validate_dimension(0, 1024, 2).is_err());
        assert!(DimensionSelector::validate_dimension(256, 0, 2).is_err());
        assert!(DimensionSelector::validate_dimension(256, 1024, 0).is_err());
        assert!(DimensionSelector::validate_dimension(256, 1024, 15).is_err());
    }

    #[test]
    fn test_minimize_key_size() {
        let (dimension, key_size) = DimensionOptimizer::minimize_key_size(256, 1024);
        assert!(dimension > 0);
        assert!(key_size > 0.0);
    }

    #[test]
    fn test_minimize_space() {
        let (dimension, space) = DimensionOptimizer::minimize_space(256, 1024);
        assert!(dimension > 0);
        assert!(space > 0);
    }

    #[test]
    fn test_minimize_time() {
        let (dimension, time) = DimensionOptimizer::minimize_time(256, 1024);
        assert!(dimension > 0);
        assert!(time > 0);
    }

    #[test]
    fn test_balance_space_time() {
        let (dimension, space, time) = DimensionOptimizer::balance_space_time(256, 1024);
        assert!(dimension > 0);
        assert!(space > 0);
        assert!(time > 0);
    }
}
