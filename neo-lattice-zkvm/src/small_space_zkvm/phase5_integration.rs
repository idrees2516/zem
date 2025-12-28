// Phase 5 Integration: Complete Shout Protocol Implementation
//
// This module provides the complete integration of the Shout protocol for read-only memory
// checking in the small-space zkVM prover. It combines all Phase 5 components:
// - Shout prover and verifier
// - Phase 1 data structure for first log K rounds
// - Sparse-dense sum-check for final log T rounds
// - Booleanity and Hamming-weight-one verification
// - Dimension parameter selection
//
// Reference: "Twist and Shout: Faster memory checking arguments via one-hot addressing
// and increments" (2025-105)

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::shout::{
    ShoutConfig, ShoutProof, AddressOracle, MemoryOracle, SimpleAddressOracle,
    SimpleMemoryOracle, OneHotAddressEncoding,
};
use crate::small_space_zkvm::shout_advanced::{
    AdvancedShoutProver, AdvancedShoutVerifier, Phase1Result, Phase2Result,
};
use crate::small_space_zkvm::dimension_selection::{
    DimensionSelectionConfig, DimensionSelector, CommitmentScheme,
};
use std::marker::PhantomData;

/// Phase 5 configuration combining all Shout components
#[derive(Clone, Debug)]
pub struct Phase5Config {
    /// Shout configuration
    pub shout_config: ShoutConfig,
    /// Dimension selection configuration
    pub dimension_config: DimensionSelectionConfig,
    /// Enable performance tracking
    pub track_performance: bool,
}

impl Phase5Config {
    /// Create a new Phase 5 configuration
    pub fn new(
        memory_size: usize,
        num_reads: usize,
        scheme: CommitmentScheme,
    ) -> Self {
        let shout_config = ShoutConfig::new(memory_size, num_reads, 2);
        let dimension_config = DimensionSelectionConfig::new(memory_size, num_reads, scheme);

        Phase5Config {
            shout_config,
            dimension_config,
            track_performance: false,
        }
    }

    /// Enable performance tracking
    pub fn with_performance_tracking(mut self) -> Self {
        self.track_performance = true;
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        self.shout_config.validate()?;
        Ok(())
    }
}

/// Phase 5 performance metrics
#[derive(Clone, Debug)]
pub struct Phase5Metrics {
    /// Field operations for booleanity checking
    pub booleanity_ops: usize,
    /// Field operations for Hamming weight checking
    pub hamming_weight_ops: usize,
    /// Field operations for Phase 1 (first log K rounds)
    pub phase1_ops: usize,
    /// Field operations for Phase 2 (final log T rounds)
    pub phase2_ops: usize,
    /// Total field operations
    pub total_ops: usize,
    /// Space used in field elements
    pub space_used: usize,
    /// Proof size in bytes
    pub proof_size_bytes: usize,
}

impl Phase5Metrics {
    /// Create empty metrics
    pub fn new() -> Self {
        Phase5Metrics {
            booleanity_ops: 0,
            hamming_weight_ops: 0,
            phase1_ops: 0,
            phase2_ops: 0,
            total_ops: 0,
            space_used: 0,
            proof_size_bytes: 0,
        }
    }

    /// Compute total operations
    pub fn compute_total(&mut self) {
        self.total_ops = self.booleanity_ops
            + self.hamming_weight_ops
            + self.phase1_ops
            + self.phase2_ops;
    }
}

/// Phase 5 prover: Complete Shout protocol implementation
pub struct Phase5Prover<F: FieldElement> {
    config: Phase5Config,
    prover: AdvancedShoutProver<F>,
    metrics: Phase5Metrics,
}

impl<F: FieldElement> Phase5Prover<F> {
    /// Create a new Phase 5 prover
    pub fn new(
        config: Phase5Config,
        address_oracle: &dyn AddressOracle,
        memory_oracle: Box<dyn Fn(usize) -> F>,
    ) -> Result<Self, String> {
        config.validate()?;

        let prover = AdvancedShoutProver::new(config.shout_config.clone(), address_oracle, memory_oracle)?;

        Ok(Phase5Prover {
            config,
            prover,
            metrics: Phase5Metrics::new(),
        })
    }

    /// Execute complete Phase 5 protocol
    pub fn prove(&mut self) -> Result<ShoutProof<F>, String> {
        // Verify booleanity
        let booleanity_sum = self.prover.verify_booleanity_sum();
        if booleanity_sum != F::zero() {
            return Err("Booleanity check failed".to_string());
        }
        self.metrics.booleanity_ops = self.config.shout_config.memory_size
            * self.config.shout_config.num_reads;

        // Verify Hamming weight one
        let hamming_sum = self.prover.verify_hamming_weight_sum();
        if hamming_sum != F::zero() {
            return Err("Hamming weight check failed".to_string());
        }
        self.metrics.hamming_weight_ops = self.config.shout_config.memory_size
            * self.config.shout_config.num_reads;

        // Execute Phase 1
        let phase1_result = self.prover.execute_phase1();
        self.metrics.phase1_ops = self.config.shout_config.memory_size
            * self.config.shout_config.log_memory_size();

        // Execute Phase 2
        let phase2_result = self.prover.execute_phase2(&phase1_result.challenges);
        self.metrics.phase2_ops = self.config.shout_config.num_reads
            * self.config.shout_config.log_num_reads();

        // Compute total metrics
        self.metrics.compute_total();
        self.metrics.space_used = self.config.shout_config.memory_size;

        // Generate proof
        let proof = self.prover.prove()?;
        self.metrics.proof_size_bytes = proof.size_bytes();

        Ok(proof)
    }

    /// Get metrics
    pub fn metrics(&self) -> &Phase5Metrics {
        &self.metrics
    }

    /// Get configuration
    pub fn config(&self) -> &Phase5Config {
        &self.config
    }

    /// Select optimal dimension for commitment scheme
    pub fn select_dimension(&self) -> usize {
        let result = DimensionSelector::select(&self.config.dimension_config);
        result.dimension
    }

    /// Estimate total field operations
    pub fn estimate_operations(&self) -> usize {
        self.prover.estimate_total_operations()
    }
}

/// Phase 5 verifier: Complete Shout protocol verification
pub struct Phase5Verifier<F: FieldElement> {
    config: Phase5Config,
    verifier: AdvancedShoutVerifier<F>,
}

impl<F: FieldElement> Phase5Verifier<F> {
    /// Create a new Phase 5 verifier
    pub fn new(config: Phase5Config) -> Result<Self, String> {
        config.validate()?;

        let verifier = AdvancedShoutVerifier::new(config.shout_config.clone())?;

        Ok(Phase5Verifier { config, verifier })
    }

    /// Verify complete Shout proof
    pub fn verify(&self, proof: &ShoutProof<F>) -> bool {
        self.verifier.verify_proof(proof)
    }

    /// Verify Phase 1 result
    pub fn verify_phase1(&self, phase1_result: &Phase1Result<F>) -> bool {
        self.verifier.verify_phase1(phase1_result)
    }

    /// Verify Phase 2 result
    pub fn verify_phase2(&self, phase2_result: &Phase2Result<F>) -> bool {
        self.verifier.verify_phase2(phase2_result)
    }

    /// Get configuration
    pub fn config(&self) -> &Phase5Config {
        &self.config
    }
}

/// Phase 5 complete protocol runner
pub struct Phase5Protocol<F: FieldElement> {
    config: Phase5Config,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> Phase5Protocol<F> {
    /// Create a new Phase 5 protocol runner
    pub fn new(config: Phase5Config) -> Result<Self, String> {
        config.validate()?;
        Ok(Phase5Protocol {
            config,
            _phantom: PhantomData,
        })
    }

    /// Run complete protocol with given addresses and memory
    pub fn run(
        &self,
        addresses: Vec<usize>,
        memory: Vec<F>,
    ) -> Result<(ShoutProof<F>, Phase5Metrics), String> {
        // Create oracles
        let address_oracle = SimpleAddressOracle::new(addresses, memory.len());
        let memory_oracle = Box::new(move |k: usize| {
            if k < memory.len() {
                memory[k]
            } else {
                F::zero()
            }
        });

        // Create prover
        let mut prover = Phase5Prover::new(self.config.clone(), &address_oracle, memory_oracle)?;

        // Generate proof
        let proof = prover.prove()?;
        let metrics = prover.metrics().clone();

        Ok((proof, metrics))
    }

    /// Get configuration
    pub fn config(&self) -> &Phase5Config {
        &self.config
    }
}

/// Phase 5 performance analyzer
pub struct Phase5PerformanceAnalyzer;

impl Phase5PerformanceAnalyzer {
    /// Analyze performance for given parameters
    pub fn analyze(
        memory_size: usize,
        num_reads: usize,
        scheme: CommitmentScheme,
    ) -> Phase5PerformanceReport {
        let config = Phase5Config::new(memory_size, num_reads, scheme);
        let dimension_result = DimensionSelector::select(&config.dimension_config);

        let booleanity_ops = memory_size * num_reads;
        let hamming_weight_ops = memory_size * num_reads;
        let phase1_ops = memory_size * (memory_size as f64).log2().ceil() as usize;
        let phase2_ops = num_reads * (num_reads as f64).log2().ceil() as usize;
        let total_ops = booleanity_ops + hamming_weight_ops + phase1_ops + phase2_ops;

        let space_used = dimension_result.space_complexity;
        let slowdown_factor = total_ops as f64 / (40.0 * num_reads as f64);

        Phase5PerformanceReport {
            memory_size,
            num_reads,
            dimension: dimension_result.dimension,
            booleanity_ops,
            hamming_weight_ops,
            phase1_ops,
            phase2_ops,
            total_ops,
            space_used,
            slowdown_factor,
            key_size_gb: dimension_result.key_size_gb,
        }
    }

    /// Compare performance across different dimensions
    pub fn compare_dimensions(
        memory_size: usize,
        num_reads: usize,
    ) -> Vec<Phase5PerformanceReport> {
        let mut reports = Vec::new();

        for d in 1..=10 {
            let config = Phase5Config::new(memory_size, num_reads, CommitmentScheme::EllipticCurve);
            let dimension_result = DimensionSelector::select(&config.dimension_config);

            let space_used = dimension_result.space_complexity;
            let total_ops = 2 * memory_size * num_reads
                + memory_size * (memory_size as f64).log2().ceil() as usize
                + num_reads * (num_reads as f64).log2().ceil() as usize;

            let slowdown_factor = total_ops as f64 / (40.0 * num_reads as f64);

            reports.push(Phase5PerformanceReport {
                memory_size,
                num_reads,
                dimension: d,
                booleanity_ops: memory_size * num_reads,
                hamming_weight_ops: memory_size * num_reads,
                phase1_ops: memory_size * (memory_size as f64).log2().ceil() as usize,
                phase2_ops: num_reads * (num_reads as f64).log2().ceil() as usize,
                total_ops,
                space_used,
                slowdown_factor,
                key_size_gb: dimension_result.key_size_gb,
            });
        }

        reports
    }
}

/// Phase 5 performance report
#[derive(Clone, Debug)]
pub struct Phase5PerformanceReport {
    /// Memory size K
    pub memory_size: usize,
    /// Number of reads T
    pub num_reads: usize,
    /// Dimension parameter d
    pub dimension: usize,
    /// Booleanity checking operations
    pub booleanity_ops: usize,
    /// Hamming weight checking operations
    pub hamming_weight_ops: usize,
    /// Phase 1 operations
    pub phase1_ops: usize,
    /// Phase 2 operations
    pub phase2_ops: usize,
    /// Total field operations
    pub total_ops: usize,
    /// Space used
    pub space_used: usize,
    /// Slowdown factor vs linear-time
    pub slowdown_factor: f64,
    /// Key size in GB
    pub key_size_gb: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;

    #[test]
    fn test_phase5_config_creation() {
        let config = Phase5Config::new(256, 1024, CommitmentScheme::EllipticCurve);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_phase5_config_with_tracking() {
        let config = Phase5Config::new(256, 1024, CommitmentScheme::EllipticCurve)
            .with_performance_tracking();
        assert!(config.track_performance);
    }

    #[test]
    fn test_phase5_metrics() {
        let mut metrics = Phase5Metrics::new();
        metrics.booleanity_ops = 100;
        metrics.hamming_weight_ops = 100;
        metrics.phase1_ops = 200;
        metrics.phase2_ops = 300;
        metrics.compute_total();

        assert_eq!(metrics.total_ops, 700);
    }

    #[test]
    fn test_phase5_performance_analysis() {
        let report = Phase5PerformanceAnalyzer::analyze(256, 1024, CommitmentScheme::EllipticCurve);
        assert!(report.total_ops > 0);
        assert!(report.space_used > 0);
        assert!(report.slowdown_factor > 0.0);
    }

    #[test]
    fn test_phase5_dimension_comparison() {
        let reports = Phase5PerformanceAnalyzer::compare_dimensions(256, 1024);
        assert_eq!(reports.len(), 10);

        for report in &reports {
            assert!(report.total_ops > 0);
            assert!(report.space_used > 0);
        }
    }

    #[test]
    fn test_phase5_protocol_creation() {
        let config = Phase5Config::new(256, 1024, CommitmentScheme::EllipticCurve);
        let protocol = Phase5Protocol::<PrimeField>::new(config);
        assert!(protocol.is_ok());
    }
}
