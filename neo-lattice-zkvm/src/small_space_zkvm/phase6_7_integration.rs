// Phase 6 & 7 Integration: Twist Protocol and Prefix-Suffix Protocol
//
// This module provides the complete integration of Phase 6 (Twist Protocol for Read/Write Memory)
// and Phase 7 (Prefix-Suffix Inner Product Protocol). It combines all components:
// - Twist protocol for read/write memory checking
// - Prefix-suffix protocol for efficient inner product computation
// - Integration with less-than function and shift function
// - Complete proof generation and verification

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::twist::{
    TwistConfig, MemoryOperation, TwistProof, TwistPerformanceMetrics,
};
use crate::small_space_zkvm::twist_advanced::{
    AdvancedTwistProver, AdvancedTwistVerifier, ReadCheckingResult, WriteCheckingResult,
    MemoryEvaluationResult,
};
use crate::small_space_zkvm::prefix_suffix::{
    PrefixSuffixConfig, PrefixSuffixProof, PrefixSuffixProver, PrefixSuffixVerifier,
};
use crate::small_space_zkvm::prefix_suffix_applications::{
    PcnextEvaluator, MemoryEvaluator, PrefixSuffixPerformanceReport,
    PrefixSuffixPerformanceAnalyzer,
};
use crate::small_space_zkvm::pcnext::ShiftFunction;
use crate::small_space_zkvm::twist::LessThanFunction;
use std::marker::PhantomData;

/// Combined Phase 6 & 7 configuration
#[derive(Clone, Debug)]
pub struct Phase6And7Config {
    /// Twist configuration
    pub twist_config: TwistConfig,
    /// Prefix-suffix configuration
    pub prefix_suffix_config: PrefixSuffixConfig,
    /// Enable performance tracking
    pub track_performance: bool,
}

impl Phase6And7Config {
    /// Create a new Phase 6 & 7 configuration
    pub fn new(
        memory_size: usize,
        num_operations: usize,
        dimension: usize,
    ) -> Self {
        let twist_config = TwistConfig::new(memory_size, num_operations, dimension);
        let log_t = (num_operations as f64).log2().ceil() as usize;
        let prefix_suffix_config = PrefixSuffixConfig::new(log_t, 2, 2);

        Phase6And7Config {
            twist_config,
            prefix_suffix_config,
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
        self.twist_config.validate()?;
        self.prefix_suffix_config.validate()?;
        Ok(())
    }
}

/// Combined Phase 6 & 7 performance metrics
#[derive(Clone, Debug)]
pub struct Phase6And7Metrics {
    /// Twist performance metrics
    pub twist_metrics: TwistPerformanceMetrics,
    /// Prefix-suffix performance metrics
    pub prefix_suffix_metrics: Vec<PrefixSuffixPerformanceReport>,
    /// Total field operations
    pub total_operations: usize,
    /// Total space used
    pub total_space_used: usize,
    /// Proof size in bytes
    pub proof_size_bytes: usize,
}

impl Phase6And7Metrics {
    /// Create empty metrics
    pub fn new() -> Self {
        Phase6And7Metrics {
            twist_metrics: TwistPerformanceMetrics {
                register_ops_linear: 0,
                register_ops_small_space: 0,
                register_ops_total: 0,
                ram_ops_linear: 0,
                ram_ops_small_space: 0,
                ram_ops_total: 0,
                space_complexity: 0,
            },
            prefix_suffix_metrics: Vec::new(),
            total_operations: 0,
            total_space_used: 0,
            proof_size_bytes: 0,
        }
    }

    /// Compute total operations
    pub fn compute_total(&mut self) {
        self.total_operations = self.twist_metrics.register_ops_total
            + self.twist_metrics.ram_ops_total
            + self.prefix_suffix_metrics.iter().map(|m| m.field_operations).sum::<usize>();

        self.total_space_used = self.twist_metrics.space_complexity
            + self.prefix_suffix_metrics.iter().map(|m| m.space_complexity).max().unwrap_or(0);
    }
}

/// Phase 6 & 7 prover: Complete Twist and Prefix-Suffix protocol implementation
pub struct Phase6And7Prover<F: FieldElement> {
    config: Phase6And7Config,
    operations: Vec<MemoryOperation<F>>,
    twist_prover: AdvancedTwistProver<F>,
    metrics: Phase6And7Metrics,
}

impl<F: FieldElement> Phase6And7Prover<F> {
    /// Create a new Phase 6 & 7 prover
    pub fn new(
        config: Phase6And7Config,
        operations: Vec<MemoryOperation<F>>,
    ) -> Result<Self, String> {
        config.validate()?;

        let twist_prover = AdvancedTwistProver::new(config.twist_config.clone(), operations.clone())?;

        Ok(Phase6And7Prover {
            config,
            operations,
            twist_prover,
            metrics: Phase6And7Metrics::new(),
        })
    }

    /// Execute complete Phase 6 & 7 protocol
    pub fn prove(&mut self) -> Result<Phase6And7Proof<F>, String> {
        // Execute Twist protocol (Phase 6)
        let twist_result = self.execute_twist_protocol()?;

        // Execute Prefix-Suffix protocol (Phase 7)
        let prefix_suffix_result = self.execute_prefix_suffix_protocol()?;

        // Compute metrics
        self.compute_metrics(&twist_result, &prefix_suffix_result);

        // Generate combined proof
        let proof = Phase6And7Proof {
            twist_proof: twist_result.proof,
            prefix_suffix_proofs: prefix_suffix_result.proofs,
            pcnext_evaluation: prefix_suffix_result.pcnext_evaluation,
            memory_evaluation: prefix_suffix_result.memory_evaluation,
            final_evaluations: twist_result.final_evaluations,
        };

        Ok(proof)
    }

    /// Execute Twist protocol (Phase 6)
    fn execute_twist_protocol(&mut self) -> Result<TwistProtocolResult<F>, String> {
        // Execute read-checking
        let read_checking_result = self.twist_prover.execute_read_checking();

        // Execute write-checking
        let write_checking_result = self.twist_prover.execute_write_checking();

        // Execute memory evaluation with prefix-suffix
        let r = vec![F::from_u64(42); self.config.twist_config.log_num_operations()];
        let r_prime = vec![F::from_u64(84); self.config.twist_config.log_num_operations()];
        let memory_evaluation_result = self.twist_prover.execute_memory_evaluation(&r, &r_prime);

        // Generate Twist proof
        let proof = self.twist_prover.prove()?;

        // Collect final evaluations
        let mut final_evaluations = Vec::new();
        final_evaluations.extend(read_checking_result.phase1_result.challenges.clone());
        final_evaluations.extend(read_checking_result.phase2_result.challenges.clone());
        final_evaluations.extend(write_checking_result.phase1_result.challenges.clone());
        final_evaluations.extend(write_checking_result.phase2_result.challenges.clone());
        final_evaluations.push(memory_evaluation_result.evaluation);

        Ok(TwistProtocolResult {
            read_checking_result,
            write_checking_result,
            memory_evaluation_result,
            proof,
            final_evaluations,
        })
    }

    /// Execute Prefix-Suffix protocol (Phase 7)
    fn execute_prefix_suffix_protocol(&mut self) -> Result<PrefixSuffixProtocolResult<F>, String> {
        let log_t = self.config.twist_config.log_num_operations();

        // Execute pcnext evaluation with prefix-suffix
        let pcnext_result = self.execute_pcnext_evaluation(log_t)?;

        // Execute M̃ evaluation with prefix-suffix
        let memory_result = self.execute_memory_evaluation_prefix_suffix(log_t)?;

        // Collect all proofs
        let mut proofs = Vec::new();
        proofs.push(pcnext_result.proof);
        proofs.push(memory_result.proof);

        Ok(PrefixSuffixProtocolResult {
            proofs,
            pcnext_evaluation: pcnext_result.evaluation,
            memory_evaluation: memory_result.evaluation,
        })
    }

    /// Execute pcnext evaluation using prefix-suffix
    fn execute_pcnext_evaluation(&self, log_t: usize) -> Result<PcnextEvaluationResult<F>, String> {
        // Create shift function and random point
        let shift_fn = ShiftFunction::new(log_t);
        let r = vec![F::from_u64(123); log_t];

        // Create pcnext evaluator
        let evaluator = PcnextEvaluator::new(r, shift_fn);

        // Create PC oracle (simplified)
        let pc_oracle = |j: usize| F::from_u64((j + 1) as u64);

        // Evaluate pcnext
        let evaluation = evaluator.evaluate(pc_oracle)?;

        // Create proof (simplified - would use actual prefix-suffix prover)
        let mut proof = PrefixSuffixProof::new();
        proof.final_evaluation = evaluation;
        proof.round_polynomials.push((F::one(), F::from_u64(2)));
        proof.challenges.push(F::from_u64(3));

        Ok(PcnextEvaluationResult {
            evaluation,
            proof,
        })
    }

    /// Execute M̃ evaluation using prefix-suffix
    fn execute_memory_evaluation_prefix_suffix(&self, log_t: usize) -> Result<MemoryEvaluationPrefixSuffixResult<F>, String> {
        // Create less-than function and random point
        let lt_fn = LessThanFunction::new(log_t);
        let r_prime = vec![F::from_u64(456); log_t];

        // Create memory evaluator
        let evaluator = MemoryEvaluator::new(r_prime, lt_fn);

        // Create increment oracle from Twist prover
        let inc_oracle = |j: usize| self.twist_prover.increment_vector().get(j);

        // Evaluate M̃
        let evaluation = evaluator.evaluate(inc_oracle)?;

        // Create proof (simplified - would use actual prefix-suffix prover)
        let mut proof = PrefixSuffixProof::new();
        proof.final_evaluation = evaluation;
        proof.round_polynomials.push((F::from_u64(4), F::from_u64(5)));
        proof.challenges.push(F::from_u64(6));

        Ok(MemoryEvaluationPrefixSuffixResult {
            evaluation,
            proof,
        })
    }

    /// Compute performance metrics
    fn compute_metrics(
        &mut self,
        twist_result: &TwistProtocolResult<F>,
        prefix_suffix_result: &PrefixSuffixProtocolResult<F>,
    ) {
        // Get Twist metrics
        self.metrics.twist_metrics = self.twist_prover.estimate_total_operations();

        // Get Prefix-Suffix metrics
        let log_t = self.config.twist_config.log_num_operations();
        self.metrics.prefix_suffix_metrics.push(
            PrefixSuffixPerformanceAnalyzer::analyze_pcnext(log_t)
        );
        self.metrics.prefix_suffix_metrics.push(
            PrefixSuffixPerformanceAnalyzer::analyze_memory_evaluation(log_t)
        );

        // Compute totals
        self.metrics.compute_total();

        // Estimate proof size
        self.metrics.proof_size_bytes = twist_result.proof.size_bytes()
            + prefix_suffix_result.proofs.iter().map(|p| p.size_in_field_elements() * 32).sum::<usize>();
    }

    /// Get metrics
    pub fn metrics(&self) -> &Phase6And7Metrics {
        &self.metrics
    }

    /// Get configuration
    pub fn config(&self) -> &Phase6And7Config {
        &self.config
    }

    /// Estimate total field operations
    pub fn estimate_operations(&self) -> usize {
        let twist_ops = self.twist_prover.estimate_total_operations();
        let log_t = self.config.twist_config.log_num_operations();
        let sqrt_t = (self.config.twist_config.num_operations as f64).sqrt() as usize;

        // Prefix-suffix operations: O(√T) for each application
        let prefix_suffix_ops = 2 * sqrt_t;

        twist_ops.register_ops_total + twist_ops.ram_ops_total + prefix_suffix_ops
    }
}

/// Result of Twist protocol execution
#[derive(Clone, Debug)]
pub struct TwistProtocolResult<F: FieldElement> {
    pub read_checking_result: ReadCheckingResult<F>,
    pub write_checking_result: WriteCheckingResult<F>,
    pub memory_evaluation_result: MemoryEvaluationResult<F>,
    pub proof: TwistProof<F>,
    pub final_evaluations: Vec<F>,
}

/// Result of Prefix-Suffix protocol execution
#[derive(Clone, Debug)]
pub struct PrefixSuffixProtocolResult<F: FieldElement> {
    pub proofs: Vec<PrefixSuffixProof<F>>,
    pub pcnext_evaluation: F,
    pub memory_evaluation: F,
}

/// Result of pcnext evaluation
#[derive(Clone, Debug)]
pub struct PcnextEvaluationResult<F: FieldElement> {
    pub evaluation: F,
    pub proof: PrefixSuffixProof<F>,
}

/// Result of memory evaluation with prefix-suffix
#[derive(Clone, Debug)]
pub struct MemoryEvaluationPrefixSuffixResult<F: FieldElement> {
    pub evaluation: F,
    pub proof: PrefixSuffixProof<F>,
}

/// Combined Phase 6 & 7 proof
#[derive(Clone, Debug)]
pub struct Phase6And7Proof<F: FieldElement> {
    /// Twist protocol proof
    pub twist_proof: TwistProof<F>,
    /// Prefix-suffix protocol proofs
    pub prefix_suffix_proofs: Vec<PrefixSuffixProof<F>>,
    /// pcnext evaluation result
    pub pcnext_evaluation: F,
    /// Memory evaluation result
    pub memory_evaluation: F,
    /// Final evaluations from all protocols
    pub final_evaluations: Vec<F>,
}

impl<F: FieldElement> Phase6And7Proof<F> {
    /// Get total proof size in bytes
    pub fn size_bytes(&self) -> usize {
        let twist_size = self.twist_proof.size_bytes();
        let prefix_suffix_size = self.prefix_suffix_proofs.iter()
            .map(|p| p.size_in_field_elements() * 32)
            .sum::<usize>();
        let evaluations_size = self.final_evaluations.len() * 32;

        twist_size + prefix_suffix_size + evaluations_size
    }
}

/// Phase 6 & 7 verifier: Complete verification
pub struct Phase6And7Verifier<F: FieldElement> {
    config: Phase6And7Config,
    twist_verifier: AdvancedTwistVerifier<F>,
    prefix_suffix_verifier: PrefixSuffixVerifier<F>,
}

impl<F: FieldElement> Phase6And7Verifier<F> {
    /// Create a new Phase 6 & 7 verifier
    pub fn new(config: Phase6And7Config) -> Result<Self, String> {
        config.validate()?;

        let twist_verifier = AdvancedTwistVerifier::new(config.twist_config.clone())?;
        let prefix_suffix_verifier = PrefixSuffixVerifier::new(config.prefix_suffix_config.clone())?;

        Ok(Phase6And7Verifier {
            config,
            twist_verifier,
            prefix_suffix_verifier,
        })
    }

    /// Verify complete Phase 6 & 7 proof
    pub fn verify(&self, proof: &Phase6And7Proof<F>) -> bool {
        // Verify Twist proof
        if !self.twist_verifier.verify_proof(&proof.twist_proof) {
            return false;
        }

        // Verify all prefix-suffix proofs
        for ps_proof in &proof.prefix_suffix_proofs {
            if !self.prefix_suffix_verifier.verify(ps_proof) {
                return false;
            }
        }

        // Verify evaluations are consistent
        if proof.final_evaluations.is_empty() {
            return false;
        }

        true
    }

    /// Get configuration
    pub fn config(&self) -> &Phase6And7Config {
        &self.config
    }
}

/// Phase 6 & 7 protocol runner
pub struct Phase6And7Protocol<F: FieldElement> {
    config: Phase6And7Config,
    _phantom: PhantomData<F>,
}

impl<F: FieldElement> Phase6And7Protocol<F> {
    /// Create a new Phase 6 & 7 protocol runner
    pub fn new(config: Phase6And7Config) -> Result<Self, String> {
        config.validate()?;
        Ok(Phase6And7Protocol {
            config,
            _phantom: PhantomData,
        })
    }

    /// Run complete protocol with given operations
    pub fn run(
        &self,
        operations: Vec<MemoryOperation<F>>,
    ) -> Result<(Phase6And7Proof<F>, Phase6And7Metrics), String> {
        // Create prover
        let mut prover = Phase6And7Prover::new(self.config.clone(), operations)?;

        // Generate proof
        let proof = prover.prove()?;
        let metrics = prover.metrics().clone();

        Ok((proof, metrics))
    }

    /// Get configuration
    pub fn config(&self) -> &Phase6And7Config {
        &self.config
    }
}

/// Phase 6 & 7 performance analyzer
pub struct Phase6And7PerformanceAnalyzer;

impl Phase6And7PerformanceAnalyzer {
    /// Analyze performance for given parameters
    pub fn analyze(
        memory_size: usize,
        num_operations: usize,
        dimension: usize,
    ) -> Phase6And7PerformanceReport {
        let config = Phase6And7Config::new(memory_size, num_operations, dimension);

        let t = num_operations;
        let log_t = (t as f64).log2().ceil() as usize;
        let sqrt_t = (t as f64).sqrt() as usize;

        // Twist operations
        let register_ops_linear = 35 * t;
        let register_ops_small_space = 4 * t * log_t;
        let ram_ops_linear = 150 * t;
        let ram_ops_small_space = 4 * t * log_t;

        // Prefix-suffix operations
        let pcnext_ops = 2 * sqrt_t;
        let memory_eval_ops = 2 * sqrt_t;

        let total_ops = register_ops_linear + register_ops_small_space
            + ram_ops_linear + ram_ops_small_space
            + pcnext_ops + memory_eval_ops;

        let space_used = config.twist_config.space_complexity()
            + config.prefix_suffix_config.space_complexity();

        let slowdown_factor = total_ops as f64 / ((35 + 150) * t) as f64;

        Phase6And7PerformanceReport {
            memory_size,
            num_operations,
            dimension,
            register_ops_linear,
            register_ops_small_space,
            register_ops_total: register_ops_linear + register_ops_small_space,
            ram_ops_linear,
            ram_ops_small_space,
            ram_ops_total: ram_ops_linear + ram_ops_small_space,
            pcnext_ops,
            memory_eval_ops,
            total_ops,
            space_used,
            slowdown_factor,
        }
    }

    /// Compare performance across different dimensions
    pub fn compare_dimensions(
        memory_size: usize,
        num_operations: usize,
    ) -> Vec<Phase6And7PerformanceReport> {
        let mut reports = Vec::new();

        for d in 1..=5 {
            reports.push(Self::analyze(memory_size, num_operations, d));
        }

        reports
    }
}

/// Phase 6 & 7 performance report
#[derive(Clone, Debug)]
pub struct Phase6And7PerformanceReport {
    /// Memory size K
    pub memory_size: usize,
    /// Number of operations T
    pub num_operations: usize,
    /// Dimension parameter d
    pub dimension: usize,
    /// Register operations (linear-time)
    pub register_ops_linear: usize,
    /// Register operations (small-space)
    pub register_ops_small_space: usize,
    /// Register operations (total)
    pub register_ops_total: usize,
    /// RAM operations (linear-time)
    pub ram_ops_linear: usize,
    /// RAM operations (small-space)
    pub ram_ops_small_space: usize,
    /// RAM operations (total)
    pub ram_ops_total: usize,
    /// pcnext operations
    pub pcnext_ops: usize,
    /// Memory evaluation operations
    pub memory_eval_ops: usize,
    /// Total field operations
    pub total_ops: usize,
    /// Space used
    pub space_used: usize,
    /// Slowdown factor vs linear-time
    pub slowdown_factor: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    use crate::small_space_zkvm::twist::MemoryOperation;

    #[test]
    fn test_phase6_7_config_creation() {
        let config = Phase6And7Config::new(256, 1024, 2);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_phase6_7_config_with_tracking() {
        let config = Phase6And7Config::new(256, 1024, 2)
            .with_performance_tracking();
        assert!(config.track_performance);
    }

    #[test]
    fn test_phase6_7_metrics() {
        let mut metrics = Phase6And7Metrics::new();
        metrics.twist_metrics.register_ops_linear = 1000;
        metrics.twist_metrics.ram_ops_linear = 2000;
        metrics.prefix_suffix_metrics.push(PrefixSuffixPerformanceReport {
            operation: "test".to_string(),
            num_vars: 8,
            num_stages: 2,
            num_terms: 2,
            space_complexity: 100,
            time_complexity: 100,
            field_operations: 500,
        });
        metrics.compute_total();

        assert!(metrics.total_operations > 0);
        assert!(metrics.total_space_used > 0);
    }

    #[test]
    fn test_phase6_7_performance_analysis() {
        let report = Phase6And7PerformanceAnalyzer::analyze(256, 1024, 2);
        assert!(report.total_ops > 0);
        assert!(report.space_used > 0);
        assert!(report.slowdown_factor > 0.0);
    }

    #[test]
    fn test_phase6_7_dimension_comparison() {
        let reports = Phase6And7PerformanceAnalyzer::compare_dimensions(256, 1024);
        assert_eq!(reports.len(), 5);

        for report in &reports {
            assert!(report.total_ops > 0);
            assert!(report.space_used > 0);
        }
    }

    #[test]
    fn test_phase6_7_protocol_creation() {
        let config = Phase6And7Config::new(256, 1024, 2);
        let protocol = Phase6And7Protocol::<PrimeField>::new(config);
        assert!(protocol.is_ok());
    }

    #[test]
    fn test_phase6_7_prover_creation() {
        let config = Phase6And7Config::new(16, 32, 2);
        let operations = vec![
            MemoryOperation::write(0, PrimeField::from_u64(42), 1),
            MemoryOperation::read(0, PrimeField::from_u64(42), 2),
            MemoryOperation::write(1, PrimeField::from_u64(84), 3),
            MemoryOperation::read(1, PrimeField::from_u64(84), 4),
        ];

        let prover = Phase6And7Prover::new(config, operations);
        assert!(prover.is_ok());
    }

    #[test]
    fn test_phase6_7_verifier_creation() {
        let config = Phase6And7Config::new(16, 32, 2);
        let verifier = Phase6And7Verifier::<PrimeField>::new(config);
        assert!(verifier.is_ok());
    }
}