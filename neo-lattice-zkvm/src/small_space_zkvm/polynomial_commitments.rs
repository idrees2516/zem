// Unified Polynomial Commitment Scheme Interface
//
// This module provides a unified interface for all polynomial commitment schemes
// implemented in the small-space zkVM: Hyrax, Dory, and hash-based schemes.
//
// Based on:
// - Requirements 8.1-8.17 from the small-space zkVM specification
// - "Proving CPU Executions in Small Space" performance requirements
//
// Key features:
// - Unified trait for all commitment schemes
// - Automatic scheme selection based on parameters
// - Performance comparison and benchmarking
// - Streaming computation support across all schemes
// - Security assumption analysis

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::hyrax::{
    GroupElement, HyraxProver, HyraxCommitmentKey, HyraxCommitment, 
    SimpleEvaluationProof, SimpleHyraxVerifier, PolynomialOracle
};
use crate::small_space_zkvm::dory::{
    BilinearPairing, DoryProver, DoryCommitmentKey, DoryCommitment, 
    DoryEvaluationProof, DoryVerifier, StreamingDoryProver
};
use crate::small_space_zkvm::hash_based_commitments::{
    HashFunction, ErrorCorrectingCode, HashBasedProver, HashBasedVerifier,
    HashBasedCommitment, HashBasedEvaluationProof, HashBasedConfig
};
use crate::small_space_zkvm::bulletproofs::{BulletproofsEvaluationProof, StreamingBulletproofsProver};
use std::marker::PhantomData;

/// Security assumptions for polynomial commitment schemes
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityAssumption {
    /// Elliptic curve discrete logarithm (pre-quantum)
    EllipticCurveDiscreteLog,
    /// Bilinear pairing assumptions (pre-quantum)
    BilinearPairing,
    /// Hash function security (post-quantum)
    HashFunction,
    /// Lattice-based assumptions (post-quantum)
    Lattice,
}

/// Polynomial commitment scheme type
#[derive(Debug, Clone, PartialEq)]
pub enum CommitmentSchemeType {
    /// Hyrax scheme (elliptic curve based)
    Hyrax,
    /// Dory scheme (bilinear pairing based)
    Dory,
    /// Hash-based schemes (Ligero, Brakedown, Binius)
    HashBased,
    /// Lattice-based schemes (HyperWolf, SALSAA)
    LatticeBased,
}

/// Performance characteristics of a commitment scheme
#[derive(Debug, Clone)]
pub struct PerformanceCharacteristics {
    /// Commitment size in bytes
    pub commitment_size: usize,
    /// Evaluation proof size in bytes
    pub proof_size: usize,
    /// Prover time complexity (field operations)
    pub prover_time: usize,
    /// Verifier time complexity (operations)
    pub verifier_time: usize,
    /// Prover space complexity (field elements)
    pub prover_space: usize,
    /// Setup size (group elements or similar)
    pub setup_size: usize,
    /// Security assumption
    pub security_assumption: SecurityAssumption,
}

/// Unified polynomial commitment scheme trait
pub trait PolynomialCommitmentScheme<F: FieldElement> {
    type Commitment: Clone;
    type EvaluationProof: Clone;
    type Error: std::fmt::Debug;
    
    /// Commit to polynomial
    fn commit<P: PolynomialOracle<F>>(
        &self,
        oracle: &P
    ) -> Result<Self::Commitment, Self::Error>;
    
    /// Generate evaluation proof
    fn prove_evaluation<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        commitment: &Self::Commitment,
        evaluation_point: &[F],
        claimed_evaluation: F
    ) -> Result<Self::EvaluationProof, Self::Error>;
    
    /// Verify evaluation proof
    fn verify_evaluation(
        &self,
        commitment: &Self::Commitment,
        evaluation_point: &[F],
        claimed_evaluation: F,
        proof: &Self::EvaluationProof
    ) -> Result<bool, Self::Error>;
    
    /// Get performance characteristics
    fn performance_characteristics(&self) -> PerformanceCharacteristics;
    
    /// Get scheme type
    fn scheme_type(&self) -> CommitmentSchemeType;
    
    /// Get security assumption
    fn security_assumption(&self) -> SecurityAssumption;
}

/// Hyrax commitment scheme wrapper
pub struct HyraxCommitmentScheme<G: GroupElement> {
    /// Hyrax prover
    pub prover: HyraxProver<G>,
    /// Hyrax verifier
    pub verifier: SimpleHyraxVerifier<G>,
    /// Performance parameters
    pub memory_size: usize,
    pub num_operations: usize,
}

impl<G: GroupElement> HyraxCommitmentScheme<G> {
    /// Create new Hyrax commitment scheme
    pub fn new(
        commitment_key: HyraxCommitmentKey<G>,
        memory_size: usize,
        num_operations: usize
    ) -> Self {
        let prover = HyraxProver::new(commitment_key.clone());
        let verifier = SimpleHyraxVerifier::new(commitment_key);
        
        HyraxCommitmentScheme {
            prover,
            verifier,
            memory_size,
            num_operations,
        }
    }
}

impl<G: GroupElement> PolynomialCommitmentScheme<G::Scalar> for HyraxCommitmentScheme<G> {
    type Commitment = HyraxCommitment<G>;
    type EvaluationProof = SimpleEvaluationProof<G>;
    type Error = String;
    
    fn commit<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P
    ) -> Result<Self::Commitment, Self::Error> {
        self.prover.commit(oracle)
    }
    
    fn prove_evaluation<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        _commitment: &Self::Commitment,
        evaluation_point: &[G::Scalar],
        _claimed_evaluation: G::Scalar
    ) -> Result<Self::EvaluationProof, Self::Error> {
        let (_, r2) = self.prover.split_evaluation_point(evaluation_point)?;
        let k_vector = self.prover.compute_matrix_vector_product(oracle, &r2)?;
        Ok(SimpleEvaluationProof::new(k_vector))
    }
    
    fn verify_evaluation(
        &self,
        commitment: &Self::Commitment,
        evaluation_point: &[G::Scalar],
        claimed_evaluation: G::Scalar,
        proof: &Self::EvaluationProof
    ) -> Result<bool, Self::Error> {
        self.verifier.verify_evaluation(commitment, evaluation_point, claimed_evaluation, proof)
    }
    
    fn performance_characteristics(&self) -> PerformanceCharacteristics {
        let sqrt_kt = ((self.memory_size * self.num_operations) as f64).sqrt() as usize;
        
        PerformanceCharacteristics {
            commitment_size: sqrt_kt * 32, // √(KT) group elements
            proof_size: sqrt_kt * 32, // O(√n) field elements
            prover_time: self.memory_size * self.num_operations, // O(n) field operations
            verifier_time: sqrt_kt, // O(√n) group operations
            prover_space: sqrt_kt, // O(√n) field elements
            setup_size: sqrt_kt * 32, // √(KT) group elements
            security_assumption: SecurityAssumption::EllipticCurveDiscreteLog,
        }
    }
    
    fn scheme_type(&self) -> CommitmentSchemeType {
        CommitmentSchemeType::Hyrax
    }
    
    fn security_assumption(&self) -> SecurityAssumption {
        SecurityAssumption::EllipticCurveDiscreteLog
    }
}

/// Dory commitment scheme wrapper
pub struct DoryCommitmentScheme<P: BilinearPairing> {
    /// Dory prover
    pub prover: DoryProver<P>,
    /// Dory verifier
    pub verifier: DoryVerifier<P>,
    /// Performance parameters
    pub memory_size: usize,
    pub num_operations: usize,
}

impl<P: BilinearPairing> DoryCommitmentScheme<P> {
    /// Create new Dory commitment scheme
    pub fn new(
        commitment_key: DoryCommitmentKey<P>,
        memory_size: usize,
        num_operations: usize
    ) -> Self {
        let prover = DoryProver::new(commitment_key.clone());
        let verifier = DoryVerifier::new(commitment_key);
        
        DoryCommitmentScheme {
            prover,
            verifier,
            memory_size,
            num_operations,
        }
    }
}

impl<P: BilinearPairing> PolynomialCommitmentScheme<<P::G1 as GroupElement>::Scalar> for DoryCommitmentScheme<P> {
    type Commitment = DoryCommitment<P>;
    type EvaluationProof = DoryEvaluationProof<P>;
    type Error = String;
    
    fn commit<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        oracle: &O
    ) -> Result<Self::Commitment, Self::Error> {
        self.prover.commit(oracle)
    }
    
    fn prove_evaluation<O: PolynomialOracle<<P::G1 as GroupElement>::Scalar>>(
        &self,
        _oracle: &O,
        _commitment: &Self::Commitment,
        _evaluation_point: &[<P::G1 as GroupElement>::Scalar],
        _claimed_evaluation: <P::G1 as GroupElement>::Scalar
    ) -> Result<Self::EvaluationProof, Self::Error> {
        // Simplified - in practice would use the streaming Dory prover
        Ok(DoryEvaluationProof {
            bulletproofs_proof: BulletproofsEvaluationProof {
                rounds: Vec::new(),
                final_a: <P::G1 as GroupElement>::Scalar::zero(),
                final_b: <P::G1 as GroupElement>::Scalar::zero(),
            },
            pairing_elements: Vec::new(),
        })
    }
    
    fn verify_evaluation(
        &self,
        commitment: &Self::Commitment,
        evaluation_point: &[<P::G1 as GroupElement>::Scalar],
        claimed_evaluation: <P::G1 as GroupElement>::Scalar,
        proof: &Self::EvaluationProof
    ) -> Result<bool, Self::Error> {
        self.verifier.verify_evaluation(commitment, evaluation_point, claimed_evaluation, proof)
    }
    
    fn performance_characteristics(&self) -> PerformanceCharacteristics {
        let sqrt_kt = ((self.memory_size * self.num_operations) as f64).sqrt() as usize;
        
        PerformanceCharacteristics {
            commitment_size: 48, // Single GT element
            proof_size: (sqrt_kt as f64).log2() as usize * 96 + 64, // O(log √n) group elements
            prover_time: 30 * self.num_operations, // ≤ 30T field operations
            verifier_time: (sqrt_kt as f64).log2() as usize, // O(log √n) pairings
            prover_space: sqrt_kt, // O(√n) field elements
            setup_size: 2 * sqrt_kt * 32, // 2√(KT) group elements
            security_assumption: SecurityAssumption::BilinearPairing,
        }
    }
    
    fn scheme_type(&self) -> CommitmentSchemeType {
        CommitmentSchemeType::Dory
    }
    
    fn security_assumption(&self) -> SecurityAssumption {
        SecurityAssumption::BilinearPairing
    }
}

/// Hash-based commitment scheme wrapper
pub struct HashBasedCommitmentScheme<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> {
    /// Hash-based prover
    pub prover: HashBasedProver<F, H, E>,
    /// Hash-based verifier
    pub verifier: HashBasedVerifier<F, H, E>,
    /// Configuration
    pub config: HashBasedConfig,
}

impl<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> HashBasedCommitmentScheme<F, H, E> {
    /// Create new hash-based commitment scheme
    pub fn new(config: HashBasedConfig, ecc: E) -> Self {
        let prover = HashBasedProver::new(config.clone(), ecc.clone());
        let verifier = HashBasedVerifier::new(config.clone(), ecc);
        
        HashBasedCommitmentScheme {
            prover,
            verifier,
            config,
        }
    }
}

impl<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F> + Clone> PolynomialCommitmentScheme<F> for HashBasedCommitmentScheme<F, H, E> {
    type Commitment = HashBasedCommitment;
    type EvaluationProof = HashBasedEvaluationProof<F>;
    type Error = String;
    
    fn commit<P: PolynomialOracle<F>>(
        &self,
        oracle: &P
    ) -> Result<Self::Commitment, Self::Error> {
        let (commitment, _) = self.prover.commit(oracle)?;
        Ok(commitment)
    }
    
    fn prove_evaluation<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        _commitment: &Self::Commitment,
        evaluation_point: &[F],
        claimed_evaluation: F
    ) -> Result<Self::EvaluationProof, Self::Error> {
        // Need to recreate Merkle tree - in practice would store it
        let (_, merkle_tree) = self.prover.commit(oracle)?;
        self.prover.prove_evaluation(oracle, &merkle_tree, evaluation_point, claimed_evaluation)
    }
    
    fn verify_evaluation(
        &self,
        commitment: &Self::Commitment,
        evaluation_point: &[F],
        claimed_evaluation: F,
        proof: &Self::EvaluationProof
    ) -> Result<bool, Self::Error> {
        self.verifier.verify_evaluation(commitment, evaluation_point, claimed_evaluation, proof)
    }
    
    fn performance_characteristics(&self) -> PerformanceCharacteristics {
        PerformanceCharacteristics {
            commitment_size: H::OUTPUT_SIZE, // Single hash
            proof_size: self.config.proof_size_estimate(),
            prover_time: self.config.num_evaluations, // O(n) field operations
            verifier_time: self.config.security_parameter * self.config.matrix_dim, // O(λ√n)
            prover_space: self.config.matrix_dim, // O(√n) field elements
            setup_size: 0, // No trusted setup
            security_assumption: SecurityAssumption::HashFunction,
        }
    }
    
    fn scheme_type(&self) -> CommitmentSchemeType {
        CommitmentSchemeType::HashBased
    }
    
    fn security_assumption(&self) -> SecurityAssumption {
        SecurityAssumption::HashFunction
    }
}

/// Commitment scheme selector for automatic scheme selection
pub struct CommitmentSchemeSelector {
    /// Target security level (bits)
    pub security_level: usize,
    /// Memory size K
    pub memory_size: usize,
    /// Number of operations T
    pub num_operations: usize,
    /// Post-quantum requirement
    pub post_quantum: bool,
    /// Proof size priority (0.0 = don't care, 1.0 = minimize)
    pub proof_size_priority: f64,
    /// Prover time priority (0.0 = don't care, 1.0 = minimize)
    pub prover_time_priority: f64,
    /// Verifier time priority (0.0 = don't care, 1.0 = minimize)
    pub verifier_time_priority: f64,
}

impl CommitmentSchemeSelector {
    /// Create new commitment scheme selector
    pub fn new(
        security_level: usize,
        memory_size: usize,
        num_operations: usize,
        post_quantum: bool
    ) -> Self {
        CommitmentSchemeSelector {
            security_level,
            memory_size,
            num_operations,
            post_quantum,
            proof_size_priority: 0.3,
            prover_time_priority: 0.4,
            verifier_time_priority: 0.3,
        }
    }
    
    /// Set optimization priorities
    pub fn with_priorities(
        mut self,
        proof_size: f64,
        prover_time: f64,
        verifier_time: f64
    ) -> Self {
        let total = proof_size + prover_time + verifier_time;
        self.proof_size_priority = proof_size / total;
        self.prover_time_priority = prover_time / total;
        self.verifier_time_priority = verifier_time / total;
        self
    }
    
    /// Select optimal commitment scheme
    pub fn select_scheme(&self) -> CommitmentSchemeType {
        if self.post_quantum {
            // Post-quantum schemes only
            if self.proof_size_priority > 0.5 {
                CommitmentSchemeType::LatticeBased // Better proof sizes
            } else {
                CommitmentSchemeType::HashBased // Better prover time
            }
        } else {
            // Pre-quantum schemes available
            let sqrt_kt = ((self.memory_size * self.num_operations) as f64).sqrt();
            
            if sqrt_kt < 1000.0 {
                // Small instances: Hyrax is efficient
                CommitmentSchemeType::Hyrax
            } else if self.proof_size_priority > 0.6 {
                // Proof size critical: Dory (single GT element)
                CommitmentSchemeType::Dory
            } else if self.prover_time_priority > 0.6 {
                // Prover time critical: Hash-based (linear time)
                CommitmentSchemeType::HashBased
            } else {
                // Balanced: Dory for good overall performance
                CommitmentSchemeType::Dory
            }
        }
    }
    
    /// Get recommendation explanation
    pub fn explain_selection(&self) -> String {
        let scheme = self.select_scheme();
        let sqrt_kt = ((self.memory_size * self.num_operations) as f64).sqrt();
        
        match scheme {
            CommitmentSchemeType::Hyrax => {
                format!(
                    "Hyrax selected: Small instance (√(KT) = {:.0}), good for elliptic curve efficiency",
                    sqrt_kt
                )
            }
            CommitmentSchemeType::Dory => {
                format!(
                    "Dory selected: Balanced performance with single GT element commitment (√(KT) = {:.0})",
                    sqrt_kt
                )
            }
            CommitmentSchemeType::HashBased => {
                if self.post_quantum {
                    "Hash-based selected: Post-quantum requirement with good prover time".to_string()
                } else {
                    "Hash-based selected: Prover time priority with linear-time proving".to_string()
                }
            }
            CommitmentSchemeType::LatticeBased => {
                "Lattice-based selected: Post-quantum requirement with good proof sizes".to_string()
            }
        }
    }
}

/// Performance comparison tool
pub struct PerformanceComparison {
    /// Schemes to compare
    pub schemes: Vec<(CommitmentSchemeType, PerformanceCharacteristics)>,
}

impl PerformanceComparison {
    /// Create new performance comparison
    pub fn new() -> Self {
        PerformanceComparison {
            schemes: Vec::new(),
        }
    }
    
    /// Add scheme for comparison
    pub fn add_scheme(
        mut self,
        scheme_type: CommitmentSchemeType,
        characteristics: PerformanceCharacteristics
    ) -> Self {
        self.schemes.push((scheme_type, characteristics));
        self
    }
    
    /// Generate comparison report
    pub fn generate_report(&self) -> String {
        let mut report = String::from("Polynomial Commitment Scheme Comparison:\n\n");
        
        // Header
        report.push_str(&format!(
            "{:<15} {:<12} {:<12} {:<12} {:<12} {:<12} {:<15}\n",
            "Scheme", "Commit(B)", "Proof(B)", "Prover(ops)", "Verifier", "Space", "Security"
        ));
        report.push_str(&"-".repeat(100));
        report.push('\n');
        
        // Data rows
        for (scheme_type, chars) in &self.schemes {
            let security_str = match chars.security_assumption {
                SecurityAssumption::EllipticCurveDiscreteLog => "ECDL",
                SecurityAssumption::BilinearPairing => "Pairing",
                SecurityAssumption::HashFunction => "Hash",
                SecurityAssumption::Lattice => "Lattice",
            };
            
            report.push_str(&format!(
                "{:<15} {:<12} {:<12} {:<12} {:<12} {:<12} {:<15}\n",
                format!("{:?}", scheme_type),
                self.format_size(chars.commitment_size),
                self.format_size(chars.proof_size),
                self.format_ops(chars.prover_time),
                self.format_ops(chars.verifier_time),
                self.format_size(chars.prover_space * 32), // Convert to bytes
                security_str
            ));
        }
        
        report.push('\n');
        
        // Analysis
        report.push_str("Analysis:\n");
        
        // Best commitment size
        if let Some((best_scheme, best_chars)) = self.schemes.iter()
            .min_by_key(|(_, chars)| chars.commitment_size) {
            report.push_str(&format!(
                "- Smallest commitment: {:?} ({} bytes)\n",
                best_scheme,
                best_chars.commitment_size
            ));
        }
        
        // Best proof size
        if let Some((best_scheme, best_chars)) = self.schemes.iter()
            .min_by_key(|(_, chars)| chars.proof_size) {
            report.push_str(&format!(
                "- Smallest proof: {:?} ({} bytes)\n",
                best_scheme,
                best_chars.proof_size
            ));
        }
        
        // Best prover time
        if let Some((best_scheme, best_chars)) = self.schemes.iter()
            .min_by_key(|(_, chars)| chars.prover_time) {
            report.push_str(&format!(
                "- Fastest prover: {:?} ({} ops)\n",
                best_scheme,
                best_chars.prover_time
            ));
        }
        
        // Post-quantum schemes
        let pq_schemes: Vec<_> = self.schemes.iter()
            .filter(|(_, chars)| matches!(
                chars.security_assumption,
                SecurityAssumption::HashFunction | SecurityAssumption::Lattice
            ))
            .collect();
        
        if !pq_schemes.is_empty() {
            report.push_str(&format!(
                "- Post-quantum schemes: {} available\n",
                pq_schemes.len()
            ));
        }
        
        report
    }
    
    /// Format size in human-readable form
    fn format_size(&self, size: usize) -> String {
        if size >= 1_000_000 {
            format!("{:.1}M", size as f64 / 1_000_000.0)
        } else if size >= 1_000 {
            format!("{:.1}K", size as f64 / 1_000.0)
        } else {
            size.to_string()
        }
    }
    
    /// Format operations in human-readable form
    fn format_ops(&self, ops: usize) -> String {
        if ops >= 1_000_000_000 {
            format!("{:.1}G", ops as f64 / 1_000_000_000.0)
        } else if ops >= 1_000_000 {
            format!("{:.1}M", ops as f64 / 1_000_000.0)
        } else if ops >= 1_000 {
            format!("{:.1}K", ops as f64 / 1_000.0)
        } else {
            ops.to_string()
        }
    }
}

/// Commitment scheme benchmarker
pub struct CommitmentSchemeBenchmarker {
    /// Number of variables for test polynomial
    pub num_vars: usize,
    /// Number of benchmark iterations
    pub iterations: usize,
}

impl CommitmentSchemeBenchmarker {
    /// Create new benchmarker
    pub fn new(num_vars: usize, iterations: usize) -> Self {
        CommitmentSchemeBenchmarker {
            num_vars,
            iterations,
        }
    }
    
    /// Benchmark commitment scheme
    pub fn benchmark<F: FieldElement, S: PolynomialCommitmentScheme<F>>(
        &self,
        scheme: &S,
        oracle: &dyn PolynomialOracle<F>
    ) -> BenchmarkResult {
        let start_time = std::time::Instant::now();
        
        // Benchmark commitment
        let commit_start = std::time::Instant::now();
        let commitment = scheme.commit(oracle).unwrap();
        let commit_time = commit_start.elapsed();
        
        // Benchmark evaluation proof
        let evaluation_point: Vec<F> = (0..self.num_vars)
            .map(|i| F::from_u64(i as u64))
            .collect();
        let claimed_evaluation = F::from_u64(42);
        
        let prove_start = std::time::Instant::now();
        let proof = scheme.prove_evaluation(
            oracle,
            &commitment,
            &evaluation_point,
            claimed_evaluation
        ).unwrap();
        let prove_time = prove_start.elapsed();
        
        // Benchmark verification
        let verify_start = std::time::Instant::now();
        let is_valid = scheme.verify_evaluation(
            &commitment,
            &evaluation_point,
            claimed_evaluation,
            &proof
        ).unwrap();
        let verify_time = verify_start.elapsed();
        
        let total_time = start_time.elapsed();
        
        BenchmarkResult {
            scheme_type: scheme.scheme_type(),
            commit_time_ms: commit_time.as_millis() as usize,
            prove_time_ms: prove_time.as_millis() as usize,
            verify_time_ms: verify_time.as_millis() as usize,
            total_time_ms: total_time.as_millis() as usize,
            is_valid,
            characteristics: scheme.performance_characteristics(),
        }
    }
}

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Scheme type
    pub scheme_type: CommitmentSchemeType,
    /// Commitment time in milliseconds
    pub commit_time_ms: usize,
    /// Proof generation time in milliseconds
    pub prove_time_ms: usize,
    /// Verification time in milliseconds
    pub verify_time_ms: usize,
    /// Total time in milliseconds
    pub total_time_ms: usize,
    /// Whether verification succeeded
    pub is_valid: bool,
    /// Performance characteristics
    pub characteristics: PerformanceCharacteristics,
}

impl BenchmarkResult {
    /// Generate benchmark report
    pub fn generate_report(&self) -> String {
        format!(
            "Benchmark Result for {:?}:\n\
             - Commitment time: {} ms\n\
             - Proof time: {} ms\n\
             - Verification time: {} ms\n\
             - Total time: {} ms\n\
             - Verification: {}\n\
             - Commitment size: {} bytes\n\
             - Proof size: {} bytes\n\
             - Security: {:?}",
            self.scheme_type,
            self.commit_time_ms,
            self.prove_time_ms,
            self.verify_time_ms,
            self.total_time_ms,
            if self.is_valid { "PASSED" } else { "FAILED" },
            self.characteristics.commitment_size,
            self.characteristics.proof_size,
            self.characteristics.security_assumption
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    use crate::small_space_zkvm::hyrax::{HyraxConfig, MockGroupElement};
    
    // Mock polynomial oracle for testing
    struct MockPolynomialOracle {
        evaluations: Vec<PrimeField>,
        num_vars: usize,
    }
    
    impl PolynomialOracle<PrimeField> for MockPolynomialOracle {
        fn evaluate_at(&self, index: usize) -> PrimeField {
            if index < self.evaluations.len() {
                self.evaluations[index]
            } else {
                PrimeField::zero()
            }
        }
        
        fn num_evaluations(&self) -> usize {
            self.evaluations.len()
        }
        
        fn num_variables(&self) -> usize {
            self.num_vars
        }
    }
    
    #[test]
    fn test_commitment_scheme_selector() {
        let selector = CommitmentSchemeSelector::new(128, 1024, 1024, false);
        let scheme = selector.select_scheme();
        
        // Should select Hyrax for small instances
        assert_eq!(scheme, CommitmentSchemeType::Hyrax);
        
        let explanation = selector.explain_selection();
        assert!(explanation.contains("Hyrax"));
    }
    
    #[test]
    fn test_commitment_scheme_selector_post_quantum() {
        let selector = CommitmentSchemeSelector::new(128, 1024, 1024, true);
        let scheme = selector.select_scheme();
        
        // Should select post-quantum scheme
        assert!(matches!(
            scheme,
            CommitmentSchemeType::HashBased | CommitmentSchemeType::LatticeBased
        ));
    }
    
    #[test]
    fn test_performance_comparison() {
        let mut comparison = PerformanceComparison::new();
        
        // Add Hyrax characteristics
        comparison = comparison.add_scheme(
            CommitmentSchemeType::Hyrax,
            PerformanceCharacteristics {
                commitment_size: 1024,
                proof_size: 1024,
                prover_time: 1000000,
                verifier_time: 1000,
                prover_space: 1024,
                setup_size: 1024,
                security_assumption: SecurityAssumption::EllipticCurveDiscreteLog,
            }
        );
        
        // Add hash-based characteristics
        comparison = comparison.add_scheme(
            CommitmentSchemeType::HashBased,
            PerformanceCharacteristics {
                commitment_size: 32,
                proof_size: 4096,
                prover_time: 500000,
                verifier_time: 2000,
                prover_space: 512,
                setup_size: 0,
                security_assumption: SecurityAssumption::HashFunction,
            }
        );
        
        let report = comparison.generate_report();
        assert!(report.contains("Polynomial Commitment Scheme Comparison"));
        assert!(report.contains("Hyrax"));
        assert!(report.contains("HashBased"));
        assert!(report.contains("Smallest commitment"));
    }
    
    #[test]
    fn test_hyrax_commitment_scheme_wrapper() {
        let config = HyraxConfig::new(4, 128).unwrap();
        let key = HyraxCommitmentKey::<MockGroupElement>::generate(config);
        let scheme = HyraxCommitmentScheme::new(key, 1024, 1024);
        
        assert_eq!(scheme.scheme_type(), CommitmentSchemeType::Hyrax);
        assert_eq!(scheme.security_assumption(), SecurityAssumption::EllipticCurveDiscreteLog);
        
        let characteristics = scheme.performance_characteristics();
        assert!(characteristics.commitment_size > 0);
        assert!(characteristics.proof_size > 0);
    }
    
    #[test]
    fn test_commitment_scheme_benchmarker() {
        let benchmarker = CommitmentSchemeBenchmarker::new(4, 1);
        
        // Create mock scheme and oracle
        let config = HyraxConfig::new(4, 128).unwrap();
        let key = HyraxCommitmentKey::<MockGroupElement>::generate(config);
        let scheme = HyraxCommitmentScheme::new(key, 1024, 1024);
        
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        let result = benchmarker.benchmark(&scheme, &oracle);
        assert!(result.is_valid);
        assert!(result.total_time_ms >= result.commit_time_ms);
        
        let report = result.generate_report();
        assert!(report.contains("Benchmark Result"));
        assert!(report.contains("PASSED"));
    }
}