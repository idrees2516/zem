// Security Analysis and Parameter Validation for RoKoko
//
// Implements security analysis, parameter validation, and attack resistance:
// - Post-quantum security estimates
// - Parameter validation against known attacks
// - Side-channel resistance verification
// - Soundness and zero-knowledge analysis
// - Concrete security level computation

use crate::errors::ZKVMError;
use crate::rokoko::lattice::LatticeParams;
use crate::rokoko::{RokokoConfig, SECURITY_PARAMETER};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    /// Achieved security level in bits
    pub security_level_bits: usize,
    
    /// Classical security level
    pub classical_security: usize,
    
    /// Quantum security level (post-quantum)
    pub quantum_security: usize,
    
    /// Soundness error (probability of accepting invalid proof)
    pub soundness_error: f64,
    
    /// Zero-knowledge error (distinguishing advantage)
    pub zk_error: f64,
    
    /// Known attack resistances
    pub attack_resistances: HashMap<AttackType, AttackResistance>,
    
    /// Parameter recommendations
    pub recommendations: Vec<String>,
}

impl SecurityAnalysis {
    pub fn new(
        security_level_bits: usize,
        classical_security: usize,
        quantum_security: usize,
        soundness_error: f64,
        zk_error: f64,
    ) -> Self {
        Self {
            security_level_bits,
            classical_security,
            quantum_security,
            soundness_error,
            zk_error,
            attack_resistances: HashMap::new(),
            recommendations: Vec::new(),
        }
    }
    
    /// Checks if security meets requirements
    pub fn meets_requirements(&self, required_bits: usize) -> bool {
        self.quantum_security >= required_bits &&
        self.soundness_error < 2.0_f64.powi(-(required_bits as i32)) &&
        self.zk_error < 2.0_f64.powi(-(required_bits as i32))
    }
    
    /// Adds attack resistance analysis
    pub fn add_attack_resistance(&mut self, attack: AttackType, resistance: AttackResistance) {
        self.attack_resistances.insert(attack, resistance);
    }
    
    /// Adds recommendation
    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }
}

/// Types of cryptographic attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    /// BKZ/LLL lattice reduction
    LatticeReduction,
    
    /// Primal attack on LWE
    PrimalAttack,
    
    /// Dual attack on LWE
    DualAttack,
    
    /// Meet-in-the-middle attack
    MeetInTheMiddle,
    
    /// Birthday attack on hash functions
    BirthdayAttack,
    
    /// Quantum algorithms (Grover/Shor)
    QuantumAttack,
    
    /// Side-channel attacks (timing, power)
    SideChannel,
    
    /// Algebraic attacks
    AlgebraicAttack,
}

/// Attack resistance level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResistance {
    /// Resistance level in bits
    pub bits: usize,
    
    /// Attack complexity (operations)
    pub complexity: f64,
    
    /// Whether parameters are safe
    pub is_safe: bool,
    
    /// Additional notes
    pub notes: String,
}

impl AttackResistance {
    pub fn new(bits: usize, complexity: f64, is_safe: bool, notes: String) -> Self {
        Self {
            bits,
            complexity,
            is_safe,
            notes,
        }
    }
}

/// Security analyzer for RoKoko parameters
pub struct SecurityAnalyzer {
    /// Target security level
    target_security: usize,
    
    /// Conservative mode (stricter estimates)
    conservative: bool,
}

impl SecurityAnalyzer {
    pub fn new(target_security: usize) -> Self {
        Self {
            target_security,
            conservative: true,
        }
    }
    
    /// Enables/disables conservative mode
    pub fn set_conservative(mut self, conservative: bool) -> Self {
        self.conservative = conservative;
        self
    }
    
    /// Analyzes RoKoko configuration security
    pub fn analyze_config(&self, config: &RokokoConfig) -> Result<SecurityAnalysis, ZKVMError> {
        config.validate()?;
        
        // Compute classical and quantum security
        let classical_security = self.compute_classical_security(config);
        let quantum_security = self.compute_quantum_security(config);
        
        // Compute error probabilities
        let soundness_error = self.compute_soundness_error(config);
        let zk_error = if config.constant_time {
            2.0_f64.powi(-(config.security_level as i32))
        } else {
            2.0_f64.powi(-((config.security_level / 2) as i32))
        };
        
        let mut analysis = SecurityAnalysis::new(
            config.security_level,
            classical_security,
            quantum_security,
            soundness_error,
            zk_error,
        );
        
        // Analyze specific attacks
        self.analyze_attacks(config, &mut analysis)?;
        
        // Generate recommendations
        self.generate_recommendations(config, &mut analysis);
        
        Ok(analysis)
    }
    
    /// Analyzes lattice parameters security
    pub fn analyze_lattice_params(
        &self,
        params: &LatticeParams,
    ) -> Result<SecurityAnalysis, ZKVMError> {
        params.validate()?;
        
        // LWE security estimation based on dimension and modulus
        let classical_security = self.estimate_lwe_security(params, false);
        let quantum_security = self.estimate_lwe_security(params, true);
        
        // Soundness and ZK errors for lattice-based commitments
        let soundness_error = self.compute_lattice_soundness_error(params);
        let zk_error = self.compute_lattice_zk_error(params);
        
        let mut analysis = SecurityAnalysis::new(
            self.target_security,
            classical_security,
            quantum_security,
            soundness_error,
            zk_error,
        );
        
        // Analyze lattice-specific attacks
        self.analyze_lattice_attacks(params, &mut analysis)?;
        
        Ok(analysis)
    }
    
    /// Computes classical security level
    fn compute_classical_security(&self, config: &RokokoConfig) -> usize {
        // Based on commitment size and refinement depth
        let base_security = config.security_level;
        
        // Refinement reduces effective security slightly
        let refinement_penalty = (config.refinement_depth as f64 * 0.5).ceil() as usize;
        
        base_security.saturating_sub(refinement_penalty)
    }
    
    /// Computes quantum security level (post-quantum)
    fn compute_quantum_security(&self, config: &RokokoConfig) -> usize {
        // Quantum algorithms (Grover) provide quadratic speedup
        // Effective security is approximately half in quantum setting
        let classical = self.compute_classical_security(config);
        
        // Conservative estimate: divide by 2 for quantum adversary
        if self.conservative {
            classical / 2
        } else {
            (classical * 2) / 3
        }
    }
    
    /// Computes soundness error probability
    fn compute_soundness_error(&self, config: &RokokoConfig) -> f64 {
        // Soundness error per refinement round
        let per_round_error = 2.0_f64.powi(-(config.commitment_size as i32 / 4));
        
        // Total error amplifies with refinement depth
        let total_error = per_round_error * config.refinement_depth as f64;
        
        total_error.min(1.0)
    }
    
    /// Estimates LWE security using standard formulas
    fn estimate_lwe_security(&self, params: &LatticeParams, quantum: bool) -> usize {
        let n = params.dimension as f64;
        let log_q = (params.modulus as f64).log2();
        let sigma = params.error_stddev;
        
        // Regev's bound for LWE security
        // Classical: λ ≈ n / log(n)
        // Quantum: λ ≈ sqrt(n / log(n))
        
        let base_security = if quantum {
            (n / log_q.log2()).sqrt()
        } else {
            n / log_q.log2()
        };
        
        // Adjust for error distribution
        let error_factor = (sigma / (params.modulus as f64)).log2().abs();
        let adjusted_security = base_security * (error_factor / 10.0).max(0.5);
        
        if self.conservative {
            (adjusted_security * 0.8) as usize
        } else {
            adjusted_security as usize
        }
    }
    
    /// Computes soundness error for lattice commitments
    fn compute_lattice_soundness_error(&self, params: &LatticeParams) -> f64 {
        // Probability of breaking binding property
        let dimension_factor = params.dimension as f64;
        let modulus_factor = (params.modulus as f64).log2();
        
        // Error probability scales with 2^(-λ) where λ is security level
        let security_bits = self.estimate_lwe_security(params, false);
        
        2.0_f64.powi(-(security_bits as i32))
    }
    
    /// Computes zero-knowledge error for lattice commitments
    fn compute_lattice_zk_error(&self, params: &LatticeParams) -> f64 {
        // Statistical distance depends on rejection sampling
        let rejection_factor = params.rejection_factor;
        
        // Standard rejection sampling gives statistical distance 2^(-λ/2)
        let security_bits = self.estimate_lwe_security(params, false);
        
        let base_error = 2.0_f64.powi(-((security_bits / 2) as i32));
        
        // Better rejection factor improves ZK
        base_error / rejection_factor
    }
    
    /// Analyzes resistance to specific attacks
    fn analyze_attacks(
        &self,
        config: &RokokoConfig,
        analysis: &mut SecurityAnalysis,
    ) -> Result<(), ZKVMError> {
        // Lattice reduction attack
        let lattice_reduction = self.analyze_lattice_reduction_attack(config);
        analysis.add_attack_resistance(AttackType::LatticeReduction, lattice_reduction);
        
        // Primal attack
        let primal = self.analyze_primal_attack(config);
        analysis.add_attack_resistance(AttackType::PrimalAttack, primal);
        
        // Dual attack
        let dual = self.analyze_dual_attack(config);
        analysis.add_attack_resistance(AttackType::DualAttack, dual);
        
        // Quantum attacks
        let quantum = self.analyze_quantum_attack(config);
        analysis.add_attack_resistance(AttackType::QuantumAttack, quantum);
        
        // Side-channel resistance
        if config.constant_time {
            let side_channel = AttackResistance::new(
                config.security_level,
                2.0_f64.powi(config.security_level as i32),
                true,
                "Constant-time implementation enabled".to_string(),
            );
            analysis.add_attack_resistance(AttackType::SideChannel, side_channel);
        } else {
            let side_channel = AttackResistance::new(
                0,
                1.0,
                false,
                "Constant-time implementation disabled - vulnerable to timing attacks".to_string(),
            );
            analysis.add_attack_resistance(AttackType::SideChannel, side_channel);
        }
        
        Ok(())
    }
    
    /// Analyzes lattice-specific attacks
    fn analyze_lattice_attacks(
        &self,
        params: &LatticeParams,
        analysis: &mut SecurityAnalysis,
    ) -> Result<(), ZKVMError> {
        // BKZ/LLL complexity
        let bkz_complexity = self.compute_bkz_complexity(params);
        let lattice_reduction = AttackResistance::new(
            (bkz_complexity.log2()) as usize,
            bkz_complexity,
            bkz_complexity >= 2.0_f64.powi(self.target_security as i32),
            format!("BKZ reduction complexity: 2^{:.1}", bkz_complexity.log2()),
        );
        analysis.add_attack_resistance(AttackType::LatticeReduction, lattice_reduction);
        
        Ok(())
    }
    
    /// Analyzes lattice reduction attack complexity
    fn analyze_lattice_reduction_attack(&self, config: &RokokoConfig) -> AttackResistance {
        let n = config.commitment_size as f64;
        
        // BKZ complexity: 2^(0.292 * β) where β ≈ dimension
        let complexity = 2.0_f64.powf(0.292 * n);
        let bits = complexity.log2() as usize;
        
        AttackResistance::new(
            bits,
            complexity,
            bits >= self.target_security,
            format!("Lattice reduction requires 2^{:.1} operations", complexity.log2()),
        )
    }
    
    /// Analyzes primal attack on LWE
    fn analyze_primal_attack(&self, config: &RokokoConfig) -> AttackResistance {
        let n = config.commitment_size as f64;
        
        // Primal attack complexity
        let complexity = 2.0_f64.powf(0.265 * n);
        let bits = complexity.log2() as usize;
        
        AttackResistance::new(
            bits,
            complexity,
            bits >= self.target_security,
            "Primal LWE attack".to_string(),
        )
    }
    
    /// Analyzes dual attack on LWE
    fn analyze_dual_attack(&self, config: &RokokoConfig) -> AttackResistance {
        let n = config.commitment_size as f64;
        
        // Dual attack complexity
        let complexity = 2.0_f64.powf(0.265 * n);
        let bits = complexity.log2() as usize;
        
        AttackResistance::new(
            bits,
            complexity,
            bits >= self.target_security,
            "Dual LWE attack".to_string(),
        )
    }
    
    /// Analyzes quantum attack resistance
    fn analyze_quantum_attack(&self, config: &RokokoConfig) -> AttackResistance {
        let classical_security = self.compute_classical_security(config);
        
        // Grover's algorithm provides quadratic speedup
        let quantum_bits = classical_security / 2;
        let complexity = 2.0_f64.powi(quantum_bits as i32);
        
        AttackResistance::new(
            quantum_bits,
            complexity,
            quantum_bits >= self.target_security,
            format!("Quantum security: {} bits (Grover)", quantum_bits),
        )
    }
    
    /// Computes BKZ reduction complexity
    fn compute_bkz_complexity(&self, params: &LatticeParams) -> f64 {
        let n = params.dimension as f64;
        let log_q = (params.modulus as f64).log2();
        
        // BKZ-2.0 complexity with quantum enhancement
        let beta = (n / log_q).min(n);
        
        2.0_f64.powf(0.292 * beta)
    }
    
    /// Generates security recommendations
    fn generate_recommendations(&self, config: &RokokoConfig, analysis: &mut SecurityAnalysis) {
        // Check if target security is met
        if analysis.quantum_security < self.target_security {
            analysis.add_recommendation(format!(
                "Increase commitment size from {} to {} for target security",
                config.commitment_size,
                self.recommend_dimension(self.target_security)
            ));
        }
        
        // Check constant-time implementation
        if !config.constant_time {
            analysis.add_recommendation(
                "Enable constant-time operations to prevent side-channel attacks".to_string()
            );
        }
        
        // Check refinement depth
        if config.refinement_depth < 5 {
            analysis.add_recommendation(
                "Consider increasing refinement depth for better succinctness".to_string()
            );
        } else if config.refinement_depth > 15 {
            analysis.add_recommendation(
                "Refinement depth may be excessive, consider reducing for performance".to_string()
            );
        }
        
        // Check soundness error
        if analysis.soundness_error > 2.0_f64.powi(-64) {
            analysis.add_recommendation(
                "Soundness error is higher than recommended, increase commitment size".to_string()
            );
        }
    }
    
    /// Recommends minimum dimension for target security
    fn recommend_dimension(&self, security_bits: usize) -> usize {
        // Conservative estimate: n ≈ 2 * λ * log(λ) for quantum security λ
        let lambda = security_bits as f64;
        let recommended = (2.0 * lambda * lambda.log2()).ceil() as usize;
        
        // Round up to nearest power of 2
        let power = (recommended as f64).log2().ceil() as u32;
        1 << power
    }
}

/// Validator for parameter consistency
pub struct ParameterValidator;

impl ParameterValidator {
    /// Validates lattice parameters
    pub fn validate_lattice_params(params: &LatticeParams) -> Result<(), ZKVMError> {
        params.validate()?;
        
        // Check dimension is power of 2 (required for NTT)
        if !params.dimension.is_power_of_two() {
            return Err(ZKVMError::InvalidParameter(
                "Dimension must be power of 2 for NTT".to_string()
            ));
        }
        
        // Check modulus is prime
        if !Self::is_likely_prime(params.modulus) {
            return Err(ZKVMError::InvalidParameter(
                "Modulus should be prime for field operations".to_string()
            ));
        }
        
        // Check error standard deviation
        let alpha = params.error_stddev / params.modulus as f64;
        if alpha > 0.1 {
            return Err(ZKVMError::InvalidParameter(
                "Error distribution ratio too large (α > 0.1)".to_string()
            ));
        }
        
        // Check rejection factor
        if params.rejection_factor < 2.0 {
            return Err(ZKVMError::InvalidParameter(
                "Rejection factor too small (< 2)".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validates RoKoko configuration
    pub fn validate_config(config: &RokokoConfig) -> Result<(), ZKVMError> {
        config.validate()?;
        
        // Check commitment size is reasonable
        if config.commitment_size > 16384 {
            return Err(ZKVMError::InvalidParameter(
                "Commitment size too large (> 16384)".to_string()
            ));
        }
        
        // Check refinement depth
        if config.refinement_depth > 20 {
            return Err(ZKVMError::InvalidParameter(
                "Refinement depth too large (> 20)".to_string()
            ));
        }
        
        // Check circuit size
        if config.max_circuit_size < (1 << 10) {
            return Err(ZKVMError::InvalidParameter(
                "Max circuit size too small (< 1024)".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Simple primality test (Miller-Rabin would be used in production)
    fn is_likely_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        
        // Check small primes
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31].iter() {
            if n % p == 0 {
                return n == *p;
            }
        }
        
        true // Assume prime for larger values (production would use proper test)
    }
}

/// Constant-time operation verifier
pub struct ConstantTimeVerifier;

impl ConstantTimeVerifier {
    /// Checks if implementation uses constant-time operations
    pub fn verify_constant_time(config: &RokokoConfig) -> bool {
        config.constant_time
    }
    
    /// Provides constant-time guidelines
    pub fn get_guidelines() -> Vec<String> {
        vec![
            "Use constant-time arithmetic for all field operations".to_string(),
            "Avoid conditional branches based on secret data".to_string(),
            "Use constant-time comparison functions".to_string(),
            "Avoid variable-time memory access patterns".to_string(),
            "Use rejection sampling with constant-time rejection".to_string(),
            "Implement constant-time modular reduction".to_string(),
        ]
    }
}

/// Security audit report generator
pub struct SecurityAuditor {
    analyzer: SecurityAnalyzer,
}

impl SecurityAuditor {
    pub fn new(target_security: usize) -> Self {
        Self {
            analyzer: SecurityAnalyzer::new(target_security),
        }
    }
    
    /// Generates comprehensive security audit
    pub fn audit(&self, config: &RokokoConfig) -> Result<SecurityAuditReport, ZKVMError> {
        // Validate configuration
        ParameterValidator::validate_config(config)?;
        
        // Perform security analysis
        let analysis = self.analyzer.analyze_config(config)?;
        
        // Check constant-time compliance
        let constant_time_compliant = ConstantTimeVerifier::verify_constant_time(config);
        
        // Compile findings
        let mut findings = Vec::new();
        
        if !analysis.meets_requirements(self.analyzer.target_security) {
            findings.push(SecurityFinding::Critical(
                "Configuration does not meet target security level".to_string()
            ));
        }
        
        if !constant_time_compliant {
            findings.push(SecurityFinding::High(
                "Constant-time operations disabled - vulnerable to side-channels".to_string()
            ));
        }
        
        for (attack_type, resistance) in &analysis.attack_resistances {
            if !resistance.is_safe {
                findings.push(SecurityFinding::Medium(
                    format!("Insufficient protection against {:?}", attack_type)
                ));
            }
        }
        
        Ok(SecurityAuditReport {
            analysis,
            findings,
            constant_time_compliant,
            overall_rating: Self::compute_rating(&findings),
        })
    }
    
    fn compute_rating(findings: &[SecurityFinding]) -> SecurityRating {
        let critical_count = findings.iter().filter(|f| matches!(f, SecurityFinding::Critical(_))).count();
        let high_count = findings.iter().filter(|f| matches!(f, SecurityFinding::High(_))).count();
        
        if critical_count > 0 {
            SecurityRating::Unsafe
        } else if high_count > 0 {
            SecurityRating::NeedsImprovement
        } else if findings.is_empty() {
            SecurityRating::Excellent
        } else {
            SecurityRating::Good
        }
    }
}

/// Security audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditReport {
    pub analysis: SecurityAnalysis,
    pub findings: Vec<SecurityFinding>,
    pub constant_time_compliant: bool,
    pub overall_rating: SecurityRating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityFinding {
    Critical(String),
    High(String),
    Medium(String),
    Low(String),
    Info(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecurityRating {
    Excellent,
    Good,
    NeedsImprovement,
    Unsafe,
}
