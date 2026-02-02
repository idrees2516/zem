/// Error Handling and Validation Module
/// 
/// Comprehensive error handling, validation checks, and error propagation
/// for the small-space zkVM prover.

use std::fmt;

/// Prover error types
#[derive(Clone, Debug)]
pub enum ProverError {
    /// Field arithmetic error
    FieldError(String),
    
    /// Memory error
    MemoryError(String),
    
    /// Constraint system error
    ConstraintError(String),
    
    /// Witness generation error
    WitnessError(String),
    
    /// Sum-check protocol error
    SumCheckError(String),
    
    /// Commitment scheme error
    CommitmentError(String),
    
    /// Memory checking error (Shout/Twist)
    MemoryCheckError(String),
    
    /// Lookup argument error (Lasso/Spice)
    LookupError(String),
    
    /// Polynomial commitment error
    PolynomialCommitmentError(String),
    
    /// Configuration error
    ConfigError(String),
    
    /// Verification error
    VerificationError(String),
    
    /// I/O error
    IoError(String),
    
    /// Timeout error
    TimeoutError(String),
    
    /// Invalid parameter error
    InvalidParameter(String),
    
    /// Unsupported operation error
    UnsupportedOperation(String),
    
    /// Internal error
    InternalError(String),
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProverError::FieldError(msg) => write!(f, "Field error: {}", msg),
            ProverError::MemoryError(msg) => write!(f, "Memory error: {}", msg),
            ProverError::ConstraintError(msg) => write!(f, "Constraint error: {}", msg),
            ProverError::WitnessError(msg) => write!(f, "Witness error: {}", msg),
            ProverError::SumCheckError(msg) => write!(f, "Sum-check error: {}", msg),
            ProverError::CommitmentError(msg) => write!(f, "Commitment error: {}", msg),
            ProverError::MemoryCheckError(msg) => write!(f, "Memory check error: {}", msg),
            ProverError::LookupError(msg) => write!(f, "Lookup error: {}", msg),
            ProverError::PolynomialCommitmentError(msg) => write!(f, "Polynomial commitment error: {}", msg),
            ProverError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            ProverError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            ProverError::IoError(msg) => write!(f, "I/O error: {}", msg),
            ProverError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            ProverError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            ProverError::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),
            ProverError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ProverError {}

/// Result type for prover operations
pub type ProverResult<T> = Result<T, ProverError>;

/// Validation context for error checking
pub struct ValidationContext {
    /// Maximum allowed memory in bytes
    pub max_memory_bytes: Option<usize>,
    
    /// Maximum allowed time in milliseconds
    pub max_time_ms: Option<u64>,
    
    /// Minimum security level in bits
    pub min_security_bits: usize,
    
    /// Enable strict validation
    pub strict_mode: bool,
}

impl ValidationContext {
    /// Create default validation context
    pub fn default() -> Self {
        Self {
            max_memory_bytes: None,
            max_time_ms: None,
            min_security_bits: 128,
            strict_mode: false,
        }
    }
    
    /// Create strict validation context
    pub fn strict() -> Self {
        Self {
            max_memory_bytes: Some(100 * 1024 * 1024), // 100 MB
            max_time_ms: Some(300_000), // 5 minutes
            min_security_bits: 256,
            strict_mode: true,
        }
    }
}

/// Validation result with detailed information
#[derive(Clone, Debug)]
pub struct ValidationResult {
    /// Whether validation passed
    pub passed: bool,
    
    /// Validation errors
    pub errors: Vec<String>,
    
    /// Validation warnings
    pub warnings: Vec<String>,
    
    /// Validation metrics
    pub metrics: ValidationMetrics,
}

impl ValidationResult {
    /// Create new validation result
    pub fn new() -> Self {
        Self {
            passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            metrics: ValidationMetrics::default(),
        }
    }
    
    /// Add error
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.passed = false;
    }
    
    /// Add warning
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
    
    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        self.passed && self.errors.is_empty()
    }
    
    /// Format validation report
    pub fn format_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("Validation Result: {}\n", if self.is_valid() { "PASS" } else { "FAIL" }));
        
        if !self.errors.is_empty() {
            report.push_str("\nErrors:\n");
            for error in &self.errors {
                report.push_str(&format!("  - {}\n", error));
            }
        }
        
        if !self.warnings.is_empty() {
            report.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                report.push_str(&format!("  - {}\n", warning));
            }
        }
        
        report.push_str(&format!("\nMetrics:\n{}", self.metrics.format_summary()));
        
        report
    }
}

/// Validation metrics
#[derive(Clone, Debug, Default)]
pub struct ValidationMetrics {
    /// Memory usage in bytes
    pub memory_bytes: usize,
    
    /// Time in milliseconds
    pub time_ms: u64,
    
    /// Number of field operations
    pub field_ops: u64,
    
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Number of witnesses
    pub num_witnesses: usize,
}

impl ValidationMetrics {
    /// Format metrics as string
    pub fn format_summary(&self) -> String {
        format!(
            "  Memory: {} MB\n  Time: {} ms\n  Field Ops: {:.2}B\n  Constraints: {}\n  Witnesses: {}",
            self.memory_bytes / (1024 * 1024),
            self.time_ms,
            self.field_ops as f64 / 1_000_000_000.0,
            self.num_constraints,
            self.num_witnesses
        )
    }
}

/// Validator for prover components
pub struct ProverValidator;

impl ProverValidator {
    /// Validate field element count
    pub fn validate_field_count(count: usize) -> ProverResult<()> {
        if count == 0 {
            return Err(ProverError::InvalidParameter("Field count must be > 0".to_string()));
        }
        Ok(())
    }
    
    /// Validate memory size
    pub fn validate_memory_size(size: usize, max_size: Option<usize>) -> ProverResult<()> {
        if size == 0 {
            return Err(ProverError::InvalidParameter("Memory size must be > 0".to_string()));
        }
        
        if let Some(max) = max_size {
            if size > max {
                return Err(ProverError::MemoryError(format!(
                    "Memory size {} exceeds maximum {}",
                    size, max
                )));
            }
        }
        
        Ok(())
    }
    
    /// Validate number of cycles
    pub fn validate_num_cycles(cycles: usize) -> ProverResult<()> {
        if cycles == 0 {
            return Err(ProverError::InvalidParameter("Number of cycles must be > 0".to_string()));
        }
        
        // Check for reasonable upper bound (2^50)
        if cycles > (1 << 50) {
            return Err(ProverError::InvalidParameter(
                "Number of cycles exceeds reasonable bound".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate constraint system
    pub fn validate_constraint_system(
        num_constraints: usize,
        num_variables: usize,
    ) -> ProverResult<()> {
        if num_constraints == 0 {
            return Err(ProverError::ConstraintError("No constraints".to_string()));
        }
        
        if num_variables == 0 {
            return Err(ProverError::ConstraintError("No variables".to_string()));
        }
        
        if num_constraints > num_variables * 1000 {
            return Err(ProverError::ConstraintError(
                "Too many constraints relative to variables".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate witness vector
    pub fn validate_witness(
        witness_size: usize,
        expected_size: usize,
    ) -> ProverResult<()> {
        if witness_size != expected_size {
            return Err(ProverError::WitnessError(format!(
                "Witness size {} does not match expected {}",
                witness_size, expected_size
            )));
        }
        
        Ok(())
    }
    
    /// Validate sum-check proof
    pub fn validate_sumcheck_proof(
        num_rounds: usize,
        num_variables: usize,
    ) -> ProverResult<()> {
        if num_rounds != num_variables {
            return Err(ProverError::SumCheckError(format!(
                "Sum-check rounds {} does not match variables {}",
                num_rounds, num_variables
            )));
        }
        
        Ok(())
    }
    
    /// Validate commitment
    pub fn validate_commitment(commitment_size: usize) -> ProverResult<()> {
        if commitment_size == 0 {
            return Err(ProverError::CommitmentError("Empty commitment".to_string()));
        }
        
        Ok(())
    }
    
    /// Validate evaluation proof
    pub fn validate_evaluation_proof(proof_size: usize) -> ProverResult<()> {
        if proof_size == 0 {
            return Err(ProverError::PolynomialCommitmentError("Empty proof".to_string()));
        }
        
        Ok(())
    }
    
    /// Validate memory operation
    pub fn validate_memory_operation(
        address: usize,
        memory_size: usize,
    ) -> ProverResult<()> {
        if address >= memory_size {
            return Err(ProverError::MemoryCheckError(format!(
                "Address {} out of bounds (memory size {})",
                address, memory_size
            )));
        }
        
        Ok(())
    }
    
    /// Validate lookup query
    pub fn validate_lookup_query(
        index: usize,
        table_size: usize,
    ) -> ProverResult<()> {
        if index >= table_size {
            return Err(ProverError::LookupError(format!(
                "Lookup index {} out of bounds (table size {})",
                index, table_size
            )));
        }
        
        Ok(())
    }
}

/// Error recovery strategies
pub struct ErrorRecovery;

impl ErrorRecovery {
    /// Attempt to recover from field error
    pub fn recover_field_error(error: &ProverError) -> Option<String> {
        match error {
            ProverError::FieldError(msg) => {
                Some(format!("Field error recovery: {}", msg))
            },
            _ => None,
        }
    }
    
    /// Attempt to recover from memory error
    pub fn recover_memory_error(error: &ProverError) -> Option<String> {
        match error {
            ProverError::MemoryError(msg) => {
                Some(format!("Memory error recovery: {}", msg))
            },
            _ => None,
        }
    }
    
    /// Attempt to recover from constraint error
    pub fn recover_constraint_error(error: &ProverError) -> Option<String> {
        match error {
            ProverError::ConstraintError(msg) => {
                Some(format!("Constraint error recovery: {}", msg))
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prover_error_display() {
        let error = ProverError::FieldError("test error".to_string());
        assert_eq!(format!("{}", error), "Field error: test error");
    }
    
    #[test]
    fn test_validation_context() {
        let ctx = ValidationContext::default();
        assert_eq!(ctx.min_security_bits, 128);
        assert!(!ctx.strict_mode);
        
        let strict_ctx = ValidationContext::strict();
        assert_eq!(strict_ctx.min_security_bits, 256);
        assert!(strict_ctx.strict_mode);
    }
    
    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();
        assert!(result.is_valid());
        
        result.add_error("test error".to_string());
        assert!(!result.is_valid());
        
        result.add_warning("test warning".to_string());
        assert_eq!(result.warnings.len(), 1);
    }
    
    #[test]
    fn test_validator_field_count() {
        assert!(ProverValidator::validate_field_count(0).is_err());
        assert!(ProverValidator::validate_field_count(1).is_ok());
    }
    
    #[test]
    fn test_validator_memory_size() {
        assert!(ProverValidator::validate_memory_size(0, None).is_err());
        assert!(ProverValidator::validate_memory_size(1000, None).is_ok());
        assert!(ProverValidator::validate_memory_size(2000, Some(1000)).is_err());
    }
    
    #[test]
    fn test_validator_num_cycles() {
        assert!(ProverValidator::validate_num_cycles(0).is_err());
        assert!(ProverValidator::validate_num_cycles(1000).is_ok());
    }
    
    #[test]
    fn test_validator_constraint_system() {
        assert!(ProverValidator::validate_constraint_system(0, 100).is_err());
        assert!(ProverValidator::validate_constraint_system(100, 0).is_err());
        assert!(ProverValidator::validate_constraint_system(100, 100).is_ok());
    }
    
    #[test]
    fn test_validator_memory_operation() {
        assert!(ProverValidator::validate_memory_operation(100, 100).is_err());
        assert!(ProverValidator::validate_memory_operation(50, 100).is_ok());
    }
    
    #[test]
    fn test_error_recovery() {
        let error = ProverError::FieldError("test".to_string());
        assert!(ErrorRecovery::recover_field_error(&error).is_some());
        assert!(ErrorRecovery::recover_memory_error(&error).is_none());
    }
}
