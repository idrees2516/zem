// Comprehensive Error Handling for HyperWolf PCS
// Per HyperWolf paper Requirement 35 and Design Section "Error Handling"

use std::fmt;
use std::error::Error as StdError;

/// Comprehensive error type for HyperWolf PCS operations
#[derive(Debug, Clone)]
pub enum HyperWolfError {
    // ==================== Parameter Validation Errors ====================
    
    /// Invalid parameters provided
    InvalidParameters {
        reason: String,
    },
    
    /// Parameters do not meet security requirements
    InsecureParameters {
        required_norm_bound: usize,
        actual_norm_bound: usize,
        parameter: String,
    },
    
    /// Wrap-around condition violated: 2γ ≥ q/√n
    WrapAroundViolation {
        gamma: String,
        threshold: String,
        suggestion: String,
    },
    
    /// Challenge space size insufficient
    InsufficientChallengeSpace {
        actual_size: String,
        required_size: String,
    },
    
    /// LaBRADOR constraint violated: (3k-1)² < max(2κι, 3ι)
    LabradorConstraintViolation {
        constraint: String,
        actual: usize,
        required: usize,
    },
    
    // ==================== Runtime Validation Errors ====================
    
    /// Challenge sampling failed after maximum attempts
    ChallengeSamplingFailed {
        attempts: usize,
        reason: String,
    },
    
    /// Challenge difference is not invertible
    NonInvertibleChallenge {
        challenge1: String,
        challenge2: String,
    },
    
    /// Norm bound check failed
    NormBoundViolation {
        actual_norm: String,
        bound: String,
        norm_type: String,
    },
    
    /// Commitment verification failed
    CommitmentVerificationFailed {
        round: usize,
        reason: String,
    },
    
    /// Evaluation verification failed
    EvaluationVerificationFailed {
        round: usize,
        reason: String,
    },
    
    /// Proof verification failed
    ProofVerificationFailed {
        component: String,
        reason: String,
    },
    
    // ==================== Tensor and Ring Operation Errors ====================
    
    /// Tensor dimension mismatch
    TensorDimensionMismatch {
        expected: Vec<usize>,
        actual: Vec<usize>,
        operation: String,
    },
    
    /// Ring operation error
    RingOperationError {
        operation: String,
        reason: String,
    },
    
    /// Polynomial degree exceeds bound
    PolynomialDegreeTooLarge {
        actual_degree: usize,
        degree_bound: usize,
    },
    
    /// Invalid polynomial format
    InvalidPolynomial {
        reason: String,
    },
    
    // ==================== Integration Errors ====================
    
    /// Integration error with other schemes
    IntegrationError {
        scheme: String,
        reason: String,
    },
    
    /// Conversion error between schemes
    ConversionError {
        from_scheme: String,
        to_scheme: String,
        reason: String,
    },
    
    /// Batching error
    BatchingError {
        strategy: String,
        reason: String,
    },
    
    /// Sum-check protocol error
    SumCheckError {
        round: usize,
        reason: String,
    },
    
    // ==================== I/O and Serialization Errors ====================
    
    /// Serialization error
    SerializationError {
        reason: String,
    },
    
    /// Deserialization error
    DeserializationError {
        reason: String,
    },
    
    /// File I/O error
    IoError {
        operation: String,
        path: String,
        reason: String,
    },
}

impl fmt::Display for HyperWolfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Parameter validation errors
            HyperWolfError::InvalidParameters { reason } => {
                write!(f, "Invalid parameters: {}", reason)
            }
            HyperWolfError::InsecureParameters { required_norm_bound, actual_norm_bound, parameter } => {
                write!(
                    f,
                    "Insecure parameters for {}: M-SIS requires norm bound ≥ {}, but got {}. \
                     Increase security parameter or adjust ring dimension.",
                    parameter, required_norm_bound, actual_norm_bound
                )
            }
            HyperWolfError::WrapAroundViolation { gamma, threshold, suggestion } => {
                write!(
                    f,
                    "Wrap-around condition violated: 2γ = {} ≥ q/√n = {}. \
                     This violates exact ℓ₂-soundness. Suggestion: {}",
                    gamma, threshold, suggestion
                )
            }
            HyperWolfError::InsufficientChallengeSpace { actual_size, required_size } => {
                write!(
                    f,
                    "Challenge space too small: |C| = {} < required {}. \
                     Increase ring dimension or adjust challenge distribution.",
                    actual_size, required_size
                )
            }
            HyperWolfError::LabradorConstraintViolation { constraint, actual, required } => {
                write!(
                    f,
                    "LaBRADOR constraint violated: {} = {} < required {}. \
                     Increase number of rounds or adjust parameters.",
                    constraint, actual, required
                )
            }
            
            // Runtime validation errors
            HyperWolfError::ChallengeSamplingFailed { attempts, reason } => {
                write!(
                    f,
                    "Challenge sampling failed after {} attempts: {}. \
                     Check challenge space parameters.",
                    attempts, reason
                )
            }
            HyperWolfError::NonInvertibleChallenge { challenge1, challenge2 } => {
                write!(
                    f,
                    "Challenge difference not invertible: c₁ - c₂ where c₁ = {}, c₂ = {}. \
                     This violates challenge space invertibility property.",
                    challenge1, challenge2
                )
            }
            HyperWolfError::NormBoundViolation { actual_norm, bound, norm_type } => {
                write!(
                    f,
                    "{}-norm bound violated: ∥·∥ = {} > bound = {}. \
                     Witness does not satisfy norm constraints.",
                    norm_type, actual_norm, bound
                )
            }
            HyperWolfError::CommitmentVerificationFailed { round, reason } => {
                write!(
                    f,
                    "Commitment verification failed in round {}: {}",
                    round, reason
                )
            }
            HyperWolfError::EvaluationVerificationFailed { round, reason } => {
                write!(
                    f,
                    "Evaluation verification failed in round {}: {}",
                    round, reason
                )
            }
            HyperWolfError::ProofVerificationFailed { component, reason } => {
                write!(
                    f,
                    "Proof verification failed for {}: {}",
                    component, reason
                )
            }
            
            // Tensor and ring operation errors
            HyperWolfError::TensorDimensionMismatch { expected, actual, operation } => {
                write!(
                    f,
                    "Tensor dimension mismatch in {}: expected {:?}, got {:?}",
                    operation, expected, actual
                )
            }
            HyperWolfError::RingOperationError { operation, reason } => {
                write!(
                    f,
                    "Ring operation '{}' failed: {}",
                    operation, reason
                )
            }
            HyperWolfError::PolynomialDegreeTooLarge { actual_degree, degree_bound } => {
                write!(
                    f,
                    "Polynomial degree {} exceeds bound {}. \
                     Increase degree bound or reduce polynomial size.",
                    actual_degree, degree_bound
                )
            }
            HyperWolfError::InvalidPolynomial { reason } => {
                write!(f, "Invalid polynomial: {}", reason)
            }
            
            // Integration errors
            HyperWolfError::IntegrationError { scheme, reason } => {
                write!(
                    f,
                    "Integration error with {}: {}",
                    scheme, reason
                )
            }
            HyperWolfError::ConversionError { from_scheme, to_scheme, reason } => {
                write!(
                    f,
                    "Conversion error from {} to {}: {}",
                    from_scheme, to_scheme, reason
                )
            }
            HyperWolfError::BatchingError { strategy, reason } => {
                write!(
                    f,
                    "Batching error with strategy {}: {}",
                    strategy, reason
                )
            }
            HyperWolfError::SumCheckError { round, reason } => {
                write!(
                    f,
                    "Sum-check error in round {}: {}",
                    round, reason
                )
            }
            
            // I/O and serialization errors
            HyperWolfError::SerializationError { reason } => {
                write!(f, "Serialization error: {}", reason)
            }
            HyperWolfError::DeserializationError { reason } => {
                write!(f, "Deserialization error: {}", reason)
            }
            HyperWolfError::IoError { operation, path, reason } => {
                write!(
                    f,
                    "I/O error during {} on '{}': {}",
                    operation, path, reason
                )
            }
        }
    }
}

impl StdError for HyperWolfError {}

/// Result type for HyperWolf operations
pub type Result<T> = std::result::Result<T, HyperWolfError>;

/// Helper functions for creating common errors
impl HyperWolfError {
    /// Create parameter validation error
    pub fn invalid_params(reason: impl Into<String>) -> Self {
        HyperWolfError::InvalidParameters {
            reason: reason.into(),
        }
    }
    
    /// Create insecure parameters error
    pub fn insecure_params(
        parameter: impl Into<String>,
        required: usize,
        actual: usize,
    ) -> Self {
        HyperWolfError::InsecureParameters {
            required_norm_bound: required,
            actual_norm_bound: actual,
            parameter: parameter.into(),
        }
    }
    
    /// Create wrap-around violation error
    pub fn wrap_around(
        gamma: impl Into<String>,
        threshold: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        HyperWolfError::WrapAroundViolation {
            gamma: gamma.into(),
            threshold: threshold.into(),
            suggestion: suggestion.into(),
        }
    }
    
    /// Create norm bound violation error
    pub fn norm_violation(
        norm_type: impl Into<String>,
        actual: impl Into<String>,
        bound: impl Into<String>,
    ) -> Self {
        HyperWolfError::NormBoundViolation {
            actual_norm: actual.into(),
            bound: bound.into(),
            norm_type: norm_type.into(),
        }
    }
    
    /// Create tensor dimension mismatch error
    pub fn dimension_mismatch(
        operation: impl Into<String>,
        expected: Vec<usize>,
        actual: Vec<usize>,
    ) -> Self {
        HyperWolfError::TensorDimensionMismatch {
            expected,
            actual,
            operation: operation.into(),
        }
    }
    
    /// Create ring operation error
    pub fn ring_op_error(
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        HyperWolfError::RingOperationError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
    
    /// Create verification failed error
    pub fn verification_failed(
        component: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        HyperWolfError::ProofVerificationFailed {
            component: component.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = HyperWolfError::invalid_params("test reason");
        assert!(err.to_string().contains("Invalid parameters"));
        assert!(err.to_string().contains("test reason"));
    }
    
    #[test]
    fn test_insecure_params_error() {
        let err = HyperWolfError::insecure_params("M-SIS", 1000, 500);
        let msg = err.to_string();
        assert!(msg.contains("Insecure parameters"));
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }
    
    #[test]
    fn test_wrap_around_error() {
        let err = HyperWolfError::wrap_around(
            "100",
            "50",
            "Increase modulus q or reduce norm bound",
        );
        let msg = err.to_string();
        assert!(msg.contains("Wrap-around"));
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }
    
    #[test]
    fn test_norm_violation_error() {
        let err = HyperWolfError::norm_violation("ℓ₂", "150", "100");
        let msg = err.to_string();
        assert!(msg.contains("norm bound violated"));
        assert!(msg.contains("150"));
        assert!(msg.contains("100"));
    }
    
    #[test]
    fn test_dimension_mismatch_error() {
        let err = HyperWolfError::dimension_mismatch(
            "tensor_product",
            vec![2, 3, 4],
            vec![2, 3, 5],
        );
        let msg = err.to_string();
        assert!(msg.contains("Tensor dimension mismatch"));
        assert!(msg.contains("tensor_product"));
    }
    
    #[test]
    fn test_verification_failed_error() {
        let err = HyperWolfError::verification_failed(
            "commitment",
            "Matrix multiplication mismatch",
        );
        let msg = err.to_string();
        assert!(msg.contains("Proof verification failed"));
        assert!(msg.contains("commitment"));
        assert!(msg.contains("Matrix multiplication"));
    }
    
    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HyperWolfError>();
    }
}
