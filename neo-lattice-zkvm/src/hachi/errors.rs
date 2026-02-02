// Error types for Hachi implementation

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HachiError {
    // Parameter errors
    InvalidRingDimension(String),
    InvalidExtensionDegree(String),
    InvalidModulus(String),
    InvalidSecurityParameter(String),
    IncompatibleParameters(String),
    
    // Mathematical errors
    NotInFixedSubgroup(String),
    InvalidGaloisAutomorphism(String),
    TraceMapFailed(String),
    InnerProductMismatch(String),
    NormBoundViolation(String),
    
    // Commitment errors
    CommitmentFailed(String),
    InvalidOpening(String),
    BindingViolation(String),
    WeakOpeningFailed(String),
    
    // Ring switching errors
    PolynomialLiftingFailed(String),
    ChallengeSubstitutionFailed(String),
    MLECommitmentFailed(String),
    
    // Sumcheck errors
    SumcheckRoundFailed(String),
    InvalidSumcheckProof(String),
    EvaluationMismatch(String),
    
    // Norm verification errors
    RangeProofFailed(String),
    ZeroCoefficientCheckFailed(String),
    CoordinateWiseSoundnessFailed(String),
    
    // Protocol errors
    SetupFailed(String),
    ProvingFailed(String),
    VerificationFailed(String),
    RecursionDepthExceeded(String),
    
    // Serialization errors
    SerializationFailed(String),
    DeserializationFailed(String),
    
    // Generic errors
    InvalidInput(String),
    InternalError(String),
}

impl fmt::Display for HachiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HachiError::InvalidRingDimension(msg) => write!(f, "Invalid ring dimension: {}", msg),
            HachiError::InvalidExtensionDegree(msg) => write!(f, "Invalid extension degree: {}", msg),
            HachiError::InvalidModulus(msg) => write!(f, "Invalid modulus: {}", msg),
            HachiError::InvalidSecurityParameter(msg) => write!(f, "Invalid security parameter: {}", msg),
            HachiError::IncompatibleParameters(msg) => write!(f, "Incompatible parameters: {}", msg),
            
            HachiError::NotInFixedSubgroup(msg) => write!(f, "Element not in fixed subgroup: {}", msg),
            HachiError::InvalidGaloisAutomorphism(msg) => write!(f, "Invalid Galois automorphism: {}", msg),
            HachiError::TraceMapFailed(msg) => write!(f, "Trace map failed: {}", msg),
            HachiError::InnerProductMismatch(msg) => write!(f, "Inner product mismatch: {}", msg),
            HachiError::NormBoundViolation(msg) => write!(f, "Norm bound violation: {}", msg),
            
            HachiError::CommitmentFailed(msg) => write!(f, "Commitment failed: {}", msg),
            HachiError::InvalidOpening(msg) => write!(f, "Invalid opening: {}", msg),
            HachiError::BindingViolation(msg) => write!(f, "Binding violation: {}", msg),
            HachiError::WeakOpeningFailed(msg) => write!(f, "Weak opening failed: {}", msg),
            
            HachiError::PolynomialLiftingFailed(msg) => write!(f, "Polynomial lifting failed: {}", msg),
            HachiError::ChallengeSubstitutionFailed(msg) => write!(f, "Challenge substitution failed: {}", msg),
            HachiError::MLECommitmentFailed(msg) => write!(f, "MLE commitment failed: {}", msg),
            
            HachiError::SumcheckRoundFailed(msg) => write!(f, "Sumcheck round failed: {}", msg),
            HachiError::InvalidSumcheckProof(msg) => write!(f, "Invalid sumcheck proof: {}", msg),
            HachiError::EvaluationMismatch(msg) => write!(f, "Evaluation mismatch: {}", msg),
            
            HachiError::RangeProofFailed(msg) => write!(f, "Range proof failed: {}", msg),
            HachiError::ZeroCoefficientCheckFailed(msg) => write!(f, "Zero coefficient check failed: {}", msg),
            HachiError::CoordinateWiseSoundnessFailed(msg) => write!(f, "Coordinate-wise soundness failed: {}", msg),
            
            HachiError::SetupFailed(msg) => write!(f, "Setup failed: {}", msg),
            HachiError::ProvingFailed(msg) => write!(f, "Proving failed: {}", msg),
            HachiError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            HachiError::RecursionDepthExceeded(msg) => write!(f, "Recursion depth exceeded: {}", msg),
            
            HachiError::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
            HachiError::DeserializationFailed(msg) => write!(f, "Deserialization failed: {}", msg),
            
            HachiError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            HachiError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for HachiError {}

pub type Result<T> = std::result::Result<T, HachiError>;
