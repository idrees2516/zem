use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IVCError {
    InvalidState(String),
    DepthBoundExceeded,
    FunctionApplicationFailed(String),
    BaseCase NotReached,
    InvalidWitness(String),
    ExtractionFailed(String),
}

impl fmt::Display for IVCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IVCError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            IVCError::DepthBoundExceeded => write!(f, "Depth bound exceeded"),
            IVCError::FunctionApplicationFailed(msg) => write!(f, "Function application failed: {}", msg),
            IVCError::BaseCaseNotReached => write!(f, "Base case not reached"),
            IVCError::InvalidWitness(msg) => write!(f, "Invalid witness: {}", msg),
            IVCError::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
        }
    }
}

impl std::error::Error for IVCError {}

pub type IVCResult<T> = Result<T, IVCError>;
