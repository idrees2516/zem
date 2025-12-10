use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OSNARKError {
    ExtractionFailed(String),
    InvalidAuxiliaryInput(String),
    SigningOracleFailed(String),
    OAdPoKFailed(String),
    KZGExtractionFailed(String),
    DiscreteLogBreak,
}

impl fmt::Display for OSNARKError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OSNARKError::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
            OSNARKError::InvalidAuxiliaryInput(msg) => write!(f, "Invalid auxiliary input: {}", msg),
            OSNARKError::SigningOracleFailed(msg) => write!(f, "Signing oracle failed: {}", msg),
            OSNARKError::OAdPoKFailed(msg) => write!(f, "O-AdPoK failed: {}", msg),
            OSNARKError::KZGExtractionFailed(msg) => write!(f, "KZG extraction failed: {}", msg),
            OSNARKError::DiscreteLogBreak => write!(f, "Discrete log problem broken"),
        }
    }
}

impl std::error::Error for OSNARKError {}

pub type OSNARKResult<T> = Result<T, OSNARKError>;
