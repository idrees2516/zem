use serde::{Serialize, Deserialize};

/// Auxiliary input for O-SNARK
///
/// Sampled by Z(1^λ, θ) to provide additional context
/// Example: For aggregate signatures, aux = vk (verification key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuxiliaryInput {
    pub data: Vec<u8>,
}

impl AuxiliaryInput {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Signing query: (message, signature)
///
/// Recorded in signing oracle transcript Q
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningQuery<M, Sig> {
    pub message: M,
    pub signature: Sig,
}

impl<M, Sig> SigningQuery<M, Sig> {
    pub fn new(message: M, signature: Sig) -> Self {
        Self { message, signature }
    }
}
