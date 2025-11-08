// Cryptographic Primitives Module
// 
// Provides production-grade cryptographic implementations for the zkVM

pub mod secure_random;

pub use secure_random::{
    SecureRng,
    DeterministicPrf,
    UniformityTester,
    RandomnessError,
    secure_random_bytes,
    secure_random_u64,
    secure_random_range,
};
