// Oracle Module
//
// Implements various oracle models for AGM-secure cryptographic protocols:
// - Random Oracle Model (ROM)
// - Arithmetized Random Oracle Model (AROM)
// - Signed Random Oracle Model
//
// References:
// - AGM-Secure Functionalities with Cryptographic Proofs (2025)
// - Section 3: Oracle Distributions and Transcript Management

pub mod transcript;
pub mod rom;
pub mod arom;
pub mod signed_rom;
pub mod emulator;
pub mod arom_emulator;
pub mod types;
pub mod errors;

pub use transcript::{OracleQuery, OracleTranscript, Oracle};
pub use rom::RandomOracle;
pub use arom::{AROM, WitnessOracle, VerificationOracle};
pub use signed_rom::{SignedOracle, SigningOracle};
pub use emulator::{AROMEmulator as AROMEmulatorOld, EmulatorState as EmulatorStateOld};
pub use arom_emulator::{AROMEmulator, EmulatorState, SecurityLifting, OracleAugmentation};
pub use types::{OracleDistribution, OracleResponse};
pub use errors::{OracleError, OracleResult};

#[cfg(test)]
mod tests;
