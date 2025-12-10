// AGM (Algebraic Group Model) Module
//
// This module implements the extended Algebraic Group Model with oracle support,
// enabling provably secure composition of AGM-secure cryptographic primitives.
//
// Key components:
// - Group representation management and verification
// - Algebraic adversary interfaces
// - Group element parsing from mixed data structures
//
// References:
// - AGM-Secure Functionalities with Cryptographic Proofs (2025)
// - Section 3.1: Extended AGM with Oracle Support

pub mod group_representation;
pub mod algebraic_adversary;
pub mod parser;
pub mod types;
pub mod errors;

pub use group_representation::{GroupRepresentation, GroupRepresentationManager};
pub use algebraic_adversary::{AlgebraicAdversary, AlgebraicOutput};
pub use parser::GroupParser;
pub use types::{BasisElement, Coefficient, RepresentationMatrix};
pub use errors::AGMError;

#[cfg(test)]
mod tests;
