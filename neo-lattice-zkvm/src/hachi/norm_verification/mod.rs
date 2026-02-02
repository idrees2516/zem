// Norm verification protocol
//
// Implements verification that committed values satisfy norm bounds,
// enabling soundness proofs for the complete Hachi protocol.
//
// This module implements:
// - Range proofs over F_{q^k} (Lemma 6)
// - Zero-coefficient verification (Lemma 10)
// - Coordinate-wise special soundness (CWSS)

pub mod range_proof;
pub mod zero_coefficient;
pub mod coordinate_wise;

pub use range_proof::*;
pub use zero_coefficient::*;
pub use coordinate_wise::*;
