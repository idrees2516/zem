// Ring switching protocol module
//
// Implements the ring switching technique that transforms relations from R_q
// to polynomial ring Z_q[X], then evaluates at random point in F_{q^k}.
// This enables sumcheck protocol over extension field instead of cyclotomic ring.

pub mod polynomial_lifting;
pub mod mle_commitment;
pub mod challenge_substitution;
pub mod inner_product_reduction;

pub use polynomial_lifting::*;
pub use mle_commitment::*;
pub use challenge_substitution::*;
pub use inner_product_reduction::*;
