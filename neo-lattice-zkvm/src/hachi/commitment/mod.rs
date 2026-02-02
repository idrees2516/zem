// Commitment scheme module
//
// Implements the Ajtai-style inner-outer commitment structure for Hachi,
// providing binding security via Module-SIS hardness.

pub mod inner_outer;
pub mod weak_opening;
pub mod binding;
pub mod homomorphic;

pub use inner_outer::*;
pub use weak_opening::*;
pub use binding::*;
pub use homomorphic::*;
