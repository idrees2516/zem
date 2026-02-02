// Extension field embedding module
//
// This module implements the transformation of multilinear polynomial evaluation
// claims over extension fields F_{q^k} to equivalent relations over cyclotomic
// rings R_q.
//
// Key components:
// - Generic transformation: F_{q^k} → R_q (Section 3.1)
// - Optimized F_q polynomial case (Section 3.2)
// - Quadratic reduction: multilinear → quadratic form
// - Gadget decomposition: G_n^{-1} operations

pub mod generic_transform;
pub mod optimized_fq;
pub mod quadratic_reduction;
pub mod gadget_decomposition;

pub use generic_transform::*;
pub use optimized_fq::*;
pub use quadratic_reduction::*;
pub use gadget_decomposition::*;
