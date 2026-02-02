// Mathematical primitives for Hachi
//
// This module provides the core mathematical building blocks for the Hachi
// polynomial commitment scheme, including:
// - Extension field arithmetic (F_{q^k})
// - Ring fixed subgroups (R_q^H ≅ F_{q^k})
// - Galois automorphisms (σ_i operations)
// - Trace maps (Tr_H : R_q → R_q^H)
// - Inner product preservation (Theorem 2)
// - Norm preservation and bounds (Lemma 6)

pub mod extension_field;
pub mod ring_fixed_subgroup;
pub mod galois_automorphisms;
pub mod trace_map;
pub mod inner_product;
pub mod norm_preservation;

pub use extension_field::*;
pub use ring_fixed_subgroup::*;
pub use galois_automorphisms::*;
pub use trace_map::*;
pub use inner_product::*;
pub use norm_preservation::*;
