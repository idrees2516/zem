// Phase 4: Virtual Polynomials and Address Conversion Module

pub mod framework;
pub mod address_field;
pub mod write_values;
pub mod chaining;

pub use framework::{VirtualPolynomialFramework, VirtualPolyTrait, NestedSumCheck};
pub use address_field::VirtualAddressField;
pub use write_values::VirtualWriteValues;
pub use chaining::{VirtualPolyChain, DependencyGraph};
