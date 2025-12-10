// High-Level API Module
//
// Provides ergonomic, high-level APIs for using AGM-secure cryptographic systems.

pub mod builders;
pub mod examples;

pub use builders::{
    SecurityLevel,
    IVCBuilder,
    IVCSystem,
    AggregateSignatureBuilder,
    AggregateSignatureSystem,
    PCDBuilder,
    PCDSystem,
};

pub use examples::{
    fibonacci_ivc_example,
    aggregate_signature_example,
    pcd_dag_example,
};
