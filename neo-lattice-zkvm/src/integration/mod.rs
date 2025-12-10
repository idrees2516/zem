// Integration Module
//
// Provides adapters and utilities for integrating AGM-secure components
// with existing Neo codebase.

pub mod symphony_adapter;
pub mod config;

pub use symphony_adapter::{
    SymphonyRelSNARK,
    AGMConfig,
    OracleForcingStrategy,
};

pub use config::{
    NeoAGMConfig,
    IntegrationMode,
};
