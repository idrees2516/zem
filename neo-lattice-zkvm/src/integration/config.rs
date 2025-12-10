// Configuration for Neo-AGM Integration

use serde::{Serialize, Deserialize};

/// Neo AGM Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeoAGMConfig {
    /// Integration mode
    pub mode: IntegrationMode,
    
    /// Enable AGM security
    pub enable_agm: bool,
}

impl Default for NeoAGMConfig {
    fn default() -> Self {
        Self {
            mode: IntegrationMode::Hybrid,
            enable_agm: true,
        }
    }
}

/// Integration Mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationMode {
    /// Use only Neo components (no AGM)
    NeoOnly,
    
    /// Use only AGM components
    AGMOnly,
    
    /// Hybrid: Neo for efficiency, AGM for security
    Hybrid,
}
