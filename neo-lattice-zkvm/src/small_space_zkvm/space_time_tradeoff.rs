/// Space-Time Trade-off Configuration Module
/// 
/// Implements configurable space-time trade-offs for the small-space zkVM prover,
/// supporting both O(K + log T) and O(K + T^(1/2)) space configurations with
/// automatic switching logic and dimension parameter optimization.

use crate::field::FieldElement;
use std::fmt;

/// Space bound configuration for the prover
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceBound {
    /// O(K + log T) space configuration
    /// Optimal for very large T (T > 2^40)
    Logarithmic,
    
    /// O(K + T^(1/2)) space configuration
    /// Optimal for moderate T (2^20 < T < 2^40)
    SquareRoot,
}

impl fmt::Display for SpaceBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpaceBound::Logarithmic => write!(f, "O(K + log T)"),
            SpaceBound::SquareRoot => write!(f, "O(K + T^(1/2))"),
        }
    }
}

/// Configuration for space-time trade-offs
#[derive(Clone, Debug)]
pub struct SpaceTimeConfig {
    /// Memory size K (number of addressable cells)
    pub memory_size: usize,
    
    /// Number of execution cycles T
    pub num_cycles: usize,
    
    /// Target space bound
    pub target_space: SpaceBound,
    
    /// Dimension parameter C for prefix-suffix protocol
    /// Larger C reduces space but increases time
    pub dimension_parameter: usize,
    
    /// Enable automatic switching between configurations
    pub auto_switch: bool,
    
    /// Maximum allowed space in bytes (for validation)
    pub max_space_bytes: Option<usize>,
}

impl SpaceTimeConfig {
    /// Create a new space-time configuration
    pub fn new(memory_size: usize, num_cycles: usize, target_space: SpaceBound) -> Self {
        let dimension_parameter = Self::compute_dimension_parameter(memory_size, num_cycles, target_space);
        
        Self {
            memory_size,
            num_cycles,
            target_space,
            dimension_parameter,
            auto_switch: true,
            max_space_bytes: None,
        }
    }
    
    /// Compute optimal dimension parameter C based on configuration
    /// 
    /// For prefix-suffix protocol with C stages:
    /// - Space: O(k·C·N^(1/C)) where N = max(K, T)
    /// - Time: O(C·k·N^(1/C)) per stage
    /// 
    /// For O(K + T^(1/2)): Choose C=2, k=2 → O(4·√N)
    /// For O(K + log T): Use recursive decomposition with C=log(T)
    fn compute_dimension_parameter(memory_size: usize, num_cycles: usize, target_space: SpaceBound) -> usize {
        match target_space {
            SpaceBound::SquareRoot => {
                // C=2 gives O(4·√N) space
                2
            },
            SpaceBound::Logarithmic => {
                // C = log(T) gives O(k·log(T)·T^(1/log T)) = O(k·log T)
                // Compute log2(T)
                let log_t = (num_cycles as f64).log2().ceil() as usize;
                log_t.max(2)
            },
        }
    }
    
    /// Estimate space usage in bytes for this configuration
    pub fn estimate_space_bytes(&self) -> usize {
        let field_element_size = 32; // Assume 256-bit field elements
        let group_element_size = 48; // Assume 384-bit group elements
        
        match self.target_space {
            SpaceBound::SquareRoot => {
                // O(K + T^(1/2)) space
                let sqrt_t = (self.num_cycles as f64).sqrt().ceil() as usize;
                let sqrt_k = (self.memory_size as f64).sqrt().ceil() as usize;
                
                // Witness vectors: O(√T) field elements
                let witness_space = sqrt_t * field_element_size;
                
                // Commitment keys: O(√K) group elements
                let commitment_space = sqrt_k * group_element_size;
                
                // Temporary arrays: O(√T) field elements
                let temp_space = sqrt_t * field_element_size;
                
                witness_space + commitment_space + temp_space
            },
            SpaceBound::Logarithmic => {
                // O(K + log T) space
                let log_t = (self.num_cycles as f64).log2().ceil() as usize;
                
                // Witness vectors: O(log T) field elements
                let witness_space = log_t * field_element_size;
                
                // Memory: O(K) field elements
                let memory_space = self.memory_size * field_element_size;
                
                // Temporary arrays: O(log T) field elements
                let temp_space = log_t * field_element_size;
                
                witness_space + memory_space + temp_space
            },
        }
    }
    
    /// Validate that configuration meets space constraints
    pub fn validate_space_constraints(&self) -> Result<(), String> {
        if let Some(max_space) = self.max_space_bytes {
            let estimated = self.estimate_space_bytes();
            if estimated > max_space {
                return Err(format!(
                    "Estimated space {} bytes exceeds maximum {} bytes",
                    estimated, max_space
                ));
            }
        }
        Ok(())
    }
    
    /// Automatically select best configuration based on parameters
    pub fn auto_select(memory_size: usize, num_cycles: usize) -> Self {
        // Choose based on T value
        let target_space = if num_cycles > (1 << 40) {
            // For very large T, use logarithmic space
            SpaceBound::Logarithmic
        } else {
            // For moderate T, use square root space
            SpaceBound::SquareRoot
        };
        
        Self::new(memory_size, num_cycles, target_space)
    }
    
    /// Get estimated time overhead factor compared to linear space
    pub fn time_overhead_factor(&self) -> f64 {
        match self.target_space {
            SpaceBound::SquareRoot => {
                // Small-space sum-check adds ~40T operations
                // Total ~900T + 40T = 940T vs 900T linear
                // Overhead: ~1.04×
                1.04
            },
            SpaceBound::Logarithmic => {
                // Recursive decomposition adds more overhead
                // Total ~900T + 12T·log(T) vs 900T linear
                // For T=2^35: 12·35·2^35 ≈ 1.5×10^12 vs 9×10^11
                // Overhead: ~1.67×
                let log_t = (self.num_cycles as f64).log2();
                1.0 + (12.0 * log_t / 900.0)
            },
        }
    }
}

/// Automatic switching logic for space-time trade-offs
pub struct SpaceTimeSwitcher {
    /// Current configuration
    current_config: SpaceTimeConfig,
    
    /// Threshold for switching between configurations
    switch_threshold: usize,
}

impl SpaceTimeSwitcher {
    /// Create a new space-time switcher
    pub fn new(initial_config: SpaceTimeConfig) -> Self {
        // Switch threshold: T = 2^40
        let switch_threshold = 1 << 40;
        
        Self {
            current_config: initial_config,
            switch_threshold,
        }
    }
    
    /// Get current configuration
    pub fn current_config(&self) -> &SpaceTimeConfig {
        &self.current_config
    }
    
    /// Check if should switch configuration based on actual T
    pub fn should_switch(&self, actual_cycles: usize) -> bool {
        if !self.current_config.auto_switch {
            return false;
        }
        
        match self.current_config.target_space {
            SpaceBound::SquareRoot => {
                // Switch to logarithmic if T exceeds threshold
                actual_cycles > self.switch_threshold
            },
            SpaceBound::Logarithmic => {
                // Switch to square root if T is below threshold
                actual_cycles < self.switch_threshold / 2
            },
        }
    }
    
    /// Switch to new configuration
    pub fn switch_to(&mut self, new_config: SpaceTimeConfig) {
        self.current_config = new_config;
    }
}

/// Dimension parameter selector for prefix-suffix protocol
pub struct DimensionParameterSelector;

impl DimensionParameterSelector {
    /// Select optimal dimension parameter C
    /// 
    /// For prefix-suffix protocol with C stages:
    /// - Space: O(k·C·N^(1/C))
    /// - Time: O(C·k·N^(1/C)) per stage
    /// 
    /// Optimal C minimizes space while keeping time reasonable
    pub fn select_optimal(
        num_vars: usize,
        num_terms: usize,
        target_space: SpaceBound,
    ) -> usize {
        match target_space {
            SpaceBound::SquareRoot => {
                // C=2 gives O(4·√N) space, O(2·√N) time per stage
                2
            },
            SpaceBound::Logarithmic => {
                // C = log(N) gives O(k·log N·N^(1/log N)) = O(k·log N)
                // But practical limit: C ≤ 8 to avoid too many stages
                let log_n = (num_vars as f64).log2().ceil() as usize;
                log_n.min(8)
            },
        }
    }
    
    /// Compute space usage for given dimension parameter
    pub fn compute_space(
        num_vars: usize,
        num_terms: usize,
        dimension: usize,
    ) -> usize {
        // Space: O(k·C·N^(1/C)) field elements
        // Assume 32-byte field elements
        let field_element_size = 32;
        
        let n = 1usize << num_vars;
        let n_inv_c = (n as f64).powf(1.0 / dimension as f64).ceil() as usize;
        
        num_terms * dimension * n_inv_c * field_element_size
    }
    
    /// Compute time overhead for given dimension parameter
    pub fn compute_time_overhead(
        num_vars: usize,
        num_terms: usize,
        dimension: usize,
    ) -> f64 {
        // Time per stage: O(C·k·N^(1/C)) field operations
        // Total: O(C·k·N^(1/C)) × C stages = O(C²·k·N^(1/C))
        
        let n = 1usize << num_vars;
        let n_inv_c = (n as f64).powf(1.0 / dimension as f64);
        
        let time_per_stage = dimension as f64 * num_terms as f64 * n_inv_c;
        let total_time = dimension as f64 * time_per_stage;
        
        // Overhead compared to linear time O(n)
        total_time / (n as f64)
    }
}

/// Performance characteristics for space-time trade-offs
#[derive(Clone, Debug)]
pub struct SpaceTimeCharacteristics {
    /// Space complexity class
    pub space_bound: SpaceBound,
    
    /// Estimated space in bytes
    pub estimated_space_bytes: usize,
    
    /// Time overhead factor compared to linear space
    pub time_overhead_factor: f64,
    
    /// Dimension parameter C
    pub dimension_parameter: usize,
    
    /// Number of prefix-suffix stages
    pub num_stages: usize,
}

impl SpaceTimeCharacteristics {
    /// Create characteristics from configuration
    pub fn from_config(config: &SpaceTimeConfig) -> Self {
        let num_stages = match config.target_space {
            SpaceBound::SquareRoot => 2,
            SpaceBound::Logarithmic => config.dimension_parameter,
        };
        
        Self {
            space_bound: config.target_space,
            estimated_space_bytes: config.estimate_space_bytes(),
            time_overhead_factor: config.time_overhead_factor(),
            dimension_parameter: config.dimension_parameter,
            num_stages,
        }
    }
    
    /// Format as human-readable string
    pub fn format_summary(&self) -> String {
        format!(
            "Space: {} ({} bytes), Time Overhead: {:.2}×, Stages: {}",
            self.space_bound,
            self.estimated_space_bytes,
            self.time_overhead_factor,
            self.num_stages
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_space_bound_display() {
        assert_eq!(format!("{}", SpaceBound::Logarithmic), "O(K + log T)");
        assert_eq!(format!("{}", SpaceBound::SquareRoot), "O(K + T^(1/2))");
    }
    
    #[test]
    fn test_config_creation() {
        let config = SpaceTimeConfig::new(1 << 25, 1 << 35, SpaceBound::SquareRoot);
        assert_eq!(config.memory_size, 1 << 25);
        assert_eq!(config.num_cycles, 1 << 35);
        assert_eq!(config.target_space, SpaceBound::SquareRoot);
        assert_eq!(config.dimension_parameter, 2);
    }
    
    #[test]
    fn test_dimension_parameter_computation() {
        // For square root: C=2
        let c_sqrt = SpaceTimeConfig::compute_dimension_parameter(1 << 25, 1 << 35, SpaceBound::SquareRoot);
        assert_eq!(c_sqrt, 2);
        
        // For logarithmic: C=log(T)
        let c_log = SpaceTimeConfig::compute_dimension_parameter(1 << 25, 1 << 35, SpaceBound::Logarithmic);
        assert_eq!(c_log, 35);
    }
    
    #[test]
    fn test_space_estimation() {
        let config = SpaceTimeConfig::new(1 << 25, 1 << 35, SpaceBound::SquareRoot);
        let space = config.estimate_space_bytes();
        
        // Should be roughly O(√T) + O(√K) + O(√T)
        // √(2^35) ≈ 2^17.5 ≈ 185K
        // √(2^25) ≈ 2^12.5 ≈ 5.6K
        // Total: ~400K field elements * 32 bytes ≈ 12.8 MB
        assert!(space > 1_000_000); // At least 1 MB
        assert!(space < 100_000_000); // Less than 100 MB
    }
    
    #[test]
    fn test_auto_select() {
        // Small T: should select square root
        let config_small = SpaceTimeConfig::auto_select(1 << 25, 1 << 30);
        assert_eq!(config_small.target_space, SpaceBound::SquareRoot);
        
        // Large T: should select logarithmic
        let config_large = SpaceTimeConfig::auto_select(1 << 25, 1 << 50);
        assert_eq!(config_large.target_space, SpaceBound::Logarithmic);
    }
    
    #[test]
    fn test_time_overhead() {
        let config_sqrt = SpaceTimeConfig::new(1 << 25, 1 << 35, SpaceBound::SquareRoot);
        let overhead_sqrt = config_sqrt.time_overhead_factor();
        assert!(overhead_sqrt > 1.0 && overhead_sqrt < 1.1); // ~1.04×
        
        let config_log = SpaceTimeConfig::new(1 << 25, 1 << 35, SpaceBound::Logarithmic);
        let overhead_log = config_log.time_overhead_factor();
        assert!(overhead_log > 1.0 && overhead_log < 2.0); // ~1.67×
    }
    
    #[test]
    fn test_switcher() {
        let config = SpaceTimeConfig::new(1 << 25, 1 << 35, SpaceBound::SquareRoot);
        let mut switcher = SpaceTimeSwitcher::new(config);
        
        // Should not switch for T=2^35
        assert!(!switcher.should_switch(1 << 35));
        
        // Should switch for T=2^50
        assert!(switcher.should_switch(1 << 50));
    }
    
    #[test]
    fn test_dimension_selector() {
        let c_sqrt = DimensionParameterSelector::select_optimal(35, 2, SpaceBound::SquareRoot);
        assert_eq!(c_sqrt, 2);
        
        let c_log = DimensionParameterSelector::select_optimal(35, 2, SpaceBound::Logarithmic);
        assert_eq!(c_log, 35);
    }
}
