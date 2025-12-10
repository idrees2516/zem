// Parameter Selection Logic - Task 12.1
// Provides optimal parameter selection for different memory sizes and use cases

use crate::field::Field;

/// Parameter selection for Shout/Twist protocols
#[derive(Clone, Debug)]
pub struct ParameterSelection {
    /// Memory size K
    pub memory_size: usize,
    
    /// Number of lookups/cycles T
    pub num_operations: usize,
    
    /// Optimal d parameter
    pub optimal_d: usize,
    
    /// Chunk size K^{1/d}
    pub chunk_size: usize,
    
    /// Committed values per address
    pub committed_per_address: usize,
    
    /// Commitment key size
    pub commitment_key_size: usize,
    
    /// Proof size estimate (field elements)
    pub proof_size: usize,
}

impl ParameterSelection {
    /// Select optimal parameters for given memory size and operations
    /// 
    /// Algorithm:
    /// - K ≤ 2^16: d=1 (small memory, simple)
    /// - K ≤ 2^20: d=2 (medium memory, balanced)
    /// - K ≤ 2^30: d=4 (large memory, efficient)
    /// - K > 2^30: d=8 (gigantic memory, sparse-dense)
    pub fn select(memory_size: usize, num_operations: usize) -> Self {
        let optimal_d = Self::select_d(memory_size);
        let chunk_size = Self::compute_chunk_size(memory_size, optimal_d);
        let committed_per_address = optimal_d * chunk_size;
        let commitment_key_size = committed_per_address * num_operations;
        let proof_size = Self::estimate_proof_size(optimal_d, memory_size);
        
        Self {
            memory_size,
            num_operations,
            optimal_d,
            chunk_size,
            committed_per_address,
            commitment_key_size,
            proof_size,
        }
    }
    
    /// Select optimal d parameter
    fn select_d(memory_size: usize) -> usize {
        match memory_size {
            k if k <= 65536 => 1,        // ≤ 2^16 (64KB)
            k if k <= 1048576 => 2,      // ≤ 2^20 (1MB)
            k if k <= 1073741824 => 4,   // ≤ 2^30 (1GB)
            _ => 8,                       // > 2^30
        }
    }
    
    /// Compute chunk size K^{1/d}
    fn compute_chunk_size(memory_size: usize, d: usize) -> usize {
        (memory_size as f64).powf(1.0 / d as f64).ceil() as usize
    }
    
    /// Estimate proof size in field elements
    fn estimate_proof_size(d: usize, memory_size: usize) -> usize {
        let log_k = (memory_size as f64).log2() as usize;
        
        // Proof size: d commitments + log K sum-check rounds
        d * 32 + log_k * 3 // 32 elements per commitment, 3 per round
    }
    
    /// Print parameter selection report
    pub fn print_report(&self) {
        println!("Parameter Selection Report:");
        println!("  Memory size K: {}", self.memory_size);
        println!("  Operations T: {}", self.num_operations);
        println!("  Optimal d: {}", self.optimal_d);
        println!("  Chunk size K^{{1/d}}: {}", self.chunk_size);
        println!("  Committed per address: {}", self.committed_per_address);
        println!("  Commitment key size: {}", self.commitment_key_size);
        println!("  Proof size: {} field elements", self.proof_size);
    }
    
    /// Compare different d values
    pub fn compare_d_values(memory_size: usize, num_operations: usize) -> Vec<Self> {
        let mut results = Vec::new();
        
        for d in [1, 2, 4, 8] {
            let chunk_size = Self::compute_chunk_size(memory_size, d);
            let committed_per_address = d * chunk_size;
            let commitment_key_size = committed_per_address * num_operations;
            let proof_size = Self::estimate_proof_size(d, memory_size);
            
            results.push(Self {
                memory_size,
                num_operations,
                optimal_d: d,
                chunk_size,
                committed_per_address,
                commitment_key_size,
                proof_size,
            });
        }
        
        results
    }
}

/// Use case specific parameter selection
pub struct UseCaseParameters;

impl UseCaseParameters {
    /// Parameters for RISC-V register file (K=32)
    pub fn riscv_registers() -> ParameterSelection {
        ParameterSelection::select(32, 1_048_576) // 32 registers, 1M cycles
    }
    
    /// Parameters for small RAM (K=2^16 = 64KB)
    pub fn small_ram() -> ParameterSelection {
        ParameterSelection::select(65536, 1_048_576) // 64KB, 1M cycles
    }
    
    /// Parameters for medium RAM (K=2^20 = 1MB)
    pub fn medium_ram() -> ParameterSelection {
        ParameterSelection::select(1_048_576, 1_048_576) // 1MB, 1M cycles
    }
    
    /// Parameters for large RAM (K=2^24 = 16MB)
    pub fn large_ram() -> ParameterSelection {
        ParameterSelection::select(16_777_216, 1_048_576) // 16MB, 1M cycles
    }
    
    /// Parameters for instruction fetch (K=2^20 program size)
    pub fn instruction_fetch() -> ParameterSelection {
        ParameterSelection::select(1_048_576, 1_048_576) // 1MB program, 1M cycles
    }
    
    /// Parameters for instruction execution tables (K=2^16)
    pub fn instruction_tables() -> ParameterSelection {
        ParameterSelection::select(65536, 1_048_576) // 64K table, 1M lookups
    }
}

/// Trade-off analysis
pub struct TradeoffAnalysis {
    /// Parameter selections for different d values
    pub selections: Vec<ParameterSelection>,
}

impl TradeoffAnalysis {
    /// Analyze trade-offs for given memory size
    pub fn analyze(memory_size: usize, num_operations: usize) -> Self {
        let selections = ParameterSelection::compare_d_values(memory_size, num_operations);
        Self { selections }
    }
    
    /// Print trade-off analysis
    pub fn print_analysis(&self) {
        println!("\nTrade-off Analysis:");
        println!("{:<6} {:<12} {:<20} {:<20} {:<15}", 
                 "d", "Chunk Size", "Committed/Address", "Key Size", "Proof Size");
        println!("{}", "-".repeat(80));
        
        for sel in &self.selections {
            println!("{:<6} {:<12} {:<20} {:<20} {:<15}",
                     sel.optimal_d,
                     sel.chunk_size,
                     sel.committed_per_address,
                     sel.commitment_key_size,
                     sel.proof_size);
        }
        
        println!("\nRecommendation:");
        let optimal = &self.selections[0];
        let recommended_d = ParameterSelection::select_d(optimal.memory_size);
        let recommended = self.selections.iter()
            .find(|s| s.optimal_d == recommended_d)
            .unwrap();
        
        println!("  For K={}, use d={}", optimal.memory_size, recommended.optimal_d);
        println!("  Rationale: Balances commitment costs, prover time, and proof size");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parameter_selection() {
        // Test RISC-V registers
        let params = UseCaseParameters::riscv_registers();
        assert_eq!(params.optimal_d, 1);
        assert_eq!(params.memory_size, 32);
        
        println!("RISC-V Registers:");
        params.print_report();
    }
    
    #[test]
    fn test_memory_sizes() {
        // Test different memory sizes
        let test_cases = vec![
            (32, 1),           // Registers: d=1
            (65536, 1),        // 64KB: d=1
            (1048576, 2),      // 1MB: d=2
            (16777216, 4),     // 16MB: d=4
            (1073741824, 4),   // 1GB: d=4
            (2147483648, 8),   // 2GB: d=8
        ];
        
        for (k, expected_d) in test_cases {
            let params = ParameterSelection::select(k, 1_000_000);
            assert_eq!(params.optimal_d, expected_d, 
                      "For K={}, expected d={}, got d={}", k, expected_d, params.optimal_d);
        }
    }
    
    #[test]
    fn test_tradeoff_analysis() {
        let analysis = TradeoffAnalysis::analyze(1_048_576, 1_000_000);
        analysis.print_analysis();
        
        // Verify we have results for all d values
        assert_eq!(analysis.selections.len(), 4);
    }
    
    #[test]
    fn test_use_cases() {
        println!("\n=== Use Case Parameters ===\n");
        
        println!("1. RISC-V Registers:");
        UseCaseParameters::riscv_registers().print_report();
        
        println!("\n2. Small RAM:");
        UseCaseParameters::small_ram().print_report();
        
        println!("\n3. Medium RAM:");
        UseCaseParameters::medium_ram().print_report();
        
        println!("\n4. Large RAM:");
        UseCaseParameters::large_ram().print_report();
        
        println!("\n5. Instruction Fetch:");
        UseCaseParameters::instruction_fetch().print_report();
        
        println!("\n6. Instruction Tables:");
        UseCaseParameters::instruction_tables().print_report();
    }
}
