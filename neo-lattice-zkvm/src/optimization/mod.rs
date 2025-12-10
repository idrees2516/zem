// Optimization module - Task 8
// Implements Gruen's optimization, parallel proving, streaming, and cache optimization

pub mod gruen;
pub mod parallel_sumcheck;
pub mod streaming;
pub mod cache;

pub use gruen::{GruenSumCheckProver, GruenPerformanceComparison};
pub use parallel_sumcheck::{ParallelSumCheckProver, ParallelConfig, ParallelPerformance};

// Re-export existing optimization modules
pub use crate::optimization::memory::MemoryPool;
pub use crate::optimization::parallel::ParallelConfig as ExistingParallelConfig;
pub use crate::optimization::sparse::SparseOptimization;
