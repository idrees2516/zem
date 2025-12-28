// Optimization module - Tasks 8 & 20
// Implements Gruen's optimization, parallel proving, streaming, cache optimization,
// and AVX-512 hardware acceleration

pub mod gruen;
pub mod parallel_sumcheck;
pub mod streaming;
pub mod cache;
pub mod parallel_sumcheck_full;
pub mod avx512_ring;
pub mod ntt_opt;
pub mod memory;
pub mod parallel;
pub mod sparse;

pub use gruen::{GruenSumCheckProver, GruenPerformanceComparison};
pub use parallel_sumcheck::{ParallelSumCheckProver, ParallelConfig, ParallelPerformance};
pub use parallel_sumcheck_full::{
    ParallelSumCheckProver as FullParallelProver,
    ParallelConfig as FullParallelConfig,
    ParallelPerformance as FullParallelPerformance,
};
pub use avx512_ring::{
    AVX512Vector, AVX512ModArith, AVX512NTT,
    is_avx512_ifma_available,
};

// Re-export existing optimization modules
pub use memory::MemoryPool;
pub use parallel::ParallelConfig as ExistingParallelConfig;
pub use sparse::SparseOptimization;
