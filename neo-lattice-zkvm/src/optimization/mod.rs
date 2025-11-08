// Performance optimizations for Neo folding scheme
//
// This module implements:
// - Task 17: Parallel processing
// - Task 17.1: Memory pooling
// - Task 17.2: Sparse matrix optimizations
// - Task 17.3: NTT optimizations

pub mod parallel;
pub mod memory;
pub mod sparse;
pub mod ntt_opt;

pub use parallel::{ParallelConfig, parallel_commitment_batch, parallel_mle_evaluations};
pub use memory::{MemoryPool, BufferPool};
pub use sparse::{CSRMatrix, optimize_sparse_matmul};
pub use ntt_opt::{NTTCache, precompute_twiddles};
