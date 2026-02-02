// Performance optimization module
//
// Implements SIMD vectorization, parallel execution, memory management,
// and caching strategies for efficient Hachi protocol execution.

pub mod simd;
pub mod parallel;
pub mod memory;
pub mod cache;

pub use simd::*;
pub use parallel::*;
pub use memory::*;
pub use cache::*;
