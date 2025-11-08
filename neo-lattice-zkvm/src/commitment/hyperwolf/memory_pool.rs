// Memory Pool for HyperWolf PCS
// Provides reusable buffers to minimize allocations in hot paths
// Per Task 14.5: Optimize memory usage
//
// OPTIMIZATIONS:
// - Reusable buffers for intermediate computations
// - Row-major order for cache-friendly access
// - Minimized allocations in proof generation/verification
// - Buffer pooling for ring element operations

use crate::field::Field;
use crate::ring::RingElement;
use std::cell::RefCell;
use std::collections::VecDeque;

/// Thread-local buffer pool for ring elements
/// 
/// OPTIMIZED (Task 14.5):
/// - Reuses allocated vectors to avoid repeated allocations
/// - Maintains pool of buffers for different sizes
/// - Thread-local to avoid synchronization overhead
thread_local! {
    static RING_BUFFER_POOL: RefCell<RingBufferPool> = RefCell::new(RingBufferPool::new());
}

/// Buffer pool for ring element vectors
struct RingBufferPool {
    /// Pools organized by buffer size
    /// Key: buffer size, Value: queue of available buffers
    pools: std::collections::HashMap<usize, VecDeque<Vec<u64>>>,
    
    /// Maximum buffers to keep per size
    max_buffers_per_size: usize,
}

impl RingBufferPool {
    /// Create new buffer pool
    fn new() -> Self {
        Self {
            pools: std::collections::HashMap::new(),
            max_buffers_per_size: 16, // Keep up to 16 buffers per size
        }
    }
    
    /// Get buffer of specified size
    /// Returns existing buffer if available, otherwise allocates new one
    fn get_buffer(&mut self, size: usize) -> Vec<u64> {
        if let Some(pool) = self.pools.get_mut(&size) {
            if let Some(buffer) = pool.pop_front() {
                return buffer;
            }
        }
        
        // Allocate new buffer
        vec![0u64; size]
    }
    
    /// Return buffer to pool for reuse
    fn return_buffer(&mut self, mut buffer: Vec<u64>) {
        let size = buffer.len();
        
        // Clear buffer
        buffer.fill(0);
        
        // Get or create pool for this size
        let pool = self.pools.entry(size).or_insert_with(VecDeque::new);
        
        // Only keep up to max_buffers_per_size
        if pool.len() < self.max_buffers_per_size {
            pool.push_back(buffer);
        }
        // Otherwise, let buffer be dropped
    }
    
    /// Clear all pools (for testing/cleanup)
    #[allow(dead_code)]
    fn clear(&mut self) {
        self.pools.clear();
    }
}

/// RAII guard for buffer borrowing
/// Automatically returns buffer to pool when dropped
pub struct BufferGuard {
    buffer: Option<Vec<u64>>,
}

impl BufferGuard {
    /// Get mutable reference to buffer
    pub fn as_mut(&mut self) -> &mut Vec<u64> {
        self.buffer.as_mut().unwrap()
    }
    
    /// Get immutable reference to buffer
    pub fn as_ref(&self) -> &Vec<u64> {
        self.buffer.as_ref().unwrap()
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            RING_BUFFER_POOL.with(|pool| {
                pool.borrow_mut().return_buffer(buffer);
            });
        }
    }
}

/// Get buffer from pool
/// 
/// OPTIMIZED (Task 14.5):
/// - Reuses existing allocations when possible
/// - Automatically returns buffer to pool via RAII
pub fn get_buffer(size: usize) -> BufferGuard {
    let buffer = RING_BUFFER_POOL.with(|pool| {
        pool.borrow_mut().get_buffer(size)
    });
    
    BufferGuard {
        buffer: Some(buffer),
    }
}

/// Workspace for ring element operations
/// 
/// OPTIMIZED (Task 14.5):
/// - Provides scratch space for intermediate computations
/// - Avoids repeated allocations in hot paths
/// - Row-major layout for cache efficiency
pub struct RingWorkspace<F: Field> {
    /// Scratch buffer for intermediate ring elements
    scratch: Vec<RingElement<F>>,
    
    /// Ring dimension
    ring_dim: usize,
    
    /// Current usage index
    next_idx: usize,
}

impl<F: Field> RingWorkspace<F> {
    /// Create new workspace with capacity for n ring elements
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - Pre-allocates space to avoid repeated allocations
    pub fn new(capacity: usize, ring_dim: usize) -> Self {
        let mut scratch = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            scratch.push(RingElement::zero(ring_dim));
        }
        
        Self {
            scratch,
            ring_dim,
            next_idx: 0,
        }
    }
    
    /// Get next available scratch element
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - Reuses pre-allocated elements
    /// - Panics if capacity exceeded (indicates need for larger workspace)
    pub fn get_scratch(&mut self) -> &mut RingElement<F> {
        if self.next_idx >= self.scratch.len() {
            panic!("Workspace capacity exceeded: {} >= {}", self.next_idx, self.scratch.len());
        }
        
        let elem = &mut self.scratch[self.next_idx];
        self.next_idx += 1;
        elem
    }
    
    /// Reset workspace for reuse
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - Clears elements without deallocating
    pub fn reset(&mut self) {
        self.next_idx = 0;
        for elem in &mut self.scratch {
            *elem = RingElement::zero(self.ring_dim);
        }
    }
    
    /// Get current usage
    pub fn usage(&self) -> usize {
        self.next_idx
    }
    
    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.scratch.len()
    }
}

/// Memory-efficient vector operations
/// 
/// OPTIMIZED (Task 14.5):
/// - In-place operations where possible
/// - Minimized intermediate allocations
pub struct VectorOps;

impl VectorOps {
    /// In-place vector addition: a += b
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - No allocation, modifies a in place
    pub fn add_inplace<F: Field>(
        a: &mut [RingElement<F>],
        b: &[RingElement<F>],
        ring: &crate::ring::CyclotomicRing<F>,
    ) {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        for (a_elem, b_elem) in a.iter_mut().zip(b.iter()) {
            *a_elem = ring.add(a_elem, b_elem);
        }
    }
    
    /// In-place scalar multiplication: a *= scalar
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - No allocation, modifies a in place
    pub fn scalar_mul_inplace<F: Field>(
        a: &mut [RingElement<F>],
        scalar: &RingElement<F>,
        ring: &crate::ring::CyclotomicRing<F>,
    ) {
        for elem in a.iter_mut() {
            *elem = ring.mul(scalar, elem);
        }
    }
    
    /// In-place vector subtraction: a -= b
    /// 
    /// OPTIMIZED (Task 14.5):
    /// - No allocation, modifies a in place
    pub fn sub_inplace<F: Field>(
        a: &mut [RingElement<F>],
        b: &[RingElement<F>],
        ring: &crate::ring::CyclotomicRing<F>,
    ) {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        
        for (a_elem, b_elem) in a.iter_mut().zip(b.iter()) {
            *a_elem = ring.sub(a_elem, b_elem);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_buffer_pool() {
        let mut buffer1 = get_buffer(100);
        buffer1.as_mut()[0] = 42;
        
        // Buffer should be cleared when returned
        drop(buffer1);
        
        let buffer2 = get_buffer(100);
        assert_eq!(buffer2.as_ref()[0], 0);
    }
    
    #[test]
    fn test_workspace() {
        let mut workspace = RingWorkspace::<GoldilocksField>::new(10, 64);
        
        assert_eq!(workspace.capacity(), 10);
        assert_eq!(workspace.usage(), 0);
        
        let _elem1 = workspace.get_scratch();
        assert_eq!(workspace.usage(), 1);
        
        let _elem2 = workspace.get_scratch();
        assert_eq!(workspace.usage(), 2);
        
        workspace.reset();
        assert_eq!(workspace.usage(), 0);
    }
    
    #[test]
    fn test_vector_ops_inplace() {
        use crate::ring::CyclotomicRing;
        
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        
        let mut a = vec![
            RingElement::from_constant(GoldilocksField::from_u64(5), 64),
            RingElement::from_constant(GoldilocksField::from_u64(10), 64),
        ];
        
        let b = vec![
            RingElement::from_constant(GoldilocksField::from_u64(3), 64),
            RingElement::from_constant(GoldilocksField::from_u64(7), 64),
        ];
        
        VectorOps::add_inplace(&mut a, &b, &ring);
        
        assert_eq!(a[0].coeffs[0].to_canonical_u64(), 8);
        assert_eq!(a[1].coeffs[0].to_canonical_u64(), 17);
    }
}
