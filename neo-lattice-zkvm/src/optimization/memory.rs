// Memory pooling and buffer management for Neo
//
// Task 17.1: Implement memory pooling
// - Memory pool for field element buffers
// - Memory pool for ring element buffers
// - Buffer reuse to reduce allocations
// - Streaming computation for large witnesses

use crate::field::Field;
use crate::ring::cyclotomic::RingElement;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Memory pool for reusable buffers
///
/// Reduces allocation overhead by reusing buffers across computations.
/// Thread-safe for concurrent access.
pub struct MemoryPool<T> {
    /// Pool of available buffers
    buffers: Arc<Mutex<VecDeque<Vec<T>>>>,
    
    /// Maximum number of buffers to keep in pool
    max_pool_size: usize,
    
    /// Default buffer capacity
    default_capacity: usize,
}

impl<T: Clone> MemoryPool<T> {
    /// Create a new memory pool
    ///
    /// # Arguments
    /// * `max_pool_size` - Maximum number of buffers to cache
    /// * `default_capacity` - Default capacity for new buffers
    pub fn new(max_pool_size: usize, default_capacity: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(VecDeque::with_capacity(max_pool_size))),
            max_pool_size,
            default_capacity,
        }
    }
    
    /// Get a buffer from the pool or allocate a new one
    ///
    /// # Arguments
    /// * `min_capacity` - Minimum required capacity
    ///
    /// # Returns
    /// A buffer with at least the requested capacity
    pub fn get(&self, min_capacity: usize) -> PooledBuffer<T> {
        let mut buffers = self.buffers.lock().unwrap();
        
        // Try to find a buffer with sufficient capacity
        let buffer = buffers
            .iter()
            .position(|buf| buf.capacity() >= min_capacity)
            .and_then(|idx| buffers.remove(idx))
            .unwrap_or_else(|| {
                // Allocate new buffer
                Vec::with_capacity(min_capacity.max(self.default_capacity))
            });
        
        PooledBuffer {
            buffer: Some(buffer),
            pool: Arc::clone(&self.buffers),
            max_pool_size: self.max_pool_size,
        }
    }
    
    /// Get a buffer with default capacity
    pub fn get_default(&self) -> PooledBuffer<T> {
        self.get(self.default_capacity)
    }
    
    /// Clear all buffers from the pool
    pub fn clear(&self) {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.clear();
    }
    
    /// Get current pool size
    pub fn size(&self) -> usize {
        let buffers = self.buffers.lock().unwrap();
        buffers.len()
    }
}

/// A buffer borrowed from a memory pool
///
/// Automatically returns the buffer to the pool when dropped.
pub struct PooledBuffer<T> {
    buffer: Option<Vec<T>>,
    pool: Arc<Mutex<VecDeque<Vec<T>>>>,
    max_pool_size: usize,
}

impl<T> PooledBuffer<T> {
    /// Get mutable reference to the buffer
    pub fn as_mut(&mut self) -> &mut Vec<T> {
        self.buffer.as_mut().unwrap()
    }
    
    /// Get immutable reference to the buffer
    pub fn as_ref(&self) -> &Vec<T> {
        self.buffer.as_ref().unwrap()
    }
    
    /// Clear the buffer contents
    pub fn clear(&mut self) {
        if let Some(buf) = &mut self.buffer {
            buf.clear();
        }
    }
    
    /// Resize the buffer
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        if let Some(buf) = &mut self.buffer {
            buf.resize(new_len, value);
        }
    }
}

impl<T> Drop for PooledBuffer<T> {
    fn drop(&mut self) {
        if let Some(mut buffer) = self.buffer.take() {
            buffer.clear(); // Clear contents but keep capacity
            
            let mut pool = self.pool.lock().unwrap();
            if pool.len() < self.max_pool_size {
                pool.push_back(buffer);
            }
            // Otherwise, buffer is dropped and deallocated
        }
    }
}

impl<T> std::ops::Deref for PooledBuffer<T> {
    type Target = Vec<T>;
    
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl<T> std::ops::DerefMut for PooledBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

/// Specialized buffer pool for field elements
pub struct BufferPool<F: Field> {
    pool: MemoryPool<F>,
}

impl<F: Field> BufferPool<F> {
    /// Create a new buffer pool for field elements
    pub fn new(max_pool_size: usize, default_capacity: usize) -> Self {
        Self {
            pool: MemoryPool::new(max_pool_size, default_capacity),
        }
    }
    
    /// Get a buffer for field elements
    pub fn get(&self, min_capacity: usize) -> PooledBuffer<F> {
        self.pool.get(min_capacity)
    }
    
    /// Get a buffer initialized with zeros
    pub fn get_zeros(&self, size: usize) -> PooledBuffer<F> {
        let mut buffer = self.pool.get(size);
        buffer.clear();
        buffer.resize(size, F::zero());
        buffer
    }
    
    /// Get a buffer initialized with ones
    pub fn get_ones(&self, size: usize) -> PooledBuffer<F> {
        let mut buffer = self.pool.get(size);
        buffer.clear();
        buffer.resize(size, F::one());
        buffer
    }
}

/// Streaming computation manager for large witnesses
///
/// Processes large witnesses in chunks to reduce memory usage.
pub struct StreamingComputation<F: Field> {
    /// Chunk size for streaming
    chunk_size: usize,
    
    /// Buffer pool for temporary storage
    buffer_pool: BufferPool<F>,
}

impl<F: Field> StreamingComputation<F> {
    /// Create a new streaming computation manager
    ///
    /// # Arguments
    /// * `chunk_size` - Size of chunks to process at a time
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            buffer_pool: BufferPool::new(10, chunk_size),
        }
    }
    
    /// Process a large vector in chunks
    ///
    /// # Arguments
    /// * `data` - Input data to process
    /// * `processor` - Function to apply to each chunk
    ///
    /// # Returns
    /// Accumulated result
    pub fn process_chunks<R, P>(&self, data: &[F], mut processor: P) -> R
    where
        P: FnMut(&[F], &mut R),
        R: Default,
    {
        let mut result = R::default();
        
        for chunk in data.chunks(self.chunk_size) {
            processor(chunk, &mut result);
        }
        
        result
    }
    
    /// Process and accumulate results from chunks
    pub fn map_reduce<R, M, Acc>(
        &self,
        data: &[F],
        mut mapper: M,
        mut accumulator: Acc,
        init: R,
    ) -> R
    where
        M: FnMut(&[F]) -> R,
        Acc: FnMut(R, R) -> R,
    {
        let mut result = init;
        
        for chunk in data.chunks(self.chunk_size) {
            let chunk_result = mapper(chunk);
            result = accumulator(result, chunk_result);
        }
        
        result
    }
    
    /// Get a temporary buffer from the pool
    pub fn get_buffer(&self, size: usize) -> PooledBuffer<F> {
        self.buffer_pool.get(size)
    }
}

/// Scratch space manager for temporary allocations
pub struct ScratchSpace<F: Field> {
    /// Reusable scratch buffers
    buffers: Vec<Vec<F>>,
    
    /// Current buffer index
    current: usize,
}

impl<F: Field> ScratchSpace<F> {
    /// Create a new scratch space with pre-allocated buffers
    pub fn new(num_buffers: usize, buffer_size: usize) -> Self {
        let buffers = (0..num_buffers)
            .map(|_| Vec::with_capacity(buffer_size))
            .collect();
        
        Self {
            buffers,
            current: 0,
        }
    }
    
    /// Get the next available scratch buffer
    pub fn next(&mut self) -> &mut Vec<F> {
        let buffer = &mut self.buffers[self.current];
        buffer.clear();
        self.current = (self.current + 1) % self.buffers.len();
        buffer
    }
    
    /// Reset all scratch buffers
    pub fn reset(&mut self) {
        for buffer in &mut self.buffers {
            buffer.clear();
        }
        self.current = 0;
    }
}

/// Memory-efficient batch processor
pub struct BatchProcessor<F: Field> {
    /// Maximum batch size
    max_batch_size: usize,
    
    /// Buffer pool
    pool: BufferPool<F>,
}

impl<F: Field> BatchProcessor<F> {
    /// Create a new batch processor
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            max_batch_size,
            pool: BufferPool::new(20, max_batch_size),
        }
    }
    
    /// Process items in batches
    pub fn process<I, O, P>(&self, items: &[I], mut processor: P) -> Vec<O>
    where
        P: FnMut(&[I]) -> Vec<O>,
    {
        let mut results = Vec::with_capacity(items.len());
        
        for batch in items.chunks(self.max_batch_size) {
            let batch_results = processor(batch);
            results.extend(batch_results);
        }
        
        results
    }
    
    /// Process and collect results with buffer reuse
    pub fn process_with_buffer<P, O>(
        &self,
        items: &[F],
        mut processor: P,
    ) -> Vec<O>
    where
        P: FnMut(&[F], &mut PooledBuffer<F>) -> O,
    {
        let mut results = Vec::with_capacity(items.len() / self.max_batch_size + 1);
        
        for batch in items.chunks(self.max_batch_size) {
            let mut buffer = self.pool.get(self.max_batch_size);
            let result = processor(batch, &mut buffer);
            results.push(result);
        }
        
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;
    
    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::<u64>::new(5, 100);
        
        {
            let mut buf1 = pool.get(50);
            buf1.push(42);
            assert_eq!(buf1.len(), 1);
        }
        
        // Buffer should be returned to pool
        assert_eq!(pool.size(), 1);
        
        {
            let buf2 = pool.get(50);
            // Should reuse the buffer
            assert_eq!(buf2.len(), 0); // Cleared when returned
            assert!(buf2.capacity() >= 50);
        }
    }
    
    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::<GoldilocksField>::new(5, 100);
        
        let zeros = pool.get_zeros(10);
        assert_eq!(zeros.len(), 10);
        for val in zeros.iter() {
            assert_eq!(val.to_canonical_u64(), 0);
        }
        
        let ones = pool.get_ones(10);
        assert_eq!(ones.len(), 10);
        for val in ones.iter() {
            assert_eq!(val.to_canonical_u64(), 1);
        }
    }
    
    #[test]
    fn test_streaming_computation() {
        let streaming = StreamingComputation::<GoldilocksField>::new(100);
        
        let data: Vec<GoldilocksField> = (0..1000)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect();
        
        // Sum all elements using streaming
        let sum = streaming.map_reduce(
            &data,
            |chunk| {
                let mut sum = GoldilocksField::zero();
                for val in chunk {
                    sum = sum.add(val);
                }
                sum
            },
            |acc, val| acc.add(&val),
            GoldilocksField::zero(),
        );
        
        // Verify result
        let expected_sum = data.iter().fold(GoldilocksField::zero(), |acc, val| acc.add(val));
        assert_eq!(sum.to_canonical_u64(), expected_sum.to_canonical_u64());
    }
    
    #[test]
    fn test_scratch_space() {
        let mut scratch = ScratchSpace::<GoldilocksField>::new(3, 100);
        
        let buf1 = scratch.next();
        buf1.push(GoldilocksField::one());
        
        let buf2 = scratch.next();
        buf2.push(GoldilocksField::from_canonical_u64(2));
        
        // Buffers should be independent
        assert_eq!(buf1.len(), 1);
        assert_eq!(buf2.len(), 1);
        
        scratch.reset();
        let buf3 = scratch.next();
        assert_eq!(buf3.len(), 0); // Should be cleared
    }
    
    #[test]
    fn test_batch_processor() {
        let processor = BatchProcessor::<GoldilocksField>::new(100);
        
        let items: Vec<GoldilocksField> = (0..500)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect();
        
        let results = processor.process_with_buffer(&items, |batch, buffer| {
            buffer.clear();
            for val in batch {
                buffer.push(val.mul(val)); // Square each element
            }
            buffer.len()
        });
        
        // Should have processed in batches
        assert!(results.len() >= 5);
    }
}
