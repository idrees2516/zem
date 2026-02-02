// Memory management and optimization
//
// Implements memory-efficient data structures and algorithms
// for Hachi protocol execution.

use crate::hachi::errors::HachiError;
use crate::field::Field;

/// Memory pool
///
/// Pre-allocated memory pool for efficient allocation
pub struct MemoryPool<F: Field> {
    /// Available buffers
    available: Vec<Vec<F>>,
    
    /// In-use buffers
    in_use: Vec<Vec<F>>,
    
    /// Buffer size
    buffer_size: usize,
}

impl<F: Field> MemoryPool<F> {
    /// Create new memory pool
    pub fn new(num_buffers: usize, buffer_size: usize) -> Self {
        let mut available = Vec::new();
        
        for _ in 0..num_buffers {
            available.push(vec![F::zero(); buffer_size]);
        }
        
        Self {
            available,
            in_use: Vec::new(),
            buffer_size,
        }
    }
    
    /// Allocate buffer
    pub fn allocate(&mut self) -> Result<Vec<F>, HachiError> {
        if let Some(buffer) = self.available.pop() {
            self.in_use.push(buffer.clone());
            Ok(buffer)
        } else {
            Err(HachiError::InvalidParameters(
                "Memory pool exhausted".to_string()
            ))
        }
    }
    
    /// Deallocate buffer
    pub fn deallocate(&mut self, buffer: Vec<F>) -> Result<(), HachiError> {
        if buffer.len() != self.buffer_size {
            return Err(HachiError::InvalidDimension {
                expected: self.buffer_size,
                actual: buffer.len(),
            });
        }
        
        self.in_use.retain(|b| b.as_ptr() != buffer.as_ptr());
        self.available.push(buffer);
        
        Ok(())
    }
    
    /// Get available buffers
    pub fn available_buffers(&self) -> usize {
        self.available.len()
    }
    
    /// Get in-use buffers
    pub fn in_use_buffers(&self) -> usize {
        self.in_use.len()
    }
}

/// Streaming buffer
///
/// Efficient streaming of large data
pub struct StreamingBuffer<F: Field> {
    /// Buffer
    buffer: Vec<F>,
    
    /// Position
    position: usize,
    
    /// Capacity
    capacity: usize,
}

impl<F: Field> StreamingBuffer<F> {
    /// Create new streaming buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![F::zero(); capacity],
            position: 0,
            capacity,
        }
    }
    
    /// Write to buffer
    pub fn write(&mut self, data: &[F]) -> Result<(), HachiError> {
        if self.position + data.len() > self.capacity {
            return Err(HachiError::InvalidParameters(
                "Buffer overflow".to_string()
            ));
        }
        
        for (i, &value) in data.iter().enumerate() {
            self.buffer[self.position + i] = value;
        }
        
        self.position += data.len();
        
        Ok(())
    }
    
    /// Read from buffer
    pub fn read(&self, size: usize) -> Result<Vec<F>, HachiError> {
        if self.position + size > self.capacity {
            return Err(HachiError::InvalidParameters(
                "Buffer underflow".to_string()
            ));
        }
        
        Ok(self.buffer[self.position..self.position + size].to_vec())
    }
    
    /// Reset buffer
    pub fn reset(&mut self) {
        self.position = 0;
    }
    
    /// Get position
    pub fn position(&self) -> usize {
        self.position
    }
}

/// Sparse vector
///
/// Memory-efficient sparse vector representation
#[derive(Clone, Debug)]
pub struct SparseVector<F: Field> {
    /// Non-zero indices
    indices: Vec<usize>,
    
    /// Non-zero values
    values: Vec<F>,
    
    /// Vector size
    size: usize,
}

impl<F: Field> SparseVector<F> {
    /// Create new sparse vector
    pub fn new(size: usize) -> Self {
        Self {
            indices: Vec::new(),
            values: Vec::new(),
            size,
        }
    }
    
    /// Set value
    pub fn set(&mut self, index: usize, value: F) -> Result<(), HachiError> {
        if index >= self.size {
            return Err(HachiError::InvalidParameters(
                format!("Index {} out of bounds", index)
            ));
        }
        
        if let Some(pos) = self.indices.iter().position(|&i| i == index) {
            self.values[pos] = value;
        } else {
            self.indices.push(index);
            self.values.push(value);
        }
        
        Ok(())
    }
    
    /// Get value
    pub fn get(&self, index: usize) -> Result<F, HachiError> {
        if index >= self.size {
            return Err(HachiError::InvalidParameters(
                format!("Index {} out of bounds", index)
            ));
        }
        
        if let Some(pos) = self.indices.iter().position(|&i| i == index) {
            Ok(self.values[pos])
        } else {
            Ok(F::zero())
        }
    }
    
    /// Get sparsity
    pub fn sparsity(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            self.indices.len() as f64 / self.size as f64
        }
    }
    
    /// Get number of non-zeros
    pub fn nnz(&self) -> usize {
        self.indices.len()
    }
}

/// Memory statistics
#[derive(Clone, Debug)]
pub struct MemoryStats {
    /// Peak memory usage (bytes)
    pub peak_memory_bytes: usize,
    
    /// Current memory usage (bytes)
    pub current_memory_bytes: usize,
    
    /// Number of allocations
    pub num_allocations: u64,
    
    /// Number of deallocations
    pub num_deallocations: u64,
}

impl MemoryStats {
    pub fn new() -> Self {
        Self {
            peak_memory_bytes: 0,
            current_memory_bytes: 0,
            num_allocations: 0,
            num_deallocations: 0,
        }
    }
    
    /// Record allocation
    pub fn record_allocation(&mut self, size: usize) {
        self.current_memory_bytes += size;
        self.num_allocations += 1;
        
        if self.current_memory_bytes > self.peak_memory_bytes {
            self.peak_memory_bytes = self.current_memory_bytes;
        }
    }
    
    /// Record deallocation
    pub fn record_deallocation(&mut self, size: usize) {
        if self.current_memory_bytes >= size {
            self.current_memory_bytes -= size;
        }
        self.num_deallocations += 1;
    }
}

/// Memory allocator
///
/// Custom memory allocator for Hachi
pub struct MemoryAllocator<F: Field> {
    /// Memory pool
    pool: MemoryPool<F>,
    
    /// Statistics
    stats: MemoryStats,
}

impl<F: Field> MemoryAllocator<F> {
    /// Create new allocator
    pub fn new(num_buffers: usize, buffer_size: usize) -> Self {
        Self {
            pool: MemoryPool::new(num_buffers, buffer_size),
            stats: MemoryStats::new(),
        }
    }
    
    /// Allocate
    pub fn allocate(&mut self) -> Result<Vec<F>, HachiError> {
        let buffer = self.pool.allocate()?;
        self.stats.record_allocation(buffer.len() * std::mem::size_of::<F>());
        Ok(buffer)
    }
    
    /// Deallocate
    pub fn deallocate(&mut self, buffer: Vec<F>) -> Result<(), HachiError> {
        let size = buffer.len() * std::mem::size_of::<F>();
        self.pool.deallocate(buffer)?;
        self.stats.record_deallocation(size);
        Ok(())
    }
    
    /// Get statistics
    pub fn stats(&self) -> &MemoryStats {
        &self.stats
    }
}

/// Memory-efficient polynomial
///
/// Polynomial with memory optimization
#[derive(Clone, Debug)]
pub struct MemoryEfficientPolynomial<F: Field> {
    /// Coefficients (sparse)
    coefficients: SparseVector<F>,
}

impl<F: Field> MemoryEfficientPolynomial<F> {
    /// Create new polynomial
    pub fn new(degree: usize) -> Self {
        Self {
            coefficients: SparseVector::new(degree + 1),
        }
    }
    
    /// Set coefficient
    pub fn set_coefficient(&mut self, index: usize, value: F) -> Result<(), HachiError> {
        self.coefficients.set(index, value)
    }
    
    /// Get coefficient
    pub fn get_coefficient(&self, index: usize) -> Result<F, HachiError> {
        self.coefficients.get(index)
    }
    
    /// Get sparsity
    pub fn sparsity(&self) -> f64 {
        self.coefficients.sparsity()
    }
}

/// Memory optimization level
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOptimizationLevel {
    /// No optimization
    None,
    
    /// Basic optimization (sparse vectors)
    Basic,
    
    /// Advanced optimization (streaming, pooling)
    Advanced,
    
    /// Maximum optimization (all techniques)
    Maximum,
}

impl MemoryOptimizationLevel {
    /// Should use sparse vectors
    pub fn use_sparse_vectors(&self) -> bool {
        matches!(self, 
            MemoryOptimizationLevel::Basic |
            MemoryOptimizationLevel::Advanced |
            MemoryOptimizationLevel::Maximum
        )
    }
    
    /// Should use streaming
    pub fn use_streaming(&self) -> bool {
        matches!(self,
            MemoryOptimizationLevel::Advanced |
            MemoryOptimizationLevel::Maximum
        )
    }
    
    /// Should use memory pooling
    pub fn use_memory_pooling(&self) -> bool {
        matches!(self,
            MemoryOptimizationLevel::Advanced |
            MemoryOptimizationLevel::Maximum
        )
    }
}
