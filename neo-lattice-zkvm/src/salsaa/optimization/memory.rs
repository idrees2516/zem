// Memory-Efficient Witness Storage
//
// This module provides memory-efficient storage strategies for large witnesses:
// - In-memory: Standard Vec storage for small witnesses
// - Memory-mapped: File-backed storage for large witnesses (> 100MB)
// - Streaming: On-demand loading for very large witnesses
// - Arena allocation: Efficient temporary allocations

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use memmap2::{Mmap, MmapMut};
use crate::ring::cyclotomic::RingElement;
use crate::salsaa::matrix::Matrix;

/// Storage strategy for witnesses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageStrategy {
    /// In-memory storage (default for < 100MB)
    InMemory,
    /// Memory-mapped file storage (for 100MB - 10GB)
    MemoryMapped,
    /// Streaming storage (for > 10GB)
    Streaming,
}

impl StorageStrategy {
    /// Choose strategy based on witness size
    pub fn for_size(size_bytes: usize) -> Self {
        const MB_100: usize = 100 * 1024 * 1024;
        const GB_10: usize = 10 * 1024 * 1024 * 1024;
        
        if size_bytes < MB_100 {
            StorageStrategy::InMemory
        } else if size_bytes < GB_10 {
            StorageStrategy::MemoryMapped
        } else {
            StorageStrategy::Streaming
        }
    }
}

/// Witness storage with multiple backend strategies
pub enum WitnessStorage {
    /// In-memory storage
    InMemory(Vec<i64>),
    
    /// Memory-mapped file storage
    MemoryMapped {
        file: File,
        mmap: Mmap,
        size: usize,
    },
    
    /// Streaming storage
    Streaming {
        file: File,
        chunk_size: usize,
        total_size: usize,
    },
}

impl WitnessStorage {
    /// Create new witness storage
    pub fn new(size: usize, strategy: StorageStrategy) -> io::Result<Self> {
        match strategy {
            StorageStrategy::InMemory => {
                Ok(WitnessStorage::InMemory(vec![0; size]))
            }
            
            StorageStrategy::MemoryMapped => {
                let temp_path = Self::temp_file_path();
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(&temp_path)?;
                
                // Set file size
                file.set_len((size * 8) as u64)?;
                
                // Create memory map
                let mmap = unsafe { Mmap::map(&file)? };
                
                Ok(WitnessStorage::MemoryMapped {
                    file,
                    mmap,
                    size,
                })
            }
            
            StorageStrategy::Streaming => {
                let temp_path = Self::temp_file_path();
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(&temp_path)?;
                
                file.set_len((size * 8) as u64)?;
                
                Ok(WitnessStorage::Streaming {
                    file,
                    chunk_size: 1024 * 1024, // 1MB chunks
                    total_size: size,
                })
            }
        }
    }
    
    /// Generate temporary file path
    fn temp_file_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("salsaa_witness_{}.tmp", std::process::id()));
        path
    }
    
    /// Read element at index
    pub fn read(&self, index: usize) -> io::Result<i64> {
        match self {
            WitnessStorage::InMemory(data) => {
                Ok(data.get(index).copied().unwrap_or(0))
            }
            
            WitnessStorage::MemoryMapped { mmap, size, .. } => {
                if index >= *size {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Index out of bounds"));
                }
                
                let offset = index * 8;
                let bytes = &mmap[offset..offset + 8];
                Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
            }
            
            WitnessStorage::Streaming { file, .. } => {
                let mut file = file.try_clone()?;
                file.seek(SeekFrom::Start((index * 8) as u64))?;
                
                let mut bytes = [0u8; 8];
                file.read_exact(&mut bytes)?;
                Ok(i64::from_le_bytes(bytes))
            }
        }
    }
    
    /// Write element at index
    pub fn write(&mut self, index: usize, value: i64) -> io::Result<()> {
        match self {
            WitnessStorage::InMemory(data) => {
                if index < data.len() {
                    data[index] = value;
                }
                Ok(())
            }
            
            WitnessStorage::MemoryMapped { file, size, .. } => {
                if index >= *size {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Index out of bounds"));
                }
                
                // Recreate mutable map for writing
                let mut mmap = unsafe { MmapMut::map_mut(file)? };
                let offset = index * 8;
                mmap[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                Ok(())
            }
            
            WitnessStorage::Streaming { file, .. } => {
                let mut file = file.try_clone()?;
                file.seek(SeekFrom::Start((index * 8) as u64))?;
                file.write_all(&value.to_le_bytes())?;
                Ok(())
            }
        }
    }
    
    /// Read range of elements
    pub fn read_range(&self, start: usize, count: usize) -> io::Result<Vec<i64>> {
        let mut result = Vec::with_capacity(count);
        for i in start..start + count {
            result.push(self.read(i)?);
        }
        Ok(result)
    }
    
    /// Get storage size
    pub fn size(&self) -> usize {
        match self {
            WitnessStorage::InMemory(data) => data.len(),
            WitnessStorage::MemoryMapped { size, .. } => *size,
            WitnessStorage::Streaming { total_size, .. } => *total_size,
        }
    }
}

/// Arena allocator for temporary ring elements
///
/// Provides fast allocation/deallocation for temporary computations
pub struct RingArena {
    /// Pre-allocated buffer
    buffer: Vec<i64>,
    
    /// Current allocation offset
    offset: usize,
    
    /// Capacity
    capacity: usize,
}

impl RingArena {
    /// Create new arena with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0; capacity],
            offset: 0,
            capacity,
        }
    }
    
    /// Allocate space for n elements
    pub fn alloc(&mut self, n: usize) -> Option<&mut [i64]> {
        if self.offset + n > self.capacity {
            return None;
        }
        
        let start = self.offset;
        self.offset += n;
        Some(&mut self.buffer[start..self.offset])
    }
    
    /// Reset arena (invalidates all previous allocations)
    pub fn reset(&mut self) {
        self.offset = 0;
    }
    
    /// Get current usage
    pub fn usage(&self) -> usize {
        self.offset
    }
    
    /// Get available space
    pub fn available(&self) -> usize {
        self.capacity - self.offset
    }
}

/// Memory pool for matrix operations
pub struct MatrixMemoryPool {
    /// Pool of pre-allocated matrices
    pool: Vec<Matrix>,
    
    /// Available matrices
    available: Vec<usize>,
}

impl MatrixMemoryPool {
    /// Create new memory pool
    pub fn new(count: usize, rows: usize, cols: usize, ring: std::sync::Arc<crate::ring::cyclotomic::CyclotomicRing>) -> Self {
        let mut pool = Vec::with_capacity(count);
        let mut available = Vec::with_capacity(count);
        
        for i in 0..count {
            pool.push(Matrix::zero(rows, cols, ring.clone()));
            available.push(i);
        }
        
        Self { pool, available }
    }
    
    /// Acquire a matrix from the pool
    pub fn acquire(&mut self) -> Option<&mut Matrix> {
        self.available.pop().map(|idx| &mut self.pool[idx])
    }
    
    /// Release a matrix back to the pool
    pub fn release(&mut self, matrix: &Matrix) {
        // Find matrix index and mark as available
        for (idx, m) in self.pool.iter().enumerate() {
            if std::ptr::eq(m, matrix) {
                self.available.push(idx);
                break;
            }
        }
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.pool.len(), self.available.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_strategy_selection() {
        assert_eq!(StorageStrategy::for_size(1024), StorageStrategy::InMemory);
        assert_eq!(StorageStrategy::for_size(200 * 1024 * 1024), StorageStrategy::MemoryMapped);
    }
    
    #[test]
    fn test_in_memory_storage() {
        let mut storage = WitnessStorage::new(100, StorageStrategy::InMemory).unwrap();
        
        storage.write(0, 42).unwrap();
        storage.write(50, 123).unwrap();
        
        assert_eq!(storage.read(0).unwrap(), 42);
        assert_eq!(storage.read(50).unwrap(), 123);
    }
    
    #[test]
    fn test_ring_arena() {
        let mut arena = RingArena::new(1000);
        
        let slice1 = arena.alloc(100).unwrap();
        assert_eq!(slice1.len(), 100);
        
        let slice2 = arena.alloc(200).unwrap();
        assert_eq!(slice2.len(), 200);
        
        assert_eq!(arena.usage(), 300);
        assert_eq!(arena.available(), 700);
        
        arena.reset();
        assert_eq!(arena.usage(), 0);
    }
}
