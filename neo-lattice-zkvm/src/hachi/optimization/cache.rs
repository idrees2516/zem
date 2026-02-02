// Caching strategies for Hachi protocol
//
// Implements various caching strategies to improve performance
// by avoiding redundant computations.

use crate::hachi::errors::HachiError;
use crate::field::Field;
use std::collections::HashMap;

/// Cache entry
#[derive(Clone, Debug)]
pub struct CacheEntry<K, V> {
    /// Key
    pub key: K,
    
    /// Value
    pub value: V,
    
    /// Access count
    pub access_count: u64,
    
    /// Last access time
    pub last_access_time: u64,
}

/// Cache eviction policy
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used
    LRU,
    
    /// Least Frequently Used
    LFU,
    
    /// First In First Out
    FIFO,
    
    /// Random
    Random,
}

/// Generic cache
///
/// Generic caching structure with configurable eviction policy
pub struct Cache<K: Clone + Eq + std::hash::Hash, V: Clone> {
    /// Cache entries
    entries: HashMap<K, CacheEntry<K, V>>,
    
    /// Maximum size
    max_size: usize,
    
    /// Eviction policy
    eviction_policy: EvictionPolicy,
    
    /// Current time
    current_time: u64,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> Cache<K, V> {
    /// Create new cache
    pub fn new(max_size: usize, eviction_policy: EvictionPolicy) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            eviction_policy,
            current_time: 0,
        }
    }
    
    /// Get value from cache
    pub fn get(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.access_count += 1;
            entry.last_access_time = self.current_time;
            self.current_time += 1;
            Some(entry.value.clone())
        } else {
            None
        }
    }
    
    /// Insert value into cache
    pub fn insert(&mut self, key: K, value: V) {
        if self.entries.len() >= self.max_size {
            self.evict();
        }
        
        let entry = CacheEntry {
            key: key.clone(),
            value,
            access_count: 1,
            last_access_time: self.current_time,
        };
        
        self.entries.insert(key, entry);
        self.current_time += 1;
    }
    
    /// Evict entry based on policy
    fn evict(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        
        let key_to_remove = match self.eviction_policy {
            EvictionPolicy::LRU => self.find_lru_key(),
            EvictionPolicy::LFU => self.find_lfu_key(),
            EvictionPolicy::FIFO => self.find_fifo_key(),
            EvictionPolicy::Random => self.find_random_key(),
        };
        
        if let Some(key) = key_to_remove {
            self.entries.remove(&key);
        }
    }
    
    /// Find LRU key
    fn find_lru_key(&self) -> Option<K> {
        self.entries.iter()
            .min_by_key(|(_, entry)| entry.last_access_time)
            .map(|(key, _)| key.clone())
    }
    
    /// Find LFU key
    fn find_lfu_key(&self) -> Option<K> {
        self.entries.iter()
            .min_by_key(|(_, entry)| entry.access_count)
            .map(|(key, _)| key.clone())
    }
    
    /// Find FIFO key
    fn find_fifo_key(&self) -> Option<K> {
        self.entries.iter().next().map(|(key, _)| key.clone())
    }
    
    /// Find random key
    fn find_random_key(&self) -> Option<K> {
        self.entries.keys().next().cloned()
    }
    
    /// Get cache size
    pub fn size(&self) -> usize {
        self.entries.len()
    }
    
    /// Clear cache
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Field element cache
///
/// Cache for field element computations
pub struct FieldElementCache<F: Field> {
    /// Cache
    cache: Cache<Vec<u8>, F>,
}

impl<F: Field> FieldElementCache<F> {
    /// Create new field element cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Cache::new(max_size, EvictionPolicy::LRU),
        }
    }
    
    /// Get cached element
    pub fn get(&mut self, key: &[u8]) -> Option<F> {
        self.cache.get(&key.to_vec())
    }
    
    /// Cache element
    pub fn cache(&mut self, key: &[u8], value: F) {
        self.cache.insert(key.to_vec(), value);
    }
}

/// Polynomial cache
///
/// Cache for polynomial computations
pub struct PolynomialCache<F: Field> {
    /// Cache
    cache: Cache<String, Vec<F>>,
}

impl<F: Field> PolynomialCache<F> {
    /// Create new polynomial cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Cache::new(max_size, EvictionPolicy::LRU),
        }
    }
    
    /// Get cached polynomial
    pub fn get(&mut self, key: &str) -> Option<Vec<F>> {
        self.cache.get(&key.to_string())
    }
    
    /// Cache polynomial
    pub fn cache(&mut self, key: &str, value: Vec<F>) {
        self.cache.insert(key.to_string(), value);
    }
}

/// Commitment cache
///
/// Cache for commitment computations
pub struct CommitmentCache<F: Field> {
    /// Cache
    cache: Cache<String, F>,
}

impl<F: Field> CommitmentCache<F> {
    /// Create new commitment cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Cache::new(max_size, EvictionPolicy::LRU),
        }
    }
    
    /// Get cached commitment
    pub fn get(&mut self, key: &str) -> Option<F> {
        self.cache.get(&key.to_string())
    }
    
    /// Cache commitment
    pub fn cache(&mut self, key: &str, value: F) {
        self.cache.insert(key.to_string(), value);
    }
}

/// Trace map cache
///
/// Cache for trace map computations
pub struct TraceMapCache<F: Field> {
    /// Cache
    cache: Cache<Vec<usize>, F>,
}

impl<F: Field> TraceMapCache<F> {
    /// Create new trace map cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Cache::new(max_size, EvictionPolicy::LRU),
        }
    }
    
    /// Get cached trace
    pub fn get(&mut self, key: &[usize]) -> Option<F> {
        self.cache.get(&key.to_vec())
    }
    
    /// Cache trace
    pub fn cache(&mut self, key: &[usize], value: F) {
        self.cache.insert(key.to_vec(), value);
    }
}

/// Multi-level cache
///
/// Hierarchical caching with multiple levels
pub struct MultiLevelCache<F: Field> {
    /// L1 cache (small, fast)
    l1_cache: Cache<String, F>,
    
    /// L2 cache (larger, slower)
    l2_cache: Cache<String, F>,
    
    /// L3 cache (largest, slowest)
    l3_cache: Cache<String, F>,
}

impl<F: Field> MultiLevelCache<F> {
    /// Create new multi-level cache
    pub fn new(l1_size: usize, l2_size: usize, l3_size: usize) -> Self {
        Self {
            l1_cache: Cache::new(l1_size, EvictionPolicy::LRU),
            l2_cache: Cache::new(l2_size, EvictionPolicy::LRU),
            l3_cache: Cache::new(l3_size, EvictionPolicy::LRU),
        }
    }
    
    /// Get value from cache hierarchy
    pub fn get(&mut self, key: &str) -> Option<F> {
        // Try L1
        if let Some(value) = self.l1_cache.get(&key.to_string()) {
            return Some(value);
        }
        
        // Try L2
        if let Some(value) = self.l2_cache.get(&key.to_string()) {
            self.l1_cache.insert(key.to_string(), value.clone());
            return Some(value);
        }
        
        // Try L3
        if let Some(value) = self.l3_cache.get(&key.to_string()) {
            self.l1_cache.insert(key.to_string(), value.clone());
            return Some(value);
        }
        
        None
    }
    
    /// Insert value into cache hierarchy
    pub fn insert(&mut self, key: &str, value: F) {
        self.l1_cache.insert(key.to_string(), value);
    }
}

/// Cache statistics
#[derive(Clone, Debug)]
pub struct CacheStats {
    /// Number of hits
    pub hits: u64,
    
    /// Number of misses
    pub misses: u64,
    
    /// Total accesses
    pub total_accesses: u64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self {
            hits: 0,
            misses: 0,
            total_accesses: 0,
        }
    }
    
    /// Record hit
    pub fn record_hit(&mut self) {
        self.hits += 1;
        self.total_accesses += 1;
    }
    
    /// Record miss
    pub fn record_miss(&mut self) {
        self.misses += 1;
        self.total_accesses += 1;
    }
    
    /// Get hit rate
    pub fn hit_rate(&self) -> f64 {
        if self.total_accesses == 0 {
            0.0
        } else {
            self.hits as f64 / self.total_accesses as f64
        }
    }
}

/// Cache configuration
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// L1 cache size
    pub l1_size: usize,
    
    /// L2 cache size
    pub l2_size: usize,
    
    /// L3 cache size
    pub l3_size: usize,
    
    /// Eviction policy
    pub eviction_policy: EvictionPolicy,
    
    /// Enable statistics
    pub enable_stats: bool,
}

impl CacheConfig {
    /// Create default configuration
    pub fn default() -> Self {
        Self {
            l1_size: 256,
            l2_size: 1024,
            l3_size: 4096,
            eviction_policy: EvictionPolicy::LRU,
            enable_stats: true,
        }
    }
    
    /// Create aggressive caching configuration
    pub fn aggressive() -> Self {
        Self {
            l1_size: 1024,
            l2_size: 4096,
            l3_size: 16384,
            eviction_policy: EvictionPolicy::LRU,
            enable_stats: true,
        }
    }
}
