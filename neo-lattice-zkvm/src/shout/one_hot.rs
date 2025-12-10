// Task 2.1: One-Hot Address Encoding with Tensor Decomposition
// 
// OVERVIEW:
// One-hot encoding represents a memory address as a unit vector where exactly one position
// is 1 and all others are 0. This is crucial for the Shout protocol because it allows us to
// express memory lookups as linear combinations, enabling efficient sum-check proofs.
//
// TENSOR DECOMPOSITION:
// Instead of committing to a full K-length one-hot vector (expensive for large K), we use
// tensor product decomposition to break the address into d chunks of size K^{1/d} each.
// This reduces commitment costs from K to d·K^{1/d}.
//
// EXAMPLE: For K=1024, d=2:
// - Full encoding: 1024 values (1023 zeros, 1 one)
// - Tensor encoding: 2 chunks of 32 values each = 64 total values
// - Savings: 16x reduction in commitment size
//
// REFERENCE: "Lasso and Jolt" paper, Section 4.2 on one-hot encodings

use crate::field::extension_framework::ExtensionFieldElement;
use std::fmt::Debug;

/// One-hot address encoding with d-dimensional tensor decomposition
/// 
/// MATHEMATICAL REPRESENTATION:
/// An address k ∈ [0, K) is decomposed as k = k_1 + k_2·K^{1/d} + ... + k_d·K^{(d-1)/d}
/// Each k_i ∈ [0, K^{1/d}) is encoded as a one-hot vector of length K^{1/d}
/// The full one-hot vector is the tensor product: chunks[0] ⊗ chunks[1] ⊗ ... ⊗ chunks[d-1]
///
/// COMMITMENT COST ANALYSIS:
/// - Without decomposition: K field elements (mostly zeros)
/// - With decomposition: d·K^{1/d} field elements
/// - For K=2^20, d=4: 4·2^5 = 128 vs 2^20 = 1,048,576 (8192x reduction!)
#[derive(Clone, Debug)]
pub struct OneHotAddress<K: ExtensionFieldElement> {
    /// Number of dimensions in tensor decomposition
    /// Chosen based on memory size K:
    /// - d=1 for K ≤ 2^16 (small tables, no decomposition needed)
    /// - d=2 for K ≤ 2^20 (medium tables, √K chunks)
    /// - d=4 for K ≤ 2^30 (large tables, K^{1/4} chunks)
    /// - d=8 for K > 2^30 (gigantic tables, K^{1/8} chunks)
    pub d: usize,
    
    /// Size of each chunk: K^{1/d}
    /// All chunks have the same size for uniform tensor structure
    pub chunk_size: usize,
    
    /// d one-hot vectors, each of length chunk_size
    /// chunks[i][j] = 1 if j is the i-th digit of the address in base chunk_size
    /// chunks[i][j] = 0 otherwise
    pub chunks: Vec<Vec<K>>,
}

impl<K: ExtensionFieldElement> OneHotAddress<K> {
    /// Encode an address into d-dimensional one-hot representation
    /// 
    /// ALGORITHM:
    /// 1. Compute chunk_size = ⌈K^{1/d}⌉ (ceiling to handle non-perfect powers)
    /// 2. For each dimension i from 0 to d-1:
    ///    a. Extract digit: digit_i = (address / chunk_size^i) % chunk_size
    ///    b. Create one-hot vector: chunks[i][digit_i] = 1, rest = 0
    /// 3. Verify: address = Σ_i digit_i · chunk_size^i
    ///
    /// COMPLEXITY: O(d·K^{1/d}) space, O(d) time
    ///
    /// EXAMPLE: encode(42, K=1024, d=2)
    /// - chunk_size = 32
    /// - digit_0 = 42 % 32 = 10
    /// - digit_1 = (42 / 32) % 32 = 1
    /// - chunks[0] = [0,0,0,0,0,0,0,0,0,0,1,0,...,0] (1 at position 10)
    /// - chunks[1] = [0,1,0,0,...,0] (1 at position 1)
    /// - Verification: 10 + 1·32 = 42 ✓
    pub fn encode(address: usize, memory_size: usize, d: usize) -> Result<Self, String> {
        if d == 0 {
            return Err("Dimension d must be at least 1".to_string());
        }
        
        if address >= memory_size {
            return Err(format!(
                "Address {} out of bounds for memory size {}",
                address, memory_size
            ));
        }
        
        // Compute chunk size: K^{1/d}
        // We use ceiling to handle cases where K is not a perfect d-th power
        let chunk_size = ((memory_size as f64).powf(1.0 / d as f64).ceil()) as usize;
        
        let mut chunks = Vec::with_capacity(d);
        let mut remaining_address = address;
        
        // Extract each digit in base chunk_size
        for dim in 0..d {
            let digit = remaining_address % chunk_size;
            
            // Create one-hot vector for this digit
            let mut one_hot = vec![K::zero(); chunk_size];
            one_hot[digit] = K::one();
            
            chunks.push(one_hot);
            remaining_address /= chunk_size;
        }
        
        Ok(Self {
            d,
            chunk_size,
            chunks,
        })
    }
    
    /// Verify that this is a valid one-hot encoding
    /// 
    /// VERIFICATION CHECKS:
    /// 1. Each chunk sums to exactly 1: Σ_k chunks[i][k] = 1
    /// 2. Each element is Boolean: chunks[i][k] ∈ {0, 1}
    ///
    /// These properties are crucial for the Shout protocol's correctness:
    /// - Sum = 1 ensures exactly one position is selected
    /// - Boolean values ensure no fractional selections
    ///
    /// REFERENCE: Requirement 11A.2 - one-hot property verification
    pub fn verify_one_hot(&self) -> bool {
        for chunk in &self.chunks {
            // Check sum equals 1
            let sum: K = chunk.iter().copied().fold(K::zero(), |acc, x| acc.add(&x));
            if sum != K::one() {
                return false;
            }
            
            // Check all elements are Boolean (0 or 1)
            for &elem in chunk {
                if elem != K::zero() && elem != K::one() {
                    return false;
                }
            }
        }
        true
    }
    
    /// Compute full K-length one-hot vector via tensor product
    /// 
    /// TENSOR PRODUCT ALGORITHM:
    /// The full vector is computed as: chunks[0] ⊗ chunks[1] ⊗ ... ⊗ chunks[d-1]
    /// 
    /// For two vectors a, b, the tensor product a ⊗ b is:
    /// (a ⊗ b)[i·|b| + j] = a[i] · b[j]
    ///
    /// ITERATIVE COMPUTATION:
    /// 1. Start with result = [1]
    /// 2. For each chunk c:
    ///    result_new = []
    ///    for each r in result:
    ///      for each c_elem in c:
    ///        result_new.append(r · c_elem)
    ///    result = result_new
    ///
    /// COMPLEXITY: O(K) time and space (unavoidable for full vector)
    ///
    /// USAGE: This is primarily for verification and testing. In the actual protocol,
    /// we never materialize the full vector - we work with the chunked representation.
    ///
    /// REFERENCE: Requirement 11A.3 - tensor product reconstruction
    pub fn to_full_vector(&self, memory_size: usize) -> Vec<K> {
        // Start with scalar 1
        let mut result = vec![K::one()];
        
        // Iteratively compute tensor products
        for chunk in &self.chunks {
            let mut new_result = Vec::with_capacity(result.len() * chunk.len());
            
            // For each element in current result
            for &r in &result {
                // Tensor with each element in chunk
                for &c in chunk {
                    new_result.push(r.mul(&c));
                }
            }
            
            result = new_result;
        }
        
        // Truncate to memory size (handles non-perfect powers)
        result.truncate(memory_size);
        result
    }
    
    /// Get the original address from the one-hot encoding
    /// 
    /// DECODING ALGORITHM:
    /// For each chunk i, find position j where chunks[i][j] = 1
    /// Reconstruct: address = Σ_i j_i · chunk_size^i
    ///
    /// This is the inverse of the encode operation.
    pub fn decode(&self) -> Result<usize, String> {
        let mut address = 0;
        let mut multiplier = 1;
        
        for (dim, chunk) in self.chunks.iter().enumerate() {
            // Find the position of the 1
            let mut digit = None;
            for (pos, &val) in chunk.iter().enumerate() {
                if val == K::one() {
                    if digit.is_some() {
                        return Err(format!(
                            "Multiple 1s found in chunk {} (not one-hot)",
                            dim
                        ));
                    }
                    digit = Some(pos);
                }
            }
            
            let digit = digit.ok_or_else(|| {
                format!("No 1 found in chunk {} (not one-hot)", dim)
            })?;
            
            address += digit * multiplier;
            multiplier *= self.chunk_size;
        }
        
        Ok(address)
    }
    
    /// Get commitment cost in field elements
    /// 
    /// COST ANALYSIS:
    /// - Total elements to commit: d · chunk_size = d · K^{1/d}
    /// - With elliptic curve commitments, zeros are "free" (identity element)
    /// - Only pay for the d ones (one per chunk)
    /// - Actual cost: d group operations for commitment
    ///
    /// COMPARISON:
    /// | K      | d | chunk_size | Total elements | Ones | Savings    |
    /// |--------|---|------------|----------------|------|------------|
    /// | 32     | 1 | 32         | 32             | 1    | 1x         |
    /// | 1024   | 2 | 32         | 64             | 2    | 16x        |
    /// | 2^20   | 4 | 32         | 128            | 4    | 8192x      |
    /// | 2^30   | 8 | 16         | 128            | 8    | 8388608x   |
    ///
    /// REFERENCE: Requirement 11A.16 - commitment cost optimization
    pub fn commitment_cost(&self) -> usize {
        self.d * self.chunk_size
    }
    
    /// Get number of non-zero elements (always d for valid one-hot)
    pub fn num_ones(&self) -> usize {
        self.d
    }
}

/// Trait for one-hot encoding strategies
/// 
/// This abstraction allows different encoding strategies for different scenarios:
/// - Standard one-hot for small memory
/// - Tensor decomposition for large memory
/// - Hierarchical encoding for very large memory
pub trait OneHotEncoding<K: ExtensionFieldElement> {
    /// Encode an address
    fn encode(&self, address: usize) -> Result<OneHotAddress<K>, String>;
    
    /// Get memory size
    fn memory_size(&self) -> usize;
    
    /// Get dimension parameter
    fn dimension(&self) -> usize;
    
    /// Compute optimal dimension for given memory size
    /// 
    /// HEURISTIC:
    /// - K ≤ 2^16: d=1 (no decomposition, direct encoding)
    /// - K ≤ 2^20: d=2 (square root decomposition)
    /// - K ≤ 2^30: d=4 (fourth root decomposition)
    /// - K > 2^30: d=8 (eighth root decomposition)
    ///
    /// RATIONALE:
    /// - Smaller d: fewer sum-check rounds, simpler protocol
    /// - Larger d: smaller commitment keys, less memory
    /// - Trade-off point: d·K^{1/d} minimized around d = ln(K)
    ///
    /// REFERENCE: Requirement 9.28-9.31 - parameter selection
    fn optimal_dimension(memory_size: usize) -> usize {
        if memory_size <= (1 << 16) {
            1
        } else if memory_size <= (1 << 20) {
            2
        } else if memory_size <= (1 << 30) {
            4
        } else {
            8
        }
    }
}

/// Standard one-hot encoding configuration
pub struct StandardOneHotEncoding {
    pub memory_size: usize,
    pub dimension: usize,
}

impl StandardOneHotEncoding {
    pub fn new(memory_size: usize) -> Self {
        let dimension = Self::optimal_dimension_for_size(memory_size);
        Self {
            memory_size,
            dimension,
        }
    }
    
    pub fn with_dimension(memory_size: usize, dimension: usize) -> Self {
        Self {
            memory_size,
            dimension,
        }
    }
    
    fn optimal_dimension_for_size(memory_size: usize) -> usize {
        if memory_size <= (1 << 16) {
            1
        } else if memory_size <= (1 << 20) {
            2
        } else if memory_size <= (1 << 30) {
            4
        } else {
            8
        }
    }
}

impl<K: ExtensionFieldElement> OneHotEncoding<K> for StandardOneHotEncoding {
    fn encode(&self, address: usize) -> Result<OneHotAddress<K>, String> {
        OneHotAddress::encode(address, self.memory_size, self.dimension)
    }
    
    fn memory_size(&self) -> usize {
        self.memory_size
    }
    
    fn dimension(&self) -> usize {
        self.dimension
    }
}

// ============================================================================
// DETAILED EXPLANATION OF KEY CONCEPTS
// ============================================================================

// 1. WHY ONE-HOT ENCODING?
//    
//    In the Shout protocol, we need to prove that rv(j) = f(address[j]) for many j.
//    One-hot encoding allows us to express this as:
//    
//    rv(j) = Σ_k ra(k,j) · f(k)
//    
//    where ra(k,j) is the one-hot encoding of address[j]. Since ra(k,j) = 1 only
//    when k = address[j], this sum picks out exactly f(address[j]).
//
// 2. WHY TENSOR DECOMPOSITION?
//    
//    For large K, committing to K-length vectors is expensive. Tensor decomposition
//    exploits the structure: instead of committing to one K-length vector, we commit
//    to d vectors of length K^{1/d}.
//    
//    The key insight: the tensor product structure is preserved under multilinear
//    extension, so we can work with the decomposed form throughout the protocol.
//
// 3. COMMITMENT COST WITH ELLIPTIC CURVES
//    
//    With Pedersen commitments over elliptic curves:
//    - Committing to 0: add identity element (free)
//    - Committing to 1: add generator point (one group operation)
//    - Committing to x: scalar multiplication (expensive)
//    
//    One-hot vectors are optimal: mostly zeros (free) with few ones (cheap).
//
// 4. MULTILINEAR EXTENSION OF ONE-HOT
//    
//    The MLE of a one-hot vector at position k is:
//    ˜ra(r) = Π_i ((1-r_i)(1-k_i) + r_i·k_i)
//    
//    For tensor product: ˜ra(r_1,...,r_d) = Π_ℓ ˜ra_ℓ(r_ℓ)
//    
//    This factorization is crucial for efficient sum-check.
//
// 5. PARAMETER SELECTION TRADE-OFFS
//    
//    Choosing d involves trade-offs:
//    - Commitment key size: d·K^{1/d} (want small)
//    - Number of sum-check rounds: log(K) (independent of d)
//    - Prover time per round: O(K^{1/d}) (want small)
//    - Verifier time: O(d) evaluations (want small)
//    
//    Optimal d ≈ ln(K) minimizes d·K^{1/d}, but practical considerations
//    (round complexity, implementation simplicity) favor smaller d.

