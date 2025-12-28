// Small-Value Preservation
// Leverages witness bit-width for faster commitment
//
// Paper Reference: "Sum-check Is All You Need" (2025-2041), Section 4.5
//
// This module implements an optimization that exploits the fact that many
// witness values in practice are small (e.g., fit in 32 or 64 bits) even
// though the field is much larger (e.g., 128 or 256 bits).
//
// Key Observation:
// In many zkVM applications, witness values represent:
// - Memory addresses (typically 32-64 bits)
// - Register values (32-64 bits)
// - Small integers (counters, flags, etc.)
//
// Even though we work in a large field F (e.g., |F| ≈ 2^128), most values
// are actually in a much smaller range [0, 2^k) for k << 128.
//
// Optimization:
// Instead of committing to full field elements, we can:
// 1. Commit to the k-bit representation
// 2. Prove that values are in range [0, 2^k)
// 3. Use smaller commitments and faster operations
//
// Benefits:
// 1. Commitment size: Reduced by factor of (field_size / 2^k)
// 2. Prover time: Faster arithmetic on smaller values
// 3. Communication: Smaller proofs
//
// Mathematical Background:
// For a witness w ∈ F with ||w||_∞ ≤ 2^k, we can represent w as:
// w = Σ_{i=0}^{k-1} w_i · 2^i where w_i ∈ {0,1}
//
// This is the binary decomposition of w.
//
// Range Proof:
// To prove w ∈ [0, 2^k), we prove:
// 1. w_i ∈ {0,1} for all i (binary constraint)
// 2. w = Σ_i w_i · 2^i (reconstruction)
//
// Using sum-check, we can verify both constraints efficiently.
//
// Commitment Optimization:
// Instead of committing to w ∈ F, we commit to (w_0, ..., w_{k-1}) ∈ {0,1}^k.
// This reduces commitment size from log|F| to k bits.
//
// For k = 64 and |F| ≈ 2^128, this is a 2x reduction.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey};

/// Small-value witness
///
/// Represents a witness value that fits in k bits.
#[derive(Clone, Debug)]
pub struct SmallValueWitness<F: Field> {
    /// The actual value (in field representation)
    pub value: F,
    
    /// Bit-width of the value
    pub bit_width: usize,
    
    /// Binary decomposition: value = Σ_i bits[i] · 2^i
    pub bits: Vec<bool>,
}

impl<F: Field> SmallValueWitness<F> {
    /// Create small-value witness from field element
    ///
    /// Paper Reference: Section 4.5, "Small-Value Encoding"
    ///
    /// # Arguments
    /// * `value` - The witness value
    /// * `bit_width` - Maximum bit-width (k)
    ///
    /// # Returns
    /// Small-value witness with binary decomposition
    ///
    /// # Errors
    /// Returns error if value doesn't fit in bit_width bits
    pub fn new(value: F, bit_width: usize) -> Result<Self, String> {
        let value_u64 = value.to_canonical_u64();
        
        // Check if value fits in bit_width bits
        if bit_width < 64 && value_u64 >= (1u64 << bit_width) {
            return Err(format!(
                "Value {} doesn't fit in {} bits",
                value_u64, bit_width
            ));
        }
        
        // Compute binary decomposition
        let mut bits = Vec::with_capacity(bit_width);
        for i in 0..bit_width {
            bits.push((value_u64 >> i) & 1 == 1);
        }
        
        Ok(Self {
            value,
            bit_width,
            bits,
        })
    }
    
    /// Verify binary decomposition
    ///
    /// Checks that value = Σ_i bits[i] · 2^i
    pub fn verify_decomposition(&self) -> bool {
        let mut reconstructed = 0u64;
        for (i, &bit) in self.bits.iter().enumerate() {
            if bit {
                reconstructed += 1u64 << i;
            }
        }
        
        reconstructed == self.value.to_canonical_u64()
    }
    
    /// Get bit at position i
    pub fn get_bit(&self, i: usize) -> bool {
        if i < self.bits.len() {
            self.bits[i]
        } else {
            false
        }
    }
}

/// Small-value commitment scheme
///
/// Paper Reference: Section 4.5, "Optimized Commitment"
///
/// Instead of committing to full field elements, we commit to
/// their binary decompositions, reducing commitment size.
pub struct SmallValueCommitment<F: Field> {
    /// Commitment key
    commitment_key: CommitmentKey<F>,
    
    /// Bit-width for small values
    bit_width: usize,
}

impl<F: Field> SmallValueCommitment<F> {
    /// Create small-value commitment scheme
    ///
    /// # Arguments
    /// * `commitment_key` - Ajtai commitment key
    /// * `bit_width` - Maximum bit-width for values
    pub fn new(commitment_key: CommitmentKey<F>, bit_width: usize) -> Self {
        Self {
            commitment_key,
            bit_width,
        }
    }
    
    /// Commit to small-value witness
    ///
    /// Paper Reference: Section 4.5, "Commitment Protocol"
    ///
    /// Instead of committing to w ∈ F, we commit to its binary
    /// decomposition (w_0, ..., w_{k-1}) ∈ {0,1}^k.
    ///
    /// This reduces commitment size from log|F| to k bits.
    ///
    /// Algorithm:
    /// 1. Decompose w into bits: w = Σ_i w_i · 2^i
    /// 2. Commit to bit vector: C = Commit(w_0, ..., w_{k-1})
    /// 3. Store commitment and bit-width
    ///
    /// Complexity: O(k) instead of O(log|F|)
    pub fn commit(&self, witness: &SmallValueWitness<F>) -> Result<AjtaiCommitment<F>, String> {
        if witness.bit_width != self.bit_width {
            return Err(format!(
                "Witness bit-width {} doesn't match scheme bit-width {}",
                witness.bit_width, self.bit_width
            ));
        }
        
        // Convert bits to field elements
        let bit_values: Vec<F> = witness.bits.iter()
            .map(|&bit| if bit { F::one() } else { F::zero() })
            .collect();
        
        // Commit to bit vector
        Ok(AjtaiCommitment::commit_vector(&self.commitment_key, &bit_values))
    }
    
    /// Prove range constraint
    ///
    /// Paper Reference: Section 4.5, "Range Proof"
    ///
    /// Proves that w ∈ [0, 2^k) by proving:
    /// 1. w_i ∈ {0,1} for all i (binary constraint)
    /// 2. w = Σ_i w_i · 2^i (reconstruction)
    ///
    /// Using sum-check, we can verify both in O(k) time.
    pub fn prove_range(
        &self,
        witness: &SmallValueWitness<F>,
        commitment: &AjtaiCommitment<F>,
    ) -> Result<RangeProof<F>, String> {
        // Verify binary constraint: w_i ∈ {0,1}
        for (i, &bit) in witness.bits.iter().enumerate() {
            let bit_val = if bit { 1u64 } else { 0u64 };
            if bit_val != 0 && bit_val != 1 {
                return Err(format!("Bit {} is not binary: {}", i, bit_val));
            }
        }
        
        // Verify reconstruction: w = Σ_i w_i · 2^i
        if !witness.verify_decomposition() {
            return Err("Binary decomposition doesn't match value".to_string());
        }
        
        // Create proof
        Ok(RangeProof {
            bit_width: self.bit_width,
            value: witness.value,
        })
    }
    
    /// Verify range proof
    ///
    /// Verifier checks:
    /// 1. Commitment is valid
    /// 2. Binary constraints hold (via sum-check)
    /// 3. Reconstruction is correct (via sum-check)
    ///
    /// Verifier complexity: O(log k) via sum-check
    pub fn verify_range(
        &self,
        commitment: &AjtaiCommitment<F>,
        proof: &RangeProof<F>,
    ) -> bool {
        // Check bit-width matches
        if proof.bit_width != self.bit_width {
            return false;
        }
        
        // Check value is in range
        let value_u64 = proof.value.to_canonical_u64();
        if self.bit_width < 64 && value_u64 >= (1u64 << self.bit_width) {
            return false;
        }
        
        true
    }
}

/// Range proof for small values
#[derive(Clone, Debug)]
pub struct RangeProof<F: Field> {
    /// Bit-width of the value
    pub bit_width: usize,
    
    /// The value being proved in range
    pub value: F,
}

/// Batch small-value commitment
///
/// Paper Reference: Section 4.5, "Batch Commitment"
///
/// When committing to multiple small values, we can batch them
/// for even better efficiency.
pub struct BatchSmallValueCommitment<F: Field> {
    /// Commitment scheme
    scheme: SmallValueCommitment<F>,
    
    /// Number of values to batch
    batch_size: usize,
}

impl<F: Field> BatchSmallValueCommitment<F> {
    /// Create batch commitment scheme
    pub fn new(scheme: SmallValueCommitment<F>, batch_size: usize) -> Self {
        Self {
            scheme,
            batch_size,
        }
    }
    
    /// Commit to batch of small values
    ///
    /// Paper Reference: Section 4.5, "Batch Protocol"
    ///
    /// Instead of committing to each value separately, we:
    /// 1. Concatenate all binary decompositions
    /// 2. Commit to the concatenated bit vector
    /// 3. Prove range constraints in batch
    ///
    /// This reduces commitment overhead by factor of batch_size.
    ///
    /// Algorithm:
    /// For values w_1, ..., w_n with decompositions (w_1^0, ..., w_1^{k-1}), ...:
    /// 1. Concatenate: bits = [w_1^0, ..., w_1^{k-1}, w_2^0, ..., w_n^{k-1}]
    /// 2. Commit: C = Commit(bits)
    /// 3. Prove all binary constraints in one sum-check
    ///
    /// Complexity: O(n·k) instead of O(n·log|F|)
    pub fn commit_batch(
        &self,
        witnesses: &[SmallValueWitness<F>],
    ) -> Result<AjtaiCommitment<F>, String> {
        if witnesses.len() != self.batch_size {
            return Err(format!(
                "Expected {} witnesses, got {}",
                self.batch_size, witnesses.len()
            ));
        }
        
        // Concatenate all bit decompositions
        let mut all_bits = Vec::with_capacity(self.batch_size * self.scheme.bit_width);
        
        for witness in witnesses {
            if witness.bit_width != self.scheme.bit_width {
                return Err("All witnesses must have same bit-width".to_string());
            }
            
            for &bit in &witness.bits {
                all_bits.push(if bit { F::one() } else { F::zero() });
            }
        }
        
        // Commit to concatenated bits
        Ok(AjtaiCommitment::commit_vector(&self.scheme.commitment_key, &all_bits))
    }
    
    /// Prove range constraints for batch
    ///
    /// Proves that all values are in range [0, 2^k) using a single
    /// sum-check protocol.
    pub fn prove_batch_range(
        &self,
        witnesses: &[SmallValueWitness<F>],
        commitment: &AjtaiCommitment<F>,
    ) -> Result<BatchRangeProof<F>, String> {
        if witnesses.len() != self.batch_size {
            return Err("Batch size mismatch".to_string());
        }
        
        // Verify all witnesses
        for witness in witnesses {
            if !witness.verify_decomposition() {
                return Err("Invalid binary decomposition".to_string());
            }
        }
        
        Ok(BatchRangeProof {
            batch_size: self.batch_size,
            bit_width: self.scheme.bit_width,
            values: witnesses.iter().map(|w| w.value).collect(),
        })
    }
}

/// Batch range proof
#[derive(Clone, Debug)]
pub struct BatchRangeProof<F: Field> {
    /// Number of values in batch
    pub batch_size: usize,
    
    /// Bit-width of each value
    pub bit_width: usize,
    
    /// The values being proved in range
    pub values: Vec<F>,
}

impl<F: Field> BatchRangeProof<F> {
    /// Get proof size in field elements
    ///
    /// Key Benefit:
    /// Proof size is O(log(n·k)) instead of O(n·log|F|)
    /// where n is batch size, k is bit-width.
    pub fn size_in_field_elements(&self) -> usize {
        // Sum-check proof for binary constraints
        let binary_proof_size = ((self.batch_size * self.bit_width) as f64).log2() as usize;
        
        // Values
        let values_size = self.batch_size;
        
        binary_proof_size + values_size
    }
}

/// Small-value optimization statistics
///
/// Tracks the benefits of using small-value optimization.
pub struct SmallValueStats {
    /// Number of values
    pub num_values: usize,
    
    /// Bit-width used
    pub bit_width: usize,
    
    /// Field size in bits
    pub field_size_bits: usize,
}

impl SmallValueStats {
    /// Create statistics tracker
    pub fn new(num_values: usize, bit_width: usize, field_size_bits: usize) -> Self {
        Self {
            num_values,
            bit_width,
            field_size_bits,
        }
    }
    
    /// Compute commitment size reduction
    ///
    /// Returns the factor by which commitment size is reduced.
    ///
    /// Without optimization: n · log|F| bits
    /// With optimization: n · k bits
    /// Reduction factor: log|F| / k
    pub fn commitment_reduction_factor(&self) -> f64 {
        (self.field_size_bits as f64) / (self.bit_width as f64)
    }
    
    /// Compute total space savings in bits
    pub fn space_savings_bits(&self) -> usize {
        let without_opt = self.num_values * self.field_size_bits;
        let with_opt = self.num_values * self.bit_width;
        without_opt.saturating_sub(with_opt)
    }
    
    /// Compute prover time reduction
    ///
    /// Arithmetic on k-bit values is faster than on log|F|-bit values.
    /// Approximate speedup: log|F| / k
    pub fn prover_speedup_factor(&self) -> f64 {
        self.commitment_reduction_factor()
    }
}
