// Matrix commitment scheme with pay-per-bit costs
// Maps field vectors to ring vectors via coefficient packing

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use super::ajtai::{AjtaiCommitmentScheme, Commitment, CommitmentError};

/// Matrix commitment scheme with pay-per-bit optimization
pub struct MatrixCommitmentScheme<F: Field> {
    pub ajtai: AjtaiCommitmentScheme<F>,
    pub packing_degree: usize,  // d = ring degree
}

/// Vector commitment with bit-width tracking
#[derive(Clone, Debug)]
pub struct VectorCommitment<F: Field> {
    pub commitment: Commitment<F>,
    pub original_length: usize,
    pub bit_widths: Vec<usize>,
}

impl<F: Field> MatrixCommitmentScheme<F> {
    /// Create new matrix commitment scheme
    pub fn new(ring: CyclotomicRing<F>, kappa: usize, norm_bound: u64, seed: [u8; 32]) -> Self {
        let packing_degree = ring.degree;
        
        // Initial m=1, will be updated based on vector length
        let ajtai = AjtaiCommitmentScheme::setup(ring, kappa, 1, norm_bound, seed);
        
        Self {
            ajtai,
            packing_degree,
        }
    }
    
    /// Commit to field vector f ∈ F_q^N with pay-per-bit costs
    /// bit_widths[i] specifies the bit-width of vector[i]
    pub fn commit_vector(&mut self, vector: &[F], bit_widths: &[usize]) 
        -> Result<VectorCommitment<F>, CommitmentError> {
        if vector.len() != bit_widths.len() {
            return Err(CommitmentError::DimensionMismatch);
        }
        
        // Pack field elements into ring elements
        let ring_vector = self.pack_to_ring(vector, bit_widths)?;
        
        // Update Ajtai scheme dimension if needed
        if self.ajtai.m != ring_vector.len() {
            let ring = self.ajtai.ring.clone();
            let kappa = self.ajtai.kappa;
            let norm_bound = self.ajtai.norm_bound;
            let seed = self.ajtai.seed;
            self.ajtai = AjtaiCommitmentScheme::setup(ring, kappa, ring_vector.len(), norm_bound, seed);
        }
        
        // Commit using Ajtai scheme
        let commitment = self.ajtai.commit(&ring_vector)?;
        
        Ok(VectorCommitment {
            commitment,
            original_length: vector.len(),
            bit_widths: bit_widths.to_vec(),
        })
    }
    
    /// Pack field vector into ring vector with coefficient embedding
    /// Key insight: d consecutive field elements → 1 ring element
    /// w_i = Σⱼ f_{i·d+j} · X^j
    pub fn pack_to_ring(&self, vector: &[F], bit_widths: &[usize]) 
        -> Result<Vec<RingElement<F>>, CommitmentError> {
        let d = self.packing_degree;
        let n = vector.len();
        
        // Pad to multiple of d
        let padded_len = ((n + d - 1) / d) * d;
        let mut padded = vector.to_vec();
        padded.resize(padded_len, F::zero());
        
        let mut padded_widths = bit_widths.to_vec();
        padded_widths.resize(padded_len, 0);
        
        let mut ring_elements = Vec::new();
        
        // Pack each chunk of d field elements
        for chunk_idx in 0..(padded_len / d) {
            let start = chunk_idx * d;
            let end = start + d;
            let chunk = &padded[start..end];
            
            // Create ring element: w_i = Σⱼ f_{i·d+j} · X^j
            let ring_elem = RingElement::from_coeffs(chunk.to_vec());
            
            // Verify norm bound based on bit-widths
            let max_bit_width = padded_widths[start..end]
                .iter()
                .max()
                .copied()
                .unwrap_or(0);
            
            if max_bit_width > 0 {
                let max_value = if max_bit_width < 64 {
                    (1u64 << max_bit_width) - 1
                } else {
                    u64::MAX
                };
                
                if ring_elem.norm_infinity() > max_value {
                    return Err(CommitmentError::NormBoundViolation);
                }
            }
            
            ring_elements.push(ring_elem);
        }
        
        Ok(ring_elements)
    }
    
    /// Unpack ring vector back to field vector
    /// Inverse of pack_to_ring
    pub fn unpack_from_ring(&self, ring_vector: &[RingElement<F>], original_length: usize) -> Vec<F> {
        let mut result: Vec<F> = ring_vector.iter()
            .flat_map(|elem| elem.coeffs.clone())
            .collect();
        
        // Truncate to original length
        result.truncate(original_length);
        result
    }
    
    /// Compute commitment cost based on bit-widths
    /// Cost = O(κ · (N/d) · b/log(q)) for b-bit values
    pub fn commitment_cost(&self, vector_len: usize, bit_widths: &[usize]) -> usize {
        let d = self.packing_degree;
        let field_bits = F::MODULUS_BITS;
        
        // Number of ring elements needed
        let num_ring_elems = (vector_len + d - 1) / d;
        
        // Average bit-width per ring element
        let total_bits: usize = bit_widths.iter().sum();
        let avg_bits_per_elem = if vector_len > 0 {
            total_bits / vector_len
        } else {
            0
        };
        
        // Cost scales with bit-width fraction
        let cost_per_ring_elem = (avg_bits_per_elem * d + field_bits - 1) / field_bits;
        
        num_ring_elems * cost_per_ring_elem * self.ajtai.kappa
    }
    
    /// Estimate speedup factor for b-bit values vs full field elements
    /// Speedup = log(q) / b
    pub fn speedup_factor(bit_width: usize) -> f64 {
        let field_bits = F::MODULUS_BITS;
        if bit_width > 0 {
            field_bits as f64 / bit_width as f64
        } else {
            1.0
        }
    }
    
    /// Verify round-trip: unpack(pack(f)) = f
    pub fn verify_packing_roundtrip(&self, vector: &[F], bit_widths: &[usize]) -> bool {
        match self.pack_to_ring(vector, bit_widths) {
            Ok(ring_vector) => {
                let unpacked = self.unpack_from_ring(&ring_vector, vector.len());
                unpacked == vector
            }
            Err(_) => false,
        }
    }
}

impl<F: Field> VectorCommitment<F> {
    /// Get the underlying Ajtai commitment
    pub fn get_commitment(&self) -> &Commitment<F> {
        &self.commitment
    }
    
    /// Get original vector length
    pub fn length(&self) -> usize {
        self.original_length
    }
    
    /// Get bit-widths
    pub fn bit_widths(&self) -> &[usize] {
        &self.bit_widths
    }
    
    /// Compute total cost for this commitment
    pub fn cost(&self) -> usize {
        let d = self.commitment.values[0].coeffs.len();
        let field_bits = F::MODULUS_BITS;
        
        let num_ring_elems = (self.original_length + d - 1) / d;
        let total_bits: usize = self.bit_widths.iter().sum();
        let avg_bits = if self.original_length > 0 {
            total_bits / self.original_length
        } else {
            0
        };
        
        let cost_per_elem = (avg_bits * d + field_bits - 1) / field_bits;
        num_ring_elems * cost_per_elem * self.commitment.kappa
    }
}

/// Support for mixed bit-widths
pub struct MixedBitWidthVector<F: Field> {
    pub values: Vec<F>,
    pub bit_widths: Vec<usize>,
}

impl<F: Field> MixedBitWidthVector<F> {
    /// Create new mixed bit-width vector
    pub fn new(values: Vec<F>, bit_widths: Vec<usize>) -> Result<Self, CommitmentError> {
        if values.len() != bit_widths.len() {
            return Err(CommitmentError::DimensionMismatch);
        }
        
        // Verify each value fits in its bit-width
        for (val, &width) in values.iter().zip(bit_widths.iter()) {
            if width > 0 && width < 64 {
                let max_val = (1u64 << width) - 1;
                if val.to_canonical_u64() > max_val {
                    return Err(CommitmentError::NormBoundViolation);
                }
            }
        }
        
        Ok(Self { values, bit_widths })
    }
    
    /// Get value at index
    pub fn get(&self, index: usize) -> Option<(F, usize)> {
        if index < self.values.len() {
            Some((self.values[index], self.bit_widths[index]))
        } else {
            None
        }
    }
    
    /// Compute average bit-width
    pub fn average_bit_width(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        
        let total: usize = self.bit_widths.iter().sum();
        total as f64 / self.values.len() as f64
    }
    
    /// Compute maximum bit-width
    pub fn max_bit_width(&self) -> usize {
        self.bit_widths.iter().copied().max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_packing() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [0u8; 32];
        let mut scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20, seed);
        
        // Create vector with 128 elements (will pack into 2 ring elements)
        let vector: Vec<_> = (0..128).map(|i| GoldilocksField::from_u64(i)).collect();
        let bit_widths = vec![8; 128]; // 8-bit values
        
        let ring_vector = scheme.pack_to_ring(&vector, &bit_widths).unwrap();
        assert_eq!(ring_vector.len(), 2); // 128 / 64 = 2
    }
    
    #[test]
    fn test_unpacking() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [1u8; 32];
        let scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20, seed);
        
        let vector: Vec<_> = (0..100).map(|i| GoldilocksField::from_u64(i)).collect();
        let bit_widths = vec![8; 100];
        
        let ring_vector = scheme.pack_to_ring(&vector, &bit_widths).unwrap();
        let unpacked = scheme.unpack_from_ring(&ring_vector, 100);
        
        assert_eq!(unpacked, vector);
    }
    
    #[test]
    fn test_packing_roundtrip() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [2u8; 32];
        let scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20, seed);
        
        let vector: Vec<_> = (0..75).map(|i| GoldilocksField::from_u64(i * 2)).collect();
        let bit_widths = vec![16; 75];
        
        assert!(scheme.verify_packing_roundtrip(&vector, &bit_widths));
    }
    
    #[test]
    fn test_vector_commitment() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [3u8; 32];
        let mut scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20, seed);
        
        let vector: Vec<_> = (0..64).map(|i| GoldilocksField::from_u64(i)).collect();
        let bit_widths = vec![8; 64];
        
        let commitment = scheme.commit_vector(&vector, &bit_widths).unwrap();
        assert_eq!(commitment.original_length, 64);
        assert_eq!(commitment.bit_widths.len(), 64);
    }
    
    #[test]
    fn test_commitment_cost() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [4u8; 32];
        let scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20, seed);
        
        // 8-bit values should be much cheaper than 64-bit values
        let cost_8bit = scheme.commitment_cost(64, &vec![8; 64]);
        let cost_64bit = scheme.commitment_cost(64, &vec![64; 64]);
        
        assert!(cost_8bit < cost_64bit);
    }
    
    #[test]
    fn test_speedup_factor() {
        // For 1-bit values with 64-bit field, expect 64x speedup
        let speedup_1bit = MatrixCommitmentScheme::<GoldilocksField>::speedup_factor(1);
        assert!((speedup_1bit - 64.0).abs() < 0.1);
        
        // For 32-bit values, expect 2x speedup
        let speedup_32bit = MatrixCommitmentScheme::<GoldilocksField>::speedup_factor(32);
        assert!((speedup_32bit - 2.0).abs() < 0.1);
    }
    
    #[test]
    fn test_mixed_bit_widths() {
        let values = vec![
            GoldilocksField::from_u64(1),   // 1-bit
            GoldilocksField::from_u64(255), // 8-bit
            GoldilocksField::from_u64(1000), // 10-bit
        ];
        let bit_widths = vec![1, 8, 10];
        
        let mixed = MixedBitWidthVector::new(values, bit_widths).unwrap();
        assert_eq!(mixed.max_bit_width(), 10);
        assert!((mixed.average_bit_width() - 6.33).abs() < 0.1);
    }
    
    #[test]
    fn test_bit_width_violation() {
        let values = vec![
            GoldilocksField::from_u64(256), // Too large for 8 bits
        ];
        let bit_widths = vec![8];
        
        let result = MixedBitWidthVector::new(values, bit_widths);
        assert!(result.is_err());
    }
}
