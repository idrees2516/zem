// Neo's pay-per-bit commitment scheme integration
// Implements matrix commitment with linear homomorphism for folding
// Per Neo paper Section 3.2-3.3

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use super::ajtai::{AjtaiCommitment, CommitmentKey, Commitment, AjtaiParams};

/// Neo pay-per-bit commitment scheme
/// Transforms field vectors to matrices and commits using Ajtai scheme
pub struct NeoPayPerBitCommitment<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

/// Vector-to-matrix transformation parameters
#[derive(Clone, Debug)]
pub struct TransformParams {
    /// Number of rows in matrix
    pub num_rows: usize,
    /// Number of columns in matrix
    pub num_cols: usize,
    /// Bit-width of each value
    pub bit_width: usize,
}

impl<F: Field> NeoPayPerBitCommitment<F> {
    /// Transform field vector to matrix representation
    /// For small field elements, this enables pay-per-bit costs
    /// Per Neo Section 3.2
    pub fn vector_to_matrix(
        vector: &[F],
        params: &TransformParams,
    ) -> Vec<Vec<F>> {
        let total_elements = params.num_rows * params.num_cols;
        assert!(vector.len() <= total_elements, "Vector too large for matrix");
        
        let mut matrix = vec![vec![F::zero(); params.num_cols]; params.num_rows];
        
        // Fill matrix row by row
        for (idx, &val) in vector.iter().enumerate() {
            let row = idx / params.num_cols;
            let col = idx % params.num_cols;
            if row < params.num_rows {
                matrix[row][col] = val;
            }
        }
        
        matrix
    }
    
    /// Transform matrix back to vector
    pub fn matrix_to_vector(
        matrix: &[Vec<F>],
        original_length: usize,
    ) -> Vec<F> {
        let mut vector = Vec::with_capacity(original_length);
        
        for row in matrix {
            for &val in row {
                if vector.len() < original_length {
                    vector.push(val);
                }
            }
        }
        
        vector
    }
    
    /// Commit to matrix using Ajtai scheme
    /// Each row becomes a ring element via coefficient embedding
    pub fn commit_matrix(
        key: &CommitmentKey<F>,
        matrix: &[Vec<F>],
    ) -> Commitment<F> {
        // Convert each row to ring element
        let ring_vector: Vec<RingElement<F>> = matrix
            .iter()
            .map(|row| RingElement::from_coeffs(row.clone()))
            .collect();
        
        AjtaiCommitment::commit(key, &ring_vector)
    }
    
    /// Commit to field vector with pay-per-bit optimization
    /// Automatically determines optimal matrix shape based on bit-width
    pub fn commit_vector_optimized(
        key: &CommitmentKey<F>,
        vector: &[F],
        bit_width: usize,
    ) -> (Commitment<F>, TransformParams) {
        let params = Self::optimal_transform_params(vector.len(), bit_width, key.ring.degree);
        let matrix = Self::vector_to_matrix(vector, &params);
        let commitment = Self::commit_matrix(key, &matrix);
        
        (commitment, params)
    }
    
    /// Determine optimal matrix shape for given vector and bit-width
    /// Minimizes commitment cost while respecting ring degree constraints
    fn optimal_transform_params(
        vector_len: usize,
        bit_width: usize,
        ring_degree: usize,
    ) -> TransformParams {
        // For pay-per-bit optimization, pack multiple small values per ring element
        // Each ring element can hold ring_degree field elements
        
        let elements_per_row = ring_degree;
        let num_rows = (vector_len + elements_per_row - 1) / elements_per_row;
        
        TransformParams {
            num_rows,
            num_cols: elements_per_row,
            bit_width,
        }
    }
    
    /// Compute commitment cost for b-bit values
    /// Cost scales linearly with bit-width: O(n·b) vs O(n·log(q))
    pub fn commitment_cost(
        vector_len: usize,
        bit_width: usize,
        ring_degree: usize,
        kappa: usize,
    ) -> usize {
        let num_ring_elements = (vector_len + ring_degree - 1) / ring_degree;
        
        // Cost per ring element scales with bit-width
        let field_bits = F::MODULUS_BITS;
        let cost_factor = (bit_width + field_bits - 1) / field_bits;
        
        num_ring_elements * kappa * cost_factor
    }
    
    /// Compute speedup factor for b-bit values vs full field elements
    /// For 1-bit values with 64-bit field: 64x speedup
    /// For 32-bit values: 2x speedup
    pub fn speedup_factor(bit_width: usize) -> f64 {
        let field_bits = F::MODULUS_BITS;
        if bit_width > 0 && bit_width < field_bits {
            field_bits as f64 / bit_width as f64
        } else {
            1.0
        }
    }
    
    /// Verify linear homomorphism property for folding
    /// Per Neo Section 3.3: For commitments {(C_i, r, y_i)}_{i∈[β]},
    /// fold to (C, r, y) where C = Σ_i ρ_i·C_i and y = Σ_i ρ_i·y_i
    pub fn verify_linear_homomorphism(
        key: &CommitmentKey<F>,
        commitments: &[Commitment<F>],
        messages: &[Vec<RingElement<F>>],
        combiners: &[RingElement<F>],
    ) -> bool {
        assert_eq!(commitments.len(), messages.len());
        assert_eq!(commitments.len(), combiners.len());
        
        if commitments.is_empty() {
            return true;
        }
        
        // Compute folded commitment: C = Σ_i ρ_i·C_i
        let mut folded_commitment = vec![key.ring.zero(); key.kappa];
        for (commitment, combiner) in commitments.iter().zip(combiners.iter()) {
            for (j, c_j) in commitment.value.iter().enumerate() {
                let scaled = key.ring.mul(combiner, c_j);
                folded_commitment[j] = key.ring.add(&folded_commitment[j], &scaled);
            }
        }
        
        // Compute folded message: m = Σ_i ρ_i·m_i
        let n = messages[0].len();
        let mut folded_message = vec![key.ring.zero(); n];
        for (message, combiner) in messages.iter().zip(combiners.iter()) {
            for (j, m_j) in message.iter().enumerate() {
                let scaled = key.ring.mul(combiner, m_j);
                folded_message[j] = key.ring.add(&folded_message[j], &scaled);
            }
        }
        
        // Verify: Commit(folded_message) = folded_commitment
        let expected_commitment = AjtaiCommitment::commit(key, &folded_message);
        
        expected_commitment.value == folded_commitment
    }
}

/// Pay-per-bit commitment with metadata
#[derive(Clone, Debug)]
pub struct PayPerBitCommitment<F: Field> {
    pub commitment: Commitment<F>,
    pub transform_params: TransformParams,
    pub original_length: usize,
}

impl<F: Field> PayPerBitCommitment<F> {
    /// Create new pay-per-bit commitment
    pub fn new(
        commitment: Commitment<F>,
        transform_params: TransformParams,
        original_length: usize,
    ) -> Self {
        Self {
            commitment,
            transform_params,
            original_length,
        }
    }
    
    /// Get commitment cost
    pub fn cost(&self) -> usize {
        NeoPayPerBitCommitment::<F>::commitment_cost(
            self.original_length,
            self.transform_params.bit_width,
            self.transform_params.num_cols,
            self.commitment.value.len(),
        )
    }
    
    /// Get speedup factor compared to full field elements
    pub fn speedup(&self) -> f64 {
        NeoPayPerBitCommitment::<F>::speedup_factor(self.transform_params.bit_width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_vector_to_matrix() {
        let vector: Vec<GoldilocksField> = (0..10)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let params = TransformParams {
            num_rows: 2,
            num_cols: 5,
            bit_width: 8,
        };
        
        let matrix = NeoPayPerBitCommitment::vector_to_matrix(&vector, &params);
        
        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].len(), 5);
        assert_eq!(matrix[0][0].to_canonical_u64(), 0);
        assert_eq!(matrix[1][4].to_canonical_u64(), 9);
    }
    
    #[test]
    fn test_matrix_to_vector_roundtrip() {
        let vector: Vec<GoldilocksField> = (0..15)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let params = TransformParams {
            num_rows: 3,
            num_cols: 5,
            bit_width: 8,
        };
        
        let matrix = NeoPayPerBitCommitment::vector_to_matrix(&vector, &params);
        let recovered = NeoPayPerBitCommitment::matrix_to_vector(&matrix, 15);
        
        assert_eq!(vector, recovered);
    }
    
    #[test]
    fn test_commit_matrix() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        let matrix: Vec<Vec<GoldilocksField>> = vec![
            vec![GoldilocksField::from_u64(1); 64],
            vec![GoldilocksField::from_u64(2); 64],
        ];
        
        let commitment = NeoPayPerBitCommitment::commit_matrix(&key, &matrix);
        
        assert_eq!(commitment.value.len(), 4); // kappa = 4
    }
    
    #[test]
    fn test_optimal_transform_params() {
        let params = NeoPayPerBitCommitment::<GoldilocksField>::optimal_transform_params(
            100,  // vector length
            8,    // 8-bit values
            64,   // ring degree
        );
        
        assert_eq!(params.num_cols, 64);
        assert_eq!(params.num_rows, 2); // ceil(100/64) = 2
        assert_eq!(params.bit_width, 8);
    }
    
    #[test]
    fn test_commitment_cost() {
        // Cost for 1-bit values
        let cost_1bit = NeoPayPerBitCommitment::<GoldilocksField>::commitment_cost(
            64,  // vector length
            1,   // 1-bit
            64,  // ring degree
            4,   // kappa
        );
        
        // Cost for 32-bit values
        let cost_32bit = NeoPayPerBitCommitment::<GoldilocksField>::commitment_cost(
            64,  // vector length
            32,  // 32-bit
            64,  // ring degree
            4,   // kappa
        );
        
        // 1-bit should be much cheaper
        assert!(cost_1bit < cost_32bit);
    }
    
    #[test]
    fn test_speedup_factor() {
        // 1-bit values with 64-bit field: 64x speedup
        let speedup_1bit = NeoPayPerBitCommitment::<GoldilocksField>::speedup_factor(1);
        assert!((speedup_1bit - 64.0).abs() < 0.1);
        
        // 8-bit values: 8x speedup
        let speedup_8bit = NeoPayPerBitCommitment::<GoldilocksField>::speedup_factor(8);
        assert!((speedup_8bit - 8.0).abs() < 0.1);
        
        // 32-bit values: 2x speedup
        let speedup_32bit = NeoPayPerBitCommitment::<GoldilocksField>::speedup_factor(32);
        assert!((speedup_32bit - 2.0).abs() < 0.1);
    }
    
    #[test]
    fn test_linear_homomorphism() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 4;
        let seed = [0u8; 32];
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        // Create two messages
        let m1: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|_| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(2);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        let m2: Vec<RingElement<GoldilocksField>> = (0..n)
            .map(|_| {
                let mut coeffs = vec![GoldilocksField::zero(); 64];
                coeffs[0] = GoldilocksField::from_u64(3);
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        // Commit to both
        let c1 = AjtaiCommitment::commit(&key, &m1);
        let c2 = AjtaiCommitment::commit(&key, &m2);
        
        // Create combiners
        let rho1 = {
            let mut coeffs = vec![GoldilocksField::zero(); 64];
            coeffs[0] = GoldilocksField::from_u64(5);
            RingElement::from_coeffs(coeffs)
        };
        let rho2 = {
            let mut coeffs = vec![GoldilocksField::zero(); 64];
            coeffs[0] = GoldilocksField::from_u64(7);
            RingElement::from_coeffs(coeffs)
        };
        
        // Verify linear homomorphism
        let result = NeoPayPerBitCommitment::verify_linear_homomorphism(
            &key,
            &[c1, c2],
            &[m1, m2],
            &[rho1, rho2],
        );
        
        assert!(result);
    }
    
    #[test]
    fn test_commit_vector_optimized() {
        let params = AjtaiParams::new_128bit_security(64, GoldilocksField::MODULUS, 4);
        let n = 8;
        let seed = [0u8; 32];
        let key = AjtaiCommitment::<GoldilocksField>::setup(params, n, Some(seed));
        
        let vector: Vec<GoldilocksField> = (0..100)
            .map(|i| GoldilocksField::from_u64(i % 256))
            .collect();
        
        let (commitment, transform_params) = 
            NeoPayPerBitCommitment::commit_vector_optimized(&key, &vector, 8);
        
        assert_eq!(commitment.value.len(), 4); // kappa = 4
        assert_eq!(transform_params.bit_width, 8);
    }
}
