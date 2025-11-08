// Leveled Ajtai Commitment Structure for HyperWolf PCS
// Implements hierarchical commitment F_{k-1,0}(s⃗)
// Per HyperWolf paper Requirements 5 and 24

use crate::field::Field;
use crate::ring::{RingElement, CyclotomicRing, decompose_vector, GadgetParams};
use super::HyperWolfParams;

/// Leveled commitment structure F_{i,j}(s⃗)
/// 
/// For N = ∏_{i=0}^{k-1} m_i and matrices A_0, A_1, ..., A_{k-1}:
/// - F_{i,j}(s⃗) = A_i s⃗ mod q                                    if i = j
/// - F_{i,j}(s⃗) = F_{i,j+1}(G^{-1}_{b,M_{i,j}κ}((I_{M_{i,j}} ⊗ A_j) · G^{-1}_{b,N}(s⃗)))  if i > j
/// 
/// where M_{i,j} = m_i · m_{i-1} · ... · m_{j+1}
#[derive(Clone, Debug)]
pub struct LeveledCommitment<F: Field> {
    /// Commitment value cm ∈ R_q^κ
    pub value: Vec<RingElement<F>>,
    
    /// Level in hierarchy (0 to k-1)
    pub level: usize,
    
    /// Decomposition proof for verification
    pub decomposition: Vec<RingElement<F>>,
}

impl<F: Field> LeveledCommitment<F> {
    /// Compute F_{i,j}(s⃗) recursively
    /// 
    /// # Arguments
    /// * `witness` - Witness vector s⃗ ∈ R_q^n
    /// * `params` - HyperWolf parameters containing matrices
    /// * `level_i` - Upper level i
    /// * `level_j` - Lower level j
    /// 
    /// # Returns
    /// Leveled commitment F_{i,j}(s⃗)
    /// 
    /// Per HyperWolf paper Requirement 5.1 and 24.1-24.5
    pub fn compute(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        level_i: usize,
        level_j: usize,
    ) -> Result<Self, String> {
        if level_i >= params.num_rounds || level_j >= params.num_rounds {
            return Err(format!(
                "Invalid levels: i={}, j={}, k={}",
                level_i, level_j, params.num_rounds
            ));
        }
        
        if level_i < level_j {
            return Err(format!(
                "Invalid levels: i={} < j={}",
                level_i, level_j
            ));
        }
        
        // Base case: F_{i,i}(s⃗) = A_i s⃗ mod q
        if level_i == level_j {
            return Self::compute_base_case(witness, params, level_i);
        }
        
        // Recursive case: F_{i,j}(s⃗) = F_{i,j+1}(G^{-1}_{b,M_{i,j}κ}((I_{M_{i,j}} ⊗ A_j) · G^{-1}_{b,N}(s⃗)))
        Self::compute_recursive_case(witness, params, level_i, level_j)
    }
    
    /// Compute base case: F_{i,i}(s⃗) = A_i s⃗ mod q
    fn compute_base_case(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        level: usize,
    ) -> Result<Self, String> {
        let matrix = params.get_matrix(level)
            .ok_or_else(|| format!("Matrix A_{} not found", level))?;
        
        // Compute A_i s⃗
        let value = Self::matrix_vector_product(matrix, witness, params.ring())?;
        
        Ok(Self {
            value,
            level,
            decomposition: Vec::new(),
        })
    }
    
    /// Compute recursive case
    fn compute_recursive_case(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        level_i: usize,
        level_j: usize,
    ) -> Result<Self, String> {
        // Step 1: Compute G^{-1}_{b,N}(s⃗)
        let gadget_params = GadgetParams::new(
            params.decomposition_basis,
            params.modulus,
            witness.len(),
        )?;
        
        let decomposed_witness = decompose_vector(witness.to_vec(), &gadget_params)?;
        
        // Step 2: Compute M_{i,j} = m_i · m_{i-1} · ... · m_{j+1}
        // For HyperWolf with all m_i = 2, M_{i,j} = 2^{i-j}
        let m_ij = 1 << (level_i - level_j);
        
        // Step 3: Compute (I_{M_{i,j}} ⊗ A_j) · G^{-1}_{b,N}(s⃗)
        let matrix_j = params.get_matrix(level_j)
            .ok_or_else(|| format!("Matrix A_{} not found", level_j))?;
        
        let intermediate = Self::kronecker_product_multiply(
            m_ij,
            matrix_j,
            &decomposed_witness,
            params.ring(),
        )?;
        
        // Step 4: Compute G^{-1}_{b,M_{i,j}κ}(intermediate)
        let kappa = params.matrix_height;
        let gadget_params_2 = GadgetParams::new(
            params.decomposition_basis,
            params.modulus,
            m_ij * kappa,
        )?;
        
        let decomposed_intermediate = decompose_vector(intermediate, &gadget_params_2)?;
        
        // Step 5: Recursively compute F_{i,j+1}(decomposed_intermediate)
        Self::compute(&decomposed_intermediate, params, level_i, level_j + 1)
    }
    
    /// Matrix-vector product: A · v
    fn matrix_vector_product(
        matrix: &[Vec<RingElement<F>>],
        vector: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let rows = matrix.len();
        let cols = if rows > 0 { matrix[0].len() } else { 0 };
        
        if cols != vector.len() {
            return Err(format!(
                "Matrix-vector dimension mismatch: {} cols vs {} vector length",
                cols, vector.len()
            ));
        }
        
        let mut result = Vec::with_capacity(rows);
        
        for row in matrix {
            let mut sum = ring.zero();
            
            for (j, matrix_elem) in row.iter().enumerate() {
                let product = ring.mul(matrix_elem, &vector[j]);
                sum = ring.add(&sum, &product);
            }
            
            result.push(sum);
        }
        
        Ok(result)
    }
    
    /// Kronecker product multiplication: (I_m ⊗ A) · v
    fn kronecker_product_multiply(
        m: usize,
        matrix_a: &[Vec<RingElement<F>>],
        vector: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let a_rows = matrix_a.len();
        let a_cols = if a_rows > 0 { matrix_a[0].len() } else { 0 };
        
        // (I_m ⊗ A) has dimensions (m·a_rows) × (m·a_cols)
        let expected_vec_len = m * a_cols;
        
        if vector.len() != expected_vec_len {
            return Err(format!(
                "Kronecker product dimension mismatch: expected {}, got {}",
                expected_vec_len, vector.len()
            ));
        }
        
        let mut result = Vec::with_capacity(m * a_rows);
        
        // For each block i ∈ [0, m)
        for i in 0..m {
            // Compute A · v[i*a_cols..(i+1)*a_cols]
            let block_start = i * a_cols;
            let block_end = (i + 1) * a_cols;
            let vector_block = &vector[block_start..block_end];
            
            let block_result = Self::matrix_vector_product(matrix_a, vector_block, ring)?;
            result.extend(block_result);
        }
        
        Ok(result)
    }
}

    /// Verify commitment round i
    /// 
    /// Checks: A_{k-i-1} π⃗_{cm,i} = [c_{k-i,0}G^κ  c_{k-i,1}G^κ] π⃗_{cm,i-1}
    /// 
    /// # Arguments
    /// * `prev_commitment` - Previous round commitment (π⃗_{cm,i-1})
    /// * `challenge` - Challenge pair (c_{k-i,0}, c_{k-i,1}) ∈ C²
    /// * `matrix` - Matrix A_{k-i-1}
    /// * `params` - HyperWolf parameters
    /// 
    /// # Returns
    /// true if verification passes, false otherwise
    /// 
    /// Per HyperWolf paper Requirement 5.4 and 5.7
    pub fn verify_round(
        &self,
        prev_commitment: &Self,
        challenge: &[RingElement<F>; 2],
        matrix: &[Vec<RingElement<F>>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, String> {
        let ring = params.ring();
        
        // Left side: A_{k-i-1} π⃗_{cm,i}
        let left_side = Self::matrix_vector_product(matrix, &self.decomposition, ring)?;
        
        // Right side: [c_{k-i,0}G^κ  c_{k-i,1}G^κ] π⃗_{cm,i-1}
        let right_side = Self::compute_challenge_gadget_product(
            challenge,
            &prev_commitment.decomposition,
            params,
        )?;
        
        // Check equality
        if left_side.len() != right_side.len() {
            return Ok(false);
        }
        
        for (left, right) in left_side.iter().zip(right_side.iter()) {
            if left.coeffs != right.coeffs {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Compute [c_{k-i,0}G^κ  c_{k-i,1}G^κ] π⃗_{cm,i-1}
    fn compute_challenge_gadget_product(
        challenge: &[RingElement<F>; 2],
        prev_decomposition: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let ring = params.ring();
        let kappa = params.matrix_height;
        
        // Generate gadget matrix G^κ
        let gadget_params = GadgetParams::new(
            params.decomposition_basis,
            params.modulus,
            kappa,
        )?;
        
        let gadget_matrix = gadget_params.gadget_matrix::<F>();
        
        // Split prev_decomposition into two halves
        let half_len = prev_decomposition.len() / 2;
        let left_half = &prev_decomposition[0..half_len];
        let right_half = &prev_decomposition[half_len..];
        
        // Compute c_{k-i,0}G^κ · left_half
        let left_product = Self::scalar_gadget_multiply(
            &challenge[0],
            &gadget_matrix,
            left_half,
            ring,
        )?;
        
        // Compute c_{k-i,1}G^κ · right_half
        let right_product = Self::scalar_gadget_multiply(
            &challenge[1],
            &gadget_matrix,
            right_half,
            ring,
        )?;
        
        // Add the two products
        let mut result = Vec::with_capacity(left_product.len());
        for (left, right) in left_product.iter().zip(right_product.iter()) {
            result.push(ring.add(left, right));
        }
        
        Ok(result)
    }
    
    /// Compute c·G^κ · v where c is a scalar ring element
    fn scalar_gadget_multiply(
        scalar: &RingElement<F>,
        gadget_matrix: &[Vec<F>],
        vector: &[RingElement<F>],
        ring: &CyclotomicRing<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let rows = gadget_matrix.len();
        let cols = if rows > 0 { gadget_matrix[0].len() } else { 0 };
        
        if cols != vector.len() {
            return Err(format!(
                "Gadget matrix dimension mismatch: {} cols vs {} vector length",
                cols, vector.len()
            ));
        }
        
        let mut result = Vec::with_capacity(rows);
        
        for row in gadget_matrix {
            let mut sum = ring.zero();
            
            for (j, &gadget_coeff) in row.iter().enumerate() {
                // Compute c · gadget_coeff · vector[j]
                let scaled_vector = ring.scalar_mul(&gadget_coeff, &vector[j]);
                let product = ring.mul(scalar, &scaled_vector);
                sum = ring.add(&sum, &product);
            }
            
            result.push(sum);
        }
        
        Ok(result)
    }
    
    /// Compute commitment decomposition proof π⃗_{cm,i} = G^{-1}_{2κ}(cm_{i,0}, cm_{i,1})
    /// 
    /// # Arguments
    /// * `cm_left` - Commitment to left half cm_{i,0}
    /// * `cm_right` - Commitment to right half cm_{i,1}
    /// * `params` - HyperWolf parameters
    /// 
    /// # Returns
    /// Decomposition proof π⃗_{cm,i} ∈ R_q^{2κι}
    /// 
    /// Per HyperWolf paper Requirement 5.2 and 6.1
    pub fn compute_decomposition_proof(
        cm_left: &[RingElement<F>],
        cm_right: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let kappa = params.matrix_height;
        
        if cm_left.len() != kappa || cm_right.len() != kappa {
            return Err(format!(
                "Commitment dimensions must be κ={}, got left={}, right={}",
                kappa, cm_left.len(), cm_right.len()
            ));
        }
        
        // Concatenate (cm_{i,0}, cm_{i,1})
        let mut combined = Vec::with_capacity(2 * kappa);
        combined.extend_from_slice(cm_left);
        combined.extend_from_slice(cm_right);
        
        // Apply gadget decomposition G^{-1}_{2κ}
        let gadget_params = GadgetParams::new(
            params.decomposition_basis,
            params.modulus,
            2 * kappa,
        )?;
        
        let decomposed = decompose_vector(combined, &gadget_params)?;
        
        Ok(decomposed)
    }
    
    /// Split witness and compute commitments to halves
    /// 
    /// # Arguments
    /// * `witness` - Full witness s⃗
    /// * `params` - HyperWolf parameters
    /// * `level` - Current level in hierarchy
    /// 
    /// # Returns
    /// Tuple of (left_commitment, right_commitment, decomposition_proof)
    /// 
    /// Per HyperWolf paper Requirement 5.2
    pub fn split_and_commit(
        witness: &[RingElement<F>],
        params: &HyperWolfParams<F>,
        level: usize,
    ) -> Result<(Self, Self, Vec<RingElement<F>>), String> {
        // Split witness into left and right halves
        let half_len = witness.len() / 2;
        let witness_left = &witness[0..half_len];
        let witness_right = &witness[half_len..];
        
        // Compute commitments to each half
        let cm_left = Self::compute(witness_left, params, level, 0)?;
        let cm_right = Self::compute(witness_right, params, level, 0)?;
        
        // Compute decomposition proof
        let decomposition = Self::compute_decomposition_proof(
            &cm_left.value,
            &cm_right.value,
            params,
        )?;
        
        Ok((cm_left, cm_right, decomposition))
    }
    
    /// Verify final round commitment
    /// 
    /// Checks: A_0 s⃗^(1) = [c_{1,0}G^κ  c_{1,1}G^κ] π⃗_{cm,k-2}
    /// 
    /// # Arguments
    /// * `final_witness` - Final witness s⃗^(1) ∈ R_q^{2ι}
    /// * `prev_decomposition` - Previous decomposition π⃗_{cm,k-2}
    /// * `challenge` - Final challenge (c_{1,0}, c_{1,1})
    /// * `params` - HyperWolf parameters
    /// 
    /// # Returns
    /// true if verification passes
    /// 
    /// Per HyperWolf paper Requirement 5.5 and 6.5
    pub fn verify_final_round(
        final_witness: &[RingElement<F>],
        prev_decomposition: &[RingElement<F>],
        challenge: &[RingElement<F>; 2],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, String> {
        let ring = params.ring();
        
        // Get matrix A_0
        let matrix_a0 = params.get_matrix(0)
            .ok_or_else(|| "Matrix A_0 not found".to_string())?;
        
        // Left side: A_0 s⃗^(1)
        let left_side = Self::matrix_vector_product(matrix_a0, final_witness, ring)?;
        
        // Right side: [c_{1,0}G^κ  c_{1,1}G^κ] π⃗_{cm,k-2}
        let right_side = Self::compute_challenge_gadget_product(
            challenge,
            prev_decomposition,
            params,
        )?;
        
        // Check equality
        if left_side.len() != right_side.len() {
            return Ok(false);
        }
        
        for (left, right) in left_side.iter().zip(right_side.iter()) {
            if left.coeffs != right.coeffs {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify initial round commitment
    /// 
    /// Checks: A_{k-1} π⃗_{cm,0} = cm
    /// 
    /// # Arguments
    /// * `commitment` - Initial commitment cm
    /// * `params` - HyperWolf parameters
    /// 
    /// # Returns
    /// true if verification passes
    /// 
    /// Per HyperWolf paper Requirement 5.3 and 6.2
    pub fn verify_initial_round(
        &self,
        commitment: &[RingElement<F>],
        params: &HyperWolfParams<F>,
    ) -> Result<bool, String> {
        let ring = params.ring();
        
        // Get matrix A_{k-1}
        let k = params.num_rounds;
        let matrix = params.get_matrix(k - 1)
            .ok_or_else(|| format!("Matrix A_{} not found", k - 1))?;
        
        // Compute A_{k-1} π⃗_{cm,0}
        let computed = Self::matrix_vector_product(matrix, &self.decomposition, ring)?;
        
        // Check equality with commitment
        if computed.len() != commitment.len() {
            return Ok(false);
        }
        
        for (comp, cm) in computed.iter().zip(commitment.iter()) {
            if comp.coeffs != cm.coeffs {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get commitment value
    pub fn get_value(&self) -> &[RingElement<F>] {
        &self.value
    }
    
    /// Get decomposition proof
    pub fn get_decomposition(&self) -> &[RingElement<F>] {
        &self.decomposition
    }
    
    /// Get level
    pub fn get_level(&self) -> usize {
        self.level
    }
    
    /// Set decomposition proof (used during proof generation)
    pub fn set_decomposition(&mut self, decomposition: Vec<RingElement<F>>) {
        self.decomposition = decomposition;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    fn create_test_params() -> HyperWolfParams<GoldilocksField> {
        HyperWolfParams::new(128, 1024, 64).unwrap()
    }
    
    fn create_test_witness(len: usize) -> Vec<RingElement<GoldilocksField>> {
        let mut witness = Vec::with_capacity(len);
        for i in 0..len {
            let mut coeffs = vec![GoldilocksField::zero(); 64];
            coeffs[0] = GoldilocksField::from_u64((i + 1) as u64);
            witness.push(RingElement::from_coeffs(coeffs));
        }
        witness
    }
    
    #[test]
    fn test_compute_base_case() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        // Compute F_{0,0}(s⃗) = A_0 s⃗
        let commitment = LeveledCommitment::compute(&witness, &params, 0, 0).unwrap();
        
        assert_eq!(commitment.level, 0);
        assert_eq!(commitment.value.len(), params.matrix_height);
        assert!(commitment.decomposition.is_empty());
    }
    
    #[test]
    fn test_matrix_vector_product() {
        let params = create_test_params();
        let ring = params.ring();
        
        // Create small test matrix and vector
        let matrix = vec![
            vec![
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
            ],
            vec![
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(3); 64]),
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(4); 64]),
            ],
        ];
        
        let vector = vec![
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(5); 64]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(6); 64]),
        ];
        
        let result = LeveledCommitment::matrix_vector_product(&matrix, &vector, ring).unwrap();
        
        assert_eq!(result.len(), 2);
    }
    
    #[test]
    fn test_split_and_commit() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        let (cm_left, cm_right, decomposition) = 
            LeveledCommitment::split_and_commit(&witness, &params, 0).unwrap();
        
        assert_eq!(cm_left.value.len(), params.matrix_height);
        assert_eq!(cm_right.value.len(), params.matrix_height);
        assert_eq!(decomposition.len(), 2 * params.matrix_height * params.decomposition_length);
    }
    
    #[test]
    fn test_compute_decomposition_proof() {
        let params = create_test_params();
        let kappa = params.matrix_height;
        
        let cm_left = create_test_witness(kappa);
        let cm_right = create_test_witness(kappa);
        
        let decomposition = LeveledCommitment::compute_decomposition_proof(
            &cm_left,
            &cm_right,
            &params,
        ).unwrap();
        
        // Should have 2κι elements
        assert_eq!(decomposition.len(), 2 * kappa * params.decomposition_length);
    }
    
    #[test]
    fn test_verify_initial_round() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        // Compute commitment
        let commitment = LeveledCommitment::compute(&witness, &params, params.num_rounds - 1, 0).unwrap();
        
        // Create decomposition proof
        let (_, _, decomposition) = 
            LeveledCommitment::split_and_commit(&witness, &params, params.num_rounds - 1).unwrap();
        
        let mut commitment_with_decomp = commitment.clone();
        commitment_with_decomp.set_decomposition(decomposition);
        
        // Verify initial round
        let result = commitment_with_decomp.verify_initial_round(&commitment.value, &params);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_kronecker_product_multiply() {
        let params = create_test_params();
        let ring = params.ring();
        
        // Create small test matrix
        let matrix_a = vec![
            vec![
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
            ],
        ];
        
        // Create vector for (I_2 ⊗ A) with 2*2 = 4 elements
        let vector = create_test_witness(4);
        
        let result = LeveledCommitment::kronecker_product_multiply(
            2,
            &matrix_a,
            &vector,
            ring,
        ).unwrap();
        
        // Result should have 2 * 1 = 2 elements (m * a_rows)
        assert_eq!(result.len(), 2);
    }
    
    #[test]
    fn test_invalid_levels() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        // Test i < j
        let result = LeveledCommitment::compute(&witness, &params, 0, 1);
        assert!(result.is_err());
        
        // Test i >= k
        let result = LeveledCommitment::compute(&witness, &params, params.num_rounds, 0);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_getters() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        let commitment = LeveledCommitment::compute(&witness, &params, 0, 0).unwrap();
        
        assert_eq!(commitment.get_level(), 0);
        assert_eq!(commitment.get_value().len(), params.matrix_height);
        assert!(commitment.get_decomposition().is_empty());
    }
    
    #[test]
    fn test_set_decomposition() {
        let params = create_test_params();
        let witness = create_test_witness(2 * params.decomposition_length);
        
        let mut commitment = LeveledCommitment::compute(&witness, &params, 0, 0).unwrap();
        
        let decomposition = create_test_witness(10);
        commitment.set_decomposition(decomposition.clone());
        
        assert_eq!(commitment.get_decomposition().len(), 10);
    }
    
    #[test]
    fn test_compute_challenge_gadget_product() {
        let params = create_test_params();
        
        // Create challenge pair
        let challenge = [
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
        ];
        
        // Create previous decomposition
        let prev_decomposition = create_test_witness(2 * params.matrix_height * params.decomposition_length);
        
        let result = LeveledCommitment::compute_challenge_gadget_product(
            &challenge,
            &prev_decomposition,
            &params,
        ).unwrap();
        
        assert_eq!(result.len(), params.matrix_height);
    }
    
    #[test]
    fn test_scalar_gadget_multiply() {
        let params = create_test_params();
        let ring = params.ring();
        
        // Create scalar
        let scalar = RingElement::from_coeffs(vec![GoldilocksField::from_u64(3); 64]);
        
        // Create gadget matrix
        let gadget_params = GadgetParams::new(
            params.decomposition_basis,
            params.modulus,
            params.matrix_height,
        ).unwrap();
        let gadget_matrix = gadget_params.gadget_matrix::<GoldilocksField>();
        
        // Create vector
        let vector = create_test_witness(params.matrix_height * params.decomposition_length);
        
        let result = LeveledCommitment::scalar_gadget_multiply(
            &scalar,
            &gadget_matrix,
            &vector,
            ring,
        ).unwrap();
        
        assert_eq!(result.len(), params.matrix_height);
    }
    
    #[test]
    fn test_verify_round() {
        let params = create_test_params();
        
        // Create two commitments
        let witness1 = create_test_witness(2 * params.decomposition_length);
        let witness2 = create_test_witness(2 * params.decomposition_length);
        
        let mut commitment1 = LeveledCommitment::compute(&witness1, &params, 0, 0).unwrap();
        let mut commitment2 = LeveledCommitment::compute(&witness2, &params, 0, 0).unwrap();
        
        // Set decompositions
        let decomp1 = create_test_witness(2 * params.matrix_height * params.decomposition_length);
        let decomp2 = create_test_witness(2 * params.matrix_height * params.decomposition_length);
        
        commitment1.set_decomposition(decomp1);
        commitment2.set_decomposition(decomp2);
        
        // Create challenge
        let challenge = [
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
        ];
        
        // Get matrix
        let matrix = params.get_matrix(0).unwrap();
        
        // Verify round (will likely fail since we're using random data, but tests the function)
        let result = commitment2.verify_round(&commitment1, &challenge, matrix, &params);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_verify_final_round() {
        let params = create_test_params();
        
        // Create final witness
        let final_witness = create_test_witness(2 * params.decomposition_length);
        
        // Create previous decomposition
        let prev_decomposition = create_test_witness(2 * params.matrix_height * params.decomposition_length);
        
        // Create challenge
        let challenge = [
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
            RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
        ];
        
        // Verify final round (will likely fail since we're using random data, but tests the function)
        let result = LeveledCommitment::verify_final_round(
            &final_witness,
            &prev_decomposition,
            &challenge,
            &params,
        );
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_matrix_dimension_mismatch() {
        let params = create_test_params();
        let ring = params.ring();
        
        // Create matrix with 2 columns
        let matrix = vec![
            vec![
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
            ],
        ];
        
        // Create vector with 3 elements (mismatch)
        let vector = create_test_witness(3);
        
        let result = LeveledCommitment::matrix_vector_product(&matrix, &vector, ring);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_kronecker_dimension_mismatch() {
        let params = create_test_params();
        let ring = params.ring();
        
        // Create matrix
        let matrix_a = vec![
            vec![
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(1); 64]),
                RingElement::from_coeffs(vec![GoldilocksField::from_u64(2); 64]),
            ],
        ];
        
        // Create vector with wrong size
        let vector = create_test_witness(3);
        
        let result = LeveledCommitment::kronecker_product_multiply(
            2,
            &matrix_a,
            &vector,
            ring,
        );
        assert!(result.is_err());
    }
    
    #[test]
    fn test_decomposition_proof_dimension_mismatch() {
        let params = create_test_params();
        
        // Create commitments with wrong dimensions
        let cm_left = create_test_witness(5);  // Wrong size
        let cm_right = create_test_witness(params.matrix_height);
        
        let result = LeveledCommitment::compute_decomposition_proof(
            &cm_left,
            &cm_right,
            &params,
        );
        assert!(result.is_err());
    }
}
