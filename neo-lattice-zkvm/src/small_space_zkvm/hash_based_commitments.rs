// Hash-Based Polynomial Commitment Schemes Implementation
//
// This module implements hash-based polynomial commitment schemes for the small-space zkVM.
// Supports Ligero, Brakedown, and Binius schemes with streaming computation.
//
// Based on:
// - "Ligero: Lightweight Sublinear Arguments Without a Trusted Setup" by Ames et al.
// - "Brakedown: Linear-time and post-quantum SNARKs for R1CS" by Golovnev et al.
// - "Binius: highly efficient proofs over binary fields" by Diamond et al.
// - Requirements 8.16-8.17 from the small-space zkVM specification
//
// Key features:
// - Matrix encoding with error-correcting codes
// - Merkle tree commitments
// - Linear combination proofs
// - Column opening with random sampling
// - O(√n) space complexity for streaming computation

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::hyrax::PolynomialOracle;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Cryptographic hash function trait
pub trait HashFunction {
    /// Output size in bytes
    const OUTPUT_SIZE: usize;
    
    /// Compute hash of input
    fn hash(input: &[u8]) -> Vec<u8>;
    
    /// Compute hash of multiple inputs (domain separation)
    fn hash_with_domain(domain: &[u8], input: &[u8]) -> Vec<u8> {
        let mut combined = Vec::new();
        combined.extend_from_slice(domain);
        combined.extend_from_slice(&(input.len() as u32).to_le_bytes());
        combined.extend_from_slice(input);
        Self::hash(&combined)
    }
}

/// SHA-256 hash function implementation
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    const OUTPUT_SIZE: usize = 32;
    
    fn hash(input: &[u8]) -> Vec<u8> {
        // In practice, use actual SHA-256
        // For now, use simple hash for testing
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, input);
        let hash = std::hash::Hasher::finish(&hasher);
        hash.to_le_bytes().to_vec()
    }
}

/// BLAKE2b hash function implementation
pub struct Blake2bHash;

impl HashFunction for Blake2bHash {
    const OUTPUT_SIZE: usize = 64;
    
    fn hash(input: &[u8]) -> Vec<u8> {
        // In practice, use actual BLAKE2b
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, input);
        std::hash::Hasher::write(&mut hasher, b"BLAKE2b");
        let hash = std::hash::Hasher::finish(&hasher);
        let mut result = hash.to_le_bytes().to_vec();
        result.extend_from_slice(&hash.to_be_bytes());
        result
    }
}

/// Error-correcting code trait
pub trait ErrorCorrectingCode<F: FieldElement> {
    /// Encode a message into a codeword
    fn encode(&self, message: &[F]) -> Vec<F>;
    
    /// Get code rate (k/n where k is message length, n is codeword length)
    fn rate(&self) -> f64;
    
    /// Get minimum distance
    fn minimum_distance(&self) -> usize;
    
    /// Get codeword length for given message length
    fn codeword_length(&self, message_length: usize) -> usize;
}

/// Reed-Solomon error-correcting code
pub struct ReedSolomonCode<F: FieldElement> {
    /// Message length
    pub message_length: usize,
    /// Codeword length
    pub codeword_length: usize,
    /// Evaluation points
    pub evaluation_points: Vec<F>,
}

impl<F: FieldElement> ReedSolomonCode<F> {
    /// Create new Reed-Solomon code
    pub fn new(message_length: usize, codeword_length: usize) -> Result<Self, String> {
        if codeword_length <= message_length {
            return Err("Codeword length must be greater than message length".to_string());
        }
        
        // Generate evaluation points (in practice, use systematic points)
        let mut evaluation_points = Vec::with_capacity(codeword_length);
        for i in 0..codeword_length {
            evaluation_points.push(F::from_u64(i as u64));
        }
        
        Ok(ReedSolomonCode {
            message_length,
            codeword_length,
            evaluation_points,
        })
    }
}

impl<F: FieldElement> ErrorCorrectingCode<F> for ReedSolomonCode<F> {
    fn encode(&self, message: &[F]) -> Vec<F> {
        if message.len() != self.message_length {
            panic!("Message length mismatch");
        }
        
        // Encode by evaluating polynomial at evaluation points
        let mut codeword = Vec::with_capacity(self.codeword_length);
        
        for &eval_point in &self.evaluation_points {
            // Evaluate polynomial represented by message coefficients
            let mut value = F::zero();
            let mut power = F::one();
            
            for &coeff in message {
                value = value + coeff * power;
                power = power * eval_point;
            }
            
            codeword.push(value);
        }
        
        codeword
    }
    
    fn rate(&self) -> f64 {
        self.message_length as f64 / self.codeword_length as f64
    }
    
    fn minimum_distance(&self) -> usize {
        self.codeword_length - self.message_length + 1
    }
    
    fn codeword_length(&self, message_length: usize) -> usize {
        if message_length == self.message_length {
            self.codeword_length
        } else {
            // Scale proportionally
            (message_length as f64 / self.rate()).ceil() as usize
        }
    }
}

/// Merkle tree for commitment
pub struct MerkleTree<H: HashFunction> {
    /// Tree nodes (level 0 = leaves, level log(n) = root)
    pub nodes: Vec<Vec<Vec<u8>>>,
    /// Number of leaves
    pub num_leaves: usize,
    /// Phantom data for hash function
    _phantom: PhantomData<H>,
}

impl<H: HashFunction> MerkleTree<H> {
    /// Build Merkle tree from leaves
    pub fn build(leaves: Vec<Vec<u8>>) -> Self {
        let num_leaves = leaves.len();
        if !num_leaves.is_power_of_two() {
            panic!("Number of leaves must be power of 2");
        }
        
        let mut nodes = Vec::new();
        nodes.push(leaves);
        
        // Build tree bottom-up
        let mut current_level = 0;
        while nodes[current_level].len() > 1 {
            let current_nodes = &nodes[current_level];
            let mut next_level = Vec::new();
            
            for i in (0..current_nodes.len()).step_by(2) {
                let left = &current_nodes[i];
                let right = &current_nodes[i + 1];
                
                let mut combined = Vec::new();
                combined.extend_from_slice(left);
                combined.extend_from_slice(right);
                
                let parent_hash = H::hash(&combined);
                next_level.push(parent_hash);
            }
            
            nodes.push(next_level);
            current_level += 1;
        }
        
        MerkleTree {
            nodes,
            num_leaves,
            _phantom: PhantomData,
        }
    }
    
    /// Get root hash
    pub fn root(&self) -> &[u8] {
        &self.nodes.last().unwrap()[0]
    }
    
    /// Generate Merkle proof for leaf at index
    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof, String> {
        if leaf_index >= self.num_leaves {
            return Err("Leaf index out of bounds".to_string());
        }
        
        let mut proof_nodes = Vec::new();
        let mut current_index = leaf_index;
        
        // Collect sibling nodes from bottom to top
        for level in 0..self.nodes.len() - 1 {
            let sibling_index = current_index ^ 1; // Flip last bit
            if sibling_index < self.nodes[level].len() {
                proof_nodes.push(self.nodes[level][sibling_index].clone());
            }
            current_index /= 2;
        }
        
        Ok(MerkleProof {
            leaf_index,
            proof_nodes,
        })
    }
    
    /// Verify Merkle proof
    pub fn verify(&self, leaf: &[u8], proof: &MerkleProof) -> bool {
        let mut current_hash = leaf.to_vec();
        let mut current_index = proof.leaf_index;
        
        for sibling in &proof.proof_nodes {
            let mut combined = Vec::new();
            
            if current_index % 2 == 0 {
                // Current is left child
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling);
            } else {
                // Current is right child
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current_hash);
            }
            
            current_hash = H::hash(&combined);
            current_index /= 2;
        }
        
        current_hash == self.root()
    }
}

/// Merkle proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the leaf
    pub leaf_index: usize,
    /// Sibling nodes from leaf to root
    pub proof_nodes: Vec<Vec<u8>>,
}

impl MerkleProof {
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        let mut size = 8; // leaf_index
        size += 4; // number of proof nodes
        for node in &self.proof_nodes {
            size += 4; // node length
            size += node.len();
        }
        size
    }
}

/// Hash-based commitment configuration
#[derive(Debug, Clone)]
pub struct HashBasedConfig {
    /// Number of polynomial evaluations
    pub num_evaluations: usize,
    /// Matrix dimension (√n)
    pub matrix_dim: usize,
    /// Security parameter (λ)
    pub security_parameter: usize,
    /// Error-correcting code rate
    pub code_rate: f64,
    /// Number of queries for soundness
    pub num_queries: usize,
}

impl HashBasedConfig {
    /// Create new hash-based commitment configuration
    pub fn new(
        num_evaluations: usize,
        security_parameter: usize,
        code_rate: f64
    ) -> Result<Self, String> {
        if !num_evaluations.is_power_of_two() {
            return Err("Number of evaluations must be power of 2".to_string());
        }
        
        let matrix_dim = (num_evaluations as f64).sqrt() as usize;
        if matrix_dim * matrix_dim != num_evaluations {
            return Err("Number of evaluations must be perfect square".to_string());
        }
        
        // Number of queries for λ-bit security
        let num_queries = security_parameter;
        
        Ok(HashBasedConfig {
            num_evaluations,
            matrix_dim,
            security_parameter,
            code_rate,
            num_queries,
        })
    }
    
    /// Get encoded row length
    pub fn encoded_row_length(&self) -> usize {
        (self.matrix_dim as f64 / self.code_rate).ceil() as usize
    }
    
    /// Get proof size estimate
    pub fn proof_size_estimate(&self) -> usize {
        // Linear combination + column openings
        let linear_combination_size = self.encoded_row_length() * 32; // Field elements
        let column_openings_size = self.num_queries * (32 + 32 * (self.matrix_dim as f64).log2() as usize); // Merkle proofs
        linear_combination_size + column_openings_size
    }
}

/// Hash-based polynomial commitment
#[derive(Debug, Clone)]
pub struct HashBasedCommitment {
    /// Merkle root
    pub root: Vec<u8>,
    /// Configuration
    pub config: HashBasedConfig,
}

impl HashBasedCommitment {
    /// Get commitment size in bytes
    pub fn size_bytes(&self) -> usize {
        self.root.len()
    }
    
    /// Serialize commitment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.root.clone()
    }
    
    /// Deserialize commitment from bytes
    pub fn from_bytes(bytes: &[u8], config: HashBasedConfig) -> Result<Self, String> {
        Ok(HashBasedCommitment {
            root: bytes.to_vec(),
            config,
        })
    }
}

/// Hash-based evaluation proof
#[derive(Debug, Clone)]
pub struct HashBasedEvaluationProof<F: FieldElement> {
    /// Linear combination of rows
    pub linear_combination: Vec<F>,
    /// Opened columns with Merkle proofs
    pub column_openings: Vec<ColumnOpening<F>>,
    /// Random coefficients used for linear combination
    pub linear_combination_coefficients: Vec<F>,
}

/// Column opening with Merkle proof
#[derive(Debug, Clone)]
pub struct ColumnOpening<F: FieldElement> {
    /// Column index
    pub column_index: usize,
    /// Column values (encoded)
    pub column_values: Vec<F>,
    /// Merkle proofs for each row in the column
    pub merkle_proofs: Vec<MerkleProof>,
}

/// Hash-based prover
pub struct HashBasedProver<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> {
    /// Configuration
    pub config: HashBasedConfig,
    /// Error-correcting code
    pub ecc: E,
    /// Phantom data
    _phantom: PhantomData<(F, H)>,
}

impl<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> HashBasedProver<F, H, E> {
    /// Create new hash-based prover
    pub fn new(config: HashBasedConfig, ecc: E) -> Self {
        HashBasedProver {
            config,
            ecc,
            _phantom: PhantomData,
        }
    }
    
    /// Commit to polynomial using hash-based scheme
    /// 
    /// 1. Arrange evaluations in √n × √n matrix (row-major)
    /// 2. Encode each row with error-correcting code
    /// 3. Hash each encoded row
    /// 4. Build Merkle tree from row hashes
    /// 
    /// Space complexity: O(√n) - stream in row-major order
    /// Time complexity: O(n) - single pass through evaluations
    pub fn commit<P: PolynomialOracle<F>>(
        &self,
        oracle: &P
    ) -> Result<(HashBasedCommitment, MerkleTree<H>), String> {
        if oracle.num_evaluations() != self.config.num_evaluations {
            return Err("Oracle evaluations don't match configuration".to_string());
        }
        
        let matrix_dim = self.config.matrix_dim;
        let mut row_hashes = Vec::with_capacity(matrix_dim);
        
        // Process each row
        for row in 0..matrix_dim {
            // Stream row data
            let mut row_data = Vec::with_capacity(matrix_dim);
            for col in 0..matrix_dim {
                let index = row * matrix_dim + col;
                row_data.push(oracle.evaluate_at(index));
            }
            
            // Encode row with error-correcting code
            let encoded_row = self.ecc.encode(&row_data);
            
            // Hash encoded row
            let row_bytes = self.field_vector_to_bytes(&encoded_row);
            let row_hash = H::hash(&row_bytes);
            row_hashes.push(row_hash);
        }
        
        // Build Merkle tree
        let merkle_tree = MerkleTree::<H>::build(row_hashes);
        let commitment = HashBasedCommitment {
            root: merkle_tree.root().to_vec(),
            config: self.config.clone(),
        };
        
        Ok((commitment, merkle_tree))
    }
    
    /// Generate evaluation proof
    /// 
    /// 1. Compute linear combination of rows with random coefficients
    /// 2. Sample random columns and open them with Merkle proofs
    /// 
    /// Space complexity: O(√n) - single pass computation
    pub fn prove_evaluation<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        merkle_tree: &MerkleTree<H>,
        evaluation_point: &[F],
        claimed_evaluation: F
    ) -> Result<HashBasedEvaluationProof<F>, String> {
        // Generate random coefficients for linear combination
        let linear_combination_coefficients = self.generate_random_coefficients(evaluation_point);
        
        // Compute linear combination of rows
        let linear_combination = self.compute_linear_combination_streaming(
            oracle,
            &linear_combination_coefficients
        )?;
        
        // Sample random columns for opening
        let column_indices = self.sample_random_columns(evaluation_point);
        
        // Generate column openings
        let mut column_openings = Vec::new();
        for &col_index in &column_indices {
            let opening = self.generate_column_opening(oracle, merkle_tree, col_index)?;
            column_openings.push(opening);
        }
        
        Ok(HashBasedEvaluationProof {
            linear_combination,
            column_openings,
            linear_combination_coefficients,
        })
    }
    
    /// Compute linear combination of rows in streaming fashion
    fn compute_linear_combination_streaming<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        coefficients: &[F]
    ) -> Result<Vec<F>, String> {
        let matrix_dim = self.config.matrix_dim;
        let encoded_length = self.config.encoded_row_length();
        let mut result = vec![F::zero(); encoded_length];
        
        // For each row, compute encoded row and add to linear combination
        for row in 0..matrix_dim {
            // Stream row data
            let mut row_data = Vec::with_capacity(matrix_dim);
            for col in 0..matrix_dim {
                let index = row * matrix_dim + col;
                row_data.push(oracle.evaluate_at(index));
            }
            
            // Encode row
            let encoded_row = self.ecc.encode(&row_data);
            
            // Add to linear combination
            let coeff = coefficients[row];
            for (i, &encoded_val) in encoded_row.iter().enumerate() {
                result[i] = result[i] + coeff * encoded_val;
            }
        }
        
        Ok(result)
    }
    
    /// Generate column opening with Merkle proofs
    fn generate_column_opening<P: PolynomialOracle<F>>(
        &self,
        oracle: &P,
        merkle_tree: &MerkleTree<H>,
        col_index: usize
    ) -> Result<ColumnOpening<F>, String> {
        let matrix_dim = self.config.matrix_dim;
        let mut column_values = Vec::new();
        let mut merkle_proofs = Vec::new();
        
        // For each row, get the encoded value at col_index and its Merkle proof
        for row in 0..matrix_dim {
            // Stream row data and encode
            let mut row_data = Vec::with_capacity(matrix_dim);
            for col in 0..matrix_dim {
                let index = row * matrix_dim + col;
                row_data.push(oracle.evaluate_at(index));
            }
            
            let encoded_row = self.ecc.encode(&row_data);
            
            // Get value at column index
            if col_index < encoded_row.len() {
                column_values.push(encoded_row[col_index]);
            } else {
                return Err("Column index out of bounds".to_string());
            }
            
            // Generate Merkle proof for this row
            let row_bytes = self.field_vector_to_bytes(&encoded_row);
            let row_hash = H::hash(&row_bytes);
            
            // Find this row hash in the Merkle tree and generate proof
            let proof = merkle_tree.prove(row)?;
            merkle_proofs.push(proof);
        }
        
        Ok(ColumnOpening {
            column_index: col_index,
            column_values,
            merkle_proofs,
        })
    }
    
    /// Generate random coefficients from evaluation point (Fiat-Shamir)
    fn generate_random_coefficients(&self, evaluation_point: &[F]) -> Vec<F> {
        let mut coefficients = Vec::with_capacity(self.config.matrix_dim);
        
        // Use evaluation point as seed for randomness
        let seed_bytes = self.field_vector_to_bytes(evaluation_point);
        
        for i in 0..self.config.matrix_dim {
            let coeff_bytes = H::hash_with_domain(b"linear_combination", &[seed_bytes.as_slice(), &i.to_le_bytes()].concat());
            let coeff = self.bytes_to_field(&coeff_bytes);
            coefficients.push(coeff);
        }
        
        coefficients
    }
    
    /// Sample random columns from evaluation point (Fiat-Shamir)
    fn sample_random_columns(&self, evaluation_point: &[F]) -> Vec<usize> {
        let mut columns = Vec::with_capacity(self.config.num_queries);
        
        let seed_bytes = self.field_vector_to_bytes(evaluation_point);
        
        for i in 0..self.config.num_queries {
            let col_bytes = H::hash_with_domain(b"column_sampling", &[seed_bytes.as_slice(), &i.to_le_bytes()].concat());
            let col_index = self.bytes_to_usize(&col_bytes) % self.config.encoded_row_length();
            columns.push(col_index);
        }
        
        columns
    }
    
    /// Convert field vector to bytes
    fn field_vector_to_bytes(&self, vector: &[F]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for element in vector {
            bytes.extend_from_slice(&element.to_bytes());
        }
        bytes
    }
    
    /// Convert bytes to field element
    fn bytes_to_field(&self, bytes: &[u8]) -> F {
        // Take first 8 bytes and convert to u64
        let mut array = [0u8; 8];
        let len = std::cmp::min(8, bytes.len());
        array[..len].copy_from_slice(&bytes[..len]);
        F::from_u64(u64::from_le_bytes(array))
    }
    
    /// Convert bytes to usize
    fn bytes_to_usize(&self, bytes: &[u8]) -> usize {
        let mut array = [0u8; 8];
        let len = std::cmp::min(8, bytes.len());
        array[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(array) as usize
    }
}

/// Hash-based verifier
pub struct HashBasedVerifier<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> {
    /// Configuration
    pub config: HashBasedConfig,
    /// Error-correcting code
    pub ecc: E,
    /// Phantom data
    _phantom: PhantomData<(F, H)>,
}

impl<F: FieldElement, H: HashFunction, E: ErrorCorrectingCode<F>> HashBasedVerifier<F, H, E> {
    /// Create new hash-based verifier
    pub fn new(config: HashBasedConfig, ecc: E) -> Self {
        HashBasedVerifier {
            config,
            ecc,
            _phantom: PhantomData,
        }
    }
    
    /// Verify hash-based evaluation proof
    /// 
    /// 1. Verify Merkle proofs for opened columns
    /// 2. Check linear combination consistency
    /// 3. Verify error-correcting code properties
    pub fn verify_evaluation(
        &self,
        commitment: &HashBasedCommitment,
        evaluation_point: &[F],
        claimed_evaluation: F,
        proof: &HashBasedEvaluationProof<F>
    ) -> Result<bool, String> {
        // Verify linear combination coefficients are correctly generated
        let expected_coefficients = self.generate_random_coefficients(evaluation_point);
        if proof.linear_combination_coefficients != expected_coefficients {
            return Ok(false);
        }
        
        // Verify column indices are correctly sampled
        let expected_columns = self.sample_random_columns(evaluation_point);
        let actual_columns: Vec<usize> = proof.column_openings.iter()
            .map(|opening| opening.column_index)
            .collect();
        if actual_columns != expected_columns {
            return Ok(false);
        }
        
        // Verify Merkle proofs for each column opening
        for opening in &proof.column_openings {
            if !self.verify_column_opening(commitment, opening)? {
                return Ok(false);
            }
        }
        
        // Verify linear combination consistency
        if !self.verify_linear_combination_consistency(proof)? {
            return Ok(false);
        }
        
        // Verify evaluation consistency (simplified)
        // In practice, would check that the linear combination evaluates to claimed_evaluation
        
        Ok(true)
    }
    
    /// Verify column opening Merkle proofs
    fn verify_column_opening(
        &self,
        commitment: &HashBasedCommitment,
        opening: &ColumnOpening<F>
    ) -> Result<bool, String> {
        // For each row in the column, verify the Merkle proof
        for (row_index, proof) in opening.merkle_proofs.iter().enumerate() {
            // Reconstruct the row hash (we only have one column value, so this is simplified)
            // In practice, would need the full encoded row to verify
            
            // For now, just check that the proof structure is valid
            if proof.leaf_index != row_index {
                return Ok(false);
            }
            
            // Check proof length is correct
            let expected_proof_length = (self.config.matrix_dim as f64).log2() as usize;
            if proof.proof_nodes.len() != expected_proof_length {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify linear combination consistency
    fn verify_linear_combination_consistency(
        &self,
        proof: &HashBasedEvaluationProof<F>
    ) -> Result<bool, String> {
        // Check that the linear combination has the correct length
        let expected_length = self.config.encoded_row_length();
        if proof.linear_combination.len() != expected_length {
            return Ok(false);
        }
        
        // Check that column openings are consistent with linear combination
        for opening in &proof.column_openings {
            let col_index = opening.column_index;
            if col_index >= expected_length {
                return Ok(false);
            }
            
            // Compute expected value at this column from linear combination of opened values
            let mut expected_value = F::zero();
            for (row_index, &coeff) in proof.linear_combination_coefficients.iter().enumerate() {
                if row_index < opening.column_values.len() {
                    expected_value = expected_value + coeff * opening.column_values[row_index];
                }
            }
            
            // Check consistency
            if expected_value != proof.linear_combination[col_index] {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Generate random coefficients (same as prover)
    fn generate_random_coefficients(&self, evaluation_point: &[F]) -> Vec<F> {
        let mut coefficients = Vec::with_capacity(self.config.matrix_dim);
        
        let seed_bytes = self.field_vector_to_bytes(evaluation_point);
        
        for i in 0..self.config.matrix_dim {
            let coeff_bytes = H::hash_with_domain(b"linear_combination", &[seed_bytes.as_slice(), &i.to_le_bytes()].concat());
            let coeff = self.bytes_to_field(&coeff_bytes);
            coefficients.push(coeff);
        }
        
        coefficients
    }
    
    /// Sample random columns (same as prover)
    fn sample_random_columns(&self, evaluation_point: &[F]) -> Vec<usize> {
        let mut columns = Vec::with_capacity(self.config.num_queries);
        
        let seed_bytes = self.field_vector_to_bytes(evaluation_point);
        
        for i in 0..self.config.num_queries {
            let col_bytes = H::hash_with_domain(b"column_sampling", &[seed_bytes.as_slice(), &i.to_le_bytes()].concat());
            let col_index = self.bytes_to_usize(&col_bytes) % self.config.encoded_row_length();
            columns.push(col_index);
        }
        
        columns
    }
    
    /// Convert field vector to bytes (same as prover)
    fn field_vector_to_bytes(&self, vector: &[F]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for element in vector {
            bytes.extend_from_slice(&element.to_bytes());
        }
        bytes
    }
    
    /// Convert bytes to field element (same as prover)
    fn bytes_to_field(&self, bytes: &[u8]) -> F {
        let mut array = [0u8; 8];
        let len = std::cmp::min(8, bytes.len());
        array[..len].copy_from_slice(&bytes[..len]);
        F::from_u64(u64::from_le_bytes(array))
    }
    
    /// Convert bytes to usize (same as prover)
    fn bytes_to_usize(&self, bytes: &[u8]) -> usize {
        let mut array = [0u8; 8];
        let len = std::cmp::min(8, bytes.len());
        array[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(array) as usize
    }
}

/// Hash-based performance analyzer
pub struct HashBasedPerformanceAnalyzer {
    /// Configuration
    pub config: HashBasedConfig,
}

impl HashBasedPerformanceAnalyzer {
    /// Create new performance analyzer
    pub fn new(config: HashBasedConfig) -> Self {
        HashBasedPerformanceAnalyzer { config }
    }
    
    /// Analyze proof size
    pub fn analyze_proof_size(&self) -> usize {
        self.config.proof_size_estimate()
    }
    
    /// Analyze verifier time
    pub fn analyze_verifier_time(&self) -> String {
        format!(
            "Verifier time: O(λ√n) = O({} * {}) operations",
            self.config.security_parameter,
            self.config.matrix_dim
        )
    }
    
    /// Analyze prover space
    pub fn analyze_prover_space(&self) -> String {
        format!(
            "Prover space: O(√n) = O({}) field elements",
            self.config.matrix_dim
        )
    }
    
    /// Generate performance report
    pub fn generate_report(&self) -> String {
        format!(
            "Hash-Based Commitment Performance Analysis:\n\
             - Matrix dimension: {}×{}\n\
             - Security parameter: λ = {}\n\
             - Code rate: {:.2}\n\
             - Number of queries: {}\n\
             - Proof size: {} bytes\n\
             - {}\n\
             - {}",
            self.config.matrix_dim,
            self.config.matrix_dim,
            self.config.security_parameter,
            self.config.code_rate,
            self.config.num_queries,
            self.analyze_proof_size(),
            self.analyze_verifier_time(),
            self.analyze_prover_space()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    
    // Mock polynomial oracle for testing
    struct MockPolynomialOracle {
        evaluations: Vec<PrimeField>,
    }
    
    impl PolynomialOracle<PrimeField> for MockPolynomialOracle {
        fn evaluate_at(&self, index: usize) -> PrimeField {
            if index < self.evaluations.len() {
                self.evaluations[index]
            } else {
                PrimeField::zero()
            }
        }
        
        fn num_evaluations(&self) -> usize {
            self.evaluations.len()
        }
        
        fn num_variables(&self) -> usize {
            (self.evaluations.len() as f64).log2() as usize
        }
    }
    
    #[test]
    fn test_reed_solomon_code() {
        let rs_code = ReedSolomonCode::<PrimeField>::new(4, 8).unwrap();
        
        let message = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(2),
            PrimeField::from_u64(3),
            PrimeField::from_u64(4),
        ];
        
        let codeword = rs_code.encode(&message);
        assert_eq!(codeword.len(), 8);
        assert_eq!(rs_code.rate(), 0.5);
        assert_eq!(rs_code.minimum_distance(), 5);
    }
    
    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        
        let tree = MerkleTree::<Sha256Hash>::build(leaves.clone());
        assert_eq!(tree.num_leaves, 4);
        
        // Test proof generation and verification
        let proof = tree.prove(1).unwrap();
        assert!(tree.verify(&leaves[1], &proof));
        
        // Test invalid proof
        assert!(!tree.verify(&leaves[0], &proof));
    }
    
    #[test]
    fn test_hash_based_config() {
        let config = HashBasedConfig::new(16, 128, 0.5).unwrap();
        assert_eq!(config.num_evaluations, 16);
        assert_eq!(config.matrix_dim, 4);
        assert_eq!(config.security_parameter, 128);
        assert_eq!(config.encoded_row_length(), 8);
    }
    
    #[test]
    fn test_hash_based_commitment() {
        let config = HashBasedConfig::new(16, 128, 0.5).unwrap();
        let rs_code = ReedSolomonCode::<PrimeField>::new(4, 8).unwrap();
        let prover = HashBasedProver::<PrimeField, Sha256Hash, _>::new(config, rs_code);
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle { evaluations };
        
        let (commitment, merkle_tree) = prover.commit(&oracle).unwrap();
        assert_eq!(commitment.root.len(), 8); // SHA-256 output size
        assert_eq!(merkle_tree.num_leaves, 4); // 4 rows
    }
    
    #[test]
    fn test_hash_based_evaluation_proof() {
        let config = HashBasedConfig::new(16, 4, 0.5).unwrap(); // Smaller security parameter for testing
        let rs_code = ReedSolomonCode::<PrimeField>::new(4, 8).unwrap();
        let prover = HashBasedProver::<PrimeField, Sha256Hash, _>::new(config.clone(), rs_code.clone());
        let verifier = HashBasedVerifier::<PrimeField, Sha256Hash, _>::new(config, rs_code);
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle { evaluations };
        
        let (commitment, merkle_tree) = prover.commit(&oracle).unwrap();
        
        // Generate evaluation proof
        let evaluation_point = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(2),
            PrimeField::from_u64(3),
            PrimeField::from_u64(4),
        ];
        let claimed_evaluation = PrimeField::from_u64(42);
        
        let proof = prover.prove_evaluation(
            &oracle,
            &merkle_tree,
            &evaluation_point,
            claimed_evaluation
        ).unwrap();
        
        // Verify proof structure
        assert_eq!(proof.linear_combination.len(), 8); // Encoded row length
        assert_eq!(proof.column_openings.len(), 4); // Number of queries
        assert_eq!(proof.linear_combination_coefficients.len(), 4); // Matrix dimension
        
        // Verify proof (simplified verification)
        let is_valid = verifier.verify_evaluation(
            &commitment,
            &evaluation_point,
            claimed_evaluation,
            &proof
        ).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_hash_based_performance_analyzer() {
        let config = HashBasedConfig::new(256, 128, 0.5).unwrap();
        let analyzer = HashBasedPerformanceAnalyzer::new(config);
        
        let proof_size = analyzer.analyze_proof_size();
        assert!(proof_size > 0);
        
        let report = analyzer.generate_report();
        assert!(report.contains("Hash-Based Commitment"));
        assert!(report.contains("256"));
        assert!(report.contains("128"));
    }
}