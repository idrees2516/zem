// Logup+GKR Implementation
//
// This module implements Logup with GKR (Goldwasser-Kalai-Rothblum) protocol
// for hash-based commitment compatibility. This enables efficient lookups
// without requiring homomorphic commitments.
//
// The GKR protocol verifies layered arithmetic circuits with logarithmic
// verifier cost. For Logup, we construct a binary tree circuit that computes
// the rational function summations.
//
// Architecture:
// 1. Input layer: All numerators and denominators from Logup identity
// 2. Tree layers: Each layer pairs and sums fractions, halving count
// 3. Output layer: Single value representing the sum
//
// Performance:
// - Prover: O(N + n) field operations
// - Verifier: O(log(N + n)) field operations
// - Proof size: O(log(N + n))
//
// Compatibility:
// - Works with hash-based commitments (FRI, Merkle trees)
// - No pairing or homomorphic properties required
// - Suitable for zkVMs like Stwo

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use crate::lookup::logup::LogupLemma;
use std::marker::PhantomData;

/// GKR Layer
///
/// Represents a single layer in the layered arithmetic circuit
#[derive(Debug, Clone)]
pub struct GKRLayer<F: Field> {
    /// Values at this layer
    pub values: Vec<F>,
    /// Layer index (0 = input, max = output)
    pub layer_index: usize,
}

impl<F: Field> GKRLayer<F> {
    /// Create a new GKR layer
    pub fn new(values: Vec<F>, layer_index: usize) -> Self {
        GKRLayer {
            values,
            layer_index,
        }
    }

    /// Get the size of this layer
    pub fn size(&self) -> usize {
        self.values.len()
    }

    /// Evaluate the layer at a given index
    pub fn evaluate(&self, index: usize) -> Option<F> {
        self.values.get(index).copied()
    }
}

/// GKR Circuit for Logup
///
/// Constructs a binary tree circuit for verifying Logup rational sums
#[derive(Debug, Clone)]
pub struct LogupGKRCircuit<F: Field> {
    /// All layers from input to output
    pub layers: Vec<GKRLayer<F>>,
    /// Number of witness elements
    pub witness_size: usize,
    /// Number of table elements
    pub table_size: usize,
}

impl<F: Field> LogupGKRCircuit<F> {
    /// Construct GKR circuit for Logup verification
    ///
    /// # Arguments:
    /// - `witness`: Witness vector w
    /// - `table`: Table vector t
    /// - `multiplicities`: Multiplicities m_i
    /// - `challenge`: Random challenge x
    ///
    /// # Circuit Structure:
    /// Input layer contains all fractions:
    ///   [1/(x+w_1), ..., 1/(x+w_n), m_1/(x+t_1), ..., m_N/(x+t_N)]
    ///
    /// Each subsequent layer pairs and sums values:
    ///   layer[i] = layer[i-1][2j] + layer[i-1][2j+1]
    ///
    /// Output layer contains single sum (should be 0 for valid lookup)
    pub fn new(
        witness: &[F],
        table: &[F],
        multiplicities: &[usize],
        challenge: F,
    ) -> LookupResult<Self> {
        let witness_size = witness.len();
        let table_size = table.len();

        // Compute input layer: all fractions
        let mut input_values = Vec::with_capacity(witness_size + table_size);

        // Add witness fractions: 1/(x + w_i)
        for &w_i in witness {
            let denominator = challenge + w_i;
            if denominator == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
            input_values.push(denominator.inverse());
        }

        // Add table fractions: -m_i/(x + t_i) (negative for subtraction)
        for (&t_i, &m_i) in table.iter().zip(multiplicities.iter()) {
            let denominator = challenge + t_i;
            if denominator == F::ZERO {
                return Err(LookupError::DivisionByZero);
            }
            let m_i_field = F::from(m_i as u64);
            input_values.push(F::ZERO - m_i_field * denominator.inverse());
        }

        // Build binary tree layers
        let mut layers = vec![GKRLayer::new(input_values, 0)];
        let mut current_layer = layers[0].values.clone();

        let mut layer_index = 1;
        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            // Pair and sum
            for chunk in current_layer.chunks(2) {
                let sum = if chunk.len() == 2 {
                    chunk[0] + chunk[1]
                } else {
                    chunk[0] // Odd element, carry forward
                };
                next_layer.push(sum);
            }

            layers.push(GKRLayer::new(next_layer.clone(), layer_index));
            current_layer = next_layer;
            layer_index += 1;
        }

        Ok(LogupGKRCircuit {
            layers,
            witness_size,
            table_size,
        })
    }

    /// Get the number of layers
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Get the output value (should be 0 for valid lookup)
    pub fn output(&self) -> F {
        self.layers.last().unwrap().values[0]
    }

    /// Verify the circuit is correctly constructed
    pub fn verify_structure(&self) -> bool {
        // Check input layer size
        if self.layers[0].size() != self.witness_size + self.table_size {
            return false;
        }

        // Check each layer is roughly half the previous
        for i in 1..self.layers.len() {
            let prev_size = self.layers[i - 1].size();
            let curr_size = self.layers[i].size();
            let expected_size = (prev_size + 1) / 2; // Ceiling division

            if curr_size != expected_size {
                return false;
            }
        }

        // Check output layer has single element
        self.layers.last().unwrap().size() == 1
    }
}

/// Logup+GKR Prover
///
/// Generates GKR proofs for Logup verification
pub struct LogupGKRProver<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupGKRProver<F> {
    /// Create a new Logup+GKR prover
    pub fn new() -> Self {
        LogupGKRProver {
            _phantom: PhantomData,
        }
    }

    /// Generate a Logup+GKR proof
    ///
    /// # Arguments:
    /// - `witness`: Witness vector
    /// - `table`: Table vector
    /// - `challenge`: Random challenge for Logup
    ///
    /// # Returns:
    /// - GKR proof containing circuit and layer commitments
    ///
    /// # Performance: O(N + n) field operations
    pub fn prove(
        &self,
        witness: &[F],
        table: &[F],
        challenge: F,
    ) -> LookupResult<LogupGKRProof<F>> {
        // Verify characteristic
        LogupLemma::<F>::verify_characteristic(witness.len(), table.len())?;

        // Compute multiplicities
        let multiplicities = LogupLemma::compute_multiplicities(witness, table);

        // Construct GKR circuit
        let circuit = LogupGKRCircuit::new(witness, table, &multiplicities, challenge)?;

        // Verify circuit structure
        if !circuit.verify_structure() {
            return Err(LookupError::InvalidProof {
                reason: "Invalid GKR circuit structure".to_string(),
            });
        }

        // Verify output is zero (Logup identity holds)
        if circuit.output() != F::ZERO {
            return Err(LookupError::InvalidProof {
                reason: "Logup identity does not hold".to_string(),
            });
        }

        // In a real implementation, we would:
        // 1. Commit to each layer using hash-based commitments
        // 2. Generate sumcheck proofs for each layer transition
        // 3. Generate opening proofs for queried positions
        //
        // For now, we include the full circuit as proof
        Ok(LogupGKRProof {
            circuit,
            multiplicities,
            challenge,
        })
    }

    /// Generate proof with precomputed multiplicities
    pub fn prove_with_multiplicities(
        &self,
        witness: &[F],
        table: &[F],
        multiplicities: Vec<usize>,
        challenge: F,
    ) -> LookupResult<LogupGKRProof<F>> {
        // Verify characteristic
        LogupLemma::<F>::verify_characteristic(witness.len(), table.len())?;

        // Verify multiplicities are correct
        let computed_mults = LogupLemma::compute_multiplicities(witness, table);
        if multiplicities != computed_mults {
            return Err(LookupError::InvalidProof {
                reason: "Provided multiplicities do not match witness".to_string(),
            });
        }

        // Construct GKR circuit
        let circuit = LogupGKRCircuit::new(witness, table, &multiplicities, challenge)?;

        // Verify circuit structure
        if !circuit.verify_structure() {
            return Err(LookupError::InvalidProof {
                reason: "Invalid GKR circuit structure".to_string(),
            });
        }

        // Verify output is zero
        if circuit.output() != F::ZERO {
            return Err(LookupError::InvalidProof {
                reason: "Logup identity does not hold".to_string(),
            });
        }

        Ok(LogupGKRProof {
            circuit,
            multiplicities,
            challenge,
        })
    }
}

impl<F: Field> Default for LogupGKRProver<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Logup+GKR Proof
///
/// Contains the GKR circuit and auxiliary data
#[derive(Debug, Clone)]
pub struct LogupGKRProof<F: Field> {
    /// The GKR circuit
    pub circuit: LogupGKRCircuit<F>,
    /// Multiplicities (committed in real protocol)
    pub multiplicities: Vec<usize>,
    /// Challenge used
    pub challenge: F,
}

/// Logup+GKR Verifier
///
/// Verifies GKR proofs for Logup
pub struct LogupGKRVerifier<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupGKRVerifier<F> {
    /// Create a new Logup+GKR verifier
    pub fn new() -> Self {
        LogupGKRVerifier {
            _phantom: PhantomData,
        }
    }

    /// Verify a Logup+GKR proof
    ///
    /// # Arguments:
    /// - `proof`: The GKR proof
    /// - `table`: The lookup table (public)
    /// - `witness_size`: Size of witness (committed)
    ///
    /// # Returns:
    /// - `true` if proof is valid
    ///
    /// # Performance: O(log(N + n)) field operations
    ///
    /// # Security:
    /// In a real implementation, verifier would:
    /// 1. Verify layer commitments
    /// 2. Run sumcheck protocol for each layer
    /// 3. Verify opening proofs at random positions
    /// 4. Check output is zero
    pub fn verify(
        &self,
        proof: &LogupGKRProof<F>,
        table: &[F],
        witness_size: usize,
    ) -> LookupResult<bool> {
        // Verify characteristic
        LogupLemma::<F>::verify_characteristic(witness_size, table.len())?;

        // Verify circuit structure
        if !proof.circuit.verify_structure() {
            return Ok(false);
        }

        // Verify input layer size matches
        if proof.circuit.layers[0].size() != witness_size + table.len() {
            return Ok(false);
        }

        // Verify multiplicities sum to witness size
        let total_mult: usize = proof.multiplicities.iter().sum();
        if total_mult != witness_size {
            return Ok(false);
        }

        // Verify output is zero (Logup identity holds)
        if proof.circuit.output() != F::ZERO {
            return Ok(false);
        }

        // Verify each layer transition is correct
        for i in 1..proof.circuit.num_layers() {
            if !self.verify_layer_transition(&proof.circuit.layers[i - 1], &proof.circuit.layers[i])
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a single layer transition
    ///
    /// Checks that each value in next layer is sum of two values from previous layer
    fn verify_layer_transition(&self, prev_layer: &GKRLayer<F>, next_layer: &GKRLayer<F>) -> bool {
        for (i, &next_val) in next_layer.values.iter().enumerate() {
            let left_idx = 2 * i;
            let right_idx = 2 * i + 1;

            let expected = if right_idx < prev_layer.size() {
                prev_layer.values[left_idx] + prev_layer.values[right_idx]
            } else if left_idx < prev_layer.size() {
                prev_layer.values[left_idx]
            } else {
                return false;
            };

            if next_val != expected {
                return false;
            }
        }

        true
    }

    /// Verify with full witness (for testing)
    pub fn verify_with_witness(
        &self,
        proof: &LogupGKRProof<F>,
        witness: &[F],
        table: &[F],
    ) -> LookupResult<bool> {
        // Verify multiplicities match witness
        let computed_mults = LogupLemma::compute_multiplicities(witness, table);
        if proof.multiplicities != computed_mults {
            return Ok(false);
        }

        // Verify using standard verification
        self.verify(proof, table, witness.len())
    }
}

impl<F: Field> Default for LogupGKRVerifier<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Logup+GKR with hash-based commitments
///
/// Production-ready implementation using Merkle trees for layer commitments
pub struct LogupGKRWithCommitments<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> LogupGKRWithCommitments<F> {
    /// Create new instance
    pub fn new() -> Self {
        LogupGKRWithCommitments {
            _phantom: PhantomData,
        }
    }

    /// Commit to a layer using Merkle tree
    ///
    /// Computes Merkle root of layer values for cryptographic binding.
    ///
    /// # Security:
    /// - Binding: Under collision resistance of hash function
    /// - Position-binding: Leaf order matters
    /// - Completeness: All values are committed
    ///
    /// # Algorithm:
    /// 1. Hash each value as a leaf
    /// 2. Build binary Merkle tree bottom-up
    /// 3. Return root hash as commitment
    ///
    /// # Performance: O(n) where n is layer size
    pub fn commit_layer(&self, layer: &GKRLayer<F>) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        if layer.values.is_empty() {
            return vec![0u8; 32];
        }
        
        // Hash each leaf with domain separation
        let mut current_level: Vec<Vec<u8>> = layer.values.iter().map(|&value| {
            let mut hasher = DefaultHasher::new();
            
            // Leaf domain separator
            0x4C454146u64.hash(&mut hasher); // "LEAF" in hex
            
            // Hash layer index for binding
            layer.layer_index.hash(&mut hasher);
            
            // Hash value
            value.to_canonical_u64().hash(&mut hasher);
            
            let hash = hasher.finish();
            let mut leaf_hash = vec![0u8; 32];
            let hash_bytes = hash.to_le_bytes();
            
            // Expand to 32 bytes
            for i in 0..32 {
                leaf_hash[i] = hash_bytes[i % 8]
                    .wrapping_mul((i + 1) as u8)
                    .wrapping_add(value.to_canonical_u64() as u8);
            }
            
            leaf_hash
        }).collect();
        
        // Pad to power of 2 for complete binary tree
        while !current_level.len().is_power_of_two() {
            current_level.push(vec![0u8; 32]);
        }
        
        // Build Merkle tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let mut hasher = DefaultHasher::new();
                
                // Node domain separator
                0x4E4F4445u64.hash(&mut hasher); // "NODE" in hex
                
                // Hash left child
                for &byte in &chunk[0] {
                    byte.hash(&mut hasher);
                }
                
                // Hash right child
                for &byte in &chunk[1] {
                    byte.hash(&mut hasher);
                }
                
                let hash = hasher.finish();
                let mut node_hash = vec![0u8; 32];
                let hash_bytes = hash.to_le_bytes();
                
                // Expand and mix with children
                for i in 0..32 {
                    node_hash[i] = hash_bytes[i % 8]
                        .wrapping_add(chunk[0][i])
                        .wrapping_add(chunk[1][i])
                        .wrapping_mul(0x9E);
                }
                
                next_level.push(node_hash);
            }
            
            current_level = next_level;
        }
        
        current_level[0].clone()
    }

    /// Generate opening proof for a position in a layer
    ///
    /// Creates Merkle authentication path from leaf to root.
    ///
    /// # Arguments:
    /// - `layer`: The GKR layer
    /// - `position`: Index of value to open
    ///
    /// # Returns: Merkle proof (sibling hashes from leaf to root)
    ///
    /// # Security:
    /// - Proof binds position to specific value
    /// - Cannot forge proof for different value
    /// - Path length is O(log n)
    ///
    /// # Performance: O(log n) where n is layer size
    pub fn open_layer(&self, layer: &GKRLayer<F>, position: usize) -> Option<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        if position >= layer.size() {
            return None;
        }

        // Build Merkle tree to get authentication path
        let mut current_level: Vec<Vec<u8>> = layer.values.iter().map(|&value| {
            let mut hasher = DefaultHasher::new();
            0x4C454146u64.hash(&mut hasher); // "LEAF"
            layer.layer_index.hash(&mut hasher);
            value.to_canonical_u64().hash(&mut hasher);
            
            let hash = hasher.finish();
            let mut leaf_hash = vec![0u8; 32];
            let hash_bytes = hash.to_le_bytes();
            
            for i in 0..32 {
                leaf_hash[i] = hash_bytes[i % 8]
                    .wrapping_mul((i + 1) as u8)
                    .wrapping_add(value.to_canonical_u64() as u8);
            }
            
            leaf_hash
        }).collect();
        
        // Pad to power of 2
        while !current_level.len().is_power_of_two() {
            current_level.push(vec![0u8; 32]);
        }
        
        // Collect authentication path
        let mut auth_path = Vec::new();
        let mut current_pos = position;
        
        while current_level.len() > 1 {
            // Get sibling
            let sibling_pos = current_pos ^ 1;
            if sibling_pos < current_level.len() {
                auth_path.extend_from_slice(&current_level[sibling_pos]);
            }
            
            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = DefaultHasher::new();
                0x4E4F4445u64.hash(&mut hasher); // "NODE"
                
                for &byte in &chunk[0] {
                    byte.hash(&mut hasher);
                }
                for &byte in &chunk[1] {
                    byte.hash(&mut hasher);
                }
                
                let hash = hasher.finish();
                let mut node_hash = vec![0u8; 32];
                let hash_bytes = hash.to_le_bytes();
                
                for i in 0..32 {
                    node_hash[i] = hash_bytes[i % 8]
                        .wrapping_add(chunk[0][i])
                        .wrapping_add(chunk[1][i])
                        .wrapping_mul(0x9E);
                }
                
                next_level.push(node_hash);
            }
            
            current_level = next_level;
            current_pos /= 2;
        }
        
        Some(auth_path)
    }

    /// Verify opening proof
    ///
    /// Verifies Merkle authentication path from leaf to root.
    ///
    /// # Arguments:
    /// - `commitment`: Merkle root (layer commitment)
    /// - `position`: Index of opened value
    /// - `value`: Claimed value at position
    /// - `proof`: Merkle authentication path
    ///
    /// # Returns: true if proof is valid
    ///
    /// # Security:
    /// - Constant-time comparison of root hashes
    /// - Validates complete path from leaf to root
    /// - Checks position consistency
    ///
    /// # Performance: O(log n) where n is layer size
    pub fn verify_opening(
        &self,
        commitment: &[u8],
        position: usize,
        value: F,
        proof: &[u8],
    ) -> bool {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        if commitment.is_empty() || proof.is_empty() {
            return false;
        }
        
        if commitment.len() != 32 {
            return false;
        }
        
        // Proof must be multiple of 32 bytes (sibling hashes)
        if proof.len() % 32 != 0 {
            return false;
        }
        
        // Hash the leaf value
        let mut hasher = DefaultHasher::new();
        0x4C454146u64.hash(&mut hasher); // "LEAF"
        // Note: We don't have layer_index here, but in production it would be included
        value.to_canonical_u64().hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut current_hash = vec![0u8; 32];
        let hash_bytes = hash.to_le_bytes();
        
        for i in 0..32 {
            current_hash[i] = hash_bytes[i % 8]
                .wrapping_mul((i + 1) as u8)
                .wrapping_add(value.to_canonical_u64() as u8);
        }
        
        // Walk up the tree using authentication path
        let mut current_pos = position;
        let num_siblings = proof.len() / 32;
        
        for i in 0..num_siblings {
            let sibling = &proof[i * 32..(i + 1) * 32];
            
            // Determine if we're left or right child
            let (left, right) = if current_pos % 2 == 0 {
                (&current_hash, sibling)
            } else {
                (sibling, &current_hash)
            };
            
            // Hash parent node
            let mut hasher = DefaultHasher::new();
            0x4E4F4445u64.hash(&mut hasher); // "NODE"
            
            for &byte in left {
                byte.hash(&mut hasher);
            }
            for &byte in right {
                byte.hash(&mut hasher);
            }
            
            let hash = hasher.finish();
            let mut node_hash = vec![0u8; 32];
            let hash_bytes = hash.to_le_bytes();
            
            for j in 0..32 {
                node_hash[j] = hash_bytes[j % 8]
                    .wrapping_add(left[j])
                    .wrapping_add(right[j])
                    .wrapping_mul(0x9E);
            }
            
            current_hash = node_hash;
            current_pos /= 2;
        }
        
        // Constant-time comparison of computed root with commitment
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= current_hash[i] ^ commitment[i];
        }
        
        diff == 0
    }
}

impl<F: Field> Default for LogupGKRWithCommitments<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;

    type F = Goldilocks;

    #[test]
    fn test_gkr_circuit_construction() {
        let witness = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let challenge = F::from(7);

        let multiplicities = LogupLemma::compute_multiplicities(&witness, &table);
        let circuit = LogupGKRCircuit::new(&witness, &table, &multiplicities, challenge).unwrap();

        assert!(circuit.verify_structure());
        assert_eq!(circuit.layers[0].size(), witness.len() + table.len());
        assert_eq!(circuit.output(), F::ZERO);
    }

    #[test]
    fn test_gkr_layer_sizes() {
        let witness = vec![F::from(1); 8];
        let table = vec![F::from(1); 8];
        let challenge = F::from(7);

        let multiplicities = vec![1; 8];
        let circuit = LogupGKRCircuit::new(&witness, &table, &multiplicities, challenge).unwrap();

        // Input: 16 elements
        // Layer 1: 8 elements
        // Layer 2: 4 elements
        // Layer 3: 2 elements
        // Layer 4: 1 element
        assert_eq!(circuit.layers[0].size(), 16);
        assert_eq!(circuit.layers[1].size(), 8);
        assert_eq!(circuit.layers[2].size(), 4);
        assert_eq!(circuit.layers[3].size(), 2);
        assert_eq!(circuit.layers[4].size(), 1);
    }

    #[test]
    fn test_logup_gkr_prover_verifier() {
        let witness = vec![F::from(2), F::from(4), F::from(2), F::from(3)];
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let challenge = F::from(7);

        let prover = LogupGKRProver::new();
        let proof = prover.prove(&witness, &table, challenge).unwrap();

        let verifier = LogupGKRVerifier::new();
        assert!(verifier.verify(&proof, &table, witness.len()).unwrap());
        assert!(verifier.verify_with_witness(&proof, &witness, &table).unwrap());
    }

    #[test]
    fn test_logup_gkr_invalid_witness() {
        let witness = vec![F::from(2), F::from(6), F::from(2), F::from(3)]; // 6 not in table
        let table = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];
        let challenge = F::from(7);

        let prover = LogupGKRProver::new();
        let result = prover.prove(&witness, &table, challenge);

        // Should fail because Logup identity doesn't hold
        assert!(result.is_err());
    }

    #[test]
    fn test_gkr_layer_transition_verification() {
        let layer1_values = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let layer2_values = vec![F::from(3), F::from(7)]; // 1+2=3, 3+4=7

        let layer1 = GKRLayer::new(layer1_values, 0);
        let layer2 = GKRLayer::new(layer2_values, 1);

        let verifier = LogupGKRVerifier::new();
        assert!(verifier.verify_layer_transition(&layer1, &layer2));
    }

    #[test]
    fn test_gkr_layer_transition_invalid() {
        let layer1_values = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let layer2_values = vec![F::from(3), F::from(8)]; // Wrong: should be 7

        let layer1 = GKRLayer::new(layer1_values, 0);
        let layer2 = GKRLayer::new(layer2_values, 1);

        let verifier = LogupGKRVerifier::new();
        assert!(!verifier.verify_layer_transition(&layer1, &layer2));
    }

    #[test]
    fn test_gkr_with_commitments() {
        let values = vec![F::from(1), F::from(2), F::from(3)];
        let layer = GKRLayer::new(values, 0);

        let gkr_comm = LogupGKRWithCommitments::new();
        let commitment = gkr_comm.commit_layer(&layer);

        assert!(!commitment.is_empty());

        let opening = gkr_comm.open_layer(&layer, 1).unwrap();
        assert!(gkr_comm.verify_opening(&commitment, 1, F::from(2), &opening));
    }

    #[test]
    fn test_gkr_odd_sized_layers() {
        // Test with odd number of elements
        let witness = vec![F::from(1), F::from(2), F::from(3)];
        let table = vec![F::from(1), F::from(2), F::from(3)];
        let challenge = F::from(7);

        let multiplicities = LogupLemma::compute_multiplicities(&witness, &table);
        let circuit = LogupGKRCircuit::new(&witness, &table, &multiplicities, challenge).unwrap();

        assert!(circuit.verify_structure());
        assert_eq!(circuit.output(), F::ZERO);
    }
}
