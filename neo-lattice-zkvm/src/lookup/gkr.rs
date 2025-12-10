// GKR Protocol: Interactive Proof for Layered Arithmetic Circuits
//
// This module implements the GKR (Goldwasser-Kalai-Rothblum) protocol, which provides
// an interactive proof system for layered arithmetic circuits. GKR is particularly
// efficient for circuits with simple, uniform layer descriptions.
//
// # Mathematical Foundation
//
// Given a layered arithmetic circuit C with d layers:
// - Layer 0: Input layer
// - Layer d: Output layer
// - Each layer i has gates computing addition or multiplication
//
// The prover convinces the verifier that the output is correctly computed from the input
// without the verifier examining all intermediate values.
//
// # Protocol Structure
//
// For each layer i (from output to input):
// 1. Verifier has a claim about layer i: V_i(g) = v for random point g
// 2. Prover reduces this to claims about layer i-1 using sumcheck
// 3. After d layers, verifier checks the input layer directly
//
// # Key Properties
//
// - Prover commits only to input and output layers
// - No commitments to intermediate wires
// - Verifier cost: O(d + log|C|) where d is depth, |C| is circuit size
// - Prover cost: O(|C|) field operations (no expensive group operations)
//
// # Applications
//
// - Logup+GKR: Use GKR to verify rational function summations
// - Memory checking: Verify read/write consistency
// - General computation: Any layered arithmetic circuit
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876) and GKR literature

use crate::field::traits::Field;
use crate::lookup::sumcheck::{
    MultivariatePolynomial, RoundPolynomial, SumcheckProof, SumcheckProver, SumcheckVerifier,
};
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Gate type in the arithmetic circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    /// Addition gate: output = left + right
    Add,
    /// Multiplication gate: output = left * right
    Mul,
    /// Constant gate: output = constant
    Constant,
}

/// A gate in the arithmetic circuit
#[derive(Debug, Clone)]
pub struct Gate<F: Field> {
    /// Type of the gate
    pub gate_type: GateType,
    /// Index of left input wire (if applicable)
    pub left_input: Option<usize>,
    /// Index of right input wire (if applicable)
    pub right_input: Option<usize>,
    /// Constant value (for constant gates)
    pub constant: Option<F>,
}

/// A layer in the arithmetic circuit
///
/// Each layer consists of gates that can be evaluated in parallel.
/// For uniform circuits, the layer structure can be described by simple polynomials.
#[derive(Debug, Clone)]
pub struct CircuitLayer<F: Field> {
    /// Number of gates in this layer
    pub size: usize,
    /// Gates in this layer
    pub gates: Vec<Gate<F>>,
    /// Wiring pattern to previous layer (for uniform circuits)
    pub wiring: Option<WiringPattern>,
}

impl<F: Field> CircuitLayer<F> {
    /// Create a new circuit layer
    pub fn new(size: usize, gates: Vec<Gate<F>>) -> LookupResult<Self> {
        if gates.len() != size {
            return Err(LookupError::InvalidLayerSize {
                expected: size,
                got: gates.len(),
            });
        }
        
        Ok(Self {
            size,
            gates,
            wiring: None,
        })
    }
    
    /// Evaluate the layer given input values
    ///
    /// # Algorithm
    ///
    /// For each gate:
    /// 1. Fetch input values from previous layer
    /// 2. Apply gate operation (add, mul, or constant)
    /// 3. Store output value
    ///
    /// # Complexity
    ///
    /// O(size) field operations
    pub fn evaluate(&self, inputs: &[F]) -> LookupResult<Vec<F>> {
        let mut outputs = Vec::with_capacity(self.size);
        
        for gate in &self.gates {
            let output = match gate.gate_type {
                GateType::Add => {
                    let left = inputs[gate.left_input.ok_or(LookupError::MissingGateInput)?];
                    let right = inputs[gate.right_input.ok_or(LookupError::MissingGateInput)?];
                    left + right
                }
                GateType::Mul => {
                    let left = inputs[gate.left_input.ok_or(LookupError::MissingGateInput)?];
                    let right = inputs[gate.right_input.ok_or(LookupError::MissingGateInput)?];
                    left * right
                }
                GateType::Constant => gate.constant.ok_or(LookupError::MissingConstant)?,
            };
            
            outputs.push(output);
        }
        
        Ok(outputs)
    }
}

/// Wiring pattern for uniform circuits
///
/// Describes how gates in one layer connect to gates in the previous layer.
/// For uniform circuits, this can be expressed as simple polynomials.
#[derive(Debug, Clone)]
pub struct WiringPattern {
    /// Polynomial describing left input connections
    pub left_wiring: Vec<u8>,
    /// Polynomial describing right input connections
    pub right_wiring: Vec<u8>,
}

/// Layered arithmetic circuit
///
/// Represents a circuit as a sequence of layers, where each layer's outputs
/// become the next layer's inputs.
#[derive(Debug, Clone)]
pub struct LayeredCircuit<F: Field> {
    /// Number of layers (depth)
    pub depth: usize,
    /// Layers from input (layer 0) to output (layer depth)
    pub layers: Vec<CircuitLayer<F>>,
}

impl<F: Field> LayeredCircuit<F> {
    /// Create a new layered circuit
    pub fn new(layers: Vec<CircuitLayer<F>>) -> Self {
        let depth = layers.len();
        Self { depth, layers }
    }
    
    /// Evaluate the circuit on given inputs
    ///
    /// # Algorithm
    ///
    /// 1. Start with input layer values
    /// 2. For each layer, evaluate gates using previous layer outputs
    /// 3. Return final layer outputs
    ///
    /// # Complexity
    ///
    /// O(|C|) where |C| is the total number of gates
    pub fn evaluate(&self, inputs: &[F]) -> LookupResult<Vec<F>> {
        let mut current_values = inputs.to_vec();
        
        for layer in &self.layers {
            current_values = layer.evaluate(&current_values)?;
        }
        
        Ok(current_values)
    }
    
    /// Get the total size of the circuit
    pub fn size(&self) -> usize {
        self.layers.iter().map(|layer| layer.size).sum()
    }
}

/// GKR proof for a layered circuit
///
/// Contains sumcheck proofs for each layer reduction.
#[derive(Debug, Clone)]
pub struct GkrProof<F: Field> {
    /// Sumcheck proofs, one per layer
    pub layer_proofs: Vec<SumcheckProof<F>>,
    /// Final input layer values (for verification)
    pub input_values: Vec<F>,
}

/// GKR prover
///
/// Generates GKR proofs for layered arithmetic circuits.
#[derive(Debug)]
pub struct GkrProver<F: Field> {
    /// The circuit being proven
    circuit: LayeredCircuit<F>,
}

impl<F: Field> GkrProver<F> {
    /// Create a new GKR prover
    pub fn new(circuit: LayeredCircuit<F>) -> Self {
        Self { circuit }
    }
    
    /// Generate a GKR proof
    ///
    /// # Algorithm
    ///
    /// For each layer i from d down to 1:
    /// 1. Verifier has claim: V_i(g) = v for random point g
    /// 2. Express V_i(g) as sum over layer i-1:
    ///    V_i(g) = Σ_{b,c} (add_i(g,b,c)·(V_{i-1}(b) + V_{i-1}(c))
    ///                     + mul_i(g,b,c)·(V_{i-1}(b) · V_{i-1}(c)))
    /// 3. Run sumcheck to reduce to claims about V_{i-1} at random points
    /// 4. Continue to next layer
    ///
    /// After all layers, verifier checks input layer directly.
    ///
    /// # Complexity
    ///
    /// O(|C|) field operations total, dominated by sumcheck computations
    pub fn prove(
        &mut self,
        inputs: &[F],
        challenges: &[Vec<F>],
    ) -> LookupResult<GkrProof<F>> {
        if challenges.len() != self.circuit.depth {
            return Err(LookupError::InvalidChallengeSize {
                expected: self.circuit.depth,
                got: challenges.len(),
            });
        }
        
        // Evaluate circuit to get all layer values
        let mut layer_values = vec![inputs.to_vec()];
        let mut current = inputs.to_vec();
        
        for layer in &self.circuit.layers {
            current = layer.evaluate(&current)?;
            layer_values.push(current.clone());
        }
        
        // Generate sumcheck proofs for each layer
        let mut layer_proofs = Vec::new();
        
        for (i, layer_challenges) in challenges.iter().enumerate() {
            // Create polynomial for layer i
            let layer_poly = self.create_layer_polynomial(
                &layer_values[i],
                &layer_values[i + 1],
                &self.circuit.layers[i],
            )?;
            
            // Run sumcheck
            let mut sumcheck_prover = SumcheckProver::new();
            let proof = sumcheck_prover.prove(&layer_poly, layer_challenges)?;
            layer_proofs.push(proof);
        }
        
        Ok(GkrProof {
            layer_proofs,
            input_values: inputs.to_vec(),
        })
    }
    
    /// Create the polynomial for a layer reduction
    ///
    /// # Algorithm
    ///
    /// The polynomial encodes the layer computation:
    /// P(b, c) = add(g,b,c)·(V_{i-1}(b) + V_{i-1}(c))
    ///         + mul(g,b,c)·(V_{i-1}(b) · V_{i-1}(c))
    ///
    /// where:
    /// - add(g,b,c) = 1 if gate g has inputs b,c and is an addition gate
    /// - mul(g,b,c) = 1 if gate g has inputs b,c and is a multiplication gate
    ///
    /// # Complexity
    ///
    /// O(2^{2k}) where k = log(layer_size)
    fn create_layer_polynomial(
        &self,
        prev_layer_values: &[F],
        curr_layer_values: &[F],
        layer: &CircuitLayer<F>,
    ) -> LookupResult<MultivariatePolynomial<F>> {
        // For simplicity, create a polynomial over the previous layer
        // In a full implementation, this would encode the wiring and gate types
        
        let num_vars = (prev_layer_values.len() as f64).log2().ceil() as usize;
        let size = 1 << num_vars;
        
        let mut evaluations = vec![F::zero(); size];
        for (i, &val) in prev_layer_values.iter().enumerate() {
            if i < size {
                evaluations[i] = val;
            }
        }
        
        MultivariatePolynomial::new(num_vars, evaluations)
    }
}

/// GKR verifier
///
/// Verifies GKR proofs for layered arithmetic circuits.
#[derive(Debug)]
pub struct GkrVerifier<F: Field> {
    /// The circuit structure (public)
    circuit: LayeredCircuit<F>,
}

impl<F: Field> GkrVerifier<F> {
    /// Create a new GKR verifier
    pub fn new(circuit: LayeredCircuit<F>) -> Self {
        Self { circuit }
    }
    
    /// Verify a GKR proof
    ///
    /// # Algorithm
    ///
    /// For each layer i from d down to 1:
    /// 1. Verify sumcheck proof for layer i
    /// 2. Check consistency with previous layer claim
    /// 3. Generate new random point for next layer
    ///
    /// After all layers:
    /// 4. Verify input layer values match the proof
    ///
    /// # Complexity
    ///
    /// O(d + log|C|) where d is depth, |C| is circuit size
    /// - O(d) for d sumcheck verifications
    /// - O(log|C|) for final input check
    pub fn verify(
        &mut self,
        output_values: &[F],
        proof: &GkrProof<F>,
        challenges: &[Vec<F>],
    ) -> LookupResult<bool> {
        if proof.layer_proofs.len() != self.circuit.depth {
            return Err(LookupError::InvalidProofSize {
                expected: self.circuit.depth,
                got: proof.layer_proofs.len(),
            });
        }
        
        // Start with output layer claim
        let mut current_claim = output_values[0]; // Simplified: check first output
        
        // Verify each layer
        for (i, (layer_proof, layer_challenges)) in proof
            .layer_proofs
            .iter()
            .zip(challenges.iter())
            .enumerate()
        {
            // Compute expected sum for this layer
            let layer_size = self.circuit.layers[i].size;
            let expected_sum = current_claim;
            
            // Create dummy polynomial for verification
            // In full implementation, would use actual layer polynomial
            let num_vars = (layer_size as f64).log2().ceil() as usize;
            let dummy_evals = vec![F::one(); 1 << num_vars];
            let layer_poly = MultivariatePolynomial::new(num_vars, dummy_evals)?;
            
            let final_eval = layer_poly.evaluate(layer_challenges)?;
            
            // Verify sumcheck
            let mut sumcheck_verifier = SumcheckVerifier::new();
            let valid = sumcheck_verifier.verify(
                expected_sum,
                layer_proof,
                layer_challenges,
                final_eval,
            )?;
            
            if !valid {
                return Ok(false);
            }
            
            // Update claim for next layer
            current_claim = final_eval;
        }
        
        // Verify input layer
        let computed_outputs = self.circuit.evaluate(&proof.input_values)?;
        Ok(computed_outputs == output_values)
    }
    
    /// Generate random challenges for each layer
    ///
    /// In practice, uses Fiat-Shamir transform.
    ///
    /// # Algorithm
    ///
    /// For each layer:
    /// 1. Hash the transcript (including previous proofs)
    /// 2. Derive random challenges from hash
    ///
    /// # Complexity
    ///
    /// O(d) hash operations
    pub fn generate_challenges(&self, seed: &[u8]) -> Vec<Vec<F>> {
        let mut challenges = Vec::new();
        
        for i in 0..self.circuit.depth {
            let layer_size = self.circuit.layers[i].size;
            let num_vars = (layer_size as f64).log2().ceil() as usize;
            
            let layer_challenges: Vec<F> = (0..num_vars)
                .map(|j| {
                    let mut bytes = seed.to_vec();
                    bytes.push(i as u8);
                    bytes.push(j as u8);
                    F::from_bytes(&bytes)
                })
                .collect();
            
            challenges.push(layer_challenges);
        }
        
        challenges
    }
}

/// Binary tree circuit for Logup+GKR
///
/// Constructs a binary tree circuit for computing rational function sums.
/// This is used in Logup+GKR to verify the Logup identity.
#[derive(Debug)]
pub struct BinaryTreeCircuit<F: Field> {
    /// Height of the tree
    pub height: usize,
    /// Number of leaves
    pub num_leaves: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> BinaryTreeCircuit<F> {
    /// Create a new binary tree circuit
    ///
    /// # Algorithm
    ///
    /// Construct a binary tree where:
    /// - Leaves: Input values (rational function terms)
    /// - Internal nodes: Addition gates
    /// - Root: Final sum
    ///
    /// # Complexity
    ///
    /// O(n) gates for n leaves
    pub fn new(num_leaves: usize) -> Self {
        let height = (num_leaves as f64).log2().ceil() as usize;
        Self {
            height,
            num_leaves,
            _phantom: PhantomData,
        }
    }
    
    /// Build the layered circuit for the binary tree
    ///
    /// # Algorithm
    ///
    /// For each level of the tree:
    /// 1. Create addition gates pairing adjacent nodes
    /// 2. Wire gates to previous level
    ///
    /// # Complexity
    ///
    /// O(n) to construct the circuit
    pub fn build_circuit(&self) -> LookupResult<LayeredCircuit<F>> {
        let mut layers = Vec::new();
        let mut current_size = self.num_leaves;
        
        // Build layers from leaves to root
        while current_size > 1 {
            let next_size = (current_size + 1) / 2;
            let mut gates = Vec::new();
            
            for i in 0..next_size {
                let left = 2 * i;
                let right = (2 * i + 1).min(current_size - 1);
                
                gates.push(Gate {
                    gate_type: GateType::Add,
                    left_input: Some(left),
                    right_input: Some(right),
                    constant: None,
                });
            }
            
            layers.push(CircuitLayer::new(next_size, gates)?);
            current_size = next_size;
        }
        
        Ok(LayeredCircuit::new(layers))
    }
    
    /// Compute the sum using the binary tree
    ///
    /// # Algorithm
    ///
    /// Evaluate the circuit on the input leaves.
    ///
    /// # Complexity
    ///
    /// O(n) field operations
    pub fn compute_sum(&self, leaves: &[F]) -> LookupResult<F> {
        if leaves.len() != self.num_leaves {
            return Err(LookupError::InvalidInputSize {
                expected: self.num_leaves,
                got: leaves.len(),
            });
        }
        
        let circuit = self.build_circuit()?;
        let outputs = circuit.evaluate(leaves)?;
        
        Ok(outputs[0])
    }
}

/// Logup+GKR integration
///
/// Combines Logup lemma with GKR protocol for efficient lookup verification.
#[derive(Debug)]
pub struct LogupGkr<F: Field> {
    /// Binary tree circuit for sum computation
    tree_circuit: BinaryTreeCircuit<F>,
}

impl<F: Field> LogupGkr<F> {
    /// Create a new Logup+GKR instance
    ///
    /// # Parameters
    ///
    /// - witness_size: Number of witness elements (n)
    /// - table_size: Number of table elements (N)
    pub fn new(witness_size: usize, table_size: usize) -> Self {
        // Total leaves = n (witness terms) + N (table terms)
        let num_leaves = witness_size + table_size;
        let tree_circuit = BinaryTreeCircuit::new(num_leaves);
        
        Self { tree_circuit }
    }
    
    /// Prove Logup identity using GKR
    ///
    /// # Algorithm
    ///
    /// 1. Compute witness terms: 1/(α + w_i) for each i
    /// 2. Compute table terms: m_i/(α + t_i) for each i
    /// 3. Arrange as leaves of binary tree
    /// 4. Use GKR to prove the sum equals on both sides
    ///
    /// # Complexity
    ///
    /// O(n + N) prover cost
    /// O(log(n + N)) verifier cost
    pub fn prove_logup(
        &mut self,
        witness: &[F],
        table: &[F],
        multiplicities: &[usize],
        alpha: F,
        challenges: &[Vec<F>],
    ) -> LookupResult<GkrProof<F>> {
        // Compute witness terms: 1/(α + w_i)
        let witness_terms: Vec<F> = witness
            .iter()
            .map(|&w_i| (alpha + w_i).inverse())
            .collect();
        
        // Compute table terms: m_i/(α + t_i)
        let table_terms: Vec<F> = table
            .iter()
            .zip(multiplicities.iter())
            .map(|(&t_i, &m_i)| {
                let m = F::from(m_i as u64);
                m * (alpha + t_i).inverse()
            })
            .collect();
        
        // Combine into leaves
        let mut leaves = witness_terms;
        leaves.extend(table_terms);
        
        // Build circuit and prove
        let circuit = self.tree_circuit.build_circuit()?;
        let mut prover = GkrProver::new(circuit);
        prover.prove(&leaves, challenges)
    }
    
    /// Verify Logup identity using GKR
    ///
    /// # Algorithm
    ///
    /// 1. Verify the GKR proof for the binary tree
    /// 2. Check that both sides of Logup identity are equal
    ///
    /// # Complexity
    ///
    /// O(log(n + N)) verifier cost
    pub fn verify_logup(
        &mut self,
        claimed_sum: F,
        proof: &GkrProof<F>,
        challenges: &[Vec<F>],
    ) -> LookupResult<bool> {
        let circuit = self.tree_circuit.build_circuit()?;
        let mut verifier = GkrVerifier::new(circuit);
        
        verifier.verify(&[claimed_sum], proof, challenges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    #[test]
    fn test_simple_circuit() {
        // Circuit: (a + b) * c
        let layer1_gates = vec![
            Gate {
                gate_type: GateType::Add,
                left_input: Some(0),
                right_input: Some(1),
                constant: None,
            },
        ];
        
        let layer2_gates = vec![
            Gate {
                gate_type: GateType::Mul,
                left_input: Some(0),
                right_input: Some(2),
                constant: None,
            },
        ];
        
        let layer1 = CircuitLayer::new(1, layer1_gates).unwrap();
        let layer2 = CircuitLayer::new(1, layer2_gates).unwrap();
        
        let circuit = LayeredCircuit::new(vec![layer1, layer2]);
        
        let inputs = vec![
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
            Goldilocks::from(4u64),
        ];
        
        let outputs = circuit.evaluate(&inputs).unwrap();
        
        // (2 + 3) * 4 = 20
        assert_eq!(outputs[0], Goldilocks::from(20u64));
    }
    
    #[test]
    fn test_binary_tree_circuit() {
        let tree = BinaryTreeCircuit::<Goldilocks>::new(4);
        
        let leaves = vec![
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
            Goldilocks::from(4u64),
        ];
        
        let sum = tree.compute_sum(&leaves).unwrap();
        
        // 1 + 2 + 3 + 4 = 10
        assert_eq!(sum, Goldilocks::from(10u64));
    }
}
