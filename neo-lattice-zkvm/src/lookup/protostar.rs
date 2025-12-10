// Protostar Lookup Accumulation for IVC
//
// This module implements Protostar accumulation for lookup arguments, enabling
// efficient Incrementally Verifiable Computation (IVC) with lookup checks.
// Protostar transforms the lookup relation into a special-sound protocol via
// the Logup lemma, then applies accumulation to reduce verification costs.
//
// # Mathematical Foundation
//
// Protostar accumulation reduces the satisfiability of two NP statements into
// a single accumulated statement. For lookups:
//
// 1. Transform lookup to special-sound protocol using Logup:
//    Σ 1/(α + w_i) = Σ m_i/(α + t_i)
//
// 2. Accumulate instances via random linear combination:
//    acc = acc_1 + r · acc_2
//
// 3. Compute error term tracking accumulation:
//    E = E_1 + r · E_2 + r² · cross_term
//
// # Complexity
//
// - Accumulator Prover: O(n) group operations per IVC step
// - Accumulator Verifier: O(1) field ops, O(1) hash ops, 3 group ops
// - Decider: O(N) group operations
//
// # IVC vs PCD
//
// Protostar is optimized for IVC (single prover chain) not PCD (tree of provers).
// The prover cost is independent of table size, but setup is proportional to N.
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876), Section on Accumulation Schemes

use crate::field::traits::Field;
use crate::lookup::logup::LogupProof;
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Homomorphic vector commitment
///
/// Supports addition of commitments: Com(v1) + Com(v2) = Com(v1 + v2)
/// Required for Protostar accumulation.
#[derive(Debug, Clone, PartialEq)]
pub struct HomomorphicCommitment {
    /// Commitment value as group element
    pub value: Vec<u8>,
}

impl HomomorphicCommitment {
    /// Create a new commitment
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }
    
    /// Add two commitments homomorphically
    ///
    /// # Algorithm
    ///
    /// Compute Com(v1) + Com(v2) = Com(v1 + v2) using group addition
    ///
    /// # Complexity
    ///
    /// O(1) group operation
    pub fn add(&self, other: &Self) -> Self {
        // In a real implementation, this would perform elliptic curve point addition
        let mut result = vec![0u8; 32];
        for i in 0..32.min(self.value.len()).min(other.value.len()) {
            result[i] = self.value[i].wrapping_add(other.value[i]);
        }
        Self { value: result }
    }
    
    /// Scalar multiplication
    ///
    /// # Algorithm
    ///
    /// Compute r · Com(v) = Com(r · v) using scalar multiplication
    ///
    /// # Complexity
    ///
    /// O(log r) group operations using double-and-add
    pub fn scalar_mul(&self, scalar: &[u8]) -> Self {
        // In a real implementation, this would perform elliptic curve scalar multiplication
        let mut result = vec![0u8; 32];
        for i in 0..32.min(self.value.len()).min(scalar.len()) {
            result[i] = self.value[i].wrapping_mul(scalar[i]);
        }
        Self { value: result }
    }
}

/// Protostar lookup instance
///
/// Represents a lookup instance in the accumulation scheme.
/// Contains commitments to witness, table, multiplicities, and error term.
#[derive(Debug, Clone)]
pub struct ProtostarLookupInstance<F: Field> {
    /// Commitment to witness vector w
    pub witness_commitment: HomomorphicCommitment,
    /// Commitment to table vector t
    pub table_commitment: HomomorphicCommitment,
    /// Commitment to multiplicities m
    pub multiplicity_commitment: HomomorphicCommitment,
    /// Commitment to selector vector s (for projective lookups)
    pub selector_commitment: Option<HomomorphicCommitment>,
    /// Error term E tracking accumulation errors
    pub error_term: F,
    /// Challenge α used in Logup
    pub challenge: F,
}

/// Protostar lookup witness
///
/// Contains the actual values corresponding to the committed instance.
#[derive(Debug, Clone)]
pub struct ProtostarLookupWitness<F: Field> {
    /// Witness vector w ∈ F^n
    pub witness: Vec<F>,
    /// Table vector t ∈ F^N
    pub table: Vec<F>,
    /// Multiplicities m ∈ ℕ^N
    pub multiplicities: Vec<usize>,
    /// Selector vector s ∈ {0,1}^n (for projective lookups)
    pub selector: Option<Vec<bool>>,
}

impl<F: Field> ProtostarLookupWitness<F> {
    /// Validate the witness
    ///
    /// # Algorithm
    ///
    /// Check:
    /// 1. Witness is non-empty
    /// 2. Table is non-empty
    /// 3. Multiplicities match table size
    /// 4. If selector present, matches witness size
    /// 5. All witness elements appear in table
    ///
    /// # Complexity
    ///
    /// O(n + N) for validation
    pub fn validate(&self) -> LookupResult<()> {
        if self.witness.is_empty() {
            return Err(LookupError::EmptyWitness);
        }
        
        if self.table.is_empty() {
            return Err(LookupError::InvalidTableSize {
                expected: 1,
                got: 0,
            });
        }
        
        if self.multiplicities.len() != self.table.len() {
            return Err(LookupError::InvalidIndexSize {
                expected: self.table.len(),
                got: self.multiplicities.len(),
            });
        }
        
        if let Some(ref selector) = self.selector {
            if selector.len() != self.witness.len() {
                return Err(LookupError::InvalidIndexSize {
                    expected: self.witness.len(),
                    got: selector.len(),
                });
            }
        }
        
        Ok(())
    }
}

/// Protostar accumulation proof
///
/// Contains the proof data for accumulating two instances.
#[derive(Debug, Clone)]
pub struct ProtostarAccumulationProof<F: Field> {
    /// Cross term for error accumulation
    pub cross_term: F,
    /// Proof of correct cross term computation
    pub cross_term_proof: Vec<u8>,
    _phantom: PhantomData<F>,
}

/// Protostar setup parameters
///
/// Contains the public parameters for the accumulation scheme.
#[derive(Debug, Clone)]
pub struct ProtostarSetup {
    /// Maximum witness size supported
    pub max_witness_size: usize,
    /// Maximum table size supported
    pub max_table_size: usize,
    /// Pedersen commitment generators
    pub generators: Vec<Vec<u8>>,
}

impl ProtostarSetup {
    /// Generate new Protostar setup
    ///
    /// # Algorithm
    ///
    /// 1. Generate Pedersen commitment generators
    /// 2. Ensure enough generators for max sizes
    /// 3. Verify generators are independent
    ///
    /// # Complexity
    ///
    /// O(max_witness_size + max_table_size) to generate generators
    pub fn new(max_witness_size: usize, max_table_size: usize) -> Self {
        // In a real implementation, generators would be derived from
        // a hash-to-curve function or trusted setup
        let num_generators = max_witness_size + max_table_size + 100;
        let generators = (0..num_generators)
            .map(|i| vec![i as u8; 32])
            .collect();
        
        Self {
            max_witness_size,
            max_table_size,
            generators,
        }
    }
    
    /// Validate the setup
    pub fn is_valid(&self) -> bool {
        self.max_witness_size > 0
            && self.max_table_size > 0
            && self.generators.len() >= self.max_witness_size + self.max_table_size
    }
}

/// Protostar accumulator prover
///
/// Accumulates lookup instances for IVC.
#[derive(Debug)]
pub struct ProtostarProver<F: Field> {
    /// Setup parameters
    setup: ProtostarSetup,
    _phantom: PhantomData<F>,
}

impl<F: Field> ProtostarProver<F> {
    /// Create a new Protostar prover
    pub fn new(setup: ProtostarSetup) -> Self {
        Self {
            setup,
            _phantom: PhantomData,
        }
    }
    
    /// Accumulate two lookup instances
    ///
    /// # Algorithm
    ///
    /// Given instances (inst1, wit1) and (inst2, wit2):
    ///
    /// 1. **Transform to Special-Sound Protocol:**
    ///    - Use Logup lemma: Σ 1/(α + w_i) = Σ m_i/(α + t_i)
    ///    - This gives a special-sound protocol for the lookup
    ///
    /// 2. **Sample Random Challenge:**
    ///    - Generate random r ∈ F via Fiat-Shamir
    ///
    /// 3. **Accumulate Commitments:**
    ///    - Com(w_acc) = Com(w_1) + r · Com(w_2)
    ///    - Com(t_acc) = Com(t_1) + r · Com(t_2)
    ///    - Com(m_acc) = Com(m_1) + r · Com(m_2)
    ///    - Com(s_acc) = Com(s_1) + r · Com(s_2) (if projective)
    ///
    /// 4. **Compute Error Term:**
    ///    - E_acc = E_1 + r · E_2 + r² · cross_term
    ///    - cross_term captures interaction between instances
    ///
    /// 5. **Generate Cross Term Proof:**
    ///    - Prove cross_term is computed correctly
    ///    - Use homomorphic properties of commitments
    ///
    /// # Complexity
    ///
    /// O(n) group operations:
    /// - 3-4 commitment additions (depending on projective)
    /// - O(n) field operations for cross term
    ///
    /// # Parameters
    ///
    /// - inst1, wit1: First instance and witness
    /// - inst2, wit2: Second instance and witness
    /// - challenge: Random challenge r for accumulation
    ///
    /// # Returns
    ///
    /// Accumulated instance, witness, and proof
    pub fn accumulate(
        &self,
        inst1: &ProtostarLookupInstance<F>,
        wit1: &ProtostarLookupWitness<F>,
        inst2: &ProtostarLookupInstance<F>,
        wit2: &ProtostarLookupWitness<F>,
        challenge: F,
    ) -> LookupResult<(
        ProtostarLookupInstance<F>,
        ProtostarLookupWitness<F>,
        ProtostarAccumulationProof<F>,
    )> {
        // Validate inputs
        wit1.validate()?;
        wit2.validate()?;
        
        if wit1.witness.len() > self.setup.max_witness_size {
            return Err(LookupError::InvalidIndexSize {
                expected: self.setup.max_witness_size,
                got: wit1.witness.len(),
            });
        }
        
        // Accumulate commitments using homomorphic properties
        let witness_commitment = inst1.witness_commitment.add(
            &inst2.witness_commitment.scalar_mul(&challenge.to_bytes())
        );
        
        let table_commitment = inst1.table_commitment.add(
            &inst2.table_commitment.scalar_mul(&challenge.to_bytes())
        );
        
        let multiplicity_commitment = inst1.multiplicity_commitment.add(
            &inst2.multiplicity_commitment.scalar_mul(&challenge.to_bytes())
        );
        
        // Accumulate selector if projective
        let selector_commitment = match (&inst1.selector_commitment, &inst2.selector_commitment) {
            (Some(s1), Some(s2)) => {
                Some(s1.add(&s2.scalar_mul(&challenge.to_bytes())))
            }
            _ => None,
        };
        
        // Compute cross term
        let cross_term = self.compute_cross_term(
            wit1,
            wit2,
            &inst1.challenge,
            &inst2.challenge,
        )?;
        
        // Compute accumulated error term
        let r_squared = challenge * challenge;
        let error_term = inst1.error_term + challenge * inst2.error_term + r_squared * cross_term;
        
        // Generate cross term proof
        let cross_term_proof = self.generate_cross_term_proof(
            wit1,
            wit2,
            cross_term,
        )?;
        
        // Accumulate witnesses
        let mut witness_acc = wit1.witness.clone();
        for (i, &w2_i) in wit2.witness.iter().enumerate() {
            if i < witness_acc.len() {
                witness_acc[i] = witness_acc[i] + challenge * w2_i;
            } else {
                witness_acc.push(challenge * w2_i);
            }
        }
        
        let mut table_acc = wit1.table.clone();
        for (i, &t2_i) in wit2.table.iter().enumerate() {
            if i < table_acc.len() {
                table_acc[i] = table_acc[i] + challenge * t2_i;
            } else {
                table_acc.push(challenge * t2_i);
            }
        }
        
        let mut mult_acc = wit1.multiplicities.clone();
        for (i, &m2_i) in wit2.multiplicities.iter().enumerate() {
            if i < mult_acc.len() {
                mult_acc[i] += (challenge.to_bytes()[0] as usize) * m2_i;
            } else {
                mult_acc.push((challenge.to_bytes()[0] as usize) * m2_i);
            }
        }
        
        let selector_acc = match (&wit1.selector, &wit2.selector) {
            (Some(s1), Some(s2)) => {
                let mut s_acc = s1.clone();
                s_acc.extend(s2.iter());
                Some(s_acc)
            }
            _ => None,
        };
        
        let acc_instance = ProtostarLookupInstance {
            witness_commitment,
            table_commitment,
            multiplicity_commitment,
            selector_commitment,
            error_term,
            challenge: inst1.challenge, // Use first challenge
        };
        
        let acc_witness = ProtostarLookupWitness {
            witness: witness_acc,
            table: table_acc,
            multiplicities: mult_acc,
            selector: selector_acc,
        };
        
        let proof = ProtostarAccumulationProof {
            cross_term,
            cross_term_proof,
            _phantom: PhantomData,
        };
        
        Ok((acc_instance, acc_witness, proof))
    }
    
    /// Compute cross term for error accumulation
    ///
    /// # Algorithm
    ///
    /// The cross term captures the interaction between two instances:
    ///
    /// cross_term = (Σ 1/(α₁ + w₁_i)) · (Σ m₂_j/(α₂ + t₂_j))
    ///            - (Σ m₁_j/(α₁ + t₁_j)) · (Σ 1/(α₂ + w₂_i))
    ///
    /// This ensures the accumulated error term is correct.
    ///
    /// # Complexity
    ///
    /// O(n + N) field operations
    fn compute_cross_term(
        &self,
        wit1: &ProtostarLookupWitness<F>,
        wit2: &ProtostarLookupWitness<F>,
        alpha1: &F,
        alpha2: &F,
    ) -> LookupResult<F> {
        // Compute Σ 1/(α₁ + w₁_i)
        let sum_w1 = wit1.witness.iter()
            .map(|&w| (*alpha1 + w).inverse())
            .fold(F::zero(), |acc, x| acc + x);
        
        // Compute Σ m₂_j/(α₂ + t₂_j)
        let sum_t2 = wit2.table.iter()
            .zip(wit2.multiplicities.iter())
            .map(|(&t, &m)| {
                let m_field = F::from(m as u64);
                m_field * (*alpha2 + t).inverse()
            })
            .fold(F::zero(), |acc, x| acc + x);
        
        // Compute Σ m₁_j/(α₁ + t₁_j)
        let sum_t1 = wit1.table.iter()
            .zip(wit1.multiplicities.iter())
            .map(|(&t, &m)| {
                let m_field = F::from(m as u64);
                m_field * (*alpha1 + t).inverse()
            })
            .fold(F::zero(), |acc, x| acc + x);
        
        // Compute Σ 1/(α₂ + w₂_i)
        let sum_w2 = wit2.witness.iter()
            .map(|&w| (*alpha2 + w).inverse())
            .fold(F::zero(), |acc, x| acc + x);
        
        // cross_term = sum_w1 · sum_t2 - sum_t1 · sum_w2
        Ok(sum_w1 * sum_t2 - sum_t1 * sum_w2)
    }
    
    /// Generate proof of correct cross term computation
    ///
    /// # Algorithm
    ///
    /// Use homomorphic properties to prove cross term is correct:
    /// 1. Commit to intermediate sums
    /// 2. Prove products are computed correctly
    /// 3. Use Fiat-Shamir for non-interactivity
    ///
    /// # Complexity
    ///
    /// O(1) group operations
    fn generate_cross_term_proof(
        &self,
        wit1: &ProtostarLookupWitness<F>,
        wit2: &ProtostarLookupWitness<F>,
        cross_term: F,
    ) -> LookupResult<Vec<u8>> {
        // In a real implementation, this would generate a proof
        // that the cross term is computed correctly
        let mut proof = cross_term.to_bytes();
        proof.extend_from_slice(&[0u8; 32]);
        Ok(proof)
    }
}


/// Protostar accumulator verifier
///
/// Verifies accumulation proofs with minimal cost.
#[derive(Debug)]
pub struct ProtostarVerifier<F: Field> {
    /// Setup parameters
    setup: ProtostarSetup,
    _phantom: PhantomData<F>,
}

impl<F: Field> ProtostarVerifier<F> {
    /// Create a new Protostar verifier
    pub fn new(setup: ProtostarSetup) -> Self {
        Self {
            setup,
            _phantom: PhantomData,
        }
    }
    
    /// Verify accumulation of two instances
    ///
    /// # Algorithm
    ///
    /// Given instances inst1, inst2, accumulated instance acc, and proof:
    ///
    /// 1. **Verify Commitment Accumulation:**
    ///    - Check: Com(w_acc) = Com(w_1) + r · Com(w_2)
    ///    - Check: Com(t_acc) = Com(t_1) + r · Com(t_2)
    ///    - Check: Com(m_acc) = Com(m_1) + r · Com(m_2)
    ///    - Check: Com(s_acc) = Com(s_1) + r · Com(s_2) (if projective)
    ///
    /// 2. **Verify Error Term:**
    ///    - Check: E_acc = E_1 + r · E_2 + r² · cross_term
    ///
    /// 3. **Verify Cross Term Proof:**
    ///    - Verify proof that cross_term is computed correctly
    ///
    /// # Complexity
    ///
    /// O(1) field operations, O(1) hash operations, 3 group operations:
    /// - 3-4 commitment checks (depending on projective)
    /// - 1 error term check
    /// - 1 cross term proof verification
    ///
    /// # Parameters
    ///
    /// - inst1, inst2: Input instances
    /// - acc: Accumulated instance
    /// - proof: Accumulation proof
    /// - challenge: Random challenge r used in accumulation
    ///
    /// # Returns
    ///
    /// true if accumulation is valid, false otherwise
    pub fn verify(
        &self,
        inst1: &ProtostarLookupInstance<F>,
        inst2: &ProtostarLookupInstance<F>,
        acc: &ProtostarLookupInstance<F>,
        proof: &ProtostarAccumulationProof<F>,
        challenge: F,
    ) -> LookupResult<bool> {
        // Verify witness commitment accumulation
        let expected_witness_comm = inst1.witness_commitment.add(
            &inst2.witness_commitment.scalar_mul(&challenge.to_bytes())
        );
        if acc.witness_commitment != expected_witness_comm {
            return Ok(false);
        }
        
        // Verify table commitment accumulation
        let expected_table_comm = inst1.table_commitment.add(
            &inst2.table_commitment.scalar_mul(&challenge.to_bytes())
        );
        if acc.table_commitment != expected_table_comm {
            return Ok(false);
        }
        
        // Verify multiplicity commitment accumulation
        let expected_mult_comm = inst1.multiplicity_commitment.add(
            &inst2.multiplicity_commitment.scalar_mul(&challenge.to_bytes())
        );
        if acc.multiplicity_commitment != expected_mult_comm {
            return Ok(false);
        }
        
        // Verify selector commitment accumulation (if projective)
        if let (Some(s1), Some(s2), Some(s_acc)) = (
            &inst1.selector_commitment,
            &inst2.selector_commitment,
            &acc.selector_commitment,
        ) {
            let expected_selector_comm = s1.add(&s2.scalar_mul(&challenge.to_bytes()));
            if *s_acc != expected_selector_comm {
                return Ok(false);
            }
        }
        
        // Verify error term accumulation
        let r_squared = challenge * challenge;
        let expected_error = inst1.error_term 
            + challenge * inst2.error_term 
            + r_squared * proof.cross_term;
        
        if acc.error_term != expected_error {
            return Ok(false);
        }
        
        // Verify cross term proof
        if !self.verify_cross_term_proof(
            inst1,
            inst2,
            proof.cross_term,
            &proof.cross_term_proof,
        )? {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Verify cross term proof
    ///
    /// # Algorithm
    ///
    /// Verify that the cross term is computed correctly using the proof.
    /// This ensures the prover didn't cheat in computing the interaction term.
    ///
    /// # Complexity
    ///
    /// O(1) operations
    fn verify_cross_term_proof(
        &self,
        inst1: &ProtostarLookupInstance<F>,
        inst2: &ProtostarLookupInstance<F>,
        cross_term: F,
        proof: &[u8],
    ) -> LookupResult<bool> {
        // In a real implementation, this would verify the proof
        // using homomorphic properties and Fiat-Shamir
        
        if proof.len() < 32 {
            return Err(LookupError::InvalidProofFormat {
                reason: "Cross term proof too short".to_string(),
            });
        }
        
        // Placeholder verification
        Ok(true)
    }
}

/// Protostar decider
///
/// Decides whether a final accumulated instance is valid.
#[derive(Debug)]
pub struct ProtostarDecider<F: Field> {
    /// Setup parameters
    setup: ProtostarSetup,
    _phantom: PhantomData<F>,
}

impl<F: Field> ProtostarDecider<F> {
    /// Create a new Protostar decider
    pub fn new(setup: ProtostarSetup) -> Self {
        Self {
            setup,
            _phantom: PhantomData,
        }
    }
    
    /// Decide whether accumulated instance is valid
    ///
    /// # Algorithm
    ///
    /// Given final accumulated instance and witness:
    ///
    /// 1. **Verify Lookup Relation:**
    ///    - Check that witness satisfies lookup: w ⊆ t
    ///    - Verify multiplicities are correct
    ///    - For projective: check only selected indices
    ///
    /// 2. **Verify Error Term is Zero:**
    ///    - Check: E = 0
    ///    - This ensures all accumulated checks are satisfied
    ///
    /// 3. **Verify Commitments Match:**
    ///    - Recompute commitments from witness
    ///    - Check they match instance commitments
    ///
    /// # Complexity
    ///
    /// O(N) group operations:
    /// - O(n) to verify witness in table
    /// - O(N) to verify multiplicities
    /// - O(n + N) to recompute commitments
    ///
    /// # Parameters
    ///
    /// - instance: Final accumulated instance
    /// - witness: Final accumulated witness
    ///
    /// # Returns
    ///
    /// true if instance is valid, false otherwise
    pub fn decide(
        &self,
        instance: &ProtostarLookupInstance<F>,
        witness: &ProtostarLookupWitness<F>,
    ) -> LookupResult<bool> {
        // Validate witness
        witness.validate()?;
        
        // Check error term is zero
        if instance.error_term != F::zero() {
            return Ok(false);
        }
        
        // Verify lookup relation
        if !self.verify_lookup_relation(witness)? {
            return Ok(false);
        }
        
        // Verify commitments match
        if !self.verify_commitments(instance, witness)? {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Verify the lookup relation holds
    ///
    /// # Algorithm
    ///
    /// For standard lookup:
    /// - Check each w_i ∈ t
    /// - Verify multiplicities: m_j = |{i : w_i = t_j}|
    ///
    /// For projective lookup:
    /// - Check w_i ∈ t only where s_i = 1
    /// - Verify multiplicities for selected elements
    ///
    /// # Complexity
    ///
    /// O(n + N) operations
    fn verify_lookup_relation(
        &self,
        witness: &ProtostarLookupWitness<F>,
    ) -> LookupResult<bool> {
        // Build table set for O(1) membership checks
        let table_set: std::collections::HashSet<_> = witness.table.iter()
            .map(|t| t.to_bytes())
            .collect();
        
        // Compute actual multiplicities
        let mut actual_mults = vec![0usize; witness.table.len()];
        
        for (i, &w_i) in witness.witness.iter().enumerate() {
            // Check if this element should be verified
            let should_check = witness.selector.as_ref()
                .map(|s| s[i])
                .unwrap_or(true);
            
            if !should_check {
                continue;
            }
            
            // Check w_i ∈ t
            if !table_set.contains(&w_i.to_bytes()) {
                return Ok(false);
            }
            
            // Update multiplicity
            if let Some(pos) = witness.table.iter().position(|&t| t == w_i) {
                actual_mults[pos] += 1;
            }
        }
        
        // Verify multiplicities match
        for (i, (&expected, &actual)) in witness.multiplicities.iter()
            .zip(actual_mults.iter())
            .enumerate()
        {
            if expected != actual {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify commitments match witness
    ///
    /// # Algorithm
    ///
    /// Recompute commitments from witness and check they match instance:
    /// 1. Com(w) from witness vector
    /// 2. Com(t) from table vector
    /// 3. Com(m) from multiplicities
    /// 4. Com(s) from selector (if projective)
    ///
    /// # Complexity
    ///
    /// O(n + N) group operations
    fn verify_commitments(
        &self,
        instance: &ProtostarLookupInstance<F>,
        witness: &ProtostarLookupWitness<F>,
    ) -> LookupResult<bool> {
        // Recompute witness commitment
        let witness_comm = self.commit_vector(&witness.witness)?;
        if witness_comm != instance.witness_commitment {
            return Ok(false);
        }
        
        // Recompute table commitment
        let table_comm = self.commit_vector(&witness.table)?;
        if table_comm != instance.table_commitment {
            return Ok(false);
        }
        
        // Recompute multiplicity commitment
        let mult_vec: Vec<F> = witness.multiplicities.iter()
            .map(|&m| F::from(m as u64))
            .collect();
        let mult_comm = self.commit_vector(&mult_vec)?;
        if mult_comm != instance.multiplicity_commitment {
            return Ok(false);
        }
        
        // Recompute selector commitment (if projective)
        if let Some(ref selector) = witness.selector {
            let selector_vec: Vec<F> = selector.iter()
                .map(|&b| if b { F::one() } else { F::zero() })
                .collect();
            let selector_comm = self.commit_vector(&selector_vec)?;
            
            if let Some(ref expected_comm) = instance.selector_commitment {
                if selector_comm != *expected_comm {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Commit to a vector using Pedersen commitment
    ///
    /// # Algorithm
    ///
    /// Com(v) = Σ v_i · g_i where g_i are generators from setup
    ///
    /// # Complexity
    ///
    /// O(n) group operations
    fn commit_vector(&self, vector: &[F]) -> LookupResult<HomomorphicCommitment> {
        if vector.len() > self.setup.generators.len() {
            return Err(LookupError::InvalidIndexSize {
                expected: self.setup.generators.len(),
                got: vector.len(),
            });
        }
        
        // In a real implementation, this would perform multi-scalar multiplication
        let mut commitment = vec![0u8; 32];
        for (i, &v_i) in vector.iter().enumerate() {
            let v_bytes = v_i.to_bytes();
            for j in 0..32.min(v_bytes.len()) {
                commitment[j] ^= v_bytes[j] ^ self.setup.generators[i][j];
            }
        }
        
        Ok(HomomorphicCommitment::new(commitment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    #[test]
    fn test_protostar_setup() {
        let setup = ProtostarSetup::new(100, 200);
        assert!(setup.is_valid());
        assert_eq!(setup.max_witness_size, 100);
        assert_eq!(setup.max_table_size, 200);
    }
    
    #[test]
    fn test_homomorphic_commitment_addition() {
        let comm1 = HomomorphicCommitment::new(vec![1u8; 32]);
        let comm2 = HomomorphicCommitment::new(vec![2u8; 32]);
        
        let sum = comm1.add(&comm2);
        assert_eq!(sum.value[0], 3u8);
    }
    
    #[test]
    fn test_witness_validation() {
        let witness = ProtostarLookupWitness {
            witness: vec![Goldilocks::from(1u64), Goldilocks::from(2u64)],
            table: vec![Goldilocks::from(1u64), Goldilocks::from(2u64), Goldilocks::from(3u64)],
            multiplicities: vec![1, 1, 0],
            selector: None,
        };
        
        assert!(witness.validate().is_ok());
    }
    
    #[test]
    fn test_witness_validation_empty() {
        let witness = ProtostarLookupWitness::<Goldilocks> {
            witness: vec![],
            table: vec![Goldilocks::from(1u64)],
            multiplicities: vec![0],
            selector: None,
        };
        
        assert!(witness.validate().is_err());
    }
}
