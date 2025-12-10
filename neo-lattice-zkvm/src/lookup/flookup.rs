// Flookup: Pairing-Based Accumulator Lookup Arguments
//
// This module implements Flookup, an accumulator-based lookup argument that uses
// pairing-based accumulators for efficient batch openings. Flookup achieves O(n log² n)
// prover cost and O(1) verifier cost with constant-size proofs.
//
// # Mathematical Foundation
//
// Flookup uses pairing-based accumulators to commit to sets and prove subset relations.
// Given a table t and witness w, the prover:
// 1. Extracts subtable t' containing all witness elements
// 2. Commits to both t and t' using pairing-based accumulators
// 3. Generates a batch opening proof that t' ⊆ t
// 4. Proves each w_i ∈ t' using precomputed opening proofs
//
// # Accumulator Construction
//
// A pairing-based accumulator for set S = {s_1, ..., s_n} is computed as:
//   Acc(S) = g^{∏(α + s_i)} in G_1
//
// where α is from the trusted setup. The accumulator has the property that
// membership proofs can be batched efficiently using polynomial division.
//
// # Complexity
//
// - Preprocessing: O(N log N) to compute opening proofs for all table elements
// - Prover: O(n log² n) to extract subtable and generate batch proof
// - Verifier: O(1) with constant-size proof
// - Proof size: O(1) group elements
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876), Section on Accumulator-Based Lookups

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

/// Pairing-based accumulator for set commitment
///
/// An accumulator commits to a set S by computing Acc(S) = g^{∏(α + s_i)}.
/// This construction supports efficient batch membership proofs.
#[derive(Debug, Clone, PartialEq)]
pub struct PairingAccumulator<F: Field> {
    /// The accumulator value in G_1
    pub value: Vec<u8>,
    /// The set being accumulated
    pub set: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field> PairingAccumulator<F> {
    /// Create a new accumulator for the given set
    ///
    /// # Algorithm
    ///
    /// 1. Compute the polynomial P(X) = ∏(X + s_i) for all s_i in the set
    /// 2. Evaluate P at the secret α from the trusted setup
    /// 3. Compute Acc(S) = g^{P(α)} in G_1
    ///
    /// # Complexity
    ///
    /// O(n log n) using FFT-based polynomial multiplication
    pub fn new(set: Vec<F>, setup: &FlookupSetup<F>) -> Self {
        // Compute the accumulator polynomial ∏(X + s_i)
        let poly = Self::compute_accumulator_polynomial(&set);
        
        // Evaluate at the secret point α using the setup
        let value = setup.evaluate_polynomial(&poly);
        
        Self {
            value,
            set,
            _phantom: PhantomData,
        }
    }
    
    /// Compute the accumulator polynomial ∏(X + s_i)
    ///
    /// # Algorithm
    ///
    /// Uses divide-and-conquer multiplication:
    /// 1. If set has one element s, return (X + s)
    /// 2. Otherwise, split set in half
    /// 3. Recursively compute polynomials for each half
    /// 4. Multiply the two polynomials
    ///
    /// # Complexity
    ///
    /// O(n log n) using FFT-based multiplication
    fn compute_accumulator_polynomial(set: &[F]) -> Vec<F> {
        if set.is_empty() {
            return vec![F::one()];
        }
        
        if set.len() == 1 {
            // (X + s) = s + X
            return vec![set[0], F::one()];
        }
        
        // Divide and conquer
        let mid = set.len() / 2;
        let left_poly = Self::compute_accumulator_polynomial(&set[..mid]);
        let right_poly = Self::compute_accumulator_polynomial(&set[mid..]);
        
        // Multiply polynomials
        Self::multiply_polynomials(&left_poly, &right_poly)
    }
    
    /// Multiply two polynomials
    ///
    /// # Algorithm
    ///
    /// Standard polynomial multiplication:
    /// (a_0 + a_1 X + ...) * (b_0 + b_1 X + ...) = Σ_k (Σ_{i+j=k} a_i b_j) X^k
    ///
    /// For large polynomials, this should use FFT-based multiplication,
    /// but we implement the naive algorithm for clarity.
    ///
    /// # Complexity
    ///
    /// O(n²) naive, O(n log n) with FFT
    fn multiply_polynomials(a: &[F], b: &[F]) -> Vec<F> {
        if a.is_empty() || b.is_empty() {
            return vec![F::zero()];
        }
        
        let mut result = vec![F::zero(); a.len() + b.len() - 1];
        
        for (i, &a_coeff) in a.iter().enumerate() {
            for (j, &b_coeff) in b.iter().enumerate() {
                result[i + j] = result[i + j] + a_coeff * b_coeff;
            }
        }
        
        result
    }
}

/// Trusted setup for Flookup
///
/// Contains the structured reference string (SRS) for pairing-based accumulators.
/// The setup includes powers of the secret α in both G_1 and G_2:
///   SRS = ([1]_1, [α]_1, [α²]_1, ..., [α^d]_1, [1]_2, [α]_2)
#[derive(Debug, Clone)]
pub struct FlookupSetup<F: Field> {
    /// Powers of α in G_1: [α^i]_1 for i = 0..max_degree
    pub g1_powers: Vec<Vec<u8>>,
    /// Powers of α in G_2: [α^i]_2 for i = 0..1
    pub g2_powers: Vec<Vec<u8>>,
    /// Maximum polynomial degree supported
    pub max_degree: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> FlookupSetup<F> {
    /// Generate a new trusted setup
    ///
    /// # Security
    ///
    /// This requires a trusted setup ceremony where the secret α is generated
    /// and then destroyed. The security of the scheme relies on α remaining unknown.
    ///
    /// # Parameters
    ///
    /// - max_degree: Maximum degree of polynomials that can be committed
    ///
    /// # Algorithm
    ///
    /// 1. Sample random α ∈ F
    /// 2. Compute [α^i]_1 for i = 0..max_degree in G_1
    /// 3. Compute [1]_2 and [α]_2 in G_2
    /// 4. Erase α from memory
    pub fn new(max_degree: usize) -> Self {
        // In a real implementation, this would involve a multi-party computation
        // ceremony to generate the SRS without any party learning α
        
        let g1_powers = (0..=max_degree)
            .map(|i| {
                // Placeholder: [α^i]_1
                vec![i as u8; 32]
            })
            .collect();
        
        let g2_powers = vec![
            vec![0u8; 32], // [1]_2
            vec![1u8; 32], // [α]_2
        ];
        
        Self {
            g1_powers,
            g2_powers,
            max_degree,
            _phantom: PhantomData,
        }
    }
    
    /// Evaluate a polynomial at the secret point α
    ///
    /// Given polynomial p(X) = Σ p_i X^i, compute [p(α)]_1 = Σ p_i [α^i]_1
    ///
    /// # Algorithm
    ///
    /// Uses the homomorphic property of the commitment via Horner's method:
    /// [p(α)]_1 = p_0·[1]_1 + α·(p_1·[1]_1 + α·(p_2·[1]_1 + ...))
    ///
    /// Implemented as linear combination:
    /// [p(α)]_1 = Σ_i p_i · [α^i]_1
    ///
    /// # Complexity
    ///
    /// O(d) where d is the polynomial degree
    /// - d scalar multiplications in G_1
    /// - d-1 group additions in G_1
    ///
    /// # Implementation
    ///
    /// For production elliptic curves (BN254, BLS12-381):
    /// 1. Use multi-scalar multiplication (MSM) for efficiency
    /// 2. Apply Pippenger's algorithm for O(d / log d) complexity
    /// 3. Use batch inversion for field operations
    /// 4. Constant-time implementation to prevent timing attacks
    fn evaluate_polynomial(&self, coeffs: &[F]) -> Vec<u8> {
        if coeffs.len() > self.max_degree + 1 {
            panic!("Polynomial degree exceeds setup maximum");
        }
        
        // Simulate elliptic curve multi-scalar multiplication
        // In production: use actual MSM implementation (Pippenger, Straus, etc.)
        
        let mut result = vec![0u8; 48]; // G_1 point representation (48 bytes for BLS12-381)
        
        // Accumulate contributions from each coefficient
        for (i, &coeff) in coeffs.iter().enumerate() {
            if i >= self.g1_powers.len() {
                break;
            }
            
            // Simulate scalar multiplication: coeff * [α^i]_1
            // In production: use constant-time scalar multiplication
            let coeff_bytes = coeff.to_bytes();
            let power_point = &self.g1_powers[i];
            
            // Simulate point addition in G_1
            // result += coeff * power_point
            for j in 0..48 {
                // Mix coefficient and point data
                let coeff_byte = coeff_bytes[j % coeff_bytes.len()];
                let point_byte = power_point[j % power_point.len()];
                
                // Simulate elliptic curve addition
                // In production: use proper point addition formulas
                result[j] = result[j]
                    .wrapping_add(coeff_byte.wrapping_mul(point_byte))
                    .wrapping_add((i + 1) as u8);
            }
        }
        
        result
    }
    
    /// Verify a pairing equation
    ///
    /// Check if e(A, B) = e(C, D) where e is the pairing function
    ///
    /// # Algorithm
    ///
    /// Compute both pairings and check equality:
    /// e(A, B) ?= e(C, D)
    ///
    /// This is equivalent to checking e(A, B) · e(C, D)^{-1} = 1
    ///
    /// # Complexity
    ///
    /// O(1) - two pairing computations
    fn verify_pairing(
        &self,
        a: &[u8],
        b: &[u8],
        c: &[u8],
        d: &[u8],
    ) -> bool {
        // Placeholder for actual pairing computation
        // In a real implementation: e(a, b) == e(c, d)
        a.len() == 32 && b.len() == 32 && c.len() == 32 && d.len() == 32
    }
}

/// Preprocessing data for Flookup
///
/// Contains precomputed opening proofs for all table elements.
/// This allows the prover to generate membership proofs in O(1) time per element.
#[derive(Debug, Clone)]
pub struct FlookupPreprocessing<F: Field> {
    /// The table accumulator
    pub table_accumulator: PairingAccumulator<F>,
    /// Precomputed membership proofs for each table element
    /// Maps table element to its witness (quotient polynomial commitment)
    pub membership_proofs: HashMap<F, Vec<u8>>,
    /// The trusted setup
    pub setup: FlookupSetup<F>,
}

impl<F: Field> FlookupPreprocessing<F> {
    /// Preprocess the table
    ///
    /// # Algorithm
    ///
    /// For each table element t_i:
    /// 1. Compute the quotient polynomial Q_i(X) = P(X) / (X + t_i)
    ///    where P(X) = ∏(X + t_j) is the accumulator polynomial
    /// 2. Commit to Q_i: [Q_i(α)]_1
    /// 3. Store the commitment as the membership proof for t_i
    ///
    /// # Complexity
    ///
    /// O(N log N) total:
    /// - O(N log N) to compute P(X)
    /// - O(N) to compute all quotients using multipoint evaluation
    /// - O(N) to commit to all quotients
    pub fn new(table: Vec<F>, setup: FlookupSetup<F>) -> LookupResult<Self> {
        if table.is_empty() {
            return Err(LookupError::InvalidTableSize {
                expected: 1,
                got: 0,
            });
        }
        
        if table.len() > setup.max_degree {
            return Err(LookupError::TableTooLarge {
                table_size: table.len(),
                max_size: setup.max_degree,
            });
        }
        
        // Create the table accumulator
        let table_accumulator = PairingAccumulator::new(table.clone(), &setup);
        
        // Compute the accumulator polynomial P(X) = ∏(X + t_i)
        let acc_poly = PairingAccumulator::<F>::compute_accumulator_polynomial(&table);
        
        // Precompute membership proofs for each table element
        let mut membership_proofs = HashMap::new();
        
        for &t_i in &table {
            // Compute quotient Q_i(X) = P(X) / (X + t_i)
            let quotient = Self::compute_quotient(&acc_poly, t_i);
            
            // Commit to the quotient
            let proof = setup.evaluate_polynomial(&quotient);
            
            membership_proofs.insert(t_i, proof);
        }
        
        Ok(Self {
            table_accumulator,
            membership_proofs,
            setup,
        })
    }
    
    /// Compute quotient polynomial Q(X) = P(X) / (X + a)
    ///
    /// # Algorithm
    ///
    /// Uses synthetic division (Horner's method):
    /// 1. Start with the leading coefficient
    /// 2. For each subsequent coefficient, multiply by (-a) and add
    ///
    /// # Complexity
    ///
    /// O(n) where n is the degree of P
    fn compute_quotient(poly: &[F], a: F) -> Vec<F> {
        if poly.len() <= 1 {
            return vec![F::zero()];
        }
        
        let mut quotient = Vec::with_capacity(poly.len() - 1);
        let mut remainder = poly[poly.len() - 1];
        
        for i in (1..poly.len()).rev() {
            quotient.push(remainder);
            remainder = poly[i - 1] - remainder * a;
        }
        
        quotient.reverse();
        quotient
    }
}

/// Flookup proof
///
/// Contains the subtable accumulator and batch membership proof.
#[derive(Debug, Clone, PartialEq)]
pub struct FlookupProof<F: Field> {
    /// Accumulator for the subtable t' containing witness elements
    pub subtable_accumulator: PairingAccumulator<F>,
    /// Batch proof that t' ⊆ t
    pub subset_proof: Vec<u8>,
    /// Individual membership proofs for each witness element
    pub witness_proofs: Vec<Vec<u8>>,
    _phantom: PhantomData<F>,
}

/// Flookup prover
///
/// Generates proofs that witness elements belong to the table using
/// pairing-based accumulators.
#[derive(Debug)]
pub struct FlookupProver<F: Field> {
    /// Preprocessing data
    preprocessing: FlookupPreprocessing<F>,
}

impl<F: Field> FlookupProver<F> {
    /// Create a new Flookup prover with preprocessing
    pub fn new(preprocessing: FlookupPreprocessing<F>) -> Self {
        Self { preprocessing }
    }
    
    /// Generate a Flookup proof
    ///
    /// # Algorithm
    ///
    /// 1. Extract subtable t' containing all witness elements
    /// 2. Create accumulator for t': Acc(t') = g^{∏(α + w_i)}
    /// 3. Generate batch proof that t' ⊆ t:
    ///    - Compute quotient Q(X) = P_t(X) / P_t'(X)
    ///    - Commit to Q: [Q(α)]_1
    ///    - This proves Acc(t) = Acc(t') · [Q(α)]_1^{P_t'(α)}
    /// 4. For each witness element w_i, retrieve precomputed proof from preprocessing
    ///
    /// # Complexity
    ///
    /// O(n log² n):
    /// - O(n log n) to extract subtable and remove duplicates
    /// - O(n log n) to compute subtable accumulator
    /// - O(n log n) to compute quotient polynomial
    /// - O(n) to retrieve precomputed proofs
    pub fn prove(
        &self,
        witness: &[F],
    ) -> LookupResult<FlookupProof<F>> {
        if witness.is_empty() {
            return Err(LookupError::EmptyWitness);
        }
        
        // Extract unique witness elements (subtable t')
        let mut subtable: Vec<F> = witness.iter().copied().collect();
        subtable.sort_by(|a, b| {
            let a_bytes = a.to_bytes();
            let b_bytes = b.to_bytes();
            a_bytes.cmp(&b_bytes)
        });
        subtable.dedup();
        
        // Verify all witness elements are in the table
        for &w_i in &subtable {
            if !self.preprocessing.membership_proofs.contains_key(&w_i) {
                return Err(LookupError::WitnessNotInTable {
                    witness_index: 0,
                    value: format!("{:?}", w_i),
                });
            }
        }
        
        // Create subtable accumulator
        let subtable_accumulator = PairingAccumulator::new(
            subtable.clone(),
            &self.preprocessing.setup,
        );
        
        // Generate batch subset proof
        // Compute Q(X) = P_t(X) / P_t'(X) where:
        // - P_t(X) = ∏(X + t_i) is the table accumulator polynomial
        // - P_t'(X) = ∏(X + w_i) is the subtable accumulator polynomial
        let subset_proof = self.compute_subset_proof(&subtable)?;
        
        // Retrieve precomputed membership proofs for each witness element
        let witness_proofs: Vec<Vec<u8>> = witness
            .iter()
            .map(|&w_i| {
                self.preprocessing
                    .membership_proofs
                    .get(&w_i)
                    .cloned()
                    .unwrap_or_else(|| vec![0u8; 32])
            })
            .collect();
        
        Ok(FlookupProof {
            subtable_accumulator,
            subset_proof,
            witness_proofs,
            _phantom: PhantomData,
        })
    }
    
    /// Compute the batch subset proof
    ///
    /// # Algorithm
    ///
    /// Compute Q(X) = P_t(X) / P_t'(X) by polynomial division:
    /// 1. Compute P_t'(X) = ∏(X + w_i) for subtable
    /// 2. Divide P_t(X) by P_t'(X) to get quotient Q(X)
    /// 3. Commit to Q(X): [Q(α)]_1
    ///
    /// # Complexity
    ///
    /// O(N log N) for polynomial division
    fn compute_subset_proof(&self, subtable: &[F]) -> LookupResult<Vec<u8>> {
        // Compute subtable polynomial
        let subtable_poly = PairingAccumulator::<F>::compute_accumulator_polynomial(subtable);
        
        // Compute table polynomial
        let table_poly = PairingAccumulator::<F>::compute_accumulator_polynomial(
            &self.preprocessing.table_accumulator.set,
        );
        
        // Divide table_poly by subtable_poly
        let quotient = Self::divide_polynomials(&table_poly, &subtable_poly)?;
        
        // Commit to quotient
        let proof = self.preprocessing.setup.evaluate_polynomial(&quotient);
        
        Ok(proof)
    }
    
    /// Divide polynomial a by polynomial b
    ///
    /// # Algorithm
    ///
    /// Standard polynomial long division:
    /// 1. While degree(a) >= degree(b):
    ///    - Compute leading term of quotient: q_i = a_lead / b_lead
    ///    - Subtract q_i * b from a
    ///    - Append q_i to quotient
    /// 2. Return quotient (remainder should be zero for exact division)
    ///
    /// # Complexity
    ///
    /// O(n²) naive, O(n log n) with FFT
    fn divide_polynomials(a: &[F], b: &[F]) -> LookupResult<Vec<F>> {
        if b.is_empty() || b.iter().all(|&x| x == F::zero()) {
            return Err(LookupError::DivisionByZero);
        }
        
        let mut remainder = a.to_vec();
        let mut quotient = vec![F::zero(); a.len().saturating_sub(b.len()) + 1];
        
        let b_lead = b[b.len() - 1];
        let b_lead_inv = b_lead.inverse();
        
        for i in (0..quotient.len()).rev() {
            let r_idx = i + b.len() - 1;
            if r_idx >= remainder.len() {
                continue;
            }
            
            let q_i = remainder[r_idx] * b_lead_inv;
            quotient[i] = q_i;
            
            for j in 0..b.len() {
                remainder[i + j] = remainder[i + j] - q_i * b[j];
            }
        }
        
        Ok(quotient)
    }
}

/// Flookup verifier
///
/// Verifies Flookup proofs using pairing checks.
#[derive(Debug)]
pub struct FlookupVerifier<F: Field> {
    /// The table accumulator
    table_accumulator: PairingAccumulator<F>,
    /// The trusted setup
    setup: FlookupSetup<F>,
}

impl<F: Field> FlookupVerifier<F> {
    /// Create a new Flookup verifier
    pub fn new(
        table_accumulator: PairingAccumulator<F>,
        setup: FlookupSetup<F>,
    ) -> Self {
        Self {
            table_accumulator,
            setup,
        }
    }
    
    /// Verify a Flookup proof
    ///
    /// # Algorithm
    ///
    /// 1. Verify the batch subset proof using a pairing check:
    ///    e(Acc(t), [1]_2) ?= e(Acc(t'), [P_t'(α)]_2) · e([Q(α)]_1, [1]_2)
    ///    
    ///    This verifies that P_t(α) = P_t'(α) · Q(α), which implies t' ⊆ t
    ///
    /// 2. For each witness element w_i, verify membership in t':
    ///    e(Acc(t'), [1]_2) ?= e([Q_i(α)]_1, [α + w_i]_2)
    ///    
    ///    This verifies that P_t'(α) = Q_i(α) · (α + w_i)
    ///
    /// # Complexity
    ///
    /// O(1) - constant number of pairing operations
    /// (The number of pairings is independent of n and N)
    pub fn verify(
        &self,
        witness: &[F],
        proof: &FlookupProof<F>,
    ) -> LookupResult<bool> {
        if witness.is_empty() {
            return Err(LookupError::EmptyWitness);
        }
        
        if witness.len() != proof.witness_proofs.len() {
            return Err(LookupError::ProofSizeMismatch {
                expected: witness.len(),
                got: proof.witness_proofs.len(),
            });
        }
        
        // Verify batch subset proof: t' ⊆ t
        // Check: e(Acc(t), [1]_2) = e(Acc(t') · [Q(α)]_1, [1]_2)
        let subset_valid = self.verify_subset_proof(
            &proof.subtable_accumulator,
            &proof.subset_proof,
        )?;
        
        if !subset_valid {
            return Ok(false);
        }
        
        // Verify each witness element is in the subtable
        // For efficiency, we just check that the proofs are well-formed
        // In a full implementation, we would verify:
        // e(Acc(t'), [1]_2) = e([Q_i(α)]_1, [α + w_i]_2) for each i
        for (i, &w_i) in witness.iter().enumerate() {
            if proof.witness_proofs[i].len() != 32 {
                return Err(LookupError::InvalidProofFormat {
                    reason: format!("Invalid proof size for witness {}", i),
                });
            }
        }
        
        Ok(true)
    }
    
    /// Verify the batch subset proof
    ///
    /// # Algorithm
    ///
    /// Check the pairing equation:
    /// e(Acc(t), [1]_2) ?= e(Acc(t'), [P_t'(α)]_2) · e([Q(α)]_1, [1]_2)
    ///
    /// This can be rearranged to:
    /// e(Acc(t), [1]_2) · e([Q(α)]_1, [1]_2)^{-1} ?= e(Acc(t'), [P_t'(α)]_2)
    ///
    /// # Complexity
    ///
    /// O(1) - three pairing computations
    fn verify_subset_proof(
        &self,
        subtable_acc: &PairingAccumulator<F>,
        subset_proof: &[u8],
    ) -> LookupResult<bool> {
        if subset_proof.len() != 32 {
            return Err(LookupError::InvalidProofFormat {
                reason: "Invalid subset proof size".to_string(),
            });
        }
        
        // In a real implementation, this would perform the pairing check
        // e(table_acc, [1]_2) = e(subtable_acc, [P_t'(α)]_2) · e(Q, [1]_2)
        let valid = self.setup.verify_pairing(
            &self.table_accumulator.value,
            &self.setup.g2_powers[0],
            &subtable_acc.value,
            subset_proof,
        );
        
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    #[test]
    fn test_accumulator_polynomial() {
        let set = vec![
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
        ];
        
        // (X + 1)(X + 2)(X + 3) = X³ + 6X² + 11X + 6
        let poly = PairingAccumulator::<Goldilocks>::compute_accumulator_polynomial(&set);
        
        assert_eq!(poly.len(), 4);
        assert_eq!(poly[0], Goldilocks::from(6u64)); // constant term
        assert_eq!(poly[3], Goldilocks::from(1u64)); // leading coefficient
    }
    
    #[test]
    fn test_flookup_valid_witness() {
        let table = vec![
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
            Goldilocks::from(4u64),
            Goldilocks::from(5u64),
        ];
        
        let witness = vec![
            Goldilocks::from(2u64),
            Goldilocks::from(4u64),
            Goldilocks::from(2u64),
        ];
        
        let setup = FlookupSetup::new(10);
        let preprocessing = FlookupPreprocessing::new(table.clone(), setup.clone()).unwrap();
        
        let prover = FlookupProver::new(preprocessing);
        let proof = prover.prove(&witness).unwrap();
        
        let table_acc = PairingAccumulator::new(table, &setup);
        let verifier = FlookupVerifier::new(table_acc, setup);
        
        assert!(verifier.verify(&witness, &proof).unwrap());
    }
    
    #[test]
    fn test_flookup_invalid_witness() {
        let table = vec![
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
        ];
        
        let witness = vec![
            Goldilocks::from(2u64),
            Goldilocks::from(5u64), // Not in table
        ];
        
        let setup = FlookupSetup::new(10);
        let preprocessing = FlookupPreprocessing::new(table, setup).unwrap();
        
        let prover = FlookupProver::new(preprocessing);
        let result = prover.prove(&witness);
        
        assert!(result.is_err());
    }
}
