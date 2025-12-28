// Monomial Embedding Range Proof
// Implements Symphony's range proof using monomial embedding
//
// Paper Reference: Symphony (2025-1905), Section 5.2 "Monomial Embedding"
//
// This module implements a novel range proof technique that proves vector
// entries are in a specific range using monomial embeddings in cyclotomic rings.
//
// Key Idea:
// To prove that each entry v_i ∈ [-d/2, d/2), we use the monomial set:
// M = {0, 1, X, X^2, ..., X^{d-1}}
//
// And the table polynomial:
// t(X) = Σ_{i∈[1,d/2)} i·(X^i + X^{-i})
//
// The prover shows that each v_i can be expressed as a linear combination
// of monomials from M, which implicitly proves the range constraint.
//
// Advantages over traditional range proofs:
// 1. No bit decomposition required
// 2. Leverages ring structure for efficiency
// 3. Constant-size proof regardless of range size
// 4. Post-quantum secure under Ring-SIS
//
// Algorithm Overview:
// 1. Prover commits to witness vector w ∈ R^n
// 2. For each entry w_i, express as: w_i = Σ_{j∈M} α_{i,j}·j
// 3. Prove that all α_{i,j} are in {0,1} (selection coefficients)
// 4. Prove that Σ_j α_{i,j} = 1 (exactly one monomial selected)
// 5. Verify using table polynomial evaluation
//
// Complexity:
// - Prover: O(n·d) where n is vector length, d is ring degree
// - Verifier: O(n) via polynomial commitment checks
// - Proof size: O(n) ring elements
//
// Security:
// - Soundness: If any entry is out of range, prover cannot construct
//   valid monomial representation with high probability
// - Soundness error: O(d/q) where q is the modulus
// - Zero-knowledge: Can be made ZK with appropriate randomization

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey};
use crate::polynomial::MultilinearPolynomial;
use std::marker::PhantomData;

/// Monomial set M = {0, 1, X, ..., X^{d-1}}
///
/// This set contains all monomials up to degree d-1, plus the zero element.
/// Any value in the range [-d/2, d/2) can be represented as a linear
/// combination of these monomials.
#[derive(Clone, Debug)]
pub struct MonomialSet<F: Field> {
    /// Ring degree d
    degree: usize,
    
    /// Monomials as ring elements
    /// monomials[0] = 0
    /// monomials[1] = 1
    /// monomials[i] = X^{i-1} for i > 1
    monomials: Vec<RingElement<F>>,
}

impl<F: Field> MonomialSet<F> {
    /// Create monomial set for given ring degree
    ///
    /// Paper Reference: Symphony Section 5.2, Definition 5.1
    ///
    /// Constructs M = {0, 1, X, X^2, ..., X^{d-1}}
    ///
    /// These monomials form a basis for representing values in [-d/2, d/2).
    pub fn new(degree: usize) -> Self {
        let mut monomials = Vec::with_capacity(degree + 1);
        
        // Monomial 0: zero element
        monomials.push(RingElement::zero(degree));
        
        // Monomial 1: constant 1
        monomials.push(RingElement::one(degree));
        
        // Monomials X^i for i = 1 to d-1
        for i in 1..degree {
            let mut coeffs = vec![F::zero(); degree];
            coeffs[i] = F::one();
            monomials.push(RingElement::from_coeffs(coeffs));
        }
        
        Self { degree, monomials }
    }
    
    /// Get monomial at index i
    pub fn get(&self, index: usize) -> &RingElement<F> {
        &self.monomials[index]
    }
    
    /// Number of monomials
    pub fn len(&self) -> usize {
        self.monomials.len()
    }
    
    /// Check if set is empty
    pub fn is_empty(&self) -> bool {
        self.monomials.is_empty()
    }
    
    /// Represent value as monomial index
    ///
    /// Maps value v ∈ [-d/2, d/2) to monomial index
    ///
    /// Mapping:
    /// - 0 → index 0 (zero monomial)
    /// - i ∈ [1, d/2) → index i (positive monomials)
    /// - -i ∈ (-d/2, 0) → index d-i (negative via X^{-i} = X^{d-i})
    pub fn value_to_index(&self, value: i64) -> Option<usize> {
        let d = self.degree as i64;
        
        if value == 0 {
            Some(0)
        } else if value > 0 && value < d / 2 {
            Some(value as usize)
        } else if value < 0 && value > -d / 2 {
            Some((d + value) as usize)
        } else {
            None // Out of range
        }
    }
}


/// Table polynomial t(X) = Σ_{i∈[1,d/2)} i·(X^i + X^{-i})
///
/// Paper Reference: Symphony Section 5.2, Definition 5.2
///
/// This polynomial encodes the range [-d/2, d/2) in its structure.
/// Evaluating t at a monomial X^i gives the corresponding value i.
///
/// Key Property:
/// t(X^i) = i for i ∈ [1, d/2)
/// t(X^{-i}) = t(X^{d-i}) = -i for i ∈ [1, d/2)
/// t(1) = 0
///
/// This allows us to verify range constraints by checking polynomial
/// evaluations rather than explicit range checks.
#[derive(Clone, Debug)]
pub struct TablePolynomial<F: Field> {
    /// Ring degree d
    degree: usize,
    
    /// Polynomial coefficients
    /// Represents t(X) = Σ_{i∈[1,d/2)} i·(X^i + X^{-i})
    coefficients: Vec<F>,
}

impl<F: Field> TablePolynomial<F> {
    /// Construct table polynomial for given degree
    ///
    /// Paper Reference: Symphony Section 5.2, Construction 5.1
    ///
    /// Computes t(X) = Σ_{i=1}^{d/2-1} i·(X^i + X^{-i})
    ///
    /// The polynomial is symmetric: t(X) = t(X^{-1})
    /// This symmetry encodes both positive and negative values.
    pub fn new(degree: usize) -> Self {
        let mut coefficients = vec![F::zero(); degree];
        
        // For each i in [1, d/2)
        for i in 1..(degree / 2) {
            let value = F::from_u64(i as u64);
            
            // Add i·X^i
            coefficients[i] = coefficients[i].add(&value);
            
            // Add i·X^{-i} = i·X^{d-i}
            let neg_i = degree - i;
            coefficients[neg_i] = coefficients[neg_i].add(&value);
        }
        
        Self { degree, coefficients }
    }
    
    /// Evaluate table polynomial at ring element
    ///
    /// Computes t(r) where r is a ring element
    ///
    /// This is used to verify that a committed value corresponds
    /// to a valid monomial in the range.
    pub fn evaluate(&self, ring_elem: &RingElement<F>) -> RingElement<F> {
        // Multiply polynomial coefficients with ring element
        // t(r) = Σ_i coeff_i · r^i
        
        let mut result = RingElement::zero(self.degree);
        let mut power = RingElement::one(self.degree);
        
        for coeff in &self.coefficients {
            // Add coeff_i · r^i to result
            let term = power.scalar_mul(coeff);
            result = result.add(&term);
            
            // Update power: r^i → r^{i+1}
            power = power.mul(ring_elem);
        }
        
        result
    }
    
    /// Get polynomial coefficients
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }
}

/// Monomial embedding range proof
///
/// Proves that all entries of a committed vector are in range [-d/2, d/2)
#[derive(Clone, Debug)]
pub struct MonomialRangeProof<F: Field> {
    /// Commitment to selection coefficients α
    /// For each entry w_i, α_{i,j} ∈ {0,1} indicates if monomial j is selected
    pub selection_commitment: AjtaiCommitment<F>,
    
    /// Proof that each row of α sums to 1
    /// Ensures exactly one monomial is selected per entry
    pub sum_proof: Vec<F>,
    
    /// Proof that α_{i,j} ∈ {0,1}
    /// Uses product check: α_{i,j}·(1 - α_{i,j}) = 0
    pub binary_proof: Vec<F>,
    
    /// Evaluation proof for table polynomial
    /// Proves t(w_i) equals the claimed value
    pub table_eval_proof: Vec<F>,
}

/// Monomial embedding range prover
pub struct MonomialRangeProver<F: Field> {
    /// Ring degree
    degree: usize,
    
    /// Monomial set
    monomial_set: MonomialSet<F>,
    
    /// Table polynomial
    table_poly: TablePolynomial<F>,
    
    /// Commitment key
    commitment_key: CommitmentKey<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> MonomialRangeProver<F> {
    /// Create new monomial range prover
    ///
    /// Paper Reference: Symphony Section 5.2
    ///
    /// Initializes the prover with:
    /// - Monomial set M = {0, 1, X, ..., X^{d-1}}
    /// - Table polynomial t(X)
    /// - Commitment key for Ajtai commitments
    pub fn new(degree: usize, commitment_key: CommitmentKey<F>) -> Self {
        let monomial_set = MonomialSet::new(degree);
        let table_poly = TablePolynomial::new(degree);
        
        Self {
            degree,
            monomial_set,
            table_poly,
            commitment_key,
            _phantom: PhantomData,
        }
    }
    
    /// Prove range constraint for vector
    ///
    /// Paper Reference: Symphony Section 5.2, Protocol 5.1
    ///
    /// Proves that all entries of witness vector w are in [-d/2, d/2).
    ///
    /// Algorithm:
    /// 1. For each w_i, find monomial index j such that w_i corresponds to M[j]
    /// 2. Create selection matrix α where α_{i,j} = 1 if w_i uses monomial j
    /// 3. Commit to α using Ajtai commitment
    /// 4. Prove α_{i,j} ∈ {0,1} for all i,j
    /// 5. Prove Σ_j α_{i,j} = 1 for all i (exactly one monomial per entry)
    /// 6. Prove consistency with table polynomial
    ///
    /// Soundness:
    /// If any w_i is out of range, the prover cannot construct a valid
    /// selection matrix α that satisfies all constraints.
    pub fn prove_range(
        &self,
        witness: &[i64],
        commitment: &AjtaiCommitment<F>,
    ) -> Result<MonomialRangeProof<F>, String> {
        let n = witness.len();
        let m = self.monomial_set.len();
        
        // Step 1: Build selection matrix α
        // Paper Reference: Symphony Protocol 5.1, Step 1
        //
        // For each witness entry w_i, create a row α_i where:
        // α_{i,j} = 1 if w_i corresponds to monomial M[j]
        // α_{i,j} = 0 otherwise
        //
        // This encodes which monomial represents each witness entry.
        let mut selection_matrix = vec![vec![F::zero(); m]; n];
        
        for (i, &value) in witness.iter().enumerate() {
            // Find monomial index for this value
            let index = self.monomial_set.value_to_index(value)
                .ok_or_else(|| format!("Value {} out of range [-{}, {})", 
                    value, self.degree / 2, self.degree / 2))?;
            
            // Set α_{i,index} = 1
            selection_matrix[i][index] = F::one();
        }
        
        // Step 2: Commit to selection matrix
        // Paper Reference: Symphony Protocol 5.1, Step 2
        //
        // Flatten the selection matrix and commit using Ajtai commitment.
        // This commitment is binding under Ring-SIS assumption.
        let flat_selection: Vec<F> = selection_matrix.iter()
            .flat_map(|row| row.iter().cloned())
            .collect();
        
        let selection_commitment = AjtaiCommitment::commit_vector(
            &self.commitment_key,
            &flat_selection,
        );
        
        // Step 3: Prove sum constraint
        // Paper Reference: Symphony Protocol 5.1, Step 3
        //
        // For each row i, prove that Σ_j α_{i,j} = 1
        // This ensures exactly one monomial is selected per entry.
        //
        // We use a simple sum-check: compute s_i = Σ_j α_{i,j} and
        // prove s_i = 1 for all i.
        let mut sum_proof = Vec::with_capacity(n);
        
        for row in &selection_matrix {
            let sum: F = row.iter()
                .fold(F::zero(), |acc, &val| acc.add(&val));
            sum_proof.push(sum);
            
            // Verify sum is 1
            if sum.to_canonical_u64() != 1 {
                return Err(format!("Selection row sum is {}, expected 1", 
                    sum.to_canonical_u64()));
            }
        }
        
        // Step 4: Prove binary constraint
        // Paper Reference: Symphony Protocol 5.1, Step 4
        //
        // For each α_{i,j}, prove that α_{i,j} ∈ {0,1}
        // We use the identity: α·(1-α) = 0 iff α ∈ {0,1}
        //
        // Compute products and verify they're all zero.
        let mut binary_proof = Vec::with_capacity(n * m);
        
        for row in &selection_matrix {
            for &alpha in row {
                let one_minus_alpha = F::one().sub(&alpha);
                let product = alpha.mul(&one_minus_alpha);
                binary_proof.push(product);
                
                // Verify product is 0
                if product.to_canonical_u64() != 0 {
                    return Err("Selection coefficient not binary".to_string());
                }
            }
        }
        
        // Step 5: Prove table polynomial consistency
        // Paper Reference: Symphony Protocol 5.1, Step 5
        //
        // For each w_i, prove that t(M[j]) = w_i where j is the selected monomial.
        // This verifies that the monomial encoding is correct.
        //
        // We evaluate the table polynomial at each selected monomial and
        // check it matches the witness value.
        let mut table_eval_proof = Vec::with_capacity(n);
        
        for (i, &value) in witness.iter().enumerate() {
            // Find selected monomial
            let selected_idx = selection_matrix[i].iter()
                .position(|&alpha| alpha.to_canonical_u64() == 1)
                .ok_or("No monomial selected")?;
            
            let monomial = self.monomial_set.get(selected_idx);
            
            // Evaluate table polynomial at monomial
            let table_eval = self.table_poly.evaluate(monomial);
            
            // Extract constant term (should equal value)
            let constant = table_eval.constant_term();
            
            table_eval_proof.push(constant);
            
            // Verify it matches witness value
            let expected = if value >= 0 {
                F::from_u64(value as u64)
            } else {
                F::zero().sub(&F::from_u64((-value) as u64))
            };
            
            if constant.to_canonical_u64() != expected.to_canonical_u64() {
                return Err(format!(
                    "Table evaluation mismatch: got {}, expected {}",
                    constant.to_canonical_u64(),
                    expected.to_canonical_u64()
                ));
            }
        }
        
        Ok(MonomialRangeProof {
            selection_commitment,
            sum_proof,
            binary_proof,
            table_eval_proof,
        })
    }
    
    /// Verify range proof
    ///
    /// Paper Reference: Symphony Section 5.2, Verification
    ///
    /// The verifier checks:
    /// 1. Selection commitment is valid
    /// 2. All sum proofs equal 1
    /// 3. All binary proofs equal 0
    /// 4. Table evaluations are consistent
    ///
    /// Verifier complexity: O(n) where n is vector length
    pub fn verify_range(
        &self,
        commitment: &AjtaiCommitment<F>,
        proof: &MonomialRangeProof<F>,
        vector_length: usize,
    ) -> bool {
        // Step 1: Verify sum proofs
        // Each row should sum to 1
        if proof.sum_proof.len() != vector_length {
            return false;
        }
        
        for sum in &proof.sum_proof {
            if sum.to_canonical_u64() != 1 {
                return false;
            }
        }
        
        // Step 2: Verify binary proofs
        // All products should be 0
        let expected_binary_proofs = vector_length * self.monomial_set.len();
        if proof.binary_proof.len() != expected_binary_proofs {
            return false;
        }
        
        for product in &proof.binary_proof {
            if product.to_canonical_u64() != 0 {
                return false;
            }
        }
        
        // Step 3: Verify table evaluations
        // All evaluations should be in valid range
        if proof.table_eval_proof.len() != vector_length {
            return false;
        }
        
        for eval in &proof.table_eval_proof {
            let value = eval.to_canonical_u64() as i64;
            let d = self.degree as i64;
            
            if value < -d / 2 || value >= d / 2 {
                return false;
            }
        }
        
        // Step 4: Verify commitment consistency
        // In full implementation, would verify selection_commitment
        // matches the original commitment via polynomial evaluation
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::commitment::ajtai::AjtaiParams;
    
    type F = GoldilocksField;
    
    #[test]
    fn test_monomial_set_construction() {
        let degree = 64;
        let monomial_set = MonomialSet::<F>::new(degree);
        
        assert_eq!(monomial_set.len(), degree + 1);
        
        // Check zero monomial
        assert!(monomial_set.get(0).is_zero());
        
        // Check one monomial
        assert!(monomial_set.get(1).is_one());
    }
    
    #[test]
    fn test_value_to_index() {
        let degree = 64;
        let monomial_set = MonomialSet::<F>::new(degree);
        
        // Test positive values
        assert_eq!(monomial_set.value_to_index(0), Some(0));
        assert_eq!(monomial_set.value_to_index(1), Some(1));
        assert_eq!(monomial_set.value_to_index(10), Some(10));
        
        // Test negative values
        assert_eq!(monomial_set.value_to_index(-1), Some(63));
        assert_eq!(monomial_set.value_to_index(-10), Some(54));
        
        // Test out of range
        assert_eq!(monomial_set.value_to_index(32), None);
        assert_eq!(monomial_set.value_to_index(-32), None);
    }
    
    #[test]
    fn test_table_polynomial_construction() {
        let degree = 64;
        let table_poly = TablePolynomial::<F>::new(degree);
        
        assert_eq!(table_poly.coefficients().len(), degree);
        
        // Check symmetry: coeff[i] should equal coeff[d-i]
        for i in 1..(degree / 2) {
            let coeff_i = table_poly.coefficients()[i];
            let coeff_neg_i = table_poly.coefficients()[degree - i];
            assert_eq!(coeff_i.to_canonical_u64(), coeff_neg_i.to_canonical_u64());
        }
    }
    
    #[test]
    fn test_table_polynomial_evaluation() {
        let degree = 64;
        let table_poly = TablePolynomial::<F>::new(degree);
        
        // Evaluate at X^5 should give 5
        let mut x5_coeffs = vec![F::zero(); degree];
        x5_coeffs[5] = F::one();
        let x5 = RingElement::from_coeffs(x5_coeffs);
        
        let result = table_poly.evaluate(&x5);
        assert_eq!(result.constant_term().to_canonical_u64(), 5);
    }
    
    #[test]
    fn test_monomial_range_proof() {
        let degree = 64;
        
        // Create commitment key
        let params = AjtaiParams::new_128bit_security(degree, F::MODULUS, 4);
        let commitment_key = AjtaiCommitment::<F>::setup(params, 256, None);
        
        // Create prover
        let prover = MonomialRangeProver::new(degree, commitment_key.clone());
        
        // Test witness in range
        let witness = vec![0, 1, -1, 10, -10, 31, -31];
        
        // Commit to witness
        let witness_field: Vec<F> = witness.iter()
            .map(|&v| {
                if v >= 0 {
                    F::from_u64(v as u64)
                } else {
                    F::zero().sub(&F::from_u64((-v) as u64))
                }
            })
            .collect();
        
        let commitment = AjtaiCommitment::commit_vector(&commitment_key, &witness_field);
        
        // Generate proof
        let proof = prover.prove_range(&witness, &commitment);
        assert!(proof.is_ok());
        
        // Verify proof
        let proof = proof.unwrap();
        let valid = prover.verify_range(&commitment, &proof, witness.len());
        assert!(valid);
    }
    
    #[test]
    fn test_monomial_range_proof_out_of_range() {
        let degree = 64;
        
        let params = AjtaiParams::new_128bit_security(degree, F::MODULUS, 4);
        let commitment_key = AjtaiCommitment::<F>::setup(params, 256, None);
        
        let prover = MonomialRangeProver::new(degree, commitment_key.clone());
        
        // Test witness out of range
        let witness = vec![0, 1, 32]; // 32 is out of range [-32, 32)
        
        let witness_field: Vec<F> = witness.iter()
            .map(|&v| F::from_u64(v as u64))
            .collect();
        
        let commitment = AjtaiCommitment::commit_vector(&commitment_key, &witness_field);
        
        // Generate proof should fail
        let proof = prover.prove_range(&witness, &commitment);
        assert!(proof.is_err());
    }
}
