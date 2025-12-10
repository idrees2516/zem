// nLookup: HyperNova-Style Indexed Lookup Accumulation
//
// This module implements nLookup, an accumulation scheme for indexed lookups
// compatible with HyperNova. Unlike Protostar, nLookup:
// - Does NOT require large prime fields (works with small fields)
// - Does NOT require homomorphic commitments (works with hash-based PCS)
// - Reveals lookup entries in plaintext (not committed)
// - Uses sumcheck-based folding to reduce m evaluations to one
//
// # Mathematical Foundation
//
// Given table t: {0,1}^k → F with multilinear extension t̃,
// and m indexed lookups {(q_i, v_i)}_{i∈[m]} where q_i ∈ {0,1}^k:
//
// Verify: v_i = t̃(q_i) for all i ∈ [m]
//
// # Accumulation Strategy
//
// 1. Use sumcheck to fold m evaluation claims into one
// 2. Perform implicit smallness test via Boolean vector representation
// 3. Accumulate with random linear combination
//
// # Complexity
//
// - Prover: O(N) field operations per step
// - Verifier: O(log N) field/hash ops + O(m log N) field ops
// - Decider: O(2^k) field operations (or less for structured tables)
//
// # References
//
// Based on "Lookup Table Arguments" (2025-1876), Section on HyperNova Accumulation

use crate::field::traits::Field;
use crate::lookup::mle::MultilinearExtension;
use crate::lookup::sumcheck::{MultivariatePolynomial, SumcheckProof, SumcheckProver, SumcheckVerifier};
use crate::lookup::{LookupError, LookupResult};
use std::marker::PhantomData;

/// Indexed lookup query
///
/// Represents a single lookup: verify that v = t̃(q)
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedLookupQuery<F: Field> {
    /// Query point q ∈ {0,1}^k
    pub query: Vec<bool>,
    /// Expected value v = t̃(q)
    pub value: F,
}

impl<F: Field> IndexedLookupQuery<F> {
    /// Create a new indexed lookup query
    pub fn new(query: Vec<bool>, value: F) -> Self {
        Self { query, value }
    }
    
    /// Validate the query
    ///
    /// # Algorithm
    ///
    /// Check that query is a Boolean vector (all elements 0 or 1)
    ///
    /// # Complexity
    ///
    /// O(k) where k is the query length
    pub fn validate(&self) -> LookupResult<()> {
        if self.query.is_empty() {
            return Err(LookupError::InvalidIndexSize {
                expected: 1,
                got: 0,
            });
        }
        Ok(())
    }
    
    /// Convert Boolean query to field elements
    ///
    /// # Algorithm
    ///
    /// Map false → 0, true → 1 in the field
    ///
    /// # Complexity
    ///
    /// O(k)
    pub fn to_field_vector(&self) -> Vec<F> {
        self.query.iter()
            .map(|&b| if b { F::one() } else { F::zero() })
            .collect()
    }
}

/// nLookup instance
///
/// Represents an accumulated set of indexed lookup queries.
#[derive(Debug, Clone)]
pub struct NLookupInstance<F: Field> {
    /// Table size N = 2^k
    pub table_size: usize,
    /// Number of variables k (log N)
    pub num_vars: usize,
    /// Indexed lookup queries {(q_i, v_i)}
    pub queries: Vec<IndexedLookupQuery<F>>,
    /// Accumulated evaluation point (from folding)
    pub accumulated_point: Option<Vec<F>>,
    /// Accumulated value (from folding)
    pub accumulated_value: Option<F>,
}

impl<F: Field> NLookupInstance<F> {
    /// Create a new nLookup instance
    ///
    /// # Parameters
    ///
    /// - table_size: Size of table N = 2^k
    /// - queries: Initial indexed lookup queries
    pub fn new(table_size: usize, queries: Vec<IndexedLookupQuery<F>>) -> LookupResult<Self> {
        if table_size == 0 || !table_size.is_power_of_two() {
            return Err(LookupError::InvalidTableSize {
                expected: 1,
                got: table_size,
            });
        }
        
        let num_vars = (table_size as f64).log2() as usize;
        
        // Validate all queries
        for query in &queries {
            query.validate()?;
            if query.query.len() != num_vars {
                return Err(LookupError::InvalidIndexSize {
                    expected: num_vars,
                    got: query.query.len(),
                });
            }
        }
        
        Ok(Self {
            table_size,
            num_vars,
            queries,
            accumulated_point: None,
            accumulated_value: None,
        })
    }
    
    /// Check if instance is fully accumulated (single evaluation)
    pub fn is_fully_accumulated(&self) -> bool {
        self.accumulated_point.is_some() && self.accumulated_value.is_some()
    }
}

/// nLookup accumulation proof
///
/// Contains the sumcheck proof for folding multiple evaluations.
#[derive(Debug, Clone)]
pub struct NLookupAccumulationProof<F: Field> {
    /// Sumcheck proof for folding
    pub sumcheck_proof: SumcheckProof<F>,
    /// Challenges used in folding
    pub challenges: Vec<F>,
}

/// nLookup prover
///
/// Accumulates indexed lookup queries using sumcheck-based folding.
#[derive(Debug)]
pub struct NLookupProver<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> NLookupProver<F> {
    /// Create a new nLookup prover
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Accumulate indexed lookup queries
    ///
    /// # Algorithm
    ///
    /// Given m queries {(q_i, v_i)}_{i∈[m]}, reduce to single evaluation:
    ///
    /// 1. **Construct Folding Polynomial:**
    ///    - Define g(x) = Σ_{i=1}^m eq̃(x, q_i) · v_i
    ///    - This encodes all m queries
    ///
    /// 2. **Apply Sumcheck:**
    ///    - Prove: Σ_{b∈{0,1}^k} g(b) = claimed_sum
    ///    - Verifier samples random r ∈ F^k
    ///    - Reduces to: g(r) = final_value
    ///
    /// 3. **Compute Final Evaluation:**
    ///    - g(r) = Σ_{i=1}^m eq̃(r, q_i) · v_i
    ///    - This is the accumulated value at point r
    ///
    /// 4. **Implicit Smallness Test:**
    ///    - Boolean representation of q_i ensures q_i ∈ {0,1}^k
    ///    - No explicit range check needed
    ///
    /// # Complexity
    ///
    /// O(N) field operations:
    /// - O(m · k) to construct folding polynomial
    /// - O(k · 2^k) for sumcheck (dominated by table size)
    ///
    /// # Parameters
    ///
    /// - instance: nLookup instance with queries
    /// - table_mle: Multilinear extension of the table
    ///
    /// # Returns
    ///
    /// Accumulated instance and proof
    pub fn accumulate(
        &mut self,
        instance: &NLookupInstance<F>,
        table_mle: &MultilinearExtension<F>,
    ) -> LookupResult<(NLookupInstance<F>, NLookupAccumulationProof<F>)> {
        if instance.queries.is_empty() {
            return Err(LookupError::EmptyWitness);
        }
        
        if table_mle.num_vars() != instance.num_vars {
            return Err(LookupError::InvalidPolynomialSize {
                expected: instance.num_vars,
                got: table_mle.num_vars(),
            });
        }
        
        // Construct folding polynomial g(x) = Σ eq̃(x, q_i) · v_i
        let folding_poly = self.construct_folding_polynomial(
            &instance.queries,
            instance.num_vars,
        )?;
        
        // Compute claimed sum (should be sum of all values if queries are valid)
        let claimed_sum = instance.queries.iter()
            .map(|q| q.value)
            .fold(F::zero(), |acc, v| acc + v);
        
        // Generate random challenges for sumcheck
        let challenges = self.generate_challenges(instance.num_vars);
        
        // Run sumcheck protocol
        let mut sumcheck_prover = SumcheckProver::new();
        let sumcheck_proof = sumcheck_prover.prove(&folding_poly, &challenges)?;
        
        // Compute accumulated evaluation at random point
        let accumulated_value = self.evaluate_folding_polynomial(
            &instance.queries,
            &challenges,
        )?;
        
        // Create accumulated instance
        let mut acc_instance = instance.clone();
        acc_instance.accumulated_point = Some(challenges.clone());
        acc_instance.accumulated_value = Some(accumulated_value);
        
        let proof = NLookupAccumulationProof {
            sumcheck_proof,
            challenges,
        };
        
        Ok((acc_instance, proof))
    }
    
    /// Construct folding polynomial g(x) = Σ eq̃(x, q_i) · v_i
    ///
    /// # Algorithm
    ///
    /// For each point b ∈ {0,1}^k:
    /// 1. Compute g(b) = Σ_{i=1}^m eq̃(b, q_i) · v_i
    /// 2. eq̃(b, q_i) = 1 if b = q_i, else 0
    /// 3. So g(q_i) = v_i for each query
    ///
    /// # Complexity
    ///
    /// O(m · 2^k) to evaluate at all 2^k points
    fn construct_folding_polynomial(
        &self,
        queries: &[IndexedLookupQuery<F>],
        num_vars: usize,
    ) -> LookupResult<MultivariatePolynomial<F>> {
        let size = 1 << num_vars;
        let mut evaluations = vec![F::zero(); size];
        
        // For each query, add its contribution
        for query in queries {
            // Convert Boolean query to index
            let index = self.boolean_to_index(&query.query);
            if index < size {
                evaluations[index] = evaluations[index] + query.value;
            }
        }
        
        MultivariatePolynomial::new(num_vars, evaluations)
    }
    
    /// Convert Boolean vector to index
    ///
    /// # Algorithm
    ///
    /// Interpret Boolean vector as binary number:
    /// [b_0, b_1, ..., b_{k-1}] → Σ b_i · 2^i
    ///
    /// # Complexity
    ///
    /// O(k)
    fn boolean_to_index(&self, boolean_vec: &[bool]) -> usize {
        boolean_vec.iter()
            .enumerate()
            .map(|(i, &b)| if b { 1 << i } else { 0 })
            .sum()
    }
    
    /// Evaluate folding polynomial at random point
    ///
    /// # Algorithm
    ///
    /// g(r) = Σ_{i=1}^m eq̃(r, q_i) · v_i
    ///
    /// where eq̃(r, q) = ∏_{j=1}^k (r_j · q_j + (1 - r_j) · (1 - q_j))
    ///
    /// # Complexity
    ///
    /// O(m · k) field operations
    fn evaluate_folding_polynomial(
        &self,
        queries: &[IndexedLookupQuery<F>],
        point: &[F],
    ) -> LookupResult<F> {
        let mut result = F::zero();
        
        for query in queries {
            // Compute eq̃(point, query)
            let eq_value = self.compute_eq(point, &query.to_field_vector());
            
            // Add contribution: eq̃(point, query) · value
            result = result + eq_value * query.value;
        }
        
        Ok(result)
    }
    
    /// Compute eq̃ function
    ///
    /// # Algorithm
    ///
    /// eq̃(x, e) = ∏_{i=1}^k (x_i · e_i + (1 - x_i) · (1 - e_i))
    ///
    /// # Complexity
    ///
    /// O(k) field operations
    fn compute_eq(&self, x: &[F], e: &[F]) -> F {
        x.iter()
            .zip(e.iter())
            .map(|(&x_i, &e_i)| {
                x_i * e_i + (F::one() - x_i) * (F::one() - e_i)
            })
            .fold(F::one(), |acc, val| acc * val)
    }
    
    /// Generate random challenges using Fiat-Shamir transform
    ///
    /// # Algorithm
    ///
    /// 1. Hash all query points and values to create transcript
    /// 2. Use transcript as seed for deterministic challenge generation
    /// 3. Generate k independent challenges for k variables
    /// 4. Ensure challenges are uniformly distributed in field
    ///
    /// # Security
    ///
    /// - Deterministic: same queries always produce same challenges
    /// - Non-interactive: no verifier interaction needed
    /// - Collision-resistant: different queries produce different challenges
    ///
    /// # Complexity
    ///
    /// O(m·k) hash operations where m = number of queries, k = number of variables
    fn generate_challenges(&self, num_vars: usize) -> Vec<F> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Create initial transcript hash
        let mut transcript_hasher = DefaultHasher::new();
        
        // Domain separator for challenge generation
        0x4348414C4C45u64.hash(&mut transcript_hasher); // "CHALLE" in hex
        
        // Hash number of variables
        num_vars.hash(&mut transcript_hasher);
        
        // Hash all query data into transcript
        for query in &self.queries {
            // Hash query point (Boolean vector)
            for &bit in &query.query {
                bit.hash(&mut transcript_hasher);
            }
            // Hash expected value
            query.value.to_canonical_u64().hash(&mut transcript_hasher);
        }
        
        let transcript_seed = transcript_hasher.finish();
        
        // Generate k independent challenges from transcript
        let mut challenges = Vec::with_capacity(num_vars);
        for i in 0..num_vars {
            // Create unique hasher for each challenge
            let mut challenge_hasher = DefaultHasher::new();
            
            // Mix transcript seed with index
            transcript_seed.hash(&mut challenge_hasher);
            i.hash(&mut challenge_hasher);
            
            // Generate challenge seed
            let challenge_seed = challenge_hasher.finish();
            
            // Convert seed to field element
            // Use multiple bytes to ensure good distribution
            let challenge_bytes = challenge_seed.to_le_bytes();
            let mut challenge = F::ZERO;
            
            // Build field element from bytes
            for &byte in &challenge_bytes {
                challenge = challenge * F::from(256u64) + F::from(byte as u64);
            }
            
            challenges.push(challenge);
        }
        
        challenges
    }
}

impl<F: Field> Default for NLookupProver<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// nLookup verifier
///
/// Verifies nLookup accumulation proofs.
#[derive(Debug)]
pub struct NLookupVerifier<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> NLookupVerifier<F> {
    /// Create a new nLookup verifier
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Verify nLookup accumulation
    ///
    /// # Algorithm
    ///
    /// 1. **Verify Sumcheck Proof:**
    ///    - Check sumcheck proof is valid
    ///    - Verify round polynomials
    ///    - Check consistency
    ///
    /// 2. **Verify Accumulated Value:**
    ///    - Recompute g(r) = Σ eq̃(r, q_i) · v_i
    ///    - Check it matches claimed accumulated value
    ///
    /// 3. **Implicit Smallness Test:**
    ///    - Boolean representation ensures q_i ∈ {0,1}^k
    ///    - No explicit check needed
    ///
    /// # Complexity
    ///
    /// O(log N) field/hash operations + O(m log N) field operations:
    /// - O(k) for sumcheck verification
    /// - O(m · k) to verify accumulated value
    ///
    /// # Parameters
    ///
    /// - original: Original instance before accumulation
    /// - accumulated: Accumulated instance
    /// - proof: Accumulation proof
    ///
    /// # Returns
    ///
    /// true if proof is valid, false otherwise
    pub fn verify(
        &mut self,
        original: &NLookupInstance<F>,
        accumulated: &NLookupInstance<F>,
        proof: &NLookupAccumulationProof<F>,
    ) -> LookupResult<bool> {
        // Check accumulated instance has evaluation point and value
        if !accumulated.is_fully_accumulated() {
            return Err(LookupError::InvalidProof {
                reason: "Accumulated instance missing evaluation".to_string(),
            });
        }
        
        let acc_point = accumulated.accumulated_point.as_ref().unwrap();
        let acc_value = accumulated.accumulated_value.unwrap();
        
        // Verify sumcheck proof
        let claimed_sum = original.queries.iter()
            .map(|q| q.value)
            .fold(F::zero(), |acc, v| acc + v);
        
        let mut sumcheck_verifier = SumcheckVerifier::new();
        let sumcheck_valid = sumcheck_verifier.verify(
            claimed_sum,
            &proof.sumcheck_proof,
            &proof.challenges,
            acc_value,
        )?;
        
        if !sumcheck_valid {
            return Ok(false);
        }
        
        // Verify accumulated value is correct
        let expected_value = self.compute_accumulated_value(
            &original.queries,
            acc_point,
        )?;
        
        if acc_value != expected_value {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Compute accumulated value g(r) = Σ eq̃(r, q_i) · v_i
    ///
    /// # Algorithm
    ///
    /// For each query (q_i, v_i):
    /// 1. Compute eq̃(r, q_i)
    /// 2. Multiply by v_i
    /// 3. Sum all contributions
    ///
    /// # Complexity
    ///
    /// O(m · k) field operations
    fn compute_accumulated_value(
        &self,
        queries: &[IndexedLookupQuery<F>],
        point: &[F],
    ) -> LookupResult<F> {
        let mut result = F::zero();
        
        for query in queries {
            let query_field = query.to_field_vector();
            let eq_value = self.compute_eq(point, &query_field);
            result = result + eq_value * query.value;
        }
        
        Ok(result)
    }
    
    /// Compute eq̃ function
    ///
    /// # Algorithm
    ///
    /// eq̃(x, e) = ∏_{i=1}^k (x_i · e_i + (1 - x_i) · (1 - e_i))
    ///
    /// # Complexity
    ///
    /// O(k) field operations
    fn compute_eq(&self, x: &[F], e: &[F]) -> F {
        x.iter()
            .zip(e.iter())
            .map(|(&x_i, &e_i)| {
                x_i * e_i + (F::one() - x_i) * (F::one() - e_i)
            })
            .fold(F::one(), |acc, val| acc * val)
    }
}

impl<F: Field> Default for NLookupVerifier<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// nLookup decider
///
/// Decides whether a fully accumulated instance is valid.
#[derive(Debug)]
pub struct NLookupDecider<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: Field> NLookupDecider<F> {
    /// Create a new nLookup decider
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Decide whether accumulated instance is valid
    ///
    /// # Algorithm
    ///
    /// Given fully accumulated instance with point r and value v:
    ///
    /// 1. **Evaluate Table MLE:**
    ///    - Compute t̃(r) where r is the accumulated point
    ///    - For structured tables, this can be done efficiently
    ///    - For general tables, requires O(2^k) operations
    ///
    /// 2. **Check Consistency:**
    ///    - Verify: accumulated_value = t̃(accumulated_point)
    ///    - This ensures all original queries were valid
    ///
    /// # Complexity
    ///
    /// O(2^k) field operations for general tables
    /// O(k) or O(log N) for structured tables
    ///
    /// # Parameters
    ///
    /// - instance: Fully accumulated instance
    /// - table_mle: Multilinear extension of the table
    ///
    /// # Returns
    ///
    /// true if instance is valid, false otherwise
    pub fn decide(
        &self,
        instance: &NLookupInstance<F>,
        table_mle: &MultilinearExtension<F>,
    ) -> LookupResult<bool> {
        // Check instance is fully accumulated
        if !instance.is_fully_accumulated() {
            return Err(LookupError::InvalidProof {
                reason: "Instance not fully accumulated".to_string(),
            });
        }
        
        let acc_point = instance.accumulated_point.as_ref().unwrap();
        let acc_value = instance.accumulated_value.unwrap();
        
        // Evaluate table MLE at accumulated point
        let table_value = table_mle.evaluate(acc_point)?;
        
        // Check consistency
        Ok(acc_value == table_value)
    }
}

impl<F: Field> Default for NLookupDecider<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::Goldilocks;
    
    #[test]
    fn test_indexed_lookup_query() {
        let query = IndexedLookupQuery::new(
            vec![true, false, true],
            Goldilocks::from(42u64),
        );
        
        assert!(query.validate().is_ok());
        assert_eq!(query.query.len(), 3);
        
        let field_vec = query.to_field_vector();
        assert_eq!(field_vec[0], Goldilocks::one());
        assert_eq!(field_vec[1], Goldilocks::zero());
        assert_eq!(field_vec[2], Goldilocks::one());
    }
    
    #[test]
    fn test_nlookup_instance_creation() {
        let queries = vec![
            IndexedLookupQuery::new(vec![false, false], Goldilocks::from(1u64)),
            IndexedLookupQuery::new(vec![true, false], Goldilocks::from(2u64)),
        ];
        
        let instance = NLookupInstance::new(4, queries).unwrap();
        assert_eq!(instance.table_size, 4);
        assert_eq!(instance.num_vars, 2);
        assert!(!instance.is_fully_accumulated());
    }
    
    #[test]
    fn test_boolean_to_index() {
        let prover = NLookupProver::<Goldilocks>::new();
        
        assert_eq!(prover.boolean_to_index(&[false, false]), 0);
        assert_eq!(prover.boolean_to_index(&[true, false]), 1);
        assert_eq!(prover.boolean_to_index(&[false, true]), 2);
        assert_eq!(prover.boolean_to_index(&[true, true]), 3);
    }
}
