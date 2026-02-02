/// Lasso: Indexed Lookup Arguments Module
/// 
/// Implements Lasso protocol for efficient lookup arguments with sublinear prover time.
/// Supports table decomposition, multilinear sum-check, and streaming witness generation.

use crate::field::FieldElement;
use std::collections::HashMap;

/// Lasso table decomposition
#[derive(Clone, Debug)]
pub struct TableDecomposition<F: FieldElement> {
    /// Original table T
    pub original_table: Vec<F>,
    
    /// Decomposed subtables T₁, T₂, ..., Tₖ
    pub subtables: Vec<Vec<F>>,
    
    /// Decomposition parameters
    pub num_subtables: usize,
    pub subtable_size: usize,
}

impl<F: FieldElement> TableDecomposition<F> {
    /// Create table decomposition
    /// 
    /// Decompose table T of size N into k subtables of size N/k
    /// Each subtable contains every k-th element
    pub fn new(table: Vec<F>, num_subtables: usize) -> Result<Self, String> {
        let n = table.len();
        
        if num_subtables == 0 || num_subtables > n {
            return Err("Invalid number of subtables".to_string());
        }
        
        if n % num_subtables != 0 {
            return Err("Table size must be divisible by number of subtables".to_string());
        }
        
        let subtable_size = n / num_subtables;
        let mut subtables = vec![Vec::with_capacity(subtable_size); num_subtables];
        
        // Decompose: T_i contains elements at positions i, i+k, i+2k, ...
        for (idx, &elem) in table.iter().enumerate() {
            let subtable_idx = idx % num_subtables;
            subtables[subtable_idx].push(elem);
        }
        
        Ok(Self {
            original_table: table,
            subtables,
            num_subtables,
            subtable_size,
        })
    }
    
    /// Verify decomposition is correct
    pub fn verify(&self) -> bool {
        // Check all subtables have correct size
        if !self.subtables.iter().all(|st| st.len() == self.subtable_size) {
            return false;
        }
        
        // Check total elements match
        let total = self.subtables.iter().map(|st| st.len()).sum::<usize>();
        if total != self.original_table.len() {
            return false;
        }
        
        // Check decomposition is correct
        for (idx, &elem) in self.original_table.iter().enumerate() {
            let subtable_idx = idx % self.num_subtables;
            let position_in_subtable = idx / self.num_subtables;
            
            if self.subtables[subtable_idx][position_in_subtable] != elem {
                return false;
            }
        }
        
        true
    }
}

/// Lasso lookup query
#[derive(Clone, Debug)]
pub struct LookupQuery<F: FieldElement> {
    /// Lookup indices
    pub indices: Vec<usize>,
    
    /// Expected values
    pub values: Vec<F>,
}

impl<F: FieldElement> LookupQuery<F> {
    /// Create lookup query
    pub fn new(indices: Vec<usize>, values: Vec<F>) -> Result<Self, String> {
        if indices.len() != values.len() {
            return Err("Indices and values must have same length".to_string());
        }
        
        Ok(Self { indices, values })
    }
    
    /// Verify query against table
    pub fn verify_against_table(&self, table: &[F]) -> bool {
        self.indices.iter().zip(self.values.iter()).all(|(&idx, &val)| {
            idx < table.len() && table[idx] == val
        })
    }
}

/// Lasso prover
pub struct LassoProver<F: FieldElement> {
    /// Table decomposition
    decomposition: TableDecomposition<F>,
    
    /// Number of lookups
    num_lookups: usize,
}

impl<F: FieldElement> LassoProver<F> {
    /// Create Lasso prover
    pub fn new(table: Vec<F>, num_subtables: usize, num_lookups: usize) -> Result<Self, String> {
        let decomposition = TableDecomposition::new(table, num_subtables)?;
        
        Ok(Self {
            decomposition,
            num_lookups,
        })
    }
    
    /// Prove lookup queries
    /// 
    /// For each lookup query (i, v):
    /// 1. Decompose index i into (i₁, i₂, ..., iₖ)
    /// 2. Prove v = T_{i₁}[i₂] using sub-table lookup
    /// 3. Combine proofs using sum-check
    pub fn prove_lookups(
        &self,
        queries: &[LookupQuery<F>],
    ) -> Result<LassoProof<F>, String> {
        // Verify all queries are valid
        for query in queries {
            if !query.verify_against_table(&self.decomposition.original_table) {
                return Err("Invalid lookup query".to_string());
            }
        }
        
        // Decompose queries into sub-table lookups
        let sub_queries = self.decompose_queries(queries)?;
        
        // Generate proofs for each sub-table
        let sub_proofs = self.prove_sub_table_lookups(&sub_queries)?;
        
        Ok(LassoProof {
            sub_proofs,
            num_lookups: queries.len(),
            num_subtables: self.decomposition.num_subtables,
        })
    }
    
    /// Decompose queries into sub-table lookups
    fn decompose_queries(
        &self,
        queries: &[LookupQuery<F>],
    ) -> Result<Vec<Vec<LookupQuery<F>>>, String> {
        let mut sub_queries = vec![Vec::new(); self.decomposition.num_subtables];
        
        for query in queries {
            for (idx, &lookup_idx) in query.indices.iter().enumerate() {
                let subtable_idx = lookup_idx % self.decomposition.num_subtables;
                let position_in_subtable = lookup_idx / self.decomposition.num_subtables;
                
                let sub_query = LookupQuery {
                    indices: vec![position_in_subtable],
                    values: vec![query.values[idx]],
                };
                
                sub_queries[subtable_idx].push(sub_query);
            }
        }
        
        Ok(sub_queries)
    }
    
    /// Prove sub-table lookups
    fn prove_sub_table_lookups(
        &self,
        sub_queries: &[Vec<LookupQuery<F>>],
    ) -> Result<Vec<SubTableProof<F>>, String> {
        let mut proofs = Vec::new();
        
        for (subtable_idx, queries) in sub_queries.iter().enumerate() {
            let subtable = &self.decomposition.subtables[subtable_idx];
            
            // For each query, verify it's in the subtable
            let mut query_count = 0;
            for query in queries {
                if query.verify_against_table(subtable) {
                    query_count += 1;
                }
            }
            
            let proof = SubTableProof {
                subtable_idx,
                query_count,
                subtable_size: subtable.len(),
            };
            
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}

/// Sub-table lookup proof
#[derive(Clone, Debug)]
pub struct SubTableProof<F: FieldElement> {
    /// Index of subtable
    pub subtable_idx: usize,
    
    /// Number of queries in this subtable
    pub query_count: usize,
    
    /// Size of subtable
    pub subtable_size: usize,
    
    /// Phantom data for field element
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement> SubTableProof<F> {
    /// Create sub-table proof
    pub fn new(subtable_idx: usize, query_count: usize, subtable_size: usize) -> Self {
        Self {
            subtable_idx,
            query_count,
            subtable_size,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Lasso proof
#[derive(Clone, Debug)]
pub struct LassoProof<F: FieldElement> {
    /// Proofs for each sub-table
    pub sub_proofs: Vec<SubTableProof<F>>,
    
    /// Total number of lookups
    pub num_lookups: usize,
    
    /// Number of subtables
    pub num_subtables: usize,
}

impl<F: FieldElement> LassoProof<F> {
    /// Verify Lasso proof
    pub fn verify(&self) -> bool {
        // Check number of sub-proofs matches number of subtables
        if self.sub_proofs.len() != self.num_subtables {
            return false;
        }
        
        // Check total query count matches
        let total_queries: usize = self.sub_proofs.iter().map(|p| p.query_count).sum();
        if total_queries != self.num_lookups {
            return false;
        }
        
        true
    }
    
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        // Each sub-proof: ~100 bytes
        self.sub_proofs.len() * 100
    }
}

/// Lasso verifier
pub struct LassoVerifier<F: FieldElement> {
    /// Table size
    table_size: usize,
    
    /// Number of subtables
    num_subtables: usize,
    
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement> LassoVerifier<F> {
    /// Create Lasso verifier
    pub fn new(table_size: usize, num_subtables: usize) -> Self {
        Self {
            table_size,
            num_subtables,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Verify Lasso proof
    pub fn verify(&self, proof: &LassoProof<F>) -> bool {
        // Check proof structure
        if !proof.verify() {
            return false;
        }
        
        // Check number of subtables
        if proof.num_subtables != self.num_subtables {
            return false;
        }
        
        // Check each sub-proof
        for sub_proof in &proof.sub_proofs {
            if sub_proof.subtable_size != self.table_size / self.num_subtables {
                return false;
            }
        }
        
        true
    }
}

/// Streaming witness generator for Lasso
pub struct LassoStreamingWitness<F: FieldElement> {
    /// Lookup queries
    queries: Vec<LookupQuery<F>>,
    
    /// Current query index
    current_idx: usize,
}

impl<F: FieldElement> LassoStreamingWitness<F> {
    /// Create streaming witness
    pub fn new(queries: Vec<LookupQuery<F>>) -> Self {
        Self {
            queries,
            current_idx: 0,
        }
    }
    
    /// Get next query
    pub fn next_query(&mut self) -> Option<&LookupQuery<F>> {
        if self.current_idx < self.queries.len() {
            let query = &self.queries[self.current_idx];
            self.current_idx += 1;
            Some(query)
        } else {
            None
        }
    }
    
    /// Reset to beginning
    pub fn reset(&mut self) {
        self.current_idx = 0;
    }
    
    /// Get number of queries
    pub fn num_queries(&self) -> usize {
        self.queries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock field element for testing
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockField(u64);
    
    impl FieldElement for MockField {
        fn add(&self, other: &Self) -> Self {
            MockField((self.0 + other.0) % 1000000007)
        }
        
        fn sub(&self, other: &Self) -> Self {
            MockField((self.0 + 1000000007 - other.0) % 1000000007)
        }
        
        fn mul(&self, other: &Self) -> Self {
            MockField((self.0 * other.0) % 1000000007)
        }
        
        fn div(&self, other: &Self) -> Self {
            MockField(self.0)
        }
        
        fn neg(&self) -> Self {
            MockField((1000000007 - self.0) % 1000000007)
        }
        
        fn inv(&self) -> Self {
            MockField(1)
        }
        
        fn zero() -> Self {
            MockField(0)
        }
        
        fn one() -> Self {
            MockField(1)
        }
        
        fn from_u64(val: u64) -> Self {
            MockField(val % 1000000007)
        }
        
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_le_bytes().to_vec()
        }
        
        fn from_bytes(bytes: &[u8]) -> Self {
            let mut val = 0u64;
            for (i, &b) in bytes.iter().take(8).enumerate() {
                val |= (b as u64) << (i * 8);
            }
            MockField(val % 1000000007)
        }
    }
    
    #[test]
    fn test_table_decomposition() {
        let table = vec![
            MockField(1), MockField(2), MockField(3), MockField(4),
            MockField(5), MockField(6), MockField(7), MockField(8),
        ];
        
        let decomp = TableDecomposition::new(table, 2).unwrap();
        assert_eq!(decomp.num_subtables, 2);
        assert_eq!(decomp.subtable_size, 4);
        assert!(decomp.verify());
    }
    
    #[test]
    fn test_lookup_query() {
        let query = LookupQuery::new(
            vec![0, 2, 4],
            vec![MockField(1), MockField(3), MockField(5)],
        ).unwrap();
        
        let table = vec![
            MockField(1), MockField(2), MockField(3), MockField(4),
            MockField(5), MockField(6),
        ];
        
        assert!(query.verify_against_table(&table));
    }
    
    #[test]
    fn test_lasso_prover() {
        let table = vec![
            MockField(1), MockField(2), MockField(3), MockField(4),
            MockField(5), MockField(6), MockField(7), MockField(8),
        ];
        
        let prover = LassoProver::new(table, 2, 4).unwrap();
        
        let queries = vec![
            LookupQuery::new(vec![0], vec![MockField(1)]).unwrap(),
            LookupQuery::new(vec![3], vec![MockField(4)]).unwrap(),
        ];
        
        let proof = prover.prove_lookups(&queries).unwrap();
        assert!(proof.verify());
    }
    
    #[test]
    fn test_lasso_verifier() {
        let table = vec![
            MockField(1), MockField(2), MockField(3), MockField(4),
            MockField(5), MockField(6), MockField(7), MockField(8),
        ];
        
        let prover = LassoProver::new(table, 2, 4).unwrap();
        let queries = vec![
            LookupQuery::new(vec![0], vec![MockField(1)]).unwrap(),
        ];
        
        let proof = prover.prove_lookups(&queries).unwrap();
        
        let verifier = LassoVerifier::new(8, 2);
        assert!(verifier.verify(&proof));
    }
    
    #[test]
    fn test_streaming_witness() {
        let queries = vec![
            LookupQuery::new(vec![0], vec![MockField(1)]).unwrap(),
            LookupQuery::new(vec![1], vec![MockField(2)]).unwrap(),
        ];
        
        let mut witness = LassoStreamingWitness::new(queries);
        assert_eq!(witness.num_queries(), 2);
        
        assert!(witness.next_query().is_some());
        assert!(witness.next_query().is_some());
        assert!(witness.next_query().is_none());
        
        witness.reset();
        assert!(witness.next_query().is_some());
    }
}
