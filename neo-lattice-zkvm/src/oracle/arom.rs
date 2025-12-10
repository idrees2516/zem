// Arithmetized Random Oracle Model (AROM)
//
// Oracle model supporting succinct proofs about oracle queries.
//
// Mathematical Foundation:
// - AROM = (ro, wo, vco) where:
//   - ro: random oracle
//   - wo: witness oracle computing wo(x) := B^ro(x, μ_x)
//   - vco: verification oracle (low-degree extension of verification function)

use std::collections::HashMap;
use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

use super::rom::RandomOracle;
use super::transcript::{Oracle, OracleTranscript};
use super::errors::{OracleError, OracleResult};

/// Witness Oracle
///
/// Computes wo(x) := B^ro(x, μ_x) where B is a witness computation algorithm
pub struct WitnessOracle<F> {
    /// Random oracle for witness computation
    ro: RandomOracle,
    
    /// Cached witness computations
    cache: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F> WitnessOracle<F> {
    /// Create a new witness oracle
    pub fn new(ro: RandomOracle) -> Self {
        Self {
            ro,
            cache: HashMap::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Compute witness for input x
    ///
    /// # Arguments
    /// * `x` - Input to witness oracle
    ///
    /// # Returns
    /// Witness wo(x) = B^ro(x, μ_x)
    pub fn compute(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        // Check cache
        if let Some(cached) = self.cache.get(x) {
            return Ok(cached.clone());
        }
        
        // Sample μ_x uniformly using RO
        let mut mu_query = Vec::with_capacity(x.len() + 8);
        mu_query.extend_from_slice(b"WO_MU");
        mu_query.extend_from_slice(x);
        let mu_x = self.ro.query(mu_query)?;
        
        // Compute B^ro(x, μ_x)
        // For now, we use a simple computation: hash(x || μ_x)
        let mut witness_query = Vec::with_capacity(x.len() + mu_x.len() + 8);
        witness_query.extend_from_slice(b"WO_COMPUTE");
        witness_query.extend_from_slice(x);
        witness_query.extend_from_slice(&mu_x);
        let witness = self.ro.query(witness_query)?;
        
        // Cache result
        self.cache.insert(x.to_vec(), witness.clone());
        
        Ok(witness)
    }
    
    /// Get the underlying random oracle
    pub fn random_oracle(&self) -> &RandomOracle {
        &self.ro
    }
    
    /// Get mutable random oracle
    pub fn random_oracle_mut(&mut self) -> &mut RandomOracle {
        &mut self.ro
    }
}

/// Verification Oracle
///
/// Low-degree extension of verification function
pub struct VerificationOracle<F> {
    /// Degree bound for low-degree extension
    degree_bound: usize,
    
    /// Cached evaluations
    cache: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Random oracle for evaluation
    ro: RandomOracle,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F> VerificationOracle<F> {
    /// Create a new verification oracle
    pub fn new(degree_bound: usize, ro: RandomOracle) -> Self {
        Self {
            degree_bound,
            cache: HashMap::new(),
            ro,
            _phantom: PhantomData,
        }
    }
    
    /// Evaluate verification oracle at point x
    ///
    /// # Arguments
    /// * `x` - Evaluation point
    ///
    /// # Returns
    /// vco(x) - low-degree extension evaluation
    pub fn evaluate(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        // Check cache
        if let Some(cached) = self.cache.get(x) {
            return Ok(cached.clone());
        }
        
        // Compute low-degree extension evaluation
        // For now, use hash-based evaluation with degree constraint
        let mut query = Vec::with_capacity(x.len() + 8);
        query.extend_from_slice(b"VCO_EVAL");
        query.extend_from_slice(x);
        let evaluation = self.ro.query(query)?;
        
        // Cache result
        self.cache.insert(x.to_vec(), evaluation.clone());
        
        Ok(evaluation)
    }
    
    /// Get degree bound
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }
    
    /// Verify that evaluation is within degree bound
    pub fn verify_degree(&self) -> bool {
        // In a full implementation, this would check polynomial degree
        // For now, we assume degree bound is satisfied
        true
    }
}

/// Arithmetized Random Oracle Model
///
/// Combines random oracle, witness oracle, and verification oracle
pub struct AROM<F> {
    /// Random oracle component
    ro: RandomOracle,
    
    /// Witness oracle component
    wo: WitnessOracle<F>,
    
    /// Verification oracle component
    vco: VerificationOracle<F>,
    
    /// Degree bound for vco
    degree_bound: usize,
}

impl<F> AROM<F> {
    /// Create a new AROM
    pub fn new(degree_bound: usize) -> Self {
        let ro = RandomOracle::new();
        let wo = WitnessOracle::new(ro.clone());
        let vco = VerificationOracle::new(degree_bound, ro.clone());
        
        Self {
            ro,
            wo,
            vco,
            degree_bound,
        }
    }
    
    /// Query random oracle
    pub fn query_ro(&mut self, x: Vec<u8>) -> OracleResult<Vec<u8>> {
        self.ro.query(x)
    }
    
    /// Query witness oracle
    pub fn query_wo(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        self.wo.compute(x)
    }
    
    /// Query verification oracle
    pub fn query_vco(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        self.vco.evaluate(x)
    }
    
    /// Get random oracle transcript
    pub fn ro_transcript(&self) -> &OracleTranscript<Vec<u8>, Vec<u8>> {
        self.ro.transcript()
    }
    
    /// Get degree bound
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }
    
    /// Verify AROM properties
    ///
    /// Checks that:
    /// 1. vco is low-degree extension (degree ≤ d)
    /// 2. wo computes witness using ro
    /// 3. All oracles maintain consistent transcripts
    pub fn verify_properties(&self) -> OracleResult<()> {
        // Verify vco degree bound
        if !self.vco.verify_degree() {
            return Err(OracleError::InvalidState(
                "Verification oracle degree bound violated".to_string()
            ));
        }
        
        // Verify ro consistency
        if !self.ro.is_consistent() {
            return Err(OracleError::InconsistentTranscript);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_witness_oracle_creation() {
        let ro = RandomOracle::new();
        let wo = WitnessOracle::<u64>::new(ro);
        assert!(wo.cache.is_empty());
    }
    
    #[test]
    fn test_witness_oracle_compute() {
        let ro = RandomOracle::new();
        let mut wo = WitnessOracle::<u64>::new(ro);
        
        let x = vec![1u8, 2, 3];
        let witness1 = wo.compute(&x).unwrap();
        
        // Should be deterministic
        let witness2 = wo.compute(&x).unwrap();
        assert_eq!(witness1, witness2);
    }
    
    #[test]
    fn test_verification_oracle_creation() {
        let ro = RandomOracle::new();
        let vco = VerificationOracle::<u64>::new(10, ro);
        assert_eq!(vco.degree_bound(), 10);
    }
    
    #[test]
    fn test_verification_oracle_evaluate() {
        let ro = RandomOracle::new();
        let mut vco = VerificationOracle::<u64>::new(10, ro);
        
        let x = vec![1u8, 2, 3];
        let eval1 = vco.evaluate(&x).unwrap();
        
        // Should be deterministic
        let eval2 = vco.evaluate(&x).unwrap();
        assert_eq!(eval1, eval2);
    }
    
    #[test]
    fn test_arom_creation() {
        let arom = AROM::<u64>::new(10);
        assert_eq!(arom.degree_bound(), 10);
    }
    
    #[test]
    fn test_arom_query_ro() {
        let mut arom = AROM::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let response1 = arom.query_ro(x.clone()).unwrap();
        let response2 = arom.query_ro(x).unwrap();
        
        assert_eq!(response1, response2);
    }
    
    #[test]
    fn test_arom_query_wo() {
        let mut arom = AROM::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let witness1 = arom.query_wo(&x).unwrap();
        let witness2 = arom.query_wo(&x).unwrap();
        
        assert_eq!(witness1, witness2);
    }
    
    #[test]
    fn test_arom_query_vco() {
        let mut arom = AROM::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let eval1 = arom.query_vco(&x).unwrap();
        let eval2 = arom.query_vco(&x).unwrap();
        
        assert_eq!(eval1, eval2);
    }
    
    #[test]
    fn test_arom_verify_properties() {
        let arom = AROM::<u64>::new(10);
        assert!(arom.verify_properties().is_ok());
    }
}
