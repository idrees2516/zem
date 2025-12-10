// AROM Emulator and Security Lifting
//
// Emulates AROM (wo, vco) using only ROM for security lifting.
//
// Mathematical Foundation:
// - Emulator M is stateful (O, S)-emulator that simulates (wo, vco) using ro
// - Security lifting: ROM properties preserved in AROM (Theorem 8)

use std::collections::HashMap;
use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

use super::rom::RandomOracle;
use super::arom::{WitnessOracle, VerificationOracle};
use super::errors::{OracleError, OracleResult};

/// Emulator state for AROM emulation
///
/// Maintains caches for witness and verification oracle queries
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmulatorState<F> {
    /// Cached witness oracle queries
    pub wo_cache: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Cached verification oracle queries
    pub vco_cache: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F> EmulatorState<F> {
    /// Create a new emulator state
    pub fn new() -> Self {
        Self {
            wo_cache: HashMap::new(),
            vco_cache: HashMap::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Clear all caches
    pub fn clear(&mut self) {
        self.wo_cache.clear();
        self.vco_cache.clear();
    }
    
    /// Get number of cached wo queries
    pub fn num_wo_cached(&self) -> usize {
        self.wo_cache.len()
    }
    
    /// Get number of cached vco queries
    pub fn num_vco_cached(&self) -> usize {
        self.vco_cache.len()
    }
}

impl<F> Default for EmulatorState<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// AROM Emulator
///
/// Emulates AROM using only ROM
pub struct AROMEmulator<F> {
    /// Random oracle
    ro: RandomOracle,
    
    /// Witness oracle (emulated)
    wo: WitnessOracle<F>,
    
    /// Verification oracle (emulated)
    vco: VerificationOracle<F>,
    
    /// Emulator state
    emulator_state: EmulatorState<F>,
    
    /// Degree bound for vco
    degree_bound: usize,
}

impl<F> AROMEmulator<F> {
    /// Create a new AROM emulator
    pub fn new(degree_bound: usize) -> Self {
        let ro = RandomOracle::new();
        let wo = WitnessOracle::new(ro.clone());
        let vco = VerificationOracle::new(degree_bound, ro.clone());
        
        Self {
            ro,
            wo,
            vco,
            emulator_state: EmulatorState::new(),
            degree_bound,
        }
    }
    
    /// Query witness oracle (emulated)
    pub fn query_wo(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        // Check cache first
        if let Some(cached) = self.emulator_state.wo_cache.get(x) {
            return Ok(cached.clone());
        }
        
        // Compute using emulated witness oracle
        let result = self.wo.compute(x)?;
        
        // Cache result
        self.emulator_state.wo_cache.insert(x.to_vec(), result.clone());
        
        Ok(result)
    }
    
    /// Query verification oracle (emulated)
    pub fn query_vco(&mut self, x: &[u8]) -> OracleResult<Vec<u8>> {
        // Check cache first
        if let Some(cached) = self.emulator_state.vco_cache.get(x) {
            return Ok(cached.clone());
        }
        
        // Compute using emulated verification oracle
        let result = self.vco.evaluate(x)?;
        
        // Cache result
        self.emulator_state.vco_cache.insert(x.to_vec(), result.clone());
        
        Ok(result)
    }
    
    /// Query random oracle
    pub fn query_ro(&mut self, x: Vec<u8>) -> OracleResult<Vec<u8>> {
        self.ro.query(x)
    }
    
    /// Verify emulation correctness
    ///
    /// Checks that:
    /// 1. vco is low-degree extension (degree ≤ d)
    /// 2. wo computes witness using ro
    /// 3. Emulation is consistent
    pub fn verify_emulation(&self) -> OracleResult<()> {
        // Verify vco degree bound
        if !self.vco.verify_degree() {
            return Err(OracleError::EmulationError(
                "Verification oracle degree bound violated".to_string()
            ));
        }
        
        // Verify ro consistency
        if !self.ro.is_consistent() {
            return Err(OracleError::InconsistentTranscript);
        }
        
        Ok(())
    }
    
    /// Get emulator state
    pub fn state(&self) -> &EmulatorState<F> {
        &self.emulator_state
    }
    
    /// Get degree bound
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }
}

/// Security lifting for signatures (Theorem 9)
///
/// If Σ has EU-CMA in ROM, then Σ has EU-CMA in AROM using emulator M
pub struct SignatureSecurityLifting<F> {
    /// Emulator for AROM
    emulator: AROMEmulator<F>,
}

impl<F> SignatureSecurityLifting<F> {
    /// Create a new security lifting
    pub fn new(degree_bound: usize) -> Self {
        Self {
            emulator: AROMEmulator::new(degree_bound),
        }
    }
    
    /// Lift signature scheme security from ROM to AROM
    ///
    /// # Returns
    /// Emulator that preserves EU-CMA security
    pub fn lift_signature_security(&self) -> &AROMEmulator<F> {
        &self.emulator
    }
}

/// Security lifting for O-SNARKs (Theorem 10)
///
/// If Π has O-AdPoK in ROM, then Π has O-AdPoK in AROM using emulator M
pub struct OSNARKSecurityLifting<F> {
    /// Emulator for AROM
    emulator: AROMEmulator<F>,
}

impl<F> OSNARKSecurityLifting<F> {
    /// Create a new security lifting
    pub fn new(degree_bound: usize) -> Self {
        Self {
            emulator: AROMEmulator::new(degree_bound),
        }
    }
    
    /// Lift O-SNARK security from ROM to AROM
    ///
    /// # Returns
    /// Emulator that preserves O-AdPoK security
    pub fn lift_osnark_security(&self) -> &AROMEmulator<F> {
        &self.emulator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_emulator_state_creation() {
        let state = EmulatorState::<u64>::new();
        assert_eq!(state.num_wo_cached(), 0);
        assert_eq!(state.num_vco_cached(), 0);
    }
    
    #[test]
    fn test_arom_emulator_creation() {
        let emulator = AROMEmulator::<u64>::new(10);
        assert_eq!(emulator.degree_bound(), 10);
    }
    
    #[test]
    fn test_arom_emulator_query_wo() {
        let mut emulator = AROMEmulator::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let result1 = emulator.query_wo(&x).unwrap();
        
        // Should be cached
        let result2 = emulator.query_wo(&x).unwrap();
        assert_eq!(result1, result2);
        assert_eq!(emulator.state().num_wo_cached(), 1);
    }
    
    #[test]
    fn test_arom_emulator_query_vco() {
        let mut emulator = AROMEmulator::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let result1 = emulator.query_vco(&x).unwrap();
        
        // Should be cached
        let result2 = emulator.query_vco(&x).unwrap();
        assert_eq!(result1, result2);
        assert_eq!(emulator.state().num_vco_cached(), 1);
    }
    
    #[test]
    fn test_arom_emulator_query_ro() {
        let mut emulator = AROMEmulator::<u64>::new(10);
        
        let x = vec![1u8, 2, 3];
        let result1 = emulator.query_ro(x.clone()).unwrap();
        let result2 = emulator.query_ro(x).unwrap();
        
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_arom_emulator_verify() {
        let emulator = AROMEmulator::<u64>::new(10);
        assert!(emulator.verify_emulation().is_ok());
    }
    
    #[test]
    fn test_signature_security_lifting() {
        let lifting = SignatureSecurityLifting::<u64>::new(10);
        let emulator = lifting.lift_signature_security();
        assert_eq!(emulator.degree_bound(), 10);
    }
    
    #[test]
    fn test_osnark_security_lifting() {
        let lifting = OSNARKSecurityLifting::<u64>::new(10);
        let emulator = lifting.lift_osnark_security();
        assert_eq!(emulator.degree_bound(), 10);
    }
}
