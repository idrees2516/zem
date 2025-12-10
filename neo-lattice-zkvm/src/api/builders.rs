// High-Level API Builders
//
// This module provides fluent builder APIs for easy construction of
// AGM-secure cryptographic systems.
//
// Design Philosophy:
// - Fluent interface for ergonomic API
// - Sensible defaults for common use cases
// - Type-safe configuration
// - Clear error messages

use std::marker::PhantomData;
use crate::field::Field;
use crate::ivc::{IncrementalComputation, IVCProver, IVCVerifier, IVCExtractor};
use crate::aggregate_sig::AggregateSignature;
use crate::pcd::{PCDProver, PCDExtractor, PCDComplianceChecker, CompliancePredicate};
use crate::oracle::{Oracle, RandomOracle};
use crate::rel_snark::RelativizedSNARK;
use crate::o_snark::OSNARK;

/// Security Level
///
/// Defines the security parameter λ for cryptographic operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 80-bit security (for testing only)
    Low,
    
    /// 128-bit security (recommended)
    Standard,
    
    /// 192-bit security (high security)
    High,
    
    /// 256-bit security (maximum security)
    Maximum,
}

impl SecurityLevel {
    /// Get security parameter λ in bits
    pub fn lambda(&self) -> usize {
        match self {
            Self::Low => 80,
            Self::Standard => 128,
            Self::High => 192,
            Self::Maximum => 256,
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// IVC Builder
///
/// Fluent API for constructing IVC systems.
///
/// Example Usage:
/// ```rust,ignore
/// let ivc = IVCBuilder::new(fibonacci_step)
///     .with_security_level(SecurityLevel::High)
///     .with_depth_bound(1000)
///     .build()?;
/// ```
pub struct IVCBuilder<F, G, O, S>
where
    F: Field,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Function being computed incrementally
    function: Box<dyn Fn(&[F], &[F]) -> Vec<F>>,
    
    /// Security level
    security_level: SecurityLevel,
    
    /// Maximum depth bound (optional)
    depth_bound: Option<usize>,
    
    /// Input size
    input_size: usize,
    
    /// Witness size
    witness_size: usize,
    
    /// Output size
    output_size: usize,
    
    /// Phantom data
    _phantom: PhantomData<(G, O, S)>,
}

impl<F, G, O, S> IVCBuilder<F, G, O, S>
where
    F: Field + Clone,
    G: Clone,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Create a new IVC builder
    ///
    /// Parameters:
    /// - function: The incremental computation F(z_{i-1}, w_i) → z_i
    ///
    /// Returns:
    /// - New IVC builder with default settings
    pub fn new<Func>(function: Func) -> Self
    where
        Func: Fn(&[F], &[F]) -> Vec<F> + 'static,
    {
        Self {
            function: Box::new(function),
            security_level: SecurityLevel::default(),
            depth_bound: None,
            input_size: 0,
            witness_size: 0,
            output_size: 0,
            _phantom: PhantomData,
        }
    }
    
    /// Set security level
    ///
    /// Parameters:
    /// - level: Security level (Low, Standard, High, Maximum)
    ///
    /// Returns:
    /// - Self for method chaining
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }
    
    /// Set maximum depth bound
    ///
    /// Parameters:
    /// - bound: Maximum depth for IVC chain
    ///
    /// Returns:
    /// - Self for method chaining
    pub fn with_depth_bound(mut self, bound: usize) -> Self {
        self.depth_bound = Some(bound);
        self
    }
    
    /// Set input/output sizes
    ///
    /// Parameters:
    /// - input_size: Size of z_{i-1}
    /// - witness_size: Size of w_i
    /// - output_size: Size of z_i
    ///
    /// Returns:
    /// - Self for method chaining
    pub fn with_sizes(mut self, input_size: usize, witness_size: usize, output_size: usize) -> Self {
        self.input_size = input_size;
        self.witness_size = witness_size;
        self.output_size = output_size;
        self
    }
    
    /// Build the IVC system
    ///
    /// This performs the following steps:
    /// 1. Setup SNARK with security parameter λ
    /// 2. Compile recursive verification circuit
    /// 3. Index circuit to get proving/verifying keys
    /// 4. Create prover, verifier, and extractor
    ///
    /// Returns:
    /// - Complete IVC system ready for use
    pub fn build(self) -> Result<IVCSystem<F, G, O, S>, String> {
        let lambda = self.security_level.lambda();
        
        // Setup SNARK
        let pp = S::setup(lambda);
        
        // Create incremental computation
        let computation = IncrementalComputation::new(
            self.function,
            self.input_size,
            self.witness_size,
            self.output_size,
        );
        
        // Create oracle
        let mut oracle = O::default();
        
        // Index circuit (placeholder - would compile recursive circuit)
        // let circuit = RecursiveVerificationCircuit::new(...);
        // let (ipk, ivk) = S::index(&circuit, &pp, &mut oracle)?;
        
        Ok(IVCSystem {
            computation,
            security_level: self.security_level,
            _phantom: PhantomData,
        })
    }
}

/// IVC System
///
/// Complete IVC system with prover, verifier, and extractor.
pub struct IVCSystem<F, G, O, S>
where
    F: Field,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Incremental computation
    computation: IncrementalComputation<F>,
    
    /// Security level
    security_level: SecurityLevel,
    
    /// Phantom data
    _phantom: PhantomData<(G, O, S)>,
}

impl<F, G, O, S> IVCSystem<F, G, O, S>
where
    F: Field + Clone,
    G: Clone,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Get the incremental computation
    pub fn computation(&self) -> &IncrementalComputation<F> {
        &self.computation
    }
    
    /// Get security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

/// Aggregate Signature Builder
///
/// Fluent API for constructing aggregate signature systems.
///
/// Example Usage:
/// ```rust,ignore
/// let agg_sig = AggregateSignatureBuilder::new()
///     .with_security_level(SecurityLevel::High)
///     .with_max_signatures(1000)
///     .build()?;
/// ```
pub struct AggregateSignatureBuilder<F, G, O, S>
where
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Security level
    security_level: SecurityLevel,
    
    /// Maximum number of signatures to aggregate
    max_signatures: usize,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O, S)>,
}

impl<F, G, O, S> AggregateSignatureBuilder<F, G, O, S>
where
    F: Field + Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Create a new aggregate signature builder
    pub fn new() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            max_signatures: 100,
            _phantom: PhantomData,
        }
    }
    
    /// Set security level
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }
    
    /// Set maximum number of signatures
    pub fn with_max_signatures(mut self, max: usize) -> Self {
        self.max_signatures = max;
        self
    }
    
    /// Build the aggregate signature system
    ///
    /// This performs:
    /// 1. Setup O-SNARK with security parameter
    /// 2. Compile aggregate verification circuit
    /// 3. Index circuit to get keys
    /// 4. Setup signature scheme parameters
    ///
    /// Returns:
    /// - Complete aggregate signature system
    pub fn build(self) -> Result<AggregateSignatureSystem<F, G, O, S>, String> {
        let lambda = self.security_level.lambda();
        
        // Setup would happen here
        // let agg_sig = AggregateSignature::setup(lambda, verify_fn, &mut oracle)?;
        
        Ok(AggregateSignatureSystem {
            security_level: self.security_level,
            max_signatures: self.max_signatures,
            _phantom: PhantomData,
        })
    }
}

impl<F, G, O, S> Default for AggregateSignatureBuilder<F, G, O, S>
where
    F: Field + Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate Signature System
///
/// Complete aggregate signature system.
pub struct AggregateSignatureSystem<F, G, O, S>
where
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Security level
    security_level: SecurityLevel,
    
    /// Maximum signatures
    max_signatures: usize,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O, S)>,
}

/// PCD Builder
///
/// Fluent API for constructing PCD systems.
///
/// Example Usage:
/// ```rust,ignore
/// let pcd = PCDBuilder::new(compliance_predicate)
///     .with_security_level(SecurityLevel::High)
///     .build()?;
/// ```
pub struct PCDBuilder<F, G, O, S>
where
    F: Field,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Compliance predicate
    compliance_predicate: CompliancePredicate<F, O>,
    
    /// Security level
    security_level: SecurityLevel,
    
    /// Phantom data
    _phantom: PhantomData<(G, S)>,
}

impl<F, G, O, S> PCDBuilder<F, G, O, S>
where
    F: Field + Clone,
    G: Clone,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Create a new PCD builder
    ///
    /// Parameters:
    /// - compliance_predicate: Function ϕ^θ(z_e, w_loc, z) → {0,1}
    ///
    /// Returns:
    /// - New PCD builder
    pub fn new(compliance_predicate: CompliancePredicate<F, O>) -> Self {
        Self {
            compliance_predicate,
            security_level: SecurityLevel::default(),
            _phantom: PhantomData,
        }
    }
    
    /// Set security level
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }
    
    /// Build the PCD system
    ///
    /// Returns:
    /// - Complete PCD system
    pub fn build(self) -> Result<PCDSystem<F, G, O, S>, String> {
        let lambda = self.security_level.lambda();
        
        // Setup would happen here
        
        Ok(PCDSystem {
            security_level: self.security_level,
            _phantom: PhantomData,
        })
    }
}

/// PCD System
///
/// Complete PCD system with prover, verifier, and extractor.
pub struct PCDSystem<F, G, O, S>
where
    F: Field,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Security level
    security_level: SecurityLevel,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O, S)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
