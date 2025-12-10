// IVC Verifier
//
// Mathematical Foundation:
// V^θ(ivk, z_0, z_out, π_out):
//   1. Forward all oracle queries to θ
//   2. Base case: if z_0 = z_out, return ⊤
//   3. Recursive case: b ← V^θ(ivk, (ivk, z_0, z_out), π_out)
//   4. Return b
//
// Key Properties:
// - Constant-time verification (independent of depth)
// - Succinctness: runtime is poly(λ + |x|), independent of |F| and depth
// - Handles both base case (z_0 = z_out) and recursive case

use std::marker::PhantomData;

use crate::oracle::Oracle;
use crate::rel_snark::{RelativizedSNARK, VerifierKey, Statement, Proof};

use super::types::IVCState;
use super::errors::{IVCError, IVCResult};

/// IVC Verifier
///
/// Verifies IVC proofs in constant time regardless of computation depth
pub struct IVCVerifier<F, G, O, S>
where
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    /// Verifier key
    ivk: VerifierKey,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O, S)>,
}

impl<F, G, O, S> IVCVerifier<F, G, O, S>
where
    F: Clone + PartialEq,
    G: crate::agm::Group,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: RelativizedSNARK<F, G, O>,
{
    pub fn new(ivk: VerifierKey) -> Self {
        Self {
            ivk,
            _phantom: PhantomData,
        }
    }
    
    /// Verify IVC proof: V^θ(ivk, z_0, z_out, π_out) → ⊤/⊥
    ///
    /// Mathematical steps:
    /// 1. Check base case: z_0 = z_out
    /// 2. If not base case, verify SNARK proof
    /// 3. Return verification result
    ///
    /// Complexity: O(poly(λ + |z_0| + |z_out|)), independent of depth
    pub fn verify(
        &self,
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
        proof: &Proof,
        oracle: &mut O,
    ) -> IVCResult<bool> {
        // Base case: z_0 = z_out
        // This means we're at the initial state, no computation performed
        if z_0.data == z_out.data {
            return Ok(true);
        }
        
        // Recursive case: verify SNARK proof
        // Statement: (ivk, z_0, z_out)
        let statement = self.build_statement(z_0, z_out)?;
        
        // Verify using underlying SNARK
        S::verify(&self.ivk, &statement, proof, oracle)
            .map_err(|e| IVCError::InvalidState(format!("SNARK verification failed: {}", e)))
    }
    
    /// Build statement for verification: (ivk, z_0, z_out)
    fn build_statement(
        &self,
        z_0: &IVCState<F>,
        z_out: &IVCState<F>,
    ) -> IVCResult<Statement> {
        let mut statement_data = Vec::new();
        
        // Add ivk
        statement_data.extend_from_slice(&self.ivk.data);
        
        // Add z_0
        let z0_bytes = bincode::serialize(&z_0.data)
            .map_err(|e| IVCError::InvalidState(format!("z_0 serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&z0_bytes);
        
        // Add z_out
        let zout_bytes = bincode::serialize(&z_out.data)
            .map_err(|e| IVCError::InvalidState(format!("z_out serialization failed: {}", e)))?;
        statement_data.extend_from_slice(&zout_bytes);
        
        Ok(Statement::new(statement_data))
    }
    
    /// Get verifier key
    pub fn verifier_key(&self) -> &VerifierKey {
        &self.ivk
    }
    
    /// Verify batch of IVC proofs
    ///
    /// Verifies multiple proofs with same z_0 but different z_out
    /// Useful for parallel verification
    pub fn verify_batch(
        &self,
        z_0: &IVCState<F>,
        outputs: &[(IVCState<F>, Proof)],
        oracle: &mut O,
    ) -> IVCResult<Vec<bool>> {
        let mut results = Vec::with_capacity(outputs.len());
        
        for (z_out, proof) in outputs {
            let result = self.verify(z_0, z_out, proof, oracle)?;
            results.push(result);
        }
        
        Ok(results)
    }
}
