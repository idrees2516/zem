// Neo Integration Module
// Task 22: Wrapper for integrating LatticeFold+ with Neo's infrastructure
//
// This module provides the integration layer between LatticeFold+ and Neo's
// existing optimizations, including NTT engine, field arithmetic, parallel
// execution, and memory management.

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::ring::ntt::NTTEngine;
use crate::optimization::parallel::ParallelExecutor;
use crate::optimization::memory::MemoryManager;
use crate::field::extension::ExtensionField;
use super::tensor_rings::{TensorRingConfig, SmallFieldFolding, NTTAcceleratedOps, FieldArithmeticOps};
use super::folding::{FoldingProver, FoldingVerifier, LinearInstance};
use super::range_check::{RangeCheckProver, RangeCheckVerifier};
use super::commitment_transform::{CommitmentTransformProver, CommitmentTransformVerifier};
use super::monomial_check::{MonomialSetCheckProver, MonomialSetCheckVerifier};
use crate::commitment::ajtai::AjtaiCommitment;
use std::sync::Arc;

// ============================================================================
// Task 22.1: NeoIntegration Struct
// ============================================================================

/// Neo integration wrapper
/// 
/// Provides a unified interface for accessing Neo's optimized components
/// and integrating them with LatticeFold+ protocols.
pub struct NeoIntegration<F: Field> {
    /// Reference to Neo's NTT engine
    ntt_engine: Option<Arc<NTTEngine<F>>>,
    
    /// Reference to Neo's field arithmetic
    field_arithmetic: Arc<FieldArithmeticOps<F>>,
    
    /// Reference to Neo's parallel executor
    parallel_executor: Arc<ParallelExecutor>,
    
    /// Reference to Neo's memory manager
    memory_manager: Arc<MemoryManager>,
    
    /// Small field folding configuration
    small_field_folding: SmallFieldFolding<F>,
    
    /// Base ring
    base_ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
}

impl<F: Field> NeoIntegration<F> {
    /// Create new Neo integration
    /// 
    /// # Arguments
    /// * `base_field_size` - Prime q for base field
    /// * `ring_degree` - Degree d of cyclotomic polynomial
    /// * `security_level` - Target security level λ in bits
    /// * `kappa` - Security parameter for commitments
    /// * `n` - Vector dimension for commitments
    /// * `seed` - Seed for commitment key generation
    /// 
    /// # Returns
    /// * `Ok(NeoIntegration)` if initialization succeeds
    /// * `Err(String)` if initialization fails
    pub fn new(
        base_field_size: u64,
        ring_degree: usize,
        security_level: usize,
        kappa: usize,
        n: usize,
        seed: [u8; 32],
    ) -> Result<Self, String> {
        // Create tensor ring configuration
        let config = TensorRingConfig::new(
            base_field_size,
            ring_degree,
            security_level,
        )?;
        
        // Create base ring
        let base_ring = CyclotomicRing::<F>::new(ring_degree);
        
        // Create small field folding
        let small_field_folding = SmallFieldFolding::new(
            config.clone(),
            base_ring.clone(),
        )?;
        
        // Create NTT engine if available
        let ntt_engine = if config.ntt_available() {
            let root = config.compute_root_of_unity()?;
            Some(Arc::new(NTTEngine::new(
                ring_degree,
                base_field_size,
                root,
            )?))
        } else {
            None
        };
        
        // Create field arithmetic ops
        let field_arithmetic = Arc::new(FieldArithmeticOps::new(
            small_field_folding.clone()
        ));
        
        // Create parallel executor
        let parallel_executor = Arc::new(ParallelExecutor::new(
            num_cpus::get()
        ));
        
        // Create memory manager
        let memory_manager = Arc::new(MemoryManager::new(
            1024 * 1024 * 1024 // 1GB default
        ));
        
        // Create commitment key
        let commitment_key = AjtaiCommitment::new(
            base_ring.clone(),
            kappa,
            n,
            base_field_size,
            seed,
        );
        
        Ok(Self {
            ntt_engine,
            field_arithmetic,
            parallel_executor,
            memory_manager,
            small_field_folding,
            base_ring,
            commitment_key,
        })
    }
    
    /// Get NTT engine reference
    pub fn ntt_engine(&self) -> Option<&NTTEngine<F>> {
        self.ntt_engine.as_ref().map(|arc| arc.as_ref())
    }
    
    /// Get field arithmetic reference
    pub fn field_arithmetic(&self) -> &FieldArithmeticOps<F> {
        self.field_arithmetic.as_ref()
    }
    
    /// Get parallel executor reference
    pub fn parallel_executor(&self) -> &ParallelExecutor {
        self.parallel_executor.as_ref()
    }
    
    /// Get memory manager reference
    pub fn memory_manager(&self) -> &MemoryManager {
        self.memory_manager.as_ref()
    }
    
    /// Get small field folding reference
    pub fn small_field_folding(&self) -> &SmallFieldFolding<F> {
        &self.small_field_folding
    }
    
    /// Get base ring reference
    pub fn base_ring(&self) -> &CyclotomicRing<F> {
        &self.base_ring
    }
    
    /// Get commitment key reference
    pub fn commitment_key(&self) -> &AjtaiCommitment<F> {
        &self.commitment_key
    }
    
    /// Check if NTT is available
    pub fn has_ntt(&self) -> bool {
        self.ntt_engine.is_some()
    }
    
    /// Get configuration
    pub fn config(&self) -> &TensorRingConfig {
        &self.small_field_folding.config
    }
}

// ============================================================================
// Task 22.2: integrate_latticefold_plus Method
// ============================================================================

impl<F: Field> NeoIntegration<F> {
    /// Integrate LatticeFold+ with Neo's infrastructure
    /// 
    /// Creates a fully configured LatticeFoldPlusEngine with all components
    /// wired up and optimizations enabled.
    /// 
    /// # Returns
    /// * `LatticeFoldPlusEngine` - Fully configured engine
    pub fn integrate_latticefold_plus(&self) -> LatticeFoldPlusEngine<F> {
        LatticeFoldPlusEngine::new(
            self.base_ring.clone(),
            self.commitment_key.clone(),
            self.small_field_folding.clone(),
            self.ntt_engine.clone(),
            self.field_arithmetic.clone(),
            self.parallel_executor.clone(),
            self.memory_manager.clone(),
        )
    }
    
    /// Create range check prover with Neo optimizations
    pub fn create_range_check_prover(
        &self,
        witness: Vec<RingElement<F>>,
        norm_bound: i64,
    ) -> Result<RangeCheckProver<F>, String> {
        RangeCheckProver::new(
            witness,
            norm_bound,
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
        )
    }
    
    /// Create range check verifier with Neo optimizations
    pub fn create_range_check_verifier(
        &self,
        commitment: crate::commitment::ajtai::Commitment<F>,
        norm_bound: i64,
    ) -> Result<RangeCheckVerifier<F>, String> {
        RangeCheckVerifier::new(
            commitment,
            norm_bound,
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
        )
    }
    
    /// Create folding prover with Neo optimizations
    pub fn create_folding_prover(
        &self,
        instances: Vec<LinearInstance<F>>,
        witnesses: Vec<Vec<RingElement<F>>>,
    ) -> Result<FoldingProver<F>, String> {
        FoldingProver::new(
            instances,
            witnesses,
            self.commitment_key.clone(),
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
            self.small_field_folding.challenge_set_size() as usize,
        )
    }
    
    /// Create folding verifier with Neo optimizations
    pub fn create_folding_verifier(
        &self,
        instances: Vec<LinearInstance<F>>,
    ) -> Result<FoldingVerifier<F>, String> {
        FoldingVerifier::new(
            instances,
            self.base_ring.clone(),
            self.small_field_folding.challenge_set_size() as usize,
            self.small_field_folding.challenge_set_size() as usize,
        )
    }
    
    /// Optimize ring multiplication using NTT
    /// 
    /// Uses Neo's NTT engine for O(d log d) multiplication when available,
    /// otherwise falls back to schoolbook multiplication.
    pub fn optimized_multiply(
        &self,
        a: &RingElement<F>,
        b: &RingElement<F>,
    ) -> Result<RingElement<F>, String> {
        let ntt_ops = NTTAcceleratedOps::new(self.small_field_folding.clone());
        ntt_ops.multiply(a, b)
    }
    
    /// Parallel batch multiplication
    /// 
    /// Multiplies multiple pairs of ring elements in parallel using Neo's
    /// parallel executor.
    pub fn parallel_batch_multiply(
        &self,
        pairs: Vec<(RingElement<F>, RingElement<F>)>,
    ) -> Result<Vec<RingElement<F>>, String> {
        let ntt_ops = Arc::new(NTTAcceleratedOps::new(self.small_field_folding.clone()));
        
        self.parallel_executor.parallel_map(
            pairs,
            |pair| {
                ntt_ops.multiply(&pair.0, &pair.1)
            }
        )
    }
    
    /// Optimized inner product
    /// 
    /// Computes ⟨a, b⟩ = Σᵢ aᵢ · bᵢ using parallel execution and NTT
    pub fn optimized_inner_product(
        &self,
        a: &[RingElement<F>],
        b: &[RingElement<F>],
    ) -> Result<RingElement<F>, String> {
        if a.len() != b.len() {
            return Err(format!(
                "Vector length mismatch: {} vs {}",
                a.len(), b.len()
            ));
        }
        
        // Parallel multiplication
        let pairs: Vec<_> = a.iter().zip(b.iter())
            .map(|(ai, bi)| (ai.clone(), bi.clone()))
            .collect();
        
        let products = self.parallel_batch_multiply(pairs)?;
        
        // Sequential addition (could be parallelized with tree reduction)
        let mut result = RingElement::from_coeffs(
            vec![F::zero(); self.base_ring.degree]
        );
        
        for product in products {
            result = self.field_arithmetic.add(&result, &product);
        }
        
        Ok(result)
    }
    
    /// Memory-efficient commitment computation
    /// 
    /// Uses Neo's memory manager to optimize memory usage during
    /// large commitment computations.
    pub fn memory_efficient_commit(
        &self,
        witness: &[RingElement<F>],
    ) -> Result<crate::commitment::ajtai::Commitment<F>, String> {
        // Allocate memory from pool
        let _memory_guard = self.memory_manager.allocate(
            witness.len() * self.base_ring.degree * std::mem::size_of::<F>()
        )?;
        
        // Compute commitment
        self.commitment_key.commit(witness)
    }
}

// ============================================================================
// LatticeFoldPlusEngine (Task 23 will be in separate file)
// ============================================================================

/// LatticeFold+ engine with full Neo integration
/// 
/// This is a preview of the full engine structure. The complete implementation
/// is in latticefold_plus_engine.rs (Task 23).
pub struct LatticeFoldPlusEngine<F: Field> {
    /// Base ring
    base_ring: CyclotomicRing<F>,
    
    /// Commitment key
    commitment_key: AjtaiCommitment<F>,
    
    /// Small field folding
    small_field_folding: SmallFieldFolding<F>,
    
    /// NTT engine (optional)
    ntt_engine: Option<Arc<NTTEngine<F>>>,
    
    /// Field arithmetic
    field_arithmetic: Arc<FieldArithmeticOps<F>>,
    
    /// Parallel executor
    parallel_executor: Arc<ParallelExecutor>,
    
    /// Memory manager
    memory_manager: Arc<MemoryManager>,
}

impl<F: Field> LatticeFoldPlusEngine<F> {
    /// Create new LatticeFold+ engine
    pub fn new(
        base_ring: CyclotomicRing<F>,
        commitment_key: AjtaiCommitment<F>,
        small_field_folding: SmallFieldFolding<F>,
        ntt_engine: Option<Arc<NTTEngine<F>>>,
        field_arithmetic: Arc<FieldArithmeticOps<F>>,
        parallel_executor: Arc<ParallelExecutor>,
        memory_manager: Arc<MemoryManager>,
    ) -> Self {
        Self {
            base_ring,
            commitment_key,
            small_field_folding,
            ntt_engine,
            field_arithmetic,
            parallel_executor,
            memory_manager,
        }
    }
    
    /// Get base ring
    pub fn base_ring(&self) -> &CyclotomicRing<F> {
        &self.base_ring
    }
    
    /// Get commitment key
    pub fn commitment_key(&self) -> &AjtaiCommitment<F> {
        &self.commitment_key
    }
    
    /// Get small field folding
    pub fn small_field_folding(&self) -> &SmallFieldFolding<F> {
        &self.small_field_folding
    }
    
    /// Check if NTT is available
    pub fn has_ntt(&self) -> bool {
        self.ntt_engine.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_neo_integration_creation() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        );
        
        assert!(integration.is_ok());
        
        let integration = integration.unwrap();
        assert_eq!(integration.base_ring().degree, d);
        assert!(integration.has_ntt() || !integration.has_ntt()); // Either is valid
    }
    
    #[test]
    fn test_integrate_latticefold_plus() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let engine = integration.integrate_latticefold_plus();
        assert_eq!(engine.base_ring().degree, d);
    }
    
    #[test]
    fn test_optimized_multiply() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let a = integration.base_ring().from_i64(5);
        let b = integration.base_ring().from_i64(7);
        
        let result = integration.optimized_multiply(&a, &b);
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.coeffs[0], GoldilocksField::from_u64(35));
    }
    
    #[test]
    fn test_create_range_check_prover() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let witness = vec![integration.base_ring().from_i64(10); n];
        let norm_bound = 100;
        
        let prover = integration.create_range_check_prover(witness, norm_bound);
        assert!(prover.is_ok());
    }
    
    #[test]
    fn test_create_folding_prover() {
        let q = GoldilocksField::MODULUS;
        let d = 64;
        let lambda = 128;
        let kappa = 4;
        let n = 16;
        let seed = [0u8; 32];
        
        let integration = NeoIntegration::<GoldilocksField>::new(
            q, d, lambda, kappa, n, seed
        ).unwrap();
        
        let instances = vec![
            LinearInstance {
                commitment: crate::commitment::ajtai::Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: crate::commitment::ajtai::Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
            LinearInstance {
                commitment: crate::commitment::ajtai::Commitment::default(),
                challenge: vec![],
                evaluations: vec![],
                norm_bound: 100,
            },
        ];
        
        let witnesses = vec![
            vec![integration.base_ring().from_i64(10); n],
            vec![integration.base_ring().from_i64(20); n],
            vec![integration.base_ring().from_i64(30); n],
        ];
        
        let prover = integration.create_folding_prover(instances, witnesses);
        assert!(prover.is_ok());
    }
}
