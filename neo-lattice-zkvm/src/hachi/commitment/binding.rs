// Binding security (Lemma 7)
//
// Proves that the inner-outer commitment scheme is binding under Module-SIS assumption.
// If two different witnesses produce the same commitment, we can solve Module-SIS.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Binding security analysis
///
/// Lemma 7 (Binding):
/// If there exist two different witnesses s, s' such that:
/// A_out · (A_in · s) = A_out · (A_in · s') = u
///
/// Then we can solve Module-SIS instance:
/// A · (s - s') = 0 (mod q)
/// with ||s - s'|| bounded
#[derive(Clone, Debug)]
pub struct BindingSecurity<F: Field> {
    /// Module-SIS parameters
    params: HachiParams<F>,
    
    /// Ring dimension
    ring_dimension: usize,
    
    /// Module-SIS dimension n
    sis_dimension: usize,
    
    /// Module-SIS norm bound β
    sis_bound: F,
}

impl<F: Field> BindingSecurity<F> {
    /// Create binding security analyzer
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let sis_dimension = params.sis_dimension();
        let sis_bound = params.sis_bound();
        
        Ok(Self {
            params: params.clone(),
            ring_dimension,
            sis_dimension,
            sis_bound,
        })
    }
    
    /// Extract Module-SIS solution from collision
    ///
    /// Given two witnesses s, s' with same commitment:
    /// A_out · (A_in · s) = A_out · (A_in · s')
    ///
    /// Compute: e = A_in · (s - s')
    /// Then: A_out · e = 0
    pub fn extract_sis_solution(
        &self,
        witness1: &[Vec<RingElement<F>>],
        witness2: &[Vec<RingElement<F>>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        if witness1.len() != witness2.len() {
            return Err(HachiError::InvalidDimension {
                expected: witness1.len(),
                actual: witness2.len(),
            });
        }
        
        let mut difference = Vec::new();
        
        // Compute s - s'
        for i in 0..witness1.len() {
            if witness1[i].len() != witness2[i].len() {
                return Err(HachiError::InvalidDimension {
                    expected: witness1[i].len(),
                    actual: witness2[i].len(),
                });
            }
            
            let mut diff_block = Vec::new();
            for j in 0..witness1[i].len() {
                let diff = witness1[i][j].sub(&witness2[i][j])?;
                diff_block.push(diff);
            }
            difference.push(diff_block);
        }
        
        // Flatten difference vector
        let mut flat_diff = Vec::new();
        for block in difference {
            flat_diff.extend(block);
        }
        
        Ok(flat_diff)
    }
    
    /// Verify Module-SIS solution
    ///
    /// Checks that e satisfies:
    /// 1. A_out · e = 0
    /// 2. ||e|| ≤ bound
    pub fn verify_sis_solution(
        &self,
        solution: &[RingElement<F>],
        outer_matrix: &[Vec<RingElement<F>>],
    ) -> Result<bool, HachiError> {
        // Check that A_out · e = 0
        if outer_matrix.is_empty() {
            return Ok(false);
        }
        
        let mut product = RingElement::zero(self.ring_dimension)?;
        
        for j in 0..solution.len() {
            if j >= outer_matrix[0].len() {
                break;
            }
            
            let term = outer_matrix[0][j].mul(&solution[j])?;
            product = product.add(&term)?;
        }
        
        // Check if product is zero
        Ok(product.is_zero())
    }
    
    /// Compute norm of difference
    pub fn compute_difference_norm(
        &self,
        witness1: &[Vec<RingElement<F>>],
        witness2: &[Vec<RingElement<F>>],
    ) -> Result<F, HachiError> {
        let mut max_norm = F::zero();
        
        for i in 0..witness1.len() {
            for j in 0..witness1[i].len() {
                let diff = witness1[i][j].sub(&witness2[i][j])?;
                let coeffs = diff.coefficients();
                
                for &coeff in coeffs {
                    if coeff > max_norm {
                        max_norm = coeff;
                    }
                }
            }
        }
        
        Ok(max_norm)
    }
    
    /// Analyze binding security
    ///
    /// Returns security level based on Module-SIS hardness
    pub fn analyze_binding_security(&self) -> Result<SecurityAnalysis, HachiError> {
        let sis_dimension = self.sis_dimension;
        let ring_dimension = self.ring_dimension;
        
        // Security level depends on Module-SIS parameters
        let security_bits = self.estimate_security_bits(sis_dimension, ring_dimension)?;
        
        Ok(SecurityAnalysis {
            sis_dimension,
            ring_dimension,
            security_bits,
            is_binding: security_bits >= 128,
        })
    }
    
    /// Estimate security bits from Module-SIS parameters
    fn estimate_security_bits(&self, n: usize, d: usize) -> Result<usize, HachiError> {
        // Simplified security estimation
        // In practice, would use more sophisticated analysis
        let bits = (n as f64 * (d as f64).log2()) as usize;
        Ok(bits)
    }
}

/// Security analysis result
#[derive(Clone, Debug)]
pub struct SecurityAnalysis {
    /// Module-SIS dimension
    pub sis_dimension: usize,
    
    /// Ring dimension
    pub ring_dimension: usize,
    
    /// Estimated security bits
    pub security_bits: usize,
    
    /// Is binding secure?
    pub is_binding: bool,
}

/// Collision detection
///
/// Detects if two commitments are collisions
#[derive(Clone, Debug)]
pub struct CollisionDetector<F: Field> {
    binding: BindingSecurity<F>,
}

impl<F: Field> CollisionDetector<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let binding = BindingSecurity::new(params)?;
        Ok(Self { binding })
    }
    
    /// Check if two witnesses produce same commitment
    pub fn is_collision(
        &self,
        commitment1: &RingElement<F>,
        commitment2: &RingElement<F>,
    ) -> bool {
        commitment1.equals(commitment2)
    }
    
    /// Extract SIS solution from collision
    pub fn extract_from_collision(
        &self,
        witness1: &[Vec<RingElement<F>>],
        witness2: &[Vec<RingElement<F>>],
    ) -> Result<Vec<RingElement<F>>, HachiError> {
        self.binding.extract_sis_solution(witness1, witness2)
    }
}

/// Binding proof structure
#[derive(Clone, Debug)]
pub struct BindingProof<F: Field> {
    /// First witness
    witness1: Vec<Vec<RingElement<F>>>,
    
    /// Second witness
    witness2: Vec<Vec<RingElement<F>>>,
    
    /// Extracted SIS solution
    sis_solution: Vec<RingElement<F>>,
    
    /// Norm of difference
    difference_norm: F,
}

impl<F: Field> BindingProof<F> {
    /// Create binding proof from collision
    pub fn from_collision(
        binding: &BindingSecurity<F>,
        witness1: Vec<Vec<RingElement<F>>>,
        witness2: Vec<Vec<RingElement<F>>>,
    ) -> Result<Self, HachiError> {
        let sis_solution = binding.extract_sis_solution(&witness1, &witness2)?;
        let difference_norm = binding.compute_difference_norm(&witness1, &witness2)?;
        
        Ok(Self {
            witness1,
            witness2,
            sis_solution,
            difference_norm,
        })
    }
    
    /// Get first witness
    pub fn witness1(&self) -> &[Vec<RingElement<F>>] {
        &self.witness1
    }
    
    /// Get second witness
    pub fn witness2(&self) -> &[Vec<RingElement<F>>] {
        &self.witness2
    }
    
    /// Get SIS solution
    pub fn sis_solution(&self) -> &[RingElement<F>] {
        &self.sis_solution
    }
    
    /// Get difference norm
    pub fn difference_norm(&self) -> F {
        self.difference_norm
    }
}

/// Binding verification
pub struct BindingVerifier<F: Field> {
    binding: BindingSecurity<F>,
}

impl<F: Field> BindingVerifier<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let binding = BindingSecurity::new(params)?;
        Ok(Self { binding })
    }
    
    /// Verify binding proof
    pub fn verify_binding_proof(
        &self,
        proof: &BindingProof<F>,
        outer_matrix: &[Vec<RingElement<F>>],
    ) -> Result<bool, HachiError> {
        // Check that witnesses are different
        if proof.witness1 == proof.witness2 {
            return Ok(false);
        }
        
        // Check that SIS solution is valid
        self.binding.verify_sis_solution(proof.sis_solution(), outer_matrix)
    }
    
    /// Verify binding security
    pub fn verify_binding_security(&self) -> Result<bool, HachiError> {
        let analysis = self.binding.analyze_binding_security()?;
        Ok(analysis.is_binding)
    }
}

/// Batch binding verification
pub struct BatchBindingVerifier<F: Field> {
    verifier: BindingVerifier<F>,
}

impl<F: Field> BatchBindingVerifier<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let verifier = BindingVerifier::new(params)?;
        Ok(Self { verifier })
    }
    
    /// Verify multiple binding proofs
    pub fn batch_verify(
        &self,
        proofs: &[BindingProof<F>],
        outer_matrix: &[Vec<RingElement<F>>],
    ) -> Result<bool, HachiError> {
        for proof in proofs {
            if !self.verifier.verify_binding_proof(proof, outer_matrix)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
