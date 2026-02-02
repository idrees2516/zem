// Inner product reduction (Section 4.4 of paper)
//
// Reduces polynomial relations to inner product claims over extension fields,
// enabling efficient sumcheck protocol execution.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Inner product reduction
///
/// After challenge substitution X = α, polynomial relation becomes:
/// Σ_k M_k(α) · z_k(α) = w(α) + (α^d + 1) · r(α)
///
/// This can be viewed as inner product claim:
/// ⟨M(α), z(α)⟩ = target
///
/// where M(α) and z(α) are vectors in F_{q^k}
#[derive(Clone, Debug)]
pub struct InnerProductReduction<F: Field> {
    /// Ring dimension d
    ring_dimension: usize,
    
    /// Extension degree k
    extension_degree: usize,
}

impl<F: Field> InnerProductReduction<F> {
    /// Create inner product reduction
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Reduce polynomial relation to inner product claim
    ///
    /// Given:
    /// - Matrices M_k ∈ R_q^{m×n}
    /// - Witnesses z_k ∈ R_q^n
    /// - Challenge α ∈ F_{q^k}
    ///
    /// Compute:
    /// - M_vec = vec(M_1(α), ..., M_r(α)) ∈ F_{q^k}^{m·r}
    /// - z_vec = vec(z_1(α), ..., z_r(α)) ∈ F_{q^k}^{n·r}
    /// - target = w(α) + (α^d + 1) · r(α) ∈ F_{q^k}
    ///
    /// Claim: ⟨M_vec, z_vec⟩ = target
    pub fn reduce_to_inner_product(
        &self,
        matrices: &[Vec<Vec<RingElement<F>>>],
        witnesses: &[Vec<RingElement<F>>],
        target: F,
        challenge: F,
    ) -> Result<InnerProductClaim<F>, HachiError> {
        // Evaluate matrices at challenge
        let mut m_vec = Vec::new();
        for matrix in matrices {
            for row in matrix {
                for elem in row {
                    let evaluated = self.evaluate_at_challenge(elem, challenge)?;
                    m_vec.push(evaluated);
                }
            }
        }
        
        // Evaluate witnesses at challenge
        let mut z_vec = Vec::new();
        for witness in witnesses {
            for elem in witness {
                let evaluated = self.evaluate_at_challenge(elem, challenge)?;
                z_vec.push(evaluated);
            }
        }
        
        Ok(InnerProductClaim {
            m_vector: m_vec,
            z_vector: z_vec,
            target,
            challenge,
        })
    }
    
    /// Evaluate ring element at challenge
    fn evaluate_at_challenge(
        &self,
        element: &RingElement<F>,
        challenge: F,
    ) -> Result<F, HachiError> {
        let coeffs = element.coefficients();
        let mut result = F::zero();
        let mut power = F::one();
        
        for &coeff in coeffs {
            result = result + (coeff * power);
            power = power * challenge;
        }
        
        Ok(result)
    }
    
    /// Compute inner product
    pub fn compute_inner_product(
        &self,
        m_vec: &[F],
        z_vec: &[F],
    ) -> Result<F, HachiError> {
        if m_vec.len() != z_vec.len() {
            return Err(HachiError::InvalidDimension {
                expected: m_vec.len(),
                actual: z_vec.len(),
            });
        }
        
        let mut result = F::zero();
        for i in 0..m_vec.len() {
            result = result + (m_vec[i] * z_vec[i]);
        }
        
        Ok(result)
    }
    
    /// Verify inner product claim
    pub fn verify_inner_product_claim(
        &self,
        claim: &InnerProductClaim<F>,
    ) -> Result<bool, HachiError> {
        let computed = self.compute_inner_product(&claim.m_vector, &claim.z_vector)?;
        Ok(computed == claim.target)
    }
}

/// Inner product claim
#[derive(Clone, Debug)]
pub struct InnerProductClaim<F: Field> {
    /// M vector: M_1(α), ..., M_r(α)
    pub m_vector: Vec<F>,
    
    /// z vector: z_1(α), ..., z_r(α)
    pub z_vector: Vec<F>,
    
    /// Target value
    pub target: F,
    
    /// Challenge α
    pub challenge: F,
}

impl<F: Field> InnerProductClaim<F> {
    /// Get vector length
    pub fn vector_length(&self) -> usize {
        self.m_vector.len()
    }
    
    /// Verify claim
    pub fn verify(&self) -> Result<bool, HachiError> {
        if self.m_vector.len() != self.z_vector.len() {
            return Ok(false);
        }
        
        let mut computed = F::zero();
        for i in 0..self.m_vector.len() {
            computed = computed + (self.m_vector[i] * self.z_vector[i]);
        }
        
        Ok(computed == self.target)
    }
}

/// Multilinear inner product claim
///
/// For multilinear polynomials, inner product can be expressed as:
/// ⟨P, Q⟩ = Σ_{i∈{0,1}^μ} P(i) · Q(i)
#[derive(Clone, Debug)]
pub struct MultilinearInnerProductClaim<F: Field> {
    /// P polynomial values
    pub p_values: Vec<F>,
    
    /// Q polynomial values
    pub q_values: Vec<F>,
    
    /// Target value
    pub target: F,
    
    /// Number of variables
    pub num_variables: usize,
}

impl<F: Field> MultilinearInnerProductClaim<F> {
    /// Create multilinear inner product claim
    pub fn new(
        p_values: Vec<F>,
        q_values: Vec<F>,
        target: F,
    ) -> Result<Self, HachiError> {
        if p_values.len() != q_values.len() {
            return Err(HachiError::InvalidDimension {
                expected: p_values.len(),
                actual: q_values.len(),
            });
        }
        
        let size = p_values.len();
        let num_variables = (size as f64).log2() as usize;
        
        if 1 << num_variables != size {
            return Err(HachiError::InvalidParameters(
                format!("Vector size {} must be power of 2", size)
            ));
        }
        
        Ok(Self {
            p_values,
            q_values,
            target,
            num_variables,
        })
    }
    
    /// Verify claim
    pub fn verify(&self) -> Result<bool, HachiError> {
        let mut computed = F::zero();
        for i in 0..self.p_values.len() {
            computed = computed + (self.p_values[i] * self.q_values[i]);
        }
        
        Ok(computed == self.target)
    }
    
    /// Get vector length
    pub fn vector_length(&self) -> usize {
        self.p_values.len()
    }
}

/// Batch inner product reduction
pub struct BatchInnerProductReduction<F: Field> {
    reduction: InnerProductReduction<F>,
}

impl<F: Field> BatchInnerProductReduction<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let reduction = InnerProductReduction::new(params)?;
        Ok(Self { reduction })
    }
    
    /// Reduce multiple relations
    pub fn batch_reduce(
        &self,
        relations: &[RelationForReduction<F>],
        challenge: F,
    ) -> Result<Vec<InnerProductClaim<F>>, HachiError> {
        relations.iter()
            .map(|r| {
                self.reduction.reduce_to_inner_product(
                    &r.matrices,
                    &r.witnesses,
                    r.target,
                    challenge,
                )
            })
            .collect()
    }
    
    /// Verify multiple claims
    pub fn batch_verify(
        &self,
        claims: &[InnerProductClaim<F>],
    ) -> Result<bool, HachiError> {
        for claim in claims {
            if !self.reduction.verify_inner_product_claim(claim)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Relation data for reduction
#[derive(Clone, Debug)]
pub struct RelationForReduction<F: Field> {
    pub matrices: Vec<Vec<Vec<RingElement<F>>>>,
    pub witnesses: Vec<Vec<RingElement<F>>>,
    pub target: F,
}

/// Inner product to sumcheck transformation
///
/// Transforms inner product claim to sumcheck claim
pub struct InnerProductToSumcheck<F: Field> {
    reduction: InnerProductReduction<F>,
}

impl<F: Field> InnerProductToSumcheck<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let reduction = InnerProductReduction::new(params)?;
        Ok(Self { reduction })
    }
    
    /// Transform inner product to sumcheck
    ///
    /// Inner product ⟨P, Q⟩ = Σ_i P_i · Q_i
    /// can be viewed as sumcheck claim:
    /// Σ_{i∈{0,1}^μ} P(i) · Q(i) = target
    pub fn transform_to_sumcheck(
        &self,
        claim: &InnerProductClaim<F>,
    ) -> Result<SumcheckClaim<F>, HachiError> {
        let num_variables = (claim.m_vector.len() as f64).log2() as usize;
        
        if 1 << num_variables != claim.m_vector.len() {
            return Err(HachiError::InvalidParameters(
                format!("Vector length {} must be power of 2", claim.m_vector.len())
            ));
        }
        
        Ok(SumcheckClaim {
            p_values: claim.m_vector.clone(),
            q_values: claim.z_vector.clone(),
            target: claim.target,
            num_variables,
        })
    }
}

/// Sumcheck claim
#[derive(Clone, Debug)]
pub struct SumcheckClaim<F: Field> {
    /// P polynomial values
    pub p_values: Vec<F>,
    
    /// Q polynomial values
    pub q_values: Vec<F>,
    
    /// Target sum
    pub target: F,
    
    /// Number of variables
    pub num_variables: usize,
}

impl<F: Field> SumcheckClaim<F> {
    /// Verify claim
    pub fn verify(&self) -> Result<bool, HachiError> {
        let mut sum = F::zero();
        for i in 0..self.p_values.len() {
            sum = sum + (self.p_values[i] * self.q_values[i]);
        }
        
        Ok(sum == self.target)
    }
}
