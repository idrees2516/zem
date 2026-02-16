// Challenge substitution: X = α evaluation (Section 4.3 of paper)
//
// Substitutes random challenge α ∈ F_{q^k} for polynomial variable X,
// reducing polynomial ring relations to field arithmetic.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::ring::RingElement;
use crate::field::Field;

/// Challenge substitution mechanism
///
/// For polynomial relation in Z_q[X]:
/// Σ_k M_k(X) · z_k(X) = w(X) + (X^d + 1) · r(X)
///
/// Substitute X = α ∈ F_{q^k} to get field relation:
/// Σ_k M_k(α) · z_k(α) = w(α) + (α^d + 1) · r(α)
#[derive(Clone, Debug)]
pub struct ChallengeSubstitution<F: Field> {
    /// Ring dimension d
    ring_dimension: usize,
    
    /// Extension degree k
    extension_degree: usize,
}

impl<F: Field> ChallengeSubstitution<F> {
    /// Create challenge substitution
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        let extension_degree = params.extension_degree();
        
        Ok(Self {
            ring_dimension,
            extension_degree,
        })
    }
    
    /// Evaluate polynomial at challenge point
    ///
    /// For polynomial p(X) = Σ_i p_i X^i, compute p(α)
    pub fn evaluate_polynomial_at_challenge(
        &self,
        poly: &[F],
        challenge: F,
    ) -> Result<F, HachiError> {
        let mut result = F::zero();
        let mut power = F::one();
        
        for coeff in poly {
            result = result + (*coeff * power);
            power = power * challenge;
        }
        
        Ok(result)
    }
    
    /// Evaluate ring element at challenge
    ///
    /// For a ∈ R_q with a = Σ_i a_i X^i, compute a(α) ∈ F_{q^k}
    pub fn evaluate_ring_element_at_challenge(
        &self,
        element: &RingElement<F>,
        challenge: F,
    ) -> Result<F, HachiError> {
        let coeffs = element.coefficients();
        self.evaluate_polynomial_at_challenge(coeffs, challenge)
    }
    
    /// Evaluate matrix at challenge
    ///
    /// For matrix M ∈ R_q^{m×n}, compute M(α) ∈ F_{q^k}^{m×n}
    pub fn evaluate_matrix_at_challenge(
        &self,
        matrix: &[Vec<RingElement<F>>],
        challenge: F,
    ) -> Result<Vec<Vec<F>>, HachiError> {
        let mut result = Vec::new();
        
        for row in matrix {
            let mut result_row = Vec::new();
            for elem in row {
                let evaluated = self.evaluate_ring_element_at_challenge(elem, challenge)?;
                result_row.push(evaluated);
            }
            result.push(result_row);
        }
        
        Ok(result)
    }
    
    /// Transform polynomial relation to field relation
    ///
    /// Given polynomial relation:
    /// Σ_k M_k(X) · z_k(X) = w(X) + (X^d + 1) · r(X)
    ///
    /// Compute field relation by substituting X = α
    pub fn transform_relation(
        &self,
        matrices: &[Vec<Vec<RingElement<F>>>],
        witnesses: &[Vec<RingElement<F>>],
        target: &RingElement<F>,
        remainder: &RingElement<F>,
        challenge: F,
    ) -> Result<FieldRelation<F>, HachiError> {
        // Evaluate all components at challenge
        let mut left_side = F::zero();
        
        for k in 0..matrices.len() {
            let M_k_alpha = self.evaluate_matrix_at_challenge(&matrices[k], challenge)?;
            
            for i in 0..M_k_alpha.len() {
                for j in 0..M_k_alpha[i].len() {
                    let z_k_j_alpha = self.evaluate_ring_element_at_challenge(&witnesses[k][j], challenge)?;
                    left_side = left_side + (M_k_alpha[i][j] * z_k_j_alpha);
                }
            }
        }
        
        // Evaluate target
        let w_alpha = self.evaluate_ring_element_at_challenge(target, challenge)?;
        
        // Evaluate remainder
        let r_alpha = self.evaluate_ring_element_at_challenge(remainder, challenge)?;
        
        // Compute (α^d + 1) · r(α)
        let alpha_d = self.compute_alpha_power(challenge, self.ring_dimension)?;
        let cyclotomic_factor = alpha_d + F::one();
        let cyclotomic_term = cyclotomic_factor * r_alpha;
        
        // Right side: w(α) + (α^d + 1) · r(α)
        let right_side = w_alpha + cyclotomic_term;
        
        Ok(FieldRelation {
            left_side,
            right_side,
            challenge,
        })
    }
    
    /// Compute α^d
    fn compute_alpha_power(&self, alpha: F, power: usize) -> Result<F, HachiError> {
        let mut result = F::one();
        let mut base = alpha;
        let mut exp = power;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        
        Ok(result)
    }
    
    /// Verify field relation
    pub fn verify_field_relation(&self, relation: &FieldRelation<F>) -> Result<bool, HachiError> {
        Ok(relation.left_side == relation.right_side)
    }
    
    /// Generate random challenge
    pub fn generate_challenge(&self) -> Result<F, HachiError> {
        // In production, would use cryptographic randomness
        Ok(F::from_u64(42))
    }
}

/// Field relation after challenge substitution
#[derive(Clone, Debug)]
pub struct FieldRelation<F: Field> {
    /// Left side: Σ_k M_k(α) · z_k(α)
    pub left_side: F,
    
    /// Right side: w(α) + (α^d + 1) · r(α)
    pub right_side: F,
    
    /// Challenge α
    pub challenge: F,
}

impl<F: Field> FieldRelation<F> {
    /// Check if relation is satisfied
    pub fn is_satisfied(&self) -> bool {
        self.left_side == self.right_side
    }
    
    /// Get challenge
    pub fn challenge(&self) -> F {
        self.challenge
    }
}

/// Batch challenge substitution
pub struct BatchChallengeSubstitution<F: Field> {
    substitution: ChallengeSubstitution<F>,
}

impl<F: Field> BatchChallengeSubstitution<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let substitution = ChallengeSubstitution::new(params)?;
        Ok(Self { substitution })
    }
    
    /// Evaluate multiple polynomials at challenge
    pub fn batch_evaluate_polynomials(
        &self,
        polys: &[Vec<F>],
        challenge: F,
    ) -> Result<Vec<F>, HachiError> {
        polys.iter()
            .map(|p| self.substitution.evaluate_polynomial_at_challenge(p, challenge))
            .collect()
    }
    
    /// Evaluate multiple ring elements at challenge
    pub fn batch_evaluate_ring_elements(
        &self,
        elements: &[RingElement<F>],
        challenge: F,
    ) -> Result<Vec<F>, HachiError> {
        elements.iter()
            .map(|e| self.substitution.evaluate_ring_element_at_challenge(e, challenge))
            .collect()
    }
    
    /// Transform multiple relations
    pub fn batch_transform_relations(
        &self,
        relations: &[RelationData<F>],
        challenge: F,
    ) -> Result<Vec<FieldRelation<F>>, HachiError> {
        relations.iter()
            .map(|r| {
                self.substitution.transform_relation(
                    &r.matrices,
                    &r.witnesses,
                    &r.target,
                    &r.remainder,
                    challenge,
                )
            })
            .collect()
    }
}

/// Relation data for batch transformation
#[derive(Clone, Debug)]
pub struct RelationData<F: Field> {
    pub matrices: Vec<Vec<Vec<RingElement<F>>>>,
    pub witnesses: Vec<Vec<RingElement<F>>>,
    pub target: RingElement<F>,
    pub remainder: RingElement<F>,
}

/// Challenge generation and management
pub struct ChallengeManager<F: Field> {
    substitution: ChallengeSubstitution<F>,
    
    /// Generated challenges
    challenges: Vec<F>,
}

impl<F: Field> ChallengeManager<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let substitution = ChallengeSubstitution::new(params)?;
        Ok(Self {
            substitution,
            challenges: Vec::new(),
        })
    }
    
    /// Generate new challenge
    pub fn generate_challenge(&mut self) -> Result<F, HachiError> {
        let challenge = self.substitution.generate_challenge()?;
        self.challenges.push(challenge);
        Ok(challenge)
    }
    
    /// Get all generated challenges
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
    
    /// Clear challenges
    pub fn clear_challenges(&mut self) {
        self.challenges.clear();
    }
}

/// Fiat-Shamir challenge generation
pub struct FiatShamirChallenge<F: Field> {
    substitution: ChallengeSubstitution<F>,
}

impl<F: Field> FiatShamirChallenge<F> {
    pub fn new(params: &HachiParams<F>) -> Result<Self, HachiError> {
        let substitution = ChallengeSubstitution::new(params)?;
        Ok(Self { substitution })
    }
    
    /// Generate challenge from transcript
    pub fn generate_from_transcript(
        &self,
        transcript: &[u8],
    ) -> Result<F, HachiError> {
        // Hash transcript to get challenge
        // In production, would use cryptographic hash
        let hash_value = transcript.iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });
        
        Ok(F::from_u64(hash_value))
    }
    
    /// Generate multiple challenges from transcript
    pub fn batch_generate_from_transcript(
        &self,
        transcript: &[u8],
        count: usize,
    ) -> Result<Vec<F>, HachiError> {
        let mut challenges = Vec::new();
        
        for i in 0..count {
            let mut extended_transcript = transcript.to_vec();
            extended_transcript.extend_from_slice(&(i as u64).to_le_bytes());
            
            let challenge = self.generate_from_transcript(&extended_transcript)?;
            challenges.push(challenge);
        }
        
        Ok(challenges)
    }
}
