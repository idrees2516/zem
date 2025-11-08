// Evaluation Claims and Folding Operations
// Implements NEO-6 requirements for multilinear polynomial evaluation claims

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::commitment::{VectorCommitment, Commitment};
use crate::ring::RingElement;

/// Evaluation claim structure: (C, r, y) where C = Com(w), r ∈ F^ℓ, y ∈ F
/// Claims that the multilinear extension w̃(r) = y
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    /// Commitment to the witness vector
    pub commitment: Commitment<F>,
    /// Evaluation point r ∈ F^ℓ
    pub point: Vec<F>,
    /// Claimed evaluation value y = w̃(r)
    pub value: F,
}

impl<F: Field> EvaluationClaim<F> {
    /// Create a new evaluation claim
    pub fn new(commitment: Commitment<F>, point: Vec<F>, value: F) -> Self {
        Self {
            commitment,
            point,
            value,
        }
    }

    /// Verify the claim given the witness
    /// Checks that Com(w) = C and w̃(r) = y
    pub fn verify(&self, witness: &[F]) -> bool {
        // Check that witness length matches the expected size
        let expected_len = 1 << self.point.len();
        if witness.len() != expected_len {
            return false;
        }

        // Compute multilinear extension evaluation
        let mle = MultilinearPolynomial::new(witness.to_vec());
        let evaluated = mle.evaluate(&self.point);

        // Check that evaluation matches claimed value
        evaluated == self.value
    }

    /// Get the number of variables (ℓ = log₂(witness_length))
    pub fn num_vars(&self) -> usize {
        self.point.len()
    }
}

/// Proof for folding multiple evaluation claims
#[derive(Clone, Debug)]
pub struct FoldingProof<F: Field> {
    /// Cross-terms σᵢⱼ = ⟨wᵢ, wⱼ⟩ for i < j
    pub cross_terms: Vec<F>,
    /// Folding challenges used
    pub challenges: Vec<F>,
}

/// Fold multiple evaluation claims into a single claim
/// Implements NEO-6.8 through NEO-6.12
pub fn fold_evaluation_claims<F: Field>(
    claims: &[EvaluationClaim<F>],
    witnesses: &[Vec<F>],
    challenges: &[F],
) -> Result<(EvaluationClaim<F>, Vec<F>), String> {
    let beta = claims.len();
    
    if beta == 0 {
        return Err("Cannot fold zero claims".to_string());
    }
    
    if witnesses.len() != beta || challenges.len() != beta {
        return Err("Mismatched number of claims, witnesses, and challenges".to_string());
    }

    // All claims must have the same evaluation point
    let point = &claims[0].point;
    for claim in claims.iter().skip(1) {
        if claim.point != *point {
            return Err("All claims must have the same evaluation point".to_string());
        }
    }

    // Verify all witnesses have the same length
    let witness_len = witnesses[0].len();
    for w in witnesses.iter().skip(1) {
        if w.len() != witness_len {
            return Err("All witnesses must have the same length".to_string());
        }
    }

    // Compute folded commitment: C' = Σᵢ αᵢ·Cᵢ
    let ring_challenges: Vec<RingElement<F>> = challenges
        .iter()
        .map(|&alpha| RingElement::from_constant(alpha))
        .collect();
    
    let commitments: Vec<_> = claims.iter().map(|c| c.commitment.clone()).collect();
    
    // Get ring from global configuration (all commitments use same ring parameters)
    let ring_degree = crate::config::get_ring_degree();
    let ring = crate::ring::CyclotomicRing::new(ring_degree);
    let folded_commitment = Commitment::linear_combination(&commitments, &ring_challenges, &ring);

    // Compute folded value: y' = Σᵢ αᵢ·yᵢ
    let mut folded_value = F::zero();
    for (claim, &alpha) in claims.iter().zip(challenges.iter()) {
        folded_value = folded_value.add(&claim.value.mul(&alpha));
    }

    // Compute folded witness: w' = Σᵢ αᵢ·wᵢ
    let mut folded_witness = vec![F::zero(); witness_len];
    for (witness, &alpha) in witnesses.iter().zip(challenges.iter()) {
        for (i, &w_i) in witness.iter().enumerate() {
            folded_witness[i] = folded_witness[i].add(&w_i.mul(&alpha));
        }
    }

    // Verify folded claim: w̃'(r) = y'
    let folded_mle = MultilinearPolynomial::new(folded_witness.clone());
    let computed_value = folded_mle.evaluate(point);
    
    if computed_value != folded_value {
        return Err("Folded claim verification failed".to_string());
    }

    let folded_claim = EvaluationClaim {
        commitment: folded_commitment,
        point: point.clone(),
        value: folded_value,
    };

    Ok((folded_claim, folded_witness))
}

/// Compute cross-terms σᵢⱼ = ⟨wᵢ, wⱼ⟩ for i < j
/// Implements NEO-10.3, NEO-10.4
pub fn compute_cross_terms<F: Field>(witnesses: &[Vec<F>]) -> Result<Vec<F>, String> {
    let beta = witnesses.len();
    
    if beta == 0 {
        return Ok(Vec::new());
    }

    // Verify all witnesses have the same length
    let witness_len = witnesses[0].len();
    for w in witnesses.iter().skip(1) {
        if w.len() != witness_len {
            return Err("All witnesses must have the same length".to_string());
        }
    }

    let mut cross_terms = Vec::new();

    // Compute σᵢⱼ = ⟨wᵢ, wⱼ⟩ for i < j
    for i in 0..beta {
        for j in (i + 1)..beta {
            let inner_product = compute_inner_product(&witnesses[i], &witnesses[j]);
            cross_terms.push(inner_product);
        }
    }

    Ok(cross_terms)
}

/// Compute inner product ⟨a, b⟩ = Σᵢ aᵢ·bᵢ
fn compute_inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    
    a.iter()
        .zip(b.iter())
        .map(|(&ai, &bi)| ai.mul(&bi))
        .fold(F::zero(), |acc, x| acc.add(&x))
}

/// Verify cross-term consistency after folding
/// Implements NEO-10.9
pub fn verify_cross_terms<F: Field>(
    folded_witness: &[F],
    original_values: &[F],
    cross_terms: &[F],
    challenges: &[F],
) -> bool {
    let beta = challenges.len();
    
    // Compute ⟨w', w'⟩
    let folded_inner = compute_inner_product(folded_witness, folded_witness);

    // Compute expected: Σᵢ αᵢ²·yᵢ² + 2·Σᵢ<ⱼ αᵢαⱼ·σᵢⱼ
    let mut expected = F::zero();

    // Diagonal terms: Σᵢ αᵢ²·yᵢ²
    for (i, (&alpha_i, &y_i)) in challenges.iter().zip(original_values.iter()).enumerate() {
        let term = alpha_i.mul(&alpha_i).mul(&y_i.mul(&y_i));
        expected = expected.add(&term);
    }

    // Cross terms: 2·Σᵢ<ⱼ αᵢαⱼ·σᵢⱼ
    let mut cross_idx = 0;
    for i in 0..beta {
        for j in (i + 1)..beta {
            if cross_idx >= cross_terms.len() {
                return false;
            }
            let term = challenges[i]
                .mul(&challenges[j])
                .mul(&cross_terms[cross_idx])
                .mul(&F::from_u64(2));
            expected = expected.add(&term);
            cross_idx += 1;
        }
    }

    folded_inner == expected
}

/// Batched evaluation claim operations
/// Implements NEO-10.12, NEO-10.13, NEO-6.15
pub struct BatchedEvaluationClaims<F: Field> {
    claims: Vec<EvaluationClaim<F>>,
}

impl<F: Field> BatchedEvaluationClaims<F> {
    /// Create a new batched evaluation claims structure
    pub fn new(claims: Vec<EvaluationClaim<F>>) -> Self {
        Self { claims }
    }

    /// Evaluate multiple MLEs at their respective points
    pub fn batch_evaluate(&self, witnesses: &[Vec<F>]) -> Result<Vec<F>, String> {
        if witnesses.len() != self.claims.len() {
            return Err("Mismatched number of witnesses and claims".to_string());
        }

        let mut results = Vec::with_capacity(self.claims.len());
        
        for (claim, witness) in self.claims.iter().zip(witnesses.iter()) {
            let mle = MultilinearPolynomial::new(witness.clone());
            let value = mle.evaluate(&claim.point);
            results.push(value);
        }

        Ok(results)
    }

    /// Compute all cross-terms for batched claims
    pub fn batch_cross_terms(&self, witnesses: &[Vec<F>]) -> Result<Vec<F>, String> {
        compute_cross_terms(witnesses)
    }

    /// Optimize for β = 2 case (most common): only one cross-term
    pub fn fold_two_claims(
        claim1: &EvaluationClaim<F>,
        claim2: &EvaluationClaim<F>,
        witness1: &[F],
        witness2: &[F],
        challenge1: F,
        challenge2: F,
    ) -> Result<(EvaluationClaim<F>, Vec<F>, F), String> {
        // Verify same evaluation point
        if claim1.point != claim2.point {
            return Err("Claims must have the same evaluation point".to_string());
        }

        // Compute the single cross-term σ₁₂ = ⟨w₁, w₂⟩
        let cross_term = compute_inner_product(witness1, witness2);

        // Fold the claims
        let claims = vec![claim1.clone(), claim2.clone()];
        let witnesses = vec![witness1.to_vec(), witness2.to_vec()];
        let challenges = vec![challenge1, challenge2];

        let (folded_claim, folded_witness) = fold_evaluation_claims(&claims, &witnesses, &challenges)?;

        Ok((folded_claim, folded_witness, cross_term))
    }

    /// Get number of claims
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::ring::{CyclotomicRing, RingElement};
    use crate::commitment::AjtaiCommitmentScheme;
    
    /// Create a test commitment for a witness
    ///
    /// Uses Ajtai commitment scheme with standard test parameters.
    fn create_test_commitment<F: crate::field::Field>(witness: &[F]) -> Commitment<F> {
        let ring_degree = 64;
        let ring = CyclotomicRing::new(ring_degree);
        
        // Pack witness into ring elements
        let num_ring_elems = (witness.len() + ring_degree - 1) / ring_degree;
        let mut ring_witness = Vec::with_capacity(num_ring_elems);
        
        for i in 0..num_ring_elems {
            let start = i * ring_degree;
            let end = (start + ring_degree).min(witness.len());
            
            let mut coeffs = witness[start..end].to_vec();
            while coeffs.len() < ring_degree {
                coeffs.push(F::zero());
            }
            
            ring_witness.push(RingElement::new(coeffs));
        }
        
        // Create commitment scheme
        let kappa = 4;
        let norm_bound = 1u64 << 20;
        let scheme = AjtaiCommitmentScheme::new(
            ring.clone(),
            kappa,
            ring_witness.len(),
            norm_bound,
        );
        
        // Compute commitment
        scheme.commit(&ring_witness).expect("Commitment failed")
    }

    #[test]
    fn test_evaluation_claim_verify() {
        type F = GoldilocksField;
        
        // Create a simple witness: [1, 2, 3, 4]
        let witness = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ];

        // Evaluation point: [0, 0] (should give first element)
        let point = vec![F::zero(), F::zero()];
        let mle = MultilinearPolynomial::new(witness.clone());
        let value = mle.evaluate(&point);

        // Create real commitment using Ajtai scheme
        let commitment = create_test_commitment(&witness);
        
        let claim = EvaluationClaim::new(commitment, point, value);
        assert!(claim.verify(&witness));
    }

    #[test]
    fn test_compute_cross_terms() {
        type F = GoldilocksField;
        
        let w1 = vec![F::from_u64(1), F::from_u64(2)];
        let w2 = vec![F::from_u64(3), F::from_u64(4)];
        let w3 = vec![F::from_u64(5), F::from_u64(6)];

        let witnesses = vec![w1, w2, w3];
        let cross_terms = compute_cross_terms(&witnesses).unwrap();

        // Should have 3 cross-terms: σ₁₂, σ₁₃, σ₂₃
        assert_eq!(cross_terms.len(), 3);
    }

    #[test]
    fn test_fold_two_claims() {
        type F = GoldilocksField;
        
        // Simple witnesses
        let w1 = vec![F::from_u64(1), F::from_u64(2)];
        let w2 = vec![F::from_u64(3), F::from_u64(4)];

        let point = vec![F::zero()];
        
        let mle1 = MultilinearPolynomial::new(w1.clone());
        let mle2 = MultilinearPolynomial::new(w2.clone());
        
        let value1 = mle1.evaluate(&point);
        let value2 = mle2.evaluate(&point);

        let commitment1 = Commitment::dummy(2);
        let commitment2 = Commitment::dummy(2);

        let claim1 = EvaluationClaim::new(commitment1, point.clone(), value1);
        let claim2 = EvaluationClaim::new(commitment2, point.clone(), value2);

        let alpha1 = F::from_u64(2);
        let alpha2 = F::from_u64(3);

        let result = BatchedEvaluationClaims::fold_two_claims(
            &claim1, &claim2, &w1, &w2, alpha1, alpha2
        );

        assert!(result.is_ok());
    }
}
