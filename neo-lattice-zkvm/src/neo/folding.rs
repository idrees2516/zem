// Neo Folding Scheme Implementation
// Tasks 7.4, 7.5: Implement folded witness evaluation and norm bound tracking
//
// **Paper Reference**: Neo Section 3 "Folding Scheme", Requirements 5.1-5.3
//
// **Folding Overview**:
// Given ℓ CCS instances (x^(1), w^(1)), ..., (x^(ℓ), w^(ℓ)), the folding scheme:
// 1. Builds union polynomial w̃_∪(Y,X)
// 2. Verifier sends random challenge τ ∈ F^{log ℓ}
// 3. Prover computes folded witness w̃(X) = w̃_∪(τ,X)
// 4. Tracks norm bound: ||w'|| ≤ ℓ·||γ||·max_i||w_i||
//
// **Key Innovation**:
// Unlike pairing-based folding, lattice folding must carefully track norm growth
// to maintain binding security under Module-SIS.

use crate::field::Field;
use crate::ring::RingElement;
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey};
use super::ccs::{CCSInstance, CCSWitness};
use super::union_polynomial::{NeoUnionPolynomial, UnionPolynomialComputation};

/// Folded CCS instance after folding ℓ instances
/// 
/// **Paper Reference**: Neo Section 3.2, Requirement 5.1
/// 
/// **Structure**:
/// - Accumulated public input (aggregated from all instances)
/// - Folding challenge τ used to fold
/// - Error term from folding (should be small)
/// - Commitment to folded witness
#[derive(Clone, Debug)]
pub struct FoldedCCSInstance<F: Field> {
    /// Folded CCS instance structure
    pub instance: CCSInstance<F>,
    /// Folding challenge τ ∈ F^{log ℓ}
    pub challenge: Vec<F>,
    /// Error term from folding
    pub error: F,
    /// Commitment to folded witness
    pub commitment: AjtaiCommitment<F>,
}

/// Folded CCS witness
/// 
/// **Paper Reference**: Neo Section 3.2, Requirement 5.2
/// 
/// **Formula**: w̃(X) = w̃_∪(τ,X) = Σ_k eq̃_k(τ)·w̃^(k)(X)
/// 
/// This is the witness for the folded instance, computed by evaluating
/// the union polynomial at the verifier's challenge.
#[derive(Clone, Debug)]
pub struct FoldedCCSWitness<F: Field> {
    /// Folded witness vector
    pub witness: Vec<F>,
    /// Norm bound ||w'||
    pub norm_bound: f64,
    /// Union polynomial (for proof generation)
    pub union_polynomial: Option<NeoUnionPolynomial<F>>,
}

/// Neo folding proof
/// 
/// **Paper Reference**: Neo Section 3, Requirements 5.10-5.11
/// 
/// **Components**:
/// - Sumcheck proof for CCS reduction
/// - Decomposition proof for norm control
/// - Evaluation claims for polynomial openings
#[derive(Clone, Debug)]
pub struct NeoFoldingProof<F: Field> {
    /// Sumcheck proof for CCS constraint verification
    pub sumcheck_proof: SumcheckProof<F>,
    /// Decomposition proof for norm bounds
    pub decomposition_proof: Option<DecompositionProof<F>>,
    /// Evaluation claims for polynomial commitments
    pub evaluation_claims: Vec<EvaluationClaim<F>>,
    /// Random linear combination coefficients
    pub rlc_coefficients: Vec<F>,
}

/// Sumcheck proof (simplified for now)
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials
    pub round_polynomials: Vec<Vec<F>>,
    /// Final evaluation
    pub final_evaluation: F,
}

/// Decomposition proof (for norm control)
#[derive(Clone, Debug)]
pub struct DecompositionProof<F: Field> {
    /// Decomposed witness vectors
    pub decomposed_witnesses: Vec<Vec<F>>,
    /// Base for decomposition
    pub base: usize,
}

/// Evaluation claim for polynomial opening
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    /// Evaluation point
    pub point: Vec<F>,
    /// Claimed value
    pub value: F,
}

/// Folding parameters
/// 
/// **Paper Reference**: Neo Section 3.2
/// 
/// **Parameters**:
/// - ℓ: number of instances to fold
/// - β: norm bound for individual witnesses
/// - T: operator norm bound for challenge set (typically ≤ 15)
#[derive(Clone, Debug)]
pub struct FoldingParameters {
    /// Number of instances to fold
    pub num_instances: usize,
    /// Individual witness norm bound
    pub beta: f64,
    /// Challenge set operator norm bound
    pub operator_norm_bound: f64,
}

impl FoldingParameters {
    /// Create new folding parameters
    pub fn new(num_instances: usize, beta: f64, operator_norm_bound: f64) -> Self {
        Self {
            num_instances,
            beta,
            operator_norm_bound,
        }
    }
    
    /// Compute folded witness norm bound
    /// 
    /// **Paper Reference**: Neo Section 3.2, Requirement 5.3
    /// 
    /// **Formula**: ||w'|| ≤ ℓ·||γ||·max_i||w_i||
    /// where:
    /// - ℓ is the number of instances
    /// - ||γ|| ≤ 2ℓ for subtractive challenge sets
    /// - max_i||w_i|| ≤ β is the maximum witness norm
    /// 
    /// **For LaBRADOR challenge set**:
    /// ||γ|| ≤ ||S||_op ≤ 15, giving tighter bound:
    /// ||w'|| ≤ ℓ·15·β
    /// 
    /// **Why This Matters**:
    /// Norm growth is the key challenge in lattice-based folding.
    /// After k folding steps, norm grows as ℓ^k·β, which can quickly
    /// exceed the Module-SIS bound. This requires:
    /// 1. Careful parameter selection
    /// 2. Decomposition to reset norms
    /// 3. Limited folding depth
    pub fn compute_folded_norm_bound(&self) -> f64 {
        let ell = self.num_instances as f64;
        let gamma_norm = 2.0 * ell; // Subtractive challenge set
        ell * gamma_norm * self.beta
    }
    
    /// Compute folded norm bound with LaBRADOR challenge set
    /// 
    /// **Paper Reference**: Symphony Section 3.1, Neo Section 3.2
    /// 
    /// **Tighter Bound**: ||w'|| ≤ ℓ·T·β where T = ||S||_op ≤ 15
    /// 
    /// This is significantly better than the generic bound of ℓ·2ℓ·β.
    pub fn compute_folded_norm_bound_labrador(&self) -> f64 {
        let ell = self.num_instances as f64;
        ell * self.operator_norm_bound * self.beta
    }
}

/// Neo folding scheme trait
/// 
/// **Paper Reference**: Neo Section 3, Requirements 5.1-5.12
/// 
/// Provides interface for folding multiple CCS instances into one.
pub trait NeoFoldingScheme<F: Field> {
    /// Fold ℓ CCS instances into one
    /// 
    /// **Input**:
    /// - instances: ℓ CCS instances to fold
    /// - witnesses: corresponding witnesses
    /// - params: folding parameters
    /// - commitment_key: for committing to folded witness
    /// 
    /// **Output**:
    /// - folded_instance: single folded CCS instance
    /// - folded_witness: folded witness w̃(X) = w̃_∪(τ,X)
    /// - proof: folding proof for verification
    fn fold(
        instances: &[CCSInstance<F>],
        witnesses: &[CCSWitness<F>],
        params: &FoldingParameters,
        commitment_key: &CommitmentKey<F>,
    ) -> (FoldedCCSInstance<F>, FoldedCCSWitness<F>, NeoFoldingProof<F>);
    
    /// Verify folding proof
    fn verify_fold(
        instances: &[CCSInstance<F>],
        folded: &FoldedCCSInstance<F>,
        proof: &NeoFoldingProof<F>,
    ) -> bool;
}

/// Neo folding scheme implementation
pub struct NeoFoldingImpl;

impl NeoFoldingImpl {
    /// Build union polynomial from witnesses
    /// 
    /// **Paper Reference**: Neo Section 3.2, Requirement 5.1
    fn build_union_polynomial<F: Field>(
        witnesses: &[CCSWitness<F>],
    ) -> NeoUnionPolynomial<F> {
        NeoUnionPolynomial::from_witnesses(witnesses)
    }
    
    /// Generate folding challenge τ
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// **Challenge Generation**:
    /// τ ∈ F^{log ℓ} is sampled uniformly at random (via Fiat-Shamir).
    /// 
    /// **Security**:
    /// Randomness of τ ensures that the folded witness is a random
    /// linear combination, preventing the prover from cheating.
    fn generate_folding_challenge<F: Field>(
        num_instances: usize,
        transcript: &[u8],
    ) -> Vec<F> {
        let log_ell = (num_instances as f64).log2().ceil() as usize;
        
        // In production, use proper Fiat-Shamir transform
        // For now, derive from transcript hash
        let mut challenges = Vec::with_capacity(log_ell);
        
        for i in 0..log_ell {
            let mut hash_input = transcript.to_vec();
            hash_input.extend_from_slice(&(i as u64).to_le_bytes());
            
            // Simple hash-to-field (use proper hash in production)
            let hash_val: u64 = hash_input.iter()
                .enumerate()
                .map(|(j, &b)| (b as u64).wrapping_mul(31u64.wrapping_pow(j as u32)))
                .sum();
            
            challenges.push(F::from_u64(hash_val % F::MODULUS));
        }
        
        challenges
    }
    
    /// Compute folded witness: w̃(X) = w̃_∪(τ,X)
    /// 
    /// **Paper Reference**: Neo Section 3.2, Requirement 5.2
    /// 
    /// **Formula**: w̃(X) = Σ_k eq̃_k(τ)·w̃^(k)(X)
    /// 
    /// **This is the core folding operation!**
    /// 
    /// The verifier's random challenge τ "selects" a random linear combination
    /// of the ℓ witnesses, giving a single folded witness.
    fn compute_folded_witness<F: Field>(
        union_poly: &NeoUnionPolynomial<F>,
        tau: &[F],
    ) -> Vec<F> {
        union_poly.evaluate_partial(tau)
    }
    
    /// Track norm bound for folded witness
    /// 
    /// **Paper Reference**: Neo Section 3.2, Requirement 5.3
    /// 
    /// **Formula**: ||w'|| ≤ ℓ·||γ||·max_i||w_i||
    /// 
    /// **Implementation**:
    /// 1. Compute ||w_i|| for each witness
    /// 2. Take maximum: β = max_i||w_i||
    /// 3. Compute ||γ|| from challenge set (typically ≤ 15 for LaBRADOR)
    /// 4. Bound: ||w'|| ≤ ℓ·||γ||·β
    /// 
    /// **Why This Matters**:
    /// This bound must be verified to ensure the folded witness doesn't
    /// exceed the Module-SIS parameter β_SIS. If it does, the commitment
    /// binding breaks and the scheme is insecure.
    fn compute_norm_bound<F: Field>(
        witnesses: &[CCSWitness<F>],
        params: &FoldingParameters,
    ) -> f64 {
        // Compute max witness norm
        let max_witness_norm = witnesses
            .iter()
            .map(|w| Self::compute_witness_norm(w))
            .fold(0.0, f64::max);
        
        // Use LaBRADOR bound if operator norm is set
        if params.operator_norm_bound > 0.0 {
            params.num_instances as f64 * params.operator_norm_bound * max_witness_norm
        } else {
            // Generic bound
            let ell = params.num_instances as f64;
            ell * 2.0 * ell * max_witness_norm
        }
    }
    
    /// Compute L2 norm of witness
    fn compute_witness_norm<F: Field>(witness: &CCSWitness<F>) -> f64 {
        let sum_squared: u128 = witness.witness
            .iter()
            .map(|v| {
                let val = v.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation
                let balanced = if val <= modulus / 2 {
                    val as i128
                } else {
                    -((modulus - val) as i128)
                };
                (balanced * balanced) as u128
            })
            .sum();
        
        (sum_squared as f64).sqrt()
    }
    
    /// Aggregate public inputs from all instances
    /// 
    /// **Paper Reference**: Neo Section 3.2
    /// 
    /// The folded instance's public input is the concatenation of all
    /// individual public inputs: x' = (x^(1), ..., x^(ℓ))
    fn aggregate_public_inputs<F: Field>(
        instances: &[CCSInstance<F>],
    ) -> Vec<F> {
        instances.iter()
            .flat_map(|inst| inst.public_input.clone())
            .collect()
    }
    
    /// Commit to folded witness
    fn commit_folded_witness<F: Field>(
        folded_witness: &[F],
        commitment_key: &CommitmentKey<F>,
    ) -> AjtaiCommitment<F> {
        // Convert field elements to ring elements for commitment
        let ring_witness: Vec<RingElement<F>> = folded_witness
            .iter()
            .map(|v| {
                let mut coeffs = vec![F::zero(); commitment_key.ring.degree];
                coeffs[0] = *v;
                RingElement::from_coeffs(coeffs)
            })
            .collect();
        
        crate::commitment::ajtai::AjtaiCommitment::commit(commitment_key, &ring_witness)
    }
}

impl<F: Field> NeoFoldingScheme<F> for NeoFoldingImpl {
    fn fold(
        instances: &[CCSInstance<F>],
        witnesses: &[CCSWitness<F>],
        params: &FoldingParameters,
        commitment_key: &CommitmentKey<F>,
    ) -> (FoldedCCSInstance<F>, FoldedCCSWitness<F>, NeoFoldingProof<F>) {
        assert_eq!(instances.len(), witnesses.len(), "Instance/witness count mismatch");
        assert_eq!(instances.len(), params.num_instances, "Parameter mismatch");
        
        // Step 1: Build union polynomial w̃_∪(Y,X)
        let union_poly = Self::build_union_polynomial(witnesses);
        
        // Step 2: Generate folding challenge τ
        // In production, use Fiat-Shamir with instance commitments
        let transcript = b"neo_folding";
        let tau = Self::generate_folding_challenge(params.num_instances, transcript);
        
        // Step 3: Compute folded witness w̃(X) = w̃_∪(τ,X)
        let folded_witness_vec = Self::compute_folded_witness(&union_poly, &tau);
        
        // Step 4: Track norm bound
        let norm_bound = Self::compute_norm_bound(witnesses, params);
        
        // Step 5: Commit to folded witness
        let commitment = Self::commit_folded_witness(&folded_witness_vec, commitment_key);
        
        // Step 6: Aggregate public inputs
        let aggregated_public_input = Self::aggregate_public_inputs(instances);
        
        // Step 7: Create folded instance
        // For simplicity, use first instance's structure
        let folded_instance = FoldedCCSInstance {
            instance: CCSInstance {
                m: instances[0].m,
                n: instances[0].n,
                ell: aggregated_public_input.len(),
                t: instances[0].t,
                q: instances[0].q,
                matrices: instances[0].matrices.clone(),
                selectors: instances[0].selectors.clone(),
                coefficients: instances[0].coefficients.clone(),
                public_input: aggregated_public_input,
            },
            challenge: tau.clone(),
            error: F::zero(), // Computed during verification
            commitment: commitment.clone(),
        };
        
        // Step 8: Create folded witness
        let folded_witness = FoldedCCSWitness {
            witness: folded_witness_vec,
            norm_bound,
            union_polynomial: Some(union_poly),
        };
        
        // Step 9: Generate proof (simplified)
        let proof = NeoFoldingProof {
            sumcheck_proof: SumcheckProof {
                round_polynomials: vec![],
                final_evaluation: F::zero(),
            },
            decomposition_proof: None,
            evaluation_claims: vec![],
            rlc_coefficients: tau,
        };
        
        (folded_instance, folded_witness, proof)
    }
    
    fn verify_fold(
        instances: &[CCSInstance<F>],
        folded: &FoldedCCSInstance<F>,
        proof: &NeoFoldingProof<F>,
    ) -> bool {
        // Verify challenge consistency
        if folded.challenge != proof.rlc_coefficients {
            return false;
        }
        
        // Verify public input aggregation
        let expected_public_input: Vec<F> = instances.iter()
            .flat_map(|inst| inst.public_input.clone())
            .collect();
        
        if folded.instance.public_input != expected_public_input {
            return false;
        }
        
        // In full implementation:
        // 1. Verify sumcheck proof
        // 2. Verify evaluation claims
        // 3. Verify decomposition proof (if present)
        // 4. Check norm bounds
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    use crate::neo::ccs::SparseMatrix;
    
    type F = GoldilocksField;
    
    fn create_test_instance() -> (CCSInstance<F>, CCSWitness<F>) {
        let m = 2;
        let n = 3;
        let ell = 1;
        
        let mut matrix = SparseMatrix::new(m, n);
        matrix.set(0, 0, F::one());
        matrix.set(1, 1, F::one());
        
        let instance = CCSInstance::new(
            m,
            n,
            ell,
            vec![matrix],
            vec![super::super::ccs::SelectorSet::new(vec![0])],
            vec![F::one()],
            vec![F::from_u64(5)],
        ).unwrap();
        
        let witness = CCSWitness::new(vec![F::from_u64(1), F::from_u64(2)]);
        
        (instance, witness)
    }
    
    #[test]
    fn test_folding_parameters() {
        let params = FoldingParameters::new(4, 100.0, 15.0);
        
        // Generic bound: ℓ·2ℓ·β = 4·8·100 = 3200
        let generic_bound = params.compute_folded_norm_bound();
        assert_eq!(generic_bound, 3200.0);
        
        // LaBRADOR bound: ℓ·T·β = 4·15·100 = 6000
        let labrador_bound = params.compute_folded_norm_bound_labrador();
        assert_eq!(labrador_bound, 6000.0);
    }
    
    #[test]
    fn test_union_polynomial_building() {
        let (_, w1) = create_test_instance();
        let (_, w2) = create_test_instance();
        
        let witnesses = vec![w1, w2];
        let union_poly = NeoFoldingImpl::build_union_polynomial(&witnesses);
        
        assert_eq!(union_poly.num_instances(), 2);
    }
    
    #[test]
    fn test_challenge_generation() {
        let transcript = b"test_transcript";
        let challenges = NeoFoldingImpl::generate_folding_challenge::<F>(4, transcript);
        
        assert_eq!(challenges.len(), 2); // log_2(4) = 2
    }
}
