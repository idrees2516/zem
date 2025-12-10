// Π^norm+: Norm-Check Composition (Corollary 1)
//
// Mathematical Background:
// Composes three protocols to reduce norm-bound relation to linear relation:
// Ξ^norm → Ξ^sum → Ξ^lde-⊗ → Ξ^lin
//
// Protocol Chain:
// 1. Π^norm: Compute inner products, verify norm bounds
// 2. Π^sum: Run sumcheck protocol with dynamic programming
// 3. Π^lde-⊗: Reduce LDE evaluations to linear equations
//
// Properties:
// - Knowledge error: κ = (2µ(d-1) + r - 1)/q^e
// - Communication: (2d-1)µe log q + 3r log |R_q| bits
//   * Norm-check: r log |R_q| (inner products)
//   * Sumcheck: (2d-1)µe log q (round polynomials)
//   * Final evals: 2r log |R_q| (LDE evaluations)
// - Prover time: O(d^µ · r) ring operations
// - Verifier time: O(µ · d · e + r) operations
//
// Reference: SALSAA paper Corollary 1, Requirement 7.2

use crate::field::Field;
use crate::ring::cyclotomic::CyclotomicRing;
use crate::ring::crt::CRTContext;
use crate::salsaa::lde::LDEContext;
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{
    NormStatement, NormWitness, LinearStatement, LinearWitness,
};
use crate::salsaa::transcript::Transcript;
use crate::salsaa::protocols::{
    NormCheckReduction, SumcheckReduction, LDETensorReduction,
};
use std::sync::Arc;

/// Norm-check composition protocol
///
/// Combines Π^norm, Π^sum, and Π^lde-⊗ into single reduction
pub struct NormCheckComposition<F: Field> {
    /// Norm-check protocol
    norm_check: NormCheckReduction<F>,
    
    /// Sumcheck protocol
    sumcheck: SumcheckReduction<F>,
    
    /// LDE tensor reduction
    lde_tensor: LDETensorReduction<F>,
}

impl<F: Field> NormCheckComposition<F> {
    /// Create new norm-check composition
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        lde_context: Arc<LDEContext<F>>,
        crt_context: Arc<CRTContext<F>>,
    ) -> Self {
        let norm_check = NormCheckReduction::new(
            ring.clone(),
            crt_context.clone(),
        );
        
        let sumcheck = SumcheckReduction::new(
            ring.clone(),
            lde_context.clone(),
            crt_context.clone(),
        );
        
        let lde_tensor = LDETensorReduction::new(
            ring.clone(),
            lde_context.clone(),
            crt_context.clone(),
        );
        
        Self {
            norm_check,
            sumcheck,
            lde_tensor,
        }
    }
    
    /// Prover reduction: Ξ^norm → Ξ^lin
    ///
    /// Executes full protocol chain:
    /// 1. Run Π^norm to get sumcheck statement
    /// 2. Run Π^sum to get LDE statement
    /// 3. Run Π^lde-⊗ to get linear statement
    ///
    /// Returns final linear statement and witness, plus all intermediate proofs
    pub fn prover_reduce(
        &self,
        norm_statement: &NormStatement<F>,
        norm_witness: &NormWitness<F>,
        transcript: &mut Transcript,
        existing_h: Option<&Matrix<F>>,
        existing_f: Option<&Matrix<F>>,
        existing_y: Option<&Matrix<F>>,
    ) -> (LinearStatement<F>, LinearWitness<F>) {
        // Step 1: Π^norm - Compute inner products and create sumcheck statement
        let (sumcheck_statement, sumcheck_witness) = self.norm_check.prover_norm_check(
            norm_statement,
            norm_witness,
            transcript,
        );
        
        // Step 2: Π^sum - Run sumcheck protocol
        let sumcheck_proof = self.sumcheck.prover_sumcheck(
            &sumcheck_statement,
            &sumcheck_witness,
            transcript,
        );
        
        // Step 3: Create LDE witness from sumcheck witness
        let lde_witness = crate::salsaa::relations::LDEWitness {
            w_matrix: sumcheck_witness.w_matrix.clone(),
        };
        
        // Create LDE statement from sumcheck proof
        let lde_statement = crate::salsaa::relations::LDEStatement {
            eval_points: vec![
                sumcheck_proof.challenge_point.clone(),
                sumcheck_proof.challenge_point.iter()
                    .map(|c| self.conjugate_ext_field(c))
                    .collect(),
            ],
            claimed_values: vec![
                sumcheck_proof.final_eval_w.clone(),
                sumcheck_proof.final_eval_w_conj.clone(),
            ],
            tensor_matrices: vec![],
        };
        
        // Step 4: Π^lde-⊗ - Reduce LDE to linear
        let (linear_statement, linear_witness) = self.lde_tensor.prover_reduce(
            &lde_statement,
            &lde_witness,
            existing_h,
            existing_f,
            existing_y,
        );
        
        (linear_statement, linear_witness)
    }
    
    /// Verifier reduction: Ξ^norm → Ξ^lin
    ///
    /// Verifies full protocol chain and outputs linear statement
    ///
    /// Algorithm:
    /// 1. Receive and verify norm-check (inner products)
    /// 2. Verify sumcheck protocol
    /// 3. Compute LDE tensor reduction
    ///
    /// Returns linear statement that verifier can check
    pub fn verifier_reduce(
        &self,
        norm_statement: &NormStatement<F>,
        inner_products: &[crate::ring::cyclotomic::RingElement<F>],
        sumcheck_proof: &crate::salsaa::protocols::sumcheck::SumcheckProof<F>,
        transcript: &mut Transcript,
        existing_h: Option<&Matrix<F>>,
        existing_f: Option<&Matrix<F>>,
        existing_y: Option<&Matrix<F>>,
    ) -> Result<LinearStatement<F>, String> {
        // Step 1: Verify norm-check
        let sumcheck_statement = self.norm_check.verifier_norm_check(
            norm_statement,
            inner_products,
            transcript,
        )?;
        
        // Step 2: Verify sumcheck
        let lde_statement = self.sumcheck.verifier_sumcheck(
            &sumcheck_statement,
            sumcheck_proof,
            transcript,
        )?;
        
        // Step 3: Compute LDE tensor reduction
        let linear_statement = self.lde_tensor.verifier_reduce(
            &lde_statement,
            existing_h,
            existing_f,
            existing_y,
        );
        
        Ok(linear_statement)
    }
    
    /// Compute knowledge error
    ///
    /// κ = (2µ(d-1) + r - 1)/q^e
    ///
    /// This bounds the probability that a malicious prover can convince
    /// the verifier without knowing a valid witness.
    pub fn knowledge_error(&self, d: usize, mu: usize, r: usize, q_e: u64) -> f64 {
        let numerator = 2 * mu * (d - 1) + r - 1;
        numerator as f64 / q_e as f64
    }
    
    /// Estimate communication cost in bits
    ///
    /// Total: (2d-1)µe log q + 3r log |R_q|
    /// - Norm-check: r log |R_q|
    /// - Sumcheck: (2d-1)µe log q
    /// - Final evaluations: 2r log |R_q|
    pub fn communication_bits(
        &self,
        d: usize,
        mu: usize,
        r: usize,
        e: usize,
        log_q: usize,
        log_ring_size: usize,
    ) -> usize {
        let norm_check_bits = r * log_ring_size;
        let sumcheck_bits = (2 * d - 1) * mu * e * log_q;
        let final_eval_bits = 2 * r * log_ring_size;
        
        norm_check_bits + sumcheck_bits + final_eval_bits
    }
    
    /// Conjugate extension field element
    fn conjugate_ext_field(
        &self,
        elem: &crate::ring::crt::ExtFieldElement<F>,
    ) -> crate::ring::crt::ExtFieldElement<F> {
        let mut conj_coeffs = elem.coeffs.clone();
        for i in (1..conj_coeffs.len()).step_by(2) {
            conj_coeffs[i] = conj_coeffs[i].neg();
        }
        
        crate::ring::crt::ExtFieldElement {
            coeffs: conj_coeffs,
            degree: elem.degree,
            modulus_type: elem.modulus_type.clone(),
        }
    }
}
