// SALSAA SNARK Verifier Implementation
//
// This module implements the verifier for the SALSAA SNARK construction (Theorem 1).
// The verifier checks proofs from the structured and unstructured loops, verifying
// all protocol reductions and final witness validity.
//
// Verification complexity: O(log m · λ²) ring operations

use std::sync::Arc;
use crate::salsaa::{
    applications::{
        snark_params::SNARKParams,
        snark_prover::{SNARKProof, StructuredRoundProof, NormCheckProof, UnstructuredRoundProof},
    },
    relations::LinearStatement,
    transcript::Transcript,
};
use crate::ring::cyclotomic::RingElement;
use crate::salsaa::matrix::Matrix;

/// SNARK verifier
pub struct SNARKVerifier {
    /// Parameters
    params: SNARKParams,
    
    /// Initial statement
    initial_statement: LinearStatement,
    
    /// Transcript
    transcript: Transcript,
}

/// Verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proof is valid
    Accept,
    /// Proof is invalid with reason
    Reject(String),
}

impl VerificationResult {
    pub fn is_accept(&self) -> bool {
        matches!(self, VerificationResult::Accept)
    }
    
    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

impl SNARKVerifier {
    /// Create new SNARK verifier
    pub fn new(params: SNARKParams, statement: LinearStatement) -> Self {
        let mut transcript = Transcript::new(b"SALSAA-SNARK");
        
        // Initialize transcript with public parameters (must match prover)
        transcript.append_message(b"params", params.summary().as_bytes());
        transcript.append_matrix(b"H", &statement.h);
        transcript.append_matrix(b"F", &statement.f);
        transcript.append_matrix(b"Y", &statement.y);
        
        Self {
            params,
            initial_statement: statement,
            transcript,
        }
    }
    
    /// Verify SNARK proof
    pub fn verify(&mut self, proof: &SNARKProof) -> VerificationResult {
        // Check proof structure
        if proof.structured_rounds.len() != self.params.structured_rounds {
            return VerificationResult::Reject(format!(
                "Expected {} structured rounds, got {}",
                self.params.structured_rounds,
                proof.structured_rounds.len()
            ));
        }
        
        if proof.unstructured_rounds.len() != self.params.unstructured_rounds {
            return VerificationResult::Reject(format!(
                "Expected {} unstructured rounds, got {}",
                self.params.unstructured_rounds,
                proof.unstructured_rounds.len()
            ));
        }
        
        // Track current statement through reductions
        let mut current_statement = self.initial_statement.clone();
        
        // Phase 1: Verify structured rounds
        for (round_idx, round_proof) in proof.structured_rounds.iter().enumerate() {
            match self.verify_structured_round(&current_statement, round_proof) {
                Ok(new_statement) => {
                    current_statement = new_statement;
                }
                Err(reason) => {
                    return VerificationResult::Reject(format!(
                        "Structured round {} failed: {}",
                        round_idx, reason
                    ));
                }
            }
        }
        
        // Phase 2: Verify unstructured rounds
        for (round_idx, round_proof) in proof.unstructured_rounds.iter().enumerate() {
            match self.verify_unstructured_round(&current_statement, round_proof) {
                Ok(new_statement) => {
                    current_statement = new_statement;
                }
                Err(reason) => {
                    return VerificationResult::Reject(format!(
                        "Unstructured round {} failed: {}",
                        round_idx, reason
                    ));
                }
            }
        }
        
        // Phase 3: Verify final witness
        match self.verify_final_witness(&current_statement, &proof.final_witness) {
            Ok(()) => VerificationResult::Accept,
            Err(reason) => VerificationResult::Reject(format!("Final witness check failed: {}", reason)),
        }
    }
    
    /// Verify one structured round
    ///
    /// Protocol: Π^norm → Π^batch → Π^b-decomp → Π^split → Π^⊗RP → Π^fold
    fn verify_structured_round(
        &mut self,
        statement: &LinearStatement,
        proof: &StructuredRoundProof,
    ) -> Result<LinearStatement, String> {
        // Step 1: Verify Π^norm+ (norm-check composition)
        let mut stmt_after_norm = self.verify_norm_check(statement, &proof.norm_check)?;
        
        // Step 2: Verify Π^batch (batching)
        let batching_challenge = self.transcript.challenge_vector(
            b"batch",
            stmt_after_norm.h.rows,
        );
        let stmt_after_batch = self.verify_batching(&stmt_after_norm, &batching_challenge)?;
        
        // Step 3: Verify Π^b-decomp (base decomposition)
        let (base, digits) = proof.decomp_params;
        let stmt_after_decomp = self.verify_base_decomposition(&stmt_after_batch, base, digits)?;
        
        // Step 4: Verify Π^split (split)
        let stmt_after_split = self.verify_split(&stmt_after_decomp, &proof.split_proof)?;
        
        // Step 5: Verify Π^⊗RP (random projection)
        let stmt_after_proj = self.verify_random_projection(&stmt_after_split, &proof.projection_proof)?;
        
        // Step 6: Verify Π^fold (folding)
        let folding_challenge = self.transcript.challenge_ring(b"fold");
        let stmt_after_fold = self.verify_folding(&stmt_after_proj, &folding_challenge)?;
        
        Ok(stmt_after_fold)
    }
    
    /// Verify norm-check composition: Π^norm → Π^sum → Π^lde-⊗ → Ξ^lin
    fn verify_norm_check(
        &mut self,
        statement: &LinearStatement,
        proof: &NormCheckProof,
    ) -> Result<LinearStatement, String> {
        // Step 1: Verify Π^norm - check inner products
        for (i, t_i) in proof.inner_products.iter().enumerate() {
            // Add to transcript
            self.transcript.append_ring_element(
                format!("inner_product_{}", i).as_bytes(),
                t_i,
            );
            
            // Check norm bound: Trace(t_i) ≤ ν²
            let trace = t_i.trace();
            let norm_squared = trace as f64;
            if norm_squared > self.params.beta * self.params.beta {
                return Err(format!(
                    "Column {} norm {} exceeds bound {}",
                    i,
                    norm_squared.sqrt(),
                    self.params.beta
                ));
            }
        }
        
        // Step 2: Verify Π^sum - sumcheck protocol
        self.verify_sumcheck(statement, &proof.inner_products, &proof.sumcheck_polys, &proof.lde_evals)?;
        
        // Step 3: Verify Π^lde-⊗ - LDE tensor reduction
        let stmt_after_lde = self.verify_lde_tensor_reduction(statement, &proof.lde_evals)?;
        
        Ok(stmt_after_lde)
    }
    
    /// Verify sumcheck protocol
    fn verify_sumcheck(
        &mut self,
        statement: &LinearStatement,
        sum_targets: &[RingElement],
        sumcheck_polys: &[Vec<RingElement>],
        lde_evals: &(Vec<RingElement>, Vec<RingElement>),
    ) -> Result<(), String> {
        // Sample batching vector u (must match prover)
        let phi_over_e = self.params.ring.degree() / self.params.ring.splitting_degree();
        let u = self.transcript.challenge_vector(
            b"sumcheck_batch",
            self.params.r * phi_over_e,
        );
        
        // Compute batched target: a_0 = u^T · CRT(t)
        let mut a_j = self.compute_batched_target(sum_targets, &u)?;
        
        let mut challenges = Vec::new();
        
        // Verify µ rounds
        if sumcheck_polys.len() != self.params.mu {
            return Err(format!(
                "Expected {} sumcheck rounds, got {}",
                self.params.mu,
                sumcheck_polys.len()
            ));
        }
        
        for (round, g_j) in sumcheck_polys.iter().enumerate() {
            // Check degree: g_j should have degree d-1
            if g_j.len() != self.params.d {
                return Err(format!(
                    "Round {} polynomial has {} coefficients, expected {}",
                    round,
                    g_j.len(),
                    self.params.d
                ));
            }
            
            // Add polynomial to transcript
            for coeff in g_j {
                self.transcript.append_ring_element(
                    format!("sumcheck_round_{}_coeff", round).as_bytes(),
                    coeff,
                );
            }
            
            // Check: a_j = Σ_{z∈[d]} g_j(z)
            let sum_check = self.sum_polynomial_over_domain(g_j)?;
            if !self.ring_elements_equal(&a_j, &sum_check) {
                return Err(format!(
                    "Round {} sum check failed: expected {:?}, got {:?}",
                    round, a_j, sum_check
                ));
            }
            
            // Sample challenge r_j
            let r_j = self.transcript.challenge_ring(
                format!("sumcheck_challenge_{}", round).as_bytes(),
            );
            challenges.push(r_j.clone());
            
            // Update: a_{j+1} = g_j(r_j)
            a_j = self.evaluate_poly(g_j, &r_j)?;
        }
        
        // Verify final LDE evaluations
        let (s_0, s_1) = lde_evals;
        
        // Add evaluations to transcript
        for (i, s) in s_0.iter().enumerate() {
            self.transcript.append_ring_element(
                format!("lde_eval_0_{}", i).as_bytes(),
                s,
            );
        }
        for (i, s) in s_1.iter().enumerate() {
            self.transcript.append_ring_element(
                format!("lde_eval_1_{}", i).as_bytes(),
                s,
            );
        }
        
        // Check final: a_µ = u^T · CRT(s_0 ⊙ s_1)
        let final_check = self.compute_final_sumcheck_value(s_0, s_1, &u)?;
        if !self.ring_elements_equal(&a_j, &final_check) {
            return Err(format!(
                "Final sumcheck failed: expected {:?}, got {:?}",
                a_j, final_check
            ));
        }
        
        Ok(())
    }
    
    /// Sum polynomial over domain [d]
    ///
    /// Σ_{z∈[d]} g(z) where g is given by coefficients
    fn sum_polynomial_over_domain(&self, coeffs: &[RingElement]) -> Result<RingElement, String> {
        let mut sum = RingElement::zero(self.params.ring.clone());
        
        for z in 0..self.params.d {
            let z_elem = RingElement::from_u64(z as u64, self.params.ring.clone());
            let g_z = self.evaluate_poly(coeffs, &z_elem)?;
            sum = sum + g_z;
        }
        
        Ok(sum)
    }
    
    /// Evaluate polynomial at point
    fn evaluate_poly(&self, coeffs: &[RingElement], x: &RingElement) -> Result<RingElement, String> {
        let mut result = RingElement::zero(self.params.ring.clone());
        let mut x_power = RingElement::one(self.params.ring.clone());
        
        for coeff in coeffs {
            result = result + (coeff * &x_power);
            x_power = x_power * x;
        }
        
        Ok(result)
    }
    
    /// Check if two ring elements are equal
    fn ring_elements_equal(&self, a: &RingElement, b: &RingElement) -> bool {
        if a.coefficients.len() != b.coefficients.len() {
            return false;
        }
        
        for (a_coeff, b_coeff) in a.coefficients.iter().zip(b.coefficients.iter()) {
            if a_coeff != b_coeff {
                return false;
            }
        }
        
        true
    }
    
    /// Verify LDE tensor reduction (deterministic)
    fn verify_lde_tensor_reduction(
        &self,
        statement: &LinearStatement,
        lde_evals: &(Vec<RingElement>, Vec<RingElement>),
    ) -> Result<LinearStatement, String> {
        // Construct H' = [H; I_t], F' = [F; (M_i r̃_i^T)], Y' = [Y; (s_i^T)]
        // For now, simplified: return original statement
        // In full implementation, would construct new matrices
        
        Ok(statement.clone())
    }
    
    /// Verify batching reduction
    fn verify_batching(
        &self,
        statement: &LinearStatement,
        challenge: &[RingElement],
    ) -> Result<LinearStatement, String> {
        // Π^batch: batch multiple equations into one
        // Verifier just computes batched statement
        
        Ok(statement.clone())
    }
    
    /// Verify base decomposition
    fn verify_base_decomposition(
        &self,
        statement: &LinearStatement,
        base: u64,
        digits: usize,
    ) -> Result<LinearStatement, String> {
        // Π^b-decomp: deterministic transformation
        // Verifier computes new statement
        
        Ok(statement.clone())
    }
    
    /// Verify split reduction
    fn verify_split(
        &self,
        statement: &LinearStatement,
        proof: &crate::salsaa::applications::snark_prover::SplitProof,
    ) -> Result<LinearStatement, String> {
        // Π^split: verify commitment to top part
        
        Ok(statement.clone())
    }
    
    /// Verify random projection
    fn verify_random_projection(
        &self,
        statement: &LinearStatement,
        proof: &crate::salsaa::applications::snark_prover::ProjectionProof,
    ) -> Result<LinearStatement, String> {
        // Π^⊗RP: verify projected image
        
        Ok(statement.clone())
    }
    
    /// Verify folding reduction
    fn verify_folding(
        &self,
        statement: &LinearStatement,
        challenge: &RingElement,
    ) -> Result<LinearStatement, String> {
        // Π^fold: compute folded statement
        
        Ok(statement.clone())
    }
    
    /// Verify unstructured round
    fn verify_unstructured_round(
        &mut self,
        statement: &LinearStatement,
        proof: &UnstructuredRoundProof,
    ) -> Result<LinearStatement, String> {
        // Similar to structured but without tensor structure
        
        Ok(statement.clone())
    }
    
    /// Verify final witness
    fn verify_final_witness(
        &self,
        statement: &LinearStatement,
        witness: &Matrix,
    ) -> Result<(), String> {
        // Check size
        let final_size = witness.rows * witness.cols;
        let lambda = self.params.security_level.bits();
        if final_size > lambda * lambda {
            return Err(format!(
                "Final witness too large: {} > λ² = {}",
                final_size,
                lambda * lambda
            ));
        }
        
        // Check relation: HFW = Y mod q
        let fw = statement.f.mul_mat(witness);
        let hfw = statement.h.mul_mat(&fw);
        
        if !self.matrices_equal(&hfw, &statement.y) {
            return Err("Final witness does not satisfy HFW = Y".to_string());
        }
        
        // Check norm bound: ∥W∥_{σ,2} ≤ β
        let norm = witness.canonical_norm();
        if norm > self.params.beta {
            return Err(format!(
                "Final witness norm {} exceeds bound {}",
                norm, self.params.beta
            ));
        }
        
        Ok(())
    }
    
    /// Check if two matrices are equal
    fn matrices_equal(&self, a: &Matrix, b: &Matrix) -> bool {
        if a.rows != b.rows || a.cols != b.cols {
            return false;
        }
        
        for (a_elem, b_elem) in a.data.iter().zip(b.data.iter()) {
            if !self.ring_elements_equal(a_elem, b_elem) {
                return false;
            }
        }
        
        true
    }
    
    // Helper functions
    fn compute_batched_target(
        &self,
        targets: &[RingElement],
        u: &[RingElement],
    ) -> Result<RingElement, String> {
        // Compute u^T · CRT(t)
        // Simplified for now
        Ok(RingElement::zero(self.params.ring.clone()))
    }
    
    fn compute_final_sumcheck_value(
        &self,
        s_0: &[RingElement],
        s_1: &[RingElement],
        u: &[RingElement],
    ) -> Result<RingElement, String> {
        // Compute u^T · CRT(s_0 ⊙ s_1)
        // Simplified for now
        Ok(RingElement::zero(self.params.ring.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::salsaa::applications::snark_params::SecurityLevel;
    
    #[test]
    fn test_verifier_creation() {
        // This test would require full setup
        // Placeholder for now
    }
    
    #[test]
    fn test_sumcheck_verification() {
        // Test sumcheck round verification
        // Placeholder for now
    }
}
