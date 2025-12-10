// Π^norm: Norm-Check Reduction Protocol
//
// Mathematical Background:
// Reduces norm-bound relation ∥W∥_{σ,2} ≤ ν to sumcheck relation.
// Verifies that witness columns have bounded canonical norm.
//
// Protocol (Figure 3, Lemma 4):
// 1. Prover computes inner products: t_i = ⟨w_i, w̄_i⟩ for each column i ∈ [r]
// 2. Prover sends t = (t_0, ..., t_{r-1}) to verifier
// 3. Verifier checks: Trace(t_i) ≤ ν² for all i
// 4. Output sumcheck statement: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t
//
// Canonical Norm:
// ∥w∥_{σ,2}² = Trace(⟨w, w̄⟩) = Σ_{j∈[φ]} |σ_j(w)|²
// where σ_j: K → ℂ are canonical embeddings
//
// Properties:
// - Communication: r log |R_q| bits (one ring element per column)
// - Verifier work: O(r) trace computations
// - Reduces to sumcheck with target t
//
// Reference: SALSAA paper Figure 3, Lemma 4, Requirements 7.1, 7.2

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::{CRTContext, ExtFieldElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{
    NormStatement, NormWitness, SumcheckStatement, SumcheckWitness,
};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Norm-check reduction protocol
pub struct NormCheckReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// CRT context for batching
    pub crt_context: Arc<CRTContext<F>>,
}

impl<F: Field> NormCheckReduction<F> {
    /// Create new norm-check reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        crt_context: Arc<CRTContext<F>>,
    ) -> Self {
        Self {
            ring,
            crt_context,
        }
    }
    
    /// Prover norm-check: Ξ^norm → Ξ^sum
    ///
    /// Algorithm:
    /// 1. For each column w_i, compute t_i = ⟨w_i, w̄_i⟩
    /// 2. Send t = (t_0, ..., t_{r-1}) to verifier
    /// 3. Create sumcheck witness with W and W̄
    /// 4. Create sumcheck statement with target t
    ///
    /// Complexity: O(r · d^µ) ring operations
    pub fn prover_norm_check(
        &self,
        statement: &NormStatement<F>,
        witness: &NormWitness<F>,
        transcript: &mut Transcript,
    ) -> (SumcheckStatement<F>, SumcheckWitness<F>) {
        let num_cols = statement.num_columns;
        
        // Step 1: Compute inner products t_i = ⟨w_i, w̄_i⟩
        let mut inner_products = Vec::with_capacity(num_cols);
        
        for col_idx in 0..num_cols {
            let column = witness.w_matrix.get_col(col_idx);
            let inner_product = self.compute_inner_product(&column);
            inner_products.push(inner_product);
        }
        
        // Step 2: Send inner products to transcript
        transcript.append_ring_vector(b"norm-check-inner-products", &inner_products);
        
        // Step 3: Compute conjugate witness W̄
        let w_conjugate = self.conjugate_matrix(&witness.w_matrix);
        
        // Step 4: Create batching vector (verifier will sample this)
        // For now, use deterministic batching based on transcript
        let batching_vector = self.generate_batching_vector(
            num_cols,
            transcript,
        );
        
        // Step 5: Compute claimed sum t = Σ_i u_i · t_i
        let claimed_sum = self.compute_claimed_sum(
            &inner_products,
            &batching_vector,
        );
        
        let sumcheck_statement = SumcheckStatement {
            claimed_sum,
            batching_vector,
            num_columns: num_cols,
        };
        
        let sumcheck_witness = SumcheckWitness {
            w_matrix: witness.w_matrix.clone(),
            w_conjugate,
        };
        
        (sumcheck_statement, sumcheck_witness)
    }
    
    /// Verifier norm-check: Ξ^norm → Ξ^sum
    ///
    /// Algorithm:
    /// 1. Receive inner products t from prover
    /// 2. Check Trace(t_i) ≤ ν² for all i
    /// 3. Sample batching vector u
    /// 4. Compute claimed sum t = Σ_i u_i · t_i
    /// 5. Output sumcheck statement
    ///
    /// Complexity: O(r · φ) for trace computations
    pub fn verifier_norm_check(
        &self,
        statement: &NormStatement<F>,
        inner_products: &[RingElement<F>],
        transcript: &mut Transcript,
    ) -> Result<SumcheckStatement<F>, String> {
        let num_cols = statement.num_columns;
        
        if inner_products.len() != num_cols {
            return Err(format!(
                "Expected {} inner products, got {}",
                num_cols, inner_products.len()
            ));
        }
        
        // Step 1: Add inner products to transcript
        transcript.append_ring_vector(b"norm-check-inner-products", inner_products);
        
        // Step 2: Verify norm bounds
        for (i, inner_product) in inner_products.iter().enumerate() {
            let trace = self.ring.trace(inner_product);
            let norm_squared = trace.to_canonical_u64();
            
            if norm_squared > statement.norm_bound * statement.norm_bound {
                return Err(format!(
                    "Column {} norm bound violated: {} > {}",
                    i, norm_squared, statement.norm_bound * statement.norm_bound
                ));
            }
        }
        
        // Step 3: Generate batching vector
        let batching_vector = self.generate_batching_vector(
            num_cols,
            transcript,
        );
        
        // Step 4: Compute claimed sum
        let claimed_sum = self.compute_claimed_sum(
            inner_products,
            &batching_vector,
        );
        
        Ok(SumcheckStatement {
            claimed_sum,
            batching_vector,
            num_columns: num_cols,
        })
    }
    
    /// Compute inner product ⟨w, w̄⟩ = Σ_j w_j · w̄_j
    fn compute_inner_product(&self, column: &[RingElement<F>]) -> RingElement<F> {
        let mut result = self.ring.zero();
        
        for elem in column {
            let conjugate = self.ring.conjugate(elem);
            let prod = self.ring.mul(elem, &conjugate);
            result = self.ring.add(&result, &prod);
        }
        
        result
    }
    
    /// Conjugate matrix: W̄ where each entry is conjugated
    fn conjugate_matrix(&self, matrix: &Matrix<F>) -> Matrix<F> {
        let conjugate_data: Vec<RingElement<F>> = matrix.data.iter()
            .map(|elem| self.ring.conjugate(elem))
            .collect();
        
        Matrix::from_data(matrix.rows, matrix.cols, conjugate_data)
    }
    
    /// Generate batching vector u ∈ F_{q^e}^{rφ/e}
    ///
    /// Samples random vector from transcript for batching columns
    fn generate_batching_vector(
        &self,
        num_cols: usize,
        transcript: &mut Transcript,
    ) -> Vec<ExtFieldElement<F>> {
        let slots_per_col = self.crt_context.num_slots;
        let total_slots = num_cols * slots_per_col;
        
        transcript.challenge_ext_field_vector(
            b"norm-check-batching",
            total_slots,
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        )
    }
    
    /// Compute claimed sum t = Σ_i u_i · CRT(t_i)
    ///
    /// Batches inner products using random linear combination
    fn compute_claimed_sum(
        &self,
        inner_products: &[RingElement<F>],
        batching_vector: &[ExtFieldElement<F>],
    ) -> ExtFieldElement<F> {
        // Convert inner products to CRT representation
        let inner_products_crt = self.crt_context.vector_to_crt(inner_products);
        
        // Compute inner product with batching vector
        let mut result = ExtFieldElement::zero(
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        for (u_i, t_i) in batching_vector.iter().zip(inner_products_crt.iter()) {
            let prod = u_i.mul(t_i);
            result = result.add(&prod);
        }
        
        result
    }
}
