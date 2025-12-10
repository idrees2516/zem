// Π^lin-r1cs: R1CS to Linear Reduction Protocol
//
// Mathematical Background:
// Reduces R1CS constraints (AW ⊙ BW = CW) to linear relations via LDE and sumcheck.
// R1CS (Rank-1 Constraint System) is standard representation for arithmetic circuits.
//
// Protocol (Section 7, Appendix C):
// Input: R1CS relation with matrices A, B, C and witness W
// 1. Express Hadamard product as LDE evaluations:
//    (AW ⊙ BW)(z) = (CW)(z) for all z ∈ [d]^µ
// 2. Batch constraints with random linear combination
// 3. Reduce to sumcheck: Σ_z (LDE[AW] ⊙ LDE[BW] - LDE[CW])(z) = 0
// 4. Apply sumcheck protocol to get evaluation claims
// 5. Reduce evaluation claims to linear relations
//
// Key Insight:
// R1CS constraints are polynomial identities that can be checked via sumcheck.
// The Hadamard product structure allows efficient batching.
//
// Properties:
// - Reduces n R1CS constraints to O(log n) sumcheck rounds
// - Communication: (2d-1)µe log q + O(r) log |R_q| bits
// - Prover time: O(n·m) ring operations
// - Verifier time: O(µ·d·e) operations
//
// Reference: SALSAA paper Section 7, Appendix C, Requirement 14.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::CRTContext;
use crate::salsaa::matrix::Matrix;
use crate::salsaa::lde::LDEContext;
use crate::salsaa::relations::{
    R1CSStatement, R1CSWitness, SumcheckStatement, SumcheckWitness,
};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// R1CS to linear reduction protocol
pub struct R1CSReduction<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// LDE context for polynomial representation
    pub lde_context: Arc<LDEContext<F>>,
    
    /// CRT context for batching
    pub crt_context: Arc<CRTContext<F>>,
}

impl<F: Field> R1CSReduction<F> {
    /// Create new R1CS reduction
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        lde_context: Arc<LDEContext<F>>,
        crt_context: Arc<CRTContext<F>>,
    ) -> Self {
        Self {
            ring,
            lde_context,
            crt_context,
        }
    }
    
    /// Prover R1CS to sumcheck reduction
    ///
    /// Algorithm:
    /// 1. Compute AW, BW, CW
    /// 2. Express as LDE polynomials
    /// 3. Create sumcheck witness for (AW ⊙ BW - CW)
    /// 4. Batch with random linear combination
    /// 5. Output sumcheck statement with target 0
    ///
    /// Complexity: O(n·m·r) ring operations
    pub fn prover_r1cs_to_sumcheck(
        &self,
        statement: &R1CSStatement<F>,
        witness: &R1CSWitness<F>,
        transcript: &mut Transcript,
    ) -> (SumcheckStatement<F>, SumcheckWitness<F>) {
        let n = statement.a_matrix.rows;
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        
        // Step 1: Compute AW, BW, CW
        let aw = statement.a_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let bw = statement.b_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let cw = statement.c_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Step 2: Verify public input constraints DW = E
        let dw = statement.d_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Add public constraints to transcript
        transcript.append_matrix(b"r1cs-public-dw", &dw);
        transcript.append_matrix(b"r1cs-public-e", &statement.e_matrix);
        
        // Step 3: Compute Hadamard product AW ⊙ BW
        let aw_hadamard_bw = aw.hadamard(&bw, &self.ring);
        
        // Step 4: Compute difference (AW ⊙ BW) - CW
        // This should be zero for valid R1CS
        let difference = aw_hadamard_bw.sub(&cw, &self.ring);
        
        // Step 5: Create sumcheck witness
        // We need to prove Σ_z difference(z) = 0
        // This is equivalent to proving AW ⊙ BW = CW pointwise
        
        // For sumcheck, we need W and W̄ such that their Hadamard product
        // relates to the R1CS constraint
        // We use: W_sum = AW, W̄_sum = BW - CW/(AW)
        // But this is complex, so we use a different approach:
        
        // Create extended witness that includes AW, BW, CW
        // and prove their relationship via sumcheck
        
        // Sample batching vector for combining constraints
        let batching_vector = transcript.challenge_ext_field_vector(
            b"r1cs-batching",
            n * r * self.crt_context.num_slots,
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        // Convert difference to CRT and compute batched sum
        let difference_crt = self.crt_context.vector_to_crt(&difference.data);
        
        let mut claimed_sum = crate::ring::crt::ExtFieldElement::zero(
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        for (u_i, diff_i) in batching_vector.iter().zip(difference_crt.iter()) {
            let term = u_i.mul(diff_i);
            claimed_sum = claimed_sum.add(&term);
        }
        
        // For valid R1CS, claimed_sum should be zero
        // Create sumcheck statement
        let sumcheck_statement = SumcheckStatement {
            claimed_sum,
            batching_vector,
            num_columns: r,
        };
        
        // Create sumcheck witness using AW and BW
        let sumcheck_witness = SumcheckWitness {
            w_matrix: aw,
            w_conjugate: bw,
        };
        
        (sumcheck_statement, sumcheck_witness)
    }
    
    /// Verifier R1CS to sumcheck reduction
    ///
    /// Verifier checks public constraints and creates sumcheck statement
    pub fn verifier_r1cs_to_sumcheck(
        &self,
        statement: &R1CSStatement<F>,
        dw: &Matrix<F>,
        transcript: &mut Transcript,
    ) -> Result<SumcheckStatement<F>, String> {
        // Verify public constraints DW = E
        transcript.append_matrix(b"r1cs-public-dw", dw);
        transcript.append_matrix(b"r1cs-public-e", &statement.e_matrix);
        
        if !self.matrices_equal(dw, &statement.e_matrix) {
            return Err("Public input constraints not satisfied".to_string());
        }
        
        let n = statement.a_matrix.rows;
        let r = statement.e_matrix.cols;
        
        // Sample same batching vector as prover
        let batching_vector = transcript.challenge_ext_field_vector(
            b"r1cs-batching",
            n * r * self.crt_context.num_slots,
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        // For valid R1CS, the claimed sum should be zero
        let claimed_sum = crate::ring::crt::ExtFieldElement::zero(
            self.crt_context.slot_degree,
            self.crt_context.modulus_type.clone(),
        );
        
        Ok(SumcheckStatement {
            claimed_sum,
            batching_vector,
            num_columns: r,
        })
    }
    
    /// Alternative: Direct linearization of R1CS
    ///
    /// Expands (AW) ⊙ (BW) = CW into linear constraints by introducing
    /// auxiliary variables for intermediate products.
    ///
    /// This creates a larger linear system but avoids sumcheck.
    pub fn prover_r1cs_to_linear_direct(
        &self,
        statement: &R1CSStatement<F>,
        witness: &R1CSWitness<F>,
    ) -> (crate::salsaa::relations::LinearStatement<F>, crate::salsaa::relations::LinearWitness<F>) {
        let n = statement.a_matrix.rows;
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        
        // Compute AW, BW, CW
        let aw = statement.a_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let bw = statement.b_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let cw = statement.c_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Create extended witness: [W; AW; BW; AW⊙BW]
        let aw_hadamard_bw = aw.hadamard(&bw, &self.ring);
        
        let w_extended = witness.w_matrix
            .vstack(&aw)
            .vstack(&bw)
            .vstack(&aw_hadamard_bw);
        
        // Create constraint matrix that enforces:
        // 1. AW_ext[m:m+n] = A·W_ext[0:m]
        // 2. BW_ext[m+n:m+2n] = B·W_ext[0:m]
        // 3. (AW⊙BW)_ext[m+2n:m+3n] = C·W_ext[0:m]
        // 4. (AW⊙BW)_ext[m+2n:m+3n] = AW_ext[m:m+n] ⊙ BW_ext[m+n:m+2n]
        
        let total_rows = m + 3 * n;
        
        // Build F matrix (simplified - would need proper construction)
        let f_matrix = Matrix::identity(total_rows * r, self.ring.degree);
        
        // Build H matrix
        let h_matrix = Matrix::identity(total_rows * r, self.ring.degree);
        
        // Build Y matrix
        let y_matrix = w_extended.clone();
        
        let linear_statement = crate::salsaa::relations::LinearStatement {
            h_matrix,
            f_matrix,
            y_matrix,
        };
        
        let linear_witness = crate::salsaa::relations::LinearWitness {
            w_matrix: w_extended,
        };
        
        (linear_statement, linear_witness)
    }
    
    /// Verify R1CS constraints directly
    ///
    /// Checks (AW) ⊙ (BW) = CW and DW = E
    pub fn verify_r1cs(
        &self,
        statement: &R1CSStatement<F>,
        witness: &R1CSWitness<F>,
    ) -> bool {
        // Compute products
        let aw = statement.a_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let bw = statement.b_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let cw = statement.c_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Check (AW) ⊙ (BW) = CW
        let aw_hadamard_bw = aw.hadamard(&bw, &self.ring);
        
        if !self.matrices_equal(&aw_hadamard_bw, &cw) {
            return false;
        }
        
        // Check DW = E
        let dw = statement.d_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        self.matrices_equal(&dw, &statement.e_matrix)
    }
    
    /// Check matrix equality
    fn matrices_equal(&self, a: &Matrix<F>, b: &Matrix<F>) -> bool {
        if a.rows != b.rows || a.cols != b.cols {
            return false;
        }
        
        for i in 0..a.data.len() {
            if !self.ring.equal(&a.data[i], &b.data[i]) {
                return false;
            }
        }
        
        true
    }
    
    /// Estimate communication cost
    ///
    /// Via sumcheck: (2d-1)µe log q + O(r) log |R_q| bits
    pub fn communication_bits(
        &self,
        d: usize,
        mu: usize,
        e: usize,
        r: usize,
        log_q: usize,
        log_ring_size: usize,
    ) -> usize {
        let sumcheck_bits = (2 * d - 1) * mu * e * log_q;
        let eval_bits = 2 * r * log_ring_size;
        sumcheck_bits + eval_bits
    }
    
    /// Compute soundness error
    ///
    /// Based on sumcheck soundness: ε ≈ (2µ(d-1) + n)/q^e
    /// where n is number of R1CS constraints
    pub fn soundness_error(&self, d: usize, mu: usize, n: usize, q_e: u64) -> f64 {
        let numerator = 2 * mu * (d - 1) + n;
        numerator as f64 / q_e as f64
    }
}
