// Π^⊗RP: Tensor Random Projection Protocol
//
// Mathematical Background:
// Projects witness to lower dimension using random matrix.
// Reduces witness height while preserving structure with high probability.
//
// Protocol (from [KLNO25]):
// Input: Linear relation HFW = Y with W ∈ R_q^{m×r}
// 1. Verifier samples random projection matrix R ∈ R_q^{m_rp×m}
// 2. Prover computes projected witness: w_proj = R·W ∈ R_q^{m_rp×r}
// 3. Prover computes projected commitment: y_proj = F·w_proj
// 4. Output two statements:
//    - Main: HFW = Y (original)
//    - Projection: H_rp·F_rp·w_proj = y_proj (projected)
//
// Properties:
// - Reduces witness height from m to m_rp (typically m_rp << m)
// - Norm bound: ∥w_proj∥ ≤ √m_rp · ∥W∥ with high probability
// - Soundness: Based on leftover hash lemma
// - Communication: |y_proj| bits
//
// Use Cases:
// - Witness compression in SNARK
// - Reducing proof size
// - Amortizing verification cost
//
// Reference: SALSAA paper Section 6.2, [KLNO25], Requirement 10.1

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::salsaa::matrix::Matrix;
use crate::salsaa::relations::{LinearStatement, LinearWitness};
use crate::salsaa::transcript::Transcript;
use std::sync::Arc;

/// Tensor random projection protocol
pub struct TensorRandomProjection<F: Field> {
    /// Cyclotomic ring for arithmetic
    pub ring: Arc<CyclotomicRing<F>>,
    
    /// Target projection dimension
    pub projection_dim: usize,
    
    /// Norm bound for projected witness
    pub norm_bound: u64,
}

/// Random projection proof
#[derive(Clone, Debug)]
pub struct RandomProjectionProof<F: Field> {
    /// Projection matrix R ∈ R_q^{m_rp×m}
    pub projection_matrix: Matrix<F>,
    
    /// Projected witness w_proj = R·W
    pub projected_witness: Matrix<F>,
    
    /// Projected commitment y_proj = F·w_proj
    pub projected_commitment: Matrix<F>,
}

impl<F: Field> TensorRandomProjection<F> {
    /// Create new tensor random projection
    ///
    /// projection_dim: Target dimension m_rp (should be << original dimension)
    /// norm_bound: Expected norm bound β for projected witness
    pub fn new(
        ring: Arc<CyclotomicRing<F>>,
        projection_dim: usize,
        norm_bound: u64,
    ) -> Self {
        assert!(projection_dim > 0, "Projection dimension must be positive");
        
        Self {
            ring,
            projection_dim,
            norm_bound,
        }
    }
    
    /// Prover projection: Create projected statement
    ///
    /// Algorithm:
    /// 1. Receive projection matrix R from verifier (via transcript)
    /// 2. Compute w_proj = R·W
    /// 3. Compute y_proj = F·w_proj
    /// 4. Create projection statement with H_rp, F_rp
    /// 5. Return both original and projected statements
    ///
    /// Complexity: O(m_rp·m·r) ring operations
    pub fn prover_project(
        &self,
        statement: &LinearStatement<F>,
        witness: &LinearWitness<F>,
        transcript: &mut Transcript,
    ) -> (LinearStatement<F>, LinearWitness<F>, RandomProjectionProof<F>) {
        let m = witness.w_matrix.rows;
        let r = witness.w_matrix.cols;
        
        // Step 1: Generate projection matrix from transcript
        let projection_matrix = self.generate_projection_matrix(m, transcript);
        
        // Step 2: Compute projected witness w_proj = R·W
        let w_proj = projection_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Step 3: Compute projected commitment y_proj = F·w_proj
        let y_proj = statement.f_matrix.mul_mat(&w_proj, &self.ring);
        
        // Step 4: Send projected commitment to transcript
        transcript.append_matrix(b"random-projection-y-proj", &y_proj);
        
        // Step 5: Create projection statement
        // Use identity for H_rp (simplest case)
        let h_proj = Matrix::identity(y_proj.rows, self.ring.degree);
        
        // F_rp is same as original F (projects in witness space, not commitment space)
        let f_proj = statement.f_matrix.clone();
        
        let projection_statement = LinearStatement {
            h_matrix: h_proj,
            f_matrix: f_proj,
            y_matrix: y_proj.clone(),
        };
        
        let projection_witness = LinearWitness {
            w_matrix: w_proj.clone(),
        };
        
        let proof = RandomProjectionProof {
            projection_matrix,
            projected_witness: w_proj,
            projected_commitment: y_proj,
        };
        
        (projection_statement, projection_witness, proof)
    }
    
    /// Verifier projection: Verify and create projected statement
    ///
    /// Algorithm:
    /// 1. Generate same projection matrix R from transcript
    /// 2. Receive y_proj from prover
    /// 3. Create projection statement
    /// 4. Verify norm bound (if witness is revealed)
    pub fn verifier_project(
        &self,
        statement: &LinearStatement<F>,
        y_proj: &Matrix<F>,
        transcript: &mut Transcript,
    ) -> LinearStatement<F> {
        // Generate projection matrix
        let m = statement.f_matrix.cols / statement.y_matrix.cols;
        let _projection_matrix = self.generate_projection_matrix(m, transcript);
        
        // Add y_proj to transcript
        transcript.append_matrix(b"random-projection-y-proj", y_proj);
        
        // Create projection statement
        let h_proj = Matrix::identity(y_proj.rows, self.ring.degree);
        let f_proj = statement.f_matrix.clone();
        
        LinearStatement {
            h_matrix: h_proj,
            f_matrix: f_proj,
            y_matrix: y_proj.clone(),
        }
    }
    
    /// Generate random projection matrix from transcript
    ///
    /// R ∈ R_q^{m_rp×m} with entries sampled from transcript
    ///
    /// Properties:
    /// - Deterministic given transcript state
    /// - Entries are pseudorandom ring elements
    /// - Satisfies leftover hash lemma for appropriate parameters
    fn generate_projection_matrix(
        &self,
        original_dim: usize,
        transcript: &mut Transcript,
    ) -> Matrix<F> {
        let m_rp = self.projection_dim;
        let m = original_dim;
        
        let mut matrix_data = Vec::with_capacity(m_rp * m);
        
        // Generate each entry from transcript
        for i in 0..m_rp {
            for j in 0..m {
                let label = format!("proj-matrix-{}-{}", i, j);
                let entry = transcript.challenge_ring(label.as_bytes(), &self.ring);
                matrix_data.push(entry);
            }
        }
        
        Matrix::from_data(m_rp, m, matrix_data)
    }
    
    /// Verify projection correctness
    ///
    /// Checks:
    /// 1. w_proj = R·W
    /// 2. y_proj = F·w_proj
    /// 3. ∥w_proj∥ ≤ β (norm bound)
    pub fn verify_projection(
        &self,
        original_statement: &LinearStatement<F>,
        original_witness: &LinearWitness<F>,
        projection_statement: &LinearStatement<F>,
        projection_witness: &LinearWitness<F>,
        proof: &RandomProjectionProof<F>,
    ) -> bool {
        // Check w_proj = R·W
        let computed_w_proj = proof.projection_matrix.mul_mat(
            &original_witness.w_matrix,
            &self.ring,
        );
        
        if !self.matrices_equal(&computed_w_proj, &projection_witness.w_matrix) {
            return false;
        }
        
        // Check y_proj = F·w_proj
        let computed_y_proj = original_statement.f_matrix.mul_mat(
            &projection_witness.w_matrix,
            &self.ring,
        );
        
        if !self.matrices_equal(&computed_y_proj, &projection_statement.y_matrix) {
            return false;
        }
        
        // Check norm bound
        self.check_norm_bound(&projection_witness.w_matrix)
    }
    
    /// Check norm bound on projected witness
    ///
    /// Verifies ∥w_proj∥_{σ,2} ≤ β for each column
    fn check_norm_bound(&self, w_proj: &Matrix<F>) -> bool {
        for col_idx in 0..w_proj.cols {
            let column = w_proj.get_col(col_idx);
            
            // Compute ∥column∥²_{σ,2} = Trace(⟨column, column̄⟩)
            let mut inner_product = self.ring.zero();
            
            for elem in &column {
                let conjugate = self.ring.conjugate(elem);
                let prod = self.ring.mul(elem, &conjugate);
                inner_product = self.ring.add(&inner_product, &prod);
            }
            
            let trace = self.ring.trace(&inner_product);
            let norm_squared = trace.to_canonical_u64();
            
            if norm_squared > self.norm_bound * self.norm_bound {
                return false;
            }
        }
        
        true
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
    
    /// Compute expected norm bound
    ///
    /// For random projection with Gaussian entries:
    /// E[∥R·W∥²] ≈ m_rp · ∥W∥²
    /// So ∥R·W∥ ≈ √m_rp · ∥W∥ with high probability
    pub fn expected_norm_bound(&self, original_norm: u64) -> u64 {
        let sqrt_m_rp = (self.projection_dim as f64).sqrt();
        (sqrt_m_rp * original_norm as f64).ceil() as u64
    }
    
    /// Estimate communication cost in bits
    ///
    /// Communication: |y_proj| = t·r·log|R_q| bits
    /// where t is number of rows in H, r is number of columns
    pub fn communication_bits(&self, t: usize, r: usize, log_ring_size: usize) -> usize {
        t * r * log_ring_size
    }
    
    /// Compute soundness error
    ///
    /// Based on leftover hash lemma:
    /// ε ≈ 2^{-(m_rp - m - λ)/2}
    /// where λ is security parameter
    pub fn soundness_error(&self, original_dim: usize, security_param: usize) -> f64 {
        if self.projection_dim <= original_dim + security_param {
            return 1.0; // Insecure parameters
        }
        
        let exponent = (self.projection_dim - original_dim - security_param) as f64 / 2.0;
        2.0_f64.powf(-exponent)
    }
    
    /// Compute compression ratio
    ///
    /// Ratio of projected dimension to original dimension
    pub fn compression_ratio(&self, original_dim: usize) -> f64 {
        self.projection_dim as f64 / original_dim as f64
    }
}
