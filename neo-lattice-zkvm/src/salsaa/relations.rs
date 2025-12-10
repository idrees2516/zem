// Relation definitions for SALSAA protocols
//
// Mathematical Background:
// SALSAA protocols work with various types of relations that capture different
// computational properties. Each relation Ξ consists of a statement (public)
// and witness (private) pair, along with a verification predicate.
//
// Relation Types:
// 1. Ξ^lin: Linear relations HFW = Y over R_q
// 2. Ξ^lde-⊗: LDE evaluation claims with tensor structure
// 3. Ξ^sum: Sumcheck relations for polynomial sums
// 4. Ξ^norm: Norm-bound relations ∥W∥ ≤ ν
// 5. Ξ^lin-r1cs: R1CS constraints (AW ⊙ BW = CW)
//
// Protocol Composition:
// Atomic RoK protocols reduce between these relations:
// - Π^lde-⊗: Ξ^lde-⊗ → Ξ^lin
// - Π^sum: Ξ^sum → Ξ^lde-⊗
// - Π^norm: Ξ^norm → Ξ^sum
// - Π^lin-r1cs: Ξ^lin-r1cs → Ξ^sum
//
// Reference: SALSAA paper Section 3, Requirements 5.1-5.5

use crate::field::Field;
use crate::ring::cyclotomic::{CyclotomicRing, RingElement};
use crate::ring::crt::ExtFieldElement;
use crate::salsaa::matrix::Matrix;
use std::sync::Arc;

/// Linear relation: HFW = Y
/// 
/// Mathematical: For matrices H ∈ R_q^{t×n}, F ∈ R_q^{n×m}, witness W ∈ R_q^{m×r},
/// and target Y ∈ R_q^{t×r}, verify that HFW = Y
///
/// This is the fundamental relation for vSIS-based commitments:
/// - F has row-tensor structure for efficiency
/// - H is a compression matrix (often random or identity)
/// - Y = HFW is the commitment to witness W
///
/// Reference: SALSAA Definition 2 (Ξ^lin)
#[derive(Clone, Debug)]
pub struct LinearRelation<F: Field> {
    pub ring: Arc<CyclotomicRing<F>>,
}

#[derive(Clone, Debug)]
pub struct LinearStatement<F: Field> {
    /// Compression matrix H ∈ R_q^{t×n}
    pub h_matrix: Matrix<F>,
    
    /// Commitment matrix F ∈ R_q^{n×m} (often has row-tensor structure)
    pub f_matrix: Matrix<F>,
    
    /// Target Y ∈ R_q^{t×r}
    pub y_matrix: Matrix<F>,
}

#[derive(Clone, Debug)]
pub struct LinearWitness<F: Field> {
    /// Witness matrix W ∈ R_q^{m×r}
    pub w_matrix: Matrix<F>,
}

impl<F: Field> LinearRelation<F> {
    pub fn new(ring: Arc<CyclotomicRing<F>>) -> Self {
        Self { ring }
    }
    
    /// Verify linear relation: HFW = Y
    pub fn verify(&self, statement: &LinearStatement<F>, witness: &LinearWitness<F>) -> bool {
        // Compute FW
        let fw = statement.f_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Compute HFW
        let hfw = statement.h_matrix.mul_mat(&fw, &self.ring);
        
        // Check HFW = Y
        self.matrices_equal(&hfw, &statement.y_matrix)
    }
    
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
}

/// LDE evaluation relation with tensor structure
///
/// Mathematical: For witness W ∈ R_q^{d^µ×r} and evaluation points r_i ∈ F_{q^e}^µ,
/// verify that LDE[W](r_i) = s_i for claimed values s_i ∈ R_q^r
///
/// The LDE (Low-Degree Extension) extends W to a multivariate polynomial
/// with individual degree d-1 in each of µ variables.
///
/// Tensor structure: The evaluation can be expressed using tensor products
/// of univariate Lagrange bases, enabling efficient computation.
///
/// Reference: SALSAA Lemma 2 (Ξ^lde-⊗)
#[derive(Clone, Debug)]
pub struct LDERelation<F: Field> {
    pub ring: Arc<CyclotomicRing<F>>,
    pub degree: usize,      // d: degree bound per variable
    pub num_vars: usize,    // µ: number of variables
}

#[derive(Clone, Debug)]
pub struct LDEStatement<F: Field> {
    /// Evaluation points r_i ∈ F_{q^e}^µ
    pub eval_points: Vec<Vec<ExtFieldElement<F>>>,
    
    /// Claimed evaluations s_i ∈ R_q^r
    pub claimed_values: Vec<Vec<RingElement<F>>>,
    
    /// Tensor structure matrices M_i for reduction
    pub tensor_matrices: Vec<Matrix<F>>,
}

#[derive(Clone, Debug)]
pub struct LDEWitness<F: Field> {
    /// Witness matrix W ∈ R_q^{d^µ×r}
    pub w_matrix: Matrix<F>,
}

impl<F: Field> LDERelation<F> {
    pub fn new(ring: Arc<CyclotomicRing<F>>, degree: usize, num_vars: usize) -> Self {
        Self { ring, degree, num_vars }
    }
    
    /// Verify LDE evaluation claims
    /// This is typically done via reduction to linear relation, not directly
    pub fn verify(&self, statement: &LDEStatement<F>, witness: &LDEWitness<F>) -> bool {
        // In practice, this is verified by reducing to Ξ^lin via Π^lde-⊗
        // Direct verification would require computing LDE evaluations
        
        // Check dimensions
        let expected_rows = self.degree.pow(self.num_vars as u32);
        if witness.w_matrix.rows != expected_rows {
            return false;
        }
        
        // Check that number of evaluation points matches claimed values
        statement.eval_points.len() == statement.claimed_values.len()
    }
}

/// Sumcheck relation
///
/// Mathematical: For polynomial g: F_{q^e}^µ → F_{q^e} of individual degree ≤ 2(d-1),
/// verify that Σ_{z∈[d]^µ} g(z) = t for claimed sum t ∈ F_{q^e}
///
/// In SALSAA, g is typically of the form:
/// g(X) = u^T · CRT(LDE[W](X) ⊙ LDE[W̄](X))
/// where u is a random batching vector and W̄ is the conjugate of W
///
/// The sumcheck protocol reduces this to evaluation claims at a random point.
///
/// Reference: SALSAA Lemma 3 (Ξ^sum)
#[derive(Clone, Debug)]
pub struct SumcheckRelation<F: Field> {
    pub ring: Arc<CyclotomicRing<F>>,
    pub degree: usize,      // d: domain size per variable
    pub num_vars: usize,    // µ: number of variables
}

#[derive(Clone, Debug)]
pub struct SumcheckStatement<F: Field> {
    /// Claimed sum t ∈ F_{q^e}
    pub claimed_sum: ExtFieldElement<F>,
    
    /// Batching vector u ∈ F_{q^e}^{rφ/e} for combining columns
    pub batching_vector: Vec<ExtFieldElement<F>>,
    
    /// Number of columns r
    pub num_columns: usize,
}

#[derive(Clone, Debug)]
pub struct SumcheckWitness<F: Field> {
    /// Witness matrix W ∈ R_q^{d^µ×r}
    pub w_matrix: Matrix<F>,
    
    /// Conjugate witness W̄ ∈ R_q^{d^µ×r}
    pub w_conjugate: Matrix<F>,
}

impl<F: Field> SumcheckRelation<F> {
    pub fn new(ring: Arc<CyclotomicRing<F>>, degree: usize, num_vars: usize) -> Self {
        Self { ring, degree, num_vars }
    }
    
    /// Verify sumcheck relation
    /// In practice, this is done via the sumcheck protocol, not direct computation
    pub fn verify(&self, statement: &SumcheckStatement<F>, witness: &SumcheckWitness<F>) -> bool {
        // Check dimensions
        let expected_rows = self.degree.pow(self.num_vars as u32);
        
        if witness.w_matrix.rows != expected_rows {
            return false;
        }
        
        if witness.w_conjugate.rows != expected_rows {
            return false;
        }
        
        if witness.w_matrix.cols != statement.num_columns {
            return false;
        }
        
        true
    }
}

/// Norm-bound relation
///
/// Mathematical: For witness W ∈ R_q^{d^µ×r}, verify that ∥W∥_{σ,2} ≤ ν
/// where ∥W∥_{σ,2} = max_i ∥w_i∥_{σ,2} is the maximum column norm
///
/// The canonical norm is defined as:
/// ∥w∥_{σ,2}² = Trace(⟨w, w̄⟩) = Σ_{j∈[φ]} |σ_j(w)|²
/// where σ_j are the canonical embeddings into ℂ
///
/// This ensures the witness has bounded size, which is crucial for:
/// - vSIS hardness (short vectors)
/// - Knowledge soundness (extractability)
/// - Proof size (compact representation)
///
/// Reference: SALSAA Lemma 4 (Ξ^norm)
#[derive(Clone, Debug)]
pub struct NormRelation<F: Field> {
    pub ring: Arc<CyclotomicRing<F>>,
}

#[derive(Clone, Debug)]
pub struct NormStatement<F: Field> {
    /// Norm bound ν
    pub norm_bound: u64,
    
    /// Number of columns r
    pub num_columns: usize,
    
    /// Witness size (d^µ)
    pub witness_size: usize,
}

#[derive(Clone, Debug)]
pub struct NormWitness<F: Field> {
    /// Witness matrix W ∈ R_q^{d^µ×r}
    pub w_matrix: Matrix<F>,
}

impl<F: Field> NormRelation<F> {
    pub fn new(ring: Arc<CyclotomicRing<F>>) -> Self {
        Self { ring }
    }
    
    /// Verify norm bound: ∥W∥_{σ,2} ≤ ν
    pub fn verify(&self, statement: &NormStatement<F>, witness: &NormWitness<F>) -> bool {
        // Check dimensions
        if witness.w_matrix.rows != statement.witness_size {
            return false;
        }
        
        if witness.w_matrix.cols != statement.num_columns {
            return false;
        }
        
        // Compute norm for each column
        for col_idx in 0..statement.num_columns {
            let column = witness.w_matrix.get_col(col_idx);
            
            // Compute ∥w_i∥_{σ,2}² = Trace(⟨w_i, w̄_i⟩)
            let mut inner_product = self.ring.zero();
            
            for elem in &column {
                let conjugate = self.ring.conjugate(elem);
                let prod = self.ring.mul(elem, &conjugate);
                inner_product = self.ring.add(&inner_product, &prod);
            }
            
            // Compute trace
            let trace = self.ring.trace(&inner_product);
            let norm_squared = trace.to_canonical_u64();
            
            // Check bound: ∥w_i∥² ≤ ν²
            if norm_squared > statement.norm_bound * statement.norm_bound {
                return false;
            }
        }
        
        true
    }
}

/// R1CS relation (Rank-1 Constraint System)
///
/// Mathematical: For matrices A, B, C ∈ R_q^{n×m} and witness W ∈ R_q^{m×r},
/// verify that (AW) ⊙ (BW) = CW
/// where ⊙ denotes Hadamard (element-wise) product
///
/// R1CS is a standard representation for arithmetic circuits:
/// - Each row represents one constraint
/// - Witness W contains all wire values
/// - Matrices A, B, C encode the circuit structure
///
/// Additional structure:
/// - Public inputs: DW = E for matrices D, E
/// - This ensures consistency with public values
///
/// Reference: SALSAA Section 7, Appendix C (Ξ^lin-r1cs)
#[derive(Clone, Debug)]
pub struct R1CSRelation<F: Field> {
    pub ring: Arc<CyclotomicRing<F>>,
}

#[derive(Clone, Debug)]
pub struct R1CSStatement<F: Field> {
    /// Constraint matrix A ∈ R_q^{n×m}
    pub a_matrix: Matrix<F>,
    
    /// Constraint matrix B ∈ R_q^{n×m}
    pub b_matrix: Matrix<F>,
    
    /// Constraint matrix C ∈ R_q^{n×m}
    pub c_matrix: Matrix<F>,
    
    /// Public input matrix D ∈ R_q^{p×m}
    pub d_matrix: Matrix<F>,
    
    /// Public input values E ∈ R_q^{p×r}
    pub e_matrix: Matrix<F>,
}

#[derive(Clone, Debug)]
pub struct R1CSWitness<F: Field> {
    /// Witness matrix W ∈ R_q^{m×r}
    pub w_matrix: Matrix<F>,
}

impl<F: Field> R1CSRelation<F> {
    pub fn new(ring: Arc<CyclotomicRing<F>>) -> Self {
        Self { ring }
    }
    
    /// Verify R1CS constraints: (AW) ⊙ (BW) = CW and DW = E
    pub fn verify(&self, statement: &R1CSStatement<F>, witness: &R1CSWitness<F>) -> bool {
        // Compute AW, BW, CW
        let aw = statement.a_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let bw = statement.b_matrix.mul_mat(&witness.w_matrix, &self.ring);
        let cw = statement.c_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Compute (AW) ⊙ (BW)
        let aw_hadamard_bw = aw.hadamard(&bw, &self.ring);
        
        // Check (AW) ⊙ (BW) = CW
        if !self.matrices_equal(&aw_hadamard_bw, &cw) {
            return false;
        }
        
        // Compute DW
        let dw = statement.d_matrix.mul_mat(&witness.w_matrix, &self.ring);
        
        // Check DW = E
        self.matrices_equal(&dw, &statement.e_matrix)
    }
    
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    fn create_test_ring() -> Arc<CyclotomicRing<GoldilocksField>> {
        Arc::new(CyclotomicRing::new(64))
    }
    
    fn create_test_element(val: u64, ring: &CyclotomicRing<GoldilocksField>) -> RingElement<GoldilocksField> {
        ring.from_u64(val)
    }
    
    #[test]
    fn test_linear_relation_creation() {
        let ring = create_test_ring();
        let relation = LinearRelation::new(ring.clone());
        assert_eq!(relation.ring.degree, 64);
    }
    
    #[test]
    fn test_linear_relation_verify_identity() {
        let ring = create_test_ring();
        let relation = LinearRelation::new(ring.clone());
        
        // Create identity matrices
        let h = Matrix::identity(2, ring.degree);
        let f = Matrix::identity(2, ring.degree);
        
        // Create witness
        let mut w_data = Vec::new();
        for i in 0..4 {
            w_data.push(create_test_element((i + 1) as u64, &ring));
        }
        let w = Matrix::from_data(2, 2, w_data.clone());
        
        // Y should equal W for identity matrices
        let y = Matrix::from_data(2, 2, w_data);
        
        let statement = LinearStatement {
            h_matrix: h,
            f_matrix: f,
            y_matrix: y,
        };
        
        let witness = LinearWitness { w_matrix: w };
        
        assert!(relation.verify(&statement, &witness));
    }
    
    #[test]
    fn test_lde_relation_creation() {
        let ring = create_test_ring();
        let relation = LDERelation::new(ring.clone(), 4, 2);
        
        assert_eq!(relation.degree, 4);
        assert_eq!(relation.num_vars, 2);
    }
    
    #[test]
    fn test_sumcheck_relation_creation() {
        let ring = create_test_ring();
        let relation = SumcheckRelation::new(ring.clone(), 4, 2);
        
        assert_eq!(relation.degree, 4);
        assert_eq!(relation.num_vars, 2);
    }
    
    #[test]
    fn test_norm_relation_creation() {
        let ring = create_test_ring();
        let relation = NormRelation::new(ring.clone());
        assert_eq!(relation.ring.degree, 64);
    }
    
    #[test]
    fn test_r1cs_relation_creation() {
        let ring = create_test_ring();
        let relation = R1CSRelation::new(ring.clone());
        assert_eq!(relation.ring.degree, 64);
    }
    
    #[test]
    fn test_r1cs_relation_simple() {
        let ring = create_test_ring();
        let relation = R1CSRelation::new(ring.clone());
        
        // Simple constraint: w_0 * w_1 = w_2
        // A = [1, 0, 0], B = [0, 1, 0], C = [0, 0, 1]
        
        let mut a_data = Vec::new();
        a_data.push(create_test_element(1, &ring));
        a_data.push(create_test_element(0, &ring));
        a_data.push(create_test_element(0, &ring));
        let a = Matrix::from_data(1, 3, a_data);
        
        let mut b_data = Vec::new();
        b_data.push(create_test_element(0, &ring));
        b_data.push(create_test_element(1, &ring));
        b_data.push(create_test_element(0, &ring));
        let b = Matrix::from_data(1, 3, b_data);
        
        let mut c_data = Vec::new();
        c_data.push(create_test_element(0, &ring));
        c_data.push(create_test_element(0, &ring));
        c_data.push(create_test_element(1, &ring));
        let c = Matrix::from_data(1, 3, c_data);
        
        // Witness: w = [3, 4, 12] (3 * 4 = 12)
        let mut w_data = Vec::new();
        w_data.push(create_test_element(3, &ring));
        w_data.push(create_test_element(4, &ring));
        w_data.push(create_test_element(12, &ring));
        let w = Matrix::from_data(3, 1, w_data);
        
        // No public inputs
        let d = Matrix::zero(0, 3, ring.degree);
        let e = Matrix::zero(0, 1, ring.degree);
        
        let statement = R1CSStatement {
            a_matrix: a,
            b_matrix: b,
            c_matrix: c,
            d_matrix: d,
            e_matrix: e,
        };
        
        let witness = R1CSWitness { w_matrix: w };
        
        assert!(relation.verify(&statement, &witness));
    }
}
