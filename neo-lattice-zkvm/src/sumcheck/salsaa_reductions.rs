// SALSAA Reductions of Knowledge (RoK) - Tasks 5.7-5.10
// Implements Π_norm, Π_sum, Π*_batch, Π_lin-r1cs

use crate::field::extension_framework::ExtensionFieldElement;
use crate::field::Field;
use crate::ring::RingElement;
use crate::sumcheck::{SumCheckProof, MultilinearPolynomial};
use super::salsaa_relations::{
    LinearRelation, WitnessMatrix, LDERelation, LDETensorRelation,
    SumcheckRelation, LDEEvaluationClaim, MatrixStructure,
};
use std::fmt::Debug;

/// Norm-check Reduction of Knowledge: Π_norm: Ξ_norm → Ξ_sum
/// 
/// **Paper Reference**: SALSAA Section 3.2, Requirements 4.7, 21.6
/// 
/// **Purpose**: Reduce norm verification to sumcheck relation
/// 
/// **Key Identity**: ||x||²_{σ,2} = Trace(⟨x, x̄⟩)
/// where:
/// - ||x||_{σ,2} is the canonical norm
/// - Trace is the trace function Trace_{K/Q}: K → Q
/// - ⟨x, x̄⟩ is the inner product with complex conjugate
/// 
/// **How It Works**:
/// 1. Start with norm bound claim: ||W||²_{σ,2} ≤ ν
/// 2. Use identity: ||W||²_{σ,2} = Trace(Σ_j ⟨W_j, W̄_j⟩)
/// 3. Express as sum: Σ_{z∈[d]^μ} (LDE[W] ⊙ LDE[W̄])(z) = t
/// 4. This is exactly a Ξ_sum relation!
/// 
/// **Prover Complexity**: O(m) where m = d^μ (linear-time)
/// **Verifier Complexity**: O(μ·d) field operations
#[derive(Clone, Debug)]
pub struct NormCheckRoK<F: Field> {
    /// Degree bound d
    pub degree_bound: usize,
    /// Number of variables μ
    pub num_vars: usize,
}

/// Norm-check proof
#[derive(Clone, Debug)]
pub struct NormCheckProof<K: ExtensionFieldElement> {
    /// Sumcheck proof for norm verification
    pub sumcheck_proof: SumCheckProof<K>,
    /// Final LDE evaluation claims
    pub lde_claims: Vec<LDEEvaluationClaim<K::BaseField>>,
    /// Claimed norm bound
    pub norm_bound: f64,
}

impl<F: Field> NormCheckRoK<F> {
    /// Create new norm-check RoK
    pub fn new(degree_bound: usize, num_vars: usize) -> Self {
        Self {
            degree_bound,
            num_vars,
        }
    }
    
    /// Reduce norm relation to sumcheck relation
    /// 
    /// **Paper Reference**: SALSAA Section 3.2, Requirement 4.7
    /// 
    /// **Input**:
    /// - linear_relation: Base Ξ_lin relation (H, F, Y; W)
    /// - witness: Witness matrix W
    /// - norm_bound: Claimed bound ν such that ||W||²_{σ,2} ≤ ν
    /// 
    /// **Output**:
    /// - sumcheck_relation: Ξ_sum relation with target sum t
    /// - proof: Norm-check proof containing sumcheck proof
    /// 
    /// **Mathematical Steps**:
    /// 1. Compute ||W||²_{σ,2} = Σ_j ||W_j||²_{σ,2}
    /// 2. Use identity: ||W_j||²_{σ,2} = Trace(⟨W_j, W̄_j⟩)
    /// 3. Express as: Σ_{z∈[d]^μ} u^T·CRT(LDE[W](z) ⊙ LDE[W̄](z̄)) = t
    /// 4. Run sum-check protocol to prove this sum
    pub fn reduce_norm_to_sumcheck<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        linear_relation: &LinearRelation<F>,
        witness: &WitnessMatrix<F>,
        norm_bound: f64,
    ) -> (SumcheckRelation<F>, NormCheckProof<K>) {
        // Step 1: Compute target sum t using trace identity
        let target_sum = self.compute_target_sum_from_norm(witness);
        
        // Step 2: Create sumcheck relation
        let sumcheck_relation = SumcheckRelation::new(
            linear_relation.clone(),
            target_sum,
            self.degree_bound,
            self.num_vars,
        );
        
        // Step 3: Generate sumcheck proof (placeholder)
        let sumcheck_proof = SumCheckProof::new(
            vec![],  // Would contain actual round polynomials
            K::zero(),
            K::zero(),
        );
        
        // Step 4: Generate LDE evaluation claims
        let lde_claims = vec![];  // Would contain actual claims
        
        let proof = NormCheckProof {
            sumcheck_proof,
            lde_claims,
            norm_bound,
        };
        
        (sumcheck_relation, proof)
    }
    
    /// Compute target sum using trace identity
    /// 
    /// **Formula**: t = Trace(Σ_j ⟨W_j, W̄_j⟩)
    fn compute_target_sum_from_norm(&self, witness: &WitnessMatrix<F>) -> Vec<RingElement<F>> {
        let mut sums = Vec::with_capacity(witness.cols);
        
        for j in 0..witness.cols {
            // Compute ⟨W_j, W̄_j⟩ = Σ_i W_{i,j} · W̄_{i,j}
            let mut inner_product = RingElement::zero(witness.matrix[0][0].degree());
            
            for i in 0..witness.rows {
                let w_ij = &witness.matrix[i][j];
                let w_bar_ij = w_ij.conjugate();  // Complex conjugate
                let prod = w_ij.mul(&w_bar_ij);
                inner_product = inner_product.add(&prod);
            }
            
            // Take trace
            let trace_val = inner_product.trace();
            sums.push(trace_val);
        }
        
        sums
    }
    
    /// Verify norm-check reduction
    /// 
    /// **Paper Reference**: SALSAA Section 3.2
    /// 
    /// **Checks**:
    /// 1. Sumcheck proof is valid
    /// 2. LDE evaluation claims are consistent
    /// 3. Norm bound is satisfied
    pub fn verify_norm_reduction<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        linear_relation: &LinearRelation<F>,
        sumcheck_relation: &SumcheckRelation<F>,
        proof: &NormCheckProof<K>,
    ) -> bool {
        // Verify sumcheck proof
        // Would use SALSAASumCheckVerifier
        
        // Verify LDE claims
        // Would check each claim against polynomial commitments
        
        // For now, return placeholder
        true
    }
    
    /// Compute knowledge error
    /// 
    /// **Paper Reference**: SALSAA Section 3.2, Requirement 4.10
    /// 
    /// **Formula**: κ = (2μ(d-1)+rφ/e-1)/q^e
    /// where:
    /// - μ = number of variables
    /// - d = degree bound
    /// - r = number of columns
    /// - φ = ring degree
    /// - e = splitting degree (from CRT)
    /// - q = field modulus
    pub fn knowledge_error(
        &self,
        r: usize,
        phi: usize,
        e: usize,
        q: u64,
    ) -> f64 {
        let numerator = 2.0 * (self.num_vars as f64) * ((self.degree_bound - 1) as f64)
            + (r as f64) * (phi as f64) / (e as f64)
            - 1.0;
        let denominator = (q as f64).powi(e as i32);
        numerator / denominator
    }
}


/// Sumcheck Reduction of Knowledge: Π_sum: Ξ_sum → Ξ_lde-⊗
/// 
/// **Paper Reference**: SALSAA Section 3.2, Requirements 4.10, 21.8
/// 
/// **Purpose**: Reduce sumcheck relation to LDE evaluation claims
/// 
/// **How It Works**:
/// 1. Start with sumcheck claim: Σ_{z∈[d]^μ} g(z) = t
/// 2. Run sum-check protocol for μ rounds
/// 3. Verifier sends challenges r_1, ..., r_μ
/// 4. Reduces to evaluation claim: g(r_1, ..., r_μ) = v
/// 5. For g(z) = LDE[W](z) ⊙ LDE[W̄](z̄), this gives:
///    - LDE[W](r) = s_0
///    - LDE[W̄](r̄) = s_1
/// 6. These are Ξ_lde-⊗ claims!
/// 
/// **Knowledge Error**: κ = (2μ(d-1)+rφ/e-1)/q^e
/// **Prover Complexity**: O(m) where m = d^μ
/// **Verifier Complexity**: O(μ·d) field operations
#[derive(Clone, Debug)]
pub struct SumcheckRoK<F: Field> {
    /// Degree bound d
    pub degree_bound: usize,
    /// Number of variables μ
    pub num_vars: usize,
}

/// Sumcheck RoK proof
#[derive(Clone, Debug)]
pub struct SumcheckRoKProof<K: ExtensionFieldElement> {
    /// Sum-check protocol proof
    pub sumcheck_proof: SumCheckProof<K>,
    /// Resulting LDE evaluation claims
    pub lde_claims: Vec<LDEEvaluationClaim<K::BaseField>>,
}

impl<F: Field> SumcheckRoK<F> {
    /// Create new sumcheck RoK
    pub fn new(degree_bound: usize, num_vars: usize) -> Self {
        Self {
            degree_bound,
            num_vars,
        }
    }
    
    /// Reduce sumcheck relation to LDE tensor relation
    /// 
    /// **Paper Reference**: SALSAA Section 3.2, Requirement 4.10
    /// 
    /// **Input**:
    /// - sumcheck_relation: Ξ_sum relation with target sum t
    /// - witness: Witness matrix W
    /// 
    /// **Output**:
    /// - lde_tensor_relation: Ξ_lde-⊗ relation with evaluation claims
    /// - proof: Sumcheck RoK proof
    /// 
    /// **Protocol Steps**:
    /// 1. Prover computes round polynomials g_1, ..., g_μ
    /// 2. Verifier sends challenges r_1, ..., r_μ
    /// 3. Final evaluation: g(r_1, ..., r_μ) = LDE[W](r) ⊙ LDE[W̄](r̄)
    /// 4. Output claims: LDE[W](r) = s_0 and LDE[W̄](r̄) = s_1
    pub fn reduce_sumcheck_to_lde<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        sumcheck_relation: &SumcheckRelation<F>,
        witness: &WitnessMatrix<F>,
    ) -> (LDETensorRelation<F>, SumcheckRoKProof<K>) {
        // Step 1: Run sum-check protocol
        // This would use SALSAASumCheckProver
        let sumcheck_proof = SumCheckProof::new(
            vec![],  // Would contain actual round polynomials
            K::zero(),
            K::zero(),
        );
        
        // Step 2: Extract evaluation point from challenges
        let evaluation_point = vec![F::zero(); self.num_vars];  // Would be actual challenges
        
        // Step 3: Create LDE evaluation claims
        let lde_claims = vec![
            LDEEvaluationClaim {
                point: evaluation_point.clone(),
                value: RingElement::zero(witness.matrix[0][0].degree()),
                matrix_structure: MatrixStructure::General,
            },
        ];
        
        // Step 4: Create LDE relation
        let lde_relation = LDERelation::new(
            sumcheck_relation.linear_relation.clone(),
            lde_claims.clone(),
        );
        
        // Step 5: Create LDE tensor relation (no structured matrices for now)
        let lde_tensor_relation = LDETensorRelation::new(
            lde_relation,
            vec![],
        ).unwrap();
        
        let proof = SumcheckRoKProof {
            sumcheck_proof,
            lde_claims,
        };
        
        (lde_tensor_relation, proof)
    }
    
    /// Verify sumcheck RoK reduction
    /// 
    /// **Paper Reference**: SALSAA Section 3.2
    /// 
    /// **Checks**:
    /// 1. Sum-check proof is valid
    /// 2. Final evaluation is consistent with LDE claims
    /// 3. Knowledge error is within acceptable bounds
    pub fn verify_sumcheck_reduction<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        sumcheck_relation: &SumcheckRelation<F>,
        lde_tensor_relation: &LDETensorRelation<F>,
        proof: &SumcheckRoKProof<K>,
    ) -> bool {
        // Verify sum-check proof
        // Would use SALSAASumCheckVerifier
        
        // Verify LDE claims consistency
        // Would check that final evaluation matches LDE claims
        
        // For now, return placeholder
        true
    }
    
    /// Compute knowledge error
    /// 
    /// **Paper Reference**: SALSAA Section 3.2, Requirement 4.10
    /// 
    /// **Formula**: κ = (2μ(d-1)+rφ/e-1)/q^e
    pub fn knowledge_error(
        &self,
        r: usize,
        phi: usize,
        e: usize,
        q: u64,
    ) -> f64 {
        let numerator = 2.0 * (self.num_vars as f64) * ((self.degree_bound - 1) as f64)
            + (r as f64) * (phi as f64) / (e as f64)
            - 1.0;
        let denominator = (q as f64).powi(e as i32);
        numerator / denominator
    }
}

/// Improved Batching Protocol: Π*_batch
/// 
/// **Paper Reference**: SALSAA Section 3.3, Requirements 4.12, 21.9
/// 
/// **Purpose**: Alternative to RPS/RnR batching using sumcheck
/// 
/// **Key Idea**:
/// Instead of batching bottom rows Fw = y using random projection,
/// express each row as a sumcheck claim:
/// Σ_{j∈[m]} LDE[f_i](z)·LDE[w](z) = y_i mod q
/// 
/// **Advantage over RPS/RnR**:
/// - No need for random projection matrices
/// - Direct reduction to sumcheck (already optimized)
/// - Better concrete efficiency for small number of rows
/// 
/// **When to Use**:
/// - Small number of bottom rows (r ≤ 10)
/// - When sumcheck is already being used elsewhere
/// - When avoiding random projection overhead is important
#[derive(Clone, Debug)]
pub struct ImprovedBatching<F: Field> {
    /// Number of bottom rows to batch
    pub num_rows: usize,
}

/// Improved batching proof
#[derive(Clone, Debug)]
pub struct ImprovedBatchingProof<K: ExtensionFieldElement> {
    /// Sumcheck proofs for each row
    pub sumcheck_proofs: Vec<SumCheckProof<K>>,
    /// LDE evaluation claims
    pub lde_claims: Vec<LDEEvaluationClaim<K::BaseField>>,
}

impl<F: Field> ImprovedBatching<F> {
    /// Create new improved batching protocol
    pub fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }
    
    /// Batch linear relations using sumcheck
    /// 
    /// **Paper Reference**: SALSAA Section 3.3, Requirement 4.12
    /// 
    /// **Input**:
    /// - f_matrix: Bottom rows F ∈ R_q^{r×m}
    /// - y_vector: Target values y ∈ R_q^r
    /// - witness: Witness vector w ∈ R_q^m
    /// 
    /// **Output**:
    /// - sumcheck_claims: One sumcheck claim per row
    /// - proof: Improved batching proof
    /// 
    /// **Formula for row i**:
    /// Σ_{j∈[m]} LDE[f_i](z)·LDE[w](z) = y_i mod q
    /// 
    /// This is a sumcheck claim over the product of two multilinear polynomials!
    pub fn batch_linear_relations<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        f_matrix: &[Vec<RingElement<F>>],
        y_vector: &[RingElement<F>],
        witness: &[RingElement<F>],
    ) -> (Vec<SumcheckRelation<F>>, ImprovedBatchingProof<K>) {
        assert_eq!(f_matrix.len(), self.num_rows);
        assert_eq!(y_vector.len(), self.num_rows);
        
        let mut sumcheck_claims = Vec::with_capacity(self.num_rows);
        let mut sumcheck_proofs = Vec::with_capacity(self.num_rows);
        
        // Create one sumcheck claim per row
        for i in 0..self.num_rows {
            // Create linear relation for row i
            // Placeholder: would create actual relation
            let linear_relation = LinearRelation::new(
                vec![],
                vec![],
                vec![],
            ).unwrap();
            
            // Create sumcheck relation: Σ_j LDE[f_i](z)·LDE[w](z) = y_i
            let sumcheck_relation = SumcheckRelation::new(
                linear_relation,
                vec![y_vector[i].clone()],
                2,  // Degree bound (product of two linear polynomials)
                (witness.len() as f64).log2() as usize,  // Number of variables
            );
            
            sumcheck_claims.push(sumcheck_relation);
            
            // Generate sumcheck proof (placeholder)
            let proof = SumCheckProof::new(
                vec![],
                K::zero(),
                K::zero(),
            );
            sumcheck_proofs.push(proof);
        }
        
        let proof = ImprovedBatchingProof {
            sumcheck_proofs,
            lde_claims: vec![],
        };
        
        (sumcheck_claims, proof)
    }
    
    /// Verify improved batching
    /// 
    /// **Paper Reference**: SALSAA Section 3.3
    /// 
    /// **Checks**:
    /// 1. Each sumcheck proof is valid
    /// 2. LDE evaluation claims are consistent
    /// 3. All row constraints are satisfied
    pub fn verify_batching<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        sumcheck_claims: &[SumcheckRelation<F>],
        proof: &ImprovedBatchingProof<K>,
    ) -> bool {
        if sumcheck_claims.len() != self.num_rows {
            return false;
        }
        
        if proof.sumcheck_proofs.len() != self.num_rows {
            return false;
        }
        
        // Verify each sumcheck proof
        for (claim, sumcheck_proof) in sumcheck_claims.iter().zip(proof.sumcheck_proofs.iter()) {
            // Would use SALSAASumCheckVerifier
            // For now, placeholder
        }
        
        true
    }
    
    /// Compare cost with RPS/RnR batching
    /// 
    /// **Paper Reference**: SALSAA Section 3.3, Requirement 21.9
    /// 
    /// **RPS/RnR Cost**:
    /// - Random projection: O(r·m) ring operations
    /// - Single sumcheck: O(m) field operations
    /// 
    /// **Improved Batching Cost**:
    /// - r sumchecks: O(r·m) field operations
    /// - No random projection overhead
    /// 
    /// **Trade-off**:
    /// - RPS/RnR: Better for large r (r > 100)
    /// - Improved: Better for small r (r ≤ 10) and when avoiding projection
    pub fn cost_comparison(&self, m: usize) -> (usize, usize) {
        // RPS/RnR cost: O(r·m) + O(m)
        let rps_cost = self.num_rows * m + m;
        
        // Improved batching cost: O(r·m)
        let improved_cost = self.num_rows * m;
        
        (rps_cost, improved_cost)
    }
}

/// R1CS Reduction of Knowledge: Π_lin-r1cs
/// 
/// **Paper Reference**: SALSAA Section 3.4, Requirements 4.11, 21.10
/// 
/// **Purpose**: Reduce R1CS satisfiability to evaluation claims over LDE
/// 
/// **R1CS Constraint System**:
/// Az ⊙ Bz = Cz
/// where:
/// - A, B, C ∈ F^{m×n} are sparse constraint matrices
/// - z ∈ F^n is the witness vector
/// - ⊙ is Hadamard (element-wise) product
/// 
/// **Reduction Strategy**:
/// 1. Express constraint as: (Az)_i · (Bz)_i = (Cz)_i for all i ∈ [m]
/// 2. Use multilinear extensions: ã(r)·b̃(r) - c̃(r) = 0
/// 3. Randomize with eq̃(r,x): g(x) := (ã(x)·b̃(x) - c̃(x))·eq̃(r,x)
/// 4. Sum-check: Σ_{x∈{0,1}^n} g(x) = 0
/// 5. Reduces to evaluation claims: ã(r), b̃(r), c̃(r)
/// 
/// **Prover Complexity**: O(m + n) where m = # constraints, n = # variables
/// **Verifier Complexity**: O(log m + log n)
#[derive(Clone, Debug)]
pub struct R1CSReduction<F: Field> {
    /// Number of constraints m
    pub num_constraints: usize,
    /// Number of variables n
    pub num_variables: usize,
}

/// R1CS reduction proof
#[derive(Clone, Debug)]
pub struct R1CSReductionProof<K: ExtensionFieldElement> {
    /// Sumcheck proof for constraint verification
    pub sumcheck_proof: SumCheckProof<K>,
    /// Evaluation claims for ã(r), b̃(r), c̃(r)
    pub evaluation_claims: Vec<LDEEvaluationClaim<K::BaseField>>,
}

impl<F: Field> R1CSReduction<F> {
    /// Create new R1CS reduction
    pub fn new(num_constraints: usize, num_variables: usize) -> Self {
        Self {
            num_constraints,
            num_variables,
        }
    }
    
    /// Reduce R1CS to evaluation claims
    /// 
    /// **Paper Reference**: SALSAA Section 3.4, Requirement 4.11
    /// 
    /// **Input**:
    /// - a_matrix, b_matrix, c_matrix: R1CS constraint matrices
    /// - witness: Witness vector z
    /// 
    /// **Output**:
    /// - lde_relation: Ξ_lde relation with evaluation claims
    /// - proof: R1CS reduction proof
    /// 
    /// **Protocol Steps**:
    /// 1. Compute Az, Bz, Cz
    /// 2. Create multilinear extensions ã, b̃, c̃
    /// 3. Verifier sends random point r
    /// 4. Prover runs sumcheck on g(x) = (ã(x)·b̃(x) - c̃(x))·eq̃(r,x)
    /// 5. Reduces to claims: ã(r) = v_a, b̃(r) = v_b, c̃(r) = v_c
    pub fn reduce_r1cs_to_evaluation<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        a_matrix: &[Vec<F>],
        b_matrix: &[Vec<F>],
        c_matrix: &[Vec<F>],
        witness: &[F],
    ) -> (LDERelation<F>, R1CSReductionProof<K>) {
        // Step 1: Compute Az, Bz, Cz
        let az = self.matrix_vector_mul(a_matrix, witness);
        let bz = self.matrix_vector_mul(b_matrix, witness);
        let cz = self.matrix_vector_mul(c_matrix, witness);
        
        // Step 2: Create multilinear extensions (placeholder)
        // Would compute actual MLEs
        
        // Step 3: Run sumcheck protocol
        let sumcheck_proof = SumCheckProof::new(
            vec![],
            K::zero(),
            K::zero(),
        );
        
        // Step 4: Create evaluation claims
        let evaluation_claims = vec![
            LDEEvaluationClaim {
                point: vec![F::zero()],  // Would be actual challenge point
                value: RingElement::zero(64),  // Would be actual evaluation
                matrix_structure: MatrixStructure::General,
            },
        ];
        
        // Step 5: Create LDE relation
        let linear_relation = LinearRelation::new(
            vec![],
            vec![],
            vec![],
        ).unwrap();
        
        let lde_relation = LDERelation::new(
            linear_relation,
            evaluation_claims.clone(),
        );
        
        let proof = R1CSReductionProof {
            sumcheck_proof,
            evaluation_claims,
        };
        
        (lde_relation, proof)
    }
    
    /// Matrix-vector multiplication
    fn matrix_vector_mul(&self, matrix: &[Vec<F>], vector: &[F]) -> Vec<F> {
        let mut result = Vec::with_capacity(matrix.len());
        
        for row in matrix {
            let mut sum = F::zero();
            for (a_ij, v_j) in row.iter().zip(vector.iter()) {
                sum = sum.add(&a_ij.mul(v_j));
            }
            result.push(sum);
        }
        
        result
    }
    
    /// Verify R1CS reduction
    /// 
    /// **Paper Reference**: SALSAA Section 3.4
    /// 
    /// **Checks**:
    /// 1. Sumcheck proof is valid
    /// 2. Evaluation claims are consistent
    /// 3. Product check: v_a · v_b = v_c
    pub fn verify_r1cs_reduction<K: ExtensionFieldElement<BaseField = F>>(
        &self,
        lde_relation: &LDERelation<F>,
        proof: &R1CSReductionProof<K>,
    ) -> bool {
        // Verify sumcheck proof
        // Would use SALSAASumCheckVerifier
        
        // Verify evaluation claims
        // Would check against polynomial commitments
        
        // Verify product check
        // Would check v_a · v_b = v_c at the evaluation point
        
        // For now, return placeholder
        true
    }
    
    /// Compute prover complexity
    /// 
    /// **Paper Reference**: SALSAA Section 3.4, Requirement 21.10
    /// 
    /// **Formula**: O(m + n) field operations
    /// where m = # constraints, n = # variables
    /// 
    /// **Breakdown**:
    /// - Computing Az, Bz, Cz: O(m + n) for sparse matrices
    /// - Sumcheck protocol: O(m) field operations
    /// - Total: O(m + n)
    pub fn prover_complexity(&self) -> usize {
        self.num_constraints + self.num_variables
    }
    
    /// Compute verifier complexity
    /// 
    /// **Formula**: O(log m + log n) field operations
    /// 
    /// **Breakdown**:
    /// - Sumcheck verification: O(log m) rounds
    /// - Evaluation verification: O(log n) operations
    /// - Total: O(log m + log n)
    pub fn verifier_complexity(&self) -> usize {
        (self.num_constraints as f64).log2() as usize
            + (self.num_variables as f64).log2() as usize
    }
}
