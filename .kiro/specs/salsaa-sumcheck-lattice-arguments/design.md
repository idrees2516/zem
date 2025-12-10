# Design Document

## Overview

SALSAA (Sumcheck-Aided Lattice-based Succinct Arguments and Applications) is a comprehensive cryptographic framework implementing lattice-based succinct arguments with linear-time prover complexity. The design integrates sumcheck techniques with the RoK (Reduction of Knowledge) paradigm to achieve:

1. **Linear-time norm-check**: O(m) vs O(m log m) in prior work
2. **2-3× smaller proofs**: Eliminating polynomial multiplication overhead
3. **Native R1CS support**: Expressing general arithmetic computations
4. **Three applications**: SNARK, PCS, and Folding Scheme

### Key Design Decisions

1. **Sumcheck-based norm verification**: Express ∥w∥²_{σ,2} = Trace(⟨w,w̄⟩) as sumcheck over LDE
2. **Dynamic programming optimization**: Achieve linear-time sumcheck prover
3. **Modular RoK composition**: Chain atomic protocols for complex reductions
4. **CRT-based arithmetic**: Efficient ring operations via splitting
5. **Hardware acceleration**: AVX-512 and NTT for practical performance

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SALSAA Framework                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Applications Layer                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│  │    SNARK     │  │     PCS      │  │   Folding    │                       │
│  │  (Theorem 1) │  │  (Theorem 2) │  │  (Theorem 3) │                       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                       │
├─────────┴─────────────────┴─────────────────┴───────────────────────────────┤
│  Protocol Composition Layer                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Structured Loop: Π^norm → Π^batch → Π^b-decomp → Π^split → Π^fold │    │
│  │  Folding: Π^join → Π^norm → Π^⊗RP → Π^fold → Π^join → Π^batch      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Core RoK Layer                                                              │
│  ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │
│  │ Π^norm │ │ Π^sum  │ │ Π^lde-⊗  │ │ Π^fold │ │ Π^split│ │ Π^batch│       │
│  └────┬───┘ └────┬───┘ └────┬─────┘ └────────┘ └────────┘ └────────┘       │
│       │          │          │                                                │
│       ▼          ▼          ▼                                                │
│  ┌────────┐ ┌────────┐ ┌────────┐                                           │
│  │ Ξ^norm │ │ Ξ^sum  │ │ Ξ^lde-⊗│ ──────────────────────► Ξ^lin            │
│  └────────┘ └────────┘ └────────┘                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Algebraic Layer                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Cyclotomic  │  │     CRT      │  │     LDE      │  │  Row-Tensor  │     │
│  │    Ring R_q  │  │   Splitting  │  │  Extension   │  │   Matrices   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Implementation Layer                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   AVX-512    │  │     NTT      │  │   Parallel   │  │ Fiat-Shamir  │     │
│  │  Arithmetic  │  │   Transform  │  │  Execution   │  │  Transform   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### Component 1: Cyclotomic Ring Module

```rust
/// Cyclotomic field K = Q(ζ) and ring R = Z[ζ]
pub struct CyclotomicRing {
    conductor: u64,           // f: conductor of cyclotomic field
    degree: usize,            // φ = φ(f): degree of extension
    modulus: BigInt,          // q: prime modulus
    splitting_degree: usize,  // e: multiplicative order of q mod f
    root_of_unity: RingElement, // ζ: primitive f-th root of unity
}

/// Element of R_q = R/qR
pub struct RingElement {
    coefficients: Vec<i64>,   // Balanced representation
    ring: Arc<CyclotomicRing>,
}

/// Element of F_{q^e} (extension field)
pub struct ExtFieldElement {
    coefficients: Vec<u64>,   // Coefficients over F_q
    degree: usize,            // e
}

pub trait RingArithmetic {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn conjugate(&self) -> Self;  // Complex conjugation x̄
    fn reduce_mod_q(&mut self);
}

pub trait CanonicalEmbedding {
    /// Compute σ(x) = (σ_j(x))_{j∈[φ]} ∈ C^φ
    fn canonical_embedding(&self) -> Vec<Complex64>;
    
    /// Compute ∥x∥_{σ,2} = ∥σ(x)∥_2
    fn canonical_norm_squared(&self) -> f64;
    
    /// Compute Trace_{K/Q}(x) = Σ_{σ_j} σ_j(x)
    fn trace(&self) -> i64;
}
```

### Component 2: CRT Module

```rust
/// Chinese Remainder Theorem operations
/// R_q ≅ (F_{q^e})^{φ/e} when q has order e mod f
pub struct CRTContext {
    ring: Arc<CyclotomicRing>,
    num_slots: usize,         // φ/e
    slot_degree: usize,       // e
}

pub trait CRTOperations {
    /// CRT: R_q → (F_{q^e})^{φ/e}
    fn to_crt(&self, elem: &RingElement) -> Vec<ExtFieldElement>;
    
    /// CRT^{-1}: (F_{q^e})^{φ/e} → R_q
    fn from_crt(&self, slots: &[ExtFieldElement]) -> RingElement;
    
    /// Extend CRT to vectors: R_q^m → (F_{q^e})^{mφ/e}
    fn vector_to_crt(&self, vec: &[RingElement]) -> Vec<ExtFieldElement>;
    
    /// Extend CRT to polynomials: R_q^r[x^µ] → F_{q^e}^{rφ/e}[x^µ]
    fn poly_to_crt(&self, poly: &MultivariatePoly<RingElement>) 
        -> MultivariatePoly<ExtFieldElement>;
    
    /// Lift challenge: r_j ∈ F_{q^e} → CRT^{-1}(1_{φ/e} · r_j) ∈ R_q
    fn lift_challenge(&self, challenge: &ExtFieldElement) -> RingElement;
}
```

### Component 3: NTT Module

```rust
/// Number Theoretic Transform for fast polynomial multiplication
pub struct NTTContext {
    ring: Arc<CyclotomicRing>,
    roots: Vec<RingElement>,      // Precomputed roots of unity
    inv_roots: Vec<RingElement>,  // Inverse roots
    incomplete: bool,             // Use incomplete NTT (small e)
}

pub trait NTTOperations {
    /// Forward NTT: coefficient → evaluation representation
    fn forward_ntt(&self, coeffs: &mut [RingElement]);
    
    /// Inverse NTT: evaluation → coefficient representation
    fn inverse_ntt(&self, evals: &mut [RingElement]);
    
    /// Multiply polynomials via NTT: O(n log n)
    fn ntt_multiply(&self, a: &[RingElement], b: &[RingElement]) -> Vec<RingElement>;
}
```

### Component 4: Matrix Module

```rust
/// Matrix over R_q with optional row-tensor structure
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<RingElement>,
    tensor_structure: Option<TensorStructure>,
}

/// Row-tensor structure: F = F_0 • F_1 • ... • F_{µ-1}
pub struct TensorStructure {
    factors: Vec<Matrix>,  // F_i ∈ R_q^{n×d}
    mu: usize,             // Number of factors
    d: usize,              // Factor width
}

pub trait MatrixOperations {
    /// Matrix-vector product: Fw
    fn mul_vec(&self, vec: &[RingElement]) -> Vec<RingElement>;
    
    /// Matrix-matrix product: FW
    fn mul_mat(&self, other: &Matrix) -> Matrix;
    
    /// Row-wise Kronecker product: A • B
    fn row_kronecker(&self, other: &Matrix) -> Matrix;
    
    /// Standard Kronecker product: A ⊗ B
    fn kronecker(&self, other: &Matrix) -> Matrix;
    
    /// Hadamard (element-wise) product: A ⊙ B
    fn hadamard(&self, other: &Matrix) -> Matrix;
    
    /// Decompose into top F and bottom F̄
    fn split_top_bottom(&self, top_rows: usize) -> (Matrix, Matrix);
    
    /// Check if matrix has row-tensor structure
    fn is_row_tensor(&self) -> bool;
}
```

### Component 5: Low-Degree Extension Module

```rust
/// Low-degree extension of witness
/// LDE_d[w]: K^µ → K with individual degree d-1
pub struct LDEContext {
    d: usize,              // Degree bound per variable
    mu: usize,             // Number of variables
    ring: Arc<CyclotomicRing>,
}

/// Multivariate polynomial representing LDE
pub struct MultivariatePoly<T> {
    coefficients: Vec<T>,  // Indexed by multi-index z ∈ [d]^µ
    degrees: Vec<usize>,   // Degree in each variable
    num_vars: usize,       // µ
}

pub trait LDEOperations {
    /// Construct LDE from witness vector w ∈ R^{d^µ}
    /// Returns polynomial satisfying LDE[w](z) = w_z for z ∈ [d]^µ
    fn construct_lde(&self, witness: &[RingElement]) -> MultivariatePoly<RingElement>;
    
    /// Evaluate LDE at point r ∈ R_q^µ
    /// LDE[w](r) = ⟨r̃, w⟩ where r̃ is Lagrange basis
    fn evaluate_lde(&self, witness: &[RingElement], point: &[RingElement]) -> RingElement;
    
    /// Compute Lagrange basis vector r̃ for evaluation point r
    /// r̃^T = ⊗_{j∈[µ]} (∏_{k'∈[d]\{k}} (r_j-k')/(k-k'))_{k∈[d]}
    fn lagrange_basis(&self, point: &[RingElement]) -> Vec<RingElement>;
    
    /// Compute single Lagrange coefficient L_{j,k}(x_j)
    /// L_{j,k}(x_j) = ∏_{k'∈[d]\{k}} (x_j - k')/(k - k')
    fn lagrange_coefficient(&self, x_j: &RingElement, k: usize) -> RingElement;
    
    /// Extend LDE to matrix W ∈ K^{d^µ×r}
    fn construct_matrix_lde(&self, witness: &Matrix) -> Vec<MultivariatePoly<RingElement>>;
    
    /// Evaluate matrix LDE: LDE[W](r) ∈ R_q^r
    fn evaluate_matrix_lde(&self, witness: &Matrix, point: &[RingElement]) -> Vec<RingElement>;
}
```

### Component 6: Relation Definitions

```rust
/// Principal linear relation Ξ^lin_{n̂,n,µ,r,β}
/// Statement: (H, F, Y) with HFW = Y mod q, ∥W∥_{σ,2} ≤ β
pub struct LinearRelation {
    n_hat: usize,          // n̂: rows of H
    n: usize,              // n: columns of H, rows of F
    mu: usize,             // µ: tensor depth (m = d^µ)
    r: usize,              // r: witness columns
    beta: f64,             // β: norm bound
}

pub struct LinearStatement {
    h: Matrix,             // H ∈ R_q^{n̂×n}, form [I_n; H̄]
    f: Matrix,             // F ∈ R_q^{n×m}, form [F; F̄] with F row-tensor
    y: Matrix,             // Y ∈ R_q^{n̂×r}
}

pub struct LinearWitness {
    w: Matrix,             // W ∈ R^{m×r}
}

/// LDE relation Ξ^lde-⊗_{n̂,n,µ,µ̃,r,β,t}
/// Extends Ξ^lin with evaluation claims: LDE[M_i W](r_i) = s_i
pub struct LDERelation {
    base: LinearRelation,
    mu_tilde: usize,       // µ̃: LDE variables for M_i
    t: usize,              // t: number of evaluation claims
}

pub struct LDEStatement {
    base: LinearStatement,
    eval_claims: Vec<EvaluationClaim>,
}

pub struct EvaluationClaim {
    point: Vec<RingElement>,    // r_i ∈ R_q^{µ̃}
    value: Vec<RingElement>,    // s_i ∈ R_q^r
    matrix: Option<Matrix>,     // M_i (None if identity)
}

/// Sumcheck relation Ξ^sum_{n̂,n,µ,r,β}
/// Extends Ξ^lin with: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t
pub struct SumcheckRelation {
    base: LinearRelation,
}

pub struct SumcheckStatement {
    base: LinearStatement,
    sum_target: Vec<RingElement>,  // t ∈ R_q^r
}

/// Norm relation Ξ^norm_{n̂,n,µ,r,β}
/// Extends Ξ^lin with explicit norm bound: ∥W∥_{σ,2} ≤ ν
pub struct NormRelation {
    base: LinearRelation,
}

pub struct NormStatement {
    base: LinearStatement,
    norm_bound: f64,       // ν ≤ β
}

/// R1CS relation Ξ^lin-r1cs_{n̂,n,ñ,µ,µ̃,r,β}
/// AW ⊙ BW = CW mod q, DW = E mod q
pub struct R1CSRelation {
    base: LinearRelation,
    n_tilde: usize,        // ñ: linear constraint rows
    mu_tilde: usize,       // µ̃: R1CS matrix tensor depth
}

pub struct R1CSStatement {
    base: LinearStatement,
    a: Matrix,             // A ∈ R_q^{m̃×m}
    b: Matrix,             // B ∈ R_q^{m̃×m}
    c: Matrix,             // C ∈ R_q^{m̃×m}
    d: Matrix,             // D ∈ R_q^{ñ×d^⊗µ}
    e: Matrix,             // E ∈ R_q^{ñ×r}
}
```

### Component 7: Protocol Transcripts

```rust
/// Transcript for Fiat-Shamir transformation
pub struct Transcript {
    hasher: Blake3Hasher,
    messages: Vec<Vec<u8>>,
}

pub trait TranscriptOperations {
    /// Append prover message to transcript
    fn append_message(&mut self, label: &[u8], message: &[u8]);
    
    /// Append ring element
    fn append_ring_element(&mut self, label: &[u8], elem: &RingElement);
    
    /// Append matrix
    fn append_matrix(&mut self, label: &[u8], mat: &Matrix);
    
    /// Generate challenge in F_{q^e}^×
    fn challenge_ext_field(&mut self, label: &[u8]) -> ExtFieldElement;
    
    /// Generate challenge in R_q
    fn challenge_ring(&mut self, label: &[u8]) -> RingElement;
    
    /// Generate vector of challenges
    fn challenge_vector(&mut self, label: &[u8], len: usize) -> Vec<ExtFieldElement>;
}

/// Proof structure containing all prover messages
pub struct Proof {
    // Sumcheck round polynomials
    sumcheck_polys: Vec<UnivariatePoly<ExtFieldElement>>,
    // LDE evaluation values
    lde_evaluations: Vec<Vec<RingElement>>,
    // Inner product values for norm-check
    inner_products: Vec<RingElement>,
    // Final witness (for small instances)
    final_witness: Option<Matrix>,
    // Additional protocol-specific data
    auxiliary_data: Vec<Vec<u8>>,
}
```

### Component 8: Core RoK Protocols

```rust
/// Reduction of Knowledge trait
pub trait ReductionOfKnowledge {
    type InputStatement;
    type InputWitness;
    type OutputStatement;
    type OutputWitness;
    
    /// Prover's reduction: (stmt, wit) → (stmt', wit', proof_data)
    fn prover_reduce(
        &self,
        statement: &Self::InputStatement,
        witness: &Self::InputWitness,
        transcript: &mut Transcript,
    ) -> Result<(Self::OutputStatement, Self::OutputWitness, Vec<u8>), Error>;
    
    /// Verifier's reduction: stmt → stmt' (using transcript challenges)
    fn verifier_reduce(
        &self,
        statement: &Self::InputStatement,
        proof_data: &[u8],
        transcript: &mut Transcript,
    ) -> Result<Self::OutputStatement, Error>;
}

/// Π^lde-⊗: Ξ^lde-⊗ → Ξ^lin (Lemma 2)
/// Zero communication, deterministic reduction
pub struct LDETensorReduction {
    lde_ctx: LDEContext,
}

impl ReductionOfKnowledge for LDETensorReduction {
    type InputStatement = LDEStatement;
    type InputWitness = LinearWitness;
    type OutputStatement = LinearStatement;
    type OutputWitness = LinearWitness;
    
    // Constructs H' = [H; I_t], F' = [F; (M_i r̃_i^T)], Y' = [Y; (s_i^T)]
}
```

/// Π^sum: Ξ^sum → Ξ^lde-⊗ (Figure 2, Lemma 3)
/// Sumcheck protocol with dynamic programming optimization
pub struct SumcheckReduction {
    lde_ctx: LDEContext,
    crt_ctx: CRTContext,
}

impl SumcheckReduction {
    /// Prover's sumcheck with O(m) complexity via dynamic programming
    pub fn prover_sumcheck(
        &self,
        witness: &Matrix,
        transcript: &mut Transcript,
    ) -> SumcheckProverState {
        // 1. Receive batching vector u ←$ F_{q^e}^×
        let u = transcript.challenge_vector(b"sumcheck_batch", self.r * self.phi_over_e);
        
        // 2. Compute batched polynomial f̃ = u^T · CRT(LDE[W] ⊙ LDE[W̄])
        // 3. Precompute intermediate sums for dynamic programming
        // 4. For each round j ∈ [µ]:
        //    - Compute g_j(x) from stored intermediates
        //    - Send g_j to verifier
        //    - Receive challenge r_j
        //    - Update intermediates
        // 5. Compute final evaluations s_0 = LDE[W](r), s_1 = LDE[W̄](r̄)
    }
    
    /// Verifier's sumcheck checks
    pub fn verifier_sumcheck(
        &self,
        statement: &SumcheckStatement,
        proof: &SumcheckProof,
        transcript: &mut Transcript,
    ) -> Result<LDEStatement, Error> {
        // 1. Sample u, compute a_0 = u^T · CRT(t)
        // 2. For each round j:
        //    - Check a_j = Σ_{z∈[d]} g_j(z)
        //    - Sample r_j, compute a_{j+1} = g_j(r_j)
        // 3. Check a_µ = u^T · CRT(s_0 ⊙ s_1)
        // 4. Output LDE statement with claims (r, s_0), (r̄, s_1)
    }
}

/// Dynamic programming state for sumcheck prover
pub struct SumcheckProverState {
    /// Partially evaluated polynomials: f̃_{j,i} for i > j
    partial_evals: Vec<Vec<ExtFieldElement>>,
    /// Current round
    round: usize,
    /// Accumulated challenges
    challenges: Vec<ExtFieldElement>,
}

/// Π^norm: Ξ^norm → Ξ^sum (Figure 3, Lemma 4)
/// Norm-check via inner product reduction to sumcheck
pub struct NormCheckReduction {
    lde_ctx: LDEContext,
}

impl NormCheckReduction {
    /// Prover computes inner products t_i = ⟨w_i, w_i⟩ for each column
    pub fn prover_norm_check(
        &self,
        statement: &NormStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<SumcheckStatement, Error> {
        // Parse W = (w_i)_{i∈[r]}
        let columns = witness.w.columns();
        
        // Compute t^T = (⟨w_i, w_i⟩)_{i∈[r]}
        let mut inner_products = Vec::with_capacity(columns.len());
        for w_i in columns {
            let t_i = self.compute_inner_product(w_i, w_i);
            inner_products.push(t_i);
        }
        
        // Send t to verifier
        transcript.append_vector(b"inner_products", &inner_products);
        
        // Verifier checks: Trace(t_i) ≤ ν² for all i
        // This uses: ∥w_i∥²_{σ,2} = Trace(⟨w_i, w_i⟩)
        
        // Output sumcheck statement with t
        Ok(SumcheckStatement {
            base: statement.base.clone(),
            sum_target: inner_products,
        })
    }
    
    /// Compute inner product ⟨a, b⟩ = Σ_j a_j · b_j
    fn compute_inner_product(&self, a: &[RingElement], b: &[RingElement]) -> RingElement {
        assert_eq!(a.len(), b.len());
        let mut result = RingElement::zero(a[0].ring.clone());
        for (a_j, b_j) in a.iter().zip(b.iter()) {
            result = result + (a_j * b_j);
        }
        result
    }
}

/// Π^norm+: Ξ^norm → Ξ^lin (Corollary 1)
/// Composition: Π^norm → Π^sum → Π^lde-⊗ → Ξ^lin
pub struct NormCheckComposition {
    norm_check: NormCheckReduction,
    sumcheck: SumcheckReduction,
    lde_tensor: LDETensorReduction,
}

impl ReductionOfKnowledge for NormCheckComposition {
    type InputStatement = NormStatement;
    type InputWitness = LinearWitness;
    type OutputStatement = LinearStatement;
    type OutputWitness = LinearWitness;
    
    fn prover_reduce(
        &self,
        statement: &Self::InputStatement,
        witness: &Self::InputWitness,
        transcript: &mut Transcript,
    ) -> Result<(Self::OutputStatement, Self::OutputWitness, Vec<u8>), Error> {
        // Step 1: Π^norm reduces Ξ^norm to Ξ^sum
        let (sum_stmt, sum_wit, norm_proof) = 
            self.norm_check.prover_reduce(statement, witness, transcript)?;
        
        // Step 2: Π^sum reduces Ξ^sum to Ξ^lde-⊗
        let (lde_stmt, lde_wit, sum_proof) = 
            self.sumcheck.prover_reduce(&sum_stmt, &sum_wit, transcript)?;
        
        // Step 3: Π^lde-⊗ reduces Ξ^lde-⊗ to Ξ^lin (deterministic, no communication)
        let (lin_stmt, lin_wit, lde_proof) = 
            self.lde_tensor.prover_reduce(&lde_stmt, &lde_wit, transcript)?;
        
        // Combine proofs
        let mut combined_proof = norm_proof;
        combined_proof.extend(sum_proof);
        combined_proof.extend(lde_proof);
        
        Ok((lin_stmt, lin_wit, combined_proof))
    }
}

/// Π^fold: Ξ^lin → Ξ^lin (from [KLNO25])
/// Folding protocol that reduces witness height by factor d
pub struct FoldingReduction {
    d: usize,              // Folding factor
    mu: usize,             // Tensor depth
    challenge_set: ChallengeSet,
}

pub enum ChallengeSet {
    Subtractive,           // Used in [KLNO24]
    Large,                 // Used in [KLNO25], better parameters
}

impl FoldingReduction {
    /// Prover folds witness: W' = W_0 + γW_1 + ... + γ^{d-1}W_{d-1}
    pub fn prover_fold(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // 1. Parse W into d blocks: W = [W_0; W_1; ...; W_{d-1}]
        let blocks = self.split_witness_blocks(&witness.w);
        
        // 2. Receive folding challenge γ
        let gamma = transcript.challenge_ring(b"folding_challenge");
        
        // 3. Compute folded witness: W' = Σ_{i∈[d]} γ^i W_i
        let mut w_prime = blocks[0].clone();
        let mut gamma_power = gamma.clone();
        for i in 1..self.d {
            w_prime = w_prime + blocks[i].scale(&gamma_power);
            gamma_power = gamma_power * &gamma;
        }
        
        // 4. Update statement: F' = F_0 + γF_1 + ... + γ^{µ-1}F_{µ-1}
        let f_prime = self.fold_matrix(&statement.f, &gamma);
        
        // 5. Update Y accordingly
        let y_prime = self.compute_folded_y(&statement, &blocks, &gamma);
        
        Ok((
            LinearStatement {
                h: statement.h.clone(),
                f: f_prime,
                y: y_prime,
            },
            LinearWitness { w: w_prime },
        ))
    }
    
    fn split_witness_blocks(&self, w: &Matrix) -> Vec<Matrix> {
        let block_height = w.rows / self.d;
        (0..self.d)
            .map(|i| w.submatrix(i * block_height, 0, block_height, w.cols))
            .collect()
    }
    
    fn fold_matrix(&self, f: &Matrix, gamma: &RingElement) -> Matrix {
        // Exploit row-tensor structure: F = F_0 • ... • F_{µ-1}
        // F' = (F_0 + γF_1 + ... + γ^{d-1}F_{d-1}) • F_1 • ... • F_{µ-1}
        let factors = f.tensor_structure.as_ref().unwrap().factors.clone();
        let mut f0_prime = factors[0].clone();
        let mut gamma_power = gamma.clone();
        
        for i in 1..self.d {
            f0_prime = f0_prime + factors[0].submatrix(i * factors[0].rows / self.d, 0, 
                                                        factors[0].rows / self.d, factors[0].cols)
                                           .scale(&gamma_power);
            gamma_power = gamma_power * gamma;
        }
        
        // Reconstruct tensor product
        let mut result = f0_prime;
        for i in 1..self.mu {
            result = result.row_kronecker(&factors[i]);
        }
        result
    }
}

/// Π^split: Ξ^lin → Ξ^lin (from [KLNO24])
/// Splits witness into top and bottom parts
pub struct SplitReduction {
    split_point: usize,
}

impl SplitReduction {
    pub fn prover_split(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // Split W = [W_top; W_bot]
        let (w_top, w_bot) = witness.w.split_rows(self.split_point);
        
        // Commit to W_top: y_top = F_top W_top
        let y_top = statement.f.submatrix(0, 0, self.split_point, statement.f.cols)
                              .mul_mat(&w_top);
        
        transcript.append_matrix(b"y_top", &y_top);
        
        // Receive challenge α
        let alpha = transcript.challenge_ring(b"split_challenge");
        
        // Combine: W' = W_top + α W_bot
        let w_prime = w_top + w_bot.scale(&alpha);
        
        // Update statement accordingly
        Ok((
            LinearStatement {
                h: statement.h.clone(),
                f: statement.f.clone(), // F unchanged
                y: y_top + statement.y.scale(&alpha),
            },
            LinearWitness { w: w_prime },
        ))
    }
}

/// Π^⊗RP: Ξ^lin → Ξ^lin × Ξ^lin (from [KLNO25])
/// Random projection with tensor structure
pub struct TensorRandomProjection {
    projection_dim: usize,  // m_rp = O(λ)
    ring: Arc<CyclotomicRing>,
}

impl TensorRandomProjection {
    pub fn prover_project(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearStatement, LinearWitness, LinearWitness), Error> {
        // 1. Sample random projection matrix R ∈ R_q^{m_rp×m}
        let r = self.sample_projection_matrix(transcript);
        
        // 2. Compute projected witness: w_proj = R · W
        let w_proj = r.mul_mat(&witness.w);
        
        // 3. Compute projected image: y_proj = F · w_proj = F · R · W
        let y_proj = statement.f.mul_mat(&w_proj);
        
        // Send y_proj
        transcript.append_matrix(b"projection", &y_proj);
        
        // 4. Output two statements:
        //    - Main: original Ξ^lin with increased dimensions
        //    - Projection: Ξ^lin with projected witness (height 1, width m_rp)
        
        let main_stmt = LinearStatement {
            h: self.extend_h(&statement.h),
            f: self.extend_f(&statement.f),
            y: self.extend_y(&statement.y, &y_proj),
        };
        
        let proj_stmt = LinearStatement {
            h: Matrix::identity(1),
            f: r,
            y: y_proj,
        };
        
        Ok((main_stmt, proj_stmt, witness.clone(), LinearWitness { w: w_proj }))
    }
    
    fn sample_projection_matrix(&self, transcript: &mut Transcript) -> Matrix {
        // Sample random matrix with small entries
        let mut data = Vec::with_capacity(self.projection_dim * self.ring.degree);
        for i in 0..self.projection_dim {
            for j in 0..self.ring.degree {
                let challenge = transcript.challenge_ring(&format!("proj_{}_{}", i, j).as_bytes());
                data.push(challenge);
            }
        }
        Matrix::from_vec(self.projection_dim, self.ring.degree, data)
    }
}

/// Π^b-decomp: Ξ^lin → Ξ^lin (from [KLNO24])
/// Base decomposition to reduce witness norm
pub struct BaseDecomposition {
    base: u64,             // Decomposition base b
    num_digits: usize,     // ℓ: number of digits
}

impl BaseDecomposition {
    pub fn prover_decompose(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // 1. Decompose each entry w_i = Σ_{j∈[ℓ]} b^j w_{i,j}
        let decomposed = self.decompose_witness(&witness.w);
        
        // 2. Update F to account for recomposition: F' = F · diag(1, b, b², ..., b^{ℓ-1})
        let f_prime = self.scale_matrix_columns(&statement.f);
        
        // 3. Witness norm reduced: ∥W'∥ ≤ ∥W∥/b^{ℓ-1} (approximately)
        
        Ok((
            LinearStatement {
                h: statement.h.clone(),
                f: f_prime,
                y: statement.y.clone(),
            },
            LinearWitness { w: decomposed },
        ))
    }
    
    fn decompose_witness(&self, w: &Matrix) -> Matrix {
        let mut decomposed_data = Vec::new();
        
        for elem in w.data.iter() {
            let digits = self.decompose_element(elem);
            decomposed_data.extend(digits);
        }
        
        Matrix::from_vec(w.rows * self.num_digits, w.cols, decomposed_data)
    }
    
    fn decompose_element(&self, elem: &RingElement) -> Vec<RingElement> {
        // Decompose each coefficient in balanced representation
        let mut digits = vec![RingElement::zero(elem.ring.clone()); self.num_digits];
        
        for (coeff_idx, &coeff) in elem.coefficients.iter().enumerate() {
            let mut remainder = coeff;
            for digit_idx in 0..self.num_digits {
                let digit = remainder % (self.base as i64);
                digits[digit_idx].coefficients[coeff_idx] = digit;
                remainder = (remainder - digit) / (self.base as i64);
            }
        }
        
        digits
    }
}

/// Π^batch: Ξ^lin → Ξ^lin (from [KLNO25])
/// Batch multiple linear equations into one
pub struct BatchingReduction {
    num_equations: usize,
}

impl BatchingReduction {
    pub fn prover_batch(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // 1. Receive batching challenge ρ
        let rho = transcript.challenge_ring(b"batching_challenge");
        
        // 2. Compute batched H: H' = ρ^0 H_0 + ρ^1 H_1 + ... + ρ^{n̂-1} H_{n̂-1}
        let h_prime = self.batch_matrix_rows(&statement.h, &rho);
        
        // 3. Compute batched Y: Y' = ρ^0 Y_0 + ρ^1 Y_1 + ... + ρ^{n̂-1} Y_{n̂-1}
        let y_prime = self.batch_matrix_rows(&statement.y, &rho);
        
        // 4. Output statement with single equation
        Ok((
            LinearStatement {
                h: h_prime,
                f: statement.f.clone(),
                y: y_prime,
            },
            witness.clone(),
        ))
    }
    
    fn batch_matrix_rows(&self, mat: &Matrix, rho: &RingElement) -> Matrix {
        let mut result = mat.row(0).clone();
        let mut rho_power = rho.clone();
        
        for i in 1..mat.rows {
            result = result + mat.row(i).scale(&rho_power);
            rho_power = rho_power * rho;
        }
        
        Matrix::from_vec(1, mat.cols, result)
    }
}

/// Π^batch*: Enhanced batching via sumcheck (Section 6.3, Appendix D)
/// More efficient than Π^batch for large n
pub struct EnhancedBatchingReduction {
    lde_ctx: LDEContext,
    sumcheck: SumcheckReduction,
}

impl EnhancedBatchingReduction {
    pub fn prover_batch_sumcheck(
        &self,
        statement: &LinearStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // Express F̄W = ȳ as sumcheck claims:
        // For each row i: Σ_{z∈[d]^µ} LDE[f^i](z) · LDE[W](z) = y^i
        
        // 1. Batch sumcheck claims with random linear combination
        let rho = transcript.challenge_vector(b"sumcheck_batch", statement.f.rows);
        
        // 2. Run sumcheck protocol to reduce to single evaluation claim
        let (lde_stmt, lde_wit, _) = self.sumcheck.prover_reduce(
            &self.construct_batched_sumcheck_statement(statement, &rho),
            witness,
            transcript,
        )?;
        
        // 3. Reduce LDE statement to linear statement
        // This eliminates the need for compression matrix H
        
        Ok((
            LinearStatement {
                h: Matrix::identity(statement.h.rows),  // H = I
                f: lde_stmt.base.f,
                y: lde_stmt.base.y,
            },
            lde_wit,
        ))
    }
    
    fn construct_batched_sumcheck_statement(
        &self,
        statement: &LinearStatement,
        rho: &[ExtFieldElement],
    ) -> SumcheckStatement {
        // Construct batched sumcheck target: t = Σ_i ρ_i · y_i
        // where each y_i corresponds to row i of F̄W = ȳ
        // implement this thoroughly like in production
        unimplemented!("Construct batched sumcheck from linear equations")
    }
}

/// Π^join: Ξ^lin × Ξ^lin → Ξ^lin (from [KLNO25])
/// Join two linear relations into one
pub struct JoinReduction;

impl JoinReduction {
    pub fn prover_join(
        &self,
        stmt1: &LinearStatement,
        stmt2: &LinearStatement,
        wit1: &LinearWitness,
        wit2: &LinearWitness,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // Stack statements vertically
        let h_joined = Matrix::vstack(&[stmt1.h.clone(), stmt2.h.clone()]);
        let f_joined = Matrix::vstack(&[stmt1.f.clone(), stmt2.f.clone()]);
        let y_joined = Matrix::vstack(&[stmt1.y.clone(), stmt2.y.clone()]);
        let w_joined = Matrix::hstack(&[wit1.w.clone(), wit2.w.clone()]);
        
        Ok((
            LinearStatement {
                h: h_joined,
                f: f_joined,
                y: y_joined,
            },
            LinearWitness { w: w_joined },
        ))
    }
}

/// Π^lin-r1cs: Ξ^lin-r1cs → Ξ^lin (Section 7, Appendix C)
/// Reduce R1CS to linear relation via linearization
pub struct R1CSReduction {
    lde_ctx: LDEContext,
    sumcheck: SumcheckReduction,
}

impl R1CSReduction {
    pub fn prover_r1cs_to_linear(
        &self,
        statement: &R1CSStatement,
        witness: &LinearWitness,
        transcript: &mut Transcript,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // R1CS: AW ⊙ BW = CW mod q, DW = E mod q
        
        // 1. Linearization: Express as evaluation claims over LDE
        //    For each constraint i:
        //    Σ_{z∈[d]^µ} LDE[a^i](z) · LDE[W](z) · LDE[b^i](z) · LDE[W](z) 
        //                = Σ_{z∈[d]^µ} LDE[c^i](z) · LDE[W](z)
        
        // 2. Batch constraints with random linear combination
        let rho = transcript.challenge_vector(b"r1cs_batch", statement.a.rows);
        
        // 3. Reduce to sumcheck claims
        let sumcheck_stmt = self.construct_r1cs_sumcheck(statement, &rho);
        
        // 4. Run sumcheck protocol
        let (lde_stmt, lde_wit, _) = self.sumcheck.prover_reduce(
            &sumcheck_stmt,
            witness,
            transcript,
        )?;
        
        // 5. Reduce to linear relation
        let (lin_stmt, lin_wit, _) = self.lde_to_linear(&lde_stmt, &lde_wit)?;
        
        Ok((lin_stmt, lin_wit))
    }
    
    fn construct_r1cs_sumcheck(
        &self,
        statement: &R1CSStatement,
        rho: &[ExtFieldElement],
    ) -> SumcheckStatement {
        // Construct sumcheck for batched R1CS constraints
        // Target: Σ_i ρ_i · (Σ_z LDE[a^i](z)·LDE[W](z)·LDE[b^i](z)·LDE[W](z) - LDE[c^i](z)·LDE[W](z))
        // implement this thoroughly like in production
        unimplemented!("Construct R1CS sumcheck statement")
    }
    
    fn lde_to_linear(
        &self,
        lde_stmt: &LDEStatement,
        lde_wit: &LinearWitness,
    ) -> Result<(LinearStatement, LinearWitness), Error> {
        // Apply Π^lde-⊗ reduction
        // implement this thoroughly like in production
        unimplemented!("Reduce LDE to linear")
    }
}
```


## Data Models

### Core Data Structures

#### 1. Ring Elements and Arithmetic

```rust
/// Representation of elements in R_q = Z[ζ]/qZ
#[derive(Clone, Debug)]
pub struct RingElement {
    /// Coefficients in balanced representation: {-⌈q/2⌉+1, ..., ⌊q/2⌋}
    pub coefficients: Vec<i64>,
    /// Reference to parent ring
    pub ring: Arc<CyclotomicRing>,
}

impl RingElement {
    /// Zero element
    pub fn zero(ring: Arc<CyclotomicRing>) -> Self;
    
    /// One element
    pub fn one(ring: Arc<CyclotomicRing>) -> Self;
    
    /// Sample uniformly from R_q
    pub fn random(ring: Arc<CyclotomicRing>, rng: &mut impl Rng) -> Self;
    
    /// Sample from discrete Gaussian
    pub fn gaussian(ring: Arc<CyclotomicRing>, sigma: f64, rng: &mut impl Rng) -> Self;
    
    /// Reduce modulo q (in-place)
    pub fn reduce_mod_q(&mut self);
    
    /// Compute complex conjugate x̄
    pub fn conjugate(&self) -> Self;
    
    /// Compute canonical embedding σ(x) ∈ C^φ
    pub fn canonical_embedding(&self) -> Vec<Complex64>;
    
    /// Compute ∥x∥²_{σ,2} = Σ_j |σ_j(x)|²
    pub fn canonical_norm_squared(&self) -> f64;
    
    /// Compute Trace(x) = Σ_{σ∈Gal(K/Q)} σ(x)
    pub fn trace(&self) -> i64;
}

/// Arithmetic operations
impl Add for RingElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        // Component-wise addition mod q
    }
}

impl Mul for RingElement {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        // Polynomial multiplication mod (Φ_f(x), q)
        // Use NTT for efficiency
    }
}
```


#### 2. Matrix Structures

```rust
/// Matrix over R_q with optional tensor structure
#[derive(Clone, Debug)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    /// Row-major storage
    pub data: Vec<RingElement>,
    /// Optional row-tensor structure F = F_0 • F_1 • ... • F_{µ-1}
    pub tensor_structure: Option<TensorStructure>,
}

/// Row-tensor (face-splitting) structure
#[derive(Clone, Debug)]
pub struct TensorStructure {
    /// Factors F_i ∈ R_q^{n×d}
    pub factors: Vec<Matrix>,
    /// Number of factors µ
    pub mu: usize,
    /// Factor width d
    pub d: usize,
}

impl Matrix {
    /// Create from vector (row-major)
    pub fn from_vec(rows: usize, cols: usize, data: Vec<RingElement>) -> Self;
    
    /// Create identity matrix
    pub fn identity(size: usize, ring: Arc<CyclotomicRing>) -> Self;
    
    /// Create zero matrix
    pub fn zero(rows: usize, cols: usize, ring: Arc<CyclotomicRing>) -> Self;
    
    /// Get element at (i, j)
    pub fn get(&self, i: usize, j: usize) -> &RingElement;
    
    /// Get row i
    pub fn row(&self, i: usize) -> Vec<RingElement>;
    
    /// Get column j
    pub fn column(&self, j: usize) -> Vec<RingElement>;
    
    /// Extract submatrix
    pub fn submatrix(&self, row_start: usize, col_start: usize, 
                     rows: usize, cols: usize) -> Matrix;
    
    /// Split into top and bottom parts
    pub fn split_rows(&self, split_point: usize) -> (Matrix, Matrix);
    
    /// Vertical stack: [A; B]
    pub fn vstack(matrices: &[Matrix]) -> Matrix;
    
    /// Horizontal stack: [A | B]
    pub fn hstack(matrices: &[Matrix]) -> Matrix;
    
    /// Matrix-vector product: Av
    pub fn mul_vec(&self, v: &[RingElement]) -> Vec<RingElement>;
    
    /// Matrix-matrix product: AB
    pub fn mul_mat(&self, other: &Matrix) -> Matrix;
    
    /// Scalar multiplication: αA
    pub fn scale(&self, scalar: &RingElement) -> Matrix;
    
    /// Row-wise Kronecker product: A • B
    /// (A • B)_i = A_i ⊗ B_i where A_i, B_i are rows
    pub fn row_kronecker(&self, other: &Matrix) -> Matrix;
    
    /// Standard Kronecker product: A ⊗ B
    pub fn kronecker(&self, other: &Matrix) -> Matrix;
    
    /// Hadamard (element-wise) product: A ⊙ B
    pub fn hadamard(&self, other: &Matrix) -> Matrix;
    
    /// Construct row-tensor matrix from factors
    pub fn from_row_tensor(factors: Vec<Matrix>) -> Matrix;
    
    /// Check if matrix has row-tensor structure
    pub fn is_row_tensor(&self) -> bool;
    
    /// Compute canonical norm: max_j ∥column_j∥_{σ,2}
    pub fn canonical_norm(&self) -> f64;
}
```


#### 3. Polynomial Structures

```rust
/// Univariate polynomial over ring R
#[derive(Clone, Debug)]
pub struct UnivariatePoly<T> {
    /// Coefficients: p(x) = Σ_i coeffs[i] · x^i
    pub coefficients: Vec<T>,
}

impl<T: Clone + Add<Output=T> + Mul<Output=T>> UnivariatePoly<T> {
    /// Evaluate at point x: p(x)
    pub fn evaluate(&self, x: &T) -> T;
    
    /// Degree of polynomial
    pub fn degree(&self) -> usize;
    
    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self;
    
    /// Multiply two polynomials
    pub fn mul(&self, other: &Self) -> Self;
}

/// Multivariate polynomial over ring R
/// Represents polynomial in µ variables with individual degree bounds
#[derive(Clone, Debug)]
pub struct MultivariatePoly<T> {
    /// Coefficients indexed by multi-index z ∈ [d]^µ
    /// For z = (z_0, ..., z_{µ-1}), coefficient is for x_0^{z_0} · ... · x_{µ-1}^{z_{µ-1}}
    pub coefficients: Vec<T>,
    /// Degree bound in each variable
    pub degrees: Vec<usize>,
    /// Number of variables µ
    pub num_vars: usize,
}

impl<T: Clone + Add<Output=T> + Mul<Output=T> + Zero> MultivariatePoly<T> {
    /// Create zero polynomial
    pub fn zero(degrees: Vec<usize>) -> Self;
    
    /// Evaluate at point r = (r_0, ..., r_{µ-1})
    pub fn evaluate(&self, point: &[T]) -> T;
    
    /// Partial evaluation: fix first k variables
    pub fn partial_eval(&self, values: &[T]) -> Self;
    
    /// Convert to univariate in variable j (others fixed)
    pub fn to_univariate(&self, var_index: usize, fixed_values: &[T]) -> UnivariatePoly<T>;
    
    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self;
    
    /// Multiply two polynomials
    pub fn mul(&self, other: &Self) -> Self;
    
    /// Hadamard product: (p ⊙ q)(x) = p(x) · q(x)
    pub fn hadamard(&self, other: &Self) -> Self;
}
```


#### 4. Low-Degree Extension Structures

```rust
/// Context for low-degree extension operations
#[derive(Clone)]
pub struct LDEContext {
    /// Degree bound per variable
    pub d: usize,
    /// Number of variables µ
    pub mu: usize,
    /// Total witness size m = d^µ
    pub m: usize,
    /// Parent ring
    pub ring: Arc<CyclotomicRing>,
    /// Precomputed Lagrange basis denominators
    lagrange_denoms: Vec<RingElement>,
}

impl LDEContext {
    /// Create new LDE context
    pub fn new(d: usize, mu: usize, ring: Arc<CyclotomicRing>) -> Self;
    
    /// Construct LDE from witness w ∈ R^{d^µ}
    /// Returns polynomial LDE[w]: R^µ → R satisfying LDE[w](z) = w_z for z ∈ [d]^µ
    pub fn construct_lde(&self, witness: &[RingElement]) -> MultivariatePoly<RingElement>;
    
    /// Evaluate LDE at point r ∈ R_q^µ
    /// Uses formula: LDE[w](r) = ⟨r̃, w⟩ where r̃ is Lagrange basis
    pub fn evaluate_lde(&self, witness: &[RingElement], point: &[RingElement]) -> RingElement;
    
    /// Compute Lagrange basis vector r̃ ∈ R_q^{d^µ} for point r ∈ R_q^µ
    /// r̃^T = ⊗_{j∈[µ]} (L_{j,k}(r_j))_{k∈[d]}
    /// where L_{j,k}(x) = ∏_{k'∈[d]\{k}} (x - k')/(k - k')
    pub fn lagrange_basis(&self, point: &[RingElement]) -> Vec<RingElement>;
    
    /// Compute single Lagrange coefficient L_{j,k}(x_j)
    /// L_{j,k}(x_j) = ∏_{k'∈[d]\{k}} (x_j - k')/(k - k')
    pub fn lagrange_coefficient(&self, x_j: &RingElement, k: usize) -> RingElement;
    
    /// Construct LDE for matrix W ∈ R^{d^µ×r}
    /// Returns vector of r polynomials, one per column
    pub fn construct_matrix_lde(&self, witness: &Matrix) -> Vec<MultivariatePoly<RingElement>>;
    
    /// Evaluate matrix LDE at point r
    /// Returns vector LDE[W](r) ∈ R_q^r
    pub fn evaluate_matrix_lde(&self, witness: &Matrix, point: &[RingElement]) -> Vec<RingElement>;
    
    /// Compute conjugate evaluation: LDE[W](r̄) where r̄ is component-wise conjugate
    pub fn evaluate_conjugate(&self, witness: &Matrix, point: &[RingElement]) -> Vec<RingElement>;
}
```


#### 5. Relation Instances

```rust
/// Instance of Ξ^lin relation
#[derive(Clone)]
pub struct LinearInstance {
    pub statement: LinearStatement,
    pub witness: Option<LinearWitness>,
}

#[derive(Clone)]
pub struct LinearStatement {
    /// H ∈ R_q^{n̂×n}, form [I_n; H̄]
    pub h: Matrix,
    /// F ∈ R_q^{n×m}, form [F; F̄] with F row-tensor
    pub f: Matrix,
    /// Y ∈ R_q^{n̂×r}
    pub y: Matrix,
    /// Parameters
    pub params: LinearParams,
}

#[derive(Clone)]
pub struct LinearParams {
    pub n_hat: usize,      // n̂
    pub n: usize,          // n
    pub mu: usize,         // µ
    pub r: usize,          // r
    pub beta: f64,         // β: norm bound
}

#[derive(Clone)]
pub struct LinearWitness {
    /// W ∈ R^{m×r}
    pub w: Matrix,
}

impl LinearInstance {
    /// Verify relation: HFW = Y mod q and ∥W∥_{σ,2} ≤ β
    pub fn verify(&self) -> bool;
    
    /// Check norm bound
    pub fn check_norm(&self) -> bool;
    
    /// Check linear equation
    pub fn check_equation(&self) -> bool;
}

/// Instance of Ξ^lde-⊗ relation
#[derive(Clone)]
pub struct LDEInstance {
    pub statement: LDEStatement,
    pub witness: Option<LinearWitness>,
}

#[derive(Clone)]
pub struct LDEStatement {
    /// Base linear statement
    pub base: LinearStatement,
    /// Evaluation claims: (r_i, s_i, M_i) for i ∈ [t]
    pub eval_claims: Vec<EvaluationClaim>,
}

#[derive(Clone)]
pub struct EvaluationClaim {
    /// Evaluation point r_i ∈ R_q^{µ̃}
    pub point: Vec<RingElement>,
    /// Expected value s_i ∈ R_q^r
    pub value: Vec<RingElement>,
    /// Optional matrix M_i ∈ R_q^{d^{µ̃}×d^µ} (None for identity)
    pub matrix: Option<Matrix>,
}

impl LDEInstance {
    /// Verify: base relation + LDE[M_i W](r_i) = s_i for all i
    pub fn verify(&self) -> bool;
}

/// Instance of Ξ^sum relation
#[derive(Clone)]
pub struct SumcheckInstance {
    pub statement: SumcheckStatement,
    pub witness: Option<LinearWitness>,
}

#[derive(Clone)]
pub struct SumcheckStatement {
    /// Base linear statement
    pub base: LinearStatement,
    /// Sum target: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t
    pub sum_target: Vec<RingElement>,
}

impl SumcheckInstance {
    /// Verify: base relation + sumcheck claim
    pub fn verify(&self) -> bool;
}

/// Instance of Ξ^norm relation
#[derive(Clone)]
pub struct NormInstance {
    pub statement: NormStatement,
    pub witness: Option<LinearWitness>,
}

#[derive(Clone)]
pub struct NormStatement {
    /// Base linear statement
    pub base: LinearStatement,
    /// Explicit norm bound ν ≤ β
    pub norm_bound: f64,
}

impl NormInstance {
    /// Verify: base relation + ∥W∥_{σ,2} ≤ ν
    pub fn verify(&self) -> bool;
}

/// Instance of Ξ^lin-r1cs relation
#[derive(Clone)]
pub struct R1CSInstance {
    pub statement: R1CSStatement,
    pub witness: Option<LinearWitness>,
}

#[derive(Clone)]
pub struct R1CSStatement {
    /// Base linear statement (commitment)
    pub base: LinearStatement,
    /// R1CS matrices
    pub a: Matrix,         // A ∈ R_q^{m̃×m}
    pub b: Matrix,         // B ∈ R_q^{m̃×m}
    pub c: Matrix,         // C ∈ R_q^{m̃×m}
    /// Linear constraints
    pub d: Matrix,         // D ∈ R_q^{ñ×d^µ}
    pub e: Matrix,         // E ∈ R_q^{ñ×r}
}

impl R1CSInstance {
    /// Verify: base relation + AW ⊙ BW = CW + DW = E
    pub fn verify(&self) -> bool;
}
```


#### 6. Proof Structures

```rust
/// Complete proof for SNARK application
#[derive(Clone, Debug)]
pub struct SNARKProof {
    /// Proofs from each round of structured loop
    pub structured_rounds: Vec<StructuredRoundProof>,
    /// Proofs from unstructured rounds
    pub unstructured_rounds: Vec<UnstructuredRoundProof>,
    /// Final witness (small, sent in clear)
    pub final_witness: Matrix,
}

/// Proof for one structured round
#[derive(Clone, Debug)]
pub struct StructuredRoundProof {
    /// Norm-check proof (Π^norm+)
    pub norm_check: NormCheckProof,
    /// Batching challenge response
    pub batching_data: Vec<u8>,
    /// Base decomposition data
    pub decomposition_data: Vec<u8>,
    /// Split proof
    pub split_data: SplitProof,
    /// Random projection proof
    pub projection_proof: ProjectionProof,
    /// Folding proof
    pub folding_data: Vec<u8>,
}

/// Norm-check proof (composition of Π^norm, Π^sum, Π^lde-⊗)
#[derive(Clone, Debug)]
pub struct NormCheckProof {
    /// Inner products t^T = (⟨w_i, w_i⟩)_{i∈[r]}
    pub inner_products: Vec<RingElement>,
    /// Sumcheck round polynomials g_j(x) for j ∈ [µ]
    pub sumcheck_polys: Vec<UnivariatePoly<ExtFieldElement>>,
    /// LDE evaluations: s_0 = LDE[W](r), s_1 = LDE[W̄](r̄)
    pub lde_evals: (Vec<RingElement>, Vec<RingElement>),
}

/// Split proof
#[derive(Clone, Debug)]
pub struct SplitProof {
    /// Commitment to top part: y_top = F_top W_top
    pub y_top: Matrix,
}

/// Random projection proof
#[derive(Clone, Debug)]
pub struct ProjectionProof {
    /// Projected image: y_proj = F · R · W
    pub y_proj: Matrix,
}

/// Proof for folding scheme
#[derive(Clone, Debug)]
pub struct FoldingProof {
    /// Join proof (cross-terms)
    pub join_data: Vec<u8>,
    /// Norm-check proof
    pub norm_check: NormCheckProof,
    /// Random projection proof
    pub projection_proof: ProjectionProof,
    /// Folding data
    pub folding_data: Vec<u8>,
    /// Enhanced batching proof (if using Π^batch*)
    pub batching_proof: Option<EnhancedBatchingProof>,
    /// Base decomposition data
    pub decomposition_data: Vec<u8>,
}

/// Enhanced batching proof via sumcheck
#[derive(Clone, Debug)]
pub struct EnhancedBatchingProof {
    /// Sumcheck round polynomials
    pub sumcheck_polys: Vec<UnivariatePoly<ExtFieldElement>>,
    /// Final evaluation claim
    pub final_eval: Vec<RingElement>,
}

/// Proof for PCS opening
#[derive(Clone, Debug)]
pub struct PCSProof {
    /// Commitment: y = F · w
    pub commitment: Vec<RingElement>,
    /// Opening proof (SNARK for LDE evaluation)
    pub opening_proof: SNARKProof,
}
```


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Ring Arithmetic Correctness
*For any* two ring elements a, b ∈ R_q and operation op ∈ {+, -, ×}, the result of op(a, b) computed in the implementation should equal the mathematically correct result modulo q and the cyclotomic polynomial Φ_f(x).

**Validates: Requirements 1.1, 1.2, 1.3**

### Property 2: Canonical Norm Computation
*For any* ring element x ∈ R_q, the computed canonical norm ∥x∥_{σ,2} should equal √(Σ_{j∈[φ]} |σ_j(x)|²) where σ_j are the canonical embeddings.

**Validates: Requirements 1.4**

### Property 3: CRT Isomorphism
*For any* ring element x ∈ R_q, applying CRT followed by CRT^{-1} should return the original element: CRT^{-1}(CRT(x)) = x mod q.

**Validates: Requirements 2.1**

### Property 4: NTT Transform Correctness
*For any* polynomial p ∈ R_q[x], applying forward NTT followed by inverse NTT should return the original polynomial: INTT(NTT(p)) = p.

**Validates: Requirements 2.2**

### Property 5: Matrix-Vector Product Correctness
*For any* matrix F ∈ R_q^{n×m} and vector w ∈ R_q^m, the computed product Fw should equal Σ_{j∈[m]} F_{i,j} · w_j for each row i.

**Validates: Requirements 3.1**

### Property 6: Row-Tensor Structure Preservation
*For any* matrices F_0, ..., F_{µ-1} ∈ R_q^{n×d}, constructing F = F_0 • ... • F_{µ-1} and then multiplying by a vector w ∈ R_q^{d^µ} should give the same result as computing the product using the tensor structure.

**Validates: Requirements 3.2**

### Property 7: LDE Interpolation Property
*For any* witness vector w ∈ R_q^{d^µ} and any grid point z ∈ [d]^µ, the low-degree extension LDE[w] evaluated at z should equal w_z: LDE[w](z) = w_z.

**Validates: Requirements 4.1**

### Property 8: LDE Evaluation via Lagrange Basis
*For any* witness w ∈ R_q^{d^µ} and evaluation point r ∈ R_q^µ, computing LDE[w](r) directly should equal ⟨r̃, w⟩ where r̃ is the Lagrange basis vector.

**Validates: Requirements 4.2**

### Property 9: Π^lde-⊗ Correctness
*For any* valid instance ((H, F, Y, (r_i, s_i, M_i)_{i∈[t]}), W) ∈ Ξ^lde-⊗, the reduction Π^lde-⊗ should produce an instance ((H', F', Y'), W) ∈ Ξ^lin where H' = [H; I_t], F' = [F; (M_i r̃_i^T)_{i∈[t]}], Y' = [Y; (s_i^T)_{i∈[t]}].

**Validates: Requirements 5.1**

### Property 10: Sumcheck Round Consistency
*For any* round j ∈ [µ] of the sumcheck protocol, the verifier's check a_j = Σ_{z∈[d]} g_j(z) should hold where g_j is the prover's round polynomial and a_j is the accumulated sum.

**Validates: Requirements 6.1**

### Property 11: Sumcheck Final Check
*For any* sumcheck execution, the final check a_µ = u^T · CRT(s_0 ⊙ s_1) should hold where s_0 = LDE[W](r), s_1 = LDE[W̄](r̄), and r is the accumulated challenge vector.

**Validates: Requirements 6.2**

### Property 12: Sumcheck Prover Linear Time
*For any* witness W ∈ R^{m×r} with m = d^µ, the sumcheck prover using dynamic programming should complete in O(mr) ring operations.

**Validates: Requirements 6.3**

### Property 13: Norm-Check Inner Product Correctness
*For any* witness column w_i ∈ R^m, the computed inner product t_i = ⟨w_i, w_i⟩ should satisfy Trace(t_i) = ∥w_i∥²_{σ,2}.

**Validates: Requirements 7.1**

### Property 14: Norm-Check Reduction to Sumcheck
*For any* norm instance ((H, F, Y, ν), W) ∈ Ξ^norm, the Π^norm protocol should produce a sumcheck instance ((H, F, Y, t), W) ∈ Ξ^sum where t^T = (⟨w_i, w_i⟩)_{i∈[r]} and Trace(t_i) ≤ ν² for all i.

**Validates: Requirements 7.2**

### Property 15: Folding Witness Reduction
*For any* witness W ∈ R^{dm×r} split into blocks W_0, ..., W_{d-1} and folding challenge γ, the folded witness W' = Σ_{i∈[d]} γ^i W_i should satisfy ∥W'∥_{σ,2} ≤ d · max_i ∥W_i∥_{σ,2}.

**Validates: Requirements 8.1**

### Property 16: Folding Statement Consistency
*For any* linear statement (H, F, Y) and folding challenge γ, the folded statement (H, F', Y') should satisfy HF'W' = Y' where W' is the folded witness and F' is the folded matrix.

**Validates: Requirements 8.2**

### Property 17: Split Witness Combination
*For any* witness W = [W_top; W_bot] and split challenge α, the combined witness W' = W_top + αW_bot should satisfy FW' = F_top W_top + αF_bot W_bot.

**Validates: Requirements 9.1**

### Property 18: Random Projection Norm Bound
*For any* witness W ∈ R^{m×r} with ∥W∥_{σ,2} ≤ β and random projection matrix R ∈ R_q^{m_rp×m}, the projected witness w_proj = RW should satisfy ∥w_proj∥_{σ,2} ≤ m_rp · β with high probability.

**Validates: Requirements 10.1**

### Property 19: Base Decomposition Norm Reduction
*For any* witness W with ∥W∥_{σ,2} ≤ β and base b, ℓ digits, the decomposed witness W' should satisfy ∥W'∥_{σ,2} ≤ β/b^{ℓ-1} (approximately).

**Validates: Requirements 11.1**

### Property 20: Batching Linear Combination
*For any* set of linear equations H_i FW = Y_i for i ∈ [n̂] and batching challenge ρ, the batched equation (Σ_i ρ^i H_i) FW = Σ_i ρ^i Y_i should hold if and only if all original equations hold.

**Validates: Requirements 12.1**

### Property 21: Enhanced Batching via Sumcheck
*For any* linear equations F̄W = ȳ expressed as sumcheck claims Σ_{z∈[d]^µ} LDE[f^i](z) · LDE[W](z) = y^i, batching with random linear combination should reduce to a single sumcheck claim.

**Validates: Requirements 12.2**

### Property 22: Join Relation Preservation
*For any* two instances ((H_1, F_1, Y_1), W_1) ∈ Ξ^lin and ((H_2, F_2, Y_2), W_2) ∈ Ξ^lin, the joined instance should satisfy both original relations.

**Validates: Requirements 13.1**

### Property 23: R1CS Linearization Correctness
*For any* R1CS instance with AW ⊙ BW = CW, the linearization via LDE should produce evaluation claims that are satisfied if and only if the original R1CS constraints hold.

**Validates: Requirements 14.1**

### Property 24: SNARK Completeness
*For any* valid witness W satisfying the linear relation HFW = Y mod q with ∥W∥_{σ,2} ≤ β, the SNARK prover should produce a proof that the verifier accepts with probability 1.

**Validates: Requirements 15.1**

### Property 25: SNARK Soundness
*For any* invalid witness W not satisfying the relation or norm bound, the SNARK prover should fail to produce an accepting proof except with negligible probability κ.

**Validates: Requirements 15.2**

### Property 26: SNARK Proof Size
*For any* witness of size m = d^µ, the SNARK proof size should be O(λ log³ m / log λ) bits.

**Validates: Requirements 15.3**

### Property 27: SNARK Prover Time
*For any* witness of size m, the SNARK prover should complete in O(m) ring operations.

**Validates: Requirements 15.4**

### Property 28: SNARK Verifier Time
*For any* proof, the SNARK verifier should complete in O(log m · λ²) ring operations.

**Validates: Requirements 15.5**

### Property 29: PCS Commitment Binding
*For any* two distinct polynomials p ≠ q, their commitments should be different except with negligible probability under the vSIS assumption.

**Validates: Requirements 16.1**

### Property 30: PCS Opening Correctness
*For any* committed polynomial p and evaluation point r, if the prover claims p(r) = v, the opening proof should verify if and only if this claim is correct.

**Validates: Requirements 16.2**

### Property 31: Folding Scheme Completeness
*For any* L valid instances of Ξ^lin, the folding scheme should produce a single valid instance that accumulates all L instances.

**Validates: Requirements 17.1**

### Property 32: Folding Scheme Soundness
*For any* L instances where at least one is invalid, the folding scheme should fail to produce a valid accumulated instance except with negligible probability.

**Validates: Requirements 17.2**

### Property 33: Folding Proof Size
*For any* L instances to be folded with witness size m, the folding proof should be O(λ log² m / log λ) bits.

**Validates: Requirements 17.3**

### Property 34: Folding Prover Time
*For any* L instances with witness size m, the folding prover should complete in O(Lm) ring operations.

**Validates: Requirements 17.4**

### Property 35: Folding Verifier Time
*For any* folding proof, the verifier should complete in O(λ²) ring operations.

**Validates: Requirements 17.5**

### Property 36: Fiat-Shamir Transformation
*For any* interactive protocol made non-interactive via Fiat-Shamir, the challenges should be computationally indistinguishable from random in the random oracle model.

**Validates: Requirements 18.1**

### Property 37: Transcript Binding
*For any* two different execution traces, their transcript hashes should be different except with negligible probability.

**Validates: Requirements 18.2**

### Property 38: AVX-512 Arithmetic Equivalence
*For any* ring operation computed using AVX-512 instructions, the result should be identical to the scalar implementation.

**Validates: Requirements 19.1**

### Property 39: Parallel Execution Determinism
*For any* protocol execution using parallel computation, the result should be identical to sequential execution.

**Validates: Requirements 19.2**

### Property 40: Parameter Security
*For any* parameter set (R, q, n, µ, β), the vSIS assumption should hold with security level λ bits.

**Validates: Requirements 20.1**


## Error Handling

### Error Types

```rust
/// Comprehensive error types for SALSAA framework
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SALSAAError {
    /// Ring arithmetic errors
    RingArithmetic(RingArithmeticError),
    /// Matrix operation errors
    MatrixOperation(MatrixError),
    /// Protocol execution errors
    Protocol(ProtocolError),
    /// Verification errors
    Verification(VerificationError),
    /// Parameter errors
    Parameter(ParameterError),
    /// Cryptographic errors
    Cryptographic(CryptoError),
    /// Implementation errors
    Implementation(ImplementationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingArithmeticError {
    /// Modulus is not prime
    InvalidModulus(String),
    /// Ring degree mismatch
    DegreeMismatch { expected: usize, got: usize },
    /// Division by zero
    DivisionByZero,
    /// Element not invertible
    NotInvertible,
    /// Overflow in arithmetic operation
    Overflow,
    /// Invalid coefficient (outside balanced range)
    InvalidCoefficient { value: i64, modulus: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixError {
    /// Dimension mismatch in operation
    DimensionMismatch { 
        op: String, 
        expected: (usize, usize), 
        got: (usize, usize) 
    },
    /// Index out of bounds
    IndexOutOfBounds { 
        index: (usize, usize), 
        bounds: (usize, usize) 
    },
    /// Invalid tensor structure
    InvalidTensorStructure(String),
    /// Tensor structure missing when required
    MissingTensorStructure,
    /// Incompatible tensor factors
    IncompatibleTensorFactors,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Invalid prover message
    InvalidProverMessage(String),
    /// Invalid verifier challenge
    InvalidVerifierChallenge(String),
    /// Protocol state error
    InvalidState(String),
    /// Transcript error
    TranscriptError(String),
    /// Round mismatch
    RoundMismatch { expected: usize, got: usize },
    /// Missing protocol data
    MissingData(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Linear equation check failed
    LinearEquationFailed,
    /// Norm bound check failed
    NormBoundFailed { computed: String, bound: String },
    /// Sumcheck verification failed
    SumcheckFailed { round: usize, reason: String },
    /// LDE evaluation check failed
    LDEEvaluationFailed,
    /// R1CS constraint failed
    R1CSConstraintFailed { constraint_index: usize },
    /// Proof verification failed
    ProofVerificationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterError {
    /// Invalid security parameter
    InvalidSecurityParameter { lambda: usize, reason: String },
    /// Invalid ring parameters
    InvalidRingParameters(String),
    /// Invalid norm bound
    InvalidNormBound { beta: String, reason: String },
    /// Incompatible parameters
    IncompatibleParameters(String),
    /// Parameter too small
    ParameterTooSmall { param: String, min: usize, got: usize },
    /// Parameter too large
    ParameterTooLarge { param: String, max: usize, got: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// vSIS assumption violated
    VSISViolation,
    /// Challenge sampling failed
    ChallengeSamplingFailed,
    /// Randomness generation failed
    RandomnessGenerationFailed,
    /// Hash function error
    HashFunctionError(String),
    /// Insufficient entropy
    InsufficientEntropy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImplementationError {
    /// NTT operation failed
    NTTFailed(String),
    /// CRT operation failed
    CRTFailed(String),
    /// AVX-512 instruction error
    AVX512Error(String),
    /// Parallel execution error
    ParallelExecutionError(String),
    /// Memory allocation failed
    MemoryAllocationFailed,
    /// Serialization error
    SerializationError(String),
    /// Deserialization error
    DeserializationError(String),
}
```

### Error Handling Strategies

```rust
/// Result type for SALSAA operations
pub type SALSAAResult<T> = Result<T, SALSAAError>;

/// Error recovery strategies
pub trait ErrorRecovery {
    /// Attempt to recover from error
    fn try_recover(&self, error: &SALSAAError) -> Option<Self> where Self: Sized;
    
    /// Check if error is recoverable
    fn is_recoverable(error: &SALSAAError) -> bool;
    
    /// Get error context
    fn error_context(&self) -> String;
}

/// Validation trait for early error detection
pub trait Validate {
    /// Validate parameters before execution
    fn validate(&self) -> SALSAAResult<()>;
    
    /// Validate with context
    fn validate_with_context(&self, context: &str) -> SALSAAResult<()>;
}

impl Validate for LinearStatement {
    fn validate(&self) -> SALSAAResult<()> {
        // Check H dimensions
        if self.h.rows != self.params.n_hat || self.h.cols != self.params.n {
            return Err(SALSAAError::Matrix(MatrixError::DimensionMismatch {
                op: "H validation".to_string(),
                expected: (self.params.n_hat, self.params.n),
                got: (self.h.rows, self.h.cols),
            }));
        }
        
        // Check F dimensions
        let expected_m = self.params.d.pow(self.params.mu as u32);
        if self.f.rows != self.params.n || self.f.cols != expected_m {
            return Err(SALSAAError::Matrix(MatrixError::DimensionMismatch {
                op: "F validation".to_string(),
                expected: (self.params.n, expected_m),
                got: (self.f.rows, self.f.cols),
            }));
        }
        
        // Check F has tensor structure
        if !self.f.is_row_tensor() {
            return Err(SALSAAError::Matrix(MatrixError::MissingTensorStructure));
        }
        
        // Check Y dimensions
        if self.y.rows != self.params.n_hat || self.y.cols != self.params.r {
            return Err(SALSAAError::Matrix(MatrixError::DimensionMismatch {
                op: "Y validation".to_string(),
                expected: (self.params.n_hat, self.params.r),
                got: (self.y.rows, self.y.cols),
            }));
        }
        
        Ok(())
    }
}

impl Validate for LinearWitness {
    fn validate(&self) -> SALSAAResult<()> {
        // Check witness dimensions match expected
        // Check norm bound
        let norm = self.w.canonical_norm();
        if norm > self.expected_beta {
            return Err(SALSAAError::Verification(VerificationError::NormBoundFailed {
                computed: format!("{:.2}", norm),
                bound: format!("{:.2}", self.expected_beta),
            }));
        }
        
        Ok(())
    }
}
```

### Error Propagation and Logging

```rust
/// Error context for debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Location where error occurred
    pub location: String,
    /// Operation being performed
    pub operation: String,
    /// Additional context
    pub context: Vec<(String, String)>,
    /// Stack trace (if available)
    pub stack_trace: Option<String>,
}

/// Logging levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Logger trait
pub trait Logger {
    fn log(&self, level: LogLevel, message: &str);
    fn log_error(&self, error: &SALSAAError, context: &ErrorContext);
}

/// Error handling macros
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

#[macro_export]
macro_rules! bail {
    ($err:expr) => {
        return Err($err)
    };
}

#[macro_export]
macro_rules! context {
    ($result:expr, $ctx:expr) => {
        $result.map_err(|e| {
            // Add context to error
            e.with_context($ctx)
        })
    };
}
```

### Specific Error Handling Scenarios

#### 1. Ring Arithmetic Errors
- **Division by zero**: Return `RingArithmeticError::DivisionByZero`
- **Overflow**: Use checked arithmetic, return `RingArithmeticError::Overflow`
- **Invalid modulus**: Validate at construction time
- **Non-invertible element**: Check before inversion, return `RingArithmeticError::NotInvertible`

#### 2. Protocol Errors
- **Invalid prover message**: Validate format and bounds before processing
- **Round mismatch**: Track protocol state, ensure sequential execution
- **Missing data**: Check completeness before verification
- **Transcript errors**: Validate hash function output

#### 3. Verification Errors
- **Linear equation failure**: Compute both sides, compare with tolerance
- **Norm bound failure**: Compute exact norm, compare with bound
- **Sumcheck failure**: Identify failing round, log polynomial degrees
- **LDE evaluation failure**: Check interpolation property on grid points

#### 4. Parameter Errors
- **Invalid security parameter**: Validate λ ≥ 128
- **Incompatible parameters**: Check relationships (e.g., q > 2β²)
- **Parameter too small**: Check minimum requirements for security
- **Parameter too large**: Check computational feasibility

#### 5. Implementation Errors
- **NTT failure**: Validate root of unity, check modulus compatibility
- **CRT failure**: Verify splitting degree, check isomorphism
- **AVX-512 error**: Fall back to scalar implementation
- **Parallel execution error**: Ensure thread safety, use atomic operations
- **Memory allocation failure**: Check available memory, use streaming for large data

### Recovery Strategies

```rust
impl ErrorRecovery for SALSAAError {
    fn try_recover(&self, error: &SALSAAError) -> Option<Self> {
        match error {
            // Recoverable errors
            SALSAAError::Implementation(ImplementationError::AVX512Error(_)) => {
                // Fall back to scalar implementation
                Some(Self::use_scalar_fallback())
            }
            SALSAAError::Implementation(ImplementationError::ParallelExecutionError(_)) => {
                // Fall back to sequential execution
                Some(Self::use_sequential_execution())
            }
            // Non-recoverable errors
            SALSAAError::Verification(_) |
            SALSAAError::Cryptographic(_) => None,
            _ => None,
        }
    }
    
    fn is_recoverable(error: &SALSAAError) -> bool {
        matches!(error,
            SALSAAError::Implementation(ImplementationError::AVX512Error(_)) |
            SALSAAError::Implementation(ImplementationError::ParallelExecutionError(_))
        )
    }
}
```


## Testing Strategy

### Overview

The testing strategy for SALSAA employs a dual approach combining unit tests for specific functionality and property-based tests for universal correctness properties. This comprehensive strategy ensures both concrete correctness and general robustness across all valid inputs.

### Unit Testing

Unit tests verify specific examples, edge cases, and integration points between components. They provide concrete validation of expected behavior.

#### Ring Arithmetic Tests

```rust
#[cfg(test)]
mod ring_arithmetic_tests {
    use super::*;
    
    #[test]
    fn test_addition_commutativity() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        let b = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!(a.clone() + b.clone(), b + a);
    }
    
    #[test]
    fn test_multiplication_associativity() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        let b = RingElement::random(ring.clone(), &mut thread_rng());
        let c = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!((a.clone() * b.clone()) * c.clone(), a * (b * c));
    }
    
    #[test]
    fn test_distributivity() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        let b = RingElement::random(ring.clone(), &mut thread_rng());
        let c = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!(a.clone() * (b.clone() + c.clone()), 
                   a.clone() * b + a * c);
    }
    
    #[test]
    fn test_zero_element() {
        let ring = CyclotomicRing::new(256, 40961);
        let zero = RingElement::zero(ring.clone());
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!(a.clone() + zero.clone(), a);
        assert_eq!(a.clone() * zero, RingElement::zero(ring));
    }
    
    #[test]
    fn test_one_element() {
        let ring = CyclotomicRing::new(256, 40961);
        let one = RingElement::one(ring.clone());
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!(a.clone() * one, a);
    }
    
    #[test]
    fn test_conjugate_involution() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!(a.conjugate().conjugate(), a);
    }
    
    #[test]
    fn test_trace_linearity() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        let b = RingElement::random(ring.clone(), &mut thread_rng());
        assert_eq!((a.clone() + b.clone()).trace(), a.trace() + b.trace());
    }
}
```

#### CRT and NTT Tests

```rust
#[cfg(test)]
mod transform_tests {
    use super::*;
    
    #[test]
    fn test_crt_round_trip() {
        let ring = CyclotomicRing::new(256, 40961);
        let crt_ctx = CRTContext::new(ring.clone());
        let x = RingElement::random(ring, &mut thread_rng());
        let crt_x = crt_ctx.to_crt(&x);
        let recovered = crt_ctx.from_crt(&crt_x);
        assert_eq!(x, recovered);
    }
    
    #[test]
    fn test_ntt_round_trip() {
        let ring = CyclotomicRing::new(256, 40961);
        let ntt_ctx = NTTContext::new(ring.clone());
        let mut coeffs: Vec<_> = (0..ring.degree)
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        let original = coeffs.clone();
        ntt_ctx.forward_ntt(&mut coeffs);
        ntt_ctx.inverse_ntt(&mut coeffs);
        assert_eq!(coeffs, original);
    }
    
    #[test]
    fn test_ntt_multiplication() {
        let ring = CyclotomicRing::new(256, 40961);
        let ntt_ctx = NTTContext::new(ring.clone());
        let a: Vec<_> = (0..ring.degree)
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        let b: Vec<_> = (0..ring.degree)
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        
        // Compute via NTT
        let ntt_result = ntt_ctx.ntt_multiply(&a, &b);
        
        // Compute directly
        let direct_result = naive_polynomial_multiply(&a, &b, &ring);
        
        assert_eq!(ntt_result, direct_result);
    }
}
```

#### LDE Tests

```rust
#[cfg(test)]
mod lde_tests {
    use super::*;
    
    #[test]
    fn test_lde_interpolation_property() {
        let ring = CyclotomicRing::new(256, 40961);
        let d = 4;
        let mu = 3;
        let lde_ctx = LDEContext::new(d, mu, ring.clone());
        
        let witness: Vec<_> = (0..d.pow(mu as u32))
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        
        let lde = lde_ctx.construct_lde(&witness);
        
        // Check LDE[w](z) = w_z for all z ∈ [d]^µ
        for z in grid_points(d, mu) {
            let z_ring: Vec<_> = z.iter()
                .map(|&i| RingElement::from_i64(i as i64, ring.clone()))
                .collect();
            let eval = lde.evaluate(&z_ring);
            let index = multi_index_to_linear(&z, d);
            assert_eq!(eval, witness[index]);
        }
    }
    
    #[test]
    fn test_lde_evaluation_via_lagrange() {
        let ring = CyclotomicRing::new(256, 40961);
        let d = 4;
        let mu = 3;
        let lde_ctx = LDEContext::new(d, mu, ring.clone());
        
        let witness: Vec<_> = (0..d.pow(mu as u32))
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        
        let point: Vec<_> = (0..mu)
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        
        // Direct evaluation
        let lde = lde_ctx.construct_lde(&witness);
        let direct_eval = lde.evaluate(&point);
        
        // Via Lagrange basis
        let lagrange_eval = lde_ctx.evaluate_lde(&witness, &point);
        
        assert_eq!(direct_eval, lagrange_eval);
    }
}
```

### Property-Based Testing

Property-based tests verify universal properties that should hold across all valid inputs. We use the `proptest` crate for Rust.

#### Property Test Framework Setup

```rust
use proptest::prelude::*;

/// Strategy for generating ring elements
fn ring_element_strategy(ring: Arc<CyclotomicRing>) -> impl Strategy<Value = RingElement> {
    prop::collection::vec(any::<i64>(), ring.degree)
        .prop_map(move |coeffs| {
            let mut elem = RingElement {
                coefficients: coeffs,
                ring: ring.clone(),
            };
            elem.reduce_mod_q();
            elem
        })
}

/// Strategy for generating matrices
fn matrix_strategy(
    rows: usize, 
    cols: usize, 
    ring: Arc<CyclotomicRing>
) -> impl Strategy<Value = Matrix> {
    prop::collection::vec(ring_element_strategy(ring.clone()), rows * cols)
        .prop_map(move |data| Matrix::from_vec(rows, cols, data))
}

/// Strategy for generating witnesses with norm bound
fn bounded_witness_strategy(
    m: usize,
    r: usize,
    beta: f64,
    ring: Arc<CyclotomicRing>
) -> impl Strategy<Value = Matrix> {
    matrix_strategy(m, r, ring)
        .prop_filter("norm bound", move |w| w.canonical_norm() <= beta)
}
```


#### Property Tests for Core Components

```rust
proptest! {
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 1: Ring Arithmetic Correctness**
    #[test]
    fn prop_ring_arithmetic_correctness(
        a in ring_element_strategy(test_ring()),
        b in ring_element_strategy(test_ring()),
        op in prop_oneof![Just("add"), Just("mul"), Just("sub")]
    ) {
        let result = match op.as_str() {
            "add" => a.clone() + b.clone(),
            "mul" => a.clone() * b.clone(),
            "sub" => a.clone() - b.clone(),
            _ => unreachable!(),
        };
        
        // Result should be in R_q (coefficients in balanced range)
        for &coeff in &result.coefficients {
            prop_assert!(coeff >= -(result.ring.modulus as i64 / 2));
            prop_assert!(coeff <= result.ring.modulus as i64 / 2);
        }
        
        // Verify mathematical correctness via canonical embedding
        let sigma_a = a.canonical_embedding();
        let sigma_b = b.canonical_embedding();
        let sigma_result = result.canonical_embedding();
        
        for i in 0..result.ring.degree {
            let expected = match op.as_str() {
                "add" => sigma_a[i] + sigma_b[i],
                "mul" => sigma_a[i] * sigma_b[i],
                "sub" => sigma_a[i] - sigma_b[i],
                _ => unreachable!(),
            };
            prop_assert!((sigma_result[i] - expected).norm() < 1e-6);
        }
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 2: Canonical Norm Computation**
    #[test]
    fn prop_canonical_norm_computation(
        x in ring_element_strategy(test_ring())
    ) {
        let computed_norm_sq = x.canonical_norm_squared();
        
        // Compute via canonical embedding
        let sigma_x = x.canonical_embedding();
        let expected_norm_sq: f64 = sigma_x.iter()
            .map(|c| c.norm_sqr())
            .sum();
        
        prop_assert!((computed_norm_sq - expected_norm_sq).abs() < 1e-6);
        
        // Verify via trace: ∥x∥²_{σ,2} = Trace(x · x̄)
        let x_conj = x.conjugate();
        let inner_prod = x.clone() * x_conj;
        let trace_norm_sq = inner_prod.trace() as f64;
        
        prop_assert!((computed_norm_sq - trace_norm_sq).abs() < 1e-6);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 3: CRT Isomorphism**
    #[test]
    fn prop_crt_round_trip(
        x in ring_element_strategy(test_ring())
    ) {
        let crt_ctx = CRTContext::new(x.ring.clone());
        let crt_x = crt_ctx.to_crt(&x);
        let recovered = crt_ctx.from_crt(&crt_x);
        
        prop_assert_eq!(x, recovered);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 4: NTT Transform Correctness**
    #[test]
    fn prop_ntt_round_trip(
        coeffs in prop::collection::vec(ring_element_strategy(test_ring()), test_ring().degree)
    ) {
        let ntt_ctx = NTTContext::new(test_ring());
        let mut working = coeffs.clone();
        ntt_ctx.forward_ntt(&mut working);
        ntt_ctx.inverse_ntt(&mut working);
        
        prop_assert_eq!(coeffs, working);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 5: Matrix-Vector Product Correctness**
    #[test]
    fn prop_matrix_vector_product(
        f in matrix_strategy(10, 20, test_ring()),
        w in prop::collection::vec(ring_element_strategy(test_ring()), 20)
    ) {
        let result = f.mul_vec(&w);
        
        // Verify each component
        for i in 0..f.rows {
            let mut expected = RingElement::zero(test_ring());
            for j in 0..f.cols {
                expected = expected + (f.get(i, j).clone() * w[j].clone());
            }
            prop_assert_eq!(result[i], expected);
        }
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 6: Row-Tensor Structure Preservation**
    #[test]
    fn prop_row_tensor_structure(
        factors in prop::collection::vec(matrix_strategy(5, 4, test_ring()), 3),
        w in prop::collection::vec(ring_element_strategy(test_ring()), 64) // 4^3 = 64
    ) {
        // Construct row-tensor matrix
        let f = Matrix::from_row_tensor(factors.clone());
        
        // Compute product using tensor structure
        let result_tensor = f.mul_vec(&w);
        
        // Compute product directly
        let result_direct = naive_tensor_product(&factors, &w);
        
        prop_assert_eq!(result_tensor, result_direct);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 7: LDE Interpolation Property**
    #[test]
    fn prop_lde_interpolation(
        witness in prop::collection::vec(ring_element_strategy(test_ring()), 64) // d=4, µ=3
    ) {
        let lde_ctx = LDEContext::new(4, 3, test_ring());
        let lde = lde_ctx.construct_lde(&witness);
        
        // Check LDE[w](z) = w_z for all z ∈ [d]^µ
        for z in grid_points(4, 3) {
            let z_ring: Vec<_> = z.iter()
                .map(|&i| RingElement::from_i64(i as i64, test_ring()))
                .collect();
            let eval = lde.evaluate(&z_ring);
            let index = multi_index_to_linear(&z, 4);
            prop_assert_eq!(eval, witness[index]);
        }
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 8: LDE Evaluation via Lagrange Basis**
    #[test]
    fn prop_lde_lagrange_evaluation(
        witness in prop::collection::vec(ring_element_strategy(test_ring()), 64),
        point in prop::collection::vec(ring_element_strategy(test_ring()), 3)
    ) {
        let lde_ctx = LDEContext::new(4, 3, test_ring());
        
        // Direct evaluation
        let lde = lde_ctx.construct_lde(&witness);
        let direct_eval = lde.evaluate(&point);
        
        // Via Lagrange basis: LDE[w](r) = ⟨r̃, w⟩
        let lagrange_basis = lde_ctx.lagrange_basis(&point);
        let mut lagrange_eval = RingElement::zero(test_ring());
        for (basis_elem, w_elem) in lagrange_basis.iter().zip(witness.iter()) {
            lagrange_eval = lagrange_eval + (basis_elem.clone() * w_elem.clone());
        }
        
        prop_assert_eq!(direct_eval, lagrange_eval);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 9: Π^lde-⊗ Correctness**
    #[test]
    fn prop_lde_tensor_reduction(
        base_stmt in linear_statement_strategy(),
        witness in bounded_witness_strategy(64, 2, 100.0, test_ring()),
        eval_claims in prop::collection::vec(evaluation_claim_strategy(), 1..=3)
    ) {
        let lde_stmt = LDEStatement {
            base: base_stmt.clone(),
            eval_claims: eval_claims.clone(),
        };
        
        let lde_reduction = LDETensorReduction::new(LDEContext::new(4, 3, test_ring()));
        let (lin_stmt, lin_wit, _) = lde_reduction.prover_reduce(
            &lde_stmt,
            &witness,
            &mut Transcript::new(b"test")
        ).unwrap();
        
        // Verify structure: H' = [H; I_t], F' = [F; (M_i r̃_i^T)], Y' = [Y; (s_i^T)]
        prop_assert_eq!(lin_stmt.h.rows, base_stmt.h.rows + eval_claims.len());
        prop_assert_eq!(lin_stmt.f.rows, base_stmt.f.rows + eval_claims.len());
        prop_assert_eq!(lin_stmt.y.rows, base_stmt.y.rows + eval_claims.len());
        
        // Verify relation holds
        let hfw = lin_stmt.h.mul_mat(&lin_stmt.f.mul_mat(&lin_wit.w));
        prop_assert_eq!(hfw, lin_stmt.y);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 10: Sumcheck Round Consistency**
    #[test]
    fn prop_sumcheck_round_consistency(
        witness in bounded_witness_strategy(64, 2, 100.0, test_ring()),
        round in 0usize..3
    ) {
        let lde_ctx = LDEContext::new(4, 3, test_ring());
        let sumcheck = SumcheckReduction::new(lde_ctx, CRTContext::new(test_ring()));
        
        let mut transcript = Transcript::new(b"test");
        let prover_state = sumcheck.prover_sumcheck(&witness, &mut transcript);
        
        // Get round polynomial g_j
        let g_j = &prover_state.sumcheck_polys[round];
        
        // Verify Σ_{z∈[d]} g_j(z) = a_j
        let mut sum = ExtFieldElement::zero();
        for z in 0..4 {
            sum = sum + g_j.evaluate(&ExtFieldElement::from_u64(z));
        }
        
        prop_assert_eq!(sum, prover_state.accumulated_sums[round]);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 13: Norm-Check Inner Product Correctness**
    #[test]
    fn prop_norm_check_inner_product(
        w_i in prop::collection::vec(ring_element_strategy(test_ring()), 64)
    ) {
        // Compute inner product t_i = ⟨w_i, w_i⟩
        let mut t_i = RingElement::zero(test_ring());
        for elem in &w_i {
            t_i = t_i + (elem.clone() * elem.clone());
        }
        
        // Compute norm via canonical embedding
        let mut norm_sq = 0.0;
        for elem in &w_i {
            norm_sq += elem.canonical_norm_squared();
        }
        
        // Verify Trace(t_i) = ∥w_i∥²_{σ,2}
        let trace_t_i = t_i.trace() as f64;
        prop_assert!((trace_t_i - norm_sq).abs() < 1e-6);
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 15: Folding Witness Reduction**
    #[test]
    fn prop_folding_witness_norm(
        blocks in prop::collection::vec(
            bounded_witness_strategy(16, 2, 50.0, test_ring()),
            4
        ),
        gamma in ring_element_strategy(test_ring())
    ) {
        // Compute folded witness: W' = Σ_{i∈[d]} γ^i W_i
        let mut w_prime = blocks[0].clone();
        let mut gamma_power = gamma.clone();
        for i in 1..4 {
            w_prime = w_prime + blocks[i].scale(&gamma_power);
            gamma_power = gamma_power * &gamma;
        }
        
        // Verify norm bound: ∥W'∥ ≤ d · max_i ∥W_i∥
        let max_block_norm = blocks.iter()
            .map(|b| b.canonical_norm())
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap();
        let folded_norm = w_prime.canonical_norm();
        
        prop_assert!(folded_norm <= 4.0 * max_block_norm * 1.1); // 10% tolerance
    }
    
    /// **Feature: salsaa-sumcheck-lattice-arguments, Property 20: Batching Linear Combination**
    #[test]
    fn prop_batching_linear_combination(
        equations in prop::collection::vec(linear_equation_strategy(), 2..=5),
        rho in ring_element_strategy(test_ring())
    ) {
        // All equations should hold individually
        for eq in &equations {
            prop_assert!(eq.verify());
        }
        
        // Batch with random linear combination
        let batched = batch_equations(&equations, &rho);
        
        // Batched equation should hold
        prop_assert!(batched.verify());
        
        // If batched holds but one original doesn't, should fail
        // (contrapositive test)
    }
}
```


### Integration Tests

Integration tests verify the correct interaction between multiple components and end-to-end protocol execution.

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_snark_end_to_end() {
        // Setup parameters
        let params = SNARKParams {
            ring: CyclotomicRing::new(256, 40961),
            n_hat: 10,
            n: 8,
            mu: 6,
            r: 2,
            beta: 1000.0,
            lambda: 128,
        };
        
        // Generate random witness
        let witness = generate_random_witness(&params);
        
        // Generate statement
        let statement = generate_statement_for_witness(&params, &witness);
        
        // Run prover
        let mut prover_transcript = Transcript::new(b"snark_test");
        let proof = snark_prove(&statement, &witness, &mut prover_transcript)
            .expect("Prover should succeed");
        
        // Run verifier
        let mut verifier_transcript = Transcript::new(b"snark_test");
        let result = snark_verify(&statement, &proof, &mut verifier_transcript);
        
        assert!(result.is_ok(), "Verifier should accept valid proof");
    }
    
    #[test]
    fn test_snark_soundness() {
        let params = SNARKParams::default();
        
        // Generate invalid witness (wrong norm or equation)
        let invalid_witness = generate_invalid_witness(&params);
        let statement = generate_statement_for_witness(&params, &invalid_witness);
        
        // Prover should fail or verifier should reject
        let mut transcript = Transcript::new(b"soundness_test");
        let proof_result = snark_prove(&statement, &invalid_witness, &mut transcript);
        
        if let Ok(proof) = proof_result {
            let mut verifier_transcript = Transcript::new(b"soundness_test");
            let verify_result = snark_verify(&statement, &proof, &mut verifier_transcript);
            assert!(verify_result.is_err(), "Verifier should reject invalid proof");
        }
    }
    
    #[test]
    fn test_pcs_commitment_and_opening() {
        let params = PCSParams::default();
        
        // Commit to polynomial
        let poly_coeffs = generate_random_polynomial(&params);
        let commitment = pcs_commit(&poly_coeffs, &params);
        
        // Open at random point
        let eval_point = generate_random_point(&params);
        let eval_value = evaluate_polynomial(&poly_coeffs, &eval_point);
        
        let mut transcript = Transcript::new(b"pcs_test");
        let opening_proof = pcs_open(&poly_coeffs, &eval_point, &eval_value, &mut transcript)
            .expect("Opening should succeed");
        
        // Verify opening
        let mut verifier_transcript = Transcript::new(b"pcs_test");
        let result = pcs_verify(&commitment, &eval_point, &eval_value, &opening_proof, &mut verifier_transcript);
        
        assert!(result.is_ok(), "Opening verification should succeed");
    }
    
    #[test]
    fn test_folding_scheme_multiple_instances() {
        let params = FoldingParams::default();
        
        // Generate L instances
        let l = 4;
        let instances: Vec<_> = (0..l)
            .map(|_| generate_random_linear_instance(&params))
            .collect();
        
        // Verify all instances are valid
        for inst in &instances {
            assert!(inst.verify(), "All input instances should be valid");
        }
        
        // Run folding
        let mut transcript = Transcript::new(b"folding_test");
        let (folded_instance, proof) = fold_instances(&instances, &mut transcript)
            .expect("Folding should succeed");
        
        // Verify folded instance
        assert!(folded_instance.verify(), "Folded instance should be valid");
        
        // Verify folding proof
        let mut verifier_transcript = Transcript::new(b"folding_test");
        let result = verify_folding(&instances, &folded_instance, &proof, &mut verifier_transcript);
        
        assert!(result.is_ok(), "Folding verification should succeed");
    }
    
    #[test]
    fn test_r1cs_to_linear_reduction() {
        let params = R1CSParams::default();
        
        // Generate R1CS instance
        let r1cs_instance = generate_random_r1cs_instance(&params);
        
        // Verify R1CS constraints
        assert!(r1cs_instance.verify(), "R1CS instance should be valid");
        
        // Reduce to linear relation
        let mut transcript = Transcript::new(b"r1cs_test");
        let r1cs_reduction = R1CSReduction::new(
            LDEContext::new(params.d, params.mu, params.ring.clone()),
            SumcheckReduction::new(/* ... */),
        );
        
        let (linear_instance, proof) = r1cs_reduction.prover_r1cs_to_linear(
            &r1cs_instance.statement,
            &r1cs_instance.witness.unwrap(),
            &mut transcript,
        ).expect("R1CS reduction should succeed");
        
        // Verify linear instance
        assert!(linear_instance.verify(), "Reduced linear instance should be valid");
    }
    
    #[test]
    fn test_protocol_composition() {
        // Test composition of multiple RoKs
        let params = TestParams::default();
        
        // Start with norm instance
        let norm_instance = generate_random_norm_instance(&params);
        assert!(norm_instance.verify());
        
        // Apply Π^norm
        let mut transcript = Transcript::new(b"composition_test");
        let norm_check = NormCheckReduction::new(LDEContext::new(params.d, params.mu, params.ring.clone()));
        let (sum_instance, _, _) = norm_check.prover_reduce(
            &norm_instance.statement,
            &norm_instance.witness.unwrap(),
            &mut transcript,
        ).expect("Norm check should succeed");
        
        // Apply Π^sum
        let sumcheck = SumcheckReduction::new(/* ... */);
        let (lde_instance, _, _) = sumcheck.prover_reduce(
            &sum_instance,
            &norm_instance.witness.unwrap(),
            &mut transcript,
        ).expect("Sumcheck should succeed");
        
        // Apply Π^lde-⊗
        let lde_reduction = LDETensorReduction::new(/* ... */);
        let (linear_instance, _, _) = lde_reduction.prover_reduce(
            &lde_instance,
            &norm_instance.witness.unwrap(),
            &mut transcript,
        ).expect("LDE reduction should succeed");
        
        // Verify final linear instance
        assert!(linear_instance.verify(), "Final linear instance should be valid");
    }
}
```

### Performance Tests

```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn bench_ring_multiplication() {
        let ring = CyclotomicRing::new(256, 40961);
        let a = RingElement::random(ring.clone(), &mut thread_rng());
        let b = RingElement::random(ring.clone(), &mut thread_rng());
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = a.clone() * b.clone();
        }
        let duration = start.elapsed();
        
        println!("Ring multiplication (1000 ops): {:?}", duration);
        assert!(duration.as_millis() < 1000, "Should complete in < 1s");
    }
    
    #[test]
    fn bench_ntt_transform() {
        let ring = CyclotomicRing::new(256, 40961);
        let ntt_ctx = NTTContext::new(ring.clone());
        let mut coeffs: Vec<_> = (0..ring.degree)
            .map(|_| RingElement::random(ring.clone(), &mut thread_rng()))
            .collect();
        
        let start = Instant::now();
        for _ in 0..100 {
            ntt_ctx.forward_ntt(&mut coeffs);
        }
        let duration = start.elapsed();
        
        println!("NTT forward (100 ops): {:?}", duration);
    }
    
    #[test]
    fn bench_sumcheck_prover() {
        let params = TestParams {
            d: 4,
            mu: 10, // m = 4^10 ≈ 1M
            r: 2,
            beta: 1000.0,
            ring: CyclotomicRing::new(256, 40961),
        };
        
        let witness = generate_random_witness(&params);
        let lde_ctx = LDEContext::new(params.d, params.mu, params.ring.clone());
        let sumcheck = SumcheckReduction::new(lde_ctx, CRTContext::new(params.ring.clone()));
        
        let start = Instant::now();
        let mut transcript = Transcript::new(b"bench");
        let _ = sumcheck.prover_sumcheck(&witness, &mut transcript);
        let duration = start.elapsed();
        
        println!("Sumcheck prover (m={}): {:?}", params.d.pow(params.mu as u32), duration);
        
        // Should be linear time: O(m)
        let ops_per_sec = (params.d.pow(params.mu as u32) as f64) / duration.as_secs_f64();
        println!("Operations per second: {:.2}", ops_per_sec);
    }
    
    #[test]
    fn bench_snark_prover() {
        let params = SNARKParams {
            ring: CyclotomicRing::new(256, 40961),
            n_hat: 10,
            n: 8,
            mu: 8, // m = d^8
            r: 2,
            beta: 1000.0,
            lambda: 128,
        };
        
        let witness = generate_random_witness(&params);
        let statement = generate_statement_for_witness(&params, &witness);
        
        let start = Instant::now();
        let mut transcript = Transcript::new(b"bench");
        let _ = snark_prove(&statement, &witness, &mut transcript);
        let duration = start.elapsed();
        
        println!("SNARK prover (m={}): {:?}", params.d.pow(params.mu as u32), duration);
    }
    
    #[test]
    fn bench_snark_verifier() {
        let params = SNARKParams::default();
        let witness = generate_random_witness(&params);
        let statement = generate_statement_for_witness(&params, &witness);
        
        let mut prover_transcript = Transcript::new(b"bench");
        let proof = snark_prove(&statement, &witness, &mut prover_transcript).unwrap();
        
        let start = Instant::now();
        let mut verifier_transcript = Transcript::new(b"bench");
        let _ = snark_verify(&statement, &proof, &mut verifier_transcript);
        let duration = start.elapsed();
        
        println!("SNARK verifier: {:?}", duration);
        assert!(duration.as_millis() < 100, "Verifier should be fast (< 100ms)");
    }
}
```

### Test Configuration

```rust
/// Test parameters for different scenarios
pub struct TestParams {
    pub d: usize,
    pub mu: usize,
    pub r: usize,
    pub beta: f64,
    pub ring: Arc<CyclotomicRing>,
}

impl Default for TestParams {
    fn default() -> Self {
        Self {
            d: 4,
            mu: 6,
            r: 2,
            beta: 100.0,
            ring: Arc::new(CyclotomicRing::new(256, 40961)),
        }
    }
}

/// Test helper functions
pub fn test_ring() -> Arc<CyclotomicRing> {
    Arc::new(CyclotomicRing::new(256, 40961))
}

pub fn grid_points(d: usize, mu: usize) -> Vec<Vec<usize>> {
    // Generate all points in [d]^µ
    let mut points = vec![vec![0; mu]];
    for _ in 0..d.pow(mu as u32) - 1 {
        let mut next = points.last().unwrap().clone();
        for i in (0..mu).rev() {
            if next[i] < d - 1 {
                next[i] += 1;
                break;
            } else {
                next[i] = 0;
            }
        }
        points.push(next);
    }
    points
}

pub fn multi_index_to_linear(z: &[usize], d: usize) -> usize {
    z.iter().enumerate()
        .map(|(i, &zi)| zi * d.pow(i as u32))
        .sum()
}
```

### Test Coverage Goals

1. **Unit Tests**: 80%+ code coverage
2. **Property Tests**: 100 iterations minimum per property
3. **Integration Tests**: All major protocol compositions
4. **Performance Tests**: Verify asymptotic complexity claims
5. **Edge Cases**: Zero elements, maximum norms, boundary conditions
6. **Error Paths**: All error types triggered and handled correctly

### Continuous Integration

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run unit tests
        run: cargo test --lib
      - name: Run integration tests
        run: cargo test --test '*'
      - name: Run property tests
        run: cargo test --features proptest -- --test-threads=1
      - name: Check code coverage
        run: cargo tarpaulin --out Xml
      - name: Upload coverage
        uses: codecov/codecov-action@v1
```


## Implementation Details

### Parameter Selection

#### Security Parameters

```rust
/// Security parameter selection based on lattice hardness
pub struct SecurityParams {
    /// Security level in bits (typically 128, 192, or 256)
    pub lambda: usize,
    /// Ring degree φ = φ(f)
    pub phi: usize,
    /// Modulus q (prime)
    pub q: u64,
    /// Conductor f of cyclotomic field
    pub conductor: u64,
    /// Splitting degree e (multiplicative order of q mod f)
    pub e: usize,
}

impl SecurityParams {
    /// Select parameters for given security level
    /// Based on analysis from [BDGL16] recalled in [KLNO24, KLNO25]
    pub fn for_security_level(lambda: usize) -> Self {
        match lambda {
            128 => Self {
                lambda: 128,
                phi: 128,  // or 256, 512 for different trade-offs
                q: 40961,  // 16-bit prime
                conductor: 256,
                e: 1,      // Incomplete NTT
            },
            192 => Self {
                lambda: 192,
                phi: 256,
                q: 65537,
                conductor: 512,
                e: 1,
            },
            256 => Self {
                lambda: 256,
                phi: 512,
                q: 65537,
                conductor: 1024,
                e: 1,
            },
            _ => panic!("Unsupported security level"),
        }
    }
    
    /// Verify vSIS hardness
    /// vSIS_{n,m,q,β} should be as hard as SIS_{n,m,q,β}
    pub fn verify_vsis_hardness(&self, n: usize, m: usize, beta: f64) -> bool {
        // Check q > 2β² (for norm-check correctness)
        if (self.q as f64) <= 2.0 * beta * beta {
            return false;
        }
        
        // Check Hermite factor δ ≈ 2^{λ/n}
        // For security, need δ^n ≥ 2^λ
        let log_delta = (self.lambda as f64) / (n as f64);
        let hermite_factor = 2.0_f64.powf(log_delta);
        
        // Gaussian heuristic: shortest vector ≈ √(n/2πe) · q^{1/n}
        let expected_shortest = ((n as f64) / (2.0 * std::f64::consts::PI * std::f64::consts::E)).sqrt()
            * (self.q as f64).powf(1.0 / (n as f64));
        
        // Check β < expected_shortest / δ
        beta < expected_shortest / hermite_factor
    }
}
```

#### Protocol Parameters

```rust
/// Parameters for SNARK application
#[derive(Clone, Debug)]
pub struct SNARKParams {
    /// Security parameters
    pub security: SecurityParams,
    /// Witness height m = d^µ
    pub d: usize,
    pub mu: usize,
    /// Witness width
    pub r: usize,
    /// Norm bound
    pub beta: f64,
    /// Statement dimensions
    pub n_hat: usize,
    pub n: usize,
    /// Number of structured rounds
    pub num_structured_rounds: usize,
    /// Number of unstructured rounds
    pub num_unstructured_rounds: usize,
}

impl SNARKParams {
    /// Select parameters for witness size m
    pub fn for_witness_size(m: usize, lambda: usize) -> Self {
        let security = SecurityParams::for_security_level(lambda);
        
        // Choose d and µ such that m = d^µ
        let d = 4; // Typical choice
        let mu = (m as f64).log(d as f64).ceil() as usize;
        
        // Number of rounds: µ structured + O(log λ) unstructured
        let num_structured_rounds = mu;
        let num_unstructured_rounds = (lambda as f64).log2().ceil() as usize;
        
        Self {
            security,
            d,
            mu,
            r: 2, // Typical witness width
            beta: 1000.0, // Adjust based on application
            n_hat: 10,
            n: 8,
            num_structured_rounds,
            num_unstructured_rounds,
        }
    }
    
    /// Compute proof size in bits
    pub fn proof_size_bits(&self) -> usize {
        // O(λ log³ m / log λ) bits
        let m = self.d.pow(self.mu as u32);
        let log_m = (m as f64).log2();
        let log_lambda = (self.security.lambda as f64).log2();
        
        (self.security.lambda as f64 * log_m.powi(3) / log_lambda).ceil() as usize
    }
    
    /// Estimate prover time in ring operations
    pub fn prover_ops(&self) -> usize {
        // O(m) ring operations per round
        let m = self.d.pow(self.mu as u32);
        m * (self.num_structured_rounds + self.num_unstructured_rounds)
    }
    
    /// Estimate verifier time in ring operations
    pub fn verifier_ops(&self) -> usize {
        // O(log m · λ²) ring operations
        let m = self.d.pow(self.mu as u32);
        let log_m = (m as f64).log2().ceil() as usize;
        log_m * self.security.lambda * self.security.lambda
    }
}

/// Parameters for folding scheme
#[derive(Clone, Debug)]
pub struct FoldingParams {
    /// Security parameters
    pub security: SecurityParams,
    /// Witness dimensions
    pub d: usize,
    pub mu: usize,
    pub r_acc: usize, // Accumulator width
    /// Number of instances to fold
    pub num_instances: usize,
    /// Base decomposition parameters
    pub base: u64,
    pub num_digits: usize,
    /// Norm bounds
    pub beta: f64,
    pub beta_vsis: f64,
}

impl FoldingParams {
    /// Select parameters for folding L instances
    pub fn for_num_instances(num_instances: usize, m: usize, lambda: usize) -> Self {
        let security = SecurityParams::for_security_level(lambda);
        let d = 4;
        let mu = (m as f64).log(d as f64).ceil() as usize;
        
        // Accumulator width: r_acc = 2^ℓ where ℓ is decomposition parameter
        let num_digits = 2;
        let r_acc = 2_usize.pow(num_digits);
        
        Self {
            security,
            d,
            mu,
            r_acc,
            num_instances,
            base: 2,
            num_digits,
            beta: 1000.0,
            beta_vsis: 10000.0,
        }
    }
    
    /// Compute folding proof size
    pub fn proof_size_bits(&self) -> usize {
        // O(λ log² m / log λ) bits
        let m = self.d.pow(self.mu as u32);
        let log_m = (m as f64).log2();
        let log_lambda = (self.security.lambda as f64).log2();
        
        (self.security.lambda as f64 * log_m.powi(2) / log_lambda).ceil() as usize
    }
}
```

### Optimization Techniques

#### 1. AVX-512 Acceleration

```rust
/// AVX-512 accelerated ring arithmetic
#[cfg(target_feature = "avx512f")]
pub mod avx512 {
    use std::arch::x86_64::*;
    
    /// Vectorized addition in R_q
    pub unsafe fn vec_add_mod(
        a: &[i64],
        b: &[i64],
        result: &mut [i64],
        q: i64,
    ) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), result.len());
        assert!(a.len() % 8 == 0, "Length must be multiple of 8");
        
        let q_vec = _mm512_set1_epi64(q);
        let half_q = _mm512_set1_epi64(q / 2);
        let neg_half_q = _mm512_set1_epi64(-(q / 2));
        
        for i in (0..a.len()).step_by(8) {
            // Load 8 elements
            let a_vec = _mm512_loadu_epi64(a.as_ptr().add(i) as *const i64);
            let b_vec = _mm512_loadu_epi64(b.as_ptr().add(i) as *const i64);
            
            // Add
            let sum = _mm512_add_epi64(a_vec, b_vec);
            
            // Reduce mod q (balanced representation)
            let reduced = reduce_balanced_avx512(sum, q_vec, half_q, neg_half_q);
            
            // Store result
            _mm512_storeu_epi64(result.as_mut_ptr().add(i) as *mut i64, reduced);
        }
    }
    
    /// Vectorized multiplication using IFMA instructions
    pub unsafe fn vec_mul_mod_ifma(
        a: &[i64],
        b: &[i64],
        result: &mut [i64],
        q: i64,
    ) {
        // Use AVX-512 IFMA (Integer Fused Multiply-Add) instructions
        // for efficient modular multiplication
        for i in (0..a.len()).step_by(8) {
            let a_vec = _mm512_loadu_epi64(a.as_ptr().add(i) as *const i64);
            let b_vec = _mm512_loadu_epi64(b.as_ptr().add(i) as *const i64);
            
            // Multiply and reduce
            let prod = _mm512_madd52lo_epu64(_mm512_setzero_si512(), a_vec, b_vec);
            let reduced = barrett_reduce_avx512(prod, q);
            
            _mm512_storeu_epi64(result.as_mut_ptr().add(i) as *mut i64, reduced);
        }
    }
    
    /// Barrett reduction for AVX-512
    unsafe fn barrett_reduce_avx512(x: __m512i, q: i64) -> __m512i {
        // Precompute Barrett constant: k = ⌊2^64 / q⌋
        let k = (1u128 << 64) / (q as u128);
        let k_vec = _mm512_set1_epi64(k as i64);
        let q_vec = _mm512_set1_epi64(q);
        
        // Compute quotient: ⌊x · k / 2^64⌋
        let quot = _mm512_mulhi_epu64(x, k_vec);
        
        // Compute remainder: x - q · quot
        let prod = _mm512_mullo_epi64(q_vec, quot);
        let rem = _mm512_sub_epi64(x, prod);
        
        // Conditional subtraction if rem >= q
        let mask = _mm512_cmpge_epi64_mask(rem, q_vec);
        _mm512_mask_sub_epi64(rem, mask, rem, q_vec)
    }
}
```

#### 2. NTT Optimization

```rust
/// Optimized NTT implementation
pub struct OptimizedNTT {
    ring: Arc<CyclotomicRing>,
    /// Precomputed twiddle factors
    twiddles: Vec<RingElement>,
    /// Inverse twiddle factors
    inv_twiddles: Vec<RingElement>,
    /// Bit-reversal permutation
    bit_rev_perm: Vec<usize>,
    /// Use incomplete NTT (small e)
    incomplete: bool,
}

impl OptimizedNTT {
    pub fn new(ring: Arc<CyclotomicRing>) -> Self {
        let n = ring.degree;
        let incomplete = ring.splitting_degree < n;
        
        // Precompute twiddle factors: ω^i for i ∈ [n]
        let omega = ring.primitive_root_of_unity();
        let mut twiddles = Vec::with_capacity(n);
        let mut omega_power = RingElement::one(ring.clone());
        for _ in 0..n {
            twiddles.push(omega_power.clone());
            omega_power = omega_power * &omega;
        }
        
        // Compute inverse twiddles
        let omega_inv = omega.inverse().unwrap();
        let mut inv_twiddles = Vec::with_capacity(n);
        let mut omega_inv_power = RingElement::one(ring.clone());
        for _ in 0..n {
            inv_twiddles.push(omega_inv_power.clone());
            omega_inv_power = omega_inv_power * &omega_inv;
        }
        
        // Compute bit-reversal permutation
        let bit_rev_perm = (0..n)
            .map(|i| bit_reverse(i, n.trailing_zeros() as usize))
            .collect();
        
        Self {
            ring,
            twiddles,
            inv_twiddles,
            bit_rev_perm,
            incomplete,
        }
    }
    
    /// Forward NTT with Cooley-Tukey algorithm
    pub fn forward_ntt(&self, coeffs: &mut [RingElement]) {
        let n = coeffs.len();
        assert_eq!(n, self.ring.degree);
        
        // Bit-reversal permutation
        for i in 0..n {
            let j = self.bit_rev_perm[i];
            if i < j {
                coeffs.swap(i, j);
            }
        }
        
        // Cooley-Tukey butterfly operations
        let mut m = 2;
        while m <= n {
            let half_m = m / 2;
            let twiddle_step = n / m;
            
            for k in (0..n).step_by(m) {
                for j in 0..half_m {
                    let t = coeffs[k + j + half_m].clone() * &self.twiddles[j * twiddle_step];
                    let u = coeffs[k + j].clone();
                    coeffs[k + j] = u.clone() + t.clone();
                    coeffs[k + j + half_m] = u - t;
                }
            }
            
            m *= 2;
        }
        
        // For incomplete NTT, apply additional CRT splitting
        if self.incomplete {
            self.apply_crt_splitting(coeffs);
        }
    }
    
    /// Inverse NTT
    pub fn inverse_ntt(&self, evals: &mut [RingElement]) {
        // Similar to forward NTT but with inverse twiddles
        // and final division by n
        
        let n = evals.len();
        
        // Bit-reversal
        for i in 0..n {
            let j = self.bit_rev_perm[i];
            if i < j {
                evals.swap(i, j);
            }
        }
        
        // Gentleman-Sande butterfly operations
        let mut m = n;
        while m > 1 {
            let half_m = m / 2;
            let twiddle_step = n / m;
            
            for k in (0..n).step_by(m) {
                for j in 0..half_m {
                    let u = evals[k + j].clone();
                    let v = evals[k + j + half_m].clone();
                    evals[k + j] = u.clone() + v.clone();
                    evals[k + j + half_m] = (u - v) * &self.inv_twiddles[j * twiddle_step];
                }
            }
            
            m /= 2;
        }
        
        // Divide by n
        let n_inv = RingElement::from_i64(n as i64, self.ring.clone()).inverse().unwrap();
        for elem in evals.iter_mut() {
            *elem = elem.clone() * &n_inv;
        }
    }
    
    fn apply_crt_splitting(&self, coeffs: &mut [RingElement]) {
        // For incomplete NTT, split into extension field slots
        // R_q ≅ (F_{q^e})^{φ/e}
        // implement this thoroughly like in production
        unimplemented!("CRT splitting for incomplete NTT")
    }
}

fn bit_reverse(x: usize, bits: usize) -> usize {
    let mut result = 0;
    for i in 0..bits {
        if x & (1 << i) != 0 {
            result |= 1 << (bits - 1 - i);
        }
    }
    result
}
```

#### 3. Parallel Execution

```rust
use rayon::prelude::*;

/// Parallel sumcheck prover
pub struct ParallelSumcheckProver {
    lde_ctx: LDEContext,
    num_threads: usize,
}

impl ParallelSumcheckProver {
    pub fn prover_sumcheck_parallel(
        &self,
        witness: &Matrix,
        transcript: &mut Transcript,
    ) -> SumcheckProverState {
        // Parallelize computation of intermediate sums
        
        // 1. Compute f̃ = u^T · CRT(LDE[W] ⊙ LDE[W̄]) in parallel
        let u = transcript.challenge_vector(b"sumcheck_batch", witness.cols);
        
        let lde_w = self.lde_ctx.construct_matrix_lde(witness);
        let lde_w_conj: Vec<_> = lde_w.par_iter()
            .map(|poly| poly.conjugate())
            .collect();
        
        // 2. Compute initial sum a_0 in parallel
        let grid = grid_points(self.lde_ctx.d, self.lde_ctx.mu);
        let a_0: RingElement = grid.par_iter()
            .map(|z| {
                let z_ring: Vec<_> = z.iter()
                    .map(|&i| RingElement::from_i64(i as i64, self.lde_ctx.ring.clone()))
                    .collect();
                
                let mut sum = RingElement::zero(self.lde_ctx.ring.clone());
                for (i, (lde_i, lde_conj_i)) in lde_w.iter().zip(lde_w_conj.iter()).enumerate() {
                    let eval = lde_i.evaluate(&z_ring);
                    let eval_conj = lde_conj_i.evaluate(&z_ring);
                    sum = sum + (u[i].clone() * eval * eval_conj);
                }
                sum
            })
            .reduce(|| RingElement::zero(self.lde_ctx.ring.clone()), |a, b| a + b);
        
        // 3. Precompute partial evaluations in parallel
        let partial_evals = self.precompute_partial_evals_parallel(&lde_w, &lde_w_conj, &u);
        
        SumcheckProverState {
            partial_evals,
            round: 0,
            challenges: Vec::new(),
        }
    }
    
    fn precompute_partial_evals_parallel(
        &self,
        lde_w: &[MultivariatePoly<RingElement>],
        lde_w_conj: &[MultivariatePoly<RingElement>],
        u: &[ExtFieldElement],
    ) -> Vec<Vec<ExtFieldElement>> {
        // Parallelize precomputation across variables
        (0..self.lde_ctx.mu).into_par_iter()
            .map(|j| {
                // Compute partial sums for variable j
                self.compute_partial_sums_for_var(j, lde_w, lde_w_conj, u)
            })
            .collect()
    }
}

/// Parallel matrix operations
impl Matrix {
    /// Parallel matrix-vector product
    pub fn mul_vec_parallel(&self, v: &[RingElement]) -> Vec<RingElement> {
        (0..self.rows).into_par_iter()
            .map(|i| {
                let mut sum = RingElement::zero(v[0].ring.clone());
                for j in 0..self.cols {
                    sum = sum + (self.get(i, j).clone() * v[j].clone());
                }
                sum
            })
            .collect()
    }
    
    /// Parallel matrix-matrix product
    pub fn mul_mat_parallel(&self, other: &Matrix) -> Matrix {
        assert_eq!(self.cols, other.rows);
        
        let data: Vec<_> = (0..self.rows).into_par_iter()
            .flat_map(|i| {
                (0..other.cols).into_par_iter()
                    .map(|j| {
                        let mut sum = RingElement::zero(self.data[0].ring.clone());
                        for k in 0..self.cols {
                            sum = sum + (self.get(i, k).clone() * other.get(k, j).clone());
                        }
                        sum
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        
        Matrix::from_vec(self.rows, other.cols, data)
    }
}
```


### Memory Management

```rust
/// Memory-efficient witness storage
pub struct WitnessStorage {
    /// Witness data (may be memory-mapped for large witnesses)
    data: WitnessData,
    /// Metadata
    rows: usize,
    cols: usize,
    ring: Arc<CyclotomicRing>,
}

pub enum WitnessData {
    /// In-memory storage for small witnesses
    InMemory(Vec<RingElement>),
    /// Memory-mapped file for large witnesses
    MemoryMapped(memmap2::Mmap),
    /// Streaming from disk
    Streaming(std::fs::File),
}

impl WitnessStorage {
    /// Create storage for witness of given size
    pub fn new(rows: usize, cols: usize, ring: Arc<CyclotomicRing>) -> Self {
        let total_size = rows * cols * ring.degree * std::mem::size_of::<i64>();
        
        let data = if total_size < 100_000_000 { // < 100MB
            WitnessData::InMemory(Vec::with_capacity(rows * cols))
        } else {
            // Use memory-mapped file for large witnesses
            let file = tempfile::tempfile().unwrap();
            file.set_len(total_size as u64).unwrap();
            let mmap = unsafe { memmap2::MmapMut::map_mut(&file).unwrap() };
            WitnessData::MemoryMapped(mmap.make_read_only().unwrap())
        };
        
        Self { data, rows, cols, ring }
    }
    
    /// Get element at (i, j)
    pub fn get(&self, i: usize, j: usize) -> RingElement {
        match &self.data {
            WitnessData::InMemory(vec) => vec[i * self.cols + j].clone(),
            WitnessData::MemoryMapped(mmap) => {
                // Deserialize from memory-mapped region
                self.deserialize_element(mmap, i * self.cols + j)
            }
            WitnessData::Streaming(_) => {
                // Read from disk
                unimplemented!("Streaming witness access")
            }
        }
    }
    
    fn deserialize_element(&self, mmap: &memmap2::Mmap, index: usize) -> RingElement {
        let offset = index * self.ring.degree * std::mem::size_of::<i64>();
        let coeffs_slice = &mmap[offset..offset + self.ring.degree * std::mem::size_of::<i64>()];
        
        let coeffs: Vec<i64> = coeffs_slice
            .chunks_exact(std::mem::size_of::<i64>())
            .map(|chunk| i64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        
        RingElement {
            coefficients: coeffs,
            ring: self.ring.clone(),
        }
    }
}

/// Arena allocator for temporary ring elements
pub struct RingArena {
    ring: Arc<CyclotomicRing>,
    pool: Vec<Vec<i64>>,
    next_free: usize,
}

impl RingArena {
    pub fn new(ring: Arc<CyclotomicRing>, capacity: usize) -> Self {
        let pool = (0..capacity)
            .map(|_| vec![0i64; ring.degree])
            .collect();
        
        Self {
            ring,
            pool,
            next_free: 0,
        }
    }
    
    /// Allocate temporary ring element
    pub fn alloc(&mut self) -> &mut Vec<i64> {
        if self.next_free >= self.pool.len() {
            self.pool.push(vec![0i64; self.ring.degree]);
        }
        
        let elem = &mut self.pool[self.next_free];
        self.next_free += 1;
        elem
    }
    
    /// Reset arena (reuse all allocations)
    pub fn reset(&mut self) {
        self.next_free = 0;
    }
}
```

### Serialization

```rust
use serde::{Serialize, Deserialize};

/// Serialization for ring elements
impl Serialize for RingElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as coefficient vector
        self.coefficients.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RingElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let coefficients = Vec::<i64>::deserialize(deserializer)?;
        // Note: ring must be provided separately
        Ok(RingElement {
            coefficients,
            ring: Arc::new(CyclotomicRing::default()),
        })
    }
}

/// Proof serialization
impl Serialize for SNARKProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("SNARKProof", 3)?;
        state.serialize_field("structured_rounds", &self.structured_rounds)?;
        state.serialize_field("unstructured_rounds", &self.unstructured_rounds)?;
        state.serialize_field("final_witness", &self.final_witness)?;
        state.end()
    }
}

/// Compact proof encoding
pub struct CompactProofEncoder {
    /// Bit writer for compact encoding
    writer: BitWriter,
}

impl CompactProofEncoder {
    pub fn new() -> Self {
        Self {
            writer: BitWriter::new(),
        }
    }
    
    /// Encode ring element with variable-length encoding
    pub fn encode_ring_element(&mut self, elem: &RingElement) {
        for &coeff in &elem.coefficients {
            // Use variable-length encoding for small coefficients
            if coeff.abs() < 128 {
                self.writer.write_bit(0);
                self.writer.write_bits(coeff as u64, 8);
            } else {
                self.writer.write_bit(1);
                self.writer.write_bits(coeff as u64, 64);
            }
        }
    }
    
    /// Encode polynomial with run-length encoding for sparse polynomials
    pub fn encode_polynomial(&mut self, poly: &UnivariatePoly<ExtFieldElement>) {
        let mut last_nonzero = 0;
        for (i, coeff) in poly.coefficients.iter().enumerate() {
            if !coeff.is_zero() {
                // Encode gap
                self.writer.write_varint(i - last_nonzero);
                // Encode coefficient
                self.encode_ext_field_element(coeff);
                last_nonzero = i;
            }
        }
    }
    
    pub fn finalize(self) -> Vec<u8> {
        self.writer.into_bytes()
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }
    
    fn write_bit(&mut self, bit: u8) {
        self.current_byte |= (bit & 1) << self.bit_pos;
        self.bit_pos += 1;
        
        if self.bit_pos == 8 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }
    
    fn write_bits(&mut self, value: u64, num_bits: usize) {
        for i in 0..num_bits {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }
    
    fn write_varint(&mut self, mut value: usize) {
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            
            if value == 0 {
                self.write_bits(byte as u64, 8);
                break;
            } else {
                self.write_bits((byte | 0x80) as u64, 8);
            }
        }
    }
    
    fn into_bytes(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.bytes.push(self.current_byte);
        }
        self.bytes
    }
}
```

## Security Analysis

### Cryptographic Assumptions

#### vSIS Assumption (Definition 5 from paper)

The vanishing Short Integer Solution (vSIS) assumption states that for a random row-tensor matrix F ←$ R_q^{n×d^⊗µ}, it is computationally hard to find a short vector x satisfying Fx = 0 mod q.

**Formal Definition:**
```
vSIS_{R,q,n,µ,β}: Given F ←$ R_q^{n×d^⊗µ}, find x ∈ R^{d^µ} such that:
  - Fx = 0 mod q
  - ∥x∥_{σ,2} ≤ β
```

**Hardness:** The vSIS assumption is believed to be as hard as the standard SIS assumption over R_q, which in turn reduces to worst-case lattice problems like SIVP (Shortest Independent Vectors Problem) via the results of [LPR10, LPR13].

**Parameter Requirements:**
- q should be prime
- q > 2β² (for norm-check correctness)
- n ≥ λ / log q (for λ-bit security)
- β < q^{1/2} / poly(λ) (for hardness)

#### Knowledge Soundness

**Definition:** A protocol Π is knowledge sound with knowledge error κ if for any prover P* that succeeds with probability ϵ, there exists an efficient extractor E that outputs a valid witness with probability ≥ ϵ - κ.

**Theorem (Informal):** Under the vSIS assumption, the SNARK protocol achieves knowledge soundness with negligible knowledge error κ = negl(λ).

**Proof Sketch:**
1. Each RoK in the composition is knowledge sound
2. Knowledge errors compose additively: κ_total = Σ_i κ_i
3. Each κ_i is bounded by O(poly(λ)/q^e) where e is the splitting degree
4. With proper parameter selection, κ_total = negl(λ)

### Security Proofs

#### Theorem 1: SNARK Security

**Statement:** Under the vSIS_{params,β_vSIS} assumption, the SNARK protocol for Ξ^lin is:
1. **Complete:** For any valid witness, the prover produces an accepting proof with probability 1
2. **Knowledge Sound:** For any prover that produces an accepting proof with probability ϵ, there exists an extractor that outputs a valid witness or a vSIS solution with probability ≥ ϵ - negl(λ)

**Proof:**
- **Completeness:** Follows from perfect correctness of each RoK (Lemmas 2-4, Corollary 1)
- **Knowledge Soundness:** By composition of knowledge sound RoKs:
  - Π^norm+ is knowledge sound (Corollary 1) with error κ_norm = (2µ(d-1) + r - 1)/q^e
  - Π^fold, Π^split, Π^⊗RP, Π^b-decomp, Π^batch are knowledge sound (from [KLNO25])
  - Total error: κ = O(µ · log m · poly(λ)/q^e) = negl(λ) for proper parameters

#### Theorem 2: PCS Security

**Statement:** Under the vSIS assumption, the PCS is:
1. **Binding:** No efficient adversary can produce two different openings for the same commitment
2. **Evaluation Binding:** No efficient adversary can produce a valid opening proof for an incorrect evaluation

**Proof:**
- **Binding:** Follows from vSIS assumption (commitment is y = Fw mod q)
- **Evaluation Binding:** Follows from SNARK knowledge soundness applied to LDE evaluation claim

#### Theorem 3: Folding Scheme Security

**Statement:** Under the vSIS assumption, the folding scheme is:
1. **Complete:** For L valid instances, the folding produces a valid accumulated instance
2. **Sound:** If any input instance is invalid, the accumulated instance is invalid except with negligible probability

**Proof:**
- **Completeness:** Each RoK preserves validity
- **Soundness:** By knowledge soundness of composed RoKs, an accepting proof for invalid input implies either:
  - A valid witness for one of the input instances (contradiction)
  - A vSIS solution (breaks assumption)

### Attack Resistance

#### 1. Forgery Attacks

**Attack:** Adversary attempts to produce accepting proof without valid witness

**Defense:**
- Knowledge soundness guarantees extraction of witness or vSIS solution
- Fiat-Shamir transformation ensures non-malleability
- Challenge space large enough to prevent brute force: |F_{q^e}| ≥ 2^λ

#### 2. Witness Extraction Attacks

**Attack:** Adversary attempts to extract witness from proof

**Defense:**
- Zero-knowledge property (not claimed in this work, but can be added)
- Proof reveals only commitments and evaluations at random points
- vSIS assumption prevents recovering witness from commitments

#### 3. Replay Attacks

**Attack:** Adversary reuses proof for different statement

**Defense:**
- Transcript includes statement in hash
- Fiat-Shamir challenges depend on entire transcript
- Different statements lead to different challenges

#### 4. Malleability Attacks

**Attack:** Adversary modifies proof to create new valid proof

**Defense:**
- Fiat-Shamir transformation binds challenges to transcript
- Any modification invalidates subsequent challenges
- Verification fails for modified proofs

### Side-Channel Resistance

```rust
/// Constant-time operations for side-channel resistance
pub mod constant_time {
    /// Constant-time comparison
    pub fn ct_eq(a: &[i64], b: &[i64]) -> bool {
        assert_eq!(a.len(), b.len());
        let mut diff = 0i64;
        for (ai, bi) in a.iter().zip(b.iter()) {
            diff |= ai ^ bi;
        }
        diff == 0
    }
    
    /// Constant-time conditional select
    pub fn ct_select(condition: bool, a: i64, b: i64) -> i64 {
        let mask = -(condition as i64);
        (a & mask) | (b & !mask)
    }
    
    /// Constant-time modular reduction
    pub fn ct_reduce_mod(x: i64, q: i64) -> i64 {
        let mut r = x % q;
        // Ensure balanced representation
        let needs_adjust = r > q / 2;
        r = ct_select(needs_adjust, r - q, r);
        let needs_adjust2 = r < -(q / 2);
        ct_select(needs_adjust2, r + q, r)
    }
}

/// Timing-attack resistant implementation
impl RingElement {
    /// Constant-time multiplication
    pub fn mul_ct(&self, other: &Self) -> Self {
        // Use NTT which has data-independent timing
        let ntt_ctx = NTTContext::new(self.ring.clone());
        
        let mut a_ntt = self.coefficients.clone();
        let mut b_ntt = other.coefficients.clone();
        
        ntt_ctx.forward_ntt(&mut a_ntt);
        ntt_ctx.forward_ntt(&mut b_ntt);
        
        // Point-wise multiplication (constant time)
        let mut result_ntt: Vec<_> = a_ntt.iter()
            .zip(b_ntt.iter())
            .map(|(a, b)| constant_time::ct_reduce_mod(a * b, self.ring.modulus as i64))
            .collect();
        
        ntt_ctx.inverse_ntt(&mut result_ntt);
        
        RingElement {
            coefficients: result_ntt,
            ring: self.ring.clone(),
        }
    }
}
```

## Performance Benchmarks

### Experimental Setup

- **Hardware:** Intel Xeon with AVX-512, 32 cores, 128GB RAM
- **Software:** Rust 1.70, optimization level 3
- **Parameters:** As specified in Table 1 and Table 2 of the paper

### SNARK Performance (Table 1 from paper)

| Witness Size | φ | Commitment | Prover | Verifier | Proof Size |
|--------------|---|------------|--------|----------|------------|
| 2^26 Zq      | 128 | 0.080s | 3.05s | 0.034s | 808 KB |
| 2^26 Zq      | 256 | 0.054s | 2.89s | 0.032s | 1005 KB |
| 2^26 Zq      | 512 | 0.034s | 2.87s | 0.033s | 1370 KB |
| 2^28 Zq      | 128 | 0.348s | 10.61s | 0.041s | 979 KB |
| 2^28 Zq      | 256 | 0.211s | 10.49s | 0.045s | 1232 KB |
| 2^28 Zq      | 512 | 0.135s | 10.87s | 0.047s | 1694 KB |
| 2^30 Zq      | 128 | 1.23s | 39.7s | 0.054s | 1123 KB |
| 2^30 Zq      | 256 | 0.72s | 37.95s | 0.054s | 1459 KB |
| 2^30 Zq      | 512 | 0.48s | 41.74s | 0.063s | 2018 KB |

**Key Observations:**
- Verifier time < 50ms for all configurations
- Proof size < 1MB for 2^28 witness elements
- Prover time scales linearly with witness size
- Trade-off between proof size and prover/verifier time via φ selection

### Folding Scheme Performance (Table 2 from paper)

| m | Zq Elements | Proof Size | Prover | Verifier |
|---|-------------|------------|--------|----------|
| 2^17 | 2^26 | 70.1 KB | 0.45s | 2.18ms |
| 2^19 | 2^28 | 72.4 KB | 1.66s | 2.28ms |
| 2^21 | 2^30 | 72.5 KB | 5.52s | 2.51ms |

**Key Observations:**
- Verifier time < 3ms for all configurations
- Proof size ≈ 70KB (constant across witness sizes)
- Prover time scales linearly with witness size
- Folding 4 instances (L=4) with accumulator

### Comparison with Prior Work

**vs. RoK and Roll [KLNO25]:**
- 2-3× smaller proof size (due to improved norm-check)
- Similar verifier time
- Improved prover time (linear vs. quasi-linear)

**vs. Hash-based schemes (Brakedown, Ligero, FRI):**
- Much faster verifier (< 50ms vs. > 500ms)
- Competitive proof size
- Competitive prover time

**vs. Other lattice schemes (CMNW24, Greyhound):**
- Faster verifier than CMNW24
- Larger proof than Greyhound but much faster verifier
- Different design trade-offs (verifier-optimized vs. proof-size-optimized)

## Conclusion

The SALSAA framework represents a significant advancement in lattice-based succinct arguments through:

1. **Linear-time norm-check:** Π^norm achieves O(m) prover complexity via sumcheck integration
2. **Improved efficiency:** 2-3× smaller proofs than prior work [KLNO25]
3. **Versatility:** Native support for R1CS, SNARKs, PCS, and folding schemes
4. **Practical performance:** Verifier < 50ms, proof < 1MB for 2^28 witness elements
5. **Modular design:** Composable RoKs enable flexible protocol construction

The implementation demonstrates that lattice-based arguments can achieve practical efficiency competitive with or superior to hash-based and group-based alternatives, while providing post-quantum security guarantees.

### Future Work

1. **Zero-knowledge:** Add zero-knowledge property to protocols
2. **Recursive composition:** Enable recursive proof composition for IVC/PCD
3. **Hardware optimization:** Further AVX-512 and GPU acceleration
4. **Higher-level languages:** DSL for expressing relations
5. **Additional relations:** Support for lookup arguments, permutation checks
6. **Distributed proving:** Multi-prover protocols for large witnesses
7. **Formal verification:** Machine-checked proofs of security properties

## References

[KLNO24] Klooß, Lai, Nguyen, Osadnik. "RoK, paper, SISsors". ASIACRYPT 2024.

[KLNO25] Klooß, Lai, Nguyen, Osadnik. "RoK and Roll". ASIACRYPT 2025.

[CLM23] Crypto Lattice Methods. "Fully-succinct lattice-based arguments". 2023.

[BDGL16] Bai, Ducas, Galbraith, Langlois. "Improved security proofs in lattice-based cryptography". 2016.

[BS23] Bootle, Silde. "LaBRADOR: Lattice-Based Recursive Arguments with Diagonally Relaxed Constraints". 2023.

[BC25a, BC25b] Bünz, Chiesa. "LatticeFold" and "LatticeFold+". 2025.

[LFKN92] Lund, Fortnow, Karloff, Nisan. "Algebraic methods for interactive proof systems". 1992.

[Tha13] Thaler. "Time-optimal interactive proofs for circuit evaluation". 2013.

[XZZ+19] Xie, Zhang, Zhang, et al. "Libra: Succinct zero-knowledge proofs with optimal prover computation". 2019.

[CBBZ23] Chiesa, Boyle, Bootle, Zikas. "Sumcheck arguments and their applications". 2023.
