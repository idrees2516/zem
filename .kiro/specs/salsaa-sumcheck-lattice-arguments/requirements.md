# Requirements Document

## Introduction

SALSAA (Sumcheck-Aided Lattice-based Succinct Arguments and Applications) is an advanced cryptographic framework that extends the state-of-the-art lattice-based fully-succinct argument frameworks "RoK, paper, SISsors (RPS)" and "RoK and Roll (RnR)" by integrating the sumcheck technique as a main component. This integration enables:

1. An efficient norm-check protocol with a strictly linear-time prover (vs. quasi-linear in prior work)
2. 2-3× smaller proof sizes compared to previous norm-check protocols  
3. Native support for a wider class of relations including R1CS (Rank-1 Constraint Systems)
4. Three key applications: SNARK, Polynomial Commitment Scheme (PCS), and Folding Scheme

The framework operates over cyclotomic rings with post-quantum security guarantees based on the vanishing Short Integer Solution (vSIS) assumption. The key innovation is expressing norm-check claims as sumcheck claims over low-degree extensions, enabling linear-time prover complexity.

### Key Performance Targets (from paper benchmarks)
- SNARK: Verifier time 41ms, Prover time 10.61s, Proof size 979KB for 2^28 Z_q elements (φ=128)
- Folding: Verifier time 2.28ms, Proof size 72.4KB for 2^28 Z_q elements with L=4 instances
- First lattice-based SNARK with verification < 50ms and proof size < 1MB for 2^28 elements

## Glossary

### Core Mathematical Objects

- **λ ∈ ℕ**: Security parameter
- **[n]**: Set {0, 1, ..., n-1} counting from 0
- **[m:n]**: Set [n] \ [m] = {m, m+1, ..., n-1}
- **Z_q**: Integers modulo q using balanced representation {-⌈q/2⌉+1, ..., ⌊q/2⌋}
- **K = Q(ζ)**: Cyclotomic field with conductor f of degree φ = φ(f), where ζ is primitive f-th root of unity
- **R = O_K = Z[ζ]**: Ring of integers of K
- **R_q := R/qR**: Quotient ring (q always prime)
- **R× and R_q×**: Sets of units in R and R_q respectively
- **σ: K → C^φ**: Canonical embedding where σ(x) := (σ_j(x))_{j∈[φ]} with σ_j ∈ Gal(K/Q)
- **cf_b(x)**: Coefficient vector (x_i)_{i∈[φ]} for x = Σ_{i∈[φ]} x_i b_i given Z-basis b = (b_i)_{i∈[φ]}
- **∥x∥_{σ,p}**: ℓ_p-norm over canonical embedding: ∥σ(x)∥_p for x ∈ R^m
- **∥M∥_{σ,p}**: Matrix norm: max_{i∈[n]} ∥m_i∥_{σ,p} where m_i is i-th column
- **Trace_{M/L}**: Field trace: Σ_{σ_j ∈ Gal(K/L)} σ_j(x), write Trace = Trace_{K/Q}
- **x̄**: Complex conjugate of x ∈ K
- **⟨x, y⟩**: Inner product Σ_{j∈[m]} x_j · ȳ_j for vectors x, y ∈ K^m

### Ring Splitting and CRT
- **e**: Multiplicative order of q modulo f (q^e ≡ 1 mod f)
- **CRT: R_q → (F_{q^e})^{φ/e}**: Chinese Remainder Theorem isomorphism when q has order e mod f
- **CRT^{-1}: (F_{q^e})^{φ/e} → R_q**: Inverse CRT isomorphism
- **CRT(x): R_q^m → (F_{q^e})^{mφ/e}**: Extended CRT to vectors (concatenation)
- **CRT: R_q^r[x^µ] → F_{q^e}^{rφ/e}[x^µ]**: Extended CRT to polynomials (coefficient-wise)

### Matrix and Tensor Notation
- **v**: Bold lowercase for vectors
- **M**: Bold uppercase for matrices
- **(M_i)_{i∈[k]}**: Horizontal concatenation of matrices
- **0_r, 1_r**: r-dimensional vectors of all 0s or 1s
- **e_{i,r}**: Unit vector equal to 0_r except 1 at position i
- **E_{i,j,m,n}**: Unit matrix (simplified to E_{i,j})
- **•**: Row-wise Kronecker product (face-splitting product)
- **⊗**: Standard Kronecker product
- **F ∈ R_q^{n×d^⊗µ}**: Row-tensor matrix F = F_0 • F_1 • ... • F_{µ-1} where F_i ∈ R_q^{n×d}
- **⊙**: Element-wise (Hadamard) product

### Relations
- **Ξ^lin_{n̂,n,µ,r,β}**: Principal linear relation with parameters (n̂, n, µ, r, β)
- **Ξ^sis_{R,q,m,n̂,r,β}**: SIS break relation
- **Ξ^lde_{n̂,n,µ,µ̃,r,β,t}**: Low-degree extension relation with t evaluation claims
- **Ξ^lde-⊗**: Structured LDE relation (matrices have tensor structure)
- **Ξ^sum_{n̂,n,µ,r,β}**: Sumcheck relation
- **Ξ^norm_{n̂,n,µ,r,β}**: Norm relation with explicit bound
- **Ξ^lin-r1cs_{n̂,n,ñ,µ,µ̃,r,β}**: Committed R1CS relation
- **Ξ^lin-pub_{n̂,n,µ,r,β,F}**: Linear relation with F as public parameter
- **Ξ^vsis_{β}**: Vanishing SIS relation

### Reductions of Knowledge (RoKs)
- **RoK**: Reduction of Knowledge - protocol reducing (stmt, wit) of Ξ to (stmt', wit') of Ξ'
- **Π^lde-⊗**: RoK from Ξ^lde-⊗ to Ξ^lin (zero communication)
- **Π^sum**: RoK from Ξ^sum to Ξ^lde-⊗ (sumcheck protocol)
- **Π^norm**: RoK from Ξ^norm to Ξ^sum (norm to sumcheck)
- **Π^norm+**: Composed RoK: Π^norm → Π^sum → Π^lde-⊗
- **Π^fold**: Folding RoK reducing witness columns
- **Π^split**: Splitting RoK dividing witness
- **Π^batch**: Batching RoK combining linear relations
- **Π^batch***: Enhanced batching using sumcheck
- **Π^b-decomp**: Base decomposition RoK
- **Π^⊗RP**: Structured random projection RoK
- **Π^RP**: Unstructured random projection RoK
- **Π^join**: Join RoK merging relations
- **Π^id**: Identity RoK (no-op)
- **Π^lin-r1cs**: RoK from R1CS to LDE relation
- **Π^fs**: Folding scheme composition

### Low-Degree Extension
- **LDE_d[w]: K^µ → K**: Degree-d low-degree extension of w ∈ K^{d^µ}
- **LDE_d[W]: K^µ → K^r**: Column-wise LDE for matrix W ∈ K^{d^µ×r}
- **r̃**: Lagrange basis vector for LDE evaluation: r̃^T = ⊗_{j∈[µ]} (∏_{k'∈[d]\{k}} (r_j-k')/(k-k'))_{k∈[d]}

### Protocol Participants
- **P**: Prover with input (stmt, wit)
- **V**: Verifier with input stmt
- **E**: Knowledge extractor
- **P***: Malicious/cheating prover

### Security Notions
- **Knowledge soundness**: If P* succeeds, extractor E can extract valid witness
- **Knowledge error κ**: Probability bound for extraction failure
- **Correctness**: Honest execution always succeeds
- **vSIS assumption**: Hardness of finding short x with Fx = 0 for row-tensor F

### Applications
- **SNARK**: Succinct Non-interactive Argument of Knowledge
- **PCS**: Polynomial Commitment Scheme
- **IVC**: Incrementally Verifiable Computation
- **Folding Scheme**: Protocol reducing multiple instances to one
- **VDF**: Verifiable Delay Function

## Requirements

### Requirement 1: Cyclotomic Field and Ring Infrastructure

**User Story:** As a cryptographic protocol implementer, I want complete cyclotomic field and ring arithmetic infrastructure, so that I can perform all algebraic operations required by SALSAA.

#### Acceptance Criteria

1. WHEN initializing cyclotomic field K = Q(ζ) with conductor f THEN the System SHALL:
   - Compute degree φ = φ(f) using Euler's totient function
   - Store primitive f-th root of unity ζ
   - Establish ring of integers R = O_K = Z[ζ]
   - Create quotient ring R_q = R/qR for prime modulus q

2. WHEN computing canonical embedding σ: K → C^φ THEN the System SHALL:
   - Enumerate all σ_j ∈ Gal(K/Q) (Galois automorphisms)
   - For element x ∈ K, compute σ(x) := (σ_j(x))_{j∈[φ]}
   - For vector x = (x_i)_{i∈[m]} ∈ K^m, compute σ(x) as concatenation (σ(x_i))_{i∈[m]}

3. WHEN computing coefficient representation THEN the System SHALL:
   - Given Z-basis b = (b_i)_{i∈[φ]} of R
   - For x = Σ_{i∈[φ]} x_i b_i, compute cf_b(x) := (x_i)_{i∈[φ]}

4. WHEN computing ℓ_p-norms over canonical embedding THEN the System SHALL:
   - For x ∈ R^m: ∥x∥_{σ,p} := ∥σ(x)∥_p = (Σ_{i∈[φ]} Σ_{j∈[m]} |σ_i(x_j)|^p)^{1/p}
   - For matrix M ∈ R^{n×m}: ∥M∥_{σ,p} = max_{i∈[n]} ∥m_i∥_{σ,p} (m_i = i-th column)
   - Verify identity: ∥x∥²_{σ,2} = Trace(⟨x, x̄⟩) = Σ_{i∈[φ]} Σ_{j∈[m]} σ_i(x_j · x̄_j)

5. WHEN computing field trace THEN the System SHALL:
   - For Galois extension M/L: Trace_{M/L}(x) := Σ_{σ_j ∈ Gal(K/L)} σ_j(x)
   - Default to Trace = Trace_{K/Q} when L = Q
   - Verify: Trace(⟨w, w̄⟩) = Σ_{j∈[m]} Σ_{σ∈Gal(R/Z)} σ(w_j · w̄_j) = ∥w∥²_{σ,2}

6. WHEN computing complex conjugation THEN the System SHALL:
   - For x ∈ K, compute x̄ (complex conjugate under canonical embedding)
   - Extend to vectors: w̄ = (w̄_i)_{i∈[m]}
   - Verify conjugation identity: LDE[w](r̄) = LDE[w̄](r) mod q

7. WHEN computing inner products THEN the System SHALL:
   - For x, y ∈ K^m: ⟨x, y⟩ := Σ_{j∈[m]} x_j · ȳ_j
   - Verify: ⟨w, w̄⟩ = Σ_{j∈[m]} w_j · w̄_j

### Requirement 2: Ring Splitting and CRT Operations

**User Story:** As a protocol implementer, I want CRT-based ring decomposition, so that I can perform efficient arithmetic in split representation.

#### Acceptance Criteria

1. WHEN q has multiplicative order e modulo f (i.e., q^e ≡ 1 mod f, e minimal) THEN the System SHALL:
   - Compute ring splitting R_q ≅ (F_{q^e})^{φ/e}
   - Implement isomorphism CRT: R_q → (F_{q^e})^{φ/e}
   - Implement inverse CRT^{-1}: (F_{q^e})^{φ/e} → R_q

2. WHEN extending CRT to vectors THEN the System SHALL:
   - For x ∈ R_q^m: CRT(x): R_q^m → (F_{q^e})^{mφ/e}
   - Apply CRT to each entry and concatenate results

3. WHEN extending CRT to polynomials THEN the System SHALL:
   - For polynomial p ∈ R_q^r[x^µ]: CRT: R_q^r[x^µ] → F_{q^e}^{rφ/e}[x^µ]
   - Apply CRT to each coefficient vector

4. WHEN lifting challenges from F_{q^e} to R_q THEN the System SHALL:
   - Given r_j ∈ F_{q^e}, compute r := CRT^{-1}(1_{φ/e} · r_j) ∈ R_q
   - For vector of challenges: r := (CRT^{-1}(1_{φ/e} · r_j)^T)_{j∈[µ]}

### Requirement 3: Row-Tensor Matrix Structure

**User Story:** As a protocol implementer, I want row-tensor matrix operations, so that I can work with the structured matrices required by vSIS commitments.

#### Acceptance Criteria

1. WHEN constructing row-tensor matrix F ∈ R_q^{n×d^⊗µ} THEN the System SHALL:
   - Accept factor matrices F_0, F_1, ..., F_{µ-1} ∈ R_q^{n×d}
   - Compute F = F_0 • F_1 • ... • F_{µ-1} using row-wise Kronecker product
   - Verify resulting dimension: n rows, d^µ = m columns

2. WHEN computing row-wise Kronecker product (•) THEN the System SHALL:
   - For A ∈ R^{n×a}, B ∈ R^{n×b}: (A • B)_{i,:} = A_{i,:} ⊗ B_{i,:}
   - Result dimension: n × (a·b)

3. WHEN interpreting tensor product as polynomial evaluation THEN the System SHALL:
   - For F = (1, f, f², ..., f^{m-1}) = (1, f^{m/2}) ⊗ (1, f^{m/4}) ⊗ ... ⊗ (1, f)
   - Verify Fw = Σ_{i=0}^{m-1} w_i f^i (polynomial evaluation)

4. WHEN decomposing matrix F into top and bottom parts THEN the System SHALL:
   - Parse F = [F; F̄] ∈ R_q^{(n+n̄)×m} with F ∈ R_q^{n×m} (top) and F̄ ∈ R_q^{n̄×m} (bottom)
   - Require F (top part) has row-tensor structure F ∈ R_q^{n×d^⊗µ}
   - Allow F̄ (bottom part) to be unstructured

### Requirement 4: Principal Linear Relation Ξ^lin Definition

**User Story:** As a protocol designer, I want precise definition of the principal linear relation, so that I can correctly implement and verify Ξ^lin instances.

#### Acceptance Criteria

1. WHEN defining Ξ^lin_{n̂,n,µ,r,β} instance THEN the System SHALL accept:
   - Statement: (H, F, Y) where:
     - H ∈ R_q^{n̂×n} restricted to form H = [I_n; H̄] for some n ≤ n̄
     - F ∈ R_q^{n×m} with m = d^µ, decomposed as F = [F; F̄]
     - Y ∈ R_q^{n̂×r}
   - Witness: W ∈ R^{m×r}

2. WHEN verifying Ξ^lin membership THEN the System SHALL check:
   - Linear constraint: HFW = Y mod q
   - Norm bound: ∥W∥_{σ,2} ≤ β
   - Both conditions must hold simultaneously

3. WHEN expanding HFW = Y THEN the System SHALL compute:
   - First: FW ∈ R_q^{n×r} (matrix-matrix product)
   - Then: HFW = [I_n; H̄] · FW = [FW; H̄·FW] ∈ R_q^{n̂×r}
   - Verify equality with Y mod q

4. WHEN the witness W is treated as vector THEN the System SHALL:
   - Flatten W ∈ R^{m×r} to w ∈ R^m when r = 1
   - Generalize all operations column-wise for r > 1

### Requirement 5: SIS Break Relation Ξ^sis

**User Story:** As a security analyst, I want to handle SIS break scenarios, so that extractors can properly manage cases where prover solves vSIS.

#### Acceptance Criteria

1. WHEN defining Ξ^sis_{R,q,m,n̂,r,β} THEN the System SHALL accept:
   - Statement: (H, F, Y) with same space as Ξ^lin
   - Witness: x ∈ R^{m×r}
   - Constraints: ∥x∥_{σ,2} ≤ β AND Fx = 0 mod q

2. WHEN handling knowledge reduction claims THEN the System SHALL:
   - Support form Ξ^lin ∪ Ξ^sis ← Ξ^lin ∪ Ξ^sis
   - Simplify to Ξ^lin ∪ Ξ^sis ← Ξ^lin when SIS-break handling is straightforward
   - Further simplify to Ξ^lin ← Ξ^lin when SIS-breaks are trivially managed

3. WHEN extractor encounters SIS break THEN the System SHALL:
   - If W' ≠ W mod q for two accepting transcripts
   - Extract v = W' - W (non-zero column) satisfying Fv = 0 mod q
   - Output (F, v) ∈ Ξ^vsis_{2β'}

### Requirement 6: Low-Degree Extension (LDE) Definition

**User Story:** As a protocol implementer, I want to compute low-degree extensions of witnesses, so that I can express norm-check claims as sumcheck claims.

#### Acceptance Criteria

1. WHEN defining LDE for vector w^T = (w_z)_{z∈[d]^µ} ∈ K^{1×d^µ} THEN the System SHALL:
   - Construct µ-variate polynomial LDE_d[w]: K^µ → K
   - Ensure individual degree d-1 in each variable
   - Satisfy interpolation: ∀z ∈ [d]^µ: LDE_d[w](z) = w_z

2. WHEN extending LDE to matrix W ∈ K^{d^µ×r} THEN the System SHALL:
   - Define LDE_d[W]: K^µ → K^r as column-wise concatenation
   - For column j: (LDE_d[W])_j = LDE_d[w_j] where w_j is j-th column
   - Satisfy: ∀z ∈ [d]^µ: LDE[W](z) = w_z^T (row of W indexed by z)

3. WHEN evaluating LDE[W](x) for x ∈ K^µ THEN the System SHALL:
   - Compute LDE[W](x)^T = x̃^T · W where x̃ is Lagrange basis vector
   - Lagrange basis: x̃^T = ⊗_{j∈[µ]} (∏_{k'∈[d]\{k}} (x_j - k')/(k - k'))_{k∈[d]}
   - Verify tensor structure of x̃ (product of µ vectors of dimension d)

4. WHEN computing Lagrange coefficients THEN the System SHALL:
   - For variable j and evaluation point x_j:
   - Compute L_{j,k}(x_j) = ∏_{k'∈[d]\{k}} (x_j - k')/(k - k') for each k ∈ [d]
   - Form vector (L_{j,0}(x_j), L_{j,1}(x_j), ..., L_{j,d-1}(x_j))
   - Take tensor product across all j ∈ [µ]

5. WHEN verifying LDE uniqueness (Lemma 1) THEN the System SHALL:
   - Confirm: univariate degree-d polynomial over field has at most d roots
   - By induction over j ∈ [µ]: LDE[W] is uniquely determined
   - Verify: ∀x ∈ K^µ: LDE[W](x)^T = x̃^T · W

### Requirement 7: LDE Relation Ξ^lde and Ξ^lde-⊗ Definition

**User Story:** As a protocol designer, I want LDE relations that extend Ξ^lin with evaluation claims, so that I can verify polynomial evaluations.

#### Acceptance Criteria

1. WHEN defining Ξ^lde_{n̂,n,µ,µ̃,r,β,t} THEN the System SHALL accept:
   - Base requirement: ((H, F, Y), W) ∈ Ξ^lin_{n̂,n,µ,r,β}
   - Evaluation claims: (r_i, s_i, M_i)_{i∈[t]} ∈ (R_q^{µ̃} × R_q^r × R_q^{m̃×m})^t
   - Additional constraint: ∀i∈[t]: s_i = LDE[M_i W](r_i) mod q

2. WHEN defining structured Ξ^lde-⊗ THEN the System SHALL:
   - Require matrices M_i ∈ R_q^{d^⊗µ̃ × d^⊗µ} (row-tensor structure)
   - If M_i = I_m (identity), omit from statement

3. WHEN computing LDE[M_i W](r_i) for structured M_i THEN the System SHALL:
   - Compute r̃_i^T · M_i using mixed-product property of Kronecker product
   - Result: r̃_i^T · M_i = ⊗_{j∈[µ̃]} ((∏_{k'∈[d]\{k}} (r_{i,j}-k')/(k-k')) · M_{i,j})_{k∈[d]}
   - Verify tensor structure is preserved

### Requirement 8: Reduction Π^lde-⊗ from Ξ^lde-⊗ to Ξ^lin (Lemma 2)

**User Story:** As a protocol implementer, I want to reduce LDE evaluation claims to linear relations, so that I can verify evaluations within Ξ^lin framework.

#### Acceptance Criteria

1. WHEN given Ξ^lde-⊗_{n̂,n,µ,µ̃,r,β,t} instance ((H, F, Y, (r_i, s_i, M_i)_{i∈[t]}), W) THEN the System SHALL:
   - Compute Lagrange vectors r̃_i for each i ∈ [t] as defined in Lemma 1
   - Output Ξ^lin_{n̂+t,n+t,µ,r,β} instance ((H', F', Y'), W)

2. WHEN constructing output statement THEN the System SHALL compute:
   - H' := [H; I_t] (append t×t identity below H)
   - F' := [F; (M_i r̃_i^T)_{i∈[t]}] (append t rows of evaluation constraints)
   - Y' := [Y; (s_i^T)_{i∈[t]}] (append t rows of expected values)

3. WHEN verifying reduction correctness THEN the System SHALL confirm:
   - Original: LDE[M_i W](r_i) = s_i mod q
   - Equivalent: (M_i r̃_i^T) · W = s_i^T mod q (linear constraint)
   - Combined: H'F'W = Y' mod q

4. WHEN analyzing Π^lde-⊗ properties THEN the System SHALL verify:
   - Perfect correctness: honest execution always succeeds
   - Knowledge soundness: Ξ^lde-⊗_{n̂,n,µ,µ̃,r,β,t} ↔ Ξ^lin_{n̂+t,n+t,µ,r,β}
   - Communication cost: 0 (deterministic, no interaction)

### Requirement 9: Sumcheck Relation Ξ^sum Definition (Definition 3)

**User Story:** As a protocol designer, I want the sumcheck relation that captures inner-product claims, so that I can reduce norm-check to sumcheck.

#### Acceptance Criteria

1. WHEN defining Ξ^sum_{n̂,n,µ,r,β} THEN the System SHALL accept:
   - Base requirement: ((H, F, Y), W) ∈ Ξ^lin_{n̂,n,µ,r,β}
   - Sumcheck claim: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t mod q ∈ R_q^r
   - Statement: ((H, F, Y, t), W)

2. WHEN expanding sumcheck claim THEN the System SHALL verify:
   - For each column i ∈ [r]: Σ_{z∈[d]^µ} LDE[w_i](z) · LDE[w̄_i](z) = t_i mod q
   - Equivalently: Σ_{z∈[d]^µ} |LDE[w_i](z)|² = t_i mod q
   - Sum over all d^µ grid points z ∈ [d]^µ

3. WHEN relating to inner product THEN the System SHALL verify:
   - ⟨w, w̄⟩ = Σ_{j∈[m]} w_j · w̄_j = Σ_{z∈[d]^µ} w_z · w̄_z
   - = Σ_{z∈[d]^µ} LDE[w](z) · LDE[w̄](z) = t mod q
   - Connection to norm: Trace(t) = Trace(⟨w, w̄⟩) = ∥w∥²_{σ,2}

### Requirement 10: Sumcheck Protocol Π^sum (Figure 2, Lemma 3)

**User Story:** As a protocol implementer, I want the complete sumcheck protocol reducing Ξ^sum to Ξ^lde-⊗, so that I can verify sumcheck claims efficiently.

#### Acceptance Criteria

1. WHEN initializing Π^sum protocol THEN the Verifier SHALL:
   - Sample random batching vector u ←$ F_{q^e}^× (rφ/e components)
   - Compute initial sum a_0 := u^T · CRT(t) mod q

2. WHEN Prover prepares sumcheck polynomial THEN the Prover SHALL:
   - Compute f̃ := u^T · CRT(LDE[W] ⊙ LDE[W̄]) mod q ∈ F_{q^e}[x^µ]
   - This is degree 2(d-1) polynomial in each of µ variables
   - Batches r columns into single polynomial over F_{q^e}

3. WHEN executing sumcheck rounds (for j = 0, 1, ..., µ-1) THEN:
   - Prover computes: g_j(x) := Σ_{z_j ∈ [d]^{µ-j-1}} f̃(r_0, ..., r_{j-1}, x, z_j) mod q
   - Prover sends: g_j(x) ∈ F_{q^e}[x] (univariate, degree 2(d-1))
   - Verifier checks: a_j = Σ_{z∈[d]} g_j(z) mod q
   - Verifier samples: r_j ← F_{q^e}^×
   - Verifier updates: a_{j+1} := g_j(r_j) mod q

4. WHEN completing sumcheck (after µ rounds) THEN the Prover SHALL:
   - Lift challenges to ring: r := (CRT^{-1}(1_{φ/e} · r_j)^T)_{j∈[µ]} ∈ R_q^µ
   - Compute evaluation: s_0 := LDE[W](r) mod q ∈ R_q^r
   - Compute conjugate evaluation: s_1 := LDE[W̄](r̄) mod q ∈ R_q^r
   - Send (s_0, s_1) to Verifier

5. WHEN Verifier performs final check THEN the Verifier SHALL:
   - Verify: a_µ = u^T · CRT(s_0 ⊙ s_1) mod q
   - This confirms f̃(r) = u^T · CRT(LDE[W](r) ⊙ LDE[W̄](r̄))

6. WHEN outputting reduced instance THEN the System SHALL produce:
   - ((H, F, Y, (r_i, s_i)_{i∈[2]}), W) ∈ Ξ^lde-⊗_{n̂,n,µ,r,β,2}
   - With r_0 := r and r_1 := r̄
   - Two evaluation claims: LDE[W](r) = s_0 and LDE[W](r̄) = s_1

7. WHEN using conjugation identity THEN the System SHALL verify:
   - LDE[W̄](r) = LDE[W](r̄) mod q
   - Therefore s_1 = LDE[W̄](r̄) ↔ LDE[W](r̄) = s_1
   - Both claims reduce to evaluations of LDE[W]

### Requirement 11: Π^sum Security Analysis (Lemma 3 Proof)

**User Story:** As a security analyst, I want complete security proof for Π^sum, so that I can verify the protocol's knowledge soundness.

#### Acceptance Criteria

1. WHEN proving correctness THEN the System SHALL verify:
   - a_j = g_{j-1}(r_{j-1}) = Σ_{z_{j-1}∈[d]^{µ-j}} f̃(r_0,...,r_{j-1},z_{j-1})
   - = Σ_{z∈[d]} Σ_{z_j∈[d]^{µ-j-1}} f̃(r_0,...,r_{j-1},z,z_j) = Σ_{z∈[d]} g_j(z) mod q
   - Final: f̃(r_0,...,r_{µ-1}) = u^T · CRT(f ⊙ f̄(r)) = u^T · CRT(s_0 ⊙ s_1) for f := LDE[W]

2. WHEN proving knowledge soundness THEN the Extractor E SHALL:
   - Assume P* is deterministic with success probability ε
   - Run P* on random challenge (u, r), abort if fails
   - On success, obtain (W, (g_j)_{j∈[µ]}, s_0, s_1) satisfying all checks
   - If W satisfies Ξ^sum, output W and terminate

3. WHEN extracting via rewinding THEN the Extractor E SHALL:
   - Re-run P* on fresh challenges (u', r') until second accepting transcript
   - Obtain (W', (g'_j)_{j∈[µ]}, s'_0, s'_1)
   - If W' ≠ W mod q: extract v = W' - W with Fv = 0 mod q
   - Output (F, v) ∈ Ξ^vsis_{2β'}

4. WHEN computing knowledge error THEN the System SHALL:
   - For µ = 1: g'_0(x) is degree 2(d-1) univariate polynomial
   - If g'_0(x) ≠ f̃(x) mod q: agree at most 2(d-1) points
   - Probability g'_0(r'_0) = f̃(r'_0): at most 2(d-1)/(εq^e)
   - By induction and union bound: κ_0 := 2µ(d-1)/q^e

5. WHEN bounding Schwartz-Zippel error THEN the System SHALL:
   - If LDE[W] ⊙ LDE[W̄] ≠ s_0 ⊙ s̄_1: Eq.(1) fails unless probability κ_1/ε
   - κ_1 := (rφ/e - 1)/q^e by Schwartz-Zippel lemma
   - Total knowledge error: κ = (2µ(d-1) + rφ/e - 1)/q^e

6. WHEN analyzing extractor runtime THEN the System SHALL verify:
   - Success probability ε > 0 on random challenge
   - Expected invocations: E[T] = (1-ε) + ε·(1 + 1/ε) = 2
   - Extractor runs in expected polynomial time

7. WHEN measuring communication THEN the System SHALL compute:
   - µ polynomials g_j of degree 2(d-1), each with (2d-1) coefficients in F_{q^e}
   - 2 vectors s_0, s_1 of length r in R_q
   - Total: (2d-1)µe log q + 2r log|R_q| bits

### Requirement 12: Dynamic Programming Optimization for Π^sum Prover

**User Story:** As a performance engineer, I want optimized sumcheck prover achieving linear time, so that the overall protocol has linear-time prover.

#### Acceptance Criteria

1. WHEN precomputing for sumcheck THEN the Prover SHALL:
   - Compute initial sum: a_0 := Σ_{z∈[d]^µ} f̃(z) mod q
   - Store intermediate evaluations: f̃_{0,i} := Σ_{z_i∈[d]^{µ-i-1}} f̃(x_0,...,x_i,z) mod q
   - Store for all i ∈ [µ]
   - Precomputation cost: O(m) ring operations

2. WHEN computing round j polynomial THEN the Prover SHALL:
   - Observe: g_j = f̃_{j,j} mod q (already computed)
   - Send g_j without additional computation for polynomial itself

3. WHEN updating after receiving challenge r_j THEN the Prover SHALL:
   - For all i > j: update f̃_{j+1,i} := f̃_{j,i}(r_j, x_{j+1},...,x_i) mod q
   - Substitute r_j into stored partial evaluations

4. WHEN analyzing per-round complexity THEN the System SHALL verify:
   - First round: partial polynomials of degrees 2m/d-1, 2m/d²-1, ..., 2m-1
   - Geometric series sums to O(m)
   - Each subsequent round: cost decreases by factor d
   - Total across all rounds: O(m) by geometric series

5. WHEN verifying total prover complexity THEN the System SHALL confirm:
   - Precomputation: O(m) ring operations
   - All rounds combined: O(m) ring operations
   - Total: O(rm) ring operations (linear in witness size)

### Requirement 13: Norm Relation Ξ^norm Definition

**User Story:** As a protocol designer, I want the norm relation with explicit bounds, so that I can verify witness norms during extraction.

#### Acceptance Criteria

1. WHEN defining Ξ^norm_{n̂,n,µ,r,β} THEN the System SHALL accept:
   - Base requirement: ((H, F, Y), W) ∈ Ξ^lin_{n̂,n,µ,r,β}
   - Explicit norm bound: ν with ∥W∥_{σ,2} ≤ ν ≤ β
   - Statement: ((H, F, Y, ν), W)

2. WHEN interpreting norm bound THEN the System SHALL verify:
   - For W = (w_i)_{i∈[r]} (column vectors)
   - Each column: ∥w_i∥_{σ,2} ≤ ν
   - Equivalently: Trace(⟨w_i, w̄_i⟩) ≤ ν² for all i ∈ [r]

### Requirement 14: Norm-Check Protocol Π^norm (Figure 3, Lemma 4)

**User Story:** As a protocol implementer, I want the norm-check protocol reducing Ξ^norm to Ξ^sum, so that I can verify norm bounds via sumcheck.

#### Acceptance Criteria

1. WHEN executing Π^norm protocol THEN the Prover SHALL:
   - Parse witness: W = (w_i)_{i∈[r]} as r column vectors
   - Compute inner products: t^T := (⟨w_i, w̄_i⟩)_{i∈[r]}
   - Where ⟨w_i, w̄_i⟩ = Σ_{j∈[m]} w_{j,i} · w̄_{j,i}
   - Send t ∈ R_q^r to Verifier

2. WHEN Verifier receives t THEN the Verifier SHALL:
   - Parse t^T = (t_0, t_1, ..., t_{r-1})
   - For each i ∈ [r]: check Trace(t_i) ≤ ν²
   - Reject if any check fails

3. WHEN outputting reduced instance THEN the System SHALL produce:
   - ((H, F, Y, t), W) ∈ Ξ^sum_{n̂,n,µ,r,β}
   - Sumcheck claim: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t mod q

4. WHEN proving correctness THEN the System SHALL verify:
   - Trace(⟨w_i, w̄_i⟩) = Trace(Σ_{j∈[m]} w_{j,i} · w̄_{j,i})
   - = Σ_{j∈[m]} Σ_{σ∈Gal(R/Z)} σ(w_{j,i} · w̄_{j,i})
   - = Trace(t_i) = ν_i² where ν_i = ∥w_i∥_{σ,2}
   - Since t := (⟨w_i, w̄_i⟩): ((H, F, Y, t), W) ∈ Ξ^sum

5. WHEN proving knowledge soundness THEN the System SHALL:
   - From Ξ^sum definition: Σ_{z∈[d]^µ} (LDE[W] ⊙ LDE[W̄])(z) = t mod q
   - Equivalently: t'_i = Σ_{j∈[m]} w_{j,i} · w̄_{j,i}
   - Trace(t'_i) = Trace(Σ_{j∈[m]} w_{j,i} · w̄_{j,i}) mod q
   - Require β'² < q/2 so equation holds without mod q
   - Conclude: ν² ≥ Trace(Σ_{j∈[m]} w_{j,i} · w̄_{j,i}) = ∥w_i∥²_{σ,2}
   - Therefore (H, F, Y, ν) ∈ Ξ^norm

6. WHEN measuring Π^norm complexity THEN the System SHALL verify:
   - Communication: r log|R_q| bits (sending t)
   - Prover time: O(r·m) ring operations (computing inner products)

### Requirement 15: Composed Norm-Check Π^norm+ (Corollary 1)

**User Story:** As a protocol implementer, I want the complete norm-check composition, so that I can reduce Ξ^norm directly to Ξ^lin.

#### Acceptance Criteria

1. WHEN composing Π^norm+ THEN the System SHALL chain:
   - Π^norm: Ξ^norm_{n̂,n,µ,r,β} → Ξ^sum_{n̂,n,µ,r,β}
   - Π^sum: Ξ^sum_{n̂,n,µ,r,β} → Ξ^lde-⊗_{n̂,n,µ,r,β,2}
   - Π^lde-⊗: Ξ^lde-⊗_{n̂,n,µ,r,β,2} → Ξ^lin_{n̂+2,n+2,µ,r,β}

2. WHEN analyzing Π^norm+ correctness THEN the System SHALL verify:
   - Perfect correctness for: Ξ^norm_{n̂,n,µ,r,β} → Ξ^lin_{n̂+2,n+2,r,µ,β}
   - Dimension increase: n̂ → n̂+2, n → n+2 (from 2 evaluation claims)

3. WHEN analyzing Π^norm+ security THEN the System SHALL verify:
   - Knowledge error: κ = (2µ(d-1) + r - 1)/q^e
   - For: Ξ^norm_{n̂,n,µ,r,β} ∪ Ξ^sis_{2β'} ← Ξ^lin_{n̂+2,n+2,r,µ,β'}
   - Requirement: β'² < q/2

4. WHEN measuring Π^norm+ complexity THEN the System SHALL verify:
   - Communication: (2d-1)µe log q + 3r log|R_q| bits
   - Prover time: O(rm) ring operations (LINEAR TIME - key improvement)
   - Compare to prior Π^norm-klno24: O(m log m) quasi-linear time

### Requirement 16: Automorphism-Generalized Sumcheck (Remark 1)

**User Story:** As a protocol designer, I want sumcheck generalized to automorphisms, so that I can handle more complex algebraic relations.

#### Acceptance Criteria

1. WHEN generalizing Π^sum with automorphism set S ⊆ Aut THEN the System SHALL:
   - Define Aut := {σ: ζ ↦ ζ^k | k ∈ (Z/fZ)×} (Galois automorphisms)
   - Support sumcheck claim: Σ_{z∈[d]^{µ̃}} ⊗_{σ∈S} LDE[σ(W)](z) = t mod q

2. WHEN computing evaluation claims THEN the Prover SHALL:
   - Use identity: σ^{-1}(LDE[σ(W)](r)) = LDE[W](σ^{-1}(r)) mod q
   - Set s_i := LDE[W](σ_i^{-1}(r)) mod q for each σ_i ∈ S

3. WHEN Verifier checks final claim THEN the Verifier SHALL:
   - Verify: a_µ = u^T · CRT(⊗_{(i,σ)∈[|S|,S]} σ(s_i)) mod q

4. WHEN analyzing generalized security THEN the System SHALL:
   - Knowledge error: κ = (|S|µ(d-1) + rφ/e - 1)/q^e
   - Communication: (|S|d - 1)µe log q + |S|r log|R_q| bits
   - Growth due to higher degree sumcheck polynomial

### Requirement 17: RoK Building Blocks from RPS/RnR

**User Story:** As a protocol implementer, I want all RoK building blocks from prior work, so that I can compose the complete SNARK and folding scheme.

#### Acceptance Criteria

1. WHEN implementing Π^split THEN the System SHALL:
   - Split witness W into smaller parts
   - Reduce witness height by constant factor
   - Maintain linear constraint structure
   - Run in O(m) ring operations

2. WHEN implementing Π^fold THEN the System SHALL:
   - Fold multiple witness columns into one
   - Input: r columns, Output: 1 column
   - Norm expansion: β → (r)γβ where γ is challenge set expansion
   - Run in O(m) ring operations

3. WHEN implementing Π^batch THEN the System SHALL:
   - Batch multiple linear relations via matrix H
   - Reduce number of output rows from n̂ to n
   - Verifier/prover time scales linearly in n̄
   - Run in O(m) ring operations

4. WHEN implementing Π^b-decomp THEN the System SHALL:
   - Perform base decomposition of witness
   - Reduce norm from max(β̂, (r_acc+L)γβ) to β
   - Increase columns: r → 2ℓ for decomposition parameter ℓ
   - Run in O(m) ring operations

5. WHEN implementing Π^⊗RP (structured random projection) THEN the System SHALL:
   - Compute randomized projections of witness
   - Output two branches: main relation and projection relation
   - Projection norm: β̂ = m_rp · β where m_rp = O(λ)
   - Verifier computes O(λ²) operations in R_q
   - Run in O(m) ring operations

6. WHEN implementing Π^RP (unstructured random projection) THEN the System SHALL:
   - Similar to Π^⊗RP but without tensor structure requirement
   - Used in unstructured loop when witness height is O(λ)

7. WHEN implementing Π^join THEN the System SHALL:
   - Merge multiple relation instances into single relation
   - Send cross-terms of bottom rows F̄ for different instances
   - Increase rows: n → n + (n̄-n)·(L-1) for L instances
   - Run in O(m) ring operations

8. WHEN implementing Π^id (identity) THEN the System SHALL:
   - Forward messages without modification
   - Used as placeholder in composition when no action needed

### Requirement 18: SNARK Construction - Structured Loop (Section 5)

**User Story:** As a cryptographic application developer, I want the complete SNARK construction, so that I can prove knowledge of Ξ^lin witnesses succinctly.

#### Acceptance Criteria

1. WHEN composing SNARK structured loop THEN the System SHALL implement sequence:
   - Π^norm → Π^batch → Π^b-decomp → Π^split → (Π^fold or Π^id) → Π^⊗RP → Π^join
   - This replaces prior: Π^norm-klno24 → Π^b-decomp → Π^split → Π^⊗RP → (Π^fold/Π^id) → Π^join → Π^batch

2. WHEN executing structured loop iterations THEN the System SHALL:
   - Repeat µ = O(log_λ m) times
   - Each iteration reduces witness height by constant factor
   - Continue until witness height reaches O(λ)

3. WHEN tracking parameter changes per structured iteration THEN the System SHALL:
   - After Π^norm: n̂ → n̂+2, n → n+2
   - After Π^batch: reduce rows via batching
   - After Π^b-decomp: restore norm bound
   - After Π^split: reduce witness height
   - After Π^fold: reduce columns to 1
   - After Π^⊗RP: create projection branch
   - After Π^join: merge branches

### Requirement 19: SNARK Construction - Unstructured Loop

**User Story:** As a protocol implementer, I want the unstructured loop for small witnesses, so that I can complete the SNARK when tensor structure is lost.

#### Acceptance Criteria

1. WHEN witness height reaches O(λ) THEN the System SHALL switch to unstructured loop:
   - Π^norm → Π^b-decomp → Π^split → Π^RP → Π^fold → Π^batch
   - Note: Π^⊗RP replaced by Π^RP (unstructured projection)

2. WHEN executing unstructured loop THEN the System SHALL:
   - Repeat O(log λ) times
   - Each iteration reduces witness height
   - Continue until witness height is constant O(1)

3. WHEN witness height is constant THEN the Prover SHALL:
   - Send remaining witness W in the clear
   - Verifier checks HFW = Y mod q directly
   - Verifier checks ∥W∥_{σ,2} ≤ β directly

### Requirement 20: SNARK Complexity Analysis (Theorem 1)

**User Story:** As a system architect, I want precise complexity bounds, so that I can evaluate SNARK performance.

#### Acceptance Criteria

1. WHEN measuring proof size THEN the System SHALL achieve:
   - O(λ log³ m / log λ) bits total
   - Per structured round: O(1) R_q elements
   - Final witness: O(λ · log² m / log λ) bits

2. WHEN measuring prover time THEN the System SHALL achieve:
   - O(m) ring operations total (LINEAR TIME)
   - Per round: O(m) operations
   - Geometric series: Σ_i m/d^i = O(m) as witness shrinks

3. WHEN measuring verifier time THEN the System SHALL achieve:
   - O(log m · λ²) ring operations
   - Dominated by Π^⊗RP: O(λ²) per round
   - O(log m) rounds total

4. WHEN instantiating parameters THEN the System SHALL:
   - Ring degree: φ = Θ(λ log m / log λ)
   - Modulus: log q = O(log m)
   - Achieve negligible correctness and knowledge error

### Requirement 21: Polynomial Commitment Scheme (Theorem 2)

**User Story:** As a cryptographic application developer, I want a multilinear PCS, so that I can commit to polynomials and prove evaluations.

#### Acceptance Criteria

1. WHEN committing to polynomial THEN the System SHALL:
   - Accept coefficients w ∈ R_q^{d^µ} (multilinear polynomial)
   - Compute vSIS commitment: y = Fw mod q
   - Commitment size: O(λ log² m / log λ) bits
   - Commitment time: O(m) ring operations

2. WHEN opening commitment at point x = (x_i)_{i∈[µ]} THEN the System SHALL:
   - Prove LDE[w](x) = t as Ξ^lde-⊗ instance
   - Apply Π^lde-⊗ to reduce to Ξ^lin
   - Run SNARK for Ξ^lin

3. WHEN measuring opening complexity THEN the System SHALL achieve:
   - Opening size: O(λ log³ m / log λ) bits
   - Prover time: O(m) ring operations
   - Verifier time: O(log m · λ²) ring operations

4. WHEN verifying PCS security THEN the System SHALL:
   - Inherit knowledge soundness from SNARK
   - Binding from vSIS assumption
   - Negligible correctness and knowledge error

### Requirement 22: Folding Scheme Relation Ξ^lin-pub (Section 6)

**User Story:** As a protocol designer, I want the folding relation with public F, so that I can accumulate multiple instances.

#### Acceptance Criteria

1. WHEN defining Ξ^lin-pub_{n̂,n,µ,r,β,F} THEN the System SHALL:
   - Treat F as public parameter (not part of statement)
   - F = [F; F̄] ∈ R_q^{n×m} with F ∈ R_q^{n×m} (top) and F̄ ∈ R_q^{n̄×m} (bottom)
   - Statement: (H, Y) with H ∈ R_q^{n̂×n}, Y ∈ R_q^{n̂×r}
   - Witness: W ∈ R^{m×r}
   - Constraints: ∥W∥_{σ,2} ≤ β and HFW = Y mod q

2. WHEN defining Ξ^lin-pub-⊗ THEN the System SHALL:
   - Require F (top part) has row-tensor structure
   - F ∈ R_q^{n×d^⊗µ}

### Requirement 23: Folding Scheme Composition (Theorem 3)

**User Story:** As a cryptographic application developer, I want a folding scheme for IVC, so that I can accumulate proofs efficiently.

#### Acceptance Criteria

1. WHEN composing folding scheme Π^fs THEN the System SHALL implement:
   - Π^join → Π^norm → Π^⊗RP → (Π^fold or Π^id) → Π^join → Π^batch → Π^b-decomp

2. WHEN folding L instances with accumulator THEN the System SHALL:
   - Input: (Ξ^lin-pub-⊗)^{r_acc+L} (r_acc accumulator columns + L new instances)
   - Output: (Ξ^lin-pub-⊗)^{r_acc} (r_acc accumulator columns)
   - Where r_acc = 2ℓ for decomposition parameter ℓ

3. WHEN tracking parameter changes through folding THEN the System SHALL:
   - Start: Ξ^lin_{n̂,n,µ,r_acc+L,β}
   - After first Π^join: merge L instances, n → n + (n̄-n)·(L-1)
   - After Π^norm: n̂ → n̂+2, n → n+2
   - After Π^⊗RP: two branches with β̂ = m_rp · β
   - After Π^fold: r → 1, β → (r_acc+L)γβ
   - After second Π^join: merge branches, Ξ^lin_{n̂+4,n+4,µ,2,max(β̂,(r_acc+L)γβ)}
   - After Π^batch and Π^b-decomp: Ξ^lin_{n̂,n+4,µ,2ℓ,β}

4. WHEN measuring folding scheme complexity THEN the System SHALL achieve:
   - Proof size: O(λ log² m / log λ) bits
   - Prover time: O(m) ring operations
   - Verifier time: O(λ²) ring operations
   - Assuming L, n̄ = O(1)

5. WHEN instantiating folding parameters THEN the System SHALL:
   - Decomposition parameter: ℓ = 2 (accumulator has 4 columns)
   - Number of instances: L = 4 (fold 4 instances at a time)
   - Ring degree: φ = 128 (256-th cyclotomic ring)

### Requirement 24: Enhanced Batching Π^batch* (Section 6.3)

**User Story:** As a protocol optimizer, I want sumcheck-based batching, so that folding doesn't degrade with many rounds.

#### Acceptance Criteria

1. WHEN batching via Π^batch* THEN the System SHALL:
   - Express F̄W = ȳ mod q as sumcheck claims
   - For each row f̄_i: Σ_{j∈[m]} LDE[f̄_i](z) · LDE[w](z) = ȳ_i mod q
   - Batch all sumcheck claims with random coefficients
   - Reduce to single evaluation claim in Ξ^lde-⊗

2. WHEN comparing to standard Π^batch THEN the System SHALL:
   - Π^batch: verifier/prover time scales with n̄ (unbatched rows)
   - Π^batch*: restores structure, constant overhead per round
   - Eliminates need for compressing matrix H (set to identity)

3. WHEN using Π^batch* in folding (Theorem 4) THEN the System SHALL:
   - Replace Π^batch with Π^batch* in Π^fs to get Π^fs+
   - Achieve: (Ξ^lin-pub-⊗)^{r_acc+L} ↔ (Ξ^lin-pub-⊗)^{r_acc}
   - Maintain same complexity bounds independent of folding rounds

### Requirement 25: R1CS Relation Ξ^lin-r1cs (Definition 4, Section 7)

**User Story:** As a protocol designer, I want R1CS support, so that I can express general arithmetic computations.

#### Acceptance Criteria

1. WHEN defining Ξ^lin-r1cs_{n̂,n,ñ,µ,µ̃,r,β} THEN the System SHALL accept:
   - Base requirement: ((H, F, Y), W) ∈ Ξ^lin_{n̂,n,µ,r,β}
   - R1CS matrices: A, B, C ∈ R_q^{m̃×m}
   - Linear constraint matrices: D ∈ R_q^{ñ×d^⊗µ}, E ∈ R_q^{ñ×r}
   - R1CS constraint: AW ⊙ BW = CW mod q
   - Linear constraint: DW = E mod q

2. WHEN defining structured Ξ^lin-r1cs-⊗ THEN the System SHALL:
   - Require A, B, C ∈ R_q^{d^⊗µ̃ × d^⊗µ} (row-tensor structure)

3. WHEN handling witness format THEN the System SHALL:
   - Typical R1CS: w = (1, w̄) with Aw ⊙ Bw = Cw
   - Check via D: (1, 0, ..., 0)w = 1
   - D can be tensor product if dimension appropriate
   - Witness norm bounded by β

### Requirement 26: R1CS Reduction Π^lin-r1cs (Lemma 5)

**User Story:** As a protocol implementer, I want R1CS to LDE reduction, so that I can verify R1CS constraints via sumcheck.

#### Acceptance Criteria

1. WHEN reducing R1CS via linearization THEN the System SHALL:
   - Follow linearization strategy from [KS24, BC25b]
   - Reduce R1CS relation to evaluation claims over LDE
   - Claims over LDE of witness W and matrices A, B, C

2. WHEN executing Π^lin-r1cs THEN the System SHALL:
   - Input: Ξ^lin-r1cs(-⊗)_{n̂,n,ñ,µ,µ̃,r,β}
   - Output: Ξ^lde(-⊗)_{n̂,n,ñ,µ,µ̃,r,β,3} (3 evaluation claims)

3. WHEN analyzing Π^lin-r1cs security THEN the System SHALL:
   - Perfect correctness
   - Knowledge error: (m̃-1)/q^e + (rφ/e-1+µ̃3(d-1))/q^e
   - For: Ξ^lin-r1cs(-⊗) ∪ Ξ^sis_{2β'} ← Ξ^lde(-⊗)

4. WHEN measuring Π^lin-r1cs complexity THEN the System SHALL:
   - Communication: (3(d-1)+1)µ̃e log q + 3r log|R_q| bits
   - Prover time: O(mm̃r) ring operations

### Requirement 27: vSIS Assumption and Security Foundation

**User Story:** As a security analyst, I want precise vSIS assumption definition, so that I can verify security reductions.

#### Acceptance Criteria

1. WHEN defining vSIS assumption THEN the System SHALL:
   - For random row-tensor F ←$ R_q^{n×d^⊗µ}
   - Hardness: finding short x with Fx = 0 mod q is hard
   - Norm bound: ∥x∥_{σ,2} ≤ β_{vSIS}
   - Assumed as hard as standard ring-SIS for unstructured F ∈ R_q^{n×m}

2. WHEN using vSIS for commitment THEN the System SHALL:
   - For short w: y = Fw mod q is computationally binding commitment
   - Binding: finding w' ≠ w with Fw' = Fw mod q implies SIS solution

3. WHEN setting security parameters THEN the System SHALL:
   - Require 0 < β ≪ β_{vSIS} < q/2
   - Ensure β'² < q/2 for norm-check soundness
   - Target negligible knowledge error in security parameter λ

### Requirement 28: Concrete Parameter Selection

**User Story:** As a system implementer, I want concrete parameter guidelines, so that I can instantiate secure and efficient protocols.

#### Acceptance Criteria

1. WHEN selecting ring parameters THEN the System SHALL:
   - Ring degree options: φ ∈ {128, 256, 512}
   - Conductor f such that φ = φ(f)
   - Modulus q prime with small multiplicative order e mod f

2. WHEN selecting SNARK parameters THEN the System SHALL:
   - Number of rounds: µ ∈ [9, 15] depending on witness size
   - Last 3 rounds: unstructured
   - Witness sizes: m·φ ∈ {2^26, 2^28, 2^30}

3. WHEN selecting folding parameters THEN the System SHALL:
   - Decomposition parameter: ℓ = 2
   - Accumulator columns: r_acc = 2ℓ = 4
   - Instances per fold: L = 4
   - Witness rows: m ∈ {2^17, 2^19, 2^21}

4. WHEN targeting performance THEN the System SHALL achieve:
   - SNARK (φ=128, 2^28 elements): V=41ms, P=10.61s, Proof=979KB
   - Folding (φ=128, 2^28 elements): V=2.28ms, P=1.66s, Proof=72.4KB

### Requirement 29: Implementation Optimizations

**User Story:** As a systems engineer, I want hardware-accelerated implementation, so that I achieve practical performance.

#### Acceptance Criteria

1. WHEN implementing ring arithmetic THEN the System SHALL:
   - Use AVX-512-IFMA instructions for 52-bit integer multiplication
   - Implement NTT with incomplete transformation (small extension degree e)
   - Parallelize across multiple cores for prover operations

2. WHEN implementing NTT THEN the System SHALL:
   - Use incomplete NTT when ring splits to small-degree extensions
   - R_q ≅ (F_{q^e})^{φ/e} with small e
   - Avoid full splitting to degree-1 extensions

3. WHEN implementing parallelization THEN the System SHALL:
   - Parallelize matrix-vector products
   - Parallelize NTT computations
   - Parallelize sumcheck round computations
   - Verifier remains mostly sequential (efficient on limited cores)

4. WHEN implementing memory management THEN the System SHALL:
   - Minimize allocations in hot paths
   - Reuse buffers for intermediate computations
   - Stream large witness data when possible

### Requirement 30: Serialization and Transcript

**User Story:** As a protocol implementer, I want serialization for all data types, so that I can transmit proofs and apply Fiat-Shamir.

#### Acceptance Criteria

1. WHEN serializing ring elements THEN the System SHALL:
   - Use balanced representation: {-⌈q/2⌉+1, ..., ⌊q/2⌋}
   - Encode coefficients in coefficient basis
   - Support both R_q and F_{q^e} representations

2. WHEN serializing matrices and vectors THEN the System SHALL:
   - Encode dimensions first
   - Encode elements in row-major order
   - Support sparse encoding for structured matrices

3. WHEN serializing proof transcripts THEN the System SHALL:
   - Include all prover messages in protocol order
   - Include public inputs and statement
   - Support incremental hashing for Fiat-Shamir

4. WHEN deserializing THEN the System SHALL:
   - Reconstruct exact original values (round-trip property)
   - Validate ranges and formats
   - Reject malformed inputs

### Requirement 31: Fiat-Shamir Transformation

**User Story:** As a protocol implementer, I want non-interactive proofs via Fiat-Shamir, so that I can deploy in non-interactive settings.

#### Acceptance Criteria

1. WHEN generating verifier challenges THEN the System SHALL:
   - Hash transcript using cryptographic hash (e.g., SHA-3, BLAKE3)
   - Include all prior prover messages
   - Include public inputs and statement

2. WHEN generating challenges in F_{q^e}^× THEN the System SHALL:
   - Hash and reduce modulo q^e
   - Reject zero and resample if needed
   - Ensure uniform distribution over F_{q^e}^×

3. WHEN generating challenges in R_q THEN the System SHALL:
   - Generate φ/e challenges in F_{q^e}
   - Apply CRT^{-1} to lift to R_q
   - Or generate directly via coefficient sampling

4. WHEN applying Fiat-Shamir to full protocol THEN the System SHALL:
   - Transform all interactive rounds
   - Maintain security in random oracle model
   - Produce non-interactive proof string

### Requirement 32: Relation Overview and Reduction Graph (Figure 1)

**User Story:** As a protocol architect, I want clear understanding of relation hierarchy, so that I can compose protocols correctly.

#### Acceptance Criteria

1. WHEN understanding relation reductions THEN the System SHALL implement:
   - Ξ^norm → Ξ^sum (via Π^norm)
   - Ξ^sum → Ξ^lde-⊗ (via Π^sum)
   - Ξ^lde-⊗ → Ξ^lin (via Π^lde-⊗)
   - Ξ^lde → Ξ^sum-⊗ (via Π^sum variant)
   - Ξ^sum → Ξ^lde (via Π^lde)
   - Ξ^lin-r1cs → Ξ^sum (via Π^lin-r1cs)
   - All paths eventually reach Ξ^lin

2. WHEN composing reductions THEN the System SHALL:
   - Chain reductions in correct order
   - Track parameter changes through each reduction
   - Accumulate communication costs
   - Compose knowledge errors

### Requirement 33: Error Handling and Validation

**User Story:** As a robust system implementer, I want comprehensive error handling, so that the system fails gracefully on invalid inputs.

#### Acceptance Criteria

1. WHEN validating inputs THEN the System SHALL:
   - Check matrix dimensions match
   - Verify norm bounds are satisfiable
   - Validate tensor structure where required
   - Check modular arithmetic consistency

2. WHEN verifier detects invalid proof THEN the System SHALL:
   - Reject with clear error indication
   - Not leak information about witness
   - Log rejection reason for debugging (optional)

3. WHEN prover encounters invalid witness THEN the System SHALL:
   - Fail before generating partial proof
   - Report which constraint is violated
   - Not produce accepting proof for invalid witness

### Requirement 34: Testing and Verification

**User Story:** As a quality engineer, I want comprehensive testing, so that I can verify correctness of implementation.

#### Acceptance Criteria

1. WHEN testing ring arithmetic THEN the System SHALL verify:
   - CRT and CRT^{-1} are inverses
   - NTT and inverse NTT are inverses
   - Norm computation matches definition
   - Trace computation matches definition

2. WHEN testing LDE THEN the System SHALL verify:
   - LDE interpolates correctly at grid points
   - Lagrange basis computation is correct
   - Tensor structure is preserved

3. WHEN testing protocols THEN the System SHALL verify:
   - Honest execution always accepts (completeness)
   - Random witnesses satisfy relations with correct probability
   - Parameter tracking through compositions is correct

4. WHEN testing end-to-end THEN the System SHALL verify:
   - SNARK proves and verifies for valid witnesses
   - SNARK rejects for invalid witnesses (soundness)
   - PCS commits and opens correctly
   - Folding accumulates correctly
