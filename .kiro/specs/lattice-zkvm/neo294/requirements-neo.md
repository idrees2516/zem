# Neo: Lattice-based Folding Scheme for CCS - Detailed Requirements

## Paper Overview

Neo introduces a lattice-based folding scheme for CCS (Customizable Constraint System) that works over small prime fields (e.g., Goldilocks) and provides plausible post-quantum security. The key innovation is a folding-friendly instantiation of Ajtai's commitments with "pay-per-bit" commitment costs.

## Glossary - Neo Specific Terms

- **CCS (Customizable Constraint System)**: An NP-complete relation generalizing R1CS, Plonkish, and AIR
- **Folding Scheme**: Reduces checking two instance-witness pairs to checking one pair
- **Ajtai Commitment**: Lattice-based commitment Com(w) = Aw mod q
- **Pay-Per-Bit**: Commitment cost scales with bit-width, not full field element size
- **Small Prime Field**: Fields like Goldilocks (q = 2^64 - 2^32 + 1) or M61 (q = 2^61 - 1)
- **Cyclotomic Ring**: R = Z[X]/(X^d + 1) for power-of-2 d
- **Module-SIS**: Module Short Integer Solution hardness assumption
- **Multilinear Extension (MLE)**: Unique multilinear polynomial extending Boolean function
- **Sum-Check Protocol**: Interactive proof for polynomial summation claims
- **Linear Homomorphism**: Com(αx + βy) = α·Com(x) + β·Com(y)
- **Coefficient Embedding**: Map cf: Rq → Zq^d extracting polynomial coefficients
- **Folding-Friendly**: Commitment scheme supporting efficient folding operations

## Core Mathematical Foundations

### Requirement NEO-1: Cyclotomic Ring Structure

**User Story:** As a cryptographic implementer, I want to understand the exact cyclotomic ring structure used in Neo, so that I can implement the ring operations correctly.

#### Mathematical Background

Neo operates over cyclotomic polynomial rings defined as:
- R = Z[X]/(X^d + 1) where d is a power of 2
- Rq = R/qR = Zq[X]/(X^d + 1) for prime q
- Elements f ∈ Rq are polynomials f = Σ_{i=0}^{d-1} f_i X^i with coefficients f_i ∈ Zq

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define cyclotomic ring R = Z[X]/(X^d + 1) where d = 2^k for some k ≥ 6
2. THE Neo_Implementation SHALL define residue ring Rq = Zq[X]/(X^d + 1) for prime modulus q
3. THE Neo_Implementation SHALL represent Zq = {-⌊q/2⌋, ..., ⌊q/2⌋} with balanced representation
4. THE Neo_Implementation SHALL implement polynomial addition in Rq as coefficient-wise addition modulo q
5. THE Neo_Implementation SHALL implement polynomial multiplication in Rq using reduction X^d = -1
6. THE Neo_Implementation SHALL compute polynomial multiplication using NTT when q ≡ 1 + 2e (mod 4e) for e | d
7. THE Neo_Implementation SHALL implement coefficient embedding cf: Rq → Zq^d where cf(Σ f_i X^i) = (f_0, f_1, ..., f_{d-1})
8. THE Neo_Implementation SHALL implement constant term extraction ct: Rq → Zq where ct(f) = f_0
9. THE Neo_Implementation SHALL verify ring isomorphism Rq ≅ F_q^(d/e) when q ≡ 1 + 2e (mod 4e) via NTT
10. THE Neo_Implementation SHALL ensure d ≥ 64 for 128-bit post-quantum security

### Requirement NEO-2: Field Selection and Parameters

**User Story:** As a parameter selector, I want to understand which small prime fields are compatible with Neo, so that I can choose optimal parameters for my application.

#### Mathematical Background

Neo supports small prime fields that satisfy specific conditions:
- Goldilocks: q = 2^64 - 2^32 + 1 (64-bit prime)
- Almost Goldilocks: q = (2^64 - 2^32 + 1) - 32
- Mersenne 61: q = 2^61 - 1

For security, Neo requires extension fields when base field is small:
- If q is 64-bit, use extension F_q^2 for sum-check to achieve 128-bit security
- Challenge set size must be at least 2^128

#### Acceptance Criteria

1. THE Neo_Implementation SHALL support Goldilocks field q = 2^64 - 2^32 + 1 = 18446744069414584321
2. THE Neo_Implementation SHALL support Almost Goldilocks field q = 2^64 - 2^32 - 31 = 18446744069414584290
3. THE Neo_Implementation SHALL support Mersenne 61 field q = 2^61 - 1 = 2305843009213693951
4. THE Neo_Implementation SHALL verify q ≡ 1 + 2e (mod 4e) for chosen (q, d, e) triple
5. THE Neo_Implementation SHALL compute extension degree τ = d/e where Rq ≅ F_q^τ
6. WHEN using 64-bit field, THE Neo_Implementation SHALL use degree-2 extension F_q^2 for sum-check protocols
7. THE Neo_Implementation SHALL ensure challenge set size |C| ≥ 2^128 for negligible soundness error
8. THE Neo_Implementation SHALL verify that cyclotomic ring does NOT fully split (τ > 1) to maintain security
9. THE Neo_Implementation SHALL implement fast modular arithmetic for Goldilocks using properties q = 2^64 - 2^32 + 1
10. THE Neo_Implementation SHALL implement fast modular arithmetic for M61 using Mersenne prime properties

### Requirement NEO-3: Ajtai Commitment Scheme

**User Story:** As a commitment scheme user, I want to understand the exact Ajtai commitment construction, so that I can implement and verify commitments correctly.

#### Mathematical Background

Ajtai commitments are defined as:
- Public matrix: A ∈ Rq^(κ×n) sampled uniformly at random
- Witness vector: w ∈ Rq^n with small norm ||w||_∞ ≤ β
- Commitment: Com(w) = Aw mod q ∈ Rq^κ

Security is based on Module-SIS assumption:
- Given A, find short w ≠ 0 such that Aw = 0 mod q
- Hardness parameter: (κ, n, q, β) chosen for 128-bit security

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define Ajtai commitment as Com(w) = Aw mod q where A ∈ Rq^(κ×n), w ∈ Rq^n
2. THE Neo_Implementation SHALL generate public matrix A by hashing public seed using cryptographic hash function
3. THE Neo_Implementation SHALL expand hash output to matrix entries using rejection sampling or modular reduction
4. THE Neo_Implementation SHALL ensure matrix A is statistically close to uniform distribution over Rq^(κ×n)
5. THE Neo_Implementation SHALL verify witness norm ||w||_∞ ≤ β before computing commitment
6. THE Neo_Implementation SHALL compute commitment using matrix-vector multiplication: c_i = Σ_{j=1}^n A_{i,j} · w_j mod q for i ∈ [κ]
7. THE Neo_Implementation SHALL implement commitment computation in time O(κ · n · d · log d) using NTT
8. THE Neo_Implementation SHALL verify commitment binding under Module-SIS(κ, n, q, β) assumption
9. THE Neo_Implementation SHALL implement commitment opening by revealing witness w and verifying Com(w) = c
10. THE Neo_Implementation SHALL check opened witness satisfies norm bound ||w||_∞ ≤ β

### Requirement NEO-4: Pay-Per-Bit Commitment Cost

**User Story:** As an efficiency-focused developer, I want commitments to cost proportionally to bit-width, so that committing to small values is much cheaper than committing to full field elements.

#### Mathematical Background

Neo achieves pay-per-bit costs through coefficient packing:
- Map field vector f ∈ F_q^N to ring vector w ∈ Rq^(N/d) by packing d consecutive field elements as coefficients
- For b-bit values, only b/log(q) fraction of ring element is used
- Commitment cost scales as O(n · b/d) instead of O(n) for b-bit values

Example: For d = 64 and 32-bit values:
- Traditional: Cost is O(n) ring multiplications
- Neo: Cost is O(n · 32/64) = O(n/2) ring multiplications
- Speedup: 2x for 32-bit values, 32x for 1-bit values

#### Acceptance Criteria

1. THE Neo_Implementation SHALL map field vector f ∈ F_q^N to ring vector w ∈ Rq^(N/d) by coefficient packing
2. THE Neo_Implementation SHALL pack d consecutive field elements f_{i·d}, ..., f_{i·d+d-1} into ring element w_i = Σ_{j=0}^{d-1} f_{i·d+j} X^j
3. THE Neo_Implementation SHALL compute commitment cost as O(κ · (N/d) · b/log(q)) for b-bit values
4. THE Neo_Implementation SHALL achieve 32x speedup when committing to bits vs 32-bit values with d = 64
5. THE Neo_Implementation SHALL support mixed bit-widths where different vector positions have different bit-widths
6. THE Neo_Implementation SHALL compute commitment for b-bit values by only processing non-zero coefficients
7. THE Neo_Implementation SHALL optimize NTT computation for sparse polynomials when b ≪ log(q)
8. THE Neo_Implementation SHALL track actual bit-width per vector element for optimal cost calculation
9. THE Neo_Implementation SHALL provide cost estimation function returning expected ring multiplications for given bit-widths
10. THE Neo_Implementation SHALL document pay-per-bit advantage: Cost(b-bit) / Cost(full) = b / log(q)

### Requirement NEO-5: Linear Homomorphism Property

**User Story:** As a folding scheme designer, I want commitments to be linearly homomorphic, so that I can combine commitments efficiently during folding.

#### Mathematical Background

Linear homomorphism is essential for folding:
- For witnesses w₁, w₂ ∈ Rq^n and scalars α, β ∈ Rq:
  Com(αw₁ + βw₂) = α·Com(w₁) + β·Com(w₂) mod q

Proof of homomorphism:
  Com(αw₁ + βw₂) = A(αw₁ + βw₂) mod q
                  = αAw₁ + βAw₂ mod q
                  = α·Com(w₁) + β·Com(w₂) mod q

This property enables folding verifier to compute folded commitment without knowing witnesses.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL verify linear homomorphism: Com(αw₁ + βw₂) = α·Com(w₁) + β·Com(w₂) mod q
2. THE Neo_Implementation SHALL implement scalar multiplication of commitments: α·c = (α·c₁, ..., α·c_κ) where c = (c₁, ..., c_κ)
3. THE Neo_Implementation SHALL implement addition of commitments: c₁ + c₂ = (c₁,₁ + c₂,₁, ..., c₁,_κ + c₂,_κ) mod q
4. THE Neo_Implementation SHALL compute folded commitment c' = Σᵢ βᵢ·cᵢ for challenge vector β and commitments {cᵢ}
5. THE Neo_Implementation SHALL verify folded commitment matches Com(w') where w' = Σᵢ βᵢ·wᵢ
6. THE Neo_Implementation SHALL implement batched linear combination computing Σᵢ βᵢ·cᵢ in time O(κ·ℓ) for ℓ commitments
7. THE Neo_Implementation SHALL use Horner's method for efficient scalar multiplication by challenge vector
8. THE Neo_Implementation SHALL verify homomorphism preserves norm bounds: ||αw₁ + βw₂||_∞ ≤ ||α||_∞·||w₁||_∞ + ||β||_∞·||w₂||_∞
9. THE Neo_Implementation SHALL implement homomorphism testing function verifying property on random inputs
10. THE Neo_Implementation SHALL document that homomorphism holds over Rq, not just over base field Fq

### Requirement NEO-6: Multilinear Extension and Evaluation Claims

**User Story:** As a polynomial commitment user, I want to understand how vectors are treated as multilinear polynomials, so that I can prove evaluation claims correctly.

#### Mathematical Background

Neo treats committed vectors as multilinear polynomials:
- Vector w ∈ Fq^N with N = 2^ℓ defines multilinear polynomial w̃ in ℓ variables
- Multilinear extension: w̃(x₁, ..., x_ℓ) = Σ_{b∈{0,1}^ℓ} w[b] · ∏ᵢ (xᵢ·bᵢ + (1-xᵢ)·(1-bᵢ))
- Evaluation claim: (C, r, y) where C = Com(w), r ∈ Fq^ℓ, y ∈ Fq, claiming w̃(r) = y

Folding evaluation claims:
- Given β commitments {(Cᵢ, r, yᵢ)}ᵢ₌₁^β with witnesses {wᵢ}
- Sample random ρ ∈ Fq
- Folded claim: (C', r, y') where:
  * C' = Σᵢ ρⁱ⁻¹·Cᵢ
  * y' = Σᵢ ρⁱ⁻¹·yᵢ
  * w' = Σᵢ ρⁱ⁻¹·wᵢ satisfies w̃'(r) = y'

#### Acceptance Criteria

1. THE Neo_Implementation SHALL represent vector w ∈ Fq^(2^ℓ) as multilinear polynomial w̃: Fq^ℓ → Fq
2. THE Neo_Implementation SHALL compute multilinear extension using formula: w̃(x) = Σ_{b∈{0,1}^ℓ} w[b] · eq(b, x)
3. THE Neo_Implementation SHALL implement equality polynomial: eq(b, x) = ∏ᵢ₌₁^ℓ (xᵢ·bᵢ + (1-xᵢ)·(1-bᵢ))
4. THE Neo_Implementation SHALL evaluate w̃(r) in time O(2^ℓ) using direct summation over Boolean hypercube
5. THE Neo_Implementation SHALL optimize evaluation using recursive formula: w̃(r₁, ..., r_ℓ) = (1-r_ℓ)·w̃_L(r₁, ..., r_{ℓ-1}) + r_ℓ·w̃_R(r₁, ..., r_{ℓ-1})
6. THE Neo_Implementation SHALL define evaluation claim as tuple (C, r, y) where C ∈ Rq^κ, r ∈ Fq^ℓ, y ∈ Fq
7. THE Neo_Implementation SHALL verify evaluation claim by checking w̃(r) = y for witness w satisfying Com(w) = C
8. THE Neo_Implementation SHALL implement folding of β evaluation claims using random challenge ρ ∈ Fq
9. THE Neo_Implementation SHALL compute folded commitment C' = Σᵢ₌₁^β ρⁱ⁻¹·Cᵢ using linear homomorphism
10. THE Neo_Implementation SHALL compute folded evaluation y' = Σᵢ₌₁^β ρⁱ⁻¹·yᵢ
11. THE Neo_Implementation SHALL compute folded witness w' = Σᵢ₌₁^β ρⁱ⁻¹·wᵢ
12. THE Neo_Implementation SHALL verify folded claim satisfies w̃'(r) = y' by multilinearity: (Σᵢ ρⁱ⁻¹·wᵢ)~(r) = Σᵢ ρⁱ⁻¹·w̃ᵢ(r)
13. THE Neo_Implementation SHALL ensure folding soundness: if folded claim is valid, then with high probability all original claims are valid
14. THE Neo_Implementation SHALL implement extraction algorithm recovering individual witnesses from folded witness
15. THE Neo_Implementation SHALL document that folding reduces β claims to 1 claim with same evaluation point r

### Requirement NEO-7: CCS Relation Definition

**User Story:** As a constraint system user, I want to understand the exact CCS relation format, so that I can encode my computations correctly.

#### Mathematical Background

CCS (Customizable Constraint System) is defined by:
- Public parameters: (m, n, N, ℓ, t, q, d) where:
  * m: number of constraints
  * n: number of variables (witness length)
  * N = 2^ℓ: size of multilinear polynomial domain
  * t: number of matrices per constraint
  * q: field modulus
  * d: maximum degree of constraints
- Matrices: M₀, M₁, ..., M_{t-1} ∈ Fq^(m×n)
- Selector vectors: S₀, S₁, ..., S_{q-1} ⊆ [t] indicating which matrices appear in each constraint
- Constants: c₀, c₁, ..., c_{q-1} ∈ Fq

CCS relation: (M, S, c, z) where z ∈ Fq^n satisfies:
  Σᵢ₌₀^{q-1} cᵢ · ∘_{j∈Sᵢ} Mⱼz = 0

Here ∘ denotes Hadamard (element-wise) product.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define CCS structure with parameters (m, n, N, ℓ, t, q, d)
2. THE Neo_Implementation SHALL store matrices M₀, ..., M_{t-1} ∈ Fq^(m×n) in sparse or dense format
3. THE Neo_Implementation SHALL define selector vectors S₀, ..., S_{q-1} as subsets of [t]
4. THE Neo_Implementation SHALL define constant vector c = (c₀, ..., c_{q-1}) ∈ Fq^q
5. THE Neo_Implementation SHALL verify witness z ∈ Fq^n satisfies CCS relation: Σᵢ cᵢ · ∘_{j∈Sᵢ} Mⱼz = 0
6. THE Neo_Implementation SHALL compute matrix-vector product Mⱼz in time O(m·n) for dense matrices
7. THE Neo_Implementation SHALL compute matrix-vector product Mⱼz in time O(nnz(Mⱼ)) for sparse matrices with nnz non-zeros
8. THE Neo_Implementation SHALL compute Hadamard product ∘_{j∈Sᵢ} Mⱼz by element-wise multiplication of vectors
9. THE Neo_Implementation SHALL verify final sum Σᵢ cᵢ · (∘_{j∈Sᵢ} Mⱼz) equals zero vector
10. THE Neo_Implementation SHALL support R1CS as special case with q=1, t=3, S₀={0,1,2}, c₀=1, constraint (M₀z) ∘ (M₁z) = M₂z
11. THE Neo_Implementation SHALL support Plonkish constraints by appropriate choice of matrices and selectors
12. THE Neo_Implementation SHALL support AIR constraints by encoding transition constraints as CCS
13. THE Neo_Implementation SHALL provide CCS builder API for constructing constraint systems programmatically
14. THE Neo_Implementation SHALL validate CCS well-formedness: all Sᵢ ⊆ [t], all matrices have dimension m×n
15. THE Neo_Implementation SHALL optimize CCS evaluation for structured matrices (circulant, Toeplitz, etc.)

### Requirement NEO-8: CCS Folding Scheme - Reduction to Multilinear Evaluation

**User Story:** As a folding scheme implementer, I want to understand how CCS is reduced to multilinear evaluation claims, so that I can implement the reduction correctly.

#### Mathematical Background

Neo reduces CCS satisfiability to multilinear evaluation using sum-check:

Step 1: Represent matrices as multilinear polynomials
- For matrix M ∈ Fq^(m×n), define M̃: {0,1}^(log m + log n) → Fq
- M̃(x, y) extends M[x][y] to multilinear polynomial

Step 2: Represent witness as multilinear polynomial
- For witness z ∈ Fq^n, define z̃: {0,1}^(log n) → Fq
- z̃(y) extends z[y] to multilinear polynomial

Step 3: Express CCS as polynomial equation
- Define g(x, y) = Σᵢ cᵢ · ∏_{j∈Sᵢ} M̃ⱼ(x, y) · z̃(y)
- CCS is satisfied iff Σ_{x,y∈{0,1}^ℓ} g(x, y) = 0

Step 4: Apply sum-check protocol
- Prover and verifier run sum-check on claim Σ_{x,y} g(x, y) = 0
- Reduces to evaluation claim: g(r_x, r_y) = v for random r_x, r_y
- Further reduces to evaluations of M̃ⱼ(r_x, r_y) and z̃(r_y)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL represent matrix M ∈ Fq^(m×n) as multilinear polynomial M̃: Fq^(log m + log n) → Fq
2. THE Neo_Implementation SHALL compute M̃(x, y) using formula: M̃(x, y) = Σ_{i,j∈{0,1}^ℓ} M[i][j] · eq(i, x) · eq(j, y)
3. THE Neo_Implementation SHALL represent witness z ∈ Fq^n as multilinear polynomial z̃: Fq^(log n) → Fq
4. THE Neo_Implementation SHALL compute z̃(y) using formula: z̃(y) = Σ_{j∈{0,1}^(log n)} z[j] · eq(j, y)
5. THE Neo_Implementation SHALL define CCS polynomial g(x, y) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (M̃ⱼ(x, y) · z̃(y))
6. THE Neo_Implementation SHALL verify CCS satisfaction by checking Σ_{x,y∈{0,1}^ℓ} g(x, y) = 0
7. THE Neo_Implementation SHALL implement sum-check protocol for proving Σ_{x,y} g(x, y) = 0
8. THE Neo_Implementation SHALL reduce sum-check to evaluation claim g(r_x, r_y) = v at random point (r_x, r_y)
9. THE Neo_Implementation SHALL further reduce to evaluations M̃ⱼ(r_x, r_y) for j ∈ [t] and z̃(r_y)
10. THE Neo_Implementation SHALL commit to witness z before starting sum-check protocol
11. THE Neo_Implementation SHALL use committed z̃ evaluations in sum-check without revealing z
12. THE Neo_Implementation SHALL implement prover algorithm computing sum-check messages in time O(m·n·d)
13. THE Neo_Implementation SHALL implement verifier algorithm checking sum-check messages in time O(log(m·n))
14. THE Neo_Implementation SHALL ensure soundness: if sum-check accepts, then with high probability CCS is satisfied
15. THE Neo_Implementation SHALL document reduction: CCS → Sum-Check → Multilinear Evaluation Claims

### Requirement NEO-9: Sum-Check Protocol for CCS

**User Story:** As a sum-check implementer, I want detailed specification of the sum-check protocol for CCS, so that I can implement prover and verifier correctly.

#### Mathematical Background

Sum-check protocol for polynomial g(x₁, ..., x_ℓ) claiming Σ_{x∈{0,1}^ℓ} g(x) = H:

Round i (for i = 1 to ℓ):
1. Prover sends univariate polynomial sᵢ(Xᵢ) = Σ_{x_{i+1},...,x_ℓ∈{0,1}^{ℓ-i}} g(r₁, ..., r_{i-1}, Xᵢ, x_{i+1}, ..., x_ℓ)
2. Verifier checks: sᵢ(0) + sᵢ(1) = H (for i=1) or sᵢ(0) + sᵢ(1) = s_{i-1}(r_{i-1}) (for i>1)
3. Verifier samples random challenge rᵢ ∈ Fq
4. Update H ← sᵢ(rᵢ)

Final check:
- Verifier computes g(r₁, ..., r_ℓ) directly
- Verifier checks g(r₁, ..., r_ℓ) = s_ℓ(r_ℓ)

For CCS, g(x, y) has ℓ_x + ℓ_y variables where ℓ_x = log m, ℓ_y = log n.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement sum-check prover for polynomial g: Fq^ℓ → Fq
2. THE Neo_Implementation SHALL initialize sum-check with claimed sum H = Σ_{x∈{0,1}^ℓ} g(x)
3. IN round i, THE Neo_Implementation SHALL compute univariate polynomial sᵢ(Xᵢ) of degree at most d
4. THE Neo_Implementation SHALL compute sᵢ(Xᵢ) by summing g(r₁, ..., r_{i-1}, Xᵢ, x_{i+1}, ..., x_ℓ) over x_{i+1}, ..., x_ℓ ∈ {0,1}^{ℓ-i}
5. THE Neo_Implementation SHALL represent sᵢ(Xᵢ) by its evaluations at points 0, 1, ..., d
6. THE Neo_Implementation SHALL send (d+1) field elements representing sᵢ to verifier
7. THE Neo_Implementation SHALL implement verifier checking sᵢ(0) + sᵢ(1) = H (round 1) or sᵢ(0) + sᵢ(1) = s_{i-1}(r_{i-1}) (round i>1)
8. THE Neo_Implementation SHALL sample random challenge rᵢ ∈ Fq using Fiat-Shamir transform
9. THE Neo_Implementation SHALL update running sum H ← sᵢ(rᵢ) for next round
10. AFTER ℓ rounds, THE Neo_Implementation SHALL verify final check: g(r₁, ..., r_ℓ) = s_ℓ(r_ℓ)
11. THE Neo_Implementation SHALL compute g(r₁, ..., r_ℓ) by evaluating multilinear extensions M̃ⱼ(r_x, r_y) and z̃(r_y)
12. THE Neo_Implementation SHALL achieve prover time O(2^ℓ · d) for degree-d polynomial over ℓ variables
13. THE Neo_Implementation SHALL achieve verifier time O(ℓ · d) plus time to evaluate g at random point
14. THE Neo_Implementation SHALL achieve soundness error O(ℓ · d / |Fq|) by Schwartz-Zippel lemma
15. THE Neo_Implementation SHALL run sum-check over extension field F_{q^2} when base field Fq is 64-bit for 128-bit security

### Requirement NEO-10: Random Linear Combination (RLC) Reduction

**User Story:** As a folding implementer, I want to understand the random linear combination step, so that I can fold multiple instances correctly.

#### Mathematical Background

Random Linear Combination (RLC) reduces multiple instances to one:

Input: L instances {(Cᵢ, xᵢ, wᵢ)}ᵢ₌₁^L where:
- Cᵢ = Com(wᵢ) is commitment to witness wᵢ
- xᵢ is public input
- wᵢ satisfies relation R(xᵢ, wᵢ) = 1

RLC Protocol:
1. Verifier samples random vector ρ = (ρ₁, ..., ρ_L) ∈ Fq^L from challenge set C
2. Prover computes folded witness: w' = Σᵢ₌₁^L ρᵢ · wᵢ
3. Verifier computes folded commitment: C' = Σᵢ₌₁^L ρᵢ · Cᵢ (using linear homomorphism)
4. Verifier computes folded public input: x' = (ρ, {xᵢ}ᵢ)

Soundness: If w' satisfies folded relation R'(x', w'), then with probability 1 - ε over ρ,
all original witnesses {wᵢ} satisfy their relations {R(xᵢ, wᵢ)}.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement RLC reduction taking L instances {(Cᵢ, xᵢ, wᵢ)}ᵢ₌₁^L as input
2. THE Neo_Implementation SHALL sample random challenge vector ρ = (ρ₁, ..., ρ_L) from challenge set C^L
3. THE Neo_Implementation SHALL ensure challenge set C has size |C| ≥ 2^128 for negligible soundness error
4. THE Neo_Implementation SHALL compute folded witness w' = Σᵢ₌₁^L ρᵢ · wᵢ using scalar multiplication and addition
5. THE Neo_Implementation SHALL compute folded commitment C' = Σᵢ₌₁^L ρᵢ · Cᵢ using commitment homomorphism
6. THE Neo_Implementation SHALL verify C' = Com(w') by commitment binding property
7. THE Neo_Implementation SHALL construct folded public input x' encoding challenge ρ and original inputs {xᵢ}
8. THE Neo_Implementation SHALL define folded relation R'(x', w') checking that w' is valid linear combination
9. THE Neo_Implementation SHALL implement extraction algorithm: given w' and ρ, recover individual witnesses {wᵢ}
10. THE Neo_Implementation SHALL prove soundness: if R'(x', w') holds, then with probability ≥ 1 - L·d/|C|, all R(xᵢ, wᵢ) hold
11. THE Neo_Implementation SHALL optimize RLC for L = 2^k by using binary tree structure
12. THE Neo_Implementation SHALL compute folded commitment in time O(L · κ) field operations
13. THE Neo_Implementation SHALL compute folded witness in time O(L · n) field operations
14. THE Neo_Implementation SHALL use Fiat-Shamir to derive ρ from hash of all commitments {Cᵢ} and public inputs {xᵢ}
15. THE Neo_Implementation SHALL document that RLC preserves witness norm up to factor ||ρ||_∞: ||w'||_∞ ≤ ||ρ||_∞ · max_i ||wᵢ||_∞

### Requirement NEO-11: Decomposition Reduction for Norm Control

**User Story:** As a norm management implementer, I want to understand witness decomposition, so that I can prevent norm blowup during recursive folding.

#### Mathematical Background

Decomposition prevents norm growth in recursive folding:

Problem: Random linear combination increases witness norm:
- If ||wᵢ||_∞ ≤ β and ||ρᵢ||_∞ ≤ B_ρ, then ||Σᵢ ρᵢ·wᵢ||_∞ ≤ L·B_ρ·β
- After k folding steps, norm grows to (L·B_ρ)^k·β

Solution: Decompose witness before folding:
- Given w with ||w||_∞ ≤ B, decompose into w = Σⱼ₌₀^{ℓ-1} bʲ·wⱼ where ||wⱼ||_∞ < b
- Choose base b such that after folding, ||Σᵢ ρᵢ·wᵢ,ⱼ||_∞ ≤ β for all j
- This keeps norm bounded across recursive folding steps

Decomposition algorithm:
- Input: w ∈ Rq^n with ||w||_∞ ≤ B
- Output: w₀, ..., w_{ℓ-1} ∈ Rq^n with ||wⱼ||_∞ < b and w = Σⱼ bʲ·wⱼ
- For each coefficient w[i] = Σⱼ₌₀^{d-1} w[i]ⱼ·Xʲ:
  * Decompose each w[i]ⱼ in base b: w[i]ⱼ = Σₖ₌₀^{ℓ-1} w[i]ⱼ,ₖ·bᵏ with |w[i]ⱼ,ₖ| < b/2
  * Set wₖ[i] = Σⱼ w[i]ⱼ,ₖ·Xʲ

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement witness decomposition taking w ∈ Rq^n with ||w||_∞ ≤ B as input
2. THE Neo_Implementation SHALL select decomposition base b and length ℓ = ⌈log_b(B)⌉
3. THE Neo_Implementation SHALL decompose each coefficient w[i]ⱼ ∈ Zq into base-b digits: w[i]ⱼ = Σₖ₌₀^{ℓ-1} w[i]ⱼ,ₖ·bᵏ
4. THE Neo_Implementation SHALL ensure each digit satisfies |w[i]ⱼ,ₖ| < b/2 using balanced representation
5. THE Neo_Implementation SHALL construct decomposed witnesses wₖ[i] = Σⱼ₌₀^{d-1} w[i]ⱼ,ₖ·Xʲ for k ∈ [ℓ]
6. THE Neo_Implementation SHALL verify decomposition correctness: w = Σₖ₌₀^{ℓ-1} bᵏ·wₖ
7. THE Neo_Implementation SHALL verify norm bounds: ||wₖ||_∞ < b for all k ∈ [ℓ]
8. THE Neo_Implementation SHALL compute commitments Cₖ = Com(wₖ) for each decomposed piece
9. THE Neo_Implementation SHALL verify commitment consistency: C = Σₖ₌₀^{ℓ-1} bᵏ·Cₖ using linear homomorphism
10. THE Neo_Implementation SHALL choose base b such that after RLC with L instances, ||Σᵢ ρᵢ·wᵢ,ₖ||_∞ ≤ β
11. THE Neo_Implementation SHALL compute optimal base: b ≈ (β / (L·||ρ||_∞))^(1/ℓ)
12. THE Neo_Implementation SHALL implement decomposition in time O(n·d·ℓ) field operations
13. THE Neo_Implementation SHALL prove that decomposition eliminates correctness gap: norm stays bounded across folding steps
14. THE Neo_Implementation SHALL document decomposition overhead: increases witness count from 1 to ℓ ≈ log_b(B)
15. THE Neo_Implementation SHALL optimize decomposition for small B by using smaller ℓ when possible

### Requirement NEO-12: Challenge Set Selection

**User Story:** As a security parameter selector, I want to understand challenge set requirements, so that I can choose parameters achieving target security level.

#### Mathematical Background

Challenge set C ⊆ Rq must satisfy:
1. Size: |C| ≥ 2^λ for λ-bit security
2. Norm bound: ||c||_∞ ≤ B_c for all c ∈ C (to control norm growth)
3. Invertibility: c - c' is invertible in Rq for all distinct c, c' ∈ C (for extraction)

Neo uses challenge set from LaBRADOR:
- C ⊆ Rq where Rq = Zq[X]/(X^64 + 1)
- Each c ∈ C has coefficients in {0, ±1, ±2}
- Operator norm: ||c||_op ≤ 15 for all c ∈ C
- Size: |C| ≥ 2^128 (exponentially large)
- Invertibility: c - c' invertible for all c ≠ c' by Lemma 2.4 (Corollary 1.2 of [LS18])

Lemma 2.4 states: If d, e are powers of 2 with e|d, q ≡ 1 + 2e (mod 4e) is prime,
then every non-zero y ∈ Rq with ||y||_∞ < q^(1/e)/√e is invertible.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define challenge set C ⊆ Rq with size |C| ≥ 2^128
2. THE Neo_Implementation SHALL ensure all c ∈ C have coefficients in {0, ±1, ±2}
3. THE Neo_Implementation SHALL verify operator norm ||c||_op ≤ 15 for all c ∈ C
4. THE Neo_Implementation SHALL implement operator norm computation: ||c||_op = sup_{y∈R} ||c·y||_∞ / ||y||_∞
5. THE Neo_Implementation SHALL verify invertibility condition: ||c - c'||_∞ < q^(1/e)/√e for all c ≠ c' ∈ C
6. THE Neo_Implementation SHALL apply Lemma 2.4 to prove c - c' is invertible in Rq
7. THE Neo_Implementation SHALL sample challenges uniformly from C using rejection sampling or table lookup
8. THE Neo_Implementation SHALL implement challenge sampling in constant time to prevent timing attacks
9. THE Neo_Implementation SHALL use Fiat-Shamir transform to derive challenges from transcript hash
10. THE Neo_Implementation SHALL ensure Fiat-Shamir hash output maps uniformly to C
11. THE Neo_Implementation SHALL document challenge set parameters: d = 64, coefficients in {0, ±1, ±2}, ||·||_op ≤ 15
12. THE Neo_Implementation SHALL verify that chosen (q, d, e) triple satisfies q ≡ 1 + 2e (mod 4e)
13. THE Neo_Implementation SHALL compute soundness error: ε ≤ (L·deg(g)) / |C| for L instances and degree-deg(g) polynomial
14. THE Neo_Implementation SHALL achieve negligible soundness error ε ≤ 2^(-128) by ensuring |C| ≥ 2^128 · L · deg(g)
15. THE Neo_Implementation SHALL provide challenge set generation algorithm producing C with required properties

### Requirement NEO-13: Folding Scheme Composition

**User Story:** As a folding scheme user, I want to understand how all reductions compose, so that I can implement the complete folding protocol.

#### Mathematical Background

Neo's folding scheme composes three reductions:
1. CCS Reduction (Π_CCS): CCS → Multilinear Evaluation Claims
2. Random Linear Combination (Π_RLC): L Evaluation Claims → 1 Evaluation Claim  
3. Decomposition (Π_DEC): High-Norm Witness → Low-Norm Witnesses

Complete folding protocol:
Input: L CCS instances {(Cᵢ, xᵢ, wᵢ)}ᵢ₌₁^L

Step 1 (Π_CCS): For each instance i:
- Run sum-check to reduce CCS(xᵢ, wᵢ) to evaluation claims
- Obtain evaluation claims {(Cᵢ, rᵢ, yᵢ,ⱼ)}ⱼ for multilinear polynomials

Step 2 (Π_RLC): Fold evaluation claims:
- Sample random ρ ∈ Fq^L
- Compute folded commitment: C' = Σᵢ ρᵢ·Cᵢ
- Compute folded evaluations: y'ⱼ = Σᵢ ρᵢ·yᵢ,ⱼ
- Compute folded witness: w' = Σᵢ ρᵢ·wᵢ

Step 3 (Π_DEC): Decompose folded witness:
- Decompose w' = Σₖ bᵏ·w'ₖ with ||w'ₖ||_∞ < b
- Compute commitments C'ₖ = Com(w'ₖ)
- Verify C' = Σₖ bᵏ·C'ₖ

Output: Single instance (C'₀, x', w'₀) with bounded norm

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement complete folding protocol composing Π_CCS, Π_RLC, and Π_DEC
2. THE Neo_Implementation SHALL take L CCS instances {(Cᵢ, xᵢ, wᵢ)}ᵢ₌₁^L as input
3. THE Neo_Implementation SHALL apply Π_CCS to each instance, reducing to evaluation claims
4. THE Neo_Implementation SHALL collect all evaluation claims from L instances
5. THE Neo_Implementation SHALL apply Π_RLC to fold evaluation claims using random challenge ρ
6. THE Neo_Implementation SHALL compute folded commitment C' = Σᵢ ρᵢ·Cᵢ
7. THE Neo_Implementation SHALL compute folded witness w' = Σᵢ ρᵢ·wᵢ
8. THE Neo_Implementation SHALL apply Π_DEC to decompose w' into low-norm pieces {w'ₖ}
9. THE Neo_Implementation SHALL output single instance (C'₀, x', w'₀) with ||w'₀||_∞ ≤ β
10. THE Neo_Implementation SHALL verify output instance satisfies CCS relation
11. THE Neo_Implementation SHALL implement prover algorithm running in time O(L·m·n + L·n·ℓ)
12. THE Neo_Implementation SHALL implement verifier algorithm running in time O(L·κ + log(m·n))
13. THE Neo_Implementation SHALL achieve soundness: if output instance is valid, then with probability ≥ 1-ε, all input instances are valid
14. THE Neo_Implementation SHALL compute soundness error: ε ≤ (L·deg(g))/|C| + (ℓ·deg(g))/|Fq|
15. THE Neo_Implementation SHALL document that folding reduces L instances to 1 instance with same norm bound

### Requirement NEO-14: IVC/PCD Construction from Folding

**User Story:** As an IVC builder, I want to understand how to construct IVC from Neo's folding scheme, so that I can build incrementally verifiable computation systems.

#### Mathematical Background

IVC (Incrementally Verifiable Computation) from folding:

Setup: Define step function F: X × W → X computing one step of computation

IVC Protocol:
- Initial state: x₀ (public), w₀ (witness)
- Accumulator: (C_acc, x_acc, w_acc) representing accumulated computation

Step i:
1. Compute new state: xᵢ = F(xᵢ₋₁, wᵢ)
2. Create instance: (Cᵢ, xᵢ, wᵢ) where Cᵢ = Com(wᵢ)
3. Fold with accumulator: (C_acc, x_acc, w_acc) ← Fold((C_acc, x_acc, w_acc), (Cᵢ, xᵢ, wᵢ))
4. Update accumulator

After n steps:
- Accumulator (C_acc, x_acc, w_acc) represents all n steps
- Generate final proof: π = Prove(C_acc, x_acc, w_acc)
- Verifier checks: Verify(C_acc, x_acc, π) and x_acc encodes correct final state

Recursive verifier circuit:
- Circuit C_verify checks: (1) previous accumulator valid, (2) current step correct, (3) folding correct
- Size of C_verify: O(κ + log(m·n)) (dominated by commitment verification and sum-check verification)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement IVC construction from Neo folding scheme
2. THE Neo_Implementation SHALL define step function F: X × W → X computing one computation step
3. THE Neo_Implementation SHALL initialize accumulator (C_acc, x_acc, w_acc) with first instance
4. FOR each step i, THE Neo_Implementation SHALL compute new state xᵢ = F(xᵢ₋₁, wᵢ)
5. THE Neo_Implementation SHALL create instance (Cᵢ, xᵢ, wᵢ) where Cᵢ = Com(wᵢ)
6. THE Neo_Implementation SHALL fold new instance with accumulator: (C_acc, x_acc, w_acc) ← Fold((C_acc, x_acc, w_acc), (Cᵢ, xᵢ, wᵢ))
7. THE Neo_Implementation SHALL update accumulator after each folding step
8. AFTER n steps, THE Neo_Implementation SHALL generate final proof π for accumulated instance
9. THE Neo_Implementation SHALL implement verifier checking accumulator validity and final state correctness
10. THE Neo_Implementation SHALL implement recursive verifier circuit C_verify with size O(κ + log(m·n))
11. THE Neo_Implementation SHALL verify previous accumulator in C_verify
12. THE Neo_Implementation SHALL verify current step correctness in C_verify
13. THE Neo_Implementation SHALL verify folding correctness in C_verify
14. THE Neo_Implementation SHALL achieve IVC prover time O(n·(m·n + κ·n)) for n steps
15. THE Neo_Implementation SHALL achieve IVC verifier time O(κ + log(m·n)) independent of n

### Requirement NEO-15: Proof Compression with SNARK

**User Story:** As a proof system designer, I want to compress the final IVC proof, so that verification is truly succinct.

#### Mathematical Background

After IVC, we have accumulator (C_acc, x_acc, w_acc) representing n computation steps.
To achieve succinct verification, we compress using a SNARK:

Compression Protocol:
1. Define relation R_acc: (C_acc, x_acc, w_acc) ∈ R_acc iff w_acc is valid witness for accumulated instance
2. Generate SNARK proof: π_snark ← SNARK.Prove(R_acc, (C_acc, x_acc), w_acc)
3. Final proof: (C_acc, x_acc, π_snark)
4. Verifier checks: SNARK.Verify(R_acc, (C_acc, x_acc), π_snark)

SNARK choice:
- Can use any SNARK (Groth16, Plonk, STARKs, etc.)
- For post-quantum security, use lattice-based or hash-based SNARK
- Neo paper suggests using another lattice-based SNARK for R_acc

Proof size:
- Without compression: O(κ·d + n·log(m·n)) (accumulator + folding proofs)
- With compression: O(κ·d + |π_snark|) where |π_snark| = O(log(m·n)) for succinct SNARK

#### Acceptance Criteria

1. THE Neo_Implementation SHALL implement proof compression using SNARK
2. THE Neo_Implementation SHALL define accumulator relation R_acc checking witness validity
3. THE Neo_Implementation SHALL generate SNARK proof π_snark for (C_acc, x_acc, w_acc) ∈ R_acc
4. THE Neo_Implementation SHALL support multiple SNARK backends (Groth16, Plonk, STARKs, lattice-based)
5. THE Neo_Implementation SHALL use post-quantum SNARK for end-to-end post-quantum security
6. THE Neo_Implementation SHALL output compressed proof (C_acc, x_acc, π_snark)
7. THE Neo_Implementation SHALL implement verifier checking SNARK.Verify(R_acc, (C_acc, x_acc), π_snark)
8. THE Neo_Implementation SHALL achieve proof size O(κ·d + |π_snark|) where |π_snark| = O(log(m·n))
9. THE Neo_Implementation SHALL achieve verification time O(|π_snark|) for SNARK verification
10. THE Neo_Implementation SHALL document compression ratio: (uncompressed size) / (compressed size) ≈ n
11. THE Neo_Implementation SHALL implement SNARK proving in time O(m·n·log(m·n)) for accumulator relation
12. THE Neo_Implementation SHALL optimize SNARK proving for structured accumulator relation
13. THE Neo_Implementation SHALL support batching multiple IVC proofs into single SNARK proof
14. THE Neo_Implementation SHALL implement proof aggregation combining multiple compressed proofs
15. THE Neo_Implementation SHALL provide configuration for trading off proof size vs proving time

### Requirement NEO-16: Concrete Parameters for Goldilocks Field

**User Story:** As a parameter implementer, I want concrete parameter values for Goldilocks field, so that I can instantiate Neo with specific security level.

#### Mathematical Background

Goldilocks field parameters:
- Prime: q = 2^64 - 2^32 + 1 = 18446744069414584321
- Cyclotomic ring: R = Z[X]/(X^64 + 1), so d = 64
- Extension degree: e = 2, so τ = d/e = 32
- Ring isomorphism: Rq ≅ F_q^32 via NTT

Module-SIS parameters for 128-bit security:
- Commitment dimension: κ = 4
- Witness dimension: n = 256
- Modulus: q = 2^64 - 2^32 + 1
- Norm bound: β = 2^20
- Security: Module-SIS(4, 256, q, 2^20) ≈ 128-bit

Sum-check parameters:
- Run over extension field F_q^2 for 128-bit security
- Challenge set size: |C| ≥ 2^128
- Soundness error: ε ≤ 2^(-128)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL use Goldilocks prime q = 2^64 - 2^32 + 1 for 64-bit field arithmetic
2. THE Neo_Implementation SHALL use cyclotomic ring R = Z[X]/(X^64 + 1) with d = 64
3. THE Neo_Implementation SHALL verify q ≡ 1 + 2^2 (mod 4·2^2), so e = 2
4. THE Neo_Implementation SHALL compute extension degree τ = 64/2 = 32
5. THE Neo_Implementation SHALL use ring isomorphism Rq ≅ F_q^32 for NTT-based multiplication
6. THE Neo_Implementation SHALL set commitment dimension κ = 4 for 128-bit security
7. THE Neo_Implementation SHALL set witness dimension n = 256 (adjustable based on application)
8. THE Neo_Implementation SHALL set norm bound β = 2^20 for witness elements
9. THE Neo_Implementation SHALL verify Module-SIS(4, 256, q, 2^20) provides ≥ 128-bit security using Lattice Estimator
10. THE Neo_Implementation SHALL run sum-check over extension field F_q^2 with elements represented as pairs (a, b) ∈ F_q^2
11. THE Neo_Implementation SHALL implement F_q^2 arithmetic using irreducible polynomial X^2 + 1 over F_q
12. THE Neo_Implementation SHALL use challenge set C with |C| ≥ 2^128 and coefficients in {0, ±1, ±2}
13. THE Neo_Implementation SHALL achieve soundness error ε ≤ 2^(-128) for all protocol invocations
14. THE Neo_Implementation SHALL document concrete parameters in configuration file
15. THE Neo_Implementation SHALL provide parameter validation function checking security requirements

### Requirement NEO-17: Concrete Parameters for Mersenne 61 Field

**User Story:** As a parameter implementer, I want concrete parameter values for M61 field, so that I can use Mersenne prime for faster arithmetic.

#### Mathematical Background

Mersenne 61 field parameters:
- Prime: q = 2^61 - 1 = 2305843009213693951 (Mersenne prime)
- Cyclotomic ring: R = Z[X]/(X^64 + 1), so d = 64
- Extension degree: e = 1 (q ≡ 1 (mod 128), so ring splits completely)
- Ring isomorphism: Rq ≅ F_q^64 via NTT

Fast arithmetic with Mersenne primes:
- Modular reduction: a mod (2^61 - 1) = (a & (2^61-1)) + (a >> 61)
- No expensive division needed
- Multiplication: O(1) using 128-bit intermediate results

Module-SIS parameters for 128-bit security:
- Commitment dimension: κ = 5 (slightly larger due to smaller q)
- Witness dimension: n = 256
- Modulus: q = 2^61 - 1
- Norm bound: β = 2^18
- Security: Module-SIS(5, 256, q, 2^18) ≈ 128-bit

#### Acceptance Criteria

1. THE Neo_Implementation SHALL use Mersenne 61 prime q = 2^61 - 1 for fast modular arithmetic
2. THE Neo_Implementation SHALL implement fast modular reduction: a mod q = (a & (2^61-1)) + (a >> 61)
3. THE Neo_Implementation SHALL use cyclotomic ring R = Z[X]/(X^64 + 1) with d = 64
4. THE Neo_Implementation SHALL verify q ≡ 1 (mod 128), so e = 1 and ring splits completely
5. THE Neo_Implementation SHALL compute extension degree τ = 64/1 = 64
6. THE Neo_Implementation SHALL use ring isomorphism Rq ≅ F_q^64 for NTT-based multiplication
7. THE Neo_Implementation SHALL set commitment dimension κ = 5 for 128-bit security with smaller modulus
8. THE Neo_Implementation SHALL set witness dimension n = 256 (adjustable based on application)
9. THE Neo_Implementation SHALL set norm bound β = 2^18 for witness elements
10. THE Neo_Implementation SHALL verify Module-SIS(5, 256, q, 2^18) provides ≥ 128-bit security
11. THE Neo_Implementation SHALL run sum-check over extension field F_q^2 for 128-bit security
12. THE Neo_Implementation SHALL implement F_q^2 arithmetic using irreducible polynomial over F_q
13. THE Neo_Implementation SHALL use challenge set C with |C| ≥ 2^128
14. THE Neo_Implementation SHALL achieve soundness error ε ≤ 2^(-128)
15. THE Neo_Implementation SHALL benchmark M61 vs Goldilocks to compare concrete performance

### Requirement NEO-18: Security Analysis and Proofs

**User Story:** As a security analyst, I want to understand the security proofs, so that I can verify the claimed security properties.

#### Mathematical Background

Neo's security relies on three main properties:

1. Commitment Binding (Module-SIS):
   Theorem: If Module-SIS(κ, n, q, β) is hard, then Ajtai commitment is binding.
   Proof: If adversary finds w ≠ w' with Com(w) = Com(w'), then A(w - w') = 0 mod q.
   Since ||w - w'||_∞ ≤ 2β, this breaks Module-SIS.

2. Folding Soundness:
   Theorem: If folded instance is valid, then with probability ≥ 1 - ε, all original instances are valid.
   Proof: By Schwartz-Zippel lemma, if any original instance is invalid, the folded polynomial
   evaluates to non-zero with probability ≥ 1 - (L·deg(g))/|C|.

3. Knowledge Soundness:
   Theorem: If prover convinces verifier, then there exists extractor recovering valid witness.
   Proof: Extractor rewinds prover with different challenges, obtains multiple transcripts,
   solves linear system to recover witness. Invertibility of challenge differences ensures unique solution.

#### Acceptance Criteria

1. THE Neo_Implementation SHALL document security reduction from commitment binding to Module-SIS hardness
2. THE Neo_Implementation SHALL prove that breaking commitment binding implies solving Module-SIS instance
3. THE Neo_Implementation SHALL compute Module-SIS hardness using Lattice Estimator with BKZ block size b ≥ 128
4. THE Neo_Implementation SHALL document folding soundness proof using Schwartz-Zippel lemma
5. THE Neo_Implementation SHALL compute soundness error: ε ≤ (L·deg(g))/|C| for L instances and degree-deg(g) polynomial
6. THE Neo_Implementation SHALL ensure |C| ≥ 2^128 · L · deg(g) fo6. TH
E Neo_Implementation SHALL optimize commitment computation by processing only non-zero coefficients for sparse vectors
7. THE Neo_Implementation SHALL track actual bit-width of each vector element for accurate cost accounting
8. THE Neo_Implementation SHALL provide API for specifying bit-width per element: commit_with_widths(values, bit_widths)
9. THE Neo_Implementation SHALL verify that claimed bit-widths are sufficient: value < 2^bit_width for all elements
10. THE Neo_Implementation SHALL document pay-per-bit savings in commitment cost metrics

### Requirement NEO-5: Linear Homomorphism Property

**User Story:** As a folding scheme implementer, I want the commitment scheme to be linearly homomorphic, so that I can efficiently fold commitments without recomputing from scratch.

#### Mathematical Background

Linear homomorphism is essential for folding:
- For witnesses w₁, w₂ ∈ Rq^n and scalars α, β ∈ Rq
- Homomorphism: Com(αw₁ + βw₂) = α·Com(w₁) + β·Com(w₂) mod q

Proof of homomorphism:
```
Com(αw₁ + βw₂) = A(αw₁ + βw₂) mod q
                = αAw₁ + βAw₂ mod q
                = α·Com(w₁) + β·Com(w₂) mod q
```

This enables efficient folding:
- Given commitments c₁ = Com(w₁), c₂ = Com(w₂)
- Folded commitment: c' = α·c₁ + β·c₂
- Folded witness: w' = αw₁ + βw₂
- Verification: Com(w') = c' without recomputing full commitment

#### Acceptance Criteria

1. THE Neo_Implementation SHALL verify linear homomorphism: Com(αw₁ + βw₂) = α·Com(w₁) + β·Com(w₂) mod q
2. THE Neo_Implementation SHALL implement commitment addition: add_commitments(c₁, c₂) = c₁ + c₂ mod q
3. THE Neo_Implementation SHALL implement commitment scalar multiplication: scale_commitment(α, c) = α·c mod q
4. THE Neo_Implementation SHALL compute folded commitment as c' = Σᵢ αᵢ·cᵢ mod q for multiple commitments
5. THE Neo_Implementation SHALL compute folded witness as w' = Σᵢ αᵢ·wᵢ for corresponding witnesses
6. THE Neo_Implementation SHALL verify Com(w') = c' after folding operation
7. THE Neo_Implementation SHALL implement batched commitment operations for efficiency
8. THE Neo_Implementation SHALL ensure homomorphism holds for ring scalar multiplication (α ∈ Rq)
9. THE Neo_Implementation SHALL verify homomorphism preserves norm bounds: ||w'||_∞ ≤ Σᵢ |αᵢ|·||wᵢ||_∞
10. THE Neo_Implementation SHALL provide unit tests verifying homomorphism property with random inputs

### Requirement NEO-6: Multilinear Extension and Evaluation Claims

**User Story:** As a polynomial commitment user, I want to understand how vectors are treated as multilinear polynomials, so that I can prove evaluation claims efficiently.

#### Mathematical Background

Multilinear Extension (MLE):
- Given vector w ∈ F^N where N = 2^ℓ
- MLE is unique multilinear polynomial w̃: F^ℓ → F
- Satisfies: w̃(x) = w[x] for all x ∈ {0,1}^ℓ
- Explicit formula: w̃(r) = Σ_{x∈{0,1}^ℓ} w[x] · ∏ᵢ (rᵢxᵢ + (1-rᵢ)(1-xᵢ))

Evaluation claim:
- Instance: (C, r, y) where C = Com(w), r ∈ F^ℓ, y ∈ F
- Witness: w ∈ F^N
- Relation: C = Com(w) AND w̃(r) = y

Folding evaluation claims:
- Given β claims: {(Cᵢ, r, yᵢ)}ᵢ∈[β] with witnesses {wᵢ}ᵢ∈[β]
- Sample random α ∈ F^β
- Folded claim: (C', r, y') where:
  - C' = Σᵢ αᵢ·Cᵢ
  - y' = Σᵢ αᵢ·yᵢ
  - w' = Σᵢ αᵢ·wᵢ
- Correctness: w̃'(r) = Σᵢ αᵢ·w̃ᵢ(r) = Σᵢ αᵢ·yᵢ = y'

#### Acceptance Criteria

1. THE Neo_Implementation SHALL represent vector w ∈ F^N as multilinear polynomial w̃ over ℓ = log₂(N) variables
2. THE Neo_Implementation SHALL implement MLE evaluation: eval_mle(w, r) = Σ_{x∈{0,1}^ℓ} w[x] · eq(r, x)
3. THE Neo_Implementation SHALL implement equality polynomial: eq(r, x) = ∏ᵢ (rᵢxᵢ + (1-rᵢ)(1-xᵢ))
4. THE Neo_Implementation SHALL verify MLE uniqueness: only one multilinear polynomial extends given vector
5. THE Neo_Implementation SHALL implement efficient MLE evaluation in O(N) time using dynamic programming
6. THE Neo_Implementation SHALL define evaluation claim as tuple (commitment, point, value): (C, r, y)
7. THE Neo_Implementation SHALL verify evaluation claim by checking: Com(w) = C AND eval_mle(w, r) = y
8. THE Neo_Implementation SHALL implement folding of β evaluation claims into single claim
9. THE Neo_Implementation SHALL sample folding coefficients α ∈ F^β from challenge set with |C| ≥ 2^128
10. THE Neo_Implementation SHALL compute folded commitment: C' = Σᵢ αᵢ·Cᵢ using linear homomorphism
11. THE Neo_Implementation SHALL compute folded value: y' = Σᵢ αᵢ·yᵢ
12. THE Neo_Implementation SHALL compute folded witness: w' = Σᵢ αᵢ·wᵢ
13. THE Neo_Implementation SHALL verify folded claim: Com(w') = C' AND eval_mle(w', r) = y'
14. THE Neo_Implementation SHALL ensure folding preserves evaluation: w̃'(r) = Σᵢ αᵢ·w̃ᵢ(r) by linearity
15. THE Neo_Implementation SHALL implement batched MLE evaluation for multiple points efficiently

### Requirement NEO-7: CCS Relation Definition

**User Story:** As a constraint system user, I want to understand the exact CCS relation format, so that I can encode my computations correctly.

#### Mathematical Background

CCS (Customizable Constraint System) is defined by:
- Structure: (m, n, N, ℓ, t, q, d, M, S, c)
  - m: number of constraints
  - n: number of variables (witness size)
  - N = 2^ℓ: size after padding to power of 2
  - t: number of matrices
  - q: number of multilinear terms
  - d: maximum degree of each term
  - M = (M₀, ..., M_{t-1}): matrices in F^{m×n}
  - S = (S₀, ..., S_{q-1}): sets of matrix indices, Sᵢ ⊆ [t]
  - c = (c₀, ..., c_{q-1}): coefficients in F

CCS Relation:
- Instance: x ∈ F^ℓ (public input)
- Witness: w ∈ F^{n-ℓ-1} (private witness)
- Full witness: z = (1, x, w) ∈ F^n
- Constraint: Σᵢ₌₀^{q-1} cᵢ · ∘_{j∈Sᵢ} Mⱼz = 0 ∈ F^m

Where ∘ denotes Hadamard (element-wise) product.

R1CS as special case:
- q = 1, t = 3, d = 2
- M = (A, B, C), S₀ = {0, 1}, c₀ = 1
- Constraint: (Az) ∘ (Bz) - Cz = 0

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define CCS structure with parameters (m, n, N, ℓ, t, q, d, M, S, c)
2. THE Neo_Implementation SHALL represent matrices M₀, ..., M_{t-1} ∈ F^{m×n} in sparse or dense format
3. THE Neo_Implementation SHALL define matrix index sets S₀, ..., S_{q-1} where each Sᵢ ⊆ [t]
4. THE Neo_Implementation SHALL define coefficients c₀, ..., c_{q-1} ∈ F for each multilinear term
5. THE Neo_Implementation SHALL construct full witness z = (1, x, w) where x is public input, w is private witness
6. THE Neo_Implementation SHALL compute matrix-vector products: vⱼ = Mⱼz for j ∈ [t]
7. THE Neo_Implementation SHALL compute Hadamard products: ∘_{j∈Sᵢ} vⱼ for each term i
8. THE Neo_Implementation SHALL compute weighted sum: Σᵢ cᵢ · (∘_{j∈Sᵢ} vⱼ)
9. THE Neo_Implementation SHALL verify CCS satisfaction: Σᵢ cᵢ · (∘_{j∈Sᵢ} Mⱼz) = 0 ∈ F^m
10. THE Neo_Implementation SHALL support R1CS as special case with q=1, t=3, d=2
11. THE Neo_Implementation SHALL support Plonkish constraints by appropriate choice of M, S, c
12. THE Neo_Implementation SHALL support AIR constraints by appropriate choice of M, S, c
13. THE Neo_Implementation SHALL pad witness to N = 2^ℓ for power-of-2 size
14. THE Neo_Implementation SHALL validate CCS structure: |Sᵢ| ≤ d for all i, max_i |Sᵢ| = d
15. THE Neo_Implementation SHALL provide API for constructing CCS from high-level constraint descriptions

### Requirement NEO-8: Sum-Check Protocol for CCS Linearization

**User Story:** As a CCS prover, I want to understand how sum-check linearizes CCS constraints, so that I can implement the reduction correctly.

#### Mathematical Background

Sum-check reduces CCS to multilinear evaluation claims:

Step 1: Define polynomial g over Boolean hypercube
```
g(x) = Σᵢ₌₀^{q-1} cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(x)
```
where (Mⱼz)~ is the multilinear extension of vector Mⱼz.

Step 2: CCS satisfaction equivalent to:
```
Σ_{x∈{0,1}^ℓ} g(x) = 0
```

Step 3: Sum-check protocol
- Prover and verifier interact for ℓ rounds
- Round i: Prover sends univariate polynomial sᵢ(X) of degree ≤ d
- Verifier checks: sᵢ(0) + sᵢ(1) = claimed sum (or previous sᵢ₋₁(rᵢ₋₁))
- Verifier samples random challenge rᵢ ∈ F
- Continue with g(r₁, ..., rᵢ, X_{i+1}, ..., X_ℓ)

Step 4: Final check
- After ℓ rounds, verifier has point r = (r₁, ..., r_ℓ) ∈ F^ℓ
- Verifier needs to check: g(r) = s_ℓ(r_ℓ)
- This requires evaluating (Mⱼz)~(r) for all j ∈ [t]

Step 5: Reduction to evaluation claims
- Prover commits to z: C = Com(z)
- For each j ∈ [t], prover claims: (Mⱼz)~(r) = vⱼ
- Verifier checks: g(r) = Σᵢ cᵢ · ∏_{j∈Sᵢ} vⱼ = s_ℓ(r_ℓ)
- Reduced to t evaluation claims: {(C, Mⱼ, r, vⱼ)}_{j∈[t]}

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define CCS polynomial: g(x) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(x)
2. THE Neo_Implementation SHALL verify CCS satisfaction equivalent to: Σ_{x∈{0,1}^ℓ} g(x) = 0
3. THE Neo_Implementation SHALL implement sum-check prover for ℓ rounds
4. THE Neo_Implementation SHALL compute round i message: sᵢ(X) = Σ_{x∈{0,1}^{ℓ-i}} g(r₁,...,rᵢ₋₁,X,x)
5. THE Neo_Implementation SHALL ensure sᵢ(X) has degree at most d (maximum |Sᵢ|)
6. THE Neo_Implementation SHALL send sᵢ(X) as d+1 evaluation points: sᵢ(0), sᵢ(1), ..., sᵢ(d)
7. THE Neo_Implementation SHALL verify sum-check round i: sᵢ(0) + sᵢ(1) = previous_sum
8. THE Neo_Implementation SHALL sample challenge rᵢ ∈ F after receiving sᵢ(X)
9. THE Neo_Implementation SHALL update polynomial: g ← g(r₁,...,rᵢ,X_{i+1},...,X_ℓ)
10. THE Neo_Implementation SHALL compute final evaluation: g(r) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(r)
11. THE Neo_Implementation SHALL verify final check: g(r) = s_ℓ(r_ℓ)
12. THE Neo_Implementation SHALL generate t evaluation claims: {(C, Mⱼ, r, vⱼ)}_{j∈[t]}
13. THE Neo_Implementation SHALL compute claimed values: vⱼ = (Mⱼz)~(r) for j ∈ [t]
14. THE Neo_Implementation SHALL verify consistency: g(r) = Σᵢ cᵢ · ∏_{j∈Sᵢ} vⱼ
15. THE Neo_Implementation SHALL achieve sum-check prover time O(N · d) and proof size O(ℓ · d) field elements

### Requirement NEO-9: Matrix-Vector Product Evaluation Claims

**User Story:** As an evaluation claim handler, I want to understand how to reduce matrix-vector product evaluations to witness evaluations, so that I can implement the transformation correctly.

#### Mathematical Background

Matrix-vector product MLE:
- Given matrix M ∈ F^{m×n} and vector z ∈ F^n
- Product: v = Mz ∈ F^m
- MLE of v: ṽ(r) = (Mz)~(r)

Key insight: Express as inner product
```
ṽ(r) = Σ_{x∈{0,1}^ℓ} v[x] · eq(r, x)
      = Σ_{x∈{0,1}^ℓ} (Σⱼ M[x,j] · z[j]) · eq(r, x)
      = Σⱼ z[j] · (Σ_{x∈{0,1}^ℓ} M[x,j] · eq(r, x))
      = Σⱼ z[j] · M̃ⱼ(r)
      = ⟨z, M̃(r)⟩
```

where M̃ⱼ(r) is the MLE of j-th column of M evaluated at r.

Reduction:
- Evaluation claim: (C, M, r, v) where v = (Mz)~(r)
- Equivalent to: (C, r', v) where r' = M̃(r) and v = z̃(r')
- This is a standard witness evaluation claim!

#### Acceptance Criteria

1. THE Neo_Implementation SHALL represent matrix M ∈ F^{m×n} with m = 2^{ℓ_m}, n = 2^{ℓ_n}
2. THE Neo_Implementation SHALL compute matrix-vector product: v = Mz ∈ F^m
3. THE Neo_Implementation SHALL define MLE of product: ṽ(r) = (Mz)~(r) for r ∈ F^{ℓ_m}
4. THE Neo_Implementation SHALL express ṽ(r) as inner product: ṽ(r) = ⟨z, M̃(r)⟩
5. THE Neo_Implementation SHALL compute column MLEs: M̃ⱼ(r) for j ∈ [n]
6. THE Neo_Implementation SHALL define evaluation vector: r' = (M̃₀(r), M̃₁(r), ..., M̃_{n-1}(r)) ∈ F^n
7. THE Neo_Implementation SHALL reduce matrix-vector claim (C, M, r, v) to witness claim (C, r', v)
8. THE Neo_Implementation SHALL verify equivalence: (Mz)~(r) = z̃(r') where r' = M̃(r)
9. THE Neo_Implementation SHALL implement efficient computation of M̃(r) in O(m·n) time
10. THE Neo_Implementation SHALL cache M̃(r) when same matrix M is used for multiple claims
11. THE Neo_Implementation SHALL support sparse matrix representation for efficient M̃(r) computation
12. THE Neo_Implementation SHALL verify reduction correctness: v = ṽ(r) = ⟨z, M̃(r)⟩ = z̃(r')
13. THE Neo_Implementation SHALL batch multiple matrix-vector claims with same r
14. THE Neo_Implementation SHALL implement structured matrix optimizations (circulant, Toeplitz, etc.)
15. THE Neo_Implementation SHALL provide API: reduce_mv_claim(C, M, r, v) → (C, r', v)

### Requirement NEO-10: Folding Scheme for Evaluation Claims

**User Story:** As a folding implementer, I want to understand the complete folding protocol for evaluation claims, so that I can implement Neo's core folding scheme.

#### Mathematical Background

Folding Protocol for β evaluation claims:

Input:
- Claims: {(Cᵢ, r, yᵢ)}ᵢ∈[β]
- Witnesses: {wᵢ}ᵢ∈[β] where Cᵢ = Com(wᵢ) and w̃ᵢ(r) = yᵢ

Protocol:
1. Prover computes cross-terms:
   - For i < j: compute σᵢⱼ = ⟨wᵢ, wⱼ⟩ where ⟨·,·⟩ is inner product
   - Send all σᵢⱼ to verifier

2. Verifier samples random α = (α₀, ..., α_{β-1}) ∈ F^β from challenge set C

3. Prover computes folded witness:
   - w' = Σᵢ αᵢ · wᵢ

4. Prover computes folded commitment:
   - C' = Σᵢ αᵢ · Cᵢ (using linear homomorphism)

5. Prover computes folded evaluation:
   - y' = Σᵢ αᵢ · yᵢ

6. Verifier checks consistency:
   - Verify: ⟨w', w'⟩ = Σᵢ αᵢ² · yᵢ² + 2·Σ_{i<j} αᵢαⱼ · σᵢⱼ
   - This ensures cross-terms are correct

Output:
- Folded claim: (C', r, y')
- Folded witness: w'
- Relation: C' = Com(w') and w̃'(r) = y'

Soundness:
- If prover can open C' to w' with w̃'(r) = y'
- Then with high probability, prover knows wᵢ for all i with w̃ᵢ(r) = yᵢ
- Soundness error: O(d/|C|) where d is polynomial degree

#### Acceptance Criteria

1. THE Neo_Implementation SHALL accept β evaluation claims: {(Cᵢ, r, yᵢ)}ᵢ∈[β] with witnesses {wᵢ}ᵢ∈[β]
2. THE Neo_Implementation SHALL verify input claims: Cᵢ = Com(wᵢ) AND w̃ᵢ(r) = yᵢ for all i
3. THE Neo_Implementation SHALL compute cross-terms: σᵢⱼ = ⟨wᵢ, wⱼ⟩ for all i < j
4. THE Neo_Implementation SHALL send cross-terms {σᵢⱼ}_{i<j} to verifier (β(β-1)/2 field elements)
5. THE Neo_Implementation SHALL sample folding coefficients α ∈ F^β from challenge set with |C| ≥ 2^128
6. THE Neo_Implementation SHALL compute folded witness: w' = Σᵢ αᵢ · wᵢ
7. THE Neo_Implementation SHALL compute folded commitment: C' = Σᵢ αᵢ · Cᵢ using homomorphism
8. THE Neo_Implementation SHALL compute folded value: y' = Σᵢ αᵢ · yᵢ
9. THE Neo_Implementation SHALL verify cross-term consistency: ⟨w', w'⟩ = Σᵢ αᵢ² · yᵢ² + 2·Σ_{i<j} αᵢαⱼ · σᵢⱼ
10. THE Neo_Implementation SHALL verify folded claim: C' = Com(w') AND w̃'(r) = y'
11. THE Neo_Implementation SHALL achieve soundness error ≤ d/|C| per folding step
12. THE Neo_Implementation SHALL implement batched cross-term computation for efficiency
13. THE Neo_Implementation SHALL optimize for β = 2 case (most common): only one cross-term σ₀₁
14. THE Neo_Implementation SHALL support arbitrary β ≥ 2 for flexible folding
15. THE Neo_Implementation SHALL provide folding proof size: O(β²) field elements for cross-terms

### Requirement NEO-11: Random Linear Combination Reduction (ΠRLC)

**User Story:** As a reduction implementer, I want to understand the RLC reduction protocol, so that I can batch multiple evaluation claims efficiently.

#### Mathematical Background

Random Linear Combination (RLC) reduces multiple claims to one:

Input:
- L evaluation claims: {(Cᵢ, rᵢ, yᵢ)}ᵢ∈[L]
- Witnesses: {wᵢ}ᵢ∈[L]

Protocol ΠRLC:
1. Verifier samples random coefficients: ρ = (ρ₀, ..., ρ_{L-1}) ∈ F^L

2. Prover computes combined witness:
   - w* = Σᵢ ρᵢ · wᵢ

3. Prover computes combined commitment:
   - C* = Σᵢ ρᵢ · Cᵢ

4. Define combined evaluation function:
   - f*(x) = Σᵢ ρᵢ · w̃ᵢ(rᵢ) · eq(rᵢ, x)
   - Note: f*(rⱼ) = ρⱼ · w̃ⱼ(rⱼ) = ρⱼ · yⱼ for each j

5. Verifier samples random point: r* ∈ F^ℓ

6. Prover computes combined value:
   - y* = f*(r*) = Σᵢ ρᵢ · w̃ᵢ(rᵢ) · eq(rᵢ, r*)

Output:
- Single claim: (C*, r*, y*)
- Witness: w*
- Relation: C* = Com(w*) and f̃*(r*) = y*

Key property:
- If prover can open C* to w* with correct evaluation
- Then with high probability, prover knows all wᵢ with correct evaluations
- Soundness: Schwartz-Zippel lemma over random point r*

#### Acceptance Criteria

1. THE Neo_Implementation SHALL accept L evaluation claims: {(Cᵢ, rᵢ, yᵢ)}ᵢ∈[L] with witnesses {wᵢ}ᵢ∈[L]
2. THE Neo_Implementation SHALL verify input claims: Cᵢ = Com(wᵢ) AND w̃ᵢ(rᵢ) = yᵢ for all i ∈ [L]
3. THE Neo_Implementation SHALL sample random coefficients: ρ = (ρ₀, ..., ρ_{L-1}) ∈ F^L
4. THE Neo_Implementation SHALL compute combined witness: w* = Σᵢ ρᵢ · wᵢ
5. THE Neo_Implementation SHALL compute combined commitment: C* = Σᵢ ρᵢ · Cᵢ using homomorphism
6. THE Neo_Implementation SHALL define combined evaluation function: f*(x) = Σᵢ ρᵢ · w̃ᵢ(rᵢ) · eq(rᵢ, x)
7. THE Neo_Implementation SHALL verify f*(rⱼ) = ρⱼ · yⱼ for each j ∈ [L]
8. THE Neo_Implementation SHALL sample random evaluation point: r* ∈ F^ℓ
9. THE Neo_Implementation SHALL compute combined value: y* = f*(r*) = Σᵢ ρᵢ · w̃ᵢ(rᵢ) · eq(rᵢ, r*)
10. THE Neo_Implementation SHALL output single claim: (C*, r*, y*)
11. THE Neo_Implementation SHALL verify output claim: C* = Com(w*) AND f̃*(r*) = y*
12. THE Neo_Implementation SHALL achieve soundness via Schwartz-Zippel: error ≤ deg(f*)/|F|
13. THE Neo_Implementation SHALL implement efficient computation of eq(rᵢ, r*) for all i
14. THE Neo_Implementation SHALL batch computation of w̃ᵢ(rᵢ) evaluations
15. THE Neo_Implementation SHALL provide RLC proof size: O(1) field elements (just random coefficients)

### Requirement NEO-12: Decomposition Reduction (ΠDEC)

**User Story:** As a norm management implementer, I want to understand the decomposition reduction, so that I can prevent norm blowup during recursive folding.

#### Mathematical Background

Decomposition prevents norm growth:

Problem:
- After folding with coefficients α, witness norm grows: ||w'|| ≤ Σᵢ |αᵢ| · ||wᵢ||
- Recursive folding causes exponential norm growth
- Eventually exceeds modulus q, breaking soundness

Solution - Decomposition:
- Decompose witness w into base-b digits: w = Σⱼ bʲ · wⱼ
- Each digit witness has small norm: ||wⱼ||_∞ < b
- Number of digits: ℓ = ⌈log_b(||w||_∞)⌉

Protocol ΠDEC:
Input:
- Claim: (C, r, y) with witness w where ||w||_∞ ≤ B

1. Prover decomposes witness:
   - For each element w[i], write w[i] = Σⱼ bʲ · wⱼ[i]
   - Ensure ||wⱼ||_∞ < b for all j

2. Prover computes digit commitments:
   - Cⱼ = Com(wⱼ) for j ∈ [ℓ]

3. Prover computes digit evaluations:
   - yⱼ = w̃ⱼ(r) for j ∈ [ℓ]

4. Verifier checks reconstruction:
   - C = Σⱼ bʲ · Cⱼ (using homomorphism)
   - y = Σⱼ bʲ · yⱼ

Output:
- ℓ claims: {(Cⱼ, r, yⱼ)}ⱼ∈[ℓ]
- Witnesses: {wⱼ}ⱼ∈[ℓ] with ||wⱼ||_∞ < b

Norm control:
- Original norm: ||w||_∞ ≤ B
- Digit norm: ||wⱼ||_∞ < b
- Typically choose b = O(√B) so ℓ = O(log B / log b) = O(1)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL accept claim (C, r, y) with witness w where ||w||_∞ ≤ B
2. THE Neo_Implementation SHALL choose decomposition base b = ⌈√B⌉ for optimal balance
3. THE Neo_Implementation SHALL compute number of digits: ℓ = ⌈log_b(B)⌉
4. THE Neo_Implementation SHALL decompose each element: w[i] = Σⱼ₌₀^{ℓ-1} bʲ · wⱼ[i]
5. THE Neo_Implementation SHALL ensure digit bounds: ||wⱼ||_∞ < b for all j ∈ [ℓ]
6. THE Neo_Implementation SHALL use balanced representation: wⱼ[i] ∈ [-b/2, b/2)
7. THE Neo_Implementation SHALL compute digit commitments: Cⱼ = Com(wⱼ) for j ∈ [ℓ]
8. THE Neo_Implementation SHALL compute digit evaluations: yⱼ = w̃ⱼ(r) for j ∈ [ℓ]
9. THE Neo_Implementation SHALL verify commitment reconstruction: C = Σⱼ bʲ · Cⱼ
10. THE Neo_Implementation SHALL verify evaluation reconstruction: y = Σⱼ bʲ · yⱼ
11. THE Neo_Implementation SHALL output ℓ claims: {(Cⱼ, r, yⱼ)}ⱼ∈[ℓ] with small-norm witnesses
12. THE Neo_Implementation SHALL achieve decomposition proof size: O(ℓ) commitments and evaluations
13. THE Neo_Implementation SHALL implement efficient decomposition using lookup tables for small b
14. THE Neo_Implementation SHALL support variable base decomposition for different norm bounds
15. THE Neo_Implementation SHALL verify decomposition correctness before proceeding with folding

### Requirement NEO-13: Complete Neo Folding Scheme

**User Story:** As a complete system implementer, I want to understand how all reductions combine into Neo's full folding scheme, so that I can implement the end-to-end protocol.

#### Mathematical Background

Complete Neo Folding Scheme:

Input:
- Two CCS instances: (x₁, w₁) and (x₂, w₂)
- CCS structure: (m, n, N, ℓ, t, q, d, M, S, c)

Phase 1: CCS to Evaluation Claims (both instances)
1. For each instance i ∈ {1, 2}:
   - Construct full witness: zᵢ = (1, xᵢ, wᵢ)
   - Commit to witness: Cᵢ = Com(zᵢ)
   - Run sum-check on: Σ_{x∈{0,1}^ℓ} gᵢ(x) = 0
   - Reduce to t evaluation claims: {(Cᵢ, Mⱼ, r, vᵢⱼ)}ⱼ∈[t]

Phase 2: Matrix-Vector Reduction
- For each j ∈ [t], reduce (Cᵢ, Mⱼ, r, vᵢⱼ) to (Cᵢ, r'ⱼ, vᵢⱼ)
- Where r'ⱼ = M̃ⱼ(r)
- Now have 2t witness evaluation claims

Phase 3: Random Linear Combination
- Apply ΠRLC to combine 2t claims into single claim: (C*, r*, y*)
- Witness: w* = Σᵢ,ⱼ ρᵢⱼ · zᵢ

Phase 4: Decomposition
- Apply ΠDEC to (C*, r*, y*) with witness w*
- Get ℓ claims: {(C*ⱼ, r*, y*ⱼ)}ⱼ∈[ℓ] with small-norm witnesses

Phase 5: Folding
- Apply folding protocol to ℓ claims
- Get single claim: (C', r*, y') with witness w'
- Norm: ||w'||_∞ ≤ poly(λ) · b where b is decomposition base

Output:
- Folded instance: (C', r*, y')
- Folded witness: w'
- Relation: C' = Com(w') and w̃'(r*) = y'

Key properties:
- Prover time: O(N) dominated by commitments
- Verifier time: O(log N) dominated by sum-check verification
- Proof size: O(log N) field elements
- Soundness: negligible error with |C| ≥ 2^128

#### Acceptance Criteria

1. THE Neo_Implementation SHALL accept two CCS instances: (x₁, w₁) and (x₂, w₂)
2. THE Neo_Implementation SHALL verify both instances satisfy CCS relation
3. THE Neo_Implementation SHALL construct full witnesses: z₁ = (1, x₁, w₁), z₂ = (1, x₂, w₂)
4. THE Neo_Implementation SHALL commit to witnesses: C₁ = Com(z₁), C₂ = Com(z₂)
5. THE Neo_Implementation SHALL run sum-check for both instances reducing to 2t evaluation claims
6. THE Neo_Implementation SHALL apply matrix-vector reduction to all 2t claims
7. THE Neo_Implementation SHALL apply RLC combining 2t claims into single claim (C*, r*, y*)
8. THE Neo_Implementation SHALL apply decomposition to (C*, r*, y*) producing ℓ small-norm claims
9. THE Neo_Implementation SHALL apply folding protocol to ℓ claims producing final claim (C', r*, y')
10. THE Neo_Implementation SHALL verify folded claim: C' = Com(w') AND w̃'(r*) = y'
11. THE Neo_Implementation SHALL achieve prover time O(N) dominated by O(N) ring multiplications for commitments
12. THE Neo_Implementation SHALL achieve verifier time O(log N) dominated by sum-check verification
13. THE Neo_Implementation SHALL achieve proof size O(log N) field elements
14. THE Neo_Implementation SHALL achieve soundness error ≤ 2^(-128) with appropriate challenge set
15. THE Neo_Implementation SHALL support recursive folding by treating (C', r*, y') as new instance

### Requirement NEO-14: Challenge Set Selection

**User Story:** As a security parameter selector, I want to understand challenge set requirements, so that I can ensure adequate soundness.

#### Mathematical Background

Challenge set C ⊆ Rq must satisfy:

1. Size requirement:
   - |C| ≥ 2^λ for λ-bit security
   - Typically λ = 128, so |C| ≥ 2^128

2. Norm requirement:
   - All c ∈ C have small norm: ||c||_∞ ≤ B_challenge
   - Prevents norm blowup during folding
   - Typically B_challenge = O(1) or O(log λ)

3. Invertibility (for some protocols):
   - All differences c - c' for c ≠ c' ∈ C are invertible in Rq
   - Ensures extraction works correctly

Neo's challenge set construction:
- Use Rq = Zq[X]/(X^d + 1) with q = 2^64 - 2^32 + 1, d = 64
- Challenge set: C = {Σᵢ cᵢ X^i : cᵢ ∈ {-1, 0, 1}}
- Size: |C| = 3^d = 3^64 ≈ 2^101 (sufficient for 128-bit security with repetition)
- Norm: ||c||_∞ = 1 for all c ∈ C
- Operator norm: ||c||_op ≤ √d = 8 for all c ∈ C

Alternative: Use extension field
- Work over F_q^2 instead of F_q
- Challenge set: C = F_q^2
- Size: |C| = q^2 ≈ 2^128 (sufficient for 128-bit security)
- Norm: ||c||_∞ ≤ q/2 (larger, but acceptable with proper parameters)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL define challenge set C ⊆ Rq with |C| ≥ 2^128
2. THE Neo_Implementation SHALL ensure all c ∈ C have small norm: ||c||_∞ ≤ B_challenge
3. THE Neo_Implementation SHALL compute operator norm bound: ||c||_op ≤ √d · B_challenge
4. THE Neo_Implementation SHALL verify invertibility: c - c' invertible for all c ≠ c' ∈ C (if required)
5. THE Neo_Implementation SHALL implement ternary challenge set: C = {Σᵢ cᵢ X^i : cᵢ ∈ {-1, 0, 1}}
6. THE Neo_Implementation SHALL compute ternary set size: |C| = 3^d
7. THE Neo_Implementation SHALL verify 3^d ≥ 2^128 for chosen d (requires d ≥ 81)
8. THE Neo_Implementation SHALL implement extension field challenge set: C = F_q^τ for appropriate τ
9. THE Neo_Implementation SHALL verify extension field size: q^τ ≥ 2^128
10. THE Neo_Implementation SHALL sample challenges uniformly from C using cryptographic randomness
11. THE Neo_Implementation SHALL implement Fiat-Shamir transform for non-interactive challenge generation
12. THE Neo_Implementation SHALL hash transcript to generate challenge: c = H(transcript) mod C
13. THE Neo_Implementation SHALL ensure challenge distribution is statistically close to uniform
14. THE Neo_Implementation SHALL document challenge set choice and security justification
15. THE Neo_Implementation SHALL provide challenge set validation function checking all requirements

### Requirement NEO-15: Security Analysis and Parameter Selection

**User Story:** As a security analyst, I want to understand Neo's security guarantees and parameter selection methodology, so that I can verify the system achieves claimed security levels.

#### Mathematical Background

Security is based on Module-SIS assumption:

Module-SIS(κ, n, q, β):
- Given: A ∈ Rq^(κ×n) sampled uniformly
- Find: w ∈ Rq^n with ||w||_∞ ≤ β and Aw = 0 mod q
- Hardness: No polynomial-time algorithm succeeds with non-negligible probability

Parameter selection for 128-bit security:
1. Ring dimension: d ≥ 64
2. Module dimensions: κ, n chosen so κ·d·log(q) ≈ 128 bits
3. Modulus: q ≥ β^2 · N to prevent overflow
4. Norm bound: β chosen so Module-SIS(κ, n, q, β) is hard

Concrete parameters (Goldilocks field):
- q = 2^64 - 2^32 + 1
- d = 64 (ring dimension)
- κ = 4 (commitment dimension)
- n = 2^10 (witness dimension)
- β = 2^20 (norm bound)
- Security: ≈ 128 bits against BKZ attacks

Soundness analysis:
- Sum-check soundness: O(d·ℓ/|F|) where ℓ = log N
- Folding soundness: O(d/|C|) per folding step
- RLC soundness: O(deg/|F|) via Schwartz-Zippel
- Total soundness error: sum of all components
- Target: ≤ 2^(-128)

#### Acceptance Criteria

1. THE Neo_Implementation SHALL base security on Module-SIS(κ, n, q, β) assumption
2. THE Neo_Implementation SHALL select ring dimension d ≥ 64 for 128-bit security
3. THE Neo_Implementation SHALL select module dimensions κ, n such that κ·n·d·log(q) provides 128-bit security
4. THE Neo_Implementation SHALL select modulus q ≥ β^2 · N to prevent modular overflow
5. THE Neo_Implementation SHALL select norm bound β such that Module-SIS(κ, n, q, β) is hard
6. THE Neo_Implementation SHALL use Lattice Estimator to verify Module-SIS hardness
7. THE Neo_Implementation SHALL ensure BKZ block size b ≥ 128 for 128-bit security
8. THE Neo_Implementation SHALL compute sum-check soundness error: ε_sc = O(d·ℓ/|F|)
9. THE Neo_Implementation SHALL compute folding soundness error: ε_fold = O(d/|C|)
10. THE Neo_Implementation SHALL compute RLC soundness error: ε_rlc = O(deg/|F|)
11. THE Neo_Implementation SHALL compute total soundness error: ε_total = ε_sc + ε_fold + ε_rlc
12. THE Neo_Implementation SHALL verify ε_total ≤ 2^(-128)
13. THE Neo_Implementation SHALL document all parameter choices with security justification
14. THE Neo_Implementation SHALL provide parameter generation tool for different security levels
15. THE Neo_Implementation SHALL implement parameter validation checking runtime parameters meet security requirements

### Requirement NEO-16: IVC/PCD Construction

**User Story:** As an IVC/PCD builder, I want to understand how to use Neo for incrementally verifiable computation, so that I can build scalable proof systems.

#### Mathematical Background

IVC (Incrementally Verifiable Computation):
- Prove correctness of iterative computation: y_n = F^n(x)
- At step i, prove: y_i = F(y_{i-1}) and previous proof was valid

Using Neo for IVC:
1. Define step circuit as CCS instance
2. At step i:
   - Instance: (y_{i-1}, y_i, π_{i-1})
   - Witness: (w_i, opening of π_{i-1})
   - Constraint: y_i = F(y_{i-1}) AND VerifyFold(π_{i-1})

3. Fold current instance with accumulated instance:
   - Accumulated: (C_acc, r_acc, y_acc)
   - Current: (C_i, r_i, y_i)
   - Folded: (C'_acc, r'_acc, y'_acc)

4. Output new proof: π_i = (C'_acc, r'_acc, y'_acc, folding_proof)

PCD (Proof-Carrying Data):
- Generalize IVC to arbitrary computation graphs
- Each node proves: output correct AND all input proofs valid
- Use Neo folding to combine multiple input proofs

Proof compression:
- After many folding steps, final proof is still O(log N)
- Can apply SNARK to final folded instance for O(1) proof
- Trade-off: SNARK proving time vs proof size

#### Acceptance Criteria

1. THE Neo_Implementation SHALL support IVC construction using Neo folding
2. THE Neo_Implementation SHALL define step circuit as CCS instance
3. THE Neo_Implementation SHALL encode step constraint: y_i = F(y_{i-1})
4. THE Neo_Implementation SHALL encode verification constraint: VerifyFold(π_{i-1}) in CCS
5. THE Neo_Implementation SHALL fold current instance with accumulated instance
6. THE Neo_Implementation SHALL output new proof: π_i = (C'_acc, r'_acc, y'_acc, folding_proof)
7. THE Neo_Implementation SHALL achieve IVC proof size: O(log N) per step
8. THE Neo_Implementation SHALL achieve IVC verifier time: O(log N) per step
9. THE Neo_Implementation SHALL support PCD by folding multiple input proofs
10. THE Neo_Implementation SHALL implement proof compression using final SNARK
11. THE Neo_Implementation SHALL apply SNARK to final folded instance for O(1) proof
12. THE Neo_Implementation SHALL support various SNARK backends (Groth16, Plonk, STARKs)
13. THE Neo_Implementation SHALL optimize folding verifier circuit for efficient SNARK proving
14. THE Neo_Implementation SHALL provide IVC/PCD API: init, step, verify, compress
15. THE Neo_Implementation SHALL document IVC/PCD construction with security analysis

---

## Summary

This comprehensive requirements document for Neo covers:

1. **Mathematical Foundations**: Cyclotomic rings, field selection, Ajtai commitments
2. **Core Innovation**: Pay-per-bit commitment costs through coefficient packing
3. **Polynomial Commitments**: Multilinear extensions, evaluation claims, folding
4. **CCS Support**: Complete CCS relation definition and sum-check linearization
5. **Reduction Protocols**: RLC, decomposition, matrix-vector reductions
6. **Complete Folding Scheme**: End-to-end protocol combining all reductions
7. **Security**: Challenge sets, parameter selection, soundness analysis
8. **Applications**: IVC/PCD construction and proof compression

Total Requirements: 16 major requirements with 240 detailed acceptance criteria covering every aspect of the Neo paper.
