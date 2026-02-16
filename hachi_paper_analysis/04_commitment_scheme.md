# Commitment Scheme - Detailed Requirements

## 1. Inner-Outer Commitment Structure

### 1.1 Public Parameters
**Requirements**:
```
A ∈ R_q^{n_A × δ·2^m}  (inner commitment matrix)
B ∈ R_q^{n_B × n_A·δ·2^r}  (outer commitment matrix)
D ∈ R_q^{n_D × δ·2^r}  (evaluation commitment matrix)
```

Where:
- n_A, n_B, n_D = O(1) security parameters
- Must satisfy: n_A·d ≥ 2^10, n_B·d ≥ 2^10 for 128-bit security
- Matrices sampled uniformly at random
- Public and reusable across commitments

### 1.2 Decomposition Base
**Requirements**:
- b > 1 is decomposition base (typically b = 16 or 256)
- δ := ⌈log_b(q)⌉ is expansion factor
- Smaller b → larger δ → longer witness
- Larger b → smaller δ → faster decomposition
- Trade-off: proof size vs. computation

### 1.3 Witness Structure
**Input**: 2^r vectors f_i ∈ R_q^{2^m} for i ∈ [2^r]
**Requirements**:
- Total witness size: 2^r · 2^m = 2^ℓ ring elements
- ℓ = m + r (split parameter)
- Typically m ≈ r for balanced split

## 2. Inner Commitment (Ajtai-Style)

### 2.1 Decomposition Step
**For each i ∈ [2^r]**:
```
s_{1+∑_{z=1}^r i_z·2^{z-1}} := G_{2^m}^{-1}(f_i) ∈ R_q^{2^m·δ}
```

**Requirements**:
- G_{2^m}^{-1} decomposes each coefficient base-b
- Result has coefficients in [⌈-b/2⌉, ⌈b/2⌉-1]
- ||s_i||_∞ ≤ b/2
- Deterministic decomposition

### 2.2 Inner Commitment Computation
**For each i ∈ [2^r]**:
```
t_i := A·s_i ∈ R_q^{n_A}
```

**Requirements**:
- Matrix-vector multiplication over R_q
- Binding under Module-SIS assumption
- Computational cost: O(n_A·δ·2^m·d) ring operations

### 2.3 Inner Commitment Decomposition
**For each i ∈ [2^r]**:
```
t̂_i := G_{n_A}^{-1}(t_i) ∈ R_q^{n_A·δ}
```

**Requirements**:
- Further decomposition for outer commitment
- Coefficients in [⌈-b/2⌉, ⌈b/2⌉-1]
- ||t̂_i||_∞ ≤ b/2

## 3. Outer Commitment

### 3.1 Commitment Computation
```
u := B·[t̂_1; t̂_2; ...; t̂_{2^r}] ∈ R_q^{n_B}
```

**Requirements**:
- Stacks all inner commitments
- Single outer commitment for entire witness
- Binding under Module-SIS assumption
- Computational cost: O(n_B·n_A·δ·2^r·d) ring operations

### 3.2 Commitment Opening
**Standard Opening**:
```
(s_i, t̂_i)_{i∈[2^r]}
```

**Requirements**:
- Reveals all decomposed witness vectors
- Reveals all inner commitment decompositions
- Verifier checks:
  1. A·s_i = G_{n_A}·t̂_i for all i
  2. B·[t̂_1;...;t̂_{2^r}] = u
  3. ||s_i||_∞ ≤ b/2 for all i

### 3.3 Weak Opening
**Definition**:
```
(s_i, t̂_i, c_i)_{i∈[2^r]}
```

**Requirements**:
- c_i ∈ R_q^× (invertible challenge)
- ||c_i·s_i||_∞ ≤ β̄ (relaxed norm bound)
- ||c_i||_1 ≤ ω̄ (challenge norm bound)
- A·s_i = G_{n_A}·t̂_i for all i
- B·[t̂_1;...;t̂_{2^r}] = u
- ||[t̂_1;...;t̂_{2^r}]||_∞ ≤ γ̄

**Purpose**:
- Extracted by knowledge extractor
- Allows relaxed norm bounds
- Still binds to unique message

## 4. Weak Binding Property (Lemma 7)

### 4.1 Statement
```
Given two weak openings:
- (s_i, t̂_i, c_i)_{i∈[2^r]}
- (s'_i, t̂'_i, c'_i)_{i∈[2^r]}
For same commitment u
If s_j ≠ s'_j for some j ∈ [2^r]
Then can solve Module-SIS
```

### 4.2 Proof Requirements

**Step 1**: Identify difference
- Find j where s_j ≠ s'_j
- Both satisfy: A·s_j = G_{n_A}·t̂_j and A·s'_j = G_{n_A}·t̂'_j

**Step 2**: Construct solution
```
If t̂_j ≠ t̂'_j:
  z := [t̂_j - t̂'_j; 0] ∈ R_q^{2^m·δ + n_A·δ·2^r}
  [A | B]·z = B·(t̂_j - t̂'_j) = 0
  ||z||_∞ ≤ 2γ̄

If t̂_j = t̂'_j:
  A·(s_j - s'_j) = 0
  s_j - s'_j = c_j^{-1}·(c_j·s_j) - c'_j^{-1}·(c'_j·s'_j)
  ||s_j - s'_j||_∞ ≤ 2ω̄·β̄ (using Micciancio inequality)
  z := [s_j - s'_j; 0]
  ||z||_∞ ≤ 2ω̄·β̄
```

**Step 3**: Verify Module-SIS solution
- [A | B]·z = 0
- 0 < ||z||_∞ ≤ max(2ω̄·β̄, 2γ̄)
- Breaks Module-SIS assumption

### 4.3 Parameter Requirements
**For binding security**:
- max(2ω̄·β̄, 2γ̄) must be small enough
- Module-SIS_{q,d,n_B,2^m·δ+n_A·δ·2^r,max(2ω̄·β̄,2γ̄)} must be hard
- Use Lattice Estimator to verify

## 5. Polynomial Evaluation as Quadratic Equation

### 5.1 Problem Setup
**Given**: Polynomial evaluation claim
```
f(x_1,...,x_ℓ) = u
```
Where:
- f ∈ R_q^{≤1}[X_1,...,X_ℓ]
- Coefficients (f_ι)_{ι∈{0,1}^ℓ}
- Evaluation point (x_1,...,x_ℓ) ∈ R_q^ℓ
- Image u ∈ R_q

### 5.2 Split Representation
**For ℓ = m + r**:
```
f(x_1,...,x_ℓ) = b^T · [f_{0...0}; ...; f_{1...1}] · a
```

Where:
```
a^T := (x_{r+1}^{j_1}·...·x_ℓ^{j_m})_{j∈{0,1}^m} ∈ R_q^{2^m}
b^T := (x_1^{i_1}·...·x_r^{i_r})_{i∈{0,1}^r} ∈ R_q^{2^r}
f_i^T := (f_{i||j})_{j∈{0,1}^m} ∈ R_q^{2^m} for i ∈ {0,1}^r
```

### 5.3 Commitment Opening Relation
**Using decomposition s_i = G_{2^m}^{-1}(f_i)**:
```
u = f(x_1,...,x_ℓ) = b^T · [a^T·G_{2^m}; ...; a^T·G_{2^m}] · [s_1; ...; s_{2^r}]
```

**Simplify**:
```
u = b^T · (a^T ⊗ I_{2^r}) · [G_{2^m}; ...; G_{2^m}] · [s_1; ...; s_{2^r}]
  = b^T · (a^T ⊗ I_{2^r}) · (G_{2^m} ⊗ I_{2^r}) · [s_1; ...; s_{2^r}]
  = b^T · (a^T·G_{2^m} ⊗ I_{2^r}) · [s_1; ...; s_{2^r}]
```

Using mixed product property of tensor products.

### 5.4 Intermediate Witness
**Define**:
```
w := (w_1,...,w_{2^r}) ∈ R_q^{2^r}
where w_i := a^T·G_{2^m}·s_i ∈ R_q
```

**Then**:
```
u = b^T·w = b^T·G_{2^r}·ŵ
```
where ŵ := G_{2^r}^{-1}(w) ∈ R_q^{δ·2^r}

### 5.5 Evaluation Commitment
**Prover commits to w**:
```
v := D·ŵ ∈ R_q^{n_D}
```

**Requirements**:
- D is public random matrix
- Binding under Module-SIS
- Allows verifier to check: b^T·G_{2^r}·ŵ = u

## 6. Split-and-Fold Protocol (Figure 3)

### 6.1 Round 1: Prover Commits
**Prover computes**:
```
For i ∈ [2^r]:
  w_i := a^T·G_{2^m}·s_i
w := (w_1,...,w_{2^r})
ŵ := G_{2^r}^{-1}(w)
v := D·ŵ
```

**Prover sends**: v ∈ R_q^{n_D}

**Requirements**:
- Computational cost: O(2^r·2^m·δ·d) for computing w
- Decomposition cost: O(2^r·δ·d) for ŵ
- Commitment cost: O(n_D·δ·2^r·d) for v

### 6.2 Round 2: Verifier Challenges
**Verifier samples**:
```
c := (c_1,...,c_{2^r}) ← C^{2^r}
```

**Challenge Space C**:
```
C ⊆ {c ∈ R_q : ||c||_1 ≤ ω}
```

**Requirements**:
- |C| must be exponential for soundness
- ω small enough for norm bounds
- Typically: sparse challenges with k non-zero coefficients
- For d = 1024, k = 16: |C| ≈ (d choose k)·2^k ≈ 2^128

### 6.3 Round 3: Prover Folds
**Prover computes**:
```
z := c_1·s_1 + c_2·s_2 + ... + c_{2^r}·s_{2^r} ∈ R_q^{2^m·δ}
```

**Abort condition**:
```
If ||z||_∞ > β: abort
```

**Further decomposition**:
```
τ := ⌈log_b(β)⌉
ẑ := J_{2^m}^{-1}(z) ∈ R_q^{2^m·δ·τ}
where J_{2^m} := I_{2^m} ⊗ [1, b, b^2, ..., b^{τ-1}]
```

**Prover sends**: (t̂, ŵ, ẑ)

**Requirements**:
- Folding cost: O(2^r·2^m·δ·d) ring operations
- Decomposition cost: O(2^m·δ·τ·d)
- All coefficients in [⌈-b/2⌉, ⌈b/2⌉-1]

### 6.4 Verification Equations
**Verifier checks**:
```
1. (ŵ, t̂, ẑ) ∈ S_b^{2^r·δ + 2^r·n_A·δ + 2^m·δ·τ}

2. [D      0        0     ] [ŵ]   [v]
   [0      B        0     ] [t̂] = [u]
   [b^T·G_{2^r}  0  0     ] [ẑ]   [u]
   [(c^T⊗G_1)  0  -a^T·G_{2^m}·J_{2^m}]   [0]
   [0  c^T⊗G_{n_A}  -A·J_{2^m}]           [0]
```

**Requirements**:
- First row: commitment to w
- Second row: outer commitment
- Third row: evaluation equation
- Fourth row: w-z consistency
- Fifth row: inner commitment consistency

### 6.5 Norm Bound Analysis
**Naive bound for β**:
```
||z||_∞ ≤ ∑_{i=1}^{2^r} ||c_i·s_i||_∞
        ≤ ∑_{i=1}^{2^r} ||c_i||_1·||s_i||_∞  (Micciancio inequality)
        ≤ 2^r·ω·b
```

**Therefore**:
```
β := 2^r·ω·b
τ := ⌈log_b(β)⌉ = O(r + log(ω))
```

**For concrete parameters**:
- r = 10, ω = 16, b = 16
- β ≈ 2^10·16·16 = 2^18
- τ = ⌈log_16(2^18)⌉ = 5

## 7. Coordinate-Wise Special Soundness (Lemma 8)

### 7.1 Statement
```
Let (β̄, ω̄, γ̄) := (2b^k, 2ω, b)
Assume ω < (1/(2√2))·q^{1/2}

Given:
- Public parameters (A, B, D)
- Statement (u, u)
- 2^r + 1 valid transcripts:
  tr^(j) := (v, c^(j), (ŵ^(j), t̂^(j), ẑ^(j)))
  where (c^(j))_{0≤j≤2^r} ∈ SS(C, 2^r, 2)

Can extract weak opening (s̄^(j), t̄^(j), c^(j))_{j∈[2^r]} such that:
u = b^T·[a^T·G_{2^m}; ...; a^T·G_{2^m}]·[s̄_1; ...; s̄_{2^r}]
```

### 7.2 Extraction Algorithm

**Step 1**: Reconstruct z vectors
```
For each j ∈ [2^r]:
  z^(j) := J_{2^m}·ẑ^(j)
  ||z^(j)||_∞ ≤ b^k
```

**Step 2**: Check for commitment collisions
```
If ∃i≠j: t̂^(i) ≠ t̂^(j):
  Solve Module-SIS for B with solution t̂^(i) - t̂^(j)
  ||t̂^(i) - t̂^(j)||_∞ ≤ 2b

If ∃i≠j: ŵ^(i) ≠ ŵ^(j):
  Solve Module-SIS for D with solution ŵ^(i) - ŵ^(j)
  ||ŵ^(i) - ŵ^(j)||_∞ ≤ 2b
```

**Step 3**: Assume no collisions
```
t̂^(j) := t̂ for all j
ŵ^(j) := ŵ for all j
w := G_{2^r}·ŵ
Parse w = (w_i)_{i∈[2^r]}
Parse t̂ = (t̂_i)_{i∈[2^r]}
```

**Step 4**: Extract witness for each coordinate
```
Fix j ∈ [2^r]
Let c^(j) := (c_{j,i})_i and c^(0) := (c_{0,i})_i
Note: c_{j,i} = c_{0,i} for all i ≠ j (coordinate-wise property)

From verification equations:
  b^T·G_{2^m}·(z^(j) - z^(0)) = (c_{j,j} - c_{0,j})·w_j
  A·(z^(j) - z^(0)) = (c_{j,j} - c_{0,j})·G_{n_A}·t̂_j

Define:
  s̄_j := (z^(j) - z^(0))/(c_{j,j} - c_{0,j})
  c̄_j := c_{j,j} - c_{0,j}
```

**Step 5**: Verify weak opening properties
```
||c̄_j·s̄_j||_∞ = ||z^(j) - z^(0)||_∞ ≤ 2b^k = β̄
||c̄_j||_1 ≤ ||c_{j,j}||_1 + ||c_{0,j}||_1 ≤ 2ω = ω̄
c̄_j invertible since ||c̄_j||_∞ ≤ 2ω < (1/√2)·q^{1/2}
A·s̄_j = G_{n_A}·t̂_j
a^T·G_{2^m}·s̄_j = w_j
```

**Step 6**: Verify evaluation equation
```
u = b^T·w = b^T·[w_1; ...; w_{2^r}]
  = b^T·[a^T·G_{2^m}·s̄_1; ...; a^T·G_{2^m}·s̄_{2^r}]
```

### 7.3 Knowledge Error
**Requirements**:
- Need 2^r + 1 transcripts with coordinate-wise structure
- Knowledge error: (2^r·2)/|C|^{2^r}
- For |C| ≥ 2^λ: error ≤ 2^{r+1-λ·2^r} (negligible)

### 7.4 Parameter Constraints
**For soundness**:
```
1. ω < (1/(2√2))·q^{1/2}  (invertibility)
2. |C| ≥ 2^λ  (exponential challenge space)
3. Module-SIS hard for parameters (n_A, n_B, n_D, β̄, γ̄)
```
