# Ring Switching and Sumcheck Protocol - Detailed Requirements

## 1. Unstructured Linear Relations over R_q

### 1.1 Relation Definition
```
R^lin_{q,d,n,μ,b} := {
  (z ∈ R_q^μ, (M ∈ R_q^{n×μ}, y ∈ R_q^n)) :
  M·z = y ∧ ||z||_∞ ≤ b-1
}
```

**Requirements**:
- M is public matrix
- y is public vector
- z is witness (short vector)
- Must prove both linear equation and norm bound

### 1.2 Input from Section 4.2
**After split-and-fold protocol, need to prove**:
```
[D      0        0     ] [ŵ]   [v]
[0      B        0     ] [t̂] = [u]
[b^T·G_{2^r}  0  0     ] [ẑ]   [u]
[(c^T⊗G_1)  0  -a^T·G_{2^m}·J_{2^m}]   [0]
[0  c^T⊗G_{n_A}  -A·J_{2^m}]           [0]

With (ŵ, t̂, ẑ) ∈ S_b^{2^r·δ + 2^r·n_A·δ + 2^m·δ·τ}
```

**Dimensions**:
- Witness length: μ = 2^r·δ + 2^r·n_A·δ + 2^m·δ·τ
- Number of equations: n = n_D + n_B + 1 + 2^r + 2^m
- Norm bound: b

## 2. Ring Switching Technique

### 2.1 Lifting to Polynomial Ring
**Key Observation**:
```
M·z = y over R_q
⟺
∃r ∈ (Z_q^{<d}[X])^n: M·z = y + (X^d + 1)·r over Z_q[X]
```

**Requirements**:
- Treat M, z, y as elements of Z_q^{<d}[X]
- r is quotient polynomial (degree < d)
- Equation holds in polynomial ring, not just R_q

### 2.2 Extension to F_{q^k}[X]
**Further lift to extension field**:
```
M·z = y + (X^d + 1)·r over F_{q^k}^{<d}[X]
```

**Requirements**:
- k chosen so |F_{q^k}| ≥ 2^λ (exponential for soundness)
- Typically k = λ/log(q)
- Enables sumcheck over small field

### 2.3 Coefficient Representation
**For M_{i,j}, z_j, y_i, r_i ∈ Z_q^{<d}[X]**:
```
M_{i,j} = ∑_{ℓ<d} M_{i,j,ℓ}·X^ℓ
z_j = ∑_{ℓ<d} z_{j,ℓ}·X^ℓ
y_i = ∑_{ℓ<d} y_{i,ℓ}·X^ℓ
r_i = ∑_{ℓ<d} r_{i,ℓ}·X^ℓ
```

**Requirements**:
- All coefficients in Z_q
- M, y are public (verifier knows coefficients)
- z, r are witness (prover must prove)

### 2.4 Gadget Decomposition of r
**To avoid large coefficients**:
```
r = ∑_u b^u·r_u
where r_u ∈ (Z_q^{<d}[X])^n with ||r_u||_∞ ≤ b-1
```

**Requirements**:
- Decomposes r base-b
- Each r_u has small coefficients
- Number of components: log_b(q)
- Prover commits to (z, r_1, ..., r_{log_b(q)})

### 2.5 Simplified Presentation
**For clarity, write**:
```
M·z = y + (X^d + 1)·r
```
Understanding r is actually decomposed.

## 3. Random Evaluation (Figure 4)

### 3.1 Protocol Overview
**Round 1**: Prover commits
```
t := Com(z, r)
```

**Round 2**: Verifier challenges
```
α ← F_{q^k}
```

**Round 3**: Prover opens
```
Send z, r
```

**Verification**:
```
1. t = Com(z, r)
2. z ∈ Z_q^{<d}[X] and ||z||_∞, ||r||_∞ ≤ b-1
3. ∀i ∈ [n]: ∑_j M_{i,j}(α)·z_j(α) = y_i(α) + (α^d + 1)·r_i(α)
```

### 3.2 Soundness Analysis (Lemma 9)

**Statement**:
```
Given 2d valid transcripts (t_i, α_i, (z_i, r_i))
with (α_i)_i ∈ SS(F_{q^k}, 1, 2d)
Can extract z̄, r̄ satisfying M·z̄ = y + (X^d + 1)·r̄ over Z_q[X]
Or break binding of Com
```

**Proof Requirements**:

**Step 1**: Check for commitment collision
```
If ∃i≠j: (z_i, r_i) ≠ (z_j, r_j) but t_i = t_j:
  Break binding of Com
```

**Step 2**: Assume no collision
```
z̄ := z_i for all i
r̄ := r_i for all i
```

**Step 3**: Polynomial identity
```
For each i ∈ [n], define polynomial:
P_i(X) := ∑_j M_{i,j}(X)·z_j(X) - y_i(X) - (X^d + 1)·r_i(X)
```

**Step 4**: Degree bound
```
deg(P_i) ≤ max(2d-1, d) = 2d-1
```

**Step 5**: Root counting
```
Have 2d distinct roots: P_i(α_j) = 0 for all j
Since deg(P_i) < 2d, must have P_i ≡ 0
Therefore: M·z̄ = y + (X^d + 1)·r̄
```

### 3.3 Soundness Error
**Requirements**:
- Polynomial of degree 2d-1 has ≤ 2d-1 roots
- Need 2d evaluation points
- Soundness error: (2d-1)/|F_{q^k}|
- For |F_{q^k}| ≥ 2^λ: error ≤ 2d/2^λ (negligible)

## 4. Multilinear Extension of Witness

### 4.1 Witness Vector
**Define**:
```
w̃ ∈ F_q^{(μ+n)×d}
w̃(u, ℓ) := {
  z_{u,ℓ}     if u ≤ μ
  r_{u-μ,ℓ}   if μ < u ≤ μ+n
}
```

**Requirements**:
- Packs z and r into single structure
- u indexes witness component (binary representation)
- ℓ indexes coefficient within polynomial
- Total size: (μ+n)·d elements

### 4.2 Multilinear Extension
```
w̃ := mle[w̃] ∈ F_{q^k}^{≤1}[X_1,...,X_{log(μ+n)+log(d)}]
```

**Requirements**:
- Multilinear in all variables
- Agrees with w̃ on {0,1}^{log(μ+n)+log(d)}
- Number of variables: log(μ+n) + log(d)

### 4.3 Commitment to w̃
**Prover commits**:
```
t := Com(w̃)
```

**Requirements**:
- Uses polynomial commitment scheme
- Binding under Module-SIS
- Enables evaluation proofs

## 5. Constraint Polynomials

### 5.1 Public Polynomials

**α̃ polynomial**:
```
∀ℓ: α̃(ℓ) = α^ℓ ∈ F_{q^k}
```
**Requirements**:
- Encodes powers of α
- Multilinear extension of (α^0, α^1, ..., α^{d-1})

**M̃_α polynomial**:
```
M̃_α(i, u) := {
  M_{i,u}(α)     if u ≤ μ and i ≤ n
  -(α^d + 1)     if i + μ = u
  0              otherwise
}
```
**Requirements**:
- Encodes matrix M evaluated at α
- Encodes quotient term -(α^d + 1)
- Multilinear in (i, u)

### 5.2 Linear Constraint Polynomial H_α

**Definition**:
```
H_α(t) := ∑_{i∈[n]} eq(t, i)·[∑_{u,ℓ} M̃_α(i,u)·w̃(u,ℓ)·α̃(ℓ) - y_i(α)]
```

**Requirements**:
- Batches all n linear equations
- Uses equality polynomial for batching
- H_α(t) = 0 for all t ⟺ all equations satisfied

**Degree**:
```
deg(H_α) = log(n) + log(μ+n) + log(d)
```

### 5.3 Norm Constraint Polynomial H_0

**Definition**:
```
H_0(t) := ∑_{ℓ,u} eq(t, (u,ℓ))·w̃(u,ℓ)·(w̃(u,ℓ)-1)·(w̃(u,ℓ)+1)·...·(w̃(u,ℓ)-b+1)·(w̃(u,ℓ)+b-1)·1_{≤μ}(u,ℓ)
```

**Requirements**:
- Checks w̃(u,ℓ) ∈ {-(b-1), ..., -1, 0, 1, ..., b-1}
- Product is zero iff w̃(u,ℓ) in range
- Only checks z coefficients (u ≤ μ)
- 1_{≤μ} is indicator function

**Degree**:
```
deg(H_0) = log(μ+n) + log(d) + (2b-1)
```

## 6. Random Point Evaluation (Figure 5)

### 6.1 Protocol Overview
**Round 1**: Prover commits
```
t := Com(w̃)
```

**Round 2**: Verifier challenges
```
τ_0 ← F_{q^k}^{log(μ)+log(d)}
τ_1 ← F_{q^k}^{log(n)}
```

**Round 3**: Prover opens
```
Send w̃
```

**Verification**:
```
1. t = Com(w̃)
2. Reconstruct H_0, H_α from w̃
3. H_0(τ_0) = 0
4. H_α(τ_1) = 0
```

### 6.2 Soundness Analysis (Lemma 10)

**Statement**:
```
Given D := max(2d, 2b-1) valid transcripts
with ((τ_{i,0}, τ_{i,1}), w̃_i)
where (τ_{i,0}, τ_{i,1})_i ∈ SS(F_{q^k}, 2, D)
Can extract w̃ satisfying H_0 ≡ 0 and H_α ≡ 0
Or break binding of Com
```

**Proof Requirements**:

**Step 1**: Check collision
```
If ∃i≠j: w̃_i ≠ w̃_j:
  Break binding
```

**Step 2**: Assume no collision
```
w̃ := w̃_i for all i
```

**Step 3**: Root counting for H_α
```
deg(H_α) ≤ 2d-1
Have 2d distinct roots
Therefore H_α ≡ 0
```

**Step 4**: Root counting for H_0
```
deg(H_0) ≤ 2b-2
Have 2b-1 distinct roots
Therefore H_0 ≡ 0
```

### 6.3 Soundness Error
**Requirements**:
- Need max(2d, 2b-1) evaluation points
- Error: max(2d-1, 2b-2)/|F_{q^k}|
- For |F_{q^k}| ≥ 2^λ: negligible

## 7. Sumcheck Protocol (Figure 6)

### 7.1 Generic Sumcheck for H(X) = P(X)·Q(w̃(X))

**Goal**: Prove
```
∑_{b_i,...,b_ℓ} H(a_1,...,a_{i-1},b_i,...,b_ℓ) = z_{i-1}
```

**Round i Protocol**:

**Prover computes**:
```
g_i(X_i) := ∑_{b_j} H(a_1,...,a_{i-1},X_i,b_{i+1},...,b_ℓ)
```

**Prover sends**: g_i(X_i) (univariate polynomial)

**Verifier checks**:
```
1. g_i(0) + g_i(1) = z_{i-1}
2. deg(g_i) ≤ deg(H)
```

**Verifier samples**: a_i ← F_{q^k}

**Update**: z_i := g_i(a_i)

**Final round**: 
```
z_ℓ = H(a_1,...,a_ℓ) = P(a_1,...,a_ℓ)·Q(w̃(a_1,...,a_ℓ))
```

### 7.2 Soundness (Lemma 11)

**Statement**:
```
Given D := deg(H) + 1 valid transcripts
with (g_i(X_i), a_{i,j}, w̃_j)
where (a_{i,j})_j ∈ SS(F_{q^k}, 1, D)
Can extract w̃ satisfying:
∑_{b_j} H(a_1,...,a_i,b_{i+1},...,b_ℓ) = g_i(a_i)
Or break binding
```

**Proof Requirements**:

**Step 1**: Check collision
```
If ∃j≠k: w̃_j ≠ w̃_k:
  Break binding
```

**Step 2**: Polynomial identity
```
Define: P_i(X_i) := ∑_{b_j} H(a_1,...,a_{i-1},X_i,b_{i+1},...,b_ℓ) - g_i(X_i)
deg(P_i) ≤ deg(H)
Have deg(H)+1 roots
Therefore P_i ≡ 0
```

### 7.3 Application to H_0 and H_α

**For H_0(τ_0)**:
```
Define: F_{0,τ_0}(x,y) := eq(τ_0,(x,y))·w̃(x,y)·(w̃(x,y)-1)·...·(w̃(x,y)+b-1)·1_{≤μ}(x,y)
Goal: ∑_{x,y} F_{0,τ_0}(x,y) = 0
```

**For H_α(τ_1)**:
```
Define: F_{α,τ_1}(x,y) := w̃(x,y)·α̃(y)·∑_i eq(τ_1,i)·M̃_α(i,x)
Goal: ∑_{x,y} F_{α,τ_1}(x,y) = a
where a := ∑_i eq(τ_1,i)·y_i(α) (verifier computes)
```

**Requirements**:
- Run sumcheck on F_{0,τ_0} with log(μ+n)+log(d) rounds
- Run sumcheck on F_{α,τ_1} with log(μ+n)+log(d) rounds
- Each round: prover sends univariate polynomial
- Degree: max(2b-1, 2d) for F_0, degree 2d for F_α

### 7.4 Communication Cost per Round
**Requirements**:
- For F_0: send (2b-1+1) = 2b coefficients in F_{q^k}
- For F_α: send (2d+1) coefficients in F_{q^k}
- Total per round: (2b + 2d + 2)·k·log(q) bits
- Number of rounds: log(μ+n) + log(d)
- Total: O((b+d)·k·log(q)·log(μ·d)) bits

## 8. Final Evaluation Proof

### 8.1 Evaluation Claim
**After sumcheck, need to prove**:
```
w̃(a_1,...,a_{log(μ+n)+log(d)}) = y'
```
Where:
- (a_1,...,a_{log(μ+n)+log(d)}) ∈ F_{q^k}^{log(μ+n)+log(d)}
- y' ∈ F_{q^k}
- Both public (derived from sumcheck)

### 8.2 Recursive Application
**Requirements**:
- w̃ is multilinear polynomial over F_{q^k}
- Number of variables: log(μ+n) + log(d)
- Apply transformation from Section 3
- Reduces to polynomial over R_q with fewer variables
- Recurse until witness small enough

### 8.3 Termination Condition
**After t iterations**:
```
Variables reduced to: (2/3)^t·ℓ + 2α + O(t)
```

**For t = O(log(ℓ))**:
```
Variables: O(log(ℓ) + α)
Witness size: poly(ℓ, λ)
```

**Final step**: Send witness in clear
