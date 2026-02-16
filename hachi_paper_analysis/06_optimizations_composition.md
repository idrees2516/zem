# Optimizations and Protocol Composition - Detailed Requirements

## 1. Avoiding Re-Decomposition (Section 4.5)

### 1.1 Problem Statement
**Naive approach**:
- After sumcheck, have witness w̃ with small coefficients
- To commit for next iteration: decompose w̃ again
- Witness length increases by factor δ
- Inefficient and unnecessary

**Better approach**:
- w̃ already has small coefficients (≤ b-1)
- Commit directly without decomposition
- Prove evaluation of mle[w̃] directly

### 1.2 Multilinear Extension Structure

**Recall from Section 4.3**:
```
w̃(u, ℓ) = {
  z_{u,ℓ}     if u ≤ μ
  r_{u-μ,ℓ}   if μ < u ≤ μ+n
}
```

**Multilinear extension**:
```
mle[w̃](x_0 || x_1) = ∑_{i∈{0,1}^r} ∑_{j∈{0,1}^m} w̃_{i||j}·eq(i,x_0)·eq(j,x_1)
                    = ∑_{i∈{0,1}^r} eq(i,x_0)·[∑_{j∈{0,1}^m} w̃_{i||j}·eq(j,x_1)]
```

Where:
- μ = r + m (split for next iteration)
- x_0 ∈ F_{q^k}^r (first r variables)
- x_1 ∈ F_{q^k}^m (last m variables)

### 1.3 Homomorphic Property of eq

**Key Observation**:
```
eq(i, x_0)·eq(j, x_1) = eq(i||j, x_0||x_1)
```

**Proof**:
```
eq(i,x_0)·eq(j,x_1) = [∏_{t=1}^r ((1-i_t)(1-x_{0,t}) + i_t·x_{0,t})]
                      · [∏_{s=1}^m ((1-j_s)(1-x_{1,s}) + j_s·x_{1,s})]
                    = ∏_{t=1}^{r+m} ((1-(i||j)_t)(1-(x_0||x_1)_t) + (i||j)_t·(x_0||x_1)_t)
                    = eq(i||j, x_0||x_1)
```

### 1.4 Partial Evaluation Representation

**For evaluation point (x_0, x_1) ∈ F_{q^k}^{r+m}**:
```
mle[w̃](x_0||x_1) = ∑_{i∈{0,1}^r} eq(i,x_0)·y_i
```

Where:
```
y_i := ∑_{j∈{0,1}^m} w̃_{i||j}·eq(j,x_1) ∈ F_{q^k}
```

**Requirements**:
- Prover sends k partial evaluations y_i
- Optimization: send only k-1 (verifier computes y_{0...0})
- Verifier checks: mle[w̃](x_0||x_1) = ∑_i eq(i,x_0)·y_i

### 1.5 Reduction to Greyhound Relation

**Step 1**: Define polynomial over F_{q^k}
```
Let F_{q^k} = F_q[Z]/φ(Z) where φ irreducible of degree k
Define f' ∈ F_{q^k}^{≤1}[X_{κ+1},...,X_ℓ]:
f'(X_{κ+1},...,X_ℓ) := ∑_{i∈{0,1}^κ} f_i(X_{κ+1},...,X_ℓ)·Z^{∑_{t=1}^κ i_t·2^{t-1}}
```

Where:
```
f_i(X_{κ+1},...,X_ℓ) := ∑_{j∈{0,1}^{ℓ-κ}} w̃_{i||j}·X_{κ+1}^{j_1}·...·X_ℓ^{j_{ℓ-κ}}
```

**Step 2**: Evaluation claim
```
f'(x_{κ+1},...,x_ℓ) = ∑_{i∈{0,1}^κ} y_i·Z^{∑_{t=1}^κ i_t·2^{t-1}} ∈ F_{q^k}
```

**Step 3**: Apply Section 3.1 transformation
- Reduces to (ℓ-κ-α+κ) = (ℓ-α)-variate polynomial over R_q
- Define ring elements using ψ map

**Step 4**: Quadratic equation form
```
For each i ∈ {0,1}^{ℓ-α+κ}:
  F_i := ψ((f_{i||j})_{j∈{0,1}^{α-κ}}) ∈ R_q'

v := ψ((x_{ℓ-α+κ+1}^{j_1}·...·x_ℓ^{j_{α-κ}})_{j∈{0,1}^{α-κ}}) ∈ R_q'

p := e^T·(σ_{-1}(ψ(f))^T ⊗ I_{2^r})·ψ(ŵ) ∈ R_q'
```

Where:
- R_q' uses ring dimension d' (potentially different from d)
- e := (eq(i,x_0))_{i∈{0,1}^r} ∈ F_{q^k}^{2^r}
- f := (eq(j,x_1))_{j∈{0,1}^m} ∈ F_{q^k}^{2^m·d'/k}

**Step 5**: Trace verification
```
Tr_H(p·σ_{-1}(v)) = (d'/k)·∑_i eq(i,x_0)·y_i
```

### 1.6 Greyhound Compatibility

**Witness structure**:
```
ψ(ŵ) ∈ R_q'^{2^{ℓ-α}/d'}
```

**Requirements**:
- ||ψ(ŵ)||_∞ ≤ 2β (by Lemma 6)
- No initial decomposition needed
- Directly compatible with Greyhound protocol
- Greyhound proves quadratic equation with short witness

### 1.7 Communication Cost
```
(k-1)·k·log(q) + d'·log(q) bits
```

**Breakdown**:
- (k-1)·k·log(q): partial evaluations y_i
- d'·log(q): ring element p

## 2. Switching to LaBRADOR

### 2.1 Decision Point
**When to switch**:
- After several Hachi iterations
- Witness length reduced significantly
- Johnson-Lindenstrauss projection becomes cheap

**Typical threshold**:
- Witness length ≈ 2^20 to 2^22 Z_q elements
- Corresponds to ≈ 2^16 to 2^18 R_q elements (with d=64)

### 2.2 Advantages of LaBRADOR at Small Scale

**Faster witness reduction**:
- Can use larger decomposition base b
- Smaller expansion factor δ
- Witness reduces faster per iteration

**Example**:
- Hachi: b=16, δ=8 (for sumcheck efficiency)
- LaBRADOR: b=256, δ=5 (no sumcheck constraint)

**Concrete impact**:
- After decomposition: witness × δ
- Smaller δ → smaller witness for next iteration
- Can recurse more times before sending in clear

### 2.3 Trade-offs

**Hachi advantages**:
- Faster verification (no ring operations)
- Better for large witnesses
- Asymptotically better verifier time

**LaBRADOR advantages**:
- Faster witness reduction
- Better for small witnesses
- Smaller final proof

**Optimal strategy**:
- Use Hachi for first iteration(s)
- Switch to LaBRADOR when witness small
- Combines best of both approaches

### 2.4 Composition Protocol

**Step 1**: Run Hachi
```
Input: ℓ-variate polynomial over F_{q^k}
Output: ℓ'-variate polynomial over R_q with ℓ' ≈ ℓ/2
Witness: 2^{ℓ'} R_q elements with small coefficients
```

**Step 2**: Check witness size
```
If 2^{ℓ'}·d < threshold:
  Switch to LaBRADOR
Else:
  Continue with Hachi
```

**Step 3**: LaBRADOR recursion
```
Input: ℓ'-variate polynomial over R_q
Apply LaBRADOR protocol
Recurse until witness ≈ 2^15 R_q elements
Send final witness in clear
```

## 3. Challenge Space Optimization

### 3.1 Sparse Challenges
**For large ring dimension d**:
```
C := {c ∈ R_q : exactly k non-zero coefficients, each ±1}
```

**Requirements**:
- k chosen so |C| ≥ 2^λ
- For d=1024, k=16: |C| ≈ (1024 choose 16)·2^16 ≈ 2^128
- Much sparser than dense challenges

### 3.2 Efficient Sparse Multiplication

**Standard multiplication**:
- NTT-based: O(d·log(d)) operations
- Works for any ring elements

**Sparse multiplication**:
- Direct computation: O(k·d) operations
- Exploits sparsity of challenge
- No NTT needed

**Implementation**:
```
For c with non-zero coefficients at indices (i_1,...,i_k) with values (±1):
c·s = ∑_{j=1}^k (±1)·X^{i_j}·s
    = ∑_{j=1}^k (±1)·(rotate s by i_j positions)
```

**Requirements**:
- Store only k indices and k signs
- Multiplication: k rotations and additions
- Much faster than general multiplication

### 3.3 Sampling Sparse Challenges

**Fisher-Yates-like algorithm**:
```
1. Sample k distinct indices from [0, d-1]
2. For each index, sample sign ±1
3. Construct sparse polynomial
```

**Requirements**:
- Uniform distribution over sparse challenges
- Efficient: O(k) time
- Verifiable: deterministic from random seed

## 4. Complete Protocol Flow

### 4.1 Iteration 1: Field Extension to R_q

**Input**:
- ℓ-variate polynomial f over F_{q^k}
- Evaluation point (x_1,...,x_ℓ) ∈ F_{q^k}^ℓ
- Image y ∈ F_{q^k}

**Step 1**: Apply Section 3 transformation
```
If f over F_q:
  Use optimized transformation (Section 3.2)
  Output: (ℓ-α)-variate polynomial over R_q
Else:
  Use generic transformation (Section 3.1)
  Output: (ℓ-α+κ)-variate polynomial over R_q
```

**Step 2**: Commit to polynomial
```
Use inner-outer commitment (Section 4.1)
Commitment size: n_B·d·log(q) bits
```

**Step 3**: Split-and-fold
```
Choose m ≈ r ≈ (ℓ-α)/2
Run protocol from Figure 3
Output: Linear relation over R_q
Witness: (ŵ, t̂, ẑ) with μ ≈ 2^{(ℓ-α)/2} elements
```

### 4.2 Iteration 1: Ring Switching and Sumcheck

**Step 1**: Ring switching
```
Lift to F_{q^k}[X] (Section 4.3)
Commit to w̃ := mle[(z,r)]
```

**Step 2**: Random evaluation
```
Sample α ← F_{q^k}
Sample τ_0, τ_1 ← F_{q^k}
Reduce to proving H_0(τ_0) = 0 and H_α(τ_1) = 0
```

**Step 3**: Sumcheck
```
Run sumcheck on F_{0,τ_0} and F_{α,τ_1}
Number of rounds: log(μ) + log(d)
Per round: send (2b+2d+2) F_{q^k} elements
```

**Step 4**: Final evaluation
```
Prove w̃(a_1,...,a_{log(μ)+log(d)}) = y'
Number of variables: log(μ) + log(d)
```

### 4.3 Iteration 2+: Recursive Application

**Input**:
- log(μ)+log(d) variate polynomial over F_{q^k}
- Already committed (no re-decomposition)

**Step 1**: Partial evaluations
```
Use Section 4.5 optimization
Send k-1 partial evaluations
Reduce to (log(μ)+log(d)-α)-variate over R_q'
```

**Step 2**: Greyhound relation
```
Quadratic equation with short witness
Witness size: 2^{log(μ)+log(d)-α}/d' R_q' elements
```

**Step 3**: Decision
```
If witness small enough:
  Switch to LaBRADOR
Else:
  Continue with Hachi (go to Iteration 1 Step 3)
```

### 4.4 Final Step: LaBRADOR or Direct Send

**Option 1: LaBRADOR**
```
Apply LaBRADOR protocol
Recurse until witness ≈ 2^15 R_q elements
Send final witness in clear
Proof size: ≈ 30-40 KB
```

**Option 2: Direct send**
```
If witness already small (≈ 2^15 elements):
  Send in clear
  Proof size: ≈ 2^15·d·log(q) bits
```

## 5. Asymptotic Analysis

### 5.1 Witness Length Reduction

**After one Hachi iteration**:
```
ℓ ↦ (ℓ+α)/2 + 2·log(ℓ+α) + O(1) ≤ (2/3)·(ℓ+α) + O(1)
```

**After t iterations**:
```
ℓ_t ≤ (2/3)^t·ℓ + 2α + O(t)
```

**To reach O(log(ℓ)+α)**:
```
Need t = O(log(ℓ)) iterations
```

### 5.2 Proof Size per Iteration

**Field extension transformation**:
```
O(d·log(q) + k^2·log(q)) = O(λ·ℓ/log(λ)) bits
```

**Commitment**:
```
O(d·log(q)) = O(λ·ℓ/log(λ)) bits
```

**Sumcheck**:
```
O((b+d)·k·log(q)·(log(ℓ)+α)) = O(λ·ℓ/log(λ)) bits
```

**Total per iteration**:
```
O(λ·ℓ/log(λ)) bits
```

**Total for O(log(ℓ)) iterations**:
```
O(λ·ℓ·log(ℓ)/log(λ)) = poly(ℓ,λ) bits
```

### 5.3 Verifier Time per Iteration

**Field extension verification**:
```
O(d) = poly(λ) operations
```

**Commitment verification**:
```
O(1) operations (just check commitment)
```

**Sumcheck verification**:
```
Per round: O(b+d) = poly(λ) operations
Number of rounds: O(log(ℓ)+α) = O(log(ℓ))
Total: O(log(ℓ)·poly(λ)) operations
```

**Final evaluation**:
```
O(√(2^{log(μ)+log(d)})) = O(√(2^ℓ)·λ) operations
Using dynamic programming for multilinear extension
```

**Total per iteration**:
```
O(√(2^ℓ)·λ) operations
```

**Key insight**: No cyclotomic ring operations!

### 5.4 Comparison with Greyhound

**Greyhound verifier**:
```
O(λ·√(2^ℓ)·λ) = O(λ^2·√(2^ℓ)) operations
Includes Johnson-Lindenstrauss projection over R_q
```

**Hachi verifier**:
```
O(√(2^ℓ)·λ) operations
No ring operations (sumcheck over F_{q^k})
```

**Asymptotic improvement**: Factor of λ

**Concrete improvement**: 
- λ = 128
- Factor of 128 in theory
- Factor of 12.5 in practice (due to constants)

## 6. Parameter Selection Guidelines

### 6.1 Security Parameters
```
λ = 128 (security level)
q ≈ 2^32 (prime modulus, q ≡ 5 mod 8)
k = λ/log(q) ≈ 4 (extension degree)
n_A = n_B = n_D = 1 (commitment heights)
```

### 6.2 Ring Dimension
```
d = 2^α where α ∈ {8, 9, 10}
Larger d:
  + Faster commitment (better NTT)
  + Sparser challenges
  - Larger proof (more sumcheck rounds)
Typical: d = 1024 (α = 10)
```

### 6.3 Decomposition Base
```
b ∈ {16, 256}
Smaller b:
  + Smaller sumcheck proof
  - Larger witness after decomposition
Hachi: b = 16
LaBRADOR: b = 256
```

### 6.4 Split Parameters
```
m ≈ r ≈ ℓ/2 (balanced split)
Ensures witness reduces by factor ≈ 2 per iteration
```

### 6.5 Challenge Parameters
```
ω = O(d) (challenge norm)
k = O(log(λ)) (number of non-zero coefficients)
Must satisfy: ω < (1/(2√2))·q^{1/2}
```
