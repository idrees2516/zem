# Hachi: Exhaustive Implementation Requirements
## Complete Technical Specification from Research Paper

**Document Purpose:** This document provides a complete, line-by-line analysis of the Hachi paper, ensuring every mathematical detail, proof step, algorithm, and implementation requirement is fully specified.

**Paper Reference:** "Hachi: Efficient Lattice-Based Multilinear Polynomial Commitments over Extension Fields" by Nguyen, O'Rourke, and Zhang (2026)

---

## TABLE OF CONTENTS

### PART I: INTRODUCTION AND MOTIVATION
1. Problem Statement and Context
2. Prior Work Analysis
3. Core Contributions
4. Technical Overview

### PART II: MATHEMATICAL PRELIMINARIES
5. Notation and Conventions
6. Cyclotomic Ring Theory
7. Galois Automorphisms and Trace Maps
8. Norm Definitions and Properties
9. Multilinear Extensions
10. Coordinate-Wise Special Soundness

### PART III: EXTENSION FIELD EMBEDDING THEORY
11. Subfield Identification (Lemma 5)
12. Inner Product Preservation (Theorem 2)
13. Norm Preservation (Lemma 6)
14. Generic F_{q^k} to R_q Transformation
15. Optimized F_q Polynomial Case

### PART IV: COMMITMENT SCHEME CONSTRUCTION
16. Ajtai-Style Commitment Framework
17. Inner-Outer Commitment Structure
18. Weak Opening Definition
19. Binding Properties (Lemma 7)

### PART V: RING SWITCHING PROTOCOL
20. Polynomial Lifting to Z_q[X]
21. Multilinear Extension Commitment
22. Challenge Substitution Mechanism
23. Inner Product Reduction

### PART VI: SUMCHECK PROTOCOL INTEGRATION
24. Sumcheck Protocol Specification
25. Round-by-Round Analysis
26. Special Soundness (Lemma 9)
27. Evaluation Proof Construction

### PART VII: NORM VERIFICATION PROTOCOL
28. Range Proof Framework
29. Zero-Coefficient Verification (Lemma 10)
30. Coordinate-Wise Soundness Analysis

### PART VIII: RECURSIVE PROTOCOL STRUCTURE
31. Multilinear Extension Homomorphism
32. Recursive Evaluation Strategy
33. Communication Optimization

### PART IX: COMPLETE PROTOCOL SPECIFICATION
34. Setup Algorithm
35. Commitment Algorithm
36. Evaluation Proof Algorithm
37. Verification Algorithm

### PART X: SECURITY ANALYSIS
38. Module-SIS Hardness
39. Knowledge Soundness Proof
40. Soundness Error Bounds
41. Completeness Analysis

### PART XI: PERFORMANCE ANALYSIS
42. Asymptotic Complexity
43. Concrete Performance Metrics
44. Comparison with Greyhound
45. Parameter Selection Guidelines

### PART XII: IMPLEMENTATION SPECIFICATIONS
46. Data Structure Definitions
47. Algorithm Pseudocode
48. Optimization Strategies
49. Testing Requirements

---


# PART I: INTRODUCTION AND MOTIVATION

## 1. Problem Statement and Context

### 1.1 Multilinear Polynomial Commitment Schemes

**Definition:**
A multilinear polynomial commitment scheme (PCS) is a cryptographic primitive that enables:
- **Commitment Phase:** Prover commits to an ℓ-dimensional multilinear polynomial f ∈ F^{≤1}[X_1, ..., X_ℓ]
- **Evaluation Phase:** Prover proves evaluation f(x_1, ..., x_ℓ) = y
- **Verification Phase:** Verifier checks proof with evaluation point (x_1, ..., x_ℓ) ∈ F^ℓ and value y ∈ F

**Applications:**
1. **SNARKs:** Core building block for succinct arguments [WTs+18, Set20, CHM+20, GLS+23, CBBZ23]
2. **Lookup Arguments:** Efficient table lookups [STW24]
3. **Multi-Party Computation:** Secure distributed protocols [BHV+23]

**Critical Requirements:**
- **Succinctness:** Proof size poly(ℓ, λ) independent of 2^ℓ evaluations
- **Efficiency:** Fast verification time
- **Post-Quantum Security:** Resistance to quantum attacks

### 1.2 Quantum-Safe PCS Landscape

**Current Approaches:**

**Lattice-Based PCS:**
- **Advantages:**
  - Efficient prover runtime
  - Compact proof sizes (concretely and asymptotically)
  - Module-SIS hardness assumption
- **Disadvantages:**
  - Slow verification time (major bottleneck)
  - Complex cyclotomic ring operations

**Hash-Based PCS:**
- **Advantages:**
  - Fast verification (2 orders of magnitude faster)
  - Simple implementation
- **Disadvantages:**
  - Larger proof sizes
  - Higher prover overhead

**Research Question:**
> Can we design a lattice-based PCS with fast verification while retaining compact proof sizes?

**Hachi's Answer:** YES - through ring switching and extension field sumcheck

### 1.3 Performance Comparison Table

```
┌─────────────┬──────────┬───────────┬─────────────────┬──────────────────┬──────────┬──────────┐
│   Scheme    │Multilinear│Extension │  Asymptotic     │   Asymptotic     │ Concrete │ Concrete │
│             │           │  Fields  │   Proof Size    │  Verifier Time   │  Proof   │ Verifier │
├─────────────┼──────────┼───────────┼─────────────────┼──────────────────┼──────────┼──────────┤
│ Greyhound   │    ✗     │     ✗    │  poly(ℓ, λ)     │ Õ(λ·√(2^ℓ)·λ)    │  53 KB   │  2.8 s   │
│  [NS24]     │          │          │                 │                  │          │          │
├─────────────┼──────────┼───────────┼─────────────────┼──────────────────┼──────────┼──────────┤
│   Hachi     │    ✓     │     ✓    │  poly(ℓ, λ)     │   Õ(√(2^ℓ)·λ)    │  55 KB   │  227 ms  │
│  (This)     │          │          │                 │                  │          │          │
└─────────────┴──────────┴───────────┴─────────────────┴──────────────────┴──────────┴──────────┘
```

**Key Metrics (ℓ = 30 variables):**
- **Verification Speedup:** 12.5× faster (227ms vs 2.8s)
- **Asymptotic Improvement:** Õ(λ) factor reduction
- **Proof Size:** Comparable (~55KB vs ~53KB)

---

## 2. Prior Work Analysis

### 2.1 Split-and-Fold Framework [BBC+18]

**Core Relation:**
Prove knowledge of vectors s_1, ..., s_r ∈ R_q^m such that:
```
[A    ]   [s_1]
[  B  ] · [ ⋮ ] = u  (mod q)  AND  ||s_i||_∞ ≤ β  for i = 1, ..., r
[    A]   [s_r]
```

**Protocol Steps:**

**Step 1: Split**
- Prover sends partial evaluations: t_i = A·s_i for i ∈ [r]
- Communication: r ring elements

**Step 2: Challenge**
- Verifier sends short challenges: c_1, ..., c_r ∈ C ⊂ R_q
- Challenge space C must have special properties

**Step 3: Fold**
- Prover computes linear combination: z := c_1·s_1 + ... + c_r·s_r ∈ R_q^m
- Prover sends z

**Step 4: Verification**
Verifier checks three conditions:
```
1. B·[t_1; ...; t_r] = u
2. A·z = Σ_{i=1}^r c_i·t_i
3. ||z||_∞ is short
```

**Complexity Analysis:**
- **Communication:** r + m ring elements
- **Sublinear Property:** r + m ≪ r·m (witness length)
- **Square-Root Proofs:** Setting r ≈ √N yields Õ(√N·λ) proof size

**Follow-Up Works:**
- [BLNS20, AFLN24, CMNW24, KLNO24]: Reduced to polylog(N) ring elements
- **Key Insight:** Tensor-structured matrix A enables recursive application

### 2.2 Exact Norm Proof Techniques

#### 2.2.1 Subtractive Sets Approach

**Definition:**
Set C ⊆ R_q is subtractive if for any distinct c, c' ∈ C:
- (c - c')^{-1} exists in R_q
- ||(c - c')^{-1}||_∞ is small

**Knowledge Extraction:**
Given two accepting transcripts with challenges c, c':
```
z = c·s + noise
z' = c'·s + noise'
⟹ s = (z - z')·(c - c')^{-1}
```

**Limitations:**
- **Polynomial Size:** |C| = poly(λ) [AL21]
- **Multiple Repetitions:** Need O(λ) repetitions for negligible soundness
- **Efficiency Impact:** Significantly larger proofs

**Works Using This:** [BLNS20, AL21, ACK21, CLM23, FMN24, AFLN24, KLNO24]

#### 2.2.2 Random Projection Approach

**Johnson-Lindenstrauss Lemma Application:**

**Setup:**
- Witness: s ∈ R_q^m with coefficient vector s' ∈ Z_q^{md}
- Projection matrix: J ∈ Z^{r×md} with small random entries
- Soundness parameter: r = O(λ)

**Property:**
```
||J·s'|| ≈ ||s'|| = ||s||
```

**Protocol:**
1. Verifier sends (or derives via hash) projection matrix J
2. Prover computes and sends v := J·s' ∈ Z^r
3. Verifier checks ||v||_∞ ≤ β

**Soundness Argument:**
- If ||s|| > β, then with probability 1 - exp(-r), ||v|| > β
- Setting r = O(λ) gives negligible soundness error

**Well-Formedness Proof:**
Must prove v is correctly computed. Reduces to proving r polynomials u_1, ..., u_r ∈ R_q have zero constant coefficients.

**Batching Technique:**
- Verifier sends challenges α_1, ..., α_r ← Z_q
- Prover returns u := Σ_{i=1}^r α_i·u_i
- Verifier checks constant coefficient of u is zero
- Soundness error: 1/q per repetition
- Need O(λ/log q) repetitions

**Concrete Implementations:**

**LaBRADOR [BS23]:**
- Proof size: ≈60KB for large statements (2^30)
- Verification: Linear time in witness length
- Not suitable for SNARK applications

**Klooß et al. [KLNO25]:**
- Tensor-structured projection matrices
- Verification: polylog(md) time
- Trade-off: 40× larger proofs than LaBRADOR

### 2.3 Greyhound Hybrid Approach [NS24]

**Strategy:**
Combine split-and-fold with LaBRADOR for square-root verification.

**Protocol Structure:**
1. Follow [BBC+18] three-round protocol
2. **Commit** to (t_i)_i and z instead of sending in clear
3. **Prove** verification equations via LaBRADOR on smaller statement

**Complexity:**
- **Verification:** Õ(√(2^ℓ)·λ) - square-root time
- **Proof Size:** ~53KB - compact
- **Bottleneck:** Still requires cyclotomic ring operations

### 2.4 Sumcheck-Based Norm Proofs

#### 2.4.1 LatticeFold [BC24]

**Approach:**
- Execute sumcheck protocol over cyclotomic ring R_q
- Prove committed NTT coefficients are binary

**Limitation:**
- Each ring element is large
- Significantly increased proof sizes

#### 2.4.2 Kuriyama et al. [KLOT25]

**Extension:**
- Prove exact Euclidean norm bounds
- Still uses R_q-based sumchecks
- Proof size overhead remains

#### 2.4.3 Neo [NS25]

**Innovation:**
- Map R_q relations to Z_q via rotational (skew-circulant) matrices
- Run sumcheck directly over Z_q or F_{q^k}
- Achieves negligible soundness error

**Advantage:**
- Avoids large ring element communication
- More efficient than R_q-based sumcheck

#### 2.4.4 LatticeFold+ [BC25]

**Range Proof Technique:**
To prove a ∈ [0, d):
1. Commit to monomial X^a ∈ R_q
2. Prove committed element is indeed a monomial
3. Reduce to sumcheck claims over R_q

**Observation:**
- Claims don't involve "full-fledged" R_q multiplications
- Can reduce to O(d) sumcheck claims over Z_q

**Efficiency Bottleneck:**
- For witness s' ∈ Z_q^{md}, must commit to md elements of R_q
- Larger than [BS23, NS24, NS25] which commit to m elements

---

## 3. Core Contributions

### 3.1 Faster Verification via Ring Switching

**Problem:**
Sumcheck over large polynomial rings R_q is inefficient.

**Solution:**
Integrate Greyhound framework with ring-switching technique [HMZ25].

**Key Innovation:**
Lift statements from R_q to polynomial ring F_{q^k}[X], then:
1. Evaluate at random point X := α ∈ F_{q^k}
2. Run sumcheck protocol over extension field F_{q^k}
3. Verifier performs NO cyclotomic ring operations

**Result:**
- Total verifier complexity: Õ(√(2^ℓ)·λ) operations over F_{q^k}
- Asymptotic improvement: Õ(λ) factor over Greyhound
- Concrete speedup: 12.5× faster verification

**Uniqueness:**
First lattice-based SNARK/PCS/folding scheme eliminating cyclotomic ring operations for verifiers.

### 3.2 Embedding Multilinear Evaluation Claims

**Generic Transformation:**
Prove ℓ-variate polynomial evaluations over F_{q^k} by proving (ℓ - α + κ)-variate evaluations over R_q.

**Parameters:**
- d = 2^α (ring dimension)
- k = 2^κ (extension degree)

**Generalization of SLAP [AFLN24]:**
1. **Extension to Field Extensions:** Support F_{q^k} not just F_q
2. **Multivariate Case:** Extend from univariate to multivariate polynomials

**Optimization for F_q Polynomials:**
When f ∈ F_q[X_1, ..., X_ℓ] but evaluation points in F_{q^k}:
- More efficient transformation
- Reduces to (ℓ - α)-variate instead of (ℓ - α + κ)-variate

### 3.3 Flexibility in Ring Dimension Selection

**Traditional Constraints (LaBRADOR/Greyhound):**
- Must prove constant coefficients are zero
- Requires sending O(λ/log q) ring elements per iteration
- Small d (e.g., d=64) essential for small proofs

**Hachi Advantage:**
- Sumcheck over extension field F_{q^k} independent of d
- Freedom to choose larger d

**Benefits of Larger d:**
1. **Faster Commitment:** Optimized NTT-based ring multiplication
2. **Sparse Challenges:** Define challenge space C with sparse ring elements
3. **Faster Folding:** Sparse multiplication for computing z = Σ c_i·s_i

### 3.4 Implementation Results

**Prototype in Rust:**
- Early stage but amenable to SIMD optimizations
- Already demonstrates clear advantages

**Observed Performance:**

**Verification Time:**
- One order of magnitude faster than Greyhound
- Without advanced optimizations (SIMD not yet implemented)

**Commitment Time:**
- 3-5× faster than Greyhound
- Due to larger ring dimension enabling better NTT performance

**Future Potential:**
- SIMD optimizations will further improve performance
- Parallel sumcheck round computation
- Batch verification opportunities

---


## 4. Technical Overview

### 4.1 Parameter Setup

**Security Parameter:** λ

**Ring Parameters:**
- **Ring Dimension:** d := 2^α (power-of-two)
- **Cyclotomic Ring:** R := Z[X]/(X^d + 1)
- **Prime Modulus:** q (odd prime, q ≡ 5 (mod 8))
- **Quotient Ring:** R_q := R/(q)
- **Decomposition Base:** δ := ⌈log q⌉

**Extension Field:**
- **Extension Degree:** k ≥ 1 (must divide d/2)
- **Extension Field:** F_{q^k} (finite field of order q^k)

**Gadget Matrix:**
```
G_n := I_n ⊗ [1, 2, 4, ..., 2^{δ-1}] ∈ R_q^{n×nδ}
```

**Inverse Function:**
```
G_n^{-1} : R_q^n → R_q^{nδ}
```
Properties:
- G_n · G_n^{-1}(t) = t for all t ∈ R_q^n
- G_n^{-1}(t) has binary coefficients

**Galois Automorphisms:**
- **Automorphism:** σ_i : R → R defined by X ↦ X^i for i ∈ Z_{2d}^×
- **Automorphism Group:** Aut(R) := {σ_i : i ∈ Z_{2d}^×}
- **Subgroup:** H := ⟨σ_{-1}, σ_{4k+1}⟩ ⊆ Aut(R)
- **Fixed Ring:** R_q^H := {x ∈ R_q : ∀σ ∈ H, σ(x) = x}
- **Trace Map:** Tr_H : R_q → R_q^H defined as Tr_H(a) := Σ_{σ∈H} σ(a)

### 4.2 Reducing Multilinear Evaluation to R_q Relations

**Goal:**
Transform f(x_1, ..., x_ℓ) = y over F_{q^k} into equivalent relation over R_q.

**Challenge:**
Translate field extension operations (addition, multiplication in F_{q^k}) to cyclotomic ring operations.

#### Step 1: Identify Finite Fields within R_q

**Lemma 1 (Informal):**
Let q ≡ 5 (mod 8) and k ≥ 1 divide d/2. Consider subgroup H := ⟨σ_{-1}, σ_{4k+1}⟩ of Aut(R).
Then R_q^H is a subfield of R_q isomorphic to F_{q^k}.

**Proof Sketch:**
- R_q^H is subset of elements stable under σ_{-1} (which forms a field)
- Closed under addition and multiplication (homomorphic properties)
- Size |R_q^H| = q^k (k degrees of freedom in coefficient representation)

**Element Structure in R_q^H:**
```
a := a_0 + Σ_{j=1}^{k-1} a_{k-j} · (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
```
with a_0, a_1, ..., a_{k-1} ∈ Z_q

#### Step 2: Inner Product Preservation via Trace Map

**Theorem 1 (Informal):**
Let q ≡ 5 (mod 8), k divide d/2, H := ⟨σ_{-1}, σ_{4k+1}⟩ ⊆ Aut(R).
There exists efficiently computable bijection ψ : (R_q^H)^{d/k} → R_q such that for any a, b ∈ (R_q^H)^{d/k}:
```
Tr_H(ψ(a) · σ_{-1}(ψ(b))) = (d/k) · ⟨a, b⟩
```

**Bijection Definition:**
```
ψ(a_0, a_1, ..., a_{d/k-1}) := Σ_{i=0}^{d/(2k)-1} a_i · X^i + X^{d/2} · Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} · X^i
```

**Properties:**
- **Packing:** Embeds d/k extension field elements into one ring element
- **Invertibility:** Crucial for knowledge soundness
- **Inner Product:** Preserved via trace map

#### Step 3: Apply to Polynomial Evaluation

**Polynomial Evaluation Equation:**
For k = 2^κ dividing d/2, rewrite f(x_1, ..., x_ℓ) = y as:
```
y = Σ_{i∈{0,1}^{ℓ-α+κ}} x_1^{i_1} · ... · x_{ℓ-α+κ}^{i_{ℓ-α+κ}} · 
    (Σ_{j∈{0,1}^{α-κ}} f_{i||j} · x_{ℓ-α+κ+1}^{j_1} · ... · x_ℓ^{j_{α-κ}})
```

**Ring Element Construction:**
For each i ∈ {0,1}^{ℓ-α+κ}:
```
F_i := ψ((f_{i||j})_{j∈{0,1}^{α-κ}})
v := ψ((x_{ℓ-α+κ+1}^{j_1} · ... · x_ℓ^{j_{α-κ}})_{j∈{0,1}^{α-κ}})
```

**Trace Equation:**
Using R_q^H stability under Tr_H and Theorem 1:
```
(d/k) · y = Tr_H(Y · σ_{-1}(v))
```
where:
```
Y := Σ_{i∈{0,1}^{ℓ-α+κ}} x_1^{i_1} · ... · x_{ℓ-α+κ}^{i_{ℓ-α+κ}} · F_i
```

**Verification:**
1. Prover sends single ring element Y ∈ R_q
2. Verifier checks Tr_H(Y · σ_{-1}(v)) = (d/k) · y
3. Prover proves Y is well-formed (evaluation of (ℓ-α+κ)-variate polynomial F over R_q)

#### Step 4: Optimization for F_q Polynomials

**Scenario:**
Evaluation point in F_{q^k} but polynomial coefficients in F_q.

**Rewrite Evaluation:**
```
y = Σ_{i∈{0,1}^κ} x_1^{i_1} · ... · x_κ^{i_κ} · 
    (Σ_{j∈{0,1}^{ℓ-κ}} f_{i||j} · x_{κ+1}^{j_1} · ... · x_ℓ^{j_{ℓ-κ}})
```

**Partial Evaluations:**
Define y_i := Σ_{j∈{0,1}^{ℓ-κ}} f_{i||j} · x_{κ+1}^{j_1} · ... · x_ℓ^{j_{ℓ-κ}} for i ∈ {0,1}^κ

**Prover Action:**
Send k partial evaluations y_i ∈ F_{q^k} (or k-1, deriving one deterministically)

**Verifier Check:**
Directly verify: y = Σ_{i∈{0,1}^κ} x_1^{i_1} · ... · x_κ^{i_κ} · y_i

**Aggregated Polynomial:**
Define F_{q^k} := F_q[Z]/φ(Z) where φ is irreducible of degree k.
Construct:
```
f'(X_{κ+1}, ..., X_ℓ) := Σ_{i∈{0,1}^κ} f_i(X_{κ+1}, ..., X_ℓ) · Z^{Σ_{t=1}^κ i_t·2^{t-1}}
```

**Evaluation Claim:**
```
f'(x_{κ+1}, ..., x_ℓ) = Σ_{i∈{0,1}^κ} y_i · Z^{Σ_{t=1}^κ i_t·2^{t-1}} ∈ F_{q^k}
```

**Reduction:**
Apply generic transformation to prove (ℓ-α)-variate evaluation over R_q (better than (ℓ-α+κ)-variate).

### 4.3 Polynomial Evaluation as Quadratic Equation

**Folklore Strategy:**
For μ-variate polynomial f with μ = m + r, coefficient vector f := (f_ι)_{ι∈{0,1}^μ}:

**Rewrite Evaluation:**
```
f(X_1, ..., X_μ) = Σ_{i∈{0,1}^r} Σ_{j∈{0,1}^m} f_{i||j} · (X_1^{i_1} · ... · X_r^{i_r}) · (X_{r+1}^{j_1} · ... · X_μ^{j_m})
```

**Vector Definitions:**
```
b^T := (x_1^{i_1} · ... · x_r^{i_r})_{i∈{0,1}^r} ∈ R_q^{2^r}
a^T := (x_{r+1}^{j_1} · ... · x_μ^{j_m})_{j∈{0,1}^m} ∈ R_q^{2^m}
f_i := (f_{i||j})_{j∈{0,1}^m} ∈ R_q^{2^m} for i ∈ {0,1}^r
```

**Matrix Form:**
```
f(x_1, ..., x_μ) = b^T · [f_0^T]
                         [  ⋮  ] · a
                         [f_{2^r-1}^T]
                  = b^T · (a^T ⊗ I_{2^r}) · f
```

**Gadget Decomposition:**
Define s := G_{2^μ}^{-1}(f) ∈ R_q^{2^m·δ}

**Mixed Product Property:**
```
f(x_1, ..., x_μ) = b^T · (a^T ⊗ I_{2^r}) · f
                  = b^T · (a^T ⊗ I_{2^r}) · (g^T ⊗ I_{2^{m+r}}) · s
                  = b^T · (a^T · (g^T ⊗ I_{2^r}) ⊗ I_{2^r}) · s
```

**Target Relation:**
Prove knowledge of short vector s satisfying quadratic equation above.

**Greyhound Integration:**
Following [NS24]:
1. Apply square-root interactive proof [BBC+18]
2. Commit to prover messages instead of sending in clear
3. Prove knowledge of committed values satisfying verification equations

**Resulting Relation:**
Prove knowledge of short vector z ∈ R_q^{(2^m + 2^r)·poly(λ)} such that:
```
M·z = w  AND  ||z||_∞ ≤ β
```

**Divergence from Greyhound:**
Instead of LaBRADOR [BS23], use sumcheck-based solution.

### 4.4 Ring Switching and Sumcheck over Extension Fields

**Inspiration:**
Ring switching approach from [HMZ25].

**Multilinear Extension:**
For function f : {0,1}^μ → F_{q^k}, define:
```
mle[f](x) := Σ_{i∈{0,1}^μ} f(i) · eq(i, x)
```
where eq(i, x) := ∏_{j=1}^μ ((1-i_j)·(1-x_j) + i_j·x_j) is equality polynomial.

#### Step 1: Polynomial Lifting

**Lift Relation from R_q to Z_q[X]:**
For simplicity, consider single-row matrix M (generalize to multiple rows later):
```
Σ_k M_k(X) · z_k(X) = w(X) + (X^d + 1) · r(X)
```
for some r ∈ Z_q^{<d-1}[X]

**Coefficient Vectors:**
- z': Z_q-coefficient vector of z
- r': Z_q-coefficient vector of r

#### Step 2: Multilinear Extension Commitment

**Prover Action:**
Commit to multilinear extension:
```
P := mle[(z', r')] ∈ F_{q^k}^{≤1}[X_1, ..., X_μ]
```

**Note:**
Treat vector a ∈ F_q^{2^L} as indexing function from {0,1}^L to F_q.

**Size Observation:**
|P| ≪ |f| (original committed polynomial), enabling recursion.

#### Step 3: Challenge Substitution

**Verifier Action:**
Send challenge α ← F_{q^k}

**Substitution:**
X = α reduces to inner product claim over F_{q^k}

#### Step 4: Sumcheck Transformation

**Sumcheck Relation:**
Transform to:
```
Σ_{i∈{0,1}^μ} P(i) · Q(i) = V
```
where:
- P: Committed multilinear polynomial (witness)
- Q: Public multilinear polynomial (constraint)
- V: Public target value ∈ F_{q^k}

#### Step 5: Norm Verification

**Advantage of Ring Switching:**
Statements now over finite field F_{q^k}, not polynomial ring R_q.

**Coordinate Bounds:**
Prove all coordinates of z' satisfy |z'_i| ≤ β.

**Standard Range Proof:**
Use finite field range proof techniques (more efficient than ring-based proofs).

**Verification Complexity:**
- Traditional (LaBRADOR): Linear in witness length over R_q
- Hachi: Õ(√(2^ℓ)·λ) operations over F_{q^k}

#### Step 6: Sumcheck Protocol Execution

**Final Claim:**
After sumcheck protocol, obtain polynomial evaluation claim:
```
P(r_1*, ..., r_μ*) · Q(r_1*, ..., r_μ*) = y*
```
where (r_1*, ..., r_μ*) and y* are public.

**Prover Action:**
Send evaluation P(r_1*, ..., r_μ*)

**Verifier Check:**
Directly verify equation above.

**Remaining Task:**
Prove evaluation claim for polynomial P (recursive application).

### 4.5 Committing to P and Avoiding Re-Decomposition

**Naive Approach:**
1. Decompose coefficients of P = mle[(z', r')]
2. Apply Ajtai-style commitment [Ajt96]
3. Problem: Witness gets longer (re-decomposition overhead)

**Efficient Approach:**
Directly commit to (z', r') without decomposition.

**Rationale:**
- Coefficients of z' already small (no decomposition needed)
- Only r' needs decomposition

**Challenge:**
How to prove mle[(z', r')](x_1, ..., x_μ) = y' when only committed to (z', r')?

**Solution:**
Homomorphic property of equality polynomials.

**Key Property:**
For vectors i, j and evaluation points x_0, x_1:
```
eq(i, x_0) · eq(j, x_1) = eq(i||j, x_0||x_1)
```

**Application:**
For μ = m + r:
```
mle[(z', r')](x_0||x_1) = Σ_{i∈{0,1}^r} Σ_{j∈{0,1}^m} (z', r')_{i||j} · eq(i||j, x_0||x_1)
                         = Σ_{i∈{0,1}^r} eq(i, x_0) · (Σ_{j∈{0,1}^m} (z', r')_{i||j} · eq(j, x_1))
```

**Observation:**
Same structure as Equation (4)!

**Recursive Application:**
Run protocol recursively to prove evaluation of P without explicitly committing to its coefficients.

**Communication Efficiency:**
- Traditional: Commit to 2^μ polynomial coefficients
- Hachi: Commit to |z'| + |r'| ≪ 2^μ witness elements

---


# PART II: MATHEMATICAL PRELIMINARIES

## 5. Notation and Conventions

### 5.1 Basic Notation

**Security Parameter:**
- λ: Security parameter (typically λ = 128 or λ = 256)

**Modular Arithmetic:**
- q ≡ 5 (mod 8): Odd prime modulus
- Z_q := {0, 1, ..., q-1}: Ring of integers modulo q
- F_q: Galois field of order q (used interchangeably with Z_q)
- F_{q^k}: Galois field of dimension k and size q^k

**Natural Numbers:**
- N: Set of natural numbers
- [n] := {1, 2, ..., n} for n ∈ N

**Asymptotic Notation:**
- O_λ(T): Denotes T · poly(λ)
- Õ(T): Hides logarithmic factors
- negl(λ): Unspecified negligible function

**Probability:**
- X: Probability distribution or finite set
- x ← X: Sample x from distribution X or uniformly from set X

### 5.2 Indexing Conventions

**Index Variables:**
- i, j: Primary indexing variables
- ι, κ: Alternative index variables

**Binary Vectors:**
- i ∈ {0,1}^k: Binary vector (i_1, ..., i_k) of length k
- Dual interpretation: i ∈ [2^k] means binary encoding of integer i

**Concatenation:**
- i||j: Concatenation of binary vectors i and j

**Usage Context:**
Binary interpretation useful for sumcheck-based norm protocol (Section 4.3).

### 5.3 Vector and Matrix Notation

**Scalars:**
- Lower-case letters: Elements in R or R_q (e.g., a, b, c)

**Vectors:**
- Bold lower-case: Column vectors with coefficients in R or R_q (e.g., **a**, **b**, **s**)
- Superscript T: Transpose (e.g., **a**^T for row vector)

**Matrices:**
- Bold upper-case: Matrices with coefficients in R or R_q (e.g., **A**, **B**, **M**)

**Coefficient Extraction:**
For y = Σ_{i=0}^{d-1} y_i · X^i ∈ R_q:
```
cf(y) := (y_0, ..., y_{d-1}) ∈ F_q^d
```
Natural extension to vectors: cf(**y**) extracts all coefficients.

---

## 6. Cyclotomic Ring Theory

### 6.1 Ring Definitions

**Power-of-Two Dimension:**
```
d := 2^α for some α ∈ N
```

**Cyclotomic Polynomial:**
```
Φ_{2d}(X) = X^d + 1
```

**Ring of Integers:**
```
R := Z[X]/(X^d + 1)
```
This is the ring of integers of the 2d-th cyclotomic field Q(ζ_{2d}).

**Quotient Ring:**
```
R_q := Z_q[X]/(X^d + 1) = R/(q)
```

**Element Representation:**
Any element a ∈ R_q can be written as:
```
a = Σ_{i=0}^{d-1} a_i · X^i where a_i ∈ Z_q
```

### 6.2 Gadget Matrices and Decomposition

**Base-b Gadget Matrix:**
For base b ≥ 2 and dimension n ≥ 1:
```
G_{b,n} := I_n ⊗ [1, b, b^2, ..., b^{δ-1}] ∈ R_q^{n×nδ}
```
where δ = ⌈log_b q⌉

**Tensor Product:**
I_n ⊗ g means:
```
[g   0   ...  0  ]
[0   g   ...  0  ]
[⋮   ⋮   ⋱    ⋮  ]
[0   0   ...  g  ]
```
where g = [1, b, b^2, ..., b^{δ-1}]

**Inverse Function:**
```
G_{b,n}^{-1} : R_q^n → R_q^{nδ}
```

**Properties:**
1. **Correctness:** G_{b,n} · G_{b,n}^{-1}(t) = t for all t ∈ R_q^n
2. **Coefficient Bounds:** G_{b,n}^{-1}(t) has coefficients in [⌈-b/2⌉, ⌈b/2⌉-1]
3. **Deterministic:** Decomposition is unique given coefficient bounds

**Base-2 Decomposition (Default):**
When b = 2:
- δ = ⌈log_2 q⌉
- Coefficients are binary: {0, 1}
- Notation: G_n := G_{2,n} (omit base subscript)

**Example:**
For t = (t_1, t_2) ∈ R_q^2 with q = 17 (so δ = 5):
```
G_2^{-1}(t) = (t_{1,0}, t_{1,1}, t_{1,2}, t_{1,3}, t_{1,4}, t_{2,0}, t_{2,1}, t_{2,2}, t_{2,3}, t_{2,4})
```
where t_i = Σ_{j=0}^4 t_{i,j} · 2^j and t_{i,j} ∈ {0, 1}

### 6.3 Galois Automorphisms

**Definition:**
For i ∈ Z_{2d}^× (units of Z_{2d}), define Galois automorphism:
```
σ_i : R → R
X ↦ X^i
```

**Extension to Polynomials:**
For a = Σ_{j=0}^{d-1} a_j · X^j:
```
σ_i(a) = Σ_{j=0}^{d-1} a_j · X^{ij}
```
where X^{ij} is reduced modulo X^d + 1.

**Automorphism Group:**
```
Aut(R) := {σ_i : i ∈ Z_{2d}^×}
```

**Group Properties:**
- **Composition:** σ_i ∘ σ_j = σ_{ij mod 2d}
- **Identity:** σ_1 = id
- **Inverse:** σ_i^{-1} = σ_{i^{-1} mod 2d}
- **Order:** |Aut(R)| = φ(2d) = d (Euler's totient)

**Key Automorphisms:**

**Conjugation:**
```
σ_{-1} : X ↦ X^{-1} = X^{2d-1} = -X^{d-1}
```
Effect: σ_{-1}(Σ a_i X^i) = Σ a_i X^{-i} = Σ a_i (-1)^{⌈i/d⌉} X^{d-i}

**Frobenius-Type:**
```
σ_{4k+1} : X ↦ X^{4k+1}
```

### 6.4 Fixed Rings and Trace Maps

**Fixed Ring:**
For subgroup H ⊆ Aut(R):
```
R_q^H := {x ∈ R_q : ∀σ ∈ H, σ(x) = x}
```

**Properties:**
- R_q^H is a subring of R_q
- Closed under addition and multiplication
- Contains identity and zero

**Trace Map:**
```
Tr_H : R_q → R_q^H
a ↦ Σ_{σ∈H} σ(a)
```

**Properties:**
1. **Additively Homomorphic:** Tr_H(a + b) = Tr_H(a) + Tr_H(b)
2. **R_q^H-Linear:** Tr_H(c · a) = c · Tr_H(a) for c ∈ R_q^H
3. **Idempotent on R_q^H:** Tr_H(a) = |H| · a for a ∈ R_q^H
4. **Surjective:** Tr_H maps onto R_q^H

**Subgroup for Extension Fields:**
```
H := ⟨σ_{-1}, σ_{4k+1}⟩
```
Generated by σ_{-1} and σ_{4k+1}.

**Group Structure:**
- |H| = 2 · (d/(2k)) = d/k
- Elements: {σ_{(-1)^a · (4k+1)^b} : a ∈ {0,1}, b ∈ [d/(2k)]}

---

## 7. Galois Automorphisms and Trace Maps (Detailed Analysis)

### 7.1 Conjugation Automorphism σ_{-1}

**Definition:**
```
σ_{-1}(X) = X^{-1} = X^{2d-1}
```

**Reduction:**
Since X^{2d} = (X^d)^2 = (-1)^2 = 1 in R:
```
X^{2d-1} = X^{-1}
```

**Effect on Monomials:**
```
σ_{-1}(X^i) = X^{-i} = X^{2d-i}
```

**Reduction Modulo X^d + 1:**
- If i = 0: X^0 = 1 → σ_{-1}(1) = 1
- If 1 ≤ i < d: X^{2d-i} = X^{d} · X^{d-i} = -X^{d-i}
- If i = d: X^d = -1 → σ_{-1}(X^d) = X^{-d} = X^d = -1

**General Formula:**
```
σ_{-1}(Σ_{i=0}^{d-1} a_i X^i) = a_0 - Σ_{i=1}^{d-1} a_i X^{d-i}
```

**Fixed Points:**
Element a ∈ R_q is fixed by σ_{-1} iff:
```
a = σ_{-1}(a)
```

**Characterization:**
a = Σ a_i X^i is fixed by σ_{-1} iff:
- a_0 = a_0 (always true)
- a_i = -a_{d-i} for i = 1, ..., d-1

**Dimension of Fixed Space:**
dim(R_q^{⟨σ_{-1}⟩}) = (d+1)/2 (approximately d/2)

### 7.2 Frobenius-Type Automorphism σ_{4k+1}

**Definition:**
```
σ_{4k+1}(X) = X^{4k+1}
```

**Order Calculation:**

**Claim:**
The order of 4k+1 in Z_{2d}^× is d/(2k).

**Proof:**
Need smallest m such that (4k+1)^m ≡ 1 (mod 2d).

**Observation:**
```
(4k+1)^m = Σ_{j=0}^m (m choose j) (4k)^j
         ≡ 1 + m·4k (mod (4k)^2)
```

For (4k+1)^m ≡ 1 (mod 2d):
```
m·4k ≡ 0 (mod 2d)
m ≡ 0 (mod 2d/(4k))
m ≡ 0 (mod d/(2k))
```

Smallest such m is d/(2k).

**Orbit Structure:**
```
⟨σ_{4k+1}⟩ = {σ_{(4k+1)^j} : j = 0, ..., d/(2k)-1}
           = {σ_{4k·α+1} : α = 0, ..., d/(2k)-1}
```

**Fixed Points:**
Element a is fixed by σ_{4k+1} iff:
```
a(X) = a(X^{4k+1})
```

### 7.3 Combined Subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩

**Group Structure:**
```
H = {σ_{(-1)^a · (4k+1)^b} : a ∈ {0,1}, b ∈ {0, ..., d/(2k)-1}}
```

**Group Size:**
```
|H| = 2 · d/(2k) = d/k
```

**Fixed Ring R_q^H:**
Elements fixed by both σ_{-1} and σ_{4k+1}.

**Element Structure (Equation 7):**
Any a ∈ R_q^H has the form:
```
a = a_0 + Σ_{j=1}^{k-1} a_{k-j} · (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
```

**Degrees of Freedom:**
k coefficients: a_0, a_1, ..., a_{k-1} ∈ Z_q

**Verification:**
1. **Fixed by σ_{-1}:** Symmetric structure ensures σ_{-1}(a) = a
2. **Fixed by σ_{4k+1}:** Periodicity with period d/(2k) ensures σ_{4k+1}(a) = a

**Dimension:**
```
dim_Zq(R_q^H) = k
```

**Cardinality:**
```
|R_q^H| = q^k
```

### 7.4 Trace Map Properties

**Definition:**
```
Tr_H(a) = Σ_{σ∈H} σ(a)
```

**Explicit Formula:**
```
Tr_H(a) = Σ_{b=0}^{d/(2k)-1} (σ_{4k·b+1}(a) + σ_{-(4k·b+1)}(a))
```

**Key Properties:**

**Property 1: Additivity**
```
Tr_H(a + b) = Tr_H(a) + Tr_H(b)
```

**Property 2: R_q^H-Linearity**
For c ∈ R_q^H:
```
Tr_H(c · a) = c · Tr_H(a)
```

**Property 3: Idempotence on Fixed Elements**
For a ∈ R_q^H:
```
Tr_H(a) = |H| · a = (d/k) · a
```

**Property 4: Surjectivity**
```
Im(Tr_H) = R_q^H
```

**Property 5: Kernel Structure**
```
Ker(Tr_H) = {a ∈ R_q : Tr_H(a) = 0}
```
Dimension: dim(Ker(Tr_H)) = d - k

---

## 8. Norm Definitions and Properties

### 8.1 Modular Reduction

**Centered Reduction (mod± q):**
For r ∈ Z, define r' = r mod± q as unique element satisfying:
```
-q/2 ≤ r' ≤ q/2  AND  r' ≡ r (mod q)
```

**Positive Reduction (mod+ q):**
For r ∈ Z, define r' = r mod+ q as unique element satisfying:
```
0 ≤ r' < q  AND  r' ≡ r (mod q)
```

**Default Convention:**
When exact representation not important, write r mod q.

### 8.2 Infinity Norm

**For Integers:**
For w ∈ Z_q:
```
||w||_∞ := |w mod± q|
```

**For Ring Elements:**
For w = Σ_{i=0}^{d-1} w_i X^i ∈ R:
```
||w||_∞ := max_{i∈{0,...,d-1}} ||w_i||_∞
```

**For Vectors:**
For **w** = (w_1, ..., w_m) ∈ R^m:
```
||**w**||_∞ := max_{j∈{1,...,m}} ||w_j||_∞
```

### 8.3 ℓ_p Norms

**For Ring Elements:**
For w = Σ_{i=0}^{d-1} w_i X^i ∈ R and p ≥ 1:
```
||w||_p := (Σ_{i=0}^{d-1} ||w_i||_∞^p)^{1/p}
```

**For Vectors:**
For **w** = (w_1, ..., w_m) ∈ R^m:
```
||**w**||_p := (Σ_{j=1}^m ||w_j||_p^p)^{1/p}
```

**Default Norm:**
```
||**w**|| := ||**w**||_2 (Euclidean norm)
```

### 8.4 Short Element Sets

**Definition:**
For β ≥ 1:
```
S_β := {a ∈ R : coefficients of a are in [⌈-β/2⌉, ⌈β/2⌉-1]}
```

**Equivalently:**
```
S_β = {a ∈ R : ||a||_∞ ≤ β/2}
```

**Properties:**
- S_β is closed under addition (with appropriate β)
- S_β contains 0 and small multiples of 1
- Used to define challenge spaces and norm bounds

### 8.5 Norm Inequalities

**Lemma 2 (Micciancio [Mic07]):**
For any f, g ∈ R:
```
||f · g||_∞ ≤ ||f||_1 · ||g||_∞
```

**Proof Sketch:**
Product f · g has coefficients:
```
(f · g)_k = Σ_{i+j≡k (mod d)} f_i · g_j · (-1)^{⌊(i+j)/d⌋}
```

Bound:
```
|(f · g)_k| ≤ Σ_i |f_i| · max_j |g_j| = ||f||_1 · ||g||_∞
```

**Application:**
Used extensively to bound norms after ring multiplications.

**Corollary:**
For f, g ∈ R with ||f||_∞ ≤ α and ||g||_∞ ≤ β:
```
||f · g||_∞ ≤ d · α · β
```

**Proof:**
```
||f||_1 ≤ d · ||f||_∞ ≤ d · α
```
Apply Lemma 2.

---

## 9. Multilinear Extensions

### 9.1 Definition over Arbitrary Rings

**Definition 2 (Multilinear Extension over Rings):**
Let R be an arbitrary ring with zero 0 and identity 1.
Given function f : {0,1}^μ → R, define multilinear extension:
```
mle[f] ∈ R^{≤1}[X_1, ..., X_μ]
```
as:
```
mle[f](x) := Σ_{i∈{0,1}^μ} f(i) · eq(i, x)
```

**Equality Polynomial:**
```
eq(i, x) := ∏_{j=1}^μ ((1-i_j)·(1-x_j) + i_j·x_j)
```

**Properties:**
1. **Interpolation:** mle[f](i) = f(i) for all i ∈ {0,1}^μ
2. **Multilinearity:** Degree at most 1 in each variable
3. **Uniqueness:** Only multilinear polynomial agreeing with f on {0,1}^μ

### 9.2 Equality Polynomial Properties

**Evaluation on Boolean Cube:**
For i, j ∈ {0,1}^μ:
```
eq(i, j) = 1 if i = j
eq(i, j) = 0 if i ≠ j
```

**Recursive Structure:**
```
eq(i||i', x||x') = eq(i, x) · eq(i', x')
```

**Explicit Expansion:**
```
eq(i, x) = ∏_{j=1}^μ ((1-i_j)·(1-x_j) + i_j·x_j)
         = ∏_{j: i_j=0} (1-x_j) · ∏_{j: i_j=1} x_j
```

**Homomorphic Property (Crucial for Hachi):**
For i, j ∈ {0,1}^r, {0,1}^m and x_0, x_1:
```
eq(i, x_0) · eq(j, x_1) = eq(i||j, x_0||x_1)
```

### 9.3 Vector Notation

**Convention:**
For vector **f** := (f_i)_{i∈{0,1}^μ} ∈ R^{2^μ}, denote:
```
**f**~ := mle[f]
```
where f : {0,1}^μ → R is defined by i ↦ f_i.

**Example:**
For **f** = (f_0, f_1, f_2, f_3) ∈ R^4 (μ = 2):
```
**f**~(X_1, X_2) = f_0·(1-X_1)·(1-X_2) + f_1·X_1·(1-X_2) + f_2·(1-X_1)·X_2 + f_3·X_1·X_2
```

### 9.4 Multilinear Extension over Extension Fields

**Specific Case:**
For f : {0,1}^μ → F_{q^k}:
```
mle[f] ∈ F_{q^k}^{≤1}[X_1, ..., X_μ]
```

**Coefficient Ring:**
All coefficients in F_{q^k}.

**Evaluation:**
For x ∈ F_{q^k}^μ:
```
mle[f](x) ∈ F_{q^k}
```

**Application in Hachi:**
After ring switching, work with multilinear extensions over F_{q^k} instead of R_q.

---


## 10. Coordinate-Wise Special Soundness

### 10.1 Relation Definitions

**Ternary Relation:**
```
R ⊆ {0,1}* × {0,1}* × {0,1}*
```

**Components:**
- pp: Public parameters
- x: Statement
- w: Witness for x w.r.t. pp

**Notation:**
```
R(pp, x, w) = 1 iff (pp, x, w) ∈ R
R(pp, x) := {w : R(pp, x, w) = 1}
```

**Simplified Notation:**
When pp not relevant, write R(x, w).

### 10.2 Interactive Proof System

**Definition:**
Π = (S, P, V) consists of:
- **S:** Setup algorithm (generates pp)
- **P:** Prover (interactive, stateful, PPT)
- **V:** Verifier (interactive, stateful, PPT)

**Public Coin Property:**
Protocol is public coin if verifier's challenges are chosen uniformly at random, independently of prover's messages.

### 10.3 Coordinate-Wise Relation

**Vector Relation ≡_i:**
For vectors **x** := (x_1, ..., x_ℓ), **y** := (y_1, ..., y_ℓ) ∈ S^ℓ and fixed i ∈ [ℓ]:
```
**x** ≡_i **y** ⟺ x_i ≠ y_i AND ∀j ∈ [ℓ]\{i}, x_j = y_j
```

**Interpretation:**
Vectors differ only in i-th coordinate.

**Special Case (ℓ = 1):**
```
x ≡_1 y ⟺ x ≠ y
```
Just checks distinctness.

### 10.4 Special Soundness Set

**Definition:**
```
SS(S, ℓ, k) := {**x**_1, ..., **x**_K} ⊆ (S^ℓ)^K
```
where K := ℓ(k-1) + 1, satisfying:
```
∃e ∈ [K], ∃J = {j_1, ..., j_{k-1}} ⊆ [K]\{e},
∀i ∈ [ℓ], ∀j ∈ J, **x**_e ≡_i **x**_j
```

**Interpretation:**
- Central vector **x**_e
- For each coordinate i, there are k-1 other vectors differing only in coordinate i
- Total: k vectors per coordinate (including **x**_e)

**Example (ℓ = 2, k = 2):**
K = 2·(2-1) + 1 = 3
```
**x**_1 = (a, b)  [central]
**x**_2 = (a', b) [differs in coordinate 1]
**x**_3 = (a, b') [differs in coordinate 2]
```

### 10.5 Coordinate-Wise Special Soundness Definition

**Definition 3 (CWSS for Multi-Round Protocols):**

**Protocol Structure:**
- (2μ+1)-round public-coin interactive proof
- Round 2i (i ∈ [μ]): Verifier sends challenge from S_i^{ℓ_i}

**Transcript Tree:**
Set of K := ∏_{i=1}^μ (ℓ_i(k_i-1) + 1) transcripts arranged in tree structure:
- **Nodes:** Prover messages
- **Edges:** Verifier challenges
- **Depth i node:** Has ℓ_i(k_i-1) + 1 children
- **Children challenges:** Form set in SS(S_i, ℓ_i, k_i)
- **Paths:** Root to leaf = complete transcript

**CWSS Property:**
Π is (ℓ_1, ..., ℓ_μ)-coordinate-wise (k_1, ..., k_μ)-special sound if:
```
∃ polynomial-time algorithm Extract:
  Input: pp, x, transcript tree
  Output: w ∈ R(pp, x)
```

**Simplified Notation:**
If ℓ_1 = ... = ℓ_μ = 1, say protocol is (k_1, ..., k_μ)-special sound.

### 10.6 Knowledge Soundness from CWSS

**Lemma 4 (FMN24):**
Let Π be (ℓ_1, ..., ℓ_μ)-coordinate-wise (k_1, ..., k_μ)-special sound.
Assume K := ∏_{i=1}^μ (ℓ_i(k_i-1) + 1) = poly(λ).

Then Π is knowledge sound with knowledge error:
```
ε_knowledge ≤ Σ_{i=1}^μ (ℓ_i · k_i) / |S_i|^{ℓ_i}
```

**Proof Intuition:**
- Extractor rewinds prover to obtain tree of transcripts
- If prover succeeds with probability > ε_knowledge, can obtain valid tree
- Extract witness from tree using CWSS property

**Fiat-Shamir Transformation:**
Similar result holds in random oracle model after Fiat-Shamir [FMN24, Section 8].

**Application in Hachi:**
All protocols designed to satisfy CWSS, enabling knowledge soundness analysis.

---

# PART III: EXTENSION FIELD EMBEDDING THEORY

## 11. Subfield Identification (Lemma 5)

### 11.1 Statement

**Lemma 5 (Subfields of R_q):**
Let q ≡ 5 (mod 8) and k ≥ 1 divide d/2.
Let H := ⟨σ_{-1}, σ_{4k+1}⟩ ⊆ Aut(R).
Then R_q^H is a subfield of R_q isomorphic to F_{q^k}.

### 11.2 Proof

**Step 1: R_q^H is a Subset of a Field**

**Known Result [LNP22, Lemma 2.6]:**
Set of elements in R_q stable under σ_{-1} forms a field.

**Observation:**
R_q^H ⊆ {x ∈ R_q : σ_{-1}(x) = x}

**Conclusion:**
R_q^H is subset of a field.

**Step 2: R_q^H is Closed Under Operations**

**Addition:**
For a, b ∈ R_q^H and σ ∈ H:
```
σ(a + b) = σ(a) + σ(b) = a + b
```
So a + b ∈ R_q^H.

**Multiplication:**
For a, b ∈ R_q^H and σ ∈ H:
```
σ(a · b) = σ(a) · σ(b) = a · b
```
So a · b ∈ R_q^H.

**Conclusion:**
R_q^H is a subring of R_q.

**Step 3: R_q^H is a Field**

Since R_q^H is:
- Subset of a field
- Closed under multiplication
- Finite

Every non-zero element has an inverse in the ambient field, which is also in R_q^H (by closure).

**Step 4: Cardinality**

**Element Structure (Equation 7):**
Any a ∈ R_q^H has form:
```
a = a_0 + Σ_{j=1}^{k-1} a_{k-j} · (X^{d/(2k)·(k-j)} - X^{d/(2k)·(k+j)})
```

**Degrees of Freedom:**
k coefficients a_0, a_1, ..., a_{k-1} ∈ Z_q

**Cardinality:**
```
|R_q^H| = q^k
```

**Step 5: Isomorphism to F_{q^k}**

Since:
- R_q^H is a field
- |R_q^H| = q^k
- Finite fields of same order are isomorphic

We have R_q^H ≅ F_{q^k}.

### 11.3 Explicit Element Representation

**Basis Elements:**
For j = 0, ..., k-1, define:
```
e_j := X^{d/(2k)·j} - X^{d/(2k)·(2k-j)} for j ≥ 1
e_0 := 1
```

**Properties:**
1. **Fixed by σ_{-1}:** Symmetric structure
2. **Fixed by σ_{4k+1}:** Periodicity with period d/(2k)
3. **Linear Independence:** Over Z_q

**General Element:**
```
a = Σ_{j=0}^{k-1} a_j · e_j
```

**Verification of Fixed Property:**

**Under σ_{-1}:**
```
σ_{-1}(X^{d/(2k)·j} - X^{d/(2k)·(2k-j)}) = -X^{d-d/(2k)·j} - (-X^{d-d/(2k)·(2k-j)})
                                           = -X^{d/(2k)·(2k-j)} + X^{d/(2k)·j}
                                           = X^{d/(2k)·j} - X^{d/(2k)·(2k-j)}
```

**Under σ_{4k+1}:**
```
σ_{4k+1}(X^{d/(2k)·j}) = X^{(4k+1)·d/(2k)·j} = X^{2d·j + d/(2k)·j} = X^{d/(2k)·j}
```
(using X^{2d} = 1)

### 11.4 Field Operations in R_q^H

**Addition:**
```
(Σ a_j e_j) + (Σ b_j e_j) = Σ (a_j + b_j) e_j
```
Component-wise in Z_q.

**Multiplication:**
More complex due to basis element products.

**Isomorphism to F_{q^k}:**
Choose irreducible polynomial φ(Z) ∈ F_q[Z] of degree k.
Define F_{q^k} := F_q[Z]/φ(Z).

**Explicit Isomorphism:**
```
ι : F_{q^k} → R_q^H
Σ a_j Z^j ↦ Σ a_j e_j
```

**Verification:**
Need to check ι preserves addition and multiplication (omitted for brevity, follows from field structure).

---

## 12. Inner Product Preservation (Theorem 2)

### 12.1 Statement

**Theorem 2 (Inner Product as Output of Trace):**
Let k divide d/2 and H := ⟨σ_{-1}, σ_{4k+1}⟩ ⊆ Aut(R).
Consider map:
```
ψ : (R_q^H)^{d/k} → R_q
(a_0, a_1, ..., a_{d/k-1}) ↦ Σ_{i=0}^{d/(2k)-1} a_i · X^i + X^{d/2} · Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} · X^i
```

Then:
1. ψ is a bijection
2. For any **a**, **b** ∈ (R_q^H)^{d/k}:
   ```
   Tr_H(ψ(**a**) · σ_{-1}(ψ(**b**))) = (d/k) · ⟨**a**, **b**⟩
   ```

### 12.2 Proof of Bijectivity

**Injectivity:**
Suppose ψ(**a**) = 0. Need to show **a** = **0**.

**Expansion of ψ(**a**):**
Using element structure from Equation 7:
```
ψ(**a**) = Σ_{i=0}^{d/(2k)-1} [X^i · a_{i,0} + X^{d/2+i} · a_{d/(2k)+i,0}]
         + Σ_{j=1}^{k-1} Σ_{i=0}^{d/(2k)-1} a_{i,k-j} · (X^{d/(2k)·(k-j)+i} - X^{d/(2k)·(k+j)+i})
         + Σ_{j=1}^{k-1} Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i,k-j} · (X^{d/(2k)·(k-j)+d/2+i} - X^{d/(2k)·(k+j)+d/2+i})
```

**Coefficient Analysis:**

**Coefficients 0 to d/(2k)-1:**
For u ∈ {0, ..., d/(2k)-1}:
```
[X^u] ψ(**a**) = a_{u,0}
```

**Conclusion:**
If ψ(**a**) = 0, then a_{u,0} = 0 for all u ∈ {0, ..., d/(2k)-1}.

**Coefficients d/(2k) to d/2-1:**
For u ∈ {d/(2k), ..., d/2-1}:
```
[X^u] ψ(**a**) = a_{u-d/(2k),k-j} for appropriate j
```

**Inductive Argument:**
By analyzing coefficients at positions d/(2k)·m + v for m = 0, ..., 2k-1 and v = 0, ..., d/(2k)-1:
- Coefficients at d/(2k)·m + v determine a_{v,m mod k}
- If all coefficients zero, all a_{v,j} = 0

**Conclusion:**
ψ is injective.

**Surjectivity:**
Since |domain| = |codomain| = q^d and ψ injective, ψ is bijective.

### 12.3 Proof of Inner Product Preservation

**Goal:**
Show Tr_H(ψ(**a**) · σ_{-1}(ψ(**b**))) = (d/k) · ⟨**a**, **b**⟩.

**Step 1: Auxiliary Claims**

**Claim 1: Order of 4k+1**
In multiplicative group Z_{2d}^×:
```
⟨4k+1⟩ = {(4k)·α + 1 : α = 0, ..., d/(2k)-1}
```

**Proof:**
For any i:
```
((4k+1)^i mod 2d) mod 4k = (4k+1)^i mod 4k = 1
```
(since 4k divides 2d)

So ⟨4k+1⟩ ⊆ {(4k)·α + 1 : α ∈ Z}.

Order of 4k+1 is d/(2k) [LS18, Lemma 2.4], so:
```
⟨4k+1⟩ = {(4k)·α + 1 : α = 0, ..., d/(2k)-1}
```

**Claim 2: Trace of Non-Periodic Monomials**
Let i ∈ Z not divisible by d/(2k). Then:
```
Tr_H(X^i) = 0
```

**Proof:**
Since 4ki not divisible by 2d, X^{4ki} ≠ 1.

Using Claim 1:
```
Tr_H(X^i) = Σ_{h∈⟨-1,4k+1⟩} X^{h·i}
          = Σ_{h∈⟨4k+1⟩} (X^{h·i} + X^{-h·i})
          = Σ_{α=0}^{d/(2k)-1} (X^{((4k)·α+1)·i} + X^{-((4k)·α+1)·i})
          = X^i · (X^{4ki})^{d/(2k)} - 1 / (X^{4ki} - 1) + X^{-i} · (X^{-4ki})^{d/(2k)} - 1 / (X^{-4ki} - 1)
          = 0
```
(geometric series, using (X^{4ki})^{d/(2k)} = X^{2di} = 1)

**Claim 3: Trace of X^{d/2}**
```
Tr_H(X^{d/2}) = 0
```

**Proof:**
```
Tr_H(X^{d/2}) = Σ_{α=0}^{d/(2k)-1} (X^{((4k)·α+1)·d/2} + X^{-((4k)·α+1)·d/2})
              = Σ_{α=0}^{d/(2k)-1} (X^{d/2} + X^{-d/2})
              = Σ_{α=0}^{d/(2k)-1} (X^{d/2} - X^{d/2})
              = 0
```
(using X^{d/2} = -X^{-d/2})

**Step 2: Main Calculation**

**Product Structure:**
```
ψ(**a**) · σ_{-1}(ψ(**b**)) = (Σ_{i=0}^{d/(2k)-1} a_i X^i + X^{d/2} Σ_{i=0}^{d/(2k)-1} a_{d/(2k)+i} X^i)
                              · (Σ_{j=0}^{d/(2k)-1} b_j X^{-j} + X^{-d/2} Σ_{j=0}^{d/(2k)-1} b_{d/(2k)+j} X^{-j})
```

**Expansion:**
```
= Σ_{i,j=0}^{d/(2k)-1} a_i b_j X^{i-j}
+ Σ_{i,j=0}^{d/(2k)-1} a_i b_{d/(2k)+j} X^{i-j-d/2}
+ Σ_{i,j=0}^{d/(2k)-1} a_{d/(2k)+i} b_j X^{i-j+d/2}
+ Σ_{i,j=0}^{d/(2k)-1} a_{d/(2k)+i} b_{d/(2k)+j} X^{i-j}
```

**Apply Trace:**
Using Claims 2 and 3, only terms with i-j divisible by d/(2k) survive.

**Surviving Terms:**
When i = j:
```
Tr_H(a_i b_i + a_{d/(2k)+i} b_{d/(2k)+i}) = (d/k) · (a_i b_i + a_{d/(2k)+i} b_{d/(2k)+i})
```

**Summing Over i:**
```
Tr_H(ψ(**a**) · σ_{-1}(ψ(**b**))) = (d/k) · Σ_{i=0}^{d/k-1} a_i b_i = (d/k) · ⟨**a**, **b**⟩
```

**Conclusion:**
Theorem 2 proven. ∎

### 12.4 Computational Aspects

**Efficiency of ψ:**
- **Forward:** O(d) operations (polynomial evaluation)
- **Inverse:** O(d) operations (coefficient extraction)

**Efficiency of Tr_H:**
- **Naive:** O(d) operations (sum over |H| = d/k automorphisms)
- **Optimized:** Use FFT-like techniques for structured sums

**Efficiency of Inner Product:**
- **Direct:** O(d/k) operations
- **Via Trace:** O(d) operations + one ring multiplication

**Trade-off:**
Direct inner product faster, but trace formulation enables protocol design.

---

