# LatticeFold+: Complete Requirements Document

## Executive Summary

LatticeFold+ is a lattice-based folding protocol that improves upon LatticeFold in three key areas:
1. **5x faster prover** - Eliminates L·log₂(B) bit-decomposed commitments
2. **Simpler verification circuit** - No bit-decomposed commitments to hash
3. **Shorter proofs** - Reduces from O_λ(κd log B + d log n) to O_λ(κd + log n) bits

## Glossary

### Core Algebraic Structures
- **Cyclotomic Ring R**: Z[X]/(X^d + 1) where d is power of 2
- **Residue Ring Rq**: Zq[X]/(X^d + 1) for prime q > 2
- **Balanced Representation**: Zq = {-⌊q/2⌋, ..., ⌊q/2⌋}
- **NTT Isomorphism**: Rq ≅ F_q^(d/e) when q ≡ 1 + 2^e (mod 4e)

### Monomial Structures
- **Infinite Monomial Set M'**: {0, 1, X, X², X³, ...} ⊆ Zq[X]
- **d-Monomial Set M**: {0, 1, X, ..., X^(d-1)} ⊆ M'
- **Monomial Embedding**: exp(a) = sgn(a)·X^|a| for a ∈ (-d, d)
- **EXP Function**: EXP(a) = {exp(a)} if a ≠ 0, else {0, 1, X^(d/2)}

### Range Proof Components
- **Table Polynomial ψ**: Σ_{i∈[1,d/2)} i·(X^(-i) + X^i) ∈ Rq
- **Constant Term ct(f)**: f₀ for f = Σᵢ fᵢX^i
- **Coefficient Vector cf(f)**: (f₀, ..., f_{d-1}) ∈ Z_q^d

### Commitment Schemes
- **Linear Commitment com(·)**: Ajtai commitment com(a) = Aa for A ∈ Rq^(κ×n)
- **Double Commitment dcom(·)**: com(split(com(M))) for matrix M
- **Split Function**: Injective map Rq^(κ×m) → (-d', d')^n via gadget decomposition
- **Pow Function**: Inverse of split, pow(split(D)) = D

### Norms and Bounds
- **ℓ∞-Norm**: ||f||∞ = max_{i∈[d]} |fᵢ| for f = Σᵢ fᵢX^i
- **Operator Norm**: ||a||_op = sup_{y∈R} ||a·y||∞ / ||y||∞
- **Norm Bound B**: (d')^k for some k ∈ ℕ

### Challenge Sets
- **Folding Challenge Set S̄**: Strong sampling set with small operator norm
- **Sumcheck Challenge Set C**: Zq or extension field F_q^t
- **Module MC**: C × C for parallel sumcheck
- **Module Mq**: Rq × Rq

### Relations
- **R_{lin,B}**: Generalized committed linear relation with norm bound B
- **R_{rg,B}**: Range check relation for witnesses with ||f||∞ < B
- **R_{com}**: Commitment transformation output relation
- **R_{m,in}/R_{m,out}**: Monomial set check input/output relations

### Gadget Decomposition
- **Gadget Vector g_{b,k}**: (1, b, ..., b^(k-1)) ∈ Z^k
- **Gadget Matrix G_{b,k}**: I_m ⊗ g_{b,k} ∈ Z^(mk×m)
- **Decomposition G^(-1)**: Maps M to M' where M = M'G and ||M'||∞ < b

### Multilinear Extensions
- **Tensor Product tensor(r)**: ⊗_{i∈[k]} (1-rᵢ, rᵢ) ∈ R̄^(2^k)
- **Equality Polynomial eq(b,x)**: ∏_{i∈[k]} ((1-bᵢ)(1-xᵢ) + bᵢxᵢ)
- **MLE f̃**: Σ_{b∈{0,1}^k} f(b)·eq(b,x)

## PART 1: MATHEMATICAL FOUNDATIONS

### Requirement LFP-1: Cyclotomic Ring Operations

**User Story:** As a cryptographic engineer, I want to implement cyclotomic ring arithmetic, so that I can perform polynomial operations modulo X^d + 1.

#### Acceptance Criteria

1. THE System SHALL define R = Z[X]/(X^d + 1) with d = 2^k for k ≥ 6
2. THE System SHALL define Rq = Zq[X]/(X^d + 1) for prime q > 2
3. THE System SHALL use balanced representation Zq = {-⌊q/2⌋, ..., ⌊q/2⌋}
4. THE System SHALL implement polynomial addition in Rq with O(d) complexity
5. THE System SHALL implement polynomial multiplication in Rq with O(d log d) complexity using NTT
6. THE System SHALL handle reduction X^d = -1 automatically
7. THE System SHALL support NTT when q ≡ 1 + 2^e (mod 4e) for e | d
8. THE System SHALL compute coefficient vectors cf(f) = (f₀, ..., f_{d-1})
9. THE System SHALL extract constant terms ct(f) = f₀
10. THE System SHALL verify q > 2d' for security
11. THE System SHALL implement modular reduction mod q in balanced form
12. THE System SHALL support polynomial evaluation at arbitrary points
13. THE System SHALL implement polynomial composition a(X²)
14. THE System SHALL compute polynomial squares a(X)²
15. THE System SHALL provide unit tests for ring operations

### Requirement LFP-2: Monomial Set Characterization

**User Story:** As a range proof developer, I want to verify monomial membership, so that I can ensure committed values are monomials.

#### Mathematical Background

**Lemma 2.1 (Monomial Characterization):**
For q > 2 prime and a ∈ Zq[X]:
```
a(X²) = a(X)² ⟺ a ∈ M'
```

**Proof Structure:**
- Forward: If a = X^k, then a(X²) = X^(2k) = (X^k)² = a(X)²
- Backward: If a(X²) = a(X)² with a = Σᵢ aᵢX^(dᵢ), n > 1 terms:
  - Highest degree: a_n²X^(2d_n)
  - Second highest: 2a_n·a_{n-1}X^(d_n+d_{n-1})
  - Since 2d_n > d_n + d_{n-1} > 2d_{n-1}, no term at degree d_n + d_{n-1}
  - Therefore 2a_n·a_{n-1} = 0
  - Since q > 2, either a_n = 0 or a_{n-1} = 0, contradiction

#### Acceptance Criteria

1. THE System SHALL define M' = {0, 1, X, X², X³, ...} ⊆ Zq[X]
2. THE System SHALL define M = {0, 1, X, ..., X^(d-1)} ⊆ M'
3. THE System SHALL implement monomial test: a(X²) = a(X)²
4. THE System SHALL verify Lemma 2.1 for all test cases
5. THE System SHALL compute a(X²) by substituting X² for X
6. THE System SHALL compute a(X)² using polynomial multiplication
7. THE System SHALL handle edge case a = 0
8. THE System SHALL handle edge case a = 1
9. THE System SHALL reject non-monomials with probability ≥ 1 - 2d/|C|
10. THE System SHALL embed M into Rq via natural map
11. THE System SHALL verify X^i · X^j = X^(i+j) mod (X^d + 1)
12. THE System SHALL handle negative exponents: X^(-i) = -X^(d-i)
13. THE System SHALL provide efficient monomial multiplication
14. THE System SHALL document why Lemma 2.1 fails over Rq (Remark 2.1)
15. THE System SHALL test monomial property preservation under embedding


### Requirement LFP-3: Table Polynomial and Range Extraction

**User Story:** As a range proof implementer, I want to use the table polynomial to extract integer values from monomials, so that I can verify range constraints algebraically.

#### Mathematical Background

**Table Polynomial Definition:**
```
ψ = Σ_{i∈[1,d')} i · (X^(-i) + X^i) ∈ Rq where d' = d/2
```

**Expanded Form:**
```
ψ = 1·(-X^(d-1) + X) + 2·(-X^(d-2) + X²) + ... + (d'-1)·(-X^(d-d'+1) + X^(d'-1))
```

**Lemma 2.2 (Range Extraction):**
For a ∈ Zq and d' = d/2:

*Forward:* If a ∈ (-d', d'), then ∀b ∈ EXP(a): ct(b · ψ) = a

*Backward:* If ∃b ∈ M: ct(b · ψ) = a, then a ∈ (-d', d') and b ∈ EXP(a)

**Proof Sketch:**
- If a ≠ 0, b = exp(a) = sgn(a)·X^|a|:
  - b · ψ = sgn(a)·X^|a| · Σᵢ i·(X^(-i) + X^i)
  - Constant term from X^|a| · X^(-|a|) = 1 or X^|a| · X^(d-|a|) = -1
  - Gives ct(b · ψ) = sgn(a)·|a| = a
- If a = 0, then b ∈ {0, 1, X^(d/2)} all give ct(b · ψ) = 0
- Conversely, b · ψ rotates/flips ψ coefficients, constant term stays in (-d', d')

#### Acceptance Criteria

1. THE System SHALL compute ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i)
2. THE System SHALL compute X^(-i) = -X^(d-i) for all i ∈ [1, d')
3. THE System SHALL expand ψ with all d-1 non-zero terms
4. THE System SHALL define sgn(a) ∈ {-1, 0, 1} for a ∈ Zq
5. THE System SHALL define exp(a) = sgn(a)·X^|a| ∈ M
6. THE System SHALL define EXP(a) = {exp(a)} if a ≠ 0
7. THE System SHALL define EXP(0) = {0, 1, X^(d/2)}
8. THE System SHALL verify ct(b · ψ) = a for all b ∈ EXP(a), a ∈ (-d', d')
9. THE System SHALL verify Lemma 2.2 forward direction
10. THE System SHALL verify Lemma 2.2 backward direction
11. THE System SHALL compute b · ψ efficiently using monomial properties
12. THE System SHALL extract constant term ct(b · ψ)
13. THE System SHALL handle edge case a = 0 with three valid b values
14. THE System SHALL handle edge case a = ±(d'-1)
15. THE System SHALL support generalized table lookup (Remark 2.2)
16. THE System SHALL allow custom tables T ⊆ Zq with |T| ≤ d, 0 ∈ T
17. THE System SHALL compute ψ_T = Σ_{i∈[1,d']} (-Tᵢ)·X^i + Σ_{i∈[1,d')} T_{i+d'}·X^(-i)
18. THE System SHALL verify range extraction for random test vectors
19. THE System SHALL document rotation and sign-flip properties
20. THE System SHALL provide performance benchmarks for ψ computation

### Requirement LFP-4: Norms and Operator Norms

**User Story:** As a security analyst, I want to compute and verify norms, so that I can ensure witness vectors remain within security bounds.

#### Mathematical Background

**ℓ∞-Norm Definition:**
For f = Σᵢ fᵢX^i ∈ R: ||f||∞ = max_{i∈[d]} |fᵢ|

**Operator Norm Definition:**
For a ∈ R: ||a||_op = sup_{y∈R} ||a·y||∞ / ||y||∞

**Lemma 2.3:** For a ∈ M and b ∈ R: ||a · b||∞ ≤ ||b||∞

**Lemma 2.4 (Invertibility):** 
For d, e power-of-twos with e | d, q ≡ 1 + 2^e (mod 4e) prime:
Every non-zero y ∈ Rq with ||y||∞ < q^(1/e)/√e is invertible

**Lemma 2.5:** For all u ∈ R: ||u||_op ≤ d · ||u||∞

#### Acceptance Criteria

1. THE System SHALL compute ||f||∞ = max_{i∈[d]} |fᵢ| for f ∈ R
2. THE System SHALL compute ||F||∞ = max_{i,j} ||F_{i,j}||∞ for F ∈ R^(n×m)
3. THE System SHALL lift Rq elements to R for norm computation
4. THE System SHALL compute operator norm ||a||_op via supremum
5. THE System SHALL compute ||S||_op = max_{a∈S} ||a||_op for sets S
6. THE System SHALL verify Lemma 2.3: monomial multiplication preserves norm
7. THE System SHALL verify Lemma 2.4: invertibility criterion
8. THE System SHALL verify Lemma 2.5: operator norm bound
9. THE System SHALL check ||y||∞ < q^(1/e)/√e for invertibility
10. THE System SHALL handle norm computation for vectors and matrices
11. THE System SHALL verify norm bounds before commitment operations
12. THE System SHALL track norm growth through folding operations
13. THE System SHALL ensure accumulated witness norm stays below B
14. THE System SHALL provide norm checking utilities
15. THE System SHALL document norm preservation properties


### Requirement LFP-5: Strong Sampling Sets

**User Story:** As a protocol designer, I want to define strong sampling sets, so that I can ensure challenge invertibility for soundness.

#### Mathematical Background

**Strong Sampling Set:** S ⊆ Rq where difference of any two distinct elements is invertible

**Examples:**
- Zq ⊆ Rq is strong sampling (differences invertible in Rq)
- Small coefficient sets are strong sampling (by Lemma 2.4)

**Properties:**
- Used for folding challenges (S̄)
- Used for sumcheck challenges (C)
- Enables Schwartz-Zippel lemma over rings

#### Acceptance Criteria

1. THE System SHALL define strong sampling set S ⊆ Rq
2. THE System SHALL verify ∀s₁, s₂ ∈ S, s₁ ≠ s₂: s₁ - s₂ is invertible
3. THE System SHALL use Zq as default strong sampling set when q is prime
4. THE System SHALL verify small coefficient sets are strong sampling
5. THE System SHALL compute S - S = {s₁ - s₂ : s₁, s₂ ∈ S, s₁ ≠ s₂}
6. THE System SHALL ensure ||S||_op is small for folding challenge set S̄
7. THE System SHALL set |S̄| = |C| ≥ 2^λ for security parameter λ
8. THE System SHALL use C = Zq when q ≥ 2^λ
9. THE System SHALL use C = F_q^t (extension field) when q < 2^λ
10. THE System SHALL define MC = C × C for parallel sumcheck
11. THE System SHALL define Mq = Rq × Rq
12. THE System SHALL verify invertibility using Lemma 2.4
13. THE System SHALL sample challenges uniformly from S
14. THE System SHALL document strong sampling property importance
15. THE System SHALL provide tests for challenge invertibility

### Requirement LFP-6: Gadget Matrix Decomposition

**User Story:** As a commitment scheme implementer, I want to decompose high-norm matrices into low-norm matrices, so that I can maintain binding properties.

#### Mathematical Background

**Gadget Vector:** g_{b,k} = (1, b, ..., b^(k-1)) ∈ Z^k

**Gadget Matrix:** G_{b,k} = I_m ⊗ g_{b,k} ∈ Z^(mk×m)

**Decomposition:** For M ∈ R^(n×m) with ||M||∞ < b̂ = b^k:
- Decompose to M' ∈ R^(n×mk) with ||M'||∞ < b
- Such that M = M' G_{b,k}

**Algorithm:** For each entry x ∈ (-b̂, b̂):
1. Compute base-b decomposition (x₀, ..., x_{k-1}) of |x|
2. If x < 0, flip signs: xᵢ ← -xᵢ for all i
3. Result: x = Σᵢ xᵢb^i with |xᵢ| < b

#### Acceptance Criteria

1. THE System SHALL define g_{b,k} = (1, b, ..., b^(k-1))
2. THE System SHALL compute G_{b,k} = I_m ⊗ g_{b,k}
3. THE System SHALL implement G^(-1)_{b,k}: R^(n×m) → R^(n×mk)
4. THE System SHALL verify M = G^(-1)_{b,k}(M) · G_{b,k}
5. THE System SHALL ensure ||G^(-1)_{b,k}(M)||∞ < b when ||M||∞ < b^k
6. THE System SHALL decompose each entry independently
7. THE System SHALL compute base-b representation
8. THE System SHALL handle negative entries by sign flipping
9. THE System SHALL verify decomposition correctness
10. THE System SHALL use d' = d/2 as typical base
11. THE System SHALL set k = ⌈log_{d'}(q)⌉ for typical parameters
12. THE System SHALL flatten matrices to vectors when needed
13. THE System SHALL support tensor product notation I_m ⊗ g_{b,k}
14. THE System SHALL provide efficient decomposition algorithm
15. THE System SHALL document decomposition properties

## PART 2: MULTILINEAR EXTENSIONS AND SUMCHECK

### Requirement LFP-7: Multilinear Extensions over Rings

**User Story:** As a sumcheck protocol implementer, I want to compute multilinear extensions over rings, so that I can reduce polynomial evaluations.

#### Mathematical Background

**Definition 2.1 (MLE over Rings):**
For R̄ ring with 0, 1 and f: {0,1}^k → R̄:
```
f̃(x) = Σ_{b∈{0,1}^k} f(b) · eq(b, x)
```
where eq(b, x) = ∏_{i∈[k]} ((1-bᵢ)(1-xᵢ) + bᵢxᵢ)

**Tensor Product:**
```
tensor(r) = ⊗_{i∈[k]} (1-rᵢ, rᵢ) ∈ R̄^(2^k)
```

**Key Property:** f̃(r) = ⟨f, tensor(r)⟩

**Generalization:** For M = R̄ × R̄ and m = (r^(0), r^(1)) ∈ M^k:
```
tensor(m) = (tensor(r^(0)), tensor(r^(1)))
```

#### Acceptance Criteria

1. THE System SHALL compute eq(b, x) = ∏_{i∈[k]} ((1-bᵢ)(1-xᵢ) + bᵢxᵢ)
2. THE System SHALL compute f̃(x) = Σ_{b∈{0,1}^k} f(b) · eq(b, x)
3. THE System SHALL compute tensor(r) = ⊗_{i∈[k]} (1-rᵢ, rᵢ)
4. THE System SHALL verify f̃(r) = ⟨f, tensor(r)⟩
5. THE System SHALL support MLE over arbitrary rings R̄
6. THE System SHALL define table f = (f(⟨0⟩_k), ..., f(⟨2^k-1⟩_k))
7. THE System SHALL use binary representation ⟨b⟩_k for indexing
8. THE System SHALL compute [a]_k = Σᵢ aᵢ2^i for binary vector a
9. THE System SHALL support module tensor products
10. THE System SHALL compute tensor(m) for m ∈ M^k where M = R̄ × R̄
11. THE System SHALL evaluate f̃ at pairs of points
12. THE System SHALL optimize tensor product computation
13. THE System SHALL cache intermediate tensor values
14. THE System SHALL provide efficient MLE evaluation
15. THE System SHALL document mixed-product property


### Requirement LFP-8: Sumcheck Protocol over Rings

**User Story:** As a verifier, I want to check polynomial sums over boolean hypercube using sumcheck, so that I can verify computations efficiently.

#### Mathematical Background

**Lemma 2.6 (Generalized Schwartz-Zippel):**
For nonzero f ∈ R̄_{≤d}[X₁, ..., X_k] and strong sampling set C:
```
Pr_{r←C^k}[f(r) = 0] ≤ dk/|C|
```

**Lemma 2.7 (Generalized Sumcheck):**
For f ∈ R̄_{≤ℓ}[X₁, ..., X_k] with individual degree ≤ ℓ, C ⊆ R̄ strong sampling, s ∈ R̄:

Reduces checking s = Σ_{b∈{0,1}^k} f(b) to checking f̃(r) = v for r ← C^k

**Properties:**
- Perfect completeness
- Prover time: Õ(2^k ℓ)
- Verifier time: O(kℓ)
- Proof size: O(kℓ)
- Soundness error: kℓ/|C|

**Remark 2.4 (Boosting):** Parallel repetition r times reduces error to (kℓ/|C|)^r

**Remark 2.5 (Batching):** s claims over same domain → single claim over larger domain

**Remark 2.6 (Compression):** k claims → 1 claim via random linear combination

#### Acceptance Criteria

1. THE System SHALL implement sumcheck protocol over rings
2. THE System SHALL verify Σ_{b∈{0,1}^k} f(b) = s
3. THE System SHALL reduce to evaluation claim f̃(r) = v
4. THE System SHALL sample r ← C^k from strong sampling set
5. THE System SHALL achieve soundness error kℓ/|C|
6. THE System SHALL support parallel repetition for boosting soundness
7. THE System SHALL set MC = C × C for 2-way parallel execution
8. THE System SHALL batch multiple sumcheck claims
9. THE System SHALL view d claims over Zq as 1 claim over Rq
10. THE System SHALL view s claims over Rq as 1 claim over Rq[Y]/(Y^s+1)
11. THE System SHALL compress k claims via random linear combination
12. THE System SHALL add soundness error k/|F| for compression
13. THE System SHALL use extension field F' when |F| is small
14. THE System SHALL achieve prover time Õ(2^k ℓ) for sum-of-products
15. THE System SHALL achieve verifier time O(kℓ)
16. THE System SHALL produce proof of size O(kℓ)
17. THE System SHALL verify perfect completeness
18. THE System SHALL implement round-by-round protocol
19. THE System SHALL send univariate polynomial each round
20. THE System SHALL verify polynomial degree bounds

### Requirement LFP-9: Module-Based Ajtai Commitments

**User Story:** As a commitment scheme user, I want to commit to vectors using Ajtai commitments, so that I can achieve post-quantum security.

#### Mathematical Background

**Definition 2.2 (Module SIS):**
MSIS^∞_{q,κ,m,β_SIS} holds if for all PPT adversary A:
```
Pr[A ← Rq^(κ×m), x ← A(A): (Ax = 0 mod q) ∧ 0 < ||x||∞ < β_SIS] = negl(λ)
```

**Definition 2.3 (Relaxed Binding):**
A ← Rq^(κ×m) is (b, S)-relaxed binding if for all PPT adversary A:
```
Pr[Az₁s₁^(-1) = Az₂s₂^(-1) ∧ z₁s₁^(-1) ≠ z₂s₂^(-1) : 
   0 < ||z₁||∞, ||z₂||∞ < b ∧ s₁, s₂ ∈ S] = negl(λ)
```

**Reduction:** (b, S)-relaxed binding reduces to MSIS^∞_{q,κ,m,B} with B = 2b||S||_op

#### Acceptance Criteria

1. THE System SHALL implement Ajtai commitment com(a) = Aa
2. THE System SHALL sample A ← Rq^(κ×m) uniformly
3. THE System SHALL commit to vectors a ∈ Rq^n
4. THE System SHALL produce commitments cm ∈ Rq^κ
5. THE System SHALL base security on MSIS^∞_{q,κ,m,β_SIS}
6. THE System SHALL verify ||x||∞ < β_SIS for SIS hardness
7. THE System SHALL implement (b, S)-relaxed binding
8. THE System SHALL verify ||z₁||∞, ||z₂||∞ < b for valid openings
9. THE System SHALL check s₁, s₂ ∈ S for valid openings
10. THE System SHALL reduce relaxed binding to MSIS with B = 2b||S||_op
11. THE System SHALL compute x = s₂z₁ - s₁z₂ over R (after lifting)
12. THE System SHALL verify Ax = 0 mod q for collision
13. THE System SHALL ensure ||x||∞ < B
14. THE System SHALL set S = S̄ - S̄ for folding challenge set S̄
15. THE System SHALL choose parameters for 128-bit security
16. THE System SHALL document parameter selection rationale
17. THE System SHALL provide security analysis
18. THE System SHALL implement efficient matrix-vector multiplication
19. THE System SHALL use NTT for fast commitment computation
20. THE System SHALL verify commitment binding property

## PART 3: GENERALIZED COMMITTED LINEAR RELATIONS

### Requirement LFP-10: R_{lin,B} Relation Definition

**User Story:** As a folding scheme designer, I want to define the generalized committed linear relation, so that I can fold R1CS/CCS instances.

#### Mathematical Background

**Definition 3.1 (R_{lin,B}):**
For q > 2 prime, n, κ, n_lin ∈ ℕ, com: Rq^n → Rq^κ:

Index: i = (com(·), (M^(i) ∈ Rq^(n×n))_{i∈[n_lin]})

Instance: x = (cm_f, r ∈ MC^(log n), v ∈ Mq^(n_lin))

Witness: w = f ∈ Rq^n

Relation: (i, x, w) ∈ R_{lin,B} iff:
```
(||f||∞ < B) ∧ (cm_f = com(f)) ∧ ∀i ∈ [n_lin]: ⟨M^(i)·f, tensor(r)⟩ = vᵢ
```

where MC = C × C, Mq = Rq × Rq

**R1CS Reduction:**
For R1CS with A, B, C ∈ Rq^(n×m), derive M^(1), ..., M^(4) ∈ Rq^(n×n):
```
M^(1) = I_n
M^(2) = A · G^⊤_{B,ℓ̂}
M^(3) = B · G^⊤_{B,ℓ̂}
M^(4) = C · G^⊤_{B,ℓ̂}
```
where ℓ̂ = ⌈log_B(q)⌉

#### Acceptance Criteria

1. THE System SHALL define R_{lin,B} with norm bound B
2. THE System SHALL use commitment scheme com: Rq^n → Rq^κ
3. THE System SHALL define index i = (com(·), (M^(i))_{i∈[n_lin]})
4. THE System SHALL define instance x = (cm_f, r, v)
5. THE System SHALL define witness w = f ∈ Rq^n
6. THE System SHALL verify ||f||∞ < B
7. THE System SHALL verify cm_f = com(f)
8. THE System SHALL verify ∀i: ⟨M^(i)·f, tensor(r)⟩ = vᵢ
9. THE System SHALL use MC = C × C for challenge space
10. THE System SHALL use Mq = Rq × Rq for evaluation space
11. THE System SHALL support n_lin = 4 for R1CS
12. THE System SHALL reduce R1CS to R_{lin,B} via sumcheck
13. THE System SHALL compute M^(1) = I_n
14. THE System SHALL compute M^(2) = A · G^⊤_{B,ℓ̂}
15. THE System SHALL compute M^(3) = B · G^⊤_{B,ℓ̂}
16. THE System SHALL compute M^(4) = C · G^⊤_{B,ℓ̂}
17. THE System SHALL set ℓ̂ = ⌈log_B(q)⌉
18. THE System SHALL support CCS with higher degree constraints
19. THE System SHALL linearize via sumcheck protocol
20. THE System SHALL document reduction from R1CS to R_{lin,B}


## PART 4: REDUCTION OF KNOWLEDGE TOOLBOX

### Requirement LFP-11: Reduction of Knowledge Framework

**User Story:** As a protocol composer, I want to use reduction of knowledge framework, so that I can build secure folding schemes compositionally.

#### Mathematical Background

**Definition 2.4 (Reduction of Knowledge):**
Π from R₁ to R₂ consists of:
- G(1^λ) → i: Generate index
- P(i, x₁, w₁) → (x₂, w₂): Prover algorithm
- V(i, x₁) → x₂: Verifier algorithm

Notation: ⟨P(w₁), V⟩[i, x₁] → (x₂, w₂)

**Definition 2.5 (Perfect Completeness):**
```
Pr[(i, x₁, w₁) ∉ R₁ ∨ (i, x₂, w₂) ∈ R₂] = 1
```

**Definition 2.6 (Knowledge Soundness):**
∃ knowledge-error κ(·) and PPT extractor Ext such that:
```
Pr[(i, ⟨P*, V⟩[i, x₁]) ∈ R₂] - Pr[(i, x₁, Ext^{P*}(i, x₁, st)) ∈ R₁] ≤ κ(λ)
```

**Definition 2.7 (Public Reducibility):**
∃ deterministic poly-time f such that:
```
Pr[f(i, x₁, tr) = x₂] = 1
```

**Theorem 2.1 (Sequential Composition):**
If Π₁: R₁ → R₂ and Π₂: R₂ → R₃, then Π₂ ∘ Π₁: R₁ → R₃

#### Acceptance Criteria

1. THE System SHALL implement RoK framework
2. THE System SHALL define G(1^λ) → i for index generation
3. THE System SHALL define P(i, x₁, w₁) → (x₂, w₂) for prover
4. THE System SHALL define V(i, x₁) → x₂ for verifier
5. THE System SHALL verify perfect completeness
6. THE System SHALL implement knowledge soundness with extractor
7. THE System SHALL compute knowledge error κ(λ)
8. THE System SHALL implement public reducibility function f
9. THE System SHALL support sequential composition
10. THE System SHALL verify Π₂ ∘ Π₁ is RoK when Π₁, Π₂ are RoK
11. THE System SHALL handle transcript tr in public reducibility
12. THE System SHALL ensure ⊥ ∉ L(R₂)
13. THE System SHALL verify extractor runs in expected poly-time
14. THE System SHALL document RoK properties
15. THE System SHALL provide composition utilities

### Requirement LFP-12: Linear and Double Commitments

**User Story:** As a commitment user, I want to use both linear and double commitments, so that I can optimize proof size.

#### Mathematical Background

**Linear Commitment:**
```
com(a) = Aa for A ∈ Rq^(κ×n), a ∈ Rq^n
com(M) = A × M for M ∈ Rq^(n×m)
```

**Valid Opening:**
a ∈ Rq^n is (b, S)-valid opening of cm_a if:
- cm_a = com(a)
- a = a's for some a' ∈ Rq^n, s ∈ S with ||a'||∞ < b

**Opening Relation:**
```
R_open = {(x = cm_f ∈ Rq^κ, w = f ∈ Rq^n): f is valid opening of cm_f}
```

**Double Commitment:**
For m ∈ Rq^n: dcom(m) = com(m)
For M ∈ Rq^(n×m): dcom(M) = com(split(com(M)))

**Split Function (Construction 4.1):**
1. M' = G^(-1)_{d',ℓ}(com(M)) ∈ Rq^(κ×mℓ)
2. M'' = flat(M') ∈ Rq^(κmℓ)
3. τ'_M = flat(cf(M'')) ∈ (-d', d')^(κmℓd)
4. Pad τ'_M to τ_M ∈ (-d', d')^n
5. Return split(com(M)) = τ_M

**Pow Function:**
pow: (-d', d')^n → Rq^(κ×m) such that pow(split(D)) = D

**Double Opening Relation:**
```
R_{dopen,m} = {(x = C_M ∈ Rq^κ, w = (τ ∈ (-d', d')^n, M ∈ Rq^(n×m))):
               M valid opening of pow(τ) = com(M) ∧
               τ valid opening of C_M}
```

**Lemma 4.1:** If com(·) is binding, then dcom(·) is binding

#### Acceptance Criteria

1. THE System SHALL implement com(a) = Aa
2. THE System SHALL implement com(M) = A × M
3. THE System SHALL define (b, S)-valid opening
4. THE System SHALL verify cm_a = com(a)
5. THE System SHALL verify a = a's with ||a'||∞ < b, s ∈ S
6. THE System SHALL define R_open relation
7. THE System SHALL implement dcom(m) = com(m) for vectors
8. THE System SHALL implement dcom(M) = com(split(com(M))) for matrices
9. THE System SHALL implement split function (Construction 4.1)
10. THE System SHALL compute gadget decomposition G^(-1)_{d',ℓ}
11. THE System SHALL flatten matrix to vector
12. THE System SHALL extract coefficient matrix
13. THE System SHALL pad to length n
14. THE System SHALL verify split is injective
15. THE System SHALL implement pow function
16. THE System SHALL verify pow(split(D)) = D
17. THE System SHALL note pow is not injective (Remark 4.1)
18. THE System SHALL define R_{dopen,m} relation
19. THE System SHALL verify double commitment binding (Lemma 4.1)
20. THE System SHALL prove binding via collision reduction
21. THE System SHALL handle three collision cases
22. THE System SHALL assume κmdℓ ≤ n for double commitments
23. THE System SHALL document double commitment advantages
24. THE System SHALL provide efficient split/pow implementations
25. THE System SHALL optimize for typical parameters

### Requirement LFP-13: Monomial Set Check Protocol Π_mon

**User Story:** As a range proof builder, I want to check monomial set membership, so that I can verify committed matrices contain only monomials.

#### Mathematical Background

**Input Relation R_{m,in}:**
```
x = C_M ∈ Rq^κ, w = M ∈ Rq^(n×m)
M_{i,j} ∈ M for all (i,j) ∈ [n] × [m]
(C_M, (split(com(M)), M)) ∈ R_{dopen,m}
```

**Output Relation R_{m,out}:**
```
x = (C_M ∈ Rq^κ, r ∈ C^(log n), e ∈ Rq^m), w = M ∈ Rq^(n×m)
M^⊤ tensor(r) = e ∧ (C_M, (split(com(M)), M)) ∈ R_{dopen,m}
```

**Corollary 4.1:**
For a ∈ M ⊆ Rq, β ∈ F_q^u: ev_a(β)² = ev_a(β²)
For a ∉ M: Pr[ev_a(β)² = ev_a(β²)] < 2d/|F_q^u|

**Construction 4.2 (Π_mon):**
1. V → P: c ← C^(log n), β ← C
2. P ↔ V: Degree-3 sumcheck for ∀j ∈ [m]:
   ```
   Σ_{i∈[n]} eq(c, ⟨i⟩) · (m̃^(j)(⟨i⟩)² - m̃'^(j)(⟨i⟩)) = 0
   ```
   where m^(j) = (ev_{M_{0,j}}(β), ..., ev_{M_{n-1,j}}(β))
         m'^(j) = (ev_{M_{0,j}}(β²), ..., ev_{M_{n-1,j}}(β²))
3. P → V: {e_j = M̃_{*,j}(r)}_{j∈[m]}
4. V: Check eq(c,r) · Σ_j α^j · (ev_{e_j}(β)² - ev_{e_j}(β²)) = v

**Lemma 4.2:** Π_mon is RoK from R_{m,in} to R_{m,out}

**Lemma 4.3:** Π_mon is perfectly complete

**Lemma 4.4:** Knowledge error ε_{mon,m} = (2d + m + 4 log n)/|C| + ε_bind

#### Acceptance Criteria

1. THE System SHALL define R_{m,in} for monomial matrices
2. THE System SHALL define R_{m,out} for evaluation claims
3. THE System SHALL implement Corollary 4.1 test
4. THE System SHALL verify ev_a(β)² = ev_a(β²) for a ∈ M
5. THE System SHALL reject non-monomials with prob ≥ 1 - 2d/|F_q^u|
6. THE System SHALL send challenges c ← C^(log n), β ← C
7. THE System SHALL batch m sumcheck claims via Remark 2.6
8. THE System SHALL run degree-3 sumcheck
9. THE System SHALL compute m^(j) = evaluations at β
10. THE System SHALL compute m'^(j) = evaluations at β²
11. THE System SHALL verify sumcheck claim for each column
12. THE System SHALL send multilinear evaluations {e_j}_{j∈[m]}
13. THE System SHALL verify final check with eq(c,r)
14. THE System SHALL achieve perfect completeness
15. THE System SHALL achieve knowledge soundness with error ε_{mon,m}
16. THE System SHALL support batching multiple matrices (Remark 4.2)
17. THE System SHALL optimize for monomial commitment (Remark 4.3)
18. THE System SHALL compute com(M) in O(nκm) Rq-additions
19. THE System SHALL compute evaluations in O(n) Zq-multiplications
20. THE System SHALL run sumcheck over C (not Rq) for efficiency
21. THE System SHALL use parallel repetitions for small |C|
22. THE System SHALL document efficiency advantages
23. THE System SHALL provide performance benchmarks
24. THE System SHALL verify extractor correctness
25. THE System SHALL handle bad events B₁, B₂, B₃ in soundness proof

