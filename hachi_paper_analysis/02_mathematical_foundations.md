# Mathematical Foundations - Detailed Requirements

## 1. Notation and Basic Structures

### 1.1 Security Parameter
- **λ**: Security parameter (typically 128 bits)
- All cryptographic guarantees must hold with probability ≥ 1 - negl(λ)
- negl(λ) denotes negligible function in λ

### 1.2 Ring Structures

#### Cyclotomic Ring R
```
R := Z[X]/(X^d + 1)
```
**Requirements**:
- d := 2^α must be a power of two
- α is the ring dimension parameter
- Elements are polynomials of degree < d with integer coefficients
- Multiplication is modulo (X^d + 1)

#### Quotient Ring R_q
```
R_q := R/(q) = Z_q[X]/(X^d + 1)
```
**Requirements**:
- q is an odd prime with q ≡ 5 (mod 8)
- This congruence ensures certain algebraic properties
- Elements have coefficients in Z_q = {0, 1, ..., q-1}

#### Extension Field F_{q^k}
```
F_{q^k} := finite field of order q^k
```
**Requirements**:
- k ≥ 1 is the extension degree
- For security: k = λ/log(q) to ensure exponential size
- Can be represented as F_q[Z]/φ(Z) where φ is irreducible of degree k

### 1.3 Norms and Bounds

#### Infinity Norm for Integers
```
||w||_∞ = |w mod± q|
```
**Requirements**:
- w mod± q is unique element in range [-q/2, q/2]
- Represents centered reduction modulo q

#### Infinity Norm for Ring Elements
```
For w = w_0 + w_1·X + ... + w_{d-1}·X^{d-1} ∈ R:
||w||_∞ = max_j ||w_j||_∞
```

#### ℓ_p Norm for Ring Elements
```
||w||_p = (||w_0||_∞^p + ... + ||w_{d-1}||_∞^p)^{1/p}
```

#### Vector Norms
```
For w = (w_1, ..., w_m) ∈ R^m:
||w||_∞ = max_j ||w_j||_∞
||w||_p = (||w_1||_p^p + ... + ||w_m||_p^p)^{1/p}
```

#### Short Element Set
```
S_β := {w ∈ R : coefficients in [⌈-β/2⌉, ⌈β/2⌉ - 1]}
```

### 1.4 Gadget Matrices

#### Base-b Gadget Matrix
```
G_{b,n} := I_n ⊗ [1, b, b^2, ..., b^{δ-1}] ∈ R_q^{n×nδ}
```
**Requirements**:
- b > 1 is decomposition base
- δ := ⌈log_b(q)⌉ is expansion factor
- I_n is n×n identity matrix
- ⊗ denotes Kronecker product

#### Gadget Inverse Function
```
G_{b,n}^{-1}: R_q^n → R_q^{nδ}
```
**Requirements**:
- Decomposes each entry with respect to base b
- For any t ∈ R_q^n: G_{b,n} · G_{b,n}^{-1}(t) = t
- G_{b,n}^{-1}(t) has coefficients in [⌈-b/2⌉, ⌈b/2⌉ - 1]

## 2. Galois Automorphisms

### 2.1 Definition
```
For i ∈ Z_{2d}^×:
σ_i: R → R defined by X ↦ X^i
```
**Requirements**:
- Z_{2d}^× is multiplicative group of units modulo 2d
- σ_i is ring homomorphism
- Preserves addition and multiplication

### 2.2 Galois Group
```
Aut(R) := {σ_i : i ∈ Z_{2d}^×}
```

### 2.3 Fixed Subring
```
For subgroup H ⊆ Aut(R):
R_q^H := {x ∈ R_q : ∀σ ∈ H, σ(x) = x}
```
**Requirements**:
- Elements fixed by all automorphisms in H
- Forms a subring of R_q

### 2.4 Trace Map
```
Tr_H: R_q → R_q^H
Tr_H(a) := ∑_{σ ∈ H} σ(a)
```
**Requirements**:
- Additively homomorphic
- Maps to fixed subring
- For a ∈ R_q^H: Tr_H(a) = |H| · a

## 3. Multilinear Extensions

### 3.1 Equality Polynomial
```
For i, x ∈ {0,1}^μ:
eq(i, x) := ∏_{j=1}^μ [(1-i_j)·(1-x_j) + i_j·x_j]
```
**Requirements**:
- eq(i, x) = 1 if i = x
- eq(i, x) = 0 if i ≠ x
- Multilinear in x

### 3.2 Multilinear Extension over Rings
```
For function f: {0,1}^μ → R:
mle[f](x) := ∑_{i∈{0,1}^μ} f(i) · eq(i, x)
```
**Requirements**:
- Unique multilinear polynomial agreeing with f on {0,1}^μ
- For x ∈ {0,1}^μ: mle[f](x) = f(x)
- Degree at most 1 in each variable

### 3.3 Vector Multilinear Extension
```
For vector f = (f_i)_{i∈{0,1}^μ} ∈ R^{2^μ}:
f̃ := mle[f] where f: {0,1}^μ → R, i ↦ f_i
```

## 4. Hardness Assumptions

### 4.1 Module-SIS Problem
```
MSIS_{q,d,n,m,β} Problem:
Given: A ← R_q^{n×m} (uniformly random)
Find: z ∈ R_q^m such that:
  - Az = 0 (mod q)
  - 0 < ||z||_∞ ≤ β
```
**Requirements**:
- Computationally hard for appropriate parameters
- Foundation for binding property
- Post-quantum secure assumption

### 4.2 Parameter Selection for Security
**Requirements**:
- n·d ≥ 2^10 for 128-bit security
- β must be small enough that finding short solutions is hard
- Use Lattice Estimator to verify concrete security

## 5. Invertibility Properties

### 5.1 Short Elements are Invertible (Lyubashevsky-Seiler)
```
For q ≡ 5 (mod 8) prime and f ∈ R_q:
If 0 < ||f||_∞ < (1/2√2)·q^{1/2} OR 0 < ||f|| < q^{1/2}
Then f has inverse in R_q
```
**Requirements**:
- Critical for knowledge extraction
- Ensures challenge differences are invertible
- Used in special soundness proofs

### 5.2 Invertible Elements Set
```
R_q^× := {f ∈ R_q : ∃g ∈ R_q, f·g = 1}
```

## 6. Norm Inequalities

### 6.1 Micciancio Inequality
```
For any f, g ∈ R:
||f·g||_∞ ≤ ||f||_1 · ||g||_∞
```
**Requirements**:
- Used for bounding products
- Critical for soundness analysis
- Applies to ring multiplication

## 7. Coefficient Representation

### 7.1 Coefficient Vector
```
For y = ∑_{i=0}^{d-1} y_i·X^i ∈ R_q:
cf(y) := (y_0, ..., y_{d-1}) ∈ F_q^d
```
**Requirements**:
- Bijection between R_q and F_q^d
- Extends naturally to vectors
- Used for ring switching

## 8. Tensor Product Operations

### 8.1 Kronecker Product
```
For A ∈ R^{m×n}, B ∈ R^{p×q}:
A ⊗ B ∈ R^{mp×nq}
```
**Requirements**:
- Used in gadget matrix construction
- Mixed product property: (A ⊗ B)(C ⊗ D) = (AC) ⊗ (BD)

### 8.2 Vector Tensor Product
```
For a ∈ R^m, b ∈ R^n:
a ⊗ b = (a_1·b, a_2·b, ..., a_m·b) ∈ R^{mn}
```

## 9. Polynomial Evaluation Representation

### 9.1 Multilinear Polynomial Evaluation
```
For f ∈ R_q^{≤1}[X_1,...,X_ℓ] with coefficients (f_ι)_{ι∈{0,1}^ℓ}:
f(x_1,...,x_ℓ) = ∑_{ι∈{0,1}^ℓ} f_ι · x_1^{ι_1} · ... · x_ℓ^{ι_ℓ}
```

### 9.2 Split Representation
```
For ℓ = m + r:
f(x_1,...,x_ℓ) = b^T · [matrix of f_{i||j}] · a
```
Where:
- a^T := (x_{r+1}^{j_1} · ... · x_ℓ^{j_m})_{j∈{0,1}^m}
- b^T := (x_1^{i_1} · ... · x_r^{i_r})_{i∈{0,1}^r}

**Requirements**:
- Enables split-and-fold protocol
- Reduces to quadratic equation
- Foundation for commitment scheme
