# Requirements Document

## Introduction

Neo is a lattice-based folding scheme for CCS (Customizable Constraint Systems) that operates over small prime fields and provides plausible post-quantum security. This implementation will provide a production-ready, security-optimized cryptographic library for recursive zero-knowledge proofs.

## Glossary

- **CCS (Customizable Constraint System)**: An NP-complete relation that generalizes R1CS, Plonkish, and AIR
- **Folding Scheme**: A cryptographic primitive that reduces checking two instance-witness pairs to checking a single instance-witness pair
- **Ajtai Commitment**: A lattice-based commitment scheme based on Module-SIS assumption
- **Cyclotomic Ring**: A quotient ring F[X]/(Φ_η) where Φ_η is the η-th cyclotomic polynomial
- **Module-SIS**: Module Short Integer Solution problem, a structured lattice assumption
- **Multilinear Extension**: A unique multilinear polynomial that agrees with a vector on the Boolean hypercube
- **Sum-Check Protocol**: An interactive proof protocol for verifying polynomial evaluations
- **RoK (Reduction of Knowledge)**: A generalization of arguments of knowledge
- **IVC (Incrementally Verifiable Computation)**: A method for proving iterative computations
- **PCD (Proof-Carrying Data)**: A generalization of IVC for distributed computations

## Requirements

### Requirement 1: Core Field Arithmetic

**User Story:** As a cryptographic system developer, I want efficient arithmetic operations over small prime fields, so that I can perform computations with minimal overhead.

#### Acceptance Criteria

1. WHEN the system initializes a field with modulus q, THE System SHALL support the following prime fields:
   - Almost Goldilocks (AGL): q = (2^64 - 2^32 + 1) - 32
   - Goldilocks: q = 2^64 - 2^32 + 1
   - Mersenne-61: q = 2^61 - 1

2. WHEN performing field operations, THE System SHALL implement constant-time arithmetic to prevent timing attacks

3. WHEN computing field inversions, THE System SHALL use the extended Euclidean algorithm with constant-time guarantees

4. WHEN performing modular reduction, THE System SHALL use optimized reduction algorithms (Solinas for Goldilocks/AGL, Barrett for Mersenne-61)

5. THE System SHALL support extension fields F_q^τ where τ is the extension degree

### Requirement 2: Cyclotomic Polynomial Ring Operations

**User Story:** As a lattice cryptography implementer, I want efficient cyclotomic ring operations, so that I can perform lattice-based commitments securely.

#### Acceptance Criteria

1. WHEN initializing a cyclotomic ring R_q = F_q[X]/(Φ_η), THE System SHALL support the following configurations:
   - AGL: η = 128, Φ_η = X^64 + 1, d = 64
   - Goldilocks: η = 81, Φ_η = X^54 + X^27 + 1, d = 54
   - Mersenne-61: η = 81, Φ_η = X^54 + X^27 + 1, d = 54

2. WHEN multiplying ring elements, THE System SHALL use NTT (Number Theoretic Transform) when applicable for O(d log d) complexity

3. WHEN computing rotation matrices rot(a), THE System SHALL efficiently compute the d×d matrix representation

4. WHEN checking invertibility, THE System SHALL verify ∥cf(a)∥_∞ < b_inv according to Theorem 1

5. THE System SHALL implement coefficient mapping cf: R_q → F^d and its inverse cf^(-1)

### Requirement 3: Matrix Commitment Scheme (Ajtai-based)

**User Story:** As a proof system developer, I want a lattice-based commitment scheme with pay-per-bit costs, so that I can commit to witnesses efficiently based on their bit-width.

#### Acceptance Criteria

1. WHEN setting up the commitment scheme, THE System SHALL generate a uniformly random matrix M ← R_q^(κ×m) where κ and m are security parameters

2. WHEN committing to a matrix Z ∈ F^(d×m), THE System SHALL compute c = M·cf^(-1)(Z) with norm bound ∥Z∥_∞ < B

3. WHEN decomposing a vector z ∈ F^m, THE System SHALL apply Decomp_b to create Z = Decomp_b(z) with ∥Z∥_∞ < b^d

4. WHEN splitting a matrix Z, THE System SHALL apply split_b to create (Z_1, ..., Z_k) where Z = Σ b^(i-1)·Z_i and ∥Z_i∥_∞ < b

5. THE System SHALL provide S-homomorphic properties where S is the ring of rotation matrices

6. THE System SHALL ensure (d, m, B)-binding security under Module-SIS assumption with hardness ≥ 128 bits

### Requirement 4: Strong Sampling Sets and Challenge Generation

**User Story:** As a security engineer, I want cryptographically secure challenge generation, so that the folding scheme maintains soundness.

#### Acceptance Criteria

1. WHEN generating challenges, THE System SHALL sample from strong sampling set C ⊆ S where any two distinct elements ρ, ρ' ∈ C have (ρ - ρ') invertible

2. WHEN computing expansion factors, THE System SHALL ensure T = max(∥ρv∥_∞ / ∥v∥_∞) ≤ 2·φ(η)·max(∥ρ'∥_∞)

3. WHEN using AGL field, THE System SHALL use challenge set with coefficients in [-1, 0, 1, 2] providing |C| = 2^128 security

4. WHEN using Goldilocks field, THE System SHALL use challenge set with coefficients in [-2, -1, 0, 1, 2] providing |C| ≈ 2^125 security

5. WHEN using Mersenne-61 field, THE System SHALL use challenge set with coefficients in [-2, -1, 0, 1, 2] providing |C| ≈ 2^125 security

### Requirement 5: CCS Relation and Matrix Constraint System

**User Story:** As a constraint system designer, I want to define and verify CCS constraints, so that I can prove arbitrary computations.

#### Acceptance Criteria

1. WHEN defining a CCS structure, THE System SHALL store matrices {M_j}_(j∈[t]) ∈ F^(n×m) and constraint polynomial f ∈ F^(<u)[X_1, ..., X_t]

2. WHEN checking MCS(b, L) relation, THE System SHALL verify:
   - c = L(Z) where Z = Decomp_b(z)
   - f(M_1·z, ..., M_t·z) ∈ ZS_n (vanishes on Boolean hypercube)
   - ∥Z∥_∞ < b

3. WHEN checking ME(b, L) relation, THE System SHALL verify:
   - c = L(Z) and X = L_x(Z)
   - ∥Z∥_∞ < b
   - For all j ∈ [t], y_j = Z·M_j^T·r̂

4. THE System SHALL support witness vectors z = x || w where x is public input and w is private witness

5. THE System SHALL enforce norm bounds to maintain binding security

### Requirement 6: Sum-Check Protocol Implementation

**User Story:** As a proof system implementer, I want an efficient sum-check protocol, so that I can verify polynomial evaluations interactively.

#### Acceptance Criteria

1. WHEN running sum-check on polynomial Q(X_1, ..., X_ℓ), THE System SHALL verify Σ_(x∈{0,1}^ℓ) Q(x) = T

2. WHEN the prover sends round polynomials, THE System SHALL verify degree bounds ≤ d for each variable

3. WHEN the verifier samples challenges, THE System SHALL use cryptographically secure randomness from extension field K

4. WHEN computing soundness error, THE System SHALL ensure ε ≤ ℓd/|K| ≤ negl(λ)

5. THE System SHALL reduce the sum claim to a single evaluation claim v = Q(r) at random point r ∈ K^ℓ

### Requirement 7: CCS Reduction (Π_CCS)

**User Story:** As a folding scheme developer, I want to reduce CCS claims to evaluation claims, so that I can fold constraint systems.

#### Acceptance Criteria

1. WHEN reducing MCS(b, L) × ME(b, L)^(k-1) to ME(b, L)^k, THE System SHALL construct polynomial Q encoding:
   - CCS constraints F(X) = f(M̃_1·z_1, ..., M̃_t·z_1)
   - Norm constraints NC_i(X) for all i ∈ [k]
   - Evaluation constraints Eval_(i,j)(X) for all i ∈ [2,k], j ∈ [t]

2. WHEN sampling verifier challenges, THE System SHALL generate α ← K^(log d), β ← K^(log(dn)), γ ← K

3. WHEN running sum-check, THE System SHALL verify T = Σ_(x∈{0,1}^(log(dn))) Q(x, α, β, γ)

4. WHEN checking evaluation, THE System SHALL verify v = Q(α', r') using partial evaluations

5. THE System SHALL output k new partial evaluation claims at point r'

### Requirement 8: Random Linear Combination Reduction (Π_RLC)

**User Story:** As a cryptographic protocol designer, I want to combine multiple evaluation claims, so that I can reduce them to a single claim.

#### Acceptance Criteria

1. WHEN reducing ME(b, L)^(k+1) to ME(B, L), THE System SHALL sample challenges ρ_1, ..., ρ_(k+1) ← C

2. WHEN computing combined commitment, THE System SHALL compute c = Σ ρ_i·c_i

3. WHEN computing combined witness, THE System SHALL compute Z = Σ ρ_i·Z_i

4. WHEN computing combined evaluations, THE System SHALL compute y_j = Σ ρ_i·y_(i,j) for all j ∈ [t]

5. THE System SHALL ensure ∥Z∥_∞ ≤ (k+1)T(b-1) < B where T is expansion factor

### Requirement 9: Decomposition Reduction (Π_DEC)

**User Story:** As a norm management implementer, I want to decompose high-norm witnesses, so that I can maintain binding security.

#### Acceptance Criteria

1. WHEN reducing ME(B, L) to ME(b, L)^k, THE System SHALL compute (Z_1, ..., Z_k) ← split_b(Z)

2. WHEN the prover sends decomposed commitments, THE System SHALL compute c_i ← L(Z_i) for all i ∈ [k]

3. WHEN the prover sends decomposed evaluations, THE System SHALL compute y_(i,j) ← Z_i·M_j^T·r̂ for all i, j

4. WHEN the verifier checks consistency, THE System SHALL verify c = Σ b^(i-1)·c_i and y_j = Σ b^(i-1)·y_(i,j)

5. THE System SHALL ensure ∥Z_i∥_∞ < b for all i ∈ [k]

### Requirement 10: Folding Scheme Composition

**User Story:** As a recursive proof system architect, I want to compose reductions securely, so that I can build a complete folding scheme.

#### Acceptance Criteria

1. WHEN composing Π_DEC ◦ Π_RLC ◦ Π_CCS, THE System SHALL provide a reduction from ME(b, L)^k × MCS(b, L) to ME(b, L)^k

2. WHEN proving completeness, THE System SHALL ensure honest prover always convinces honest verifier

3. WHEN proving knowledge soundness, THE System SHALL provide an extractor E that extracts valid witnesses with probability ≥ ε(A, P*) - negl(λ)

4. WHEN checking public-coin property, THE System SHALL ensure all verifier messages are uniformly random

5. THE System SHALL support continual folding of MCS(b, L) claims without norm growth

### Requirement 11: Security Properties and Extractors

**User Story:** As a security analyst, I want formal security guarantees, so that I can trust the cryptographic construction.

#### Acceptance Criteria

1. WHEN Π_CCS is ϕ-restricted, THE System SHALL ensure output commitments (c_i)_i remain unchanged across executions

2. WHEN Π_CCS has restricted knowledge soundness, THE System SHALL provide extractor that succeeds against restricted adversaries

3. WHEN Π_RLC has ϕ-relaxed knowledge soundness, THE System SHALL provide extractor that outputs witnesses in ME(q/2, L)^(k+1)

4. WHEN checking relaxed binding, THE System SHALL ensure no adversary can find (c, Δ_1, Δ_2, Z_1, Z_2) satisfying collision conditions with probability > negl(λ)

5. THE System SHALL use coordinate-wise extraction (Theorem 6) for efficient witness extraction

### Requirement 12: Multilinear Polynomial Operations

**User Story:** As a polynomial evaluation system developer, I want efficient multilinear polynomial operations, so that I can perform sum-check efficiently.

#### Acceptance Criteria

1. WHEN computing multilinear extension ṽ of vector v ∈ F^n, THE System SHALL compute ṽ(x) = Σ v_y·eq(x, y) for x ∈ {0,1}^(log n)

2. WHEN evaluating at point r ∈ F^ℓ, THE System SHALL compute ṽ(r) = ⟨v, r̂⟩ in O(2^ℓ) operations

3. WHEN checking vanishing polynomials, THE System SHALL verify F(x) = 0 for all x ∈ {0,1}^ℓ using Lemma 10

4. WHEN computing eq polynomial, THE System SHALL compute eq(x, y) = Π (x_i·y_i + (1-x_i)·(1-y_i))

5. THE System SHALL support partial evaluations M̃(X_[1,log d], r) for matrix multilinear extensions

### Requirement 13: Parameter Selection and Security Analysis

**User Story:** As a cryptographic parameter selector, I want secure parameter choices, so that the system achieves 128-bit security.

#### Acceptance Criteria

1. WHEN using AGL field, THE System SHALL set κ=13, m=2^26, b=2, k=11, B=2^11, T=128

2. WHEN using Goldilocks field, THE System SHALL set κ=16, m=2^24, b=2, k=12, B=2^12, T=216

3. WHEN using Mersenne-61 field, THE System SHALL set κ=16, m=2^22, b=2, k=12, B=2^12, T=216

4. WHEN estimating Module-SIS hardness, THE System SHALL ensure MSIS_(m,8TB)^(∞,κ,q) ≥ 127 bits security

5. THE System SHALL verify (k+1)T(b-1) < B to prevent norm overflow

### Requirement 14: IVC/PCD Construction

**User Story:** As a recursive proof system user, I want to build IVC/PCD schemes, so that I can prove iterative and distributed computations.

#### Acceptance Criteria

1. WHEN constructing IVC proof, THE System SHALL maintain a pair of instance-witness pairs (one in MCS, one in ME)

2. WHEN folding a new computation step, THE System SHALL apply the folding scheme to accumulate the new instance

3. WHEN compressing IVC proof, THE System SHALL optionally apply Spartan+FRI to produce a succinct proof

4. WHEN verifying IVC proof, THE System SHALL check the final folded instance-witness pair

5. THE System SHALL support unbounded recursion depth without trusted setup

### Requirement 15: Constant-Time and Side-Channel Resistance

**User Story:** As a security-conscious implementer, I want side-channel resistant code, so that the implementation is secure against timing attacks.

#### Acceptance Criteria

1. WHEN performing secret-dependent operations, THE System SHALL use constant-time implementations

2. WHEN comparing secret values, THE System SHALL use constant-time comparison functions

3. WHEN performing conditional operations on secrets, THE System SHALL use constant-time select operations

4. WHEN performing modular arithmetic, THE System SHALL avoid secret-dependent branches

5. THE System SHALL use memory access patterns independent of secret data

### Requirement 16: Memory Safety and Error Handling

**User Story:** As a production system developer, I want robust error handling, so that the system fails safely and provides clear diagnostics.

#### Acceptance Criteria

1. WHEN encountering invalid parameters, THE System SHALL return descriptive error types

2. WHEN detecting security violations, THE System SHALL abort computation and clear sensitive data

3. WHEN allocating memory, THE System SHALL use Rust's ownership system to prevent memory leaks

4. WHEN performing cryptographic operations, THE System SHALL validate all inputs before processing

5. THE System SHALL provide clear error messages for debugging without leaking sensitive information

### Requirement 17: Serialization and Interoperability

**User Story:** As a system integrator, I want standard serialization formats, so that I can integrate with other systems.

#### Acceptance Criteria

1. WHEN serializing field elements, THE System SHALL use little-endian byte representation

2. WHEN serializing commitments, THE System SHALL use canonical encoding of ring elements

3. WHEN serializing proofs, THE System SHALL include version information for forward compatibility

4. WHEN deserializing data, THE System SHALL validate all constraints and reject malformed inputs

5. THE System SHALL support both binary and hex string representations for debugging

### Requirement 18: Performance Optimization

**User Story:** As a performance engineer, I want optimized implementations, so that the system achieves practical performance.

#### Acceptance Criteria

1. WHEN performing MSMs (Multi-Scalar Multiplications), THE System SHALL use Pippenger's algorithm for large inputs

2. WHEN performing NTT, THE System SHALL use cache-friendly butterfly operations

3. WHEN performing matrix operations, THE System SHALL use SIMD instructions when available

4. WHEN performing polynomial operations, THE System SHALL minimize allocations through buffer reuse

5. THE System SHALL provide batch verification APIs to amortize costs across multiple proofs
