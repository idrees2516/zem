# Requirements Document: Neo Lattice zkVM Complete System

## Introduction

This document specifies the comprehensive requirements for the Neo Lattice zkVM - a complete post-quantum secure zero-knowledge virtual machine synthesizing cutting-edge cryptographic primitives from multiple research papers. The system integrates:

- **Neo/LatticeFold+**: Lattice-based folding schemes for CCS over small fields with pay-per-bit commitments
- **SALSAA**: Sumcheck-Aided Lattice-based Succinct Arguments with linear-time provers
- **Symphony**: Hash-free high-arity folding via CP-SNARK compilation
- **HyperWolf**: Lattice polynomial commitments with standard soundness
- **Quasar**: Sublinear accumulation schemes for multi-instance IVC
- **Linear-Time Permcheck**: Efficient permutation and lookup arguments
- **AGM-Secure IVC**: Unbounded-depth IVC with algebraic group model security
- **Distributed SNARK**: Parallel proving via folding schemes
- **Streaming IVsC**: Incremental verification for streaming computations

The implementation targets post-quantum security under standard lattice assumptions (Ring-SIS, Ring-LWE) while achieving concrete efficiency competitive with pairing-based systems.

## Glossary

### Core Cryptographic Concepts

- **zkVM (Zero-Knowledge Virtual Machine)**: System proving correct program execution while hiding the execution trace
- **IVC (Incrementally Verifiable Computation)**: Cryptographic primitive for sequential computations with efficient verification
- **IVsC (Incrementally Verifiable Streaming Computation)**: IVC extension for streaming data with constant proof size
- **PCD (Proof-Carrying Data)**: Generalization of IVC to directed acyclic graph computations
- **SNARK (Succinct Non-interactive ARgument of Knowledge)**: Proof system with short proofs and fast verification
- **Folding Scheme**: Technique compressing multiple constraint instances into one, deferring verification
- **Accumulation Scheme**: Primitive for efficient accumulation of predicate instances into running accumulator
- **CP-SNARK (Commit-and-Prove SNARK)**: SNARK proving statements about committed values

### Lattice-Specific Concepts

- **R_q**: Cyclotomic polynomial ring Z_q[X]/(X^φ + 1) where φ is power of 2
- **SIS (Short Integer Solution)**: Lattice problem: find short s such that A·s = 0 mod q
- **Ring-SIS/Ring-LWE**: Structured variants over polynomial rings for efficiency
- **Ajtai Commitment**: Lattice-based commitment C = A·s where ||s|| ≤ β
- **Norm Bound (β)**: Maximum allowed Euclidean norm for witness vectors
- **Modulus (q)**: Prime defining the ring R_q = Z_q[X]/(X^φ + 1)
- **CRT (Chinese Remainder Theorem)**: Ring decomposition R_q ≅ (F_{q^e})^{φ/e}
- **NTT (Number Theoretic Transform)**: Fast polynomial multiplication via FFT over finite fields

### Protocol Components

- **Sum-Check Protocol**: Interactive proof for polynomial sums over Boolean hypercube
- **LDE (Low-Degree Extension)**: Multilinear extension of witness vectors
- **RoK (Reduction of Knowledge)**: Protocol reducing one relation to another preserving knowledge
- **PCS (Polynomial Commitment Scheme)**: Scheme for committing to polynomials with evaluation proofs
- **PIOP (Polynomial Interactive Oracle Proof)**: Interactive proof with polynomial oracles
- **Fiat-Shamir Transform**: Converting interactive protocols to non-interactive via hashing

### Constraint Systems

- **CCS (Customizable Constraint System)**: Generalized constraint system with multilinear structure
- **R1CS (Rank-1 Constraint System)**: Constraint system Az ⊙ Bz = Cz
- **Plonkish/HyperPlonk**: Constraint system with selector polynomials and custom gates

### Mathematical Notation

- **||·||₂**: Euclidean (ℓ₂) norm
- **||·||∞**: Infinity norm - maximum absolute coefficient
- **⊙**: Hadamard (element-wise) product
- **⊗**: Tensor (Kronecker) product
- **eq̃(X,Y)**: Multilinear equality polynomial
- **f̃(X)**: Multilinear extension of vector f
- **[n]**: Set {0, 1, ..., n-1}
- **B^n**: Boolean hypercube {0,1}^n
- **negl(λ)**: Negligible function in security parameter λ

---

## Requirements

### Requirement 1: Cyclotomic Ring Arithmetic Foundation

**User Story:** As a cryptographic engineer, I want efficient cyclotomic ring arithmetic, so that all lattice-based protocols have a solid algebraic foundation.

#### Acceptance Criteria

1. WHEN initializing ring R_q = Z_q[X]/(X^φ + 1), THE System SHALL support φ ∈ {64, 128, 256, 512, 1024, 2048, 4096} and prime modulus q with q ≡ 1 (mod 2φ).

2. WHEN performing ring multiplication, THE System SHALL use NTT with O(φ log φ) complexity and precomputed twiddle factors.

3. WHEN computing CRT decomposition R_q ≅ (F_{q^e})^{φ/e}, THE System SHALL support splitting degree e ∈ {1, 2, 4, 8} for incomplete NTT.

4. WHEN computing canonical embedding, THE System SHALL implement σ: R → C^φ and canonical norm ||x||_{σ,2}² = Trace(⟨x, x̄⟩).

5. WHEN performing balanced representation, THE System SHALL represent coefficients in range [-(q-1)/2, (q-1)/2] for optimal norm bounds.

6. WHEN computing Trace_{K/Q}(x), THE System SHALL implement trace function for norm verification protocols.

### Requirement 2: Ajtai Commitment Scheme

**User Story:** As a commitment scheme implementer, I want secure and efficient Ajtai commitments, so that witnesses can be committed with provable binding under Ring-SIS.

#### Acceptance Criteria

1. WHEN generating commitment key, THE System SHALL sample A ∈ R_q^{n×m} uniformly at random with n = O(λ/log q) rows.

2. WHEN committing to witness w ∈ R_q^m with ||w|| ≤ β, THE System SHALL compute C = A·w ∈ R_q^n.

3. WHEN verifying commitment binding, THE System SHALL ensure finding w' ≠ w with A·w' = A·w requires solving Ring-SIS with parameters (n, m, q, β).

4. WHEN implementing pay-per-bit commitments, THE System SHALL achieve commitment cost O(k·log q + log n) for k non-zero entries.

5. WHEN supporting homomorphic operations, THE System SHALL enable C(w₁) + C(w₂) = C(w₁ + w₂) for linear combinations.

6. WHEN tracking norm bounds, THE System SHALL maintain ||w|| ≤ β invariant across all commitment operations.

### Requirement 3: HyperWolf Polynomial Commitment Scheme

**User Story:** As a PCS implementer, I want HyperWolf lattice polynomial commitments with standard soundness, so that polynomial evaluations can be proven efficiently.

#### Acceptance Criteria

1. WHEN committing to multilinear polynomial p ∈ F^{(<2)}_μ, THE System SHALL use leveled commitment structure with O(2^μ) prover time.

2. WHEN opening at evaluation point r ∈ F^μ, THE System SHALL generate proof using guarded inner product argument.

3. WHEN verifying evaluation p(r) = v, THE System SHALL perform O(μ) field operations plus O(1) lattice operations.

4. WHEN achieving standard soundness, THE System SHALL provide ℓ₂ norm bounds without slack accumulation.

5. WHEN batching multiple openings, THE System SHALL use random linear combination reducing k openings to O(1) proof size.

6. WHEN supporting challenge space, THE System SHALL use subtractive or large challenge sets for folding compatibility.

### Requirement 4: SALSAA Sum-Check Protocol

**User Story:** As a sum-check implementer, I want SALSAA's linear-time sum-check, so that norm verification runs in O(m) time.

#### Acceptance Criteria

1. WHEN proving Σ_{z∈[d]^μ} u^T·CRT(LDE[W](z) ⊙ LDE[W̄](z̄)) = t, THE System SHALL use dynamic programming for O(m) prover complexity.

2. WHEN computing round polynomial g_j(X), THE System SHALL achieve degree at most 2(d-1) requiring (2d-1) field elements per round.

3. WHEN verifying sum-check, THE System SHALL perform O(μ·d) field operations plus O(r) ring operations.

4. WHEN batching norm checks for r columns, THE System SHALL use random linear combination reducing to single sum-check.

5. WHEN achieving communication complexity, THE System SHALL transmit (2d-1)·μ·e·log q + 2r·log|R_q| bits total.

6. WHEN reducing to LDE evaluation claims, THE System SHALL output claims LDE[W](r) = s₀ and LDE[W̄](r̄) = s₁.

7. WHEN implementing norm-check RoK Π_norm, THE System SHALL reduce norm relation Ξ_norm to sumcheck relation Ξ_sum using identity ∥x∥²_{σ,2} = Trace(⟨x,x⟩).

8. WHEN defining LDE relation Ξ_lde-⊗, THE System SHALL extend Ξ_lin to check LDE[M_i·W](r_i) = s_i mod q for structured matrices M_i.

9. WHEN implementing sumcheck relation Ξ_sum, THE System SHALL verify Σ_{z∈[d]^μ}(LDE[W] ⊙ LDE[W̄])(z) = t mod q ∈ R_q^r.

10. WHEN reducing Ξ_sum to Ξ_lde-⊗, THE System SHALL achieve knowledge-error κ = (2μ(d-1)+rφ/e-1)/q^e.

11. WHEN implementing R1CS RoK Π_lin-r1cs, THE System SHALL reduce R1CS relation to evaluation claims over LDE of witness and constraint matrices.

12. WHEN implementing improved batching Π*_batch, THE System SHALL express bottom rows Fw = y as sumcheck claims Σ_{j∈[m]} LDE[f_i](z)·LDE[w](z) = y_i mod q.

### Requirement 5: Neo Folding Scheme for CCS

**User Story:** As a folding scheme implementer, I want Neo's lattice-based folding for CCS, so that multiple constraint instances can be efficiently compressed.

#### Acceptance Criteria

1. WHEN folding ℓ CCS instances, THE System SHALL construct union polynomial w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X).

2. WHEN computing folded witness, THE System SHALL evaluate w̃(X) = w̃_∪(τ,X) where τ is verifier challenge.

3. WHEN bounding folded norm, THE System SHALL ensure ||w'|| ≤ ℓ·||γ||·max_i||w_i|| where ||γ|| ≤ 2ℓ for subtractive challenges.

4. WHEN supporting high-arity folding (ℓ ≤ 2^10), THE System SHALL use two-layer architecture with intermediate decomposition.

5. WHEN applying base decomposition Π_decomp, THE System SHALL produce k = O(log(ℓ·β)) vectors with ||w'_j|| ≤ b.

6. WHEN verifying folding, THE System SHALL perform O(log ℓ) field operations and O(1) commitment operations.

7. WHEN implementing pay-per-bit commitments, THE System SHALL achieve commitment cost O(k·log q + log n) for k non-zero entries where committing n bits is 64× cheaper than n 64-bit values.

8. WHEN implementing matrix commitment scheme, THE System SHALL transform vector of field elements to matrix and commit using Ajtai scheme over cyclotomic ring.

9. WHEN folding evaluation claims {(C_i, r, y_i)}_{i∈[β]}, THE System SHALL provide linear homomorphism for combining β ≥ 2 commitments with claimed multilinear evaluations.

10. WHEN implementing CCS reduction Π_CCS, THE System SHALL reduce CCS satisfiability to evaluation claims via single sum-check invocation over extension field.

11. WHEN implementing RLC reduction Π_RLC, THE System SHALL combine multiple evaluation claims using random linear combination with challenge from extension field.

12. WHEN supporting small prime fields, THE System SHALL work with Goldilocks (2^64 - 2^32 + 1), M61 (2^61 - 1), and "Almost Goldilocks" (2^64 - 2^32 + 1 - 32) primes.

### Requirement 6: LatticeFold+ Optimizations

**User Story:** As a performance engineer, I want LatticeFold+ optimizations, so that folding achieves faster, simpler, and shorter proofs.

#### Acceptance Criteria

1. WHEN using monomial basis, THE System SHALL represent polynomials in monomial form for efficient evaluation.

2. WHEN applying gadget decomposition, THE System SHALL decompose large coefficients into base-b digits with b ∈ {2, 4, 8, 16}.

3. WHEN implementing table polynomials, THE System SHALL precompute lookup tables for range checks.

4. WHEN using tensor ring structure, THE System SHALL exploit R_q ≅ R_{q_1} ⊗ R_{q_2} for parallel computation.

5. WHEN achieving proof size, THE System SHALL generate O(λ log² m / log λ) bits for m-sized witness.

6. WHEN achieving prover time, THE System SHALL execute O(m) ring operations for linear-time proving.

### Requirement 7: Symphony Hash-Free Recursion

**User Story:** As a recursion optimizer, I want Symphony's hash-free CP-SNARK compilation, so that recursive verification avoids Fiat-Shamir overhead.

#### Acceptance Criteria

1. WHEN implementing CP-SNARK interface, THE System SHALL provide Prove(C, w, stmt) → π where C = Commit(w).

2. WHEN verifying recursively, THE System SHALL NOT compute hash functions, instead verifying commitment relations directly.

3. WHEN instantiating with lattices, THE System SHALL use SALSAA or LaBRADOR variants for post-quantum security.

4. WHEN achieving proof size, THE System SHALL generate O(λ²) field elements independent of statement size.

5. WHEN verifying CP-SNARK, THE System SHALL perform O(λ) ring operations.

6. WHEN composing with folding, THE System SHALL enable hash-free high-arity folding for IVC.

7. WHEN implementing high-arity folding for ℓ_np statements, THE System SHALL compress via commitment, sumcheck reduction, and random linear combination steps.

8. WHEN proving range bounds, THE System SHALL use monomial embedding with table polynomial t(X) := Σ_{i∈[1,d/2)} i·(X^i + X^{-i}).

9. WHEN performing random projection, THE System SHALL use structured J := I_{n/ℓ_h} ⊗ J' for sublinear verifier with J' ∈ {0,±1}^{λ_pj × ℓ_h}.

10. WHEN compiling folding to SNARK via CM[Π_cm, Π_fold], THE System SHALL send commitments c_{fs,i} = Π_cm.Commit(m_i) instead of messages m_i.

11. WHEN implementing two-layer folding, THE System SHALL split reduced statement (x_o, w_o) to multiple uniform NP statements for second layer.

12. WHEN achieving streaming prover, THE System SHALL require space O(n) with 2 + log log(n) passes over input data.

### Requirement 8: Quasar Sublinear Accumulation

**User Story:** As an IVC designer, I want Quasar-style sublinear accumulation, so that recursive overhead is minimized.

#### Acceptance Criteria

1. WHEN accumulating ℓ instances, THE System SHALL achieve O(log ℓ) verifier complexity in random oracle queries and O(1) group operations.

2. WHEN performing CRC operations, THE System SHALL execute O(1) commitment random linear combinations per step.

3. WHEN bounding total CRC across N IVC steps, THE System SHALL achieve O(√N) total operations.

4. WHEN implementing multi-cast reduction IOR_cast, THE System SHALL reduce ℓ instances to 1 committed instance with O(1) commitments.

5. WHEN implementing 2-to-1 reduction IOR_fold, THE System SHALL reduce 2 accumulators to 1 with O(1) verifier work.

6. WHEN batching oracle openings, THE System SHALL produce proofs sublinear in polynomial length.

7. WHEN computing union polynomial w̃_∪(Y,X), THE System SHALL construct Σ_{i∈[ℓ]} eq̃_{i-1}(Y)·w̃^{(i)}(X) for all witness vectors.

8. WHEN verifying partial evaluation, THE System SHALL check w̃_∪(τ, r_x) = w̃(r_x) at random evaluation point r_x ∈ F^{log n}.

9. WHEN reducing constraint F(x,w)=0 to sum-check, THE System SHALL compute G(Y) := F(x̃(Y), w̃(Y))·eq̃(Y, r_y) with Σ_{y∈B^{log ℓ}} G(y) = 0.

10. WHEN outputting reduced relation R_acc, THE System SHALL produce (x, τ, r_x, e) where e = G_{log ℓ}(τ_{log ℓ})·eq̃^{-1}(τ, r_y).

11. WHEN implementing oracle batching IOR_batch, THE System SHALL satisfy succinctness property with proof sublinear in polynomial length.

12. WHEN instantiating with linear-code-based PCS, THE System SHALL achieve plausible post-quantum security with O(λ/log(1/ρ)·(log n + log ℓ)) random oracle queries.

### Requirement 9: Linear-Time Permutation Check

**User Story:** As a permutation check implementer, I want linear-time permcheck, so that wire identity verification is efficient.

#### Acceptance Criteria

1. WHEN proving f(x) = g(σ(x)) for all x ∈ B^μ, THE System SHALL reduce to sum-check with O(n) prover time.

2. WHEN using BiPerm (2-way split), THE System SHALL achieve O(log n / |F|) soundness error with sparse PCS.

3. WHEN using MulPerm (multi-way split), THE System SHALL achieve n·Õ(√log n) prover time with any PCS.

4. WHEN supporting prover-provided permutations, THE System SHALL additionally prove σ is valid permutation.

5. WHEN implementing bucketing algorithm, THE System SHALL reduce second sum-check cost to near-linear.

6. WHEN achieving soundness, THE System SHALL have error polylog(n)/|F| for both variants.

### Requirement 10: Lookup Table Arguments

**User Story:** As a lookup argument implementer, I want efficient lookup proofs, so that table lookups replace expensive constraint computations.

#### Acceptance Criteria

1. WHEN proving w ⊆ t for witness w and table t, THE System SHALL use Logup lemma: Σ_{i∈[n]} 1/(x + w_i) = Σ_{i∈[N]} m_i/(x + t_i).

2. WHEN using Lasso for structured tables, THE System SHALL achieve O(N + n) prover time without preprocessing.

3. WHEN using decomposable tables, THE System SHALL reduce large table lookups to smaller subtable lookups.

4. WHEN supporting indexed lookups, THE System SHALL prove w_k = t_{i_k} with committed indices.

5. WHEN supporting vector lookups, THE System SHALL handle k-tuple table entries efficiently.

6. WHEN achieving soundness, THE System SHALL have error polylog(n+T)/|F| for table size T.

### Requirement 11: Memory Checking Arguments (Twist/Spice)

**User Story:** As a memory argument implementer, I want efficient read/write memory checking, so that zkVM memory operations are verified.

#### Acceptance Criteria

1. WHEN proving read operations, THE System SHALL verify mem[addr] = value at each read.

2. WHEN proving write operations, THE System SHALL verify memory state transitions correctly.

3. WHEN using one-hot addressing, THE System SHALL represent addresses as indicator vectors.

4. WHEN using increment checking, THE System SHALL verify timestamp monotonicity for memory consistency.

5. WHEN batching memory operations, THE System SHALL use random linear combination for efficiency.

6. WHEN achieving prover complexity, THE System SHALL execute O(n) operations for n memory accesses.

### Requirement 12: AGM-Secure IVC Construction

**User Story:** As an IVC implementer, I want AGM-secure unbounded-depth IVC, so that arbitrary-length computations can be proven.

#### Acceptance Criteria

1. WHEN proving IVC step, THE System SHALL implement P^θ(ipk, z₀, z_i, (w_i, z_{i-1}, π_{i-1})) → π_i.

2. WHEN verifying IVC proof, THE System SHALL implement V^θ(ivk, z₀, z_out, π_out) → {0,1}.

3. WHEN achieving unbounded-depth soundness, THE System SHALL extract valid witness chain for any poly-bounded depth.

4. WHEN using oracle forcing, THE System SHALL query θ(g) for group elements g not in verifier transcript.

5. WHEN extracting witnesses, THE System SHALL use single group representation Γ for all iterations (avoiding exponential blowup).

6. WHEN achieving succinctness, THE System SHALL have verifier time poly(λ + |x|) independent of depth.

### Requirement 13: Distributed SNARK via Folding

**User Story:** As a distributed proving implementer, I want parallel SNARK generation, so that large circuits can be proven across multiple machines.

#### Acceptance Criteria

1. WHEN distributing across M provers, THE System SHALL assign subcircuit C_i of size T = N/M to prover P_i.

2. WHEN executing distributed SumFold, THE System SHALL achieve O(T) computation per worker prover.

3. WHEN aggregating at coordinator, THE System SHALL perform O(M) group operations.

4. WHEN achieving communication complexity, THE System SHALL transmit O(N) field elements total.

5. WHEN achieving proof size, THE System SHALL generate O(log N) field elements + O(1) group elements.

6. WHEN verifying distributed proof, THE System SHALL perform O(log N) field operations + O(M) MSM.

### Requirement 14: Streaming Proof Generation (IVsC)

**User Story:** As a streaming application developer, I want streaming proof generation, so that unbounded data streams can be proven with bounded resources.

#### Acceptance Criteria

1. WHEN processing new data chunk x_u, THE System SHALL update proof Π_t to Π_{t+1} processing only x_u.

2. WHEN maintaining proof size, THE System SHALL keep |Π_t| = O(λ²) independent of stream length T.

3. WHEN bounding prover memory, THE System SHALL operate in O(√T) space.

4. WHEN implementing rate-1 seBARG, THE System SHALL use LWE/SIS assumptions for somewhere extractability.

5. WHEN supporting streaming PCS, THE System SHALL enable O(√n) space polynomial evaluation.

6. WHEN extracting from stream, THE System SHALL recover any position x_i with probability ≥ 1 - negl(λ).

### Requirement 15: Zero-Knowledge Property

**User Story:** As a privacy engineer, I want zero-knowledge proofs, so that witnesses remain hidden.

#### Acceptance Criteria

1. WHEN generating proof, THE System SHALL reveal no information about witness beyond statement validity.

2. WHEN simulating proofs, THE System SHALL provide PPT simulator S with {S(stmt)} ≈_c {Prove(stmt, w)}.

3. WHEN using designated-verifier ZK, THE System SHALL integrate LPZK from Ring-LWE.

4. WHEN streaming with ZK, THE System SHALL maintain zero-knowledge across intermediate proofs Π_1, ..., Π_t.

5. WHEN using encrypted digests, THE System SHALL support verification against encrypted data via RDM-PKE.

6. WHEN achieving statistical ZK, THE System SHALL have simulator indistinguishable with probability 1 - negl(λ).

### Requirement 16: CCS/R1CS Constraint System Support

**User Story:** As a constraint system designer, I want support for multiple constraint formats, so that circuits can use optimal representations.

#### Acceptance Criteria

1. WHEN supporting R1CS, THE System SHALL verify Az ⊙ Bz = Cz for sparse matrices A, B, C.

2. WHEN supporting CCS, THE System SHALL verify Σ_i c_i · (Π_{j∈S_i} M_j · z) = 0 for multilinear structure.

3. WHEN supporting Plonkish, THE System SHALL verify f(q(X), w(X)) = 0 with selector polynomials.

4. WHEN batching constraints, THE System SHALL use random linear combination for efficiency.

5. WHEN mapping zkVM traces, THE System SHALL efficiently convert execution traces to constraint witnesses.

6. WHEN handling public inputs, THE System SHALL correctly incorporate public values in constraint system.

7. WHEN proving product constraints a ⊙ b = c, THE System SHALL use sum-check with g(x) := ã(x)·b̃(x) - c̃(x) and eq̃(r,x) randomization.

8. WHEN verifying wiring constraints, THE System SHALL check that values a_i and b_i are derived from c according to circuit structure.

9. WHEN using multilinear extensions, THE System SHALL compute ã(r) = Σ_{x∈{0,1}^n} a(x)·eq̃(r,x) via Lagrange interpolation.

10. WHEN handling Hadamard products, THE System SHALL compute (a ⊙ b)_i := a_i · b_i for all i = 1,...,N efficiently.

### Requirement 16.1: Sum-Check Protocol Foundations

**User Story:** As a SNARK implementer, I want comprehensive sum-check protocol support, so that I can build the fastest possible provers following the "Sum-check Is All You Need" principles.

#### Acceptance Criteria

1. WHEN proving sum Σ_{x∈{0,1}^n} g(x) = C_1, THE System SHALL reduce verifier work from 2^n evaluations to single evaluation at random point r ∈ F^n.

2. WHEN generating sum-check proof, THE System SHALL produce proof of size O(dn) field elements where d is degree per variable and n is number of variables.

3. WHEN implementing prover, THE System SHALL achieve work that halves each round with total O(d·2^n) field operations.

4. WHEN computing round polynomial s_i(X), THE System SHALL evaluate g at all points (r_1,...,r_{i-1}, t, x_{i+1},...,x_n) for t ∈ {0,1,...,d}.

5. WHEN verifying round i, THE System SHALL check s_{i-1}(r_{i-1}) = s_i(0) + s_i(1) and final check s_n(r_n) = g(r_1,...,r_n).

6. WHEN achieving soundness, THE System SHALL have error at most dn/|F| by Schwartz-Zippel lemma.

7. WHEN using quotienting PIOP alternative, THE System SHALL verify â(X)·b̂(X) - ĉ(X) = q(X)·Z_H(X) for vanishing polynomial Z_H.

8. WHEN combining with PCS, THE System SHALL support both univariate (KZG, FRI) and multilinear (Hyrax, Dory, lattice-based) commitment schemes.

### Requirement 17: Concrete Parameter Selection

**User Story:** As a deployment engineer, I want concrete parameter recommendations, so that the system can be configured for target security levels.

#### Acceptance Criteria

1. WHEN targeting λ = 128 bits, THE System SHALL provide parameters (q, φ, β) validated against Lattice Estimator.

2. WHEN targeting λ = 192 bits, THE System SHALL provide parameters with appropriate security margin.

3. WHEN targeting λ = 256 bits, THE System SHALL provide parameters for highest security applications.

4. WHEN documenting norm growth, THE System SHALL specify maximum folding depth before overflow.

5. WHEN estimating performance, THE System SHALL provide ops/sec, proof size, and memory for each parameter set.

6. WHEN enforcing parameter constraints, THE System SHALL verify q > 2·β·d^k for k folding iterations.

### Requirement 18: Implementation Efficiency

**User Story:** As a performance engineer, I want optimized implementation, so that proving is as fast as possible.

#### Acceptance Criteria

1. WHEN parallelizing, THE System SHALL use work-stealing across all CPU cores via Rayon.

2. WHEN using SIMD, THE System SHALL implement AVX-512-IFMA ring arithmetic where available for cyclotomic ring operations.

3. WHEN optimizing NTT, THE System SHALL use radix-2/radix-4 implementations with precomputed twiddles and incomplete NTT for non-splitting rings.

4. WHEN managing memory, THE System SHALL use streaming algorithms to minimize footprint with O(√T) space for stream length T.

5. WHEN ensuring cache efficiency, THE System SHALL align data structures and optimize access patterns.

6. WHEN supporting GPU, THE System SHOULD enable GPU acceleration for large polynomial operations.

7. WHEN implementing sum-check prover, THE System SHALL use dynamic programming (Thaler's optimization) achieving O(2^n) total field operations with work halving each round.

8. WHEN using batch evaluation arguments, THE System SHALL minimize commitment costs by batching multiple polynomial evaluations into single opening.

9. WHEN implementing virtual polynomials, THE System SHALL avoid materializing intermediate polynomials to reduce commitment overhead.

10. WHEN exploiting small-value preservation, THE System SHALL leverage witness bit-width for faster commitment where committing small values is proportionally cheaper.

11. WHEN implementing sparse sum-check, THE System SHALL exploit sparsity in constraint matrices for sub-linear prover time on sparse instances.

12. WHEN using memory checking protocols, THE System SHALL implement read/write memory verification with O(n) operations for n memory accesses.

### Requirement 19: Security Guarantees

**User Story:** As a security analyst, I want rigorous security guarantees, so that the system is provably secure.

#### Acceptance Criteria

1. WHEN achieving post-quantum security, THE System SHALL base security on Ring-SIS and Ring-LWE assumptions.

2. WHEN preventing timing attacks, THE System SHALL implement constant-time operations for secret-dependent code.

3. WHEN achieving knowledge soundness, THE System SHALL provide extractor recovering witness with probability ≥ 1 - negl(λ).

4. WHEN achieving completeness, THE System SHALL accept all valid proofs with probability 1.

5. WHEN bounding soundness error, THE System SHALL achieve total error ≤ 2^(-λ) across all protocol steps.

6. WHEN validating parameters, THE System SHALL verify Hermite factor and vSIS hardness.

### Requirement 20: API and Integration

**User Story:** As a developer, I want clean APIs, so that the system is easy to use and integrate.

#### Acceptance Criteria

1. WHEN providing builder pattern, THE System SHALL offer IVCBuilder, SNARKBuilder, PCDBuilder interfaces.

2. WHEN serializing proofs, THE System SHALL support efficient binary serialization with versioning.

3. WHEN providing examples, THE System SHALL include Fibonacci IVC, aggregate signatures, and PCD DAG examples.

4. WHEN documenting, THE System SHALL provide comprehensive API documentation and usage guides.

5. WHEN testing, THE System SHALL include property-based tests for all correctness properties.

6. WHEN benchmarking, THE System SHALL provide reproducible benchmarks for all major operations.

---

## Cross-Cutting Requirements

### Security Requirements

1. **Post-Quantum Security**: ALL cryptographic primitives SHALL be secure against quantum adversaries under Ring-SIS, Ring-LWE, and vSIS assumptions.
2. **Constant-Time Operations**: ALL secret-dependent operations SHALL be constant-time to prevent timing attacks.
3. **Memory Safety**: THE implementation SHALL be memory-safe with no undefined behavior.
4. **Audit Trail**: THE system SHALL log security-relevant operations for audit.
5. **Norm Tracking**: THE system SHALL track witness norm through all protocol steps with explicit bounds to prevent overflow.
6. **Challenge Set Security**: THE system SHALL ensure invertibility of differences in challenge sets for folding soundness.

### Performance Requirements (Paper-Specific Targets)

1. **SALSAA SNARK Performance**: THE system SHALL achieve verifier time ≤ 50ms, prover time ≤ 11s, proof size ≤ 1MB for witness of 2^28 Z_q elements.
2. **SALSAA Folding Performance**: THE system SHALL achieve proof size ≤ 73KB with verification ≤ 3ms for folding 4 instances with 2^30 Z_q witness.
3. **Quasar Accumulation**: THE system SHALL achieve O(log ℓ) verifier complexity and O(√N) total CRC operations across N IVC steps.
4. **Neo Pay-Per-Bit**: THE system SHALL achieve 64× cost reduction when committing bits vs 64-bit values.
5. **Symphony High-Arity**: THE system SHALL support folding 2^10 R1CS statements with proof size ≤ 200KB.
6. **Sum-Check Prover**: THE prover SHALL achieve O(2^n) total field operations with work halving each round.

### General Performance Requirements

1. **Prover Throughput**: THE prover SHALL achieve ≥ 10,000 constraints/second on commodity hardware.
2. **Verification Time**: THE verifier SHALL complete in ≤ 100ms for proofs up to 2^20 constraints.
3. **Proof Size**: THE proof size SHALL be ≤ 100KB for 2^20 constraints at 128-bit security.
4. **Memory Usage**: THE prover memory SHALL be ≤ 16GB for 2^20 constraints.
5. **Streaming Support**: THE prover SHALL support streaming with O(√T) space for stream length T.

### Compatibility Requirements

1. **Rust Ecosystem**: THE implementation SHALL be pure Rust with minimal unsafe code.
2. **WASM Support**: THE verifier SHALL compile to WebAssembly for browser deployment.
3. **Serialization**: ALL data structures SHALL support efficient serialization with versioning.
4. **API Stability**: THE public API SHALL follow semantic versioning.
5. **Field Support**: THE system SHALL support Goldilocks (2^64 - 2^32 + 1), M61 (2^61 - 1), BabyBear, and BN254 scalar fields.

### Requirement 21: Missing Components from Paper Analysis

**User Story:** As a comprehensive implementation developer, I want all missing components from the five core papers (Quasar, SALSAA, Sum-check Survey, Neo, Symphony) identified and specified, so that the implementation is complete.

#### Acceptance Criteria - Quasar Missing Components

1. WHEN implementing multi-cast reduction NIR_multicast, THE System SHALL transform multi-instance relation R^ℓ to committed relation R^cm_acc with O(1) commitments.

2. WHEN implementing oracle batching reduction IOR_batch, THE System SHALL satisfy succinctness property with proof sublinear in polynomial length.

3. WHEN implementing union polynomial commitment, THE System SHALL commit to multilinear extension w̃_∪(Y,X) of all witness vectors efficiently.

4. WHEN implementing partial evaluation verification, THE System SHALL check w̃_∪(τ, r_x) = w̃(r_x) with soundness error log n/|F|.

5. WHEN integrating with linear-time encodable codes, THE System SHALL support post-quantum instantiation with linear prover complexity.

#### Acceptance Criteria - SALSAA Missing Components

6. WHEN implementing linear-time norm-check RoK Π_norm, THE System SHALL reduce Ξ_norm to Ξ_sum using ∥x∥²_{σ,2} = Trace(⟨x,x⟩) identity.

7. WHEN implementing LDE relation Ξ_lde and structured variant Ξ_lde-⊗, THE System SHALL extend Ξ_lin to check LDE evaluations at specified points.

8. WHEN implementing sumcheck relation Ξ_sum, THE System SHALL extend Ξ_lin to check sumcheck claims over LDEs.

9. WHEN implementing efficient batching protocol Π*_batch, THE System SHALL provide alternative to RPS/RnR batching using sumcheck.

10. WHEN implementing R1CS to Ξ_lin reduction RoK, THE System SHALL follow linearisation strategy reducing R1CS to evaluation claims.

11. WHEN implementing AVX-512 accelerated NTT, THE System SHALL use AVX-512-IFMA instructions for hardware acceleration of cyclotomic ring arithmetic.

#### Acceptance Criteria - Sum-check Survey Missing Components

12. WHEN implementing optimized sum-check prover, THE System SHALL use dynamic programming (Thaler's optimization) for linear-time proving.

13. WHEN implementing batch evaluation argument protocols, THE System SHALL batch multiple polynomial evaluations into single opening proof.

14. WHEN implementing virtual polynomial framework, THE System SHALL avoid materializing intermediate polynomials to reduce commitment overhead.

15. WHEN implementing small-value preservation techniques, THE System SHALL leverage witness bit-width for faster commitment operations.

16. WHEN implementing sparse sum-check, THE System SHALL exploit sparsity for sub-linear prover time on structured computations.

17. WHEN implementing memory checking protocols, THE System SHALL support read/write memory verification with O(n) operations.

#### Acceptance Criteria - Neo Missing Components

18. WHEN implementing pay-per-bit Ajtai commitment, THE System SHALL achieve commitment cost scaling linearly with bit-width of values.

19. WHEN implementing folding-friendly linear homomorphism, THE System SHALL support combining β ≥ 2 commitments with multilinear evaluation claims.

20. WHEN implementing CCS reduction protocol Π_CCS, THE System SHALL use single sum-check invocation over extension field.

21. WHEN implementing decomposition reduction Π_DEC, THE System SHALL decompose witness to ensure norm bounds for security.

22. WHEN implementing challenge set construction, THE System SHALL ensure invertibility for small fields (Goldilocks, M61).

23. WHEN implementing extension field arithmetic, THE System SHALL support sum-check over degree-2 extensions of small primes.

#### Acceptance Criteria - Symphony Missing Components

24. WHEN implementing high-arity folding scheme, THE System SHALL compress ℓ_np > 1 R1CS statements via commitment, sumcheck, and RLC steps.

25. WHEN implementing monomial embedding range proof, THE System SHALL use table polynomial t(X) = Σ_{i∈[1,d/2)} i·(X^i + X^{-i}).

26. WHEN implementing structured random projection, THE System SHALL use J := I_{n/ℓ_h} ⊗ J' for sublinear verifier complexity.

27. WHEN implementing commit-and-prove SNARK compiler, THE System SHALL convert folding scheme to SNARK without embedding Fiat-Shamir circuit.

28. WHEN implementing two-layer folding, THE System SHALL split linear statements to support higher folding depths without recursive circuits.

29. WHEN implementing streaming prover, THE System SHALL require space O(n) with 2 + log log(n) passes over input data.

30. WHEN implementing tensor-of-rings framework, THE System SHALL support interleaving between sumcheck and folding operations.

---

## Component Spec References

This unified spec integrates requirements from the following component specifications:

1. `.kiro/specs/salsaa-sumcheck-lattice-arguments/` - SALSAA protocol details
2. `.kiro/specs/quasar-complete-implementation/` - Quasar accumulation scheme
3. `.kiro/specs/agm-secure-ivc-complete/` - AGM-secure IVC construction
4. `.kiro/specs/linear-time-permcheck/` - Permutation check protocols
5. `.kiro/specs/lookup-table-arguments/` - Lookup argument variants
6. `.kiro/specs/distributed-snark-folding/` - Distributed proving
7. `.kiro/specs/lattice-zkvm-streaming/` - Streaming computation support
8. `.kiro/specs/lattice-zkvm/` - Core lattice zkVM components

Each component spec provides detailed requirements for its specific subsystem. This unified spec defines the integration points and overall system requirements.
