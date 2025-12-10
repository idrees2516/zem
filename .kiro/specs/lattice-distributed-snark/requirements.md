# Requirements Document: Lattice-Based Distributed SNARK via Folding Schemes

## Introduction

This document specifies the requirements for implementing a **post-quantum secure** distributed Succinct Non-interactive Argument of Knowledge (SNARK) system based on folding schemes and lattice cryptography. The system addresses both scalability limitations AND quantum threats by:

1. **Distributing computation** across multiple provers (like the classical version)
2. **Using lattice-based cryptography** for post-quantum security
3. **Maintaining optimal complexity** bounds despite larger lattice parameters

The system is built on:
- **Module-SIS/LWE assumptions** (post-quantum secure)
- **Lattice-based polynomial commitments** (vSIS-based)
- **Structured lattice folding** (LatticeFold+ with norm preservation)
- **Distributed sumcheck** over lattice-friendly fields

### Performance Targets (Post-Quantum)
- Linear prover complexity O(T) where T = N/M (N = total gates, M = workers)
- Proof size O(log N · λ) where λ is security parameter (~128 bits)
- Verification time O(log N · λ) + O(M · λ²) for lattice operations
- Communication O(N · λ) field elements (larger than classical due to lattice parameters)

### Performance Optimizations (Security-Preserving)
- **NTT Optimizations**: Lazy reduction (2-3×), precomputed twiddles (1.5×), NWC (2×)
- **SIMD Acceleration**: Vectorized operations for decomposition (4-8×), norms (4-8×), Gaussian sampling (8×)
- **Memory Efficiency**: Streaming processing (10× less memory), cache-oblivious layout (2× fewer misses)
- **Network Optimization**: Incremental compression (3-4× bandwidth), batched messages (2× fewer)
- **Algorithmic**: Incremental norm updates (10×), lazy decomposition (amortized), hierarchical aggregation (1.5×)
- **Combined Target**: 7-8× faster prover, 3-4× less communication, 10× less memory (maintains 128-bit quantum security)

### Security Properties
- **Post-Quantum Secure**: Resistant to quantum adversaries
- **Module-SIS Hardness**: Based on worst-case lattice problems
- **128-bit Quantum Security**: Equivalent to AES-128 against quantum attacks

## Glossary

- **Module-SIS**: Module Short Integer Solution problem over polynomial rings
- **Module-LWE**: Module Learning With Errors problem
- **Lattice PCS**: Polynomial commitment scheme based on vSIS (vectorized SIS)
- **Cyclotomic Ring**: R = Z[X]/(Φ_m(X)) where Φ_m is cyclotomic polynomial
- **Ring-LWE**: Learning With Errors over cyclotomic rings
- **Gadget Decomposition**: Decompose ring elements to control norm growth
- **Norm-Preserving Folding**: Folding that maintains witness norm bounds
- **Structured Random Projection**: Tensor-structured matrices for efficiency

- **Goldilocks Field**: F_p where p = 2^64 - 2^32 + 1 (lattice-friendly prime)
- **M61 Field**: Mersenne prime field p = 2^61 - 1 (efficient modular reduction)
- **NTT**: Number Theoretic Transform (FFT over finite fields)
- **Rejection Sampling**: Technique to ensure output distribution is independent of secret
- **Soundness Error**: Probability that malicious prover succeeds without valid witness
- **Knowledge Error**: Probability that extractor fails to extract witness
- **Prover_System**: Distributed system with M provers P₀,...,P_{M-1}
- **Coordinator_Prover**: Prover P₀ that aggregates and performs final operations
- **Worker_Prover**: Provers P₁,...,P_{M-1} performing local computations
- **Lattice Witness**: Short vector w ∈ R^m with ||w|| ≤ β
- **Commitment Matrix**: Structured matrix A ∈ R_q^{n×m} for commitments
- **Verification Key**: Public parameters for verifying lattice-based proofs
- **Cross-Term**: Error term E in folding arising from witness interaction
- **Challenge Space**: Set of valid challenges for Fiat-Shamir transformation
- **Transcript**: Record of all protocol messages for Fiat-Shamir
- **AROM**: Algebraic Random Oracle Model (for security proofs)
- **Monomial Matrix**: Diagonal matrix with monomial entries for structured operations
- **Table Polynomial**: Lookup table encoded as polynomial for efficient evaluation
- **Tensor Structure**: Kronecker product structure J = I ⊗ J' for efficiency
- **RoK and Roll**: Structured random projections achieving Õ(λ) proof size

## Requirements

### Requirement 1: Lattice-Based Cryptographic Primitives

**User Story:** As a post-quantum cryptographer, I want to implement lattice-based cryptographic primitives, so that the distributed SNARK system is secure against quantum adversaries.

#### Acceptance Criteria

1. WHEN the system initializes, THE Prover_System SHALL generate public parameters pp ← Setup(1^λ, R_q) where λ = 128 is the quantum security parameter and R_q = Z_q[X]/(X^n + 1) is the cyclotomic ring with n = 2^k and q ≈ 2^60

2. WHEN a polynomial f ∈ R_q^m is committed, THE Prover_System SHALL compute lattice commitment C = A·w mod q where A ∈ R_q^{n×m} is structured commitment matrix and w ∈ R^m is short witness with ||w|| ≤ β

3. WHEN a commitment C is opened at evaluation point, THE Prover_System SHALL generate opening proof π demonstrating knowledge of short w such that C = A·w and f(r) = ⟨w, φ(r)⟩ where φ is evaluation map

4. WHEN verification is performed, THE Prover_System SHALL check lattice verification equation and norm bound ||w|| ≤ β with probability 1 - negl(λ) under Module-SIS assumption

5. WHEN multilinear extension is computed, THE Prover_System SHALL construct f̃ : R_q^μ → R_q extending f : {0,1}^μ → R_q using eq function over lattice-friendly field

6. WHEN eq function is evaluated, THE Prover_System SHALL compute eq(x,X) = ∏^μ_{i=1}(x_iX_i + (1-x_i)(1-X_i)) over Goldilocks or M61 field for efficiency

7. WHEN homomorphic operations are performed, THE Prover_System SHALL support additive homomorphism C₁ + C₂ = A·(w₁ + w₂) and scalar multiplication k·C = A·(k·w) while maintaining norm bounds


### Requirement 2: Lattice-Based Sum-Check Protocol

**User Story:** As a proof system implementer, I want to implement sum-check protocol over lattice-friendly fields, so that I can verify polynomial evaluations efficiently in post-quantum setting.

#### Acceptance Criteria

1. WHEN sum-check relation R_HSUM is defined, THE Prover_System SHALL accept tuples (s; x; w) = (h; (v, [[w₀]],...,[[w_{t-1}]]); (w₀,...,w_{t-1})) where ∑_{x∈B^μ} h(w₀(x),...,w_{t-1}(x)) = v and [[wᵢ]] are lattice commitments

2. WHEN sum-check protocol executes for μ rounds, THE Prover_System SHALL send univariate polynomial Q_k(X) of degree at most d over Goldilocks field in round k ∈ [μ]

3. WHEN round k verifier check is performed, THE Prover_System SHALL verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) where r_{k-1} is previous challenge from Goldilocks field

4. WHEN verifier sends challenge r_k, THE Prover_System SHALL sample r_k uniformly from Goldilocks field using SHAKE-256 hash function and update protocol state

5. WHEN final round completes, THE Prover_System SHALL reduce to polynomial evaluation Q(r_b) = c where r_b = (r₁,...,r_μ) ∈ F^μ and verify using lattice PCS opening

6. WHEN knowledge soundness is required, THE Prover_System SHALL achieve knowledge error at most dμ/|F| + negl(λ) where negl(λ) accounts for lattice soundness error

7. WHEN perfect completeness is required, THE Prover_System SHALL accept all valid proofs with probability 1 - 2^{-λ} accounting for rejection sampling failures

### Requirement 3: Lattice-Based SumFold Protocol (Single Prover)

**User Story:** As a folding scheme developer, I want to implement SumFold with lattice commitments, so that multiple sum-check instances can be folded while maintaining post-quantum security.

#### Acceptance Criteria

1. WHEN M = 2^ν instances are folded, THE Prover_System SHALL accept input {x_i = (v_i, [[w_{i,0}]],...,[[w_{i,t-1}]]); w_i = (w_{i,0},...,w_{i,t-1})}_{i∈[M]} where [[w_{i,j}]] are lattice commitments with norm ||w_{i,j}|| ≤ β

2. WHEN verifier samples randomness, THE Prover_System SHALL generate ρ ← F^ν uniformly from Goldilocks field using SHAKE-256 and send to prover

3. WHEN interpolation polynomials are constructed, THE Prover_System SHALL compute f_j(b,x) = ∑_{i∈[M]} eq(b,⟨i⟩_ν) · w_{i,j}(x) ensuring ||f_j|| ≤ M·β through careful coefficient management

4. WHEN aggregated sum is computed, THE Prover_System SHALL calculate T₀ = ∑_{i∈[M]} eq(ρ,⟨i⟩_ν) · v_i over Goldilocks field

5. WHEN sum-check polynomial is defined, THE Prover_System SHALL construct Q(b) = eq(ρ,b) · (∑_{x∈B^μ} h(f₀(b,x),...,f_{t-1}(b,x))) with bounded coefficients

6. WHEN sum-check protocol executes, THE Prover_System SHALL run ν rounds proving ∑_{b∈B^ν} Q(b) = T₀ using lattice-based commitments

7. WHEN final evaluation is reached, THE Prover_System SHALL reduce to Q(r_b) = c where r_b ∈ F^ν and verify using lattice PCS opening at r_b

8. WHEN folded witness is computed, THE Prover_System SHALL calculate w'_j = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · w_{i,j} ensuring ||w'_j|| ≤ M·β·||eq||_∞ through norm analysis

9. WHEN folded commitments are computed, THE Prover_System SHALL calculate [[w'_j]] = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · [[w_{i,j}]] using lattice commitment homomorphism

10. WHEN folded value is computed, THE Prover_System SHALL calculate v' = c · eq(ρ,r_b)^{-1} over Goldilocks field

11. WHEN output is generated, THE Prover_System SHALL produce folded instance-witness pair ((h, v', [[w'₀]],...,[[w'_{t-1}]]); (w'₀,...,w'_{t-1})) with verified norm bounds


### Requirement 4: Norm-Preserving Distributed SumFold (LatticeFold+)

**User Story:** As a distributed system architect, I want to implement distributed SumFold with norm preservation, so that folding computation is parallelized efficiently without norm explosion.

#### Acceptance Criteria

1. WHEN M = 2^ν provers participate, THE Prover_System SHALL assign prover P_i the instance-witness pair (x_i; w_i) where w_i has norm ||w_i|| ≤ β and [[w_i]] is lattice commitment

2. WHEN gadget decomposition is applied, THE Prover_System SHALL decompose witness w_i = ∑_{j=0}^{ℓ-1} b^j · w_{i,j} where b is decomposition base and ||w_{i,j}||_∞ < b ensuring ||w_i|| ≤ √ℓ · b

3. WHEN local data is stored, THE Prover_System SHALL ensure P_i stores eq(ρ,⟨i⟩_ν), decomposed witness slices {w_{i,j,k}}_{j,k}, and monomial matrix entries for structured operations

4. WHEN round k ∈ [ν] executes, THE Prover_System SHALL have P_s send to P_{2^{ν-k}+s} messages containing eq values and decomposed witness slices totaling O(T·ℓ) ring elements where T = N/M

5. WHEN partial polynomial is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} compute e_k^{(s)}(X) using decomposed witnesses and verify norm bound ||e_k^{(s)}|| ≤ 2·β

6. WHEN witness interpolation is performed, THE Prover_System SHALL compute f_{k,x}^{(s,j)}(X) from decomposed slices ensuring ||f_{k,x}^{(s,j)}|| ≤ 2·β through careful linear combination

7. WHEN partial sum-check polynomial is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} calculate Q_k^{(s)}(X) using NTT-based polynomial multiplication achieving O(T·ℓ·log(T·ℓ)) complexity

8. WHEN aggregation is performed, THE Coordinator_Prover SHALL compute Q_k(X) = ∑_{s∈[2^{ν-k}]} Q_k^{(s)}(X) and verify total norm ||Q_k|| ≤ 2^{ν-k}·2·β

9. WHEN verifier check is performed, THE Prover_System SHALL verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) over Goldilocks field and send challenge r_k ∈ F to P₀

10. WHEN challenge is distributed, THE Coordinator_Prover SHALL transmit r_k to P_{2^{ν-k}+s} for s ∈ [2^{ν-k}] using authenticated channels

11. WHEN next-round data is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} compute updated eq values and witness slices maintaining norm bounds ||·|| ≤ β

12. WHEN final round completes, THE Coordinator_Prover SHALL obtain eq(ρ,r_b) and decomposed witness slices, recompose to get w'_j, and verify ||w'_j|| ≤ β (norm preserved!)

13. WHEN witness folding is performed, THE Prover_System SHALL have P_i compute e_i = eq(r_b,⟨i⟩_ν), scale decomposed witnesses, and send lattice commitments [[w'_{i,j}]] to P₀

14. WHEN witness aggregation is performed, THE Prover_System SHALL have P_i aggregate decomposed witnesses using binary tree topology ensuring ||w'_j|| ≤ β throughout

15. WHEN final output is generated, THE Coordinator_Prover SHALL compute v' = c · eq(ρ,r_b)^{-1}, aggregate commitments [[w'_j]] = ∑_{i∈[M]} [[w'_{i,j}]], and verify norm bound ||w'_j|| ≤ β

16. WHEN verifier output is generated, THE Prover_System SHALL have verifier compute v', e_i values, and aggregate commitments [[w'_j]] = ∑_{i∈[M]} e_i · [[w_{i,j}]] homomorphically


### Requirement 5: Lattice-Based Network Communication Layer

**User Story:** As a distributed system developer, I want to implement secure and efficient network communication for lattice-based proofs, so that provers can exchange lattice commitments and field elements with minimal overhead.

#### Acceptance Criteria

1. WHEN network layer initializes, THE Prover_System SHALL establish authenticated channels between all M provers using TLS 1.3 with post-quantum key exchange (Kyber-768 or higher)

2. WHEN prover P_i sends lattice commitment [[w]], THE Prover_System SHALL serialize commitment as byte array containing n ring elements from R_q where each element requires ⌈log₂(q)⌉ bits and n = 1024

3. WHEN field element r ∈ F is transmitted, THE Prover_System SHALL encode r using 8 bytes for Goldilocks field (p = 2^64 - 2^32 + 1) or 8 bytes for M61 field (p = 2^61 - 1)

4. WHEN ring element a ∈ R_q is transmitted, THE Prover_System SHALL serialize a as n coefficients in NTT representation using ⌈60·n/8⌉ bytes where n = 1024 and q ≈ 2^60

5. WHEN decomposed witness slice w_{i,j,k} is sent, THE Prover_System SHALL batch-serialize ℓ slices totaling O(n·ℓ) coefficients where ℓ = 30 is decomposition limbs

6. WHEN message integrity is required, THE Prover_System SHALL compute HMAC-SHA3-256 tag over serialized data and verify tag upon receipt with probability 1 - 2^{-256}

7. WHEN bandwidth optimization is needed, THE Prover_System SHALL compress ring elements using structured representation exploiting cyclotomic ring structure reducing size by factor of 2

8. WHEN round k challenge r_k is broadcast, THE Coordinator_Prover SHALL send r_k ∈ F to all active provers P_{2^{ν-k}+s} for s ∈ [2^{ν-k}] using multicast with acknowledgment

9. WHEN network partition is detected, THE Prover_System SHALL abort protocol execution and return error state within timeout period of 30 seconds

10. WHEN message ordering is required, THE Prover_System SHALL attach sequence numbers to all messages and enforce FIFO delivery per sender-receiver pair

11. WHEN latency measurement is performed, THE Prover_System SHALL track round-trip time for each message type and log statistics for performance analysis

12. WHEN connection pool is managed, THE Prover_System SHALL maintain persistent connections between provers reusing TCP sockets to minimize handshake overhead


### Requirement 6: Norm-Preserving Aggregation for Lattice Witnesses

**User Story:** As a lattice cryptographer, I want to implement norm-preserving aggregation of lattice witnesses, so that distributed folding maintains security bounds without exponential norm growth.

#### Acceptance Criteria

1. WHEN witness w_i with norm ||w_i|| ≤ β is received, THE Prover_System SHALL verify norm bound using efficient norm computation ||w_i||² = ∑_{j=0}^{n-1} |w_i[j]|² ≤ β²

2. WHEN gadget decomposition is applied to w_i, THE Prover_System SHALL compute w_i = ∑_{j=0}^{ℓ-1} b^j · w_{i,j} where b = 4 is decomposition base and ||w_{i,j}||_∞ < b ensuring ||w_i|| ≤ √(n·ℓ)·b

3. WHEN decomposition correctness is verified, THE Prover_System SHALL check ∑_{j=0}^{ℓ-1} b^j · w_{i,j} ≡ w_i (mod q) for all coefficients with probability 1

4. WHEN linear combination is computed, THE Prover_System SHALL calculate w' = ∑_{i∈[M]} α_i · w_i where α_i ∈ F and verify ||w'|| ≤ (∑_{i∈[M]} |α_i|) · β using triangle inequality

5. WHEN gadget-based aggregation is performed, THE Prover_System SHALL compute w'_j = ∑_{i∈[M]} α_i · w_{i,j} for each limb j ∈ [ℓ] ensuring ||w'_j||_∞ < M·b·||α||_∞

6. WHEN recomposition is performed, THE Prover_System SHALL reconstruct w' = ∑_{j=0}^{ℓ-1} b^j · w'_j and verify ||w'|| ≤ √(n·ℓ)·M·b·||α||_∞

7. WHEN binary tree aggregation is used, THE Prover_System SHALL aggregate witnesses in log₂(M) rounds where round k combines pairs ensuring ||w^{(k)}|| ≤ 2^k·β·||α||_∞

8. WHEN structured coefficients are exploited, THE Prover_System SHALL use eq(r_b, ⟨i⟩_ν) coefficients satisfying ||eq||_∞ ≤ 1 to maintain ||w'|| ≤ M·β

9. WHEN norm explosion is detected, THE Prover_System SHALL abort aggregation if ||w'|| > 2·M·β and return error indicating norm bound violation

10. WHEN final witness is output, THE Prover_System SHALL verify ||w'|| ≤ β through careful coefficient management and gadget decomposition ensuring soundness

11. WHEN commitment aggregation is performed, THE Prover_System SHALL compute [[w']] = ∑_{i∈[M]} α_i · [[w_i]] using lattice commitment homomorphism without revealing w_i

12. WHEN aggregation proof is generated, THE Prover_System SHALL produce proof π demonstrating correct aggregation of decomposed witnesses with soundness error ε ≤ 2^{-128}

13. WHEN parallel aggregation is performed, THE Prover_System SHALL distribute aggregation across P provers computing partial sums in O(M/P) time per prover

14. WHEN memory efficiency is required, THE Prover_System SHALL stream witness slices processing O(n·ℓ/M) coefficients per prover without storing full witness

15. WHEN aggregation is verified, THE Prover_System SHALL check commitment equation [[w']] = ∑_{i∈[M]} α_i · [[w_i]] and norm bound ||w'|| ≤ β with probability 1 - negl(λ)


### Requirement 7: Rejection Sampling for Lattice Soundness

**User Story:** As a zero-knowledge proof implementer, I want to implement rejection sampling for lattice-based proofs, so that the output distribution is statistically independent of the secret witness.

#### Acceptance Criteria

1. WHEN rejection sampling is initialized, THE Prover_System SHALL set rejection bound M = 12.0 ensuring statistical distance Δ(D_σ, D_{σ,w}) ≤ 2^{-128} where D_σ is target Gaussian

2. WHEN witness w with norm ||w|| ≤ β is input, THE Prover_System SHALL sample masking vector y ← D_σ^n from discrete Gaussian with standard deviation σ = α·β where α = 11.0

3. WHEN response z is computed, THE Prover_System SHALL calculate z = y + c·w where c ∈ {-1,0,1}^κ is challenge with Hamming weight κ = 60

4. WHEN rejection condition is evaluated, THE Prover_System SHALL compute acceptance probability P_accept = min(1, D_σ(z)/(M·D_{σ,c·w}(z))) using precise floating-point arithmetic

5. WHEN random coin is sampled, THE Prover_System SHALL generate u ← [0,1) uniformly using SHAKE-256 with 256 bits of entropy

6. WHEN rejection decision is made, THE Prover_System SHALL accept z if u ≤ P_accept and reject otherwise, repeating sampling until acceptance

7. WHEN expected iterations are bounded, THE Prover_System SHALL achieve expected number of iterations E[iterations] ≤ M = 12.0 with probability 1 - 2^{-64}

8. WHEN maximum iterations are enforced, THE Prover_System SHALL abort after 100 iterations and return error indicating potential implementation bug or parameter misconfiguration

9. WHEN Gaussian sampling is performed, THE Prover_System SHALL use cumulative distribution table (CDT) method with precomputed table of size O(σ·√λ) for constant-time sampling

10. WHEN statistical distance is verified, THE Prover_System SHALL ensure Δ(output_distribution, D_σ^n) ≤ 2^{-128} through rejection sampling with bound M = 12.0

11. WHEN side-channel resistance is required, THE Prover_System SHALL implement constant-time rejection sampling avoiding branches dependent on secret w

12. WHEN norm bound is checked, THE Prover_System SHALL verify ||z|| ≤ σ·√n·ω(√log n) with probability 1 - negl(n) where ω(√log n) is tail bound factor

13. WHEN challenge space is defined, THE Prover_System SHALL sample c from challenge set C = {c ∈ {-1,0,1}^n : ||c||₁ = κ} with κ = 60 using Fisher-Yates shuffle

14. WHEN Fiat-Shamir is applied, THE Prover_System SHALL compute challenge c = H(transcript || commitment) using SHAKE-256 and map output to challenge space C

15. WHEN soundness is analyzed, THE Prover_System SHALL achieve knowledge error κ_error ≤ (2κ/n)^κ + 2^{-128} accounting for challenge space size and rejection sampling

16. WHEN parallel rejection sampling is performed, THE Prover_System SHALL sample M independent (y,z) pairs in parallel and select first accepted sample reducing expected latency

17. WHEN rejection sampling statistics are logged, THE Prover_System SHALL track acceptance rate, average iterations, and maximum iterations for performance monitoring


### Requirement 8: Distributed SumFold with Lattice Commitments

**User Story:** As a distributed proof system architect, I want to implement distributed SumFold protocol adapted for lattice commitments, so that multiple sum-check instances can be folded efficiently across M provers with post-quantum security.

#### Acceptance Criteria

1. WHEN distributed SumFold initializes with M = 2^ν provers, THE Prover_System SHALL assign prover P_i the instance-witness pair (x_i; w_i) where x_i = (v_i, [[w_{i,0}]],...,[[w_{i,t-1}]]) and w_i = (w_{i,0},...,w_{i,t-1}) with ||w_{i,j}|| ≤ β

2. WHEN public randomness ρ is generated, THE Coordinator_Prover SHALL sample ρ ← F^ν uniformly from Goldilocks field using SHAKE-256(seed || "sumfold_rho") and broadcast to all provers

3. WHEN prover P_i computes local eq value, THE Prover_System SHALL calculate e_i = eq(ρ, ⟨i⟩_ν) = ∏_{k=1}^ν (ρ_k·i_k + (1-ρ_k)·(1-i_k)) where ⟨i⟩_ν is ν-bit representation of i

4. WHEN prover P_i applies gadget decomposition, THE Prover_System SHALL decompose each w_{i,j} = ∑_{ℓ'=0}^{ℓ-1} b^{ℓ'} · w_{i,j,ℓ'} where b = 4 and ||w_{i,j,ℓ'}||_∞ < b

5. WHEN round k ∈ [ν] begins, THE Prover_System SHALL have active provers in set S_k = {s : s < 2^{ν-k}} compute partial sum-check polynomials Q_k^{(s)}(X)

6. WHEN prover P_s sends data to P_{2^{ν-k}+s}, THE Prover_System SHALL transmit eq value e_s, decomposed witness slices {w_{s,j,ℓ',x}}_{j,ℓ',x}, and commitment randomness totaling O(T·ℓ·n) ring elements

7. WHEN prover P_{2^{ν-k}+s} receives data, THE Prover_System SHALL verify message integrity using HMAC-SHA3-256 and check norm bounds ||w_{s,j,ℓ',x}||_∞ < b

8. WHEN witness interpolation is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} calculate f_{k,x}^{(s,j,ℓ')}(X) = w_{s,j,ℓ',x} + X·(w_{2^{ν-k}+s,j,ℓ',x} - w_{s,j,ℓ',x}) for each x ∈ B^μ

9. WHEN partial polynomial is evaluated, THE Prover_System SHALL compute Q_k^{(s)}(X) = e_k^{(s)}(X) · (∑_{x∈B^μ} h(f_{k,x}^{(s,0)}(X),...,f_{k,x}^{(s,t-1)}(X))) using NTT-based multiplication

10. WHEN norm bound is verified, THE Prover_System SHALL check ||Q_k^{(s)}|| ≤ 2·β·||h||·2^μ where ||h|| is Lipschitz constant of h and 2^μ is hypercube size

11. WHEN partial polynomials are aggregated, THE Coordinator_Prover SHALL compute Q_k(X) = ∑_{s∈S_k} Q_k^{(s)}(X) and verify ||Q_k|| ≤ 2^{ν-k}·2·β·||h||·2^μ

12. WHEN verifier check is performed, THE Prover_System SHALL verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) over Goldilocks field with equality check

13. WHEN challenge r_k is generated, THE Coordinator_Prover SHALL sample r_k ← F uniformly using SHAKE-256(transcript || k) and broadcast to active provers in S_k

14. WHEN prover updates state, THE Prover_System SHALL have P_{2^{ν-k}+s} compute updated eq value e'_{2^{ν-k}+s} = e_k^{(s)}(r_k) and updated witness slices w'_{2^{ν-k}+s,j,ℓ',x} = f_{k,x}^{(s,j,ℓ')}(r_k)

15. WHEN final round ν completes, THE Coordinator_Prover SHALL obtain eq(ρ,r_b) where r_b = (r_1,...,r_ν) and decomposed witness slices {w'_{0,j,ℓ',x}}_{j,ℓ',x}

16. WHEN witness recomposition is performed, THE Prover_System SHALL reconstruct w'_j(x) = ∑_{ℓ'=0}^{ℓ-1} b^{ℓ'} · w'_{0,j,ℓ',x} for each j ∈ [t] and x ∈ B^μ

17. WHEN final norm is verified, THE Prover_System SHALL check ||w'_j|| ≤ β ensuring norm preservation through gadget decomposition and careful aggregation

18. WHEN commitment folding is performed, THE Prover_System SHALL have each P_i compute e_i = eq(r_b, ⟨i⟩_ν) and send [[w'_{i,j}]] = e_i · [[w_{i,j}]] to P₀

19. WHEN commitments are aggregated, THE Coordinator_Prover SHALL compute [[w'_j]] = ∑_{i∈[M]} [[w'_{i,j}]] using lattice commitment homomorphism

20. WHEN folded value is computed, THE Prover_System SHALL calculate v' = Q_ν(r_ν) · eq(ρ,r_b)^{-1} over Goldilocks field

21. WHEN output is generated, THE Prover_System SHALL produce folded instance-witness pair ((h, v', [[w'_0]],...,[[w'_{t-1}]]); (w'_0,...,w'_{t-1})) with verified norm bounds

22. WHEN communication complexity is analyzed, THE Prover_System SHALL achieve total communication O(M·T·ℓ·n·log M) ring elements where T = N/M is local computation size

23. WHEN computation complexity is analyzed, THE Prover_System SHALL achieve O(T·ℓ·log(T·ℓ)·ν) ring operations per prover using NTT-based polynomial arithmetic

24. WHEN security is verified, THE Prover_System SHALL achieve knowledge soundness error κ_error ≤ dμν/|F| + 2^{-128} where d is polynomial degree and |F| is field size

25. WHEN rejection sampling is integrated, THE Prover_System SHALL apply rejection sampling to final witness w'_j ensuring output distribution is independent of input witnesses {w_{i,j}}_{i∈[M]}

26. WHEN parallel execution is optimized, THE Prover_System SHALL pipeline round k+1 computation with round k communication reducing total latency by factor of 2

27. WHEN fault tolerance is required, THE Prover_System SHALL detect prover failures within timeout period and abort protocol execution returning error state

28. WHEN transcript is maintained, THE Prover_System SHALL record all messages {Q_k(X), r_k}_{k∈[ν]} for Fiat-Shamir transformation and verification

29. WHEN verifier simulation is performed, THE Prover_System SHALL enable verifier to compute v', {e_i}_{i∈[M]}, and [[w'_j]] = ∑_{i∈[M]} e_i · [[w_{i,j}]] without witness access

30. WHEN distributed SumFold completes, THE Prover_System SHALL output folded instance with proof size O(ν·d·n·log q) bits where ν = log M, d is polynomial degree, n = 1024, and q ≈ 2^60


### Requirement 9: Performance Optimizations (Security-Preserving)

**User Story:** As a performance engineer, I want to implement security-preserving optimizations, so that the lattice-based distributed SNARK achieves practical performance while maintaining 128-bit quantum security.

#### Acceptance Criteria

1. WHEN NTT operations are performed, THE Prover_System SHALL use lazy reduction technique delaying modular reductions until necessary using 128-bit accumulators achieving 2-3× speedup with zero security impact

2. WHEN NTT is initialized, THE Prover_System SHALL precompute all twiddle factors ω^i mod q for i ∈ [n] and store in cache-aligned layout (64-byte boundaries) achieving 1.5× speedup with +16 KB memory overhead

3. WHEN polynomial multiplication is performed, THE Prover_System SHALL use negative wrapped convolution (NWC) exploiting X^n + 1 structure reducing NTT size from n to n/2 achieving 2× speedup and 2× memory reduction

4. WHEN gadget decomposition is performed, THE Prover_System SHALL use SIMD vectorization (AVX2 or AVX-512) processing 4-8 coefficients in parallel achieving 4-8× speedup with zero security impact

5. WHEN witness is decomposed at initialization, THE Prover_System SHALL cache decomposed form and reuse across all rounds avoiding repeated decomposition achieving amortized O(1) cost per round

6. WHEN norm computation is required, THE Prover_System SHALL maintain ||w||² incrementally using identity ||w' + α·w||² = ||w'||² + 2α⟨w',w⟩ + α²||w||² achieving 10× speedup over full recomputation

7. WHEN norm must be computed from scratch, THE Prover_System SHALL use SIMD vectorization computing 4-8 squared terms in parallel achieving 4-8× speedup with zero security impact

8. WHEN Gaussian sampling is performed, THE Prover_System SHALL use SIMD vectorization for CDT lookups sampling 4-8 values in parallel achieving 8× speedup with zero security impact

9. WHEN witness slices are transmitted, THE Prover_System SHALL apply incremental compression using coefficient packing (3 bits per limb coefficient), delta encoding, and run-length encoding achieving 3-4× bandwidth reduction

10. WHEN multiple witness slices are sent, THE Prover_System SHALL aggregate into batched messages reducing message count by 2× and TCP/IP overhead by 40 bytes per avoided packet

11. WHEN witness data is stored, THE Prover_System SHALL use cache-oblivious Z-order (Morton order) layout improving spatial locality and reducing cache misses from 40% to 20% achieving 2× speedup

12. WHEN memory is limited, THE Prover_System SHALL process witness in streaming chunks of size C = L2_cache_size / ℓ overlapping I/O with computation achieving 10× memory reduction (1.2 GB vs 12 GB)

13. WHEN witnesses are aggregated, THE Prover_System SHALL use hierarchical tree topology with depth log₂(M) instead of linear aggregation achieving 1.5× speedup and 30% communication reduction

14. WHEN round k+1 can be prepared, THE Prover_System SHALL pipeline computation with round k communication overlapping network I/O with local computation achieving 2× latency reduction

15. WHEN verification checks are performed, THE Prover_System SHALL defer all Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) checks to end of protocol and batch verify achieving 2× speedup in honest case

16. WHEN adaptive base is beneficial, THE Prover_System SHALL use variable decomposition base (b=8 for high-order limbs, b=4 for low-order) reducing ℓ from 30 to 23 limbs achieving 1.3× speedup

17. WHEN polynomial degree can vary, THE Prover_System SHALL use degree d=2 for early rounds and d=3 for final rounds reducing proof size by 25% while maintaining soundness error ≤ 2^{-128}

18. WHEN batch verification is requested, THE Prover_System SHALL verify k proofs simultaneously using random linear combination ∑ᵢ αᵢ·(LHS_i - RHS_i) = 0 achieving 5× speedup with soundness error k·ε

19. WHEN GPU is available, THE Prover_System SHALL optionally offload NTT computations to GPU using CUDA/OpenCL achieving 10-50× speedup for polynomial operations

20. WHEN AVX-512 is available, THE Prover_System SHALL use 512-bit SIMD registers processing 8 × 64-bit elements simultaneously achieving 2× speedup over AVX2 with CPU feature detection and fallback

21. WHEN norm upper bound suffices, THE Prover_System SHALL use triangle inequality ||w'|| ≤ ∑|α_i|·||w_i|| for quick check and compute exact norm only when threshold exceeded reducing exact computations by 80%

22. WHEN rejection sampling iterations are tracked, THE Prover_System SHALL log acceptance rate, average iterations, and maximum iterations enabling performance monitoring and parameter tuning

23. WHEN security level is configurable, THE Prover_System SHALL support ring dimensions n ∈ {512, 1024, 2048} providing 100-bit, 128-bit, and 160-bit quantum security respectively with corresponding performance trade-offs

24. WHEN modulus size is configurable, THE Prover_System SHALL support q ∈ {2^40, 2^60, 2^80} with corresponding decomposition limbs ℓ ∈ {13, 30, 40} enabling performance/security trade-offs

25. WHEN prover count is optimized, THE Prover_System SHALL support dynamic M selection with recommended M = 2^⌊log₂(√N)⌋ for optimal communication/computation balance

26. WHEN combined optimizations are applied, THE Prover_System SHALL achieve target performance of 0.4s prover time (vs 3.1s baseline), 0.5 GB communication (vs 1.9 GB), and 1.2 GB memory (vs 12 GB) while maintaining 128-bit quantum security

27. WHEN optimization level is selected, THE Prover_System SHALL support three tiers: BASELINE (no optimizations), OPTIMIZED (security-preserving optimizations), AGGRESSIVE (includes approximate rejection sampling with 120-bit statistical security)

28. WHEN prefetching is enabled, THE Prover_System SHALL use constant-time software prefetch (_mm_prefetch) for next witness slice k=4 cache lines ahead achieving 1.5× speedup while maintaining side-channel resistance

29. WHEN challenge speculation is enabled, THE Prover_System SHALL precompute for multiple challenge values in parallel and select correct result when challenge arrives trading 2× computation for 1.5× latency reduction

30. WHEN performance profiling is enabled, THE Prover_System SHALL track time spent in NTT operations, decomposition, norm computation, network I/O, and rejection sampling with microsecond precision for bottleneck identification
