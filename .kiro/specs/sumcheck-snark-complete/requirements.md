# Requirements Document: Complete Sum-Check Based SNARK System

## Introduction

This document specifies requirements for implementing a complete, production-ready SNARK system based on the sum-check protocol, following the principles and techniques outlined in "Sum-check Is All You Need: An Opinionated Survey on Fast Provers in SNARK Design" by Justin Thaler. The system will demonstrate that sum-check-based SNARKs, when properly implemented with sophisticated optimizations, represent the fastest and simplest approach to succinct proof generation.

## Glossary

- **SNARK**: Succinct Non-interactive Argument of Knowledge - a cryptographic proof system allowing an untrusted prover to convince a verifier of correct computation
- **Sum-Check Protocol**: An interactive proof protocol that reduces verification of a large sum to evaluation of a polynomial at a single random point
- **PIOP**: Polynomial Interactive Oracle Proof - an information-theoretically secure interactive proof where the prover sends polynomials
- **PCS**: Polynomial Commitment Scheme - cryptographic primitive allowing succinct commitment to polynomials with efficient evaluation proofs
- **Multilinear Extension (MLE)**: The unique multilinear polynomial extending a function from Boolean hypercube to full field
- **Fiat-Shamir Transform**: Technique for converting interactive protocols to non-interactive using cryptographic hash functions
- **GKR Protocol**: Goldwasser-Kalai-Rothblum protocol for verifiable computation using sum-check
- **Batch Evaluation Argument**: Protocol proving multiple polynomial evaluations simultaneously
- **Virtual Polynomial**: Polynomial expressed implicitly as low-degree function of committed data, avoiding explicit commitment
- **Small-Value Preservation**: Property where committed values remain small field elements, accelerating cryptographic operations
- **Sparse Sum-Check**: Sum-check optimization exploiting sparsity where most terms equal zero
- **Prefix-Suffix Decomposition**: Technique splitting variables into chunks to enable streaming proving with controlled memory
- **Read-Write Memory Checking**: Protocol proving correct memory access patterns with both reads and writes
- **zkVM**: Zero-Knowledge Virtual Machine - general-purpose SNARK for proving correct execution of low-level programs
- **Hadamard Product**: Entrywise product of two vectors
- **Schwartz-Zippel Lemma**: Fundamental result bounding probability that non-zero polynomial evaluates to zero at random point
- **Quotienting**: Technique using polynomial division to prove evaluation claims
- **KZG Commitment**: Pairing-based polynomial commitment using structured reference string
- **Bulletproofs/IPA**: Inner Product Argument - transparent polynomial commitment based on discrete logarithm
- **Dory**: Polynomial commitment combining benefits of Bulletproofs and Hyrax with logarithmic verification
- **Twist Protocol**: Memory checking protocol for read-write memory using virtual polynomials
- **Shout Protocol**: Batch evaluation argument using sparse sum-check and one-hot encodings
- **Jolt zkVM**: High-performance zkVM for RISC-V using sum-check-based techniques
- **Pedersen Commitment**: Homomorphic commitment scheme using multi-exponentiation
- **MSM**: Multi-Scalar Multiplication - computing linear combination of group elements
- **One-Hot Encoding**: Vector representation with single 1 and remaining 0s
- **Streaming Prover**: Prover algorithm with controlled memory usage, processing data in passes

## Requirements

### Requirement 1: Foundational Mathematical Primitives

**User Story:** As a SNARK system developer, I want complete implementations of all mathematical primitives required for sum-check based proofs, so that I can build efficient proof systems on solid foundations.

#### Acceptance Criteria

1. WHEN the system initializes finite field operations, THE System SHALL support fields of size between 2^128 and 2^256 bits with configurable field selection
2. WHEN working with multilinear polynomials, THE System SHALL implement the unique multilinear extension for any function f: {0,1}^n → F
3. WHEN computing multilinear extensions of vectors, THE System SHALL use the Lagrange interpolation formula: ã(r) = Σ_{x∈{0,1}^n} a(x) · eq̃(r,x)
4. WHEN evaluating the equality polynomial, THE System SHALL compute eq̃(x,y) = Π_{i=1}^m ((1-x_i)(1-y_i) + x_i·y_i) for inputs in F^m
5. WHEN interpreting vectors as functions, THE System SHALL map vector a ∈ F^N to function a: {0,1}^n → F where N = 2^n using natural bit-string indexing
6. WHEN computing Hadamard products, THE System SHALL implement entrywise multiplication (a ◦ b)_i = a_i · b_i for all vector positions
7. WHEN working with univariate polynomials, THE System SHALL implement low-degree extensions over evaluation domains H ⊆ F
8. WHEN applying the Factor Theorem, THE System SHALL verify that f(a) = 0 if and only if (X - a) divides f(X)
9. WHEN checking polynomial agreement, THE System SHALL apply the bounded agreement theorem: distinct degree-d polynomials agree at most d points
10. WHEN applying Schwartz-Zippel lemma, THE System SHALL bound error probability by d/|S| for degree-d polynomial over domain S
11. WHEN computing total degree, THE System SHALL find maximum sum of variable degrees across all monomials with nonzero coefficients
12. WHEN performing field arithmetic, THE System SHALL treat field multiplication as unit time operation for complexity analysis
13. WHEN working with Boolean hypercube, THE System SHALL represent {0,1}^n as domain for n-bit strings
14. WHEN extending functions to full field, THE System SHALL ensure multilinear extension differs almost everywhere if original functions differ at any point
15. WHEN verifying polynomial equality, THE System SHALL use the fact that multilinear polynomials are uniquely specified by evaluations over {0,1}^n

_Requirements: Core mathematical foundation for all sum-check protocols_

### Requirement 2: Core Sum-Check Protocol Implementation

**User Story:** As a proof system implementer, I want a complete, optimized implementation of the sum-check protocol with all verification checks, so that I can prove large sums efficiently.

#### Acceptance Criteria

1. WHEN initiating sum-check for polynomial g: F^n → F, THE System SHALL accept polynomials with degree at most d in each variable
2. WHEN the prover sends initial claim C_1, THE System SHALL claim C_1 equals Σ_{x∈{0,1}^n} g(x)
3. WHEN executing round i, THE Prover SHALL send univariate polynomial s_i(X) of degree at most d
4. WHEN the prover sends s_i(X), THE System SHALL claim s_i(X) = Σ_{x_{i+1},...,x_n ∈ {0,1}} g(r_1,...,r_{i-1},X,x_{i+1},...,x_n)
5. WHEN verifying round 1, THE Verifier SHALL check that C_1 = s_1(0) + s_1(1)
6. WHEN verifying round i > 1, THE Verifier SHALL check that s_{i-1}(r_{i-1}) = s_i(0) + s_i(1)
7. WHEN the verifier accepts round i, THE Verifier SHALL sample random challenge r_i ← F and send to prover
8. WHEN verifying degree bounds, THE Verifier SHALL reject if any s_i has degree exceeding d
9. WHEN completing round n, THE Verifier SHALL evaluate g(r_1,...,r_n) directly or via oracle query
10. WHEN performing final check, THE Verifier SHALL verify s_n(r_n) = g(r_1,...,r_n)
11. WHEN all checks pass, THE Verifier SHALL accept the proof
12. WHEN any check fails, THE Verifier SHALL reject immediately
13. WHEN the prover makes false claim, THE System SHALL ensure soundness error at most dn/|F|
14. WHEN specifying univariate polynomials, THE System SHALL support both coefficient and evaluation representations
15. WHEN sending degree-d polynomial, THE System SHALL transmit d+1 field elements
16. WHEN computing proof size, THE System SHALL achieve (d+1)n field elements total communication
17. WHEN measuring verifier time, THE System SHALL perform O(dn) field operations across all rounds
18. WHEN N = 2^n is sum size, THE System SHALL achieve logarithmic proof size and verifier time in N
19. WHEN working over 256-bit field with N=2^30 and d=2, THE System SHALL produce proofs of few kilobytes
20. WHEN the prover is honest, THE System SHALL ensure verifier always accepts (perfect completeness)

_Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

### Requirement 3: Dense Sum-Check Prover Optimization

**User Story:** As a performance-focused developer, I want linear-time sum-check proving for dense polynomials that are products of multilinear polynomials, so that I can achieve optimal prover efficiency.

#### Acceptance Criteria

1. WHEN applying sum-check to g(x) = p̃(x) · q̃(x), THE System SHALL handle products of multilinear polynomials efficiently
2. WHEN computing round i evaluations, THE Prover SHALL evaluate g at all points (r_1,...,r_{i-1},t,x_{i+1},...,x_n) for t ∈ {0,1,...,d}
3. WHEN processing round i, THE Prover SHALL perform N/2^i evaluations where N = 2^n
4. WHEN summing across all rounds, THE Prover SHALL achieve O(N + N/2 + N/4 + ... + 1) = O(N) total time
5. WHEN initializing prover state, THE System SHALL store all evaluations of p̃ and q̃ over {0,1}^n in arrays A and B of size N
6. WHEN the verifier sends challenge r_1, THE Prover SHALL update arrays to size N/2 storing evaluations at (r_1, x') for x' ∈ {0,1}^{n-1}
7. WHEN applying multilinear interpolation, THE System SHALL use p̃(r_1,x_2,...,x_n) = (1-r_1)·p̃(0,x_2,...,x_n) + r_1·p̃(1,x_2,...,x_n)
8. WHEN updating array entries, THE Prover SHALL compute A[x'] ← A[0,x'] + r_i·(A[1,x'] - A[0,x'])
9. WHEN updating array entries, THE Prover SHALL compute B[x'] ← B[0,x'] + r_i·(B[1,x'] - B[0,x'])
10. WHEN completing round i, THE Prover SHALL have arrays of size N/2^i ready for next round
11. WHEN processing each round, THE Prover SHALL perform O(N/2^i) field operations in round i
12. WHEN handling products of k multilinear polynomials, THE System SHALL generalize to g(x) = p̃_1(x)·...·p̃_k(x)
13. WHEN working with degree-2 polynomials, THE System SHALL optimize for common case of two-factor products
14. WHEN memory is constrained, THE System SHALL support in-place array updates to minimize memory usage
15. WHEN parallelizing computation, THE System SHALL enable parallel processing of independent array updates

_Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

### Requirement 4: Sparse Sum-Check and Streaming Proving

**User Story:** As a system architect, I want sparse sum-check proving with controlled memory usage, so that I can handle massive sums where most terms are zero without exhausting memory.

#### Acceptance Criteria

1. WHEN the sum has N = 2^n total terms with only T non-zero, THE System SHALL define T as the sparsity
2. WHEN T << N, THE Prover SHALL perform O(T) field operations instead of O(N)
3. WHEN targeting memory usage O(N^{1/c}), THE System SHALL support configurable constant c > 0
4. WHEN c = 2, THE System SHALL achieve O(√N) space usage
5. WHEN g(x) = p̃(x) · q̃(x) with p̃(x) ≠ 0 for T values, THE System SHALL exploit this sparsity structure
6. WHEN q̃(i,j) = f̃(i) · h̃(j) for inputs decomposed as (i,j) ∈ {0,1}^{n/2} × {0,1}^{n/2}, THE System SHALL apply prefix-suffix algorithm
7. WHEN i is the prefix and j is the suffix, THE System SHALL process variables in two stages
8. WHEN initializing Stage 1, THE Prover SHALL create arrays P and Q of size √N = 2^{n/2}
9. WHEN computing P[i], THE System SHALL calculate P[i] = Σ_{j∈{0,1}^{n/2}} p̃(i,j) · h̃(j)
10. WHEN computing Q[i], THE System SHALL set Q[i] = f̃(i)
11. WHEN initializing each stage, THE Prover SHALL make one streaming pass over non-zero terms
12. WHEN Stage 1 initialization completes, THE System SHALL have spent O(T + √N) time
13. WHEN executing first n/2 rounds, THE Prover SHALL apply standard sum-check to P̃(i) · Q̃(i)
14. WHEN Stage 1 completes, THE System SHALL have verifier challenges ⃗r = (r_1,...,r_{n/2})
15. WHEN initializing Stage 2, THE Prover SHALL create new arrays P and Q of size √N
16. WHEN computing Stage 2 arrays, THE System SHALL set P[j] = p̃(⃗r,j) and Q[j] = f̃(⃗r) · h̃(j)
17. WHEN executing final n/2 rounds, THE Prover SHALL apply sum-check to P̃(j) · Q̃(j)
18. WHEN Stage 2 completes, THE System SHALL have processed all n rounds
19. WHEN measuring total prover time, THE System SHALL achieve O(T + √N) for c = 2
20. WHEN generalizing to larger c, THE System SHALL achieve O(T + N^{1/c}) time and O(N^{1/c}) space

_Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2_

### Requirement 5: GKR Protocol for Circuit Evaluation

**User Story:** As a circuit verification developer, I want the GKR protocol with linear-time proving for layered circuits, so that I can verify arithmetic circuit execution efficiently.

#### Acceptance Criteria

1. WHEN verifying layered circuit of depth d, THE System SHALL number layers 1 to d with layer d as outputs
2. WHEN all layers have S = 2^s gates, THE System SHALL handle uniform layer sizes
3. WHEN V_k: {0,1}^s → F maps gate labels to values, THE System SHALL maintain value functions per layer
4. WHEN mult_k(a,b,c): {0,1}^{3s} → {0,1} tests if gates b,c are in-neighbors of gate a, THE System SHALL implement wiring predicate
5. WHEN relating layers, THE System SHALL verify Ṽ_k(r) = Σ_{i,j} m̃ult_k(r,i,j) · Ṽ_{k-1}(i) · Ṽ_{k-1}(j)
6. WHEN the right-hand side is multilinear in r, THE System SHALL ensure polynomial structure
7. WHEN r ∈ {0,1}^s, THE System SHALL verify right-hand side equals left-hand side
8. WHEN applying sum-check to layer k, THE System SHALL compute right-hand side of layer relation
9. WHEN p̃(i,j) = m̃ult_k(r,i,j) and q̃(i,j) = Ṽ_{k-1}(i) · Ṽ_{k-1}(j), THE System SHALL apply prefix-suffix algorithm
10. WHEN m̃ult_k has sparsity at most S, THE System SHALL exploit that only S out of S^2 inputs are non-zero
11. WHEN f̃(i) = Ṽ_{k-1}(i) and h̃(j) = Ṽ_{k-1}(j), THE System SHALL set prefix-suffix factors
12. WHEN processing each layer, THE Prover SHALL run in time linear in number of gates
13. WHEN iterating over all d layers, THE Prover SHALL achieve total time linear in circuit size
14. WHEN circuits have structured wiring, THE System SHALL enable verifier to evaluate m̃ult_k efficiently
15. WHEN wiring is regular, THE Verifier SHALL compute m̃ult_k(r,i,j) in O(log S) time
16. WHEN virtualizing gate values, THE System SHALL avoid committing to intermediate layers
17. WHEN only input layer is committed, THE System SHALL derive all other layers via sum-check
18. WHEN verifier needs Ṽ_k(r), THE System SHALL reduce to evaluating Ṽ_{k-1} at random points via sum-check
19. WHEN reaching input layer, THE System SHALL either have verifier read inputs directly or provide commitment opening
20. WHEN handling multiplication-only circuits, THE System SHALL optimize for this common case

_Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 4.1, 4.2_


### Requirement 6: Polynomial IOPs and Commitment Schemes

**User Story:** As a SNARK architect, I want to understand and implement the two-component structure of modern SNARKs (PIOP + PCS), so that I can build complete proof systems.

#### Acceptance Criteria

1. WHEN constructing a SNARK, THE System SHALL combine a Polynomial IOP with a Polynomial Commitment Scheme
2. WHEN the PIOP first message is sent, THE Prover SHALL send large polynomial encoding the witness
3. WHEN the polynomial encodes witness, THE System SHALL ensure polynomial size is comparable to witness-checking runtime
4. WHEN the verifier queries polynomial, THE System SHALL permit only single evaluation at random point
5. WHEN the PIOP continues after first message, THE Prover and Verifier SHALL run interactive proof showing encoded witness is valid
6. WHEN implementing PCS, THE System SHALL enable prover to succinctly commit to large polynomial
7. WHEN opening commitment, THE Prover SHALL provide short proof that revealed evaluation is consistent with commitment
8. WHEN applying Fiat-Shamir, THE System SHALL render interactive PIOP non-interactive
9. WHEN PCS is itself a PIOP, THE System SHALL recognize it as PIOP wrapped in cryptography
10. WHEN using KZG, THE System SHALL implement quotienting PIOP in the exponent using structured reference string
11. WHEN using Bulletproofs/IPA, THE System SHALL implement sum-check protocol in the exponent
12. WHEN using Dory, THE System SHALL implement sum-check in the exponent with additional structure
13. WHEN PIOPs are univariate-based, THE System SHALL use quotienting techniques
14. WHEN PIOPs are multilinear-based, THE System SHALL use sum-check protocol
15. WHEN pairing PIOPs with PCS, THE System SHALL match types: univariate PIOPs with univariate PCS, multilinear with multilinear
16. WHEN PCS families are categorized, THE System SHALL support KZG variants, group-based transparent schemes, hashing-based schemes, and lattice-based schemes
17. WHEN using KZG variants, THE System SHALL require pairings and trusted setup
18. WHEN using Hyrax/Bulletproofs/Dory, THE System SHALL provide transparent group-based schemes
19. WHEN using FRI/Ligero/Brakedown/WHIR, THE System SHALL implement hashing-based schemes
20. WHEN using lattice-based schemes, THE System SHALL provide post-quantum security with flexible field choice

_Requirements: 1.1, 1.2, 1.3, 2.1, 2.2_

### Requirement 7: Quotienting PIOP for Univariate Polynomials

**User Story:** As a univariate polynomial commitment developer, I want the quotienting PIOP implementation, so that I can prove polynomial evaluations using division.

#### Acceptance Criteria

1. WHEN proving a ◦ b = c for vectors a,b,c ∈ F^N, THE System SHALL verify a_i · b_i = c_i for all i
2. WHEN H = {α_1,...,α_N} ⊆ F is evaluation domain, THE System SHALL use set of size N
3. WHEN computing univariate low-degree extensions, THE System SHALL find unique polynomials â,b̂,ĉ of degree ≤ N-1
4. WHEN â,b̂,ĉ satisfy evaluation conditions, THE System SHALL ensure â(α_i) = a_i, b̂(α_i) = b_i, ĉ(α_i) = c_i for all i
5. WHEN polynomials are committed, THE System SHALL use favorite univariate PCS for â,b̂,ĉ
6. WHEN Z_H(X) = Π_{i=1}^N (X - α_i) is vanishing polynomial, THE System SHALL compute polynomial vanishing on H
7. WHEN applying Factor Theorem, THE System SHALL verify â(α_i)·b̂(α_i) = ĉ(α_i) for all α_i ∈ H iff â(X)·b̂(X) - ĉ(X) is divisible by Z_H(X)
8. WHEN the prover computes quotient, THE Prover SHALL send q(X) satisfying â(X)·b̂(X) - ĉ(X) = q(X)·Z_H(X)
9. WHEN the verifier samples challenge, THE Verifier SHALL choose r ← F uniformly at random
10. WHEN verifying at random point, THE Verifier SHALL check â(r)·b̂(r) - ĉ(r) = q(r)·Z_H(r)
11. WHEN H is N-th roots of unity, THE System SHALL use Z_H(X) = X^N - 1
12. WHEN computing Z_H(r), THE Verifier SHALL evaluate in O(log N) time for roots of unity
13. WHEN obtaining evaluations, THE Verifier SHALL get â(r), b̂(r), ĉ(r), q(r) from polynomial commitments
14. WHEN the equation is false, THE System SHALL ensure soundness error at most d/|F| where d = O(N)
15. WHEN applying bounded agreement theorem, THE System SHALL bound probability that false equation holds at random point

_Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 6.1_

### Requirement 8: Sum-Check for Proving Product Constraints

**User Story:** As a constraint system developer, I want sum-check based proving of product constraints a ◦ b = c, so that I can verify element-wise products efficiently.

#### Acceptance Criteria

1. WHEN proving a ◦ b = c for vectors a,b,c ∈ F^N with N = 2^n, THE System SHALL verify all entries satisfy product constraint
2. WHEN computing multilinear extensions, THE System SHALL define ã,b̃,c̃: F^n → F
3. WHEN defining constraint polynomial, THE System SHALL set g(x) = ã(x)·b̃(x) - c̃(x)
4. WHEN goal is g(x) = 0 for all x ∈ {0,1}^n, THE System SHALL verify constraint satisfaction
5. WHEN applying sum-check, THE System SHALL compute Σ_{x∈{0,1}^n} ẽq(r,x)·g(x)
6. WHEN r ∈ F^n is chosen randomly by verifier, THE System SHALL use random linear combination
7. WHEN the sum equals 0, THE Verifier SHALL accept if g(x) = 0 for all x ∈ {0,1}^n
8. WHEN g(x) ≠ 0 for even one x, THE System SHALL ensure sum is unlikely to equal 0
9. WHEN defining q̃(r), THE System SHALL set q̃(r) = Σ_{x∈{0,1}^n} ẽq(r,x)·g(x)
10. WHEN q̃ is multilinear in r, THE System SHALL recognize it as multilinear polynomial
11. WHEN r ∈ {0,1}^n, THE System SHALL verify q̃(r) = g(r) since ẽq(r,x) = 1 iff x = r
12. WHEN g(x) = 0 for all x, THE System SHALL ensure q̃ is zero polynomial
13. WHEN g(x) ≠ 0 for some x, THE System SHALL ensure q̃ is non-zero multilinear polynomial
14. WHEN applying Schwartz-Zippel to q̃, THE System SHALL bound error probability by n/|F|
15. WHEN random r ∈ F^n is chosen, THE System SHALL ensure non-zero n-variate multilinear polynomial evaluates to 0 with probability ≤ n/|F|

_Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_

### Requirement 9: Shout Batch Evaluation Argument for Read-Only Memory

**User Story:** As a lookup argument developer, I want the Shout protocol for batch evaluation with sparse access patterns using one-hot addressing, so that I can prove many function evaluations efficiently with minimal commitment costs.

#### Acceptance Criteria

1. WHEN proving batch evaluation, THE Prover SHALL claim z_i = f(y_i) for inputs y_1,...,y_T ∈ {0,1}^ℓ
2. WHEN f: {0,1}^ℓ → F is known function, THE Verifier SHALL know function definition
3. WHEN rv ∈ F^T is vector of claimed outputs, THE System SHALL define rv = (z_1,...,z_T)
4. WHEN ra ∈ {0,1}^{2^ℓ × T} is access matrix, THE System SHALL set ra(x,j) = 1 iff x = y_j
5. WHEN each column j is one-hot vector, THE System SHALL ensure exactly one entry equals 1
6. WHEN batch evaluation claim is expressed, THE System SHALL verify rv(j) = Σ_{x∈{0,1}^ℓ} ra(x,j)·f(x) for all j
7. WHEN right-hand side sums over all possible x, THE System SHALL test if x = y_j via ra(x,j)
8. WHEN x = y_j, THE System SHALL output f(x)
9. WHEN computing multilinear extensions, THE System SHALL define r̃a and r̃v for access matrix and read values
10. WHEN applying Schwartz-Zippel, THE System SHALL verify constraint at random r' ∈ F^{log T}
11. WHEN checking single random point, THE System SHALL ensure soundness error log(T)/|F|
12. WHEN applying sum-check, THE System SHALL prove r̃v(r') = Σ_{x∈{0,1}^ℓ} r̃a(x,r')·f̃(x)
13. WHEN f̃ is known to verifier, THE System SHALL assume fast evaluation at random point r ∈ F^ℓ
14. WHEN r̃a is committed, THE Prover SHALL provide commitment before sum-check
15. WHEN r̃v can be virtual, THE System SHALL avoid committing to read values vector
16. WHEN correct rv is implied by r̃a and f, THE System SHALL express r̃v(r') via sum-check
17. WHEN sum has 2^ℓ terms, THE System SHALL handle large domain sizes (e.g., ℓ = 128)
18. WHEN r̃a(x,r') is sparse, THE System SHALL exploit that only T out of 2^ℓ inputs are non-zero
19. WHEN f̃ is highly structured, THE System SHALL apply prefix-suffix sum-check algorithm
20. WHEN implementing Shout prover, THE System SHALL achieve time T and small space
21. WHEN proving access matrix well-formed, THE System SHALL verify ra(x,j) ∈ {0,1} for all (x,j)
22. WHEN proving one-hot property, THE System SHALL verify exactly one entry per column equals 1
23. WHEN applying additional sum-checks, THE System SHALL use prefix-suffix algorithm for well-formedness checks
24. WHEN f: {0,1}^ℓ → F with K = 2^ℓ, THE Prover SHALL perform O(cK^{1/c} + cT) field operations for any constant c > 0
25. WHEN K^{1/c} ≤ T, THE System SHALL achieve O(cT) total cost
26. WHEN K = 2^128 and T = 2^30, THE System SHALL use c = 4 or 8 for optimal performance
27. WHEN amortizing over T evaluations, THE System SHALL achieve O(c) field operations per evaluation
28. WHEN using parameter d = 1, THE Prover SHALL commit to K-1 0s and single 1 per read operation
29. WHEN using parameter d > 1, THE Prover SHALL commit to d·K^{1/d} values per read operation
30. WHEN K = 32 (RISC-V registers), THE System SHALL use d = 1 for optimal performance
31. WHEN K = 2^20 (4 MB memory), THE System SHALL use d = 4 for controlled commitment key size
32. WHEN memory is read-only, THE System SHALL use fixed lookup table f
33. WHEN lookup table is gigantic (K = 2^64), THE System SHALL handle without materializing full table
34. WHEN lookup table is structured, THE System SHALL exploit structure for sublinear prover time in K
35. WHEN applying sparse-dense sum-check, THE System SHALL achieve O(C·T) time for K = T^C
36. WHEN Shout is used in zkVMs, THE System SHALL prove correct instruction execution via lookups
37. WHEN Shout is used for program bytecode, THE System SHALL prove correct fetch and decode
38. WHEN Shout outperforms Lasso, THE System SHALL achieve over 10× speedup for logarithmic proof length
39. WHEN Shout outperforms LogUpGKR, THE System SHALL achieve 2-4× speedup even with larger proofs
40. WHEN Shout is combined with elliptic curve commitments, THE System SHALL exploit free commitment to 0s

_Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 4.1, 4.2, 4.3, 10.1, 11A.1_

### Requirement 10: Virtual Polynomials for Commitment Reduction

**User Story:** As a commitment optimization specialist, I want virtual polynomial techniques, so that I can avoid committing to large or expensive polynomials.

#### Acceptance Criteria

1. WHEN avoiding direct commitment to polynomial a, THE System SHALL commit to smaller object b such that a is low-degree function of b
2. WHEN committing to a is slow, THE System SHALL use virtualization to reduce commitment costs
3. WHEN commitment key for a is enormous, THE System SHALL virtualize to avoid large keys
4. WHEN evaluation proofs for a are expensive, THE System SHALL express a in terms of committed b
5. WHEN each a_i is low-degree function of b, THE System SHALL enable sum-check to reason about a as if committed
6. WHEN virtualizing in GKR protocol, THE System SHALL treat gate values at each layer as virtual polynomials
7. WHEN only input layer is committed in GKR, THE System SHALL derive all other layers virtually
8. WHEN virtualizing r̃v in Shout, THE System SHALL avoid explicit commitment to read values vector
9. WHEN correct rv is implied by r̃a and f, THE System SHALL express r̃v(r') via sum-check as Σ_{x∈{0,1}^ℓ} r̃a(x,r')·f̃(x)
10. WHEN verifier needs r̃v(r'), THE System SHALL apply sum-check to right-hand side
11. WHEN sum-check completes, THE System SHALL reduce to evaluating r̃a(r,r') and f̃(r) for random r
12. WHEN f̃ is public and fast to evaluate, THE Verifier SHALL compute f̃(r) directly
13. WHEN r̃a is committed, THE Prover SHALL provide r̃a(r,r') with evaluation proof
14. WHEN virtualizing r̃a in Shout, THE System SHALL avoid materializing full K × T matrix
15. WHEN K = 2^ℓ is memory size, THE System SHALL break address k into d chunks of ℓ' = log(K)/d bits
16. WHEN k = (k_1,...,k_d) with k_i ∈ {0,1}^{ℓ'}, THE System SHALL decompose address into chunks
17. WHEN defining r̃a_i(k_i,j) as one-hot for i-th chunk, THE System SHALL commit to chunk-wise one-hot vectors
18. WHEN expressing full access matrix, THE System SHALL define ra(k,j) = Π_{i=1}^d ra_i(k_i,j)
19. WHEN r = (r_1,...,r_d) ∈ F^{log(K)/d}^d, THE System SHALL verify r̃a(r,r') = Σ_{j'∈{0,1}^{log T}} ẽq(r',j')·Π_{i=1}^d r̃a_i(r_i,j')
20. WHEN both sides are multilinear in (r_1,...,r_d,r'), THE System SHALL ensure polynomial equality
21. WHEN variables are from {0,1}, THE System SHALL verify equality by definition of ẽq and product structure
22. WHEN multilinear extension is unique, THE System SHALL ensure identity holds over all of F^{log K + log T}
23. WHEN r̃a is not committed directly, THE System SHALL let sum-check query it as if committed
24. WHEN reducing to queries on r̃a_i, THE Verifier SHALL query committed chunk matrices
25. WHEN avoiding massive K × T matrix, THE Prover SHALL commit to d matrices of size K^{1/d} × T each

_Requirements: 2.1, 2.2, 2.3, 4.1, 4.2, 4.3, 9.1, 9.2_

### Requirement 11: Twist Read-Write Memory Checking via One-Hot Addressing and Increments

**User Story:** As a memory consistency developer, I want the Twist protocol using one-hot addressing and increments for mutable memory with reads and writes, so that I can prove correct memory access patterns over time with minimal commitment costs and locality-aware performance.

#### Acceptance Criteria

1. WHEN proving read-write memory, THE Prover SHALL execute T operations over array of size K
2. WHEN at time step j ∈ {0,1}^{log T}, THE System SHALL have both read and write operations
3. WHEN read logically occurs first, THE System SHALL process read before write at each step
4. WHEN defining read address via one-hot encoding, THE System SHALL encode ra(·,j) as one-hot vector in {0,1}^K with exactly one entry equal to 1
5. WHEN defining write address via one-hot encoding, THE System SHALL encode wa(·,j) as one-hot vector in {0,1}^K with exactly one entry equal to 1
6. WHEN defining write value, THE System SHALL set wv(j) as value written to cell selected by wa(·,j)
7. WHEN defining read value, THE System SHALL set rv(j) as value returned from cell selected by ra(·,j)
8. WHEN computing multilinear extensions, THE System SHALL define r̃a, w̃a for read and write addresses
9. WHEN computing value extensions, THE System SHALL define r̃v, w̃v for read and write values
10. WHEN proving correctness, THE System SHALL verify each read returns value most recently written to same cell
11. WHEN memory is static in Shout, THE System SHALL use fixed function f(k) for cell k
12. WHEN memory is mutable in Twist, THE System SHALL use dynamic function f(k,j) for cell k at time j
13. WHEN expressing read correctness, THE System SHALL verify r̃v(r) = Σ_{k∈{0,1}^{log K}, j∈{0,1}^{log T}} ẽq(r,j)·r̃a(k,j)·f̃(k,j)
14. WHEN ẽq(r,j) selects time step, THE System SHALL use equality polynomial for time selection
15. WHEN r̃a(k,j) selects memory cell, THE System SHALL use one-hot encoding for cell selection
16. WHEN avoiding commitment to f̃(k,j), THE System SHALL virtualize full K × T value table
17. WHEN defining increment, THE System SHALL set Inc(j) = wv(j) - Σ_k wa(k,j)·f(k,j)
18. WHEN Inc(j) represents change, THE System SHALL compute difference between new and current values
19. WHEN committing to increments instead of full values, THE Prover SHALL commit to only T non-zero values instead of K·T values
20. WHEN at most one register is written per cycle, THE System SHALL exploit that only T increments are non-zero
21. WHEN defining less-than predicate, THE System SHALL use L̃T(j',j) as multilinear extension of j' < j
22. WHEN verifier evaluates L̃T(r,r'), THE Verifier SHALL compute in O(log T) field operations
23. WHEN expressing cell value at time j, THE System SHALL define f̃(k,j) = Σ_{j'∈{0,1}^{log T}} w̃a(k,j')·Ĩnc(j')·L̃T(j',j)
24. WHEN virtualizing w̃v, THE System SHALL express w̃v(j) = Σ_{k∈{0,1}^{log K}} w̃a(k,j)·(f̃(k,j) + Ĩnc(j))
25. WHEN new value equals old plus increment, THE System SHALL verify write value consistency
26. WHEN committing only to w̃a and Ĩnc, THE Prover SHALL avoid committing to full memory table
27. WHEN proving read values correct, THE System SHALL use Shout-style sum-check with r̃v(r) = Σ_{j,k} ẽq(r,j)·r̃a(k,j)·f̃(k,j)
28. WHEN f̃(k,j) is virtual polynomial, THE System SHALL define via increment aggregation
29. WHEN proving memory consistency, THE System SHALL achieve O(T log K) field operations in worst case
30. WHEN memory accesses exhibit locality, THE Prover SHALL achieve work growing with locality measure rather than log K
31. WHEN read or write operation accesses cell accessed at most 2^i time steps prior, THE Prover SHALL perform only O(i) field multiplications
32. WHEN binding time variables first, THE System SHALL enable temporally-close accesses to same memory cell to quickly coalesce
33. WHEN sparsity falls quickly round-over-round, THE Prover SHALL benefit from locality of memory access
34. WHEN prover runtime in each round grows with non-zeros, THE System SHALL achieve faster performance for local access patterns
35. WHEN applying to small memories (e.g., K=32 registers), THE System SHALL be especially efficient
36. WHEN proving large memory accesses, THE System SHALL remain small fraction of total prover time in applications like Jolt
37. WHEN using elliptic curve commitments, THE System SHALL exploit that committing to 0s is free
38. WHEN committing to 1s, THE Prover SHALL perform one group operation per committed 1
39. WHEN using parameter d ≥ 1, THE Prover SHALL commit to roughly d·K^{1/d} 0s per read or write operation
40. WHEN using parameter d ≥ 1, THE Prover SHALL commit to d 1s per read or write operation

_Requirements: 2.1, 2.2, 2.3, 9.1, 9.2, 10.1, 10.2_

### Requirement 11A: One-Hot Addressing Method and Tensor Product Decomposition

**User Story:** As a memory checking protocol designer, I want the method of one-hot addressing with tensor product decomposition, so that I can minimize commitment costs and control memory overhead for arbitrary memory sizes.

#### Acceptance Criteria

1. WHEN memory addresses are specified in one-hot form, THE System SHALL represent each address as unit vector in {0,1}^K ⊆ F^K
2. WHEN address ℓ is accessed, THE System SHALL use ℓ-th unit vector e_ℓ ∈ {0,1}^K
3. WHEN one-hot encoding is used, THE System SHALL reduce correctness of reads and writes to rank-one constraint systems
4. WHEN constraint systems are very large, THE System SHALL handle K·T witness variables for T operations into memory of size K
5. WHEN constraint systems are highly sparse, THE System SHALL exploit that only about T variables are non-zero
6. WHEN sum-check prover is applied, THE System SHALL run in roughly O(K + T) time instead of O(K·T) time
7. WHEN prover does not pay for 0-variables, THE System SHALL achieve linear-time proving in number of non-zeros
8. WHEN using elliptic curve commitments, THE Prover SHALL not pay for committed 0s
9. WHEN committing to 0s is free, THE System SHALL exploit that any i where v_i = 0 does not affect commitment
10. WHEN committing to 1s, THE Prover SHALL perform one group operation per committed 1
11. WHEN values are small (in {0,1,...,2^32-1}), THE System SHALL commit faster than arbitrary field elements
12. WHEN using parameter d > 1, THE System SHALL express one-hot vector as tensor product of d smaller one-hot vectors
13. WHEN each smaller vector has length K^{1/d}, THE System SHALL decompose K-length vector into d components
14. WHEN using tensor product decomposition, THE Prover SHALL commit to d·K^{1/d} values instead of K values per address
15. WHEN d is larger, THE System SHALL commit vastly fewer 0s but slightly more 1s
16. WHEN d is larger, THE System SHALL keep commitment key size bounded
17. WHEN d is larger, THE System SHALL increase prover work outside of commitments
18. WHEN d is larger, THE System SHALL increase proof size linearly with d
19. WHEN choosing d, THE System SHALL set as small as possible subject to commitment key not being too large
20. WHEN K is in millions or billions, THE System SHALL use d ≥ 2
21. WHEN using elliptic curve commitments, THE System SHALL set d between 1 and 4 for practical memory sizes
22. WHEN using binary-field hashing commitments, THE System SHALL set d between 1 and 16 for practical memory sizes
23. WHEN larger memories are used, THE System SHALL necessitate larger values of d
24. WHEN constraints change from rank-1 to rank-d, THE System SHALL handle higher-complexity constraints
25. WHEN K = 32 (RISC-V registers), THE System SHALL use d = 1 for optimal performance
26. WHEN K = 2^20 (4 MB memory), THE System SHALL use d = 4 with 4·2^5 = 128 committed values per operation
27. WHEN using hashing-based commitments over binary fields, THE System SHALL pack multiple values into single GF(2^128) element
28. WHEN packing is used, THE System SHALL achieve 128-fold reduction in committed field elements
29. WHEN 128 values in {0,1} are packed, THE System SHALL fit into single GF(2^128) element
30. WHEN commitment key is structured, THE System SHALL generate via trusted setup with size limitations

_Requirements: 1.1, 1.2, 2.1, 2.2, 9.1, 10.1, 11.1_

### Requirement 11B: Sparse Sum-Check for Memory Checking Constraints

**User Story:** As a sparse constraint system developer, I want sparse sum-check proving for memory checking constraints, so that I can handle massive constraint systems while only paying for non-zero terms.

#### Acceptance Criteria

1. WHEN constraint systems have K·T witness variables, THE System SHALL recognize these as very large systems
2. WHEN only T out of K·T variables are non-zero, THE System SHALL define T as sparsity
3. WHEN T << K·T, THE Prover SHALL perform O(T) field operations instead of O(K·T)
4. WHEN sum-check is applied to sparse systems, THE System SHALL not pay for 0-variables
5. WHEN processing each round, THE Prover SHALL work only with non-zero terms
6. WHEN arrays are updated in-place, THE System SHALL minimize memory allocations
7. WHEN sparsity is exploited, THE System SHALL achieve prover time proportional to number of non-zeros
8. WHEN very large but structured read-only memories are used, THE System SHALL apply sparse-dense sum-check protocol
9. WHEN K = T^C with C ≥ 1, THE System SHALL implement Shout's sum-check prover in time O(C·T) << O(K + T)
10. WHEN generalizing sparse-dense sum-check, THE System SHALL extend from Generalized-Lasso protocol
11. WHEN constraint systems are rank-one, THE System SHALL verify simple product constraints
12. WHEN constraint systems are rank-d, THE System SHALL verify d-way product constraints
13. WHEN one-hot vectors are tensor products, THE System SHALL handle decomposed address representations
14. WHEN proving Booleanity, THE System SHALL verify all address components are in {0,1}
15. WHEN proving one-hot property, THE System SHALL verify exactly one entry per address equals 1
16. WHEN applying prefix-suffix algorithm, THE System SHALL use for well-formedness checks
17. WHEN memory operations are processed, THE System SHALL maintain sparsity throughout protocol
18. WHEN round-over-round updates occur, THE System SHALL preserve sparse structure
19. WHEN binding variables, THE System SHALL choose order to maximize sparsity reduction
20. WHEN time variables are bound first, THE System SHALL enable locality-aware performance
21. WHEN memory variables are bound first, THE System SHALL optimize for different access patterns
22. WHEN prover commits to sparse vectors, THE System SHALL use commitment schemes optimized for sparsity
23. WHEN evaluation proofs are generated, THE System SHALL leverage sparsity in committed polynomials
24. WHEN virtual polynomials are used, THE System SHALL avoid committing to large sparse polynomials
25. WHEN sum-check reduces to evaluation queries, THE System SHALL query only committed polynomials
26. WHEN verifier needs polynomial evaluations, THE System SHALL provide via commitment opening proofs
27. WHEN multiple sum-checks are composed, THE System SHALL maintain sparsity across composition
28. WHEN proving correctness of memory operations, THE System SHALL combine multiple sparse sum-checks
29. WHEN total prover time is measured, THE System SHALL achieve O(K + T) for small memories
30. WHEN total prover time is measured, THE System SHALL achieve O(C·T) for gigantic structured memories

_Requirements: 2.1, 2.2, 2.3, 4.1, 4.2, 9.1, 10.1, 11.1_

### Requirement 11C: Virtual Polynomials for Address and Value Representations

**User Story:** As a commitment optimization specialist, I want virtual polynomial techniques for address and value representations, so that I can minimize what the prover commits to while maintaining verifier access.

#### Acceptance Criteria

1. WHEN addresses are naturally specified via single field element, THE System SHALL support raf and waf vectors
2. WHEN zkVMs specify addresses via single field element, THE System SHALL provide verifier access to raf and waf
3. WHEN verifier needs to evaluate raf(r) and waf(r), THE System SHALL enable evaluation at random points
4. WHEN raf and waf are not committed, THE System SHALL treat as virtual polynomials
5. WHEN virtual polynomials are evaluated, THE Prover SHALL provide requested evaluation with correctness proof
6. WHEN expressing raf and waf evaluations, THE System SHALL relate to committed ra and wa via sum-check
7. WHEN sum-check reduces evaluation task, THE System SHALL transform raf(r) query to ra(r') query
8. WHEN ra and wa are committed, THE System SHALL obtain evaluations directly from commitments
9. WHEN read values rv can be virtual, THE System SHALL avoid committing to rv polynomial
10. WHEN rv is fully determined by writes and read-addresses, THE System SHALL derive implicitly
11. WHEN verifier needs rv(r) at random point, THE System SHALL use sum-check to compute evaluation
12. WHEN sum-check computes rv(r), THE System SHALL reduce to evaluating committed polynomials
13. WHEN increments are committed instead of full values, THE System SHALL virtualize full memory value table
14. WHEN f(k,j) represents cell value at time j, THE System SHALL express via increment aggregation
15. WHEN f(k,j) = Σ_{j'} wa(k,j')·Inc(j')·LT(j',j), THE System SHALL define virtual polynomial
16. WHEN verifier needs f(k,j) evaluation, THE System SHALL compute via sum-check over increments
17. WHEN write values wv can be virtual, THE System SHALL express wv(j) = Σ_k wa(k,j)·(f(k,j) + Inc(j))
18. WHEN virtual polynomial is low-degree function of committed data, THE System SHALL enable sum-check reasoning
19. WHEN avoiding direct commitment to large polynomials, THE System SHALL reduce commitment costs
20. WHEN commitment key would be enormous, THE System SHALL virtualize to avoid large keys
21. WHEN evaluation proofs would be expensive, THE System SHALL express in terms of cheaper committed polynomials
22. WHEN multiple virtual polynomials are composed, THE System SHALL chain sum-check reductions
23. WHEN final evaluation queries reach committed polynomials, THE System SHALL use commitment opening proofs
24. WHEN virtual polynomials preserve small values, THE System SHALL maintain small-value preservation property
25. WHEN virtual polynomials are structured, THE System SHALL exploit structure for fast evaluation
26. WHEN verifier evaluation time is bounded, THE System SHALL ensure O(log K + log T) time for virtual polynomial queries
27. WHEN prover provides virtual polynomial evaluations, THE System SHALL prove correctness via sum-check
28. WHEN soundness is maintained, THE System SHALL ensure virtual polynomials cannot be chosen maliciously
29. WHEN completeness is maintained, THE System SHALL ensure honest prover can always provide correct evaluations
30. WHEN comparing to direct commitment, THE System SHALL achieve 4× or greater reduction in commitment costs

_Requirements: 2.1, 2.2, 9.1, 10.1, 10.2, 11.1_

### Requirement 11D: Comparison with Offline Memory Checking and Grand Products

**User Story:** As a memory checking protocol analyst, I want to understand how one-hot addressing compares to offline memory checking via grand products, so that I can appreciate the performance improvements and design differences.

#### Acceptance Criteria

1. WHEN offline memory checking is used, THE System SHALL reduce to proving two vectors are permutations
2. WHEN permutation checking uses Lipton's trick, THE Verifier SHALL pick random r and verify Π_i(a_i - r) = Π_i(b_i - r)
3. WHEN grand product arguments are invoked, THE System SHALL prove product of many committed values equals claimed result
4. WHEN Spice is used for read/write memory, THE Prover SHALL commit to 5 values per read operation
5. WHEN Spice commits to address, value, timestamp, THE System SHALL include two additional range check values
6. WHEN Spice uses Thaler's grand product argument, THE Prover SHALL perform about 40 field operations per read
7. WHEN Spice uses Quarks grand product argument, THE Prover SHALL commit to 6 random field elements per operation
8. WHEN committing to random field elements is expensive, THE System SHALL recognize cost equivalent to over 500 field operations
9. WHEN Spice proof size is O(log^2 n) with Thaler, THE System SHALL achieve logarithmic squared proof size
10. WHEN Spice proof size is O(log n) with Quarks, THE System SHALL achieve logarithmic proof size with higher prover cost
11. WHEN Lasso is used for read-only memory, THE Prover SHALL commit to 3T + K small values
12. WHEN Lasso performs field operations, THE Prover SHALL execute about 12T + 12K field operations
13. WHEN LogUpGKR is used, THE Prover SHALL commit to 2T + K small values
14. WHEN LogUpGKR uses grand sum of rationals, THE Prover SHALL perform about twice as many field operations as Lasso
15. WHEN summing rationals a/b + c/d, THE System SHALL require three products: a·d, b·c, and b·d
16. WHEN Twist and Shout avoid grand products, THE System SHALL not invoke grand product or grand sum arguments
17. WHEN Twist and Shout embrace sparsity, THE System SHALL commit directly to sparse representations
18. WHEN Twist and Shout verify using sparse sum-checks, THE System SHALL achieve prover cost scaling with non-zeros
19. WHEN Twist and Shout are over 10× faster, THE System SHALL outperform state-of-the-art with similar proof length
20. WHEN Twist and Shout are 2-4× faster, THE System SHALL outperform even with larger proofs allowed for baselines
21. WHEN offline memory checking requires re-sorting, THE Prover SHALL commit to sorted copy of trace
22. WHEN re-sorting is incompatible with streaming, THE System SHALL note trace may be too large for memory
23. WHEN partial products are committed, THE System SHALL lose small-value preservation property
24. WHEN Twist and Shout minimize prover work, THE System SHALL optimize at both PCS and PIOP layers
25. WHEN Twist and Shout are compatible with streaming, THE System SHALL avoid relying on recursion
26. WHEN Twist and Shout match real CPU cost profiles, THE System SHALL be faster for small memories than large ones
27. WHEN Twist and Shout benefit from locality, THE System SHALL align with real CPU memory access patterns
28. WHEN compiler optimizations for real CPUs are used, THE System SHALL also benefit zkVM provers using Twist and Shout
29. WHEN Twist and Shout are simpler, THE System SHALL have fewer protocol components than offline memory checking
30. WHEN Twist and Shout achieve better performance, THE System SHALL demonstrate superiority across all practical memory sizes

_Requirements: 2.1, 2.2, 9.1, 10.1, 11.1, 17.1_

### Requirement 12: KZG Polynomial Commitment Scheme

**User Story:** As a pairing-based cryptography developer, I want KZG commitments implementing quotienting in the exponent, so that I can achieve constant-size commitments and proofs.

#### Acceptance Criteria

1. WHEN using multiplicative group notation, THE System SHALL write group elements as powers of generator g
2. WHEN structured reference string is {g^{τ^i}}_{i=0}^{N-1}, THE System SHALL use "powers of τ" SRS
3. WHEN generating SRS via ceremony, THE System SHALL enable many parties to contribute randomness
4. WHEN no entity can reconstruct τ, THE System SHALL ensure security unless all ceremony participants collude
5. WHEN p(X) is univariate polynomial of degree ≤ N-1, THE Prover SHALL commit to p
6. WHEN computing commitment, THE Prover SHALL compute cm(p) = g^{p(τ)}
7. WHEN τ is unknown, THE Prover SHALL compute g^{p(τ)} using SRS
8. WHEN p(X) = Σ_{i=0}^{N-1} c_i X^i, THE System SHALL express polynomial in monomial basis
9. WHEN computing commitment from coefficients, THE System SHALL compute g^{p(τ)} = Π_{i=0}^{N-1} (g^{τ^i})^{c_i}
10. WHEN opening commitment at point r ∈ F, THE Prover SHALL send claimed evaluation y = p(r)
11. WHEN constructing quotient polynomial, THE Prover SHALL compute q(X) = (p(X) - y)/(X - r)
12. WHEN p(r) = y, THE System SHALL ensure p(X) - y is divisible by X - r
13. WHEN quotient has degree ≤ N-2, THE System SHALL verify degree bound
14. WHEN computing quotient commitment, THE Prover SHALL compute g^{q(τ)} from SRS
15. WHEN verifier checks evaluation, THE Verifier SHALL verify p(τ) - y = q(τ)·(τ - r)
16. WHEN using symmetric pairings, THE System SHALL use bilinear map e: G × G → G_T
17. WHEN pairing satisfies bilinearity, THE System SHALL ensure e(g^a, g^b) = e(g,g)^{ab}
18. WHEN checking multiplicative relations, THE Verifier SHALL test exponent relations without learning them
19. WHEN verifying ab = c given g^a, g^b, g^c, THE Verifier SHALL check e(g^a, g^b) = e(g, g^c)
20. WHEN performing KZG check, THE Verifier SHALL verify e(g^{p(τ)}·g^{-y}, g) = e(g^{q(τ)}, g^{τ-r})
21. WHEN check passes, THE System SHALL confirm p(τ) - y = q(τ)·(τ - r) using only group elements
22. WHEN committing is fast, THE System SHALL exploit sparsity: zero coefficients don't affect commitment time
23. WHEN coefficients are small, THE System SHALL achieve faster commitment even for non-zero coefficients
24. WHEN computing evaluation proof, THE System SHALL commit to quotient polynomial q(X) = (p(X)-y)/(X-r)
25. WHEN p is sparse with small coefficients, THE System SHALL note q will not preserve these properties
26. WHEN quotienting destroys sparsity, THE System SHALL recognize quotient polynomials are expensive to commit
27. WHEN quotienting destroys small values, THE System SHALL note evaluation proofs lose small-value preservation
28. WHEN commitment is single group element, THE System SHALL achieve constant-size commitments
29. WHEN evaluation proof is single group element, THE System SHALL achieve constant-size proofs
30. WHEN verifier uses two pairings, THE System SHALL achieve constant-time verification

_Requirements: 1.1, 1.2, 6.1, 6.2, 7.1_


### Requirement 13: Bulletproofs/IPA as Homomorphic Sum-Check

**User Story:** As a transparent commitment scheme developer, I want Bulletproofs/IPA implementing sum-check homomorphically, so that I can achieve commitments without trusted setup.

#### Acceptance Criteria

1. WHEN using additive group notation, THE System SHALL write Pedersen commitment as Σ_{i=1}^N u_i·g_i
2. WHEN ⟨u,g⟩ denotes inner product, THE System SHALL abbreviate Σ_{i=1}^N u_i·g_i as ⟨u,g⟩
3. WHEN u_i·g_i is scalar multiplication, THE System SHALL compute group element scaled by field element
4. WHEN proving knowledge of preimage, THE Prover SHALL convince verifier it knows u = (u_1,...,u_N) such that C = ⟨u,g⟩
5. WHEN g = (g_1,...,g_N) is vector of random group elements, THE System SHALL use random commitment key
6. WHEN Bulletproofs commitment is Pedersen commitment, THE System SHALL commit to coefficient vector u
7. WHEN u represents polynomial coefficients, THE System SHALL interpret u as coefficient vector of p(X)
8. WHEN proving evaluation, THE Prover SHALL prove it knows u such that ⟨u,g⟩ = C and ⟨u,⃗r⟩ = y
9. WHEN ⃗r = (1,r,r^2,...,r^{N-1}) is evaluation vector, THE System SHALL use powers of evaluation point
10. WHEN y = p(r) is claimed evaluation, THE System SHALL verify polynomial evaluation
11. WHEN reducing to inner products, THE System SHALL prove knowledge of u satisfying two inner product constraints
12. WHEN focusing on ⟨u,g⟩ = C, THE System SHALL capture core of protocol
13. WHEN h is fixed group element, THE System SHALL use base for discrete logarithms
14. WHEN g_i = z_i·h for unknown z_i, THE System SHALL have commitment key with hidden discrete logs
15. WHEN discrete logarithm problem is hard, THE System SHALL ensure z_i are unknown to everyone including prover
16. WHEN prover knows g_i but not z_i, THE System SHALL work with group elements only
17. WHEN N = 2^n, THE System SHALL apply sum-check to compute ⟨u,z⟩ = Σ_{x∈{0,1}^n} ũ(x)·z̃(x)
18. WHEN in round i, THE Prover SHALL send s_i(X) = Σ_{x'∈{0,1}^{n-i}} ũ(r_1,...,r_{i-1},X,x')·z̃(r_1,...,r_{i-1},X,x')
19. WHEN s_i(X) = a + bX + cX^2, THE System SHALL represent degree-two polynomial by coefficients
20. WHEN sending polynomial, THE Prover SHALL send two coefficients (e.g., a and c) since verifier can reconstruct full polynomial
21. WHEN each coefficient is linear combination of z_i, THE System SHALL have coefficients depending only on u and challenges
22. WHEN prover doesn't know z_i explicitly, THE System SHALL compute a·h and c·h as linear combinations of g_i
23. WHEN a = 10z_1 + 20z_2, THE System SHALL compute a·h = 10·g_1 + 20·g_2 homomorphically
24. WHEN computing homomorphically, THE Prover SHALL use only public group elements without knowing hidden scalars
25. WHEN protocol ends, THE Verifier SHALL check s_n(r_n) = ũ(r_1,...,r_n)·z̃(r_1,...,r_n)
26. WHEN performing check in group, THE Prover SHALL send scalar ũ(r_1,...,r_n)
27. WHEN verifier computes z̃(r_1,...,r_n)·h, THE Verifier SHALL use commitment key g_1,...,g_N
28. WHEN verifying final check, THE Verifier SHALL check s_n(r_n)·h = ũ(r_1,...,r_n)·(z̃(r_1,...,r_n)·h)
29. WHEN Bulletproofs requires no pairings, THE System SHALL work in standard discrete log groups
30. WHEN commitment key is independently sampled, THE System SHALL not rely on structured reference string
31. WHEN evaluation proof has log N rounds, THE System SHALL send two group elements per round
32. WHEN N = 2^30, THE System SHALL produce roughly 2 KB proofs
33. WHEN prover is very slow, THE System SHALL note field multiplications become scalar multiplications
34. WHEN scalar multiplication is thousands of times slower, THE System SHALL recognize performance bottleneck
35. WHEN verifier computes z̃(r_1,...,r_n)·h, THE Verifier SHALL perform roughly N scalar multiplications
36. WHEN verifier is slow, THE System SHALL note linear-time verification in N
37. WHEN knowledge soundness differs from sum-check soundness, THE System SHALL require additional security analysis
38. WHEN mechanically equivalent to sum-check, THE System SHALL recognize structural similarity despite different security model

_Requirements: 1.1, 1.2, 2.1, 2.2, 6.1, 6.2_

### Requirement 14: Hyrax Polynomial Commitment

**User Story:** As a commitment scheme optimizer, I want Hyrax exploiting vector-matrix-vector structure, so that I can achieve fast evaluation proofs without sum-check overhead.

#### Acceptance Criteria

1. WHEN Hyrax is based on Pedersen commitments, THE System SHALL use same commitment primitive as Bulletproofs
2. WHEN Hyrax avoids sum-check, THE System SHALL exploit multiplicative structure in evaluation queries
3. WHEN p(X) = Σ_{i=0}^{N-1} c_i X^i is committed polynomial, THE System SHALL use coefficient vector c
4. WHEN ⃗r = (1,r,r^2,...,r^{N-1}) is evaluation vector, THE System SHALL use powers of evaluation point
5. WHEN p(r) = ⟨c,⃗r⟩, THE System SHALL express evaluation as inner product
6. WHEN N = m^2 is perfect square, THE System SHALL assume square dimension for convenience
7. WHEN ⃗a,⃗b ∈ F^m and M ∈ F^{m×m}, THE System SHALL decompose evaluation structure
8. WHEN ⃗a = (1,r,...,r^{m-1}), THE System SHALL define first evaluation vector
9. WHEN ⃗b = (1,r^m,...,r^{m(m-1)}), THE System SHALL define second evaluation vector
10. WHEN M_{i,j} = c_{i·m+j}, THE System SHALL reshape coefficient vector into matrix in row-major order
11. WHEN p(r) = ⃗b^T M⃗a, THE System SHALL reduce evaluation to vector-matrix-vector product
12. WHEN committing, THE Prover SHALL commit to each column of M separately
13. WHEN G = (g_1,...,g_m) is vector of generators, THE System SHALL use m group elements as commitment key
14. WHEN M^{(j)} denotes j-th column of M, THE System SHALL extract column vectors
15. WHEN computing column commitment, THE Prover SHALL compute C_j = Σ_{i=1}^m M_{i,j}·g_i = ⟨M^{(j)},G⟩
16. WHEN full commitment is (C_1,...,C_m), THE System SHALL commit to all columns
17. WHEN opening p(r), THE Prover SHALL compute ⃗v = M⃗a ∈ F^m
18. WHEN p(r) = ⟨⃗b,⃗v⟩, THE System SHALL express evaluation via partial evaluation vector
19. WHEN prover sends ⃗v, THE Prover SHALL transmit m field elements
20. WHEN verifier computes cm = Σ_{j=1}^m C_j r^j, THE Verifier SHALL homomorphically derive commitment to M⃗a
21. WHEN verifier derives commitment, THE System SHALL compute from column commitments without knowing M
22. WHEN verifier checks ⃗v, THE Verifier SHALL verify cm = ⟨⃗v,G⟩
23. WHEN check passes, THE System SHALL confirm ⃗v is consistent with committed M and vector ⃗a
24. WHEN ⃗v is correct, THE System SHALL have p(r) = ⟨⃗b,⃗v⟩ computable by verifier
25. WHEN commitment consists of √N group elements, THE System SHALL achieve sublinear commitment size
26. WHEN opening proof is √N field elements, THE System SHALL achieve sublinear proof size
27. WHEN verifier performs two MSMs of size √N, THE System SHALL achieve sublinear verification
28. WHEN compared to Bulletproofs, THE System SHALL have √N commitment key instead of N group elements
29. WHEN evaluation proofs are fast, THE System SHALL involve no cryptographic operations, just computing M·⃗a
30. WHEN verifier time is two √N MSMs, THE System SHALL improve over one N-size MSM in Bulletproofs
31. WHEN commitment is big (√N group elements), THE System SHALL trade off commitment size for fast proving
32. WHEN evaluation proof is big (√N field elements), THE System SHALL trade off proof size for fast proving
33. WHEN compared to Bulletproofs proof (2 log N group elements), THE System SHALL have larger but faster-to-compute proofs
34. WHEN leveraging multiplicative structure, THE System SHALL exploit that ⃗r has special form
35. WHEN avoiding sum-check, THE System SHALL achieve non-interactive evaluation proofs directly

_Requirements: 1.1, 1.2, 6.1, 6.2, 13.1_

### Requirement 15: Dory Polynomial Commitment

**User Story:** As an advanced commitment scheme architect, I want Dory combining best aspects of Bulletproofs and Hyrax, so that I can achieve single-element commitments with logarithmic verification.

#### Acceptance Criteria

1. WHEN Dory combines Bulletproofs and Hyrax, THE System SHALL use single group element for commitment like Bulletproofs
2. WHEN Dory supports fast evaluation, THE System SHALL exploit multiplicative structure like Hyrax
3. WHEN Dory improves over both, THE System SHALL achieve logarithmic verifier time
4. WHEN committing, THE System SHALL commit to Hyrax commitment (vector of √N group elements) instead of coefficient vector
5. WHEN using AFGHO commitment scheme, THE System SHALL support committing to group elements using pairings
6. WHEN compressing Hyrax commitment, THE System SHALL reduce √N group elements to single group element in pairing group
7. WHEN opening commitment at point r, THE Prover SHALL prove two things
8. WHEN proving first property, THE Prover SHALL prove it knows Hyrax commitment opening to Dory commitment
9. WHEN proving second property, THE Prover SHALL prove it knows Hyrax evaluation proof that would cause Hyrax verifier to accept
10. WHEN proving both properties, THE System SHALL use variant of Bulletproofs/IPA adapted to AFGHO commitments
11. WHEN using homomorphic structure, THE System SHALL enable Dory verifier to run in logarithmic time
12. WHEN verifier time is logarithmic, THE System SHALL improve over linear-time Bulletproofs verifier and square-root Hyrax verifier
13. WHEN handling sparse vectors, THE System SHALL be especially well-suited to large sparse vectors u ∈ F^N
14. WHEN commitment key is √N size, THE System SHALL not inflate key too much for large N
15. WHEN computing evaluation proof, THE System SHALL perform O(√N) scalar multiplications and pairings
16. WHEN costs scale with non-zeros, THE System SHALL benefit from sparsity in commitment time and field operations
17. WHEN zeros don't contribute, THE System SHALL have commitment time and evaluation proof field operations depend on sparsity
18. WHEN N = 2^128 would be too large, THE System SHALL note √N commitment key would be enormous
19. WHEN PIOP techniques control vector size, THE System SHALL ensure N not larger than 2^50
20. WHEN N ≤ 2^50, THE System SHALL make O(sparsity + √N) prover costs highly attractive
21. WHEN achieving small commitment size, THE System SHALL match Bulletproofs with single group element
22. WHEN achieving fast evaluation, THE System SHALL match Hyrax with O(√N) cryptographic operations
23. WHEN achieving logarithmic verification, THE System SHALL improve over both Bulletproofs and Hyrax
24. WHEN handling sparse inputs gracefully, THE System SHALL excel at sparse vector commitments
25. WHEN combining sum-check and vector-matrix-vector structure, THE System SHALL exemplify best of both approaches
26. WHEN pairing operations are expensive, THE System SHALL note O(√N) pairings can dominate for small N
27. WHEN N is large, THE System SHALL have O(√N) pairings become tiny fraction of total work
28. WHEN used in Jolt zkVM, THE System SHALL have Dory evaluation proofs under 10% of total time for executions with tens of millions of cycles
29. WHEN N grows, THE System SHALL have cryptographic overhead become negligible relative to O(N) PIOP work
30. WHEN sparse sum-check PIOPs like Twist and Shout are used, THE System SHALL provide exactly needed properties for efficient SNARKs

_Requirements: 1.1, 1.2, 6.1, 6.2, 13.1, 14.1_

### Requirement 15A: Twist and Shout Performance Characteristics and Cost Analysis

**User Story:** As a performance analyst, I want detailed cost analysis of Twist and Shout across different memory sizes and commitment schemes, so that I can make informed deployment decisions.

#### Acceptance Criteria

1. WHEN using elliptic curve commitments, THE System SHALL treat committed 0s as literally free
2. WHEN committing to 0s, THE System SHALL not affect commitment computation time
3. WHEN committing to 1, THE Prover SHALL perform one group operation
4. WHEN committing to small values (in {0,1,...,2^32-1}), THE Prover SHALL perform roughly two group operations
5. WHEN committing to arbitrary field elements, THE Prover SHALL perform dozen or more group operations
6. WHEN using Pippenger's bucketing algorithm, THE System SHALL optimize multi-scalar multiplication
7. WHEN commitment key size matters, THE System SHALL note 0s influence key size even if commitment time is free
8. WHEN using parameter d, THE System SHALL control commitment key size via tensor product decomposition
9. WHEN K = 32 and d = 1, THE Prover SHALL commit to 32 bits per address
10. WHEN K = 2^20 and d = 4, THE Prover SHALL commit to 128 bits per address
11. WHEN using hashing-based commitments over binary fields, THE System SHALL pack 128 values into single GF(2^128) element
12. WHEN packing is used, THE System SHALL achieve 128-fold reduction in committed field elements
13. WHEN committing with Binius, FRI-Binius, or Blaze, THE System SHALL support binary field schemes
14. WHEN commitment involves Θ(N) or Θ(N log N) GF(2^128) multiplications, THE System SHALL apply error-correcting code encoding
15. WHEN commitment involves Θ(N) hash evaluations, THE System SHALL use cryptographic hash functions
16. WHEN evaluation proofs are generated, THE System SHALL invoke sum-check protocol for packed values
17. WHEN d = 1 and K = 32, THE System SHALL pack four addresses into single GF(2^128) element
18. WHEN d = 4 and K = 2^20, THE System SHALL pack 128 values into single GF(2^128) element
19. WHEN increments are not in {0,1}, THE System SHALL pack four 32-bit increments into single GF(2^128) element
20. WHEN Twist prover commits per read operation, THE Prover SHALL commit to d·K^{1/d} 0s and d 1s
21. WHEN Twist prover commits per write operation, THE Prover SHALL commit to d·K^{1/d} 0s, d 1s, and one increment value
22. WHEN Shout prover commits per read operation, THE Prover SHALL commit to d·K^{1/d} 0s and d 1s
23. WHEN field operations are counted, THE System SHALL measure field multiplications and additions separately
24. WHEN group operations are counted, THE System SHALL measure elliptic curve operations
25. WHEN Twist achieves O(K + T) field operations, THE System SHALL dominate by T term when K << T
26. WHEN Shout achieves O(C·T) field operations for K = T^C, THE System SHALL handle gigantic structured memories
27. WHEN memory accesses are local, THE Twist Prover SHALL perform O(i) field multiplications for access to cell accessed 2^i steps prior
28. WHEN worst-case access pattern occurs, THE Twist Prover SHALL perform O(log K) field multiplications per operation
29. WHEN best-case access pattern occurs, THE Twist Prover SHALL perform O(1) field multiplications per operation
30. WHEN comparing to Spice with Thaler's grand product, THE System SHALL note Spice performs 40T + 40K field operations
31. WHEN comparing to Spice with Quarks, THE System SHALL note Spice commits to 6 random field elements per operation
32. WHEN comparing to Lasso, THE System SHALL note Lasso commits to 3T + K small values and performs 12T + 12K field operations
33. WHEN comparing to LogUpGKR, THE System SHALL note LogUpGKR commits to 2T + K small values and performs 24T + 24K field operations
34. WHEN Twist and Shout are over 10× faster, THE System SHALL achieve speedup for logarithmic proof length configuration
35. WHEN Twist and Shout are 2-4× faster, THE System SHALL achieve speedup even when baselines use larger proofs
36. WHEN proof size is measured, THE System SHALL report size in field elements or bytes
37. WHEN proof size grows linearly with d, THE System SHALL trade off proof size for commitment efficiency
38. WHEN verifier time is measured, THE System SHALL achieve O(log K + log T) verification time
39. WHEN memory bandwidth is bottleneck on GPUs, THE System SHALL note different performance characteristics
40. WHEN CPU is compute-bound, THE System SHALL optimize field arithmetic operations

_Requirements: 1.1, 2.1, 3.1, 9.1, 10.1, 11.1, 11A.1, 11B.1, 11D.1_

### Requirement 16: Small-Value Preservation

**User Story:** As a cryptographic optimization specialist, I want small-value preservation throughout the proof system, so that I can accelerate commitment and sum-check operations.

#### Acceptance Criteria

1. WHEN computing multi-exponentiation Π_{i=1}^N g_i^{c_i}, THE System SHALL recognize this as Pedersen commitment
2. WHEN multi-scalar multiplication (MSM) is performed, THE System SHALL use additive group notation for same operation
3. WHEN MSMs are central bottleneck, THE System SHALL recognize importance in cryptographic SNARK components
4. WHEN c_i = 0, THE System SHALL omit term g_i^{c_i} = 1 from product, saving work
5. WHEN zero coefficients are free, THE System SHALL exploit sparsity in commitment computation
6. WHEN c_i drawn from small range (e.g., {0,1,...,2^20}), THE System SHALL compute exponentiations much faster
7. WHEN small coefficients are faster, THE System SHALL note g^4 is vastly faster than g^{2^128}
8. WHEN lattice-based schemes benefit from small values, THE System SHALL apply similar optimizations
9. WHEN hashing-based schemes benefit from small values, THE System SHALL apply similar optimizations
10. WHEN SNARK design exhibits small-value preservation, THE System SHALL ensure committed vectors/polynomials consist of small field elements
11. WHEN small-value preservation holds, THE System SHALL accelerate both commitment and opening operations
12. WHEN acceleration is order of magnitude, THE System SHALL recognize practical importance
13. WHEN small-value preservation is key goal, THE System SHALL prioritize in modern prover design
14. WHEN sum-check benefits from small values, THE System SHALL note polynomials evaluating to small elements enable cheaper field operations
15. WHEN field operations are cheaper, THE System SHALL achieve both practical and asymptotic improvements
16. WHEN committed data has small values, THE System SHALL preserve this property through protocol
17. WHEN quotienting destroys small values, THE System SHALL recognize quotient polynomials lose this property
18. WHEN sum-check preserves small values, THE System SHALL maintain property through protocol rounds
19. WHEN virtual polynomials have small values, THE System SHALL ensure virtualized expressions preserve property
20. WHEN native VM data types are 32 or 64 bits, THE System SHALL exploit that registers, addresses, immediates are small integers

_Requirements: 1.1, 6.1, 6.2, 12.1, 12.2_

### Requirement 17: Permutation Checking via Grand Products

**User Story:** As a memory checking protocol developer, I want to understand traditional permutation checking via grand products, so that I can compare with modern sparse approaches.

#### Acceptance Criteria

1. WHEN reducing to permutation check, THE System SHALL introduce untrusted advice data
2. WHEN prover commits to reordered version, THE System SHALL sort operations by memory address
3. WHEN sorted, THE System SHALL verify read value equals most recent write to same address
4. WHEN trusting sorted reasoning, THE System SHALL verify sorted copy is permutation of original
5. WHEN checking permutation of vectors a,b ∈ F^n, THE System SHALL view as lists of roots of polynomials P,Q of degree n
6. WHEN reducing to polynomial equality, THE System SHALL check P = Q
7. WHEN degree-n polynomial determined by n+1 points, THE System SHALL check equality at random point
8. WHEN checking at random r, THE System SHALL verify Π_{i=1}^n (a_i - r) = Π_{i=1}^n (b_i - r)
9. WHEN proving product equation, THE System SHALL invoke grand product argument
10. WHEN grand product argument proves, THE System SHALL verify large product of committed values equals claimed result
11. WHEN memory checking via re-sorting, THE Prover SHALL commit to trace of all reads and writes
12. WHEN sorted copy is committed, THE System SHALL sort entries by memory address
13. WHEN sorted, THE System SHALL match each read against most recent write to same address
14. WHEN checking logic is straightforward, THE System SHALL prove execution of checking correctly
15. WHEN verifier must check permutation, THE System SHALL verify sorted trace is permutation of original
16. WHEN this approach is costly, THE System SHALL recognize several overhead sources
17. WHEN prover commits to extra data, THE System SHALL increase total commitment cost with sorted copy
18. WHEN sorting may be incompatible with streaming, THE System SHALL note trace may be too large for memory
19. WHEN fastest grand product arguments use GKR, THE System SHALL require nontrivial prover work per product term
20. WHEN some grand products commit to partial products, THE System SHALL commit to random field elements
21. WHEN partial products are random, THE System SHALL lose small-value preservation
22. WHEN Twist and Shout take different approach, THE System SHALL embrace sparsity instead of reducing to dense problems
23. WHEN committing directly to sparse representations, THE System SHALL verify using sparse sum-checks
24. WHEN prover cost scales with non-zero terms, THE System SHALL achieve better performance than dense approaches
25. WHEN design minimizes prover work at both PCS and PIOP layers, THE System SHALL combine techniques like virtual polynomials and prefix-suffix decompositions
26. WHEN yielding faster and simpler SNARKs, THE System SHALL be compatible with streaming proving
27. WHEN streaming provers run with low memory, THE System SHALL avoid relying on recursion
28. WHEN payoff is significant in practice, THE System SHALL achieve faster proving than best circuit-based SNARKs for many functions
29. WHEN Shout outperforms for sufficiently large batches, THE System SHALL beat even best sum-check-based circuit SNARKs like GKR
30. WHEN Twist outperforms all permutation-based approaches, THE System SHALL demonstrate superiority of sparse methods

_Requirements: 2.1, 2.2, 9.1, 10.1, 11.1_

### Requirement 17A: Memory Checking Integration with zkVMs

**User Story:** As a zkVM architect, I want to integrate Twist and Shout memory checking into zkVM design, so that I can achieve high-performance proving of register and RAM operations with minimal overhead.

#### Acceptance Criteria

1. WHEN zkVM proves RISC-V execution, THE System SHALL handle 32 registers with two reads and one write per cycle
2. WHEN registers are accessed nearly every cycle, THE System SHALL make register checking a major prover cost component
3. WHEN RAM is accessed via load/store instructions, THE System SHALL handle less frequent but still critical RAM operations
4. WHEN Twist is used for registers, THE System SHALL prove correct read and write operations to 32 registers
5. WHEN Twist is used for RAM, THE System SHALL prove correct memory access patterns for main memory
6. WHEN Shout is used for instruction execution, THE System SHALL prove correct primitive instruction execution via lookups
7. WHEN Shout is used for program bytecode, THE System SHALL prove correct fetch and decode via read-only memory lookups
8. WHEN memory checking accounts for 20% of prover time, THE System SHALL recognize registers as major cost in current Jolt
9. WHEN Lasso accounts for 25% of prover time, THE System SHALL recognize instruction execution checking as major cost
10. WHEN total memory checking is 45% of prover time, THE System SHALL expect fraction to grow as other parts optimize
11. WHEN Twist and Shout replace Spice and Lasso, THE System SHALL achieve substantial end-to-end speedups
12. WHEN addresses are naturally single field elements, THE System SHALL support raf and waf representations
13. WHEN zkVM verifier needs address evaluations, THE System SHALL provide via virtual polynomial technique
14. WHEN read values can be virtual, THE System SHALL avoid committing to rv in zkVM context
15. WHEN write values are committed, THE System SHALL commit to actual register/RAM write values
16. WHEN increments are used, THE System SHALL commit to differences rather than full values
17. WHEN at most one register written per cycle, THE System SHALL exploit sparsity of increments
18. WHEN memory operations are local, THE System SHALL achieve faster proving via locality-aware Twist
19. WHEN compiler optimizations target real CPUs, THE System SHALL also benefit zkVM provers
20. WHEN small memories (32 registers) are used, THE System SHALL achieve especially efficient proving
21. WHEN large memories (GBs of RAM) are used, THE System SHALL maintain reasonable prover costs
22. WHEN gigantic structured tables (2^64) are used, THE System SHALL handle without materialization
23. WHEN HyperKZG or Zeromorph commitments are used, THE System SHALL exploit elliptic curve properties
24. WHEN future hashing-based commitments are used, THE System SHALL support binary field schemes
25. WHEN proof composition is needed, THE System SHALL support SNARK composition for proof shrinking
26. WHEN streaming proving is used, THE System SHALL maintain low memory footprint
27. WHEN parallel proving is used, THE System SHALL distribute work across cores efficiently
28. WHEN benchmarking performance, THE System SHALL measure memory checking as fraction of total time
29. WHEN comparing to circuit-based SNARKs, THE System SHALL achieve competitive or better performance
30. WHEN general-purpose flexibility is needed, THE System SHALL avoid hand-optimized circuits

_Requirements: 2.1, 2.2, 9.1, 10.1, 11.1, 11A.1, 11B.1, 11C.1_

### Requirement 18: Jolt zkVM Architecture

**User Story:** As a zkVM developer, I want the complete Jolt architecture using sum-check-based techniques, so that I can build high-performance general-purpose SNARKs for RISC-V execution.

#### Acceptance Criteria

1. WHEN Jolt is zkVM for RISC-V, THE System SHALL target RV64IMAC architecture
2. WHEN RV64IMAC means 64-bit registers, THE System SHALL support 64-bit register operations
3. WHEN including Multiplication extension, THE System SHALL support M extension instructions
4. WHEN each VM cycle is SNARKed, THE System SHALL prove correct execution per cycle
5. WHEN Fetch stage executes, THE VM SHALL read from program bytecode to determine instruction
6. WHEN proving Fetch, THE System SHALL use Shout as read-only memory checker
7. WHEN Decode and Execute stages run, THE VM SHALL read up to two registers
8. WHEN applying instruction, THE VM SHALL compute result from register values
9. WHEN writing result, THE VM SHALL write to designated output register
10. WHEN proving register operations, THE System SHALL use Twist for register reads and writes
11. WHEN checking instruction execution, THE System SHALL use Shout as batch-evaluation argument
12. WHEN Load or Store instruction executes, THE VM SHALL read or write to main memory (RAM)
13. WHEN proving RAM access, THE System SHALL use second instance of Twist
14. WHEN enforcing global correctness, THE System SHALL check VM transition constraints are satisfied
15. WHEN using Spartan for constraints, THE System SHALL prove satisfaction of roughly 20 constraints
16. WHEN constraints are repeated identically per cycle, THE System SHALL exploit this structure
17. WHEN Jolt variant of Spartan is optimized, THE System SHALL handle repeated constraint structure efficiently
18. WHEN running two Shout instances, THE System SHALL use one for instruction execution checking
19. WHEN running two Shout instances, THE System SHALL use one as lookup argument for program code
20. WHEN producing proofs for real-world programs, THE System SHALL achieve roughly 50 KB proof sizes
21. WHEN measuring prover throughput, THE System SHALL achieve MHz range on commodity CPUs
22. WHEN running on high-end MacBook, THE System SHALL exceed 500,000 RV64IMAC cycles per second
23. WHEN running on 32-core machine, THE System SHALL exceed 1.5 million cycles per second
24. WHEN prover speed depends on VM cycles, THE System SHALL have little sensitivity to specific computation
25. WHEN comparing to circuit-SAT SNARKs, THE System SHALL achieve on par or better performance
26. WHEN circuit-SAT requires hand-optimized circuits, THE System SHALL provide general-purpose flexibility
27. WHEN Jolt is easier to use, THE System SHALL demonstrate sum-check-based SNARKs can leverage structure for speed and simplicity
28. WHEN performance was predicted in advance, THE System SHALL validate theoretical accounting of prover workload
29. WHEN Jolt prover performs roughly 500 field multiplications per cycle, THE System SHALL work over 256-bit field
30. WHEN each field multiplication costs 100 CPU cycles, THE System SHALL use conservative hardware assumptions
31. WHEN expected prover cost is 50,000 CPU cycles per VM cycle, THE System SHALL derive from field multiplication count
32. WHEN single-threaded 4 GHz core is used, THE System SHALL expect throughput of about 80,000 VM cycles per second
33. WHEN scaling across 16 threads, THE System SHALL project throughput of about 1 million VM cycles per second
34. WHEN projected performance matches observed, THE System SHALL validate theoretical cost analysis
35. WHEN real hardware is complex, THE System SHALL note substantial engineering effort was required
36. WHEN theoretical grounding played crucial role, THE System SHALL enable precise operation counts
37. WHEN operation counts guide optimization, THE System SHALL identify which parts are slower than expected
38. WHEN empirical benchmarking is valuable, THE System SHALL avoid comparisons ignoring implementation maturity
39. WHEN accurate operation-level cost analysis is essential, THE System SHALL guide practical SNARK design
40. WHEN Dory evaluation proofs are excluded from 500 field multiplications, THE System SHALL note they can be significant for small executions

_Requirements: 2.1, 2.2, 2.3, 9.1, 9.2, 10.1, 10.2, 11.1, 11.2_


### Requirement 18A: Fast-Prover SNARKs for Non-Uniform Computation via Shout

**User Story:** As a non-uniform circuit SNARK developer, I want fast-prover SNARKs using Shout for circuit wires, so that I can achieve minimal commitment costs with the prover committing only to the witness.

#### Acceptance Criteria

1. WHEN building SNARKs for non-uniform circuits, THE System SHALL reduce circuit wires to lookups
2. WHEN each gate output is stored in table, THE System SHALL compute gate inputs via lookups into output table
3. WHEN SpeedySpartan is used, THE System SHALL apply Shout as lookup argument for gate inputs
4. WHEN Spartan++ is used, THE System SHALL apply Shout to improve Spark sparse polynomial commitment scheme
5. WHEN prover commits only to witness, THE System SHALL achieve minimal commitment costs
6. WHEN using fast evaluation proof generation schemes (Hyrax, Dory), THE Prover SHALL commit to witness and nothing else
7. WHEN using HyperKZG, Zeromorph, or Bulletproofs/IPA, THE System SHALL note evaluation proofs require committing to linear data
8. WHEN SpeedySpartan replaces BabySpartan, THE System SHALL achieve 4× reduction in commitment costs
9. WHEN Spartan++ replaces Spartan, THE System SHALL achieve 6× improvement in prover times
10. WHEN SpeedySpartan uses smaller lookup table, THE System SHALL be concretely faster than Spartan++
11. WHEN SpeedySpartan lookup table is size n, THE System SHALL use table storing all gate outputs
12. WHEN Spartan++ lookup table is size n^2, THE System SHALL use table storing multilinear Lagrange basis evaluations
13. WHEN Spartan++ commitment costs grow with multiplication gates, THE System SHALL not count addition gates
14. WHEN both reduce commitment costs substantially, THE System SHALL make commitments not a prover bottleneck
15. WHEN BabySpartan used Lasso, THE System SHALL replace with Shout for improved performance
16. WHEN Shout allows virtual polynomials, THE System SHALL avoid committing to certain polynomials that BabySpartan committed
17. WHEN Spark used Lasso for lookups, THE System SHALL replace with Shout in Spartan++
18. WHEN Spark evaluation proofs perform lookups, THE System SHALL use Shout to eliminate major prover bottleneck
19. WHEN prover committed to two random values per non-zero coefficient in Spark, THE System SHALL eliminate via virtual polynomials
20. WHEN Spartan++ improves Spark, THE System SHALL enable faster sparse polynomial commitment evaluation proofs
21. WHEN circuits have n gates, THE System SHALL handle both Plonkish and R1CS constraint systems
22. WHEN CCS (Customizable Constraint Systems) is used, THE System SHALL generalize both Plonkish and R1CS
23. WHEN SpeedySpartan applies to Plonkish, THE System SHALL substantially improve over BabySpartan
24. WHEN Spartan++ applies to CCS, THE System SHALL improve over original Spartan
25. WHEN field work is reduced, THE System SHALL achieve improvements from Shout's efficiency relative to Lasso
26. WHEN commitment costs are reduced 4×, THE System SHALL achieve via virtual polynomial technique
27. WHEN lookups are used differently, THE System SHALL recognize SpeedySpartan and Spartan++ use distinct approaches
28. WHEN SpeedySpartan is practically faster, THE System SHALL prefer for concrete performance
29. WHEN Spartan++ has interesting properties, THE System SHALL recognize conceptual value of multiplication-gate-only commitment costs
30. WHEN both are orders of magnitude faster than predecessors, THE System SHALL demonstrate power of Shout-based approach

_Requirements: 2.1, 2.2, 9.1, 9.2, 10.1, 11A.1, 11B.1, 11C.1_

### Requirement 18B: Soundness Error Analysis and Security Properties

**User Story:** As a cryptographic security analyst, I want rigorous soundness error analysis for Twist and Shout, so that I can ensure adequate security levels across different field sizes and parameter choices.

#### Acceptance Criteria

1. WHEN offline memory checking uses grand products, THE System SHALL introduce soundness error at least (T + K)/|F|
2. WHEN grand product uses univariate polynomial of degree Θ(T + K), THE System SHALL bound error by degree over field size
3. WHEN one-hot addressing is used, THE System SHALL achieve soundness error of only log(TK)/|F|
4. WHEN working over 256-bit prime order fields, THE System SHALL note difference is not important
5. WHEN working over 64-bit prime fields with extensions, THE System SHALL recognize improved soundness matters
6. WHEN targeting 128-bit security with 64-bit base field, THE System SHALL use degree-2 extension for challenges
7. WHEN K = 10^9 (one billion memory cells), THE System SHALL achieve at least 98 bits of security with offline methods
8. WHEN processing 10^12 cycles without recursion, THE System SHALL achieve only 88 bits of security with offline methods
9. WHEN one-hot addressing is used with same parameters, THE System SHALL achieve over 120 bits of security
10. WHEN soundness error is log(TK)/|F|, THE System SHALL provide better security for large T and K
11. WHEN multiple sum-checks are composed, THE System SHALL add soundness errors via union bound
12. WHEN Booleanity-checking sum-check is applied, THE System SHALL verify ra(k,j) ∈ {0,1} for all (k,j)
13. WHEN Hamming-weight-one check is applied, THE System SHALL verify exactly one entry per address equals 1
14. WHEN raf-evaluation sum-check is applied, THE System SHALL verify one-hot encoding corresponds to correct address value
15. WHEN read-checking sum-check is applied, THE System SHALL verify read values match stored values
16. WHEN write-checking sum-check is applied, THE System SHALL verify increments are correctly computed
17. WHEN Val-evaluation sum-check is applied, THE System SHALL verify cell values are correct aggregations of increments
18. WHEN total soundness error is computed, THE System SHALL sum errors from all sum-check invocations
19. WHEN field size is chosen, THE System SHALL ensure total soundness error is negligible (e.g., 2^{-128})
20. WHEN security parameter is λ bits, THE System SHALL ensure soundness error ≤ 2^{-λ}
21. WHEN completeness is analyzed, THE System SHALL ensure honest prover always convinces verifier
22. WHEN soundness is analyzed, THE System SHALL bound probability malicious prover convinces verifier
23. WHEN knowledge soundness is needed, THE System SHALL prove extractor can compute witness
24. WHEN Fiat-Shamir is applied, THE System SHALL analyze security in random oracle model
25. WHEN concrete security is provided, THE System SHALL give explicit error bounds for all parameters
26. WHEN comparing to offline memory checking, THE System SHALL note logarithmic vs linear soundness error
27. WHEN small characteristic fields are used, THE System SHALL handle binary fields appropriately
28. WHEN field characteristic is greater than 2, THE System SHALL use 2^{-1} optimization for Hamming weight check
29. WHEN binary fields are used, THE System SHALL apply sum-check directly for Hamming weight check
30. WHEN security proofs are formal, THE System SHALL document all assumptions and reductions

_Requirements: 1.1, 2.1, 8.1, 9.1, 11.1, 11A.1, 21.1, 32.1_

### Requirement 18C: Implementation Optimizations and Prover Algorithms

**User Story:** As a SNARK implementation engineer, I want detailed prover algorithms and optimizations for Twist and Shout, so that I can achieve the advertised performance in practice.

#### Acceptance Criteria

1. WHEN implementing Shout prover for d = 1, THE System SHALL achieve O(K) + 5T field operations
2. WHEN implementing Shout prover for general d, THE System SHALL achieve O(K + d^2·T) field operations
3. WHEN d ≥ 8, THE System SHALL use linear-d variation with better constant factors
4. WHEN implementing Twist prover, THE System SHALL achieve O(K + T log K) field operations
5. WHEN memory accesses are local, THE Twist Prover SHALL achieve O(K + T·locality_measure) field operations
6. WHEN implementing Booleanity-checking sum-check, THE Prover SHALL perform O(K) + 2T field multiplications
7. WHEN implementing Hamming-weight-one check, THE Prover SHALL evaluate at single point (2^{-1},...,2^{-1},r') in non-binary fields
8. WHEN implementing raf-evaluation sum-check, THE Prover SHALL compute weighted sum of one-hot encodings
9. WHEN implementing read-checking sum-check, THE Prover SHALL leverage sparsity of ra(k,j)
10. WHEN implementing write-checking sum-check, THE Prover SHALL leverage that only one register written per cycle
11. WHEN implementing Val-evaluation sum-check, THE Prover SHALL aggregate increments using less-than predicate
12. WHEN less-than predicate LT is evaluated, THE Verifier SHALL compute in O(log T) time
13. WHEN equality polynomial eq is evaluated, THE Verifier SHALL compute in O(log K + log T) time
14. WHEN arrays are updated in-place during sum-check, THE System SHALL minimize memory allocations
15. WHEN processing round i of sum-check, THE Prover SHALL work with arrays of size N/2^i
16. WHEN multilinear interpolation is applied, THE System SHALL use formula p(r,x') = (1-r)·p(0,x') + r·p(1,x')
17. WHEN Gruen's optimization is applied, THE System SHALL reduce degree of prover messages by one
18. WHEN Gruen's optimization is used, THE Prover SHALL compute s'_i instead of s_i directly
19. WHEN s'_i leaves out eq contribution, THE System SHALL add it back in time independent of sum size
20. WHEN sparse-dense sum-check is applied, THE System SHALL handle gigantic structured memories
21. WHEN K = T^C for C ≥ 1, THE Prover SHALL achieve O(C·T) time via sparse-dense protocol
22. WHEN generalizing sparse-dense sum-check, THE System SHALL extend from Generalized-Lasso protocol
23. WHEN binding variables in specific order, THE System SHALL choose order to maximize sparsity reduction
24. WHEN time variables are bound first in Twist, THE System SHALL enable locality-aware performance
25. WHEN memory variables are bound first in Shout, THE System SHALL optimize for different access patterns
26. WHEN parallel processing is used, THE System SHALL distribute independent array updates across cores
27. WHEN SIMD instructions are available, THE System SHALL vectorize field operations
28. WHEN memory bandwidth is bottleneck, THE System SHALL optimize data access patterns
29. WHEN cache locality matters, THE System SHALL structure computations for cache efficiency
30. WHEN benchmarking implementations, THE System SHALL measure field operations, group operations, and wall-clock time separately

_Requirements: 2.1, 2.2, 2.3, 3.1, 4.1, 9.1, 11.1, 11A.1, 11B.1, 23.1, 29.1_

### Requirement 19: SNARK Design Hierarchy and Performance

**User Story:** As a SNARK system architect, I want to understand the complete performance hierarchy from slowest to fastest approaches, so that I can make informed design decisions.

#### Acceptance Criteria

1. WHEN SNARKs do not use sum-check at all, THE System SHALL recognize these as slowest category
2. WHEN SNARKs invoke sum-check but fail to exploit structure, THE System SHALL classify as faster but suboptimal
3. WHEN SNARKs combine sum-check with structure exploitation, THE System SHALL recognize as fastest category
4. WHEN fastest SNARKs are also simplest, THE System SHALL note correlation between performance and simplicity
5. WHEN committing to data is expensive, THE System SHALL recognize every committed value must later be proven correct
6. WHEN reducing committed objects, THE System SHALL prioritize minimizing number and size
7. WHEN sum-check offloads work without cryptography, THE System SHALL use interaction and randomness instead
8. WHEN interaction is resource, THE System SHALL use it to minimize commitments and prover work
9. WHEN removing interaction twice is wasteful, THE System SHALL avoid first removing for PCP then reintroducing
10. WHEN using Fiat-Shamir, THE System SHALL apply once directly to well-structured interactive proof
11. WHEN exploiting structure in computation, THE System SHALL recognize sparse sums, small values, repeated patterns as opportunities
12. WHEN not exploiting structure fully, THE System SHALL leave performance and simplicity on table
13. WHEN many PCSes are sum-checks in disguise, THE System SHALL recognize Bulletproofs/IPA as sum-check over inner products applied homomorphically
14. WHEN Hyrax avoids sum-check, THE System SHALL rely on vector-matrix-vector encodings instead
15. WHEN Dory combines both approaches, THE System SHALL mitigate Bulletproofs/IPA downsides
16. WHEN achieving sublinear commitment key, THE System SHALL use Dory's compression techniques
17. WHEN achieving sublinear cryptographic work, THE System SHALL use Dory's evaluation proof structure
18. WHEN post-quantum and smaller-field SNARKs are needed, THE System SHALL transition to 128-bit fields with post-quantum security
19. WHEN Twist, Shout, Jolt rely on elliptic curves, THE System SHALL currently use 256-bit fields
20. WHEN transitioning is open challenge, THE System SHALL seek simplest and most performant approach
21. WHEN lattice-based schemes are promising, THE System SHALL note they are still maturing
22. WHEN hash-based schemes are attractive, THE System SHALL recognize substantial progress but remaining challenges
23. WHEN integrating with sparse sum-checks, THE System SHALL address both engineering and theoretical challenges
24. WHEN formal verification is essential, THE System SHALL recognize SNARKs becoming critical infrastructure
25. WHEN SNARKs are vastly more complex than signatures, THE System SHALL prioritize formal verification
26. WHEN implementations contain bugs, THE System SHALL note current state has correctness issues
27. WHEN progress is underway, THE System SHALL recognize much verification work remains
28. WHEN beyond VM abstraction, THE System SHALL question if fastest circuit SNARKs still outperform general zkVMs
29. WHEN combining approaches, THE System SHALL explore right tradeoff between flexibility, usability, performance
30. WHEN precompiles are used, THE System SHALL question if there are principled alternatives to gluing optimized circuits into VM
31. WHEN core design principles are clear, THE System SHALL recognize path forward for simple and performant SNARKs
32. WHEN open problems are challenging but tractable, THE System SHALL focus on performance, simplicity, correctness
33. WHEN sum-check-based SNARKs transition to infrastructure, THE System SHALL expect coming years to see foundational deployment
34. WHEN historical context matters, THE System SHALL recognize shift from PCPs back to interactive proofs
35. WHEN univariate techniques dominated, THE System SHALL note this was due to short proofs and limited awareness of sum-check performance

_Requirements: 1.1, 2.1, 2.2, 6.1, 6.2, 9.1, 10.1, 11.1, 18.1_

### Requirement 20: Interactive Proofs and Historical Context

**User Story:** As a cryptographic protocol historian, I want to understand the evolution from interactive proofs to PCPs and back to interactive proofs, so that I can appreciate modern design choices.

#### Acceptance Criteria

1. WHEN Goldwasser, Micali, Rackoff introduced interactive proofs in 1980s, THE System SHALL recognize GMR as originators
2. WHEN it was believed interactive proofs prove slightly more than NP, THE System SHALL note initial limited expectations
3. WHEN LFKN introduced sum-check in 1990, THE System SHALL recognize Lund, Fortnow, Karloff, Nisan's contribution
4. WHEN sum-check showed #SAT has efficient verifier, THE System SHALL note counting satisfying assignments is provable
5. WHEN IP = PSPACE was proven, THE System SHALL recognize celebrated result following sum-check
6. WHEN community shifted to PCPs, THE System SHALL note move to non-interactive proof models
7. WHEN PCPs allow spot-checking, THE System SHALL recognize verifier reads only few bits
8. WHEN polynomial-size PCP from sum-check is possible, THE System SHALL note quasilinear size requires different techniques
9. WHEN univariate polynomials and quotienting are used, THE System SHALL recognize techniques for quasilinear PCPs
10. WHEN univariate techniques became SNARK foundation, THE System SHALL note Kilian showed PCP to succinct argument via Merkle commitment
11. WHEN Micali proposed Fiat-Shamir, THE System SHALL recognize removal of interaction
12. WHEN prevailing belief was PCPs are right starting point, THE System SHALL note univariate polynomials and quotienting were seen as foundation
13. WHEN compilation path is indirect and inefficient, THE System SHALL recognize interaction removed to build PCP then reintroduced
14. WHEN interaction reintroduced via Kilian then removed via Fiat-Shamir, THE System SHALL note double transformation is wasteful
15. WHEN using Fiat-Shamir, THE System SHALL apply once directly to well-structured interactive proof
16. WHEN vSQL and Hyrax in 2017 showed SNARKs from sum-check, THE System SHALL recognize first systems applying PCS to sum-check-based IP
17. WHEN compiling GKR protocol and refinements, THE System SHALL note both systems used polynomial commitment and Fiat-Shamir
18. WHEN limited to low-depth layered circuits, THE System SHALL recognize initial restrictions
19. WHEN Spartan and Clover addressed limitations, THE System SHALL note support for arbitrary circuits
20. WHEN dominant approach remained univariate-based, THE System SHALL recognize appeal of very short proofs like Groth16
21. WHEN limited awareness of sum-check performance existed, THE System SHALL note this contributed to univariate dominance
22. WHEN change began in earnest in 2023, THE System SHALL recognize Lasso and Jolt as catalysts
23. WHEN systems clarified extent of combining techniques, THE System SHALL note batch evaluation, memory checking, small-value preservation
24. WHEN general-purpose SNARKs became simpler and faster, THE System SHALL recognize superiority over univariate-based approaches
25. WHEN modern perspective developed, THE System SHALL recognize sum-check not solving all issues when applied naively
26. WHEN spectrum of sophistication exists, THE System SHALL note range from naive to highly optimized sum-check usage
27. WHEN exploiting repeated structure, THE System SHALL enable SNARKs scaling to real-world infrastructure needs
28. WHEN sum-check is foundation, THE System SHALL recognize it as starting point requiring sophisticated application
29. WHEN real computations have structure, THE System SHALL exploit sparsity, small values, repetition
30. WHEN historical arc completes, THE System SHALL recognize return to interactive proofs with modern optimizations

_Requirements: 1.1, 2.1, 2.2, 6.1, 19.1_

### Requirement 21: Fiat-Shamir Transformation

**User Story:** As a non-interactive proof developer, I want complete Fiat-Shamir transformation implementation, so that I can convert interactive protocols to non-interactive SNARKs.

#### Acceptance Criteria

1. WHEN Fiat-Shamir transformation is applied, THE System SHALL take interactive protocol and render non-interactive
2. WHEN prover derives verifier challenges, THE System SHALL have prover compute challenges itself
3. WHEN applying cryptographic hash function, THE System SHALL hash all prover messages up to that point
4. WHEN each challenge is derived, THE System SHALL use hash output as verifier challenge
5. WHEN protocol is made non-interactive, THE System SHALL eliminate verifier-to-prover communication
6. WHEN security relies on random oracle model, THE System SHALL assume hash function behaves like random oracle
7. WHEN hash function is modeled as random oracle, THE System SHALL treat outputs as uniformly random
8. WHEN applying to sum-check protocol, THE System SHALL derive each r_i by hashing transcript
9. WHEN transcript includes all prior messages, THE System SHALL ensure challenges depend on all previous prover messages
10. WHEN soundness is preserved, THE System SHALL maintain security in random oracle model
11. WHEN applying once at end, THE System SHALL avoid multiple applications to same protocol
12. WHEN interaction is removed efficiently, THE System SHALL minimize overhead from transformation
13. WHEN hash function is cryptographically secure, THE System SHALL use SHA-256, SHA-3, or similar
14. WHEN field elements are hashed, THE System SHALL serialize properly before hashing
15. WHEN challenges are in field F, THE System SHALL map hash outputs to field elements correctly
16. WHEN bias must be avoided, THE System SHALL ensure uniform distribution over field
17. WHEN multiple challenges are needed, THE System SHALL derive independently or via counter
18. WHEN transcript is maintained, THE System SHALL include all polynomial commitments and evaluations
19. WHEN public inputs are included, THE System SHALL hash public parameters and inputs
20. WHEN security proof relies on random oracle, THE System SHALL document this assumption

_Requirements: 2.1, 2.2, 6.1, 6.2_

### Requirement 22: Circuit Satisfiability and R1CS

**User Story:** As a constraint system developer, I want to understand circuit satisfiability and R1CS representation, so that I can express computations for SNARK proving.

#### Acceptance Criteria

1. WHEN arithmetic circuit consists of multiplication gates, THE System SHALL handle fan-in two gates
2. WHEN c_i denotes value at gate i, THE System SHALL track gate values
3. WHEN a_i and b_i denote in-neighbor values, THE System SHALL identify left and right inputs
4. WHEN checking gate correctness, THE System SHALL verify a_i · b_i = c_i
5. WHEN this is half the logic, THE System SHALL recognize product checking is partial verification
6. WHEN wiring constraints must be verified, THE System SHALL ensure a_i and b_i are values from correct gates
7. WHEN a and b derived from c, THE System SHALL verify values come from circuit structure
8. WHEN wiring constraints are more complicated, THE System SHALL handle sparse polynomials
9. WHEN R1CS (Rank-1 Constraint System) is used, THE System SHALL express constraints as (A·z) ◦ (B·z) = C·z
10. WHEN z is witness vector, THE System SHALL include all wire values
11. WHEN A, B, C are constraint matrices, THE System SHALL encode circuit structure
12. WHEN each row is constraint, THE System SHALL verify one multiplication gate or linear constraint
13. WHEN matrices are sparse, THE System SHALL exploit sparsity in proving
14. WHEN addition gates are free, THE System SHALL handle linear combinations without multiplication constraints
15. WHEN circuit is layered, THE System SHALL organize gates into layers by depth
16. WHEN layers have uniform size, THE System SHALL optimize for regular structure
17. WHEN wiring is structured, THE System SHALL enable efficient wiring predicate evaluation
18. WHEN circuits are hand-optimized, THE System SHALL recognize manual optimization effort
19. WHEN automatic compilation is used, THE System SHALL generate circuits from high-level code
20. WHEN circuit size affects prover time, THE System SHALL minimize gates for performance

_Requirements: 1.1, 2.1, 3.1, 5.1, 7.1, 8.1_

### Requirement 23: Memory Bandwidth and Hardware Considerations

**User Story:** As a performance engineer, I want to understand hardware bottlenecks beyond computation, so that I can optimize for real-world deployment.

#### Acceptance Criteria

1. WHEN hardware platforms vary, THE System SHALL consider different bottlenecks
2. WHEN GPUs are used, THE System SHALL recognize memory bandwidth may limit performance
3. WHEN memory bandwidth is bottleneck, THE System SHALL note compute is not limiting factor
4. WHEN running sum-check provers on GPUs, THE System SHALL expect memory-bound performance
5. WHEN bottlenecks differ across platforms, THE System SHALL maintain throughput within same order of magnitude
6. WHEN CPUs are used, THE System SHALL typically be compute-bound
7. WHEN field multiplications dominate, THE System SHALL optimize arithmetic operations
8. WHEN data access patterns matter, THE System SHALL consider cache efficiency
9. WHEN arrays are updated in-place, THE System SHALL minimize memory allocations
10. WHEN parallel processing is used, THE System SHALL consider memory contention
11. WHEN SIMD instructions are available, THE System SHALL vectorize field operations
12. WHEN multiple cores are used, THE System SHALL partition work efficiently
13. WHEN memory hierarchy is deep, THE System SHALL optimize for cache locality
14. WHEN prefetching is possible, THE System SHALL hint memory access patterns
15. WHEN streaming algorithms are used, THE System SHALL minimize memory footprint
16. WHEN data structures are chosen, THE System SHALL consider access patterns
17. WHEN benchmarking performance, THE System SHALL measure on target hardware
18. WHEN comparing platforms, THE System SHALL account for architectural differences
19. WHEN optimizing code, THE System SHALL profile to identify actual bottlenecks
20. WHEN theoretical analysis guides optimization, THE System SHALL validate with empirical measurements

_Requirements: 3.1, 4.1, 18.1_

### Requirement 24: Zero-Knowledge Property

**User Story:** As a privacy-preserving protocol developer, I want zero-knowledge extensions to sum-check-based SNARKs, so that I can hide witness information.

#### Acceptance Criteria

1. WHEN zero-knowledge is required, THE System SHALL hide all information about witness except validity
2. WHEN sum-check-based SNARKs are made ZK, THE System SHALL add minimal overhead
3. WHEN using curve-based PCSes, THE System SHALL achieve ZK with minimal cost
4. WHEN using Hyrax, Bulletproofs, Dory, THE System SHALL apply known ZK techniques
5. WHEN using some hashing-based PCSes, THE System SHALL achieve ZK without additional prover cost
6. WHEN using other hashing-based PCSes, THE System SHALL note ZK overhead remains open question
7. WHEN prover adds random masking, THE System SHALL blind committed polynomials
8. WHEN verifier checks are adjusted, THE System SHALL account for masking in verification
9. WHEN simulator exists, THE System SHALL prove zero-knowledge property formally
10. WHEN simulator produces transcripts, THE System SHALL ensure indistinguishability from real proofs
11. WHEN honest-verifier ZK is achieved, THE System SHALL provide ZK against honest verifiers
12. WHEN malicious-verifier ZK is needed, THE System SHALL use stronger techniques
13. WHEN Fiat-Shamir is applied to ZK protocol, THE System SHALL maintain ZK in random oracle model
14. WHEN blinding factors are chosen, THE System SHALL sample uniformly from appropriate distribution
15. WHEN multiple polynomials are committed, THE System SHALL blind each independently
16. WHEN evaluation proofs reveal information, THE System SHALL mask evaluations appropriately
17. WHEN sum-check rounds reveal information, THE System SHALL add random terms to messages
18. WHEN final evaluation is revealed, THE System SHALL ensure it doesn't leak witness information
19. WHEN ZK overhead is measured, THE System SHALL quantify additional prover and verifier work
20. WHEN ZK is not needed, THE System SHALL omit blinding for better performance

_Requirements: 2.1, 6.1, 12.1, 13.1, 14.1, 15.1_

### Requirement 25: Field Selection and Arithmetic

**User Story:** As a finite field arithmetic developer, I want optimal field selection and efficient arithmetic implementations, so that I can maximize prover performance.

#### Acceptance Criteria

1. WHEN selecting field size, THE System SHALL choose between 2^128 and 2^256 bits for security
2. WHEN 256-bit fields are used, THE System SHALL provide 128-bit security
3. WHEN 128-bit fields are desired, THE System SHALL enable faster arithmetic
4. WHEN post-quantum security is needed, THE System SHALL consider lattice-friendly fields
5. WHEN field has special structure, THE System SHALL exploit for faster arithmetic
6. WHEN prime fields are used, THE System SHALL implement modular arithmetic efficiently
7. WHEN binary fields are used, THE System SHALL use XOR-based arithmetic
8. WHEN extension fields are used, THE System SHALL implement tower field arithmetic
9. WHEN Montgomery form is used, THE System SHALL optimize modular multiplication
10. WHEN Barrett reduction is used, THE System SHALL optimize modular reduction
11. WHEN field multiplication is unit operation, THE System SHALL optimize this primitive
12. WHEN field addition is cheaper, THE System SHALL prefer additions over multiplications
13. WHEN field inversion is expensive, THE System SHALL batch inversions when possible
14. WHEN constant-time arithmetic is needed, THE System SHALL avoid timing side-channels
15. WHEN SIMD instructions are available, THE System SHALL vectorize field operations
16. WHEN assembly optimization is used, THE System SHALL hand-optimize critical paths
17. WHEN multiple field sizes are supported, THE System SHALL provide generic implementations
18. WHEN field arithmetic is benchmarked, THE System SHALL measure on target platforms
19. WHEN comparing fields, THE System SHALL consider both arithmetic cost and security level
20. WHEN small fields enable optimizations, THE System SHALL exploit small-value preservation

_Requirements: 1.1, 1.2, 3.1, 16.1_

### Requirement 26: Proof Composition and Recursion

**User Story:** As a recursive proof developer, I want proof composition techniques, so that I can build incrementally verifiable computation and proof aggregation.

#### Acceptance Criteria

1. WHEN composing proofs, THE System SHALL verify one proof inside another
2. WHEN recursion is used, THE System SHALL enable incremental verification
3. WHEN proof aggregation is needed, THE System SHALL combine multiple proofs into one
4. WHEN verifier circuit is created, THE System SHALL express verification as circuit
5. WHEN verifier circuit is proven, THE System SHALL generate proof of correct verification
6. WHEN cycle of curves is used, THE System SHALL enable efficient recursion
7. WHEN proof-carrying data is built, THE System SHALL chain proofs over computation steps
8. WHEN IVC (Incrementally Verifiable Computation) is implemented, THE System SHALL prove each step extends valid computation
9. WHEN folding schemes are used, THE System SHALL accumulate instances efficiently
10. WHEN accumulation is correct, THE System SHALL verify accumulated instance implies all original instances
11. WHEN final proof is generated, THE System SHALL prove accumulated instance is satisfied
12. WHEN recursion overhead is measured, THE System SHALL quantify cost of recursive verification
13. WHEN cycles of elliptic curves are used, THE System SHALL pair curves with matching field sizes
14. WHEN Pasta curves are used, THE System SHALL leverage Pallas and Vesta curve cycle
15. WHEN recursion is avoided, THE System SHALL use direct proving when possible
16. WHEN memory reduction is needed, THE System SHALL use recursion to control prover memory
17. WHEN parallel proving is used, THE System SHALL aggregate proofs from parallel workers
18. WHEN proof trees are built, THE System SHALL recursively aggregate in tree structure
19. WHEN depth of recursion matters, THE System SHALL minimize recursion depth
20. WHEN recursion is essential, THE System SHALL optimize recursive verification circuit

_Requirements: 2.1, 6.1, 18.1_

### Requirement 27: Preprocessing and Setup Phases

**User Story:** As a SNARK deployment engineer, I want to understand preprocessing and setup requirements, so that I can deploy systems with appropriate trust assumptions.

#### Acceptance Criteria

1. WHEN trusted setup is required, THE System SHALL generate structured reference string
2. WHEN universal setup is used, THE System SHALL support any circuit up to size bound
3. WHEN circuit-specific setup is used, THE System SHALL generate parameters for specific circuit
4. WHEN transparent setup is used, THE System SHALL require no trusted setup
5. WHEN setup ceremony is conducted, THE System SHALL enable multi-party computation
6. WHEN ceremony has many participants, THE System SHALL ensure security if one party is honest
7. WHEN toxic waste is generated, THE System SHALL ensure it cannot be reconstructed
8. WHEN setup is reusable, THE System SHALL amortize setup cost over many proofs
9. WHEN setup is updatable, THE System SHALL allow adding new participants later
10. WHEN preprocessing is performed, THE System SHALL compute circuit-dependent data
11. WHEN preprocessing is expensive, THE System SHALL amortize over many proof generations
12. WHEN online phase is fast, THE System SHALL minimize per-proof work
13. WHEN setup size matters, THE System SHALL minimize SRS or commitment key size
14. WHEN setup is public, THE System SHALL publish parameters for verification
15. WHEN setup is verified, THE System SHALL check parameters are well-formed
16. WHEN no setup is needed, THE System SHALL use transparent schemes
17. WHEN hash functions provide setup, THE System SHALL use public randomness
18. WHEN lattice assumptions are used, THE System SHALL generate lattice parameters
19. WHEN setup affects security, THE System SHALL document trust assumptions
20. WHEN comparing schemes, THE System SHALL consider setup requirements

_Requirements: 6.1, 12.1_


### Requirement 28: Optimized Sum-Check Message Compression

**User Story:** As a proof size optimizer, I want sum-check message compression techniques, so that I can reduce communication overhead.

#### Acceptance Criteria

1. WHEN sending degree-d univariate polynomial, THE System SHALL transmit d+1 field elements
2. WHEN using coefficient representation, THE System SHALL send coefficients a_0, a_1, ..., a_d
3. WHEN using evaluation representation, THE System SHALL send evaluations at d+1 points
4. WHEN verifier can reconstruct polynomial, THE System SHALL send only d field elements
5. WHEN consistency check provides constraint, THE System SHALL use s_{i-1}(r_{i-1}) = s_i(0) + s_i(1)
6. WHEN sending s_i(0) and s_i(d), THE Verifier SHALL compute s_i(1) from consistency check
7. WHEN d = 2, THE System SHALL send only 2 field elements per round instead of 3
8. WHEN n rounds are executed, THE System SHALL save n field elements total
9. WHEN proof size is reduced, THE System SHALL maintain same security level
10. WHEN verifier work increases slightly, THE System SHALL accept small verification overhead for smaller proofs
11. WHEN polynomial interpolation is needed, THE Verifier SHALL reconstruct full polynomial from partial evaluations
12. WHEN Lagrange interpolation is used, THE System SHALL compute polynomial from evaluations
13. WHEN monomial basis is preferred, THE System SHALL convert between representations efficiently
14. WHEN multiple polynomials are sent, THE System SHALL apply compression to each
15. WHEN compression is optional, THE System SHALL make it configurable
16. WHEN bandwidth is constrained, THE System SHALL prioritize compression
17. WHEN computation is constrained, THE System SHALL consider uncompressed messages
18. WHEN comparing proof sizes, THE System SHALL account for compression techniques
19. WHEN implementing compression, THE System SHALL ensure correctness of reconstruction
20. WHEN verifier reconstructs polynomial, THE System SHALL verify degree bound is satisfied

_Requirements: 2.1, 2.2, 2.3_

### Requirement 29: Parallel and Distributed Proving

**User Story:** As a distributed systems developer, I want parallel and distributed proving capabilities, so that I can scale proof generation across multiple machines.

#### Acceptance Criteria

1. WHEN sum-check rounds are independent within round, THE System SHALL parallelize evaluations within each round
2. WHEN array updates are independent, THE System SHALL process updates in parallel
3. WHEN multiple cores are available, THE System SHALL distribute work across cores
4. WHEN work is partitioned, THE System SHALL minimize communication between workers
5. WHEN load balancing is needed, THE System SHALL distribute work evenly
6. WHEN synchronization is required, THE System SHALL minimize synchronization points
7. WHEN distributed proving is used, THE System SHALL partition witness across machines
8. WHEN partial proofs are generated, THE System SHALL combine into final proof
9. WHEN network communication is needed, THE System SHALL minimize data transfer
10. WHEN fault tolerance is required, THE System SHALL handle worker failures
11. WHEN checkpointing is used, THE System SHALL save intermediate state
12. WHEN resuming from checkpoint, THE System SHALL continue from saved state
13. WHEN memory is distributed, THE System SHALL access remote memory efficiently
14. WHEN cache coherence matters, THE System SHALL consider NUMA effects
15. WHEN GPU acceleration is used, THE System SHALL offload suitable operations to GPU
16. WHEN CPU-GPU communication is needed, THE System SHALL minimize transfers
17. WHEN multiple GPUs are used, THE System SHALL distribute work across GPUs
18. WHEN heterogeneous hardware is used, THE System SHALL assign work based on capabilities
19. WHEN measuring scalability, THE System SHALL benchmark speedup vs number of workers
20. WHEN efficiency is measured, THE System SHALL compute parallel efficiency ratio

_Requirements: 3.1, 4.1, 18.1_

### Requirement 30: Streaming and Memory-Efficient Proving

**User Story:** As a resource-constrained prover, I want streaming algorithms with controlled memory usage, so that I can generate proofs without exhausting memory.

#### Acceptance Criteria

1. WHEN memory is limited, THE System SHALL use streaming algorithms
2. WHEN data is processed in passes, THE System SHALL make controlled number of passes
3. WHEN each pass is sequential, THE System SHALL access data in order
4. WHEN memory usage is O(N^{1/c}), THE System SHALL achieve sublinear space
5. WHEN c is configurable, THE System SHALL allow tuning memory-time tradeoff
6. WHEN larger c is used, THE System SHALL reduce memory at cost of more passes
7. WHEN smaller c is used, THE System SHALL use more memory for fewer passes
8. WHEN optimal c is chosen, THE System SHALL balance memory and time
9. WHEN streaming prover is implemented, THE System SHALL avoid materializing full data
10. WHEN stage initialization is performed, THE System SHALL make one pass over non-zero terms
11. WHEN stage execution is performed, THE System SHALL work with reduced data
12. WHEN multiple stages are used, THE System SHALL transition between stages efficiently
13. WHEN external memory is used, THE System SHALL minimize I/O operations
14. WHEN disk access is needed, THE System SHALL use efficient file formats
15. WHEN compression is used, THE System SHALL compress intermediate data
16. WHEN decompression is needed, THE System SHALL decompress on-the-fly
17. WHEN memory mapping is used, THE System SHALL let OS manage paging
18. WHEN garbage collection is used, THE System SHALL minimize allocation pressure
19. WHEN memory pools are used, THE System SHALL reuse allocations
20. WHEN measuring memory usage, THE System SHALL track peak memory consumption

_Requirements: 4.1, 4.2, 9.1, 11.1_

### Requirement 31: Batching and Amortization Techniques

**User Story:** As a batch processing developer, I want batching techniques that amortize costs, so that I can prove many statements efficiently.

#### Acceptance Criteria

1. WHEN multiple statements are proven, THE System SHALL batch them together
2. WHEN batching is used, THE System SHALL amortize fixed costs
3. WHEN random linear combination is used, THE System SHALL combine statements with random coefficients
4. WHEN combined statement is proven, THE System SHALL ensure all original statements are valid
5. WHEN soundness error is bounded, THE System SHALL ensure error is negligible
6. WHEN batch size is T, THE System SHALL achieve O(1) amortized cost per statement
7. WHEN setup costs are amortized, THE System SHALL spread over all batch elements
8. WHEN commitment costs are amortized, THE System SHALL commit to batch data structure
9. WHEN verification costs are amortized, THE System SHALL verify batch in aggregate
10. WHEN batch evaluation argument is used, THE System SHALL prove many evaluations together
11. WHEN Shout is applied, THE System SHALL batch evaluate function at many points
12. WHEN amortized cost is O(c) per evaluation, THE System SHALL achieve constant amortized cost
13. WHEN c is small constant, THE System SHALL make batching practical
14. WHEN batch size is too small, THE System SHALL note fixed costs dominate
15. WHEN batch size is large enough, THE System SHALL achieve advertised amortized costs
16. WHEN optimal batch size is determined, THE System SHALL balance fixed and variable costs
17. WHEN batching multiple proofs, THE System SHALL aggregate into single proof
18. WHEN proof aggregation is used, THE System SHALL verify many proofs with one check
19. WHEN recursive aggregation is used, THE System SHALL build aggregation tree
20. WHEN measuring amortized cost, THE System SHALL divide total cost by batch size

_Requirements: 9.1, 9.2, 9.3_

### Requirement 32: Error Handling and Soundness Analysis

**User Story:** As a security analyst, I want rigorous soundness analysis and error handling, so that I can ensure cryptographic security guarantees.

#### Acceptance Criteria

1. WHEN soundness error is analyzed, THE System SHALL bound probability of accepting false statement
2. WHEN Schwartz-Zippel is applied, THE System SHALL bound error by d/|F| for degree-d polynomial
3. WHEN sum-check soundness is analyzed, THE System SHALL bound error by dn/|F| over n rounds
4. WHEN multiple protocols are composed, THE System SHALL add soundness errors
5. WHEN union bound is applied, THE System SHALL sum individual error probabilities
6. WHEN target security level is λ bits, THE System SHALL ensure total error ≤ 2^{-λ}
7. WHEN field size is chosen, THE System SHALL ensure |F| is large enough for target security
8. WHEN 128-bit security is desired, THE System SHALL use field of size at least 2^128
9. WHEN multiple challenges are used, THE System SHALL ensure sufficient randomness
10. WHEN challenge space is too small, THE System SHALL increase field size or use extension field
11. WHEN malicious prover is considered, THE System SHALL analyze worst-case behavior
12. WHEN honest prover is considered, THE System SHALL ensure perfect completeness
13. WHEN verifier always accepts valid proofs, THE System SHALL guarantee completeness
14. WHEN verifier rejects invalid proofs with high probability, THE System SHALL guarantee soundness
15. WHEN knowledge soundness is needed, THE System SHALL prove extractor exists
16. WHEN extractor can compute witness, THE System SHALL ensure knowledge property
17. WHEN Fiat-Shamir is applied, THE System SHALL analyze security in random oracle model
18. WHEN hash function is not random oracle, THE System SHALL consider standard model security
19. WHEN concrete security is analyzed, THE System SHALL provide explicit error bounds
20. WHEN security proof is formal, THE System SHALL document all assumptions and reductions

_Requirements: 1.1, 2.1, 2.2, 8.1, 21.1_

### Requirement 33: Benchmarking and Performance Measurement

**User Story:** As a performance analyst, I want comprehensive benchmarking infrastructure, so that I can measure and compare SNARK performance accurately.

#### Acceptance Criteria

1. WHEN benchmarking prover time, THE System SHALL measure wall-clock time for proof generation
2. WHEN measuring field operations, THE System SHALL count field multiplications and additions
3. WHEN measuring cryptographic operations, THE System SHALL count MSMs, pairings, hashes
4. WHEN measuring memory usage, THE System SHALL track peak memory consumption
5. WHEN measuring proof size, THE System SHALL report size in bytes
6. WHEN measuring verifier time, THE System SHALL time verification procedure
7. WHEN comparing systems, THE System SHALL use same hardware and inputs
8. WHEN reporting results, THE System SHALL specify hardware configuration
9. WHEN CPU is used, THE System SHALL report processor model and clock speed
10. WHEN GPU is used, THE System SHALL report GPU model and memory
11. WHEN multiple runs are performed, THE System SHALL report mean and standard deviation
12. WHEN warmup is needed, THE System SHALL exclude warmup runs from measurements
13. WHEN caching affects results, THE System SHALL control for cache effects
14. WHEN parallelism is used, THE System SHALL report number of threads/cores
15. WHEN scaling is measured, THE System SHALL vary input size and measure performance
16. WHEN asymptotic behavior is analyzed, THE System SHALL fit to theoretical complexity
17. WHEN bottlenecks are identified, THE System SHALL profile to find hotspots
18. WHEN optimizations are applied, THE System SHALL measure before and after
19. WHEN comparing to baselines, THE System SHALL use mature implementations
20. WHEN reporting performance, THE System SHALL provide reproducible benchmarks

_Requirements: 3.1, 18.1, 19.1, 23.1_

### Requirement 33A: Practical Deployment Considerations and Parameter Selection

**User Story:** As a SNARK deployment engineer, I want guidance on parameter selection and deployment considerations for Twist and Shout, so that I can optimize for my specific use case and hardware.

#### Acceptance Criteria

1. WHEN deploying for RISC-V registers (K=32), THE System SHALL use d = 1 for optimal performance
2. WHEN deploying for L1 cache (K ≈ 2^13), THE System SHALL consider d = 2 or 3
3. WHEN deploying for L2 cache (K ≈ 2^16), THE System SHALL consider d = 3 or 4
4. WHEN deploying for main memory (K ≈ 2^20 to 2^30), THE System SHALL use d = 4 to 8
5. WHEN deploying for gigantic structured tables (K = 2^64), THE System SHALL use sparse-dense sum-check
6. WHEN using HyperKZG with d = 1 and K = 32, T = 2^21, THE System SHALL require SRS of size 2^26 group elements
7. WHEN SRS size is too large, THE System SHALL increase d or use commitment size batching
8. WHEN commitment size batching is used, THE System SHALL trade k-fold SRS reduction for k group elements per commitment
9. WHEN using Dory with d = 1, THE System SHALL achieve commitment key size of 2·√(K·T) group elements
10. WHEN using Dory with d = 4 and K = 2^20, T = 2^20, THE System SHALL require commitment key of size 2^21 group elements
11. WHEN using Binius, FRI-Binius, or Blaze, THE System SHALL pack 128 values into single GF(2^128) element
12. WHEN using binary field schemes with K = 32, d = 1, THE System SHALL pack four addresses into single GF(2^128) element
13. WHEN using binary field schemes with K = 2^20, d = 4, THE System SHALL pack 128 values into single GF(2^128) element
14. WHEN commitment time is bottleneck with hashing schemes, THE System SHALL increase d
15. WHEN proof size is concern, THE System SHALL minimize d as proof size grows linearly with d
16. WHEN verifier time is concern, THE System SHALL note O(log K + log T) verification time
17. WHEN prover memory is limited, THE System SHALL use streaming algorithms with controlled memory usage
18. WHEN breaking execution into shards, THE System SHALL use roughly 2^19 to 2^21 cycles per shard
19. WHEN sharding is used, THE System SHALL prove each shard semi-independently
20. WHEN SNARK composition is needed, THE System SHALL use recursion to shrink proofs
21. WHEN cycle of curves is used for recursion, THE System SHALL pair curves with matching field sizes
22. WHEN Pasta curves are used, THE System SHALL leverage Pallas and Vesta curve cycle
23. WHEN trusted setup is required, THE System SHALL conduct multi-party ceremony for SRS generation
24. WHEN transparent setup is preferred, THE System SHALL use Dory or hashing-based schemes
25. WHEN post-quantum security is needed, THE System SHALL consider lattice-based or hashing-based schemes
26. WHEN 128-bit security is target, THE System SHALL ensure field size and soundness error provide adequate security
27. WHEN compiler optimizations are used, THE System SHALL note Twist and Shout benefit from CPU-optimized code
28. WHEN existing RISC-V toolchains are used, THE System SHALL avoid need for SNARK-friendly VM design
29. WHEN mature toolchains are preferred, THE System SHALL support existing VMs rather than custom designs
30. WHEN deployment platform varies (CPU vs GPU), THE System SHALL adapt to different bottlenecks

_Requirements: 1.1, 2.1, 9.1, 11.1, 11A.1, 15A.1, 17A.1, 23.1, 27.1_

### Requirement 33B: Relationship to Existing Memory Checking and Lookup Arguments

**User Story:** As a protocol researcher, I want to understand how Twist and Shout relate to existing memory checking and lookup arguments, so that I can appreciate the design space and make informed choices.

#### Acceptance Criteria

1. WHEN comparing to Spice, THE System SHALL note Spice commits to 5 values per read and 6 per write
2. WHEN Spice uses Thaler's grand product, THE System SHALL note 40T + 40K field operations
3. WHEN Spice uses Quarks grand product, THE System SHALL note commitment to 6 random field elements per operation
4. WHEN comparing to Lasso, THE System SHALL note Lasso commits to 3T + K small values
5. WHEN Lasso performs field operations, THE System SHALL note 12T + 12K field operations
6. WHEN comparing to LogUpGKR, THE System SHALL note LogUpGKR commits to 2T + K small values
7. WHEN LogUpGKR uses grand sum of rationals, THE System SHALL note roughly 24T + 24K field operations
8. WHEN comparing to Generalized-Lasso, THE System SHALL note Shout with d = log K is roughly equivalent
9. WHEN Spark-naive is used, THE System SHALL note similarity to Shout with d = log K
10. WHEN Spark commits to binary representation, THE System SHALL note base-2 matches Shout's maximum d
11. WHEN one-hot encoding is used, THE System SHALL note standard and one-hot encodings nearly coincide for base-2
12. WHEN d = log K is used, THE System SHALL minimize committed bits for hashing-based schemes
13. WHEN d = log K has downsides, THE System SHALL note superlinear prover time and large proof size
14. WHEN optimal d is chosen, THE System SHALL balance commitment costs, prover time, and proof size
15. WHEN FLI folding scheme is compared, THE System SHALL note FLI is folding scheme for lookups
16. WHEN Proofs for Deep Thought is compared, THE System SHALL note it is folding scheme for read/write memory
17. WHEN folding schemes are used, THE System SHALL recognize different approach to memory checking
18. WHEN Arya, plookup, Caulk are compared, THE System SHALL note they solve unindexed lookup problem
19. WHEN unindexed lookups are needed, THE System SHALL transform to indexed lookups with overhead
20. WHEN LogUp is compared, THE System SHALL note LogUp uses grand sum of rationals
21. WHEN cq is compared, THE System SHALL note cq is another lookup argument approach
22. WHEN Lasso uses decomposable tables, THE System SHALL note one lookup becomes O(C) subtable lookups
23. WHEN Lasso has interaction overhead with zkVMs, THE System SHALL note inputs must be decomposed into smaller chunks
24. WHEN Jolt uses Lasso for instruction execution, THE System SHALL note current approach splits inputs into 8-bit chunks
25. WHEN Shout is used in Jolt, THE System SHALL replace Lasso for improved performance
26. WHEN Twist is used in Jolt, THE System SHALL replace Spice for improved performance
27. WHEN end-to-end Jolt performance improves, THE System SHALL expect substantial speedups from Twist and Shout
28. WHEN memory checking fraction grows, THE System SHALL expect Twist and Shout to become even more important
29. WHEN other parts of Jolt optimize, THE System SHALL note memory checking will dominate prover time
30. WHEN Twist and Shout are integrated, THE System SHALL achieve over 45% reduction in current Jolt prover time

_Requirements: 2.1, 9.1, 10.1, 11.1, 11D.1, 17A.1, 18.1_

### Requirement 34: Testing and Correctness Verification

**User Story:** As a quality assurance engineer, I want comprehensive testing infrastructure, so that I can ensure implementation correctness.

#### Acceptance Criteria

1. WHEN unit tests are written, THE System SHALL test individual components
2. WHEN integration tests are written, THE System SHALL test component interactions
3. WHEN end-to-end tests are written, THE System SHALL test complete proof generation and verification
4. WHEN property-based tests are used, THE System SHALL test with random inputs
5. WHEN edge cases are tested, THE System SHALL include boundary conditions
6. WHEN error cases are tested, THE System SHALL verify proper error handling
7. WHEN soundness is tested, THE System SHALL verify false statements are rejected
8. WHEN completeness is tested, THE System SHALL verify true statements are accepted
9. WHEN determinism is tested, THE System SHALL verify reproducible results
10. WHEN randomness is tested, THE System SHALL use fixed seeds for reproducibility
11. WHEN cryptographic primitives are tested, THE System SHALL use test vectors
12. WHEN field arithmetic is tested, THE System SHALL verify correctness against reference implementation
13. WHEN polynomial operations are tested, THE System SHALL verify evaluation and interpolation
14. WHEN commitment schemes are tested, THE System SHALL verify binding and hiding properties
15. WHEN sum-check is tested, THE System SHALL verify all round checks
16. WHEN memory checking is tested, THE System SHALL verify read-write consistency
17. WHEN batch evaluation is tested, THE System SHALL verify all evaluations correct
18. WHEN virtual polynomials are tested, THE System SHALL verify consistency with explicit polynomials
19. WHEN regression tests are maintained, THE System SHALL prevent reintroduction of bugs
20. WHEN continuous integration is used, THE System SHALL run tests automatically

_Requirements: All requirements_

### Requirement 35: Documentation and API Design

**User Story:** As a library user, I want clear documentation and well-designed APIs, so that I can integrate SNARK functionality into applications.

#### Acceptance Criteria

1. WHEN API is designed, THE System SHALL provide clear function signatures
2. WHEN types are defined, THE System SHALL use descriptive names
3. WHEN parameters are documented, THE System SHALL explain purpose and constraints
4. WHEN return values are documented, THE System SHALL explain meaning and format
5. WHEN errors are documented, THE System SHALL list possible error conditions
6. WHEN examples are provided, THE System SHALL show common usage patterns
7. WHEN tutorials are written, THE System SHALL guide users through basic tasks
8. WHEN reference documentation is generated, THE System SHALL document all public APIs
9. WHEN internal documentation is written, THE System SHALL explain implementation details
10. WHEN algorithms are documented, THE System SHALL reference papers and provide intuition
11. WHEN security considerations are documented, THE System SHALL explain trust assumptions
12. WHEN performance characteristics are documented, THE System SHALL provide complexity analysis
13. WHEN configuration options are documented, THE System SHALL explain tradeoffs
14. WHEN migration guides are provided, THE System SHALL help users upgrade versions
15. WHEN changelog is maintained, THE System SHALL document changes between versions
16. WHEN contributing guidelines are provided, THE System SHALL explain development process
17. WHEN code style is documented, THE System SHALL specify formatting conventions
18. WHEN architecture is documented, THE System SHALL explain system structure
19. WHEN design decisions are documented, THE System SHALL explain rationale
20. WHEN limitations are documented, THE System SHALL be honest about current capabilities

_Requirements: All requirements_

### Requirement 36: Lattice-Based Polynomial Commitments

**User Story:** As a post-quantum cryptography developer, I want lattice-based polynomial commitment schemes, so that I can build quantum-resistant SNARKs.

#### Acceptance Criteria

1. WHEN lattice assumptions are used, THE System SHALL provide post-quantum security
2. WHEN SIS (Short Integer Solution) problem is hard, THE System SHALL base security on SIS
3. WHEN LWE (Learning With Errors) problem is hard, THE System SHALL base security on LWE
4. WHEN Ring-LWE is used, THE System SHALL exploit ring structure for efficiency
5. WHEN Module-LWE is used, THE System SHALL balance security and performance
6. WHEN lattice parameters are chosen, THE System SHALL ensure sufficient security level
7. WHEN dimension is selected, THE System SHALL balance security and efficiency
8. WHEN modulus is selected, THE System SHALL support required field operations
9. WHEN noise distribution is chosen, THE System SHALL ensure security and correctness
10. WHEN commitment is computed, THE System SHALL use lattice-based construction
11. WHEN opening is computed, THE System SHALL provide short proof
12. WHEN verification is performed, THE System SHALL check lattice relation
13. WHEN homomorphic properties are used, THE System SHALL exploit lattice homomorphism
14. WHEN batching is used, THE System SHALL commit to multiple polynomials efficiently
15. WHEN evaluation proofs are generated, THE System SHALL use lattice-based techniques
16. WHEN small-value preservation is exploited, THE System SHALL benefit from small coefficients
17. WHEN field choice is flexible, THE System SHALL support various field sizes
18. WHEN compared to elliptic curve schemes, THE System SHALL note larger proof sizes but quantum resistance
19. WHEN performance is optimized, THE System SHALL use NTT for polynomial multiplication
20. WHEN security is analyzed, THE System SHALL provide reduction to lattice problems

_Requirements: 6.1, 6.2, 16.1, 19.1_

### Requirement 37: Hash-Based Polynomial Commitments

**User Story:** As a transparent cryptography developer, I want hash-based polynomial commitment schemes, so that I can build SNARKs without trusted setup or number-theoretic assumptions.

#### Acceptance Criteria

1. WHEN hash functions are used, THE System SHALL require no trusted setup
2. WHEN collision resistance is assumed, THE System SHALL base security on hash function properties
3. WHEN Merkle trees are used, THE System SHALL commit to polynomial evaluations
4. WHEN FRI (Fast Reed-Solomon IOP) is used, THE System SHALL prove low-degree property
5. WHEN Ligero-PCS is used, THE System SHALL use linear codes for commitments
6. WHEN Brakedown is used, THE System SHALL achieve linear-time proving
7. WHEN WHIR is used, THE System SHALL achieve super-fast verification
8. WHEN commitment is computed, THE System SHALL hash polynomial data
9. WHEN opening is computed, THE System SHALL provide Merkle proof
10. WHEN verification is performed, THE System SHALL check Merkle path
11. WHEN proof size is analyzed, THE System SHALL note logarithmic or sublinear size
12. WHEN prover time is analyzed, THE System SHALL achieve linear or quasilinear time
13. WHEN verifier time is analyzed, THE System SHALL achieve logarithmic or sublinear time
14. WHEN concrete efficiency is measured, THE System SHALL compare hash operations to field operations
15. WHEN hash function is chosen, THE System SHALL use cryptographically secure hash
16. WHEN field-agnostic schemes are used, THE System SHALL support arbitrary fields
17. WHEN small fields are used, THE System SHALL exploit for faster arithmetic
18. WHEN binary fields are used, THE System SHALL use XOR-based operations
19. WHEN compared to pairing-based schemes, THE System SHALL note transparency and post-quantum security
20. WHEN integrating with sparse sum-checks, THE System SHALL address remaining challenges

_Requirements: 6.1, 6.2, 16.1, 19.1_

### Requirement 38: Formal Verification of SNARK Implementations

**User Story:** As a formal methods engineer, I want formally verified SNARK implementations, so that I can guarantee correctness with mathematical certainty.

#### Acceptance Criteria

1. WHEN formal verification is applied, THE System SHALL prove implementation correctness
2. WHEN specification is written, THE System SHALL formally define desired properties
3. WHEN implementation is verified, THE System SHALL prove it satisfies specification
4. WHEN soundness is verified, THE System SHALL prove false statements are rejected
5. WHEN completeness is verified, THE System SHALL prove true statements are accepted
6. WHEN field arithmetic is verified, THE System SHALL prove operations are correct
7. WHEN polynomial operations are verified, THE System SHALL prove evaluation and interpolation correct
8. WHEN sum-check is verified, THE System SHALL prove protocol correctness
9. WHEN commitment schemes are verified, THE System SHALL prove binding and hiding
10. WHEN Fiat-Shamir is verified, THE System SHALL prove transformation preserves security
11. WHEN memory safety is verified, THE System SHALL prove no buffer overflows or use-after-free
12. WHEN type safety is verified, THE System SHALL prove no type errors
13. WHEN functional correctness is verified, THE System SHALL prove output matches specification
14. WHEN security properties are verified, THE System SHALL prove cryptographic guarantees
15. WHEN proof assistant is used, THE System SHALL use Coq, Lean, Isabelle, or similar
16. WHEN extraction is used, THE System SHALL generate verified code from proof
17. WHEN refinement is used, THE System SHALL prove implementation refines specification
18. WHEN invariants are maintained, THE System SHALL prove loop invariants
19. WHEN preconditions are checked, THE System SHALL verify function preconditions
20. WHEN postconditions are checked, THE System SHALL verify function postconditions

_Requirements: All requirements, especially 19.1, 34.1_

### Requirement 39: Optimization Techniques Summary

**User Story:** As a SNARK optimizer, I want a comprehensive summary of all optimization techniques, so that I can apply them systematically.

#### Acceptance Criteria

1. WHEN optimizing commitment costs, THE System SHALL minimize number and size of committed objects
2. WHEN using virtual polynomials, THE System SHALL avoid committing to large or expensive polynomials
3. WHEN exploiting sparsity, THE System SHALL use sparse sum-check algorithms
4. WHEN exploiting small values, THE System SHALL preserve small-value property throughout protocol
5. WHEN exploiting repeated structure, THE System SHALL recognize and leverage patterns in computation
6. WHEN using prefix-suffix decomposition, THE System SHALL enable streaming proving with controlled memory
7. WHEN batching evaluations, THE System SHALL amortize costs over many evaluations
8. WHEN using memory checking, THE System SHALL prefer Twist over permutation-based approaches
9. WHEN using lookup arguments, THE System SHALL prefer Shout over circuit-based approaches
10. WHEN applying sum-check, THE System SHALL use linear-time prover for dense sums
11. WHEN applying sum-check, THE System SHALL use sparse prover for sparse sums
12. WHEN choosing PCS, THE System SHALL match to PIOP type (univariate vs multilinear)
13. WHEN using KZG, THE System SHALL accept trusted setup for constant-size proofs
14. WHEN using Bulletproofs/IPA, THE System SHALL accept slower proving for transparency
15. WHEN using Hyrax, THE System SHALL exploit vector-matrix-vector structure
16. WHEN using Dory, THE System SHALL combine benefits of Bulletproofs and Hyrax
17. WHEN using lattice-based PCS, THE System SHALL achieve post-quantum security
18. WHEN using hash-based PCS, THE System SHALL achieve transparency and field-agnosticism
19. WHEN parallelizing, THE System SHALL distribute work across cores efficiently
20. WHEN streaming, THE System SHALL control memory usage with configurable tradeoff
21. WHEN compressing proofs, THE System SHALL reduce communication overhead
22. WHEN applying Fiat-Shamir, THE System SHALL do so once at end of protocol
23. WHEN choosing field, THE System SHALL balance arithmetic cost and security level
24. WHEN targeting zkVM, THE System SHALL exploit repeated structure in VM execution
25. WHEN formal verification is possible, THE System SHALL prioritize verified implementations

_Requirements: All requirements_

### Requirement 40: Future Research Directions

**User Story:** As a cryptography researcher, I want to understand open problems and future directions, so that I can contribute to advancing the field.

#### Acceptance Criteria

1. WHEN post-quantum SNARKs are developed, THE System SHALL transition to 128-bit fields with lattice-based or hash-based PCS
2. WHEN formal verification is advanced, THE System SHALL verify complete SNARK implementations
3. WHEN VM abstraction is questioned, THE System SHALL explore principled alternatives to precompiles
4. WHEN combining circuits and VMs, THE System SHALL find optimal tradeoff between flexibility and performance
5. WHEN new PCS constructions are developed, THE System SHALL integrate with sum-check-based PIOPs
6. WHEN new sum-check optimizations are discovered, THE System SHALL apply to existing protocols
7. WHEN hardware acceleration is improved, THE System SHALL optimize for GPUs, FPGAs, ASICs
8. WHEN distributed proving is advanced, THE System SHALL scale across many machines efficiently
9. WHEN proof composition is improved, THE System SHALL reduce recursion overhead
10. WHEN new applications are explored, THE System SHALL apply sum-check-based techniques
11. WHEN standardization is pursued, THE System SHALL contribute to SNARK standards
12. WHEN deployment is scaled, THE System SHALL address operational challenges
13. WHEN security is analyzed, THE System SHALL provide tighter bounds and proofs
14. WHEN usability is improved, THE System SHALL make SNARKs accessible to more developers
15. WHEN education is advanced, THE System SHALL create better learning resources
16. WHEN tooling is developed, THE System SHALL build better development tools
17. WHEN debugging is improved, THE System SHALL provide better error messages and diagnostics
18. WHEN monitoring is added, THE System SHALL instrument for production deployment
19. WHEN integration is simplified, THE System SHALL provide high-level APIs and frameworks
20. WHEN ecosystem is grown, THE System SHALL foster community and collaboration

_Requirements: All requirements, especially 19.1, 19.2, 19.3_

## Summary

This requirements document comprehensively specifies a complete sum-check based SNARK system covering:

- **Mathematical Foundations** (Requirements 1-2): Finite fields, multilinear polynomials, equality polynomials, Schwartz-Zippel lemma
- **Core Sum-Check Protocol** (Requirements 2-4): Standard protocol, dense optimization, sparse/streaming variants
- **Advanced Protocols** (Requirements 5, 9-11, 17): GKR, Shout, Twist, permutation checking
- **Polynomial Commitments** (Requirements 6-7, 12-15, 36-37): KZG, Bulletproofs/IPA, Hyrax, Dory, lattice-based, hash-based
- **Optimization Techniques** (Requirements 8, 10, 16, 28-31, 39): Virtual polynomials, small-value preservation, batching, compression
- **System Architecture** (Requirements 18-20, 22): Jolt zkVM, historical context, circuit satisfiability
- **Implementation Concerns** (Requirements 21, 23-27, 29-30, 32-35, 38): Fiat-Shamir, hardware, ZK, parallelism, testing, documentation
- **Future Directions** (Requirement 40): Open problems and research opportunities

Every aspect of the paper has been captured with detailed acceptance criteria ensuring no concept is left unexplained or underexplored.
