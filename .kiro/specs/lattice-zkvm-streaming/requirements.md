# Lattice-Based zkVM for Streaming Computations - Complete Requirements

## Introduction

This specification defines the complete requirements for constructing a post-quantum secure, lattice-based Zero-Knowledge Virtual Machine (zkVM) capable of streaming computations. The system synthesizes cutting-edge primitives including lattice-based folding schemes (Neo/LatticeFold+), sum-check based arithmetization (SALSAA), and streaming proof generation (IVsC) to achieve concrete efficiency while maintaining rigorous security guarantees.

The implementation targets three core goals:
1. **G1**: Fully optimized lattice arithmetization with efficient lookup arguments and linear-time norm checks
2. **G2**: Support for streaming computations with sublinear memory via IVsC
3. **G3**: Sublinear accumulation verification comparable to Quasar
4. **G4**: Hash-free high-arity folding via Symphony-style CP-SNARK compilation

## Glossary

### Core Cryptographic Concepts

- **zkVM (Zero-Knowledge Virtual Machine)**: A system that proves correct execution of arbitrary programs while hiding the execution trace
- **IVC (Incrementally Verifiable Computation)**: Cryptographic primitive for sequential computations with efficient verification at any point
- **IVsC (Incrementally Verifiable Streaming Computation)**: Extension of IVC supporting streaming data with constant proof size and sublinear prover memory
- **PCD (Proof-Carrying Data)**: Generalization of IVC to directed acyclic graph computations
- **Folding Scheme**: Technique to compress multiple constraint system instances into one, deferring verification
- **Accumulation Scheme**: Primitive enabling efficient accumulation of predicate instances into a running accumulator

### Lattice-Specific Concepts

- **R_q**: Cyclotomic polynomial ring Z_q[X]/(X^φ + 1) where φ is a power of 2
- **SIS (Short Integer Solution)**: Lattice problem: find short s such that A·s = 0 mod q
- **LWE (Learning With Errors)**: Lattice problem: distinguish A·s + e from uniform
- **Ring-LWE/Ring-SIS**: Structured variants over polynomial rings for efficiency
- **Ajtai Commitment**: Lattice-based commitment C = A·s where ||s|| ≤ β
- **Norm Bound (β)**: Maximum allowed Euclidean norm for witness vectors
- **Modulus (q)**: Prime defining the ring R_q = Z_q[X]/(X^φ + 1)
- **Dimension (d)**: Ring degree φ, typically 64-4096

### Protocol Components

- **Sum-Check Protocol**: Interactive proof for verifying polynomial sums over Boolean hypercube
- **LDE (Low-Degree Extension)**: Multilinear extension of witness vectors for sum-check
- **CRT (Chinese Remainder Theorem)**: Decomposition of ring elements into slots for parallel operations
- **RoK (Reduction of Knowledge)**: Protocol reducing one relation to another while preserving knowledge
- **PCS (Polynomial Commitment Scheme)**: Scheme for committing to polynomials with evaluation proofs
- **CP-SNARK (Commit-and-Prove SNARK)**: SNARK proving statements about committed values

### Lookup and Memory Arguments

- **Lookup Argument**: Proves values are contained in a predefined table
- **Lasso/Shout**: Efficient lookup arguments using sum-check
- **Twist/Spice**: Read/write memory checking arguments
- **Sparse Commitment**: Commitment scheme with cost proportional to non-zero entries

### Mathematical Notation

- **||·||₂**: Euclidean (ℓ₂) norm
- **||·||∞**: Infinity (ℓ∞) norm - maximum absolute coefficient
- **⊙**: Hadamard (element-wise) product
- **⊗**: Tensor (Kronecker) product
- **eq̃(X,Y)**: Multilinear equality polynomial
- **f̃(X)**: Multilinear extension of vector f
- **[n]**: Set {0, 1, ..., n-1}
- **B^n**: Boolean hypercube {0,1}^n
- **negl(λ)**: Negligible function in security parameter λ

---

## Requirements

### Requirement 1: Lattice-Compatible Lookup Arguments

**User Story:** As a zkVM developer, I want efficient lookup arguments that work with lattice-based commitments, so that I can replace expensive constraint computations with table lookups while maintaining post-quantum security.

#### Acceptance Criteria

1. **Lookup RoK Integration**: WHEN the system processes a lookup operation, THE lookup argument SHALL reduce to sum-check claims compatible with the lattice folding scheme, WHERE the reduction produces multilinear evaluation claims of the form Σᵢ eq̃(r,i)·T[index_i].

2. **Batch Lookup Efficiency**: WHEN multiple lookups are performed in a single step, THE system SHALL batch all lookups using random linear combination, reducing O(k) PCS openings to O(1) via union polynomial technique.

3. **Sparse Index Polynomial**: THE system SHALL represent lookup indices as sparse multilinear polynomials, WHERE only non-zero entries contribute to commitment and proof costs.

4. **Table Commitment**: THE system SHALL commit to lookup tables using Ajtai commitments with "pay-per-bit" costs, WHERE commitment size scales with log(table_size) rather than table_size.

5. **Concrete Performance**: THE lookup argument overhead SHALL be at most 3× the cost of a single multilinear evaluation claim, measured in ring operations.

6. **Memory Checking**: THE system SHALL support both read-only (Shout/Lasso style) and read-write (Twist/Spice style) memory checking arguments.

7. **Soundness**: THE lookup argument SHALL achieve knowledge soundness with error at most negl(λ) under the Ring-SIS assumption with parameters (n, q, β) where β ≤ √(n·q).

### Requirement 2: Sparse Vector Commitment Efficiency

**User Story:** As a protocol designer, I want sparse vector commitments that don't incur full-vector costs for witnesses with few non-zero entries, so that zkVM traces with small field elements remain efficient.

#### Acceptance Criteria

1. **Sparse Commitment Scheme**: THE system SHALL implement sparse Ajtai commitments WHERE commitment cost is O(k·log q + log n) for k non-zero entries out of n total.

2. **Decomposition Overhead**: WHEN committing to sparse vectors, THE low-norm decomposition cost SHALL be O(k·log β) rather than O(n·log β).

3. **Efficiency Threshold**: THE sparse commitment SHALL outperform standard commitment WHEN sparsity ratio k/n < 1/(log n), providing at least 5× improvement for typical zkVM traces.

4. **Index Commitment**: THE system SHALL commit to non-zero positions using a Merkle tree of indices, enabling O(log n) position proofs.

5. **Batch Opening**: WHEN opening multiple positions, THE system SHALL batch openings using random linear combination, achieving O(1) proof size for O(k) openings.

6. **Compatibility**: THE sparse commitment scheme SHALL be compatible with the sum-check based norm verification protocol.

### Requirement 3: Linear-Time Sum-Check Based Norm Check

**User Story:** As a prover implementer, I want norm verification that runs in strictly linear time using sum-check, so that the norm check doesn't become a bottleneck in the proving process.

#### Acceptance Criteria

1. **Sum-Check Reduction**: THE norm check Π_norm SHALL reduce ||W||² verification to a sum-check claim of the form Σ_{z∈[d]^μ} u^T·CRT(LDE[W](z) ⊙ LDE[W̄](z̄)) = t.

2. **Linear Prover Complexity**: THE prover SHALL compute all sum-check round polynomials in O(m) total ring operations WHERE m = d^μ is the witness size, using dynamic programming.

3. **No Intermediate Commitments**: THE protocol SHALL NOT require commitments to intermediate products, eliminating the O(m log m) bottleneck of traditional approaches.

4. **Round Polynomial Degree**: EACH round polynomial g_j(X) SHALL have degree at most 2(d-1), requiring (2d-1) field elements per round.

5. **Communication Complexity**: THE total communication SHALL be (2d-1)·μ·e·log q + 2r·log|R_q| bits WHERE μ is number of variables, e is extension degree, r is number of columns.

6. **Verification Complexity**: THE verifier SHALL perform O(μ·d) field operations plus O(r) ring operations for final check.

7. **Batching**: THE system SHALL batch norm checks for multiple columns using random linear combination, reducing r checks to 1.

### Requirement 4: Exact ℓ₂ Standard Soundness

**User Story:** As a security analyst, I want exact soundness guarantees that prevent norm slack from accumulating across folding iterations, so that the final extracted witness is exactly correct.

#### Acceptance Criteria

1. **Guarded IPA**: THE polynomial commitment scheme SHALL implement "guarded inner product argument" that verifies norm bounds at each protocol step.

2. **ℓ∞ Smallness Check**: THE final extraction SHALL verify ||w||∞ ≤ B for explicit bound B, ensuring coefficient-wise correctness.

3. **Norm Tracking**: THE folding scheme SHALL track accumulated norm bounds across iterations, WHERE after k folds with factor d: ||w_k|| ≤ d^k · ||w_0||.

4. **Exact Extraction**: THE knowledge extractor SHALL recover the exact witness w (not an approximation w' with ||w' - w|| ≤ ε).

5. **Soundness Error**: THE total soundness error SHALL be at most 2^(-λ) for security parameter λ, accounting for all protocol steps.

6. **Parameter Constraints**: THE system SHALL enforce q > 2·β·d^k for k folding iterations to prevent modular wrap-around.

### Requirement 5: High-Arity Folding with Controlled Norm Growth

**User Story:** As a scalability engineer, I want to fold up to 2^10 instances at once while keeping norm growth manageable, so that I can minimize recursive overhead without exploding lattice parameters.

#### Acceptance Criteria

1. **High-Arity Fold**: THE system SHALL support folding ℓ_np ≤ 2^10 R1CS/CCS instances into a single folded instance.

2. **Union Polynomial**: THE prover SHALL construct union polynomial w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X) for efficient batching.

3. **Partial Evaluation**: THE folded witness SHALL be computed as w̃(X) = w̃_∪(τ,X) WHERE τ is the verifier challenge.

4. **Norm Bound After Fold**: THE folded witness norm SHALL satisfy ||w'|| ≤ ℓ·||γ||·max_i||w_i|| WHERE ||γ|| ≤ 2ℓ for subtractive challenge set.

5. **Two-Layer Architecture**: FOR ℓ > 64, THE system SHALL use two-layer folding with intermediate decomposition to control norm growth.

6. **Decomposition RoK**: THE system SHALL apply base decomposition Π_decomp after high-arity fold, producing k = O(log(ℓ·β)) vectors with ||w'_j|| ≤ b.

7. **Verifier Complexity**: THE accumulation verifier SHALL perform O(log ℓ) field operations and O(1) commitment operations per step.

### Requirement 6: Hash-Free CP-SNARK Compilation

**User Story:** As a recursion optimizer, I want to prove folding correctness without embedding Fiat-Shamir hashing into the recursive circuit, so that I can eliminate the major source of recursive overhead.

#### Acceptance Criteria

1. **CP-SNARK Interface**: THE system SHALL implement Commit-and-Prove SNARK with interface: Prove(C, w, stmt) → π WHERE C = Commit(w).

2. **No Hash Embedding**: THE recursive verifier SHALL NOT compute hash functions, instead verifying commitment relations directly.

3. **Lattice Instantiation**: THE CP-SNARK SHALL be instantiated using SALSAA or LaBRADOR variants for post-quantum security.

4. **Commitment Compatibility**: THE commitment scheme Π_cm SHALL satisfy:
   - Homomorphic: C(m₁) + C(m₂) = C(m₁ + m₂)
   - Extractable: Valid opening implies knowledge of m
   - Succinct: |C| = O(λ) independent of |m|

5. **Proof Size**: THE CP-SNARK proof size SHALL be O(λ²) field elements, independent of statement size.

6. **Verification Cost**: THE CP-SNARK verifier SHALL perform O(λ) group/ring operations.

### Requirement 7: Streaming Proof Generation (IVsC)

**User Story:** As a streaming application developer, I want to prove correct execution of long computations where input arrives sequentially, so that I can handle unbounded data streams with bounded resources.

#### Acceptance Criteria

1. **Incremental Updates**: WHEN new data chunk x_u arrives, THE prover SHALL update proof Π_t to Π_{t+1} processing only x_u, not the full history.

2. **Constant Proof Size**: THE proof size |Π_t| SHALL remain O(λ²) independent of computation length T.

3. **Sublinear Prover Memory**: THE prover SHALL operate in O(√T) space, not O(T).

4. **Rate-1 seBARG**: THE system SHALL implement rate-1 Somewhere Extractable Batch Argument from LWE/SIS assumptions.

5. **Streaming PCS**: THE polynomial commitment scheme SHALL support streaming evaluation in O(√n) space.

6. **Digest Hiding**: THE public digest d_t SHALL hide the full data stream while enabling verification.

7. **Extraction**: FOR any position i, THE extractor SHALL recover x_i from accepting proof with probability ≥ 1 - negl(λ).

### Requirement 8: Zero-Knowledge Streaming (zk-IVsC)

**User Story:** As a privacy-focused developer, I want streaming proofs that reveal nothing about the computation beyond its correctness, so that I can process sensitive data streams.

#### Acceptance Criteria

1. **Zero-Knowledge Property**: THE proof Π_t SHALL reveal no information about witness w beyond what's implied by the statement.

2. **Encrypted Digest**: THE system SHALL support verification against encrypted digest using RDM-PKE (Randomness-Dependent Message PKE).

3. **Simulator**: THERE SHALL exist PPT simulator S such that {S(stmt)} ≈_c {Prove(stmt, w)} for all valid (stmt, w).

4. **LPZK Integration**: THE system SHALL integrate Succinct Line-Point Zero-Knowledge for designated-verifier zkSNARKs from Ring-LWE.

5. **Streaming ZK**: THE zero-knowledge property SHALL hold even when the adversary observes intermediate proofs Π_1, Π_2, ..., Π_t.

### Requirement 9: Sublinear Accumulation Verification (Quasar-Style)

**User Story:** As an IVC designer, I want accumulation verification that's sublinear in the number of accumulated instances, so that recursive overhead doesn't dominate proving cost.

#### Acceptance Criteria

1. **Sublinear Verifier**: THE accumulation verifier complexity SHALL be O(log ℓ) field operations for ℓ accumulated instances.

2. **Constant CRC**: THE number of Commitment Random Linear Combination operations SHALL be O(1) per accumulation step.

3. **Total CRC Bound**: THE total CRC operations across N IVC steps SHALL be O(√N), not O(N).

4. **Multi-Cast Reduction**: THE system SHALL implement IOR_cast reducing ℓ instances to 1 committed instance with O(1) commitments.

5. **2-to-1 Reduction**: THE system SHALL implement IOR_fold reducing 2 accumulators to 1 with O(1) verifier work.

6. **Oracle Batching**: THE oracle batching protocol SHALL produce proofs sublinear in polynomial length.

### Requirement 10: CCS/R1CS Constraint System Support

**User Story:** As a constraint system designer, I want support for both R1CS and the more general CCS format, so that I can use the most efficient representation for each computation.

#### Acceptance Criteria

1. **R1CS Support**: THE system SHALL support R1CS constraints of form Az ⊙ Bz = Cz.

2. **CCS Support**: THE system SHALL support Customizable Constraint Systems with arbitrary multilinear structure.

3. **Plonkish Support**: THE system SHALL support Plonkish/HyperPlonk style constraints with selector polynomials.

4. **Constraint Batching**: THE system SHALL batch multiple constraints using random linear combination.

5. **Witness Mapping**: THE system SHALL efficiently map zkVM execution traces to constraint witnesses.

6. **Public Input Handling**: THE system SHALL correctly handle public inputs in the constraint system.

### Requirement 11: Concrete Parameter Selection

**User Story:** As a deployment engineer, I want concrete parameter recommendations for different security levels, so that I can configure the system appropriately.

#### Acceptance Criteria

1. **Security Levels**: THE system SHALL support λ ∈ {128, 192, 256} bit security.

2. **Parameter Tables**: THE system SHALL provide parameter tables mapping security level to (q, d, β, φ).

3. **Performance Estimates**: THE system SHALL provide concrete performance estimates (ops/sec, proof size, memory) for each parameter set.

4. **Lattice Estimator**: THE parameters SHALL be validated against the Lattice Estimator for SIS/LWE hardness.

5. **Norm Growth Analysis**: THE system SHALL document maximum folding depth for each parameter set before norm overflow.

### Requirement 12: Implementation Efficiency

**User Story:** As a performance engineer, I want the implementation to use all available hardware acceleration, so that proving is as fast as possible.

#### Acceptance Criteria

1. **Parallelization**: THE prover SHALL parallelize across all available CPU cores using work-stealing.

2. **SIMD Optimization**: THE ring arithmetic SHALL use AVX-512 instructions where available.

3. **Memory Efficiency**: THE prover SHALL use streaming algorithms to minimize memory footprint.

4. **NTT Optimization**: THE Number Theoretic Transform SHALL use optimized radix-2/radix-4 implementations.

5. **Cache Efficiency**: THE data structures SHALL be cache-aligned and access patterns cache-friendly.

6. **GPU Support**: THE system SHOULD support GPU acceleration for large-scale polynomial operations.

---

## Non-Functional Requirements

### Security Requirements

1. **Post-Quantum Security**: ALL cryptographic primitives SHALL be secure against quantum adversaries under standard lattice assumptions.

2. **Constant-Time Operations**: ALL secret-dependent operations SHALL be constant-time to prevent timing attacks.

3. **Memory Safety**: THE implementation SHALL be memory-safe with no undefined behavior.

4. **Audit Trail**: THE system SHALL log all security-relevant operations for audit purposes.

### Performance Requirements

1. **Prover Throughput**: THE prover SHALL achieve ≥ 10,000 constraints/second on commodity hardware.

2. **Verification Time**: THE verifier SHALL complete in ≤ 100ms for proofs up to 2^20 constraints.

3. **Proof Size**: THE proof size SHALL be ≤ 100KB for 2^20 constraints at 128-bit security.

4. **Memory Usage**: THE prover memory SHALL be ≤ 16GB for 2^20 constraints.

### Compatibility Requirements

1. **Rust Ecosystem**: THE implementation SHALL be pure Rust with no unsafe code in core cryptography.

2. **WASM Support**: THE verifier SHALL compile to WebAssembly for browser deployment.

3. **Serialization**: ALL data structures SHALL support efficient serialization/deserialization.

4. **API Stability**: THE public API SHALL follow semantic versioning.
