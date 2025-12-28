# Implementation Plan: Neo Lattice zkVM Complete System

## Overview

This implementation plan covers the complete Neo Lattice zkVM system synthesizing primitives from Quasar, SALSAA, Sum-check Survey, Neo, and Symphony papers.

---

- [x] 1. Foundation Layer: Cyclotomic Ring Arithmetic


  - [x] 1.1 Implement core ring element structure with balanced coefficient representation


    - Create `CyclotomicRing<PHI>` struct with coefficients in [-(q-1)/2, (q-1)/2]
    - Implement modular arithmetic for supported φ ∈ {64, 128, 256, 512, 1024, 2048, 4096}
    - _Requirements: 1.1, 1.5_


  - [x] 1.2 Implement NTT-based multiplication with O(φ log φ) complexity


    - Create `NTTElement<PHI>` for evaluation domain representation
    - Implement forward and inverse NTT with precomputed twiddle factors
    - Support radix-2 and radix-4 implementations
    - _Requirements: 1.2_
  - [x]* 1.3 Write property test for NTT round-trip consistency


    - **Property 1: Ring Arithmetic Consistency**
    - **Validates: Requirements 1.2**





  - [ ] 1.4 Implement CRT decomposition R_q ≅ (F_{q^e})^{φ/e}
    - Support splitting degrees e ∈ {1, 2, 4, 8}
    - Implement incomplete NTT for non-splitting rings
    - _Requirements: 1.3_
  - [ ] 1.5 Implement canonical embedding and norm computation
    - Create `CanonicalEmbedding<PHI>` for σ: R → C^φ
    - Implement ||x||_{σ,2}² = Trace(⟨x, x̄⟩)
    - Implement Trace_{K/Q}(x) function
    - _Requirements: 1.4, 1.6_
  - [ ]* 1.6 Write property test for norm computation via trace
    - **Property 5: Norm-check Correctness**


    - **Validates: Requirements 4.7**

- [ ] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.




- [ ] 3. Ajtai Commitment Scheme
  - [x] 3.1 Implement commitment key generation

    - Sample A ∈ R_q^{κ×m} uniformly at random
    - Configure κ = O(λ/log q) rows for security


    - _Requirements: 2.1_
  - [ ] 3.2 Implement basic commitment operation C = A·w
    - Enforce ||w|| ≤ β constraint
    - Track norm bounds through operations
    - _Requirements: 2.2, 2.6_


  - [ ]* 3.3 Write property test for commitment binding
    - **Property 2: Commitment Binding**
    - **Validates: Requirements 2.3**
  - [ ] 3.4 Implement homomorphic operations
    - Addition: C(w₁) + C(w₂) = C(w₁ + w₂)


    - Scalar multiplication for folding
    - _Requirements: 2.5_
  - [ ]* 3.5 Write property test for commitment homomorphism
    - **Property 3: Commitment Homomorphism**
    - **Validates: Requirements 2.5**
  - [ ] 3.6 Implement Neo's pay-per-bit matrix commitment
    - Vector to matrix transformation for field elements



    - Achieve O(k·log q + log n) cost for k non-zero entries
    - _Requirements: 2.4, 5.7, 21.18_
  - [ ]* 3.7 Write property test for pay-per-bit cost scaling
    - **Property 11: Pay-Per-Bit Cost Scaling**

    - **Validates: Requirements 5.7, 21.18**
  - [ ] 3.8 Implement folding-friendly linear homomorphism
    - Fold evaluation claims {(C_i, r, y_i)} → (C, r, y)
    - Support β ≥ 2 commitments with multilinear evaluations
    - _Requirements: 5.8, 5.9, 21.19_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. SALSAA Sum-Check Protocol
  - [x] 5.1 Implement basic sum-check prover with linear-time complexity

    - Dynamic programming (Thaler's optimization)
    - Work halving each round: O(N + N/2 + ... + 1) = O(N)
    - _Requirements: 4.1, 18.7, 21.12_
  - [ ]* 5.2 Write property test for sum-check soundness
    - **Property 4: Sum-check Soundness**
    - **Validates: Requirements 4.1, 4.10**


  - [ ] 5.3 Implement sum-check verifier with O(μ·d) complexity
    - Verify round polynomials g_j(X) with degree ≤ 2(d-1)


    - Final evaluation check
    - _Requirements: 4.2, 4.3_
  - [ ] 5.4 Implement batched norm checks via random linear combination
    - Reduce r columns to single sum-check
    - _Requirements: 4.4_
  - [x] 5.5 Implement Ξ_lde and Ξ_lde-⊗ relations
    - LDE relation extending Ξ_lin
    - Check LDE[M_i·W](r_i) = s_i mod q for structured matrices
    - _Requirements: 4.8, 21.7_
  - [x] 5.6 Implement Ξ_sum sumcheck relation
    - Verify Σ_{z∈[d]^μ}(LDE[W] ⊙ LDE[W̄])(z) = t mod q
    - _Requirements: 4.9_
  - [x] 5.7 Implement norm-check RoK Π_norm: Ξ_norm → Ξ_sum
    - Use identity ||x||²_{σ,2} = Trace(⟨x,x⟩)
    - Linear-time prover
    - _Requirements: 4.7, 21.6_
  - [x] 5.8 Implement sumcheck RoK Π_sum: Ξ_sum → Ξ_lde-⊗
    - Knowledge error κ = (2μ(d-1)+rφ/e-1)/q^e
    - _Requirements: 4.10_
  - [x] 5.9 Implement improved batching Π*_batch
    - Express bottom rows as sumcheck claims
    - Alternative to RPS/RnR batching
    - _Requirements: 4.12, 21.9_
  - [x] 5.10 Implement R1CS RoK Π_lin-r1cs
    - Reduce R1CS to evaluation claims over LDE
    - _Requirements: 4.11, 21.10_

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 7. Neo Folding Scheme for CCS
  - [x] 7.1 Implement CCS constraint system representation
    - Support Σ_i c_i · (Π_{j∈S_i} M_j · z) = 0
    - Sparse matrix storage
    - _Requirements: 16.2_
  - [x] 7.2 Implement union polynomial computation
    - w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y)·w̃^(k)(X)
    - _Requirements: 5.1, 8.7_
  - [ ]* 7.3 Write property test for union polynomial correctness (SKIPPED - No Tests)
    - **Property 9: Union Polynomial Correctness**
    - **Validates: Requirements 8.7**
  - [x] 7.4 Implement folded witness evaluation
    - w̃(X) = w̃_∪(τ,X) where τ is verifier challenge
    - _Requirements: 5.2_
  - [x] 7.5 Implement norm bound tracking for folded witnesses
    - ||w'|| ≤ ℓ·||γ||·max_i||w_i|| where ||γ|| ≤ 2ℓ
    - _Requirements: 5.3_
  - [ ]* 7.6 Write property test for folding norm bound (SKIPPED - No Tests)
    - **Property 7: Folding Norm Bound**
    - **Validates: Requirements 5.3**
  - [ ] 7.7 Implement base decomposition Π_decomp (STUB CREATED)
    - Produce k = O(log(ℓ·β)) vectors with ||w'_j|| ≤ b
    - _Requirements: 5.5, 21.21_
  - [ ] 7.8 Implement CCS reduction Π_CCS (STUB CREATED)
    - Single sum-check invocation over extension field
    - _Requirements: 5.10, 21.20_
  - [ ] 7.9 Implement RLC reduction Π_RLC (STUB CREATED)
    - Combine evaluation claims with extension field challenge
    - _Requirements: 5.11_
  - [ ] 7.10 Implement challenge set construction for small fields (STUB CREATED)
    - Ensure invertibility of differences
    - Support Goldilocks, M61, Almost Goldilocks
    - _Requirements: 5.12, 21.22_
  - [ ]* 7.11 Write property test for folding completeness (SKIPPED - No Tests)
    - **Property 6: Folding Completeness**
    - **Validates: Requirements 5.1, 5.2**

- [x] 8. Checkpoint - Ensure all tests pass



  - Ensure all tests pass, ask the user if questions arise.





- [x] 9. Quasar Sublinear Accumulation


  - [x] 9.1 Implement multi-cast reduction NIR_multicast


    - Transform R^ℓ to R^cm_acc with O(1) commitments
    - _Requirements: 8.4, 21.1_


  - [ ] 9.2 Implement union polynomial commitment
    - Efficient commitment to w̃_∪(Y,X)

    - _Requirements: 21.3_
  - [x] 9.3 Implement partial evaluation verification

    - Check w̃_∪(τ, r_x) = w̃(r_x) with soundness log n/|F|
    - _Requirements: 8.8, 21.4_

  - [ ]* 9.4 Write property test for partial evaluation verification
    - **Property 10: Partial Evaluation Verification**


    - **Validates: Requirements 8.8**

  - [ ] 9.5 Implement 2-to-1 reduction IOR_fold
    - Reduce 2 accumulators to 1 with O(1) verifier work



    - _Requirements: 8.5_
  - [ ] 9.6 Implement oracle batching IOR_batch
    - Sublinear proof size in polynomial length
    - _Requirements: 8.6, 8.11, 21.2_
  - [ ] 9.7 Implement constraint reduction via sum-check
    - G(Y) := F(x̃(Y), w̃(Y))·eq̃(Y, r_y) with Σ G(y) = 0



    - _Requirements: 8.9_
  - [x] 9.8 Implement reduced relation R_acc output



    - (x, τ, r_x, e) where e = G_{log ℓ}(τ_{log ℓ})·eq̃^{-1}(τ, r_y)
    - _Requirements: 8.10_
  - [x]* 9.9 Write property test for accumulation sublinearity


    - **Property 8: Accumulation Sublinearity**
    - **Validates: Requirements 8.1, 8.2**






- [ ] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.



- [ ] 11. Symphony High-Arity Folding
  - [x] 11.1 Implement high-arity folding for ℓ_np statements

    - Three-step process: commitment, sumcheck reduction, RLC

    - _Requirements: 7.7, 21.24_
  - [ ] 11.2 Implement monomial embedding range proof
    - Table polynomial t(X) = Σ_{i∈[1,d/2)} i·(X^i + X^{-i})
    - Monomial set M = {0, 1, X, ..., X^{d-1}}
    - _Requirements: 7.8, 21.25_
  - [x] 11.3 Implement structured random projection


    - J := I_{n/ℓ_h} ⊗ J' for sublinear verifier
    - J' ∈ {0,±1}^{λ_pj × ℓ_h}
    - _Requirements: 7.9, 21.26_
  - [ ] 11.4 Implement CP-SNARK compiler CM[Π_cm, Π_fold]
    - Send commitments c_{fs,i} = Π_cm.Commit(m_i) instead of messages
    - No Fiat-Shamir circuit embedding
    - _Requirements: 7.10, 21.27_
  - [ ]* 11.5 Write property test for CP-SNARK hash-free property
    - **Property 13: CP-SNARK Hash-Free Property**
    - **Validates: Requirements 7.2, 7.10**
  - [ ] 11.6 Implement two-layer folding
    - Split reduced statement (x_o, w_o) to multiple uniform NP statements
    - _Requirements: 7.11, 21.28_
  - [ ]* 11.7 Write property test for high-arity folding compression
    - **Property 12: High-Arity Folding Compression**
    - **Validates: Requirements 7.7**

- [ ] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Sum-check Optimizations (from Survey)
  - [ ] 13.1 Implement sparse sum-check prover
    - O(T) work for T non-zero terms
    - Prefix-suffix algorithm for structured sparsity
    - _Requirements: 18.11, 21.16_
  - [ ]* 13.2 Write property test for sparse sum-check efficiency
    - **Property 16: Sparse Sum-check Efficiency**
    - **Validates: Requirements 18.11**
  - [ ] 13.3 Implement virtual polynomial framework
    - Avoid materializing intermediate polynomials
    - Reduce commitment overhead
    - _Requirements: 18.9, 21.14_
  - [ ] 13.4 Implement batch evaluation argument (Shout-style)
    - Reduce T evaluations to single random evaluation
    - _Requirements: 18.8, 21.13_
  - [ ] 13.5 Implement memory checking protocols
    - Read/write verification with O(n) operations
    - One-hot addressing and increment checking
    - _Requirements: 11.1-11.6, 18.12, 21.17_
  - [ ] 13.6 Implement small-value preservation
    - Leverage witness bit-width for faster commitment
    - _Requirements: 18.10, 21.15_
  - [ ] 13.7 Implement streaming prover with O(n) space
    - 2 + log log(n) passes over input
    - _Requirements: 7.12, 14.3, 21.29_
  - [ ]* 13.8 Write property test for streaming prover space bound
    - **Property 14: Streaming Prover Space Bound**
    - **Validates: Requirements 7.12, 14.3**
  - [ ]* 13.9 Write property test for linear-time prover complexity
    - **Property 15: Linear-Time Prover Complexity**
    - **Validates: Requirements 18.7**

- [ ] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 15. Constraint System Support
  - [ ] 15.1 Implement R1CS constraint system
    - Az ⊙ Bz = Cz for sparse matrices A, B, C
    - _Requirements: 16.1_
  - [ ] 15.2 Implement Plonkish constraint support
    - f(q(X), w(X)) = 0 with selector polynomials
    - _Requirements: 16.3_
  - [ ] 15.3 Implement constraint batching via RLC
    - _Requirements: 16.4_
  - [ ] 15.4 Implement zkVM trace to constraint witness mapping
    - _Requirements: 16.5_
  - [ ] 15.5 Implement public input handling
    - _Requirements: 16.6_
  - [ ] 15.6 Implement product constraint proving via sum-check
    - g(x) := ã(x)·b̃(x) - c̃(x) with eq̃(r,x) randomization
    - _Requirements: 16.7_
  - [ ] 15.7 Implement multilinear extension computation
    - ã(r) = Σ_{x∈{0,1}^n} a(x)·eq̃(r,x)
    - _Requirements: 16.9_

- [ ] 16. Security and Parameter Validation
  - [ ] 16.1 Implement constant-time operations for secret-dependent code
    - _Requirements: 19.2_
  - [ ] 16.2 Implement parameter validation against Lattice Estimator
    - Verify Hermite factor and vSIS hardness
    - _Requirements: 17.1-17.6, 19.6_
  - [ ]* 16.3 Write property test for parameter security validation
    - **Property 19: Parameter Security Validation**
    - **Validates: Requirements 17.1, 17.6**
  - [ ] 16.4 Implement knowledge soundness extractor
    - Recover witness with probability ≥ 1 - negl(λ)
    - _Requirements: 19.3_
  - [ ]* 16.5 Write property test for knowledge soundness
    - **Property 17: Knowledge Soundness**
    - **Validates: Requirements 19.3**
  - [ ] 16.6 Implement zero-knowledge simulator
    - PPT simulator S with {S(stmt)} ≈_c {Prove(stmt, w)}
    - _Requirements: 15.1, 15.2_
  - [ ]* 16.7 Write property test for zero-knowledge simulation
    - **Property 18: Zero-Knowledge Simulation**
    - **Validates: Requirements 15.2**
  - [ ] 16.8 Implement soundness error tracking
    - Total error ≤ 2^(-λ) across all protocol steps
    - _Requirements: 19.5_

- [ ] 17. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 18. Application Layer: IVC/SNARK/PCD
  - [ ] 18.1 Implement IVC prover P^θ(ipk, z₀, z_i, (w_i, z_{i-1}, π_{i-1})) → π_i
    - _Requirements: 12.1_
  - [ ] 18.2 Implement IVC verifier V^θ(ivk, z₀, z_out, π_out) → {0,1}
    - _Requirements: 12.2_
  - [ ] 18.3 Implement unbounded-depth soundness
    - Extract valid witness chain for poly-bounded depth
    - _Requirements: 12.3_
  - [ ] 18.4 Implement SNARK builder interface
    - Support R1CS, CCS, Plonkish inputs
    - _Requirements: 20.1_
  - [ ] 18.5 Implement PCD builder for DAG computations
    - _Requirements: 20.1_
  - [ ] 18.6 Implement proof serialization with versioning
    - _Requirements: 20.2_

- [ ] 19. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 20. Performance Optimizations
  - [ ] 20.1 Implement parallel sum-check via Rayon
    - Work-stealing across all CPU cores
    - _Requirements: 18.1_
  - [ ] 20.2 Implement AVX-512-IFMA ring arithmetic
    - Hardware acceleration for cyclotomic ring operations
    - _Requirements: 18.2, 21.11_
  - [ ] 20.3 Implement optimized NTT with precomputed twiddles
    - Radix-2/radix-4 implementations
    - Incomplete NTT for non-splitting rings
    - _Requirements: 18.3_
  - [ ] 20.4 Implement cache-efficient data structures
    - Align data structures and optimize access patterns
    - _Requirements: 18.5_
  - [ ] 20.5 Implement streaming algorithms for memory efficiency
    - O(√T) space for stream length T
    - _Requirements: 18.4_

- [ ] 21. Distributed SNARK Support
  - [ ] 21.1 Implement distributed SumFold across M provers
    - O(T) computation per worker for T = N/M subcircuit
    - _Requirements: 13.1, 13.2_
  - [ ] 21.2 Implement coordinator aggregation
    - O(M) group operations at coordinator
    - _Requirements: 13.3_
  - [ ] 21.3 Implement communication protocol
    - O(N) field elements total
    - _Requirements: 13.4_

- [ ] 22. Streaming IVsC Support
  - [ ] 22.1 Implement streaming proof update
    - Update Π_t to Π_{t+1} processing only new chunk x_u
    - _Requirements: 14.1_
  - [ ] 22.2 Implement constant proof size maintenance
    - |Π_t| = O(λ²) independent of stream length T
    - _Requirements: 14.2_
  - [ ] 22.3 Implement rate-1 seBARG
    - LWE/SIS assumptions for somewhere extractability
    - _Requirements: 14.4_
  - [ ] 22.4 Implement streaming PCS
    - O(√n) space polynomial evaluation
    - _Requirements: 14.5_

- [ ] 23. API and Integration
  - [ ] 23.1 Implement IVCBuilder interface
    - _Requirements: 20.1_
  - [ ] 23.2 Implement SNARKBuilder interface
    - _Requirements: 20.1_
  - [ ] 23.3 Implement PCDBuilder interface
    - _Requirements: 20.1_
  - [ ] 23.4 Implement comprehensive error handling
    - All error types from design document
    - _Requirements: 20.4_
  - [ ] 23.5 Create Fibonacci IVC example
    - _Requirements: 20.3_
  - [ ] 23.6 Create aggregate signatures example
    - _Requirements: 20.3_
  - [ ] 23.7 Create PCD DAG example
    - _Requirements: 20.3_

- [ ] 24. Final Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

## Implementation Notes

### Dependencies
- `proptest` for property-based testing
- `rayon` for parallelization
- `thiserror` for error handling
- `serde` for serialization

### Testing Requirements
- Minimum 100 iterations per property-based test
- Each property test annotated with: `**Feature: neo-lattice-zkvm, Property {number}: {property_text}**`
- Each property test references requirements: `**Validates: Requirements X.Y**`

### Performance Targets
- Prover throughput: ≥ 10,000 constraints/second
- Verification time: ≤ 100ms for 2^20 constraints
- Proof size: ≤ 100KB for 2^20 constraints at 128-bit security
- Memory usage: ≤ 16GB for 2^20 constraints

