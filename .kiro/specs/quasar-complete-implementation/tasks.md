# Quasar: Sublinear Accumulation Schemes - Implementation Tasks

## Overview

This document provides a comprehensive implementation plan for the Quasar multi-instance accumulation scheme with compact, detailed tasks that combine related functionality. Each task is self-contained and implements complete subsystems.

**Key Innovation**: Quasar achieves O(√N) total CRC operations (vs O(N) in existing systems) through partial evaluation of union polynomials, replacing random linear combinations with w̃_∪(τ,X) evaluation.

---

## Task 1: Foundation - Field Arithmetic, MLE, and Sum-Check Protocol

Implement complete foundation layer including field operations, multilinear extensions, equality polynomials, and sum-check protocol with Fiat-Shamir transformation.

**Implementation Details:**
- [ ] 1.1 Field arithmetic and extensions
  - Implement `Field` trait: add, sub, mul, inv, neg, serialization
  - Implement `GoldilocksField` (q = 2^64 - 2^32 + 1) with 64-bit optimized arithmetic
  - Implement `M61Field` (q = 2^61 - 1) with Mersenne prime optimizations
  - Implement field extension F_{q^2} for Goldilocks: represent as (a + b·u) with u² = non-residue
  - Add Montgomery multiplication and Barrett reduction for efficiency
  - Validate field size ≥ 2^128 for 128-bit security (Requirement 1.7)
  - _Requirements: 1.1, 1.2, 1.5, 1.6, 8.1_

- [ ] 1.2 Multilinear extensions and helper functions
  - Implement `MultilinearExtension<F>` with coefficient storage and evaluation
  - Compute MLE from vector: f̃(X) = Σ_{i∈[n]} f[i] · eq̃(X, Bits(i))
  - Implement evaluation at arbitrary points using Horner's method
  - Implement partial evaluation w̃_∪(τ, X) for union polynomials
  - Implement Bits(i) binary representation with variable bit-widths
  - Implement equality polynomial eq̃_i(X) = Π_{j=0}^{log n-1} (Bits(i)[j]·X_j + (1-Bits(i)[j])(1-X_j))
  - Verify Corollary 1: (eq̃_i(b))^d = eq̃_i(b) and eq̃_i(b)·eq̃_j(b) = 0 for i≠j
  - Implement power polynomial pow_j(X) = Π_{k∈S} X_k for j = Σ_{k∈S} 2^k + 1
  - Add caching for frequently used eq̃_k(Y) values
  - _Requirements: 8.1, 8.2, 8.3, 3.1, 3.11, 4.4_

- [ ] 1.3 Sum-check protocol with dynamic programming
  - Implement `SumCheckProver<F>` with O(m) complexity using dynamic programming
  - Compute round polynomial f_i(X) = Σ_{x_{i+1},...,x_n∈B^{n-i}} f̃(r_1,...,r_{i-1},X,x_{i+1},...,x_n) (Equation 4)
  - Use memoization to avoid recomputation: store intermediate sums
  - Generate log ℓ round polynomials for multi-cast reduction
  - Implement `SumCheckVerifier<F>` with checks:
    * G_1(0) + G_1(1) = claimed_sum
    * G_{i+1}(0) + G_{i+1}(1) = G_i(τ_i) for each round
    * G(τ) = f̃(r_1,...,r_n) at final step
  - Verify soundness error ≤ (log ℓ · d)/|F| per Schwartz-Zippel (Lemma 1, Equation 5)
  - _Requirements: 8.4, 8.5, 8.6, 8.7, 3.7, 3.8_

- [ ] 1.4 Fiat-Shamir transformation and transcript
  - Implement `FiatShamirTranscript` using BLAKE3 hash function
  - Add domain separation: hash("domain" || phase_id || data)
  - Implement challenge sampling: challenges derived from transcript state
  - Support transcript forking for parallel protocols
  - Ensure proper sequencing: r_0 ← RO({x^(k)}), r_i ← RO(r_{i-1}, C_{∪,i})
  - Implement state-restoration attack prevention via RBR knowledge soundness
  - Verify random oracle queries: μ + log ℓ queries for multi-cast
  - _Requirements: 14.6, 14.7, 9.6, 9.7_

- [ ]* 1.5 Property tests for foundation
  - **Property: Field axioms** - Test associativity, commutativity, distributivity, inverse
  - **Property: MLE correctness** - Test f̃(Bits(i)) = f[i], partial evaluation w̃_∪(τ,r_x) = w̃(r_x)
  - **Property 6: Sum-Check Soundness** - Test rejection probability for invalid polynomials ≤ (log ℓ·d)/|F|
  - Test with ℓ = 2,4,8,16 instances and various polynomial degrees d = 2,3,5
  - _Requirements: 8.1, 8.2, 8.6, 8.7_



## Task 2: Polynomial Commitment Schemes - Curve-Based and Code-Based

Implement complete PCS layer with both elliptic curve-based (Mercury) and linear code-based (Brakedown) commitments, including homomorphic and proximity-based oracle batching.

**Implementation Details:**
- [ ] 2.1 Generic PCS interface and curve-based implementation
  - Define `PolynomialCommitmentScheme<F>` trait with methods:
    * Setup(1^λ, n) → ck: generate commitment key for F_n^{<2} polynomials
    * Commit(ck, p(X)) → C: commit to multilinear polynomial
    * Open(ck, C, p(X)) → b: verify commitment opens to polynomial
    * Eval(P(p(X)), V(ck, C, z, y)): prove/verify p(z) = y
  - Implement Pedersen commitment: C = Σ_i p_i · G_i for generators {G_i}
  - Implement Mercury PCS with O(1) proof size and O(1) verifier group operations
  - Add homomorphic property: Commit(p_0 + p_1) = Commit(p_0) + Commit(p_1)
  - Implement batch verification for multiple commitments
  - Verify binding property: Pr[Open(C,p_0)=Open(C,p_1)=1 ∧ p_0≠p_1] ≤ negl(λ)
  - Verify knowledge soundness for Eval protocol (Definition 13)
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 9.1_

- [ ] 2.2 Homomorphic oracle batching (Algorithm 8)
  - Implement batching for homomorphic PCS:
    * Input: Two commitments C_0, C_1, challenge r, point x, value v
    * Compute batched commitment: C = eq̃_0(r)·C_0 + eq̃_1(r)·C_1
    * Verify: eq̃_0(r)·f̃_0(x) + eq̃_1(r)·f̃_1(x) = v
    * Output: C, evaluation claims [(x,v)], empty proof (homomorphic property)
  - Optimize for 2μ parallel batching operations in 2-to-1 reduction
  - Verify O(1) group operations per batching
  - _Requirements: 5.1, 5.2, 9.1, 9.2_

- [ ] 2.3 Linear code-based PCS implementation
  - Implement systematic linear code C: F^k → F^n with generator matrix G
  - Ensure first k entries of C(f) equal f (systematic property)
  - Implement Reed-Solomon code with rate ρ = k/n = 1/2
  - Use NTT-based encoding for O(n log n) complexity
  - Compute minimum distance δ(C) = 1 - ρ for RS codes
  - Implement multilinear extension for codewords:
    * ũ_i(Y,X) = eq̃_0(Y)·f̃_i(X) + Σ_{i=1}^{log(1/ρ)} eq̃_i(Y) Σ_{j=0}^{log k-1} eq̃_j(X)·u_i[i·k+j]
  - Implement zero-evader ZE(α) = (G̃(α,b))_{b∈{0,1}^{log k}} with error log n/|F|
  - Implement out-of-domain sampling: sample α ∈ F^{log n} \ {0,1}^{log n}, compute ũ(α)
  - Verify Definition 9: Pr[∃ distinct u,v ∈ Λ(C,f,δ) : ∀i, ⟨ZE(ρ_i),C^{-1}(u)⟩ = ⟨ZE(ρ_i),C^{-1}(v)⟩] ≤ |Λ(C,δ)|^{2s}/2 · ϵ_zero
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 2.4 Proximity testing and Merkle commitments
  - Implement list decoding Λ(C, u, δ): find all codewords within distance δ of u
  - Implement proximity test with distance parameter δ
  - Verify Theorem 6 security: field size |F| ≥ 2^{λ/s-1} · |L(C,δ)|^{2/s} and t ≥ λ/(-log(1-δ))
  - Implement Merkle tree commitment (BCS transform):
    * Build Merkle tree over codeword with BLAKE3 hashing
    * Generate opening proofs with authentication paths
    * Implement batch opening for multiple positions
  - Add collision-resistant hashing with 256-bit security
  - _Requirements: 7.6, 7.7, 6.6_

- [ ] 2.5 Code-based oracle batching (Algorithm 9)
  - Implement batching for code-based PCS:
    * Encode f_0, f_1 to systematic codewords u_0 = C(f_0), u_1 = C(f_1)
    * Compute batched codeword: u = eq̃_0(r)·u_0 + eq̃_1(r)·u_1
    * Sample out-of-domain points α_{r+1},...,α_{r+s} ∈ F^{log(1/ρ)+log n}
    * Compute evaluations μ_{r+j} = ũ(α_{r+j}) for j ∈ [s]
    * Verify batching: eq̃_0(r)·ũ_0(α) + eq̃_1(r)·ũ_1(α) = ũ(α)
    * Run proximity test on batched codeword u
    * Handle shift queries b_1,...,b_t ∈ {0,1}^{log(1/ρ)+log n}
  - Output: batched codeword u, evaluation claims, proximity proof
  - Verify succinctness: proof size o(n)
  - _Requirements: 5.1, 5.2, 6.6, 14.5_

- [ ]* 2.6 Property tests for PCS
  - **Property 11: Post-Quantum Security** - Verify code-based PCS security against quantum adversaries
  - **Property 7: Oracle Batching Succinctness** - Verify proof size o(n) for polynomials of size n
  - **Property 12: Constant Verification (Curve-Based)** - Verify O(1) group operations for curve-based PCS
  - Test binding, knowledge soundness, completeness for both PCS types
  - Test with n = 2^10, 2^15, 2^20 and various code rates ρ = 1/2, 1/4
  - _Requirements: 6.2, 6.3, 6.4, 7.1-7.7, 9.1, 9.2_



## Task 3: Multi-Cast Reduction - Union Polynomials and IOR_cast Protocol

Implement complete multi-cast reduction from ℓ predicate instances to one committed instance, achieving O(log ℓ) verifier complexity through partial evaluation technique.

**Implementation Details:**
- [ ] 3.1 Union polynomial construction with optimization
  - Implement `UnionPolynomial<F>` struct storing (log_ell, log_n, evaluations, mle)
  - Compute witness union: w̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y) · Σ_{i∈[n]} eq̃_i(X) · w_k[i]
  - Compute instance union: x̃_∪(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y) · Σ_{i∈[m]} eq̃_i(X) · x_k[i]
  - Verify w̃_∪(Bits(k), X) = w̃^(k)(X) for all k ∈ [ℓ]
  - Implement streaming construction: process witnesses in chunks for memory efficiency
  - Use memory-mapped files for witnesses > 100MB
  - Implement parallel construction: compute eq̃_{k-1}(Y)·w̃^(k)(X) in parallel using Rayon
  - Add configurable thread count and NUMA-aware allocation
  - Optimize memory layout: structure-of-arrays for cache efficiency
  - _Requirements: 3.1, 3.6, 14.1, 14.2, 15.1, 15.4, 15.10_

- [ ] 3.2 Partial evaluation and batching
  - Implement `BatchedPolynomial<F>` with (tau, polynomial) fields
  - Compute partial evaluation: w̃(X) = w̃_∪(τ, X) where τ ∈ F^{log ℓ} is challenge
  - Verify batching correctness: w̃(X) = Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · w̃^(k)(X) (Equation 1)
  - Implement evaluation caching: cache eq̃_{k-1}(τ) values for all k
  - Add LRU cache for frequently used evaluation points
  - Precompute Lagrange basis polynomials
  - Verify soundness error ≤ log n/|F| for partial evaluation check (Equation 3)
  - _Requirements: 3.2, 3.3, 3.4, 15.1_

- [ ] 3.3 Multi-cast reduction prover (Algorithm 1, IOR_cast)
  - Implement `MultiCastProver<F>` with complete Algorithm 1:
    * Step 1-2: Compute MLEs {w̃^(k)(X), x̃^(k)(X)}_{k∈[ℓ]} and union polynomials
    * Step 3: Commit C_∪ ← PCS.Commit(w̃_∪) using selected PCS
    * Step 4: Sample challenge τ ← F^{log ℓ} via Fiat-Shamir from transcript
    * Step 5: Compute batched polynomials w̃(X) = w̃_∪(τ,X), x̃(X) = x̃_∪(τ,X)
    * Step 6: Commit C ← PCS.Commit(w̃)
    * Step 7: Sample challenge r_y ← F^{log ℓ} via Fiat-Shamir
    * Step 8: Compute constraint polynomial G(Y) = F(x̃(Y), w̃(Y)) · eq̃(Y, r_y) (Equation 8)
    * Step 9: Run sum-check for Σ_{y∈B^{log ℓ}} G(y) = 0, extract final τ
    * Step 10: Sample challenge r_x ← F^{log n} via Fiat-Shamir
    * Step 11: Compute evaluations v_∪ = w̃_∪(τ, r_x), v = w̃(r_x)
    * Step 12: Compute reduced instance x = Σ_{k∈[ℓ]} eq̃_{k-1}(τ)·x^(k), e = G_{log ℓ}(τ_{log ℓ})·eq̃^{-1}(τ,r_y)
    * Step 13: Output x = (x, τ, r_x, e), w = w̃, π_multicast = (C_∪, C, π_sumcheck, v_∪, v)
  - Verify reduced relation R_acc: {(C_∪, C, τ, r_x; w̃_∪, w̃) : C_∪=Commit(w̃_∪) ∧ C=Commit(w̃) ∧ w̃_∪(τ,r_x)=w̃(r_x)}
  - Verify complexity: log ℓ + 2 rounds, d log ℓ field elements + (ℓn + n) oracle elements
  - _Requirements: 3.1-3.10, 8.1-8.4_

- [ ] 3.4 Multi-cast reduction verifier (Algorithm 2)
  - Implement `MultiCastVerifier<F>` with complete Algorithm 2:
    * Step 1: Compute batched instance x = Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · x^(k), verify matches claimed
    * Step 2: Verify sum-check proof π_sumcheck, extract G_{log ℓ}(τ_{log ℓ})
    * Step 3: Compute e_computed = G_{log ℓ}(τ_{log ℓ}) · eq̃^{-1}(τ, r_y), verify e = e_computed
    * Step 4: Verify partial evaluation: v_∪ = v
    * Step 5: Return Accept/Reject
  - Verify verifier complexity: O(ℓ·n) field operations, no polynomial queries
  - Verify constant commitments: exactly 2 polynomial oracles in reduced relation
  - _Requirements: 3.10, 3.11_

- [ ] 3.5 Special-sound protocol integration (CV[Π_sps], Figure 6)
  - Implement transformation for (2μ-1)-move SPS to (2μ+3)-move CV[Π_sps]:
    * For each round i ∈ [μ]: compute m_i^(k) ← P_sps(x^(k), w^(k), {m_j^(k), r_j}_{j<i})
    * Compute m̃_∪,i(Y,X) = Σ_{k∈[ℓ]} eq̃_{k-1}(Y) · m̃_i^(k)(X)
    * Send oracle [[m̃_∪,i]] instead of O(ℓn)-sized messages (optimization)
    * Receive challenge r_i ← F
    * After μ rounds: set α = r_μ, compute α = (α, α², α⁴, ..., α^{2^{log ν-1}})
    * Verify α_0 = α and α_{i+1} = α_i² for all i ∈ [log ν - 1]
  - Compute linearly combined map F(x, {m_i}_{i∈[μ]}, r, α) = Σ_{j∈[ν]} pow_j(α) · V_sps(x, {m_i}, r)[j] = 0 (Equation 14)
  - Run remaining IOR_cast process (steps 3-9 from Algorithm 1)
  - Verify Lemma 4: (2μ+3)-move protocol is (k_0,...,k_{μ-1},ν+1)-special-sound
  - Output reduced instance satisfying R_acc = R^μ_eval × R^μ_eval × R_F (Equations 16-18)
  - _Requirements: 4.1-4.12, 22.1-22.6_

- [ ]* 3.6 Property tests for multi-cast reduction
  - **Property 1: Multi-Cast Partial Evaluation Correctness** - For any ℓ witnesses and challenge τ, verify w̃(X) = Σ_{k∈[ℓ]} eq̃_{k-1}(τ)·w̃^(k)(X)
  - **Property 4: Sublinear Verifier Complexity** - Verify O(log ℓ) field ops, O(1) CRC ops
  - Test completeness with valid inputs for ℓ = 2,4,8,16,32
  - Test soundness error bounds: ϵ_zc = dℓ/|F|, ϵ^sc_i = d/|F|, ϵ_agg = n/|F|
  - Test with various constraint functions F of degree d = 2,3,5
  - Test parallel construction correctness with 1,2,4,8 threads
  - Test memory efficiency: peak usage ≤ O(ℓn + μn)
  - _Requirements: 3.1-3.11, 13.1-13.11, 14.1, 14.2, 15.1_



## Task 4: 2-to-1 Reduction - Batched Polynomials and IOR_fold Protocol

Implement complete 2-to-1 reduction from two accumulators to one, using batched polynomials, combined sum-check, and parallel oracle batching.

**Implementation Details:**
- [ ] 4.1 Batched polynomial computation and verification (Equations 22-30, Construction 1)
  - Implement batched polynomial computation for two accumulators acc^(0), acc^(1):
    * Compute x̃(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · x^(k) ∈ (F_1^{<2})^m (Equation 22)
    * Compute r̃_F(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · r_F^(k) ∈ (F_1^{<2})^{μ+log ν} (Equation 23)
    * Compute τ̃(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · τ^(k) ∈ (F_1^{<2})^{log ℓ} (Equation 24)
    * Compute r̃_x(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · r_x^(k) ∈ (F_1^{<2})^{log n} (Equation 25)
    * For all i ∈ [μ]: compute m̃_∪,i(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · m_∪^(k) ∈ (F_1^{<2})^{ℓn} (Equation 26)
    * For all i ∈ [μ]: compute m̃_i(Z) = Σ_{k∈{0,1}} eq̃_k(Z) · m_i^(k) ∈ (F_1^{<2})^n (Equation 27)
  - Verify batched polynomial constraints for all z ∈ {0,1}:
    * F(x̃(z), {m_i(z)}_{i∈[μ]}, r_F(z)) = Σ_{k∈{0,1}} eq̃_k(z) · e^(k) = ẽ(z) (Equation 28)
    * m̃_i(z, r_x(z)) = Σ_{k∈{0,1}} eq̃_k(z) · v_i^(k) = ṽ_i(z) ∀i ∈ [μ] (Equation 29)
    * m̃_∪,i(z, τ(z), r_x(z)) = Σ_{k∈{0,1}} eq̃_k(z) · v_i^(k) = ṽ_i(z) ∀i ∈ [μ] (Equation 30)
  - Optimize for parallel computation of batched polynomials
  - _Requirements: 5.3, 5.4, 5.5, 23.1-23.3_

- [ ] 4.2 Combined polynomial and 1-round sum-check (Equations 31-35, Algorithm 3)
  - Sample challenges γ ← F^{log(μ+1)}, r_z ← F via Fiat-Shamir
  - Compute combined polynomial G(Z) with degree max(d+1, log ℓ + log n):
    * G(Z) = eq̃(r_z, Z) · (F(x̃(Z), {m_i(Z)}_{i∈[μ]}, r̃_F(Z)) - ẽ(Z))
           + Σ_{i∈[μ]} pow_i(γ) · (m̃_i(Z, r̃_x(Z)) - ṽ_i(Z))
           + Σ_{i∈[μ]} pow_{μ+i}(γ) · (m̃_∪,i(Z, τ̃(Z), r̃_x(Z)) - ṽ_i(Z)) (Equation 31)
  - Run 1-round sum-check for Σ_{z∈{0,1}} G(z) = 0:
    * Prover sends polynomial G(Z)
    * Verifier checks G(0) + G(1) = 0
    * Sample challenge σ ← F via Fiat-Shamir
    * Output evaluation claim G(σ) = v_G
  - Compute evaluation values:
    * η = F(x̃(σ), {m_i(σ)}_{i∈[μ]}, r̃_F(σ)) - ẽ(σ) (Equation 32)
    * η_i = m̃_i(σ, r̃_x(σ)) - ṽ_i(σ) ∀i ∈ [μ] (Equation 33)
    * η_∪,i = m̃_∪,i(σ, τ̃(σ), r̃_x(σ)) - ṽ_i(σ) ∀i ∈ [μ] (Equation 34)
  - Verify G(σ) = eq̃(r_z, σ) · (η + Σ_{i∈[μ]} pow_i(γ)·η_i + Σ_{i∈[μ]} pow_{μ+i}(γ)·η_∪,i) (Equation 35)
  - _Requirements: 5.6, 5.7, 5.8, 5.9, 5.10_

- [ ] 4.3 2-to-1 reduction prover and verifier (Algorithms 3-4, NIR_fold)
  - Implement `TwoToOneProver<F>` with complete Algorithm 3:
    * Input: Two accumulators acc^(0), acc^(1) with format from Equations 19-21
    * Compute all batched polynomials (Task 4.1)
    * Compute combined polynomial G(Z) and run sum-check (Task 4.2)
    * Run 2μ oracle batching protocols in parallel with challenge σ
    * For each i ∈ [μ]: batch (m̃_∪,i^(0), m̃_∪,i^(1)) and (m̃_i^(0), m̃_i^(1))
    * Compute new accumulator: x = x̃(σ), τ = τ̃(σ), r_x = r̃_x(σ), r_F = r̃_F(σ), e = ẽ(σ)
    * Output acc = (x, τ, r_x, r_F, e, {m̃_∪,i, m̃_i}_{i∈[μ]}) and π_fold
  - Implement `TwoToOneVerifier<F>` with complete Algorithm 4:
    * Verify sum-check: G(0) + G(1) = 0
    * Verify G(σ) evaluation using Equation 35
    * Verify all 2μ oracle batching proofs
    * Output new accumulator instance acc.x
  - Implement optimization (Equations 39-40): reduce oracle count from 2μ to μ+1
    * Preprocess with oracle batching: v = Σ_{i∈[μ]} pow_i(β) · v_i
    * Compute m̃_∪(Y,X) = Σ_{i∈[μ]} pow_i(β) · m̃_∪,i(Y,X)
  - Verify Lemma 6 complexity: 3 rounds, O(d+μ) field elements, O(μn) oracle elements (optimized)
  - Verify soundness errors: ϵ_zc = (μ+1)/|F|, ϵ_sc = max(d+1,log(ℓn))/|F|, ϵ_eval = μ/|F|, ϵ_batch = 2μ·ϵ_0
  - _Requirements: 5.3-5.14, 13.12-13.15, 23.1-23.3_

- [ ]* 4.4 Property tests for 2-to-1 reduction
  - **Property 5: 2-to-1 Folding Correctness** - For any two valid accumulators, verify new accumulator preserves all instances
  - Test completeness with valid accumulator pairs
  - Test soundness error bounds from Lemma 6
  - Test with various μ = 1,2,5,10 values
  - Test optimization: verify μ+1 oracles vs 2μ oracles
  - Test parallel oracle batching correctness
  - _Requirements: 5.3-5.14, 13.12-13.15_



## Task 5: Multi-Instance Accumulation Scheme - Complete ACC Construction

Implement complete accumulation scheme (ACC.G, ACC.I, ACC.P, ACC.V, ACC.D) from NIR_multicast and NIR_fold, achieving sublinear verifier complexity.

**Implementation Details:**
- [ ] 5.1 Accumulator data structures and NARK construction
  - Implement `Accumulator<F>` struct: (x, τ, r_x, r_F, e, commitments)
  - Implement `MultiPredicate<F>` struct: (instances, nark_proof)
  - Implement `AccumulationProof<F>` struct: (multicast_proof, fold_proof)
  - Add serialization/deserialization with compact encoding
  - Implement accumulator compression via cryptographic hashing
  - Implement NARK from NIR_multicast (Requirement 10.4):
    * NARK.G(1^λ) → pp: generate public parameters
    * NARK.I(pp, i) → (pk, vk): compute (pk_cast, vk_cast, i') ← NIR_multicast.I, output keys
    * NARK.P(pk, {x^(k), w^(k)}_{k∈[ℓ]}) → π: run NIR_multicast.P, output (π.x, π.w)
    * NARK.V(vk, {x^(k)}_{k∈[ℓ]}, π) → b: run NIR_multicast.V, check (i', acc.x, acc.w) ∈ R_acc
  - Verify NARK completeness and knowledge soundness (Requirements 10.2, 10.3)
  - _Requirements: 2.1, 10.1-10.4, 14.1_

- [ ] 5.2 Accumulation prover (ACC.P, Theorem 3)
  - Implement `AccumulationProver<F>` with complete ACC.P algorithm:
    * Input: Multi-predicate tuple ({x_k}_{k∈[ℓ]}, π), old accumulator acc^(0)
    * Run multi-cast verifier: x_acc ← NIR_multicast.V({x_k}_{k∈[ℓ]}, π_cast)
    * Assign acc^(1) = (x_acc, π.w)
    * Run 2-to-1 prover: (π_fold, acc.w) ← NIR_fold.P({acc^(i).x, acc^(i).w}_{i∈{0,1}})
    * Run 2-to-1 verifier: acc.x ← NIR_fold.V({acc^(i).x}_{i∈{0,1}}, π_fold)
    * Output: new accumulator acc = (acc.x, acc.w), proof pf = π_fold
  - Implement streaming witness processing for large ℓ
  - Use memory-mapped storage for witnesses > 100MB
  - Add parallel instance processing with Rayon
  - Minimize peak memory usage to O(ℓ·n + μ·n)
  - Track complexity: 2μ G operations, O(ℓ·m + μ·n) F operations, μ + log ℓ RO queries
  - Verify O(1) CRC operations per step (key innovation)
  - _Requirements: 2.1, 11.4, 15.4, 15.5, 15.9_

- [ ] 5.3 Accumulation verifier and decider (ACC.V, ACC.D)
  - Implement `AccumulationVerifier<F>` with complete ACC.V algorithm:
    * Input: Multi-predicate instance ({x_k}_{k∈[ℓ]}, π.x), accumulator instances acc^(0).x, acc.x, proof pf
    * Run multi-cast verifier: x_acc ← NIR_multicast.V({x_k}_{k∈[ℓ]}, π_cast)
    * Assign acc^(1).x = x_acc
    * Verify: acc.x = NIR_fold.V({acc^(i).x}_{i∈{0,1}}, pf)
    * Output: Accept/Reject
  - Optimize verifier complexity: O(ℓ·m) F operations, O(1) CRC operations, μ + log ℓ RO queries
  - Verify sublinear in ℓ for both curve-based and code-based instantiations
  - Implement `AccumulationDecider<F>` with complete ACC.D algorithm:
    * Input: Accumulator acc = (acc.x, acc.w)
    * Extract evaluation claims from {m̃_∪,i, m̃_i}_{i∈[μ]}
    * For each claim (point, value, commitment): verify PCS.Verify(commitment, point, value)
    * Verify constraint: F(acc.x, {m_i(acc.r_x)}_{i∈[μ]}, acc.r_F) = acc.e
    * Verify partial evaluations: m̃_∪,i(acc.τ, acc.r_x) = m̃_i(acc.r_x) ∀i ∈ [μ]
    * Output: Accept/Reject
  - Verify decider complexity depends on PCS evaluation algorithm
  - _Requirements: 2.1, 11.5, 11.6, 15.5, 15.6_

- [ ] 5.4 Theorem 3 verification and security proofs
  - Verify transformation T[NIR_multicast, NIR_fold, R_acc] = (NARK, ACC)
  - Verify ACC.G, ACC.I algorithms match Theorem 3 specification
  - Implement state function State_δ(i, x, y, tr, w) for RBR knowledge soundness:
    * Empty transcript: State_δ(i, x, y, ∅, w) = 1 iff ∃y*: (i,x,y*,w) ∈ R ∧ Δ(y,y*) ≤ δ
    * Prover moves: if State_δ(i,x,y,tr,w) = 0 then State(i,x,y,tr||π,w) = 0
    * Full transcript: State_δ = 1 iff V outputs x',y' with ∃y*': (i',x',y*',w) ∈ R' ∧ Δ(y*,y*') ≤ δ
  - Implement extractors for IOR_cast and IOR_fold:
    * E_cast: extract w_∪ = {w^(i)}_{i∈[ℓ]} in time O(ℓ²·n²) where w^(i)[j] = w̃_∪(Bits(i), Bits(j))
    * E_fold: extract witnesses from batched polynomials in time O(ℓ²·n²)
  - Verify soundness error bounds:
    * IOR_cast: ϵ_zc = dℓ/|F|, ϵ^sc_i = d/|F|, ϵ_agg = n/|F|
    * IOR_fold: ϵ_zc = (μ+1)/|F|, ϵ_sc = max(d+1,log(ℓn))/|F|, ϵ_eval = μ/|F|, ϵ_batch = 2μ·ϵ_0
  - Verify completeness and knowledge soundness proofs from Appendix B.3
  - _Requirements: 11.1-11.9, 13.1-13.15, 9.4, 9.5_

- [ ]* 5.5 Property tests for accumulation scheme
  - **Property 2: Accumulation Completeness** - For any valid multi-predicate and accumulator, honest prover produces accepting proof
  - **Property 3: Accumulation Knowledge Soundness** - For any successful prover, extractor can extract valid witnesses
  - **Property 4: Sublinear Verifier Complexity** - Verify O(log ℓ) field ops, O(1) CRC ops per step
  - Test with ℓ = 2,4,8,16,32,64 instances
  - Test with various constraint systems (HyperPlonk, R1CS)
  - Test soundness error bounds with malicious provers
  - Test memory efficiency: peak usage ≤ O(ℓ·n + μ·n)
  - _Requirements: 1.5, 2.2-2.4, 11.1-11.9_

## Task 6: Multi-Instance IVC - Complete IVC Construction and Integration

Implement complete multi-instance IVC from accumulation scheme (Theorem 1), including predicate arithmetization, recursive circuit generation, and HyperPlonk integration.

**Implementation Details:**
- [ ] 6.1 IVC data structures and interface
  - Implement `IVCProof<F>` struct: (step, z_0, z_i, accumulator, acc_proof)
  - Define `MultiInstanceIVC<F>` trait with methods:
    * init(z_0) → accumulator: initialize with base case
    * prove(z_0, z_i, witnesses, z_{i+1}, acc) → (acc', proof): prove one step with ℓ instances
    * verify(z_0, z_{i+1}, proof) → bool: verify IVC proof
    * decide(acc) → bool: decide final accumulator
  - Add proof serialization with compact encoding
  - _Requirements: 1.1, 16.1_

- [ ] 6.2 IVC prover implementation (Algorithm 5, Theorem 1)
  - Implement `IVCProver<F>` with complete Algorithm 5:
    * Input: z_0, z_i, witnesses {w_k}_{k∈[ℓ]}, z_{i+1}, acc_i
    * Step 1: For each k ∈ [ℓ], verify predicate φ(z_0, z_i[k], z_{i+1}[k], w_k) = 1
    * Step 2: Arithmetize predicates: (i', x'^(k), w'^(k)) ← Arithmetize(φ, z_0, z_i[k], z_{i+1}[k], w_k)
    * Step 3: Generate NARK proof: π_nark ← NARK.Prove({x'^(k), w'^(k)}_{k∈[ℓ]})
    * Step 4: Create multi-predicate tuple: ({x'^(k)}_{k∈[ℓ]}, π_nark.x)
    * Step 5: Run accumulation prover: (acc_{i+1}, π_acc) ← ACC.P(multi_pred, π_nark, acc_i)
    * Step 6: Output acc_{i+1} and Π_{i+1} = (z_0, z_{i+1}, acc_{i+1}, π_acc)
  - Implement recursive circuit generation:
    * For k=0: include trace for verifying accumulation between multi-predicate and accumulator
    * For k=0: include trace for compressing accumulator via cryptographic hashing
    * For k>0: include dummy traces
  - Minimize recursive circuit size: O(ℓ) field operations + O(1) CRC operations
  - Verify total CRC operations across N steps: O(√N) (key result)
  - _Requirements: 1.1-1.5, 16.3, 16.4_

- [ ] 6.3 IVC verifier and HyperPlonk integration (Algorithm 6)
  - Implement `IVCVerifier<F>` with complete Algorithm 6:
    * Input: z_0, z_{i+1}, Π_{i+1}
    * Extract accumulator instance acc.x from Π_{i+1}
    * Verify accumulation proof: ACC.V(acc.x, Π_{i+1}.π_acc)
    * Output: Accept/Reject
  - Optimize verification time using sublinear accumulation verifier
  - Implement HyperPlonk constraint system (Definition 6):
    * Define `PlonkishRelation`: (q, σ, p, w) with selector q, permutation σ, instance p, witness w
    * Implement gate identity: f̃(X) = f({q̃(Bits(0),X)}_{i=0}^{s-1}, {w̃(Bits(j),X)}_{j=0}^{n-1}) = 0
    * Implement wiring identity: w̃(x) = w̃(σ(x)) for all x ∈ {0,1}^{log μ}
    * Implement instance consistency: p̃(x) = w̃(0^{log μ+log n-log m}, x) for all x ∈ {0,1}^{log m}
  - Implement gate, wiring, instance protocols (Figures 11-13)
  - Implement CV[Π_sps] transformation (Lemma 4)
  - Integrate IOR_cast for SPS (Figure 6, completed in Task 3.5)
  - _Requirements: 1.1, 12.1-12.11, 16.4, 21.1-21.7_

- [ ]* 6.4 Property tests for IVC
  - **Property 8: IVC Completeness** - For any valid computation sequence, honest prover produces accepting proof
  - **Property 9: IVC Knowledge Soundness** - For any successful prover, extractor can extract valid witnesses for all steps
  - Test multi-step IVC execution: N = 10, 50, 100 steps with ℓ = 4, 8 instances per step
  - Verify O(√N) total CRC operations: measure actual CRC count vs theoretical bound
  - Test with HyperPlonk constraints: various gate types, wiring patterns
  - Test recursive circuit generation and verification
  - Test with Fibonacci IVC example, simple zkVM example
  - _Requirements: 1.2-1.6, 15.2, 16.1-16.8_

### Task 14: Accumulator Data Structures

- [ ] 14.1 Implement accumulator state
  - Create `Accumulator<F>` struct with fields:
    * Instance vector x
    * Challenge vectors τ, r_x, r_F
    * Evaluation value e
    * Polynomial commitments
  - Add serialization/deserialization
  - Implement accumulator compression
  - _Requirements: 2.1_

- [ ] 14.2 Implement multi-predicate tuple
  - Create `MultiPredicate<F>` struct
  - Store ℓ instance vectors
  - Store NARK proof
  - Add validation methods
  - _Requirements: 2.1_

- [ ] 14.3 Implement accumulation proof
  - Create `AccumulationProof<F>` struct
  - Store multi-cast reduction proof
  - Store 2-to-1 folding proof
  - Add proof serialization
  - _Requirements: 2.1_

- [ ]* 14.4 Write unit tests for data structures
  - Test serialization round-trip
  - Test accumulator compression
  - Test proof validation
  - _Requirements: 2.1_

### Task 15: Accumulation Prover Implementation

- [ ] 15.1 Implement accumulation prover (ACC.P)
  - Create `AccumulationProver<F>` struct
  - Take multi-predicate tuple ({x_k}_{k∈[ℓ]}, π) and accumulator acc
  - Run multi-cast reduction: (acc^(1), π_multicast) ← MultiCast.Prove
  - Run 2-to-1 reduction: (acc', π_fold) ← TwoToOne.Prove(acc^(0), acc^(1))
  - Output new accumulator acc' and proof pf
  - _Requirements: 2.1, 11.4_

- [ ] 15.2 Optimize for large ℓ
  - Implement streaming witness processing
  - Use memory-mapped storage for large witnesses
  - Add parallel instance processing
  - Minimize peak memory usage
  - _Requirements: 15.4, 15.9_

- [ ] 15.3 Implement complexity tracking
  - Count field operations
  - Count CRC operations
  - Count random oracle queries
  - Verify O(ℓ·m + μ·n) field operations
  - Verify O(1) CRC operations per step
  - _Requirements: 1.5, 15.4, 15.5_

- [ ]* 15.4 Write property tests for accumulation prover
  - **Property 2: Accumulation Completeness**
  - Test with valid multi-predicate tuples
  - Verify proof generation succeeds
  - Test with various ℓ values
  - _Requirements: 1.5, 2.3, 11.1_


### Task 16: Accumulation Verifier and Decider

- [ ] 16.1 Implement accumulation verifier (ACC.V)
  - Create `AccumulationVerifier<F>` struct
  - Take multi-predicate instance, accumulator instances, proof
  - Run multi-cast verifier to get acc^(1).x
  - Run 2-to-1 verifier to check acc.x
  - Verify acc.x = NIR_fold.V(acc^(0).x, acc^(1).x, π_fold)
  - _Requirements: 2.1, 11.5_

- [ ] 16.2 Implement verifier complexity optimization
  - Minimize field operations to O(ℓ·m)
  - Ensure O(1) CRC operations
  - Optimize random oracle queries to μ + log ℓ
  - _Requirements: 2.2, 15.5_

- [ ] 16.3 Implement decider (ACC.D)
  - Create `AccumulationDecider<F>` struct
  - Extract evaluation claims from accumulator
  - Verify all evaluation claims using PCS
  - Verify constraint F(acc.x, {m_i(acc.r_x)}_{i∈[μ]}, acc.r_F) = acc.e
  - Verify partial evaluations m̃_∪,i(acc.τ, acc.r_x) = m̃_i(acc.r_x)
  - _Requirements: 2.1, 11.6, 15.6_

- [ ]* 16.4 Write property tests for verifier and decider
  - **Property 4: Sublinear Verifier Complexity**
  - Test verifier accepts valid proofs
  - Count operations and verify O(log ℓ) field ops, O(1) CRC
  - Test decider with various accumulator sizes
  - _Requirements: 2.2, 2.3, 2.4_

### Task 17: NARK Construction

- [ ] 17.1 Implement NARK from NIR_multicast
  - Create `NARK` struct with (G, I, P, V) algorithms
  - NARK.G(1^λ) outputs public parameters pp
  - NARK.I(pp, i) computes indexer keys
  - NARK.P runs NIR_multicast.P to generate proof
  - NARK.V runs NIR_multicast.V and checks R_acc
  - _Requirements: 10.1, 10.4_

- [ ] 17.2 Implement NARK completeness
  - Verify honest prover always produces accepting proof
  - Test with various relation instances
  - _Requirements: 10.2_

- [ ] 17.3 Implement NARK knowledge soundness
  - Implement extractor E
  - Verify extraction probability ≥ 1 - negl(λ)
  - Test soundness error bounds
  - _Requirements: 10.3_

- [ ]* 17.4 Write unit tests for NARK
  - Test completeness property
  - Test knowledge soundness
  - Test with various constraint systems
  - _Requirements: 10.1, 10.2, 10.3_

---

## Phase 6: Multi-Instance IVC (Weeks 11-12)

### Task 18: IVC Data Structures and Interface

- [ ] 18.1 Implement IVC proof structure
  - Create `IVCProof<F>` struct
  - Store step number, initial state z_0, current state z_i
  - Store accumulator and accumulation proof
  - Add proof serialization
  - _Requirements: 1.1_

- [ ] 18.2 Define IVC trait
  - Create `MultiInstanceIVC<F>` trait
  - Define init, prove, verify, decide methods
  - Add type parameters for proof and accumulator
  - _Requirements: 1.1_

- [ ]* 18.3 Write unit tests for IVC structures
  - Test proof serialization
  - Test state management
  - _Requirements: 1.1_

### Task 19: IVC Prover Implementation

- [ ] 19.1 Implement IVC initialization
  - Create `IVCProver<F>` struct
  - Initialize with base case z_0
  - Create initial accumulator
  - _Requirements: 1.1_

- [ ] 19.2 Implement IVC prover step (Algorithm 5)
  - Take z_0, z_i, witnesses {w_k}_{k∈[ℓ]}, z_{i+1}, acc_i
  - Verify predicates: φ(z_0, z_i[k], z_{i+1}[k], w_k) = 1 for all k
  - Arithmetize predicates into (i', x'^(k), w'^(k))
  - Generate NARK proof π_nark
  - Create multi-predicate tuple
  - Run accumulation prover
  - Output acc_{i+1} and Π_{i+1}
  - _Requirements: 1.1, 16.3_

- [ ] 19.3 Implement predicate arithmetization
  - Convert predicate φ to constraint system
  - Support HyperPlonk constraints
  - Support R1CS constraints
  - Generate instance-witness pairs
  - _Requirements: 12.1-12.5, 16.3_

- [ ] 19.4 Optimize recursive circuit generation
  - Minimize circuit size for accumulation verification
  - Implement dummy traces for k > 0
  - Add accumulator compression via hashing
  - _Requirements: 1.4, 1.5, 16.3_

- [ ]* 19.5 Write property tests for IVC prover
  - **Property 8: IVC Completeness**
  - Test with valid computation sequences
  - Test multi-step IVC execution
  - Verify O(√N) total CRC operations
  - _Requirements: 1.2, 1.4, 15.2_


### Task 20: IVC Verifier Implementation

- [ ] 20.1 Implement IVC verifier (Algorithm 6)
  - Create `IVCVerifier<F>` struct
  - Take z_0, z_{i+1}, Π_{i+1}
  - Extract accumulator instance acc.x
  - Verify accumulation proof using ACC.V
  - Output accept/reject
  - _Requirements: 1.1, 16.4_

- [ ] 20.2 Optimize IVC verification
  - Minimize verification time
  - Leverage sublinear accumulation verifier
  - Cache frequently used values
  - _Requirements: 1.4, 1.5_

- [ ]* 20.3 Write property tests for IVC verifier
  - Test verifier accepts valid IVC proofs
  - Test verifier rejects invalid proofs
  - Verify verification complexity
  - _Requirements: 1.1, 1.2_

### Task 21: Special-Sound Protocol Integration

- [ ] 21.1 Implement HyperPlonk constraint system
  - Create `PlonkishRelation` struct (Definition 6)
  - Store selector vector q, permutation σ
  - Store instance p and witness w
  - Implement gate identity verification
  - Implement wiring identity verification
  - Implement instance consistency checks
  - _Requirements: 12.1-12.5_

- [ ] 21.2 Implement gate identity protocol (Figure 11)
  - Prover inputs: f, q̃(X), w̃(X)
  - Verifier inputs: f, q̃(X)
  - Prover sends w̃(X)
  - Verifier checks f({q̃(Bits(0),X)}_{i=0}^{s-1}, {w̃(Bits(j),X)}_{j=0}^{n-1}) = 0
  - _Requirements: 12.6_

- [ ] 21.3 Implement wiring identity protocol (Figure 12)
  - Prover inputs: σ, w̃(X)
  - Verifier inputs: σ
  - Prover sends w̃(X)
  - Verifier checks w̃(x) - w̃(σ(x)) = 0 for all x ∈ {0,1}^{log μ}
  - _Requirements: 12.7_

- [ ] 21.4 Implement instance consistency protocol (Figure 13)
  - Prover inputs: p̃(x), w̃(X)
  - Verifier inputs: p̃(x)
  - Prover sends w̃(X)
  - Verifier checks p̃(x) = w̃(0^{log μ+log n-log m}, x) for all x ∈ {0,1}^{log m}
  - _Requirements: 12.8_

- [ ] 21.5 Implement special-sound protocol transformation (CV[Π_sps])
  - Transform (2μ-1)-move protocol to (2μ+3)-move
  - Add power vector computation α = (α, α², α⁴, ...)
  - Compute linearly combined map F (Equation 14)
  - Verify Lemma 4 special soundness
  - _Requirements: 4.1-4.7_

- [ ] 21.6 Implement IOR_cast for SPS (Figure 6)
  - Interleave SPS protocol with multi-cast reduction
  - For each round i: compute m_i^(k), m̃_∪,i(Y,X), send [[m̃_∪,i]]
  - Verify α₀ = α and α_{i+1} = α_i² for all i
  - Run remaining IOR_cast process
  - Output reduced instance satisfying R_acc
  - _Requirements: 4.8-4.12, 22.1-22.6_

- [ ]* 21.7 Write unit tests for SPS integration
  - Test HyperPlonk constraint satisfaction
  - Test gate, wiring, instance protocols
  - Test CV[Π_sps] transformation
  - Test IOR_cast for SPS
  - _Requirements: 12.1-12.11_

---

## Phase 7: Non-Interactive Reductions (Weeks 13-14)

### Task 22: NIR_multicast Implementation

- [ ] 22.1 Implement NIR_multicast.P (Figure 7)
  - Initialize r_0 ← RO({x^(k)}_{k∈[ℓ]})
  - For each round i ∈ [μ]:
    * Compute m_i^(k) ← P_sps for all k
    * Compute m̃_∪,i(Y,X) and commit C_∪,i
    * Update r_i ← RO(r_{i-1}, C_∪,i)
  - Compute α, run sum-check, compute commitments C_i
  - Output witness w_acc and proof π
  - _Requirements: 14.1_

- [ ] 22.2 Implement NIR_multicast.V (Figure 8)
  - Parse proof π
  - Verify random oracle queries
  - Verify sum-check: G_1(0) + G_1(1) = 0
  - Verify G_{i+1}(0) + G_{i+1}(1) = G_i(τ_i) for all i
  - Compute e = G_{log ℓ}(τ_{log ℓ}) · eq̃^{-1}(r_y, τ)
  - Compute x = Σ_{k∈ℓ} eq̃_{k-1}(τ) · x^(k)
  - Output instance x_acc
  - _Requirements: 14.2_

- [ ] 22.3 Implement Fiat-Shamir security
  - Ensure proper challenge sequencing
  - Add domain separation for each protocol phase
  - Implement state-restoration attack prevention
  - Verify RBR knowledge soundness
  - _Requirements: 14.6, 14.7_

- [ ]* 22.4 Write unit tests for NIR_multicast
  - Test prover algorithm
  - Test verifier algorithm
  - Test Fiat-Shamir transformation
  - Test with various μ and ℓ values
  - _Requirements: 14.1, 14.2_

### Task 23: NIR_fold Implementation

- [ ] 23.1 Implement NIR_fold.P (Figure 9)
  - Sample γ, r_z ← RO({acc^(i).x, acc^(i).w}_{i∈[1]})
  - Compute G(Z) as per Equation 31
  - Run 1-round sum-check, obtain G(Z) and σ
  - Compute v_G = G(σ)
  - Compute batched witnesses and evaluation values
  - Run 2μ oracle batching protocols
  - Output witness acc.w and proof π
  - _Requirements: 14.3_

- [ ] 23.2 Implement NIR_fold.V (Figure 10)
  - Sample γ, r_z ← RO({acc^(i).x, acc^(i).w}_{i∈[1]})
  - Verify G(0) + G(1) = 0
  - Verify v_G = eq̃(r_z, σ) · (η + Σ pow_i(γ)·η_i + Σ pow_{i+μ}(γ)·η_∪,i)
  - Run 2μ oracle batching verifications
  - Compute batched instance x̃(σ)
  - Output instance acc.x
  - _Requirements: 14.4_

- [ ]* 23.3 Write unit tests for NIR_fold
  - Test prover algorithm
  - Test verifier algorithm
  - Test with various μ values
  - _Requirements: 14.3, 14.4_

### Task 24: NIR_batch Implementation

- [ ] 24.1 Implement NIR_batch for linear codes (Figure 14)
  - Encode f_0, f_1 to codewords u_0, u_1
  - Compute batched codeword u = Σ_{k∈[1]} eq̃_k(r) · u_k
  - Send oracle [[ũ]]
  - Sample out-of-domain points α_{r+1}, ..., α_{r+s}
  - Compute evaluations μ_{r+1}, ..., μ_{r+s}
  - Handle shift queries b_1, ..., b_t
  - Output new instance-oracle pair
  - _Requirements: 14.5_

- [ ] 24.2 Implement security checks
  - Verify field size and repetition parameters (Theorem 6)
  - Check |F| ≥ 2^{λ/s-1} · |L(C, δ)|^{2/s}
  - Check t ≥ λ/(-log(1-δ))
  - _Requirements: 7.7_

- [ ]* 24.3 Write unit tests for NIR_batch
  - Test batching correctness
  - Test security parameter validation
  - Test with various code parameters
  - _Requirements: 14.5, 7.7_


---

## Phase 8: Security Proofs and Formal Verification (Week 15)

### Task 25: Implement Security Proof Components

- [ ] 25.1 Implement state function for IOR_cast
  - Define State_δ(i, x, y, tr, w) for empty transcript
  - Implement state updates for prover moves
  - Implement state checks for full transcripts
  - Verify Definition 17 properties
  - _Requirements: 9.4, 13.2_

- [ ] 25.2 Implement extractor for IOR_cast
  - Extract witness w_∪ = {w^(i)}_{i∈[ℓ]} in time O(ℓ²·n²)
  - Compute w^(i)[j] = w̃_∪(Bits(i), Bits(j))
  - Extract witness w' in time O(n²) where w'[j] = w̃(Bits(j))
  - Verify Lemma 3 extraction time bounds
  - _Requirements: 13.1, 13.4, 13.9_

- [ ] 25.3 Verify soundness error bounds for IOR_cast
  - Verify ϵ_zc = dℓ/|F| (zero-check error)
  - Verify ϵ^sc_i = d/|F| for all i ∈ [log ℓ] (sum-check round errors)
  - Verify ϵ_agg = n/|F| (aggregation error)
  - Verify total error ≤ (dℓ + d·log ℓ + n)/|F|
  - _Requirements: 13.1, 13.3, 13.5-13.11_

- [ ] 25.4 Implement state function for IOR_fold
  - Define state function for 2-to-1 reduction
  - Implement state updates for batched polynomials
  - Verify Definition 17 properties
  - _Requirements: 9.4_

- [ ] 25.5 Implement extractor for IOR_fold
  - Extract witnesses from batched polynomials
  - Verify extraction time O(ℓ²·n²)
  - _Requirements: 13.12_

- [ ] 25.6 Verify soundness error bounds for IOR_fold
  - Verify ϵ_zc = (μ+1)/|F|
  - Verify ϵ_sc = max(d+1, log(ℓn))/|F|
  - Verify ϵ_eval = μ/|F|
  - Verify ϵ_batch = 2μ · ϵ_0
  - Verify Equation 43 multivariate polynomial properties
  - _Requirements: 13.12-13.15_

- [ ]* 25.7 Write tests for security proofs
  - Test state function correctness
  - Test extractor correctness
  - Verify soundness error bounds
  - Test with malicious provers
  - _Requirements: 13.1-13.15_

### Task 26: Implement Theorem Proofs

- [ ] 26.1 Verify Theorem 1 (Multi-Instance IVC from Accumulation)
  - Verify IVC construction from NARK and accumulation scheme
  - Verify sublinear recursion cost when accumulation verifier is sublinear in ℓ
  - Verify constant-depth predicate support
  - Verify security preservation
  - _Requirements: 16.1-16.8_

- [ ] 26.2 Verify Theorem 2 (Multi-Instance Accumulation Construction)
  - Verify accumulation scheme construction from NIR_multicast and NIR_fold
  - Verify key difference from previous framework
  - Verify NIR_multicast and NIR_fold functionality
  - _Requirements: 17.1-17.7_

- [ ] 26.3 Verify Theorem 3 (Accumulation Scheme from Reductions)
  - Verify transformation T[NIR_multicast, NIR_fold, R_acc] = (NARK, ACC)
  - Verify ACC.G, ACC.I, ACC.P, ACC.V, ACC.D algorithms
  - Verify complexity bounds from Theorem 3
  - Verify completeness and knowledge soundness proofs
  - _Requirements: 11.1-11.9_

- [ ] 26.4 Verify Theorem 4 (Polynomial IOR Compilation)
  - Verify transformation from IOR to NIR via Fiat-Shamir
  - Verify RBR knowledge soundness preservation
  - Verify efficiency bounds
  - _Requirements: 9.6, 9.7_

- [ ]* 26.5 Write tests for theorem verification
  - Test IVC construction correctness
  - Test accumulation scheme construction
  - Test compilation correctness
  - _Requirements: 16.1-16.8, 17.1-17.7, 11.1-11.9_

### Task 27: Implement Special Soundness Verification

- [ ] 27.1 Implement tree of transcripts (Definition 19)
  - Create (a_1, ..., a_k)-tree structure
  - Represent edges as verifier challenges
  - Represent vertices as prover messages
  - Verify tree structure properties
  - _Requirements: 18.1_

- [ ] 27.2 Implement special soundness extractor (Definition 20)
  - Create extraction algorithm E
  - Extract witness w from (a_1, ..., a_k)-tree of accepting transcripts
  - Verify extraction probability ≈ 1
  - _Requirements: 18.2, 18.3_

- [ ] 27.3 Verify Lemma 4 (CV[Π_sps] special soundness)
  - Verify (2μ+3)-move protocol is (k_0, ..., k_{μ-1}, ν+1)-special-sound
  - Implement extractor E_CV that invokes E_sps
  - Verify F(x, {m_i}_{i∈[μ]}, r, α) = 0 at ν+1 distinct points implies V_sps outputs zero
  - _Requirements: 18.5-18.7_

- [ ] 27.4 Verify Lemma 7 (Knowledge soundness from special soundness)
  - Verify knowledge error κ ≤ (Σ^k_{i=1} a_i - 1)/|F|
  - Test with various challenge set sizes
  - _Requirements: 18.4_

- [ ]* 27.5 Write tests for special soundness
  - Test tree of transcripts construction
  - Test extractor correctness
  - Test knowledge error bounds
  - _Requirements: 18.1-18.7_

---

## Phase 9: Optimizations (Week 16)

### Task 28: Parallelization Implementation

- [ ] 28.1 Implement parallel union polynomial computation
  - Use Rayon for parallel iteration over instances
  - Compute eq̃_{k-1}(Y) · w̃^(k)(X) in parallel for each k
  - Implement work-stealing scheduler
  - Add configurable thread count
  - _Requirements: 14.1, 14.2, 15.10_

- [ ] 28.2 Implement parallel sum-check rounds
  - Parallelize intermediate sum computation (Equation 4)
  - Parallelize grid point evaluation
  - Use SIMD for field operations
  - _Requirements: 15.10_

- [ ] 28.3 Implement parallel oracle batching
  - Run 2μ oracle batching protocols in parallel
  - Parallelize proximity testing
  - Parallelize Merkle tree construction
  - _Requirements: 14.3, 15.10_

- [ ]* 28.4 Write property tests for parallelization
  - **Property 14: Parallelizable Proving**
  - Test speedup with different thread counts
  - Verify correctness with parallel execution
  - Measure parallel efficiency
  - _Requirements: 14.1, 14.2, 14.3_

### Task 29: Memory Optimization Implementation

- [ ] 29.1 Implement streaming prover
  - Process witnesses in chunks
  - Use memory-mapped files for large data
  - Implement incremental polynomial construction
  - Minimize peak memory usage
  - _Requirements: 15.1, 15.4, 15.9_

- [ ] 29.2 Implement arena allocation
  - Create memory arena for temporary computations
  - Implement fast allocation/deallocation
  - Add memory pool for matrix operations
  - Reduce allocation overhead
  - _Requirements: 15.9_

- [ ] 29.3 Implement memory-efficient storage strategies
  - In-memory storage for < 100MB
  - Memory-mapped storage for 100MB - 10GB
  - Streaming storage for > 10GB
  - Automatic strategy selection based on size
  - _Requirements: 15.1, 15.4_

- [ ]* 29.4 Write property tests for memory optimization
  - **Property 15: Memory Efficiency**
  - Test peak memory usage with various witness sizes
  - Verify O(n) memory bound
  - Test streaming correctness
  - _Requirements: 15.1, 15.4, 15.9_


### Task 30: SIMD and Hardware Acceleration

- [ ] 30.1 Implement AVX-512 field operations
  - Vectorize field addition, subtraction, multiplication
  - Implement IFMA for modular multiplication
  - Add Barrett reduction for efficient modular arithmetic
  - Automatic fallback to scalar operations
  - _Requirements: 15.9_

- [ ] 30.2 Implement optimized NTT
  - Use Cooley-Tukey FFT algorithm
  - Precompute twiddle factors
  - Implement in-place NTT
  - Add AVX-512 vectorization
  - _Requirements: 15.9_

- [ ] 30.3 Implement cache-friendly data structures
  - Align data to cache line boundaries
  - Use structure-of-arrays for polynomials
  - Minimize cache misses
  - Optimize memory access patterns
  - _Requirements: 15.9_

- [ ]* 30.4 Write benchmarks for optimizations
  - Benchmark field operations with/without SIMD
  - Benchmark NTT performance
  - Measure cache hit rates
  - Compare with baseline implementation
  - _Requirements: 15.9_

### Task 31: Precomputation and Caching

- [ ] 31.1 Implement precomputation strategies
  - Precompute eq̃_k(Y) for common k values
  - Cache Lagrange basis polynomials
  - Precompute NTT twiddle factors
  - Store frequently used evaluation points
  - _Requirements: 15.1_

- [ ] 31.2 Implement LRU cache
  - Create LRU cache for polynomial evaluations
  - Add cache for commitment operations
  - Implement cache eviction policy
  - Monitor cache hit rates
  - _Requirements: 15.1_

- [ ]* 31.3 Write tests for caching
  - Test cache correctness
  - Test cache hit rates
  - Verify performance improvement
  - _Requirements: 15.1_

---

## Phase 10: Integration and Testing (Weeks 17-18)

### Task 32: zkVM Integration

- [ ] 32.1 Create NARK system adapters
  - Create adapter for HyperPlonk
  - Create adapter for R1CS
  - Create adapter for AIR
  - Add constraint system conversion
  - _Requirements: 12.1-12.11_

- [ ] 32.2 Implement zkVM circuit compilation
  - Convert zkVM execution trace to constraints
  - Generate instance-witness pairs
  - Optimize circuit size
  - Add circuit verification
  - _Requirements: 16.3_

- [ ] 32.3 Create example applications
  - Implement Fibonacci IVC example
  - Implement simple zkVM example
  - Implement recursive proof composition example
  - Add documentation for each example
  - _Requirements: 1.1_

- [ ]* 32.4 Write integration tests
  - Test HyperPlonk integration
  - Test R1CS integration
  - Test zkVM execution
  - Test end-to-end IVC
  - _Requirements: 12.1-12.11, 16.3_

### Task 33: Comprehensive Testing

- [ ]* 33.1 Implement all property-based tests
  - **Property 1: Multi-Cast Partial Evaluation Correctness**
  - **Property 2: Accumulation Completeness**
  - **Property 3: Accumulation Knowledge Soundness**
  - **Property 4: Sublinear Verifier Complexity**
  - **Property 5: 2-to-1 Folding Correctness**
  - **Property 6: Sum-Check Soundness**
  - **Property 7: Oracle Batching Succinctness**
  - **Property 8: IVC Completeness**
  - **Property 9: IVC Knowledge Soundness**
  - **Property 10: Linear-Time Prover**
  - **Property 11: Post-Quantum Security**
  - **Property 12: Constant Verification (Curve-Based)**
  - **Property 13: Fiat-Shamir Security**
  - **Property 14: Parallelizable Proving**
  - **Property 15: Memory Efficiency**
  - _Requirements: All correctness properties from design_

- [ ]* 33.2 Implement edge case tests
  - Test with ℓ = 1 (single instance)
  - Test with ℓ = 2^20 (large instance count)
  - Test with n = 2^30 (large witness size)
  - Test with μ = 1 (single round)
  - Test with various field sizes
  - _Requirements: All requirements_

- [ ]* 33.3 Implement security tests
  - Test with malicious provers
  - Test soundness error bounds
  - Test challenge set size requirements
  - Test Fiat-Shamir security
  - _Requirements: 13.1-13.15, 14.6, 14.7_

- [ ]* 33.4 Implement performance benchmarks
  - Benchmark prover time vs witness size
  - Benchmark verifier time vs instance count
  - Benchmark memory usage
  - Benchmark proof size
  - Compare with existing systems (Nova, ProtoGalaxy, etc.)
  - _Requirements: 15.1-15.10_

### Task 34: Documentation and Examples

- [ ] 34.1 Write API documentation
  - Document all public interfaces
  - Add usage examples for each component
  - Document parameter selection guidelines
  - Add security considerations
  - _Requirements: All requirements_

- [ ] 34.2 Create usage guide
  - Write getting started guide
  - Add step-by-step tutorials
  - Document common patterns
  - Add troubleshooting section
  - _Requirements: All requirements_

- [ ] 34.3 Write integration guide
  - Document zkVM integration process
  - Add constraint system conversion guide
  - Document PCS selection guidelines
  - Add performance tuning guide
  - _Requirements: All requirements_

- [ ] 34.4 Create performance tuning guide
  - Document optimization strategies
  - Add profiling guidelines
  - Document parameter selection for performance
  - Add hardware-specific optimizations
  - _Requirements: 15.1-15.10_

---

## Phase 11: Concrete Instantiations (Week 19)

### Task 35: Quasar(curve) Implementation

- [ ] 35.1 Implement Quasar(curve) with Mercury PCS
  - Use BN254 scalar field (254 bits)
  - Implement Mercury PCS with constant proof size
  - Integrate with HyperPlonk constraint system
  - Configure for 128-bit classical security
  - _Requirements: 6.5, 9.1, 9.2_

- [ ] 35.2 Optimize Quasar(curve) performance
  - Optimize group operations
  - Implement batch verification
  - Add precomputation for common operations
  - Minimize verifier group operations to O(1)
  - _Requirements: 9.1, 9.2, 15.5_

- [ ]* 35.3 Benchmark Quasar(curve)
  - Measure prover time: verify O(n log n)
  - Measure verifier time: verify O(log ℓ) field ops + O(1) group ops
  - Measure proof size: verify O(log ℓ) field elements + O(1) group elements
  - Measure memory: verify O(n)
  - _Requirements: 15.1-15.10_

### Task 36: Quasar(code) Implementation

- [ ] 36.1 Implement Quasar(code) with Brakedown PCS
  - Use Goldilocks field (64 bits) with F_{q^2} extension
  - Implement Brakedown with linear-time encoding
  - Use Reed-Solomon code with rate ρ = 1/2
  - Integrate with HyperPlonk constraint system
  - Configure for 128-bit post-quantum security
  - _Requirements: 6.6, 7.1-7.7_

- [ ] 36.2 Optimize Quasar(code) performance
  - Implement linear-time encoding
  - Optimize proximity testing
  - Add parallel encoding
  - Minimize random oracle queries
  - _Requirements: 15.4, 15.5, 15.10_

- [ ]* 36.3 Benchmark Quasar(code)
  - Measure prover time: verify O(n)
  - Measure verifier time: verify O(λ/log(1/ρ) · (log n + log ℓ)) RO queries
  - Measure proof size: verify O(λ/log(1/ρ) · log n) hash values
  - Measure memory: verify O(n)
  - _Requirements: 15.1-15.10_

### Task 37: Comparison with Existing Systems

- [ ] 37.1 Implement comparison benchmarks
  - Compare with Nova (if available)
  - Compare with HyperNova (if available)
  - Compare with ProtoGalaxy (if available)
  - Measure verifier CRC operations
  - Measure total CRC operations for N steps
  - _Requirements: 15.1, 15.2_

- [ ] 37.2 Create comparison report
  - Document performance comparison
  - Analyze trade-offs
  - Highlight Quasar advantages
  - Document use case recommendations
  - _Requirements: 15.1-15.10_

---

## Phase 12: Final Validation and Deployment (Week 20)

### Task 38: Security Audit Preparation

- [ ] 38.1 Conduct internal security review
  - Review all cryptographic implementations
  - Verify soundness error bounds
  - Check for side-channel vulnerabilities
  - Review random number generation
  - _Requirements: 13.1-13.15_

- [ ] 38.2 Prepare security documentation
  - Document security assumptions
  - Document threat model
  - Document soundness error analysis
  - Document parameter selection guidelines
  - _Requirements: All security requirements_

- [ ] 38.3 Implement constant-time operations
  - Use constant-time field operations
  - Avoid data-dependent branches
  - Use constant-time polynomial evaluation
  - Implement blinding for sensitive operations
  - _Requirements: Security considerations from design_

### Task 39: Production Readiness

- [ ] 39.1 Implement error handling
  - Add comprehensive error types
  - Implement validation functions
  - Add error recovery mechanisms
  - Document error handling patterns
  - _Requirements: Error handling from design_

- [ ] 39.2 Add logging and monitoring
  - Implement structured logging
  - Add performance metrics
  - Add progress tracking
  - Implement debugging utilities
  - _Requirements: All requirements_

- [ ] 39.3 Implement serialization
  - Add proof serialization/deserialization
  - Add accumulator serialization
  - Implement compact encoding
  - Add versioning support
  - _Requirements: 2.1, 14.1_

- [ ] 39.4 Create deployment guide
  - Document deployment process
  - Add configuration guidelines
  - Document monitoring setup
  - Add troubleshooting guide
  - _Requirements: All requirements_

### Task 40: Final Testing and Validation

- [ ]* 40.1 Run comprehensive test suite
  - Run all unit tests
  - Run all property-based tests
  - Run all integration tests
  - Run all benchmarks
  - Verify all tests pass
  - _Requirements: All requirements_

- [ ]* 40.2 Validate against paper specifications
  - Verify all algorithms match paper
  - Verify all complexity bounds
  - Verify all security properties
  - Document any deviations
  - _Requirements: All requirements_

- [ ] 40.3 Create release checklist
  - Verify all tasks completed
  - Verify all tests passing
  - Verify documentation complete
  - Verify examples working
  - Prepare release notes
  - _Requirements: All requirements_

---

## Checkpoint Tasks

- [ ] Checkpoint 1: After Phase 2 - Ensure foundation and PCS implementations pass all tests
  - Verify field operations correctness
  - Verify MLE computation correctness
  - Verify sum-check protocol correctness
  - Verify PCS implementations correctness
  - Ask user if questions arise

- [ ] Checkpoint 2: After Phase 4 - Ensure multi-cast and 2-to-1 reductions pass all tests
  - Verify union polynomial construction
  - Verify partial evaluation correctness
  - Verify multi-cast reduction correctness
  - Verify 2-to-1 reduction correctness
  - Ask user if questions arise

- [ ] Checkpoint 3: After Phase 6 - Ensure IVC implementation passes all tests
  - Verify accumulation scheme correctness
  - Verify IVC prover correctness
  - Verify IVC verifier correctness
  - Verify HyperPlonk integration
  - Ask user if questions arise

- [ ] Checkpoint 4: After Phase 9 - Ensure optimizations work correctly
  - Verify parallelization correctness
  - Verify memory optimization correctness
  - Verify SIMD operations correctness
  - Verify performance improvements
  - Ask user if questions arise

- [ ] Checkpoint 5: After Phase 12 - Final validation before release
  - Verify all tests pass
  - Verify all benchmarks meet expectations
  - Verify documentation complete
  - Verify examples work
  - Ask user if ready for release

---

## Summary

This comprehensive task list provides a complete implementation plan for the Quasar multi-instance accumulation scheme. The tasks are organized into 12 phases over 20 weeks, with clear dependencies and incremental progress. Each task includes:

- Specific implementation objectives
- References to requirements and design specifications
- Expected outputs
- Testing requirements (marked with * for optional property-based tests)

The implementation follows the paper specifications exactly, with no simplifications or omissions. All algorithms, data structures, and security proofs are included. The plan ensures production-ready code with comprehensive testing, optimization, and documentation.



## Task 7: Non-Interactive Reductions and Optimizations

Implement NIR_multicast, NIR_fold, NIR_batch with Fiat-Shamir transformation, plus all optimizations (parallelization, memory, SIMD).

**Implementation Details:**
- [ ] 7.1 NIR_multicast and NIR_fold implementation (Figures 7-10)
  - Implement NIR_multicast.P (Figure 7):
    * Initialize r_0 ← RO({x^(k)}_{k∈[ℓ]})
    * For each round i ∈ [μ]: compute m_i^(k) ← P_sps, compute m̃_∪,i, commit C_∪,i, update r_i ← RO(r_{i-1}, C_∪,i)
    * Compute α, run sum-check, compute commitments C_i
    * Output witness w_acc and proof π with all commitments, challenges, sumcheck proofs
  - Implement NIR_multicast.V (Figure 8):
    * Parse proof π, verify RO queries, verify sum-check, compute e and x
    * Output instance x_acc = (x, {C_∪,i}, {C_i}, r_F, τ, r_x, e)
  - Implement NIR_fold.P (Figure 9):
    * Sample γ, r_z ← RO, compute G(Z), run 1-round sum-check
    * Compute batched witnesses and evaluations, run 2μ oracle batching
    * Output witness acc.w and proof π
  - Implement NIR_fold.V (Figure 10):
    * Sample γ, r_z ← RO, verify G(0)+G(1)=0, verify v_G equation
    * Run 2μ oracle batching verifications, compute batched instance
    * Output instance acc.x
  - Implement NIR_batch for linear codes (Figure 14):
    * Encode f_0, f_1 to codewords, compute batched codeword
    * Send oracle [[ũ]], sample out-of-domain points, compute evaluations
    * Handle shift queries, output new instance-oracle pair
  - Verify security: field size |F| ≥ 2^{λ/s-1} · |L(C,δ)|^{2/s}, t ≥ λ/(-log(1-δ))
  - Ensure proper challenge sequencing for Fiat-Shamir security
  - Implement state-restoration attack prevention via RBR knowledge soundness
  - _Requirements: 14.1-14.7, 7.7_

- [ ] 7.2 Parallelization implementation
  - Implement parallel union polynomial computation:
    * Use Rayon parallel iterator over instances k ∈ [ℓ]
    * Compute eq̃_{k-1}(Y) · w̃^(k)(X) in parallel for each k
    * Implement work-stealing scheduler with configurable thread count
    * Optimize for NUMA architectures: pin threads to cores
  - Implement parallel sum-check rounds:
    * Parallelize intermediate sum computation in Equation 4
    * Parallelize grid point evaluation for LDE
    * Use SIMD for field operations within each thread
  - Implement parallel oracle batching:
    * Run 2μ oracle batching protocols in parallel
    * Parallelize proximity testing for code-based PCS
    * Parallelize Merkle tree construction
  - Add parallel efficiency monitoring: measure speedup vs thread count
  - _Requirements: 14.1-14.3, 15.10_

- [ ] 7.3 Memory optimization implementation
  - Implement streaming prover:
    * Process witnesses in chunks of 10MB
    * Use memory-mapped files via mmap for witnesses > 100MB
    * Implement incremental polynomial construction
    * Minimize peak memory usage to O(n) per instance
  - Implement arena allocation:
    * Create memory arena for temporary computations
    * Fast bump allocation with periodic reset
    * Memory pool for matrix operations: pre-allocate common sizes
  - Implement adaptive storage strategies:
    * In-memory storage for < 100MB
    * Memory-mapped storage for 100MB - 10GB
    * Streaming storage for > 10GB
    * Automatic strategy selection based on witness size
  - Add memory profiling: track peak usage, allocation patterns
  - _Requirements: 15.1, 15.4, 15.9_

- [ ] 7.4 SIMD and hardware acceleration
  - Implement AVX-512 field operations:
    * Vectorize add, sub, mul operations: process 8 elements in parallel
    * Implement IFMA (Integer Fused Multiply-Add) for modular multiplication
    * Add Barrett reduction for efficient modular arithmetic
    * Automatic fallback to scalar operations if AVX-512 unavailable
  - Implement optimized NTT:
    * Use Cooley-Tukey FFT algorithm with radix-2 or radix-4
    * Precompute twiddle factors: ω^i for i ∈ [n]
    * Implement in-place NTT to reduce memory usage
    * Add AVX-512 vectorization for butterfly operations
  - Implement cache-friendly data structures:
    * Align data to 64-byte cache line boundaries
    * Use structure-of-arrays for polynomials: separate real/imaginary parts
    * Minimize cache misses: sequential access patterns
    * Optimize memory access: prefetch next cache lines
  - Implement precomputation and caching:
    * Precompute eq̃_k(Y) for common k values
    * Cache Lagrange basis polynomials
    * LRU cache for polynomial evaluations with configurable size
  - _Requirements: 15.1, 15.9_

- [ ]* 7.5 Property tests for optimizations
  - **Property 14: Parallelizable Proving** - Test speedup with 1,2,4,8 threads, verify correctness
  - **Property 15: Memory Efficiency** - Test peak memory ≤ O(n) for various witness sizes
  - **Property 10: Linear-Time Prover** - For code-based PCS, verify O(n) prover time
  - Test SIMD correctness: compare AVX-512 vs scalar results
  - Test streaming correctness: compare streaming vs in-memory results
  - Benchmark performance improvements: measure speedup from each optimization
  - _Requirements: 14.1-14.3, 15.1, 15.4, 15.9, 15.10_

## Task 8: Concrete Instantiations, Testing, and Production Readiness

Implement Quasar(curve) and Quasar(code), comprehensive testing, security audit preparation, and production deployment.

**Implementation Details:**
- [ ] 8.1 Quasar(curve) - Elliptic curve-based instantiation
  - Configure parameters:
    * Field: BN254 scalar field (254 bits) for 128-bit classical security
    * PCS: Mercury with O(1) proof size and O(1) verifier group operations
    * Constraint System: HyperPlonk with custom gates
    * Challenge set size: |F| = 2^254 > 2^128 for 128-bit security
  - Optimize group operations:
    * Use projective coordinates for elliptic curve arithmetic
    * Implement batch verification: verify multiple pairings simultaneously
    * Precompute common group elements
    * Minimize verifier group operations to O(1) per step
  - Verify performance characteristics:
    * Prover time: O(n log n) ring operations
    * Verifier time: O(log ℓ) field ops + O(1) group ops
    * Proof size: O(log ℓ) field elements + O(1) group elements
    * Memory: O(n)
  - _Requirements: 6.5, 9.1, 9.2, 15.1-15.10_

- [ ] 8.2 Quasar(code) - Linear code-based instantiation
  - Configure parameters:
    * Field: Goldilocks (64 bits) with F_{q^2} extension for 128-bit security
    * PCS: Brakedown with linear-time encoding
    * Code: Reed-Solomon with rate ρ = 1/2, minimum distance δ = 1/2
    * Constraint System: HyperPlonk
    * Security: 128-bit post-quantum via hash-based commitments
  - Optimize encoding:
    * Implement linear-time-encodable codes: O(n) encoding complexity
    * Use NTT-based RS encoding
    * Parallelize encoding across codeword chunks
    * Minimize random oracle queries
  - Verify performance characteristics:
    * Prover time: O(n) ring operations (linear-time!)
    * Verifier time: O(λ/log(1/ρ) · (log n + log ℓ)) RO queries
    * Proof size: O(λ/log(1/ρ) · log n) hash values
    * Memory: O(n)
  - Verify post-quantum security: plausible security against quantum adversaries
  - _Requirements: 6.6, 7.1-7.7, 15.1-15.10_

- [ ] 8.3 Comprehensive testing and benchmarking
  - Implement all property-based tests (Properties 1-15 from design)
  - Implement edge case tests:
    * ℓ = 1 (single instance), ℓ = 2^20 (large instance count)
    * n = 2^10, 2^15, 2^20, 2^25, 2^30 (various witness sizes)
    * μ = 1, 2, 5, 10 (various round counts)
    * Various field sizes and security levels
  - Implement security tests:
    * Test with malicious provers attempting to forge proofs
    * Verify soundness error bounds match theoretical predictions
    * Test challenge set size requirements
    * Test Fiat-Shamir security against state-restoration attacks
  - Implement performance benchmarks:
    * Benchmark prover time vs witness size n: verify O(n) or O(n log n)
    * Benchmark verifier time vs instance count ℓ: verify O(log ℓ)
    * Benchmark memory usage: verify O(n)
    * Benchmark proof size: verify O(log ℓ) or O(log n)
    * Compare with existing systems: Nova, HyperNova, ProtoGalaxy, KiloNova
  - Verify key results:
    * Total CRC operations for N steps: O(√N) vs O(N) in existing systems
    * Verifier CRC operations per step: O(1) vs O(ℓ) or O(ℓ·d) in existing systems
  - _Requirements: All requirements, all correctness properties_

- [ ] 8.4 Security audit preparation and production readiness
  - Implement constant-time operations:
    * Use constant-time field operations: no data-dependent branches
    * Implement constant-time polynomial evaluation
    * Add blinding for sensitive operations
    * Verify timing-attack resistance
  - Implement comprehensive error handling:
    * Define `QuasarError` enum with all error types
    * Implement validation functions: validate_field_size, validate_degree, validate_code_parameters
    * Add error recovery mechanisms
    * Document error handling patterns
  - Implement logging and monitoring:
    * Structured logging with log levels (trace, debug, info, warn, error)
    * Performance metrics: track prover/verifier time, memory usage, proof size
    * Progress tracking for long-running operations
    * Debugging utilities: dump intermediate values, trace execution
  - Implement serialization:
    * Proof serialization/deserialization with versioning
    * Accumulator serialization with compact encoding
    * Commitment serialization
    * Support multiple formats: binary, JSON, hex
  - Create deployment guide:
    * Document deployment process
    * Add configuration guidelines: parameter selection, security levels
    * Document monitoring setup: metrics, alerts
    * Add troubleshooting guide: common issues, solutions
  - Prepare security documentation:
    * Document security assumptions: Module-SIS, Ring-SIS, hash function security
    * Document threat model: malicious provers, quantum adversaries
    * Document soundness error analysis: total error ≤ 2^{-128} for 128-bit security
    * Document parameter selection guidelines: field size, challenge set size, code parameters
  - _Requirements: All security requirements, error handling from design_

- [ ] 8.5 Documentation and examples
  - Write API documentation:
    * Document all public interfaces with examples
    * Add usage examples for each component
    * Document parameter selection guidelines
    * Add security considerations
  - Create usage guide:
    * Getting started guide: installation, basic usage
    * Step-by-step tutorials: Fibonacci IVC, simple zkVM
    * Document common patterns: multi-step IVC, recursive composition
    * Add troubleshooting section
  - Write integration guide:
    * Document zkVM integration process
    * Add constraint system conversion guide: R1CS → HyperPlonk
    * Document PCS selection guidelines: curve-based vs code-based
    * Add performance tuning guide: parallelization, memory optimization
  - Create example applications:
    * Fibonacci IVC: prove Fibonacci sequence computation
    * Simple zkVM: prove RISC-V instruction execution
    * Recursive proof composition: compose multiple IVC proofs
    * Add comprehensive comments and documentation
  - _Requirements: All requirements_

---

## Checkpoint Tasks

- [ ] Checkpoint 1: After Task 2 - Foundation and PCS complete
  - Verify field operations, MLE, sum-check, PCS implementations pass all tests
  - Verify both curve-based and code-based PCS work correctly
  - Verify oracle batching for both PCS types
  - Run diagnostics, check error handling
  - Ask user if questions arise

- [ ] Checkpoint 2: After Task 4 - Multi-cast and 2-to-1 reductions complete
  - Verify union polynomial construction and partial evaluation
  - Verify multi-cast reduction prover and verifier
  - Verify 2-to-1 reduction with batched polynomials
  - Verify oracle batching in parallel
  - Run diagnostics, check error handling
  - Ask user if questions arise

- [ ] Checkpoint 3: After Task 6 - IVC implementation complete
  - Verify accumulation scheme (ACC.P, ACC.V, ACC.D)
  - Verify IVC prover and verifier
  - Verify HyperPlonk integration
  - Verify multi-step IVC execution
  - Verify O(√N) total CRC operations
  - Run diagnostics, check error handling
  - Ask user if questions arise

- [ ] Checkpoint 4: After Task 7 - Optimizations complete
  - Verify NIR implementations with Fiat-Shamir
  - Verify parallelization correctness and speedup
  - Verify memory optimization correctness and efficiency
  - Verify SIMD operations correctness
  - Run diagnostics, check error handling
  - Ask user if questions arise

- [ ] Checkpoint 5: After Task 8 - Final validation
  - Verify Quasar(curve) and Quasar(code) instantiations
  - Verify all tests pass (unit, property-based, integration, security)
  - Verify all benchmarks meet expectations
  - Verify documentation complete
  - Verify examples work
  - Ask user if ready for release

---

## Summary

This compact task list provides a complete implementation plan for Quasar in **8 comprehensive tasks** (vs 40 in the original). Each task combines related functionality into a cohesive unit:

1. **Task 1**: Foundation (fields, MLE, sum-check, Fiat-Shamir)
2. **Task 2**: PCS (curve-based and code-based, oracle batching)
3. **Task 3**: Multi-cast reduction (union polynomials, IOR_cast, SPS integration)
4. **Task 4**: 2-to-1 reduction (batched polynomials, IOR_fold, parallel batching)
5. **Task 5**: Accumulation scheme (ACC construction, NARK, security proofs)
6. **Task 6**: Multi-instance IVC (IVC construction, HyperPlonk, recursive circuits)
7. **Task 7**: NIR and optimizations (Fiat-Shamir, parallelization, memory, SIMD)
8. **Task 8**: Instantiations and production (Quasar(curve/code), testing, deployment)

**Key Results Verified:**
- O(√N) total CRC operations (vs O(N) in existing systems)
- O(1) CRC operations per step (vs O(ℓ) or O(ℓ·d))
- O(log ℓ) verifier field operations (sublinear in ℓ)
- O(n) prover time for code-based instantiation (linear-time!)
- Plausible post-quantum security for code-based instantiation

**Implementation follows paper exactly** with all algorithms (1-9), equations (1-45), lemmas (1-7), theorems (1-4), definitions (1-20), and figures (6-14) implemented completely.

