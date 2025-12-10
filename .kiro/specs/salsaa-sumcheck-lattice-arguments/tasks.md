# Implementation Plan

## Overview

This implementation plan integrates SALSAA (Sumcheck-Aided Lattice-based Succinct Arguments) into the existing neo-lattice-zkvm codebase. The plan follows an incremental approach, building core algebraic infrastructure first, then implementing atomic RoK protocols, and finally composing them into complete applications (SNARK, PCS, Folding Scheme).

## Task Organization

Tasks are organized into phases:
1. **Core Infrastructure** (Tasks 1-5): Ring arithmetic, CRT, NTT, matrices
2. **Low-Degree Extensions** (Tasks 6-7): LDE construction and evaluation
3. **Atomic RoK Protocols** (Tasks 8-14): Individual reduction protocols
4. **Protocol Composition** (Tasks 15-17): SNARK, PCS, Folding applications
5. **Optimization & Testing** (Tasks 18-20): Performance and correctness validation

**Legend:**
- `*` = Optional task (can be skipped for MVP)
- No marker = Required for core functionality

---

- [x] 1. Extend cyclotomic ring module for SALSAA



- [x] 1.1 Add balanced representation and canonical embedding

  - Extend `neo-lattice-zkvm/src/ring/cyclotomic.rs`
  - Implement `canonical_embedding()` → Vec<Complex64>
  - Implement `canonical_norm_squared()` using Trace(⟨x,x̄⟩)
  - Implement `trace()` for Trace_{K/Q}(x)
  - Add complex conjugation `conjugate()` for x̄
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
  - _Integrates with: Existing `CyclotomicRing<F>` and `RingElement<F>`_



- [x] 1.2 Implement CRT operations for ring splitting


  - Create `neo-lattice-zkvm/src/ring/crt.rs`
  - Implement `CRTContext` with `to_crt()` and `from_crt()`
  - Support R_q ≅ (F_{q^e})^{φ/e} isomorphism
  - Extend to vectors: `vector_to_crt()`
  - Extend to polynomials: `poly_to_crt()`
  - Implement `lift_challenge()` for Fiat-Shamir
  - _Requirements: 2.1_


  - _Integrates with: Existing NTT module, field extensions_



- [ ] 1.3 Enhance NTT module for incomplete NTT
  - Extend `neo-lattice-zkvm/src/ring/ntt.rs`
  - Add support for small splitting degree e
  - Implement `apply_crt_splitting()` for incomplete NTT
  - Precompute and cache twiddle factors




  - _Requirements: 2.2_
  - _Integrates with: Existing `NTT<F>` implementation_





- [ ] 2. Implement matrix operations with row-tensor structure
- [ ] 2.1 Create SALSAA matrix module
  - Create `neo-lattice-zkvm/src/salsaa/matrix.rs`
  - Implement `Matrix` with optional `TensorStructure`
  - Implement `TensorStructure` for F = F_0 • F_1 • ... • F_{µ-1}
  - Add `mul_vec()`, `mul_mat()` operations
  - Implement `row_kronecker()` for A • B
  - Implement `hadamard()` for A ⊙ B
  - Add `split_top_bottom()` for decomposition
  - _Requirements: 3.1, 3.2_
  - _Integrates with: Existing ring module_



- [ ]* 2.2 Write property test for row-tensor structure
  - **Property 6: Row-Tensor Structure Preservation**
  - **Validates: Requirements 3.2**
  - Test that tensor product matches direct computation



  - Generate random factors and witness
  - Verify (F_0 • ... • F_{µ-1})w = direct computation
  - _Requirements: 3.2_

- [ ] 3. Implement low-degree extension (LDE) module
- [ ] 3.1 Create LDE context and operations
  - Create `neo-lattice-zkvm/src/salsaa/lde.rs`
  - Implement `LDEContext` with degree d, variables µ
  - Implement `construct_lde()` from witness w ∈ R^{d^µ}
  - Implement `evaluate_lde()` using Lagrange basis
  - Implement `lagrange_basis()` computation
  - Implement `lagrange_coefficient()` for single term
  - Extend to matrices: `construct_matrix_lde()`, `evaluate_matrix_lde()`
  - _Requirements: 4.1, 4.2_
  - _Integrates with: Ring module, polynomial module_

- [ ]* 3.2 Write property test for LDE interpolation
  - **Property 7: LDE Interpolation Property**
  - **Validates: Requirements 4.1**
  - Test LDE[w](z) = w_z for all z ∈ [d]^µ
  - Generate random witness
  - Verify interpolation on grid points
  - _Requirements: 4.1_

- [ ]* 3.3 Write property test for LDE Lagrange evaluation
  - **Property 8: LDE Evaluation via Lagrange Basis**
  - **Validates: Requirements 4.2**
  - Test LDE[w](r) = ⟨r̃, w⟩
  - Generate random witness and evaluation point
  - Compare direct evaluation vs Lagrange basis
  - _Requirements: 4.2_

- [ ] 4. Implement relation definitions
- [ ] 4.1 Create relation types module
  - Create `neo-lattice-zkvm/src/salsaa/relations.rs`
  - Implement `LinearRelation` (Ξ^lin)
  - Implement `LinearStatement` with (H, F, Y)
  - Implement `LinearWitness` with W
  - Implement `LDERelation` (Ξ^lde-⊗)
  - Implement `LDEStatement` with evaluation claims
  - Implement `SumcheckRelation` (Ξ^sum)
  - Implement `SumcheckStatement` with sum target
  - Implement `NormRelation` (Ξ^norm)
  - Implement `NormStatement` with norm bound
  - Implement `R1CSRelation` (Ξ^lin-r1cs)
  - Implement `R1CSStatement` with A, B, C, D, E matrices
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_
  - _Integrates with: Matrix module, LDE module_

- [ ] 4.2 Implement relation verification methods
  - Add `verify()` method to each relation instance
  - Implement `check_norm()` for norm bounds
  - Implement `check_equation()` for linear equations
  - Implement `check_lde_claims()` for LDE evaluations
  - Implement `check_sumcheck()` for sumcheck claims
  - Implement `check_r1cs()` for R1CS constraints
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_



- [ ] 5. Implement Fiat-Shamir transcript
- [ ] 5.1 Create transcript module
  - Create `neo-lattice-zkvm/src/salsaa/transcript.rs`
  - Implement `Transcript` with Blake3 hasher
  - Implement `append_message()`, `append_ring_element()`, `append_matrix()`
  - Implement `challenge_ext_field()` for F_{q^e}^× challenges
  - Implement `challenge_ring()` for R_q challenges
  - Implement `challenge_vector()` for batching
  - _Requirements: 18.1, 18.2_
  - _Integrates with: Existing `fiat_shamir` module_

- [ ] 6. Implement Π^lde-⊗ protocol (Lemma 2)
- [ ] 6.1 Create LDE tensor reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/lde_tensor.rs`
  - Implement `LDETensorReduction` struct
  - Implement `prover_reduce()`: Ξ^lde-⊗ → Ξ^lin
  - Construct H' = [H; I_t], F' = [F; (M_i r̃_i^T)], Y' = [Y; (s_i^T)]
  - Implement `verifier_reduce()` (deterministic, no communication)
  - Zero communication cost
  - _Requirements: 5.1_
  - _Integrates with: LDE module, relations module_

- [ ]* 6.2 Write property test for Π^lde-⊗
  - **Property 9: Π^lde-⊗ Correctness**
  - **Validates: Requirements 5.1**
  - Test reduction preserves relation
  - Generate random LDE statement and witness
  - Verify output linear statement is valid
  - _Requirements: 5.1_

- [ ] 7. Implement Π^sum protocol (Figure 2, Lemma 3)
- [ ] 7.1 Create sumcheck reduction with dynamic programming
  - Create `neo-lattice-zkvm/src/salsaa/protocols/sumcheck.rs`
  - Implement `SumcheckReduction` struct
  - Implement `prover_sumcheck()` with O(m) complexity
  - Precompute intermediate sums via dynamic programming
  - For each round j ∈ [µ]: compute g_j(x), send, receive r_j
  - Compute final evaluations s_0 = LDE[W](r), s_1 = LDE[W̄](r̄)
  - Implement `verifier_sumcheck()` with checks
  - Communication: (2d-1)µe log q + 2r log |R_q| bits
  - _Requirements: 6.1, 6.2, 6.3_
  - _Integrates with: Existing `sumcheck` module, LDE module_

- [ ]* 7.2 Write property test for sumcheck round consistency
  - **Property 10: Sumcheck Round Consistency**
  - **Validates: Requirements 6.1**
  - Test a_j = Σ_{z∈[d]} g_j(z) for each round
  - Generate random witness
  - Verify sumcheck polynomial consistency
  - _Requirements: 6.1_

- [ ]* 7.3 Write property test for sumcheck final check
  - **Property 11: Sumcheck Final Check**
  - **Validates: Requirements 6.2**
  - Test a_µ = u^T · CRT(s_0 ⊙ s_1)
  - Verify final evaluation matches
  - _Requirements: 6.2_

- [ ]* 7.4 Write property test for sumcheck prover linear time
  - **Property 12: Sumcheck Prover Linear Time**
  - **Validates: Requirements 6.3**
  - Benchmark prover time for various witness sizes
  - Verify O(m) complexity empirically
  - _Requirements: 6.3_

- [ ] 8. Implement Π^norm protocol (Figure 3, Lemma 4)
- [ ] 8.1 Create norm-check reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/norm_check.rs`
  - Implement `NormCheckReduction` struct
  - Implement `prover_norm_check()`: compute t^T = (⟨w_i, w_i⟩)_{i∈[r]}
  - Send inner products to verifier
  - Verifier checks Trace(t_i) ≤ ν² for all i
  - Output sumcheck statement with t
  - Communication: r log |R_q| bits
  - _Requirements: 7.1, 7.2_
  - _Integrates with: Ring module (trace operation)_

- [ ]* 8.2 Write property test for norm-check inner product
  - **Property 13: Norm-Check Inner Product Correctness**
  - **Validates: Requirements 7.1**
  - Test Trace(⟨w_i, w_i⟩) = ∥w_i∥²_{σ,2}
  - Generate random witness columns
  - Verify inner product equals norm squared
  - _Requirements: 7.1_

- [ ]* 8.3 Write property test for norm-check reduction
  - **Property 14: Norm-Check Reduction to Sumcheck**
  - **Validates: Requirements 7.2**
  - Test Π^norm produces valid Ξ^sum instance
  - Verify sumcheck target matches inner products
  - _Requirements: 7.2_



- [ ] 9. Implement Π^norm+ composition (Corollary 1)
- [ ] 9.1 Create norm-check composition
  - Create `neo-lattice-zkvm/src/salsaa/protocols/norm_composition.rs`
  - Implement `NormCheckComposition` struct
  - Compose Π^norm → Π^sum → Π^lde-⊗
  - Implement `prover_reduce()`: Ξ^norm → Ξ^lin
  - Combine proofs from all three steps
  - Knowledge error: κ = (2µ(d-1) + r - 1)/q^e
  - Communication: (2d-1)µe log q + 3r log |R_q| bits
  - _Requirements: 7.2_
  - _Integrates with: Π^norm, Π^sum, Π^lde-⊗_

- [ ] 10. Implement Π^fold protocol (from [KLNO25])
- [ ] 10.1 Create folding reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/folding.rs`
  - Implement `FoldingReduction` struct with challenge set (Subtractive/Large)
  - Implement `prover_fold()`: split W into d blocks, fold with γ
  - Compute W' = Σ_{i∈[d]} γ^i W_i
  - Update F' using tensor structure
  - Update Y' accordingly
  - _Requirements: 8.1, 8.2_
  - _Integrates with: Existing `folding` module, matrix module_

- [ ]* 10.2 Write property test for folding witness reduction
  - **Property 15: Folding Witness Reduction**
  - **Validates: Requirements 8.1**
  - Test ∥W'∥ ≤ d · max_i ∥W_i∥
  - Generate random witness blocks
  - Verify norm bound after folding
  - _Requirements: 8.1_

- [ ]* 10.3 Write property test for folding statement consistency
  - **Property 16: Folding Statement Consistency**
  - **Validates: Requirements 8.2**
  - Test HF'W' = Y' after folding
  - Verify relation preserved
  - _Requirements: 8.2_

- [ ] 11. Implement Π^split protocol (from [KLNO24])
- [ ] 11.1 Create split reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/split.rs`
  - Implement `SplitReduction` struct
  - Implement `prover_split()`: split W = [W_top; W_bot]
  - Commit to W_top: y_top = F_top W_top
  - Receive challenge α
  - Combine: W' = W_top + α W_bot
  - _Requirements: 9.1_
  - _Integrates with: Matrix module, transcript_

- [ ]* 11.2 Write property test for split witness combination
  - **Property 17: Split Witness Combination**
  - **Validates: Requirements 9.1**
  - Test FW' = F_top W_top + αF_bot W_bot
  - Verify linear combination correctness
  - _Requirements: 9.1_

- [ ] 12. Implement Π^⊗RP protocol (from [KLNO25])
- [ ] 12.1 Create tensor random projection
  - Create `neo-lattice-zkvm/src/salsaa/protocols/random_projection.rs`
  - Implement `TensorRandomProjection` struct
  - Implement `prover_project()`: sample R ∈ R_q^{m_rp×m}
  - Compute w_proj = R · W
  - Compute y_proj = F · w_proj
  - Output two statements: main and projection
  - _Requirements: 10.1_
  - _Integrates with: Matrix module, transcript_

- [ ]* 12.2 Write property test for random projection norm bound
  - **Property 18: Random Projection Norm Bound**
  - **Validates: Requirements 10.1**
  - Test ∥w_proj∥ ≤ m_rp · β with high probability
  - Generate random witness and projection matrix
  - Verify norm bound
  - _Requirements: 10.1_

- [ ] 13. Implement Π^b-decomp protocol (from [KLNO24])
- [ ] 13.1 Create base decomposition
  - Create `neo-lattice-zkvm/src/salsaa/protocols/base_decomposition.rs`
  - Implement `BaseDecomposition` struct with base b, ℓ digits
  - Implement `prover_decompose()`: decompose w_i = Σ_{j∈[ℓ]} b^j w_{i,j}
  - Update F' = F · diag(1, b, b², ..., b^{ℓ-1})
  - Witness norm reduced: ∥W'∥ ≤ ∥W∥/b^{ℓ-1}
  - _Requirements: 11.1_
  - _Integrates with: Existing `ring/decomposition.rs`_

- [ ]* 13.2 Write property test for base decomposition norm reduction
  - **Property 19: Base Decomposition Norm Reduction**
  - **Validates: Requirements 11.1**
  - Test ∥W'∥ ≤ ∥W∥/b^{ℓ-1}
  - Generate random witness
  - Verify norm reduction after decomposition
  - _Requirements: 11.1_



- [ ] 14. Implement Π^batch and Π^batch* protocols
- [ ] 14.1 Create standard batching reduction (from [KLNO25])
  - Create `neo-lattice-zkvm/src/salsaa/protocols/batching.rs`
  - Implement `BatchingReduction` struct
  - Implement `prover_batch()`: receive ρ, batch H and Y
  - Compute H' = Σ_i ρ^i H_i, Y' = Σ_i ρ^i Y_i
  - Output single equation
  - _Requirements: 12.1_
  - _Integrates with: Matrix module, transcript_

- [ ]* 14.2 Create enhanced batching via sumcheck
  - Create `neo-lattice-zkvm/src/salsaa/protocols/enhanced_batching.rs`
  - Implement `EnhancedBatchingReduction` struct
  - Express F̄W = ȳ as sumcheck claims
  - Batch with random linear combination
  - Reduce to single evaluation claim
  - Eliminates compression matrix H
  - _Requirements: 12.2_
  - _Integrates with: Sumcheck module_

- [ ]* 14.3 Write property test for batching linear combination
  - **Property 20: Batching Linear Combination**
  - **Validates: Requirements 12.1**
  - Test batched equation holds iff all original equations hold
  - Generate random equations
  - Verify batching correctness
  - _Requirements: 12.1_

- [ ]* 14.4 Write property test for enhanced batching
  - **Property 21: Enhanced Batching via Sumcheck**
  - **Validates: Requirements 12.2**
  - Test sumcheck batching reduces to single claim
  - Verify equivalence with standard batching
  - _Requirements: 12.2_

- [ ] 15. Implement Π^join protocol (from [KLNO25])
- [ ] 15.1 Create join reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/join.rs`
  - Implement `JoinReduction` struct
  - Implement `prover_join()`: stack statements vertically
  - Combine H, F, Y, W from two instances
  - _Requirements: 13.1_
  - _Integrates with: Matrix module_

- [ ]* 15.2 Write property test for join relation preservation
  - **Property 22: Join Relation Preservation**
  - **Validates: Requirements 13.1**
  - Test joined instance satisfies both original relations
  - Generate two random instances
  - Verify join correctness
  - _Requirements: 13.1_

- [ ] 16. Implement Π^lin-r1cs protocol (Section 7, Appendix C)
- [ ] 16.1 Create R1CS reduction
  - Create `neo-lattice-zkvm/src/salsaa/protocols/r1cs.rs`
  - Implement `R1CSReduction` struct
  - Implement `prover_r1cs_to_linear()`: linearize AW ⊙ BW = CW
  - Express as evaluation claims over LDE
  - Batch constraints with random linear combination
  - Reduce to sumcheck claims
  - _Requirements: 14.1_
  - _Integrates with: LDE module, sumcheck module_

- [ ]* 16.2 Write property test for R1CS linearization
  - **Property 23: R1CS Linearization Correctness**
  - **Validates: Requirements 14.1**
  - Test linearization preserves R1CS constraints
  - Generate random R1CS instance
  - Verify reduction correctness
  - _Requirements: 14.1_

- [-] 17. Checkpoint - Ensure all atomic protocols pass tests

  - Ensure all tests pass, ask the user if questions arise.
  - Verify all RoK protocols are correctly implemented
  - Check integration between modules
  - Validate error handling




- [x] 18. Implement SNARK application (Theorem 1)


- [x] 18.1 Create SNARK parameter selection

  - Create `neo-lattice-zkvm/src/salsaa/applications/snark_params.rs`
  - Implement `SNARKParams` struct
  - Implement `for_witness_size()` to select d, µ, rounds
  - Implement `proof_size_bits()` calculation
  - Implement `prover_ops()` and `verifier_ops()` estimation
  - Verify vSIS hardness with `verify_vsis_hardness()`
  - _Requirements: 15.1, 15.3, 15.4, 15.5, 20.1_
  - _Integrates with: Parameters module_

- [x] 18.2 Create SNARK prover


  - Create `neo-lattice-zkvm/src/salsaa/applications/snark_prover.rs`
  - Implement `SNARKProver` struct
  - Implement structured loop: Π^norm → Π^batch → Π^b-decomp → Π^split → Π^⊗RP → Π^fold
  - Repeat µ = O(log m) times
  - Implement unstructured loop for final O(log λ) rounds
  - Send final witness in clear
  - _Requirements: 15.1, 15.4_
  - _Integrates with: All RoK protocols_

- [x] 18.3 Create SNARK verifier


  - Create `neo-lattice-zkvm/src/salsaa/applications/snark_verifier.rs`
  - Implement `SNARKVerifier` struct
  - Verify each round of structured and unstructured loops
  - Check final witness against relation
  - Verify all transcript challenges
  - _Requirements: 15.1, 15.5_
  - _Integrates with: All RoK protocols, transcript_

- [ ]* 18.4 Write property test for SNARK completeness
  - **Property 24: SNARK Completeness**
  - **Validates: Requirements 15.1**
  - Test valid witness produces accepting proof
  - Generate random valid instance
  - Verify prover succeeds and verifier accepts
  - _Requirements: 15.1_

- [ ]* 18.5 Write property test for SNARK soundness
  - **Property 25: SNARK Soundness**
  - **Validates: Requirements 15.2**
  - Test invalid witness fails to produce accepting proof
  - Generate invalid instance
  - Verify prover fails or verifier rejects
  - _Requirements: 15.2_

- [ ]* 18.6 Write property test for SNARK proof size
  - **Property 26: SNARK Proof Size**
  - **Validates: Requirements 15.3**
  - Test proof size is O(λ log³ m / log λ) bits
  - Measure proof size for various witness sizes
  - Verify asymptotic bound
  - _Requirements: 15.3_

- [ ]* 18.7 Write property test for SNARK prover time
  - **Property 27: SNARK Prover Time**
  - **Validates: Requirements 15.4**
  - Test prover time is O(m) ring operations
  - Benchmark prover for various witness sizes
  - Verify linear complexity
  - _Requirements: 15.4_

- [ ]* 18.8 Write property test for SNARK verifier time
  - **Property 28: SNARK Verifier Time**
  - **Validates: Requirements 15.5**
  - Test verifier time is O(log m · λ²) ring operations
  - Benchmark verifier for various proof sizes
  - Verify polylogarithmic complexity
  - _Requirements: 15.5_





- [ ] 19. Implement PCS application (Theorem 2)
- [ ] 19.1 Create PCS commitment and opening
  - Create `neo-lattice-zkvm/src/salsaa/applications/pcs.rs`
  - Implement `PCSCommitment` using vSIS commitment y = Fw
  - Implement `pcs_commit()` for polynomial coefficients
  - Implement `pcs_open()` for evaluation at point r
  - Use Π^lde-⊗ to prove LDE[w](r) = t
  - Run SNARK for LDE evaluation claim
  - _Requirements: 16.1, 16.2_
  - _Integrates with: SNARK, LDE module, commitment module_

- [ ]* 19.2 Write property test for PCS commitment binding
  - **Property 29: PCS Commitment Binding**
  - **Validates: Requirements 16.1**
  - Test different polynomials have different commitments
  - Generate two distinct polynomials
  - Verify commitments differ (under vSIS)
  - _Requirements: 16.1_

- [ ]* 19.3 Write property test for PCS opening correctness
  - **Property 30: PCS Opening Correctness**
  - **Validates: Requirements 16.2**
  - Test opening verifies iff evaluation is correct
  - Generate random polynomial and evaluation point



  - Verify opening proof correctness
  - _Requirements: 16.2_



- [ ] 20. Implement folding scheme application (Theorem 3)
- [x] 20.1 Create folding scheme parameters


  - Create `neo-lattice-zkvm/src/salsaa/applications/folding_params.rs`
  - Implement `FoldingParams` struct
  - Implement `for_num_instances()` to select parameters
  - Set accumulator width r_acc = 2^ℓ
  - Implement `proof_size_bits()` calculation
  - _Requirements: 17.1, 17.3_
  - _Integrates with: Parameters module_




- [ ] 20.2 Create folding scheme prover
  - Create `neo-lattice-zkvm/src/salsaa/applications/folding_prover.rs`
  - Implement `FoldingProver` struct
  - Compose: Π^join → Π^norm → Π^⊗RP → Π^fold → Π^join → Π^batch* → Π^b-decomp
  - Fold L instances into single accumulated instance
  - Handle cross-terms from Π^join
  - _Requirements: 17.1, 17.4_
  - _Integrates with: All RoK protocols, existing folding module_

- [ ] 20.3 Create folding scheme verifier
  - Create `neo-lattice-zkvm/src/salsaa/applications/folding_verifier.rs`
  - Implement `FoldingVerifier` struct
  - Verify folding proof
  - Check accumulated instance validity
  - Verify all transcript challenges
  - _Requirements: 17.1, 17.5_
  - _Integrates with: All RoK protocols_

- [ ]* 20.4 Write property test for folding completeness
  - **Property 31: Folding Scheme Completeness**
  - **Validates: Requirements 17.1**
  - Test L valid instances fold to valid accumulated instance
  - Generate random valid instances
  - Verify folding succeeds
  - _Requirements: 17.1_

- [ ]* 20.5 Write property test for folding soundness
  - **Property 32: Folding Scheme Soundness**
  - **Validates: Requirements 17.2**
  - Test invalid instance fails folding
  - Generate instances with at least one invalid
  - Verify folding fails or produces invalid accumulator
  - _Requirements: 17.2_

- [ ]* 20.6 Write property test for folding proof size
  - **Property 33: Folding Proof Size**
  - **Validates: Requirements 17.3**
  - Test proof size is O(λ log² m / log λ) bits
  - Measure proof size for various witness sizes
  - Verify asymptotic bound
  - _Requirements: 17.3_

- [ ]* 20.7 Write property test for folding prover time
  - **Property 34: Folding Prover Time**
  - **Validates: Requirements 17.4**
  - Test prover time is O(Lm) ring operations
  - Benchmark prover for various L and m
  - Verify linear complexity
  - _Requirements: 17.4_

- [-]* 20.8 Write property test for folding verifier time


  - **Property 35: Folding Verifier Time**
  - **Validates: Requirements 17.5**
  - Test verifier time is O(λ²) ring operations
  - Benchmark verifier for various proofs
  - Verify constant complexity in m
  - _Requirements: 17.5_

- [x] 21. Checkpoint - Ensure all applications pass tests

  - Ensure all tests pass, ask the user if questions arise.
  - Verify SNARK, PCS, and folding scheme work correctly
  - Check integration with existing zkVM components
  - Validate performance meets paper benchmarks



- [x] 22. Implement AVX-512 optimizations



- [x] 22.1 Create AVX-512 ring arithmetic module

  - Create `neo-lattice-zkvm/src/salsaa/optimization/avx512.rs`
  - Implement `vec_add_mod()` with AVX-512 instructions
  - Implement `vec_mul_mod_ifma()` using IFMA instructions
  - Implement `barrett_reduce_avx512()` for modular reduction
  - Vectorize operations on 8 elements at a time
  - _Requirements: 19.1_
  - _Integrates with: Ring module_

- [ ]* 22.2 Write property test for AVX-512 arithmetic equivalence
  - **Property 38: AVX-512 Arithmetic Equivalence**
  - **Validates: Requirements 19.1**
  - Test AVX-512 results match scalar implementation
  - Generate random ring elements


  - Compare vectorized vs scalar operations

  - _Requirements: 19.1_


- [-] 23. Implement parallel execution

- [x] 23.1 Create parallel sumcheck prover

  - Create `neo-lattice-zkvm/src/salsaa/optimization/parallel_sumcheck.rs`
  - Implement `ParallelSumcheckProver` using Rayon
  - Parallelize computation of intermediate sums

  - Parallelize precomputation of partial evaluations
  - Use parallel iterators for grid point evaluation
  - _Requirements: 19.2_
  - _Integrates with: Sumcheck module, existing parallel module_


- [ ] 23.2 Create parallel matrix operations
  - Extend matrix module with parallel operations
  - Implement `mul_vec_parallel()` using Rayon
  - Implement `mul_mat_parallel()` using Rayon
  - Parallelize row operations
  - _Requirements: 19.2_
  - _Integrates with: Matrix module_

- [ ]* 23.3 Write property test for parallel execution determinism
  - **Property 39: Parallel Execution Determinism**


  - **Validates: Requirements 19.2**
  - Test parallel results match sequential
  - Generate random operations

  - Compare parallel vs sequential execution
  - _Requirements: 19.2_



- [x] 24. Implement memory management and serialization




- [ ] 24.1 Create memory-efficient witness storage
  - Create `neo-lattice-zkvm/src/salsaa/optimization/memory.rs`
  - Implement `WitnessStorage` with in-memory/memory-mapped/streaming options
  - Implement `RingArena` for temporary allocations
  - Use memory-mapped files for large witnesses (> 100MB)
  - _Requirements: Implementation efficiency_
  - _Integrates with: Matrix module_





- [ ] 24.2 Create proof serialization
  - Create `neo-lattice-zkvm/src/salsaa/serialization.rs`
  - Implement `Serialize` and `Deserialize` for all proof types
  - Implement `CompactProofEncoder` with variable-length encoding
  - Use run-length encoding for sparse polynomials
  - Implement `BitWriter` for compact bit-level encoding



  - _Requirements: Implementation efficiency_
  - _Integrates with: All proof structures_

- [ ] 25. Implement security analysis and constant-time operations
- [ ] 25.1 Create constant-time operations module
  - Create `neo-lattice-zkvm/src/salsaa/security/constant_time.rs`
  - Implement `ct_eq()` for constant-time comparison
  - Implement `ct_select()` for conditional select

  - Implement `ct_reduce_mod()` for constant-time modular reduction
  - Add `mul_ct()` to RingElement for timing-attack resistance
  - _Requirements: Side-channel resistance_
  - _Integrates with: Ring module_

- [ ] 25.2 Create security parameter validation
  - Create `neo-lattice-zkvm/src/salsaa/security/params.rs`





  - Implement `SecurityParams` struct
  - Implement `for_security_level()` for λ ∈ {128, 192, 256}
  - Implement `verify_vsis_hardness()` to check parameter security
  - Verify q > 2β² for norm-check correctness
  - Verify Hermite factor for lattice hardness
  - _Requirements: 20.1_


  - _Integrates with: Parameters module_

- [ ]* 25.3 Write property test for parameter security
  - **Property 40: Parameter Security**
  - **Validates: Requirements 20.1**
  - Test vSIS assumption holds for parameter sets


  - Verify security level λ bits
  - Check all parameter relationships
  - _Requirements: 20.1_

- [ ] 26. Integration with existing zkVM components
- [ ] 26.1 Integrate SALSAA SNARK with zkVM
  - Create `neo-lattice-zkvm/src/salsaa/integration/zkvm_adapter.rs`
  - Implement adapter for zkVM circuit compilation
  - Convert zkVM constraints to Ξ^lin or Ξ^lin-r1cs
  - Integrate with existing `applications/zkvm.rs`
  - _Requirements: Integration_
  - _Integrates with: Existing zkVM, SNARK module_

- [ ] 26.2 Integrate SALSAA PCS with existing commitment schemes
  - Create `neo-lattice-zkvm/src/salsaa/integration/pcs_adapter.rs`
  - Implement adapter for existing PCS interface
  - Integrate with `lattice_pcs` module
  - Support both SALSAA PCS and existing schemes
  - _Requirements: Integration_
  - _Integrates with: Existing PCS, commitment module_

- [ ] 26.3 Integrate SALSAA folding with existing IVC
  - Create `neo-lattice-zkvm/src/salsaa/integration/ivc_adapter.rs`
  - Implement adapter for IVC accumulation
  - Integrate with existing `ivc` and `folding` modules
  - Support SALSAA folding as IVC backend
  - _Requirements: Integration_
  - _Integrates with: Existing IVC, folding module_