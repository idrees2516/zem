# Symphony Integration Implementation Plan

## Task Overview

This implementation plan breaks down the Symphony integration into discrete, manageable coding tasks. Each task builds incrementally on previous work, ensuring the system remains functional at every step. Tasks are organized by architectural layer and include specific requirements references.

## Task Execution Guidelines

- Each task should be completed and tested before moving to the next
- All mathematical formulations must match paper specifications exactly
- Integration tests should verify compatibility with existing Neo and LatticeFold+ code
- Performance benchmarks should be run after completing each major component

---

## Layer 1: Algebraic Foundation

- [x] 1. Implement cyclotomic ring arithmetic





  - Create `RingElement` struct with coefficient vector representation
  - Implement addition, subtraction, multiplication over Rq = Zq[X]/⟨X^d + 1⟩
  - Implement coefficient form cf(·) and constant term ct(·) extraction
  - Implement ℓ∞-norm, ℓ2-norm calculations per Section 2.1 of Symphony
  - Add unit tests verifying ring axioms (associativity, distributivity, commutativity)
  - _Requirements: 1.1, 1.2, 1.3, 25.1, 25.2_

- [x] 1.1 Implement Number Theoretic Transform (NTT)


  - Implement NTT for q ≡ 1 + 2^e (mod 4^e) where e | d
  - Implement inverse NTT for coefficient-to-evaluation conversion
  - Optimize using butterfly operations for O(d log d) complexity
  - Verify isomorphism Rq ≅ F_{q^e}^{d/e} for supported parameters
  - Add tests comparing NTT multiplication with coefficient multiplication
  - _Requirements: 1.1, 12.10, 25.1_

- [x] 1.2 Implement operator norm calculations


  - Implement operator norm ∥a∥_op := sup_{y∈R} ∥a·y∥_∞ / ∥y∥_∞ per Eq. (1)
  - Implement set operator norm ∥S∥_op := max_{a∈S} ∥a∥_op
  - Verify Lemma 2.3: For a ∈ M, b ∈ R, ∥a·b∥_∞ ≤ ∥b∥_∞
  - Verify Lemma 2.4: Invertibility for ∥y∥_∞ < q^{1/e}/√e
  - Add tests with LaBRADOR challenge set verifying ∥S∥_op ≤ 15
  - _Requirements: 1.2, 16.1, 16.2, 16.3, 25.3_

- [x] 1.3 Implement extension field arithmetic


  - Create `FieldElement` struct for K = F_{q^t}
  - Implement addition, multiplication, inversion over extension field
  - Implement tower field construction for efficient arithmetic
  - Support Goldilocks prime q = 2^64 - 2^32 + 1 with t = 2
  - Support Mersenne 61 prime q = 2^61 - 1 with t = 2
  - Add tests verifying field axioms and 128-bit security level
  - _Requirements: 1.3, 13.9, 16.5, 16.8, 16.9, 25.1_


- [x] 1.4 Implement tensor-of-rings framework


  - Create `TensorElement` struct representing E := K ⊗_{F_q} Rq as t×d matrix
  - Implement K-vector space interpretation: e = [e_1, ..., e_d] ∈ K^{1×d}
  - Implement Rq-module interpretation: e = (e'_1, ..., e'_t) ∈ Rq^t
  - Implement K-scalar multiplication: a·[e_1, ..., e_d] = [a·e_1, ..., a·e_d]
  - Implement Rq-scalar multiplication: (e'_1, ..., e'_t)·b = (b·e'_1, ..., b·e'_t)
  - Implement mixed multiplication a·b ∈ E for a ∈ K, b ∈ Rq as cf(a) ⊗ cf(b)^⊤
  - Add tests verifying both interpretations produce consistent results
  - _Requirements: 1.4, 12.1-12.10, 25.1_

## Layer 2: Cryptographic Primitives


- [ ] 2. Implement Ajtai commitment scheme
  - Create `CommitmentKey` struct with MSIS matrix A ∈ Rq^{κ×n}
  - Implement Setup(1^λ) sampling A uniformly at random
  - Implement Commit(pp_cm, m) computing c := A·m for m ∈ Rq^n
  - Implement VfyOpen checking Af = s·c AND ∥f∥_2 < B_bnd AND s·m = f
  - Implement RVfyOpen for relaxed opening with ∥f∥_2 ≤ B_rbnd := 2B_bnd
  - Set B_rbnd := β_SIS/(4T) where T = ∥S∥_op per Eq. (12)
  - Add tests verifying binding under Module-SIS assumption
  - _Requirements: 2.1-2.7, 16.6, 16.7, 25.5_



- [ ] 2.1 Implement fine-grained commitment opening
  - Implement VfyOpen_{ℓ_h,B}(pp_cm, c, f) per Eq. (13)
  - Check Af = c AND ∀(i,j) ∈ [n/ℓ_h] × [d]: ∥F_{i,j}∥_2 ≤ B
  - Parse cf(f) ∈ Z_q^{n×d} into blocks F_{i,j} ∈ Z_q^{ℓ_h×1}
  - Verify implication: VfyOpen_{ℓ_h,B} = 1 ⟹ VfyOpen = 1 if B·√(nd/ℓ_h) ≤ B_bnd


  - Add tests with various block sizes ℓ_h and bounds B
  - _Requirements: 2.7, 6.4, 25.5_

- [ ] 2.2 Integrate Neo's pay-per-bit commitment
  - Integrate Neo's matrix commitment scheme from Section 3.2 of Neo paper
  - Implement vector-to-matrix transformation for small field elements
  - Verify linear homomorphism for folding multilinear evaluation claims per Section 3.3


  - Implement pay-per-bit cost scaling: 32× cheaper for bits vs 32-bit values
  - Add tests comparing commitment costs for different bit-widths
  - Verify compatibility with existing Neo implementation
  - _Requirements: 17.1-17.10, 23.1-23.3, 25.1_

- [ ] 2.3 Implement monomial embedding system
  - Define monomial set M := {0, 1, X, ..., X^{d-1}} ⊆ Rq per Eq. (2)
  - Implement table polynomial t(X) := Σ_{i∈[1,d/2)} i·(X^{-i} + X^i) per Eq. (3)
  - Implement Exp(a) := sgn(a)X^a for a ∈ (-d/2, d/2) per Eq. (4)


  - Implement EXP(a) set: {Exp(a)} if a ≠ 0, {0, 1, X^{d/2}} if a = 0
  - Verify Lemma 2.1: For a ∈ (-d/2, d/2), b ∈ Exp(a), ct(b·t(X)) = a
  - Verify converse: If ct(b·t(X)) = a for b ∈ M, then a ∈ (-d/2, d/2)
  - Add tests for all values in range (-d/2, d/2)
  - _Requirements: 3.1-3.7, 24.1-24.3, 25.2, 25.3_


- [x] 2.4 Implement random projection system



  - Implement structured projection matrix M_J := I_{n/ℓ_h} ⊗ J per Section 3.4
  - Sample J ← χ^{λ_pj × ℓ_h} where χ is distribution over {0, ±1} with Pr[χ=0]=1/2
  - Implement projection H := (I_{n/ℓ_h} ⊗ J) × cf(f) ∈ Z_q^{m×d}
  - Verify Lemma 2.2: Pr[|⟨u,v⟩| > 9.5∥v∥_2] ≲ 2^{-141} for u ← χ^n
  - Verify Eq. (6): For ∥v∥_2 > B, Pr[∥Jv mod q∥_2 ≤ √30B] ≲ 2^{-128}
  - Set λ_pj = 256 for security
  - Add statistical tests verifying norm preservation properties
  - _Requirements: 4.1-4.8, 16.11, 16.12, 25.3, 25.4_

- [ ] 2.5 Implement norm decomposition
  - Compute k_g as minimal integer s.t. B_{d,k_g} := (d'/2)·(1 + d' + ... + d'^{k_g-1}) ≥ 9.5B
  - Implement decomposition H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g) per Eq. (33)
  - Ensure ∥H^(i)∥_∞ ≤ d'/2 for all i ∈ [k_g] where d' = d - 2
  - Implement flatten operation h^(i) := flt(H^(i)) ∈ Z_q^{md}
  - Compute monomial vectors g^(i) := Exp(h^(i)) ∈ M^n
  - Add tests verifying decomposition correctness and norm bounds
  - _Requirements: 4.3, 4.4, 4.5, 25.4_

- [ ] 2.6 Implement sumcheck protocol
  - Implement sumcheck prover generating round polynomials of degree D
  - Implement sumcheck verifier checking polynomial consistency
  - Implement reduction from R_sum (Eq. 16) to R_eval (Eq. 17)
  - Achieve linear-time prover: O(n) field operations per round
  - Achieve polylogarithmic verifier: O(D) field operations per round
  - Compute knowledge error ϵ_sum := D·log(n)/|K| + ϵ_bind
  - Implement tensor ts(r) := (eq_b(r))_{b∈{0,1}^k} per Eq. (15)
  - Add tests verifying soundness and completeness
  - _Requirements: 13.1-13.10, 25.6_

- [ ] 2.7 Implement sumcheck batching
  - Implement batching of k sumcheck statements using random linear combination
  - Sample combiner α ← K and reduce to single statement for Σ_{i=1}^k g_i·α^{i-1}
  - Implement special case for g(X) = h(f_1(X), ..., f_k(X)) per Eq. (18)
  - Reduce to linear relation R'_eval (Eq. 19) checking ⟨f_i, ts(r)⟩ = u_i
  - Verify h(u_1, ..., u_k) = v outside sumcheck
  - Add tests batching multiple sumcheck instances
  - _Requirements: 13.8, 25.6_

## Layer 3: Reduction of Knowledge Toolbox

- [x] 3. Implement monomial check protocol (Π_mon)



  - Implement protocol from Lemma 3.1 reducing R_mon (Eq. 27) to R_batchlin (Eq. 28)
  - Run single degree-3 sumcheck over K of size n
  - Verify all g^(i) ∈ M^n are monomial vectors
  - Compute evaluations u^(i) := ⟨g^(i), ts(r)⟩ ∈ E for i ∈ [k_g]
  - Achieve prover complexity T_p^mon(k_g, n) = O(nk_g) K-additions + O(n) K-ops
  - Achieve verifier complexity T_v^mon(k_g, n) = O(k_g·d + log(n)) K-ops
  - Add tests verifying reduction correctness
  - _Requirements: 3.6, 3.7, 25.7_


- [x] 3.1 Implement range proof protocol (Π_rg)

  - Implement protocol from Figure 2 reducing R_rg^{ℓ_h,B} (Eq. 30) to R_lin^auxJ × R_batchlin
  - Sample projection matrix J ← χ^{λ_pj × ℓ_h} in Step 1
  - Compute H := (I_{n/ℓ_h} ⊗ J) × cf(f) and check ∥H∥_∞ ≤ B_{d,k_g} in Step 2
  - Decompose H per Eq. (33) and compute monomial vectors in Steps 3-4
  - Send monomial commitments (c^(i) := A×g^(i))_{i=1}^{k_g} in Step 5
  - Run Π_mon protocol in Step 6
  - Verify consistency u_{t1}^(i) = ⟨ts(s), v^(i)⟩ in Step 7
  - Achieve completeness error ϵ ≈ nλ_pj·d/(ℓ_h·2^141) per Theorem 3.1
  - Extract witnesses with relaxed norm B' = 16B_{d,k_g}/√30
  - Add tests verifying approximate range proof correctness
  - _Requirements: 4.1-4.8, 25.4_

- [x] 3.2 Implement Hadamard product reduction (Π_had)

  - Implement protocol from Figure 1 reducing R_had^aux (Eq. 23) to R_lin^aux (Eq. 24)
  - Sample challenges s ← K^{log m}, α ← K in Step 1
  - Run sumcheck for claim Σ_{b,j} α^{j-1}·f_j(b) = 0 per Eq. (25) in Step 2
  - Define f_j(X) = eq(s,X)·(g_{1,j}(X)·g_{2,j}(X) - g_{3,j}(X))
  - Send evaluation matrix U ∈ K^{3×d} where U_{i,j} := g_{i,j}(r) in Step 3
  - Verify Σ_{j=1}^d α^{j-1}·eq(s,r)·(U_{1,j}·U_{2,j} - U_{3,j}) = e in Step 4
  - Compute output v_i := Σ_{j=1}^d (X^{j-1})·U_{i,j} ∈ E using tensor multiplication
  - Achieve prover complexity T_p^had(m) = 3d inner products + O((m+n)d) Z_q-muls
  - Achieve verifier complexity T_v^had(m) = O(d + log(m)) K-ops
  - Add tests verifying Hadamard check linearization
  - _Requirements: 5.1-5.8, 25.5_

## Layer 4: Folding Protocols

- [ ] 4. Implement single-instance reduction (Π_gr1cs)
  - Implement protocol from Figure 3 reducing R_gr1cs^aux (Eq. 38) to R_lin^auxcs × R_batchlin
  - Sample shared challenges J, s', α in Step 1
  - Send helper commitments (c^(i))_{i=1}^{k_g} in Step 2
  - Run two parallel sumchecks in Step 3:
    * Hadamard sumcheck (log(m) rounds)
    * Monomial check sumcheck (log(n) rounds)
  - Share challenge (r̄, s̄, s) between sumchecks
  - Execute rest of Π_had and Π_rg in Step 4
  - Output x_o = (x_*, x_bat) per Eq. (39-40)
  - Achieve prover complexity T_p^gr1cs = T_p^had(m) + T_p^rg(k_g, n)
  - Achieve verifier complexity T_v^gr1cs = T_v^had(m) + T_v^rg(k_g, n)
  - Add tests verifying reduction correctness per Lemma 4.1
  - _Requirements: 7.1-7.9, 25.7_


- [ ] 4.1 Implement generalized R1CS relation
  - Define R_gr1cs^aux with instance (c, X_in ∈ Z_q^{n_in×d}) and witness W ∈ Z_q^{n_w×d}
  - Construct F^⊤ := [X_in^⊤, W^⊤] ∈ Z_q^{d×n} where n = n_in + n_w
  - Verify Hadamard constraint (M_1 × F) ◦ (M_2 × F) = M_3 × F
  - Verify commitment opening VfyOpen_{ℓ_h,B}(pp_cm, c, cf^{-1}(F)) = 1
  - Implement base-b decomposition for standard R1CS conversion
  - Set k_cs := 1 + ⌊log_b(q)⌋ and define M_i := M̄_i ⊗ [1, b, ..., b^{k_cs-1}]
  - Convert instances X_in := [decomp_{b,k_cs}(x_in^(1)) || ... || decomp_{b,k_cs}(x_in^(d))]
  - Set norm bound B = 0.5b√ℓ_h ensuring entries bounded by b/2
  - Add tests verifying d R1CS statements batched correctly
  - _Requirements: 6.1-6.9, 25.7_






- [ ] 4.2 Implement multi-instance high-arity folding (Π_fold)
  - Implement protocol from Figure 4 folding (R_gr1cs^aux)^{ℓ_np} to R_lin^auxcs × R_batchlin
  - Execute ℓ_np parallel Π_gr1cs instances with shared randomness in Step 1
  - Merge 2ℓ_np sumcheck claims into 2 using random linear combination
  - First merged claim: Σ_{b,ℓ,j} α^{(ℓ-1)·d+j-1}·f_{ℓ,j}(b) = 0 per Eq. (45)
  - Second merged claim: batched monomial checks with α combiners
  - Verify evaluation consistency in Step 3
  - Sample folding challenge β ← S^{ℓ_np} in Step 4
  - Compute folded commitments c_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·c_ℓ in Step 5


  - Compute folded witnesses f_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ in Step 6
  - Verify norm bounds: ∥f_*∥_2 ≤ ℓ_np·∥S∥_op·B√(nd/ℓ_h)
  - Achieve prover complexity T_p^fold per Proposition 4.2
  - Add tests verifying folding correctness per Theorem 4.1
  - _Requirements: 8.1-8.10, 25.8_

- [ ] 4.3 Implement memory-efficient streaming prover
  - Implement streaming algorithm requiring memory O(n) per Remark 4.1
  - Pass 1: Compute ℓ_np input commitments in streaming fashion
  - Pass 2: Execute sumcheck using algorithm from [Baw+25] Section 4
  - Perform log log(n) passes computing evaluation tables
  - Pass 3: Stream witnesses and compute folded witness f_*
  - Achieve total 2 + log log(n) passes over input data
  - Verify memory usage stays O(n) throughout execution
  - Support starting proof generation as statements become available
  - Enable parallelization across multiple cores
  - Add tests verifying memory bounds and correctness
  - _Requirements: 14.1-14.10, 25.8_

## Layer 5: Non-Interactive Transformation

- [ ] 5. Implement commit-and-open transformation
  - Implement CM[Π_cm, Π_rok] replacing prover messages with commitments
  - For each round i, compute c_{fs,i} := Π_cm.Commit(pp_cm, m_i)
  - Send opening messages (m_i)_{i=1}^{rnd} at protocol end

  - Verify (m_i)_{i=1}^{rnd} are valid openings to (c_{fs,i})_{i=1}^{rnd}
  - Preserve reduction of knowledge property
  - Require straightline extractable commitment scheme
  - Add tests verifying transformation correctness
  - _Requirements: 9.1-9.3, 25.9_

- [ ] 5.1 Implement Fiat-Shamir transform
  - Implement FSH[Π_cm, Π_rok] deriving challenges from hash function H
  - Initialize transcript with instance x, derive r_1 := H(x)
  - For each round i, append (r_i, c_{fs,i}) to transcript
  - Derive r_{i+1} from updated transcript using H
  - Use Merkle-Damgård framework to fix hash input length


  - Model H as random oracle in security proofs
  - Account for Q oracle queries in knowledge error bound
  - Support SNARK-friendly hashes (Poseidon) and standard hashes (SHA-256, BLAKE3)
  - Add tests verifying non-interactive transformation
  - _Requirements: 9.4-9.10, 20.1-20.10, 25.9_


- [ ] 5.2 Implement coordinate-wise special soundness extraction
  - Implement extractor E^A based on Lemma 2.3 (Lemma 7.1 of [FMN24])
  - Define challenge space U := S^{ℓ_np} and predicate Ψ: U × Y → {0,1}
  - For vectors a, b ∈ S^{ℓ_np}, define a ≡_i b iff a_i ≠ b_i and a_j = b_j for j ≠ i
  - Run E^A(u_0, y_0) outputting ℓ_np + 1 pairs (u_i, y_i)_{i=0}^{ℓ_np}
  - Verify Ψ(u_i, y_i) = 1 for all i and u_i ≡_i u_0 for i ∈ [ℓ_np]
  - Achieve extraction probability ≥ ϵ_Ψ(A) - ℓ_np/|S|
  - Call adversary A for 1 + ℓ_np times in expectation
  - Extract witness f^ℓ := (f^{*,ℓ} - f^{*,0})/(u_ℓ[ℓ] - u_0[ℓ]) per Eq. (51-52)
  - Verify extracted witnesses satisfy relaxed relation R̂_lin^auxcs × R̂_batchlin
  - Add tests verifying extraction correctness
  - _Requirements: 19.1-19.10, 25.8_

## Layer 6: SNARK Construction

- [x] 6. Implement CP-SNARK relation


  - Define R_cp checking x_o = f(x, (m_i)_{i=1}^{rnd}, (r_i)_{i=1}^{rnd+1}) per Eq. (54)
  - Verify c_{fs,i} = Π_cm.Commit(pp_cm, m_i) for all i ∈ [rnd]
  - Define instance x_cp := (x, (r_i)_{i=1}^{rnd+1}, (c_{fs,i})_{i=1}^{rnd}, x_o) per Eq. (55)
  - Define witness w := (w_cp := (m_i)_{i=1}^{rnd}, w_e)

  - Support Merkle commitments for hash-based CP-SNARKs
  - Support KZG commitments for pairing-based CP-SNARKs
  - Ensure CP-SNARK proves only O(ℓ_np) Rq-multiplications
  - Compress folding proofs from >30MB to <1KB commitments
  - Add tests verifying relation correctness
  - _Requirements: 10.1-10.10, 25.10_


- [ ] 6.1 Implement CP-SNARK compiler
  - Implement Construction 6.1 compiling folding to SNARK
  - Setup: Generate (pk_*, vk_*) := (pp_cm, pk_cp, pk), (pp_cm, vk_cp, vk)
  - Prove^H: Execute FSH[Π_cm, Π_fold] obtaining (x_o, w_o)
  - Generate CP-SNARK proof π_cp for folding verification

  - Generate SNARK proof π for reduced statement (x_o, w_o) ∈ R_o
  - Output π_* := (π_cp, π, (c_{fs,i})_{i=1}^{rnd}, x_o)
  - Verify^H: Recompute challenges from x, (c_{fs,i})_{i=1}^{rnd}, H
  - Verify π_cp against x_cp and π against x_o
  - Implement instance compression using c_{fs,0} := Π_cm.Commit(pp_cm, x) per Remark 6.1
  - Add tests verifying compiler correctness per Theorem 6.1
  - _Requirements: 10.1-10.12, 11.1-11.12, 25.10_


- [ ] 6.2 Implement complete Symphony SNARK system
  - Implement SymphonySNARK with all optimizations
  - Setup: Initialize commitment scheme, CP-SNARK, SNARK, folding protocol
  - Configure parameters: d=64, q (Goldilocks or Mersenne 61), t=2, ℓ_np=2^10 to 2^16
  - Set security parameters: λ=128, β_SIS, λ_pj=256
  - Define challenge set S with ∥S∥_op ≤ 15
  - Prove: Convert R1CS to generalized R1CS, execute folding, generate proofs
  - Verify: Recompute challenges, verify CP-SNARK and SNARK proofs
  - Achieve proof size <200KB (post-quantum) or <50KB (classical)
  - Achieve verification time in tens of milliseconds
  - Achieve prover time ~3·2^32 Rq-multiplications
  - Add end-to-end tests for various statement sizes
  - _Requirements: 11.1-11.12, 21.1-21.12, 25.10_





## Layer 7: Integration and Extensions

- [ ] 7. Integrate with existing Neo implementation
  - Reuse Neo's folding-friendly lattice-based commitment from Section 3
  - Integrate Neo's matrix commitment with pay-per-bit costs
  - Utilize Neo's linear homomorphism for folding multilinear evaluations
  - Adopt Neo's CCS reduction protocol Π_CCS from Section 4.4
  - Integrate Neo's random linear combination Π_RLC from Section 4.5
  - Use Neo's decomposition reduction Π_DEC from Section 4.6
  - Leverage Neo's challenge set design ensuring invertibility
  - Integrate Neo's concrete parameters for Goldilocks and Mersenne 61
  - Reuse Neo's security analysis framework from Section 5
  - Verify compatibility with Neo's IVC/PCD construction
  - Add integration tests verifying Neo compatibility
  - _Requirements: 23.1-23.10, 26.12_

- [x] 7.1 Integrate with existing LatticeFold+ implementation

  - Integrate LatticeFold+'s monomial embedding range proof from Section 4.3
  - Utilize LatticeFold+'s table polynomial t(X)
  - Adopt LatticeFold+'s monomial set check from Section 4.2
  - Integrate LatticeFold+'s commitment transformation from Section 4.4
  - Use LatticeFold+'s double commitment optimization
  - Leverage LatticeFold+'s generalized committed linear relations from Section 3
  - Integrate LatticeFold+'s folding protocol from Section 5.1
  - Adopt LatticeFold+'s decomposition technique from Section 5.2
  - Utilize LatticeFold+'s efficiency estimates from Section 5.3
  - Verify compatibility with LatticeFold+'s small moduli support


  - Add integration tests verifying LatticeFold+ compatibility
  - _Requirements: 24.1-24.10, 26.12_


- [ ] 7.2 Implement two-layer folding extension
  - Support folding depth two for >2^40 total constraints
  - After first layer, obtain (x_o, w_o) ∈ R_o and first CP-SNARK proof
  - Split (x_o, w_o) into multiple uniform NP statements
  - Apply high-arity folding to second layer statements
  - Generate second CP-SNARK proof for second layer
  - Output two CP-SNARK proofs plus one SNARK proof
  - Avoid embedding Fiat-Shamir circuits at both layers


  - Use splitting technique from Section 8 when Ajtai parameter has structural property
  - Support Mangrove's uniformization for general cases
  - Maintain post-quantum security across both layers
  - Add tests verifying two-layer folding correctness
  - _Requirements: 15.1-15.10_

- [ ] 7.3 Implement zkVM application integration
  - Support proving RISC-V instruction execution
  - Decompose computation into uniform R1CS statements per instruction batch
  - Implement constraint system generation for RISC-V instructions
  - Support incremental proof generation (IVC-style)
  - Enable proof-carrying data (PCD) for distributed computation
  - Provide APIs for custom witness preprocessing


  - Add examples demonstrating zkVM usage
  - Benchmark performance for various program sizes
  - _Requirements: 22.1-22.10_


- [ ]* 7.4 Implement ML proof application integration
  - Support verifying neural network inference


  - Generate constraint systems for matrix multiplications and activations
  - Optimize for common ML operations (convolution, pooling, etc.)
  - Support batch proving for multiple inference runs
  - Provide APIs for model-specific optimizations
  - Add examples for common architectures (ResNet, Transformer, etc.)
  - Benchmark performance for various model sizes
  - _Requirements: 22.3_

- [ ] 7.5 Implement aggregate signature application

  - Support post-quantum aggregate signature schemes
  - Use batch proof verification for signature aggregation
  - Implement signature verification constraint systems
  - Optimize for common signature schemes (Dilithium, Falcon, etc.)
  - Provide APIs for signature aggregation
  - Add examples demonstrating aggregate signatures
  - Benchmark performance for various batch sizes
  - _Requirements: 22.4_

## Testing and Validation

- [ ] 8. Implement comprehensive unit test suite
  - Test all cryptographic primitives (commitments, hash, field ops)
  - Test all reduction of knowledge protocols
  - Validate monomial embedding for all values in (-d/2, d/2)
  - Validate random projection with statistical tests
  - Test sumcheck correctness for various polynomial degrees
  - Validate folding by checking extracted witnesses
  - Test Fiat-Shamir with multiple hash functions
  - Validate CP-SNARK compiler with various commitment schemes
  - Perform end-to-end tests for R1CS of sizes 2^10, 2^12, 2^14, 2^16
  - Test security properties with malicious prover simulations
  - _Requirements: 26.1-26.12_

- [ ]* 8.1 Implement integration test suite
  - Test Neo integration (commitment scheme, CCS folding, pay-per-bit)
  - Test LatticeFold+ integration (range proofs, double commitments)
  - Test end-to-end R1CS proving and verification
  - Test streaming prover memory efficiency
  - Test two-layer folding for large statement counts
  - Verify compatibility between all components
  - _Requirements: 26.1-26.12_

- [ ]* 8.2 Implement property-based test suite
  - Test ring arithmetic properties (associativity, commutativity, distributivity)
  - Test commitment binding with random messages
  - Test sumcheck soundness with random polynomials
  - Test folding correctness with random instances
  - Use proptest or quickcheck for property generation
  - _Requirements: 26.1-26.12_

- [ ]* 8.3 Implement benchmark suite
  - Benchmark folding for arities 1024, 2048, 4096, 8192, 16384
  - Benchmark SNARK proving and verification
  - Benchmark individual components (commitments, sumcheck, range proofs)
  - Compare performance against theoretical complexity bounds
  - Compare against HyperNova and other folding schemes
  - Generate performance reports and visualizations
  - _Requirements: 26.10_


## Documentation and Finalization

- [ ]* 9. Create comprehensive documentation
  - Document all mathematical notation matching papers
  - Provide inline comments with paper section references
  - Document security parameters with lattice estimator justification
  - Provide API documentation for all public interfaces
  - Document performance characteristics and complexity bounds
  - Provide usage examples for common applications
  - Document integration points between components
  - Maintain changelog for deviations from papers
  - Provide troubleshooting guide
  - Document testing procedures and validation methodology
  - _Requirements: 28.1-28.10_

- [ ] 9.1 Create example applications

  - Simple R1CS proving example
  - zkVM execution proof example
  - Batch proving example
  - Streaming prover example
  - Two-layer folding example
  - ML inference proof example
  - Aggregate signature example
  - _Requirements: 22.1-22.10_

- [ ] 9.2 Performance optimization pass

  - Profile prover and identify bottlenecks
  - Optimize hot paths in commitment computation
  - Optimize sumcheck evaluation table computation
  - Optimize witness folding operations
  - Implement SIMD optimizations where applicable
  - Implement multi-threading for parallelizable operations
  - Verify 8× speedup for 8-bit witnesses
  - Achieve target performance: ~3·2^32 Rq-muls
  - _Requirements: 21.5, 21.11_

- [ ]* 9.3 Security audit preparation
  - Review all cryptographic implementations
  - Verify all mathematical formulations match papers
  - Check all security parameters meet requirements
  - Verify Module-SIS parameters using lattice estimator
  - Review random number generation
  - Check for timing side-channels
  - Verify constant-time operations where required
  - Prepare security documentation
  - _Requirements: 16.1-16.12, 20.1-20.10_

- [ ]* 9.4 Final integration and validation
  - Run full test suite on all platforms
  - Verify all requirements are met
  - Validate performance targets achieved
  - Check compatibility with Neo and LatticeFold+
  - Verify proof sizes and verification times
  - Run extended stress tests
  - Validate memory efficiency claims
  - Prepare release documentation
  - _Requirements: 25.1-25.12, 26.1-26.12_

## Notes

- Tasks marked with * are optional but recommended for production readiness
- Each task should include appropriate error handling per Section "Error Handling"
- All implementations must match paper specifications exactly (Requirement 25)
- Integration tests should verify compatibility with existing Neo and LatticeFold+ code
- Performance benchmarks should be run after completing each major component
- Security parameters should be validated using lattice estimator tools

