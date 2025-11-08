# LatticeFold+ Implementation Tasks

## Task Organization

Tasks are organized into epics covering major components. Each task builds incrementally on previous tasks with no orphaned code.

## Epic 1: Core Algebraic Structures

- [x] 1. Implement cyclotomic ring operations


- [x] 1.1 Create CyclotomicRing struct with degree d and modulus q

  - Implement balanced representation Zq = {-⌊q/2⌋, ..., ⌊q/2⌋}
  - Add NTT support detection (q ≡ 1 + 2^e mod 4e)
  - Integrate with Neo's NTT engine
  - _Requirements: LFP-1_

- [x] 1.2 Implement RingElement with coefficient vector

  - Add addition with lazy reduction
  - Add multiplication using NTT when available
  - Implement X^d = -1 reduction automatically
  - Add polynomial composition a(X²)
  - Add polynomial evaluation a(β) for β ∈ F_q^u
  - _Requirements: LFP-1_

- [x] 1.3 Implement monomial set M = {0, 1, X, ..., X^(d-1)}

  - Create Monomial enum (Zero, Positive, Negative)
  - Implement exp(a) = sgn(a)·X^|a| function
  - Implement EXP(a) set function
  - Add monomial test: a(X²) = a(X)² (Lemma 2.1)
  - Implement efficient monomial multiplication
  - _Requirements: LFP-2_

- [x] 1.4 Implement MonomialMatrix for sparse representation

  - Store n×m matrix of monomials
  - Implement efficient column/row access
  - Add matrix-vector multiplication optimized for monomials
  - _Requirements: LFP-2_



- [ ] 2. Implement table polynomial and range extraction
- [ ] 2.1 Create TablePolynomial struct
  - Compute ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i)
  - Implement X^(-i) = -X^(d-i) computation
  - Cache ψ for reuse

  - _Requirements: LFP-3_

- [ ] 2.2 Implement range extraction functions
  - Add extract_value: ct(b · ψ) for b ∈ M

  - Implement verify_range: check a ∈ (-d', d') ⟺ ∃b ∈ EXP(a): ct(b·ψ) = a

  - Support generalized table lookup for custom T ⊆ Zq
  - _Requirements: LFP-3_

- [ ] 3. Implement norms and sampling sets
- [ ] 3.1 Create NormChecker struct
  - Implement ℓ∞-norm: ||f||∞ = max_i |f_i|

  - Implement operator norm: ||a||_op = sup ||a·y||∞ / ||y||∞
  - Add matrix norm computation
  - Verify Lemma 2.3: monomial multiplication preserves norm
  - _Requirements: LFP-4_


- [x] 3.2 Implement StrongSamplingSet

  - Verify all differences are invertible
  - Compute operator norm ||S||_op
  - Implement invertibility check using Lemma 2.4
  - Support Zq and extension fields F_q^t

  - _Requirements: LFP-5_

- [x] 4. Implement gadget matrix decomposition

- [ ] 4.1 Create GadgetDecomposition struct
  - Compute gadget vector g_{b,k} = (1, b, ..., b^(k-1))
  - Compute gadget matrix G_{b,k} = I_m ⊗ g_{b,k}
  - _Requirements: LFP-6_

- [ ] 4.2 Implement decomposition function G^(-1)
  - Decompose each entry to base-b with sign handling
  - Verify M = G^(-1)(M) · G
  - Ensure ||G^(-1)(M)||∞ < b when ||M||∞ < b^k
  - _Requirements: LFP-6_

## Epic 2: Commitment Schemes

- [x] 5. Implement Ajtai (linear) commitments





- [x] 5.1 Create AjtaiCommitment struct

  - Implement LazyMatrix for seed-based generation
  - Add matrix-vector multiplication com(a) = Aa using NTT
  - Support batch commitment for multiple vectors

  - _Requirements: LFP-9_

- [x] 5.2 Implement commitment opening and verification

  - Define OpeningInfo with witness, scalar, norm bound
  - Implement (b, S)-valid opening check
  - Verify cm = com(a) and a = a's with ||a'||∞ < b
  - _Requirements: LFP-11, LFP-12_




- [ ] 5.3 Implement Module-SIS security
  - Define MSISParameters struct
  - Verify (b, S)-relaxed binding reduces to MSIS
  - Compute required β_SIS = 2b||S||_op
  - _Requirements: LFP-9_

- [x] 6. Implement double commitments




- [ ] 6.1 Create DoubleCommitment struct
  - Implement for vectors: dcom(m) = com(m)
  - Implement for matrices: dcom(M) = com(split(com(M)))

  - _Requirements: LFP-12_

- [ ] 6.2 Implement split function (Construction 4.1)
  - Compute gadget decomposition G^(-1)_{d',ℓ}(com(M))
  - Flatten matrix to vector
  - Extract coefficient matrix
  - Pad to length n

  - Verify split is injective
  - _Requirements: LFP-12_

- [ ] 6.3 Implement pow function
  - Compute power-sums of sub-vectors
  - Embed results to polynomial coefficients

  - Verify pow(split(D)) = D
  - Note pow is not injective
  - _Requirements: LFP-12_

- [ ] 6.4 Implement double opening relation R_{dopen,m}
  - Verify M is valid opening of pow(τ) = com(M)





  - Verify τ is valid opening of C_M
  - Prove binding via Lemma 4.1
  - _Requirements: LFP-12_


## Epic 3: Monomial Set Check Protocol


- [ ] 7. Implement Π_mon protocol structures
- [ ] 7.1 Create MonomialSetCheckProver
  - Store matrix M, double commitment C_M
  - Implement Corollary 4.1: ev_a(β)² = ev_a(β²) test
  - _Requirements: LFP-13_

- [ ] 7.2 Create MonomialSetCheckVerifier
  - Store commitment C_M and challenge set
  - _Requirements: LFP-13_

- [ ] 7.3 Define proof and instance structures
  - MonomialSetCheckProof with sumcheck proof and evaluations
  - MonomialSetCheckInstance with commitment, challenge, evaluations
  - _Requirements: LFP-13_

- [x] 8. Implement Π_mon prover (Construction 4.2)


- [x] 8.1 Implement challenge generation

  - Receive c ← C^(log n) and β ← C from transcript
  - _Requirements: LFP-13_


- [ ] 8.2 Prepare sumcheck claims
  - Compute m^(j) = evaluations at β for each column
  - Compute m'^(j) = evaluations at β² for each column
  - Create claim: Σ_i eq(c, ⟨i⟩) · (m̃^(j)(⟨i⟩)² - m̃'^(j)(⟨i⟩)) = 0
  - Batch m claims via random linear combination
  - _Requirements: LFP-13_


- [ ] 8.3 Run degree-3 sumcheck protocol
  - Implement batched sumcheck over challenge set C
  - Reduce to evaluation claim at r ← C^(log n)

  - _Requirements: LFP-13_

- [x] 8.4 Compute and send multilinear evaluations

  - Compute {e_j = M̃_{*,j}(r)}_{j∈[m]} efficiently

  - Use O(n) Zq-additions for monomial matrices
  - _Requirements: LFP-13_

- [x] 9. Implement Π_mon verifier

- [ ] 9.1 Regenerate challenges and verify sumcheck
  - Regenerate c, β from transcript
  - Verify degree-3 sumcheck proof
  - _Requirements: LFP-13_


- [x] 9.2 Verify final check (Equation 12)

  - Compute eq(c, r) · Σ_j α^j · (ev_{e_j}(β)² - ev_{e_j}(β²))

  - Verify equals sumcheck claimed value
  - _Requirements: LFP-13_

- [x] 9.3 Return reduced instance

  - Create MonomialSetCheckInstance with (C_M, r, e)
  - _Requirements: LFP-13_

- [ ] 10. Implement Π_mon optimizations
- [x] 10.1 Implement batching for multiple matrices (Remark 4.2)


  - Combine all sumcheck statements via random linear combination

  - Run single sumcheck for all matrices
  - _Requirements: LFP-13_

- [x] 10.2 Implement efficient monomial commitment (Remark 4.3)

  - Optimize com(M) to use only Rq-additions (not multiplications)
  - Achieve O(nκm) Rq-additions = nκdm Zq-additions



  - _Requirements: LFP-13_

## Epic 4: Range Check Protocol

- [x] 11. Implement warm-up range check (Construction 4.3)

- [ ] 11.1 Create warm-up prover for τ ∈ (-d', d')^n
  - Run Π_mon for m_τ ∈ EXP(τ)
  - Send a = ⟨τ, tensor(r)⟩
  - _Requirements: LFP-3, LFP-13_


- [ ] 11.2 Create warm-up verifier
  - Verify monomial set check
  - Verify ct(ψ · b) = a using table polynomial
  - _Requirements: LFP-3, LFP-13_


- [ ] 12. Implement full range check Π_rgchk (Construction 4.4)
- [ ] 12.1 Create RangeCheckProver struct
  - Store witness f ∈ Rq^n, norm bound B = (d')^k

  - Store decomposition matrix D_f, monomial matrix M_f
  - Store double commitment C_{M_f} and helper commitment cm_{m_τ}
  - _Requirements: LFP-3_


- [ ] 12.2 Implement witness decomposition
  - Compute D_f = [D_{f,0}, ..., D_{f,k-1}] = G^(-1)_{d',k}(cf(f))
  - Ensure ||D_f||∞ < d'
  - Flatten to n×dk matrix

  - _Requirements: LFP-6_


- [ ] 12.3 Compute monomial matrix M_f ∈ EXP(D_f)
  - Apply exp function to each entry of D_f
  - Create MonomialMatrix with n×dk entries

  - _Requirements: LFP-2_

- [ ] 12.4 Compute split vector and helper monomials
  - Compute τ_D = split(com(M_f))

  - Compute m_τ ∈ EXP(τ_D)
  - _Requirements: LFP-12_

- [x] 12.5 Run batched Π_mon for M_f and m_τ

  - Batch monomial checks for both matrices
  - Extract challenge r and evaluations
  - _Requirements: LFP-13_

- [x] 12.6 Send coefficient and split evaluations

  - Compute v = cf(f)^⊤ tensor(r) ∈ C^d

  - Compute a = ⟨τ_D, tensor(r)⟩ ∈ C
  - Append to transcript
  - _Requirements: LFP-3_

- [x] 13. Implement Π_rgchk verifier

- [ ] 13.1 Verify batched monomial checks
  - Verify both M_f and m_τ monomial proofs
  - Extract challenge r and evaluations

  - _Requirements: LFP-13_

- [x] 13.2 Verify helper check ct(ψ · b) = a


  - Compute table polynomial ψ

  - Verify constant term extraction
  - _Requirements: LFP-3_

- [x] 13.3 Verify main range check (Equation 16)

  - Compute weighted sum u_0 + d'u_1 + ... + d'^(k-1)u_{k-1}
  - Verify ct(ψ · weighted_sum) = v
  - _Requirements: LFP-3_


- [ ] 13.4 Return reduced instance R_{dcom}
  - Create RangeCheckInstance with all evaluations
  - Compute v̂ = Σ_i v_i X^i
  - _Requirements: LFP-3_


## Epic 5: Commitment Transformation Protocol

- [x] 14. Implement Π_cm protocol structures

- [ ] 14.1 Create CommitmentTransformProver
  - Store witness f, split vector τ_D, helper monomials m_τ
  - Store monomial matrix M_f
  - Store commitments cm_f, C_{M_f}, cm_{m_τ}
  - _Requirements: LFP-12_


- [ ] 14.2 Create CommitmentTransformVerifier
  - Store commitments and norm bound
  - _Requirements: LFP-12_


- [ ] 14.3 Define proof and instance structures
  - CommitmentTransformProof with range proof, folded commitment, sumcheck proofs
  - CommitmentTransformInstance with folded commitment, challenge, evaluations
  - _Requirements: LFP-12_

- [ ] 15. Implement Π_cm prover (Construction 4.5)
- [ ] 15.1 Run Π_rgchk as subroutine
  - Execute range check protocol
  - Extract range instance with challenge r and evaluations e
  - _Requirements: LFP-3_

- [ ] 15.2 Receive folding challenges
  - Sample s ← S̄^3 for commitment folding
  - Sample s' ← S̄^dk for column folding
  - _Requirements: LFP-5_

- [ ] 15.3 Compute and send folded commitment
  - Compute h = M_f · s' (folded witness)
  - Compute com(h) = com(M_f)s'
  - Append to transcript
  - _Requirements: LFP-12_

- [ ] 15.4 Receive sumcheck challenges
  - Sample c^(0), c^(1) ← C^(log κ) × C^(log κ)
  - _Requirements: LFP-5_

- [ ] 15.5 Prepare evaluation claims (4 claims)
  - Verify [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
  - Compute u = ⟨e[3, 3+dk), s'⟩
  - Create 4 degree-2 sumcheck claims
  - _Requirements: LFP-7, LFP-8_

- [ ] 15.6 Prepare consistency claims (2 claims)
  - Compute t^(z) = tensor(c^(z)) ⊗ s' ⊗ (1, d', ..., d'^(ℓ-1)) ⊗ (1, X, ..., X^(d-1))
  - Verify ⟨tensor(c^(z)), pow(τ_D)s'⟩ = ⟨tensor(c^(z)), com(h)⟩ for z ∈ [2]
  - Create 2 degree-2 sumcheck claims
  - _Requirements: LFP-7, LFP-8, LFP-12_

- [ ] 15.7 Batch and run parallel sumchecks
  - Batch 6 claims into 1 via random linear combination
  - Run 2 parallel sumcheck protocols for soundness boosting
  - Reduce to evaluation claims at r_o ← (C × C)^(log n)
  - _Requirements: LFP-8_

- [x] 16. Implement Π_cm verifier



- [ ] 16.1 Verify range check
  - Run range check verifier
  - Extract range instance
  - _Requirements: LFP-3_


- [ ] 16.2 Regenerate challenges
  - Regenerate s, s', c^(0), c^(1) from transcript
  - Verify com(h) matches transcript

  - _Requirements: LFP-5_

- [ ] 16.3 Verify parallel sumchecks
  - Verify both sumcheck proofs independently
  - Ensure both reduce to same challenge r_o

  - Verify final evaluation claims
  - _Requirements: LFP-8_

- [x] 16.4 Compute folded commitment and evaluations



  - Compute cm_g = s_0·C_{M_f} + s_1·cm_{m_τ} + s_2·cm_f + com(h)
  - Compute v_o from sumcheck final values
  - Return CommitmentTransformInstance
  - _Requirements: LFP-12_


- [ ] 17. Implement Π_cm optimizations
- [ ] 17.1 Optimize sumcheck over Zq (Remark 4.6)
  - Decompose 6 Rq claims into 6d Zq claims
  - Compress to 1 claim via random linear combination
  - Use extension field F_q^t when |Zq| is small
  - _Requirements: LFP-8_




- [ ] 17.2 Implement communication optimization (Remark 4.7)
  - Compress e' = e[3, 3+dk) using split/pow technique
  - Send com(τ_e) and com(exp(τ_e)) instead of e'
  - Add consistency sumcheck claims
  - Achieve ≈ dk/(2κ) factor saving

  - _Requirements: LFP-12_

## Epic 6: Folding Protocol


- [ ] 18. Implement main folding protocol (L-to-2)
- [ ] 18.1 Create FoldingProver struct
  - Store L instances of R_{lin,B}
  - Store L witnesses

  - Store commitment key and norm bound
  - _Requirements: LFP-10_

- [ ] 18.2 Implement range check for all witnesses
  - Prove ||f_i||∞ < B for all i ∈ [L]

  - Use batched range check when possible

  - _Requirements: LFP-3_

- [ ] 18.3 Transform all commitments
  - Run Π_cm for each witness
  - Extract linear commitment instances

  - _Requirements: LFP-12_

- [ ] 18.4 Fold L linear instances to 1
  - Sample folding challenges α_i ← S̄ for i ∈ [L]
  - Compute cm_folded = Σ_i α_i · cm_i

  - Compute f_folded = Σ_i α_i · f_i
  - Verify ||f_folded||∞ < B² (norm squared due to folding)
  - _Requirements: LFP-10_

- [x] 19. Implement decomposition protocol

- [ ] 19.1 Create DecompositionProver struct
  - Store folded instance with norm B²
  - Store witness f with ||f||∞ < B²
  - Store base B
  - _Requirements: LFP-10_


- [ ] 19.2 Decompose witness into low and high parts
  - For each element: f_i = f_i,low + B · f_i,high
  - Ensure ||f_low||∞ < B and ||f_high||∞ < B
  - Use balanced decomposition for each coefficient
  - _Requirements: LFP-6_

- [ ] 19.3 Commit to decomposed witnesses
  - Compute cm_low = com(f_low)
  - Compute cm_high = com(f_high)
  - Append to transcript
  - _Requirements: LFP-9_

- [ ] 19.4 Prove consistency f = f_low + B · f_high
  - Sample challenge for multilinear evaluation
  - Compute evaluations of f, f_low, f_high
  - Verify eval_f = eval_low + B · eval_high
  - Create sumcheck proof for consistency
  - _Requirements: LFP-8_

- [ ] 19.5 Create output instances
  - Create R_{lin,B} instance for f_low
  - Create R_{lin,B} instance for f_high
  - Return 2 instances with norm bound B
  - _Requirements: LFP-10_

- [x] 20. Implement folding verifier


- [x] 20.1 Verify all range checks

  - Verify L range check proofs
  - _Requirements: LFP-3_


- [x] 20.2 Verify all commitment transformations

  - Verify L commitment transformation proofs
  - Extract linear instances
  - _Requirements: LFP-12_



- [ ] 20.3 Verify folding computation
  - Regenerate folding challenges
  - Verify cm_folded = Σ_i α_i · cm_i
  - _Requirements: LFP-10_

- [x] 20.4 Verify decomposition

  - Verify cm_low and cm_high commitments
  - Verify consistency proof
  - Verify output instances are valid R_{lin,B}
  - _Requirements: LFP-10_


## Epic 7: Neo Integration

- [ ] 21. Implement tensor-of-rings framework
- [ ] 21.1 Create TensorRingConfig struct
  - Store base field size q (64-bit prime)
  - Store embedding degree e such that q ≡ 1 + 2^e (mod 4^e)
  - Store ring degree d and extension degree t
  - Store security level λ
  - _Requirements: Neo integration_

- [ ] 21.2 Implement SmallFieldFolding
  - Compute embedding degree e from q and d
  - Compute extension degree t for F_q^t such that q^t ≥ 2^λ
  - Create challenge set of size q^e
  - Create sumcheck field F_q^t
  - _Requirements: Neo integration_

- [ ] 21.3 Integrate with Neo's NTT engine
  - Reuse Neo's optimized NTT implementation
  - Support NTT-based multiplication in cyclotomic rings
  - _Requirements: Neo integration_

- [ ] 21.4 Integrate with Neo's field arithmetic
  - Reuse Neo's field operations
  - Support extension field F_q^t arithmetic
  - _Requirements: Neo integration_

- [ ] 22. Implement NeoIntegration wrapper
- [ ] 22.1 Create NeoIntegration struct
  - Store references to Neo's NTT engine
  - Store references to Neo's field arithmetic
  - Store references to Neo's parallel executor
  - Store references to Neo's memory manager
  - _Requirements: Neo integration_

- [ ] 22.2 Implement integrate_latticefold_plus method
  - Create LatticeFoldPlusEngine with all components
  - Wire up cyclotomic ring with Neo's NTT
  - Wire up commitment schemes with Neo's optimizations
  - Configure tensor-of-rings for small fields
  - _Requirements: Neo integration_

- [ ] 23. Implement LatticeFoldPlusEngine
- [ ] 23.1 Create main engine struct
  - Combine all LatticeFold+ components
  - Integrate Neo optimizations
  - Support small field configuration
  - _Requirements: All previous requirements_

- [ ] 23.2 Implement high-level folding API
  - Provide fold() method for L-to-2 folding
  - Provide prove() and verify() methods
  - Handle transcript management
  - _Requirements: All previous requirements_

- [ ] 23.3 Implement IVC integration
  - Support incremental verifiable computation
  - Integrate with existing Neo IVC infrastructure
  - Provide accumulation interface
  - _Requirements: All previous requirements_

## Notes

- All tasks build incrementally with no orphaned code
- Each task references specific requirements from requirements document
- Implementation should be production-ready, not simplified
- No test or benchmark code in this phase
- Focus on correctness and completeness
- Integration with Neo is seamless throughout
