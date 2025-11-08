# Symphony Integration with Neo and LatticeFold+ - Requirements Document

## Introduction

This document specifies comprehensive requirements for integrating Symphony's scalable SNARKs framework with the existing Neo and LatticeFold+ implementations in the neo-lattice-zkvm project. Symphony introduces a novel high-arity folding scheme that avoids embedding hash functions in SNARK circuits, providing memory-efficient, parallelizable, streaming-friendly, and plausibly post-quantum secure proof systems.

## Glossary

- **Symphony**: A folding-based SNARK system that uses high-arity folding to compress multiple NP-complete statements without embedding Fiat-Shamir circuits
- **Neo**: A lattice-based folding scheme for CCS over small fields with pay-per-bit commitment costs
- **LatticeFold+**: An improved lattice-based folding protocol with faster prover, simpler verification, and shorter proofs
- **High-Arity Folding**: A folding scheme that compresses a large number (e.g., 1024) of statements in a single shot
- **Commit-and-Prove SNARK (CP-SNARK)**: A SNARK that proves knowledge of a witness satisfying an NP-relation and being a valid opening to instance commitments
- **R1CS**: Rank-1 Constraint System, an NP-complete relation using quadratic constraints
- **CCS**: Customizable Constraint System, a generalization of R1CS, Plonkish, and AIR
- **Ajtai Commitment**: A lattice-based binding commitment scheme based on Module-SIS assumption
- **Cyclotomic Ring**: A polynomial ring R := Z[X]/⟨X^d + 1⟩ where d is a power of 2
- **Rq**: The residual ring R/qR = Zq[X]/⟨X^d + 1⟩ for prime q
- **Module-SIS**: Module Short Integer Solution problem, the hardness assumption for Ajtai commitments
- **Monomial Embedding**: A technique encoding bounded integers as monomials X^f for range proofs
- **Random Projection**: A technique using structured matrices to reduce norm-checking complexity
- **Sumcheck Protocol**: An interactive proof protocol for verifying polynomial evaluations
- **Fiat-Shamir Transform**: A technique to make interactive protocols non-interactive using hash functions
- **Tensor-of-Rings**: A framework E := K ⊗_Fq Rq for interleaving sumcheck and folding operations
- **Reduction of Knowledge (RoK)**: A protocol reducing the task of checking one relation to checking another
- **Multilinear Extension (MLE)**: A unique multilinear polynomial extending a function over Boolean hypercube
- **Operator Norm**: For a ∈ R, ∥a∥_op := sup_{y∈R} ∥a·y∥_∞ / ∥y∥_∞
- **ℓ∞-Norm**: For f ∈ R, ∥f∥_∞ := max_i |f_i| where f = Σ f_i X^i
- **ℓ2-Norm**: For vector v, ∥v∥_2 := √(Σ v_i^2)
- **Binding Commitment**: A commitment scheme where it's computationally infeasible to find two different openings
- **Knowledge Soundness**: Property ensuring that if a prover convinces a verifier, a witness can be extracted
- **Completeness**: Property ensuring honest provers always convince the verifier
- **Succinctness**: Property where proof size and verification time are polylogarithmic in witness size


## Requirements

### Requirement 1: High-Arity Folding Core Infrastructure

**User Story:** As a zkVM developer, I want to implement Symphony's high-arity folding scheme so that I can compress 2^10 to 2^16 R1CS statements in a single folding operation without deep folding trees.

#### Acceptance Criteria

1. WHEN the System receives ℓ_np ≥ 2 committed R1CS statements over Rq, THE System SHALL reduce them to a single accumulated statement through high-arity folding
2. WHILE processing folding operations, THE System SHALL maintain witness norm bounds such that ∥folded_witness∥_2 ≤ ℓ_np · ∥S∥_op · B√(nd/ℓ_h) WHERE B is the input norm bound
3. THE System SHALL implement the three-step folding framework: (1) witness commitment using Ajtai scheme, (2) sumcheck reduction of R1CS to linear evaluation statements, (3) random linear combination using low-norm vector β ∈ S^ℓ_np
4. WHEN folding ℓ_np = 2^10 statements, THE System SHALL complete the operation with prover cost dominated by O(ℓ_np · n) Rq-multiplications for witness commitments
5. THE System SHALL support folding arity ℓ_np WHERE ℓ_np = poly(λ) AND ℓ_np satisfies B_rbnd/2 = B_bnd ≥ ℓ_np · ∥S∥_op · max(B·√(nd/ℓ_h), √n)

### Requirement 2: Lattice-Based Commitment Scheme Integration

**User Story:** As a cryptographic engineer, I want to integrate Ajtai commitments with Neo's pay-per-bit embedding so that commitment costs scale linearly with value bit-width while maintaining post-quantum security.

#### Acceptance Criteria

1. THE System SHALL implement Ajtai commitment CM = (Setup, Commit, RVfyOpen, VfyOpen) with commitment space C := Rq^κ WHERE κ = κ(λ)
2. WHEN committing to vector m ∈ Rq^n, THE System SHALL compute c := A·m WHERE A ∈ Rq^(κ×n) is the public MSIS matrix
3. THE System SHALL verify commitment openings by checking Af = s·c AND ∥f∥_2 < B_bnd AND s·m = f WHERE (f,s) is the opening
4. THE System SHALL provide relaxed opening verification checking Af = s·c AND ∥f∥_2 ≤ B_rbnd := 2B_bnd AND s·m = f
5. THE System SHALL ensure binding security under Module-SIS assumption MSIS_{q,κ,n,β_SIS} WHERE β_SIS = 4T·B_rbnd AND T = ∥S∥_op
6. WHEN committing to n-length vector of b-bit values, THE System SHALL require commitment cost proportional to n·b Rq-operations
7. THE System SHALL support fine-grained opening verification VfyOpen_{ℓ_h,B}(pp_cm, c, f) checking ∀(i,j) ∈ [n/ℓ_h] × [d]: ∥F_{i,j}∥_2 ≤ B WHERE F = cf(f)


### Requirement 3: Monomial Embedding Range Proof System

**User Story:** As a proof system developer, I want to implement Symphony's algebraic range proof using monomial embedding so that I can prove witness norm bounds without bit-decomposition commitments.

#### Acceptance Criteria

1. THE System SHALL define monomial set M := {0, 1, X, X^2, ..., X^(d-1)} ⊆ Rq
2. THE System SHALL define table lookup polynomial t(X) := Σ_{i∈[1,d/2)} i·(X^(-i) + X^i) ∈ Rq
3. WHEN proving f ∈ (-d/2, d/2), THE System SHALL commit to monomial vector g WHERE g_i = X^(f_i) for each i ∈ [n]
4. THE System SHALL verify range proof by checking ct(g_i · t(X)) = f_i for all i ∈ [n] WHERE ct(·) extracts constant term
5. THE System SHALL implement monomial check protocol Π_mon reducing relation R_mon to R_batchlin with single degree-3 sumcheck over K of size n
6. THE System SHALL compute monomial commitments with prover cost T_p^mon(k_g, n) = O(nk_g) K-additions plus O(n) K-operations
7. THE System SHALL verify monomial proofs with verifier cost T_v^mon(k_g, n) = O(k_g·d + log(n)) K-operations

### Requirement 4: Random Projection Approximate Range Proof

**User Story:** As a performance engineer, I want to implement random projection-based approximate range proofs so that I can achieve near-optimal complexity with polylogarithmic verifier time.

#### Acceptance Criteria

1. THE System SHALL implement random projection using structured matrix M_J := I_{n/ℓ_h} ⊗ J WHERE J ∈ {0,±1}^(λ_pj × ℓ_h) AND λ_pj = 256
2. WHEN checking norm of f ∈ Rq^n, THE System SHALL project to H := (I_{n/ℓ_h} ⊗ J) × cf(f) ∈ Z_q^(m×d) WHERE m = nλ_pj/ℓ_h
3. THE System SHALL decompose projected matrix H = H^(1) + d'·H^(2) + ... + d'^(k_g-1)·H^(k_g) WHERE ∥H^(i)∥_∞ ≤ d'/2 AND d' = d-2
4. THE System SHALL compute k_g as minimal integer satisfying B_{d,k_g} := (d'/2)·(1 + d' + ... + d'^(k_g-1)) ≥ 9.5B
5. THE System SHALL flatten each H^(i) to h^(i) := flt(H^(i)) AND compute monomial vectors g^(i) := Exp(h^(i)) ∈ M^n
6. THE System SHALL verify consistency by checking u^(i)·t(X) has first column u_{t1}^(i) = ⟨ts(s), v^(i)⟩ WHERE v^(i) = H^(i)⊤ ts(r)
7. THE System SHALL achieve completeness error ϵ ≈ nλ_pj·d/(ℓ_h·2^141) through union bound on random projection
8. THE System SHALL extract witnesses with relaxed norm bound B' = 16B_{d,k_g}/√30 with overwhelming probability


### Requirement 5: Hadamard Product Reduction Protocol

**User Story:** As a constraint system developer, I want to implement Hadamard product reduction so that I can linearize R1CS constraints through sumcheck protocols.

#### Acceptance Criteria

1. THE System SHALL reduce Hadamard relation R_had^aux checking (M_1 F) ◦ (M_2 F) = M_3 F to linear relation R_lin^aux
2. THE System SHALL run single degree-3 sumcheck protocol over K of size m for claim Σ_{b∈{0,1}^log m} Σ_{j=1}^d α^(j-1)·f_j(b) = 0
3. THE System SHALL define polynomial f_j(X) = eq(s,X)·(g_{1,j}(X)·g_{2,j}(X) - g_{3,j}(X)) WHERE g_{i,j} is MLE of M_i F_{*,j}
4. WHEN sumcheck reduces to evaluation claim, THE System SHALL send values U ∈ K^(3×d) WHERE U_{i,j} := g_{i,j}(r)
5. THE System SHALL verify by checking Σ_{j=1}^d α^(j-1)·eq(s,r)·(U_{1,j}·U_{2,j} - U_{3,j}) = e WHERE e is sumcheck output
6. THE System SHALL compute output evaluations v_i := Σ_{j=1}^d (X^(j-1))·U_{i,j} ∈ E for i ∈ [3] using tensor-of-rings multiplication
7. THE System SHALL achieve prover complexity T_p^had(m) = 3d inner products between Z_q^m and K^m plus cost of computing (M_i F)_{i=1}^3
8. THE System SHALL achieve verifier complexity T_v^had(m) = O(d + log(m)) K-operations

### Requirement 6: Generalized Committed R1CS Relation

**User Story:** As a zkVM architect, I want to support generalized committed R1CS relations so that I can batch-prove d R1CS statements over Z_q with low-norm witnesses.

#### Acceptance Criteria

1. THE System SHALL define relation R_gr1cs^aux with instance x = (c ∈ C, X_in ∈ Z_q^(n_in×d)) AND witness w = W ∈ Z_q^(n_w×d)
2. THE System SHALL construct witness matrix F^⊤ := [X_in^⊤, W^⊤] ∈ Z_q^(d×n) WHERE n = n_in + n_w
3. THE System SHALL verify Hadamard product constraint (M_1 × F) ◦ (M_2 × F) = M_3 × F for R1CS matrices (M_i ∈ Z_q^(m×n))_{i=1}^3
4. THE System SHALL verify commitment opening VfyOpen_{ℓ_h,B}(pp_cm, c, cf^(-1)(F)) = 1 ensuring norm bounds
5. WHEN handling standard R1CS with arbitrary witnesses, THE System SHALL decompose using base b with k_cs := 1 + ⌊log_b(q)⌋
6. THE System SHALL define converted matrices M_i := M̄_i ⊗ [1, b, ..., b^(k_cs-1)] ∈ Z_q^(m×n) WHERE n := n̄·k_cs
7. THE System SHALL set converted instance X_in := [decomp_{b,k_cs}(x_in^(1)) || ... || decomp_{b,k_cs}(x_in^(d))] ∈ Z_q^(n_in×d)
8. THE System SHALL set converted witness W := [decomp_{b,k_cs}(w^(1)) || ... || decomp_{b,k_cs}(w^(d))] ∈ Z_q^(n_w×d)
9. THE System SHALL use norm bound B = 0.5b√ℓ_h ensuring each entry of F is bounded by b/2


### Requirement 7: Single-Instance Reduction Protocol

**User Story:** As a protocol designer, I want to implement the single-instance reduction Π_gr1cs so that I can reduce one generalized R1CS statement to linear and batch-linear relations.

#### Acceptance Criteria

1. THE System SHALL implement protocol Π_gr1cs reducing R_gr1cs^aux to R_lin^auxcs × R_batchlin
2. THE System SHALL interleave approximate range proof Π_rg with Hadamard proof Π_had sharing randomness
3. WHEN executing Π_gr1cs, THE System SHALL send projection matrix J ← χ^(λ_pj × ℓ_h) AND challenges s' ← K^log(m), α ← K
4. THE System SHALL send k_g helper commitments (c^(i) := A×g^(i))_{i=1}^{k_g} for monomial vectors
5. THE System SHALL run two parallel sumcheck protocols: one for Hadamard claim (log(m) rounds) and one for monomial check (log(n) rounds)
6. THE System SHALL share sumcheck challenge (r̄ ∈ K^log(m_J), s̄ ∈ K^log(m/m_J), s ∈ K^log(n/m)) between protocols
7. THE System SHALL output x_o = (x_*, x_bat) WHERE x_* = (c, cf^(-1)(X_in), r, v := (v', v)) AND x_bat contains batch-linear instance
8. THE System SHALL achieve completeness error ϵ matching Theorem 3.1 of Symphony paper
9. THE System SHALL extract witnesses with relaxed norm bound B' = 16B_{d,k_g}/√30 under knowledge soundness

### Requirement 8: Multi-Instance High-Arity Folding Protocol

**User Story:** As a scalability engineer, I want to implement multi-instance folding Π_fold so that I can compress ℓ_np R1CS statements into two efficiently provable statements.

#### Acceptance Criteria

1. THE System SHALL implement protocol Π_fold taking input x := {x_ℓ = (c_ℓ ∈ C, X_ℓ^in ∈ Z_q^(n_in×d))}_{ℓ=1}^{ℓ_np}
2. THE System SHALL execute ℓ_np parallel instances of Π_gr1cs with shared randomness J, s', α
3. THE System SHALL merge 2ℓ_np sumcheck claims into 2 claims using random linear combination with powers of α
4. THE System SHALL define first merged claim as Σ_{b∈{0,1}^log m} Σ_{ℓ=1}^{ℓ_np} Σ_{j=1}^d α^((ℓ-1)·d+j-1)·f_{ℓ,j}(b) = 0
5. THE System SHALL verify consistency of evaluations (v_ℓ)_{ℓ=1}^{ℓ_np} and (u_ℓ^(i))_{i∈[k_g],ℓ∈[ℓ_np]} with merged sumcheck outputs e_*, u_*
6. WHEN receiving folding challenge β ← S^{ℓ_np}, THE System SHALL compute folded commitment c_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·c_ℓ
7. THE System SHALL compute folded witness f_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ AND monomial witnesses g^(i) := Σ_{ℓ=1}^{ℓ_np} β_ℓ·g_{i,ℓ}
8. THE System SHALL ensure folded witness norms satisfy ∥f_*∥_2 ≤ ℓ_np·∥S∥_op·B√(nd/ℓ_h) AND ∥g^(i)∥_2 ≤ ℓ_np·∥S∥_op·√n
9. THE System SHALL achieve prover complexity T_p^fold(ℓ_np, k_g, n, m) = nℓ_np S-Rq multiplications + k_g·nℓ_np S-M multiplications + ℓ_np·T_p^gr1cs
10. THE System SHALL achieve verifier complexity T_v^fold(ℓ_np, n_in, k_g, n, m) = (1+k_g)ℓ_np S-C multiplications + ℓ_np·n_in S-Rq multiplications + (4+k_g)tℓ_np S-Rq multiplications + ℓ_np·T_v^gr1cs


### Requirement 9: Fiat-Shamir Transform for Folding

**User Story:** As a non-interactive proof developer, I want to implement Fiat-Shamir transform for folding protocols so that I can convert interactive folding schemes to non-interactive arguments.

#### Acceptance Criteria

1. THE System SHALL implement Commit-and-Open transformation CM[Π_cm, Π_rok] replacing each prover message m_i with commitment c_{fs,i} := Π_cm.Commit(pp_cm, m_i)
2. THE System SHALL send opening messages (m_i)_{i=1}^{rnd} at protocol end for verification
3. THE System SHALL verify that (m_i)_{i=1}^{rnd} are valid openings to commitments (c_{fs,i})_{i=1}^{rnd}
4. THE System SHALL implement Fiat-Shamir transform FSH[Π_cm, Π_rok] deriving challenges from hash function H modeled as random oracle
5. THE System SHALL initialize transcript with instance x AND derive first challenge r_1 := H(x)
6. FOR each round i ∈ [rnd], THE System SHALL append (r_i, c_{fs,i}) to transcript AND derive r_{i+1} from updated transcript
7. THE System SHALL use Merkle-Damgård framework to fix hash function input length in practice
8. THE System SHALL ensure straightline extractability of commitment scheme Π_cm for security proof
9. THE System SHALL achieve knowledge soundness with error increased by factor Q (number of random oracle queries) compared to interactive version
10. THE System SHALL support security parameter adjustment by enlarging extension field K = F_{q^t} and folding challenge set S

### Requirement 10: Commit-and-Prove SNARK Compiler

**User Story:** As a SNARK system architect, I want to implement the commit-and-prove compiler so that I can convert high-arity folding into succinct arguments without embedding Fiat-Shamir circuits.

#### Acceptance Criteria

1. THE System SHALL define CP-SNARK relation R_cp with instance x_cp := (x, (r_i)_{i=1}^{rnd+1}, (c_{fs,i})_{i=1}^{rnd}, x_o)
2. THE System SHALL define CP-SNARK witness w := (w_cp := (m_i)_{i=1}^{rnd}, w_e) checking x_o := f(x, (m_i)_{i=1}^{rnd}, (r_i)_{i=1}^{rnd+1})
3. THE System SHALL verify c_{fs,i} = Π_cm.Commit(pp_cm, m_i) for all i ∈ [rnd] within CP-SNARK relation
4. THE System SHALL use Merkle commitments for hash-based CP-SNARKs OR KZG commitments for pairing-based CP-SNARKs
5. THE System SHALL compress folding proofs from >30MB to log(n) commitments under 1KB for typical statement sizes
6. THE System SHALL ensure CP-SNARK statement embeds no Fiat-Shamir circuits AND no commitment opening checks
7. THE System SHALL prove only O(ℓ_np) multiplications over Rq for combining Ajtai commitments within CP-SNARK
8. WHEN instance x is large, THE System SHALL replace x with vector commitment c_{fs,0} := Π_cm.Commit(pp_cm, x) for efficiency
9. THE System SHALL verify consistency between public inputs (X_ℓ^in)_ℓ and c_{fs,0} outside CP-SNARK circuit
10. THE System SHALL support single CP-SNARK proof proving both (x_cp, (w_cp, w_e)) ∈ R_cp AND (x_o, w_o) ∈ R_o for smaller proof sizes


### Requirement 11: SNARK Construction from High-Arity Folding

**User Story:** As a proof system implementer, I want to construct complete SNARK system from high-arity folding so that I can batch-prove many R1CS statements with polylogarithmic proof size and verification.

#### Acceptance Criteria

1. THE System SHALL implement SNARK Π_* = (Setup, Prove, Vf) for relation R with relaxed relation R'
2. THE System SHALL execute Setup generating (pk_*, vk_*) WHERE pk_* := (pp_cm, pk_cp, pk) AND vk_* := (pp_cm, vk_cp, vk)
3. THE System SHALL execute Prove^H(pk_*, R, x, w) computing:
   - Folding proof via FSH[Π_cm, Π_fold] obtaining (x_o, w_o)
   - CP-SNARK proof π_cp for folding verification
   - SNARK proof π for reduced statement (x_o, w_o) ∈ R_o
4. THE System SHALL output proof π_* := (π_cp, π, (c_{fs,i})_{i=1}^{rnd}, x_o)
5. THE System SHALL execute Vf^H(vk_*, R, x, π_*) performing:
   - Recompute challenges (r_i)_{i=1}^{rnd+1} from x, (c_{fs,i})_{i=1}^{rnd}, H
   - Verify CP-SNARK proof π_cp against x_cp = (x, (r_i)_{i=1}^{rnd+1}, (c_{fs,i})_{i=1}^{rnd}, x_o)
   - Verify SNARK proof π against x_o
6. THE System SHALL achieve succinctness with proof size poly(λ, log(|w|)) AND verifier time poly(λ, |x|, log(|w|))
7. THE System SHALL ensure completeness with overwhelming probability 1 - negl(λ) for honest provers
8. THE System SHALL ensure knowledge soundness extracting witness w for relaxed relation R' with probability ϵ_{P_*} - negl(λ)
9. THE System SHALL support ℓ_np = 2^10 to 2^16 R1CS statements over Rq = Z_q[X]/⟨X^64 + 1⟩
10. THE System SHALL achieve proof size under 200KB (or under 50KB without post-quantum security requirement)
11. THE System SHALL achieve verification time in tens of milliseconds
12. THE System SHALL dominate prover cost with approximately 3·2^32 multiplications between arbitrary and low-norm elements over Rq

### Requirement 12: Tensor-of-Rings Framework Integration

**User Story:** As a mathematical framework developer, I want to integrate tensor-of-rings framework so that I can efficiently interleave sumcheck protocols over extension fields with folding operations over cyclotomic rings.

#### Acceptance Criteria

1. THE System SHALL define tensor E := K ⊗_{F_q} Rq WHERE K = F_{q^t} is extension field AND Rq = Z_q[X]/⟨X^d + 1⟩
2. THE System SHALL represent element e ∈ E as matrix over Z_q^{t×d}
3. THE System SHALL interpret e ∈ E as K-vector space element [e_1, ..., e_d] ∈ K^{1×d} for scalar multiplication with a ∈ K
4. THE System SHALL interpret e ∈ E as Rq-module element (e'_1, ..., e'_t) ∈ Rq^t for scalar multiplication with b ∈ Rq
5. THE System SHALL define multiplication a·b ∈ E for a ∈ K, b ∈ Rq as matrix cf(a) ⊗ cf(b)^⊤ ∈ Z_q^{t×d}
6. THE System SHALL lift b ∈ Rq to e_b := [b, 0, ..., 0]^⊤ ∈ E for K-scalar multiplication interpretation
7. THE System SHALL lift a ∈ K to e_a := [a, 0, ..., 0] ∈ E for Rq-scalar multiplication interpretation
8. THE System SHALL use K-vector space interpretation for running sumcheck protocols over K
9. THE System SHALL use Rq-module interpretation for folding witnesses via low-norm challenges over S ⊆ Rq
10. WHEN q ≡ 1 + 2^e (mod 4^e) for e | d, THE System SHALL utilize isomorphism Rq ≅ F_{q^e}^{d/e} via Number Theoretic Transform


### Requirement 13: Sumcheck Protocol Implementation

**User Story:** As a protocol implementer, I want to implement sumcheck protocols over extension fields so that I can reduce polynomial evaluation claims to linear evaluation statements.

#### Acceptance Criteria

1. THE System SHALL implement sumcheck protocol as reduction of knowledge from R_sum to R_eval
2. THE System SHALL define R_sum checking Σ_{b∈{0,1}^log(n)} g(b) = v for polynomial g(X) ∈ K[X_1, ..., X_log(n)] of degree D
3. THE System SHALL define R_eval checking g(r) = v for evaluation point r ∈ K^log(n)
4. THE System SHALL achieve linear-time prover AND polylogarithmic verifier complexity
5. THE System SHALL achieve knowledge error ϵ_sum := D·log(n)/|K| + ϵ_bind WHERE ϵ_bind is commitment binding error
6. WHEN g(X) = h(f_1(X), ..., f_k(X)) for multilinear f_i, THE System SHALL reduce to checking ⟨f_i, ts(r)⟩ = u_i AND h(u_1, ..., u_k) = v
7. THE System SHALL define tensor ts(r) := (eq_b(r))_{b∈{0,1}^k} ∈ K^{2^k} WHERE eq_b(r) := Π_{i∈[k]} (1-b_i)(1-r_i) + b_i·r_i
8. THE System SHALL batch k sumcheck statements for g_1, ..., g_k by reducing to single statement for Σ_{i=1}^k g_i·α^{i-1} WHERE α ← K
9. THE System SHALL run sumcheck over extension field F_{q^2} for 64-bit prime q to achieve 128-bit security
10. THE System SHALL ensure sumcheck cost is insignificant compared to Ajtai commitment cost when d ≫ 2

### Requirement 14: Memory-Efficient Streaming Prover

**User Story:** As a resource-constrained prover, I want to implement memory-efficient streaming prover so that I can generate proofs with memory roughly equal to single witness size.

#### Acceptance Criteria

1. THE System SHALL implement streaming prover algorithm requiring memory O(n) WHERE n is single witness size
2. THE System SHALL execute prover in 2 + log log(n) passes over input data
3. WHEN starting proof generation, THE System SHALL compute ℓ_np input commitments in streaming fashion
4. WHEN receiving random combiner α, THE System SHALL execute sumcheck using algorithm from Section 4 of [Baw+25]
5. FOR each of log log(n) passes, THE System SHALL compute sumcheck evaluation table by linearly combining tables of each instance
6. THE System SHALL achieve sumcheck prover time O(n·log log(n)) plus cost of combining ℓ_np evaluation tables
7. WHEN deriving folding challenge β, THE System SHALL stream input witnesses again AND combine into single folded witness
8. THE System SHALL support starting proof generation as soon as some proven statements are known (streaming-friendly)
9. THE System SHALL enable parallelization of witness commitment computations across multiple cores
10. THE System SHALL avoid loading all ℓ_np witnesses into memory simultaneously


### Requirement 15: Two-Layer Folding Extension

**User Story:** As a scalability architect, I want to implement two-layer folding so that I can handle extremely large numbers of statements (>2^40 constraints) without recursive circuits.

#### Acceptance Criteria

1. THE System SHALL support folding depth two for handling more than 2^40 total constraints
2. WHEN completing first layer folding, THE System SHALL obtain reduced statement (x_o, w_o) ∈ R_o AND first CP-SNARK proof
3. THE System SHALL split reduced statement (x_o, w_o) into multiple uniform NP statements
4. THE System SHALL apply high-arity folding scheme again to second layer statements
5. THE System SHALL generate second CP-SNARK proof for second layer folding verification
6. THE System SHALL output final proof consisting of two CP-SNARK proofs plus one SNARK proof for final reduced statement
7. THE System SHALL avoid embedding Fiat-Shamir heuristics in circuits at both folding layers
8. WHEN Ajtai commitment parameter satisfies structural property, THE System SHALL use splitting technique from Section 8 of Symphony paper
9. FOR general cases, THE System SHALL support Mangrove's uniformization technique for statement splitting
10. THE System SHALL maintain post-quantum security guarantees across both folding layers

### Requirement 16: Challenge Set and Security Parameters

**User Story:** As a security engineer, I want to configure challenge sets and security parameters so that I can achieve desired security levels while optimizing performance.

#### Acceptance Criteria

1. THE System SHALL define folding challenge set S ⊆ Rq with operator norm ∥S∥_op ≤ 15
2. THE System SHALL ensure elements in S have coefficients in {0, ±1, ±2} for Rq := Z_q[X]/⟨X^64 + 1⟩
3. THE System SHALL ensure elements in S - S are invertible over Rq by Corollary 1.2 of [LS18]
4. THE System SHALL set challenge set size |S| = ω(poly(λ)) for security parameter λ
5. WHEN using 64-bit field, THE System SHALL use extension field degree t = 2 for 128-bit security
6. THE System SHALL set Module-SIS parameter β_SIS such that B_rbnd := β_SIS/(4T) WHERE T = ∥S∥_op
7. THE System SHALL ensure norm bound constraint B_rbnd/2 = B_bnd ≥ ℓ_np·∥S∥_op·max(B√(nd/ℓ_h), √n)
8. THE System SHALL support Goldilocks prime q = 2^64 - 2^32 + 1 for efficient arithmetic
9. THE System SHALL support Mersenne prime q = 2^61 - 1 as alternative field choice
10. THE System SHALL configure cyclotomic ring dimension d as power of 2 (typically d = 64 or d = 128)
11. THE System SHALL set projection parameter λ_pj = 256 for random projection security
12. THE System SHALL ensure random projection preserves ℓ_2-norm with probability ≥ 1 - 2^{-128}


### Requirement 17: Neo Pay-Per-Bit Commitment Integration

**User Story:** As a commitment scheme developer, I want to integrate Neo's pay-per-bit commitment scheme so that commitment costs scale with value bit-width for small field elements.

#### Acceptance Criteria

1. THE System SHALL implement Neo's matrix commitment scheme committing to vectors over small prime field F_q
2. THE System SHALL transform input vector into matrix AND commit to that matrix using Ajtai commitment
3. THE System SHALL provide linear homomorphism for folding multilinear evaluation claims
4. WHEN committing to vector of bits, THE System SHALL achieve 32× cost reduction compared to committing to 32-bit values
5. THE System SHALL support CCS constraint systems defined natively over small prime field (not cyclotomic rings)
6. THE System SHALL run single invocation of sumcheck protocol over extension of small prime field
7. THE System SHALL avoid packing multiple constraints over prime field into single constraint over ring
8. THE System SHALL support Goldilocks field (q = 2^64 - 2^32 + 1) AND Mersenne 61 field (q = 2^61 - 1)
9. THE System SHALL achieve folding challenge set size q^{d/e} WHERE Rq ≅ F_{q^e}^{d/e}
10. THE System SHALL ensure commitment scheme provides required linear homomorphism: For commitments {(C_i, r, y_i)}_{i∈[β]}, THE System SHALL fold to single commitment (C, r, y) WHERE C = Σ_{i∈[β]} ρ_i·C_i AND y = Σ_{i∈[β]} ρ_i·y_i for random ρ ∈ S^β

### Requirement 18: LatticeFold+ Double Commitment Optimization

**User Story:** As a proof size optimizer, I want to integrate LatticeFold+ double commitment technique so that I can compress multiple commitments into single commitment.

#### Acceptance Criteria

1. THE System SHALL implement double commitment dcom(M) for matrix M := [m^(0), ..., m^(d-1)] ∈ Rq^{n×d}
2. THE System SHALL compute vector of commitments c := (com(m^0), ..., com(m^{d-1})) ∈ Rq^{κ×d}
3. THE System SHALL decompose c to reduce norm AND commit to decomposition using Ajtai commitment
4. THE System SHALL ensure dcom(M) ∈ Rq^κ is short (single commitment instead of d commitments)
5. THE System SHALL implement commitment transformation technique converting double commitment statements to linear commitment statements
6. THE System SHALL use sumchecks to ensure consistency between double commitment of M and linear commitment to transformed M
7. THE System SHALL apply double commitments to range proofs avoiding d separate monomial commitments
8. THE System SHALL achieve proof size O_λ(κd + log n) bits compared to O_λ(κd·log B + d·log n) in LatticeFold
9. THE System SHALL reduce verifier circuit size by eliminating L·log_2(B) decomposed commitments from Fiat-Shamir hash
10. THE System SHALL achieve prover speedup of Ω(log(B)) times compared to LatticeFold through commitment elimination


### Requirement 19: Coordinate-Wise Special Soundness Extraction

**User Story:** As a security proof developer, I want to implement coordinate-wise special soundness extraction so that I can extract witnesses from successful provers.

#### Acceptance Criteria

1. THE System SHALL implement extractor E^A based on Lemma 7.1 of [FMN24]
2. THE System SHALL define challenge space U := S^ℓ_np AND output space Y for predicate Ψ: U × Y → {0,1}
3. FOR vectors a, b ∈ S^ℓ_np, THE System SHALL define a ≡_i b IFF a_i ≠ b_i AND a_j = b_j for all j ∈ [ℓ_np] \ {i}
4. WHEN running extractor E^A(u_0, y_0) on input u_0 ← U, y_0 ← A(u_0), THE System SHALL output ℓ_np + 1 pairs (u_i, y_i)_{i=0}^{ℓ_np}
5. THE System SHALL ensure Ψ(u_i, y_i) = 1 for all i ∈ [0, ℓ_np] AND u_i ≡_i u_0 for all i ∈ [ℓ_np]
6. THE System SHALL achieve extraction probability at least ϵ_Ψ(A) - ℓ_np/|S| WHERE ϵ_Ψ(A) := Pr_{u←U}[Ψ(u, A(u)) = 1]
7. THE System SHALL call adversary A for 1 + ℓ_np times in expectation
8. THE System SHALL extract witness f^ℓ := (f^{*,ℓ} - f^{*,0})/(u_ℓ[ℓ] - u_0[ℓ]) ∈ Rq^n for each ℓ ∈ [ℓ_np]
9. THE System SHALL ensure extracted f^ℓ is bound to commitment c_ℓ with relaxed opening (f^{*,ℓ} - f^{*,0}, u_ℓ[ℓ] - u_0[ℓ])
10. THE System SHALL verify extracted witnesses satisfy relaxed relation R̂_lin^auxcs × R̂_batchlin

### Requirement 20: Random Oracle Model Security

**User Story:** As a cryptographic theorist, I want to prove security in random oracle model so that I can provide rigorous security guarantees for the SNARK system.

#### Acceptance Criteria

1. THE System SHALL model hash function H as random oracle in security proofs
2. THE System SHALL prove knowledge soundness of FSH[Π_cm, Π_fold] in random oracle model
3. THE System SHALL account for Q random oracle queries in knowledge error bound
4. THE System SHALL achieve knowledge error ϵ_{P_*} - ℓ_np/|S| - ℓ_np·negl(λ) for adversary with success probability ϵ_{P_*}
5. THE System SHALL use straightline extractability of commitment scheme Π_cm in security reduction
6. THE System SHALL adapt coordinate-wise special soundness to random oracle model per Section 8.2 and Figure 13 of [FMN24]
7. THE System SHALL ensure committed sumcheck protocols remain sound after Fiat-Shamir transform per [Can+19; CMS19]
8. THE System SHALL prove SNARK completeness with overwhelming probability 1 - negl(λ)
9. THE System SHALL prove SNARK knowledge soundness extracting witness for relaxed relation R' with probability ϵ_{P_*} - negl(λ)
10. THE System SHALL avoid heuristic security assumptions by keeping hash function instantiation outside proven statements


### Requirement 21: Concrete Instantiation and Performance

**User Story:** As a performance engineer, I want to instantiate Symphony with concrete parameters so that I can achieve practical performance for real-world applications.

#### Acceptance Criteria

1. THE System SHALL support folding 2^16 standard R1CS statements over 64-bit field, each with over 2^16 constraints
2. THE System SHALL generate proofs under 200KB with post-quantum security OR under 50KB without post-quantum requirement
3. THE System SHALL achieve verification time in tens of milliseconds
4. THE System SHALL dominate prover cost with approximately 3·2^32 multiplications between arbitrary and low-norm Rq elements
5. WHEN witnesses are 8-bit signed integers, THE System SHALL achieve additional 8× speedup
6. THE System SHALL use Rq := Z_q[X]/⟨X^64 + 1⟩ for cyclotomic ring with d = 64
7. THE System SHALL use extension field K = F_{q^2} for 128-bit security with 64-bit prime q
8. THE System SHALL set folding arity ℓ_np = 2^10 for standard configuration
9. THE System SHALL support higher arity up to ℓ_np = 2^14 for batching over million statements
10. THE System SHALL achieve prover time comparable to or faster than HyperNova while providing post-quantum security
11. THE System SHALL use LaBRADOR challenge set with ∥S∥_op ≤ 15 for Rq = Z_q[X]/⟨X^64 + 1⟩
12. THE System SHALL set Module-SIS parameter for 128-bit post-quantum security using lattice estimator

### Requirement 22: Application Integration

**User Story:** As an application developer, I want to integrate Symphony into zkVM, proof of learning, and aggregate signature applications so that I can leverage scalable post-quantum proof systems.

#### Acceptance Criteria

1. THE System SHALL support zkVM applications proving RISC-V instruction execution
2. WHEN proving zkVM execution, THE System SHALL decompose computation into uniform R1CS statements per instruction batch
3. THE System SHALL support proof of machine learning applications verifying neural network inference
4. THE System SHALL support post-quantum aggregate signature schemes using batch proof verification
5. THE System SHALL support video editing provenance applications proving content authenticity
6. THE System SHALL enable incremental proof generation as computation progresses (IVC-style)
7. THE System SHALL support proof-carrying data (PCD) for distributed computation verification
8. THE System SHALL provide APIs for application-specific constraint system generation
9. THE System SHALL support custom witness preprocessing for application-specific optimizations
10. THE System SHALL enable proof composition across different application domains


### Requirement 23: Integration with Existing Neo Implementation

**User Story:** As a system integrator, I want to integrate Symphony with existing Neo implementation so that I can leverage Neo's CCS folding and pay-per-bit commitments.

#### Acceptance Criteria

1. THE System SHALL reuse Neo's folding-friendly lattice-based commitment scheme from Section 3 of Neo paper
2. THE System SHALL integrate Neo's matrix commitment scheme providing pay-per-bit costs
3. THE System SHALL utilize Neo's linear homomorphism for folding multilinear evaluation claims
4. THE System SHALL adopt Neo's CCS reduction protocol Π_CCS from Section 4.4
5. THE System SHALL integrate Neo's random linear combination reduction Π_RLC from Section 4.5
6. THE System SHALL use Neo's decomposition reduction Π_DEC from Section 4.6
7. THE System SHALL leverage Neo's challenge set design from Section 3.4 ensuring invertibility
8. THE System SHALL integrate Neo's concrete parameters for Goldilocks and Mersenne 61 fields from Section 6
9. THE System SHALL reuse Neo's security analysis framework from Section 5
10. THE System SHALL maintain compatibility with Neo's IVC/PCD construction with proof compression

### Requirement 24: Integration with Existing LatticeFold+ Implementation

**User Story:** As a system integrator, I want to integrate Symphony with existing LatticeFold+ implementation so that I can leverage LatticeFold+'s efficient range proofs and commitment transformations.

#### Acceptance Criteria

1. THE System SHALL integrate LatticeFold+'s monomial embedding range proof from Section 4.3
2. THE System SHALL utilize LatticeFold+'s table polynomial t(X) := Σ_{i∈[1,d/2)} i·(X^{-i} + X^i) ∈ Rq
3. THE System SHALL adopt LatticeFold+'s monomial set check protocol from Section 4.2
4. THE System SHALL integrate LatticeFold+'s commitment transformation technique from Section 4.4
5. THE System SHALL use LatticeFold+'s double commitment optimization for proof size reduction
6. THE System SHALL leverage LatticeFold+'s generalized committed linear relations from Section 3
7. THE System SHALL integrate LatticeFold+'s folding protocol from Section 5.1
8. THE System SHALL adopt LatticeFold+'s decomposition technique from Section 5.2
9. THE System SHALL utilize LatticeFold+'s efficiency estimates from Section 5.3
10. THE System SHALL maintain compatibility with LatticeFold+'s support for small moduli from Appendix B


### Requirement 25: Mathematical Correctness and Completeness

**User Story:** As a verification engineer, I want to ensure mathematical correctness of all protocols so that the implementation matches the theoretical specifications exactly.

#### Acceptance Criteria

1. THE System SHALL implement all mathematical formulations from Symphony paper Sections 2-8 without simplification or omission
2. THE System SHALL verify Lemma 2.1 (monomial embedding): For a ∈ (-d/2, d/2), b ∈ Exp(a), ct(b·t(X)) = a
3. THE System SHALL verify Lemma 2.2 (random projection): Pr[|⟨u,v⟩| > 9.5∥v∥_2] ≲ 2^{-141} for u ← χ^n
4. THE System SHALL verify Lemma 2.3 (coordinate-wise soundness): Extraction probability ≥ ϵ_Ψ(A) - ℓ/|S|
5. THE System SHALL implement Proposition 3.1 (Hadamard reduction): Π_had is RoK from R_had^aux to R_lin^aux
6. THE System SHALL implement Theorem 3.1 (range proof): Π_rg is RoK with completeness error ϵ ≈ nλ_pj·d/(ℓ_h·2^141)
7. THE System SHALL implement Lemma 4.1 (single-instance reduction): Π_gr1cs is RoK from R_gr1cs^aux to R_lin^auxcs × R_batchlin
8. THE System SHALL implement Theorem 4.1 (multi-instance folding): Π_fold is RoK from (R_gr1cs^aux)^{ℓ_np} to R_lin^auxcs × R_batchlin
9. THE System SHALL implement Theorem 5.1 (Fiat-Shamir security): FSH[Π_cm, Π_rok] maintains RoK properties in ROM
10. THE System SHALL implement Theorem 6.1 (SNARK construction): Construction 6.1 is SNARK with succinctness, completeness, and knowledge soundness
11. THE System SHALL verify all norm bounds, probability bounds, and complexity bounds match paper specifications
12. THE System SHALL implement all protocols (Figures 1-4) exactly as specified without algorithmic modifications

### Requirement 26: Testing and Validation Framework

**User Story:** As a quality assurance engineer, I want comprehensive testing framework so that I can validate correctness of all components.

#### Acceptance Criteria

1. THE System SHALL provide unit tests for all cryptographic primitives (commitments, hash functions, field operations)
2. THE System SHALL provide integration tests for all reduction of knowledge protocols
3. THE System SHALL validate monomial embedding correctness for all values in (-d/2, d/2)
4. THE System SHALL validate random projection norm preservation with statistical tests
5. THE System SHALL test sumcheck protocol correctness for polynomials of various degrees
6. THE System SHALL validate folding correctness by checking extracted witnesses satisfy original relations
7. THE System SHALL test Fiat-Shamir transform with multiple hash function instantiations
8. THE System SHALL validate CP-SNARK compiler correctness with various commitment schemes
9. THE System SHALL perform end-to-end tests proving and verifying R1CS statements of various sizes
10. THE System SHALL benchmark performance against theoretical complexity bounds
11. THE System SHALL test security properties with malicious prover simulations
12. THE System SHALL validate compatibility between Neo, LatticeFold+, and Symphony components


### Requirement 27: Error Handling and Edge Cases

**User Story:** As a robustness engineer, I want comprehensive error handling so that the system gracefully handles edge cases and invalid inputs.

#### Acceptance Criteria

1. WHEN witness norm exceeds bound B, THE System SHALL reject the proof with clear error message
2. WHEN random projection fails norm check, THE System SHALL abort prover with probability ≈ 2^{-128}
3. WHEN sumcheck verification fails, THE System SHALL reject proof and indicate which round failed
4. WHEN commitment opening verification fails, THE System SHALL reject with binding violation error
5. WHEN challenge sampling produces non-invertible element, THE System SHALL resample from S - S
6. WHEN folding arity exceeds norm bound constraint, THE System SHALL reject configuration with parameter error
7. WHEN extension field degree insufficient for security, THE System SHALL warn and suggest larger t
8. WHEN Module-SIS parameter insufficient, THE System SHALL reject setup with security parameter error
9. WHEN input R1CS matrices have incompatible dimensions, THE System SHALL reject with dimension mismatch error
10. WHEN memory allocation fails during streaming proof, THE System SHALL gracefully degrade or abort with resource error

### Requirement 28: Documentation and Specification Compliance

**User Story:** As a documentation maintainer, I want comprehensive documentation so that developers can understand and extend the implementation.

#### Acceptance Criteria

1. THE System SHALL document all mathematical notation matching Symphony, Neo, and LatticeFold+ papers
2. THE System SHALL provide inline comments explaining each protocol step with paper section references
3. THE System SHALL document all security parameters with justification from lattice estimator
4. THE System SHALL provide API documentation for all public interfaces
5. THE System SHALL document performance characteristics and complexity bounds for each component
6. THE System SHALL provide examples demonstrating usage for common applications (zkVM, ML proof, signatures)
7. THE System SHALL document integration points between Neo, LatticeFold+, and Symphony components
8. THE System SHALL maintain changelog documenting deviations from paper specifications with justification
9. THE System SHALL provide troubleshooting guide for common errors and performance issues
10. THE System SHALL document testing procedures and validation methodology

