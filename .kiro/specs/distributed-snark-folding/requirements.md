# Requirements Document: Distributed SNARK via Folding Schemes

## Introduction

This document specifies the requirements for implementing a distributed Succinct Non-interactive Argument of Knowledge (SNARK) system based on folding schemes. The system addresses scalability limitations in proof generation for large-scale circuits by distributing computation across multiple provers. The core innovation is a novel "distributed PIOP + additively homomorphic polynomial commitment" framework that achieves optimized prover time and proof size compared to existing distributed SNARK constructions.

The system is specifically optimized for data-parallel circuits and achieves:
- Linear prover complexity O(T) where T = N/M (N = total gates, M = number of workers)
- Logarithmic proof size O(log N) field elements + O(1) group elements
- Logarithmic verification time O(log N) field operations + O(M) multi-scalar multiplication
- Communication complexity O(N) field elements + O(M) group elements

## Glossary

- **SNARK (Succinct Non-interactive Argument of Knowledge)**: A cryptographic proof system enabling short proofs and fast verification of NP statements
- **PIOP (Polynomial Interactive Oracle Proof)**: An interactive proof system where the prover sends polynomial oracles and the verifier queries them at arbitrary points
- **Folding Scheme**: A reduction of knowledge that combines multiple instances of a relation into a single instance
- **SumFold Protocol**: A folding protocol that reduces multiple sum-check instances into one
- **Distributed_SumFold**: The distributed version of SumFold enabling parallel computation across multiple provers
- **Multilinear Extension (MLE)**: The unique multilinear polynomial f̃ : F^n → F extending a function f : B^μ → F
- **Sum-check Protocol**: An interactive protocol proving ∑_{x∈B^μ} h(w₀(x),...,w_{t-1}(x)) = v
- **Polynomial Commitment Scheme (PCS)**: A cryptographic primitive allowing commitment to polynomials with efficient opening proofs
- **SamaritanPCS**: An additively homomorphic multilinear polynomial commitment scheme with linear prover time
- **HyperPlonk Constraint System**: A constraint system supporting custom gates with multilinear polynomials
- **RoK (Reduction of Knowledge)**: A generalization of argument of knowledge supporting sequential and parallel composition
- **Boolean Hypercube**: The set B^μ := {0,1}^μ
- **Field**: A finite field F = F_p of prime order p where |F| = Ω(2^λ)
- **Security Parameter**: λ, determining the security level of cryptographic operations
- **Data-Parallel Circuit**: A circuit consisting of M identical subcircuits processing different data
- **Gate Identity**: Constraint ensuring each gate computes correctly: f(q,w) = 0
- **Wire Identity**: Constraint ensuring wire connections are consistent via permutation σ
- **Consistency Check**: Verification that public inputs match witness values
- **Prover_System**: The distributed system with M provers P₀,...,P_{M-1}
- **Coordinator_Prover**: Prover P₀ that aggregates results and performs final operations
- **Worker_Prover**: Provers P₁,...,P_{M-1} that perform local computations

- **Subcircuit**: Individual circuit C_i of size T = N/M processed by prover P_i
- **Witness Polynomial**: Multilinear polynomial w ∈ F^{(≤1)}_μ encoding circuit wire values
- **Selector Polynomial**: Multilinear polynomial q ∈ F^{(≤1)}_μ encoding gate types
- **Permutation**: Function σ : B^μ → B^μ defining wire connections
- **Evaluation Point**: A point in F^μ where polynomials are evaluated
- **Challenge**: Random field element(s) sent by verifier to ensure soundness
- **Transcript**: Record of all messages exchanged in the protocol
- **Oracle Notation [[f]]**: Represents polynomial commitment com_f to polynomial f
- **Homomorphic Operation**: [[a]] + [[b]] represents com_a · com_b for commitments
- **Scalar Multiplication**: k · [[a]] represents com_a^k for commitment
- **Knowledge Error**: Probability δ that a malicious prover succeeds without valid witness
- **Completeness**: Property that honest prover always convinces verifier
- **Knowledge Soundness**: Property that successful prover must know valid witness
- **Succinctness**: Property that proof size is poly(λ, log|C|) and verification is poly(λ, log|C|)
- **Public Coin Protocol**: Protocol where verifier's messages are uniformly random
- **Fiat-Shamir Transform**: Technique converting interactive protocols to non-interactive via hash functions
- **Schwartz-Zippel Lemma**: Probabilistic test for polynomial identity over finite fields
- **eq(x,X) Function**: Multilinear polynomial ∏^μ_{i=1}(x_iX_i + (1-x_i)(1-X_i))
- **Virtual Polynomial**: Polynomial f̃ defined as composition of gate function with witness polynomials
- **Relation**: Set R of tuples (structure; instance; witness) defining valid statements
- **Indexed Relation**: Relation with additional index parameter defining structure
- **Relation Product**: R₁ × R₂ combining two relations over same parameters
- **Sequential Composition**: Π₂ ∘ Π₁ applying reductions in sequence
- **Parallel Composition**: Π₁ × Π₂ applying reductions independently
- **EARS Pattern**: Easy Approach to Requirements Syntax for structured requirements
- **INCOSE Quality Rules**: Semantic quality rules for requirements engineering

## Requirements

### Requirement 1: Core Cryptographic Primitives

**User Story:** As a cryptographic system developer, I want to implement fundamental cryptographic primitives, so that the distributed SNARK system has secure building blocks.

#### Acceptance Criteria

1. WHEN the system initializes, THE Prover_System SHALL generate public parameters pp ← G(1^λ, F) where λ is the security parameter and F is the finite field F_p of prime order p with |F| = Ω(2^λ)

2. WHEN a polynomial f ∈ F^{(≤d)}_μ is committed, THE Prover_System SHALL compute commitment com_f ← Commit(f, pp) using the polynomial commitment scheme

3. WHEN a commitment com_f is opened at point x ∈ F^μ, THE Prover_System SHALL generate evaluation proof (z, π_f) ← Open(pp, com_f, x) where z = f(x)

4. WHEN verification is performed, THE Prover_System SHALL execute Verify(pp, com_f, x, z, π_f) → b ∈ {0,1} and output 1 if and only if f(x) = z with probability 1 - negl(λ)

5. WHEN the multilinear extension is computed for function f : B^μ → F, THE Prover_System SHALL construct unique polynomial f̃ : F^μ → F such that f̃(x) = f(x) for all x ∈ B^μ and f̃(X) = ∑_{x∈B^μ} f(x) · eq(x,X)

6. WHEN the eq function is evaluated, THE Prover_System SHALL compute eq(x,X) = ∏^μ_{i=1}(x_iX_i + (1-x_i)(1-X_i)) for x ∈ B^μ and X ∈ F^μ

7. WHEN homomorphic operations are performed, THE Prover_System SHALL support [[a]] + [[b]] = com_a · com_b and k · [[a]] = com_a^k for commitments

### Requirement 2: Sum-Check Protocol Implementation

**User Story:** As a proof system implementer, I want to implement the sum-check protocol for high-degree polynomials, so that I can verify polynomial evaluations efficiently.

#### Acceptance Criteria

1. WHEN the sum-check relation R_HSUM is defined, THE Prover_System SHALL accept tuples (s; x; w) = (h; (v, [[w₀]],...,[[w_{t-1}]]); (w₀,...,w_{t-1})) where ∑_{x∈B^μ} h(w₀(x),...,w_{t-1}(x)) = v

2. WHEN the sum-check protocol executes for μ rounds, THE Prover_System SHALL send univariate polynomial Q_k(X) of degree at most d in round k ∈ [μ]

3. WHEN round k verifier check is performed, THE Prover_System SHALL verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) where r_{k-1} is the previous challenge

4. WHEN the verifier sends challenge r_k, THE Prover_System SHALL sample r_k uniformly from F and update the protocol state

5. WHEN the final round completes, THE Prover_System SHALL reduce to polynomial evaluation Q(r_b) = c where r_b = (r₁,...,r_μ) ∈ F^μ

6. WHEN knowledge soundness is required, THE Prover_System SHALL achieve knowledge error at most dμ/|F| for degree-d polynomials over μ variables

7. WHEN perfect completeness is required, THE Prover_System SHALL accept all valid proofs with probability 1

### Requirement 3: SumFold Protocol for Single Prover

**User Story:** As a folding scheme developer, I want to implement the SumFold protocol, so that multiple sum-check instances can be folded into one.

#### Acceptance Criteria

1. WHEN M = 2^ν instances are folded, THE Prover_System SHALL accept input {x_i = (v_i, [[w_{i,0}]],...,[[w_{i,t-1}]]); w_i = (w_{i,0},...,w_{i,t-1})}_{i∈[M]}

2. WHEN the verifier samples randomness, THE Prover_System SHALL generate ρ ← F^ν uniformly at random and send to prover

3. WHEN interpolation polynomials are constructed, THE Prover_System SHALL compute f_j(b,x) = ∑_{i∈[M]} eq(b,⟨i⟩_ν) · w_{i,j}(x) for j ∈ [t] and b ∈ B^ν, x ∈ B^μ

4. WHEN the aggregated sum is computed, THE Prover_System SHALL calculate T₀ = ∑_{i∈[M]} eq(ρ,⟨i⟩_ν) · v_i

5. WHEN the sum-check polynomial is defined, THE Prover_System SHALL construct Q(b) = eq(ρ,b) · (∑_{x∈B^μ} h(f₀(b,x),...,f_{t-1}(b,x)))

6. WHEN the sum-check protocol executes, THE Prover_System SHALL run ν rounds proving ∑_{b∈B^ν} Q(b) = T₀

7. WHEN the final evaluation is reached, THE Prover_System SHALL reduce to Q(r_b) = c where r_b ∈ F^ν is the verifier randomness

8. WHEN folded witness is computed, THE Prover_System SHALL calculate w'_j = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · w_{i,j} for j ∈ [t]

9. WHEN folded commitments are computed, THE Prover_System SHALL calculate [[w'_j]] = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · [[w_{i,j}]] for j ∈ [t]

10. WHEN folded value is computed, THE Prover_System SHALL calculate v' = c · eq(ρ,r_b)^{-1}

11. WHEN the output is generated, THE Prover_System SHALL produce folded instance-witness pair ((h, v', [[w'₀]],...,[[w'_{t-1}]]); (w'₀,...,w'_{t-1}))

### Requirement 4: Distributed SumFold Protocol

**User Story:** As a distributed system architect, I want to implement distributed SumFold across M provers, so that folding computation is parallelized efficiently.

#### Acceptance Criteria

1. WHEN M = 2^ν provers participate, THE Prover_System SHALL assign prover P_i the instance-witness pair (x_i; w_i) = ((v_i, [[w_{i,0}]],...,[[w_{i,t-1}]]); (w_{i,0},...,w_{i,t-1})) for i ∈ [M]

2. WHEN local data is stored, THE Prover_System SHALL ensure P_i stores eq(ρ,⟨i⟩_ν) and witness slices f_j(⟨i⟩_ν,x) = w_{i,j}(x) for all x ∈ B^μ and j ∈ [t]

3. WHEN round k ∈ [ν] executes, THE Prover_System SHALL have P_s send messages to P_{2^{ν-k}+s} for s ∈ [2^{ν-k}] containing eq(ρ,{r₁,...,r_{k-1}}||⟨s⟩_{ν-k+1}) and f_j({r₁,...,r_{k-1}}||⟨s⟩_{ν-k+1},x) for x ∈ B^μ, j ∈ [t]

4. WHEN partial polynomial is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} compute e_k^{(s)}(X) = (1-X) · eq(ρ,{r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k}) + X · eq(ρ,{r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k})

5. WHEN witness interpolation is performed, THE Prover_System SHALL compute f_{k,x}^{(s,j)}(X) = (1-X) · f_j({r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k},x) + X · f_j({r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k},x)

6. WHEN partial sum-check polynomial is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} calculate Q_k^{(s)}(X) = e_k^{(s)}(X) · ∑_{x∈B^μ} h(f_{k,x}^{(s,0)}(X), f_{k,x}^{(s,1)}(X),...,f_{k,x}^{(s,t-1)}(X)) using Algorithm 1

7. WHEN aggregation is performed, THE Coordinator_Prover SHALL compute Q_k(X) = ∑_{s∈[2^{ν-k}]} Q_k^{(s)}(X) and send to verifier

8. WHEN verifier check is performed, THE Prover_System SHALL verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) and send challenge r_k ∈ F to P₀

9. WHEN challenge is distributed, THE Coordinator_Prover SHALL transmit r_k to P_{2^{ν-k}+s} for s ∈ [2^{ν-k}]

10. WHEN next-round data is computed, THE Prover_System SHALL have P_{2^{ν-k}+s} compute eq(ρ,{r₁,...,r_k}||⟨s⟩_{ν-k}) and f_j({r₁,...,r_k}||⟨s⟩_{ν-k},x) and send to P_s

11. WHEN final round completes, THE Coordinator_Prover SHALL obtain eq(ρ,r_b) and f_j(r_b,x) where r_b = {r₁,...,r_ν} and compute c = Q(r_b)

12. WHEN witness folding is performed, THE Prover_System SHALL have P_i compute e_i = eq(r_b,⟨i⟩_ν) and ([[w'_{i,j}]], w'_{i,j}) = (e_i · [[w_{i,j}]], e_i · w_{i,j}) for j ∈ [t] and send [[w'_{i,j}]] to P₀

13. WHEN witness aggregation is performed, THE Prover_System SHALL have P_i update w'_j ← w'_j + w'_{M-i-1,j} and send w'_j to P_{M-i-2} for j ∈ [t] and i ∈ [M-1]

14. WHEN final output is generated, THE Coordinator_Prover SHALL compute v' = c · eq(ρ,r_b)^{-1} and [[w'_j]] = ∑_{i∈[M]} [[w'_{i,j}]] and output ((v', [[w'₀]],...,[[w'_{t-1}]]); (w'₀,...,w'_{t-1}))

15. WHEN verifier output is generated, THE Prover_System SHALL have verifier compute v' = c · eq(ρ,r_b)^{-1}, e_i = eq(r_b,⟨i⟩_ν) and [[w'_j]] = ∑_{i∈[M]} e_i · [[w_{i,j}]] for j ∈ [t]

### Requirement 5: Complexity Guarantees for Distributed SumFold

**User Story:** As a performance engineer, I want the distributed SumFold to meet specific complexity bounds, so that the system scales efficiently.

#### Acceptance Criteria

1. WHEN prover P_i (i ∈ [M-1]) performs computation, THE Prover_System SHALL execute O(T) field operations where T = N/M

2. WHEN prover P_i (i ∈ [M-1]) performs commitment operations, THE Prover_System SHALL execute O(T) group operations

3. WHEN Coordinator_Prover performs aggregation, THE Prover_System SHALL execute O(M) group operations

4. WHEN total communication is measured, THE Prover_System SHALL transmit O(N) field elements across all provers

5. WHEN proof size is measured, THE Prover_System SHALL generate O(log M) field elements

6. WHEN verifier performs computation, THE Prover_System SHALL execute O(log M) field operations

7. WHEN verifier performs commitment verification, THE Prover_System SHALL execute O(M)-size multi-scalar multiplication

### Requirement 6: HyperPlonk Constraint System

**User Story:** As a circuit developer, I want to implement the HyperPlonk constraint system, so that arbitrary circuits can be represented and verified.

#### Acceptance Criteria

1. WHEN public parameters are defined, THE Prover_System SHALL specify pp := (F, ℓ, n, ℓ_w, ℓ_q, f) where F is field, ℓ = 2^{ν_p} is public input length, n = 2^μ is constraint count, ℓ_w = 2^{ν_w} is witness count per constraint, ℓ_q = 2^{ν_q} is selector count per constraint, and f : F^{ℓ_q+ℓ_w} → F is algebraic map of degree d

2. WHEN indexed relation is defined, THE Prover_System SHALL accept tuples (i; x, w) = ((q, σ); (p, [[w]]), w) where σ : B^{μ+ν_w} → B^{μ+ν_w} is permutation, q ∈ F^{(≤1)}_{μ+ν_q}, p ∈ F^{(≤1)}_{μ+ν_p}, w ∈ F^{(≤1)}_{μ+ν_w}

3. WHEN gate identity is checked, THE Prover_System SHALL verify f̃(X) = 0 for all X ∈ B^μ where f̃(X) := f(q(⟨0⟩_{ν_q},X),...,q(⟨ℓ_q-1⟩_{ν_q},X), w(⟨0⟩_{ν_w},X),...,w(⟨ℓ_w-1⟩_{ν_w},X))

4. WHEN wire identity is checked, THE Prover_System SHALL verify w(σ(x)) = w(x) for all x ∈ B^{μ+ν_w}

5. WHEN consistency check is performed, THE Prover_System SHALL verify p(X) = w(0^{μ+ν_w-ν_p},X) for all X ∈ B^{ν_p}

### Requirement 7: Zerocheck Relation and Reduction

**User Story:** As a protocol designer, I want to reduce zerocheck relations to sum-check, so that gate identities can be verified efficiently.

#### Acceptance Criteria

1. WHEN zerocheck relation R_ZERO is defined, THE Prover_System SHALL accept tuples (x; w) = ([[f]]; f) where f ∈ F^{(≤d)}_μ and f(x) = 0 for all x ∈ B^μ

2. WHEN reduction from R_ZERO to R_HSUM is performed, THE Prover_System SHALL have verifier send random vector r ← F^μ

3. WHEN output instance is generated, THE Prover_System SHALL produce x = (0, [[f]], [[e_r]]) where [[e_r]] = eq(·,r)

4. WHEN output witness is generated, THE Prover_System SHALL produce w = f

5. WHEN structure is updated, THE Prover_System SHALL define h'({w̃_j}_{j∈[t]}, g) = h({w̃_j}_{j∈[t]}) · g

6. WHEN public reducibility is verified, THE Prover_System SHALL compute output x = (0, [[f]], [[e_r]]) from input [[f]] and transcript containing r

### Requirement 8: Permutation Check Relation and Reduction

**User Story:** As a protocol designer, I want to reduce permutation check relations to sum-check, so that wire identities can be verified efficiently.

#### Acceptance Criteria

1. WHEN permutation check relation R_PERM is defined, THE Prover_System SHALL accept tuples (i; x; w) = (σ; ([[f]], [[g]]); (f, g)) where σ : B^μ → B^μ is permutation, f, g ∈ F^{(≤d)}_μ, and g(x) = f(σ(x)) for all x ∈ B^μ

2. WHEN verifier samples randomness, THE Prover_System SHALL generate α, β ∈ F uniformly at random and send to prover

3. WHEN identity polynomial is computed, THE Prover_System SHALL calculate f_id = s_id + α · w + β where s_id is identity selector

4. WHEN permutation polynomial is computed, THE Prover_System SHALL calculate f_σ = s_σ + α · w + β where s_σ is permutation selector

5. WHEN oracles are obtained, THE Prover_System SHALL compute [[f_id]] and [[f_σ]] using [[s_id]], [[s_σ]], [[w]]

6. WHEN accumulator polynomial is computed, THE Prover_System SHALL calculate v ∈ F^{(≤1)}_{μ+1} where v(0,x) = f_id(x)/f_σ(x) and v(1,x) = v(x,0) · v(x,1) for all x ∈ B^μ

7. WHEN accumulator is verified, THE Prover_System SHALL query [[v]] at point (1,...,1,0) ∈ F^{μ+1} and verify evaluation equals 1

8. WHEN constraint polynomial is computed, THE Prover_System SHALL calculate ĝ ∈ F^{(≤2)}_{μ+1} where ĝ(x₀,x) = (1-x₀) · (v(1,x) - v(x,0) · v(x,1)) + x₀ · (f_σ(x) · v(0,x) - f_id(x)) for x₀ ∈ B, x ∈ B^μ

9. WHEN oracle is obtained, THE Prover_System SHALL compute [[ĝ]] using [[v]], [[f_id]], [[f_σ]]

10. WHEN reduction to R_HSUM is performed, THE Prover_System SHALL execute zerocheck reduction with structure h' and input ([[ĝ]]; ĝ) where h'(a,b,c) = a · b + c

11. WHEN output is generated, THE Prover_System SHALL produce x = (0, [[f̂]], [[ê]]) and w = f̂

12. WHEN oracle query is performed for [[ĝ]], THE Prover_System SHALL query either [[ĝ(0,·)]] = {[[−v(·,0)]], [[v(·,1)]], [[v(1,·)]]} or [[ĝ(1,·)]] = {[[f_σ(·)]], [[v(0,·)]], [[−f_id(·)]]}

### Requirement 9: Consistency Check Relation and Distributed Reduction

**User Story:** As a protocol designer, I want to reduce distributed consistency checks to sum-check, so that public input verification is efficient across multiple provers.

#### Acceptance Criteria

1. WHEN consistency check relation R_CON is defined, THE Prover_System SHALL accept tuples (x; w) = ((p, [[w]]); w) where p ∈ F^{(≤1)}_{ν_p}, w ∈ F^{(≤1)}_μ, and p(X) = w(0^{μ-ν_p},X)

2. WHEN prover P_i holds data, THE Prover_System SHALL store (x_i; w_i) = ((p_i, [[w_i]]); w_i) for i ∈ [M]

3. WHEN difference polynomial is computed, THE Prover_System SHALL calculate [[w'_i]] = [[w_i(0^{μ-ν_p},·)]] − [[p_i]] for i ∈ [M]

4. WHEN zerocheck reduction is performed, THE Prover_System SHALL have P_i and verifier execute Protocol D.1 with structure h_id, input ([[w'_i]]; w'_i), and output ((0, [[w'_i]], [[e'_i]]); w'_i) with updated structure h₁

5. WHEN distributed folding is performed, THE Prover_System SHALL have P₀,...,P_{M-1} and verifier execute Protocol 3.2 with structure h₁, input ((0, [[w'_i]], [[e'_i]]); w'_i) for P_i, and output ((0, [[w']], [[e']]); w')

6. WHEN complexity is measured, THE Prover_System SHALL have each P_i perform O(T) field operations and O(T) group operations

7. WHEN total communication is measured, THE Prover_System SHALL transmit O(N) field elements

8. WHEN proof size is measured, THE Prover_System SHALL generate O(log M) field elements

9. WHEN verifier performs computation, THE Prover_System SHALL execute O(log M) field operations and O(M)-size multi-scalar multiplication

### Requirement 10: Complete Distributed SNARK Protocol

**User Story:** As a system integrator, I want to implement the complete distributed argument of knowledge, so that data-parallel circuits can be proven efficiently.

#### Acceptance Criteria

1. WHEN M provers participate, THE Prover_System SHALL have P_i run HyperPlonk indexer and hold structure f and instance-witness pair ((p_i, [[w_i]]); w_i) where ({[[w_{i,j}]]}_{j∈[ℓ_w]}; {w_{i,j}}_{j∈[ℓ_w]}) ∈ R_ZERO, (([[w_i]], [[w_i]]); (w_i, w_i)) ∈ R_PERM, and ((p_i, [[w_i]]); w_i) ∈ R_CON

2. WHEN witness slices are defined, THE Prover_System SHALL compute [[w_{i,j}]] := [[w_i(⟨j⟩_{ν_w},·)]] for j ∈ [ℓ_w]

3. WHEN gate identity reduction is performed (Step 1), THE Prover_System SHALL have P_i and verifier execute Protocol D.1 with structure f, input ({[[w_{i,j}]]}_{j∈[ℓ_w]}; {w_{i,j}}_{j∈[ℓ_w]}) and output ((0, {[[w_{i,j}]]}_{j∈[ℓ_w]}, [[e_i]]); {w_{i,j}}_{j∈[ℓ_w]}) with updated structure f'

4. WHEN wire identity reduction is performed (Step 2), THE Prover_System SHALL have P_i and verifier execute Protocol D.2 with structure h_id, input (([[w_i]], [[w_i]]); w_i) and output ((0, [[ĝ_{i,1}]], [[ĝ_{i,2}]], [[ĝ_{i,3}]], [[ê_i]]); ĝ_{i,1}, ĝ_{i,2}, ĝ_{i,3}) with updated structure h'

5. WHEN gate identity folding is performed (Step 3), THE Prover_System SHALL have P₀,...,P_{M-1} and verifier execute Protocol 3.2 with structure f', input ((0, {[[w_{i,j}]]}_{j∈[ℓ_w]}, [[e_i]]); {w_{i,j}}_{j∈[ℓ_w]}) for P_i, and output ((0, {[[w̃_j]]}_{j∈[ℓ_w]}, [[ẽ]]); {w̃_j}_{j∈[ℓ_w]})

6. WHEN wire identity folding is performed (Step 4), THE Prover_System SHALL have P₀,...,P_{M-1} and verifier execute Protocol 3.2 with structure h', input ((0, [[ĝ_{i,1}]], [[ĝ_{i,2}]], [[ĝ_{i,3}]], [[ê_i]]); ĝ_{i,1}, ĝ_{i,2}, ĝ_{i,3}) for P_i, and output ((0, [[ĝ₁]], [[ĝ₂]], [[ĝ₃]], [[ê]]); ĝ₁, ĝ₂, ĝ₃)

7. WHEN consistency check folding is performed (Step 5), THE Prover_System SHALL have P₀,...,P_{M-1} and verifier execute Protocol 4.2 with structure h_id, input ((p_i, [[w_i]]); w_i), and output ((0, [[w']], [[e']]); w') with updated structure h'_c

8. WHEN final sum-check is performed (Step 6), THE Prover_System SHALL have P₀ and verifier execute sum-check protocol to verify (f'; (0, {[[w̃_j]]}_{j∈[ℓ_w]}, [[ẽ]]); {w̃_j}_{j∈[ℓ_w]}) ∈ R_HSUM

9. WHEN final sum-check is performed (Step 6 continued), THE Prover_System SHALL have P₀ and verifier execute sum-check protocol to verify (h'; (0, [[ĝ₁]], [[ĝ₂]], [[ĝ₃]], [[ê]]); ĝ₁, ĝ₂, ĝ₃) ∈ R_HSUM

10. WHEN final sum-check is performed (Step 6 continued), THE Prover_System SHALL have P₀ and verifier execute sum-check protocol to verify ((0, [[w']], [[e']]); w') ∈ R_HSUM

11. WHEN completeness is verified, THE Prover_System SHALL accept all valid proofs from honest provers with probability 1

12. WHEN knowledge soundness is verified, THE Prover_System SHALL extract valid witness from any successful prover with probability 1 - negl(λ)

13. WHEN succinctness is verified, THE Prover_System SHALL generate proof of size O(log N) field elements plus O(1) group elements

### Requirement 11: Complexity Guarantees for Complete Protocol

**User Story:** As a performance engineer, I want the complete distributed SNARK to meet specific complexity bounds, so that the system achieves optimal performance.

#### Acceptance Criteria

1. WHEN prover P_i (i ∈ [M-1]) performs computation, THE Prover_System SHALL execute O(T) field operations where T = N/M

2. WHEN prover P_i (i ∈ [M-1]) performs commitment operations, THE Prover_System SHALL execute O(T) group operations

3. WHEN Coordinator_Prover performs final operations, THE Prover_System SHALL execute O(T) field operations and O(T) group operations for polynomial commitment opening

4. WHEN total communication is measured, THE Prover_System SHALL transmit O(N) field elements across all provers

5. WHEN proof size is measured, THE Prover_System SHALL generate O(log N) field elements plus O(1) group elements

6. WHEN verifier performs field operations, THE Prover_System SHALL execute O(log M) field operations for folding plus O(log N) field operations for sum-check

7. WHEN verifier performs group operations, THE Prover_System SHALL execute O(M)-size multi-scalar multiplication plus O(1) pairing operations

### Requirement 12: SamaritanPCS Integration

**User Story:** As a cryptographic engineer, I want to integrate SamaritanPCS as the polynomial commitment scheme, so that the system achieves optimal proof size and verification time.

#### Acceptance Criteria

1. WHEN SamaritanPCS is initialized, THE Prover_System SHALL generate public parameters pp supporting multilinear polynomials over field F

2. WHEN polynomial commitment is performed, THE Prover_System SHALL execute Commit operation with linear prover time O(2^μ) for μ-variate polynomials

3. WHEN polynomial opening is performed, THE Prover_System SHALL generate constant-size proof O(1) group elements

4. WHEN verification is performed, THE Prover_System SHALL execute Verify operation with logarithmic time O(μ) field operations plus O(1) pairing operations

5. WHEN homomorphic operations are required, THE Prover_System SHALL support additive homomorphism [[a]] + [[b]] = com_a · com_b

6. WHEN scalar multiplication is required, THE Prover_System SHALL support k · [[a]] = com_a^k for scalar k ∈ F

7. WHEN binding property is required, THE Prover_System SHALL ensure no PPT adversary can find two different polynomials with same commitment except with probability negl(λ)

8. WHEN hiding property is required, THE Prover_System SHALL ensure commitment reveals no information about polynomial except with probability negl(λ)

### Requirement 13: Reduction of Knowledge Composition

**User Story:** As a protocol theorist, I want to implement RoK composition rules, so that complex protocols can be analyzed modularly.

#### Acceptance Criteria

1. WHEN sequential composition is performed, THE Prover_System SHALL support Π₂ ∘ Π₁ : R₁ → R₃ for Π₁ : R₁ → R₂ and Π₂ : R₂ → R₃

2. WHEN sequential composition indexer is executed, THE Prover_System SHALL compute K(pp, s₁) by running (pk₁, vk₁, s₂) ← K₁(pp, s₁), (pk₂, vk₂, s₃) ← K₂(pp, s₂) and outputting ((pk₁, pk₂), (vk₁, vk₂), s₃)

3. WHEN sequential composition prover is executed, THE Prover_System SHALL compute P((pk₁, pk₂), u₁, w₁) = P₂(pk₂, P₁(pk₁, u₁, w₁))

4. WHEN sequential composition verifier is executed, THE Prover_System SHALL compute V((vk₁, vk₂), u₁) = V₂(vk₂, V₁(vk₁, u₁))

5. WHEN parallel composition is performed, THE Prover_System SHALL support Π₁ × Π₂ : R₁ × R₃ → R₂ × R₄ for Π₁ : R₁ → R₂ and Π₂ : R₃ → R₄

6. WHEN parallel composition prover is executed, THE Prover_System SHALL compute P(pk, (u₁, u₃), (w₁, w₃)) = (P₁(pk, u₁, w₁), P₂(pk, u₃, w₃))

7. WHEN parallel composition verifier is executed, THE Prover_System SHALL compute V(vk, (u₁, u₃)) = (V₁(vk, u₁), V₂(vk, u₃))

8. WHEN relation product is defined, THE Prover_System SHALL support R₁ × R₂ = {(pp, s, (u₁, u₂), (w₁, w₂)) | (pp, s, u₁, w₁) ∈ R₁, (pp, s, u₂, w₂) ∈ R₂}

9. WHEN perfect completeness is preserved, THE Prover_System SHALL ensure composed protocols accept all valid proofs with probability 1

10. WHEN knowledge soundness is preserved, THE Prover_System SHALL ensure composed protocols extract valid witnesses with probability 1 - negl(λ)

11. WHEN public reducibility is preserved, THE Prover_System SHALL ensure composed protocols compute output instances from transcripts deterministically

### Requirement 14: Algorithm for Evaluating Product Polynomials

**User Story:** As an algorithm implementer, I want to implement efficient evaluation of product polynomials h(X) = ∏ᵢ₌₁ᵈ gᵢ(X), so that sum-check rounds execute efficiently.

#### Acceptance Criteria

1. WHEN input is provided, THE Prover_System SHALL accept linear univariate functions g₁(X),...,gₐ(X)

2. WHEN initialization is performed, THE Prover_System SHALL set t₁,ⱼ ← gⱼ for all j ∈ [d]

3. WHEN iteration i ∈ [0, log d] is performed, THE Prover_System SHALL compute tᵢ₊₁,ⱼ(X) ← tᵢ,₂ⱼ₋₁(X) · tᵢ,₂ⱼ(X) using FFT for j ∈ [0, d/2ⁱ - 1]

4. WHEN output is generated, THE Prover_System SHALL return h(X) = t_{log d,1}

5. WHEN complexity is measured, THE Prover_System SHALL execute O(d log d) field operations using FFT

### Requirement 15: Fiat-Shamir Transformation

**User Story:** As a non-interactive protocol designer, I want to apply Fiat-Shamir transformation, so that interactive protocols become non-interactive.

#### Acceptance Criteria

1. WHEN public-coin protocol is provided, THE Prover_System SHALL verify all verifier messages are uniformly random

2. WHEN hash function is selected, THE Prover_System SHALL use cryptographic hash H : {0,1}* → F modeled as random oracle

3. WHEN prover generates message, THE Prover_System SHALL compute challenge rₖ = H(transcript || prover_message_k) instead of receiving from verifier

4. WHEN transcript is maintained, THE Prover_System SHALL append all messages to transcript in order

5. WHEN soundness is analyzed, THE Prover_System SHALL achieve soundness error at most ε + q_H/|F| where ε is interactive soundness and q_H is hash query count

6. WHEN proof is generated, THE Prover_System SHALL include all prover messages and exclude verifier challenges

7. WHEN verification is performed, THE Prover_System SHALL recompute all challenges from transcript and verify consistency

### Requirement 16: Data-Parallel Circuit Structure

**User Story:** As a circuit designer, I want to define data-parallel circuits, so that the distributed SNARK can be applied effectively.

#### Acceptance Criteria

1. WHEN data-parallel circuit is defined, THE Prover_System SHALL accept M identical subcircuits C₀,...,C_{M-1} each of size T = N/M

2. WHEN subcircuit structure is specified, THE Prover_System SHALL ensure all subcircuits share same gate function f and permutation structure σ

3. WHEN subcircuit differs only in data, THE Prover_System SHALL allow different witness values w_i and public inputs p_i for each subcircuit i

4. WHEN structural homogeneity is verified, THE Prover_System SHALL ensure selector polynomials q are identical across subcircuits

5. WHEN folding is applicable, THE Prover_System SHALL verify all subcircuits satisfy same constraint system with different witnesses

6. WHEN circuit size is measured, THE Prover_System SHALL compute total size N = M · T where M = 2^ν is power of 2

### Requirement 17: Communication Protocol Between Provers

**User Story:** As a distributed systems engineer, I want to implement efficient communication between provers, so that the protocol executes with minimal overhead.

#### Acceptance Criteria

1. WHEN network topology is established, THE Prover_System SHALL organize provers in binary tree structure for logarithmic communication rounds

2. WHEN round k message is sent, THE Prover_System SHALL have P_s transmit O(T) field elements to P_{2^{ν-k}+s}

3. WHEN aggregation is performed, THE Prover_System SHALL have Coordinator_Prover collect O(2^{ν-k}) partial results in round k

4. WHEN challenge is distributed, THE Prover_System SHALL have Coordinator_Prover broadcast challenge to O(2^{ν-k}) provers in round k

5. WHEN total rounds are counted, THE Prover_System SHALL execute ν = log M rounds for folding

6. WHEN bandwidth is measured, THE Prover_System SHALL transmit O(N) total data across all provers and rounds

7. WHEN latency is measured, THE Prover_System SHALL complete protocol in O(log M) sequential communication steps

### Requirement 18: Security Properties

**User Story:** As a security analyst, I want to verify all security properties, so that the distributed SNARK is cryptographically sound.

#### Acceptance Criteria

1. WHEN perfect completeness is required, THE Prover_System SHALL accept all valid proofs from honest provers with probability exactly 1

2. WHEN knowledge soundness is required, THE Prover_System SHALL ensure for any PPT adversary (A₁, A₂), there exists PPT extractor E such that Pr[⟨A₂, V⟩ = 1 ∧ (i,x,w) ∉ R] ≤ δ(|i| + |x|) where w ← E^{A₁,A₂}(pp, i, x)

3. WHEN knowledge error is bounded, THE Prover_System SHALL achieve δ ≤ negl(λ) for security parameter λ

4. WHEN Schwartz-Zippel lemma is applied, THE Prover_System SHALL bound probability of accepting invalid polynomial identity by deg(f)/|F|

5. WHEN sum-check soundness is analyzed, THE Prover_System SHALL achieve knowledge error at most dμ/|F| for degree-d polynomial over μ variables

6. WHEN folding soundness is analyzed, THE Prover_System SHALL preserve knowledge soundness through composition

7. WHEN commitment binding is required, THE Prover_System SHALL ensure no PPT adversary can find (f, f', x, π, π') with f ≠ f', com_f = com_{f'}, and both Verify operations accept, except with probability negl(λ)

8. WHEN commitment hiding is required, THE Prover_System SHALL ensure commitment com_f reveals no information about f beyond what is explicitly opened, with advantage at most negl(λ)

9. WHEN zero-knowledge is required, THE Prover_System SHALL ensure there exists PPT simulator S producing transcripts indistinguishable from real protocol executions

10. WHEN malicious prover is considered, THE Prover_System SHALL ensure verifier accepts only if prover knows valid witness, except with probability negl(λ)

11. WHEN malicious verifier is considered, THE Prover_System SHALL ensure verifier learns nothing beyond validity of statement (if zero-knowledge property is required)

### Requirement 19: Optimization Techniques

**User Story:** As a performance optimizer, I want to implement specific optimization techniques, so that the system achieves practical efficiency.

#### Acceptance Criteria

1. WHEN dynamic programming is applied to sum-check, THE Prover_System SHALL reuse intermediate computations across rounds to achieve O(T) prover time

2. WHEN FFT is applied to polynomial multiplication, THE Prover_System SHALL compute products of degree-d polynomials in O(d log d) time

3. WHEN batch verification is applied, THE Prover_System SHALL verify multiple polynomial evaluations simultaneously using random linear combinations

4. WHEN precomputation is applied, THE Prover_System SHALL compute and store eq(ρ, ·) values for reuse across evaluations

5. WHEN memory optimization is applied, THE Prover_System SHALL stream polynomial evaluations to avoid storing entire polynomials when possible

6. WHEN parallel computation is applied within prover, THE Prover_System SHALL utilize multi-core processors for independent computations

7. WHEN commitment batching is applied, THE Prover_System SHALL combine multiple commitments into single multi-scalar multiplication

### Requirement 20: Error Handling and Edge Cases

**User Story:** As a robust system developer, I want to handle all error conditions and edge cases, so that the system operates reliably.

#### Acceptance Criteria

1. WHEN field size is insufficient, THE Prover_System SHALL reject parameters if |F| < 2^λ and output error

2. WHEN circuit size is not power of 2, THE Prover_System SHALL pad circuit to next power of 2 or output error

3. WHEN prover count is not power of 2, THE Prover_System SHALL reject configuration and output error

4. WHEN polynomial degree exceeds bound, THE Prover_System SHALL reject polynomial and output error

5. WHEN commitment verification fails, THE Prover_System SHALL reject proof and output 0

6. WHEN sum-check verification fails, THE Prover_System SHALL reject proof and output 0

7. WHEN communication timeout occurs, THE Prover_System SHALL retry transmission up to maximum retry count then abort

8. WHEN prover fails, THE Prover_System SHALL detect failure and abort protocol with error message

9. WHEN memory allocation fails, THE Prover_System SHALL output error and gracefully terminate

10. WHEN invalid parameters are provided, THE Prover_System SHALL validate all inputs and reject invalid configurations with descriptive error messages

### Requirement 21: Testing and Benchmarking

**User Story:** As a quality assurance engineer, I want comprehensive testing and benchmarking capabilities, so that the system correctness and performance can be validated.

#### Acceptance Criteria

1. WHEN unit tests are executed, THE Prover_System SHALL verify correctness of each component (polynomial commitment, sum-check, folding) independently

2. WHEN integration tests are executed, THE Prover_System SHALL verify correctness of complete protocol with various circuit sizes

3. WHEN soundness tests are executed, THE Prover_System SHALL verify that invalid proofs are rejected with high probability

4. WHEN completeness tests are executed, THE Prover_System SHALL verify that all valid proofs are accepted

5. WHEN performance benchmarks are executed, THE Prover_System SHALL measure prover time for circuits of size 2^18, 2^19, 2^20, 2^21, 2^22 gates

6. WHEN scalability benchmarks are executed, THE Prover_System SHALL measure performance with 2, 4, 8, 16 provers

7. WHEN comparison benchmarks are executed, THE Prover_System SHALL compare against HyperPianist and Cirrus on identical hardware

8. WHEN proof size is measured, THE Prover_System SHALL record size in kilobytes for various circuit sizes

9. WHEN verification time is measured, THE Prover_System SHALL record time in milliseconds for various circuit sizes

10. WHEN communication overhead is measured, THE Prover_System SHALL record total bytes transmitted between provers

### Requirement 22: Implementation with Arkworks Ecosystem

**User Story:** As a Rust developer, I want to implement the system using arkworks libraries, so that the implementation is efficient and maintainable.

#### Acceptance Criteria

1. WHEN finite field operations are performed, THE Prover_System SHALL use ark_ff for field arithmetic

2. WHEN elliptic curve operations are performed, THE Prover_System SHALL use ark_ec for group operations

3. WHEN polynomial operations are performed, THE Prover_System SHALL use ark_poly for polynomial arithmetic and FFT

4. WHEN serialization is performed, THE Prover_System SHALL use ark_serialize for efficient encoding

5. WHEN BN254 curve is used, THE Prover_System SHALL use ark_bn254 for pairing-friendly curve operations

6. WHEN random number generation is performed, THE Prover_System SHALL use ark_std::rand for cryptographically secure randomness

7. WHEN parallel computation is performed, THE Prover_System SHALL use rayon for data parallelism within provers

### Requirement 23: Comparison with Existing Systems

**User Story:** As a researcher, I want to compare the system with existing distributed SNARKs, so that improvements can be quantified.

#### Acceptance Criteria

1. WHEN compared to HyperPianist, THE Prover_System SHALL achieve at least 4.1× speedup in prover time with 8 machines

2. WHEN compared to HyperPianist, THE Prover_System SHALL achieve smaller proof size (8.5-9.9 KB vs 8.9-10.7 KB for circuits 2^18 to 2^22)

3. WHEN compared to HyperPianist, THE Prover_System SHALL achieve comparable verification time (within 2× factor)

4. WHEN compared to Cirrus, THE Prover_System SHALL achieve O(1) group elements in proof vs O(log N) group elements

5. WHEN compared to Cirrus, THE Prover_System SHALL achieve O(N) communication vs O(M · log N) communication

6. WHEN compared to HEKATON, THE Prover_System SHALL achieve O(T) prover time vs O(T · log T) prover time

7. WHEN compared to Pianist, THE Prover_System SHALL achieve O(T) prover time vs O(T · log T) prover time

8. WHEN compared to deVirgo, THE Prover_System SHALL achieve O(log N) proof size vs O(log² N + M²) proof size

9. WHEN asymptotic complexity is compared, THE Prover_System SHALL match or improve all complexity metrics in Table 1 of the paper

### Requirement 24: Mathematical Correctness Proofs

**User Story:** As a formal verification engineer, I want to verify mathematical correctness of all protocols, so that the implementation is provably correct.

#### Acceptance Criteria

1. WHEN Theorem 1 (sum-check soundness) is verified, THE Prover_System SHALL prove knowledge error is at most dμ/|F| following proof in [2]

2. WHEN Theorem 2 (SumFold RoK) is verified, THE Prover_System SHALL prove Protocol 3.1 is RoK from R^M_HSUM to R_HSUM following proof in [13]

3. WHEN Theorem 3 (Distributed SumFold RoK) is verified, THE Prover_System SHALL prove Protocol 3.2 is distributed RoK with stated complexity bounds

4. WHEN Theorem 4 (Zerocheck reduction) is verified, THE Prover_System SHALL prove Protocol D.1 is RoK from R_ZERO to R_HSUM

5. WHEN Theorem 5 (Permutation check reduction) is verified, THE Prover_System SHALL prove Protocol D.2 is RoK from R_PERM to R_HSUM

6. WHEN Theorem 6 (Consistency check reduction) is verified, THE Prover_System SHALL prove Protocol 4.2 is distributed RoK from R^M_CON to R_HSUM

7. WHEN Theorem 7 (Complete protocol) is verified, THE Prover_System SHALL prove Protocol 4.3 is succinct argument of knowledge for relation C(x,w) = 1

8. WHEN Lemma 1 (Sequential composition) is verified, THE Prover_System SHALL prove Π₂ ∘ Π₁ preserves RoK properties

9. WHEN Lemma 2 (Parallel composition) is verified, THE Prover_System SHALL prove Π₁ × Π₂ preserves RoK properties

10. WHEN all proofs are complete, THE Prover_System SHALL document complete security proof in implementation

### Requirement 25: Protocol Transcript Management

**User Story:** As a protocol implementer, I want to manage protocol transcripts correctly, so that Fiat-Shamir transformation is secure.

#### Acceptance Criteria

1. WHEN transcript is initialized, THE Prover_System SHALL create empty transcript T = ∅

2. WHEN prover sends message m, THE Prover_System SHALL append m to transcript T ← T || m

3. WHEN verifier generates challenge, THE Prover_System SHALL compute r = H(T) and append to transcript T ← T || r

4. WHEN hash function is applied, THE Prover_System SHALL use domain-separated hashing H(label || T) for different protocol phases

5. WHEN transcript is serialized, THE Prover_System SHALL use canonical encoding for all field elements and group elements

6. WHEN transcript is verified, THE Prover_System SHALL recompute all challenges and verify consistency

7. WHEN multiple protocols are composed, THE Prover_System SHALL maintain separate transcripts or use proper domain separation

### Requirement 26: Polynomial Evaluation Optimization

**User Story:** As an algorithm engineer, I want to optimize polynomial evaluations, so that prover computation is minimized.

#### Acceptance Criteria

1. WHEN multilinear polynomial is evaluated at point r ∈ F^μ, THE Prover_System SHALL use O(2^μ) field operations

2. WHEN multiple evaluations at related points are needed, THE Prover_System SHALL reuse intermediate computations

3. WHEN eq(x, r) is computed for all x ∈ B^μ, THE Prover_System SHALL use dynamic programming in O(2^μ) time

4. WHEN polynomial is evaluated on Boolean hypercube, THE Prover_System SHALL use table lookup in O(1) time per point

5. WHEN univariate polynomial of degree d is evaluated, THE Prover_System SHALL use Horner's method in O(d) operations

6. WHEN FFT is applied, THE Prover_System SHALL use radix-2 FFT for polynomials of degree 2^k

7. WHEN inverse FFT is applied, THE Prover_System SHALL compute inverse in O(d log d) operations for degree-d polynomial

### Requirement 27: Memory Management

**User Story:** As a systems programmer, I want efficient memory management, so that large circuits can be processed without excessive memory usage.

#### Acceptance Criteria

1. WHEN polynomial of size 2^μ is stored, THE Prover_System SHALL allocate O(2^μ) field elements

2. WHEN streaming evaluation is possible, THE Prover_System SHALL avoid storing entire polynomial and compute evaluations on-the-fly

3. WHEN memory is deallocated, THE Prover_System SHALL free all temporary allocations after each protocol phase

4. WHEN memory limit is approached, THE Prover_System SHALL use disk-based storage for large polynomials if configured

5. WHEN multiple provers share machine, THE Prover_System SHALL limit memory usage per prover to configured maximum

6. WHEN memory allocation fails, THE Prover_System SHALL return error and clean up partial allocations

7. WHEN garbage collection is triggered, THE Prover_System SHALL ensure no memory leaks in long-running processes

### Requirement 28: Distributed Coordination

**User Story:** As a distributed systems engineer, I want robust coordination between provers, so that the protocol executes reliably in distributed environment.

#### Acceptance Criteria

1. WHEN Coordinator_Prover is selected, THE Prover_System SHALL designate P₀ as coordinator

2. WHEN synchronization is required, THE Prover_System SHALL use barrier synchronization at end of each round

3. WHEN message ordering is required, THE Prover_System SHALL ensure messages are processed in protocol order

4. WHEN prover fails, THE Prover_System SHALL detect failure within timeout period and abort protocol

5. WHEN network partition occurs, THE Prover_System SHALL detect partition and abort protocol with error

6. WHEN message is lost, THE Prover_System SHALL retransmit after timeout up to maximum retry count

7. WHEN Byzantine prover is present, THE Prover_System SHALL detect invalid messages and abort (assuming honest majority)

### Requirement 29: Configuration and Parameters

**User Story:** As a system administrator, I want configurable parameters, so that the system can be tuned for different environments.

#### Acceptance Criteria

1. WHEN security parameter is configured, THE Prover_System SHALL accept λ ∈ {128, 192, 256} bits

2. WHEN field is configured, THE Prover_System SHALL support BN254 scalar field and other pairing-friendly curves

3. WHEN prover count is configured, THE Prover_System SHALL accept M ∈ {2, 4, 8, 16, 32, ...} as power of 2

4. WHEN circuit size is configured, THE Prover_System SHALL accept N ∈ {2^10, 2^11, ..., 2^30} as power of 2

5. WHEN timeout is configured, THE Prover_System SHALL accept timeout values in milliseconds for network operations

6. WHEN retry count is configured, THE Prover_System SHALL accept maximum retry count for failed operations

7. WHEN logging level is configured, THE Prover_System SHALL support levels {ERROR, WARN, INFO, DEBUG, TRACE}

8. WHEN network addresses are configured, THE Prover_System SHALL accept IP:port pairs for each prover

9. WHEN polynomial commitment scheme is configured, THE Prover_System SHALL support SamaritanPCS and other compatible schemes

10. WHEN optimization flags are configured, THE Prover_System SHALL support enabling/disabling specific optimizations

### Requirement 30: Logging and Monitoring

**User Story:** As a system operator, I want comprehensive logging and monitoring, so that the system behavior can be observed and debugged.

#### Acceptance Criteria

1. WHEN protocol starts, THE Prover_System SHALL log configuration parameters and prover assignments

2. WHEN each round completes, THE Prover_System SHALL log round number, timing, and data sizes

3. WHEN error occurs, THE Prover_System SHALL log error message, stack trace, and system state

4. WHEN performance metrics are collected, THE Prover_System SHALL log prover time, communication time, and verification time

5. WHEN memory usage is monitored, THE Prover_System SHALL log current and peak memory usage

6. WHEN network activity is monitored, THE Prover_System SHALL log bytes sent/received per prover

7. WHEN verification fails, THE Prover_System SHALL log detailed information about failure point

8. WHEN protocol completes successfully, THE Prover_System SHALL log summary statistics and final proof size

### Requirement 31: Specific Mathematical Formulations

**User Story:** As a cryptographic implementer, I want exact mathematical formulations implemented, so that the system matches the paper specification precisely.

#### Acceptance Criteria

1. WHEN eq function is computed, THE Prover_System SHALL implement eq(x,X) = ∏^μ_{i=1}(x_iX_i + (1-x_i)(1-X_i)) exactly as specified

2. WHEN multilinear extension is computed, THE Prover_System SHALL implement f̃(X) = ∑_{x∈B^μ} f(x) · eq(x,X) exactly as specified

3. WHEN virtual polynomial is computed, THE Prover_System SHALL implement f̃(X) := f(q(⟨0⟩_{ν_q},X),...,q(⟨ℓ_q-1⟩_{ν_q},X), w(⟨0⟩_{ν_w},X),...,w(⟨ℓ_w-1⟩_{ν_w},X)) exactly as specified

4. WHEN interpolation polynomial is computed, THE Prover_System SHALL implement f_j(b,x) = ∑_{i∈[M]} eq(b,⟨i⟩_ν) · w_{i,j}(x) exactly as specified

5. WHEN sum-check polynomial is computed, THE Prover_System SHALL implement Q(b) = eq(ρ,b) · (∑_{x∈B^μ} h(f₀(b,x),...,f_{t-1}(b,x))) exactly as specified

6. WHEN aggregated sum is computed, THE Prover_System SHALL implement T₀ = ∑_{i∈[M]} eq(ρ,⟨i⟩_ν) · v_i exactly as specified

7. WHEN folded witness is computed, THE Prover_System SHALL implement w'_j = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · w_{i,j} exactly as specified

8. WHEN folded value is computed, THE Prover_System SHALL implement v' = c · eq(ρ,r_b)^{-1} exactly as specified

9. WHEN partial polynomial is computed, THE Prover_System SHALL implement e_k^{(s)}(X) = (1-X) · eq(ρ,{r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k}) + X · eq(ρ,{r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k}) exactly as specified

10. WHEN witness interpolation is computed, THE Prover_System SHALL implement f_{k,x}^{(s,j)}(X) = (1-X) · f_j({r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k},x) + X · f_j({r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k},x) exactly as specified

11. WHEN identity polynomial is computed, THE Prover_System SHALL implement f_id = s_id + α · w + β exactly as specified

12. WHEN permutation polynomial is computed, THE Prover_System SHALL implement f_σ = s_σ + α · w + β exactly as specified

13. WHEN accumulator polynomial is computed, THE Prover_System SHALL implement v(0,x) = f_id(x)/f_σ(x) and v(1,x) = v(x,0) · v(x,1) exactly as specified

14. WHEN constraint polynomial is computed, THE Prover_System SHALL implement ĝ(x₀,x) = (1-x₀) · (v(1,x) - v(x,0) · v(x,1)) + x₀ · (f_σ(x) · v(0,x) - f_id(x)) exactly as specified

### Requirement 32: Protocol State Machine

**User Story:** As a protocol engineer, I want well-defined state machine for protocol execution, so that the implementation is correct and maintainable.

#### Acceptance Criteria

1. WHEN protocol initializes, THE Prover_System SHALL enter INIT state and generate public parameters

2. WHEN indexing is performed, THE Prover_System SHALL transition to INDEXED state with structure and keys

3. WHEN witness is provided, THE Prover_System SHALL transition to READY state with instance-witness pairs

4. WHEN protocol executes, THE Prover_System SHALL transition through states {ROUND_1, ROUND_2, ..., ROUND_ν} for folding

5. WHEN folding completes, THE Prover_System SHALL transition to FOLDED state with single instance

6. WHEN sum-check executes, THE Prover_System SHALL transition through states {SUMCHECK_1, ..., SUMCHECK_μ}

7. WHEN verification succeeds, THE Prover_System SHALL transition to ACCEPTED state

8. WHEN verification fails, THE Prover_System SHALL transition to REJECTED state

9. WHEN error occurs, THE Prover_System SHALL transition to ERROR state with error information

10. WHEN state transition is invalid, THE Prover_System SHALL reject transition and output error

### Requirement 33: Serialization and Deserialization

**User Story:** As a network protocol implementer, I want efficient serialization, so that messages are transmitted compactly.

#### Acceptance Criteria

1. WHEN field element is serialized, THE Prover_System SHALL encode in ⌈log₂|F|⌉ bits

2. WHEN group element is serialized, THE Prover_System SHALL use compressed point encoding

3. WHEN polynomial is serialized, THE Prover_System SHALL encode coefficients sequentially

4. WHEN commitment is serialized, THE Prover_System SHALL encode as single group element

5. WHEN proof is serialized, THE Prover_System SHALL encode all components in canonical order

6. WHEN deserialization is performed, THE Prover_System SHALL validate all values are in correct range

7. WHEN deserialization fails, THE Prover_System SHALL return error without partial state modification

### Requirement 34: Concrete Protocol Instantiation

**User Story:** As a system integrator, I want concrete instantiation with specific parameters, so that the system can be deployed in practice.

#### Acceptance Criteria

1. WHEN BN254 curve is used, THE Prover_System SHALL use scalar field F_r where r = 21888242871839275222246405745257275088548364400416034343698204186575808495617

2. WHEN security level is 128 bits, THE Prover_System SHALL ensure |F| ≥ 2^128

3. WHEN hash function is instantiated, THE Prover_System SHALL use SHA-256 or BLAKE2 for Fiat-Shamir

4. WHEN commitment scheme is instantiated, THE Prover_System SHALL use SamaritanPCS with BN254 curve

5. WHEN circuit is instantiated, THE Prover_System SHALL support vanilla Plonk gates with degree d ≤ 3

6. WHEN prover count is instantiated, THE Prover_System SHALL support M ∈ {2, 4, 8} for practical deployments

7. WHEN circuit size is instantiated, THE Prover_System SHALL support N ∈ {2^18, 2^19, 2^20, 2^21, 2^22} for benchmarks

### Requirement 35: Compatibility and Interoperability

**User Story:** As an ecosystem developer, I want compatibility with existing tools, so that the system integrates with broader infrastructure.

#### Acceptance Criteria

1. WHEN circuit is provided, THE Prover_System SHALL accept circuits in R1CS or Plonk format

2. WHEN witness is provided, THE Prover_System SHALL accept witness in standard JSON or binary format

3. WHEN proof is generated, THE Prover_System SHALL output proof in standard serialization format

4. WHEN verification is performed, THE Prover_System SHALL accept proofs from compatible implementations

5. WHEN public parameters are shared, THE Prover_System SHALL use standard ceremony format for trusted setup (if required)

6. WHEN integration with blockchain is required, THE Prover_System SHALL support Ethereum-compatible proof format

7. WHEN integration with other SNARKs is required, THE Prover_System SHALL support proof composition via recursive verification

### Requirement 36: Documentation Requirements

**User Story:** As a developer using the system, I want comprehensive documentation, so that I can understand and use the implementation correctly.

#### Acceptance Criteria

1. WHEN API is documented, THE Prover_System SHALL provide rustdoc comments for all public functions

2. WHEN protocol is documented, THE Prover_System SHALL provide detailed description of each protocol step

3. WHEN examples are provided, THE Prover_System SHALL include working examples for common use cases

4. WHEN performance is documented, THE Prover_System SHALL provide benchmark results and comparison tables

5. WHEN security is documented, THE Prover_System SHALL provide security analysis and assumptions

6. WHEN deployment is documented, THE Prover_System SHALL provide setup and configuration guide

7. WHEN troubleshooting is documented, THE Prover_System SHALL provide common issues and solutions

### Requirement 37: Specific Algorithm Implementations

**User Story:** As an algorithm implementer, I want specific algorithms from the paper implemented exactly, so that correctness is guaranteed.

#### Acceptance Criteria

1. WHEN Algorithm 1 is implemented, THE Prover_System SHALL compute h(X) = ∏ᵢ₌₁ᵈ gᵢ(X) using binary tree multiplication with FFT

2. WHEN Protocol 3.1 (SumFold) is implemented, THE Prover_System SHALL follow all 3 steps exactly as specified

3. WHEN Protocol 3.2 (Distributed SumFold) is implemented, THE Prover_System SHALL follow all 6 steps exactly as specified

4. WHEN Protocol 4.2 (Distributed Consistency Check) is implemented, THE Prover_System SHALL follow all 2 steps exactly as specified

5. WHEN Protocol 4.3 (Complete Distributed SNARK) is implemented, THE Prover_System SHALL follow all 6 steps exactly as specified

6. WHEN Protocol D.1 (Zerocheck Reduction) is implemented, THE Prover_System SHALL follow all 2 steps exactly as specified

7. WHEN Protocol D.2 (Permutation Check Reduction) is implemented, THE Prover_System SHALL follow all 5 steps exactly as specified

8. WHEN Protocol B (HyperPlonk PIOP) is implemented, THE Prover_System SHALL follow all 4 steps exactly as specified

### Requirement 38: Numerical Precision and Field Arithmetic

**User Story:** As a numerical computing specialist, I want correct field arithmetic, so that all computations are mathematically sound.

#### Acceptance Criteria

1. WHEN field addition is performed, THE Prover_System SHALL compute (a + b) mod p correctly

2. WHEN field subtraction is performed, THE Prover_System SHALL compute (a - b) mod p correctly handling negative results

3. WHEN field multiplication is performed, THE Prover_System SHALL compute (a · b) mod p correctly

4. WHEN field division is performed, THE Prover_System SHALL compute a · b^{-1} mod p using extended Euclidean algorithm or Fermat's little theorem

5. WHEN field inversion is performed, THE Prover_System SHALL compute a^{-1} mod p correctly, returning error if a = 0

6. WHEN field exponentiation is performed, THE Prover_System SHALL compute a^k mod p using square-and-multiply algorithm

7. WHEN batch inversion is performed, THE Prover_System SHALL compute {a_i^{-1}}_{i∈[n]} using Montgomery's trick in O(n) multiplications

8. WHEN overflow is prevented, THE Prover_System SHALL use appropriate integer types (u256, u512) for intermediate computations

### Requirement 39: Group Operations and Elliptic Curves

**User Story:** As an elliptic curve cryptography implementer, I want correct group operations, so that commitments and proofs are valid.

#### Acceptance Criteria

1. WHEN point addition is performed, THE Prover_System SHALL compute P + Q on elliptic curve correctly

2. WHEN point doubling is performed, THE Prover_System SHALL compute 2P correctly

3. WHEN scalar multiplication is performed, THE Prover_System SHALL compute kP using double-and-add or windowed method

4. WHEN multi-scalar multiplication is performed, THE Prover_System SHALL compute ∑ᵢ kᵢPᵢ using Pippenger's algorithm for efficiency

5. WHEN point compression is performed, THE Prover_System SHALL encode point using x-coordinate and sign bit

6. WHEN point decompression is performed, THE Prover_System SHALL recover y-coordinate from x and verify point is on curve

7. WHEN pairing is computed, THE Prover_System SHALL compute e(P,Q) using optimal ate pairing for BN254

8. WHEN point is validated, THE Prover_System SHALL verify point is on curve and in correct subgroup

### Requirement 40: Specific Complexity Analysis

**User Story:** As a complexity theorist, I want precise complexity analysis, so that performance can be predicted accurately.

#### Acceptance Criteria

1. WHEN prover time is analyzed for P_i (i ≠ 0), THE Prover_System SHALL achieve exactly O(T)F + O(T)G where T = N/M, F = field operation, G = group operation

2. WHEN prover time is analyzed for P₀, THE Prover_System SHALL achieve exactly O(T)F + O(T)G + O(M)G

3. WHEN communication is analyzed, THE Prover_System SHALL achieve exactly O(N)|F| + O(M)|G| where |F| = field element size, |G| = group element size

4. WHEN proof size is analyzed, THE Prover_System SHALL achieve exactly O(log N)|F| + O(1)|G|

5. WHEN verifier time is analyzed, THE Prover_System SHALL achieve exactly O(log N)F + O(M)G + O(1)P where P = pairing operation

6. WHEN round complexity is analyzed, THE Prover_System SHALL achieve exactly ν + μ rounds where ν = log M, μ = log T

7. WHEN concrete constants are measured, THE Prover_System SHALL document hidden constants in O-notation for practical estimation

### Requirement 41: Relation Definitions

**User Story:** As a formal methods engineer, I want precise relation definitions, so that correctness can be formally verified.

#### Acceptance Criteria

1. WHEN R_HSUM is defined, THE Prover_System SHALL accept exactly tuples (s; x; w) = (h; (v, [[w₀]],...,[[w_{t-1}]]); (w₀,...,w_{t-1})) where ∑_{x∈B^μ} h(w₀(x),...,w_{t-1}(x)) = v, h ∈ F^{(≤d)}_t, w₀,...,w_{t-1} ∈ F^{(≤1)}_μ

2. WHEN R_ZERO is defined, THE Prover_System SHALL accept exactly tuples (x; w) = ([[f]]; f) where f ∈ F^{(≤d)}_μ and f(x) = 0 for all x ∈ B^μ

3. WHEN R_PERM is defined, THE Prover_System SHALL accept exactly tuples (i; x; w) = (σ; ([[f]], [[g]]); (f, g)) where σ : B^μ → B^μ is permutation, f, g ∈ F^{(≤d)}_μ, and g(x) = f(σ(x)) for all x ∈ B^μ

4. WHEN R_CON is defined, THE Prover_System SHALL accept exactly tuples (x; w) = ((p, [[w]]); w) where p ∈ F^{(≤1)}_{ν_p}, w ∈ F^{(≤1)}_μ, and p(X) = w(0^{μ-ν_p},X)

5. WHEN R_HP (HyperPlonk relation) is defined, THE Prover_System SHALL accept exactly tuples (i; x, w) = ((q, σ); (p, [[w]]), w) satisfying gate identity, wire identity, and consistency check

6. WHEN relation product is defined, THE Prover_System SHALL compute R₁ × R₂ = {(pp, s, (u₁, u₂), (w₁, w₂)) | (pp, s, u₁, w₁) ∈ R₁, (pp, s, u₂, w₂) ∈ R₂} exactly

7. WHEN R^n is defined, THE Prover_System SHALL compute R × ... × R (n times) exactly

### Requirement 42: Extractor Construction

**User Story:** As a security proof engineer, I want explicit extractor construction, so that knowledge soundness can be proven.

#### Acceptance Criteria

1. WHEN extractor E is constructed for sum-check, THE Prover_System SHALL extract witness by rewinding prover at each round and obtaining polynomial coefficients

2. WHEN extractor E is constructed for folding, THE Prover_System SHALL extract witnesses {w_i}_{i∈[M]} from folded witness w' by inverting linear combination

3. WHEN extractor E is constructed for commitment, THE Prover_System SHALL extract polynomial f from commitment com_f by rewinding opening protocol

4. WHEN extractor E is constructed for complete protocol, THE Prover_System SHALL compose extractors using sequential and parallel composition rules

5. WHEN extraction probability is analyzed, THE Prover_System SHALL ensure Pr[E succeeds | prover succeeds] ≥ 1 - negl(λ)

6. WHEN extraction time is analyzed, THE Prover_System SHALL ensure E runs in expected polynomial time

7. WHEN extracted witness is verified, THE Prover_System SHALL ensure (pp, s, u, w) ∈ R where w ← E^{A₁,A₂}(pp, s, u)

### Requirement 43: Simulator Construction (if Zero-Knowledge)

**User Story:** As a zero-knowledge proof engineer, I want simulator construction, so that zero-knowledge property can be proven if required.

#### Acceptance Criteria

1. WHEN simulator S is constructed, THE Prover_System SHALL generate transcripts without witness

2. WHEN simulator S generates challenges, THE Prover_System SHALL program random oracle to ensure consistency

3. WHEN simulator S generates prover messages, THE Prover_System SHALL compute messages that pass verification

4. WHEN indistinguishability is verified, THE Prover_System SHALL ensure real and simulated transcripts are computationally indistinguishable

5. WHEN simulator time is analyzed, THE Prover_System SHALL ensure S runs in expected polynomial time

6. WHEN zero-knowledge is not required, THE Prover_System SHALL document that protocol is not zero-knowledge

### Requirement 44: Concrete Security Parameters

**User Story:** As a security engineer, I want concrete security parameters, so that the system achieves target security level.

#### Acceptance Criteria

1. WHEN λ = 128 is required, THE Prover_System SHALL use field with |F| ≥ 2^128

2. WHEN λ = 128 is required, THE Prover_System SHALL use elliptic curve with group order ≥ 2^256

3. WHEN λ = 128 is required, THE Prover_System SHALL use hash function with output ≥ 256 bits

4. WHEN soundness error is computed, THE Prover_System SHALL ensure total error ≤ 2^{-λ}

5. WHEN knowledge error is computed for sum-check, THE Prover_System SHALL ensure error ≤ dμ/|F| ≤ 2^{-λ}

6. WHEN knowledge error is computed for folding, THE Prover_System SHALL ensure error ≤ dν/|F| ≤ 2^{-λ}

7. WHEN commitment binding is analyzed, THE Prover_System SHALL ensure binding error ≤ 2^{-λ}

### Requirement 45: Network Protocol Specification

**User Story:** As a network engineer, I want detailed network protocol, so that distributed communication is reliable.

#### Acceptance Criteria

1. WHEN connection is established, THE Prover_System SHALL use TCP for reliable message delivery

2. WHEN message format is defined, THE Prover_System SHALL use length-prefixed encoding: [4-byte length][message data]

3. WHEN message types are defined, THE Prover_System SHALL support types {CHALLENGE, PARTIAL_POLY, COMMITMENT, WITNESS_SHARE, FINAL_PROOF}

4. WHEN message is sent, THE Prover_System SHALL include sequence number for ordering

5. WHEN message is received, THE Prover_System SHALL verify sequence number and checksum

6. WHEN timeout occurs, THE Prover_System SHALL retry transmission up to 3 times with exponential backoff

7. WHEN connection fails, THE Prover_System SHALL attempt reconnection up to 3 times before aborting

8. WHEN bandwidth is limited, THE Prover_System SHALL implement flow control to avoid congestion

### Requirement 46: Specific Theorem and Lemma Implementations

**User Story:** As a formal verification engineer, I want all theorems and lemmas from the paper implemented with proofs, so that correctness is guaranteed.

#### Acceptance Criteria

1. WHEN Definition 1 (Interactive Argument of Knowledge) is implemented, THE Prover_System SHALL satisfy completeness and δ-knowledge soundness properties exactly as defined

2. WHEN Definition 2 (Polynomial Commitment Scheme) is implemented, THE Prover_System SHALL satisfy completeness and knowledge soundness properties exactly as defined

3. WHEN Definition 3 (PIOP) is implemented, THE Prover_System SHALL support polynomial oracles with query interface exactly as defined

4. WHEN Definition 4 (Relation Product) is implemented, THE Prover_System SHALL compute R₁ × R₂ exactly as defined

5. WHEN Definition 5 (Folding Scheme) is implemented, THE Prover_System SHALL implement RoK from R^n to R exactly as defined

6. WHEN Definition 6 (Multilinear Extension) is implemented, THE Prover_System SHALL compute unique f̃ exactly as defined

7. WHEN Definition 7 (Sum-check Relation) is implemented, THE Prover_System SHALL accept R_HSUM exactly as defined

8. WHEN Definition 8 (HyperPlonk Constraint System) is implemented, THE Prover_System SHALL accept relation R exactly as defined

9. WHEN Definition 9 (Permutation Check Relation) is implemented, THE Prover_System SHALL accept R_PERM exactly as defined

10. WHEN Definition 10 (Zerocheck Relation) is implemented, THE Prover_System SHALL accept R_ZERO exactly as defined

11. WHEN Definition 11 (Consistency Check Relation) is implemented, THE Prover_System SHALL accept R_CON exactly as defined

12. WHEN Definition 12 (Reduction of Knowledge) is implemented, THE Prover_System SHALL satisfy perfect completeness, knowledge soundness, and public reducibility exactly as defined

### Requirement 47: Appendix Protocols Implementation

**User Story:** As a complete system implementer, I want all appendix protocols implemented, so that the full system is functional.

#### Acceptance Criteria

1. WHEN Protocol B (PIOP for HyperPlonk) is implemented, THE Prover_System SHALL execute indexer K and interactive protocol ⟨P,V⟩ exactly as specified

2. WHEN Protocol D.1 (Reduction from R_ZERO to R_HSUM) is implemented, THE Prover_System SHALL execute indexer K and interactive protocol ⟨P,V⟩ exactly as specified

3. WHEN Protocol D.2 (Reduction from R_PERM to R_HSUM) is implemented, THE Prover_System SHALL execute indexer K and interactive protocol ⟨P,V⟩ with all 5 steps exactly as specified

4. WHEN accumulator polynomial v is computed in Protocol D.2, THE Prover_System SHALL verify v(1,...,1,0) = 1 exactly as specified

5. WHEN constraint polynomial ĝ is computed in Protocol D.2, THE Prover_System SHALL query [[ĝ(0,·)]] or [[ĝ(1,·)]] exactly as specified

### Requirement 48: Comparison Table Implementation

**User Story:** As a benchmarking engineer, I want to reproduce Table 1 results, so that performance claims can be verified.

#### Acceptance Criteria

1. WHEN prover time is measured for our system, THE Prover_System SHALL achieve O(T)F + O(T)G matching Table 1

2. WHEN proof size is measured for our system, THE Prover_System SHALL achieve O(log N)|F| + O(1)|G| matching Table 1

3. WHEN verifier time is measured for our system, THE Prover_System SHALL achieve O(log N)F + O(M)G + O(1)P matching Table 1

4. WHEN communication is measured for our system, THE Prover_System SHALL achieve O(N)|F| + O(M)|G| matching Table 1

5. WHEN comparison with Cirrus is performed, THE Prover_System SHALL verify our proof size is smaller (O(1)|G| vs O(log N)|G|)

6. WHEN comparison with HyperPianist is performed, THE Prover_System SHALL verify our proof size is smaller (O(1)|G| vs O(log N)|G|)

7. WHEN comparison with HEKATON is performed, THE Prover_System SHALL verify our prover time is better (O(T)F vs O(T·log T)F)

8. WHEN comparison with Pianist/Soloist is performed, THE Prover_System SHALL verify our prover time is better (O(T)F vs O(T·log T)F)

9. WHEN comparison with deVirgo is performed, THE Prover_System SHALL verify our proof size is better (O(log N)|F| vs O(log² N + M²)|H|)

### Requirement 49: Experimental Results Reproduction

**User Story:** As a validation engineer, I want to reproduce Figure 1 and Table 2 results, so that experimental claims can be verified.

#### Acceptance Criteria

1. WHEN experiments are run with 8 machines, THE Prover_System SHALL achieve 4.1× to 4.9× speedup over HyperPianist for circuits 2^18 to 2^22

2. WHEN proof size is measured with 8 machines, THE Prover_System SHALL achieve 8.5-9.9 KB for circuits 2^18 to 2^22

3. WHEN verifier time is measured with 8 machines, THE Prover_System SHALL achieve 4.05-5.08 ms for circuits 2^18 to 2^22

4. WHEN comparison with HyperPianist proof size is performed, THE Prover_System SHALL verify our proof is smaller (8.5-9.9 KB vs 8.9-10.7 KB)

5. WHEN comparison with HyperPianist verifier time is performed, THE Prover_System SHALL verify our time is within 1.4-1.8× factor (4.05-5.08 ms vs 3.20-3.44 ms)

6. WHEN hardware is specified, THE Prover_System SHALL document experiments on 2023 Apple MacBook Pro M3 Max (14 cores, 36GB RAM)

7. WHEN software is specified, THE Prover_System SHALL document implementation using Rust arkworks ecosystem with BN254 curve

### Requirement 50: Related Work Integration

**User Story:** As a research engineer, I want to understand relationship to related work, so that the system can be positioned correctly.

#### Acceptance Criteria

1. WHEN compared to DIZK, THE Prover_System SHALL document that our system eliminates FFT operations and achieves linear prover time

2. WHEN compared to deVirgo, THE Prover_System SHALL document that our system achieves better proof size and uses pairing-based PCS instead of FRI

3. WHEN compared to Pianist, THE Prover_System SHALL document that our system achieves linear prover time vs quasi-linear

4. WHEN compared to HyperPianist/Cirrus, THE Prover_System SHALL document that our system uses folding to reduce opening phase computation

5. WHEN compared to Soloist, THE Prover_System SHALL document that our system uses HyperPlonk constraint system vs R1CS

6. WHEN compared to HEKATON, THE Prover_System SHALL document that our system achieves linear prover time vs quasi-linear

7. WHEN compared to FRIttata/HyperFond, THE Prover_System SHALL document that our system uses pairing-based PCS vs code-based PCS

8. WHEN compared to Nova/SuperNova/HyperNova, THE Prover_System SHALL document that our system focuses on distributed proving vs recursive proving

9. WHEN compared to Mangrove, THE Prover_System SHALL document that our system uses distributed folding vs PCD-based chunking

### Requirement 51: Future Extensions and Optimizations

**User Story:** As a system architect, I want to identify future extensions, so that the system can evolve.

#### Acceptance Criteria

1. WHEN zero-knowledge is required, THE Prover_System SHALL support extension to zero-knowledge variant using standard techniques

2. WHEN post-quantum security is required, THE Prover_System SHALL support extension to lattice-based polynomial commitments

3. WHEN recursive composition is required, THE Prover_System SHALL support extension to IVC/PCD using folding schemes

4. WHEN non-uniform circuits are required, THE Prover_System SHALL support extension to handle different subcircuit structures

5. WHEN dynamic prover sets are required, THE Prover_System SHALL support extension to handle provers joining/leaving

6. WHEN malicious provers are considered, THE Prover_System SHALL support extension to Byzantine fault tolerance

7. WHEN GPU acceleration is required, THE Prover_System SHALL support extension to GPU-based field arithmetic and MSM

## Summary

This requirements document specifies a complete distributed SNARK system based on folding schemes, implementing all mathematical formulations, protocols, and algorithms from the paper "Distributed SNARK via folding schemes" by Li et al. The system achieves:

- Linear prover time O(T) per prover where T = N/M
- Logarithmic proof size O(log N) field elements + O(1) group elements  
- Efficient verification O(log N) field operations + O(M) MSM + O(1) pairings
- 4.1-4.9× speedup over HyperPianist with 8 machines
- Smaller proof size than existing distributed SNARKs

All requirements follow EARS patterns and INCOSE quality rules, with precise mathematical specifications, complexity bounds, security properties, and implementation details.
