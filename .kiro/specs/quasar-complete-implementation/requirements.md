# Quasar: Sublinear Accumulation Schemes for Multiple Instances - Complete Implementation Requirements

## Introduction

This specification captures the complete mathematical formulations, algorithms, and technical details from the Quasar paper without any omission or simplification. The implementation will provide a multi-instance IVC (Incrementally Verifiable Computation) with sublinear accumulation verifier complexity.

## Glossary

### Core Concepts

- **IVC (Incrementally Verifiable Computation)**: A cryptographic primitive supporting sequential computations with efficient verification at any point
- **PCD (Proof-Carrying Data)**: Generalization of IVC to directed acyclic graphs
- **SNARK (Succinct Non-interactive ARgument of Knowledge)**: Cryptographic primitive for efficient verification of computations
- **NARK (Non-interactive ARgument of Knowledge)**: Similar to SNARK but without succinctness requirement
- **Accumulation Scheme**: Primitive enabling efficient accumulation of predicate instances into running accumulator, deferring verification
- **CRC (Commitments Random linear Combination)**: Operation computing C := r₁ · C₁ + r₂ · C₂
- **PCS (Polynomial Commitment Scheme)**: Scheme for committing to polynomials with evaluation proofs
- **IOR (Interactive Oracle Reduction)**: Information-theoretic proof system generalizing IOPs to reduction language
- **NIR (Non-interactive Reduction)**: Non-interactive version of IOR obtained via Fiat-Shamir transform
- **SPS (Special-Sound Protocol)**: Interactive proof with special soundness property
- **RBR (Round-By-Round)**: Knowledge soundness property ensuring security against state-restoration attacks

### Mathematical Notation

- **F**: Finite field (e.g., prime field for large prime p)
- **λ**: Security parameter
- **negl(λ)**: Negligible function in λ
- **ℓ**: Number of predicate instances accumulated at each step
- **N**: Total number of instances in IVC
- **µ**: Number of rounds in special-sound protocol
- **d**: Maximum degree of algebraic map/relation
- **n**: Witness/polynomial size (assumed power of 2)
- **m**: Instance length
- **ρ**: Code rate for linear codes
- **[n]**: Set {0, ..., n-1} ⊆ ℕ
- **Blog n**: Boolean hypercube {0,1}^(log n)
- **Bits(i)**: Binary representation of integer i
- **F^(<d)[X]**: Multilinear polynomials over F with variables X
- **eq̃ᵢ(X)**: Multilinear equality polynomial
- **f̃(X)**: Multilinear extension of vector f
- **RO**: Random Oracle
- **pp**: Public parameters


## Requirements

### Requirement 1: Multi-Instance IVC Core Functionality

**User Story:** As a zkVM developer, I want to implement a multi-instance IVC that can accumulate ℓ predicate instances and one accumulator at each step, so that I can achieve better trade-offs between recursion overhead and number of recursive steps.

#### Acceptance Criteria

1. **Definition 1 Implementation**: THE system SHALL implement Multi-instance IVC as tuple (IVC.P, IVC.V) WHERE:
   - IVC.P(z₀, zᵢ, wᵢ, zᵢ₊₁, Πᵢ) → Πᵢ₊₁ takes initial vector z₀ ∈ F^ℓ, vector zᵢ ∈ F^ℓ output by ℓ predicate functions at step i-1, witness wᵢ ∈ F^ℓ, expected outputs zᵢ₊₁ ∈ F^ℓ at step i, IVC proof Πᵢ, outputs new proof Πᵢ₊₁
   - IVC.V(z₀, zᵢ₊₁, Πᵢ₊₁) → b takes initial vector z₀ ∈ F^ℓ, vector zᵢ₊₁ ∈ F^ℓ output at step i, IVC proof Πᵢ₊₁, outputs 1 for accept or 0 for reject

2. **Completeness Property**: WHEN honest prover generates proof Πᵢ₊₁ from valid inputs, THEN IVC.V SHALL output 1 with probability 1

3. **Knowledge Soundness**: IF malicious prover P̃ generates accepting proof, THEN extractor E SHALL extract valid witness with probability ≥ 1 - negl(λ)

4. **Recursion Overhead**: THE total recursive circuits for all steps SHALL contain quasi-linear O(√N) CRC operations WHERE N is total instance number

5. **Per-Step Complexity**: THE recursive circuit at each step SHALL include O(ℓ) field operations AND O(1) CRC operations

### Requirement 2: Multi-Instance Accumulation Scheme

**User Story:** As a cryptographic protocol designer, I want to implement a multi-instance accumulation scheme with sublinear verifier complexity, so that I can minimize recursion overhead in IVC constructions.

#### Acceptance Criteria

1. **Definition 2 Implementation**: THE system SHALL implement accumulation scheme ACC = (ACC.P, ACC.V, ACC.D) WHERE:
   - ACC.P({xₖ}ₖ∈[ℓ], π, acc) → (acc', pf) takes multi-predicate tuple ({xₖ}ₖ∈[ℓ], π) with NARK proof π, old accumulator acc, outputs new accumulator acc' with proof pf
   - ACC.V({xₖ}ₖ∈[ℓ], π.x, acc.x) → b takes multi-predicate instance ({xₖ}ₖ∈[ℓ], π.x), accumulator instance acc.x, outputs 1 for accept or 0 for reject
   - ACC.D(acc) → b takes accumulator acc, outputs 1 for accept or 0 for reject

2. **Sublinear Verifier Complexity**: THE accumulation verifier complexity SHALL be sublinear in ℓ (number of accumulated instances)

3. **Completeness**: WHEN NARK.V^RO(vk, {x^(k)}ₖ, π) = 1 AND ACC.D(adk, acc) = 1, THEN ACC.V^RO(avk, {x^(k)}ₖ, π.x, acc.x, acc'.x, pf) = 1 AND ACC.D(adk, acc') = 1 with probability 1

4. **Knowledge Soundness**: FOR every non-uniform polynomial-time malicious prover P̃, THERE SHALL exist polynomial-time extractor E such that Pr[E₁|E₂] ≥ 1 - negl(λ) WHERE E₁ represents valid verification AND E₂ represents adversary execution


### Requirement 3: Multi-Cast Reduction (IORcast)

**User Story:** As a protocol implementer, I want to implement the multi-cast reduction that batches ℓ predicate instances into one committed instance with minimal CRC operations, so that I can achieve efficient accumulation.

#### Acceptance Criteria

1. **Union Polynomial Construction**: THE prover SHALL compute union multilinear polynomial w̃∪(Y, X) := Σₖ∈[ℓ] eq̃(Bits(k), Y) · Σᵢ∈[n] eq̃(Bits(i), X) · wₖ[i] ∈ F^(<2)[Y||X]

2. **Partial Evaluation**: THE prover SHALL compute w̃(X) := w̃∪(τ, X) WHERE τ ∈ F^(log ℓ) is verifier challenge, AND w̃(X) SHALL equal multilinear extension of accumulated witness w := Σₖ∈[ℓ] eq̃(Bits(k), τ) · wₖ

3. **Equation 1 Verification**: THE verifier SHALL verify w̃∪(τ, rₓ) = w̃(rₓ) at random rₓ ∈ F^(log n) with soundness error ≤ log n/|F|

4. **Reduced Relation**: THE reduced relation Rₐcc^cm(pp) SHALL be {(C∪, C, τ, rₓ; w̃∪(Y,X), w̃(X)) : C∪ = Commit(pp, w̃∪(Y,X)) ∧ C = Commit(pp, w̃(X)) ∧ w̃∪(τ, rₓ) = w̃(rₓ)}

5. **Constant Commitments**: THE reduced relation SHALL contain constant number of commitments independent of ℓ

6. **Instance Batching**: THE system SHALL apply same technique to instances {x^(k)}ₖ∈ℓ to check x̃∪(τ, rₓ) = x̃(rₓ) WHERE x̃ is multilinear extension of accumulated instance vector

7. **Zero-Check Reduction**: FOR constraint F(x, w) = 0, THE prover SHALL compute G(Y) := F(x̃(Y), w̃(Y)) · eq̃(Y, rᵧ) WHERE:
   - x̃(Y) := Σᵢ∈[ℓ] eq̃ᵢ₋₁(Y) · x^(i) ∈ (F^(<2)_log n)^m (Equation 6)
   - w̃(Y) := Σᵢ∈[ℓ] eq̃ᵢ₋₁(Y) · w^(i) ∈ (F^(<2)_log n)^n (Equation 7)
   - G(Y) satisfies Σᵧ∈B_log ℓ G(y) = 0 (Equation 8)

8. **Sum-Check Protocol**: THE system SHALL execute log ℓ-round sum-check protocol for Σᵧ∈B_log ℓ G(y) = 0 WHERE:
   - Prover sends log ℓ sumcheck polynomials
   - Verifier replies with random vector τ ∈ F^(log ℓ)
   - Final evaluation claim: G_log ℓ(τ_log ℓ) = G(τ) = F(x̃(τ), w̃(τ)) · eq̃(τ, rᵧ)

9. **Constraint Equivalence**: THE final constraint SHALL be F(x, w) = e WHERE:
   - x = x̃(τ) (batched instance)
   - w = w̃(τ) (batched witness)
   - e = G_log ℓ(τ_log ℓ) · eq̃⁻¹(τ, rᵧ) (Equation 9)

10. **Lemma 3 Complexity**: THE protocol IORcast SHALL satisfy:
    - log ℓ + 2 rounds
    - Proof length: d log ℓ field elements for sum-check, ℓn + n field elements for oracles
    - Verifier makes no polynomial queries
    - Verifier time dominated by O(ℓ · n) field operations
    - Reduced relation contains exactly 2 polynomial oracles

11. **Corollary 1 Properties**: THE multilinear equality polynomial eq̃ᵢ(b) over B_log ℓ SHALL satisfy:
    - (eq̃ᵢ(b))^d = eq̃ᵢ(b) for all d ∈ ℕ and b ∈ B_log ℓ
    - eq̃ᵢ(b) · eq̃ⱼ(b) = 0 if and only if i ≠ j ∈ [ℓ] for all b ∈ B_log ℓ


### Requirement 4: Special-Sound Protocol Integration (CV[Πsps])

**User Story:** As a protocol designer, I want to integrate special-sound protocols with multi-cast reductions, so that I can support wide range of constraint systems including Plonkish relations.

#### Acceptance Criteria

1. **Definition 20 Compliance**: THE system SHALL implement (2µ-1)-move special-sound protocol Πsps for relation R with verifier degree d, output length m, algorithms (Psps, Vsps)

2. **Verifier Algebraic Map**: THE verifier Vsps SHALL be algebraic map with maximum degree d written as Vsps(x, {mᵢ}ᵢ∈[µ], r) := Σⱼ₌₀^d fⱼ^Vsps(x, {mᵢ}ᵢ∈[µ], r) = 0ᵥ (Equation 13) WHERE each fⱼ^Vsps is homogeneous degree-j algebraic map

3. **Power Vector Computation**: THE prover SHALL compute α := (α, α², α⁴, ..., α^(2^(log ν-1))) WHERE α := rµ AND ν is power of 2

4. **Power Polynomial**: FOR j ∈ [ν], LET S ⊂ {0, ..., log ν - 1} be set such that j = Σₖ∈S 2^k + 1, THEN αʲ = powⱼ(α) WHERE powⱼ(X) = Πₖ∈S Xₖ

5. **Equation 14 Linearly Combined Map**: THE system SHALL compute F(x, {mᵢ}ᵢ∈[µ], r, α) = Σⱼ∈[ν] powⱼ(α) · Vsps(x, {mᵢ}µᵢ₌₁, r)[j] = 0 with degree D = d + log ν

6. **Lemma 4 Special Soundness**: IF (2µ+1)-move protocol Πsps is (k₀, ..., kµ₋₁)-special-sound for R, THEN (2µ+3)-move transformed protocol CV[Πsps] SHALL be (k₀, ..., kµ₋₁, ν+1)-special-sound for R

7. **Relation Rsps**: THE transformed protocol SHALL satisfy relation Rsps = {(i, x = (x, r, α), y = ⊥, w = {mᵢ}ᵢ∈[µ]) : F(x, {mᵢ}ᵢ∈[µ], r, α) = 0 ∧ α₀ = α ∧ αᵢ₊₁ = αᵢ² ∀i ∈ [log ν - 1]}

8. **Multi-Instance Application**: FOR tuple (i, {x^(k), y^(k), w^(k)}ₖ∈[ℓ]) satisfying Rℓ, THE system SHALL:
   - Execute CV[Πsps] for each tuple (i, x^(k), y^(k), w^(k)), ∀k ∈ [ℓ]
   - Apply multi-cast reduction IORcast from Rℓsps to Racc

9. **Interleaved Protocol Optimization**: THE system SHALL interleave SPS protocol and multi-cast reduction by:
   - For each round i ∈ [µ]: compute mᵢ^(k) ← Psps(x^(k), w^(k), {mⱼ^(k), rⱼ}ⱼ∈[i-1])
   - Compute m̃∪,ᵢ(Y, X) := Σₖ∈[ℓ] eq̃ₖ₋₁(Y) · m̃ᵢ^(k)(X)
   - Send oracle [[m̃∪,ᵢ]] instead of O(ℓn)-sized messages

10. **Equation 15 Constraint**: FOR each k ∈ [ℓ], THE system SHALL ensure F(x^(k), {mᵢ^(k)}ᵢ∈[µ], rF) = 0 WHERE rF := r||α

11. **Reduced Relation Components**: THE reduced instance SHALL satisfy Racc = Rµeval × Rµeval × RF WHERE:
    - (i, x = (τ, rₓ, vᵢ), y = [[m̃∪,ᵢ]], w = ⊥) ∈ Reval ∀i ∈ [µ] (Equation 16)
    - (i, x = (rₓ, vᵢ), y = [[m̃ᵢ]], w = ⊥) ∈ Reval ∀i ∈ [µ] (Equation 17)
    - (i, x = (x, rF, e), y = ⊥, w = {mᵢ}ᵢ∈[µ]) ∈ RF (Equation 18)
    WHERE x = x̃(τ), mᵢ = m̃ᵢ(τ) ∀i ∈ [µ]

12. **Lemma 5 Complexity**: THE protocol IORcast SHALL have:
    - Proof length: 2µ elements for commitments, O(log ℓ) field elements for sum-check
    - RO query complexity: µ + log ℓ O(1)-sized queries, 1 O(log m) query, 1 O(µ + log ℓ) query, 1 O(ℓn) query
    - Verifier time dominated by O(ℓn) field computation
    - Reduced relation contains 2µ polynomial oracles


### Requirement 5: 2-to-1 Reduction (IORfold)

**User Story:** As a system architect, I want to implement the 2-to-1 reduction that folds two accumulator instances into one, so that I can complete the accumulation scheme construction.

#### Acceptance Criteria

1. **Definition 3 Oracle Batching**: THE system SHALL implement oracle batching protocol IORbatch^cm as reduction from R₀^cm to Reval^cm WHERE:
   - R₀^cm := {{Cᵢ, xᵢ, rᵢ}ᵢ₌₁², v; {p̃ᵢ(X)}ᵢ₌₁²} : Cᵢ = Commit(pp, p̃ᵢ(X)) ∀i = 1,2 ∧ r₁ · p̃₁(X) + r₂ · p̃₂(X) = v}
   - Reval^cm(pp) := {(C, {xᵢ, vᵢ}ᵢ; p̃(X)) : C = Commit(pp, p̃(X)) ∧ p̃(xᵢ) = vᵢ ∀i}

2. **Succinctness Property**: THE proof generated by IORbatch SHALL be sublinear to length of p̃ᵢ(X)'s

3. **Input Format**: THE 2-to-1 reduction SHALL take two instance-witness tuples (iₐcc, xₐcc^(k), yₐcc^(k), wₐcc^(k)) ∈ Rµeval × Rµeval × RF for k ∈ [1] WHERE:
   - xₐcc^(k) = (x^(k), τ^(k), rₓ^(k), rF^(k), e^(k), {vᵢ}ᵢ∈[µ]) (Equation 19)
   - yₐcc^(k) = ({[[m̃∪,ᵢ]], [[m̃ᵢ]]}ᵢ∈[µ]) (Equation 20)
   - wₐcc^(k) = {mᵢ^(k)}ᵢ∈[µ] (Equation 21)

4. **Batched Polynomials**: THE prover SHALL compute:
   - x̃(Z) = Σₖ∈[1] eq̃ₖ(Z) · x^(k) ∈ (F₁^(<2))^m (Equation 22)
   - r̃F(Z) = Σₖ∈[1] eq̃ₖ(Z) · rF^(k) ∈ (F₁^(<2))^(µ+log ν) (Equation 23)
   - τ̃(Z) = Σₖ∈[1] eq̃ₖ(Z) · τ^(k) ∈ (F₁^(<2))^(log ℓ) (Equation 24)
   - r̃ₓ(Z) = Σₖ∈[1] eq̃ₖ(Z) · rₓ^(k) ∈ (F₁^(<2))^(log n) (Equation 25)
   - m̃∪,ᵢ(Z) = Σₖ∈[1] eq̃ₖ(Z) · m∪^(k) ∈ (F₁^(<2))^(ℓn) ∀i ∈ [µ] (Equation 26)
   - m̃ᵢ(Z) = Σₖ∈[1] eq̃ₖ(Z) · mᵢ^(k) ∈ (F₁^(<2))^n ∀i ∈ [µ] (Equation 27)

5. **Equation 28-30 Constraints**: THE batched polynomials SHALL satisfy for all z ∈ {0,1}:
   - F(x̃(z), {mᵢ(z)}ᵢ∈[µ], rF(z)) = Σₖ∈[1] eq̃ₖ(z) · e^(k) = ẽ(z) (Equation 28)
   - m̃ᵢ(z, rₓ(z)) = Σₖ∈[1] eq̃ₖ(z) · vᵢ^(k) = ṽᵢ(z) ∀i ∈ [µ] (Equation 29)
   - m̃∪,ᵢ(z, τ(z), rₓ(z)) = Σₖ∈[1] eq̃ₖ(z) · vᵢ^(k) = ṽᵢ(z) ∀i ∈ [µ] (Equation 30)

6. **Sum-Check Combination**: GIVEN challenges γ ←$ F^(log(µ+1)), rz ←$ F, THE prover SHALL combine 2·µ+1 equations into one by γ

7. **Equation 31 Combined Polynomial**: THE prover SHALL compute G(Z) with degree max(d+1, log ℓ + log n):
   G(Z) = eq̃(rz, Z) · (F(x̃(Z), {mᵢ(Z)}ᵢ∈[µ], rF(Z)) - ẽ(Z))
        + Σᵢ∈[µ] powᵢ(γ) · (m̃ᵢ(Z, rₓ(Z)) - ṽᵢ(Z))
        + Σᵢ∈[µ] powµ₊ᵢ(γ) · (m̃∪,ᵢ(Z, τ(Z), rₓ(Z)) - ṽᵢ(Z))

8. **1-Round Sum-Check**: THE system SHALL execute 1-round sum-check for Σz∈{0,1} G(z) = 0 WHERE:
   - Prover sends polynomial G(Z)
   - Verifier checks G(0) + G(1) = 0
   - Verifier outputs evaluation claim G(σ) = vG

9. **Equation 32-34 Evaluation Claims**: THE prover SHALL send:
   - η = F(x̃(σ), {mᵢ(σ)}, rF(σ) - e(σ)) (Equation 32)
   - ηᵢ = m̃ᵢ(σ, rₓ(σ)) - vᵢ(σ) (Equation 33)
   - η∪,ᵢ = m̃∪,ᵢ(σ, τ(σ), rₓ(σ)) - vᵢ(σ) (Equation 34)

10. **Equation 35 Verification**: THE verifier SHALL check:
    G(σ) = eq̃(rz, σ) · (η + Σᵢ∈[µ] powᵢ(γ) · ηᵢ + Σᵢ∈[µ] powµ₊ᵢ(γ) · η∪,ᵢ)

11. **Oracle Batching Execution**: THE system SHALL engage in 2µ oracle batching protocols IORbatch in parallel with random σ ∈ F

12. **Output Relations**: THE derived tuple SHALL satisfy Racc = Rµeval × Rµeval × RF:
    - (iₐcc, x = {(yⱼ, xⱼ, vⱼ)}ⱼ, y = [[m̃∪,ᵢ]], w = ⊥) ∈ Reval ∀i ∈ [µ] (Equation 36)
    - (iₐcc, x = {(xₜ, vₜ)}ₜ, y = [[m̃ᵢ]], w = ⊥) ∈ Reval ∀i ∈ [µ] (Equation 37)
    - (iₐcc, x = (x, rF, e), y = ⊥, w = {mᵢ}ᵢ∈[µ]) ∈ RF (Equation 38)
    WHERE m̃∪,ᵢ = m̃∪,ᵢ(σ), m̃ᵢ = m̃ᵢ(σ) for all i ∈ [µ]

13. **Optimization**: THE system SHALL reduce oracle count from 2µ to µ+1 by preprocessing with oracle batching to obtain:
    (iₐcc, x = ((τ, rₓ, v), {(yⱼ, xⱼ, vⱼ)}ⱼ), y = [[m̃∪]], w = ⊥) ∈ Reval (Equation 39)
    WHERE v = Σᵢ∈[µ] powᵢ(β) · vᵢ AND m̃∪(Y, X) = Σᵢ∈[µ] powᵢ(β) · m̃∪,ᵢ(Y, X) (Equation 40)

14. **Lemma 6 Complexity**: THE protocol IORfold SHALL have:
    - 3 rounds
    - Proof length: O(d + µ) field elements for sum-check, proof elements for NIRbatch
    - Oracle proof length: O(µℓn) field elements (optimized to O(µn))
    - Verifier makes no queries
    - Verifier time dominated by O(ℓn) field computation and NIRbatch verification
    - Reduced relation contains 2·µ polynomial oracles (optimized to µ+1)


### Requirement 6: Polynomial Commitment Schemes Integration

**User Story:** As a cryptographic engineer, I want to integrate various polynomial commitment schemes (both curve-based and code-based), so that I can achieve different security and performance trade-offs.

#### Acceptance Criteria

1. **Definition 10 Multilinear PCS**: THE system SHALL implement multilinear polynomial commitment scheme PC = (Setup, Commit, Eval, Verify) WHERE:
   - Setup(1^λ, n) → ck takes security parameter λ, variable length n ∈ ℕ, outputs commitment key ck for polynomials in F_n^(<2)
   - Commit(ck, p(X)) → C takes multilinear polynomial p(X) ∈ F_n^(<2), outputs commitment C
   - Open(ck, C, p(X)) → b takes commitment C, multilinear polynomial p(X) ∈ F_n^(<2), outputs bit b
   - Eval(P(p(X)), V(ck, C, z, y)) is protocol between P and V with public inputs C, evaluation point z ∈ F^n, value y ∈ F

2. **Definition 11 Completeness**: FOR any bound n ∈ ℕ, polynomial p(X) ∈ F_n^(<2), point z ∈ F^n, THE probability Pr[Eval(P(p(X)), V(ck, C, z, y)) = 1 | ck ← Setup(1^λ, n), C ← Commit(ck, p(X))] SHALL equal 1

3. **Definition 12 Binding**: FOR any n ∈ ℕ and PPT adversary A, THE probability Pr[b₀ = b₁ = 1 ∧ p₀(X) ≠ p₁(X) | ck ← Setup(1^λ, n), (C, p₀(X), p₁(X)) ← A(ck), b₀ ← Open(ck, C, p₀(X)), b₁ ← Open(ck, C, p₁(X))] SHALL be ≤ negl(λ)

4. **Definition 13 Knowledge Soundness**: THE Eval protocol SHALL be argument of knowledge for relation REval(ck) := {(C, z, y; p(X)) : p(z) = y ∧ Open(ck, C, p(X)) = 1}

5. **Curve-Based Instantiation**: THE system SHALL support elliptic-curve-based PCS (e.g., Mercury) with:
   - O(n log n) prover time
   - O(1) proof size
   - O(1) verifier group operations
   - Discrete logarithm assumption security

6. **Code-Based Instantiation**: THE system SHALL support linear-code-based PCS with:
   - O(n) prover time (linear-time-encodable codes)
   - O(log n) proof size
   - O(λ/log(1/ρ) · log n) RO queries for verifier
   - Plausible post-quantum security

7. **Table 1 Comparison**: THE system SHALL achieve following verifier costs:
   - Quasar (curve): O(log ℓ)RO, O(1)G
   - Quasar (code): O(λ/log(1/ρ) · (log n + log ℓ))RO
   - Both sublinear in ℓ compared to O(ℓ) for existing schemes

### Requirement 7: Linear Codes and Code-Based Constructions

**User Story:** As a post-quantum cryptography researcher, I want to implement code-based polynomial commitments using linear codes, so that I can achieve plausible post-quantum security.

#### Acceptance Criteria

1. **Definition 7 Linear Code**: THE system SHALL implement linear code C : F^k → F^n WHERE:
   - C is injective linear map
   - Message length k, codeword length n
   - Rate ρ := k/n
   - n ∈ 2^ℕ
   - Minimum distance δ(C) := min_{u≠v∈C} Δ(u, v)

2. **Definition 8 Zero-Evaders**: THE system SHALL implement zero-evader ZE : D_ZE → F^m with error ϵ_zero such that:
   - ∀v ∈ F^m \ {0}, Pr_{ρ←D_ZE}[⟨ZE(ρ), v⟩ = 0] ≤ ϵ_zero (Equation 41)
   - For injective linear map G ∈ F^(n×k), ZE(α) := (G̃(α, b))_{b∈{0,1}^log k} is zero-evader with error log n/|F|

3. **Definition 9 Out-of-Domain Samples**: FOR linear code C : F^k → F^n, function f : [n] → F, repetition parameter s ∈ ℕ, distance parameter δ ∈ [0,1], zero-evader ZE : D_ZE → F^k with error ϵ_zero, THE probability:
   Pr_{ρ₁,...,ρₛ←$D_ZE}[∃ distinct u, v ∈ Λ(C, f, δ) : ∀i ∈ [s], ⟨ZE(ρᵢ), C⁻¹(u)⟩ = ⟨ZE(ρᵢ), C⁻¹(v)⟩] ≤ |Λ(C, δ)|²ˢ/2 · ϵ_zero

4. **Systematic Encoding**: THE coding algorithm SHALL be systematic such that for all x ∈ F^k, first k entries of C(x) equal x

5. **Codeword Multilinear Extension**: THE multilinear extension of codeword uᵢ SHALL be:
   ũᵢ(Y, X) := eq̃₀(Y) · f̃ᵢ(X) + Σᵢ₌₁^(log(1/ρ)) eq̃ᵢ(Y) Σⱼ₌₀^(log k-1) eq̃ⱼ(X) · uᵢ[i · k + j]

6. **Relation R'₀**: FOR evaluation claim f̃ᵢ(x) = vᵢ, x ∈ F^(log n), THE system SHALL encode as:
   R'₀ := {(i, x = (α := (0, x), v, r), y = ([[ũ₀]], [[ũ₀]]), w = (u₀, u₁)) : Σₖ∈[1] eq̃ₖ(r) · ũₖ(x) = v}
   WHERE u₀ = C(f₀), u₁ = C(f₁)

7. **Theorem 6 Security**: THE reduction NIRbatch based on linear codes SHALL have RBR knowledge soundness error ≤ 2^λ for every δ ∈ (0,1) IF field F and repetition parameters t, s satisfy:
   - |F| ≥ 2^(λ/s-1) · |L(C, δ)|^(2/s)
   - t ≥ λ/(-log(1-δ))


### Requirement 8: Multilinear Extensions and Sum-Check Protocol

**User Story:** As a protocol implementer, I want to implement multilinear extensions and sum-check protocols with exact mathematical formulations, so that I can ensure correctness of polynomial operations.

#### Acceptance Criteria

1. **Multilinear Extension Definition**: FOR vector f, THE multilinear extension f̃(·) : F^n → F SHALL be unique multilinear n-variate polynomial such that f̃(Bits(i)) = f[i] for all i ∈ n

2. **Multilinear Extension Formula**: THE multilinear extension SHALL be computed as:
   f̃(X) = Σᵢ∈[n] f[i] · eq̃(X, Bits(i))

3. **Equality Function**: THE equality function SHALL be:
   eq̃ᵢ(X) := eq̃(X, Bits(i)) = Πⱼ₌₀^(log n-1) (Bits(i)[j] · Xⱼ + (1 - Bits(i)[j])(1 - Xⱼ))

4. **Equation 4 Sum-Check Round**: AT each round i ∈ [1, n], THE prover SHALL compute intermediate univariate polynomial:
   fᵢ(X) = Σ_{xᵢ₊₁,...,xₙ∈Bₙ₋ᵢ} f̃(r₁, ..., rᵢ₋₁, X, xᵢ₊₁, ..., xₙ)

5. **Sum-Check Verification**: THE verifier SHALL check:
   - sum = f₁(0) + f₁(1) for i = 1
   - fᵢ₋₁(rᵢ₋₁) = fᵢ(0) + fᵢ(1) for i > 1
   - fₙ(rₙ) = f̃(r₁, ..., rₙ) at final step

6. **Lemma 1 Schwartz-Zippel**: FOR n-variate non-zero polynomial f̃ ∈ F_log n^(<d), THE probability:
   Pr_{r←$F^n}[f̃(r) = 0] ≤ n · (d - 1)/|F| (Equation 5)

7. **Sum-Check Completeness**: THE sum-check protocol SHALL satisfy completeness with probability 1

8. **Sum-Check Soundness**: THE sum-check protocol SHALL satisfy soundness according to Lund et al. [37]

### Requirement 9: Interactive Oracle Reductions (IOR)

**User Story:** As a theoretical cryptographer, I want to implement interactive oracle reductions with formal security definitions, so that I can ensure provable security of the construction.

#### Acceptance Criteria

1. **Definition 4 IOR Syntax**: THE system SHALL implement IOR = (I, P, V) WHERE:
   - Indexer I receives index i for relation R, outputs short index ι, index string I, new index i' for R'
   - Prover P receives index i, instance x, oracle string y, witness w, engages in µ rounds
   - Verifier V receives short index ι, instance x, query access to y, I, engages in µ rounds
   - At end, verifier outputs new statement (x', y') or rejects, prover outputs new witness w' such that (i', x', y', w') ∈ R'

2. **Definition 15 Completeness**: FOR any (i, x, y, w) ∈ R, THE probability:
   Pr_{{rᵢ}ᵢ∈[µ]}[(i', x', y', w') ∈ R' | (ι, I, i') ← I(i), (x', y'; w') ← ⟨P(x, y, w), V^{I,y}(x)⟩] SHALL equal 1

3. **Definition 16 Soundness**: FOR every proximity bound δ ∈ (0, δ*), statement (i, x, y) ∉ L(R) with ΔR(i, x, y) > δ, unbounded malicious prover P*, THE probability:
   Pr_{{rᵢ}ᵢ∈[µ]}[ΔR'(i', x', y') ≤ δ | (ι, I, i') ← I(i), (x', y'; w') ← ⟨P*, V^{I,y}(x)⟩] SHALL be ≤ ϵ(i, x, y, δ)

4. **Definition 17 Knowledge State Function**: THE system SHALL implement State function parameterized by proximity bound δ ∈ [0, δ*) with syntax:
   - Empty transcript: State_δ(i, x, y, ∅, w) = 1 iff ∃y* : (i, x, y*, w) ∈ R ∧ Δ(y, y*) ≤ δ
   - Prover moves: IF State_δ(i, x, y, tr, w) = 0, THEN State(i, x, y, tr||π, w) = 0 for every prover message π
   - Full transcript: State_δ(i, x, y, tr, w) = 1 iff V^{I,y,{πᵢ}ᵢ∈[k]}(x, {rᵢ}ᵢ∈[k]) outputs x', y' such that ∃y*' : (i', x', y*', w) ∈ R' ∧ Δ(y*, y*') ≤ δ

5. **Definition 18 RBR Knowledge Soundness**: THE µ-round IOR SHALL have RBR knowledge soundness errors (ϵ₁, ..., ϵµ) and extraction time (et₁, ..., etµ) IF there exist knowledge state function State and deterministic extractor E such that:
   FOR every proximity bound δ ∈ (0, δ*), statement (i, x, y), round index i ∈ [µ], interaction transcript tr = (π₁, r₁, ..., πᵢ₋₁, rᵢ₋₁, πᵢ), E runs in time ≤ etᵢ AND:
   Pr[∃w : State_δ(i, x, y, tr, E(i, x, y, tr||rᵢ, w)) = 0 ∧ State_δ(i, x, y, tr||rᵢ, w) = 1] ≤ ϵᵢ(i, x, y, δ)

6. **Theorem 4 Polynomial IOR Compilation**: THE transformation T from public-coin polynomial IOR to NIR SHALL:
   - Replace every oracle in IOR with polynomial commitment PC to obtain IOR^PC
   - Apply Fiat-Shamir transform to committed IOR^PC to obtain NIR := FS[IOR^PC]
   - IF IOR is RBR knowledge sound AND PC is extractable, THEN NIR is RBR knowledge sound under random oracle model

7. **Theorem 4 Efficiency**: THE NIR efficiency SHALL depend on IOR and PC:
   - Prover time = IOR prover time + oracle length × commitment time + query complexity × PC prover time
   - Verifier time = IOR verifier time + PC verifier time × query complexity
   - Proof size = IOR message complexity × commitment size + query complexity × PC proof size


### Requirement 10: NARK Construction and Security

**User Story:** As a security analyst, I want to implement NARK (Non-interactive ARgument of Knowledge) with formal security guarantees, so that I can ensure the soundness of the overall system.

#### Acceptance Criteria

1. **NARK Definition**: THE system SHALL implement NARK := (G, I, P, V) in random oracle model for indexed relation R relative to random oracle RO WHERE proofs have canonical partition π := (π.x, π.w)

2. **NARK Completeness**: FOR every unbounded adversary A, THE probability SHALL equal 1:
   Pr[(i, {x^(k), w^(k)}ₖ) ∈ R*(pp) ⇓ V^RO(vk, {x^(k)}ₖ, π) = 1 | RO ← U(λ), pp ← G(1^λ), (i, {x^(k), w^(k)}ₖ) ← A^RO(pp), (pk, vk) ← I^RO(pp, i), π ← P^RO(pk, {x^(k), w^(k)}ₖ)]

3. **NARK Knowledge Soundness**: FOR every non-uniform polynomial-time malicious prover P̃, THERE SHALL exist deterministic polynomial-time extractor E such that:
   Pr[V^RO(vk, {x^(k), w^(k)}ₖ, π) = 1 ∧ (i, {x^(k), w^(k)}ₖ) ∉ R*(pp) | RO ← U(λ), pp ← G(1^λ), aᵢ ← χ(1^λ), (i, {x^(k), w^(k)}ₖ), tr ← P̃^RO(pp, aᵢ), (pk, vk) ← I^RO(pp, i), w ← E(pp, i, {x^(k)}ₖ, π, aᵢ, tr)] ≤ negl(λ)

4. **NARK from NIRcast**: THE NARK construction SHALL use NIRcast as follows:
   - NARK.G(1^λ) outputs public parameters pp
   - NARK.I(pp, i) computes (pkcast, vkcast, i') ← NIRcast.I^RO(pp, i), outputs (pk, vk) := (pkcast, (vkcast, i', pp))
   - NARK.P^RO(pk, {x^(k), w^(k)}ₖ∈[ℓ]) computes (πcast, wacc) ← NIRcast.P^RO(pkcast, {x^(k), w^(k)}ₖ∈[ℓ]), assigns (π.x, π.w) := (πcast, wacc), outputs π := (π.x, π.w)
   - NARK.V^RO(vk, {x^(k)}ₖ∈[ℓ], π) computes xacc ← NIRcast.V^RO(vkcast, {x^(k)}ₖ∈[ℓ], πcast), assigns (acc.x, acc.w) := (xacc, π.w), checks (i', acc.x, acc.w) ∈ R^RO_acc(pp)

### Requirement 11: Accumulation Scheme Construction (Theorem 3)

**User Story:** As a system integrator, I want to construct the complete accumulation scheme from NIRcast and NIRfold components, so that I can achieve the full multi-instance IVC functionality.

#### Acceptance Criteria

1. **Theorem 3 Transformation**: GIVEN non-interactive reductions in random oracle model:
   - NIRcast = (Gcast, Pcast, Vcast): multi-cast reduction from (R^PC_F)^ℓ to R^PC_acc
   - NIRfold = (Gfold, Pfold, Vfold): 2-to-1 reduction from (R^PC_acc)² to R^PC_acc with same generator as NIRcast
   THERE SHALL exist transformation T[NIRcast, NIRfold, Racc] = (NARK, ACC) WHERE NARK is non-interactive argument for R AND ACC is accumulation scheme for NARK

2. **ACC.G Algorithm**: THE ACC.G(1^λ) SHALL take security parameter λ in unary, output public parameters pp

3. **ACC.I Algorithm**: THE ACC.I(pp, i) SHALL:
   - Compute (pkcast, vkcast, i') ← NIRcast.I^RO(pp, i)
   - Compute (pkfold, vkfold, i') ← NIRfold.I^RO(pp, i)
   - Output apk := (vkcast, pkfold, vkfold), avk := (vkcast, vkfold), adk := (i', pp)

4. **ACC.P Algorithm**: THE ACC.P^RO(apk, {x^(k)}ₖ∈[ℓ], π, acc^(0)) SHALL:
   - Compute xacc ← NIRcast.V^RO(vkcast, {x^(k)}ₖ∈[ℓ], πcast), assign (acc^(1).x, acc^(1).w) := (xacc, π.w)
   - Compute (πfold, acc.w) ← NIRfold.P^RO(pkfold, {acc^(i).x, acc^(i).w}ᵢ∈[1])
   - Compute acc.x ← NIRfold.V^RO(vkfold, {acc^(i).x}ᵢ∈[1], πfold)
   - Output acc ← (acc.x, acc.w) and pf ← πfold

5. **ACC.V Algorithm**: THE ACC.V^RO(avk, {x^(k)}ₖ∈[ℓ], π.x, acc^(0).x, acc.x, pf) SHALL:
   - Compute xacc ← NIRcast.V^RO(vkcast, {x^(k)}ₖ∈[ℓ], πcast), assign (acc^(1).x, acc^(1).w) := (xacc, π.w)
   - Check acc.x = NIRfold.V^RO(vkfold, {acc^(i).x}ᵢ∈[1], acc.x, pf)

6. **ACC.D Algorithm**: THE ACC.D(adk, acc) SHALL take adk := (i', pp), accumulator acc, check (i', acc.x, acc.w) ∈ R^PC_acc(pp)

7. **Theorem 3 Complexity**: THE accumulation scheme SHALL achieve:
   - Accumulation prover cost: 2µ G operations, O(ℓ·m+µ·n) F operations, µ + log ℓ RO queries, cost of 2µ NIRbatch.P
   - Accumulation verifier cost: 2µ G operations, O(ℓ·m) F operations for accumulating {x^(k)}ₖ∈[ℓ], µ + log ℓ RO queries, cost of 2µ NIRbatch.V
   - Decider cost: checking O(µ) evaluation claims with respect to oracles, dependent on PCS evaluation algorithm

8. **Completeness Proof**: THE accumulation scheme SHALL satisfy completeness as proven in Appendix B.3

9. **Knowledge Soundness Proof**: THE accumulation scheme SHALL satisfy knowledge soundness as proven in Appendix B.3


### Requirement 12: Plonkish Constraint System Support

**User Story:** As a zkVM developer, I want to support Plonkish constraint systems (HyperPlonk), so that I can build practical zero-knowledge virtual machines with the Quasar IVC.

#### Acceptance Criteria

1. **Definition 6 Multilinear Plonkish Relation**: THE system SHALL implement Rplonk with public parameters:
   - Field F
   - Instance length m
   - Total number of gates µ
   - Number of possible gate types s (number of selectors)
   - Number of fan-in/fan-outs of each gate n
   - Algebraic map f : F^(s+n) → F with degree d

2. **Plonkish Relation Components**: THE indexed oracle relation Rplonk SHALL consist of tuples {(i := (q, σ), x = p, y = [[w]], w = w)} WHERE:
   - σ : {0,1}^(log µ+log n) → {0,1}^(log µ+log n) is permutation
   - q̃ ∈ F^(<2)_log µ+log s is multilinear extension of selector vector q
   - p̃ ∈ F^(<2)_log µ+log m is multilinear extension of instance vector p
   - w̃ ∈ F^(<2)_log µ+log n is multilinear extension of witness vector w

3. **Gate Identity**: THE system SHALL verify f̃(x) = 0 for all x ∈ {0,1}^(log µ) WHERE:
   f̃(X) := f({q̃(Bits(0), X)}^(s-1)ᵢ₌₀, {w̃(Bits(j), X)}^(n-1)ⱼ₌₀)

4. **Wiring Identity**: THE system SHALL verify w̃(x) = w̃(σ(x)) for all x ∈ {0,1}^(log µ)

5. **Instance Consistency**: THE system SHALL verify p̃(x) = w̃(0^(log µ+log n-log m), x) for all x ∈ {0,1}^(log m)

6. **Figure 11 Gate Protocol**: THE system SHALL implement special-sound protocol Πgate:
   - P's inputs: f, q̃(X), w̃(X)
   - V's inputs: f, q̃(X)
   - P → V: w̃(X)
   - V checks: f({q̃(Bits(0), X)}^(s-1)ᵢ₌₀, {w̃(Bits(j), X)}^(n-1)ⱼ₌₀) = 0

7. **Figure 12 Wiring Protocol**: THE system SHALL implement special-sound protocol Πwire:
   - P's inputs: σ, w̃(X)
   - V's inputs: σ
   - P → V: w̃(X)
   - V checks: w̃(x) - w̃(σ(x)) = 0 for all x ∈ {0,1}^(log µ)

8. **Figure 13 Instance Protocol**: THE system SHALL implement special-sound protocol Πpi:
   - P's inputs: p̃(x), w̃(X)
   - V's inputs: p̃(x)
   - P → V: w̃(X)
   - V checks: p̃(x) = w̃(0^(log µ+log n-log m), x) for all x ∈ {0,1}^(log m)

9. **Compressed Version**: THE protocols SHALL be transformed into compressed versions as mentioned in Section 5.1

10. **Accumulation Scheme Instantiation**: THE system SHALL instantiate accumulation scheme for special-sound protocols via techniques in Section 5

11. **IVC with Plonkish**: THE system SHALL instantiate IVC with Plonkish constraint systems

### Requirement 13: Security Proofs and Formal Verification

**User Story:** As a security researcher, I want complete security proofs for all components, so that I can verify the cryptographic soundness of the implementation.

#### Acceptance Criteria

1. **Lemma 3 Proof (Appendix C.1)**: THE system SHALL provide proof that IORcast satisfies:
   - Completeness holds trivially
   - RBR knowledge soundness with errors: ϵzc = dℓ/|F|, ϵ^sc_i = d/|F| ∀i ∈ [log ℓ], ϵagg = n/|F|
   - Extraction time O(ℓ² · n²)

2. **State Function for Empty Transcript**: GIVEN inputs i, x = {x^(i)}ᵢ∈[ℓ], THE State(i, x, ∅) = 1 SHALL hold iff x^(i) ∈ L(RF) for all i ∈ [ℓ]

3. **Bounding ϵzc**: AT stage tr = ([[w̃∪]]), verifier sends rᵧ, THE State(i, x, tr||rᵧ) = 1 SHALL hold iff Σᵧ∈B_log ℓ G(y) = 0 (Equation 8)

4. **Extractor for ϵzc**: THE extractor SHALL output witness w∪ := {w^(i)}ᵢ∈[ℓ] in time O(ℓ² · n²) WHERE w^(i)[j] = w̃∪(Bits(i), Bits(j))

5. **Knowledge Error ϵzc**: IF extracted witness invalid (State(i, x, w∪, tr) = 0), THEN State(i, x, tr||rᵧ) = 1 SHALL hold with probability ≤ dℓ/|F| by Schwartz-Zippel lemma

6. **Bounding ϵ^sc_i**: FOR first round, tr = ([[w̃∪]], rᵧ, G₁(Y)), THE State(i, x, tr||τ₁) = 1 SHALL hold iff G₁(τ₁) = Σ_{x₂,...,x_log ℓ∈B_log ℓ-1} G(τ₁, x₂, ..., x_log ℓ)

7. **Sum-Check Round Error**: IF State(i, x, tr) = 0 (i.e., Σᵧ∈B_log ℓ G(y) ≠ 0), THEN State(i, x, tr||τ₁) = 1 SHALL hold with probability ≤ d/|F|

8. **Bounding ϵagg**: AT stage tr = ([[w̃∪]], rᵧ, G₁(Y), ..., G_log ℓ(Y), τ₁, ..., τ_log ℓ, [[w̃]]), verifier sends rₓ, THE State(i, x, tr||rₓ) = 1 SHALL hold iff w̃(rₓ) = w̃∪(τ, rₓ)

9. **Extractor for ϵagg**: THE extractor SHALL output witness w' in time O(n²) WHERE w'[j] = w̃(Bits(j)), j ∈ [n]

10. **Equation 42 Inequality**: IF State(i, x, tr) = 0, THEN eq̃(τ, rᵧ)F(x, w) = G_log ℓ(τ_log ℓ) ≠ G'(τ) = eq̃(τ, rᵧ)F(x, w') SHALL hold, implying w ≠ w'

11. **Polynomial Agreement Error**: THE probability that two different polynomials w̃(X) = w̃(τ, X) and w̃'(X) = Σᵢ∈[n] eq̃ᵢ₋₁(X)·w[i] agree at randomly sampled rₓ SHALL be ≤ n/|F|

12. **Lemma 6 Proof (Appendix C.2)**: THE system SHALL provide proof that IORfold satisfies:
   - Completeness holds trivially
   - RBR knowledge soundness with errors: ϵzc = (µ+1)/|F|, ϵsc = max(d+1, log(ℓn))/|F|, ϵeval = µ/|F|, ϵbatch = 2µ · ϵ₀
   - Extraction time O(ℓ² · n²)

13. **Equation 43 Multivariate Polynomial**: THE system SHALL define {G^(k)(Zᵧ, Zᵣ)}ₖ∈[1] as:
    G^(k)(Zᵧ, Zᵣ) = eq̃(Zᵣ, k) · (F(x̃(k), {mᵢ(k)}ᵢ∈[µ], rF(k)) - e^(k))
                    + Σᵢ∈[µ] powᵢ(Zᵧ) · (m̃ᵢ(k, rₓ(k)) - vᵢ(k))
                    + Σᵢ∈[µ] pow_{µ+i}(Zᵧ) · (m̃∪,ᵢ(k, τ(k), rₓ(k)) - vᵢ(k))

14. **Total Degree Bound**: SINCE G^(k)(Zᵧ, Zᵣ) has total degree ≤ µ+1, THEN Σₖ∈[1] G^(k)(Zᵧ, Zᵣ) SHALL equal zero with probability ϵzc ≤ (µ+1)/|F|

15. **Equation 44-45 Verification**: THE system SHALL verify:
    - Equation 44: G(σ) = eq̃(rz, σ) · (F(x̃(σ), {mᵢ(σ)}ᵢ∈[µ], rF(σ)) - e(σ)) + Σᵢ∈[µ] powᵢ(γ) · (m̃ᵢ(Z, rₓ(Z)) - vᵢ(Z)) + Σᵢ∈[µ] pow_{µ+i}(γ) · (m̃∪,ᵢ(Z, τ(Z), rₓ(Z)) - vᵢ(Z))
    - Equation 45: G(σ) = eq̃(rz, σ) · [η' + Σᵢ∈[µ] powᵢ(γ) · ηᵢ' + pow_{i+µ}(γ) · η'∪,ᵢ] with forgery probability ≤ µ/|F|


### Requirement 14: Non-Interactive Reductions (NIR)

**User Story:** As a protocol engineer, I want to implement non-interactive versions of all interactive oracle reductions using Fiat-Shamir transform, so that I can deploy the system in practice.

#### Acceptance Criteria

1. **Figure 7 NIRcast.P Algorithm**: THE prover algorithm SHALL execute:
   - r₀ ← RO({x^(k)}ₖ∈[ℓ])
   - For i ∈ [µ]:
     * Set mᵢ^(k) ← Psps(x^(k), w^(k), {mⱼ^(k), rⱼ}^(i-1)ⱼ₌₀) ∀k ∈ [ℓ]
     * Set m̃∪,ᵢ(Y, X) := Σₖ∈[ℓ] eq̃ₖ₋₁(Y) · m̃ᵢ^(k)(X)
     * Set C∪,ᵢ = Commit(ck, m̃∪,ᵢ(Y, X))
     * rᵢ ← RO(rᵢ₋₁, C∪,ᵢ)
   - Set α := rµ, α := (α, α², ..., α^(2^(log m-1)))
   - rᵧ ← RO(α)
   - Set G(Y) := F(Σₖ∈[ℓ] eq̃ₖ₋₁(Y) · x^(k), {Σₖ∈[ℓ] eq̃ₖ₋₁(Y) · mᵢ^(k)}ᵢ∈[µ], rF) · eq̃(Y, rᵧ)
   - Run log ℓ-round non-interactive sumcheck for Σᵧ∈B_log ℓ G(y) = 0, obtain log ℓ sumcheck polynomials and random vector τ ∈ F^(log ℓ)
   - Set e := G_log ℓ(τ_log ℓ)
   - Set m̃ᵢ(X) := m̃∪,ᵢ(τ, X) ∀i ∈ [µ]
   - Set Cᵢ = Commit(ck, m̃ᵢ(X)) ∀i ∈ [µ]
   - rₓ ← RO(rᵧ, {Cᵢ}ᵢ∈[µ])
   - Output witness wacc and proof π including: commitments {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], challenges rF, τ, rₓ, sumcheck proofs {Gᵢ(Y)}ᵢ∈[µ], G_log ℓ(τ_log ℓ)

2. **Figure 8 NIRcast.V Algorithm**: THE verifier algorithm SHALL execute:
   - Parse π = {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], rF, τ, rₓ, {Gᵢ(Y)}ᵢ∈[µ], e
   - Parse rF = r||α
   - Set b₁ = 1 if:
     * r₀ ← RO({x^(k)}ₖ∈[ℓ])
     * rᵢ ← RO(rᵢ₋₁, C∪,ᵢ) ∀i ∈ [µ]
     * G₁(0) + G₁(1) = 0
     * Gᵢ₊₁(0) + Gᵢ₊₁(1) = Gᵢ(τᵢ), ∀i ∈ [log ℓ - 1]
   - Set b₂ = 1 if:
     * rᵧ ← RO(α)
     * τᵢ = RO(Gᵢ(Y)), i ∈ [log ℓ]
     * rₓ ← RO(rᵧ, {Cᵢ}ᵢ∈[µ])
   - Set e = G_log ℓ(τ_log ℓ) · eq̃⁻¹(rᵧ, τ)
   - Set x = Σₖ∈ℓ eq̃ₖ₋₁(τ) · x^(k)
   - Output instance: xacc := (x, {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], rF, τ, rₓ, e)

3. **Figure 9 NIRfold.P Algorithm**: THE prover algorithm SHALL execute:
   - γ, rz ← RO({acc^(i).x, acc^(i).w}ᵢ∈[1])
   - Set G(Z) as per Equation 31
   - Run 1-round non-interactive sumcheck for Σz∈{0,1} G(z) = 0, obtain sumcheck polynomial G(Z) and random value σ ∈ F
   - Set vG := G(σ)
   - Compute batched witness {w̃∪,ᵢ(σ), m̃ᵢ(σ)}ᵢ∈[µ]
   - Compute η, {ηᵢ, η∪,ᵢ}ᵢ∈[µ] as per Equations 32-34
   - Compute ẽ(σ), {ṽᵢ(σ)}ᵢ∈[µ]
   - Run 2µ times oracle batching proving algorithm NIRbatch.P, obtain batched commitments {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], and proof πbatch
   - Output witness acc.w and proof π including: challenges γ, rz, σ, sumcheck proofs G(Z), vG, evaluation claims η, {ηᵢ, η∪,ᵢ}ᵢ∈[µ], commitments {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], batch proof πbatch

4. **Figure 10 NIRfold.V Algorithm**: THE verifier algorithm SHALL execute:
   - γ, rz ← RO({acc^(i).x, acc^(i).w}ᵢ∈[1])
   - Check G(0) + G(1) = 0
   - Check vG = eq̃(rz, σ) · (η + Σᵢ∈[µ] powᵢ(γ) · ηᵢ + Σᵢ∈[µ] pow_{i+µ}(γ) · η∪,ᵢ)
   - Compute ẽ(σ), {ṽᵢ(σ)}ᵢ∈[µ]
   - Run 2µ times oracle batching verifying algorithm NIRbatch.V to check batched commitments {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ] with proof πbatch
   - Parse {yⱼ, xⱼ, vⱼ}ⱼ, {xₜ, vₜ}ₜ from πbatch
   - Compute batched instance x̃(σ)
   - Output instance: acc.x := (x, {C∪,ᵢ}ᵢ∈[µ], {Cᵢ}ᵢ∈[µ], rF, e, {yⱼ, xⱼ, vⱼ}ⱼ, {xₜ, vₜ}ₜ)

5. **Figure 14 NIRbatch Algorithm**: THE oracle batching protocol based on linear codes SHALL execute:
   - Interaction phase:
     * P computes u := Σₖ∈[1] eq̃ₖ(r) · uₖ and its oracle [[ũ]]
     * P → V: [[ũ]]
     * V → P: αᵣ₊₁, ..., αᵣ₊ₛ ←$ F^(log(1/ρ)+log n) (out of domain samples)
     * P computes µᵣ₊₁, ..., µᵣ₊ₛ ∈ F, where µᵣ₊ⱼ := ũ(α)
     * P → V: µᵣ₊₁, ..., µᵣ₊ₛ
     * V samples b₁, ..., bₜ ←$ {0,1}^(log(1/ρ)+log n) and queries [[ũₖ(X)]] (shift queries)
   - Output phase:
     * Define µᵣ₊ₛ₊ⱼ := Σₖ∈[1] eq̃ₖ(r) · ũₖ(bⱼ) ∀j ∈ [t]
     * V outputs new instance-oracle pair as (x := {αᵢ, µᵢ}ᵢ∈r+s+t, y := [[ũ]])

6. **Random Oracle Queries**: ALL random oracle queries SHALL be properly sequenced to ensure Fiat-Shamir security

7. **State Restoration Attack Prevention**: THE non-interactive reductions SHALL be secure against state-restoration attacks via RBR knowledge soundness


### Requirement 15: Performance and Complexity Analysis

**User Story:** As a performance engineer, I want precise complexity bounds for all algorithms, so that I can optimize the implementation and verify performance claims.

#### Acceptance Criteria

1. **Table 1 Verifier Cost Comparison**: THE system SHALL achieve verifier costs:
   - ProtoGalaxy [25]: O(1)RO, O(ℓ · d)G
   - KiloNova [46]: O(log n)RO, O(ℓ)G
   - Quasar (curve): O(log ℓ)RO, O(1)G
   - Arc [20]: O(ℓ · λ/log(1/ρ) · log n)RO
   - WARP [15]: O(ℓ · λ/log(1/ρ) · log n)RO
   - Quasar (code): O(λ/log(1/ρ) · (log n + log ℓ))RO

2. **IVC Recursion Overhead**: THE total CRC operations across all N steps SHALL be O(√N) WHERE:
   - Single-instance IVC: N · t CRC operations
   - ℓ-accumulation PCD: ≤ 2Nt CRC operations
   - Quasar multi-instance IVC: O(√N) CRC operations

3. **Per-Step Complexity**: AT each IVC step, THE recursive circuit SHALL contain:
   - O(ℓ) field operations
   - O(1) CRC operations
   - Computational overhead for computing new chunk

4. **Accumulation Prover Complexity**: THE accumulation prover SHALL have:
   - 2µ group operations (for curve-based PCS)
   - O(ℓ·m + µ·n) field operations
   - µ + log ℓ random oracle queries
   - Cost of 2µ NIRbatch.P algorithms

5. **Accumulation Verifier Complexity**: THE accumulation verifier SHALL have:
   - 2µ group operations (for curve-based PCS)
   - O(ℓ·m) field operations for accumulating {x^(k)}ₖ∈[ℓ]
   - µ + log ℓ random oracle queries
   - Cost of 2µ NIRbatch.V algorithms
   - Sublinear in ℓ for both curve-based and code-based instantiations

6. **Decider Complexity**: THE decider SHALL check O(µ) evaluation claims with complexity dependent on PCS evaluation algorithm

7. **Linear-Time Prover**: WHEN instantiated with linear-time-encodable codes [31,43] or Mercury [26], THE accumulation prover SHALL achieve O(n) time complexity

8. **Proof Size**: THE proof size SHALL be:
   - NIRcast: 2µ commitments + O(log ℓ) field elements
   - NIRfold: O(d + µ) field elements + NIRbatch proofs + O(µn) oracle elements (optimized)
   - Total: Dependent on PCS commitment size and proof size

9. **Memory Complexity**: THE prover SHALL operate on O(ℓ·n + µ·n) memory at any given time, avoiding O(N·n) memory requirement of monolithic SNARKs

10. **Parallelization**: THE accumulation prover at each step SHALL support parallelization of:
    - Computing {mᵢ^(k)}ₖ∈[ℓ] for each round i
    - Polynomial evaluations
    - Commitment computations

### Requirement 16: Theorem 1 - Multi-Instance IVC from Accumulation

**User Story:** As a theoretical cryptographer, I want formal theorem proving IVC construction from accumulation scheme, so that I can ensure correctness of the overall system.

#### Acceptance Criteria

1. **Theorem 1 Statement**: IN standard model, GIVEN NARK for NP relations AND multi-instance accumulation scheme for NARK with verifier complexity sublinear in input length, THERE SHALL exist efficient transformation outputting multi-instance IVC scheme for constant-depth compliance predicates

2. **Sublinear Recursion Cost**: IF accumulation verifier complexity is sublinear in accumulated instance number ℓ, THEN recursive cost of IVC scheme SHALL be sublinear in total instance number N

3. **IVC Construction Process**: THE IVC prover SHALL:
   - Given multi-predicate input ({xₖ}ₖ∈[ℓ], π) where π is NARK proof, and accumulator acc
   - Run ACC.P to obtain new accumulator acc' and proof pf
   - Construct ℓ recursive circuits each consisting of:
     * Trace for computing predicate φ with k-th instance-witness pair
     * If k=0: trace for verifying accumulation between multi-predicate instance and accumulator at previous step; else dummy trace
     * If k=0: trace for compressing accumulator by cryptographic hash functions; else dummy trace
   - For each recursive circuit: arithmetize into tuple (i', x', w') ∈ R under constraint system
   - Call proving algorithm of NIRmulticast compiled with PCS, output reduced witness w' and NARK proof π'
   - Output multi-predicate tuple (({(x')^(k)}ₖ∈[ℓ], π'.x), w') and new accumulator acc'

4. **IVC Verification**: THE IVC verifier SHALL:
   - Take inputs multi-predicate tuple (({x^(k)}ₖ∈[ℓ], π.x), w) and accumulator acc
   - Run verification algorithm of NIRmulticast to derive x
   - Check validity of x, w, acc by running decider algorithm

5. **Constant-Depth Predicates**: THE IVC SHALL support constant-depth compliance predicates φ

6. **Security Preservation**: IF NARK and accumulation scheme are secure against quantum adversaries, THEN IVC SHALL be secure against quantum adversaries

7. **Zero-Knowledge Preservation**: IF both NARK and accumulation scheme are zero-knowledge, THEN IVC SHALL be zero-knowledge

8. **Proof Reference**: THE formal proof SHALL be provided in Appendix A.6 and follow from [16]


### Requirement 17: Theorem 2 - Multi-Instance Accumulation Construction

**User Story:** As a protocol designer, I want formal theorem for accumulation scheme construction from multi-cast and 2-to-1 reductions, so that I can ensure the construction is sound.

#### Acceptance Criteria

1. **Theorem 2 Statement**: GIVEN following non-interactive reductions in random oracle model:
   - Multi-cast reduction NIRmulticast from multi-instance relation R^ℓ to committed relation R^cm_acc
   - 2-to-1 reduction NIRfold from (R^cm_acc)² to R^cm_acc
   THERE SHALL exist transformation T[NIRmulticast, NIRfold, R^cm_acc] = (NARK, ACC) WHERE NARK is non-interactive argument for R AND ACC is accumulation scheme for NARK, both in random oracle model

2. **Key Difference from Previous Framework**: THE new construction SHALL shift task of combining ℓ committed predicate instances from NIRfold to NIRcast, performing far less CRC operations

3. **NIRmulticast Functionality**: THE multi-cast reduction SHALL enable prover to accumulate and cast multiple non-committed predicate tuples {(x^(k), w^(k))}ₖ∈[ℓ] into one committed instance-witness tuple ((x, π.x), π.w) with same form as accumulator in R^cm_acc

4. **NIRfold Functionality**: THE 2-to-1 reduction SHALL accumulate output committed tuple with another accumulator into new accumulator for next step

5. **Remark 2 Optimization**: THE multi-instance accumulation scheme in Definition 2 CAN NOT achieve verification complexity sublinear in ℓ because verifier still needs to perform accumulation for {x^(k)}ₖ∈[ℓ] over F

6. **Optimization Options**: THE cost CAN be further optimized by:
   - Extending multi-cast reduction NIRmulticast for both ℓ instances and witnesses (Section 5.3)
   - Hashing {x^(k)}ₖ∈[ℓ] into one value (more practical, linear solution from [34,14])

7. **Formal Proof**: THE formal proof of correctness SHALL be provided in Appendix B.3

### Requirement 18: Special Soundness and Tree of Transcripts

**User Story:** As a cryptographic protocol analyst, I want precise definitions of special soundness with tree of transcripts, so that I can verify security properties.

#### Acceptance Criteria

1. **Definition 19 Tree of Transcripts**: THE (a₁, ..., aₖ)-tree of transcripts SHALL constitute set of Πᵏᵢ₌₁ aᵢ transcripts with tree-like structure WHERE:
   - Edges represent verifier challenges
   - Vertices represent prover messages (can be empty)
   - Each node at depth i has aᵢ child nodes corresponding to aᵢ distinct challenges
   - Every transcript uniquely represented by one path from root to leaf

2. **Definition 20 Special Soundness**: THE protocol Π SHALL provide (a₁, ..., aₖ)-special soundness IF there exists effective PPT extraction algorithm E that can extract witness w given x and any (a₁, ..., aₖ)-tree of accepting transcripts T

3. **Extraction Probability**: FOR all PPT adversaries A, THE probability SHALL be ≈ 1:
   Pr[pp ← G(1^λ), (x, T) ← A(pp), w ← E(pp, x, T) : (x; w) ∈ R]

4. **Lemma 7 Implication**: IF (G, P, V) is (a₁, ..., aₖ)-special sound (2k+1)-move interactive protocol for relation R WHERE V samples each challenge uniformly at random from F, THEN (G, P, V) SHALL be knowledge sound with knowledge error κ ≤ (Σᵏᵢ₌₁ aᵢ - 1)/|F|

5. **Lemma 4 Application**: GIVEN (2µ+1)-move interactive protocol Πsps in terms of (Psps, Vsps) is (k₀, ..., kµ₋₁)-special-sound for relation R, THEN (2µ+3)-move transformed protocol CV[Πsps] in terms of (Psps, F) SHALL be (k₀, ..., kµ₋₁, ν+1)-special-sound for relation R

6. **Extractor Construction**: THE extractor ECV SHALL invoke Esps to extract witness from depth-(µ) transcript sub-tree

7. **Validity Demonstration**: SINCE F(x, {mᵢ}ᵢ∈[µ], r, α) with degree ν equals zero at ν+1 distinct points, THE original Vsps MUST output zero vector

### Requirement 19: Remark 1 - IVC Construction Distinction

**User Story:** As a system architect, I want clear distinction between different IVC construction approaches, so that I can make informed design decisions.

#### Acceptance Criteria

1. **Multi-Accumulation IVC**: THE IVC constructed from multi-accumulation scheme for ℓ chunks SHALL be distinct from IVC constructed using single-instance accumulation scheme for single chunk of ℓ times larger size

2. **Key Difference**: THE final proof of single-instance approach SHALL be ℓ times larger than multi-accumulation approach

3. **Trade-off Analysis**: THE multi-instance IVC SHALL allow prover to achieve trade-off between:
   - Number of recursive steps
   - Recursion overhead per step
   - Final proof size

4. **Practical Implications**: FOR zkVM applications, THE multi-instance approach SHALL provide better memory efficiency and parallelization opportunities


### Requirement 20: Remark 3 - Constraint Function Assumption

**User Story:** As a protocol implementer, I want clear specification of constraint function requirements, so that I can ensure compatibility with various constraint systems.

#### Acceptance Criteria

1. **Constraint Function F**: THE instance and witness R SHALL also satisfy constraint F(x, w) = 0 WHERE F : F^(m+n) → F is d-degree algebraic map

2. **Homogeneous Decomposition**: THE function F SHALL be written as F(x, w) := Σᵈⱼ₌₀ fⱼ^F(x, w) WHERE each fⱼ^F is homogeneous degree-d algebraic map outputting zero element in F

3. **Special-Sound Protocol Capture**: THIS assumption SHALL be sufficient to capture Special-sound protocol in Section 5.1

4. **Wide Applicability**: THE constraint function SHALL have many applications as per [14]

5. **Full Definitions**: IN full definitions of IORcast and IORfold, THE additional constraint SHALL be explicitly included

### Requirement 21: Remark 4 - Relation Mismatch Resolution

**User Story:** As a protocol engineer, I want clear specification of how to resolve relation mismatches in 2-to-1 reduction, so that I can implement the construction correctly.

#### Acceptance Criteria

1. **Mismatch Description**: THE Construction 1 SHALL be 2-to-1 reduction from (Racc)² to Racc WHERE Racc = R^µ_eval × R^µ_eval × RF

2. **New Relation Format**: THE newly generated relation Reval SHALL contain list of evaluation claims instead of one

3. **Resolution Method**: THE mismatch SHALL be resolved by adding extra evaluation claims in Racc at arbitrary point (e.g., 0) that does not have to be chosen at random

4. **Reference**: THE resolution method SHALL follow approach in [20,15]

### Requirement 22: Figure 6 - IORcast Protocol for SPS

**User Story:** As a protocol implementer, I want complete specification of IORcast protocol for special-sound protocols, so that I can implement it correctly.

#### Acceptance Criteria

1. **Prover Inputs**: THE prover SHALL receive (i, {x^(k), w^(k)}ₖ∈[ℓ])

2. **Verifier Inputs**: THE verifier SHALL receive {i, x^(k)}ₖ∈[ℓ]

3. **Interaction Phase Steps**: THE protocol SHALL execute:
   - For i ∈ [µ]:
     * ∀k ∈ [ℓ], mᵢ^(k) ← Psps(x^(k), w^(k), {mⱼ^(k), rⱼ}ʲ⁼⁰^(i-1))
     * P computes m̃∪,ᵢ(Y, X) := Σₖ∈[ℓ] eq̃ₖ₋₁(Y) · m̃ᵢ^(k)(X)
     * P → V: [[m̃∪,ᵢ]]
     * V → P: rᵢ ←$ F
   - Set α := rµ
   - P computes α := (α, α², α⁴, ..., α^(2^(log m-1)))
   - P → V: α
   - V checks:
     * α₀ = α
     * αᵢ₊₁ = αᵢ² ∀i ∈ [log ν - 1]
   - P and V run remaining process of IORcast (step 3-9)

4. **Output Phase**: THE protocol SHALL:
   - Define x = Σₖ∈[ℓ] eq̃ₖ₋₁(τ) · x^(k)
   - Define e = G_log ℓ(τ_log ℓ) · eq̃⁻¹(τ, rᵧ)
   - V outputs x = (x, rF, τ, rₓ, e), y = ({[[m̃∪,ᵢ]]}ᵢ∈[µ], {[[m̃ᵢ]]}ᵢ∈[µ])

5. **Reduced Instance Language**: THE reduced instance SHALL satisfy L(Racc) WHERE Racc = R^µ_eval × R^µ_eval × RF with Equations 16-18

6. **Efficiency Optimization**: THE random oracles SHALL take inputs as O(n)-sized messages m∪,ᵢ ∀i ∈ [µ] instead of O(ℓn) when applying Fiat-Shamir transform

### Requirement 23: Construction 1 - Complete 2-to-1 Reduction Specification

**User Story:** As a protocol implementer, I want complete specification of Construction 1 for 2-to-1 reduction, so that I can implement all steps correctly.

#### Acceptance Criteria

1. **Input Format Verification**: THE inputs SHALL be two instance-witness tuples (iₐcc, x^(k)_acc, y^(k)_acc, w^(k)_acc) ∈ R^µ_eval × R^µ_eval × RF for k ∈ [1] with format specified in Equations 19-21

2. **Batched Polynomial Computation**: THE prover SHALL compute all batched polynomials as specified in Equations 22-27

3. **Constraint Verification**: THE batched polynomials SHALL satisfy constraints in Equations 28-30 for all z ∈ {0,1}

4. **Challenge Generation**: GIVEN challenges γ ←$ F^(log(µ+1)), rz ←$ F, THE prover SHALL combine 2·µ+1 equations into one by γ

5. **Combined Polynomial G(Z)**: THE prover SHALL compute G(Z) exactly as specified in Equation 31 with degree max(d+1, log ℓ + log n)

6. **Sum-Check Execution**: THE prover and verifier SHALL engage in 1-round sum-check for Σz∈{0,1} G(z) = 0 with steps:
   - Prover sends polynomial G(Z)
   - Verifier checks G(0) + G(1) = 0
   - Verifier outputs evaluation claim G(σ) = vG

7. **Virtual Oracle Definition**: THE verifier SHALL define virtual oracle [[G]] based on batched oracles {[[m̃∪,ᵢ]]}ᵢ∈[µ], {[[m̃ᵢ]]}ᵢ∈[µ] ∈ ysps

8. **Evaluation Claims**: THE prover SHALL send η, ηᵢ, η∪,ᵢ as specified in Equations 32-34

9. **Verification Check**: THE verifier SHALL check Equation 35 holds

10. **Oracle Batching**: THE prover and verifier SHALL engage in 2µ oracle batching protocols IORbatch in parallel with random σ ∈ F

11. **Output Tuple**: THE derived tuple SHALL satisfy Racc = R^µ_eval × R^µ_eval × RF as specified in Equations 36-38

12. **Optimization Application**: THE system SHALL apply optimization from Equation 39-40 to reduce oracle count from 2µ to µ+1
