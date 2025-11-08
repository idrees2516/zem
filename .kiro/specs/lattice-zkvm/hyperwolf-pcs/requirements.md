# HyperWolf: Lattice Polynomial Commitments with Standard Soundness - Requirements Document

## Introduction

HyperWolf is a lattice-based, fully transparent polynomial commitment scheme (PCS) for univariate and multilinear polynomials. It is the first lattice PCS to simultaneously achieve logarithmic proof size and verification time with standard soundness under standard lattice assumptions over polynomial rings.

## Glossary

- **PCS (Polynomial Commitment Scheme)**: A cryptographic primitive that allows a prover to commit to a polynomial f in a short commitment Com(f), and later prove evaluations f(x) = y with a succinct proof π
- **M-SIS (Module Short Integer Solution)**: A lattice-based hardness assumption over polynomial rings Rq
- **Standard Soundness**: Soundness where the extracted witness satisfies all constraints with exact norm bounds (no relaxation)
- **Relaxed Soundness**: Soundness where the extracted witness may have a relaxed norm bound (e.g., 2B instead of B)
- **ℓ₂-norm**: Euclidean norm ∥f∥₂ = √(Σᵢ fᵢ²)
- **ℓ∞-norm**: Infinity norm ∥f∥∞ = maxᵢ |fᵢ|
- **Rq**: Polynomial ring Zq[X]/(Xᵈ + 1) where d is a power of 2
- **Tensor Product**: For vectors ⃗a ∈ Zqᵇ⁰ and ⃗b ∈ Zqᵇ¹, ⃗a ⊗ ⃗b ∈ Zqᵇ⁰ᵇ¹
- **Hypercube/Tensor**: k-dimensional array with shape b₀ × b₁ × ... × bₖ₋₁
- **Gadget Matrix**: Matrix Ga,m = Im ⊗ ⃗ga where ⃗ga = (1, a, a², ..., aⁱ⁻¹)
- **Conjugation Automorphism**: σ⁻¹(f) = Σᵢ fᵢX⁻ⁱ for f = Σᵢ fᵢXⁱ
- **LaBRADOR**: A proof-of-proof inner-product argument that compresses multiple linear/bilinear checks
- **Leveled Ajtai Commitment**: A hierarchical commitment scheme Fₖ₋₁,₀ with logarithmic structure
- **Challenge Space C**: A subset of Rq where differences of distinct elements are invertible
- **Guarded IPA**: Inner-product argument with smallness check to prevent modular wrap-around
- **Sum-Check Protocol**: Interactive proof for verifying Σₓ g(x) = v
- **zkSNARK**: Zero-knowledge Succinct Non-interactive Argument of Knowledge
- **Transparent Setup**: No trusted setup or trapdoors required
- **Witness Folding**: Recursive technique that combines witness halves using random challenges
- **Coordinate-wise Special Soundness**: Generalization of special soundness for multi-round protocols


## Requirements

### Requirement 1: Core Polynomial Commitment Scheme Interface

**User Story:** As a cryptographic protocol designer, I want a polynomial commitment scheme interface that supports both univariate and multilinear polynomials, so that I can build zkSNARKs and other advanced protocols.

#### Acceptance Criteria

1. WHEN the system is initialized with security parameter λ, THE HyperWolf_System SHALL generate public parameters pp = ((Aᵢ ∈ Rqᵏˣ²ᵏⁱ)ᵢ∈[1,k-1], A₀ ∈ Rqᵏˣ²ⁱ) where k = log(N/d), N is the polynomial degree bound, d is the ring dimension, ι = ⌈logb q⌉, and q is the prime modulus

2. WHEN a prover commits to a univariate polynomial f(X) = Σᵢ₌₀ᴺ⁻¹ fᵢXⁱ ∈ Zq[X], THE HyperWolf_System SHALL compute commitment cm = Fₖ₋₁,₀(⃗s) where ⃗s = G⁻¹b,N/d(MR(⃗f)) with MR being the integer-to-ring mapping and G⁻¹b,N/d being the gadget decomposition

3. WHEN a prover commits to a multilinear polynomial f(X₀, ..., Xₗ₋₁) = f₀ + f₁X₀ + f₂X₁ + ... + fₙ₋₁X₀X₁...Xₗ₋₁ with N = 2ℓ, THE HyperWolf_System SHALL compute commitment cm = Fₖ₋₁,₀(⃗s) using the same procedure as univariate case

4. WHEN a verifier receives commitment cm and opening (f, st), THE HyperWolf_System SHALL verify that Fₖ₋₁,₀(⃗s) = cm where ⃗s is derived from f

5. WHEN the commitment is computed, THE HyperWolf_System SHALL ensure ∥cm∥ is bounded by parameters derived from M-SIS hardness assumptions

### Requirement 2: Generalized Relation for PCS (Rpcs)

**User Story:** As a protocol implementer, I want a unified algebraic relation that captures both univariate and multilinear evaluation constraints with exact ℓ₂-norm soundness, so that I can prove polynomial evaluations with standard security guarantees.

#### Acceptance Criteria

1. WHEN proving polynomial evaluation, THE HyperWolf_System SHALL enforce relation Rpcs defined as:
   ```
   Rpcs = {
     ((cm, v, b ∈ Zq, ⃗a₀ ∈ Rqᵈ, (⃗aᵢ)ᵢ∈[1,k] ∈ Zqᵇⁱ),
      (⃗s ∈ Rqⁿ)) :
     ct(s⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻¹ ⃗aᵢ) = v,
     ct(⟨⃗s, σ⁻¹(⃗s)⟩) = b ≤ β₁²,
     Com(⃗s) = cm,
     ∥⃗s∥∞ ≤ β₂ ≤ q/√(nd)
   }
   ```
   where n = Nι/d = 2ᵏι, ct(·) extracts the constant term, and s⁽ᵏ⁾ is the k-dimensional tensor reshaping of ⃗s

2. WHEN the polynomial is univariate f(X) with evaluation point u, THE HyperWolf_System SHALL construct auxiliary vectors ⃗aᵢ = (1, u²ⁱᵈ) ∈ Z²q for i ∈ [1, k-1] and ⃗a₀ = (1, u, u², ..., u²ᵈ⁻¹) ∈ Z²ᵈq

3. WHEN the polynomial is multilinear f(X₀, ..., Xₗ₋₁) with evaluation point (u₀, ..., uₗ₋₁), THE HyperWolf_System SHALL construct ⃗aᵢ = (1, ulog d+i) ∈ Z²q and ⃗a₀ = ⊗ʲ₌₀ˡᵒᵍ ᵈ(1, uⱼ) ∈ Z²ᵈq

4. WHEN the evaluation constraint is satisfied, THE HyperWolf_System SHALL ensure ct(s⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻¹ ⃗aᵢ) = v equals f(u) or f(⃗u) depending on polynomial type

5. WHEN the norm constraint ∥⃗s∥∞ ≤ β₂ < q/√(nd) is satisfied together with ct(⟨⃗s, σ⁻¹(⃗s)⟩) = b, THE HyperWolf_System SHALL guarantee that ⟨⃗s, σ⁻¹(⃗s)⟩ mod q = ⟨⃗s, σ⁻¹(⃗s)⟩ over integers (no wrap-around)


### Requirement 3: k-Round Witness-Folding Recursion for Evaluation

**User Story:** As a prover, I want to prove polynomial evaluation through k-round recursive folding that reduces witness size dimension-by-dimension, so that I can achieve O(log N) proof size and verification time.

#### Acceptance Criteria

1. WHEN proving evaluation constraint ct(s⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻¹ ⃗aᵢ) = v, THE HyperWolf_System SHALL reshape witness ⃗s ∈ Rqⁿ into k-dimensional tensor s⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ¹ˣᵇ⁰ where N = ∏ᵢ₌₀ᵏ⁻¹ bᵢ and n = Nι/d

2. WHEN in round i ∈ [0, k-2], THE HyperWolf_System SHALL compute ⃗πeval,i = s⁽ᵏ⁻ⁱ⁾ · σ⁻¹(⃗a₀) · ∏ⱼ₌₁ᵏ⁻ⁱ⁻² ⃗aⱼ ∈ R²q using tensor-vector product as defined in Definition 1

3. WHEN the verifier receives ⃗πeval,i in round i = 0, THE HyperWolf_System SHALL verify ct(⟨⃗πeval,0, ⃗aₖ₋₁⟩) = v

4. WHEN the verifier receives ⃗πeval,i in round i ∈ [1, k-2], THE HyperWolf_System SHALL verify ⟨⃗πeval,i, ⃗aₖ₋ᵢ₋₁⟩ = ⟨⃗πeval,i-1, ⃗cₖ₋ᵢ⟩ where ⃗cₖ₋ᵢ ∈ C² is the challenge from previous round

5. WHEN the verifier samples challenge ⃗cₖ₋ᵢ₋₁ = (cₖ₋ᵢ₋₁,₀, cₖ₋ᵢ₋₁,₁) ∈ C² in round i, THE HyperWolf_System SHALL update witness to ⃗sₖ₋ᵢ₋₁ = cₖ₋ᵢ₋₁,₀⃗sₖ₋ᵢ,L + cₖ₋ᵢ₋₁,₁⃗sₖ₋ᵢ,R where ⃗sₖ₋ᵢ,L and ⃗sₖ₋ᵢ,R are left and right halves of ⃗sₖ₋ᵢ

6. WHEN in final round k-1, THE HyperWolf_System SHALL send final witness ⃗s⁽¹⁾ ∈ R²ⁱq and verifier SHALL verify ⟨⃗s⁽¹⁾, σ⁻¹(⃗a₀)⟩ = ⟨⃗πeval,k-2, ⃗c₁⟩

7. WHEN tensor-vector product f⁽ᵏ⁾ · ⃗a is computed for f⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ¹ˣᵇ⁰ and ⃗a = (a₀, ..., aᵦ₀₋₁) ∈ Rqᵇ⁰, THE HyperWolf_System SHALL compute Σᵢ₌₀ᵇ⁰⁻¹ aᵢfᵢ⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ²ˣᵇ¹ where fᵢ⁽ᵏ⁾ denotes the i-th slice along last dimension

8. WHEN vector-tensor product ⃗c⊤ · f⁽ᵏ⁾ is computed for ⃗c = (c₀, ..., cᵦₖ₋₁₋₁) ∈ Rqᵇᵏ⁻¹ and f⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ¹ˣᵇ⁰, THE HyperWolf_System SHALL compute Σᵢ₌₀ᵇᵏ⁻¹⁻¹ cᵢfᵢ⁽ᵏ⁻¹⁾ ∈ Rqᵇᵏ⁻²ˣ···ˣᵇ¹ˣᵇ⁰ where fᵢ⁽ᵏ⁻¹⁾ denotes the i-th slice along first dimension

9. WHEN k = log(N/d) and all bᵢ = 2, THE HyperWolf_System SHALL achieve O(log N) proof size and verification time for evaluation proof

### Requirement 4: Guarded Inner-Product Argument for Exact ℓ₂-Norm

**User Story:** As a security analyst, I want the norm constraint to be proven with exact ℓ₂-soundness (no relaxation), so that the extracted witness has the precise norm bound required by the relation.

#### Acceptance Criteria

1. WHEN proving norm constraint ∥⃗s∥₂ ≤ β₁, THE HyperWolf_System SHALL prove two sub-constraints: (i) ct(⟨⃗s, σ⁻¹(⃗s)⟩) mod q = b with b ≤ β₁², and (ii) ∥⃗s∥∞ ≤ β₂ where β₂² · dim(⃗s) < q

2. WHEN proving ct(⟨⃗s, σ⁻¹(⃗s)⟩) mod q = b in round i ∈ [0, k-2], THE HyperWolf_System SHALL split ⃗sᵢ into halves ⃗sᵢ,L, ⃗sᵢ,R ∈ Rq²ᵏ⁻ⁱ⁻¹ⁱ and compute:
   - Lᵢ = ⟨⃗sᵢ,L, σ⁻¹(⃗sᵢ,L)⟩
   - Mᵢ = ⟨⃗sᵢ,L, σ⁻¹(⃗sᵢ,R)⟩
   - Rᵢ = ⟨⃗sᵢ,R, σ⁻¹(⃗sᵢ,R)⟩

3. WHEN the verifier receives ⃗πnorm,i = (Lᵢ, Mᵢ, Rᵢ) in round i = 0, THE HyperWolf_System SHALL verify ct(L₀ + R₀) = b

4. WHEN the verifier receives ⃗πnorm,i in round i ∈ [1, k-2], THE HyperWolf_System SHALL verify ⟨⃗p₁, ⃗πnorm,i⟩ = ⟨⃗p₂,ᵢ, ⃗πnorm,i-1⟩ where ⃗p₁ = (1, 0, 1) and ⃗p₂,ᵢ = (c²ₖ₋ᵢ,₀, 2cₖ₋ᵢ,₀cₖ₋ᵢ,₁, c²ₖ₋ᵢ,₁)

5. WHEN the verifier samples challenge ⃗cₖ₋ᵢ₋₁ in round i, THE HyperWolf_System SHALL update witness to ⃗sₖ₋ᵢ₋₁ = cₖ₋ᵢ₋₁,₀⃗sₖ₋ᵢ,L + cₖ₋ᵢ₋₁,₁⃗sₖ₋ᵢ,R and verify ⟨⃗sₖ₋ᵢ₋₁, σ⁻¹(⃗sₖ₋ᵢ₋₁)⟩ = c²ₖ₋ᵢ₋₁,₀Lᵢ + 2cₖ₋ᵢ₋₁,₀cₖ₋ᵢ₋₁,₁Mᵢ + c²ₖ₋ᵢ₋₁,₁Rᵢ

6. WHEN in final round k-1, THE HyperWolf_System SHALL verify ⟨⃗s⁽¹⁾, σ⁻¹(⃗s⁽¹⁾)⟩ = ⟨⃗p₂,ₖ₋₁, ⃗πnorm,k-2⟩ where ⃗p₂,ₖ₋₁ = (c²₁,₀, 2c₁,₀c₁,₁, c²₁,₁)

7. WHEN in final round k-1, THE HyperWolf_System SHALL verify ∥⃗s⁽¹⁾∥∞ ≤ γ where γ = (2T)ᵏ⁻¹β₂ and T is the operator norm bound of challenges in C

8. WHEN both sub-constraints are satisfied with β₂² · nd < q, THE HyperWolf_System SHALL guarantee ⟨⃗s, σ⁻¹(⃗s)⟩ mod q = ⟨⃗s, σ⁻¹(⃗s)⟩ over integers, thus ∥⃗s∥₂² = b ≤ β₁² (exact ℓ₂-soundness)

9. WHEN the guarded IPA is complete, THE HyperWolf_System SHALL achieve O(log N) proof size and verification time for norm proof


### Requirement 5: Leveled Ajtai Commitment Verification

**User Story:** As a verifier, I want to efficiently verify the commitment structure through a logarithmic-depth hierarchy, so that I can check commitment consistency in O(log N) time.

#### Acceptance Criteria

1. WHEN proving Com(⃗s) = Fₖ₋₁,₀(⃗s) = cm, THE HyperWolf_System SHALL use leveled commitment structure where for N = ∏ᵢ₌₀ᵏ⁻¹ mᵢ and matrices A₀, A₁, ..., Aₖ₋₁ with Aᵢ ∈ Rqᵏˣᵐⁱᵏˡ and A₀ ∈ Rqᵏˣᵐ⁰ˡ, the commitment is defined recursively as:
   ```
   Fᵢ,ⱼ(⃗s) = {
     Aᵢ⃗s mod q                                           if i = j,
     Fᵢ,ⱼ₊₁(G⁻¹ᵦ,Mᵢ,ⱼᵏ((IMᵢ,ⱼ ⊗ Aⱼ) · G⁻¹ᵦ,N(⃗s)))      if i > j
   }
   ```
   where Mᵢ,ⱼ = mᵢ · mᵢ₋₁ · ... · mⱼ₊₁

2. WHEN in round i ∈ [0, k-2], THE HyperWolf_System SHALL split ⃗sᵢ into halves and compute cmᵢ,₀ = Com(⃗sᵢ,L) and cmᵢ,₁ = Com(⃗sᵢ,R)

3. WHEN the prover sends ⃗πcm,i = G⁻¹₂ᵏ(cmᵢ,₀, cmᵢ,₁) ∈ R²ᵏⁱq in round i = 0, THE HyperWolf_System SHALL verify Aₖ₋₁⃗πcm,0 = cm

4. WHEN the prover sends ⃗πcm,i in round i ∈ [1, k-2], THE HyperWolf_System SHALL verify Aₖ₋ᵢ₋₁⃗πcm,i = [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ]⃗πcm,i-1 where Gᵏ is the gadget matrix

5. WHEN in final round k-1, THE HyperWolf_System SHALL verify A₀⃗s⁽¹⁾ = [c₁,₀Gᵏ c₁,₁Gᵏ]⃗πcm,k-2

6. WHEN the leveled commitment is binding, THE HyperWolf_System SHALL ensure M-SISᵏ,ₙ,q,₂β hardness holds for n = max((mᵢκℓ)ᵢ∈[1,k], m₀ℓ) and β = max((√(mᵢκℓ) · 2b)ᵢ∈[1,k], √(m₀ℓ) · 2b)

7. WHEN all commitment checks pass, THE HyperWolf_System SHALL guarantee that the committed witness ⃗s satisfies Com(⃗s) = cm with O(log N) verification cost

### Requirement 6: Combined Protocol Integration

**User Story:** As a protocol designer, I want the evaluation proof, norm proof, and commitment proof to be integrated into a unified k-round protocol, so that I can achieve optimal efficiency with shared challenges and messages.

#### Acceptance Criteria

1. WHEN executing the combined protocol for k = log(N/d) rounds, THE HyperWolf_System SHALL send in each round i ∈ [0, k-2] a combined proof ⃗πᵢ = (⃗πeval,i, ⃗πnorm,i, ⃗πcm,i) where:
   - ⃗πeval,i ∈ R²q
   - ⃗πnorm,i = (Lᵢ, Mᵢ, Rᵢ) ∈ R³q
   - ⃗πcm,i = G⁻¹₂ᵏ(cmᵢ,₀, cmᵢ,₁) ∈ R²ᵏⁱq

2. WHEN in round i = 0, THE HyperWolf_System SHALL verify:
   - ct(⟨⃗πeval,0, ⃗aₖ₋₁⟩) = v
   - ct(⟨(1, 0, 1), ⃗πnorm,0⟩) = b
   - Aₖ₋₁⃗πcm,0 = cm

3. WHEN in round i ∈ [1, k-2], THE HyperWolf_System SHALL verify:
   - ⟨⃗πeval,i, ⃗aₖ₋ᵢ₋₁⟩ = ⟨⃗πeval,i-1, ⃗cₖ₋ᵢ⟩
   - ⟨⃗p₁, ⃗πnorm,i⟩ = ⟨⃗p₂,ᵢ, ⃗πnorm,i-1⟩
   - Aₖ₋ᵢ₋₁⃗πcm,i = [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ]⃗πcm,i-1

4. WHEN the verifier accepts round i checks, THE HyperWolf_System SHALL sample challenge ⃗cₖ₋ᵢ₋₁ ∈ C² and send to prover

5. WHEN in final round k-1, THE HyperWolf_System SHALL receive ⃗s⁽¹⁾ ∈ R²ⁱq and verify:
   - ⟨⃗s⁽¹⁾, σ⁻¹(⃗a₀)⟩ = ⟨⃗πeval,k-2, ⃗c₁⟩
   - ⟨⃗s⁽¹⁾, σ⁻¹(⃗s⁽¹⁾)⟩ = ⟨⃗p₂,ₖ₋₁, ⃗πnorm,k-2⟩
   - A₀⃗s⁽¹⁾ = [c₁,₀Gᵏ c₁,₁Gᵏ]⃗πcm,k-2
   - ∥⃗s⁽¹⁾∥∞ ≤ γ = (2T)ᵏ⁻¹β₂

6. WHEN all k rounds complete successfully, THE HyperWolf_System SHALL guarantee that the witness ⃗s satisfies all constraints in Rpcs

7. WHEN k = log(N/d), THE HyperWolf_System SHALL achieve total proof size O(k · (5 + 2κι)) = O(log N) ring elements

8. WHEN k = log(N/d), THE HyperWolf_System SHALL achieve verification time O(k · (4 + 6 + 2κ²ι + 2κ)) = O(log N) ring operations

9. WHEN k = log(N/d), THE HyperWolf_System SHALL achieve prover time O(Σᵢ₌₀ᵏ⁻¹(2ᵏ⁻ⁱ · 2κ²ι + 2ᵏ⁻ⁱ)) = O(N) ring operations


### Requirement 7: LaBRADOR Compression for Sub-logarithmic Proofs

**User Story:** As a bandwidth-conscious user, I want the proof size to be further compressed to O(log log log N) using LaBRADOR, so that I can minimize communication costs while maintaining logarithmic verification.

#### Acceptance Criteria

1. WHEN the combined protocol produces k-1 round proofs ⃗π₀, ..., ⃗πₖ₋₂ and final witness ⃗s⁽¹⁾, THE HyperWolf_System SHALL construct input vectors (⃗z₀, ..., ⃗zᵣ₋₁) for LaBRADOR where r = 3k - 1 by setting:
   - ⃗z₃ᵢ₊ⱼ = ⃗πᵢ,ⱼ for i ∈ [k-1], j ∈ [3]
   - ⃗zᵣ₋₂ = ⃗s⁽¹⁾
   - ⃗zᵣ₋₁ = σ⁻¹(⃗s⁽¹⁾)
   - Each ⃗zₗ padded to length n = r² with zeros

2. WHEN constructing the LaBRADOR relation, THE HyperWolf_System SHALL define function g(⃗z₀, ..., ⃗zᵣ₋₁) = α⟨⃗zᵣ₋₂, ⃗zᵣ₋₁⟩ + Σᵢ₌₀ʳ⁻² ⟨φᵢ, ⃗zᵢ⟩ - β = 0 where:
   - α = 1
   - β = Σᵢ₌₀ᵏ⁻¹ cmᵢ + v + b
   - φ₃ᵢ = ⃗aₖ₋ᵢ₋₁ - ⃗cₖ₋ᵢ₋₁
   - φ₃ᵢ₊₁ = ⃗p₁ - ⃗p₂,ᵢ₊₁
   - φ₃ᵢ₊₂ = Σⱼ₌₀ᵏ⁻¹ Aₖ₋ᵢ₋₁,ⱼ - [cₖ₋ᵢ₋₁,₁Gᵏ cₖ₋ᵢ₋₁,₀Gᵏ]ⱼ for i ∈ [k-1]
   - φᵣ₋₂ = σ⁻¹(⃗a₀)

3. WHEN constructing the LaBRADOR norm constraint, THE HyperWolf_System SHALL enforce Σᵢ₌₁² ∥⃗zᵣ₋ᵢ∥₂² ≤ 2nγ² where γ = (2T)ᵏ⁻¹β₂

4. WHEN the LaBRADOR input has total size N' = r · n = r³ = (3k - 1)³ = O(log³ N), THE HyperWolf_System SHALL apply LaBRADOR protocol to reduce proof size to O(log log N') = O(log log log N)

5. WHEN the LaBRADOR protocol is applied, THE HyperWolf_System SHALL maintain verification time O(log N) by exploiting sparsity: only O(log N) non-zero elements across all ⃗zᵢ vectors

6. WHEN computing inner products ⟨φᵢ, ⃗zᵢ⟩ in LaBRADOR verification, THE HyperWolf_System SHALL perform O(log N) ring operations total due to sparsity

7. WHEN the LaBRADOR proof is complete, THE HyperWolf_System SHALL achieve final proof size O(log(log(r · n))) = O(log(log(log N))) ring elements

8. WHEN the LaBRADOR verification is complete, THE HyperWolf_System SHALL maintain total verification cost O(log N + log N) = O(log N) ring operations

### Requirement 8: Challenge Space and Invertibility

**User Story:** As a security engineer, I want the challenge space to be carefully designed to ensure invertibility and bounded norms, so that the protocol achieves coordinate-wise special soundness with negligible error.

#### Acceptance Criteria

1. WHEN defining challenge space C ⊂ Rq, THE HyperWolf_System SHALL ensure that for any two distinct elements c₁, c₂ ∈ C, the difference c₁ - c₂ is invertible in Rq

2. WHEN selecting challenges from C, THE HyperWolf_System SHALL ensure ∥c∥₂ ≤ τ for all c ∈ C where τ is a constant bound

3. WHEN selecting challenges from C, THE HyperWolf_System SHALL ensure ∥c∥op ≤ T for all c ∈ C where ∥c∥op = supᵥ∈Rq ∥cv∥/∥v∥ is the operator norm

4. WHEN q is prime with q ≡ 5 mod 8, THE HyperWolf_System SHALL guarantee that any f ∈ Rq with 0 < ∥f∥ < q¹/² has an inverse in Rq (Lemma 1)

5. WHEN the challenge space is instantiated with d = 64 ring dimension, THE HyperWolf_System SHALL define C as ring elements with 24 zero coefficients, 32 coefficients in {±1}, and 8 coefficients in {±2}

6. WHEN the challenge space is instantiated as above, THE HyperWolf_System SHALL achieve |C| ≈ (⁶⁴₃₂) · 2³² + (³²₈) · 2⁸ ≈ 2¹²⁸·⁶

7. WHEN applying reject sampling to challenges, THE HyperWolf_System SHALL restrict operator norm T ≤ 10

8. WHEN the challenge space satisfies these properties, THE HyperWolf_System SHALL achieve knowledge soundness error bounded by 2(k-1)/|C| + 6(k-2)d+6dι/q


### Requirement 9: Security Properties - Completeness

**User Story:** As a protocol verifier, I want perfect completeness guarantees, so that honest provers always succeed in proving valid statements.

#### Acceptance Criteria

1. WHEN an honest prover P executes the protocol with valid witness ⃗s satisfying all constraints in Rpcs, THE HyperWolf_System SHALL ensure the verifier V accepts with probability 1

2. WHEN the challenge space C consists of ring elements with ℓ₂-norm bounded by τ and operator norm bounded by T, THE HyperWolf_System SHALL guarantee perfect completeness

3. WHEN in round i, the prover computes ⃗sᵢ = cᵢ,₀⃗sᵢ₊₁,L + cᵢ,₁⃗sᵢ₊₁,R, THE HyperWolf_System SHALL ensure ∥⃗sᵢ∥∞ ≤ 2T · ∥⃗sᵢ₊₁∥∞

4. WHEN after k-1 folding rounds, THE HyperWolf_System SHALL ensure ∥⃗s⁽¹⁾∥∞ ≤ (2T)ᵏ⁻¹∥⃗s∥∞ ≤ (2T)ᵏ⁻¹β₂ = γ

5. WHEN the final witness satisfies ∥⃗s⁽¹⁾∥∞ ≤ γ, THE HyperWolf_System SHALL pass the smallness check in the final round

6. WHEN all intermediate checks are correctly computed by honest prover, THE HyperWolf_System SHALL ensure all verification equations hold with equality

7. WHEN perfect completeness is achieved, THE HyperWolf_System SHALL have completeness error ϵ = 0

### Requirement 10: Security Properties - Coordinate-wise Special Soundness

**User Story:** As a cryptographer, I want the protocol to achieve coordinate-wise special soundness, so that I can extract valid witnesses from accepting transcripts with overwhelming probability.

#### Acceptance Criteria

1. WHEN given a tree of K = (2(k-1) + 1)ᵏ⁻¹ = 3ᵏ⁻¹ accepting transcripts organized as in Definition 8, THE HyperWolf_System SHALL extract a witness s̄ satisfying Com(s̄) = cm

2. WHEN extracting from the transcript tree, THE HyperWolf_System SHALL obtain relaxed witness s̄ where ∥c̄s̄∥∞ ≤ 2γ for c̄ = ∏ᵢ₌₁ᵏ⁻¹ c̄ᵢ with each c̄ᵢ ∈ C - C

3. WHEN extracting at depth 1 with fixed ⃗cₖ₋₁, ..., ⃗c₂ and (⃗c₁,ᵢ)ᵢ∈[3] ∈ SS(C, 2, 2), THE HyperWolf_System SHALL extract s̄₂ = ((⃗s₁,₁ - ⃗s₁,₀)/c̄₁,₁, (⃗s₁,₂ - ⃗s₁,₀)/c̄₁,₂) where c̄₁,₁ = c₁,₁,₀ - c₁,₀,₀ and c̄₁,₂ = c₁,₂,₁ - c₁,₀,₁

4. WHEN extracting at depth i, THE HyperWolf_System SHALL recursively obtain s̄ᵢ₊₁ = ((s̄ᵢ,₁ - s̄ᵢ,₀)/c̄ᵢ,₁, (s̄ᵢ,₂ - s̄ᵢ,₀)/c̄ᵢ,₂) with ∥c̄ᵢs̄ᵢ₊₁∥∞ ≤ 2∥s̄ᵢ∥∞

5. WHEN extraction reaches depth k-1, THE HyperWolf_System SHALL obtain final witness s̄ with ∥∏ᵢ₌₁ᵏ⁻¹ c̄ᵢ · s̄∥∞ ≤ 2γ

6. WHEN the extracted witness s̄ satisfies evaluation constraint, THE HyperWolf_System SHALL ensure ct(s̄⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻¹ ⃗aᵢ) = v with soundness error at most 2dι/q for base case k=1

7. WHEN the extracted witness s̄ satisfies norm constraint, THE HyperWolf_System SHALL ensure ct(⟨s̄, σ⁻¹(s̄)⟩) = b with soundness error at most 4dι/q for base case k=1

8. WHEN k ≥ 2 and prover sends incorrect ⃗πeval,0 or ⃗πnorm,0, THE HyperWolf_System SHALL bound success probability by 6d/q + (6(k-2)d + 6dι)/q = (6(k-1)d + 6dι)/q

9. WHEN the M-SIS problem is hard for rank κ and norm bound max(√(8Tγ√(2ι)), √(2γ√(2ι))) where γ = (2T)ᵏ⁻¹β₂ < q/(2√n), THE HyperWolf_System SHALL achieve 2-coordinate-wise 2-special soundness with additional soundness error 3(k-2)d+3dι/q

10. WHEN ∥c̄s̄∥∞ ≤ 2γ < q/√n, THE HyperWolf_System SHALL guarantee no wrap-around in norm computation, thus ct(⟨s̄, σ⁻¹(s̄)⟩) mod q = ct(⟨s̄, σ⁻¹(s̄)⟩) over integers

### Requirement 11: Security Properties - Knowledge Soundness

**User Story:** As a security auditor, I want knowledge soundness with negligible error, so that malicious provers cannot convince verifiers of false statements except with negligible probability.

#### Acceptance Criteria

1. WHEN the protocol achieves 2-coordinate-wise 2-special soundness with (2(k-1))ᵏ⁻¹ = poly(λ), THE HyperWolf_System SHALL achieve knowledge soundness by Lemma 2

2. WHEN the knowledge soundness error from coordinate-wise special soundness is μ·2(k-1)/|C| where μ = k-1, THE HyperWolf_System SHALL bound this component by 2(k-1)/|C|

3. WHEN the additional soundness error from extraction is 6(k-2)d+6dι/q, THE HyperWolf_System SHALL apply union bound to obtain total knowledge soundness error 2(k-1)/|C| + 6(k-2)d+6dι/q

4. WHEN security parameter λ = 128, modulus q ≈ 2¹²⁸, challenge space |C| ≈ 2¹²⁸·⁶, and k = O(log N), THE HyperWolf_System SHALL achieve knowledge soundness error O(2⁻λ) = negligible

5. WHEN there exists an expected PPT extractor E that, given accepting transcript and oracle access to malicious prover P*, THE HyperWolf_System SHALL extract witness w with (pp, x, w) ∈ Rpcs except with probability bounded by knowledge soundness error

6. WHEN the extractor E rewinds the prover to construct transcript tree, THE HyperWolf_System SHALL run in expected polynomial time

7. WHEN knowledge soundness holds, THE HyperWolf_System SHALL guarantee that any accepting proof implies existence of valid witness satisfying all constraints in Rpcs with overwhelming probability


### Requirement 12: Security Properties - Weak Binding

**User Story:** As a commitment scheme user, I want weak binding guarantees, so that it is computationally infeasible to open a commitment to two different polynomials.

#### Acceptance Criteria

1. WHEN an adversary A attempts to find two distinct polynomials f ≠ f' with valid openings to the same commitment cm, THE HyperWolf_System SHALL ensure this occurs with probability at most neg(λ)

2. WHEN the M-SISκ,n,q,2β problem is hard for parameters n = max((mᵢκℓ)ᵢ∈[1,k], m₀ℓ) and β = max((√(mᵢκℓ) · 2b)ᵢ∈[1,k], √(m₀ℓ) · 2b), THE HyperWolf_System SHALL achieve weak binding

3. WHEN two distinct witnesses ⃗s ≠ ⃗s' both satisfy Com(⃗s) = Com(⃗s') = cm, THE HyperWolf_System SHALL enable construction of M-SIS solution with norm ∥⃗s - ⃗s'∥ ≤ 2β

4. WHEN the Ajtai commitment is used with matrix A ∈ Rqκ×n, THE HyperWolf_System SHALL ensure binding under M-SISκ,n,q,2β assumption

5. WHEN weak binding holds, THE HyperWolf_System SHALL guarantee that for any PPT adversary A, Pr[f ≠ f' ∧ f, f' ∈ R<N[X] ∧ Open(pp, cm, f, st, c) = Open(pp, cm, f', st', c') = 1] = neg(λ)

### Requirement 13: Parameter Selection and Concrete Instantiation

**User Story:** As a system implementer, I want concrete parameter recommendations that achieve 128-bit security, so that I can deploy the system with confidence in its security guarantees.

#### Acceptance Criteria

1. WHEN targeting λ = 128-bit security, THE HyperWolf_System SHALL select prime modulus q ≈ 2¹²⁸ with q ≡ 5 mod 8

2. WHEN selecting ring dimension, THE HyperWolf_System SHALL use d = 64 (power of 2)

3. WHEN selecting matrix height, THE HyperWolf_System SHALL use κ = 18

4. WHEN selecting challenge norm bounds, THE HyperWolf_System SHALL use τ = 8 for ℓ₂-norm and T = 10 for operator norm

5. WHEN selecting challenge space, THE HyperWolf_System SHALL construct C with |C| ≈ 2¹²⁸·⁶ using 24 zero coefficients, 32 coefficients in {±1}, and 8 coefficients in {±2}

6. WHEN selecting decomposition basis, THE HyperWolf_System SHALL use either (b, ι) = (4, 42) or (b, ι) = (16, 32) where ι = ⌈logb q⌉

7. WHEN selecting infinity norm bound, THE HyperWolf_System SHALL use β₂ = b/2

8. WHEN the M-SIS hardness requires norm bound below min(q, 2²√(dκ log q log(1.0045))), THE HyperWolf_System SHALL ensure parameters satisfy this constraint

9. WHEN selecting maximum polynomial degree, THE HyperWolf_System SHALL ensure N < 2³³ to maintain soundness error O(2⁻λ)

10. WHEN parameters are selected, THE HyperWolf_System SHALL ensure 2γ < q/√n where γ = (2T)ᵏ⁻¹β₂ and n = Nι/d = 2ᵏι

11. WHEN parameters are selected, THE HyperWolf_System SHALL ensure knowledge soundness error 2(k-1)/|C| + 6(k-2)d+6dι/q ≤ 2⁻λ

12. WHEN LaBRADOR is used, THE HyperWolf_System SHALL ensure (3k - 1)² ≥ max(2κι, 3ι) for witness length requirement

### Requirement 14: Efficiency Guarantees

**User Story:** As a performance-conscious developer, I want concrete efficiency guarantees for proof size, verification time, and prover time, so that I can evaluate the system's practical performance.

#### Acceptance Criteria

1. WHEN k = log(N/d) and all bᵢ = 2, THE HyperWolf_System SHALL achieve proof size (without LaBRADOR) of ((k-1) · (5 + 2κι) + 2κι) · (d log q) bits = O(log N) bits

2. WHEN LaBRADOR compression is applied, THE HyperWolf_System SHALL achieve proof size O(log log log N) ring elements

3. WHEN verifying without LaBRADOR, THE HyperWolf_System SHALL perform O(k · (4 + 6 + 2κ²ι + 2κ)) = O(log N) ring operations

4. WHEN verifying with LaBRADOR, THE HyperWolf_System SHALL maintain O(log N) ring operations by exploiting sparsity

5. WHEN proving, THE HyperWolf_System SHALL perform O(Σᵢ₌₀ᵏ⁻¹(2ᵏ⁻ⁱ · 2κ²ι + 2ᵏ⁻ⁱ)) = O(2ᵏ⁺¹ · 2κ²ι) = O(N) ring operations

6. WHEN N = 2²⁰, THE HyperWolf_System SHALL achieve proof size approximately 43 KB

7. WHEN N = 2²⁶, THE HyperWolf_System SHALL achieve proof size approximately 46 KB

8. WHEN N = 2²⁸, THE HyperWolf_System SHALL achieve proof size approximately 52 KB

9. WHEN N = 2³⁰, THE HyperWolf_System SHALL achieve proof size approximately 53 KB

10. WHEN compared to Greyhound at N = 2³⁰, THE HyperWolf_System SHALL reduce verifier work from Θ(√N) to Θ(log N), yielding 2-3 orders of magnitude improvement

11. WHEN constants κ and ι are fixed, THE HyperWolf_System SHALL achieve asymptotic complexities: O(N) prover time, O(log N) verification time, O(log log log N) proof size


### Requirement 15: Batching - Multiple Polynomials at Single Point

**User Story:** As a protocol user, I want to batch multiple polynomial evaluations at a single point, so that I can reduce proof size and verification time when proving multiple claims simultaneously.

#### Acceptance Criteria

1. WHEN proving n claims fᵢ(u) = vᵢ (or fᵢ(⃗u) = vᵢ) for i ∈ [n] at common point u (or ⃗u), THE HyperWolf_System SHALL sample random challenge vector ⃗α ← Zqⁿ

2. WHEN the challenge ⃗α is sampled, THE HyperWolf_System SHALL form linear combination f = Σᵢ₌₀ⁿ⁻¹ αᵢfᵢ

3. WHEN the linear combination is formed, THE HyperWolf_System SHALL compute claimed value y = Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ

4. WHEN the batched claim is constructed, THE HyperWolf_System SHALL run single evaluation proof for f at u (or ⃗u) with claimed value y

5. WHEN the batched proof is complete, THE HyperWolf_System SHALL achieve proof size O(log N) instead of O(n log N) for n separate proofs

6. WHEN completeness holds for single evaluation, THE HyperWolf_System SHALL ensure completeness for batched evaluation

7. WHEN knowledge soundness holds for single evaluation with error ε, THE HyperWolf_System SHALL achieve knowledge soundness for batched evaluation with error at most n·ε by rewinding and extracting each fᵢ

### Requirement 16: Batching - Single Polynomial at Multiple Points (Multilinear)

**User Story:** As a sum-check protocol user, I want to batch evaluations of a single multilinear polynomial at multiple points, so that I can efficiently verify multiple evaluation claims.

#### Acceptance Criteria

1. WHEN proving n claims f(⃗uᵢ) = vᵢ for i ∈ [n] for multilinear f, THE HyperWolf_System SHALL construct f̃(⃗x) = Σ⃗b∈{0,1}^(log N) f(⃗b) · eq̃(⃗b, ⃗x) where eq̃(⃗b, ⃗x) = ∏ᵢ₌₀^(log N-1) (b[i]x[i] + (1-b[i])(1-x[i]))

2. WHEN f̃ is constructed, THE HyperWolf_System SHALL ensure f̃(⃗x) = f(⃗x) for all ⃗x ∈ Zq^(log N) since both are multilinear and agree on Boolean hypercube

3. WHEN the verifier samples ⃗α ← Zqⁿ, THE HyperWolf_System SHALL construct g(⃗x) = Σᵢ₌₀ⁿ⁻¹ αᵢ · f(⃗x) · eq̃(⃗x, ⃗uᵢ)

4. WHEN g is constructed, THE HyperWolf_System SHALL run sum-check protocol for Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ = Σ⃗b∈{0,1}^(log N) g(⃗b)

5. WHEN sum-check reduces to random point ⃗r, THE HyperWolf_System SHALL verify f(⃗r) = v using single-point PCS evaluation

6. WHEN sum-check reduces to random point ⃗r, THE HyperWolf_System SHALL compute eq̃(⃗r, ⃗uᵢ) = zᵢ directly by verifier

7. WHEN the batched proof is complete, THE HyperWolf_System SHALL achieve total cost O(n log N + log N) = O(n log N) for sum-check plus single evaluation

8. WHEN completeness and knowledge soundness hold for sum-check and PCS, THE HyperWolf_System SHALL ensure completeness and knowledge soundness for batched multilinear evaluation

### Requirement 17: Batching - Single Polynomial at Multiple Points (Univariate)

**User Story:** As a univariate polynomial user, I want to batch evaluations at multiple points by reducing to the multilinear case, so that I can leverage the same batching infrastructure.

#### Acceptance Criteria

1. WHEN proving n claims f(uᵢ) = vᵢ for i ∈ [n] for univariate f(X) = Σᵢ₌₀ᴺ⁻¹ fᵢXⁱ, THE HyperWolf_System SHALL define Xⱼ = X^(2^j) for j ∈ [0, log N - 1]

2. WHEN the variables are defined, THE HyperWolf_System SHALL rewrite f as multilinear polynomial f(X₀, X₁, ..., Xₗ₋₁) = f₀ + f₁X₀ + f₂X₁ + ... + fₙ₋₁X₀X₁...Xₗ₋₁ with same coefficient vector

3. WHEN evaluation points are transformed, THE HyperWolf_System SHALL construct ⃗uᵢ = (uᵢ, uᵢ², uᵢ⁴, ..., uᵢ^(2^(ℓ-1))) for each i ∈ [n]

4. WHEN the transformation is complete, THE HyperWolf_System SHALL ensure f(⃗uᵢ) = f(uᵢ) for all i

5. WHEN the univariate case is reduced to multilinear, THE HyperWolf_System SHALL apply the multilinear batching protocol from Requirement 16

6. WHEN the batched proof is complete, THE HyperWolf_System SHALL achieve same efficiency as multilinear case: O(n log N) total cost

### Requirement 18: Batching - Multiple Polynomials at Multiple Points

**User Story:** As an advanced protocol designer, I want to batch evaluations of multiple polynomials at multiple points, so that I can handle the most general batching scenario efficiently.

#### Acceptance Criteria

1. WHEN proving n claims fᵢ(⃗uᵢ) = vᵢ for i ∈ [n], THE HyperWolf_System SHALL sample random challenge vector ⃗α ← Zqⁿ

2. WHEN the challenge is sampled, THE HyperWolf_System SHALL construct combined polynomial g(⃗x) = Σᵢ₌₀ⁿ⁻¹ αᵢ · fᵢ(⃗x) · eq̃(⃗x, ⃗uᵢ)

3. WHEN g is constructed, THE HyperWolf_System SHALL run sum-check protocol for Σᵢ₌₀ⁿ⁻¹ αᵢvᵢ = Σ⃗b∈{0,1}^(log N) g(⃗b)

4. WHEN sum-check reduces to random point ⃗r, THE HyperWolf_System SHALL verify evaluations fᵢ(⃗r) for all i ∈ [n] using batching technique from Requirement 15

5. WHEN the batched proof is complete, THE HyperWolf_System SHALL achieve total cost O(n log N + log N) = O(n log N) for sum-check plus batched single-point evaluation

6. WHEN completeness and knowledge soundness hold for sum-check and batched PCS, THE HyperWolf_System SHALL ensure completeness and knowledge soundness for general batching


### Requirement 19: Mathematical Primitives - Polynomial Ring Operations

**User Story:** As a low-level implementer, I want precise definitions of all polynomial ring operations, so that I can implement the system correctly without ambiguity.

#### Acceptance Criteria

1. WHEN defining polynomial ring Rq, THE HyperWolf_System SHALL use Rq = Zq[X]/(Xᵈ + 1) where d is a power of 2 and q is prime

2. WHEN computing ring element norms, THE HyperWolf_System SHALL define for f = Σᵢ₌₀ᵈ⁻¹ fᵢXⁱ ∈ Rq:
   - ℓ₁-norm: ∥f∥₁ = Σᵢ₌₀ᵈ⁻¹ |fᵢ|
   - ℓ₂-norm: ∥f∥₂ = √(Σᵢ₌₀ᵈ⁻¹ fᵢ²)
   - ℓ∞-norm: ∥f∥∞ = maxᵢ∈[d] |fᵢ|

3. WHEN computing vector norms for ⃗f = (f₀, ..., fₘ₋₁) ∈ Rqᵐ, THE HyperWolf_System SHALL define:
   - ∥⃗f∥₁ = Σᵢ₌₀ᵐ⁻¹ ∥fᵢ∥₁
   - ∥⃗f∥₂ = √(Σᵢ₌₀ᵐ⁻¹ ∥fᵢ∥₂²)
   - ∥⃗f∥∞ = maxᵢ∈[m] ∥fᵢ∥∞

4. WHEN relating norms, THE HyperWolf_System SHALL ensure ∥⃗f∥∞ ≤ ∥⃗f∥₂ ≤ √(md)∥⃗f∥∞

5. WHEN computing conjugation automorphism σ⁻¹, THE HyperWolf_System SHALL define for f = Σᵢ₌₀ᵈ⁻¹ fᵢXⁱ: σ⁻¹(f) = Σᵢ₌₀ᵈ⁻¹ fᵢX⁻ⁱ

6. WHEN computing constant term ct(f), THE HyperWolf_System SHALL extract ct(f) = f₀ for f = Σᵢ₌₀ᵈ⁻¹ fᵢXⁱ

7. WHEN computing inner product between ring vectors ⃗a, ⃗b ∈ Rqⁿ, THE HyperWolf_System SHALL ensure ct(⟨σ⁻¹(⃗a), ⃗b⟩) = ⟨⃗a, ⃗b⟩ where ⃗a, ⃗b ∈ Zqⁿᵈ are coefficient representations

8. WHEN computing operator norm ∥c∥op for c ∈ Rq, THE HyperWolf_System SHALL define ∥c∥op = supᵥ∈Rq ∥cv∥/∥v∥

### Requirement 20: Mathematical Primitives - Gadget Matrix and Decomposition

**User Story:** As a commitment scheme implementer, I want precise gadget matrix definitions and decomposition algorithms, so that I can implement leveled commitments correctly.

#### Acceptance Criteria

1. WHEN defining gadget vector for basis a ∈ ℕ, THE HyperWolf_System SHALL construct ⃗ga = (1, a, a², ..., aⁱ⁻¹) where ι = ⌈loga q⌉

2. WHEN defining gadget matrix for dimension m, THE HyperWolf_System SHALL construct Ga,m = Im ⊗ ⃗ga ∈ Zqᵐˣⁱᵐ where Im is m×m identity matrix

3. WHEN decomposing matrix A ∈ Rqᵐˣⁿ, THE HyperWolf_System SHALL compute Ã = G⁻¹a,m(A) ∈ Rqⁱᵐˣⁿ such that A = Ga,mÃ

4. WHEN decomposition is applied to column Ãᵢ, THE HyperWolf_System SHALL ensure ∥Ãᵢ∥ ≤ √(a²ιm) for each i ∈ [n]

5. WHEN basis a is clear from context, THE HyperWolf_System SHALL write G⁻¹m instead of G⁻¹a,m

6. WHEN applying decomposition, THE HyperWolf_System SHALL ensure Ga,mG⁻¹a,m(A) = A (reconstruction property)

### Requirement 21: Mathematical Primitives - Integer-to-Ring Mapping

**User Story:** As a polynomial commitment implementer, I want precise integer-to-ring mapping definitions, so that I can correctly transform coefficient vectors into ring vectors.

#### Acceptance Criteria

1. WHEN mapping coefficient vector ⃗f = (f₀, f₁, ..., fₙd₋₁) ∈ Zqⁿᵈ to ring vector, THE HyperWolf_System SHALL define MR: Zqⁿᵈ → Rqⁿ as:
   ```
   MR(⃗f) = (Σⱼ₌₀ᵈ⁻¹ fⱼXʲ, Σⱼ₌₀ᵈ⁻¹ fd+jXʲ, ..., Σⱼ₌₀ᵈ⁻¹ f(n-1)d+jXʲ)
   ```

2. WHEN applying MR to univariate polynomial coefficients, THE HyperWolf_System SHALL group d consecutive coefficients into each ring element

3. WHEN applying MR to multilinear polynomial coefficients, THE HyperWolf_System SHALL use the same grouping structure

4. WHEN MR is applied, THE HyperWolf_System SHALL ensure the mapping is injective (one-to-one)

5. WHEN MR is applied, THE HyperWolf_System SHALL preserve the polynomial evaluation structure through auxiliary vectors ⃗aᵢ

### Requirement 22: Mathematical Primitives - Tensor Operations

**User Story:** As a tensor arithmetic implementer, I want precise definitions of tensor-vector products and tensor reshaping, so that I can implement k-dimensional witness folding correctly.

#### Acceptance Criteria

1. WHEN defining k-dimensional tensor f⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ¹ˣᵇ⁰, THE HyperWolf_System SHALL interpret it as hypercube with shape (bk-1, ..., b₁, b₀)

2. WHEN computing tensor-vector product f⁽ᵏ⁾ · ⃗a for ⃗a = (a₀, ..., aᵦ₀₋₁) ∈ Rqᵇ⁰, THE HyperWolf_System SHALL compute Σᵢ₌₀ᵇ⁰⁻¹ aᵢfᵢ⁽ᵏ⁾ ∈ Rqᵇᵏ⁻¹ˣ···ˣᵇ²ˣᵇ¹ where fᵢ⁽ᵏ⁾ is i-th slice along last dimension

3. WHEN computing vector-tensor product ⃗c⊤ · f⁽ᵏ⁾ for ⃗c = (c₀, ..., cᵦₖ₋₁₋₁) ∈ Rqᵇᵏ⁻¹, THE HyperWolf_System SHALL compute Σᵢ₌₀ᵇᵏ⁻¹⁻¹ cᵢfᵢ⁽ᵏ⁻¹⁾ ∈ Rqᵇᵏ⁻²ˣ···ˣᵇ¹ˣᵇ⁰ where fᵢ⁽ᵏ⁻¹⁾ is i-th slice along first dimension

4. WHEN reshaping vector ⃗s ∈ Rqⁿ into k-dimensional tensor s⁽ᵏ⁾, THE HyperWolf_System SHALL ensure concatenating row vectors of s⁽ᵏ⁾ recovers ⃗s

5. WHEN N = ∏ᵢ₌₀ᵏ⁻¹ bᵢ and n = Nι/d, THE HyperWolf_System SHALL ensure tensor s⁽ᵏ⁾ has shape (bk-1ι, ..., b₁ι, b₀ι) after decomposition

6. WHEN computing nested tensor-vector products, THE HyperWolf_System SHALL ensure f⁽ᵏ⁾ · ⃗a₀ · ⃗a₁ · ... · ⃗aₖ₋₁ = ct(s⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻¹ ⃗aᵢ) for appropriate auxiliary vectors


### Requirement 23: Mathematical Primitives - M-SIS Assumption

**User Story:** As a security analyst, I want precise definitions of the M-SIS hardness assumption and its parameters, so that I can verify the security claims of the system.

#### Acceptance Criteria

1. WHEN defining M-SISκ,n,q,β problem, THE HyperWolf_System SHALL state: given random matrix A ∈ Rqᵏˣⁿ for n > κ, find non-zero ⃗z ∈ Rqⁿ such that A⃗z = ⃗0 over Rq and ∥⃗z∥ ≤ β

2. WHEN M-SIS is hard, THE HyperWolf_System SHALL ensure any PPT algorithm solving M-SIS succeeds with probability at most neg(λ)

3. WHEN analyzing M-SIS hardness, THE HyperWolf_System SHALL reference Micciancio-Regev result: expected solution norm is ∥⃗z∥ ≥ min(√q, 2²√(dκ log q log(1.0045)))

4. WHEN q ≈ 2¹²⁸, d = 64, κ = 18, THE HyperWolf_System SHALL ensure M-SIS remains hard for norm bound β below the Micciancio-Regev threshold

5. WHEN the Ajtai commitment uses M-SISκ,n,q,2β, THE HyperWolf_System SHALL ensure binding holds: finding two distinct openings ⃗s ≠ ⃗s' with Com(⃗s) = Com(⃗s') yields M-SIS solution ⃗s - ⃗s' with norm ≤ 2β

6. WHEN coordinate-wise special soundness extracts witness s̄ with ∥c̄s̄∥∞ ≤ 2γ, THE HyperWolf_System SHALL ensure this does not violate M-SIS hardness for appropriately chosen parameters

### Requirement 24: Mathematical Primitives - Leveled Commitment Structure

**User Story:** As a commitment scheme designer, I want precise recursive definitions of leveled commitments, so that I can implement the hierarchical verification structure correctly.

#### Acceptance Criteria

1. WHEN defining leveled commitment for vector ⃗s ∈ RqN with N = ∏ᵢ₌₀ᵏ⁻¹ mᵢ, THE HyperWolf_System SHALL use matrices A₀ ∈ Rqᵏˣᵐ⁰ˡ and Aᵢ ∈ Rqᵏˣᵐⁱᵏˡ for i ∈ [1, k-1] where ℓ = ⌈logb q⌉

2. WHEN defining Mᵢ,ⱼ for i > j, THE HyperWolf_System SHALL compute Mᵢ,ⱼ = mᵢ · mᵢ₋₁ · ... · mⱼ₊₁

3. WHEN computing Fᵢ,ⱼ(⃗s) for i = j, THE HyperWolf_System SHALL return Aᵢ⃗s mod q

4. WHEN computing Fᵢ,ⱼ(⃗s) for i > j, THE HyperWolf_System SHALL recursively compute:
   ```
   Fᵢ,ⱼ(⃗s) = Fᵢ,ⱼ₊₁(G⁻¹b,Mᵢ,ⱼκ((IMᵢ,ⱼ ⊗ Aⱼ) · G⁻¹b,N(⃗s)))
   ```

5. WHEN the commitment is cm = Fk-1,0(⃗s), THE HyperWolf_System SHALL ensure this represents the full k-level hierarchy

6. WHEN k = 3 and N = 8d, THE HyperWolf_System SHALL compute commitment as shown in Equation 3 of the paper:
   ```
   cm = A₂ · G⁻¹b,2κ([A₁ · G⁻¹b,2κ([A₀ · ⃗s[0:ι], A₀ · ⃗s[ι:2ι], A₀ · ⃗s[2ι:3ι], A₀ · ⃗s[3ι:4ι]]ᵀ),
                      A₁ · G⁻¹b,2κ([A₀ · ⃗s[4ι:5ι], A₀ · ⃗s[5ι:6ι], A₀ · ⃗s[6ι:7ι], A₀ · ⃗s[7ι:8ι]]ᵀ)]ᵀ)
   ```

7. WHEN verifying leveled commitment in round i, THE HyperWolf_System SHALL check Aₖ₋ᵢ₋₁⃗πcm,i = [cₖ₋ᵢ,₀Gᵏ cₖ₋ᵢ,₁Gᵏ]⃗πcm,i-1

8. WHEN the leveled commitment is binding, THE HyperWolf_System SHALL ensure M-SISκ,n,q,2β hardness for n = max((mᵢκℓ)ᵢ∈[1,k], m₀ℓ) and β = max((√(mᵢκℓ) · 2b)ᵢ∈[1,k], √(m₀ℓ) · 2b)

### Requirement 25: LaBRADOR Integration Details

**User Story:** As a proof compression implementer, I want precise definitions of how HyperWolf transcripts are transformed into LaBRADOR inputs, so that I can implement the compression correctly.

#### Acceptance Criteria

1. WHEN constructing LaBRADOR input from HyperWolf transcript, THE HyperWolf_System SHALL set r = 3k - 1 where k is the number of HyperWolf rounds

2. WHEN constructing LaBRADOR input vectors, THE HyperWolf_System SHALL set n = r² and pad each vector to length n

3. WHEN mapping HyperWolf proof components to LaBRADOR vectors, THE HyperWolf_System SHALL set:
   - ⃗z₃ᵢ = ⃗πeval,i for i ∈ [k-1]
   - ⃗z₃ᵢ₊₁ = (Lᵢ, Mᵢ, Rᵢ) for i ∈ [k-1]
   - ⃗z₃ᵢ₊₂ = G⁻¹₂ᵏ(cmᵢ,₀, cmᵢ,₁) for i ∈ [k-1]
   - ⃗zᵣ₋₂ = ⃗s⁽¹⁾
   - ⃗zᵣ₋₁ = σ⁻¹(⃗s⁽¹⁾)

4. WHEN constructing LaBRADOR function g, THE HyperWolf_System SHALL define:
   ```
   g(⃗z₀, ..., ⃗zᵣ₋₁) = α⟨⃗zᵣ₋₂, ⃗zᵣ₋₁⟩ + Σᵢ₌₀ʳ⁻² ⟨φᵢ, ⃗zᵢ⟩ - β
   ```
   where α = 1

5. WHEN constructing LaBRADOR constraint vectors φᵢ, THE HyperWolf_System SHALL set:
   - φ₃ᵢ = ⃗aₖ₋ᵢ₋₁ - ⃗cₖ₋ᵢ₋₁ for i ∈ [k-1]
   - φ₃ᵢ₊₁ = ⃗p₁ - ⃗p₂,ᵢ₊₁ for i ∈ [k-1]
   - φ₃ᵢ₊₂ = Σⱼ₌₀ᵏ⁻¹ Aₖ₋ᵢ₋₁,ⱼ - [cₖ₋ᵢ₋₁,₁Gᵏ cₖ₋ᵢ₋₁,₀Gᵏ]ⱼ for i ∈ [k-1]
   - φᵣ₋₂ = σ⁻¹(⃗a₀)

6. WHEN constructing LaBRADOR constant β, THE HyperWolf_System SHALL set β = Σᵢ₌₀ᵏ⁻¹ cmᵢ + v + b

7. WHEN constructing LaBRADOR norm constraint, THE HyperWolf_System SHALL enforce Σᵢ₌₁² ∥⃗zᵣ₋ᵢ∥₂² ≤ 2nγ² where γ = (2T)ᵏ⁻¹β₂

8. WHEN the LaBRADOR input has size N' = r · n = r³ = (3k-1)³ = O(log³ N), THE HyperWolf_System SHALL apply LaBRADOR to achieve proof size O(log log N') = O(log log log N)

9. WHEN verifying LaBRADOR proof, THE HyperWolf_System SHALL exploit sparsity: only (5ι + 2κι) · (k-1) + 4ι = O(k) = O(log N) non-zero values across all ⃗zᵢ

10. WHEN computing LaBRADOR inner products ⟨φᵢ, ⃗zᵢ⟩, THE HyperWolf_System SHALL perform O(log N) ring operations total due to sparsity

11. WHEN LaBRADOR verification is complete, THE HyperWolf_System SHALL maintain total verification cost O(log N) ring operations


### Requirement 26: Coordinate-wise Special Soundness Framework

**User Story:** As a proof theorist, I want precise definitions of coordinate-wise special soundness and transcript tree structures, so that I can verify the extraction procedure is correct.

#### Acceptance Criteria

1. WHEN defining coordinate-wise relation ≡ᵢ for vectors ⃗x, ⃗y ∈ Sℓ, THE HyperWolf_System SHALL ensure ⃗x ≡ᵢ ⃗y ⟺ (xᵢ ≠ yᵢ ∧ ∀j ∈ [ℓ] \ {i}, xⱼ = yⱼ)

2. WHEN defining special soundness set SS(S, ℓ, k), THE HyperWolf_System SHALL construct:
   ```
   SS(S, ℓ, k) = {
     {⃗x₁, ⃗x₂, ..., ⃗xₖ} ⊆ (Sℓ)ᴷ :
     ∃e ∈ [K], ∀i ∈ [ℓ],
     ∃Jᵢ ⊆ [K] \ {e}, |Jᵢ| = k - 1,
     ∀j ∈ Jᵢ, ⃗xₑ ≡ᵢ ⃗xⱼ
   }
   ```
   where K = ℓ(k - 1) + 1

3. WHEN defining ℓ-coordinate-wise k-special soundness for (2μ + 1)-round protocol, THE HyperWolf_System SHALL require full (ℓ(k-1) + 1)-ary tree of depth μ where outgoing edges at each internal node are labeled by ℓ(k-1) + 1 distinct challenges in SS(S, ℓ, k)

4. WHEN the transcript tree has K = (ℓ(k-1) + 1)μ transcripts, THE HyperWolf_System SHALL ensure extractor runs in polynomial time and outputs valid witness

5. WHEN HyperWolf uses ℓ = 2 (two-dimensional challenges ⃗c ∈ C²) and k = 2 (binary tree), THE HyperWolf_System SHALL construct transcript tree with K = 3μ = 3ᵏ⁻¹ transcripts

6. WHEN the protocol is ℓ-coordinate-wise k-special sound with (ℓ(k-1))μ = poly(λ), THE HyperWolf_System SHALL achieve knowledge soundness with error μℓ(k-1)/|S| by Lemma 2

7. WHEN HyperWolf achieves 2-coordinate-wise 2-special soundness, THE HyperWolf_System SHALL have knowledge soundness error 2(k-1)/|C| from this component

### Requirement 27: Extraction Procedure Details

**User Story:** As an extraction algorithm implementer, I want step-by-step extraction procedures for each level of the transcript tree, so that I can implement the extractor correctly.

#### Acceptance Criteria

1. WHEN extracting at depth 1 with fixed ⃗cₖ₋₁, ..., ⃗c₂ and three transcripts with (⃗c₁,₀, ⃗c₁,₁, ⃗c₁,₂) ∈ SS(C, 2, 2), THE HyperWolf_System SHALL obtain equations:
   - c₁,₀,₀⃗s₂,L + c₁,₀,₁⃗s₂,R = ⃗s₁,₀
   - c₁,₁,₀⃗s₂,L + c₁,₀,₁⃗s₂,R = ⃗s₁,₁
   - c₁,₀,₀⃗s₂,L + c₁,₂,₁⃗s₂,R = ⃗s₁,₂

2. WHEN solving the extraction equations at depth 1, THE HyperWolf_System SHALL compute:
   - s̄₂,L = (⃗s₁,₁ - ⃗s₁,₀)/(c₁,₁,₀ - c₁,₀,₀) = (⃗s₁,₁ - ⃗s₁,₀)/c̄₁,₁
   - s̄₂,R = (⃗s₁,₂ - ⃗s₁,₀)/(c₁,₂,₁ - c₁,₀,₁) = (⃗s₁,₂ - ⃗s₁,₀)/c̄₁,₂

3. WHEN the extracted witness at depth 1 satisfies commitment equations, THE HyperWolf_System SHALL verify:
   - Com(s̄₂,L) = A₀⃗s₂,L
   - Com(s̄₂,R) = A₀⃗s₂,R
   - ∥c̄₁s̄₂∥∞ ≤ 2γ where c̄₁ = (c̄₁,₁, c̄₁,₂)

4. WHEN extracting at depth i > 1, THE HyperWolf_System SHALL recursively apply the same procedure to obtain s̄ᵢ₊₁ = ((s̄ᵢ,₁ - s̄ᵢ,₀)/c̄ᵢ,₁, (s̄ᵢ,₂ - s̄ᵢ,₀)/c̄ᵢ,₂)

5. WHEN the extraction reaches depth k-1, THE HyperWolf_System SHALL obtain final witness s̄ with:
   - Com(s̄) = cm
   - ∥∏ᵢ₌₁ᵏ⁻¹ c̄ᵢ · s̄∥∞ ≤ 2γ

6. WHEN each c̄ᵢ ∈ C - C is invertible in Rq, THE HyperWolf_System SHALL ensure the extraction equations have unique solutions

7. WHEN the norm bound ∥c̄s̄∥∞ ≤ 2γ < q/√n is satisfied, THE HyperWolf_System SHALL guarantee no wrap-around in inner product computations

### Requirement 28: Soundness Error Analysis

**User Story:** As a security auditor, I want detailed soundness error analysis for each component and round, so that I can verify the total error is negligible.

#### Acceptance Criteria

1. WHEN k = 1 (base case) and prover sends incorrect ⃗s⁽¹⁾ ≠ ⃗s, THE HyperWolf_System SHALL bound evaluation error by Pr[ct(⟨⃗s⁽¹⁾, σ⁻¹(⃗a₀)⟩) = v] ≤ 2dι/q

2. WHEN k = 1 and prover sends incorrect ⃗s⁽¹⁾ ≠ ⃗s, THE HyperWolf_System SHALL bound norm error by Pr[ct(⟨⃗s⁽¹⁾, σ⁻¹(⃗s⁽¹⁾)⟩) = b] ≤ 4dι/q

3. WHEN k = 1, THE HyperWolf_System SHALL achieve total soundness error 6dι/q

4. WHEN k ≥ 2 and prover sends incorrect ⃗πeval,0, THE HyperWolf_System SHALL bound error by Pr[⟨⃗πeval,0, ⃗cₖ₋₁⟩ = s⁽ᵏ⁾ · σ⁻¹(⃗a₀) · ∏ᵢ₌₁ᵏ⁻² ⃗aᵢ · ⃗cₖ₋₁] ≤ 2d/q

5. WHEN k ≥ 2 and prover sends incorrect ⃗πnorm,0, THE HyperWolf_System SHALL bound error by Pr[⟨⃗πnorm,0, ⃗p₂,₁⟩ = ⟨⃗sₖ₋₁, σ⁻¹(⃗sₖ₋₁)⟩] ≤ 2(3d)/q

6. WHEN k ≥ 2 and first round checks fail, THE HyperWolf_System SHALL bound total first-round error by 6d/q

7. WHEN k ≥ 2 and first round passes but subsequent rounds fail, THE HyperWolf_System SHALL apply inductive hypothesis: error ≤ (6(k-2)d + 6dι)/q

8. WHEN k ≥ 2, THE HyperWolf_System SHALL achieve total soundness error 6d/q + (6(k-2)d + 6dι)/q = (6(k-1)d + 6dι)/q

9. WHEN coordinate-wise special soundness contributes error 2(k-1)/|C|, THE HyperWolf_System SHALL apply union bound to obtain total knowledge soundness error 2(k-1)/|C| + 6(k-2)d+6dι/q

10. WHEN λ = 128, q ≈ 2¹²⁸, |C| ≈ 2¹²⁸·⁶, d = 64, ι ∈ {32, 42}, k = O(log N), THE HyperWolf_System SHALL ensure total error ≤ 2⁻λ = negligible


### Requirement 29: Tower-by-Tower IPA Optimization (Future Work)

**User Story:** As a performance optimizer, I want an alternative IPA construction that reduces proof size from O(log N) to O(log log N) without LaBRADOR, so that I can achieve better asymptotic efficiency.

#### Acceptance Criteria

1. WHEN proving IPA relation RIPA = {((cma,i, cmb,i)i∈[r], v ∈ Zq), (⃗ai, ⃗bi ∈ ZqN)i∈[r] : Σᵢ₌₀ʳ⁻¹ ⟨⃗ai, ⃗bi⟩ = v, Com(⃗ai) = cma,i, Com(⃗bi) = cmb,i, ∀i ∈ [r]} for N = 2²ᵏ, THE HyperWolf_System SHALL use tower-by-tower reduction

2. WHEN the verifier samples combining challenge c ∈ Zq with c > v and gcd(c, v) = 1, THE HyperWolf_System SHALL enable modular arithmetic preservation

3. WHEN in round i with input size 2²ⁱ, THE HyperWolf_System SHALL partition each vector into √N = 2²ⁱ⁻¹ groups of size √N

4. WHEN partitioning ⃗aj into (⃗aj,0, ..., ⃗aj,m-1) for m = √N, THE HyperWolf_System SHALL compute commitments cmaj,k = F₂ᵏ⁻¹₋₁,₀(⃗aj,k) for k ∈ [m]

5. WHEN compressing groups, THE HyperWolf_System SHALL compute ⃗wa,j = (⟨⃗aj,0, ⃗c⟩, ..., ⟨⃗aj,m-1, ⃗c⟩) and ⃗wb,j = (⟨⃗bj,0, ⃗c⁻¹⟩, ..., ⟨⃗bj,m-1, ⃗c⁻¹⟩) where ⃗c = (1, c, c², ..., cᵐ⁻¹)

6. WHEN the verifier checks Σⱼ₌₀ʳ⁻¹ ⟨⃗wa,j, ⃗wb,j⟩ mod c = v, THE HyperWolf_System SHALL ensure this preserves the original inner product relation

7. WHEN the verifier samples ⃗c' ∈ Cqᵐ, THE HyperWolf_System SHALL compute ⃗za,j = Σₖ₌₀ᵐ⁻¹ c'k⃗aj,k and ⃗zb,j = Σₖ₌₀ᵐ⁻¹ c'k⃗bj,k

8. WHEN verifying consistency, THE HyperWolf_System SHALL check ⟨⃗za,j, ⃗c⟩ = ⟨⃗wa,j, ⃗c'⟩ and ⟨⃗zb,j, ⃗c⁻¹⟩ = ⟨⃗wb,j, ⃗c'⟩

9. WHEN verifying commitments, THE HyperWolf_System SHALL check Com(⃗za,j) = Σₖ₌₀ᵐ⁻¹ c'kcmaj,k and Com(⃗zb,j) = Σₖ₌₀ᵐ⁻¹ c'kcmbj,k

10. WHEN aggregating constraints, THE HyperWolf_System SHALL combine into form Σᵢ₌₀⁵ʳ⁻¹ ⟨⃗anew,i, ⃗bnew,i⟩ = vnew with ⃗anew,i, ⃗bnew,i ∈ Zqᵏᵐⁱ

11. WHEN one round reduces input from rN to 5rκι√N, THE HyperWolf_System SHALL achieve O(log log N) rounds total

12. WHEN O(log log N) rounds complete, THE HyperWolf_System SHALL achieve proof size O(1) (constant) without LaBRADOR

13. WHEN this optimization is fully analyzed, THE HyperWolf_System SHALL characterize required challenge distribution and invertibility properties

### Requirement 30: Comparison with Prior Work

**User Story:** As a researcher, I want precise comparisons with prior lattice-based PCS schemes, so that I can understand HyperWolf's advantages and positioning.

#### Acceptance Criteria

1. WHEN compared to inner-product-based schemes [2,14,35,17], THE HyperWolf_System SHALL achieve logarithmic verification time versus their O(N) verification

2. WHEN compared to schemes with non-standard assumptions [35,20], THE HyperWolf_System SHALL rely only on standard M-SIS assumption

3. WHEN compared to schemes with heavy preprocessing [24,3], THE HyperWolf_System SHALL require no trusted setup and transparent parameter generation

4. WHEN compared to SLAP [3], THE HyperWolf_System SHALL achieve O(log log log N) proof size versus their O(log² N), and transparent setup versus their trusted setup

5. WHEN compared to Greyhound [33], THE HyperWolf_System SHALL achieve:
   - Same proof size O(log log log N) with LaBRADOR
   - Verification time O(log N) versus their O(√N)
   - Standard ℓ₂-soundness versus their relaxed ℓ∞-soundness
   - 2-3 orders of magnitude improvement in verification for large N

6. WHEN compared to Cini et al. [18], THE HyperWolf_System SHALL achieve:
   - Smaller proof size: O(log log log N) versus their O(log² N)
   - Faster verification: O(log N) versus their O(log² N)
   - Standard ℓ₂-soundness versus their relaxed ℓ∞-soundness

7. WHEN compared to code-based schemes [5,22], THE HyperWolf_System SHALL provide homomorphic structure for proof composition

8. WHEN compared to schemes with relaxed soundness, THE HyperWolf_System SHALL extract witnesses with exact norm bounds (no relaxation factor)

9. WHEN compared to schemes using ℓ∞-norm relations, THE HyperWolf_System SHALL provide exact ℓ₂-norm guarantees matching common lattice primitive outputs

10. WHEN compared to all prior lattice PCS, THE HyperWolf_System SHALL be the first to simultaneously achieve: logarithmic verification, sub-logarithmic proof size, standard soundness, transparent setup, and standard assumptions

### Requirement 31: Implementation and Practical Considerations

**User Story:** As a system implementer, I want guidance on implementation details and practical optimizations, so that I can build an efficient concrete system.

#### Acceptance Criteria

1. WHEN implementing hypercube arithmetic, THE HyperWolf_System SHALL support k-dimensional tensor operations using standard polynomial arithmetic over finite fields

2. WHEN implementing hypercube indexing, THE HyperWolf_System SHALL use bit manipulation techniques for direct computation of multidimensional coordinates without intermediate storage

3. WHEN implementing ring operations, THE HyperWolf_System SHALL use Number Theoretic Transform (NTT) for efficient polynomial multiplication in Rq

4. WHEN implementing gadget decomposition, THE HyperWolf_System SHALL use basis b ∈ {4, 16} for balance between proof size and computation

5. WHEN implementing challenge sampling, THE HyperWolf_System SHALL use reject sampling to ensure operator norm bound T ≤ 10

6. WHEN implementing commitment computation, THE HyperWolf_System SHALL cache intermediate results in leveled structure to avoid recomputation

7. WHEN implementing verification, THE HyperWolf_System SHALL exploit sparsity in LaBRADOR input vectors to reduce computation

8. WHEN implementing prover, THE HyperWolf_System SHALL use parallel computation for independent tensor slices

9. WHEN implementing for Apple Silicon M3 Max, THE HyperWolf_System SHALL use ARM64 SIMD instructions and unified memory architecture

10. WHEN implementing in Rust, THE HyperWolf_System SHALL use zero-cost abstractions and compile-time optimizations with LLVM code generation

11. WHEN benchmarking, THE HyperWolf_System SHALL measure both asymptotic complexity and concrete performance metrics

12. WHEN the implementation is complete, THE HyperWolf_System SHALL provide reproducible benchmarks and profiles for prover, verifier, and parameter generation


### Requirement 32: Concrete Protocol Example (k=3 case)

**User Story:** As a protocol implementer, I want a complete worked example for k=3 rounds, so that I can understand the full protocol flow with concrete dimensions.

#### Acceptance Criteria

1. WHEN N = 8d and k = 3, THE HyperWolf_System SHALL use witness ⃗s ∈ R⁸ⁱq after decomposition

2. WHEN computing commitment for k=3, THE HyperWolf_System SHALL use structure:
   ```
   cm = A₂ · G⁻¹b,2κ([A₁ · G⁻¹b,2κ([A₀ · ⃗s[0:ι], A₀ · ⃗s[ι:2ι], A₀ · ⃗s[2ι:3ι], A₀ · ⃗s[3ι:4ι]]ᵀ),
                      A₁ · G⁻¹b,2κ([A₀ · ⃗s[4ι:5ι], A₀ · ⃗s[5ι:6ι], A₀ · ⃗s[6ι:7ι], A₀ · ⃗s[7ι:8ι]]ᵀ)]ᵀ)
   ```

3. WHEN in round 0 for k=3, THE HyperWolf_System SHALL compute:
   - ⃗πeval,0 = s⁽³⁾ · σ⁻¹(⃗a₀) · ⃗a₁ ∈ R²q
   - L₀ = ⟨⃗sL, σ⁻¹(⃗sL)⟩, M₀ = ⟨⃗sL, σ⁻¹(⃗sR)⟩, R₀ = ⟨⃗sR, σ⁻¹(⃗sR)⟩
   - ⃗πcm,0 = G⁻¹₂κ(Com(⃗sL), Com(⃗sR))

4. WHEN verifying round 0 for k=3, THE HyperWolf_System SHALL check:
   - ct(⟨⃗πeval,0, ⃗a₂⟩) = v
   - ct(⟨(1, 0, 1), ⃗πnorm,0⟩) = b
   - A₂⃗πcm,0 = cm

5. WHEN the verifier samples ⃗c₂ ∈ C² in round 0, THE HyperWolf_System SHALL update witness to ⃗s₂ = c₂,₀⃗sL + c₂,₁⃗sR

6. WHEN in round 1 for k=3, THE HyperWolf_System SHALL compute:
   - ⃗πeval,1 = s⁽²⁾ · σ⁻¹(⃗a₀) ∈ R²q
   - ⃗πnorm,1 = (L₁, M₁, R₁)
   - ⃗πcm,1 = G⁻¹₂κ(Com(⃗s₂,L), Com(⃗s₂,R))

7. WHEN verifying round 1 for k=3, THE HyperWolf_System SHALL check:
   - ⟨⃗πeval,1, ⃗a₁⟩ = ⟨⃗πeval,0, ⃗c₂⟩
   - ⟨(1, 0, 1), ⃗πnorm,1⟩ = ⟨(c²₂,₀, 2c₂,₀c₂,₁, c²₂,₁), ⃗πnorm,0⟩
   - A₁⃗πcm,1 = [c₂,₀Gκ c₂,₁Gκ]⃗πcm,0

8. WHEN the verifier samples ⃗c₁ ∈ C² in round 1, THE HyperWolf_System SHALL update witness to ⃗s₁ = c₁,₀⃗s₂,L + c₁,₁⃗s₂,R

9. WHEN in final round 2 for k=3, THE HyperWolf_System SHALL send ⃗s⁽¹⁾ ∈ R²ⁱq

10. WHEN verifying final round for k=3, THE HyperWolf_System SHALL check:
    - ⟨⃗s⁽¹⁾, σ⁻¹(⃗a₀)⟩ = ⟨⃗πeval,1, ⃗c₁⟩
    - ⟨⃗s⁽¹⁾, σ⁻¹(⃗s⁽¹⁾)⟩ = ⟨(c²₁,₀, 2c₁,₀c₁,₁, c²₁,₁), ⃗πnorm,1⟩
    - A₀⃗s⁽¹⁾ = [c₁,₀Gκ c₁,₁Gκ]⃗πcm,1
    - ∥⃗s⁽¹⁾∥∞ ≤ 4T²β₂

11. WHEN k=3 protocol is complete, THE HyperWolf_System SHALL have sent proof ⃗π = (⃗πeval,0, ⃗πnorm,0, ⃗πcm,0, ⃗πeval,1, ⃗πnorm,1, ⃗πcm,1, ⃗s⁽¹⁾)

12. WHEN applying LaBRADOR to k=3 proof, THE HyperWolf_System SHALL construct input with r = 3·3 - 1 = 8 vectors and n = 64

### Requirement 33: Zero-Knowledge Extension

**User Story:** As a privacy-conscious user, I want optional zero-knowledge properties, so that the proof reveals nothing beyond the validity of the statement.

#### Acceptance Criteria

1. WHEN zero-knowledge is required, THE HyperWolf_System SHALL append random masking vector ⃗r to witness ⃗s

2. WHEN computing commitment with zero-knowledge, THE HyperWolf_System SHALL ensure Com(⃗s, ⃗r) hides ⃗s information-theoretically

3. WHEN proving norm constraint with zero-knowledge, THE HyperWolf_System SHALL commit to value b instead of sending it in clear

4. WHEN b is committed, THE HyperWolf_System SHALL provide range proof that b ≤ β₁²

5. WHEN zero-knowledge is enabled, THE HyperWolf_System SHALL ensure simulator can produce transcripts indistinguishable from real proofs

6. WHEN zero-knowledge is enabled, THE HyperWolf_System SHALL maintain same asymptotic efficiency: O(log N) verification, O(log log log N) proof size

### Requirement 34: Recursive Composition and Proof Aggregation

**User Story:** As a SNARK designer, I want to compose HyperWolf proofs recursively and aggregate multiple proofs, so that I can build scalable proof systems.

#### Acceptance Criteria

1. WHEN verifying HyperWolf proof inside another HyperWolf proof, THE HyperWolf_System SHALL express verification as polynomial evaluation constraints

2. WHEN aggregating n proofs for same statement, THE HyperWolf_System SHALL use batching techniques to verify all proofs with single PCS evaluation

3. WHEN composing proofs recursively, THE HyperWolf_System SHALL leverage homomorphic properties of Ajtai commitments

4. WHEN building IVC (Incrementally Verifiable Computation), THE HyperWolf_System SHALL use HyperWolf as polynomial commitment backend

5. WHEN building accumulation schemes, THE HyperWolf_System SHALL support efficient proof aggregation through linear combinations

### Requirement 35: Error Handling and Edge Cases

**User Story:** As a robust system builder, I want clear specifications for error handling and edge cases, so that the system behaves correctly in all scenarios.

#### Acceptance Criteria

1. WHEN N is not a power of 2 times d, THE HyperWolf_System SHALL pad polynomial coefficients to next valid size

2. WHEN challenge sampling fails invertibility check, THE HyperWolf_System SHALL resample until valid challenge is obtained

3. WHEN norm bound check fails in final round, THE HyperWolf_System SHALL reject proof immediately

4. WHEN commitment verification fails in any round, THE HyperWolf_System SHALL reject proof and halt

5. WHEN modulus q is not prime or q ≢ 5 mod 8, THE HyperWolf_System SHALL reject parameters during setup

6. WHEN ring dimension d is not a power of 2, THE HyperWolf_System SHALL reject parameters during setup

7. WHEN parameters do not satisfy M-SIS hardness requirements, THE HyperWolf_System SHALL reject parameters during setup

8. WHEN LaBRADOR input size constraint (3k-1)² ≥ max(2κι, 3ι) is violated, THE HyperWolf_System SHALL reject parameters during setup

9. WHEN wrap-around condition 2γ < q/√n is violated, THE HyperWolf_System SHALL reject parameters during setup

10. WHEN any arithmetic operation would cause overflow, THE HyperWolf_System SHALL use modular reduction and ensure correctness


