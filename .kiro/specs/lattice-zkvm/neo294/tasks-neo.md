# Neo Implementation Tasks

This document outlines the complete implementation plan for Neo, a lattice-based folding scheme for CCS. Tasks are organized into logical phases with clear dependencies and requirements references.

## Task Organization

- Tasks are numbered hierarchically (1, 1.1, 1.2, etc.)
- Each task references specific requirements from requirements-neo.md
- Optional tasks are marked with * (primarily testing-related)
- Core implementation tasks are never marked as optional

---

## Phase 1: Core Field Arithmetic

- [x] 1. Implement base field arithmetic layer


  - Implement trait-based field interface with zero, one, add, sub, mul, neg, inv operations
  - Implement canonical representation and conversion methods
  - Implement batch operations interface for SIMD support
  - _Requirements: NEO-2_

- [x] 1.1 Implement Goldilocks field arithmetic


  - Implement GoldilocksField struct with modulus q = 2^64 - 2^32 + 1
  - Implement fast reduction using q = 2^64 - ε where ε = 2^32 - 1
  - Implement addition with overflow handling and conditional subtraction
  - Implement multiplication using 128-bit intermediate results and fast reduction
  - Implement modular inversion using extended Euclidean algorithm
  - Implement power and square root operations
  - _Requirements: NEO-2.1, NEO-2.2, NEO-2.3, NEO-2.4, NEO-2.9_


- [x] 1.2 Implement Mersenne 61 field arithmetic



  - Implement M61Field struct with modulus q = 2^61 - 1
  - Implement ultra-fast Mersenne reduction: (a & (2^61-1)) + (a >> 61)
  - Implement addition and multiplication using Mersenne properties
  - Implement modular inversion
  - Verify q ≡ 1 (mod 128) property for NTT compatibility

  - _Requirements: NEO-2.1, NEO-2.2, NEO-2.3, NEO-2.4, NEO-2.10_


- [ ] 1.3 Implement extension field F_q^2
  - Implement ExtensionField<F, 2> struct for degree-2 extensions
  - Implement irreducible polynomial selection (X^2 + 7 for Goldilocks)
  - Implement extension field addition and multiplication


  - Implement extension field inversion
  - Implement embedding of base field into extension field
  - _Requirements: NEO-2.6, NEO-2.11, NEO-2.12_

- [ ] 1.4 Implement SIMD optimizations for field operations

  - Implement AVX2 batch addition for Goldilocks field
  - Implement AVX2 batch multiplication for Goldilocks field

  - Implement fallback scalar implementations
  - Add runtime CPU feature detection
  - _Requirements: NEO-2.9_



## Phase 2: Cyclotomic Rings and Polynomial Operations



- [ ] 2. Implement cyclotomic ring structure
  - Implement CyclotomicRing struct with degree d and modulus polynomial Φ_η
  - Implement ring element representation with coefficient vectors
  - Implement ring addition and subtraction
  - Implement ring negation and scalar multiplication
  - Verify ring degree is power of 2 for X^d + 1 cyclotomic polynomials
  - _Requirements: NEO-1.1, NEO-1.2, NEO-1.4, NEO-1.5_


- [ ] 2.1 Implement NTT-based polynomial multiplication
  - Implement primitive root of unity detection for NTT availability
  - Implement Cooley-Tukey forward NTT (radix-2 decimation-in-time)
  - Implement Gentleman-Sande inverse NTT with scaling by 1/n
  - Implement bit-reversal permutation for NTT
  - Implement NTT-based ring multiplication: NTT(a) * NTT(b) -> INTT

  - Optimize with precomputed twiddle factors

  - _Requirements: NEO-1.6, NEO-1.9_

- [ ] 2.2 Implement coefficient embedding and extraction
  - Implement cf: R_q → F_q^d coefficient extraction
  - Implement cf^-1: F_q^d → R_q coefficient embedding
  - Implement constant term extraction ct: R_q → F_q

  - Implement infinity norm computation for ring elements
  - Implement balanced representation for norm computation
  - _Requirements: NEO-1.7, NEO-1.8_

- [-] 2.3 Implement rotation matrices

  - Implement shift matrix F for cyclotomic polynomial X^d + 1
  - Implement rotation matrix construction rot(a) for ring element a
  - Implement matrix-vector multiplication using rotation matrices
  - Verify rot(a) · cf(b) = cf(a·b) property
  - _Requirements: NEO-1.5_


- [ ] 2.4 Implement fallback schoolbook multiplication
  - Implement naive polynomial multiplication for rings without NTT
  - Implement modular reduction by cyclotomic polynomial
  - Use as fallback when NTT is not available
  - _Requirements: NEO-1.5_



## Phase 3: Multilinear Polynomials

- [x] 3. Implement multilinear polynomial representation

  - Implement MultilinearPolynomial struct with evaluation vector
  - Implement construction from field vector with power-of-2 length validation
  - Implement num_vars computation as log2 of evaluation count
  - _Requirements: NEO-6.1, NEO-6.2, NEO-6.4_

- [ ] 3.1 Implement multilinear extension evaluation
  - Implement MLE evaluation at arbitrary point r ∈ F^ℓ using recursive formula
  - Implement dynamic programming optimization for O(N) evaluation
  - Implement equality polynomial eq(x, r) = ∏ᵢ (xᵢ·rᵢ + (1-xᵢ)·(1-rᵢ))
  - Verify MLE uniqueness property
  - _Requirements: NEO-6.2, NEO-6.3, NEO-6.4, NEO-6.5_

- [ ] 3.2 Implement partial evaluation
  - Implement partial evaluation fixing first k variables
  - Implement recursive interpolation for partial evaluation
  - Return new MLE with reduced number of variables
  - _Requirements: NEO-6.5_

- [ ] 3.3 Implement MLE folding operations
  - Implement linear combination of MLEs: (Σᵢ αᵢ·wᵢ)~(r) = Σᵢ αᵢ·w̃ᵢ(r)
  - Verify multilinearity preservation under linear combinations
  - _Requirements: NEO-6.12, NEO-6.14_


## Phase 4: Ajtai Commitment Scheme

- [x] 4. Implement basic Ajtai commitment scheme


  - Implement AjtaiCommitmentScheme struct with public matrix A ∈ R_q^{κ×m}
  - Implement setup generating uniformly random matrix A from seed
  - Implement commitment computation Com(w) = Aw mod q
  - Implement witness norm verification ||w||_∞ ≤ β
  - Implement commitment opening verification
  - _Requirements: NEO-3.1, NEO-3.2, NEO-3.3, NEO-3.6, NEO-3.9_

- [x] 4.1 Implement matrix generation from seed

  - Implement cryptographic hash-based matrix generation
  - Implement rejection sampling or modular reduction for uniform distribution
  - Verify statistical closeness to uniform distribution
  - _Requirements: NEO-3.2, NEO-3.3, NEO-3.4_


- [ ] 4.2 Implement commitment computation
  - Implement matrix-vector multiplication in R_q^{κ×m}
  - Optimize using NTT for ring multiplications
  - Compute c_i = Σⱼ A_{i,j} · w_j mod q for i ∈ [κ]
  - Achieve O(κ · m · d · log d) time complexity
  - _Requirements: NEO-3.6, NEO-3.7_


- [ ] 4.3 Implement linear homomorphism
  - Implement commitment addition: c₁ + c₂ mod q
  - Implement commitment scalar multiplication: α·c mod q
  - Implement batched linear combination: Σᵢ αᵢ·cᵢ
  - Verify Com(αw₁ + βw₂) = α·Com(w₁) + β·Com(w₂)
  - Implement Horner's method for efficient scalar multiplication

  - _Requirements: NEO-5.1, NEO-5.2, NEO-5.3, NEO-5.4, NEO-5.5, NEO-5.6, NEO-5.7_

- [ ] 4.4 Implement norm bound verification
  - Implement infinity norm computation for ring vectors
  - Verify ||w||_∞ ≤ β before commitment
  - Verify norm preservation under homomorphism
  - _Requirements: NEO-3.5, NEO-3.10, NEO-5.8_



## Phase 5: Pay-Per-Bit Matrix Commitments

- [-] 5. Implement field vector to ring vector packing

  - Implement coefficient packing: d consecutive field elements → 1 ring element

  - Implement packing function mapping f ∈ F_q^N to w ∈ R_q^{N/d}
  - Pack elements as w_i = Σⱼ f_{i·d+j} · X^j
  - Implement padding to multiple of d
  - _Requirements: NEO-4.1, NEO-4.2_

- [x] 5.1 Implement pay-per-bit cost tracking

  - Implement bit-width specification per vector element
  - Implement cost computation: O(κ · (N/d) · b/log(q)) for b-bit values
  - Verify bit-width bounds: value < 2^bit_width
  - Track actual bit-width for optimal cost calculation
  - _Requirements: NEO-4.3, NEO-4.5, NEO-4.8, NEO-4.9_


- [ ] 5.2 Implement sparse polynomial optimization
  - Implement sparse NTT for polynomials with many zero coefficients
  - Process only non-zero coefficients for b-bit values where b ≪ log(q)
  - Achieve 32x speedup for bits vs 32-bit values with d=64

  - _Requirements: NEO-4.4, NEO-4.6, NEO-4.7_

- [ ] 5.3 Implement unpacking operations
  - Implement ring vector to field vector unpacking
  - Extract coefficients from ring elements: cf(w_i) → f_{i·d}...f_{i·d+d-1}
  - Verify round-trip: unpack(pack(f)) = f
  - _Requirements: NEO-4.2_

- [ ] 5.4 Implement mixed bit-width support
  - Support different bit-widths for different vector positions
  - Implement per-element bit-width tracking
  - Optimize commitment for mixed bit-widths
  - _Requirements: NEO-4.5, NEO-4.8_


## Phase 6: Evaluation Claims and Folding

- [x] 6. Implement evaluation claim structure

  - Implement EvaluationClaim struct with (commitment, point, value)
  - Implement claim verification: check Com(w) = C and w̃(r) = y
  - Define claim as tuple (C, r, y) where C ∈ R_q^κ, r ∈ F^ℓ, y ∈ F
  - _Requirements: NEO-6.6, NEO-6.7_

- [x] 6.1 Implement evaluation claim folding

  - Implement folding of β evaluation claims into single claim
  - Sample folding coefficients α ∈ F^β from challenge set with |C| ≥ 2^128
  - Compute folded commitment: C' = Σᵢ αᵢ·Cᵢ using linear homomorphism
  - Compute folded value: y' = Σᵢ αᵢ·yᵢ
  - Compute folded witness: w' = Σᵢ αᵢ·wᵢ
  - Verify folded claim: Com(w') = C' and w̃'(r) = y'
  - _Requirements: NEO-6.8, NEO-6.9, NEO-6.10, NEO-6.11, NEO-6.12_


- [x] 6.2 Implement cross-term computation
  - Compute cross-terms σᵢⱼ = ⟨wᵢ, wⱼ⟩ for i < j
  - Send β(β-1)/2 cross-terms to verifier
  - Implement inner product computation
  - _Requirements: NEO-10.3, NEO-10.4_


- [x] 6.3 Implement cross-term verification
  - Verify ⟨w', w'⟩ = Σᵢ αᵢ²·yᵢ² + 2·Σᵢ<ⱼ αᵢαⱼ·σᵢⱼ
  - Ensure cross-terms are correct for folding soundness
  - _Requirements: NEO-10.9_


- [x] 6.4 Implement batched evaluation claim operations

  - Implement batched MLE evaluation for multiple points
  - Implement batched cross-term computation
  - Optimize for β = 2 case (most common): only one cross-term
  - _Requirements: NEO-10.12, NEO-10.13, NEO-6.15_


## Phase 7: CCS Structure and Operations

- [x] 7. Implement CCS structure definition

  - Implement CCSStructure with parameters (m, n, N, ℓ, t, q, d, M, S, c)
  - Implement sparse matrix representation for M₀, ..., M_{t-1} ∈ F^{m×n}
  - Implement selector vectors S₀, ..., S_{q-1} as subsets of [t]
  - Implement constant vector c = (c₀, ..., c_{q-1}) ∈ F^q
  - Validate CCS well-formedness: all Sᵢ ⊆ [t], matrices have dimension m×n
  - _Requirements: NEO-7.1, NEO-7.2, NEO-7.3, NEO-7.4, NEO-7.14_

- [x] 7.1 Implement sparse matrix operations
  - Implement sparse matrix-vector multiplication in O(nnz) time
  - Implement dense matrix-vector multiplication in O(m·n) time
  - Implement matrix storage in COO or CSR format
  - _Requirements: NEO-7.6, NEO-7.7_

- [x] 7.2 Implement CCS relation verification
  - Construct full witness z = (1, x, w) ∈ F^n
  - Compute matrix-vector products vⱼ = Mⱼz for j ∈ [t]
  - Compute Hadamard products: ∘_{j∈Sᵢ} vⱼ for each term i
  - Compute weighted sum: Σᵢ cᵢ · (∘_{j∈Sᵢ} vⱼ)
  - Verify final sum equals zero vector
  - _Requirements: NEO-7.5, NEO-7.6, NEO-7.8, NEO-7.9_

- [x] 7.3 Implement CCS special cases
  - Support R1CS as special case: q=1, t=3, S₀={0,1,2}, constraint (M₀z) ∘ (M₁z) = M₂z
  - Support Plonkish constraints by appropriate choice of M, S, c
  - Support AIR constraints by encoding transition constraints
  - _Requirements: NEO-7.10, NEO-7.11, NEO-7.12_

- [x] 7.4 Implement matrix multilinear extensions
  - Represent matrix M ∈ F^{m×n} as MLE M̃: F^{log m + log n} → F
  - Compute M̃(x, y) = Σᵢ,ⱼ M[i][j] · eq(i, x) · eq(j, y)
  - Optimize for sparse matrices
  - _Requirements: NEO-8.1, NEO-8.2_


## Phase 8: Sum-Check Protocol

- [x] 8. Implement sum-check prover
  - Implement SumCheckProver for polynomial g: F^ℓ → F
  - Initialize with claimed sum H = Σ_{x∈{0,1}^ℓ} g(x)
  - Implement ℓ rounds of interaction
  - _Requirements: NEO-9.1, NEO-9.2_

- [x] 8.1 Implement sum-check round computation
  - Compute round i univariate polynomial sᵢ(X) of degree ≤ d
  - Compute sᵢ(X) = Σ_{x∈{0,1}^{ℓ-i}} g(r₁,...,rᵢ₋₁,X,x)
  - Represent sᵢ by evaluations at 0, 1, ..., d
  - Send d+1 field elements to verifier
  - _Requirements: NEO-9.3, NEO-9.4, NEO-9.5, NEO-9.6_

- [x] 8.2 Implement sum-check verifier
  - Verify round i: check sᵢ(0) + sᵢ(1) = H (round 1) or sᵢ(0) + sᵢ(1) = sᵢ₋₁(rᵢ₋₁)
  - Sample random challenge rᵢ ∈ F using Fiat-Shamir
  - Update running sum H ← sᵢ(rᵢ)
  - _Requirements: NEO-9.7, NEO-9.8, NEO-9.9_

- [x] 8.3 Implement final verification
  - After ℓ rounds, verify g(r₁, ..., r_ℓ) = s_ℓ(r_ℓ)
  - Compute g(r) by evaluating multilinear extensions
  - _Requirements: NEO-9.10, NEO-9.11_

- [x] 8.4 Implement Lagrange interpolation
  - Implement univariate polynomial evaluation from d+1 points
  - Use Lagrange basis for evaluation at challenge point
  - _Requirements: NEO-9.6_

- [x] 8.5 Implement sum-check over extension field
  - Run sum-check over F_q^2 for 128-bit security with 64-bit base field
  - Achieve soundness error ≤ ℓ·d / |F_q^2|
  - _Requirements: NEO-9.15_

- [x] 8.6 Optimize sum-check prover performance
  - Achieve prover time O(2^ℓ · d) for degree-d polynomial over ℓ variables
  - Achieve proof size O(ℓ · d) field elements
  - Achieve verifier time O(ℓ · d) plus evaluation time
  - _Requirements: NEO-9.12, NEO-9.13, NEO-8.15_


## Phase 9: CCS to Evaluation Claims Reduction

- [x] 9. Implement CCS polynomial construction
  - Define g(x) = Σᵢ cᵢ · ∏_{j∈Sᵢ} (Mⱼz)~(x)
  - Verify CCS satisfaction equivalent to Σ_{x∈{0,1}^ℓ} g(x) = 0
  - _Requirements: NEO-8.1, NEO-8.2_

- [x] 9.1 Implement CCS sum-check reduction
  - Commit to witness z before starting sum-check
  - Run sum-check protocol for ℓ rounds on g(x)
  - Reduce to evaluation claim g(r) = s_ℓ(r_ℓ) at random point r
  - _Requirements: NEO-8.3, NEO-8.8, NEO-8.10_

- [x] 9.2 Implement matrix-vector evaluation reduction
  - Generate t evaluation claims: {(C, Mⱼ, r, vⱼ)}_{j∈[t]}
  - Compute claimed values vⱼ = (Mⱼz)~(r) for j ∈ [t]
  - Verify consistency: g(r) = Σᵢ cᵢ · ∏_{j∈Sᵢ} vⱼ
  - _Requirements: NEO-8.12, NEO-8.13, NEO-8.14_

- [x] 9.3 Implement matrix-vector to witness reduction
  - Express (Mz)~(r) as inner product: ⟨z, M̃(r)⟩
  - Compute column MLEs: M̃ⱼ(r) for j ∈ [n]
  - Define evaluation vector r' = (M̃₀(r), ..., M̃_{n-1}(r))
  - Reduce claim (C, M, r, v) to witness claim (C, r', v)
  - _Requirements: NEO-9.1, NEO-9.2, NEO-9.3, NEO-9.4, NEO-9.5, NEO-9.6, NEO-9.7_

- [x] 9.4 Optimize matrix MLE computation
  - Implement efficient M̃(r) computation in O(m·n) time
  - Cache M̃(r) when same matrix used for multiple claims
  - Optimize for sparse matrices
  - Implement structured matrix optimizations (circulant, Toeplitz)
  - _Requirements: NEO-9.9, NEO-9.10, NEO-9.11, NEO-9.14_


## Phase 10: Witness Decomposition

- [x] 10. Implement witness decomposition scheme
  - Choose decomposition base b ≈ √B for norm bound B
  - Compute number of digits ℓ = ⌈log_b(B)⌉
  - _Requirements: NEO-11.2, NEO-11.3, NEO-12.2, NEO-12.3_

- [x] 10.1 Implement base-b digit decomposition
  - Decompose each element w[i] = Σⱼ bʲ·wⱼ[i] where ||wⱼ||_∞ < b
  - Use balanced representation: wⱼ[i] ∈ [-b/2, b/2)
  - Verify decomposition correctness: w = Σⱼ bʲ·wⱼ
  - _Requirements: NEO-11.4, NEO-11.5, NEO-11.6, NEO-12.4, NEO-12.5, NEO-12.6_

- [x] 10.2 Implement digit commitment
  - Compute commitments Cⱼ = Com(wⱼ) for each digit j ∈ [ℓ]
  - Compute digit evaluations yⱼ = w̃ⱼ(r) for j ∈ [ℓ]
  - _Requirements: NEO-11.7, NEO-11.8, NEO-12.7, NEO-12.8_

- [x] 10.3 Implement decomposition verification
  - Verify commitment reconstruction: C = Σⱼ bʲ·Cⱼ
  - Verify evaluation reconstruction: y = Σⱼ bʲ·yⱼ
  - Verify digit bounds: ||wⱼ||_∞ < b for all j
  - _Requirements: NEO-11.9, NEO-11.10, NEO-11.7, NEO-12.9, NEO-12.10_

- [x] 10.4 Implement optimal base selection
  - Choose b such that after RLC with L instances, ||Σᵢ ρᵢ·wᵢ,ⱼ||_∞ ≤ β
  - Compute optimal base: b ≈ (β / (L·||ρ||_∞))^(1/ℓ)
  - _Requirements: NEO-11.10, NEO-11.11_

- [x] 10.5 Implement decomposition proof generation
  - Output ℓ claims: {(Cⱼ, r, yⱼ)}ⱼ∈[ℓ] with small-norm witnesses
  - Achieve proof size O(ℓ) commitments and evaluations
  - _Requirements: NEO-11.11, NEO-11.12, NEO-12.11_


## Phase 11: Random Linear Combination (RLC)

- [x] 11. Implement challenge set generation


  - Define challenge set C ⊆ R_q with |C| ≥ 2^128
  - Implement ternary challenge set: coefficients in {-1, 0, 1}
  - Verify size: 3^d ≥ 2^128 requires d ≥ 81
  - Ensure norm bound: ||c||_∞ = 1 for ternary challenges
  - _Requirements: NEO-12.1, NEO-12.2, NEO-12.3, NEO-14.1, NEO-14.5, NEO-14.6_

- [x] 11.1 Implement challenge sampling

  - Sample challenges uniformly from C using cryptographic randomness
  - Implement Fiat-Shamir transform for non-interactive challenges
  - Hash transcript to generate challenge: c = H(transcript) mod C
  - Ensure statistical closeness to uniform distribution
  - _Requirements: NEO-12.10, NEO-12.11, NEO-12.12, NEO-12.13, NEO-14.10_


- [x] 11.2 Implement invertibility verification

  - Verify c - c' is invertible for all distinct c, c' ∈ C
  - Use Theorem 1: if ||cf(a)||_∞ < b_inv, then a is invertible
  - Compute b_inv = q^(1/e) / √e for field parameters
  - _Requirements: NEO-12.5, NEO-12.6, NEO-14.4_



- [x] 11.3 Implement RLC reduction protocol


  - Accept L evaluation claims: {(Cᵢ, rᵢ, yᵢ)}ᵢ∈[L] with witnesses {wᵢ}
  - Sample random coefficients ρ = (ρ₀, ..., ρ_{L-1}) ∈ F^L
  - Compute combined witness: w* = Σᵢ ρᵢ·wᵢ
  - Compute combined commitment: C* = Σᵢ ρᵢ·Cᵢ

  - _Requirements: NEO-11.1, NEO-11.2, NEO-11.3, NEO-11.4, NEO-11.5_




- [x] 11.4 Implement combined evaluation function


  - Define f*(x) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, x)
  - Verify f*(rⱼ) = ρⱼ·yⱼ for each j ∈ [L]
  - Sample random evaluation point r* ∈ F^ℓ
  - Compute y* = f*(r*) = Σᵢ ρᵢ·w̃ᵢ(rᵢ)·eq(rᵢ, r*)


  - _Requirements: NEO-11.6, NEO-11.7, NEO-11.8, NEO-11.9_





- [ ] 11.5 Implement RLC soundness verification
  - Output single claim: (C*, r*, y*)
  - Verify C* = Com(w*) and f̃*(r*) = y*
  - Achieve soundness via Schwartz-Zippel: error ≤ deg(f*)/|F|
  - Provide proof size O(1) field elements
  - _Requirements: NEO-11.10, NEO-11.11, NEO-11.12, NEO-11.15_


## Phase 12: Complete Neo Folding Scheme

- [-] 12. Implement complete folding protocol

  - Accept two CCS instances: (x₁, w₁) and (x₂, w₂)
  - Verify both instances satisfy CCS relation
  - Construct full witnesses: z₁ = (1, x₁, w₁), z₂ = (1, x₂, w₂)
  - Commit to witnesses: C₁ = Com(z₁), C₂ = Com(z₂)
  - _Requirements: NEO-13.1, NEO-13.2, NEO-13.3, NEO-13.4_

- [x] 12.1 Implement Phase 1: CCS to evaluation claims

  - Run sum-check for both instances reducing to 2t evaluation claims
  - Apply matrix-vector reduction to all 2t claims
  - _Requirements: NEO-13.5, NEO-13.6_






- [ ] 12.2 Implement Phase 2: RLC combination
  - Apply RLC combining 2t claims into single claim (C*, r*, y*)
  - _Requirements: NEO-13.7_




- [x] 12.3 Implement Phase 3: Decomposition

  - Apply decomposition to (C*, r*, y*) producing ℓ small-norm claims

  - _Requirements: NEO-13.8_

- [x] 12.4 Implement Phase 4: Final folding


  - Apply folding protocol to ℓ claims producing final claim (C', r*, y')

  - Verify folded claim: C' = Com(w') and w̃'(r*) = y'

  - _Requirements: NEO-13.9, NEO-13.10_

- [ ] 12.5 Implement complexity analysis
  - Achieve prover time O(N) dominated by O(N) ring multiplications



  - Achieve verifier time O(log N) dominated by sum-check verification

  - Achieve proof size O(log N) field elements

  - Achieve soundness error ≤ 2^(-128) with appropriate parameters
  - _Requirements: NEO-13.11, NEO-13.12, NEO-13.13, NEO-13.14_

- [ ] 12.6 Implement recursive folding support
  - Support treating (C', r*, y') as new instance for recursive folding
  - Maintain norm bounds across recursive folding steps


  - _Requirements: NEO-13.15_


## Phase 13: IVC/PCD Construction



- [ ] 13. Implement IVC initialization
  - Define step function F: X × W → X computing one computation step
  - Initialize accumulator (C_acc, x_acc, w_acc) with first instance
  - Create initial evaluation claim from first step
  - _Requirements: NEO-14.2, NEO-14.3_



- [ ] 13.1 Implement IVC step proving
  - Compute new state: xᵢ = F(xᵢ₋₁, wᵢ)
  - Create instance (Cᵢ, xᵢ, wᵢ) where Cᵢ = Com(wᵢ)
  - Fold new instance with accumulator: (C_acc, x_acc, w_acc) ← Fold(...)

  - Update accumulator after folding
  - _Requirements: NEO-14.4, NEO-14.5, NEO-14.6, NEO-14.7_

- [ ] 13.2 Implement IVC verification
  - Generate final proof π for accumulated instance after n steps
  - Verify accumulator validity and final state correctness
  - _Requirements: NEO-14.8, NEO-14.9_



- [ ] 13.3 Implement recursive verifier circuit
  - Implement circuit C_verify with size O(κ + log(m·n))
  - Verify previous accumulator in C_verify
  - Verify current step correctness in C_verify
  - Verify folding correctness in C_verify

  - _Requirements: NEO-14.10, NEO-14.11, NEO-14.12, NEO-14.13_


- [ ] 13.4 Implement IVC complexity analysis
  - Achieve IVC prover time O(n·(m·n + κ·n)) for n steps
  - Achieve IVC verifier time O(κ + log(m·n)) independent of n
  - _Requirements: NEO-14.14, NEO-14.15_



## Phase 14: Proof Compression


- [ ] 14. Implement SNARK compression interface
  - Define accumulator relation R_acc checking witness validity
  - Generate SNARK proof π_snark for (C_acc, x_acc, w_acc) ∈ R_acc

  - Support multiple SNARK backends (Groth16, Plonk, STARKs, lattice-based)

  - _Requirements: NEO-15.1, NEO-15.2, NEO-15.3, NEO-15.4_

- [x] 14.1 Implement Spartan + FRI compression

  - Use Spartan to reduce accumulator relation to multilinear evaluation claims
  - Use FRI to prove multilinear polynomial evaluations
  - Maintain post-quantum security with hash-based FRI
  - Avoid wrong-field arithmetic with native field support


  - _Requirements: NEO-15.5, NEO-15.11_

- [ ] 14.2 Implement compressed proof generation
  - Output compressed proof (C_acc, x_acc, π_snark)


  - Achieve proof size O(κ·d + |π_snark|) where |π_snark| = O(log(m·n))
  - _Requirements: NEO-15.6, NEO-15.8_

- [ ] 14.3 Implement compressed verification
  - Verify SNARK.Verify(R_acc, (C_acc, x_acc), π_snark)

  - Achieve verification time O(|π_snark|) for SNARK verification
  - _Requirements: NEO-15.7, NEO-15.9_

- [-] 14.4 Implement compression ratio analysis

  - Document compression ratio: (uncompressed size) / (compressed size) ≈ n
  - Implement SNARK proving in time O(m·n·log(m·n)) for accumulator relation
  - _Requirements: NEO-15.10, NEO-15.11_

- [ ] 14.5 Implement proof aggregation
  - Support batching multiple IVC proofs into single SNARK proof
  - Implement proof aggregation combining multiple compressed proofs
  - _Requirements: NEO-15.13, NEO-15.14_


## Phase 15: Parameter Selection and Security

- [x] 15. Implement Goldilocks parameter set


  - Set q = 2^64 - 2^32 + 1 for Goldilocks field
  - Set d = 64 for cyclotomic ring degree
  - Verify q ≡ 1 + 2^2 (mod 4·2^2) so e = 2
  - Compute extension degree τ = 64/2 = 32
  - Set κ = 4 for commitment dimension
  - Set β = 2^20 for norm bound
  - _Requirements: NEO-16.1, NEO-16.2, NEO-16.3, NEO-16.4, NEO-16.5, NEO-16.6, NEO-16.7, NEO-16.8_

- [x] 15.1 Implement Mersenne 61 parameter set

  - Set q = 2^61 - 1 for M61 field
  - Set d = 64 for cyclotomic ring degree
  - Verify q ≡ 1 (mod 128) so e = 1 and ring splits completely
  - Compute extension degree τ = 64
  - Set κ = 5 for commitment dimension (larger due to smaller q)
  - Set β = 2^18 for norm bound
  - _Requirements: NEO-17.1, NEO-17.2, NEO-17.3, NEO-17.4, NEO-17.5, NEO-17.6, NEO-17.7, NEO-17.8_


- [ ] 15.2 Implement Module-SIS security verification
  - Verify Module-SIS(κ, n, q, β) provides ≥ 128-bit security
  - Use Lattice Estimator to compute BKZ block size
  - Ensure BKZ block size b ≥ 128 for 128-bit security
  - _Requirements: NEO-16.9, NEO-15.6, NEO-15.7_


- [ ] 15.3 Implement soundness error computation
  - Compute sum-check soundness: ε_sc = O(d·ℓ/|F|)
  - Compute folding soundness: ε_fold = O(d/|C|)
  - Compute RLC soundness: ε_rlc = O(deg/|F|)
  - Compute total soundness: ε_total = ε_sc + ε_fold + ε_rlc
  - Verify ε_total ≤ 2^(-128)

  - _Requirements: NEO-15.8, NEO-15.9, NEO-15.10, NEO-15.11, NEO-15.12_

- [ ] 15.4 Implement parameter validation
  - Validate all parameter choices with security justification
  - Provide parameter generation tool for different security levels
  - Implement runtime parameter validation
  - _Requirements: NEO-15.13, NEO-15.14, NEO-15.15_


## Phase 16: Transcript and Fiat-Shamir

- [x] 16. Implement transcript management


  - Implement Transcript struct using SHA3-256 or BLAKE3
  - Implement append operations for field elements, commitments, and messages
  - Implement challenge generation using hash-based Fiat-Shamir
  - Maintain challenge counter for domain separation
  - _Requirements: NEO-9.8, NEO-12.11_

- [x] 16.1 Implement field element serialization

  - Implement canonical serialization for field elements
  - Implement serialization for ring elements
  - Implement serialization for commitments
  - Ensure deterministic serialization for reproducibility
  - _Requirements: NEO-12.12_


- [ ] 16.2 Implement challenge derivation
  - Derive field element challenges from transcript hash
  - Derive ring element challenges from transcript hash
  - Ensure uniform distribution of challenges
  - Implement challenge set membership verification
  - _Requirements: NEO-12.10, NEO-12.13, NEO-14.13_

## Phase 17: Optimizations and Performance

- [x] 17. Implement parallel processing


  - Implement parallel commitment computation for multiple witnesses
  - Implement parallel matrix-vector multiplications
  - Implement parallel MLE evaluations
  - Use Rayon or similar for work-stealing parallelism

  - _Requirements: Performance optimization_

- [ ] 17.1 Implement memory pooling
  - Implement memory pool for field element buffers
  - Implement memory pool for ring element buffers
  - Implement buffer reuse to reduce allocations

  - Implement streaming computation for large witnesses
  - _Requirements: Performance optimization_

- [ ] 17.2 Implement sparse matrix optimizations
  - Implement CSR (Compressed Sparse Row) format

  - Implement optimized sparse matrix-vector multiplication
  - Implement structured matrix optimizations (circulant, Toeplitz)
  - _Requirements: NEO-7.15, NEO-9.14_

- [x] 17.3 Implement NTT optimizations

  - Implement precomputed twiddle factors
  - Implement bit-reversal permutation optimization
  - Implement cache-friendly memory access patterns
  - Benchmark and profile NTT performance
  - _Requirements: NEO-1.6_


## Phase 18: Testing and Validation

- [ ]* 18. Implement unit tests for field arithmetic
  - Test Goldilocks field operations (add, mul, inv, pow)
  - Test M61 field operations with Mersenne reduction
  - Test extension field F_q^2 operations
  - Test field arithmetic properties (commutativity, associativity, distributivity)
  - _Requirements: All NEO-2 requirements_

- [ ]* 18.1 Implement unit tests for ring operations
  - Test cyclotomic ring construction and validation
  - Test NTT forward and inverse with round-trip verification
  - Test ring multiplication correctness
  - Test coefficient embedding and extraction
  - Test rotation matrix properties
  - _Requirements: All NEO-1 requirements_

- [ ]* 18.2 Implement unit tests for multilinear polynomials
  - Test MLE construction and evaluation
  - Test evaluation at Boolean hypercube points
  - Test partial evaluation
  - Test equality polynomial
  - _Requirements: All NEO-6 requirements_

- [ ]* 18.3 Implement unit tests for commitments
  - Test Ajtai commitment binding property
  - Test commitment opening verification
  - Test linear homomorphism property
  - Test pay-per-bit cost tracking
  - Test packing and unpacking operations
  - _Requirements: All NEO-3, NEO-4, NEO-5 requirements_

- [ ]* 18.4 Implement unit tests for CCS
  - Test CCS structure construction
  - Test sparse matrix operations
  - Test CCS relation verification
  - Test R1CS special case
  - Test matrix MLE computation
  - _Requirements: All NEO-7 requirements_

- [ ]* 18.5 Implement unit tests for sum-check
  - Test sum-check prover round computation
  - Test sum-check verifier checks
  - Test Lagrange interpolation
  - Test final verification
  - Test soundness error bounds
  - _Requirements: All NEO-9 requirements_

- [ ]* 18.6 Implement unit tests for decomposition
  - Test witness decomposition correctness
  - Test digit reconstruction
  - Test norm bound verification
  - Test optimal base selection
  - _Requirements: All NEO-11, NEO-12 requirements_

- [ ]* 18.7 Implement integration tests
  - Test end-to-end R1CS folding
  - Test end-to-end CCS folding
  - Test IVC with multiple steps
  - Test proof compression
  - Test parameter validation
  - _Requirements: All NEO-13, NEO-14, NEO-15 requirements_

- [ ]* 18.8 Implement property-based tests
  - Test field arithmetic properties with random inputs
  - Test commitment homomorphism with random witnesses
  - Test decomposition reconstruction with random values
  - Test folding soundness with random instances
  - _Requirements: All requirements_

- [ ]* 18.9 Implement benchmark suite
  - Benchmark field operations (add, mul, inv)
  - Benchmark NTT performance
  - Benchmark commitment computation
  - Benchmark folding protocol
  - Benchmark IVC step proving
  - Compare with baseline implementations
  - _Requirements: Performance analysis_


## Phase 19: Documentation and Examples

- [ ]* 19. Write API documentation
  - Document all public interfaces with rustdoc
  - Document field arithmetic APIs
  - Document ring operation APIs
  - Document commitment scheme APIs
  - Document folding scheme APIs
  - Document IVC/PCD APIs
  - _Requirements: All requirements_

- [ ]* 19.1 Write usage examples
  - Example: Simple R1CS folding
  - Example: Fibonacci IVC
  - Example: Pay-per-bit commitment demonstration
  - Example: Custom CCS construction
  - Example: Parameter selection guide
  - _Requirements: All requirements_

- [ ]* 19.2 Write security documentation
  - Document Module-SIS security assumptions
  - Document soundness error analysis
  - Document parameter selection guidelines
  - Document threat model and security considerations
  - _Requirements: NEO-15, NEO-18_

- [ ]* 19.3 Write performance documentation
  - Document complexity analysis for all operations
  - Document optimization techniques
  - Document benchmarking methodology
  - Document performance comparison with other schemes
  - _Requirements: Performance analysis_

## Summary

This implementation plan provides a complete roadmap for implementing Neo with:

- **19 major phases** covering all aspects of the system
- **100+ detailed tasks** with clear requirements references
- **Logical dependencies** ensuring proper build order
- **Optional testing tasks** marked with * for flexibility
- **Comprehensive coverage** of all requirements from requirements-neo.md

The plan follows a bottom-up approach:
1. Foundation: Field arithmetic and ring operations (Phases 1-2)
2. Polynomials: Multilinear extensions (Phase 3)
3. Commitments: Ajtai and pay-per-bit schemes (Phases 4-5)
4. Evaluation: Claims and folding (Phase 6)
5. CCS: Constraint systems (Phase 7)
6. Sum-Check: Protocol implementation (Phase 8)
7. Reductions: CCS to claims (Phase 9)
8. Decomposition: Norm control (Phase 10)
9. RLC: Random linear combination (Phase 11)
10. Folding: Complete scheme (Phase 12)
11. IVC/PCD: Incrementally verifiable computation (Phase 13)
12. Compression: SNARK integration (Phase 14)
13. Parameters: Security analysis (Phase 15)
14. Transcript: Fiat-Shamir (Phase 16)
15. Optimization: Performance tuning (Phase 17)
16. Testing: Comprehensive validation (Phase 18)
17. Documentation: API and examples (Phase 19)

Each task is actionable by a coding agent and references specific requirements for traceability.

