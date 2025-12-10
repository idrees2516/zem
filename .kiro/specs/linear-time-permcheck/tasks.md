# Implementation Plan: Linear-Time Permutation Check

## Phase 1: Foundation Layer Implementation

- [x] 1. Set up project structure and core interfaces



  - Create directory structure for foundation, protocol, integration, application layers
  - Define abstract Field trait with operations: add, sub, mul, inv, neg, pow, random
  - Implement PrimeField for common prime fields (BN254, BLS12-381)
  - Implement BinaryField for F₂ⁿ
  - Set up testing framework with property-based testing support
  - _Requirements: 20.1, 20.2, 20.10_

- [x] 1.1 Implement field arithmetic operations

  - Implement modular addition, subtraction, multiplication
  - Implement modular inversion using extended Euclidean algorithm
  - Implement exponentiation using square-and-multiply
  - Implement batch inversion optimization
  - _Requirements: 1.1, 1.2, 20.2_

- [ ]* 1.2 Write property tests for field operations
  - **Property 1: Field axioms** - Verify associativity, commutativity, distributivity
  - Test additive and multiplicative identities
  - Test additive and multiplicative inverses
  - **Validates: Requirements 1.1**


- [ ] 2. Implement polynomial operations
  - [ ] 2.1 Implement MultilinearPolynomial structure
    - Store evaluations over boolean hypercube B^μ
    - Implement indexing: binary vector → array position
    - Implement evaluation at arbitrary point in F^μ
    - Implement partial evaluation (fix first k variables)

    - _Requirements: 1.3, 20.3_

- [ ] 2.2 Implement multilinear extension computation
  - Implement MLE formula: f̃(X) = ∑_{b∈B^μ} f(b) · eq(b,X)
  - Optimize using dynamic programming
  - Implement from_evaluations constructor
  - _Requirements: 1.3_

- [ ]* 2.3 Write property test for MLE correctness
  - **Property 2: MLE agreement on boolean hypercube**


  - For any function f and point b ∈ B^μ, verify f̃(b) = f(b)
  - **Validates: Requirements 1.3**

- [ ] 2.4 Implement univariate polynomial operations
  - Implement UnivariatePolynomial with coefficient representation
  - Implement evaluation using Horner's method

  - Implement Lagrange interpolation from points
  - Implement polynomial addition and multiplication
  - _Requirements: 2.2, 2.3_


- [ ] 3. Implement equality polynomial
  - [ ] 3.1 Implement eq(X,Y) computation
    - Implement formula: eq(X,Y) = ∏ᵢ [XᵢYᵢ + (1-Xᵢ)(1-Yᵢ)]
    - Optimize for boolean inputs
    - _Requirements: 1.1, 1.2_

- [ ] 3.2 Implement evaluate_all_boolean optimization
  - Implement O(2^μ) algorithm to compute eq(y,α) for all y ∈ B^μ
  - Use dynamic programming: build up from smaller dimensions
  - Critical for BiPerm O(√n) preprocessing


  - _Requirements: 1.4_

- [ ]* 3.3 Write property test for equality polynomial
  - **Property 1: Equality polynomial boolean behavior**
  - For any x,y ∈ B^μ, verify eq(x,y) = 1 iff x = y
  - **Validates: Requirements 1.1, 1.2**

- [ ] 4. Implement boolean hypercube utilities
  - Implement BooleanHypercube iterator over B^μ
  - Implement conversion between boolean vectors and field elements
  - Implement lexicographic ordering utilities




  - Implement size computation: 2^μ
  - _Requirements: 1.7, 20.4_

- [x] 5. Checkpoint - Ensure all foundation tests pass

  - Ensure all tests pass, ask the user if questions arise.


## Phase 2: Sumcheck Protocol Implementation

- [x] 6. Implement generic sumcheck protocol

  - [ ] 6.1 Define VirtualPolynomial trait
    - Define evaluate(point: &[F]) -> F method
    - Define compute_round_polynomial(challenges: &[F]) -> UnivariatePolynomial method
    - Define degree() -> usize method
    - _Requirements: 2.1, 20.4_

- [ ] 6.2 Implement SumcheckProver
    - Implement prove method executing μ rounds
    - In each round k, compute uₖ(X) = ∑_{x∈B^{μ-k}} f(α, X, x)
    - Send round polynomial as oracle (degree d-2 polynomial + u(0))
    - Collapse evaluation tables after each round
    - _Requirements: 2.1, 2.2, 2.7_

- [ ] 6.3 Implement SumcheckVerifier
    - Verify uₖ(0) + uₖ(1) = S for each round

    - Sample random challenge αₖ ∈ F
    - Update S ← uₖ(αₖ)
    - After μ rounds, verify f(α) = S
    - _Requirements: 2.3, 2.4, 2.5_



- [ ]* 6.4 Write property test for sumcheck correctness
  - **Property 3: Sumcheck round consistency**
  - For any polynomial f and claimed sum v, verify each round satisfies uₖ(0) + uₖ(1) = S
  - **Validates: Requirements 2.2**

- [ ]* 6.5 Write property test for sumcheck completeness
  - **Property 17: Sumcheck perfect completeness**
  - For any honest prover with valid witness, verify verifier accepts with probability 1
  - **Validates: Requirements 18.3**

- [ ] 7. Implement FFT optimization for round polynomials
  - Implement FFT-based polynomial multiplication
  - Use for computing products of evaluation lists
  - Reduces complexity from O(d²) to O(d log d)
  - _Requirements: 2.8, 15.2_

- [ ] 8. Implement batching for multiple sumcheck instances
  - Implement random linear combination technique
  - Batch multiple sumcheck claims into single verification
  - _Requirements: 2.9, 15.10_

- [ ] 9. Checkpoint - Ensure all sumcheck tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 3: Permutation Representation

- [ ] 10. Implement permutation data structures
  - [ ] 10.1 Implement Permutation struct
    - Store as mapping vector: σ(i) = mapping[i]
    - Implement validation: check bijection property
    - Implement inverse computation
    - Implement composition
    - _Requirements: 1.5, 4.5_

- [ ] 10.2 Implement PermutationMLE
    - Compute σ̃ᵢ(X) for each bit i ∈ [μ]
    - Each σ̃ᵢ is MLE of i-th bit of σ
    - Store as vector of μ multilinear polynomials
    - _Requirements: 1.5, 4.5_

- [ ] 10.3 Implement σ̃[μ] interpolation
    - Interpolate (μ+log μ)-variate polynomial σ̃[μ](I,X)
    - Satisfy σ̃[μ](⟨i⟩,X) = σ̃ᵢ(X) for all i ∈ [μ]
    - Use binary encoding for index I
    - _Requirements: 1.6_

- [ ] 11. Implement indicator function
  - [ ] 11.1 Implement 1σ(X,Y) computation
    - Implement indicator: 1 if σ(X)=Y, 0 otherwise
    - Works on boolean hypercube B^μ × B^μ
    - _Requirements: 1.7_

- [ ] 11.2 Implement indicator function arithmetization
    - Implement 1̃σ(X,Y) = eq(σ̃(X),Y) = ∏ᵢ eq(σ̃ᵢ(X),Yᵢ)
    - Support different arithmetization strategies
    - _Requirements: 1.8_

- [ ] 11.3 Implement ArithmetizationStrategy enum
    - Naive: μ-way product (baseline)
    - BiPerm: 2-way product
    - MulPerm { ell }: ℓ-way product
    - _Requirements: 5.1_

- [ ] 12. Implement permutation check reduction to sumcheck
  - [ ] 12.1 Implement reduction formula
    - Reduce f(x) = g(σ(x)) ∀x to sumcheck
    - Prove ∑_{x∈B^μ} f(x) · 1̃σ(x,α) = g(α)
    - _Requirements: 3.2, 4.6_

- [ ]* 12.2 Write property test for reduction correctness
  - **Property 5: Sumcheck reduction equivalence**
  - For any valid permutation, verify reduction equation holds
  - **Validates: Requirements 3.2**

- [ ] 13. Checkpoint - Ensure all permutation representation tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 4: BiPerm Protocol Implementation

- [x] 14. Implement BiPerm preprocessing



  - [ ] 14.1 Implement permutation splitting
    - Split σ into σ_L (first μ/2 bits) and σ_R (last μ/2 bits)
    - Compute 1̃σL(X,YL) and 1̃σR(X,YR)
    - Each is n^1.5-sized polynomial with n non-zero entries
    - _Requirements: 4.1, 4.2, 4.3, 4.4_


- [ ] 14.2 Implement indicator table computation
    - Compute eq(yL,αL) for all yL ∈ B^{μ/2} in O(2^{μ/2}) time
    - Compute 1̃σL(x,αL) for all x ∈ B^μ using lookup
    - Similarly for 1̃σR(x,αR)

    - Total time: O(√n + n) = O(n)

    - _Requirements: 4.8_

- [ ] 15. Implement BiPerm prover
  - [x] 15.1 Implement BiPermProver struct

    - Store f, g, σ_L, σ_R
    - Implement preprocessing method
    - _Requirements: 4.7_

- [x] 15.2 Implement BiPerm sumcheck

    - Prove ∑_{x∈B^μ} f(x) · 1̃σL(x,αL) · 1̃σR(x,αR) = g(α)
    - Degree 3 sumcheck with μ rounds
    - Use precomputed indicator tables
    - _Requirements: 4.5_

- [ ] 15.3 Implement prove method
    - Preprocess indicator functions
    - Compute indicator tables for challenge α
    - Run degree-3 sumcheck
    - Return proof with round polynomials and openings
    - _Requirements: 4.9_

- [ ]* 15.4 Write property test for BiPerm correctness
  - **Property 7: BiPerm correctness**
  - For any valid permutation, verify BiPerm accepts
  - For invalid permutation, verify BiPerm rejects with high probability
  - **Validates: Requirements 4.5**




- [ ]* 15.5 Write property test for BiPerm performance
  - **Property 6: BiPerm linear time performance**
  - Measure field operations for various n

  - Verify total operations is O(n)
  - **Validates: Requirements 4.9**

- [ ] 16. Implement BiPerm verifier
  - [ ] 16.1 Implement BiPermVerifier struct
    - Store num_vars parameter
    - _Requirements: 4.10_

- [ ] 16.2 Implement verify method
    - Query g(α) from oracle

    - Run sumcheck verifier
    - Verify final check: f(β) · 1̃σL(β,αL) · 1̃σR(β,αR) = S
    - Query oracles for f, σ_L, σ_R at point β
    - _Requirements: 4.10_

- [ ] 17. Checkpoint - Ensure all BiPerm tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 5: MulPerm Protocol - Partial Products

- [x] 18. Implement partial product computation

  - [x] 18.1 Implement group parameter selection
    - Choose ℓ = √μ = √(log n) to balance costs
    - Implement choose_ell() method
    - _Requirements: 5.1_

- [x] 18.2 Implement partial product definition
    - Define p(x,⟨j⟩) := ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃[μ](⟨j'+i⟩,x))
    - Compute for all x ∈ B^μ, j ∈ [ℓ]
    - _Requirements: 5.4_

- [x] 18.3 Implement MLE of partial products
    - Compute p̃(x*,j*) = ∑_{x∈B^μ,j∈[ℓ]} eq((x,⟨j⟩),(x*,j*)) · p(x,⟨j⟩)
    - Note: p̃(x') = p(x') on boolean hypercube
    - _Requirements: 5.5_

- [x] 19. Implement bucketing algorithm for partial products
  - [x] 19.1 Implement identity bucket computation
    - Observe: each eq(σ̃ᵢ(X),yᵢ) takes 4 forms: X, 1-X, 1, 0
    - For fixed j, p(x,⟨j⟩) has at most 2^{μ/ℓ} distinct values
    - Precompute all ℓ·2^{μ/ℓ} possible evaluations
    - _Requirements: 5.10, 6.1, 6.2_

- [x] 19.2 Implement ComputePartialProducts algorithm (Algorithm 4)
    - Create table S of size 2^{μ/ℓ} × ℓ
    - For each i,j: compute Sᵢⱼ ← eq(α[j'+1:j'+μ/ℓ], sᵢ)
    - For each x,j: lookup corresponding Sᵢⱼ
    - Total cost: (μ/ℓ)·ℓ·2^{μ/ℓ} = μ·2^{μ/ℓ} = μ·n^{1/ℓ} = o(n)
    - _Requirements: 5.10, 16.4_

- [ ]* 19.3 Write property test for partial product computation
  - Verify p̃(x') computed correctly for all x' ∈ B^{μ+log ℓ}
  - Verify computation completes in o(n) time
  - **Validates: Requirements 5.10**

- [x] 20. Checkpoint - Ensure partial product tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 6: MulPerm Protocol - First Sumcheck

- [x] 21. Implement first sumcheck for MulPerm
  - [x] 21.1 Implement first sumcheck formulation
    - Prove ∑_{x∈B^μ} f(x) ∏_{j∈[ℓ]} p̃(x,⟨j⟩) = g(α)
    - Degree ℓ+1 in each variable
    - μ rounds over x variables
    - _Requirements: 5.6_

- [x] 21.2 Implement Sumcheck1Prover (Algorithm 5)
    - For each round k ∈ [μ]:
      - Compute uₖ(X) = ∑_{x∈B^{μ-k}} f(β,X,x) ∏_{j∈[ℓ]} p̃((β,X,x),⟨j⟩)
      - Use FFT to multiply ℓ+1 lists of ℓ+2 evaluation points
      - Send [[uₖ]] to verifier
      - Receive challenge βₖ, collapse tables
    - After μ rounds, send Pⱼ := p̃(β,⟨j⟩) for j ∈ [ℓ]
    - _Requirements: 5.7, 16.5_

- [x] 21.3 Implement Sumcheck1Verifier
    - Query g(α) to get claimed sum S
    - For each round: verify uₖ(0) + uₖ(1) = S, sample βₖ, update S ← uₖ(βₖ)
    - After μ rounds: query f(β), verify S = f(β) · ∏ⱼ Pⱼ
    - Return claims [Pⱼ]ⱼ∈[ℓ] and point β
    - _Requirements: 5.7, 16.5_

- [ ]* 21.4 Write property test for first sumcheck
  - Verify reduction to ℓ claims is correct
  - Measure field operations: should be n·Õ(ℓ)
  - **Validates: Requirements 5.6, 5.7**

- [x] 22. Implement batching of partial product claims
  - [x] 22.1 Implement random linear combination
    - Verifier samples t ∈ F^{log ℓ}
    - Compute Sp̃ ← ∑_{j∈[ℓ]} eq(t,⟨j⟩) · Pⱼ
    - Reduces ℓ claims to single claim p̃(β||t) = Sp̃
    - _Requirements: 5.8_

- [x] 23. Checkpoint - Ensure first sumcheck tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 7: MulPerm Protocol - Second Sumcheck with Bucketing

- [x] 24. Implement second sumcheck formulation
  - [x] 24.1 Implement second sumcheck equation
    - Prove ∑_{x∈B^μ,j∈[ℓ]} eq(β',x||⟨j⟩) · p(x,⟨j⟩) = Sp̃
    - Where β' = β||t and p(x,⟨j⟩) = ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃[μ](⟨j'+i⟩,x))
    - Degree μ/ℓ+1 in each variable
    - μ+log ℓ rounds total
    - _Requirements: 5.9_

- [x] 25. Implement bucketing algorithm for second sumcheck
  - [x] 25.1 Implement identity bucket precomputation
    - In round k, each univariate σ̃[μ] has 2^{2^k} possible identities
    - Total identities for p̃: 2^{2^k·μ/ℓ}·ℓ
    - Precompute all identity polynomials
    - _Requirements: 6.3, 6.4_

- [x] 25.2 Implement partition by identity
    - Group evaluation points x' ∈ B^{μ+log ℓ-k} by which identity p̃(X,x') matches
    - Create buckets: bucket_i = {x' : p̃(X,x') = id_i}
    - _Requirements: 6.4_

- [x] 25.3 Implement Bucket algorithm (Algorithm 6)
    - Initialize ℓ tables t₁,...,tℓ of size 2^{2^k·μ/ℓ}
    - For each j,s: compute identity polynomial and fill tⱼ[s,1]
    - For each x,j: lookup σ̃[μ] values, determine bucket, add x to tⱼ[s,2]
    - Compute uₖ(X) = ∑ᵢ idᵢ · ∑_{x'∈bucket_i} eq((γ,X,x'),β')
    - Cost: (μ/ℓ+1)(μ/ℓ+2)·2^{2^k·μ/ℓ}·ℓ multiplications
    - _Requirements: 6.5, 16.6_

- [ ]* 25.4 Write property test for bucketing correctness
  - **Property 9: Bucketing algorithm correctness**
  - For any round, verify bucketing produces same result as direct computation
  - **Validates: Requireme5, 18.9**

- [x] 26. Implement algorithm switching logic
  - [x] 26.1 Implement cost analysis
    - Bucketing cost in round k: O(μ²/ℓ)·2^{2^k·μ/ℓ}
    - Direct cost in round k: O(n·μ²/ℓ²)
    - Switch point k' = log ℓ where costs balance
    - _Requirements: 6.6, 6.7, 6.8, 6.9, 6.10_

- [x] 26.2 Implement Collapse algorithm (Algorithm 11)
    - Before switching, compute σ̃(⟨i⟩,(γ,x)) for all i ∈ [μ]
    - Use bucketing-style algorithm
    - Cost: fewer than ℓ·2^ℓ field operations
    - _Requirements: 6.11, 16.11_

- [x] 26.3 Implement direct computation for k ≥ log ℓ
    - For rounds k ≥ log ℓ, use direct computation
    - Compute uₖ(X) = ∑_{x'∈B^{μ+log ℓ-k}} eq((γ,X,x'),β') · p(γ,X,x')
    - Use FFT for polynomial multiplication
    - _Requirements: 6.10_

- [x] 27. Implement Sumcheck2Prover (Algorithm 7)
  - [x] 27.1 Implement bucketing phase (rounds 1 to log ℓ-1)
    - For k ← 1 to log ℓ-1:
      - uₖ(X) ← Bucket(σ̃[μ], β', γ, k)
      - Send [[uₖ]] to verifier
      - Receive γₖ, append to γ
    - _Requirements: 16.7_

- [x] 27.2 Implement algorithm switch
    - Compute collapsed evaluation tables
    - Switch to direct computation
    - _Requirements: 16.7_

- [x] 27.3 Implement direct phase (rounds log ℓ to μ+log ℓ)
    - For k ← log ℓ to μ+log ℓ:
      - Compute uₖ(X) directly using FFT
      - Send [[uₖ]] to verifier
      - Receive γₖ, collapse tables
    - _Requirements: 16.7_

- [x] 28. Implement Sumcheck2Verifier
  - [x] 28.1 Implement verification loop
    - For k ← 1 to μ+log ℓ:
      - Receive [[uₖ]], verify uₖ(0) + uₖ(1) = S
      - Sample γₖ, update S ← uₖ(γₖ)
    - _Requirements: 16.7_

- [x] 28.2 Implement final verification
    - Extract x* ← γ[:μ], j* ← γ[μ+1:]
    - Batch-query σ̃[μ] at √log n points
    - Verify S = ∏_{i∈[μ/ℓ]} eq(α(j*·⟨μ/ℓ⟩+⟨i⟩), Vᵢ)
    - _Requirements: 16.7_

- [ ]* 28.3 Write property test for second sumcheck
  - Verify correctness of second sumcheck
  - Measure field operations: should be n·Õ(μ/ℓ) + ℓ·2^ℓ
  - **Validates: Requirements 5.9**

- [ ]* 28.4 Write property test for bucketing performance
  - **Property 10: Bucketing algorithm performance**
  - Measure total cost across all rounds
  - Verify matches n·Õ(μ/ℓ) + ℓ·2^ℓ
  - **Validates: Requirements 6.12**

- [x] 29. Checkpoint - Ensure second sumcheck tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 8: Complete MulPerm Protocol

- [x] 30. Implement MulPermProver
  - [x] 30.1 Implement MulPermProver struct
    - Store f, g, σ_interpolated, ell
    - Implement constructor with automatic ℓ selection
    - _Requirements: 5.2, 5.3, 5.15_

- [x] 30.2 Implement prove method (Algorithm 3)
    - Receive challenge α from verifier
    - Compute partial products p̃ over B^{μ+log ℓ}
    - Run first sumcheck, get β and [Pⱼ]
    - Receive challenge t from verifier
    - Run second sumcheck with β||t
    - Return complete proof
    - _Requirements: 16.3_

- [ ]* 30.3 Write property test for MulPerm correctness
  - For any valid permutation, verify MulPerm accepts
  - For invalid permutation, verify MulPerm rejects with high probability
  - **Validates: Requirements 5.6, 5.9**

- [ ]* 30.4 Write property test for MulPerm performance
  - **Property 8: MulPerm near-linear time performance**
  - Measure total field operations for various n
  - Verify matches n·Õ(√log n)
  - **Validates: Requirements 5.13**

- [x] 31. Implement MulPermVerifier
  - [x] 31.1 Implement MulPermVerifier struct
    - Store num_vars, ell parameters
    - _Requirements: 5.14, 5.16_

- [x] 31.2 Implement verify method
    - Sample α, query g(α)
    - Run Sumcheck1Verifier, get [Pⱼ] and β
    - Sample t, compute Sp̃
    - Run Sumcheck2Verifier
    - Verify all PCS openings
    - _Requirements: 5.14, 16.3_

- [x] 32. Implement MulPerm proof structure
  - [x] 32.1 Implement MulPermProof struct
    - Store first_sumcheck proof
    - Store partial_product_claims [Pⱼ]
    - Store second_sumcheck proof
    - Store sigma_openings (√log n openings)
    - _Requirements: 5.14_

- [x] 33. Checkpoint - Ensure all MulPerm tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 9: Prover-Provided Permutation

- [ ] 34. Implement inverse permutation check
  - [ ] 34.1 Implement inverse computation
    - Given σ, compute τ = σ^{-1}
    - Verify τ(σ(y)) = y for all y ∈ B^μ
    - _Requirements: 7.3_

- [ ] 34.2 Implement inverse check sumcheck
    - Reduce to sumcheck: ∑_{x∈B^μ} x · 1̃σ(x,α) = τ̃(α)
    - Run sumcheck protocol
    - _Requirements: 7.4, 7.5_

- [ ]* 34.3 Write property test for inverse check
  - **Property 11: Prover-provided permutation inverse check**
  - For any permutation σ and its inverse τ, verify protocol accepts
  - For non-inverse, verify protocol rejects
  - **Validates: Requirements 7.4**

- [ ] 35. Implement binary constraint check
  - [ ] 35.1 Implement binary check sumcheck
    - Prove ∑_{x∈B^μ,i∈[μ]} eq((x,⟨i⟩),s) · σ̃[μ](i,x)(1-σ̃[μ](i,x)) = 0
    - Use bucketing with parameter b = log μ' - k - 2
    - _Requirements: 7.6, 7.7, 7.8_

- [ ] 35.2 Implement folding for binary check
    - Implement h^{(b)} folding over b rounds
    - Compute h^{(b)}(x',s'') recursively
    - _Requirements: 7.8_

- [ ] 35.3 Implement BinMapBucket algorithm
    - Use bucketing for first log μ' rounds
    - Switch to direct computation after
    - Total cost: n·o(log log n) field operations
    - _Requirements: 7.9, 16.9_

- [ ]* 35.4 Write property test for binary check
  - **Property 12: Binary constraint verification**
  - For any well-formed permutation, verify binary check accepts
  - For non-binary values, verify binary check rejects
  - **Validates: Requirements 7.6**

- [ ] 36. Implement batched prover-provided permutation
  - [ ] 36.1 Implement random linear combination batching
    - Define f'(y) = y + R·f(y), g'(y) = τ(y) + R·g(y)
    - Prove f'(y) = g'(σ(y)) for all y using single MulPerm
    - Batches inverse check with permutation check
    - _Requirements: 7.11, 7.12_

- [ ] 36.2 Implement ProverProvidedPermutation struct
    - Store σ, τ commitments
    - Implement prove_batched method
    - _Requirements: 7.1, 7.2_

- [ ] 36.3 Implement PERM2 protocol (Algorithm 8)
    - Prover computes σ and τ = σ^{-1}
    - Prover commits to σ̃[μ] and τ̃[μ]
    - Run batched MulPerm for permutation + inverse check
    - Run BinMap for binary constraint
    - _Requirements: 7.13, 16.8_

- [ ] 37. Checkpoint - Ensure prover-provided permutation tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 10: Lookup Arguments

- [ ] 38. Implement lookup data structures
  - [ ] 38.1 Implement LookupMap struct
    - Store domain_size n = 2^μ
    - Store table_size T = 2^κ
    - Store mapping ρ: B^μ → B^κ
    - Support non-injective maps
    - _Requirements: 8.1, 8.2_

- [ ] 38.2 Implement lookup map MLE
    - Compute ρ̃[κ](I,X) similar to permutation
    - ρ̃[κ](⟨i⟩,X) = ρ̃ᵢ(X) for i ∈ [κ]
    - _Requirements: 8.1_

- [ ] 39. Implement outer sumcheck for lookups
  - [ ] 39.1 Implement outer sumcheck formulation
    - Add outer sum: ∑_{x∈B^μ} eq(x,s)g(x) = ∑_{y∈B^κ} f(y) ∑_{x∈B^μ} eq(x,s)1̃ρ(x,y)
    - Flip sums: ∑_{y∈B^κ} f(y) ∑_{x∈B^μ} eq(x,s)1̃ρ(x,y)
    - _Requirements: 8.5_

- [ ] 39.2 Implement sparse outer sumcheck
    - Only compute for y ∈ Iρ (image of ρ)
    - For each y, only sum over x where ρ(x) = y
    - Exploit sparsity of 1̃ρ
    - _Requirements: 8.6_

- [ ] 39.3 Implement performance optimization for T ≤ n
    - When T ≤ n, worst case all entries non-zero
    - Cost: n/2 + n/4 + ... + 1 = O(n)
    - _Requirements: 8.7_

- [ ] 39.4 Implement performance optimization for T > n
    - When T > n, table has n non-zero entries
    - Early rounds cost O(n) each for κ-μ rounds
    - Total: O(n(κ-μ)) = O(n(log T - log n))
    - _Requirements: 8.8_

- [ ]* 39.5 Write property test for outer sumcheck performance
  - **Property 14: Lookup performance for small tables**
  - For T ≤ n, verify outer sumcheck executes in O(n) operations
  - **Validates: Requirements 8.7**

- [ ] 40. Implement inner sumcheck for lookups
  - [ ] 40.1 Implement reduction after outer sumcheck
    - Reduce to: f(α) ∑_{x∈B^μ} eq(x,s)·1̃ρ(x,α) = S'
    - Equivalently: ∑_{x∈B^μ} eq(x,s)·1̃ρ(x,α) = S'/f(α)
    - _Requirements: 8.9_

- [ ] 40.2 Adapt MulPerm for lookup inner sumcheck
    - Use MulPerm with ℓ = √κ
    - Arithmetize 1̃ρ as product of ℓ sub-indicators
    - Run double-sumcheck structure
    - _Requirements: 8.10_

- [ ] 40.3 Implement table evaluation optimization
    - For structured tables, evaluate MLE efficiently
    - Example: range table t(X) = ∑ᵢ Xᵢ·2^i in O(log T) time
    - _Requirements: 8.13_

- [ ] 41. Implement MulLookupProver
  - [ ] 41.1 Implement MulLookupProver struct
    - Store witness g, table f, map ρ̃[κ]
    - Store domain_vars μ, table_vars κ
    - _Requirements: 8.1_

- [ ] 41.2 Implement prove method (Algorithm 10)
    - Receive challenge s from verifier
    - Compute S ← ∑_{x∈B^μ} eq(x,s)g(x)
    - Run outer sumcheck over table
    - Run inner sumcheck (adapted MulPerm) over witness
    - _Requirements: 9.1, 16.10_

- [ ]* 41.3 Write property test for lookup correctness
  - **Property 13: Lookup argument correctness**
  - For any valid lookup, verify protocol accepts
  - For invalid lookup, verify protocol rejects
  - **Validates: Requirements 8.2**

- [ ]* 41.4 Write property test for MulLookup performance
  - **Property 15: MulLookup performance**
  - For T < 2^{(1-ε)μ²}, verify prover cost is n·Õ(√log T)
  - **Validates: Requirements 8.11**

- [ ] 42. Implement MulLookupVerifier
  - [ ] 42.1 Implement verify method
    - Receive ρ̃[κ] commitment from prover
    - Sample s, run outer sumcheck verifier
    - Query f(α), compute S'/f(α)
    - Run inner sumcheck verifier
    - Verify all PCS openings
    - _Requirements: 9.1, 16.10_

- [ ] 43. Implement prover-provided lookup
  - [ ] 43.1 Implement binary check for lookup map
    - Prove ρ̃[κ](i,x) ∈ {0,1} for all x ∈ B^μ, i ∈ [κ]
    - Use same binary check as prover-provided permutation
    - Cost: n·o(log log n) if T ≤ n, o(n·κ/μ) if T > n
    - _Requirements: 9.2, 9.3, 9.4, 9.5_

- [ ] 43.2 Implement prover-provided lookup protocol
    - Prover computes and commits to ρ̃[κ]
    - Run MulLookup protocol
    - Run binary check for ρ̃[κ]
    - _Requirements: 9.6, 9.7, 9.8_

- [ ] 44. Checkpoint - Ensure all lookup tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 11: Polynomial Commitment Scheme Integration

- [ ] 45. Implement PCS trait and compilation
  - [ ] 45.1 Define PolynomialCommitmentScheme trait
    - Define Commitment, Opening, Params associated types
    - Define setup, commit, open, verify methods
    - Define batch_open for multiple polynomials at same point
    - _Requirements: 10.1, 10.2_

- [ ] 45.2 Implement PCS compilation for PIOP
    - Replace oracles with commitments
    - Replace queries with PCS open/verify
    - Implement batching optimization
    - _Requirements: 10.2, 10.3_

- [ ] 46. Implement KZG polynomial commitment
  - [ ] 46.1 Implement KZG for multilinear polynomials
    - Implement setup with trusted setup
    - Implement commit using multi-scalar multiplication
    - Implement open with evaluation proof
    - Implement batch_open with random linear combination
    - _Requirements: 10.10_

- [ ] 46.2 Test KZG with BiPerm and MulPerm
    - BiPerm: nW preprocessing, nF proving (W ⊆ F small subfield)
    - MulPerm: nW preprocessing, nF proving
    - _Requirements: 10.10_

- [ ] 47. Implement Dory polynomial commitment
  - [ ] 47.1 Implement Dory for multilinear polynomials
    - Implement setup
    - Implement commit with inner product argument
    - Implement open with √n verification
    - _Requirements: 10.11_

- [ ] 47.2 Test Dory with BiPerm and MulPerm
    - BiPerm: nW preprocessing, n^{0.75}F proving (sparse)
    - MulPerm: nW preprocessing, n^{0.5}F proving
    - _Requirements: 10.11_

- [ ] 48. Implement FRI polynomial commitment
  - [ ] 48.1 Implement FRI for multilinear polynomials
    - Implement setup (no trusted setup)
    - Implement commit using Merkle tree
    - Implement open with proximity testing
    - _Requirements: 10.12_

- [ ] 48.2 Test FRI with BiPerm and MulPerm
    - BiPerm: n^{1.5} preprocessing, n^{1.5} proving (hash-based)
    - MulPerm: n preprocessing, n proving
    - _Requirements: 10.12_

- [ ] 49. Implement Ligero polynomial commitment
  - [ ] 49.1 Implement Ligero for multilinear polynomials
    - Implement setup (no trusted setup)
    - Implement commit using interleaved Reed-Solomon
    - Implement open with linear-time prover
    - _Requirements: 10.12_

- [ ] 49.2 Test Ligero with BiPerm and MulPerm
    - BiPerm: n^{1.5} preprocessing, 0 proving hashes
    - MulPerm: n preprocessing, 0 proving hashes
    - _Requirements: 10.12_

- [ ] 50. Implement sparse PCS schemes
  - [ ] 50.1 Implement Hyrax
    - Optimize for sparse polynomials
    - Cost depends only on non-zero entries
    - _Requirements: 10.6_

- [ ] 50.2 Implement KZH
    - Implement sublinear accumulation
    - Optimize for sparse polynomials
    - _Requirements: 10.6_

- [ ] 50.3 Test sparse PCS with BiPerm
    - BiPerm with Hyrax/KZH: O(n) preprocessing, O(√n) opening
    - Verify linear prover time achieved
    - _Requirements: 10.6_

- [ ] 51. Implement batching for PCS
  - [ ] 51.1 Implement homomorphic batching
    - For KZG, Dory: batch t polynomials with cost n+t not n·t
    - Use random linear combination
    - _Requirements: 10.3, 10.4_

- [ ] 51.2 Implement hash-based batching
    - For FRI, Ligero: use interleaved code
    - Cryptographic operations independent of t
    - _Requirements: 10.5_

- [ ]* 51.3 Write property test for PCS compilation
  - Verify compiled protocol maintains correctness
  - Test with all PCS schemes
  - **Validates: Requirements 10.1, 10.2**

- [ ] 52. Checkpoint - Ensure all PCS integration tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 12: SNARK System Integration

- [ ] 53. Implement HyperPlonk integration
  - [ ] 53.1 Replace HyperPlonk permutation check
    - Identify permutation check in HyperPlonk
    - Replace with BiPerm or MulPerm
    - Maintain compatibility with gate checks
    - _Requirements: 11.1_

- [ ] 53.2 Implement single-commitment optimization
    - Batch permutation sumcheck with gate constraint sumcheck
    - Query witness oracle at single point
    - _Requirements: 11.4, 11.9_

- [ ] 53.3 Implement HyperPlonk with BiPerm
    - Commitment ops: |w| (witness weight)
    - Field ops: n
    - Verifier time: log(n)
    - Requires sparse PCS
    - _Requirements: 11.2_

- [ ] 53.4 Implement HyperPlonk with MulPerm
    - Commitment ops: |w|
    - Field ops: n·Õ(√log n)
    - Verifier time: log(n)
    - Works with any PCS
    - _Requirements: 11.3_

- [ ] 53.5 Replace HyperPlonk lookup argument
    - Replace with MulLookup
    - Commit to n elements of log T bit width (not n+T full elements)
    - _Requirements: 11.10_

- [ ] 53.6 Benchmark HyperPlonk improvements
    - Compare to Quarks-style (2n F elements)
    - Compare to HyperPlonk sumcheck (n·Õ(log n))
    - Measure soundness improvement: log²n → log n or log^{1.5}n
    - _Requirements: 11.6, 11.7, 11.8_

- [ ] 54. Implement Spartan/SPARK integration
  - [ ] 54.1 Implement sparse matrix encoding
    - Encode M̃ ∈ {Ã,B̃,C̃} using val(), row(), col(): B^μ → B^s
    - Compute M̃(x,y) := ∑_{j∈B^μ} val̃(j)·1̃_{row}(j,x)·1̃_{col}(j,y)
    - _Requirements: 12.1, 12.2_

- [ ] 54.2 Replace SPARK permutation check
    - Recognize sumcheck as preprocessed lookup argument
    - Apply MulPerm for preprocessed lookup
    - Achieve n·Õ(√log m) field operations
    - _Requirements: 12.3, 12.4, 12.5_

- [ ] 54.3 Implement improved SPARK compiler
    - Remove GKR-based memory checking
    - Use MulPerm lookup instead
    - Reduce soundness error: n/|F| → polylog(n)/|F|
    - Reduce verifier time: O(log²n) → O(log n)
    - Reduce proof size: O(log²n) → O(log n)
    - _Requirements: 12.6, 12.7, 12.8, 12.9_

- [ ] 54.4 Integrate with Spartan and SuperSpartan
    - Combine improved SPARK with Spartan for R1CS
    - Combine with SuperSpartan for CCS
    - Single witness oracle, one or two sumchecks
    - _Requirements: 12.10_

- [ ] 54.5 Implement PCS openings for SPARK
    - Provide val̃, row̃, col̃ evaluations as PCS openings
    - _Requirements: 12.11_

- [ ] 55. Checkpoint - Ensure SNARK integration tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 13: R1CS-Style GKR Protocol

- [ ] 56. Implement R1CS-GKR data structures
  - [ ] 56.1 Define L-layered R1CS GKR circuit
    - Layer i: A^{(i)}z_i ∘ B^{(i)}z_i = z_{i+1}
    - Matrices A^{(i)}, B^{(i)} ∈ F^{|z_{i+1}|×|z_i|}
    - Preprocess MLEs Ã^{(i)}, B̃^{(i)}
    - _Requirements: 13.1, 13.2_

- [ ] 56.2 Implement indexed relation R_{R1CSGKR}
    - Index: (Ã^{(i)}, B̃^{(i)}, [[Ã^{(i)}]], [[B̃^{(i)}]])
    - Instance: [[z̃_i]] for i ∈ [L]
    - Witness: z̃_i for i ∈ [L]
    - _Requirements: 13.1_

- [ ] 57. Implement layer verification
  - [ ] 57.1 Implement layer correctness equation
    - Verify: ∑_{y∈B^{μ_i}} Ã^{(i)}(x,y)·z̃_i(y) · ∑_{y∈B^{μ_i}} B̃^{(i)}(x,y)·z̃_i(y) = z̃_{i+1}(x)
    - For all x ∈ B^{μ_{i+1}}
    - _Requirements: 13.3_

- [ ] 57.2 Implement reduction to sumcheck
    - Reduce to: ∑_{x∈B^{μ_{i+1}}} eq(x,r)[∑_y Ã^{(i)}(x,y)·z̃_i(y)][∑_y B̃^{(i)}(x,y)·z̃_i(y)] = z̃_{i+1}(r)
    - For random challenge r ∈ F^{μ_i}
    - _Requirements: 13.4_

- [ ] 57.3 Implement sumcheck for layer
    - Run sumcheck over x variables
    - Reduce to claims A^{(i)}(r_x,r_y), B^{(i)}(r_x,r_y)
    - _Requirements: 13.5_

- [ ] 58. Implement matrix evaluation using lookup
  - [ ] 58.1 Encode sparse matrix M̃ ∈ {Ã^{(i)}, B̃^{(i)}}
    - Use val(), row(), col() polynomials
    - val(j), row(j), col(j) give j-th nonzero entry
    - M̃(x,y) := ∑_{j∈B^s} val̃(j)·1̃_{row}(j,x)·1̃_{col}(j,y)
    - _Requirements: 13.6_

- [ ] 58.2 Implement matrix evaluation sumcheck
    - Prove M̃(r_x,r_y) := ∑_{j∈B^s} val̃(j)·1̃_{row}(j,r_x)·1̃_{col}(j,r_y)
    - Recognize as preprocessed lookup argument
    - Apply MulPerm for lookup
    - _Requirements: 13.6_

- [ ] 58.3 Optimize matrix evaluation
    - Let q = 2^s be number of nonzero entries
    - Let n = max(2^{μ_i}, 2^{μ_{i+1}})
    - Achieve q·Õ(√log n) field operations
    - _Requirements: 13.7_

- [ ] 59. Implement batching for R1CS-GKR
  - [ ] 59.1 Batch 2L matrix evaluation claims
    - Use random linear combination
    - Reduce to single sumcheck
    - _Requirements: 13.8_

- [ ] 59.2 Implement PCS openings for matrices
    - Provide val̃, row̃, col̃ evaluations as PCS openings
    - _Requirements: 13.11_

- [ ] 60. Implement complete R1CS-GKR protocol
  - [ ] 60.1 Implement R1CS-GKR prover
    - For each layer i ∈ [L-1]:
      - Run sumcheck for layer correctness
      - Prove matrix evaluations using lookup
    - Only commit to witness, not intermediate layers
    - _Requirements: 13.12_

- [ ] 60.2 Implement R1CS-GKR verifier
    - Verify sumcheck for each layer
    - Verify matrix evaluation claims
    - Verify PCS openings
    - _Requirements: 13.5, 13.6_

- [ ] 60.3 Test with example: inner product
    - Model ⟨w,c⟩ = ∑ᵢ cᵢwᵢ as single layer
    - z_{in} = [1,w], A = [0,c]^T, B = [1,0^n]^T
    - Verify correctness
    - _Requirements: 13.11_

- [ ] 60.4 Compare to standard GKR
    - Support non-uniform circuits
    - Support arbitrary fan-in
    - Handle additions for free
    - No tradeoff between fan-in and prover cost
    - _Requirements: 13.9, 13.10_

- [ ] 61. Checkpoint - Ensure R1CS-GKR tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 14: Fiat-Shamir and Non-Interactive Compilation

- [ ] 62. Implement Fiat-Shamir transform
  - [ ] 62.1 Implement transcript management
    - Maintain transcript of all messages
    - Hash transcript to generate challenges
    - Use cryptographic hash (SHA-256, Blake2, etc.)
    - _Requirements: 14.12_

- [ ] 62.2 Implement challenge generation
    - Replace verifier random sampling with hash
    - Hash(transcript || message) → challenge
    - Ensure sufficient entropy
    - _Requirements: 14.12_

- [ ] 62.3 Implement non-interactive prover
    - Compute all messages deterministically
    - Generate challenges from transcript
    - Produce complete proof
    - _Requirements: 14.12_

- [ ] 62.4 Implement non-interactive verifier
    - Recompute challenges from transcript
    - Verify all checks
    - Accept or reject
    - _Requirements: 14.12_

- [ ] 62.5 Verify Fiat-Shamir security
    - Ensure multi-round special soundness
    - Avoid super-constant round protocols
    - Model hash as random oracle
    - _Requirements: 14.13_

- [ ] 63. Implement proof serialization
  - [ ] 63.1 Implement proof encoding
    - Serialize field elements
    - Serialize commitments
    - Serialize openings
    - Compact representation
    - _Requirements: 10.13, 16.16_

- [ ] 63.2 Implement proof decoding
    - Deserialize proof components
    - Validate format
    - Handle errors gracefully
    - _Requirements: 20.9_

- [ ]* 63.3 Write property test for proof size
  - **Property 16: Proof size logarithmic**
  - For any permutation check, verify proof size is O(log n)
  - **Validates: Requirements 10.13**

- [ ] 64. Checkpoint - Ensure Fiat-Shamir tests pass
  - Ensure all tests pass, ask the user if questions arise.


## Phase 15: Soundness Analysis and Security

- [ ] 65. Implement soundness error computation
  - [ ] 65.1 Implement Schwartz-Zippel error
    - Compute μ/|F| for polynomial equality test
    - _Requirements: 14.1_

- [ ] 65.2 Implement sumcheck soundness error
    - Compute dμ/|F| for degree d sumcheck
    - _Requirements: 14.2_

- [ ] 65.3 Implement BiPerm soundness error
    - Combine Schwartz-Zippel + sumcheck
    - Total: O(μ/|F|) = O(log n/|F|)
    - _Requirements: 14.4_

- [ ] 65.4 Implement MulPerm soundness error
    - First sumcheck: (ℓ+1)(μ+log ℓ)/|F|
    - Second sumcheck: (μ/ℓ+1)(μ+log ℓ)/|F|
    - Total: O(μ^{1.5}/|F|) = polylog(n)/|F|
    - _Requirements: 14.5, 14.6, 14.7_

- [ ] 65.5 Implement concrete soundness calculation
    - For n=2^32, |F|=2^128: improve 2^{-96} → 2^{-120}
    - _Requirements: 14.8_

- [ ] 65.6 Implement prover-provided permutation soundness
    - Include binary check soundness
    - Total: O(polylog n/|F|)
    - _Requirements: 14.9_

- [ ] 65.7 Implement lookup soundness error
    - Compute polylog(n+T)/|F|
    - _Requirements: 14.10_

- [ ] 66. Implement parameter selection
  - [ ] 66.1 Implement field size selection
    - For λ-bit security: |F| ≥ 2^{λ + log²n}
    - Example: n=2^32, λ=128 → |F| ≥ 2^{1152}
    - Practical: 256-bit prime for n ≤ 2^32
    - _Requirements: 19.4_

- [ ] 66.2 Implement security level verification
    - Verify field size sufficient for target security
    - Warn if soundness error too large
    - _Requirements: 19.4, 20.9_

- [ ] 67. Implement knowledge soundness
  - [ ] 67.1 Verify extractor properties
    - Ensure extractor can recover polynomial from queries
    - Verify extraction runs in O(|w|) time
    - _Requirements: 14.11_

- [ ] 67.2 Verify witness-extended emulation
    - Ensure PCS has witness-extended emulation
    - Verify compiled protocol is argument of knowledge
    - _Requirements: 14.11_

- [ ] 68. Checkpoint - Ensure soundness analysis complete
  - Ensure all tests pass, ask the user if questions arise.


## Phase 16: Performance Optimization

- [ ] 69. Implement precomputation optimizations
  - [ ] 69.1 Implement equality polynomial caching
    - Cache eq(y,α) evaluations for reuse
    - Precompute for common patterns
    - _Requirements: 15.1_

- [ ] 69.2 Implement lookup tables for small fields
    - Precompute field operations for small fields
    - Use lookup tables for multiplication
    - _Requirements: 15.13_

- [ ] 70. Implement FFT optimizations
  - [ ] 70.1 Optimize FFT for polynomial multiplication
    - Use Cooley-Tukey algorithm
    - Optimize for power-of-2 sizes
    - _Requirements: 15.2_

- [ ] 70.2 Implement in-place FFT
    - Reduce memory allocations
    - Improve cache locality
    - _Requirements: 15.13_

- [ ] 71. Implement table collapsing optimization
  - [ ] 71.1 Optimize evaluation table folding
    - Fold tables in-place after each round
    - Reduce memory usage
    - _Requirements: 15.5_

- [ ] 71.2 Implement lazy evaluation
    - Compute partial products on-demand
    - Avoid unnecessary computations
    - _Requirements: 15.12_

- [ ] 72. Implement parallelization
  - [ ] 72.1 Parallelize sumcheck rounds
    - Parallelize sum over hypercube
    - Use thread pool for work distribution
    - _Requirements: 15.13_

- [ ] 72.2 Parallelize bucketing algorithm
    - Parallelize bucket computation
    - Parallelize partition by identity
    - _Requirements: 15.13_

- [ ] 72.3 Parallelize PCS operations
    - Parallelize multi-scalar multiplications
    - Parallelize hash computations
    - _Requirements: 15.13_

- [ ] 73. Implement SIMD optimizations
  - [ ] 73.1 Vectorize field operations
    - Use SIMD instructions for batch operations
    - Optimize for AVX2/AVX-512
    - _Requirements: 15.13_

- [ ] 73.2 Vectorize polynomial evaluations
    - Batch evaluate multiple points
    - Use SIMD for coefficient operations
    - _Requirements: 15.13_

- [ ] 74. Implement memory layout optimizations
  - [ ] 74.1 Optimize for cache locality
    - Arrange data for sequential access
    - Minimize cache misses
    - _Requirements: 15.13_

- [ ] 74.2 Implement memory pooling
    - Reuse allocations across rounds
    - Reduce allocation overhead
    - _Requirements: 15.13_

- [ ] 75. Benchmark and profile
  - [ ] 75.1 Implement benchmarking suite
    - Benchmark all protocols for various n
    - Measure field operations, time, memory
    - Compare to theoretical bounds
    - _Requirements: 18.13_

- [ ] 75.2 Profile hot paths
    - Identify performance bottlenecks
    - Optimize critical sections
    - _Requirements: 18.13_

- [ ] 76. Checkpoint - Ensure optimizations maintain correctness
  - Ensure all tests pass, ask the user if questions arise.


## Phase 17: Comprehensive Testing

- [ ] 77. Implement unit tests for foundation layer
  - [ ]* 77.1 Test field operations
    - Test field axioms (associativity, commutativity, distributivity)
    - Test identities and inverses
    - Test with various field sizes
    - **Validates: Requirements 1.1, 1.2**

- [ ]* 77.2 Test equality polynomial
  - **Property 1: Equality polynomial correctness**
  - Test eq(x,y) = 1 iff x = y for μ ≤ 10
  - Test formula for random inputs
  - Test evaluate_all_boolean optimization
  - **Validates: Requirements 1.1, 1.2, 18.1**

- [ ]* 77.3 Test multilinear extension
  - **Property 2: MLE correctness**
  - Test f̃(b) = f(b) for all b ∈ B^μ
  - Test multilinearity property
  - Test partial evaluation
  - **Validates: Requirements 1.3, 18.2**

- [ ] 78. Implement unit tests for sumcheck
  - [ ]* 78.1 Test sumcheck protocol
    - **Property 3: Sumcheck round consistency**
    - **Property 17: Sumcheck perfect completeness**
    - Test with various polynomial degrees
    - Test round consistency
    - Test final verification
    - **Validates: Requirements 2.1-2.5, 18.3**

- [ ]* 78.2 Test sumcheck soundness
  - Generate invalid proofs
  - Verify rejection with high probability
  - Measure actual soundness error
  - **Validates: Requirements 18.4**

- [ ] 79. Implement unit tests for permutations
  - [ ]* 79.1 Test permutation representation
    - Test valid permutations accepted
    - Test identity permutation
    - Test cycle permutations
    - Test random permutations
    - **Validates: Requirements 18.4**

- [ ]* 79.2 Test permutation MLE
    - Test σ̃ᵢ(x) ∈ {0,1} for all x ∈ B^μ
    - Test σ̃[μ] interpolation
    - **Validates: Requirements 1.5, 1.6**

- [ ]* 79.3 Test indicator function
    - Test 1σ(x,y) = 1 iff σ(x) = y
    - Test arithmetization strategies
    - **Validates: Requirements 1.7, 1.8**

- [ ] 80. Implement integration tests for BiPerm
  - [ ]* 80.1 Test BiPerm correctness
    - **Property 7: BiPerm correctness**
    - Test with valid permutations
    - Test with invalid permutations
    - Test with various n (2^8, 2^16, 2^20)
    - **Validates: Requirements 4.5, 18.5, 18.6**

- [ ]* 80.2 Test BiPerm performance
    - **Property 6: BiPerm linear time performance**
    - Measure field operations for various n
    - Verify O(n) complexity
    - **Validates: Requirements 4.9, 18.13**

- [ ]* 80.3 Test BiPerm with sparse PCS
    - Test with Dory, KZH, Hyrax
    - Verify linear prover time maintained
    - **Validates: Requirements 4.11**

- [ ] 81. Implement integration tests for MulPerm
  - [ ]* 81.1 Test MulPerm correctness
    - Test with valid permutations
    - Test with invalid permutations
    - Test with various n and ℓ
    - **Validates: Requirements 5.6, 5.9, 18.5, 18.6**

- [ ]* 81.2 Test MulPerm performance
    - **Property 8: MulPerm near-linear time performance**
    - Measure field operations for various n
    - Verify n·Õ(√log n) complexity
    - **Validates: Requirements 5.13, 18.13**

- [ ]* 81.3 Test bucketing algorithm
    - **Property 9: Bucketing algorithm correctness**
    - **Property 10: Bucketing algorithm performance**
    - Verify bucketing equals direct computation
    - Measure performance for various rounds
    - **Validates: Requirements 6.5, 6.12, 18.9**

- [ ]* 81.4 Test algorithm switching
    - Verify switch point k' = log ℓ is optimal
    - Measure costs before and after switch
    - **Validates: Requirements 18.10**

- [ ]* 81.5 Test MulPerm with all PCS
    - Test with KZG, Dory, FRI, Ligero, STIR, WHIR
    - Verify correctness maintained
    - **Validates: Requirements 5.16, 18.12**

- [ ] 82. Implement integration tests for prover-provided permutation
  - [ ]* 82.1 Test inverse check
    - **Property 11: Prover-provided permutation inverse check**
    - Test with valid σ and τ = σ^{-1}
    - Test with non-inverse
    - **Validates: Requirements 7.4, 18.10**

- [ ]* 82.2 Test binary constraint check
    - **Property 12: Binary constraint verification**
    - Test with well-formed permutations
    - Test with non-binary values
    - **Validates: Requirements 7.6, 18.10**

- [ ] 83. Implement integration tests for lookups
  - [ ]* 83.1 Test lookup correctness
    - **Property 13: Lookup argument correctness**
    - Test with valid lookups
    - Test with invalid lookups
    - Test non-injective maps
    - **Validates: Requirements 8.2, 18.11**

- [ ]* 83.2 Test lookup performance
    - **Property 14: Lookup performance for small tables**
    - **Property 15: MulLookup performance**
    - Test with T < n, T = n, T > n
    - Measure field operations
    - **Validates: Requirements 8.7, 8.11, 18.13**

- [ ]* 83.3 Test structured tables
    - Test range proofs
    - Test efficient table evaluation
    - **Validates: Requirements 8.13, 18.11**

- [ ] 84. Implement integration tests for SNARK systems
  - [ ]* 84.1 Test HyperPlonk integration
    - Test permutation check replacement
    - Test lookup argument replacement
    - Verify correctness maintained
    - Measure performance improvements
    - **Validates: Requirements 11.1-11.10, 18.14**

- [ ]* 84.2 Test Spartan/SPARK integration
    - Test SPARK compiler replacement
    - Verify correctness maintained
    - Measure performance improvements
    - **Validates: Requirements 12.1-12.11, 18.14**

- [ ]* 84.3 Test R1CS-GKR protocol
    - Test with various circuit structures
    - Test inner product example
    - Verify correctness
    - **Validates: Requirements 13.1-13.12, 18.14**

- [ ] 85. Implement edge case tests
  - [ ]* 85.1 Test with n = 1, n = 2
    - Verify protocols work for small n
    - **Validates: Requirements 18.15**

- [ ]* 85.2 Test with sparse witnesses
    - Test with low-weight polynomials
    - Verify PCS optimizations work
    - **Validates: Requirements 18.15**

- [ ]* 85.3 Test with structured tables
    - Test range proofs
    - Test other structured tables
    - **Validates: Requirements 18.15**

- [ ] 86. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
