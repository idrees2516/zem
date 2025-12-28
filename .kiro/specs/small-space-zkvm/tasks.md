# Implementation Plan: Small-Space zkVM Prover

## Overview

This implementation plan provides a compact yet comprehensive roadmap for building the small-space zkVM prover with lattice-based integration.

**Total Tasks**: 60 consolidated tasks (300+ implementation details embedded)
**Implementation Order**: Foundation → Core Protocols → Memory Checking → Commitments → Lattice Integration → Testing

---

## Phase 1: Foundation

- [x] 1. Implement field arithmetic module


- [x] 1.1 Implement FieldElement trait

  - Define trait with add, sub, mul, div, neg, inv operations
  - Define zero(), one() constants
  - Define from_u64, to_bytes, from_bytes conversions
  - Ensure Copy + Clone + Debug + Send + Sync bounds
  - _Requirements: 0.1-0.5_
- [x] 1.2 Implement PrimeField structure

  - Store value: BigUint and modulus: BigUint
  - Support fields of size ≥ 2^λ for security parameter λ
  - _Requirements: 0.1-0.3, 0.7_

- [x] 1.3 Implement Montgomery multiplication for PrimeField

  - Convert to Montgomery form: a' = a·R mod p
  - Montgomery reduction: REDC(T) = T·R^(-1) mod p
  - Optimize for 256-bit fields (common in zkSNARKs)
  - _Requirements: 0.1-0.5_


- [x] 1.4 Implement batch field operations

  - Vectorize additions and multiplications when possible
  - Use SIMD instructions where available
  - Batch inversions using Montgomery's trick


  - _Requirements: 0.4-0.5_
- [x] 1.5 Implement BinaryField structure for GF(2^128)

  - Store value: u128
  - Use carry-less multiplication (CLMUL instruction)
  - Implement reduction modulo irreducible polynomial
  - _Requirements: 0.1-0.5_
- [x] 1.6 Implement small-value detection

  - Detect when values fit in u32 (< 2^32)
  - Detect when values fit in u64 (< 2^64)
  - Return SmallValue enum: U32(u32), U64(u64), or Large
  - _Requirements: 2.1, 2.13_

- [x] 1.7 Implement small-value arithmetic optimization

  - Use native u32/u64 multiplication for small values
  - 10-100× faster than full field operations
  - Automatically promote to full field when needed

  - _Requirements: 2.1, 2.13_

- [x] 1.8 Implement binary/integer conversion utilities

  - tobits: {0,...,2^n-1} → {0,1}^n with low-order bit first
  - val: {0,1}^n → {0,...,2^n-1} using Σᵢ 2^(i-1)·bᵢ

  - index_to_bits and bits_to_index helpers
  - _Requirements: 0.6-0.7_
- [x] 1.9 Implement field operation counting

  - Track total field operations performed
  - Separate counters for add, mul, inv operations
  - Use for performance analysis
  - _Requirements: 0.4, 12.7-12.13_

- [x] 2. Implement MLE module



- [x] 2.1 Implement MultilinearExtension structure

  - Store num_vars: usize
  - Store evaluations: Option<Vec<F>> (only when needed)


  - _Requirements: 0.8-0.11_
- [ ] 2.2 Implement MLE evaluation formula
  - f̃(X) = Σ_{x∈{0,1}^n} f(x)·∏ᵢ ((1-Xᵢ)(1-xᵢ) + Xᵢ·xᵢ)
  - Verify f̃(y) = f(y) for all y ∈ {0,1}^n
  - _Requirements: 0.8-0.9_

- [ ] 2.3 Implement standard MLE evaluation
  - Start with evaluations vector of size 2^n
  - For each variable i: halve size using interpolation
  - evals[j] = (1-point[i])·evals[2j] + point[i]·evals[2j+1]
  - Time: O(2^n), Space: O(2^n)

  - _Requirements: 0.8-0.11_
- [ ] 2.4 Implement streaming MLE evaluation
  - Compute result = Σᵢ oracle(i)·eq̃(point, tobits(i))
  - No storage of evaluations vector

  - Time: O(2^n), Space: O(n)
  - _Requirements: 0.8-0.11_
- [x] 2.5 Implement Fact 2.1 interpolation

  - ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
  - Use for efficient partial evaluation
  - _Requirements: 0.11, 17.4_

- [ ] 2.6 Implement partial MLE evaluation


  - Fix first k variables to specific values
  - Return MLE over remaining n-k variables

  - _Requirements: 0.8-0.11_
- [x] 2.7 Implement MLE from vector

  - Given w ∈ F^(2^n), compute w̃
  - Ensure w̃(tobits(i)) = wᵢ for all i
  - _Requirements: 0.10_


- [-] 3. Implement equality function module

- [x] 3.1 Implement EqualityFunction structure

  - Store num_vars: usize
  - _Requirements: 0.12_
- [ ] 3.2 Implement eq̃(X,Y) evaluation
  - eq̃(X,Y) = ∏ᵢ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)

  - Equals 1 if X=Y, 0 otherwise
  - _Requirements: 0.12, 1.5, 1.9_
- [ ] 3.3 Implement eq̃ precomputation table
  - Precompute all eq̃(r, y) for y ∈ {0,1}^n

  - Store in vector of size 2^n
  - Time: O(2^n), Space: O(2^n)
  - _Requirements: 0.12_
- [x] 3.4 Implement efficient streaming (depth-first traversal)

  - Use binary tree traversal from [CFFZE24, Rot24]
  - Stream in lexicographic order
  - Time: O(2^n), Space: O(n)

  - _Requirements: 0.12, 17.17_
- [ ] 3.5 Implement recursive streaming helper
  - stream_recursive(r, depth, current_val, callback)
  - Left child: current_val * (1 - r[depth])
  - Right child: current_val * r[depth]
  - _Requirements: 0.12, 17.17_
- [ ] 3.6 Implement eq̃ at index computation
  - Given index i and point r, compute eq̃(r, tobits(i))
  - Convert i to bits, multiply terms
  - Time: O(n), Space: O(1)
  - _Requirements: 0.12_

- [ ] 4. Implement univariate polynomial module
- [ ] 4.1 Implement UnivariatePolynomial structure
  - Store coefficients: Vec<F>
  - Support polynomials of degree ℓ (typically ≤ 3 for sum-check)
  - _Requirements: 1.2, 1.14_
- [ ] 4.2 Implement Lagrange interpolation
  - Given points (x₀,y₀),...,(xₙ,yₙ), find unique polynomial
  - Use Lagrange basis: Lᵢ(x) = ∏_{j≠i} (x-xⱼ)/(xᵢ-xⱼ)
  - p(x) = Σᵢ yᵢ·Lᵢ(x)
  - _Requirements: 1.2, 1.14_
- [ ] 4.3 Implement efficient interpolation for small degree
  - For degree 2 (sum-check): use closed-form formulas

  - Avoid general Lagrange for performance
  - _Requirements: 1.2, 1.14_
- [ ] 4.4 Implement Horner's method for evaluation
  - Evaluate p(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ
  - Use Horner: p(x) = a₀ + x(a₁ + x(a₂ + ... + x·aₙ))
  - Time: O(n), Space: O(1)

  - _Requirements: 1.2, 1.14_
- [ ] 4.5 Implement polynomial degree computation
  - Return degree (highest non-zero coefficient)
  - Handle zero polynomial (degree -1 or 0 by convention)
  - _Requirements: 1.2_
- [ ] 4.6 Implement polynomial arithmetic
  - Addition, subtraction, multiplication
  - Scalar multiplication
  - _Requirements: 1.2_

- [ ] 5. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 2: Sum-Check Protocol

- [x] 6. Implement standard sum-check prover




- [ ] 6.1 Implement PolynomialOracle trait
  - Define trait with query, num_polynomials, num_variables methods

  - _Requirements: 1.7, 17.1_
- [ ] 6.2 Implement linear-time sum-check prover structure
  - Create SumCheckProver struct with num_vars, num_polys, evaluation_points

  - Implement prove method signature
  - _Requirements: 1.1-1.5, 1.15_
- [x] 6.3 Implement round computation for linear-time algorithm

  - Implement nested loops over m and j
  - Compute f_i(α_s) for each evaluation point
  - _Requirements: 1.2, 1.14, 17.1_

- [ ] 6.4 Implement array update logic (Equation 4)
  - Update A_k arrays between rounds: A_k[m] = (1-r_{i-1})·A_k[2m] + r_{i-1}·A_k[2m+1]

  - Implement halving of array size each round

  - _Requirements: 1.1-1.5, 17.8_
- [ ] 6.5 Implement polynomial interpolation from evaluations
  - Use evaluation points to construct univariate polynomial

  - _Requirements: 1.2, 1.14_

- [x] 7. Implement small-space sum-check prover (Algorithm 1)

- [ ] 7.1 Implement Algorithm 1 main loop structure
  - Outer loop over rounds i ∈ {1,...,n}
  - Initialize accumulator array of size O(ℓ)

  - _Requirements: 1.1-1.16, 17.1_
- [ ] 7.2 Implement witness_eval array management
  - Create witness_eval[k][s] array of size O(ℓ²)

  - Initialize to zero at start of each m iteration
  - _Requirements: 1.1-1.16, 17.2_
- [x] 7.3 Implement index computation (u_even, u_odd)

  - Compute u_even = 2^i·2m + j with binary representation (j, 0, tobits(m))
  - Compute u_odd = 2^i·(2m+1) + j with binary representation (j, 1, tobits(m))
  - _Requirements: 1.10-1.11, 17.3_

- [ ] 7.4 Implement oracle querying for even/odd indices
  - Query all ℓ polynomials at u_even
  - Query all ℓ polynomials at u_odd

  - _Requirements: 1.7, 1.10-1.11_
- [ ] 7.5 Implement eq̃ evaluation for challenges
  - Compute eq̃((r₁,...,r_{i-1}), tobits(j))
  - Use formula: ∏ᵢ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
  - _Requirements: 1.5, 1.9, 1.12_
- [ ] 7.6 Implement witness_eval update logic
  - For each k and s: witness_eval[k][s] += eq̃(...)·((1-αₛ)·A_k[u_even] + αₛ·A_k[u_odd])
  - Use Fact 2.1 for interpolation

  - _Requirements: 1.12, 1.14, 17.4_

- [ ] 7.7 Implement accumulator update with products
  - Compute ∏_{k=1}^ℓ witness_eval[k][s] for each s
  - Add to accumulator[s]

  - _Requirements: 1.13, 1.14_
- [ ] 7.8 Implement round polynomial construction
  - Interpolate polynomial from accumulator values

  - Sample verifier challenge
  - _Requirements: 1.2, 1.14_
- [x]* 7.9 Write property test for Algorithm 1

  - **Property 1: Algorithm 1 Produces Identical Proofs**
  - Generate random polynomials and compare outputs
  - Verify space usage is O(n + ℓ²)

  - **Validates: Requirements 1.1-1.16, 11.1**

- [x] 8. Implement small-value sum-check optimization

- [ ] 8.1 Implement array C initialization and maintenance
  - Initialize C[j] = A₁[j]·A₂[j] for all j ∈ {0,...,2^n-1}
  - Compute on-the-fly by querying oracles (space O(2^i) at round i)

  - _Requirements: 2.2, 2.9, 17.9_
- [ ] 8.2 Implement array E computation
  - Store {eq̃(r_{i-1},y₁)·eq̃(r_{i-1},y₂)}_{y₁,y₂∈{0,1}^i}
  - Size O(2^(2i)) at round i
  - _Requirements: 2.3, 2.10, 17.9_
- [ ] 8.3 Implement f_i(0) and f_i(1) computation
  - For round 1: f₁(0) = Σ C[2·i], f₁(1) = Σ C[2·i+1]
  - For round i>1: use formula with eq̃ products

  - _Requirements: 2.4, 2.6_

- [ ] 8.4 Implement f_i(2) computation
  - For round 1: use formula with 4·C[2·i+1] - 2(...) + C[2·i]
  - For round i>1: use full formula with g₁(y₁,s,x)·g₂(y₂,s,x)

  - _Requirements: 2.5, 2.7_
- [ ] 8.5 Implement crossover detection logic
  - Compute crossover_round where 2^(2i) exceeds threshold

  - Typically around n/2 or when E array becomes too large
  - _Requirements: 2.8, 2.14_
- [x] 8.6 Implement switching to linear-time algorithm

  - After crossover, use standard algorithm with halving space
  - Seamless transition with no correctness impact


  - _Requirements: 2.5, 2.8, 11.5_
- [ ] 8.7 Implement small-field arithmetic optimization
  - Detect when values fit in machine words (u32/u64)
  - Use native multiplication instead of full field operations
  - _Requirements: 2.1, 2.13_
- [ ]* 8.8 Write property test for small-value optimization
  - **Property 3: Small-Value Optimization Equivalence**
  - Test with values in B={0,1,...,2³²-1}
  - Verify identical results to standard algorithm
  - **Validates: Requirements 2.1-2.14, 11.4**


- [ ] 9. Implement sum-check verifier
- [ ] 9.1 Implement round 1 verification
  - Check v = f₁(0) + f₁(1)
  - Sample challenge r₁
  - _Requirements: 1.3_
- [ ] 9.2 Implement rounds 2..n-1 verification
  - Check fᵢ(rᵢ) = fᵢ₋₁(0) + fᵢ₋₁(1)
  - Sample challenge rᵢ
  - _Requirements: 1.4_
- [ ] 9.3 Implement final round verification
  - Compute g(r₁,...,rₙ) = ∏_{k=1}^ℓ gₖ(r₁,...,rₙ)
  - Check g(r₁,...,rₙ) = fₙ(rₙ)
  - _Requirements: 1.5, 1.15_
- [ ] 9.4 Implement soundness error tracking
  - Track error bound ℓ·n/|F|
  - _Requirements: 1.15, 11.8_

- [ ] 10. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 3: Streaming Witness Generation

- [-] 11. Implement RISC-V VM executor

- [x] 11.1 Implement VM state structure

  - Create RiscVVM struct with registers[32], pc, memory HashMap
  - Add cycle_count tracker
  - _Requirements: 3.1-3.2_

- [ ] 11.2 Implement instruction fetch
  - Read 4 bytes from memory at PC
  - Handle memory access errors

  - _Requirements: 3.1-3.2, 3.8_
- [ ] 11.3 Implement instruction decoder
  - Decode opcode, rd, rs1, rs2, immediate fields

  - Support RV32I base instruction set
  - _Requirements: 3.1-3.2, 3.8_
- [x] 11.4 Implement ALU operations

  - ADD, SUB, AND, OR, XOR, SLL, SRL, SRA
  - SLT, SLTU for comparisons
  - _Requirements: 3.1-3.2, 3.8_
- [x] 11.5 Implement memory operations

  - LOAD (LB, LH, LW, LBU, LHU)
  - STORE (SB, SH, SW)
  - Track memory reads/writes for witness

  - _Requirements: 3.1-3.2, 3.8_
- [ ] 11.6 Implement branch operations
  - BEQ, BNE, BLT, BGE, BLTU, BGEU

  - Update PC based on branch condition
  - _Requirements: 3.1-3.2, 3.8_
- [ ] 11.7 Implement jump operations
  - JAL, JALR
  - Store return address in rd

  - _Requirements: 3.1-3.2, 3.8_
- [ ] 11.8 Implement WitnessSlice structure
  - Store register reads/writes

  - Store memory reads/writes
  - Store ALU operations
  - Store PC and next_PC
  - _Requirements: 3.1-3.2, 3.6-3.8_
- [x] 11.9 Implement witness slice generation during execution

  - Generate slice in O(1) time per cycle
  - Require O(1) space beyond K words for VM
  - _Requirements: 3.2, 3.8_
- [ ] 11.10 Implement witness vector interleaving
  - Interleave k vectors w₁,...,wₖ as w = {wᵢ,ⱼ}

  - j-th slice consists of positions (j·k,...,(j+1)·k-1)
  - _Requirements: 3.6-3.7_


- [ ] 12. Implement checkpointing system
- [ ] 12.1 Implement VMCheckpoint structure
  - Store cycle number

  - Store registers[32] snapshot
  - Store PC value
  - Store memory HashMap snapshot
  - _Requirements: 3.3, 3.9, 17.5_

- [ ] 12.2 Implement checkpoint interval calculation
  - Compute interval as T/M for M threads
  - Estimate total cycles T from program
  - _Requirements: 3.3, 3.9, 17.5_
- [x] 12.3 Implement checkpoint storage during execution

  - Check if cycle_count % checkpoint_interval == 0
  - Clone VM state and store in checkpoints vector
  - _Requirements: 3.3, 3.9, 17.5_
- [x] 12.4 Implement checkpoint restoration

  - Find nearest checkpoint before target cycle
  - Restore registers, PC, memory from checkpoint
  - Resume execution from checkpoint
  - _Requirements: 3.3, 3.9_

- [ ] 12.5 Implement checkpoint validation
  - Verify checkpoint integrity
  - Handle corrupted checkpoints
  - _Requirements: 3.3, 3.9_


- [ ] 13. Implement streaming witness generator
- [ ] 13.1 Implement StreamingWitnessGenerator structure
  - Store reference to VM

  - Track current_cycle and total_cycles
  - Optional witness_cache for performance
  - _Requirements: 3.1-3.5_
- [x] 13.2 Implement witness value retrieval


  - Map index to (cycle, offset) pair
  - Regenerate from checkpoint if needed
  - Execute cycles until target reached
  - _Requirements: 3.1-3.5_
- [ ] 13.3 Implement regeneration from checkpoint
  - Find nearest checkpoint before target
  - Restore VM state
  - Execute forward to target cycle
  - _Requirements: 3.3, 3.9_
- [ ] 13.4 Implement parallel regeneration
  - Divide witness into M chunks for M threads
  - Each thread regenerates from its checkpoint
  - Use rayon or similar for parallelism
  - _Requirements: 3.4, 3.10_
- [ ] 13.5 Implement PolynomialOracle trait for witness
  - Implement query(poly_index, index) method
  - Map to witness vector position
  - Implement num_polynomials() and num_variables()
  - _Requirements: 3.1-3.5_
- [ ] 13.6 Implement performance tracking
  - Track witness generation time
  - Verify < 5% of total prover time for single execution
  - Verify < 15% overhead for 40 regenerations with 16 threads
  - _Requirements: 3.5, 12.4-12.5_
- [ ]* 13.7 Write property test for witness regeneration
  - **Property 2: Witness Regeneration Consistency**
  - Generate random programs and execute
  - Regenerate from checkpoints and compare
  - Verify identical witness vectors
  - **Validates: Requirements 3.1-3.10, 11.2**

- [ ] 14. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 4: Spartan for Uniform R1CS

- [ ] 15. Implement R1CS structure module
- [ ] 15.1 Implement SparseRow structure
  - Store indices and values vectors
  - Implement efficient sparse row operations
  - _Requirements: 4.1-4.2, 4.4_
- [ ] 15.2 Implement ConstraintBlock structure
  - Store a_block, b_block, c_block as Vec<SparseRow>
  - Each block has β constraints over O(1) variables
  - _Requirements: 4.1-4.2, 4.4_
- [ ] 15.3 Implement UniformR1CS structure
  - Store num_constraints_per_cycle (β)
  - Store num_cycles (T)
  - Store constraint_block (constant-sized blocks)
  - _Requirements: 4.1-4.2_
- [ ] 15.4 Implement matrix MLE evaluation
  - Evaluate Ã(Y,x), B̃(Y,x), C̃(Y,x) at point Y
  - Use block-diagonal structure for O(log T) time
  - _Requirements: 4.3, 4.10_
- [ ] 15.5 Implement streaming matrix-vector product
  - Stream Az, Bz, Cz while executing VM
  - Compute block-by-block without storing full result
  - _Requirements: 4.3-4.4_
- [ ] 15.6 Implement h̃_A evaluation
  - Compute h̃_A(Y) = Σ_x Ã(Y,x)·ũ(x)
  - Stream through witness on-demand
  - _Requirements: 4.3, 4.5_
- [ ] 15.7 Implement h̃_B and h̃_C evaluation
  - Similar to h̃_A but for B and C matrices
  - Use same streaming approach
  - _Requirements: 4.3, 4.5_
- [ ]* 15.8 Write property test for block-diagonal streaming
  - **Property 7: Spartan Block-Diagonal Streaming**
  - Generate random block-diagonal matrices
  - Verify streaming produces correct matrix-vector products
  - **Validates: Requirements 4.1-4.13**

- [ ] 16. Implement Spartan prover
- [ ] 16.1 Implement SpartanProver structure
  - Store reference to UniformR1CS
  - Store configuration parameters
  - _Requirements: 4.1-4.13_
- [ ] 16.2 Implement first sum-check oracle
  - Create oracle for g(y) = eq̃(r_s, y)·(h̃_A(y)·h̃_B(y) - h̃_C(y))
  - Implement query method that computes h̃ values on-demand
  - _Requirements: 4.5, 4.8_
- [ ] 16.3 Implement first sum-check execution
  - Prove q(S) = Σ_y eq̃(S,y)·(h̃_A(y)·h̃_B(y) - h̃_C(y)) = 0
  - Use small-value sum-check optimization
  - Extract challenges r_y
  - _Requirements: 4.5, 4.8, 4.11-4.13_
- [ ] 16.4 Implement second sum-check oracle
  - Create oracle for random linear combination:
  - α·Ã(r_y,x)·ũ(x) + β·B̃(r_y,x)·ũ(x) + C̃(r_y,x)·ũ(x)
  - _Requirements: 4.5, 4.9-4.10_
- [ ] 16.5 Implement second sum-check execution
  - Prove h̃_A(r_y), h̃_B(r_y), h̃_C(r_y) evaluations
  - Use random linear combination for batching
  - Extract challenges r_x
  - _Requirements: 4.5, 4.9-4.10_
- [ ] 16.6 Implement final evaluation computation
  - Compute Ã(r_y, r_x), B̃(r_y, r_x), C̃(r_y, r_x)
  - Use block-diagonal structure for O(log T) time
  - Compute ũ(r_x) from witness
  - _Requirements: 4.5, 4.10_
- [ ] 16.7 Implement small-value optimization for Spartan
  - Detect that h_A, h_B, h_C values are in {0,1,...,2^64-1}
  - Use machine-word arithmetic for first rounds
  - _Requirements: 4.11-4.13_
- [ ] 16.8 Track Spartan performance
  - Verify ~250T field operations in linear space
  - Verify ~40T additional operations in small space
  - _Requirements: 4.12-4.13, 10.4_

- [ ] 17. Implement pcnext virtual polynomial
- [ ] 17.1 Implement ShiftFunction structure
  - Store num_vars (log T)
  - _Requirements: 4.6-4.7_
- [ ] 17.2 Implement h(r,j) computation
  - h(r,j) = (1-j₁)r₁·eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
  - Return zero if j₁ = 1
  - _Requirements: 4.7, 17.14_
- [ ] 17.3 Implement g(r,j) computation
  - g(r,j) = Σ_{k=1}^{log(T)-1} (∏ᵢ₌₁ᵏ jᵢ·(1-rᵢ))·(1-j_{k+1})r_{k+1}·eq̃(...)
  - Check first k bits are all 1 and (k+1)-th bit is 0
  - _Requirements: 4.7, 17.14_
- [ ] 17.4 Implement shift(r,j) evaluation
  - Combine h(r,j) + g(r,j)
  - Evaluate in O(log T) time and O(1) space
  - _Requirements: 4.6-4.7_
- [ ] 17.5 Implement streaming shift evaluations
  - Use depth-first traversal for h evaluations
  - Use depth-first traversal for g evaluations
  - Achieve O(T) time, O(log T) space
  - _Requirements: 4.7, 17.14, 17.18_
- [ ] 17.6 Implement pcnext oracle
  - Create oracle for p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
  - Use prefix-suffix structure (will be implemented in Phase 7)
  - _Requirements: 4.6-4.7_
- [ ] 17.7 Implement pcnext-evaluation sum-check
  - Apply sum-check with prefix-suffix protocol
  - Verify pcnext = shift * pc
  - _Requirements: 4.6-4.7_

- [ ] 18. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 5: Shout Protocol (Read-Only Memory)

- [ ] 19. Implement Shout prover module
- [ ] 19.1 Implement ShoutProver structure
  - Store memory_size (K), num_reads (T), dimension (d)
  - _Requirements: 5.1-5.2_
- [ ] 19.2 Implement AddressOracle trait
  - Define methods: get_address(j), get_address_bit(j, k), memory_size()
  - Support one-hot encoding queries
  - _Requirements: 5.1-5.2_
- [ ] 19.3 Implement MemoryOracle trait
  - Define method: get_memory_value(k)
  - Support M̃(k) evaluation in O(log K) time
  - _Requirements: 5.3, 5.7_
- [ ] 19.4 Implement one-hot address commitment
  - Commit to r̃a: multilinear extension of read addresses
  - Length T·K with one-hot encoding (unit vectors eₖ)
  - _Requirements: 5.1-5.2_
- [ ] 19.5 Implement dimension parameter selection
  - For elliptic curves: choose d to keep key < 10 GB
  - For hash-based: choose d to keep commit time reasonable
  - Compute key size as 2√(K^(1/d)·T) group elements
  - _Requirements: 5.5-5.6, 5.13, 17.13_
- [ ] 19.6 Implement read-checking sum-check oracle
  - Create oracle for r̃v(r) = Σ_{(k,j)} eq̃(r,j)·r̃a(k,j)·M̃(k)
  - Support dimension parameter d: replace r̃a(k,j) with ∏ᵢ r̃aᵢ(kᵢ,j)
  - _Requirements: 5.3, 5.5_
- [ ] 19.7 Implement read-checking sum-check (linear-time version)
  - Two phases: first log K rounds, then final log T rounds
  - Use Phase1DataStructure for first phase
  - Use prefix-suffix protocol for second phase
  - _Requirements: 5.3, 5.8-5.10_
- [ ] 19.8 Implement read-checking sum-check (sublinear version)
  - Use sparse-dense sum-check or prefix-suffix protocol
  - Achieve O(CK^(1/C) + CT) time with C passes
  - Space O(K^(1/C))
  - _Requirements: 5.10_
- [ ] 19.9 Implement Booleanity-checking oracle
  - Create oracle for Σ_{(k,j)} r̃a(k,j)·(1 - r̃a(k,j))
  - Verify all entries in {0,1}
  - _Requirements: 5.4, 5.11_
- [ ] 19.10 Implement Booleanity-checking sum-check
  - Prove sum equals 0
  - Use small-space sum-check prover
  - _Requirements: 5.4, 5.11_
- [ ] 19.11 Implement Hamming-weight-one oracle
  - Create oracle for Σ_k r̃a(k,j) for each j
  - Verify each address has exactly one 1
  - _Requirements: 5.4, 5.12_
- [ ] 19.12 Implement Hamming-weight-one sum-check
  - Prove sum equals T (one 1 per read)
  - Use small-space sum-check prover
  - _Requirements: 5.4, 5.12_
- [ ] 19.13 Track Shout performance
  - Verify ~40T field operations for instruction execution (linear)
  - Verify ~2T log T additional operations (small-space)
  - Verify ~5T operations for bytecode lookups
  - _Requirements: 5.14-5.16, 10.5_
- [ ]* 19.14 Write property test for Shout one-hot verification
  - **Property 8: Shout One-Hot Verification**
  - Generate random read addresses
  - Verify all addresses are unit vectors
  - Verify correct return values
  - **Validates: Requirements 5.1-5.16**

- [ ] 20. Implement Phase1DataStructure for first log K rounds
- [ ] 20.1 Implement Phase1DataStructure structure
  - Store table: Vec<F> of size O(K)
  - _Requirements: 5.8_
- [ ] 20.2 Implement initialization with single pass
  - Make one pass over T read addresses
  - For each read to address k, increment table[k]
  - Time O(T), space O(K)
  - _Requirements: 5.8_
- [ ] 20.3 Implement round computation
  - Compute round polynomial from table
  - Time O(K) per round
  - _Requirements: 5.8_
- [ ] 20.4 Implement update for next round
  - Halve table size using challenge
  - table[i] = table[2i]·(1-r) + table[2i+1]·r
  - _Requirements: 5.8_
- [ ] 20.5 Complete first log K rounds
  - After log K rounds, table size is O(1)
  - Extract r* for second phase
  - _Requirements: 5.8-5.9_

- [ ] 21. Implement sparse-dense sum-check for final log T rounds
- [ ] 21.1 Implement sparse-dense oracle
  - For final log T rounds: Σ_j eq̃(r,j)·r̃a(r*,j)·M̃(r*)
  - r* is fixed from first phase
  - _Requirements: 5.9-5.10_
- [ ] 21.2 Implement C-pass algorithm
  - Make C passes over read addresses
  - Each pass covers log(T)/C rounds
  - _Requirements: 5.10_
- [ ] 21.3 Implement space-efficient data structures
  - Maintain O(K^(1/C) + T^(1/C)) space
  - Build Q and P arrays for each stage
  - _Requirements: 5.10_
- [ ] 21.4 Optimize for sparsity
  - If u has sparsity m, perform O(C·k·m) field multiplications
  - Leverage sparse structure of read addresses
  - _Requirements: 5.10_

- [ ] 22. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 6: Twist Protocol (Read/Write Memory)

- [ ] 23. Implement Twist prover module
- [ ] 23.1 Implement TwistProver structure
  - Store memory_size (K), num_operations (T), dimension (d)
  - _Requirements: 6.1, 6.6_
- [ ] 23.2 Implement MemoryOperationOracle trait
  - Define methods: get_read_address(j), get_write_address(j), get_write_value(j)
  - Support querying read/write operations
  - _Requirements: 6.1_
- [ ] 23.3 Implement increment vector computation
  - For each j: Ĩnc(j) = w̃v(j) - (value at cell at time j)
  - Track memory state with HashMap<address, (timestamp, value)>
  - Find previous value: largest j' < j with w̃a(j') = w̃a(j), or 0
  - _Requirements: 6.2_
- [ ] 23.4 Implement increment vector commitment
  - Commit to Ĩnc vector
  - Store commitment for verification
  - _Requirements: 6.2_
- [ ] 23.5 Implement read-checking oracle
  - Create oracle for Σ_{(k,j)} eq̃(r,j)·r̃a(k,j)·M̃(k,j)
  - M̃(k,j) is memory state at time j
  - _Requirements: 6.3_
- [ ] 23.6 Implement read-checking sum-check
  - Two phases: first log K rounds (O(K) space, O(T) time per round)
  - Final log T rounds (use small-space algorithm)
  - Total: O(T log T) time, O(K + log T) space
  - _Requirements: 6.3, 6.8-6.9_
- [ ] 23.7 Implement write-checking oracle
  - Create oracle for Σ_{(k,j)} eq̃(r,j)·eq̃(r',k)·w̃a(k,j)·(w̃v(j) - M̃(k,j))
  - Should equal 0 for consistent writes
  - _Requirements: 6.4_
- [ ] 23.8 Implement write-checking sum-check
  - Similar two-phase structure as read-checking
  - Verify sum equals 0
  - _Requirements: 6.4, 6.8-6.9_
- [ ] 23.9 Implement M̃-evaluation oracle
  - Create oracle for M̃(r,r') = Σ_j Ĩnc(r,j)·L̃T(r',j)
  - Use prefix-suffix structure for L̃T
  - _Requirements: 6.5_
- [ ] 23.10 Implement M̃-evaluation sum-check
  - Apply sum-check with prefix-suffix protocol
  - Compute M̃ at random point (r,r')
  - _Requirements: 6.5_
- [ ] 23.11 Implement dimension parameter d optimization
  - Choose d based on commitment scheme
  - Achieve O(K^(1/d)·T^(1/2)) space
  - _Requirements: 6.6, 6.13, 17.13_
- [ ] 23.12 Track Twist performance
  - Verify ~35T operations for registers (linear)
  - Verify ~4T log T additional operations (small-space)
  - Verify ~150T operations for RAM worst-case (linear)
  - _Requirements: 6.10-6.13, 10.6-10.7_
- [ ]* 23.13 Write property test for Twist increment tracking
  - **Property 9: Twist Increment Tracking**
  - Generate random read/write sequences
  - Verify Ĩnc(j) = w̃v(j) - (previous value)
  - Verify memory consistency
  - **Validates: Requirements 6.1-6.14**

- [ ] 24. Implement less-than function module
- [ ] 24.1 Implement LessThanFunction structure
  - Store num_vars (log T)
  - _Requirements: 6.5, 6.14_
- [ ] 24.2 Implement L̃T(r',j) evaluation
  - LT(j,j') = 1 if val(j) < val(j'), else 0
  - Compute MLE using formula from requirements
  - _Requirements: 6.5, 6.14_
- [ ] 24.3 Implement L̃T decomposition
  - L̃T(r',j) = L̃T(r'₁,j₁) + L̃T(r'₂,j₂)
  - Split into two halves for efficiency
  - _Requirements: 6.14_
- [ ] 24.4 Implement L̃T(r'₁,j₁) computation
  - L̃T(r'₁,j₁) = (1-j₁)r'₁·eq̃(j₂,...,j_{log T/2}, r'₂,...,r'_{log T/2})
  - Return 0 if j₁ = 1
  - _Requirements: 6.14_
- [ ] 24.5 Implement prefix-suffix structure for L̃T
  - prefix₁(j₁) = L̃T(r'₁,j₁)
  - suffix₁(j₂) = eq̃(r'₂,j₂)
  - prefix₂(j₁) = 1
  - suffix₂(j₂) = L̃T(r'₂,j₂)
  - _Requirements: 6.5, 6.14, 7.15_
- [ ] 24.6 Implement streaming L̃T evaluations
  - Compute all L̃T(r',j) for j ∈ {0,1}^(log T) in O(√T) time
  - Use O(√T) space
  - _Requirements: 6.5, 6.14, 7.17_

- [ ] 25. Implement i-local memory access optimization
- [ ] 25.1 Implement locality tracking
  - Track last_access HashMap<address, timestamp>
  - For each access, compute distance = current_time - last_access
  - Locality factor i = log₂(distance)
  - _Requirements: 6.7_
- [ ] 25.2 Implement locality-aware field operation counting
  - For i-local access: pay O(i) field operations
  - Instead of O(log K) for general access
  - _Requirements: 6.7_
- [ ] 25.3 Implement locality statistics
  - Track distribution of locality factors
  - Estimate total field operations based on locality
  - _Requirements: 6.7_
- [ ] 25.4 Optimize for common access patterns
  - Registers: typically 0-local or 1-local
  - Stack: typically 0-local to 3-local
  - Heap: varies, but often exhibits locality
  - _Requirements: 6.7_

- [ ] 26. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 7: Prefix-Suffix Inner Product Protocol

- [ ] 27. Implement prefix-suffix prover module
- [ ] 27.1 Implement PrefixSuffixStructure trait
  - Define evaluate_prefix(stage, prev_challenges, y) method
  - Define evaluate_suffix(stage, x_idx) method
  - _Requirements: 7.1-7.2_
- [ ] 27.2 Implement PrefixSuffixProver structure
  - Store num_vars (log N), num_stages (C), num_terms (k)
  - _Requirements: 7.1-7.3_
- [ ] 27.3 Implement prefix-suffix structure validation
  - Verify ã(x) = Σⱼ prefixⱼ(x₁,...,xᵢ)·suffixⱼ(xᵢ₊₁,...,x_{log N})
  - Check cutoffs at i = log(N)/C, 2·log(N)/C, ..., (C-1)·log(N)/C
  - _Requirements: 7.2-7.3_
- [ ] 27.4 Implement stage-based proving structure
  - C stages, each covering log(N)/C rounds
  - Each stage runs sum-check on P̃(y)·Q̃(y)
  - _Requirements: 7.3, 7.5_
- [ ] 27.5 Implement Q array building for stage 1
  - Q[y] = Σ_{x: x₁=y} ũ(x)·suffix(x₂,...,x_C)
  - Single pass over u and a
  - Size O(N^(1/C))
  - _Requirements: 7.6, 7.9_
- [ ] 27.6 Implement P array building for stage 1
  - P[y] = prefix(y) for y ∈ {0,1}^(log(N)/C)
  - Size O(N^(1/C))
  - _Requirements: 7.7, 7.10_
- [ ] 27.7 Implement Q array building for stage j > 1
  - Q[y] = Σ_{x=(x₃,...,x_C)} ũ(r,y,x)·suffix(x)
  - r is challenges from previous stages
  - _Requirements: 7.9, 7.12_
- [ ] 27.8 Implement P array building for stage j > 1
  - P[y] = prefix(r,y) for y ∈ {0,1}^(log(N)/C)
  - r is challenges from previous stages
  - _Requirements: 7.10, 7.12_
- [ ] 27.9 Implement stage round computation
  - Run standard linear-time sum-check on P̃(y)·Q̃(y)
  - log(N)/C rounds per stage
  - _Requirements: 7.8, 7.11_
- [ ] 27.10 Implement ũ evaluation with sparsity optimization
  - If u has sparsity m, compute ũ(r,y,x) in O(j·N^(1/C) + m) time
  - Leverage sparse structure
  - _Requirements: 7.4, 7.13_
- [ ] 27.11 Implement space management
  - Total space: O(k·C·N^(1/C))
  - For C=2, k=2: O(4·√N) = O(√N)
  - _Requirements: 7.3, 7.11_
- [ ] 27.12 Implement time complexity tracking
  - Aside from initialization: O(C·N^(1/C)) time per stage
  - Total: O(C·k·m) field multiplications for sparsity m
  - _Requirements: 7.4, 7.11_
- [ ]* 27.13 Write property test for prefix-suffix correctness
  - **Property 4: Prefix-Suffix Inner Product Correctness**
  - Generate random vectors with prefix-suffix structure
  - Compare prefix-suffix protocol output to standard sum-check
  - Verify identical results
  - **Validates: Requirements 7.1-7.17, 11.3**

- [ ] 28. Implement pcnext-evaluation with prefix-suffix
- [ ] 28.1 Implement ShiftPrefixSuffixStructure
  - Store r: Vec<F> (random point)
  - Store shift_fn: ShiftFunction
  - _Requirements: 7.14_
- [ ] 28.2 Implement prefix evaluation for shift (stage 0)
  - prefix₁(j₁) = shift(r₁,j₁)
  - Evaluate shift function on first half of variables
  - _Requirements: 7.14_
- [ ] 28.3 Implement suffix evaluation for shift (stage 0)
  - suffix₁(j₂) = eq̃(r₂,j₂)
  - Evaluate equality function on second half
  - _Requirements: 7.14_
- [ ] 28.4 Implement prefix evaluation for shift (stage 1)
  - prefix₂(j₁) = ∏_{ℓ=1}^{log(T)/2} (1-r_ℓ)·j_{1,ℓ}
  - Return 0 if any j_{1,ℓ} = 0
  - _Requirements: 7.14_
- [ ] 28.5 Implement suffix evaluation for shift (stage 1)
  - suffix₂(j₂) = shift(r₂,j₂)
  - Evaluate shift function on second half
  - _Requirements: 7.14_
- [ ] 28.6 Implement pcnext oracle using prefix-suffix
  - Combine shift structure with pc values
  - Compute p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
  - _Requirements: 7.14, 17.14_
- [ ] 28.7 Compute eq̃(r₂,j₂) for all j₂ efficiently
  - Use standard techniques to compute in O(√T) time and space
  - _Requirements: 7.16_

- [ ] 29. Implement M̃-evaluation with prefix-suffix
- [ ] 29.1 Implement LessThanPrefixSuffixStructure
  - Store r_prime: Vec<F> (random point)
  - Store lt_fn: LessThanFunction
  - _Requirements: 7.15_
- [ ] 29.2 Implement prefix evaluation for LT (stage 0)
  - prefix₁(j₁) = L̃T(r'₁,j₁)
  - Evaluate less-than function on first half
  - _Requirements: 7.15_
- [ ] 29.3 Implement suffix evaluation for LT (stage 0)
  - suffix₁(j₂) = eq̃(r'₂,j₂)
  - Evaluate equality function on second half
  - _Requirements: 7.15_
- [ ] 29.4 Implement prefix evaluation for LT (stage 1)
  - prefix₂(j₁) = 1
  - Constant function
  - _Requirements: 7.15_
- [ ] 29.5 Implement suffix evaluation for LT (stage 1)
  - suffix₂(j₂) = L̃T(r'₂,j₂)
  - Evaluate less-than function on second half
  - _Requirements: 7.15_
- [ ] 29.6 Implement M̃ oracle using prefix-suffix
  - Combine LT structure with increment vector
  - Compute M̃(r,r') = Σ_j Ĩnc(r,j)·L̃T(r',j)
  - _Requirements: 7.15, 17.15_
- [ ] 29.7 Compute L̃T(r'₁,j₁) and L̃T(r'₂,j₂) efficiently
  - Compute in O(√T) time and space
  - _Requirements: 7.17_

- [ ] 30. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 8: Polynomial Commitment Schemes

- [ ] 31. Implement Hyrax commitment scheme
- [ ] 31.1 Implement HyraxProver structure
  - Store commitment_key: Vec<G> of √n group elements
  - _Requirements: 8.1-8.2, 8.7_
- [ ] 31.2 Implement matrix representation
  - Arrange polynomial evaluations in √n × √n matrix M
  - Support streaming in column-major order
  - _Requirements: 8.7-8.8_
- [ ] 31.3 Implement commitment computation (streaming)
  - For each column i: hᵢ = ⟨Mᵢ, g⟩
  - Stream entries in column-major order
  - Use Pippenger's algorithm for MSM
  - Space: O(√n), Time: O(n)
  - _Requirements: 8.1-8.2, 8.7-8.8_
- [ ] 31.4 Implement r₁ and r₂ computation
  - Split point r into two halves
  - r₁ = ⊗_{i=1}^{log n/2} (1-rᵢ,rᵢ)
  - r₂ = ⊗_{i=log n/2+1}^{log n} (1-rᵢ,rᵢ)
  - _Requirements: 8.9_
- [ ] 31.5 Implement matrix-vector product k = M·r₂
  - Stream polynomial in column-major order
  - Compute k in O(√n) space, O(n) time
  - _Requirements: 8.9_
- [ ] 31.6 Implement simple evaluation proof
  - Prover sends k ∈ F^√n
  - Verifier computes c* = ⟨r₂, h⟩
  - Verifier confirms ⟨k, g⟩ = c*
  - Verifier checks p(r) = ⟨r₁, k⟩
  - _Requirements: 8.9-8.10_
- [ ] 31.7 Implement Bulletproofs protocol structure
  - Prove knowledge of w₁ such that w₁ = M·r₂ and y = ⟨r₁, w₁⟩
  - log(√n) rounds
  - _Requirements: 8.11_
- [ ] 31.8 Implement Bulletproofs round computation
  - Maintain wᵢ, uᵢ, Gᵢ of size √n/2^(i-1)
  - Property: yᵢ = ⟨uᵢ, wᵢ⟩
  - _Requirements: 8.12_
- [ ] 31.9 Implement Bulletproofs folding
  - wᵢ₊₁ = αᵢ·wᵢ,L + αᵢ⁻¹·wᵢ,R
  - uᵢ₊₁ = αᵢ⁻¹·uᵢ,L + αᵢ·uᵢ,R
  - Gᵢ₊₁ = αᵢ⁻¹·Gᵢ,L + αᵢ·Gᵢ,R
  - _Requirements: 8.13_
- [ ] 31.10 Implement Bulletproofs cross-terms
  - Compute yᵢ,L = ⟨uᵢ,L, wᵢ,R⟩
  - Compute yᵢ,R = ⟨uᵢ,R, wᵢ,L⟩
  - Compute ⟨wᵢ,L, Gᵢ,R⟩ and ⟨wᵢ,R, Gᵢ,L⟩
  - _Requirements: 8.14_
- [ ] 31.11 Implement streaming Bulletproofs prover
  - Compute cross-terms without storing full w₁ vector
  - Stream polynomial once per round
  - Space: O(log n), Time: O(n log n)
  - _Requirements: 8.11-8.15_

- [ ] 32. Implement Dory commitment scheme
- [ ] 32.1 Implement DoryProver structure
  - Store hyrax_key: Vec<G1> of √n elements
  - Store afgho_key: Vec<G2> of √n elements
  - _Requirements: 8.1, 8.15_
- [ ] 32.2 Implement Hyrax commitment computation
  - Compute h = (h₁,...,h_{√n}) using Hyrax
  - _Requirements: 8.1, 8.15_
- [ ] 32.3 Implement AFGHO commitment to Hyrax
  - Commitment = ∏ᵢ e(hᵢ, qᵢ)
  - e is bilinear pairing
  - Single target group element
  - _Requirements: 8.1, 8.15_
- [ ] 32.4 Implement Dory evaluation proof
  - Use Bulletproofs-like protocol with pairings
  - O(log n) rounds, O(√n) space
  - _Requirements: 8.1, 8.15_
- [ ] 32.5 Implement streaming Dory prover
  - Stream polynomial to compute round proofs
  - Space: O(√n), Time: O(n log n) + O(log n) pairings
  - _Requirements: 8.1-8.2_
- [ ] 32.6 Implement commitment key generation on-the-fly
  - Evaluate cryptographic PRG
  - Apply hash-to-curve procedure
  - O(λ) field operations per group element
  - _Requirements: 8.5-8.6_
- [ ] 32.7 Implement hash-to-curve with square root
  - Bottleneck: square root computation in F
  - O(log |F|) = O(λ) field operations per element
  - _Requirements: 8.6_
- [ ] 32.8 Track Dory performance
  - Commitment key: 2√(KT) group elements
  - Evaluation proof: ≤ 30T field operations
  - Multi-pairings: O(1) of size O(√(KT))
  - _Requirements: 8.1-8.2, 10.8, 10.12_

- [ ] 33. Implement hash-based commitment schemes
- [ ] 33.1 Implement HashBasedProver structure
  - Store error_correcting_code implementation
  - Support Ligero, Brakedown, Binius
  - _Requirements: 8.16_
- [ ] 33.2 Implement matrix encoding (row-major streaming)
  - Arrange evaluations in √n × √n matrix
  - Stream in row-major order
  - Space: O(√n)
  - _Requirements: 8.16_
- [ ] 33.3 Implement error-correcting code encoding
  - Encode each row independently
  - Apply Reed-Solomon or other ECC
  - _Requirements: 8.16_
- [ ] 33.4 Implement Merkle hashing of rows
  - Hash each encoded row
  - Build Merkle tree from row hashes
  - Root is commitment
  - _Requirements: 8.16_
- [ ] 33.5 Implement linear combination computation
  - Compute linear combination of rows with coefficients from r₁
  - Single streaming pass in row-major order
  - Space: O(√n)
  - _Requirements: 8.17_
- [ ] 33.6 Implement column opening
  - Sample O(λ) random columns
  - Open selected columns with Merkle proofs
  - _Requirements: 8.17_
- [ ] 33.7 Implement evaluation proof generation
  - Compute linear combination
  - Open random columns
  - Both in O(√n) space with single pass
  - _Requirements: 8.17_
- [ ] 33.8 Track hash-based performance
  - Proof size: O(λ√n)
  - Verifier time: O(λ√n)
  - Prover space: O(√n)
  - _Requirements: 8.16-8.17_
- [ ]* 33.9 Write property test for commitment correctness
  - **Property 10: Commitment Scheme Correctness**
  - Test Hyrax, Dory, and hash-based schemes
  - Verify commitment binding and evaluation correctness
  - **Validates: Requirements 8.1-8.17**

- [ ] 34. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 9: Space-Time Trade-offs and Configuration

- [ ] 35. Implement space-time trade-off module
- [ ] 35.1 Implement O(K+log T) space configuration
  - _Requirements: 9.1_
- [ ] 35.2 Implement O(K+T^(1/2)) space configuration
  - _Requirements: 9.2_
- [ ] 35.3 Implement automatic switching logic
  - _Requirements: 9.3_
- [ ] 35.4 Implement dimension parameter selection
  - _Requirements: 9.6-9.9_
- [ ]* 35.5 Write property test for space bounds
  - **Property 5: Space Bounds**
  - **Validates: Requirements 9.1-9.10, 12.1-12.6**

- [ ] 36. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 10: Jolt Integration

- [ ] 37. Implement SmallSpaceJoltProver
- [ ] 37.1 Implement SmallSpaceJoltProver structure
  - Store memory_size (K), num_cycles (T)
  - Store target_space: SpaceBound enum (SquareRoot or Logarithmic)
  - Store component references: vm, spartan, shout, twist
  - Store commitment_scheme
  - _Requirements: 10.1-10.8_
- [ ] 37.2 Implement SpaceBound configuration
  - SquareRoot: O(K + T^(1/2))
  - Logarithmic: O(K + log T)
  - Choose based on deployment scenario
  - _Requirements: 9.1-9.4_
- [ ] 37.3 Implement prove method structure
  - Phase 1: Execute program and generate witness
  - Phase 2: Commit to witness vectors
  - Phase 3: Generate Spartan proof
  - Phase 4: Generate Shout proofs
  - Phase 5: Generate Twist proofs
  - _Requirements: 10.1-10.8_
- [ ] 37.4 Implement witness vector commitment
  - Commit to < 30 non-zero values per cycle
  - Use streaming commitment scheme
  - Track commitment cost (~350T field operations)
  - _Requirements: 10.8-10.12_
- [ ] 37.5 Integrate Spartan proof generation
  - Call spartan.prove(witness_gen)
  - Verify ~250T + 40T = 290T field operations
  - _Requirements: 10.4_
- [ ] 37.6 Integrate Shout proof for instruction execution
  - Memory size K = 2^64 (instruction space)
  - Verify ~40T + 2T log T field operations
  - _Requirements: 10.5_
- [ ] 37.7 Integrate Shout proof for bytecode lookups
  - Smaller memory size (bytecode << T)
  - Verify ~5T + 2T log T field operations
  - _Requirements: 10.5_
- [ ] 37.8 Integrate Twist proof for registers
  - 32 registers (K = 32)
  - Verify ~35T + 4T log T field operations
  - _Requirements: 10.6_
- [ ] 37.9 Integrate Twist proof for RAM
  - Memory size K = 2^25
  - Verify ~150T + 4T log T field operations (worst case)
  - Optimize for i-local accesses
  - _Requirements: 10.7_
- [ ] 37.10 Implement JoltProof structure
  - Store witness_commitments
  - Store spartan_proof, instruction_shout, bytecode_shout
  - Store register_twist, ram_twist
  - _Requirements: 10.1-10.8_
- [ ] 37.11 Implement commitment cost optimization
  - Commit to ≤ 50 group operations per cycle
  - Translate to ~350 field operations per cycle
  - At least 8 values equal 1, remaining ≤ 22 in {0,...,2^32-1}
  - _Requirements: 10.8-10.12_
- [ ] 37.12 Implement evaluation proof generation
  - Use Dory: ≤ 30T field operations
  - O(1) multi-pairings of size O(√(KT))
  - _Requirements: 10.12_

- [ ] 38. Implement performance analysis module
- [ ] 38.1 Implement PerformanceAnalyzer structure
  - Track field_ops_counter, group_ops_counter
  - Track memory_usage, witness_gen_time
  - _Requirements: 10.1-10.15, 12.1-12.13_
- [ ] 38.2 Implement field operation counting
  - Count operations in each component
  - Spartan: 250T (linear) + 40T (small-space)
  - Shout instruction: 40T + 2T log T
  - Shout bytecode: 5T + 2T log T
  - Twist registers: 35T + 4T log T
  - Twist RAM: 150T + 4T log T
  - Commitments: 350T
  - _Requirements: 10.1-10.15, 12.7-12.13_
- [ ] 38.3 Implement memory usage tracking
  - Track peak memory usage
  - Verify O(K + T^(1/2)) or O(K + log T)
  - For K=2^25, T=2^35: verify space reduction
  - _Requirements: 10.1-10.15, 12.1-12.6_
- [ ] 38.4 Implement concrete performance estimation
  - For K=2^25, T=2^35:
  - Linear: ~900T field operations
  - Small-space: ~900T + 12T log T ≈ 1300T
  - Slowdown factor: ~1.44× (well under 2×)
  - _Requirements: 10.1-10.15, 12.7-12.13_
- [ ] 38.5 Implement witness generation overhead tracking
  - Single generation: < 5% of total time
  - 40 regenerations with 16 threads: < 15% overhead
  - Parallel speedup: up to factor-M
  - _Requirements: 10.13-10.14, 12.4-12.5_
- [ ] 38.6 Implement performance report generation
  - Breakdown by component
  - Linear vs small-space comparison
  - Space usage statistics
  - Slowdown factor analysis
  - _Requirements: 10.1-10.15, 12.1-12.13_
- [ ]* 38.7 Write property test for performance bounds
  - **Property 6: Performance Bounds**
  - Test with various T values (2^20, 2^25, 2^30, 2^35)
  - Verify slowdown < 2× for T ≥ 2^20
  - Verify space bounds
  - **Validates: Requirements 10.1-10.15, 12.1-12.13**

- [ ] 39. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 11: Grand Product Check (for Lasso/Spice)

- [ ] 40. Implement grand product check module
- [ ] 40.1 Implement depth-first tree traversal
  - _Requirements: 14.6-14.9_
- [ ] 40.2 Implement stack-based computation
  - _Requirements: 14.10-14.14_
- [ ] 40.3 Implement g_evals accumulation
  - _Requirements: 14.11, 14.17-14.20_
- [ ] 40.4 Implement special case handling (1^n)
  - _Requirements: 14.21_
- [ ]* 40.5 Write property test for grand product correctness
  - **Validates: Requirements 14.1-14.22**

- [ ] 41. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 12: Lasso (Indexed Lookup Arguments)

- [ ] 42. Implement Lasso prover module
- [ ] 42.1 Implement table decomposition
  - _Requirements: 15.1-15.2_
- [ ] 42.2 Implement sum-check for multilinear expression
  - _Requirements: 15.3-15.5_
- [ ] 42.3 Implement sub-table lookup proofs
  - _Requirements: 15.6_
- [ ] 42.4 Implement streaming witness generation
  - _Requirements: 15.7-15.9_

- [ ] 43. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 13: Spice (Read/Write Memory Checking)

- [ ] 44. Implement Spice prover module
- [ ] 44.1 Implement Algorithm 2 (set construction)
  - _Requirements: 16.1-16.3_
- [ ] 44.2 Implement Schwartz-Zippel fingerprinting
  - _Requirements: 16.5-16.8_
- [ ] 44.3 Implement grand product checks for consistency
  - _Requirements: 16.9_
- [ ] 44.4 Implement MLE evaluation
  - _Requirements: 16.10-16.13_

- [ ] 45. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 14: Error Handling and Validation

- [ ] 46. Implement error handling
- [ ] 46.1 Implement ProverError enum
  - _Requirements: 17.1-17.18_
- [ ] 46.2 Implement error propagation
  - _Requirements: 17.1-17.18_
- [ ] 46.3 Implement validation checks
  - _Requirements: 17.1-17.18_

- [ ] 47. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 15: HyperWolf PCS and Lattice-Based Integration

- [ ] 48. Integrate HyperWolf polynomial commitment scheme
- [ ] 48.1 Implement HyperWolf commitment structure
  - Based on lattice assumptions (Module-SIS, Module-LWE)
  - Standard soundness (no knowledge assumptions)
  - Transparent setup
  - _Requirements: 8.1-8.4, Integration with lattice-based zkVM_
- [ ] 48.2 Implement lattice-based commitment key generation
  - Generate structured matrices for Module-SIS
  - Use rejection sampling for proper distribution
  - Support parameter sets for different security levels (128, 192, 256 bits)
  - _Requirements: 8.5-8.6_
- [ ] 48.3 Implement HyperWolf commitment computation
  - Commit to polynomial using lattice-based hash
  - Support streaming computation in O(√n) space
  - Use structured matrices for efficiency
  - _Requirements: 8.1-8.2, 8.7-8.8_
- [ ] 48.4 Implement HyperWolf evaluation proof
  - Generate proof that committed polynomial evaluates to claimed value
  - Use lattice-based zero-knowledge techniques
  - Achieve O(√n) proof size
  - _Requirements: 8.9-8.10_
- [ ] 48.5 Implement HyperWolf verifier
  - Verify commitment binding
  - Verify evaluation correctness
  - Check lattice-based proof validity
  - _Requirements: 8.9-8.10_
- [ ] 48.6 Optimize HyperWolf for small-space proving
  - Stream commitment key generation
  - Compute proofs in O(√n) space
  - Leverage structured matrices for speed
  - _Requirements: 8.1-8.4_
- [ ] 48.7 Implement parameter selection for HyperWolf
  - Choose lattice dimension based on security level
  - Choose modulus q for Module-SIS/LWE
  - Balance proof size vs. prover time
  - _Requirements: 8.1-8.4_

- [ ] 49. Integrate with Neo lattice-based folding
- [ ] 49.1 Implement Neo folding scheme interface
  - Support CCS (Customizable Constraint System) over small fields
  - Pay-per-bit commitments for efficiency
  - _Requirements: Integration with neo-lattice-zkvm_
- [ ] 49.2 Implement CCS to R1CS conversion
  - Convert Jolt's constraints to CCS format
  - Optimize for Neo's folding-friendly structure
  - _Requirements: 4.1-4.2_
- [ ] 49.3 Implement Neo folding prover
  - Fold multiple CCS instances
  - Use lattice-based commitments
  - Achieve logarithmic verification
  - _Requirements: Integration with neo-lattice-zkvm_
- [ ] 49.4 Implement Neo folding verifier
  - Verify folded instance
  - Check lattice-based proofs
  - _Requirements: Integration with neo-lattice-zkvm_
- [ ] 49.5 Optimize Neo for small-space
  - Stream witness during folding
  - Minimize memory footprint
  - _Requirements: 3.1-3.5, 9.1-9.4_

- [ ] 50. Integrate with LatticeFold+ scheme
- [ ] 50.1 Implement LatticeFold+ commitment scheme
  - Faster, simpler, shorter than original LatticeFold
  - Based on Module-SIS assumption
  - _Requirements: 8.1-8.4_
- [ ] 50.2 Implement LatticeFold+ folding protocol
  - Fold R1CS instances using lattice techniques
  - Achieve sublinear verification
  - _Requirements: 4.1-4.13_
- [ ] 50.3 Implement LatticeFold+ prover optimizations
  - Use structured matrices for speed
  - Stream computations for small space
  - _Requirements: 8.1-8.4, 9.1-9.4_
- [ ] 50.4 Implement LatticeFold+ verifier
  - Verify folded instance efficiently
  - Check lattice-based proofs
  - _Requirements: 8.9-8.10_

- [ ] 51. Integrate with SALSAA (Sumcheck-Aided Lattice-based Succinct Arguments)
- [ ] 51.1 Implement SALSAA commitment scheme
  - Lattice-based polynomial commitments
  - Linear-time prover
  - _Requirements: 8.1-8.4_
- [ ] 51.2 Implement SALSAA sum-check integration
  - Use lattice commitments with sum-check protocol
  - Maintain small-space properties
  - _Requirements: 1.1-1.16, 8.1-8.4_
- [ ] 51.3 Implement SALSAA evaluation proofs
  - Generate lattice-based evaluation proofs
  - Optimize for small space
  - _Requirements: 8.9-8.10_
- [ ] 51.4 Implement SALSAA verifier
  - Verify sum-check with lattice commitments
  - Check evaluation proofs
  - _Requirements: 8.9-8.10_

- [ ] 52. Implement unified commitment scheme interface
- [ ] 52.1 Define PolynomialCommitmentScheme trait
  - Methods: setup, commit, prove_evaluation, verify_evaluation
  - Support multiple backends: Hyrax, Dory, HyperWolf, SALSAA
  - _Requirements: 8.1-8.17_
- [ ] 52.2 Implement commitment scheme selection
  - Choose based on: security assumptions, proof size, prover time
  - Elliptic curve-based: Hyrax, Dory
  - Lattice-based: HyperWolf, SALSAA, LatticeFold+
  - Hash-based: Ligero, Brakedown, Binius
  - _Requirements: 8.1-8.17_
- [ ] 52.3 Implement commitment scheme benchmarking
  - Compare proof sizes across schemes
  - Compare prover times
  - Compare verifier times
  - Compare security assumptions
  - _Requirements: 8.1-8.17, 12.1-12.13_
- [ ] 52.4 Implement hybrid commitment strategies
  - Use different schemes for different components
  - E.g., lattice for witness, elliptic curve for small commitments
  - Optimize overall performance
  - _Requirements: 8.1-8.17_

- [ ] 53. Integrate with Symphony (lattice-based high-arity folding)
- [ ] 53.1 Implement Symphony folding scheme
  - High-arity folding for better efficiency
  - Lattice-based in random oracle model
  - _Requirements: Integration with Symphony paper_
- [ ] 53.2 Implement Symphony commitment scheme
  - Lattice-based commitments optimized for folding
  - _Requirements: 8.1-8.4_
- [ ] 53.3 Implement Symphony prover
  - Fold multiple instances simultaneously
  - Achieve better concrete efficiency than binary folding
  - _Requirements: Integration with Symphony paper_
- [ ] 53.4 Optimize Symphony for small-space
  - Stream witness during high-arity folding
  - Minimize memory footprint
  - _Requirements: 3.1-3.5, 9.1-9.4_

- [ ] 54. Implement lattice-based security analysis
- [ ] 54.1 Implement Module-SIS hardness estimation
  - Estimate security level for given parameters
  - Account for known attacks (BKZ, sieving)
  - _Requirements: 13.1-13.9_
- [ ] 54.2 Implement Module-LWE hardness estimation
  - Estimate security level for given parameters
  - Account for known attacks
  - _Requirements: 13.1-13.9_
- [ ] 54.3 Implement parameter selection tool
  - Given target security level, choose lattice parameters
  - Balance security vs. efficiency
  - _Requirements: 13.1-13.9, 17.6-17.7_
- [ ] 54.4 Implement security comparison across schemes
  - Compare elliptic curve vs. lattice assumptions
  - Analyze post-quantum security
  - _Requirements: 13.1-13.9_

- [ ] 55. Implement cross-scheme compatibility layer
- [ ] 55.1 Implement proof format conversion
  - Convert between different commitment scheme formats
  - Enable interoperability
  - _Requirements: 8.1-8.17_
- [ ] 55.2 Implement witness format conversion
  - Convert witness between different representations
  - Support R1CS, CCS, AIR formats
  - _Requirements: 3.1-3.10, 4.1-4.13_
- [ ] 55.3 Implement constraint system conversion
  - Convert between R1CS, CCS, Plonkish
  - Optimize for target proving system
  - _Requirements: 4.1-4.13_
- [ ] 55.4 Implement unified verifier interface
  - Single verifier that handles multiple proof formats
  - Automatic scheme detection
  - _Requirements: 8.1-8.17_

- [ ] 56. Checkpoint
  - Ensure all lattice-based integrations work correctly
  - Verify compatibility with existing components
  - Test performance across different commitment schemes

## Phase 16: Testing and Validation

- [ ] 57. Implement comprehensive test suite
- [ ] 57.1 Implement bit-identical proof comparison tests
  - Compare small-space vs linear-space proofs
  - Verify identical outputs for same inputs
  - Test across all components
  - _Requirements: 15.1, 18.1_
- [ ] 57.2 Implement space usage verification tests
  - Track peak memory usage during proving
  - Verify O(K + T^(1/2)) or O(K + log T) bounds
  - Test with various T values
  - _Requirements: 15.3, 18.3_
- [ ] 57.3 Implement performance measurement tests
  - Measure field operations per component
  - Measure total prover time
  - Compare to linear-space baseline
  - _Requirements: 15.2, 18.2, 18.19-18.20_
- [ ] 57.4 Implement correctness validation tests
  - Test witness regeneration consistency
  - Test prefix-suffix protocol correctness
  - Test small-value optimization equivalence
  - Test all memory checking protocols
  - _Requirements: 15.4-15.8, 18.4-18.18_
- [ ] 57.5 Implement cross-scheme testing
  - Test with Hyrax, Dory, HyperWolf, SALSAA
  - Verify correctness across all commitment schemes
  - Compare performance characteristics
  - _Requirements: 8.1-8.17, 18.1-18.20_

- [ ] 58. Implement concrete performance targets validation
- [ ] 58.1 Validate K=2^25, T=2^35 scenario
  - Test with realistic memory and cycle counts
  - Verify ~1300T field operations total
  - Verify space usage ~10-100 GB
  - _Requirements: 19.1_
- [ ] 58.2 Validate Spartan performance
  - Verify 250T → 290T field operations
  - Test with block-diagonal matrices
  - _Requirements: 19.2_
- [ ] 58.3 Validate Shout performance (instruction)
  - Verify 40T → 110T field operations
  - Test with K=2^64 instruction space
  - _Requirements: 19.3_
- [ ] 58.4 Validate Shout performance (bytecode)
  - Verify 5T → 75T field operations
  - Test with smaller bytecode tables
  - _Requirements: 19.4_
- [ ] 58.5 Validate Twist performance (registers)
  - Verify 35T → 175T field operations
  - Test with 32 registers
  - _Requirements: 19.5_
- [ ] 58.6 Validate Twist performance (RAM)
  - Verify 150T → 290T field operations
  - Test with K=2^25 RAM size
  - Test i-local access optimization
  - _Requirements: 19.6_
- [ ] 58.7 Validate commitment costs
  - Verify ~350T field operations
  - Test with < 30 non-zero values per cycle
  - _Requirements: 19.7-19.8_
- [ ] 58.8 Validate witness generation overhead
  - Verify < 5% for single generation
  - Verify < 15% for 40 regenerations with 16 threads
  - _Requirements: 19.9_
- [ ] 58.9 Validate total prover time
  - Verify slowdown < 2× for T ≥ 2^20
  - Test with T ∈ {2^20, 2^25, 2^30, 2^35}
  - _Requirements: 19.10_
- [ ] 58.10 Validate lattice-based scheme performance
  - Compare HyperWolf vs Hyrax/Dory
  - Measure proof sizes
  - Measure prover/verifier times
  - _Requirements: 8.1-8.17, 19.1-19.10_

- [ ] 59. Implement integration tests
- [ ] 59.1 Test end-to-end RISC-V program execution
  - Execute real programs (sorting, fibonacci, etc.)
  - Generate and verify proofs
  - Test with different commitment schemes
  - _Requirements: 3.1-3.10, 10.1-10.15_
- [ ] 59.2 Test component integration
  - Verify Spartan + Shout + Twist work together
  - Test with streaming witness generation
  - Test with checkpointing and regeneration
  - _Requirements: 10.1-10.15_
- [ ] 59.3 Test cross-platform compatibility
  - Test on different architectures (x86, ARM)
  - Test on different operating systems
  - Verify consistent results
  - _Requirements: 18.1-18.20_
- [ ] 59.4 Test security properties
  - Verify soundness error bounds
  - Test with malicious provers
  - Verify commitment binding
  - _Requirements: 13.1-13.9, 18.17_

- [ ] 60. Final Checkpoint
  - Ensure all tests pass across all commitment schemes
  - Verify performance targets met
  - Validate security properties
  - Confirm production readiness

---

## Summary

This implementation plan provides a complete, compact roadmap for building the small-space zkVM prover with comprehensive lattice-based integration:

- **60 consolidated tasks** (embedding 300+ implementation details) organized into 16 phases
- **10 property-based tests** for all core correctness properties
- **16 checkpoints** after each major phase
- **Clear requirement traceability** for every task and sub-task
- **Detailed implementation guidance** for complex components
- **Comprehensive lattice-based PCS integration** (HyperWolf, SALSAA, LatticeFold+, Symphony, Neo)

The implementation follows a bottom-up approach: foundation → protocols → memory checking → commitments → lattice integration → testing, ensuring each component is solid before building on top of it.

**Enhanced Task Structure:**

**Core Implementation (Phases 1-10):**
- **Phase 1 (Foundation)**: 31 sub-tasks covering field arithmetic, MLEs, equality functions, polynomials with thorough detail
- **Phase 2 (Sum-Check)**: 28 sub-tasks for standard, small-space, and small-value optimized sum-check
- **Phase 3 (Witness)**: 23 sub-tasks for RISC-V VM, checkpointing, and streaming generation
- **Phase 4 (Spartan)**: 24 sub-tasks for R1CS, Spartan prover, and pcnext virtual polynomial
- **Phase 5 (Shout)**: 24 sub-tasks for read-only memory checking with one-hot encoding
- **Phase 6 (Twist)**: 25 sub-tasks for read/write memory with increment tracking
- **Phase 7 (Prefix-Suffix)**: 27 sub-tasks for structured inner product protocol
- **Phase 8 (Commitments)**: 33 sub-tasks for Hyrax, Dory, and hash-based schemes
- **Phase 9 (Trade-offs)**: 5 sub-tasks for space-time configuration
- **Phase 10 (Integration)**: 19 sub-tasks for complete Jolt prover and performance analysis

**Advanced Features (Phases 11-14):**
- **Phase 11 (Grand Product)**: 5 sub-tasks for Lasso/Spice support
- **Phase 12 (Lasso)**: 4 sub-tasks for indexed lookup arguments
- **Phase 13 (Spice)**: 4 sub-tasks for read/write memory checking
- **Phase 14 (Error Handling)**: 3 sub-tasks for comprehensive error management

**Lattice-Based Integration (Phase 15):**
- **Phase 15 (HyperWolf & Lattice)**: 36 sub-tasks covering:
  - **HyperWolf PCS**: 7 sub-tasks for lattice-based polynomial commitments with standard soundness
  - **Neo Integration**: 5 sub-tasks for lattice-based folding over small fields
  - **LatticeFold+**: 4 sub-tasks for faster, simpler lattice folding
  - **SALSAA**: 4 sub-tasks for sumcheck-aided lattice arguments
  - **Symphony**: 4 sub-tasks for high-arity lattice folding
  - **Security Analysis**: 4 sub-tasks for lattice hardness estimation
  - **Unified Interface**: 4 sub-tasks for cross-scheme compatibility
  - **Benchmarking**: 4 sub-tasks for performance comparison

**Testing & Validation (Phase 16):**
- **Phase 16 (Testing)**: 24 sub-tasks covering:
  - Comprehensive test suite (5 sub-tasks)
  - Concrete performance validation (10 sub-tasks)
  - Integration tests (4 sub-tasks)
  - Cross-scheme testing (5 sub-tasks)

**Key Implementation Principles:**
1. **Thorough foundation** with detailed field arithmetic and MLE implementations
2. **Granular sub-tasks** make complex components manageable
3. **Build core protocols** (Spartan, Shout, Twist) with full mathematical detail
4. **Multiple commitment schemes** (elliptic curve, lattice, hash-based)
5. **Lattice-based integration** for post-quantum security
6. **Unified interfaces** for interoperability
7. **Comprehensive testing** across all schemes
8. **Performance validation** at every checkpoint

**Commitment Scheme Options:**
- **Elliptic Curve-Based**: Hyrax, Dory (pre-quantum secure)
- **Lattice-Based**: HyperWolf, SALSAA, LatticeFold+, Symphony, Neo (post-quantum secure)
- **Hash-Based**: Ligero, Brakedown, Binius (transparent, post-quantum)

**Testing Strategy:**
- **Property-based tests** validate universal correctness properties (10 properties)
- **Unit tests** verify specific examples and edge cases (marked with *)
- **Integration tests** ensure components work together correctly
- **Cross-scheme tests** validate all commitment schemes
- **Performance tests** validate concrete targets:
  - Slowdown < 2× for T ≥ 2^20
  - Space: O(K + T^(1/2)) or O(K + log T)
  - For K=2^25, T=2^35: ~1300T field ops vs ~900T (1.44× slowdown)

**Concrete Performance Targets:**
- **Spartan**: 250T → 290T field operations
- **Shout (instruction)**: 40T → 110T field operations
- **Shout (bytecode)**: 5T → 75T field operations
- **Twist (registers)**: 35T → 175T field operations
- **Twist (RAM)**: 150T → 290T field operations
- **Commitments**: 350T field operations (scheme-dependent)
- **Total**: 900T → 1300T field operations (1.44× slowdown)

**Lattice-Based Security:**
- **Module-SIS/LWE** hardness assumptions
- **Post-quantum secure** against quantum attacks
- **Standard soundness** (no knowledge assumptions for HyperWolf)
- **Transparent setup** (no trusted setup required)
- **Parameter selection** tools for security levels (128, 192, 256 bits)
